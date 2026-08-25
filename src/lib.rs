/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(non_snake_case)]

extern crate byteorder;
#[cfg(target_os = "macos")]
#[macro_use]
extern crate core_foundation;
extern crate env_logger;
#[macro_use]
extern crate lazy_static;
#[cfg(target_os = "macos")]
extern crate libloading;
#[macro_use]
extern crate log;
extern crate pkcs11;
#[cfg(target_os = "macos")]
#[macro_use]
extern crate rental;
extern crate sha2;
#[cfg(target_os = "windows")]
extern crate winapi;

use pkcs11::types::padding::{
    BlankPaddedString16, BlankPaddedUtf8String16, BlankPaddedUtf8String32, BlankPaddedUtf8String64,
};
use pkcs11::types::*;
use std::sync::Mutex;

mod manager;
#[macro_use]
mod util;
#[cfg(target_os = "macos")]
mod backend_macos;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod backend_other;
#[cfg(target_os = "windows")]
mod backend_windows;
mod mechanism;

use manager::ManagerProxy;
use util::crypto_error_to_rv;

use crate::mechanism::parse_rsa_cipher_mechanism;

lazy_static! {
    /// The singleton `ManagerProxy` that handles state with respect to PKCS #11. Only one thread
    /// may use it at a time, but there is no restriction on which threads may use it. However, as
    /// OS APIs being used are not necessarily thread-safe (e.g. they may be using
    /// thread-local-storage), the `ManagerProxy` forwards calls from any thread to a single thread
    /// where the real `Manager` does the actual work.
    static ref MANAGER_PROXY: Mutex<Option<ManagerProxy>> = Mutex::new(None);
}

// Obtaining a handle on the manager proxy is a two-step process. First the mutex must be locked,
// which (if successful), results in a mutex guard object. We must then get a mutable refence to the
// underlying manager proxy (if set - otherwise we return an error). This can't happen all in one
// macro without dropping a reference that needs to live long enough for this to be safe. In
// practice, this looks like:
//   let mut manager_guard = try_to_get_manager_guard!();
//   let manager = manager_guard_to_manager!(manager_guard);
macro_rules! try_to_get_manager_guard {
    () => {
        match MANAGER_PROXY.lock() {
            Ok(maybe_manager_proxy) => maybe_manager_proxy,
            Err(poison_error) => {
                error!(
                    "previous thread panicked acquiring manager lock: {}",
                    poison_error
                );
                return CKR_DEVICE_ERROR;
            }
        }
    };
}

macro_rules! manager_guard_to_manager {
    ($manager_guard:ident) => {
        match $manager_guard.as_mut() {
            Some(manager_proxy) => manager_proxy,
            None => {
                error!("manager expected to be set, but it is not");
                return CKR_DEVICE_ERROR;
            }
        }
    };
}

/// This gets called to initialize the module. For this implementation, this consists of
/// instantiating the `ManagerProxy`.
extern "C" fn C_Initialize(_pInitArgs: CK_C_INITIALIZE_ARGS_PTR) -> CK_RV {
    let _ = env_logger::try_init();
    let mut manager_guard = try_to_get_manager_guard!();
    // Per PKCS #11, initializing an already-initialized module is an error; the caller must call
    // C_Finalize first. (The manager left behind by C_Finalize is always fully stopped and taken
    // out of the proxy slot, so a fresh C_Install here starts from a clean slate.)
    if manager_guard.is_some() {
        error!("C_Initialize: module already initialized");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    *manager_guard = Some(ManagerProxy::new());
    debug!("C_Initialize: CKR_OK");
    CKR_OK
}

extern "C" fn C_Finalize(_pReserved: CK_VOID_PTR) -> CK_RV {
    let mut manager_guard = try_to_get_manager_guard!();
    // Take the manager proxy out of the slot before stopping it: after C_Finalize returns, the
    // module is uninitialized and a subsequent C_Initialize must find no leftover state.
    match manager_guard.take() {
        Some(mut manager) => match manager.stop() {
            Ok(()) => {
                debug!("C_Finalize: CKR_OK");
                CKR_OK
            }
            Err(()) => {
                debug!("C_Finalize: CKR_DEVICE_ERROR");
                CKR_DEVICE_ERROR
            }
        },
        None => {
            error!("C_Finalize: module not initialized");
            CKR_CRYPTOKI_NOT_INITIALIZED
        }
    }
}

// The specification mandates that these strings be padded with spaces to the appropriate length.
// Since the length of fixed-size arrays in rust is part of the type, the compiler enforces that
// these byte strings are of the correct length.
const MANUFACTURER_ID_BYTES: &[u8; 32] = b"Mozilla Corporation             ";
const LIBRARY_DESCRIPTION_BYTES: &[u8; 32] = b"OS Client Cert Module           ";

/// This gets called to gather some information about the module. In particular, this implementation
/// supports (portions of) cryptoki (PKCS #11) version 2.2.
extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        error!("C_GetInfo: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    debug!("C_GetInfo: CKR_OK");
    let mut info = CK_INFO::default();
    info.cryptokiVersion.major = 2;
    info.cryptokiVersion.minor = 2;
    info.manufacturerID = BlankPaddedUtf8String32(*MANUFACTURER_ID_BYTES);
    info.libraryDescription = BlankPaddedUtf8String32(*LIBRARY_DESCRIPTION_BYTES);
    unsafe {
        *pInfo = info;
    }
    CKR_OK
}

/// This module only has one slot. Its ID is 1.
const SLOT_ID: CK_SLOT_ID = 1;

// Bounds on caller-provided sizes at the FFI boundary. Legitimate callers (NSS) use values well
// under these limits; the bounds exist so that a hostile or buggy caller passing absurd counts or
// lengths makes us return CKR_ARGUMENTS_BAD instead of walking (and dereferencing) arbitrary
// amounts of memory. Note that we can never validate that a non-null pointer itself is valid -
// that remains part of the C calling contract.
/// The largest number of attributes we will accept in a template.
const MAX_TEMPLATE_COUNT: CK_ULONG = 128;
/// The largest attribute value we will copy out of caller-provided memory (labels, IDs, and even
/// full certificate values are at most a few KiB).
const MAX_ATTRIBUTE_VALUE_LEN: CK_ULONG = 64 * 1024;
/// The largest input buffer (plaintext, ciphertext, or digest) we will read from
/// caller-provided memory (RSA operations for keys up to 4096 bits use well under 1 KiB).
const MAX_DATA_LEN: CK_ULONG = 64 * 1024;

/// Converts a caller-supplied byte buffer into a slice. A null pointer is accepted only for a
/// zero-length buffer, yielding an empty slice; `slice::from_raw_parts` requires a non-null
/// pointer even for zero lengths, so this centralizes the check instead of relying on each call
/// site to remember it. The caller still warrants that, for non-zero lengths, the pointer is
/// aligned and dereferenceable for `len` bytes - that part of the C calling contract cannot be
/// validated in-process.
///
/// # Safety
///
/// For non-null pointers, `ptr` must be aligned and valid for reads of `len` bytes.
unsafe fn input_slice<'a>(ptr: CK_BYTE_PTR, len: CK_ULONG) -> Result<&'a [u8], CK_RV> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: the caller of input_slice warrants that a non-null ptr is aligned and readable for
    // len bytes; the null case never reaches from_raw_parts.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

/// This gets called twice: once with a null `pSlotList` to get the number of slots (returned via
/// `pulCount`) and a second time to get the ID for each slot.
extern "C" fn C_GetSlotList(
    _tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if pulCount.is_null() {
        error!("C_GetSlotList: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *pulCount = 1;
    }
    if !pSlotList.is_null() {
        let slotCount = unsafe { *pulCount };
        if slotCount < 1 {
            error!("C_GetSlotList: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            *pSlotList = SLOT_ID;
        }
    };
    debug!("C_GetSlotList: CKR_OK");
    CKR_OK
}

const SLOT_DESCRIPTION_BYTES: &[u8; 64] =
    b"OS Client Cert Slot                                             ";

/// This gets called to obtain information about slots. In this implementation, the token is always
/// present in the slot.
extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    if slotID != SLOT_ID || pInfo.is_null() {
        error!("C_GetSlotInfo: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let slot_info = CK_SLOT_INFO {
        slotDescription: BlankPaddedUtf8String64(*SLOT_DESCRIPTION_BYTES),
        manufacturerID: BlankPaddedUtf8String32(*MANUFACTURER_ID_BYTES),
        flags: CKF_TOKEN_PRESENT,
        hardwareVersion: CK_VERSION::default(),
        firmwareVersion: CK_VERSION::default(),
    };
    unsafe {
        *pInfo = slot_info;
    }
    debug!("C_GetSlotInfo: CKR_OK");
    CKR_OK
}

const TOKEN_LABEL_BYTES: &[u8; 32] = b"OS Client Cert Token            ";
const TOKEN_MODEL_BYTES: &[u8; 16] = b"osclientcerts   ";
const TOKEN_SERIAL_NUMBER_BYTES: &[u8; 16] = b"0000000000000000";

/// This gets called to obtain some information about tokens. This implementation only has one slot,
/// so it only has one token. This information is primarily for display purposes.
extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slotID != SLOT_ID || pInfo.is_null() {
        error!("C_GetTokenInfo: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let token_info = CK_TOKEN_INFO {
        label: BlankPaddedUtf8String32(*TOKEN_LABEL_BYTES),
        manufacturerID: BlankPaddedUtf8String32(*MANUFACTURER_ID_BYTES),
        model: BlankPaddedUtf8String16(*TOKEN_MODEL_BYTES),
        serialNumber: BlankPaddedString16(*TOKEN_SERIAL_NUMBER_BYTES),
        // Advertise what this token can do so that applications (e.g. NSS) will attempt sign,
        // encrypt, and decrypt operations.
        flags: CKF_SIGN | CKF_ENCRYPT | CKF_DECRYPT,
        ..Default::default()
    };
    unsafe {
        *pInfo = token_info;
    }
    debug!("C_GetTokenInfo: CKR_OK");
    CKR_OK
}

/// This gets called to determine what mechanisms a slot supports. This implementation supports
/// ECDSA, RSA PKCS, RSA PSS, and RSA OAEP.
extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if slotID != SLOT_ID || pulCount.is_null() {
        error!("C_GetMechanismList: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mechanisms = [CKM_ECDSA, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_RSA_PKCS_OAEP];
    if !pMechanismList.is_null() {
        if unsafe { *pulCount as usize } < mechanisms.len() {
            error!("C_GetMechanismList: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        for (i, mechanism) in mechanisms.iter().enumerate() {
            unsafe {
                *pMechanismList.add(i) = *mechanism;
            }
        }
    }
    unsafe {
        *pulCount = mechanisms.len() as CK_ULONG;
    }
    debug!("C_GetMechanismList: CKR_OK");
    CKR_OK
}

/// This gets called to determine what capabilities this module supports for a given mechanism.
/// NSS calls this after `C_GetMechanismList` to decide whether and how to use each mechanism.
extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    debug!(
        "C_GetMechanismInfo: slot {}, mechanism {}",
        slotID, mechanism_type
    );
    if slotID != SLOT_ID {
        error!("C_GetMechanismInfo: CKR_SLOT_ID_INVALID");
        return CKR_SLOT_ID_INVALID;
    }
    if pInfo.is_null() {
        error!("C_GetMechanismInfo: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let info = unsafe { &mut *pInfo };
    // Key sizes are in bits. RSA keys from 1024 up to 16384 bits are usable via CNG; for elliptic
    // curves we support the NIST curves P-256 through P-521.
    let (info_min_key_size, info_max_key_size, info_flags) = match mechanism_type {
        CKM_RSA_PKCS => (1024, 16384, CKF_SIGN | CKF_DECRYPT | CKF_ENCRYPT),
        CKM_RSA_PKCS_PSS => (1024, 16384, CKF_SIGN),
        CKM_RSA_PKCS_OAEP => (1024, 16384, CKF_ENCRYPT | CKF_DECRYPT),
        CKM_ECDSA => (192, 521, CKF_SIGN),
        _ => {
            error!(
                "C_GetMechanismInfo: unsupported mechanism: {}",
                mechanism_type
            );
            return CKR_MECHANISM_INVALID;
        }
    };
    info.ulMinKeySize = info_min_key_size;
    info.ulMaxKeySize = info_max_key_size;
    info.flags = info_flags;
    debug!("C_GetMechanismInfo: CKR_OK");
    CKR_OK
}

extern "C" fn C_InitToken(
    _slotID: CK_SLOT_ID,
    _pPin: CK_UTF8CHAR_PTR,
    _ulPinLen: CK_ULONG,
    _pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV {
    error!("C_InitToken: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_InitPIN(
    _hSession: CK_SESSION_HANDLE,
    _pPin: CK_UTF8CHAR_PTR,
    _ulPinLen: CK_ULONG,
) -> CK_RV {
    error!("C_InitPIN: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SetPIN(
    _hSession: CK_SESSION_HANDLE,
    _pOldPin: CK_UTF8CHAR_PTR,
    _ulOldLen: CK_ULONG,
    _pNewPin: CK_UTF8CHAR_PTR,
    _ulNewLen: CK_ULONG,
) -> CK_RV {
    error!("C_SetPIN: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

/// This gets called to create a new session. This module defers to the `ManagerProxy` to implement
/// this.
extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: CK_VOID_PTR,
    _Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    // The specification requires the serial-session flag on every session.
    if slotID != SLOT_ID || phSession.is_null() || flags & CKF_SERIAL_SESSION == 0 {
        error!("C_OpenSession: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    let session_handle = match manager.open_session(flags) {
        Ok(session_handle) => session_handle,
        Err(()) => {
            error!("C_OpenSession: open_session failed");
            return CKR_DEVICE_ERROR;
        }
    };
    unsafe {
        *phSession = session_handle;
    }
    debug!("C_OpenSession: CKR_OK");
    CKR_OK
}

/// This gets called to close a session. This is handled by the `ManagerProxy`.
extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    if manager.close_session(hSession).is_err() {
        error!("C_CloseSession: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    debug!("C_CloseSession: CKR_OK");
    CKR_OK
}

/// This gets called to close all open sessions at once. This is handled by the `ManagerProxy`.
extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    if slotID != SLOT_ID {
        error!("C_CloseAllSessions: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    match manager.close_all_sessions() {
        Ok(()) => {
            debug!("C_CloseAllSessions: CKR_OK");
            CKR_OK
        }
        Err(()) => {
            debug!("C_CloseAllSessions: close_all_sessions failed");
            CKR_DEVICE_ERROR
        }
    }
}

/// This gets called to obtain information about a session. The provider never implements
/// C_Login, so every session is a public session; the read-only vs read-write distinction and the
/// flags reported come from what the session was opened with via C_OpenSession.
extern "C" fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        error!("C_GetSessionInfo: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    let flags = match manager.get_session_info(hSession) {
        Ok(flags) => flags,
        Err(()) => {
            error!("C_GetSessionInfo: CKR_SESSION_HANDLE_INVALID");
            return CKR_SESSION_HANDLE_INVALID;
        }
    };
    // SAFETY: pInfo was checked non-null above; the caller warrants it points to writable memory
    // of at least size_of::<CK_SESSION_INFO>(), as required by the C calling convention.
    unsafe {
        (*pInfo).slotID = SLOT_ID;
        (*pInfo).state = if flags & CKF_RW_SESSION != 0 {
            CKS_RW_PUBLIC_SESSION
        } else {
            CKS_RO_PUBLIC_SESSION
        };
        (*pInfo).flags = flags | CKF_SERIAL_SESSION;
        (*pInfo).ulDeviceError = 0;
    }
    debug!("C_GetSessionInfo: CKR_OK (session {hSession}, flags {flags:#x})");
    CKR_OK
}

extern "C" fn C_GetOperationState(
    _hSession: CK_SESSION_HANDLE,
    _pOperationState: CK_BYTE_PTR,
    _pulOperationStateLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_GetOperationState: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SetOperationState(
    _hSession: CK_SESSION_HANDLE,
    _pOperationState: CK_BYTE_PTR,
    _ulOperationStateLen: CK_ULONG,
    _hEncryptionKey: CK_OBJECT_HANDLE,
    _hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    error!("C_SetOperationState: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Login(
    _hSession: CK_SESSION_HANDLE,
    _userType: CK_USER_TYPE,
    _pPin: CK_UTF8CHAR_PTR,
    _ulPinLen: CK_ULONG,
) -> CK_RV {
    error!("C_Login: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

/// This gets called to log out and drop any authenticated resources. Because this module does not
/// hold on to authenticated resources, this module "implements" this by doing nothing and
/// returning a success result.
extern "C" fn C_Logout(_hSession: CK_SESSION_HANDLE) -> CK_RV {
    debug!("C_Logout: CKR_OK");
    CKR_OK
}

extern "C" fn C_CreateObject(
    _hSession: CK_SESSION_HANDLE,
    _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG,
    _phObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    error!("C_CreateObject: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_CopyObject(
    _hSession: CK_SESSION_HANDLE,
    _hObject: CK_OBJECT_HANDLE,
    _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG,
    _phNewObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    error!("C_CopyObject: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DestroyObject(_hSession: CK_SESSION_HANDLE, _hObject: CK_OBJECT_HANDLE) -> CK_RV {
    error!("C_DestroyObject: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GetObjectSize(
    _hSession: CK_SESSION_HANDLE,
    _hObject: CK_OBJECT_HANDLE,
    _pulSize: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_GetObjectSize: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

/// This gets called to obtain the values of a number of attributes of an object identified by the
/// given handle. This module implements this by requesting that the `ManagerProxy` find the object
/// and attempt to get the value of each attribute. If a specified attribute is not defined on the
/// object, the length of that attribute is set to -1 to indicate that it is not available.
/// This gets called twice: once to obtain the lengths of the attributes and again to get the
/// values.
extern "C" fn C_GetAttributeValue(
    _hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() {
        error!("C_GetAttributeValue: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if ulCount > MAX_TEMPLATE_COUNT {
        error!("C_GetAttributeValue: unreasonable template count {ulCount}");
        return CKR_ARGUMENTS_BAD;
    }
    let mut attr_types = Vec::with_capacity(ulCount as usize);
    let template = unsafe { std::slice::from_raw_parts(pTemplate, ulCount as usize) };
    for attr in template {
        let attr_type = unsafe_packed_field_access!(attr.attrType);
        info!("  GetAttr handle={hObject} type=0x{:x}", attr_type);
        attr_types.push(attr_type);
    }
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    let values = match manager.get_attributes(hObject, attr_types) {
        Ok(values) => values,
        Err(()) => {
            error!("C_GetAttributeValue: CKR_ARGUMENTS_BAD");
            return CKR_ARGUMENTS_BAD;
        }
    };
    if values.len() != ulCount as usize {
        error!(
            "C_GetAttributeValue: manager.get_attributes didn't return the right number of values"
        );
        return CKR_DEVICE_ERROR;
    }
    let mut rv = CKR_OK;
    let template = unsafe { std::slice::from_raw_parts_mut(pTemplate, ulCount as usize) };
    // NB: the zip below relies on values.len() == ulCount, which is checked above
    for (attr, value) in template.iter_mut().zip(values.iter()) {
        if let Some(attr_value) = value {
            if attr.pValue.is_null() {
                attr.ulValueLen = attr_value.len() as CK_ULONG;
            } else {
                let ptr: *mut u8 = attr.pValue.cast();
                if (attr.ulValueLen as usize) < attr_value.len() {
                    // As specified, report the required length for this attribute and keep going;
                    // the caller is expected to retry with a big enough buffer.
                    attr.ulValueLen = attr_value.len() as CK_ULONG;
                    rv = CKR_BUFFER_TOO_SMALL;
                    continue;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(attr_value.as_ptr(), ptr, attr_value.len());
                }
                info!(
                    "  GetAttr result handle={hObject} type=0x{:x} len={} value={:02x?}",
                    unsafe_packed_field_access!(attr.attrType),
                    attr_value.len(),
                    &attr_value[..],
                );
            }
        } else {
            attr.ulValueLen = (0 - 1) as CK_ULONG; // CK_UNAVAILABLE_INFORMATION
        }
    }
    if rv != CKR_OK {
        error!("C_GetAttributeValue: CKR_BUFFER_TOO_SMALL");
        return rv;
    }
    debug!("C_GetAttributeValue: CKR_OK");
    CKR_OK
}

extern "C" fn C_SetAttributeValue(
    _hSession: CK_SESSION_HANDLE,
    _hObject: CK_OBJECT_HANDLE,
    _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG,
) -> CK_RV {
    error!("C_SetAttributeValue: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

/// This gets called to initialize a search for objects matching a given list of attributes. This
/// module implements this by gathering the attributes and passing them to the `ManagerProxy` to
/// start the search.
extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() {
        error!("C_FindObjectsInit: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if ulCount > MAX_TEMPLATE_COUNT {
        error!("C_FindObjectsInit: unreasonable template count {ulCount}");
        return CKR_ARGUMENTS_BAD;
    }
    let mut attrs = Vec::new();
    info!("C_FindObjectsInit:");
    for i in 0..ulCount {
        let attr = unsafe { &*pTemplate.offset(i as isize) };
        // CK_ATTRIBUTE may be packed depending on the target, so copy fields out before using
        // them (formatting or referencing a field of a packed struct is not allowed).
        let attr_type = attr.attrType;
        let value_len = attr.ulValueLen;
        if value_len > MAX_ATTRIBUTE_VALUE_LEN {
            error!("C_FindObjectsInit: unreasonable attribute value length {value_len}");
            return CKR_ARGUMENTS_BAD;
        }
        // A null value pointer is only meaningful for a zero-length value (input_slice handles
        // that combination without invoking undefined behavior).
        let slice = match unsafe { input_slice(attr.pValue as CK_BYTE_PTR, value_len) } {
            Ok(slice) => slice,
            Err(rv) => {
                error!("C_FindObjectsInit: invalid attribute value pointer/length combination");
                return rv;
            }
        };
        info!(
            "  attr[{}] type=0x{:x} len={} value={:02x?}",
            i, attr_type, value_len, slice
        );
        attrs.push((attr_type, slice.to_owned()));
    }
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    match manager.start_search(hSession, attrs) {
        Ok(()) => {}
        Err(()) => {
            error!("C_FindObjectsInit: CKR_ARGUMENTS_BAD");
            return CKR_ARGUMENTS_BAD;
        }
    }
    debug!("C_FindObjectsInit: CKR_OK");
    CKR_OK
}

/// This gets called after `C_FindObjectsInit` to get the results of a search. This module
/// implements this by looking up the search in the `ManagerProxy` and copying out the matching
/// object handles.
extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    if phObject.is_null() || pulObjectCount.is_null() || ulMaxObjectCount == 0 {
        error!("C_FindObjects: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    let handles = match manager.search(hSession, ulMaxObjectCount as usize) {
        Ok(handles) => handles,
        Err(()) => {
            error!("C_FindObjects: CKR_ARGUMENTS_BAD");
            return CKR_ARGUMENTS_BAD;
        }
    };
    debug!("C_FindObjects: found handles {:?}", handles);
    if handles.len() > ulMaxObjectCount as usize {
        error!("C_FindObjects: manager returned too many handles");
        return CKR_DEVICE_ERROR;
    }
    unsafe {
        *pulObjectCount = handles.len() as CK_ULONG;
    }
    for (index, handle) in handles.iter().enumerate() {
        if index < ulMaxObjectCount as usize {
            unsafe {
                *(phObject.add(index)) = *handle;
            }
        }
    }
    debug!("C_FindObjects: CKR_OK");
    CKR_OK
}

/// This gets called after `C_FindObjectsInit` and `C_FindObjects` to finish a search. The module
/// tells the `ManagerProxy` to clear the search.
extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    // It would be an error if there were no search for this session, but we can be permissive here.
    match manager.clear_search(hSession) {
        Ok(()) => {
            debug!("C_FindObjectsFinal: CKR_OK");
            CKR_OK
        }
        Err(()) => {
            debug!("C_FindObjectsFinal: clear_search failed");
            CKR_DEVICE_ERROR
        }
    }
}

/// This gets called to set up an encrypt operation. Only RSA is supported (with PKCS#1 v1.5 or
/// OAEP padding); encryption uses the public key of the certificate associated with the given
/// object.
extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        error!("C_EncryptInit: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mechanism = unsafe { *pMechanism };
    debug!("C_EncryptInit: mechanism is {:?}", mechanism);
    let cipher_mechanism = match parse_rsa_cipher_mechanism("C_EncryptInit", &mechanism) {
        Ok(cipher_mechanism) => cipher_mechanism,
        Err(rv) => return rv,
    };
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    match manager.start_encrypt(hSession, hKey, cipher_mechanism) {
        Ok(()) => {}
        Err(err) => {
            return crypto_error_to_rv("C_EncryptInit: start_encrypt failed", &err);
        }
    };
    debug!("C_EncryptInit: CKR_OK");
    CKR_OK
}

/// NSS calls this after `C_EncryptInit`. The module essentially defers to the `ManagerProxy` and
/// copies out the resulting ciphertext.
extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!(
        "C_Encrypt: hSession {}, ulDataLen {}, pEncryptedData null? {}",
        hSession,
        ulDataLen,
        pEncryptedData.is_null()
    );
    if pData.is_null() || pulEncryptedDataLen.is_null() {
        error!("C_Encrypt: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if ulDataLen > MAX_DATA_LEN {
        error!("C_Encrypt: unreasonable data length {ulDataLen}");
        return CKR_ARGUMENTS_BAD;
    }
    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };
    // If pEncryptedData is null, the caller is asking for the length of the ciphertext.
    if pEncryptedData.is_null() {
        let mut manager_guard = try_to_get_manager_guard!();
        let manager = manager_guard_to_manager!(manager_guard);
        match manager.get_encrypted_length(hSession, data.to_vec()) {
            Ok(encrypted_length) => {
                debug!("C_Encrypt: output length = {}", encrypted_length);
                unsafe {
                    *pulEncryptedDataLen = encrypted_length as CK_ULONG;
                }
            }
            Err(err) => {
                return crypto_error_to_rv("C_Encrypt: get_encrypted_length failed", &err);
            }
        }
    } else {
        // PKCS #11 requires that CKR_BUFFER_TOO_SMALL does not terminate the active operation, so
        // the output length must be determined (and the buffer checked) before the operation that
        // consumes it runs.
        let encrypted_length = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.get_encrypted_length(hSession, data.to_vec()) {
                Ok(encrypted_length) => encrypted_length,
                Err(err) => {
                    return crypto_error_to_rv("C_Encrypt: get_encrypted_length failed", &err);
                }
            }
        };
        let encrypted_capacity = unsafe { *pulEncryptedDataLen } as usize;
        if encrypted_capacity < encrypted_length {
            unsafe {
                *pulEncryptedDataLen = encrypted_length as CK_ULONG;
            }
            error!("C_Encrypt: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        let encrypted = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.encrypt(hSession, data.to_vec()) {
                Ok(ciphertext) => ciphertext,
                Err(err) => {
                    return crypto_error_to_rv("C_Encrypt: encrypt failed", &err);
                }
            }
        };
        unsafe {
            std::ptr::copy_nonoverlapping(encrypted.as_ptr(), pEncryptedData, encrypted.len());
            *pulEncryptedDataLen = encrypted.len() as CK_ULONG;
        }
    }
    debug!("C_Encrypt: CKR_OK");
    CKR_OK
}

/// This gets called to process one part of the plaintext of an ongoing encryption operation. The
/// part is buffered; RSA encryption is performed over the complete message when the operation is
/// finished via `C_EncryptFinal`. (The "return a partial result" behaviour allowed by the PKCS #11
/// specification for streaming mechanisms does not apply here.)
extern "C" fn C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    _pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    if pulEncryptedPartLen.is_null() {
        error!("C_EncryptUpdate: null output length pointer");
        return CKR_ARGUMENTS_BAD;
    }
    if ulPartLen > MAX_DATA_LEN {
        error!("C_EncryptUpdate: unreasonable data length {ulPartLen}");
        return CKR_ARGUMENTS_BAD;
    }
    let part = match unsafe { input_slice(pPart, ulPartLen) } {
        Ok(part) => part,
        Err(rv) => {
            error!("C_EncryptUpdate: invalid part pointer/length combination");
            return rv;
        }
    };
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    match manager.encrypt_update(hSession, part.to_vec()) {
        Ok(()) => {}
        Err(err) => {
            return crypto_error_to_rv("C_EncryptUpdate: encrypt_update failed", &err);
        }
    }
    // Explicit output convention: RSA is not a streaming mechanism, so no partial output is ever
    // produced here - the complete result is delivered by `C_EncryptFinal`. Report that through
    // the standard output contract instead of leaving the caller's length slot untouched (an
    // empty result fits any buffer the caller provided, including a null one).
    unsafe { *pulEncryptedPartLen = 0 };
    debug!("C_EncryptUpdate: CKR_OK (no partial output)");
    CKR_OK
}

/// This gets called to finish an ongoing encryption operation, encrypting all of the data that has
/// been accumulated via `C_EncryptUpdate`. As with `C_Encrypt`, if `pLastEncryptedPart` is null
/// only the required output length is determined and the operation remains active.
extern "C" fn C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    if pulLastEncryptedPartLen.is_null() {
        error!("C_EncryptFinal: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if pLastEncryptedPart.is_null() {
        let mut manager_guard = try_to_get_manager_guard!();
        let manager = manager_guard_to_manager!(manager_guard);
        match manager.get_final_encrypted_length(hSession) {
            Ok(encrypted_length) => unsafe {
                *pulLastEncryptedPartLen = encrypted_length as CK_ULONG;
            },
            Err(err) => {
                return crypto_error_to_rv(
                    "C_EncryptFinal: get_final_encrypted_length failed",
                    &err,
                );
            }
        }
    } else {
        // PKCS #11 requires that CKR_BUFFER_TOO_SMALL does not terminate the active operation, so
        // the output length must be determined (and the buffer checked) before the operation that
        // consumes it runs.
        let encrypted_length = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.get_final_encrypted_length(hSession) {
                Ok(encrypted_length) => encrypted_length,
                Err(err) => {
                    return crypto_error_to_rv(
                        "C_EncryptFinal: get_final_encrypted_length failed",
                        &err,
                    );
                }
            }
        };
        let capacity = unsafe { *pulLastEncryptedPartLen } as usize;
        if capacity < encrypted_length {
            unsafe {
                *pulLastEncryptedPartLen = encrypted_length as CK_ULONG;
            }
            error!("C_EncryptFinal: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        let ciphertext = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.encrypt_final(hSession) {
                Ok(ciphertext) => ciphertext,
                Err(err) => {
                    return crypto_error_to_rv("C_EncryptFinal: encrypt_final failed", &err);
                }
            }
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                ciphertext.as_ptr(),
                pLastEncryptedPart,
                ciphertext.len(),
            );
            *pulLastEncryptedPartLen = ciphertext.len() as CK_ULONG;
        }
    }
    debug!("C_EncryptFinal: CKR_OK");
    CKR_OK
}

extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        error!("C_DecryptInit: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    let mechanism = unsafe { *pMechanism };
    debug!("C_DecryptInit: mechanism is {:?}", mechanism);
    let cipher_mechanism = match parse_rsa_cipher_mechanism("C_DecryptInit", &mechanism) {
        Ok(cipher_mechanism) => cipher_mechanism,
        Err(rv) => return rv,
    };
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    match manager.start_decrypt(hSession, hKey, cipher_mechanism) {
        Ok(()) => {}
        Err(err) => {
            return crypto_error_to_rv("C_DecryptInit: start_decrypt failed", &err);
        }
    };
    debug!("C_DecryptInit: CKR_OK");
    CKR_OK
}

/// NSS calls this after `C_DecryptInit`. The module essentially defers to the `ManagerProxy` and
/// copies out the resulting plaintext. This is the entry point for S/MIME message decryption with
/// non-exportable Windows keys.
extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    debug!(
        "C_Decrypt: hSession {}, ulEncryptedDataLen {}, pData null? {}",
        hSession,
        ulEncryptedDataLen,
        pData.is_null()
    );
    if pEncryptedData.is_null() || pulDataLen.is_null() {
        error!("C_Decrypt: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if ulEncryptedDataLen > MAX_DATA_LEN {
        error!("C_Decrypt: unreasonable data length {ulEncryptedDataLen}");
        return CKR_ARGUMENTS_BAD;
    }
    let encrypted_data =
        unsafe { std::slice::from_raw_parts(pEncryptedData, ulEncryptedDataLen as usize) };
    // If pData is null, the caller is asking for the length of the decrypted data.
    if pData.is_null() {
        let mut manager_guard = try_to_get_manager_guard!();
        let manager = manager_guard_to_manager!(manager_guard);
        match manager.get_decrypted_length(hSession, encrypted_data.to_vec()) {
            Ok(decrypted_length) => {
                debug!("C_Decrypt: output length = {}", decrypted_length);
                unsafe {
                    *pulDataLen = decrypted_length as CK_ULONG;
                }
            }
            Err(err) => {
                return crypto_error_to_rv("C_Decrypt: get_decrypted_length failed", &err);
            }
        }
    } else {
        // PKCS #11 requires that CKR_BUFFER_TOO_SMALL does not terminate the active operation, so
        // the output length must be determined (and the buffer checked) before the operation that
        // consumes it runs.
        let decrypted_length = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.get_decrypted_length(hSession, encrypted_data.to_vec()) {
                Ok(decrypted_length) => decrypted_length,
                Err(err) => {
                    return crypto_error_to_rv("C_Decrypt: get_decrypted_length failed", &err);
                }
            }
        };
        let data_capacity = unsafe { *pulDataLen } as usize;
        if data_capacity < decrypted_length {
            unsafe {
                *pulDataLen = decrypted_length as CK_ULONG;
            }
            error!("C_Decrypt: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        let decrypted = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.decrypt(hSession, encrypted_data.to_vec()) {
                Ok(plaintext) => plaintext,
                Err(err) => {
                    return crypto_error_to_rv("C_Decrypt: decrypt failed", &err);
                }
            }
        };
        unsafe {
            std::ptr::copy_nonoverlapping(decrypted.as_ptr(), pData, decrypted.len());
            *pulDataLen = decrypted.len() as CK_ULONG;
        }
    }
    debug!("C_Decrypt: CKR_OK");
    CKR_OK
}

/// This gets called to process one part of the ciphertext of an ongoing decryption operation. The
/// part is buffered; RSA decryption is performed over the complete ciphertext when the operation
/// is finished via `C_DecryptFinal`.
extern "C" fn C_DecryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    _pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    if pulPartLen.is_null() {
        error!("C_DecryptUpdate: null output length pointer");
        return CKR_ARGUMENTS_BAD;
    }
    if ulEncryptedPartLen > MAX_DATA_LEN {
        error!("C_DecryptUpdate: unreasonable data length {ulEncryptedPartLen}");
        return CKR_ARGUMENTS_BAD;
    }
    let part = match unsafe { input_slice(pEncryptedPart, ulEncryptedPartLen) } {
        Ok(part) => part,
        Err(rv) => {
            error!("C_DecryptUpdate: invalid part pointer/length combination");
            return rv;
        }
    };
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    match manager.decrypt_update(hSession, part.to_vec()) {
        Ok(()) => {}
        Err(err) => {
            return crypto_error_to_rv("C_DecryptUpdate: decrypt_update failed", &err);
        }
    }
    // See C_EncryptUpdate: zero-length partial output is reported through the caller's length
    // slot rather than implied; the complete plaintext arrives via `C_DecryptFinal`.
    unsafe { *pulPartLen = 0 };
    debug!("C_DecryptUpdate: CKR_OK (no partial output)");
    CKR_OK
}

/// This gets called to finish an ongoing decryption operation, decrypting all of the ciphertext
/// that has been accumulated via `C_DecryptUpdate`. As with `C_Decrypt`, if `pLastPart` is null
/// only the required output length is determined and the operation remains active.
extern "C" fn C_DecryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastPart: CK_BYTE_PTR,
    pulLastPartLen: CK_ULONG_PTR,
) -> CK_RV {
    if pulLastPartLen.is_null() {
        error!("C_DecryptFinal: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if pLastPart.is_null() {
        let mut manager_guard = try_to_get_manager_guard!();
        let manager = manager_guard_to_manager!(manager_guard);
        match manager.get_final_decrypted_length(hSession) {
            Ok(decrypted_length) => unsafe {
                *pulLastPartLen = decrypted_length as CK_ULONG;
            },
            Err(err) => {
                return crypto_error_to_rv(
                    "C_DecryptFinal: get_final_decrypted_length failed",
                    &err,
                );
            }
        }
    } else {
        // PKCS #11 requires that CKR_BUFFER_TOO_SMALL does not terminate the active operation, so
        // the output length must be determined (and the buffer checked) before the operation that
        // consumes it runs.
        let decrypted_length = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.get_final_decrypted_length(hSession) {
                Ok(decrypted_length) => decrypted_length,
                Err(err) => {
                    return crypto_error_to_rv(
                        "C_DecryptFinal: get_final_decrypted_length failed",
                        &err,
                    );
                }
            }
        };
        let capacity = unsafe { *pulLastPartLen } as usize;
        if capacity < decrypted_length {
            unsafe {
                *pulLastPartLen = decrypted_length as CK_ULONG;
            }
            error!("C_DecryptFinal: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        let plaintext = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.decrypt_final(hSession) {
                Ok(plaintext) => plaintext,
                Err(err) => {
                    return crypto_error_to_rv("C_DecryptFinal: decrypt_final failed", &err);
                }
            }
        };
        unsafe {
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), pLastPart, plaintext.len());
            *pulLastPartLen = plaintext.len() as CK_ULONG;
        }
    }
    debug!("C_DecryptFinal: CKR_OK");
    CKR_OK
}

extern "C" fn C_DigestInit(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR) -> CK_RV {
    error!("C_DigestInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Digest(
    _hSession: CK_SESSION_HANDLE,
    _pData: CK_BYTE_PTR,
    _ulDataLen: CK_ULONG,
    _pDigest: CK_BYTE_PTR,
    _pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_Digest: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestUpdate(
    _hSession: CK_SESSION_HANDLE,
    _pPart: CK_BYTE_PTR,
    _ulPartLen: CK_ULONG,
) -> CK_RV {
    error!("C_DigestUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestKey(_hSession: CK_SESSION_HANDLE, _hKey: CK_OBJECT_HANDLE) -> CK_RV {
    error!("C_DigestKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestFinal(
    _hSession: CK_SESSION_HANDLE,
    _pDigest: CK_BYTE_PTR,
    _pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_DigestFinal: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

/// This gets called to set up a sign operation. The module essentially defers to the
/// `ManagerProxy`.
extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        error!("C_SignInit: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    // Presumably we should validate the mechanism against hKey, but the specification doesn't
    // actually seem to require this.
    let mechanism = unsafe { *pMechanism };
    debug!("C_SignInit: mechanism is {:?}", mechanism);
    let mechanism_params = if mechanism.mechanism == CKM_RSA_PKCS_PSS {
        if mechanism.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
            error!(
                "C_SignInit: bad ulParameterLen for CKM_RSA_PKCS_PSS: {}",
                unsafe_packed_field_access!(mechanism.ulParameterLen)
            );
            return CKR_ARGUMENTS_BAD;
        }
        Some(unsafe { *(mechanism.pParameter as *const CK_RSA_PKCS_PSS_PARAMS) })
    } else {
        None
    };
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    match manager.start_sign(hSession, hKey, mechanism_params) {
        Ok(()) => {}
        Err(err) => {
            return crypto_error_to_rv("C_SignInit: start_sign failed", &err);
        }
    };
    debug!("C_SignInit: CKR_OK");
    CKR_OK
}

/// NSS calls this after `C_SignInit` to sign a message in a single part (multipart signing via
/// `C_SignUpdate`/`C_SignFinal` is also supported). The module essentially defers to the
/// `ManagerProxy` and copies out the resulting signature.
extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    if pData.is_null() || pulSignatureLen.is_null() {
        error!("C_Sign: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if ulDataLen > MAX_DATA_LEN {
        error!("C_Sign: unreasonable data length {ulDataLen}");
        return CKR_ARGUMENTS_BAD;
    }
    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };
    if pSignature.is_null() {
        let mut manager_guard = try_to_get_manager_guard!();
        let manager = manager_guard_to_manager!(manager_guard);
        match manager.get_signature_length(hSession, data.to_vec()) {
            Ok(signature_length) => unsafe {
                *pulSignatureLen = signature_length as CK_ULONG;
            },
            Err(err) => {
                return crypto_error_to_rv("C_Sign: get_signature_length failed", &err);
            }
        }
    } else {
        // PKCS #11 requires that CKR_BUFFER_TOO_SMALL does not terminate the active operation, so
        // the output length must be determined (and the buffer checked) before the operation that
        // consumes it runs.
        let signature_length = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.get_signature_length(hSession, data.to_vec()) {
                Ok(signature_length) => signature_length,
                Err(err) => {
                    return crypto_error_to_rv("C_Sign: get_signature_length failed", &err);
                }
            }
        };
        let signature_capacity = unsafe { *pulSignatureLen } as usize;
        if signature_capacity < signature_length {
            unsafe {
                *pulSignatureLen = signature_length as CK_ULONG;
            }
            error!("C_Sign: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        let signature = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.sign(hSession, data.to_vec()) {
                Ok(signature) => signature,
                Err(err) => {
                    return crypto_error_to_rv("C_Sign: sign failed", &err);
                }
            }
        };
        unsafe {
            std::ptr::copy_nonoverlapping(signature.as_ptr(), pSignature, signature.len());
            *pulSignatureLen = signature.len() as CK_ULONG;
        }
    }
    debug!("C_Sign: CKR_OK");
    CKR_OK
}

/// This gets called to process one part of the message of an ongoing signing operation. The part
/// is buffered; RSA and ECDSA signatures are computed over the complete message when the operation
/// is finished via `C_SignFinal`.
extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    if ulPartLen > MAX_DATA_LEN {
        error!("C_SignUpdate: unreasonable data length {ulPartLen}");
        return CKR_ARGUMENTS_BAD;
    }
    let part = match unsafe { input_slice(pPart, ulPartLen) } {
        Ok(part) => part,
        Err(rv) => {
            error!("C_SignUpdate: invalid part pointer/length combination");
            return rv;
        }
    };
    let mut manager_guard = try_to_get_manager_guard!();
    let manager = manager_guard_to_manager!(manager_guard);
    match manager.sign_update(hSession, part.to_vec()) {
        Ok(()) => {}
        Err(err) => {
            return crypto_error_to_rv("C_SignUpdate: sign_update failed", &err);
        }
    }
    debug!("C_SignUpdate: CKR_OK");
    CKR_OK
}

/// This gets called to finish an ongoing signing operation, computing a signature over all of the
/// message parts that have been accumulated via `C_SignUpdate`. As with `C_Sign`, if
/// `pSignature` is null only the required signature length is determined and the operation remains
/// active.
extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    if pulSignatureLen.is_null() {
        error!("C_SignFinal: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if pSignature.is_null() {
        let mut manager_guard = try_to_get_manager_guard!();
        let manager = manager_guard_to_manager!(manager_guard);
        match manager.get_final_signature_length(hSession) {
            Ok(signature_length) => unsafe {
                *pulSignatureLen = signature_length as CK_ULONG;
            },
            Err(err) => {
                return crypto_error_to_rv("C_SignFinal: get_final_signature_length failed", &err);
            }
        }
    } else {
        // PKCS #11 requires that CKR_BUFFER_TOO_SMALL does not terminate the active operation, so
        // the output length must be determined (and the buffer checked) before the operation that
        // consumes it runs.
        let signature_length = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.get_final_signature_length(hSession) {
                Ok(signature_length) => signature_length,
                Err(err) => {
                    return crypto_error_to_rv(
                        "C_SignFinal: get_final_signature_length failed",
                        &err,
                    );
                }
            }
        };
        let capacity = unsafe { *pulSignatureLen } as usize;
        if capacity < signature_length {
            unsafe {
                *pulSignatureLen = signature_length as CK_ULONG;
            }
            error!("C_SignFinal: CKR_BUFFER_TOO_SMALL");
            return CKR_BUFFER_TOO_SMALL;
        }
        let signature = {
            let mut manager_guard = try_to_get_manager_guard!();
            let manager = manager_guard_to_manager!(manager_guard);
            match manager.sign_final(hSession) {
                Ok(signature) => signature,
                Err(err) => {
                    return crypto_error_to_rv("C_SignFinal: sign_final failed", &err);
                }
            }
        };
        unsafe {
            std::ptr::copy_nonoverlapping(signature.as_ptr(), pSignature, signature.len());
            *pulSignatureLen = signature.len() as CK_ULONG;
        }
    }
    debug!("C_SignFinal: CKR_OK");
    CKR_OK
}

extern "C" fn C_SignRecoverInit(
    _hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    error!("C_SignRecoverInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SignRecover(
    _hSession: CK_SESSION_HANDLE,
    _pData: CK_BYTE_PTR,
    _ulDataLen: CK_ULONG,
    _pSignature: CK_BYTE_PTR,
    _pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_SignRecover: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyInit(
    _hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    error!("C_VerifyInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_Verify(
    _hSession: CK_SESSION_HANDLE,
    _pData: CK_BYTE_PTR,
    _ulDataLen: CK_ULONG,
    _pSignature: CK_BYTE_PTR,
    _ulSignatureLen: CK_ULONG,
) -> CK_RV {
    error!("C_Verify: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyUpdate(
    _hSession: CK_SESSION_HANDLE,
    _pPart: CK_BYTE_PTR,
    _ulPartLen: CK_ULONG,
) -> CK_RV {
    error!("C_VerifyUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyFinal(
    _hSession: CK_SESSION_HANDLE,
    _pSignature: CK_BYTE_PTR,
    _ulSignatureLen: CK_ULONG,
) -> CK_RV {
    error!("C_VerifyFinal: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyRecoverInit(
    _hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    error!("C_VerifyRecoverInit: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_VerifyRecover(
    _hSession: CK_SESSION_HANDLE,
    _pSignature: CK_BYTE_PTR,
    _ulSignatureLen: CK_ULONG,
    _pData: CK_BYTE_PTR,
    _pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_VerifyRecover: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DigestEncryptUpdate(
    _hSession: CK_SESSION_HANDLE,
    _pPart: CK_BYTE_PTR,
    _ulPartLen: CK_ULONG,
    _pEncryptedPart: CK_BYTE_PTR,
    _pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_DigestEncryptUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DecryptDigestUpdate(
    _hSession: CK_SESSION_HANDLE,
    _pEncryptedPart: CK_BYTE_PTR,
    _ulEncryptedPartLen: CK_ULONG,
    _pPart: CK_BYTE_PTR,
    _pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_DecryptDigestUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SignEncryptUpdate(
    _hSession: CK_SESSION_HANDLE,
    _pPart: CK_BYTE_PTR,
    _ulPartLen: CK_ULONG,
    _pEncryptedPart: CK_BYTE_PTR,
    _pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_SignEncryptUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DecryptVerifyUpdate(
    _hSession: CK_SESSION_HANDLE,
    _pEncryptedPart: CK_BYTE_PTR,
    _ulEncryptedPartLen: CK_ULONG,
    _pPart: CK_BYTE_PTR,
    _pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_DecryptVerifyUpdate: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GenerateKey(
    _hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG,
    _phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    error!("C_GenerateKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GenerateKeyPair(
    _hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    _ulPublicKeyAttributeCount: CK_ULONG,
    _pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    _ulPrivateKeyAttributeCount: CK_ULONG,
    _phPublicKey: CK_OBJECT_HANDLE_PTR,
    _phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    error!("C_GenerateKeyPair: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_WrapKey(
    _hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _hWrappingKey: CK_OBJECT_HANDLE,
    _hKey: CK_OBJECT_HANDLE,
    _pWrappedKey: CK_BYTE_PTR,
    _pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV {
    error!("C_WrapKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_UnwrapKey(
    _hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _hUnwrappingKey: CK_OBJECT_HANDLE,
    _pWrappedKey: CK_BYTE_PTR,
    _ulWrappedKeyLen: CK_ULONG,
    _pTemplate: CK_ATTRIBUTE_PTR,
    _ulAttributeCount: CK_ULONG,
    _phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    error!("C_UnwrapKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_DeriveKey(
    _hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _hBaseKey: CK_OBJECT_HANDLE,
    _pTemplate: CK_ATTRIBUTE_PTR,
    _ulAttributeCount: CK_ULONG,
    _phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    error!("C_DeriveKey: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SeedRandom(
    _hSession: CK_SESSION_HANDLE,
    _pSeed: CK_BYTE_PTR,
    _ulSeedLen: CK_ULONG,
) -> CK_RV {
    error!("C_SeedRandom: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GenerateRandom(
    _hSession: CK_SESSION_HANDLE,
    _RandomData: CK_BYTE_PTR,
    _ulRandomLen: CK_ULONG,
) -> CK_RV {
    error!("C_GenerateRandom: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GetFunctionStatus(_hSession: CK_SESSION_HANDLE) -> CK_RV {
    error!("C_GetFunctionStatus: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_CancelFunction(_hSession: CK_SESSION_HANDLE) -> CK_RV {
    error!("C_CancelFunction: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _pSlot: CK_SLOT_ID_PTR,
    _pRserved: CK_VOID_PTR,
) -> CK_RV {
    error!("C_WaitForSlotEvent: CKR_FUNCTION_NOT_SUPPORTED");
    CKR_FUNCTION_NOT_SUPPORTED
}

/// To be a valid PKCS #11 module, this list of functions must be supported. At least cryptoki 2.2
/// must be supported for this module to work in NSS.
static mut FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 2 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: None,
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

/// This is the only function this module exposes. NSS calls it to obtain the list of functions
/// comprising this module.
// The PKCS #11 specification requires this export to have a safe signature (NSS calls it through
// a plain function pointer type), so the pointer dereference below cannot make this function
// `unsafe`.
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if ppFunctionList.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *ppFunctionList = std::ptr::addr_of_mut!(FUNCTION_LIST);
    }
    CKR_OK
}

#[cfg_attr(target_os = "macos", link(name = "Security", kind = "framework"))]
unsafe extern "C" {}

/// Test-only support shared by every test module that drives the exported PKCS #11 functions.
/// Initialization lives here so that exactly one `C_Initialize` happens per test process no matter
/// how many test modules (or platforms) run.
#[cfg(test)]
mod ffi_test_support {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub(crate) fn ensure_initialized() {
        INIT.call_once(|| {
            assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
        });
    }

    pub(crate) fn open_session() -> CK_SESSION_HANDLE {
        ensure_initialized();
        let mut session: CK_SESSION_HANDLE = 0;
        assert_eq!(
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session
            ),
            CKR_OK
        );
        session
    }
}

// These tests exercise the stub backend semantics (deterministic key discovery and
// cipher outputs), which only exists on platforms without a real backend.
#[cfg(all(test, not(any(target_os = "macos", target_os = "windows"))))]
mod tests {
    use super::*;
    use crate::ffi_test_support::open_session;

    #[test]
    fn get_session_info_reports_flags_state_and_slot() {
        let mut info = CK_SESSION_INFO {
            slotID: 0,
            state: 0,
            flags: 0,
            ulDeviceError: 99,
        };
        let rw_session = open_session();
        assert_eq!(C_GetSessionInfo(rw_session, &mut info), CKR_OK);
        assert_eq!(info.slotID, SLOT_ID);
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);
        assert_eq!(info.flags, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        assert_eq!(info.ulDeviceError, 0);

        let mut ro_session: CK_SESSION_HANDLE = 0;
        assert_eq!(
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &mut ro_session
            ),
            CKR_OK
        );
        assert_eq!(C_GetSessionInfo(ro_session, &mut info), CKR_OK);
        assert_eq!(info.state, CKS_RO_PUBLIC_SESSION);
        assert_eq!(info.flags, CKF_SERIAL_SESSION);
        assert_eq!(info.ulDeviceError, 0);

        assert_eq!(C_CloseSession(ro_session), CKR_OK);
        assert_eq!(
            C_GetSessionInfo(ro_session, &mut info),
            CKR_SESSION_HANDLE_INVALID
        );
        assert_eq!(
            C_GetSessionInfo(rw_session, std::ptr::null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(C_CloseSession(rw_session), CKR_OK);
    }

    #[test]
    fn open_session_requires_serial_flag() {
        let mut session: CK_SESSION_HANDLE = 0;
        assert_eq!(
            C_OpenSession(
                SLOT_ID,
                CKF_RW_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session
            ),
            CKR_ARGUMENTS_BAD
        );
    }
    use crate::util::MAX_TOTAL_OPERATION_DATA_LEN;
    use crate::util::serialize_uint;

    fn find_key(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
        let class_value = serialize_uint(CKO_PRIVATE_KEY).unwrap();
        let mut template = [CK_ATTRIBUTE {
            attrType: CKA_CLASS,
            pValue: class_value.as_ptr() as CK_VOID_PTR,
            ulValueLen: class_value.len() as CK_ULONG,
        }];
        assert_eq!(C_FindObjectsInit(session, template.as_mut_ptr(), 1), CKR_OK);
        let mut handles = [0u64; 4];
        let mut count: CK_ULONG = 0;
        assert_eq!(
            C_FindObjects(session, handles.as_mut_ptr(), 4, &mut count),
            CKR_OK
        );
        assert_eq!(count, 1);
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        handles[0]
    }

    fn pkcs1_mechanism() -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    fn oaep_mechanism(hash_alg: CK_MECHANISM_TYPE, mgf: CK_RSA_PKCS_MGF_TYPE) -> CK_MECHANISM {
        let label = b"test-label".to_vec();
        let params = Box::new(CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: hash_alg,
            mgf,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: label.as_ptr() as CK_VOID_PTR,
            ulSourceDataLen: label.len() as CK_ULONG,
        });
        // Leak is intentional for test brevity; the pointer must stay valid for the Init call.
        let params_ptr = Box::into_raw(params);
        std::mem::forget(label);
        CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: params_ptr as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        }
    }

    #[test]
    fn mechanism_info_rsa_pkcs() {
        let mut info = CK_MECHANISM_INFO::default();
        assert_eq!(C_GetMechanismInfo(SLOT_ID, CKM_RSA_PKCS, &mut info), CKR_OK);
        assert_eq!(
            unsafe_packed_field_access!(info.flags),
            CKF_SIGN | CKF_DECRYPT | CKF_ENCRYPT
        );
        assert_eq!(unsafe_packed_field_access!(info.ulMinKeySize), 1024);
        assert_eq!(unsafe_packed_field_access!(info.ulMaxKeySize), 16384);
    }

    #[test]
    fn mechanism_info_rsa_oaep() {
        let mut info = CK_MECHANISM_INFO::default();
        assert_eq!(
            C_GetMechanismInfo(SLOT_ID, CKM_RSA_PKCS_OAEP, &mut info),
            CKR_OK
        );
        assert_eq!(
            unsafe_packed_field_access!(info.flags),
            CKF_ENCRYPT | CKF_DECRYPT
        );
        assert_eq!(unsafe_packed_field_access!(info.ulMinKeySize), 1024);
        assert_eq!(unsafe_packed_field_access!(info.ulMaxKeySize), 16384);
    }

    #[test]
    fn mechanism_info_unsupported_mechanism_rejected() {
        let mut info = CK_MECHANISM_INFO::default();
        assert_eq!(
            C_GetMechanismInfo(SLOT_ID, CKM_SHA256, &mut info),
            CKR_MECHANISM_INVALID
        );
    }

    #[test]
    fn decrypt_init_accepts_oaep_and_rejects_bad_mgf() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(
            C_DecryptInit(
                session,
                &mut oaep_mechanism(CKM_SHA256, CKG_MGF1_SHA256),
                key
            ),
            CKR_OK
        );
        // The successful init above started an operation on this session; use a fresh one.
        let session = open_session();
        assert_eq!(
            C_DecryptInit(session, &mut oaep_mechanism(CKM_SHA256, CKG_MGF1_SHA1), key),
            CKR_MECHANISM_INVALID
        );
    }

    #[test]
    fn buffer_too_small_preserves_decrypt_operation() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_DecryptInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        // Inputs shorter than the stub threshold make length queries fail with
        // CKR_BUFFER_TOO_SMALL; this must not terminate the operation.
        let mut short_input = [0xEE_u8; 32];
        let mut out_len: CK_ULONG = 0;
        assert_eq!(
            C_Decrypt(
                session,
                short_input.as_mut_ptr(),
                short_input.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut out_len
            ),
            CKR_BUFFER_TOO_SMALL
        );
        let mut small_out = [0u8; 16];
        let mut out_len: CK_ULONG = small_out.len() as CK_ULONG;
        assert_eq!(
            C_Decrypt(
                session,
                short_input.as_mut_ptr(),
                short_input.len() as CK_ULONG,
                small_out.as_mut_ptr(),
                &mut out_len
            ),
            CKR_BUFFER_TOO_SMALL
        );
        // The operation is still active: a well-formed request now succeeds.
        let mut long_input = [0x5A_u8; 128];
        let mut big_out = [0u8; 256];
        let mut out_len: CK_ULONG = big_out.len() as CK_ULONG;
        assert_eq!(
            C_Decrypt(
                session,
                long_input.as_mut_ptr(),
                long_input.len() as CK_ULONG,
                big_out.as_mut_ptr(),
                &mut out_len
            ),
            CKR_OK
        );
        assert_eq!(out_len, 128);
        assert!(big_out[..128].iter().all(|&b| b == 0xAB));
        // A successful C_Decrypt consumes the operation; another attempt fails.
        let mut out_len: CK_ULONG = big_out.len() as CK_ULONG;
        assert_eq!(
            C_Decrypt(
                session,
                long_input.as_mut_ptr(),
                long_input.len() as CK_ULONG,
                big_out.as_mut_ptr(),
                &mut out_len
            ),
            CKR_FUNCTION_FAILED
        );
    }

    #[test]
    fn buffer_too_small_preserves_encrypt_operation() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_EncryptInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        let mut short_input = [0xEE_u8; 32];
        let mut out_len: CK_ULONG = 0;
        assert_eq!(
            C_Encrypt(
                session,
                short_input.as_mut_ptr(),
                short_input.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut out_len
            ),
            CKR_BUFFER_TOO_SMALL
        );
        let mut long_input = [0x5A_u8; 128];
        let mut big_out = [0u8; 256];
        let mut out_len: CK_ULONG = big_out.len() as CK_ULONG;
        assert_eq!(
            C_Encrypt(
                session,
                long_input.as_mut_ptr(),
                long_input.len() as CK_ULONG,
                big_out.as_mut_ptr(),
                &mut out_len
            ),
            CKR_OK
        );
        assert_eq!(out_len, 128);
        assert!(big_out[..128].iter().all(|&b| b == 0xCD));
    }

    #[test]
    fn close_session_clears_decrypt_operation() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_DecryptInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        assert_eq!(C_CloseSession(session), CKR_OK);
        let mut long_input = [0x5A_u8; 128];
        let mut big_out = [0u8; 256];
        let mut out_len: CK_ULONG = big_out.len() as CK_ULONG;
        assert_eq!(
            C_Decrypt(
                session,
                long_input.as_mut_ptr(),
                long_input.len() as CK_ULONG,
                big_out.as_mut_ptr(),
                &mut out_len
            ),
            CKR_FUNCTION_FAILED
        );
    }

    #[test]
    fn close_session_clears_encrypt_operation() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_EncryptInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        assert_eq!(C_CloseSession(session), CKR_OK);
        let mut long_input = [0x5A_u8; 128];
        let mut big_out = [0u8; 256];
        let mut out_len: CK_ULONG = big_out.len() as CK_ULONG;
        assert_eq!(
            C_Encrypt(
                session,
                long_input.as_mut_ptr(),
                long_input.len() as CK_ULONG,
                big_out.as_mut_ptr(),
                &mut out_len
            ),
            CKR_FUNCTION_FAILED
        );
    }

    #[test]
    fn sign_multipart_matches_single_shot() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_SignInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        let part1 = b"hello ";
        let part2 = b"world";
        assert_eq!(
            C_SignUpdate(
                session,
                part1.as_ptr() as CK_BYTE_PTR,
                part1.len() as CK_ULONG
            ),
            CKR_OK
        );
        assert_eq!(
            C_SignUpdate(
                session,
                part2.as_ptr() as CK_BYTE_PTR,
                part2.len() as CK_ULONG
            ),
            CKR_OK
        );
        // A length query must not consume the operation.
        let mut sig_len: CK_ULONG = 0;
        assert_eq!(
            C_SignFinal(session, std::ptr::null_mut(), &mut sig_len),
            CKR_OK
        );
        assert!(sig_len > 0);
        let mut signature_multipart = [0u8; 256];
        let mut multipart_len = signature_multipart.len() as CK_ULONG;
        assert_eq!(
            C_SignFinal(
                session,
                signature_multipart.as_mut_ptr(),
                &mut multipart_len
            ),
            CKR_OK
        );

        let whole = b"hello world";
        let session_b = open_session();
        assert_eq!(C_SignInit(session_b, &mut pkcs1_mechanism(), key), CKR_OK);
        let mut signature_single = [0u8; 256];
        let mut single_len = signature_single.len() as CK_ULONG;
        assert_eq!(
            C_Sign(
                session_b,
                whole.as_ptr() as CK_BYTE_PTR,
                whole.len() as CK_ULONG,
                signature_single.as_mut_ptr(),
                &mut single_len
            ),
            CKR_OK
        );
        assert_eq!(multipart_len, single_len);
        assert_eq!(
            &signature_multipart[..multipart_len as usize],
            &signature_single[..single_len as usize]
        );
    }

    #[test]
    fn sign_final_buffer_too_small_keeps_operation() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_SignInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        let message = b"multipart buffer-too-small";
        assert_eq!(
            C_SignUpdate(
                session,
                message.as_ptr() as CK_BYTE_PTR,
                message.len() as CK_ULONG
            ),
            CKR_OK
        );
        let mut required: CK_ULONG = 0;
        assert_eq!(
            C_SignFinal(session, std::ptr::null_mut(), &mut required),
            CKR_OK
        );
        assert!(required > 1);
        let mut small_out = vec![0u8; (required - 1) as usize];
        let mut out_len = small_out.len() as CK_ULONG;
        assert_eq!(
            C_SignFinal(session, small_out.as_mut_ptr(), &mut out_len),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(out_len, required);
        // The operation is still active: a well-formed request now succeeds.
        let mut full_out = vec![0u8; required as usize];
        let mut out_len = full_out.len() as CK_ULONG;
        assert_eq!(
            C_SignFinal(session, full_out.as_mut_ptr(), &mut out_len),
            CKR_OK
        );
        assert_eq!(out_len, required);
    }

    #[test]
    fn close_session_clears_pending_sign_operation() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_SignInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        let message = b"will be abandoned";
        assert_eq!(
            C_SignUpdate(
                session,
                message.as_ptr() as CK_BYTE_PTR,
                message.len() as CK_ULONG
            ),
            CKR_OK
        );
        assert_eq!(C_CloseSession(session), CKR_OK);
        // The old session handle is gone, so finishing the operation must fail.
        let mut sig_len: CK_ULONG = 0;
        assert_ne!(
            C_SignFinal(session, std::ptr::null_mut(), &mut sig_len),
            CKR_OK
        );
    }

    #[test]
    fn encrypt_decrypt_multipart_matches_single_shot() {
        let plaintext = [0x42_u8; 100];
        let session_a = open_session();
        let key = find_key(session_a);
        assert_eq!(
            C_EncryptInit(session_a, &mut pkcs1_mechanism(), key),
            CKR_OK
        );
        let (p1, p2) = plaintext.split_at(37);
        let mut partial_len: CK_ULONG = 0;
        assert_eq!(
            C_EncryptUpdate(
                session_a,
                p1.as_ptr() as CK_BYTE_PTR,
                p1.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_OK
        );
        assert_eq!(partial_len, 0);
        assert_eq!(
            C_EncryptUpdate(
                session_a,
                p2.as_ptr() as CK_BYTE_PTR,
                p2.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_OK
        );
        assert_eq!(partial_len, 0);
        let mut ct_len: CK_ULONG = 0;
        assert_eq!(
            C_EncryptFinal(session_a, std::ptr::null_mut(), &mut ct_len),
            CKR_OK
        );
        let mut ciphertext_multipart = vec![0u8; ct_len as usize];
        let mut out_len = ciphertext_multipart.len() as CK_ULONG;
        assert_eq!(
            C_EncryptFinal(session_a, ciphertext_multipart.as_mut_ptr(), &mut out_len),
            CKR_OK
        );

        let session_b = open_session();
        assert_eq!(
            C_EncryptInit(session_b, &mut pkcs1_mechanism(), key),
            CKR_OK
        );
        let mut single_ct_len: CK_ULONG = 0;
        assert_eq!(
            C_Encrypt(
                session_b,
                plaintext.as_ptr() as CK_BYTE_PTR,
                plaintext.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut single_ct_len
            ),
            CKR_OK
        );
        let mut ciphertext_single = vec![0u8; single_ct_len as usize];
        assert_eq!(
            C_Encrypt(
                session_b,
                plaintext.as_ptr() as CK_BYTE_PTR,
                plaintext.len() as CK_ULONG,
                ciphertext_single.as_mut_ptr(),
                &mut single_ct_len
            ),
            CKR_OK
        );
        assert_eq!(out_len, single_ct_len);
        assert_eq!(
            &ciphertext_multipart[..out_len as usize],
            &ciphertext_single[..single_ct_len as usize]
        );

        // Decrypt the multipart-produced ciphertext via multipart updates.
        let session_c = open_session();
        assert_eq!(
            C_DecryptInit(session_c, &mut pkcs1_mechanism(), key),
            CKR_OK
        );
        let mut partial_len: CK_ULONG = 0;
        let half = out_len as usize / 2;
        let (c1, c2) = ciphertext_multipart[..half].split_at(half / 2);
        assert_eq!(
            C_DecryptUpdate(
                session_c,
                c1.as_ptr() as CK_BYTE_PTR,
                c1.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_OK
        );
        assert_eq!(partial_len, 0);
        assert_eq!(
            C_DecryptUpdate(
                session_c,
                c2.as_ptr() as CK_BYTE_PTR,
                c2.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_OK
        );
        assert_eq!(partial_len, 0);
        let remainder = &ciphertext_multipart[half..];
        // The output buffer itself may be null because no partial output is ever produced.
        assert_eq!(
            C_DecryptUpdate(
                session_c,
                remainder.as_ptr() as CK_BYTE_PTR,
                remainder.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_OK
        );
        assert_eq!(partial_len, 0);
        let mut pt_len: CK_ULONG = 0;
        assert_eq!(
            C_DecryptFinal(session_c, std::ptr::null_mut(), &mut pt_len),
            CKR_OK
        );
        let mut decrypted = vec![0u8; pt_len as usize];
        let mut final_pt_len = decrypted.len() as CK_ULONG;
        assert_eq!(
            C_DecryptFinal(session_c, decrypted.as_mut_ptr(), &mut final_pt_len),
            CKR_OK
        );
        // The stub backend decrypts to a fixed pattern; what matters is that the multipart result
        // equals the single-shot result over the same ciphertext.
        let session_d = open_session();
        assert_eq!(
            C_DecryptInit(session_d, &mut pkcs1_mechanism(), key),
            CKR_OK
        );
        let mut single_pt_len: CK_ULONG = 0;
        assert_eq!(
            C_Decrypt(
                session_d,
                ciphertext_multipart.as_ptr() as CK_BYTE_PTR,
                ciphertext_multipart.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut single_pt_len
            ),
            CKR_OK
        );
        let mut decrypted_single = vec![0u8; single_pt_len as usize];
        assert_eq!(
            C_Decrypt(
                session_d,
                ciphertext_multipart.as_ptr() as CK_BYTE_PTR,
                ciphertext_multipart.len() as CK_ULONG,
                decrypted_single.as_mut_ptr(),
                &mut single_pt_len
            ),
            CKR_OK
        );
        assert_eq!(final_pt_len, single_pt_len);
        assert_eq!(
            &decrypted[..final_pt_len as usize],
            &decrypted_single[..single_pt_len as usize]
        );
    }

    #[test]
    fn multipart_update_without_active_operation_fails() {
        let session = open_session();
        let data = [0u8; 4];
        assert_eq!(
            C_SignUpdate(session, data.as_ptr() as CK_BYTE_PTR, 4),
            CKR_FUNCTION_FAILED
        );
        let mut partial_len: CK_ULONG = 0xdead_beef;
        assert_eq!(
            C_EncryptUpdate(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                4,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_FUNCTION_FAILED
        );
        // A failed update must leave the caller's length slot untouched.
        assert_eq!(partial_len, 0xdead_beef);
        assert_eq!(
            C_DecryptUpdate(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                4,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_FUNCTION_FAILED
        );
        assert_eq!(partial_len, 0xdead_beef);
    }

    /// The output length pointer is mandatory: without it the caller could never learn how many
    /// bytes of partial output were produced (always zero here). Rejection happens before any
    /// operation-state access, so it does not depend on an active operation existing.
    #[test]
    fn encrypt_decrypt_update_reject_null_output_length_pointer() {
        let data = [0u8; 4];
        assert_eq!(
            C_EncryptUpdate(
                1,
                data.as_ptr() as CK_BYTE_PTR,
                4,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            C_DecryptUpdate(
                1,
                data.as_ptr() as CK_BYTE_PTR,
                4,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            CKR_ARGUMENTS_BAD
        );
    }

    /// Successful updates report "no partial output" by storing zero into the caller's length
    /// slot, and accept any output buffer including a null one.
    #[test]
    fn successful_updates_report_zero_partial_output_length() {
        let plaintext = [0x11_u8; 32];
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_EncryptInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        let mut partial_len: CK_ULONG = 0xdead_beef;
        // Null output buffer is fine - no partial output is produced.
        assert_eq!(
            C_EncryptUpdate(
                session,
                plaintext.as_ptr() as CK_BYTE_PTR,
                plaintext.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_OK
        );
        assert_eq!(partial_len, 0);
        // A non-null buffer of any size is equally fine and stays untouched.
        let mut tiny_out = [0u8; 1];
        partial_len = tiny_out.len() as CK_ULONG;
        assert_eq!(
            C_EncryptUpdate(
                session,
                plaintext.as_ptr() as CK_BYTE_PTR,
                plaintext.len() as CK_ULONG,
                tiny_out.as_mut_ptr(),
                &mut partial_len
            ),
            CKR_OK
        );
        assert_eq!(partial_len, 0);
        assert_eq!(
            C_EncryptFinal(session, std::ptr::null_mut(), &mut partial_len),
            CKR_OK
        );

        let ciphertext = [0x22_u8; 128];
        let session_d = open_session();
        assert_eq!(
            C_DecryptInit(session_d, &mut pkcs1_mechanism(), key),
            CKR_OK
        );
        let mut out = [0u8; 8];
        partial_len = out.len() as CK_ULONG;
        assert_eq!(
            C_DecryptUpdate(
                session_d,
                ciphertext.as_ptr() as CK_BYTE_PTR,
                ciphertext.len() as CK_ULONG,
                out.as_mut_ptr(),
                &mut partial_len
            ),
            CKR_OK
        );
        assert_eq!(partial_len, 0);
    }

    #[test]
    fn multipart_accumulated_data_overflow_rejected() {
        let session = open_session();
        let key = find_key(session);
        assert_eq!(C_SignInit(session, &mut pkcs1_mechanism(), key), CKR_OK);
        let chunk = vec![0u8; MAX_TOTAL_OPERATION_DATA_LEN];
        assert_eq!(
            C_SignUpdate(
                session,
                chunk.as_ptr() as CK_BYTE_PTR,
                chunk.len() as CK_ULONG
            ),
            CKR_OK
        );
        let one_more = [0u8; 1];
        assert_eq!(
            C_SignUpdate(session, one_more.as_ptr() as CK_BYTE_PTR, 1),
            CKR_DATA_LEN_RANGE
        );
    }
}

/// Hostile-input tests for the C ABI boundary. These exercise the argument validation of the
/// exported functions directly with values a buggy or malicious caller could pass: null/absurd
/// template pointers and counts, inconsistent `pValue`/`ulValueLen` pairs, oversized mechanism
/// parameters, and oversized data buffers. The guards under test deliberately run before any
/// dereference, so every assertion here must return an error code rather than crash. These tests
/// are platform-neutral (they do not depend on backend semantics) and run everywhere.
#[cfg(test)]
mod ffi_hardening_tests {
    use super::*;
    use crate::ffi_test_support::open_session;

    /// Verifies the full module lifecycle in an isolated subprocess (so it cannot interfere with
    /// other tests sharing this process's manager): double initialization is rejected, finalize
    /// really empties the manager slot, finalizing twice fails, and the module can be
    /// re-initialized cleanly afterwards.
    #[test]
    fn initialize_finalize_lifecycle() {
        if std::env::var("OSCLIENTCERTS_LIFECYCLE_CHILD").is_ok() {
            // Child branch: fresh process, nothing has been initialized yet.
            assert_eq!(
                C_Finalize(std::ptr::null_mut()),
                CKR_CRYPTOKI_NOT_INITIALIZED
            );
            assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
            assert_eq!(
                C_Initialize(std::ptr::null_mut()),
                CKR_CRYPTOKI_ALREADY_INITIALIZED
            );
            let mut session: CK_SESSION_HANDLE = 0;
            assert_eq!(
                C_OpenSession(
                    SLOT_ID,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    std::ptr::null_mut(),
                    None,
                    &mut session
                ),
                CKR_OK
            );
            assert_eq!(C_CloseSession(session), CKR_OK);
            assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
            assert_eq!(
                C_Finalize(std::ptr::null_mut()),
                CKR_CRYPTOKI_NOT_INITIALIZED
            );
            assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
            return;
        }
        let exe = std::env::current_exe().expect("cannot locate test executable");
        let status = std::process::Command::new(exe)
            .args(["initialize_finalize_lifecycle", "--nocapture"])
            .env("OSCLIENTCERTS_LIFECYCLE_CHILD", "1")
            .status()
            .expect("cannot spawn lifecycle subprocess");
        assert!(status.success(), "lifecycle subprocess failed: {status}");
    }

    fn dummy_template() -> [CK_ATTRIBUTE; 1] {
        [CK_ATTRIBUTE {
            attrType: CKA_CLASS,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }]
    }

    #[test]
    fn get_attribute_value_rejects_null_template() {
        assert_eq!(
            C_GetAttributeValue(1, 2, std::ptr::null_mut(), 1),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn get_attribute_value_rejects_huge_count() {
        let template = dummy_template();
        assert_eq!(
            C_GetAttributeValue(1, 2, template.as_ptr() as CK_ATTRIBUTE_PTR, CK_ULONG::MAX),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn find_objects_init_rejects_null_template() {
        assert_eq!(
            C_FindObjectsInit(1, std::ptr::null_mut(), 1),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn find_objects_init_rejects_huge_count() {
        let mut template = dummy_template();
        assert_eq!(
            C_FindObjectsInit(1, template.as_mut_ptr(), CK_ULONG::MAX),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn find_objects_init_rejects_null_value_with_nonzero_length() {
        let mut template = dummy_template();
        template[0].ulValueLen = 4;
        assert_eq!(
            C_FindObjectsInit(1, template.as_mut_ptr(), 1),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn find_objects_init_rejects_huge_value_length() {
        let backing = [0u8; 4];
        let mut template = dummy_template();
        template[0].pValue = backing.as_ptr() as CK_VOID_PTR;
        template[0].ulValueLen = CK_ULONG::MAX;
        assert_eq!(
            C_FindObjectsInit(1, template.as_mut_ptr(), 1),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn sign_rejects_huge_data_length() {
        let input = [0u8; 8];
        let mut sig_len: CK_ULONG = 0;
        assert_eq!(
            C_Sign(
                1,
                input.as_ptr() as CK_BYTE_PTR,
                CK_ULONG::MAX,
                std::ptr::null_mut(),
                &mut sig_len
            ),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn encrypt_rejects_huge_data_length() {
        let input = [0u8; 8];
        let mut out_len: CK_ULONG = 0;
        assert_eq!(
            C_Encrypt(
                1,
                input.as_ptr() as CK_BYTE_PTR,
                CK_ULONG::MAX,
                std::ptr::null_mut(),
                &mut out_len
            ),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn decrypt_rejects_huge_encrypted_data_length() {
        let input = [0u8; 8];
        let mut out_len: CK_ULONG = 0;
        assert_eq!(
            C_Decrypt(
                1,
                input.as_ptr() as CK_BYTE_PTR,
                CK_ULONG::MAX,
                std::ptr::null_mut(),
                &mut out_len
            ),
            CKR_ARGUMENTS_BAD
        );
    }

    /// A zero-count search template is legal (it matches every object) and must leave the session
    /// in a usable state afterwards.
    #[test]
    fn find_objects_init_accepts_zero_count() {
        let session = open_session();
        // The template pointer is never dereferenced for a zero-count search, but it must still
        // be non-null (and aligned), so point it at a dummy attribute.
        let mut template = dummy_template();
        assert_eq!(C_FindObjectsInit(session, template.as_mut_ptr(), 0), CKR_OK);
        let mut handles = [0 as CK_OBJECT_HANDLE; 16];
        let mut count: CK_ULONG = 0;
        assert_eq!(
            C_FindObjects(session, handles.as_mut_ptr(), 16, &mut count),
            CKR_OK
        );
        assert!((count as usize) <= handles.len());
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        assert_eq!(C_CloseSession(session), CKR_OK);
    }

    /// Unsupported attribute types and duplicate entries in a search template must be handled
    /// gracefully (empty results), not rejected or crashed on.
    #[test]
    fn find_objects_init_handles_unsupported_and_duplicate_attributes() {
        let value = [1u8, 2, 3, 4];
        let make_attr = || CK_ATTRIBUTE {
            attrType: CKA_CERTIFICATE_TYPE,
            pValue: value.as_ptr() as CK_VOID_PTR,
            ulValueLen: value.len() as CK_ULONG,
        };
        let mut template = [make_attr(), make_attr()];
        let session = open_session();
        assert_eq!(C_FindObjectsInit(session, template.as_mut_ptr(), 2), CKR_OK);
        let mut handles = [0 as CK_OBJECT_HANDLE; 16];
        let mut count: CK_ULONG = 0;
        assert_eq!(
            C_FindObjects(session, handles.as_mut_ptr(), 16, &mut count),
            CKR_OK
        );
        assert_eq!(count, 0);
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        assert_eq!(C_CloseSession(session), CKR_OK);
    }

    /// A search-template attribute with a null value pointer and zero length is a valid
    /// empty-value attribute and must not be rejected.
    #[test]
    fn find_objects_init_accepts_null_zero_length_attribute_value() {
        let mut template = [CK_ATTRIBUTE {
            attrType: CKA_ID,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];
        let session = open_session();
        assert_eq!(C_FindObjectsInit(session, template.as_mut_ptr(), 1), CKR_OK);
        let mut handles = [0 as CK_OBJECT_HANDLE; 16];
        let mut count: CK_ULONG = 0;
        assert_eq!(
            C_FindObjects(session, handles.as_mut_ptr(), 16, &mut count),
            CKR_OK
        );
        assert!((count as usize) <= handles.len());
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        assert_eq!(C_CloseSession(session), CKR_OK);
    }

    #[test]
    fn sign_update_rejects_null_part_with_nonzero_length() {
        assert_eq!(C_SignUpdate(1, std::ptr::null_mut(), 4), CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn sign_update_rejects_huge_part_length() {
        let backing = [0u8; 4];
        assert_eq!(
            C_SignUpdate(1, backing.as_ptr() as CK_BYTE_PTR, CK_ULONG::MAX),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn encrypt_update_rejects_null_part_with_nonzero_length() {
        let mut partial_len: CK_ULONG = 0;
        assert_eq!(
            C_EncryptUpdate(
                1,
                std::ptr::null_mut(),
                4,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn encrypt_update_rejects_huge_part_length() {
        let backing = [0u8; 4];
        let mut partial_len: CK_ULONG = 0;
        assert_eq!(
            C_EncryptUpdate(
                1,
                backing.as_ptr() as CK_BYTE_PTR,
                CK_ULONG::MAX,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    fn decrypt_update_rejects_null_part_with_nonzero_length() {
        let mut partial_len: CK_ULONG = 0;
        assert_eq!(
            C_DecryptUpdate(
                1,
                std::ptr::null_mut(),
                4,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_ARGUMENTS_BAD
        );
    }

    /// A null pointer with a zero length is a valid empty part: it must pass argument validation
    /// (and then fail later, since no operation is active on session 1) instead of being rejected
    /// as malformed or invoking undefined behavior in slice creation.
    #[test]
    fn update_accepts_null_zero_length_parts() {
        assert_eq!(
            C_SignUpdate(1, std::ptr::null_mut(), 0),
            CKR_FUNCTION_FAILED
        );
        let mut partial_len: CK_ULONG = 0;
        assert_eq!(
            C_EncryptUpdate(
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_FUNCTION_FAILED
        );
        assert_eq!(
            C_DecryptUpdate(
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_FUNCTION_FAILED
        );
    }

    #[test]
    fn decrypt_update_rejects_huge_part_length() {
        let backing = [0u8; 4];
        let mut partial_len: CK_ULONG = 0;
        assert_eq!(
            C_DecryptUpdate(
                1,
                backing.as_ptr() as CK_BYTE_PTR,
                CK_ULONG::MAX,
                std::ptr::null_mut(),
                &mut partial_len
            ),
            CKR_ARGUMENTS_BAD
        );
    }
}
