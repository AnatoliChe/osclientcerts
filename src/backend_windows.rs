/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(non_camel_case_types)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use pkcs11::types::*;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::ops::Deref;
use std::slice;
use winapi::shared::bcrypt::*;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::ncrypt::*;
use winapi::um::wincrypt::*;

use crate::util::*;

/// Given a `CERT_INFO`, tries to return the bytes of the subject distinguished name as formatted by
/// `CertNameToStrA` using the flag `CERT_SIMPLE_NAME_STR`. This is used as the label for the
/// certificate.
fn get_cert_subject_dn(cert_info: &CERT_INFO) -> Result<Vec<u8>, ()> {
    let mut cert_info_subject = cert_info.Subject;
    let subject_dn_len = unsafe {
        CertNameToStrA(
            X509_ASN_ENCODING,
            &mut cert_info_subject,
            CERT_SIMPLE_NAME_STR,
            std::ptr::null_mut(),
            0,
        )
    };
    // subject_dn_len includes the terminating null byte.
    let mut subject_dn_string_bytes: Vec<u8> = vec![0; subject_dn_len as usize];
    let subject_dn_len = unsafe {
        CertNameToStrA(
            X509_ASN_ENCODING,
            &mut cert_info_subject,
            CERT_SIMPLE_NAME_STR,
            subject_dn_string_bytes.as_mut_ptr() as *mut i8,
            subject_dn_string_bytes.len().try_into().map_err(|_| ())?,
        )
    };
    if subject_dn_len as usize != subject_dn_string_bytes.len() {
        return Err(());
    }
    Ok(subject_dn_string_bytes)
}

/// Represents a certificate for which there exists a corresponding private key.
pub struct Cert {
    /// PKCS #11 object class. Will be `CKO_CERTIFICATE`.
    class: Vec<u8>,
    /// Whether or not this is on a token. Will be `CK_TRUE`.
    token: Vec<u8>,
    /// An identifier unique to this certificate. Must be the same as the ID for the private key.
    id: Vec<u8>,
    /// The bytes of a human-readable label for this certificate. Will be the subject DN.
    label: Vec<u8>,
    /// The DER bytes of the certificate.
    value: Vec<u8>,
    /// The DER bytes of the issuer distinguished name of the certificate.
    issuer: Vec<u8>,
    /// The DER bytes of the serial number of the certificate.
    serial_number: Vec<u8>,
    /// The DER bytes of the subject distinguished name of the certificate.
    subject: Vec<u8>,
}

/// Compares a stored boolean attribute (always one byte, per CK_BBOOL) against the value requested
/// in a search template. Callers normally send CK_BBOOL (one byte); be lenient and also accept a
/// native-endian CK_ULONG (four bytes).
fn bool_attr_matches(stored: &[u8], requested: &[u8]) -> bool {
    let stored_bool = match stored {
        [b] => *b != 0,
        _ => return false,
    };
    let requested_bool = match requested {
        [b] => *b != 0,
        [a, b, c, d] => u32::from_ne_bytes([*a, *b, *c, *d]) != 0,
        _ => return false,
    };
    stored_bool == requested_bool
}

/// Compares the stored certificate serial number (the raw big-endian integer content bytes) against
/// the value requested in a search template. Callers send either the bare integer content or the
/// full DER TLV encoding of the INTEGER; accept both.
fn serial_number_matches(stored: &[u8], requested: &[u8]) -> bool {
    if requested == stored {
        return true;
    }
    requested.len() == stored.len() + 2
        && requested[0] == 0x02
        && requested[1] as usize == stored.len()
        && &requested[2..] == stored
}

impl Cert {
    fn new(cert: PCCERT_CONTEXT) -> Result<Cert, ()> {
        let cert = unsafe { &*cert };
        let cert_info = unsafe { &*cert.pCertInfo };
        let value =
            unsafe { slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize) };
        let value = value.to_vec();
        let id = Sha256::digest(&value).to_vec();
        let label = get_cert_subject_dn(&cert_info)?;
        let issuer = unsafe {
            slice::from_raw_parts(cert_info.Issuer.pbData, cert_info.Issuer.cbData as usize)
        };
        let issuer = issuer.to_vec();
        let serial_number = unsafe {
            slice::from_raw_parts(
                cert_info.SerialNumber.pbData,
                cert_info.SerialNumber.cbData as usize,
            )
        };
        // Windows reports the serial number least-significant-byte first; store the big-endian
        // integer content bytes (the form used in DER and by NSS search templates).
        let mut serial_number = serial_number.to_vec();
        serial_number.reverse();
        let subject = unsafe {
            slice::from_raw_parts(cert_info.Subject.pbData, cert_info.Subject.cbData as usize)
        };
        let subject = subject.to_vec();
        Ok(Cert {
            class: serialize_uint(CKO_CERTIFICATE)?,
            token: vec![CK_TRUE as u8],
            id,
            label,
            value,
            issuer,
            serial_number,
            subject,
        })
    }

    /// Create a temporary certificate context from the DER bytes of this certificate.
    fn context(&self) -> Result<CertContext, CryptoError> {
        let cert_context = unsafe {
            CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                self.value.as_ptr(),
                self.value.len().try_into().map_err(|_| CryptoError::OperationFailed)?,
            )
        };
        if cert_context.is_null() {
            let last_error = unsafe { GetLastError() };
            error!(
                "CertCreateCertificateContext failed: {:#010x}",
                last_error
            );
            return Err(CryptoError::Windows(last_error));
        }
        Ok(CertContext(cert_context))
    }

    /// Determine the length of the ciphertext that would result from encrypting `data` with this
    /// certificate's public key.
    pub fn encrypt_length(
        &self,
        data: &[u8],
        mechanism: &RsaCipherMechanism,
    ) -> Result<usize, CryptoError> {
        let context = self.context()?;
        match context.encrypt_internal(data, false, mechanism) {
            Ok(dummy_ciphertext) => Ok(dummy_ciphertext.len()),
            Err(err) => Err(err),
        }
    }

    /// Encrypt `data` with this certificate's public key via CNG.
    pub fn encrypt(
        &self,
        data: &[u8],
        mechanism: &RsaCipherMechanism,
    ) -> Result<Vec<u8>, CryptoError> {
        let context = self.context()?;
        context.encrypt_internal(data, true, mechanism)
    }

    fn class(&self) -> &[u8] {
        &self.class
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn label(&self) -> &[u8] {
        &self.label
    }

    fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn issuer(&self) -> &[u8] {
        &self.issuer
    }

    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    fn subject(&self) -> &[u8] {
        &self.subject
    }

    fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        attrs.iter().all(|(attr_type, attr_value)| {
            match *attr_type {
                CKA_TOKEN => bool_attr_matches(self.token(), attr_value),
                CKA_SERIAL_NUMBER => serial_number_matches(self.serial_number(), attr_value),
                _ => {
                    let comparison = match *attr_type {
                        CKA_CLASS => self.class(),
                        CKA_LABEL => self.label(),
                        CKA_ID => self.id(),
                        CKA_VALUE => self.value(),
                        CKA_ISSUER => self.issuer(),
                        CKA_SUBJECT => self.subject(),
                        _ => return false,
                    };
                    attr_value.as_slice() == comparison
                }
            }
        })
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        let result = match attribute {
            CKA_CLASS => self.class(),
            CKA_TOKEN => self.token(),
            CKA_LABEL => self.label(),
            CKA_ID => self.id(),
            CKA_VALUE => self.value(),
            CKA_ISSUER => self.issuer(),
            CKA_SERIAL_NUMBER => self.serial_number(),
            CKA_SUBJECT => self.subject(),
            _ => return None,
        };
        Some(result)
    }
}

struct CertContext(PCCERT_CONTEXT);

impl CertContext {
    fn new(cert: PCCERT_CONTEXT) -> CertContext {
        CertContext(unsafe { CertDuplicateCertificateContext(cert) })
    }

    /// Encrypt `data` with this certificate's public key via CNG.
    /// If `do_encrypt` is false, only the length of the ciphertext is determined.
    fn encrypt_internal(
        &self,
        data: &[u8],
        do_encrypt: bool,
        mechanism: &RsaCipherMechanism,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = BCryptPublicKeyHandle::from_cert(self)?;
        let mut padding_info =
            CipherPaddingInfo::new(mechanism).map_err(|_| CryptoError::InvalidKey)?;
        let mut input = data.to_vec();
        let mut encrypted_len: u32 = 0;
        // The first call asks CNG for the required output buffer size without performing the
        // encryption (unlike RSA decryption, CNG can report this size cheaply).
        let status = unsafe {
            BCryptEncrypt(
                *key,
                input.as_mut_ptr(),
                input.len().try_into().map_err(|_| CryptoError::OperationFailed)?,
                padding_info.params_ptr() as *mut _,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                &mut encrypted_len,
                padding_info.flags(),
            )
        };
        if status != 0 {
            error!(
                "BCryptEncrypt failed getting output buffer length, {:#010x}",
                status
            );
            return Err(CryptoError::Windows(status as u32));
        }
        let mut encrypted = vec![0; encrypted_len as usize];
        if !do_encrypt {
            return Ok(encrypted);
        }
        let mut final_encrypted_len = encrypted_len;
        let status = unsafe {
            BCryptEncrypt(
                *key,
                input.as_mut_ptr(),
                input.len().try_into().map_err(|_| CryptoError::OperationFailed)?,
                padding_info.params_ptr() as *mut _,
                std::ptr::null_mut(),
                0,
                encrypted.as_mut_ptr(),
                encrypted_len,
                &mut final_encrypted_len,
                padding_info.flags(),
            )
        };
        if status != 0 {
            error!("BCryptEncrypt failed encrypting data, {:#010x}", status);
            return Err(CryptoError::Windows(status as u32));
        }
        if final_encrypted_len != encrypted_len {
            error!(
                "BCryptEncrypt: inconsistent encrypted lengths? {} != {}",
                final_encrypted_len, encrypted_len
            );
            return Err(CryptoError::OperationFailed);
        }
        Ok(encrypted)
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateContext(self.0);
        }
    }
}

impl Deref for CertContext {
    type Target = PCCERT_CONTEXT;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct NCryptKeyHandle(NCRYPT_KEY_HANDLE);

impl NCryptKeyHandle {
    fn from_cert(cert: &CertContext) -> Result<NCryptKeyHandle, CryptoError> {
        let mut key_handle = 0;
        let mut key_spec = 0;
        let mut must_free = 0;
        unsafe {
            if CryptAcquireCertificatePrivateKey(
                **cert,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, // currently we only support CNG
                std::ptr::null_mut(),
                &mut key_handle,
                &mut key_spec,
                &mut must_free,
            ) != 1
            {
                let last_error = GetLastError();
                error!(
                    "CryptAcquireCertificatePrivateKey failed: {:#010x}",
                    last_error
                );
                return Err(CryptoError::Windows(last_error as u32));
            }
        }
        if key_spec != CERT_NCRYPT_KEY_SPEC {
            error!("CryptAcquireCertificatePrivateKey returned non-ncrypt handle");
            return Err(CryptoError::OperationFailed);
        }
        if must_free == 0 {
            error!("CryptAcquireCertificatePrivateKey returned shared key handle");
            return Err(CryptoError::OperationFailed);
        }
        Ok(NCryptKeyHandle(key_handle as NCRYPT_KEY_HANDLE))
    }
}

impl Drop for NCryptKeyHandle {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.0 as NCRYPT_HANDLE);
        }
    }
}

impl Deref for NCryptKeyHandle {
    type Target = NCRYPT_KEY_HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A handle on a CNG public key imported from a certificate.
pub struct BCryptPublicKeyHandle(BCRYPT_KEY_HANDLE);

impl BCryptPublicKeyHandle {
    /// Import the public key of the given certificate as a CNG key. This does not touch any private
    /// key material; it only uses the (public) certificate bytes.
    fn from_cert(cert: &CertContext) -> Result<BCryptPublicKeyHandle, CryptoError> {
        let mut key_handle: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
        // Extract the subject public key info from the certificate.
        let pccert: PCCERT_CONTEXT = **cert;
        let public_key_info: &CERT_PUBLIC_KEY_INFO = unsafe {
            &(*(*pccert).pCertInfo).SubjectPublicKeyInfo
        };
        let imported = unsafe {
            CryptImportPublicKeyInfoEx2(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                public_key_info as *const CERT_PUBLIC_KEY_INFO as *mut CERT_PUBLIC_KEY_INFO,
                0,
                std::ptr::null_mut(),
                &mut key_handle,
            )
        };
        if imported == 0 {
            let last_error = unsafe { GetLastError() };
            error!("CryptImportPublicKeyInfoEx2 failed: {:#010x}", last_error);
            return Err(CryptoError::Windows(last_error));
        }
        Ok(BCryptPublicKeyHandle(key_handle))
    }
}

impl Drop for BCryptPublicKeyHandle {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyKey(self.0);
        }
    }
}

impl Deref for BCryptPublicKeyHandle {
    type Target = BCRYPT_KEY_HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// In some cases, the ncrypt API takes a pointer to a null-terminated wide-character string as a way
// of specifying an algorithm. The "right" way to do this would be to take the corresponding
// &'static str constant provided by the winapi crate, create an OsString from it, encode it as wide
// characters, and collect it into a Vec<u16>. However, since the implementation that provides this
// functionality isn't constant, we would have to manage the memory this creates and uses. Since
// rust structures generally can't be self-referrential, this memory would have to live elsewhere,
// and the nice abstractions we've created for this implementation start to break down. It's much
// simpler to hard-code the identifiers we support, since there are only four of them.
// The following arrays represent the identifiers "SHA1", "SHA256", "SHA384", and "SHA512",
// respectively.
const SHA1_ALGORITHM_STRING: &[u16] = &[83, 72, 65, 49, 0];
const SHA256_ALGORITHM_STRING: &[u16] = &[83, 72, 65, 50, 53, 54, 0];
const SHA384_ALGORITHM_STRING: &[u16] = &[83, 72, 65, 51, 56, 52, 0];
const SHA512_ALGORITHM_STRING: &[u16] = &[83, 72, 65, 53, 49, 50, 0];

enum SignParams {
    EC,
    RSA_PKCS1(BCRYPT_PKCS1_PADDING_INFO),
    RSA_PSS(BCRYPT_PSS_PADDING_INFO),
}

impl SignParams {
    fn new(key_type: KeyType, params: &Option<CK_RSA_PKCS_PSS_PARAMS>) -> Result<SignParams, ()> {
        // EC is easy, so handle that first.
        match key_type {
            KeyType::EC => return Ok(SignParams::EC),
            KeyType::RSA => {}
        }
        // If `params` is `Some`, we're doing RSA-PSS. If it is `None`, we're doing RSA-PKCS1.
        let pss_params = match params {
            Some(pss_params) => pss_params,
            None => {
                // The hash algorithm should be encoded in the data to be signed, so we don't have to
                // (and don't want to) specify a particular algorithm here.
                return Ok(SignParams::RSA_PKCS1(BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: std::ptr::null(),
                }));
            }
        };
        let algorithm_string = match pss_params.hashAlg {
            CKM_SHA_1 => SHA1_ALGORITHM_STRING,
            CKM_SHA256 => SHA256_ALGORITHM_STRING,
            CKM_SHA384 => SHA384_ALGORITHM_STRING,
            CKM_SHA512 => SHA512_ALGORITHM_STRING,
            _ => {
                error!(
                    "unsupported algorithm to use with RSA-PSS: {}",
                    unsafe_packed_field_access!(pss_params.hashAlg)
                );
                return Err(());
            }
        };
        Ok(SignParams::RSA_PSS(BCRYPT_PSS_PADDING_INFO {
            pszAlgId: algorithm_string.as_ptr(),
            cbSalt: pss_params.sLen,
        }))
    }

    fn params_ptr(&mut self) -> *mut std::ffi::c_void {
        match self {
            SignParams::EC => std::ptr::null_mut(),
            SignParams::RSA_PKCS1(params) => {
                params as *mut BCRYPT_PKCS1_PADDING_INFO as *mut std::ffi::c_void
            }
            SignParams::RSA_PSS(params) => {
                params as *mut BCRYPT_PSS_PADDING_INFO as *mut std::ffi::c_void
            }
        }
    }

    fn flags(&self) -> u32 {
        match self {
            &SignParams::EC => 0,
            &SignParams::RSA_PKCS1(_) => NCRYPT_PAD_PKCS1_FLAG,
            &SignParams::RSA_PSS(_) => NCRYPT_PAD_PSS_FLAG,
        }
    }
}

/// An owned representation of the mechanism used for an RSA encryption or decryption operation.
/// This mirrors what was parsed from the PKCS #11 `C_*Init` call (raw pointers are converted to
/// owned data so this type can safely cross threads).
#[derive(Debug)]
pub enum RsaCipherMechanism {
    /// RSA PKCS#1 v1.5 padding (`CKM_RSA_PKCS`).
    Pkcs1v15,
    /// RSA OAEP padding (`CKM_RSA_PKCS_OAEP`). Note that CNG ties the MGF1 hash function to the
    /// digest algorithm, so callers must have already ensured the MGF matches the hash algorithm
    /// before constructing this variant.
    Oaep {
        hash_alg: CK_MECHANISM_TYPE,
        label: Vec<u8>,
    },
}

impl RsaCipherMechanism {
    /// Map a PKCS #11 hash algorithm identifier onto its CNG algorithm identifier string.
    fn hash_algorithm_string(hash_alg: CK_MECHANISM_TYPE) -> Result<&'static [u16], ()> {
        match hash_alg {
            CKM_SHA_1 => Ok(SHA1_ALGORITHM_STRING),
            CKM_SHA256 => Ok(SHA256_ALGORITHM_STRING),
            CKM_SHA384 => Ok(SHA384_ALGORITHM_STRING),
            CKM_SHA512 => Ok(SHA512_ALGORITHM_STRING),
            _ => {
                error!(
                    "unsupported hash algorithm for RSA-OAEP: {}",
                    unsafe_packed_field_access!(hash_alg)
                );
                Err(())
            }
        }
    }
}

/// Padding parameters for RSA encryption and decryption operations. For the OAEP variant, the
/// label pointer points into the `RsaCipherMechanism` the parameters were built from, which must
/// outlive any use of this value.
enum CipherPaddingInfo<'a> {
    Pkcs1v15(BCRYPT_PKCS1_PADDING_INFO),
    Oaep(BCRYPT_OAEP_PADDING_INFO, std::marker::PhantomData<&'a [u8]>),
}

impl<'a> CipherPaddingInfo<'a> {
    fn new(mechanism: &'a RsaCipherMechanism) -> Result<CipherPaddingInfo<'a>, ()> {
        match mechanism {
            RsaCipherMechanism::Pkcs1v15 => {
                // As with RSA-PKCS1 signing, the padding info does not need a hash algorithm
                // identifier when encrypting or decrypting with PKCS#1 v1.5 padding.
                Ok(CipherPaddingInfo::Pkcs1v15(BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: std::ptr::null(),
                }))
            }
            RsaCipherMechanism::Oaep { hash_alg, label } => {
                let algorithm_string = RsaCipherMechanism::hash_algorithm_string(*hash_alg)?;
                // An empty label is represented by a null pointer and length 0, which is exactly
                // what CNG expects when no label was specified.
                Ok(CipherPaddingInfo::Oaep(
                    BCRYPT_OAEP_PADDING_INFO {
                        pszAlgId: algorithm_string.as_ptr(),
                        pbLabel: if label.is_empty() {
                            std::ptr::null_mut()
                        } else {
                            label.as_ptr() as *mut u8
                        },
                        cbLabel: label.len() as u32,
                    },
                    std::marker::PhantomData,
                ))
            }
        }
    }

    fn params_ptr(&mut self) -> *mut std::ffi::c_void {
        match self {
            CipherPaddingInfo::Pkcs1v15(params) => {
                params as *mut BCRYPT_PKCS1_PADDING_INFO as *mut std::ffi::c_void
            }
            CipherPaddingInfo::Oaep(params, _) => {
                params as *mut BCRYPT_OAEP_PADDING_INFO as *mut std::ffi::c_void
            }
        }
    }

    fn flags(&self) -> u32 {
        match self {
            &CipherPaddingInfo::Pkcs1v15(_) => NCRYPT_PAD_PKCS1_FLAG,
            &CipherPaddingInfo::Oaep(_, _) => NCRYPT_PAD_OAEP_FLAG,
        }
    }
}

/// A helper enum to identify a private key's type. We support EC and RSA.
#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    EC,
    RSA,
}

/// Represents a private key for which there exists a corresponding certificate.
pub struct Key {
    /// A handle on the OS mechanism that represents the certificate for this key.
    cert: CertContext,
    /// PKCS #11 object class. Will be `CKO_PRIVATE_KEY`.
    class: Vec<u8>,
    /// Whether or not this is on a token. Will be `CK_TRUE`.
    token: Vec<u8>,
    /// An identifier unique to this key. Must be the same as the ID for the certificate.
    id: Vec<u8>,
    /// Whether or not this key is "private" (can it be exported?). Will be CK_TRUE (it can't be
    /// exported).
    private: Vec<u8>,
    /// PKCS #11 key type. Will be `CKK_EC` for EC, and `CKK_RSA` for RSA.
    key_type: Vec<u8>,
    /// If this is an RSA key, this is the value of the modulus as an unsigned integer.
    modulus: Option<Vec<u8>>,
    /// If this is an EC key, this is the DER bytes of the OID identifying the curve the key is on.
    ec_params: Option<Vec<u8>>,
    /// An enum identifying this key's type.
    key_type_enum: KeyType,
}

impl Key {
    fn new(cert_context: PCCERT_CONTEXT) -> Result<Key, ()> {
        let cert = unsafe { *cert_context };
        let cert_der =
            unsafe { slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize) };
        let id = Sha256::digest(cert_der).to_vec();
        let id = id.to_vec();
        let cert_info = unsafe { &*cert.pCertInfo };
        let mut modulus = None;
        let mut ec_params = None;
        let spki = &cert_info.SubjectPublicKeyInfo;
        let algorithm_oid = unsafe { CStr::from_ptr(spki.Algorithm.pszObjId) }
            .to_str()
            .map_err(|_| ())?;
        let (key_type_enum, key_type_attribute) = if algorithm_oid == szOID_RSA_RSA {
            if spki.PublicKey.cUnusedBits != 0 {
                return Err(());
            }
            let public_key_bytes = unsafe {
                std::slice::from_raw_parts(spki.PublicKey.pbData, spki.PublicKey.cbData as usize)
            };
            let modulus_value = read_rsa_modulus(public_key_bytes)?;
            modulus = Some(modulus_value);
            (KeyType::RSA, CKK_RSA)
        } else if algorithm_oid == szOID_ECC_PUBLIC_KEY {
            let params = &spki.Algorithm.Parameters;
            ec_params = Some(
                unsafe { std::slice::from_raw_parts(params.pbData, params.cbData as usize) }
                    .to_vec(),
            );
            (KeyType::EC, CKK_EC)
        } else {
            return Err(());
        };
        Ok(Key {
            cert: CertContext::new(cert_context),
            class: serialize_uint(CKO_PRIVATE_KEY)?,
            token: vec![CK_TRUE as u8],
            id,
            private: vec![CK_TRUE as u8],
            key_type: serialize_uint(key_type_attribute)?,
            modulus,
            ec_params,
            key_type_enum,
        })
    }

    fn class(&self) -> &[u8] {
        &self.class
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    fn private(&self) -> &[u8] {
        &self.private
    }

    fn key_type(&self) -> &[u8] {
        &self.key_type
    }

    fn modulus(&self) -> Option<&[u8]> {
        match &self.modulus {
            Some(modulus) => Some(modulus.as_slice()),
            None => None,
        }
    }

    fn ec_params(&self) -> Option<&[u8]> {
        match &self.ec_params {
            Some(ec_params) => Some(ec_params.as_slice()),
            None => None,
        }
    }

    fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        attrs.iter().all(|(attr_type, attr_value)| {
            match *attr_type {
                CKA_TOKEN => bool_attr_matches(self.token(), attr_value),
                CKA_PRIVATE => bool_attr_matches(self.private(), attr_value),
                _ => {
                    let comparison = match *attr_type {
                        CKA_CLASS => self.class(),
                        CKA_ID => self.id(),
                        CKA_KEY_TYPE => self.key_type(),
                        CKA_MODULUS => {
                            if let Some(modulus) = self.modulus() {
                                modulus
                            } else {
                                return false;
                            }
                        }
                        CKA_EC_PARAMS => {
                            if let Some(ec_params) = self.ec_params() {
                                ec_params
                            } else {
                                return false;
                            }
                        }
                        _ => return false,
                    };
                    attr_value.as_slice() == comparison
                }
            }
        })
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        match attribute {
            CKA_CLASS => Some(self.class()),
            CKA_TOKEN => Some(self.token()),
            CKA_ID => Some(self.id()),
            CKA_PRIVATE => Some(self.private()),
            CKA_KEY_TYPE => Some(self.key_type()),
            CKA_MODULUS => self.modulus(),
            CKA_EC_PARAMS => self.ec_params(),
            _ => None,
        }
    }

    pub fn get_signature_length(
        &self,
        data: &[u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<usize, CryptoError> {
        match self.sign_internal(data, params, false) {
            Ok(dummy_signature_bytes) => Ok(dummy_signature_bytes.len()),
            Err(err) => Err(err),
        }
    }

    pub fn sign(
        &self,
        data: &[u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<Vec<u8>, CryptoError> {
        self.sign_internal(data, params, true)
    }

    /// data: the data to sign
    /// do_signature: if true, actually perform the signature. Otherwise, return a `Vec<u8>` of the
    /// length the signature would be, if performed.
    fn sign_internal(
        &self,
        data: &[u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
        do_signature: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        // Acquiring a handle on the key can cause the OS to show some UI to the user, so we do this
        // as late as possible (i.e. here).
        let key = NCryptKeyHandle::from_cert(&self.cert)?;
        let mut sign_params =
            SignParams::new(self.key_type_enum, params).map_err(|_| CryptoError::OperationFailed)?;
        let params_ptr = sign_params.params_ptr();
        let flags = sign_params.flags();
        let mut data = data.to_vec();
        let mut signature_len = 0;
        // We call NCryptSignHash twice: the first time to get the size of the buffer we need to
        // allocate and then again to actually sign the data, if `do_signature` is `true`.
        let status = unsafe {
            NCryptSignHash(
                *key,
                params_ptr,
                data.as_mut_ptr(),
                data.len().try_into().map_err(|_| CryptoError::OperationFailed)?,
                std::ptr::null_mut(),
                0,
                &mut signature_len,
                flags,
            )
        };
        // 0 is "ERROR_SUCCESS" (but "ERROR_SUCCESS" is unsigned, whereas SECURITY_STATUS is signed)
        if status != 0 {
            error!(
                "NCryptSignHash failed trying to get signature buffer length, {:#010x}",
                status
            );
            return Err(CryptoError::Windows(status as u32));
        }
        let mut signature = vec![0; signature_len as usize];
        if !do_signature {
            return Ok(signature);
        }
        let mut final_signature_len = signature_len;
        let status = unsafe {
            NCryptSignHash(
                *key,
                params_ptr,
                data.as_mut_ptr(),
                data.len().try_into().map_err(|_| CryptoError::OperationFailed)?,
                signature.as_mut_ptr(),
                signature_len,
                &mut final_signature_len,
                flags,
            )
        };
        if status != 0 {
            error!("NCryptSignHash failed signing data {:#010x}", status);
            return Err(CryptoError::Windows(status as u32));
        }
        if final_signature_len != signature_len {
            error!(
                "NCryptSignHash: inconsistent signature lengths? {} != {}",
                final_signature_len, signature_len
            );
            return Err(CryptoError::OperationFailed);
        }
        Ok(signature)
    }

    /// Determine the length of the plaintext that would result from decrypting `data` with this
    /// key.
    pub fn decrypt_length(
        &self,
        data: &[u8],
        mechanism: &RsaCipherMechanism,
    ) -> Result<usize, CryptoError> {
        match self.decrypt_internal(data, false, mechanism) {
            Ok(dummy_plaintext) => Ok(dummy_plaintext.len()),
            Err(err) => Err(err),
        }
    }

    /// Decrypt `data` with this (private, non-exportable) key via CNG. The private key material
    /// never leaves Windows.
    pub fn decrypt(
        &self,
        data: &[u8],
        mechanism: &RsaCipherMechanism,
    ) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_internal(data, true, mechanism)
    }

    fn decrypt_internal(
        &self,
        data: &[u8],
        do_decrypt: bool,
        mechanism: &RsaCipherMechanism,
    ) -> Result<Vec<u8>, CryptoError> {
        if !matches!(self.key_type_enum, KeyType::RSA) {
            error!("decrypt requested for non-RSA key");
            return Err(CryptoError::InvalidKey);
        }
        let mut padding_info =
            CipherPaddingInfo::new(mechanism).map_err(|_| CryptoError::InvalidKey)?;
        // Acquiring a handle on the key can cause the OS to show some UI to the user, so we do
        // this as late as possible (i.e. here).
        let key = NCryptKeyHandle::from_cert(&self.cert)?;
        let mut decrypted_len: u32 = 0;
        // The first call asks CNG for the required output buffer size. Note that to produce this
        // result CNG processes the input (including unpadding), so this is effectively one
        // decryption pass; the second call below performs the decryption again to get the data.
        let status = unsafe {
            NCryptDecrypt(
                *key,
                data.as_ptr() as *mut u8,
                data.len().try_into().map_err(|_| CryptoError::OperationFailed)?,
                padding_info.params_ptr(),
                std::ptr::null_mut(),
                0,
                &mut decrypted_len,
                padding_info.flags(),
            )
        };
        if status != 0 {
            error!(
                "NCryptDecrypt failed getting output buffer length, {:#010x}",
                status
            );
            return Err(CryptoError::Windows(status as u32));
        }
        let mut decrypted = vec![0; decrypted_len as usize];
        if !do_decrypt {
            return Ok(decrypted);
        }
        let mut final_decrypted_len = decrypted_len;
        let status = unsafe {
            NCryptDecrypt(
                *key,
                data.as_ptr() as *mut u8,
                data.len().try_into().map_err(|_| CryptoError::OperationFailed)?,
                padding_info.params_ptr(),
                decrypted.as_mut_ptr(),
                decrypted_len,
                &mut final_decrypted_len,
                padding_info.flags(),
            )
        };
        if status != 0 {
            error!("NCryptDecrypt failed decrypting data, {:#010x}", status);
            return Err(CryptoError::Windows(status as u32));
        }
        decrypted.truncate(final_decrypted_len as usize);
        Ok(decrypted)
    }

    /// Determine the length of the ciphertext that would result from encrypting `data` with this
    /// key's public key.
    pub fn encrypt_length(
        &self,
        data: &[u8],
        mechanism: &RsaCipherMechanism,
    ) -> Result<usize, CryptoError> {
        match self.cert.encrypt_internal(data, false, mechanism) {
            Ok(dummy_ciphertext) => Ok(dummy_ciphertext.len()),
            Err(err) => Err(err),
        }
    }

    /// Encrypt `data` with this key's certificate public key via CNG.
    pub fn encrypt(
        &self,
        data: &[u8],
        mechanism: &RsaCipherMechanism,
    ) -> Result<Vec<u8>, CryptoError> {
        self.cert.encrypt_internal(data, true, mechanism)
    }
}

/// A helper enum that represents the two types of PKCS #11 objects we support: certificates and
/// keys.
pub enum Object {
    Cert(Cert),
    Key(Key),
}

impl Object {
    pub fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        match self {
            Object::Cert(cert) => cert.matches(attrs),
            Object::Key(key) => key.matches(attrs),
        }
    }

    pub fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        match self {
            Object::Cert(cert) => cert.get_attribute(attribute),
            Object::Key(key) => key.get_attribute(attribute),
        }
    }
}

struct CertStore {
    handle: HCERTSTORE,
}

impl Drop for CertStore {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                CertCloseStore(self.handle, 0);
            }
        }
    }
}

impl Deref for CertStore {
    type Target = HCERTSTORE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl CertStore {
    fn new(handle: HCERTSTORE) -> CertStore {
        CertStore { handle }
    }
}

pub const SUPPORTED_ATTRIBUTES: &[CK_ATTRIBUTE_TYPE] = &[
    CKA_CLASS,
    CKA_TOKEN,
    CKA_LABEL,
    CKA_ID,
    CKA_VALUE,
    CKA_ISSUER,
    CKA_SERIAL_NUMBER,
    CKA_SUBJECT,
    CKA_PRIVATE,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_EC_PARAMS,
];

/// Attempts to enumerate certificates with private keys exposed by the OS. Currently only looks in
/// the "My" cert store of the current user. In the future this may look in more locations.
pub fn list_objects() -> Vec<Object> {
    let mut objects = Vec::new();
    let location_flags = CERT_SYSTEM_STORE_CURRENT_USER // TODO: loop over multiple locations
        | CERT_STORE_OPEN_EXISTING_FLAG
        | CERT_STORE_READONLY_FLAG;
    let store_name = match CString::new("My") {
        Ok(store_name) => store_name,
        Err(null_error) => {
            error!("CString::new given input with a null byte: {}", null_error);
            return objects;
        }
    };
    let store = CertStore::new(unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_REGISTRY_A,
            0,
            0,
            location_flags,
            store_name.as_ptr() as *const winapi::ctypes::c_void,
        )
    });
    if store.is_null() {
        error!("CertOpenStore failed");
        return objects;
    }
    let mut cert_context: PCCERT_CONTEXT = std::ptr::null_mut();
    loop {
        cert_context = unsafe {
            CertFindCertificateInStore(
                *store,
                X509_ASN_ENCODING,
                CERT_FIND_HAS_PRIVATE_KEY,
                CERT_FIND_ANY,
                std::ptr::null_mut(),
                cert_context,
            )
        };
        if cert_context.is_null() {
            break;
        }
        let cert = match Cert::new(cert_context) {
            Ok(cert) => cert,
            Err(()) => continue,
        };
        let key = match Key::new(cert_context) {
            Ok(key) => key,
            Err(()) => continue,
        };
        objects.push(Object::Cert(cert));
        objects.push(Object::Key(key));
    }
    objects
}
