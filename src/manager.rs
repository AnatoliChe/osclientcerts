/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pkcs11::types::*;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_os = "macos")]
use crate::backend_macos as backend;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use crate::backend_other as backend;
#[cfg(target_os = "windows")]
use crate::backend_windows as backend;
use backend::*;

use crate::util::CryptoError;
use crate::util::hex_encode;

use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Helper type for sending `ManagerArguments` to the real `Manager`.
type ManagerArgumentsSender = Sender<ManagerArguments>;
/// Helper type for receiving `ManagerReturnValue`s from the real `Manager`.
type ManagerReturnValueReceiver = Receiver<ManagerReturnValue>;

/// Helper enum that encapsulates arguments to send from the `ManagerProxy` to the real `Manager`.
/// `ManagerArguments::Stop` is a special variant that stops the background thread and drops the
/// `Manager`.
enum ManagerArguments {
    OpenSession,
    CloseSession(CK_SESSION_HANDLE),
    CloseAllSessions,
    StartSearch(CK_SESSION_HANDLE, Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>),
    Search(CK_SESSION_HANDLE, usize),
    ClearSearch(CK_SESSION_HANDLE),
    GetAttributes(CK_OBJECT_HANDLE, Vec<CK_ATTRIBUTE_TYPE>),
    StartSign(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        Option<CK_RSA_PKCS_PSS_PARAMS>,
    ),
    GetSignatureLength(CK_SESSION_HANDLE, Vec<u8>),
    Sign(CK_SESSION_HANDLE, Vec<u8>),
    StartDecrypt(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, RsaCipherMechanism),
    GetDecryptedLength(CK_SESSION_HANDLE, Vec<u8>),
    Decrypt(CK_SESSION_HANDLE, Vec<u8>),
    StartEncrypt(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, RsaCipherMechanism),
    GetEncryptedLength(CK_SESSION_HANDLE, Vec<u8>),
    Encrypt(CK_SESSION_HANDLE, Vec<u8>),
    Stop,
}

/// Helper enum that encapsulates return values from the real `Manager` that are sent back to the
/// `ManagerProxy`. `ManagerReturnValue::Stop` is a special variant that indicates that the
/// `Manager` will stop.
enum ManagerReturnValue {
    OpenSession(Result<CK_SESSION_HANDLE, ()>),
    CloseSession(Result<(), ()>),
    CloseAllSessions(Result<(), ()>),
    StartSearch(Result<(), ()>),
    Search(Result<Vec<CK_OBJECT_HANDLE>, ()>),
    ClearSearch(Result<(), ()>),
    GetAttributes(Result<Vec<Option<Vec<u8>>>, ()>),
    StartSign(Result<(), CryptoError>),
    GetSignatureLength(Result<usize, CryptoError>),
    Sign(Result<Vec<u8>, CryptoError>),
    StartDecrypt(Result<(), CryptoError>),
    GetDecryptedLength(Result<usize, CryptoError>),
    Decrypt(Result<Vec<u8>, CryptoError>),
    StartEncrypt(Result<(), CryptoError>),
    GetEncryptedLength(Result<usize, CryptoError>),
    Encrypt(Result<Vec<u8>, CryptoError>),
    Stop(Result<(), ()>),
}

/// Helper macro to implement the body of each public `ManagerProxy` function. Takes a
/// `ManagerProxy` instance (should always be `self`), a `ManagerArguments` representing the
/// `Manager` function to call and the arguments to use, and the qualified type of the expected
/// `ManagerReturnValue` that will be received from the `Manager` when it is done.
macro_rules! manager_proxy_fn_impl {
    ($manager:ident, $argument_enum:expr, $return_type:path) => {
        match $manager.proxy_call($argument_enum) {
            Ok($return_type(result)) => result,
            Ok(_) => {
                error!("unexpected return value from manager");
                Err(From::from(()))
            }
            Err(()) => Err(From::from(())),
        }
    };
}

/// `ManagerProxy` synchronously proxies calls from any thread to the `Manager` that runs on a
/// single thread. This is necessary because the underlying OS APIs in use are not guaranteed to be
/// thread-safe (e.g. they may use thread-local storage). Using it should be identical to using the
/// real `Manager`.
pub struct ManagerProxy {
    sender: ManagerArgumentsSender,
    receiver: ManagerReturnValueReceiver,
    thread_handle: Option<JoinHandle<()>>,
}

impl ManagerProxy {
    pub fn new() -> ManagerProxy {
        let (proxy_sender, manager_receiver) = channel();
        let (manager_sender, proxy_receiver) = channel();
        let thread_handle = thread::spawn(move || {
            let mut real_manager = Manager::new();
            loop {
                let arguments = match manager_receiver.recv() {
                    Ok(arguments) => arguments,
                    Err(e) => {
                        error!("error recv()ing arguments from ManagerProxy: {}", e);
                        break;
                    }
                };
                let results = match arguments {
                    ManagerArguments::OpenSession => {
                        ManagerReturnValue::OpenSession(real_manager.open_session())
                    }
                    ManagerArguments::CloseSession(session_handle) => {
                        ManagerReturnValue::CloseSession(real_manager.close_session(session_handle))
                    }
                    ManagerArguments::CloseAllSessions => {
                        ManagerReturnValue::CloseAllSessions(real_manager.close_all_sessions())
                    }
                    ManagerArguments::StartSearch(session, attrs) => {
                        ManagerReturnValue::StartSearch(real_manager.start_search(session, &attrs))
                    }
                    ManagerArguments::Search(session, max_objects) => {
                        ManagerReturnValue::Search(real_manager.search(session, max_objects))
                    }
                    ManagerArguments::ClearSearch(session) => {
                        ManagerReturnValue::ClearSearch(real_manager.clear_search(session))
                    }
                    ManagerArguments::GetAttributes(object_handle, attr_types) => {
                        ManagerReturnValue::GetAttributes(
                            real_manager.get_attributes(object_handle, attr_types),
                        )
                    }
                    ManagerArguments::StartSign(session, key_handle, params) => {
                        ManagerReturnValue::StartSign(
                            real_manager.start_sign(session, key_handle, params),
                        )
                    }
                    ManagerArguments::GetSignatureLength(session, data) => {
                        ManagerReturnValue::GetSignatureLength(
                            real_manager.get_signature_length(session, &data),
                        )
                    }
                    ManagerArguments::Sign(session, data) => {
                        ManagerReturnValue::Sign(real_manager.sign(session, &data))
                    }
                    ManagerArguments::StartDecrypt(session, key_handle, mechanism) => {
                        ManagerReturnValue::StartDecrypt(
                            real_manager.start_decrypt(session, key_handle, mechanism),
                        )
                    }
                    ManagerArguments::GetDecryptedLength(session, data) => {
                        ManagerReturnValue::GetDecryptedLength(
                            real_manager.get_decrypted_length(session, &data),
                        )
                    }
                    ManagerArguments::Decrypt(session, data) => {
                        ManagerReturnValue::Decrypt(real_manager.decrypt(session, &data))
                    }
                    ManagerArguments::StartEncrypt(session, key_handle, mechanism) => {
                        ManagerReturnValue::StartEncrypt(
                            real_manager.start_encrypt(session, key_handle, mechanism),
                        )
                    }
                    ManagerArguments::GetEncryptedLength(session, data) => {
                        ManagerReturnValue::GetEncryptedLength(
                            real_manager.get_encrypted_length(session, &data),
                        )
                    }
                    ManagerArguments::Encrypt(session, data) => {
                        ManagerReturnValue::Encrypt(real_manager.encrypt(session, &data))
                    }
                    ManagerArguments::Stop => {
                        debug!("ManagerArguments::Stop received - stopping Manager thread.");
                        ManagerReturnValue::Stop(Ok(()))
                    }
                };
                let stop_after_send = matches!(&results, ManagerReturnValue::Stop(_));
                match manager_sender.send(results) {
                    Ok(()) => {}
                    Err(e) => {
                        error!("error send()ing results from Manager: {}", e);
                        break;
                    }
                }
                if stop_after_send {
                    break;
                }
            }
        });
        ManagerProxy {
            sender: proxy_sender,
            receiver: proxy_receiver,
            thread_handle: Some(thread_handle),
        }
    }

    fn proxy_call(&self, args: ManagerArguments) -> Result<ManagerReturnValue, ()> {
        match self.sender.send(args) {
            Ok(()) => {}
            Err(e) => {
                error!("error send()ing arguments to Manager: {}", e);
                return Err(());
            }
        };
        let result = match self.receiver.recv() {
            Ok(result) => result,
            Err(e) => {
                error!("error recv()ing result from Manager: {}", e);
                return Err(());
            }
        };
        Ok(result)
    }

    pub fn open_session(&mut self) -> Result<CK_SESSION_HANDLE, ()> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::OpenSession,
            ManagerReturnValue::OpenSession
        )
    }

    pub fn close_session(&mut self, session: CK_SESSION_HANDLE) -> Result<(), ()> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::CloseSession(session),
            ManagerReturnValue::CloseSession
        )
    }

    pub fn close_all_sessions(&mut self) -> Result<(), ()> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::CloseAllSessions,
            ManagerReturnValue::CloseAllSessions
        )
    }

    pub fn start_search(
        &mut self,
        session: CK_SESSION_HANDLE,
        attrs: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>,
    ) -> Result<(), ()> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::StartSearch(session, attrs),
            ManagerReturnValue::StartSearch
        )
    }

    pub fn search(
        &mut self,
        session: CK_SESSION_HANDLE,
        max_objects: usize,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, ()> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::Search(session, max_objects),
            ManagerReturnValue::Search
        )
    }

    pub fn clear_search(&mut self, session: CK_SESSION_HANDLE) -> Result<(), ()> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::ClearSearch(session),
            ManagerReturnValue::ClearSearch
        )
    }

    pub fn get_attributes(
        &self,
        object_handle: CK_OBJECT_HANDLE,
        attr_types: Vec<CK_ATTRIBUTE_TYPE>,
    ) -> Result<Vec<Option<Vec<u8>>>, ()> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::GetAttributes(object_handle, attr_types,),
            ManagerReturnValue::GetAttributes
        )
    }

    pub fn start_sign(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
        params: Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<(), CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::StartSign(session, key_handle, params),
            ManagerReturnValue::StartSign
        )
    }

    pub fn get_signature_length(
        &self,
        session: CK_SESSION_HANDLE,
        data: Vec<u8>,
    ) -> Result<usize, CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::GetSignatureLength(session, data),
            ManagerReturnValue::GetSignatureLength
        )
    }

    pub fn sign(
        &mut self,
        session: CK_SESSION_HANDLE,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::Sign(session, data),
            ManagerReturnValue::Sign
        )
    }

    pub fn start_decrypt(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: RsaCipherMechanism,
    ) -> Result<(), CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::StartDecrypt(session, key_handle, mechanism),
            ManagerReturnValue::StartDecrypt
        )
    }

    pub fn get_decrypted_length(
        &self,
        session: CK_SESSION_HANDLE,
        data: Vec<u8>,
    ) -> Result<usize, CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::GetDecryptedLength(session, data),
            ManagerReturnValue::GetDecryptedLength
        )
    }

    pub fn decrypt(
        &mut self,
        session: CK_SESSION_HANDLE,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::Decrypt(session, data),
            ManagerReturnValue::Decrypt
        )
    }

    pub fn start_encrypt(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: RsaCipherMechanism,
    ) -> Result<(), CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::StartEncrypt(session, key_handle, mechanism),
            ManagerReturnValue::StartEncrypt
        )
    }

    pub fn get_encrypted_length(
        &self,
        session: CK_SESSION_HANDLE,
        data: Vec<u8>,
    ) -> Result<usize, CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::GetEncryptedLength(session, data),
            ManagerReturnValue::GetEncryptedLength
        )
    }

    pub fn encrypt(
        &mut self,
        session: CK_SESSION_HANDLE,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        manager_proxy_fn_impl!(
            self,
            ManagerArguments::Encrypt(session, data),
            ManagerReturnValue::Encrypt
        )
    }

    pub fn stop(&mut self) -> Result<(), ()> {
        manager_proxy_fn_impl!(self, ManagerArguments::Stop, ManagerReturnValue::Stop)?;
        let thread_handle = match self.thread_handle.take() {
            Some(thread_handle) => thread_handle,
            None => {
                error!("stop should only be called once");
                return Err(());
            }
        };
        match thread_handle.join() {
            Ok(()) => {}
            Err(e) => {
                error!("manager thread panicked: {:?}", e);
                return Err(());
            }
        };
        Ok(())
    }
}

/// The `Manager` keeps track of the state of this module with respect to the PKCS #11
/// specification. This includes what sessions are open, which search and sign operations are
/// ongoing, and what objects are known and by what handle.
struct Manager {
    /// A set of sessions. Sessions can be created (opened) and later closed.
    sessions: BTreeSet<CK_SESSION_HANDLE>,
    /// A map of searches to PKCS #11 object handles that match those searches.
    searches: BTreeMap<CK_SESSION_HANDLE, Vec<CK_OBJECT_HANDLE>>,
    /// A map of sign operations to a pair of the object handle and optionally some params being
    /// used by each one.
    signs: BTreeMap<CK_SESSION_HANDLE, (CK_OBJECT_HANDLE, Option<CK_RSA_PKCS_PSS_PARAMS>)>,
    /// A map of decrypt operations to a pair of the key handle and mechanism being used by each
    /// one.
    decrypts: BTreeMap<CK_SESSION_HANDLE, (CK_OBJECT_HANDLE, RsaCipherMechanism)>,
    /// A map of encrypt operations to a pair of the object handle (certificate or key) and
    /// mechanism being used by each one.
    encrypts: BTreeMap<CK_SESSION_HANDLE, (CK_OBJECT_HANDLE, RsaCipherMechanism)>,
    /// A map of object handles to the underlying objects.
    objects: BTreeMap<CK_OBJECT_HANDLE, Object>,
    /// A set of certificate identifiers (not the same as handles).
    cert_ids: BTreeSet<Vec<u8>>,
    /// A set of key identifiers (not the same as handles). For each id in this set, there should be
    /// a corresponding identical id in the `cert_ids` set, and vice-versa.
    key_ids: BTreeSet<Vec<u8>>,
    /// The next session handle to hand out.
    next_session: CK_SESSION_HANDLE,
    /// The next object handle to hand out.
    next_handle: CK_OBJECT_HANDLE,
    /// The last time the implementation looked for new objects in the backend.
    /// The implementation does this search no more than once every 3 seconds.
    last_scan_time: Option<Instant>,
}

impl Manager {
    pub fn new() -> Manager {
        let mut manager = Manager {
            sessions: BTreeSet::new(),
            searches: BTreeMap::new(),
            signs: BTreeMap::new(),
            decrypts: BTreeMap::new(),
            encrypts: BTreeMap::new(),
            objects: BTreeMap::new(),
            cert_ids: BTreeSet::new(),
            key_ids: BTreeSet::new(),
            next_session: 1,
            next_handle: 1,
            last_scan_time: None,
        };
        manager.maybe_find_new_objects();
        manager
    }

    /// When a new `Manager` is created and when a new session is opened (provided at least 3
    /// seconds have elapsed since the last session was opened), this searches for certificates and
    /// keys to expose. We de-duplicate previously-found certificates and keys by / keeping track of
    /// their IDs.
    fn maybe_find_new_objects(&mut self) {
        let now = Instant::now();
        if let Some(last_scan_time) = self.last_scan_time
            && now.duration_since(last_scan_time) < Duration::new(3, 0)
        {
            return;
        }
        self.last_scan_time = Some(now);
        let objects = list_objects();
        debug!("found {} objects", objects.len());
        for object in &objects {
            match object {
                Object::Cert(cert) => {
                    debug!(
                        "cert: label {:?}, id {}, issuer {}, serial {}",
                        String::from_utf8_lossy(cert.label()),
                        hex_encode(cert.id()),
                        hex_encode(cert.issuer()),
                        hex_encode(cert.serial_number()),
                    );
                }
                Object::Key(key) => {
                    debug!("key: id {}", hex_encode(key.id()),);
                }
            }
        }
        for object in objects {
            match &object {
                Object::Cert(cert) => {
                    if self.cert_ids.contains(cert.id()) {
                        continue;
                    }
                    self.cert_ids.insert(cert.id().to_vec());
                    let handle = self.get_next_handle();
                    self.objects.insert(handle, object);
                }
                Object::Key(key) => {
                    if self.key_ids.contains(key.id()) {
                        continue;
                    }
                    self.key_ids.insert(key.id().to_vec());
                    let handle = self.get_next_handle();
                    self.objects.insert(handle, object);
                }
            }
        }
    }

    pub fn open_session(&mut self) -> Result<CK_SESSION_HANDLE, ()> {
        self.maybe_find_new_objects();
        let next_session = self.next_session;
        self.next_session += 1;
        self.sessions.insert(next_session);
        Ok(next_session)
    }

    pub fn close_session(&mut self, session: CK_SESSION_HANDLE) -> Result<(), ()> {
        if self.sessions.remove(&session) {
            // Per PKCS #11, closing a session terminates any active operations on it.
            self.searches.remove(&session);
            self.signs.remove(&session);
            self.decrypts.remove(&session);
            self.encrypts.remove(&session);
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn close_all_sessions(&mut self) -> Result<(), ()> {
        self.sessions.clear();
        self.searches.clear();
        self.signs.clear();
        self.decrypts.clear();
        self.encrypts.clear();
        Ok(())
    }

    fn get_next_handle(&mut self) -> CK_OBJECT_HANDLE {
        let next_handle = self.next_handle;
        self.next_handle += 1;
        next_handle
    }

    /// PKCS #11 specifies that search operations happen in three phases: setup, get any matches
    /// (this part may be repeated if the caller uses a small buffer), and end. This implementation
    /// does all of the work up front and gathers all matching objects during setup and retains them
    /// until they are retrieved and consumed via `search`.
    pub fn start_search(
        &mut self,
        session: CK_SESSION_HANDLE,
        attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(), ()> {
        if self.searches.contains_key(&session) {
            return Err(());
        }
        // If the search is for an attribute we don't support, no objects will match. This check
        // saves us having to look through all of our objects.
        for (attr, _) in attrs {
            if !SUPPORTED_ATTRIBUTES.contains(attr) {
                self.searches.insert(session, Vec::new());
                return Ok(());
            }
        }
        let mut handles = Vec::new();
        for (handle, object) in &self.objects {
            if object.matches(attrs) {
                handles.push(*handle);
            }
        }
        self.searches.insert(session, handles);
        Ok(())
    }

    /// Given a session and a maximum number of object handles to return, attempts to retrieve up to
    /// that many objects from the corresponding search. Updates the search so those objects are not
    /// returned repeatedly. `max_objects` must be non-zero.
    pub fn search(
        &mut self,
        session: CK_SESSION_HANDLE,
        max_objects: usize,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, ()> {
        if max_objects == 0 {
            return Err(());
        }
        match self.searches.get_mut(&session) {
            Some(search) => {
                let split_at = if max_objects >= search.len() {
                    0
                } else {
                    search.len() - max_objects
                };
                let to_return = search.split_off(split_at);
                if to_return.len() > max_objects {
                    error!(
                        "search trying to return too many handles: {} > {}",
                        to_return.len(),
                        max_objects
                    );
                    return Err(());
                }
                Ok(to_return)
            }
            None => Err(()),
        }
    }

    pub fn clear_search(&mut self, session: CK_SESSION_HANDLE) -> Result<(), ()> {
        self.searches.remove(&session);
        Ok(())
    }

    pub fn get_attributes(
        &self,
        object_handle: CK_OBJECT_HANDLE,
        attr_types: Vec<CK_ATTRIBUTE_TYPE>,
    ) -> Result<Vec<Option<Vec<u8>>>, ()> {
        let object = match self.objects.get(&object_handle) {
            Some(object) => object,
            None => return Err(()),
        };
        let mut results = Vec::with_capacity(attr_types.len());
        for attr_type in attr_types {
            let result = object.get_attribute(attr_type).map(<[u8]>::to_owned);
            results.push(result);
        }
        Ok(results)
    }

    /// The way NSS uses PKCS #11 to sign data happens in two phases: setup and sign. This
    /// implementation makes a note of which key is to be used (if it exists) during setup. When the
    /// caller finishes with the sign operation, this implementation retrieves the key handle and
    /// performs the signature.
    pub fn start_sign(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
        params: Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<(), CryptoError> {
        if self.signs.contains_key(&session) {
            return Err(CryptoError::OperationFailed);
        }
        match self.objects.get(&key_handle) {
            Some(Object::Key(_)) => {}
            _ => return Err(CryptoError::InvalidKey),
        };
        self.signs.insert(session, (key_handle, params));
        Ok(())
    }

    pub fn get_signature_length(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<usize, CryptoError> {
        let (key_handle, params) = match self.signs.get(&session) {
            Some((key_handle, params)) => (key_handle, params),
            None => return Err(CryptoError::OperationFailed),
        };
        let key = match self.objects.get(key_handle) {
            Some(Object::Key(key)) => key,
            _ => return Err(CryptoError::InvalidKey),
        };
        key.get_signature_length(data, params)
    }

    pub fn sign(
        &mut self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Performing the signature (via C_Sign, which is the only way we support) finishes the sign
        // operation, so it needs to be removed here.
        let (key_handle, params) = match self.signs.remove(&session) {
            Some((key_handle, params)) => (key_handle, params),
            None => return Err(CryptoError::OperationFailed),
        };
        let key = match self.objects.get(&key_handle) {
            Some(Object::Key(key)) => key,
            _ => return Err(CryptoError::InvalidKey),
        };
        key.sign(data, &params)
    }

    pub fn start_decrypt(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: RsaCipherMechanism,
    ) -> Result<(), CryptoError> {
        if self.decrypts.contains_key(&session) {
            return Err(CryptoError::OperationFailed);
        }
        // Only private keys can be used for decryption.
        match self.objects.get(&key_handle) {
            Some(Object::Key(_)) => {}
            _ => return Err(CryptoError::InvalidKey),
        };
        self.decrypts.insert(session, (key_handle, mechanism));
        Ok(())
    }

    pub fn get_decrypted_length(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<usize, CryptoError> {
        let (key_handle, mechanism) = match self.decrypts.get(&session) {
            Some((key_handle, mechanism)) => (*key_handle, mechanism),
            None => return Err(CryptoError::OperationFailed),
        };
        let key = match self.objects.get(&key_handle) {
            Some(Object::Key(key)) => key,
            _ => return Err(CryptoError::InvalidKey),
        };
        key.decrypt_length(data, mechanism)
    }

    pub fn decrypt(
        &mut self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Performing the decryption (via C_Decrypt, which is the only way we support) finishes the
        // decrypt operation, so it needs to be removed here.
        let (key_handle, mechanism) = match self.decrypts.remove(&session) {
            Some((key_handle, mechanism)) => (key_handle, mechanism),
            None => return Err(CryptoError::OperationFailed),
        };
        let key = match self.objects.get(&key_handle) {
            Some(Object::Key(key)) => key,
            _ => return Err(CryptoError::InvalidKey),
        };
        key.decrypt(data, &mechanism)
    }

    pub fn start_encrypt(
        &mut self,
        session: CK_SESSION_HANDLE,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: RsaCipherMechanism,
    ) -> Result<(), CryptoError> {
        if self.encrypts.contains_key(&session) {
            return Err(CryptoError::OperationFailed);
        }
        // Encryption uses the public key of a certificate; both certificate objects and private
        // key objects (which know their certificate) are acceptable here.
        match self.objects.get(&key_handle) {
            Some(Object::Cert(_)) | Some(Object::Key(_)) => {}
            _ => return Err(CryptoError::InvalidKey),
        };
        self.encrypts.insert(session, (key_handle, mechanism));
        Ok(())
    }

    pub fn get_encrypted_length(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<usize, CryptoError> {
        let (object_handle, mechanism) = match self.encrypts.get(&session) {
            Some((object_handle, mechanism)) => (*object_handle, mechanism),
            None => return Err(CryptoError::OperationFailed),
        };
        match self.objects.get(&object_handle) {
            Some(Object::Cert(cert)) => cert.encrypt_length(data, mechanism),
            Some(Object::Key(key)) => key.encrypt_length(data, mechanism),
            _ => Err(CryptoError::InvalidKey),
        }
    }

    pub fn encrypt(
        &mut self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Performing the encryption (via C_Encrypt, which is the only way we support) finishes the
        // encrypt operation, so it needs to be removed here.
        let (object_handle, mechanism) = match self.encrypts.remove(&session) {
            Some((object_handle, mechanism)) => (object_handle, mechanism),
            None => return Err(CryptoError::OperationFailed),
        };
        match self.objects.get(&object_handle) {
            Some(Object::Cert(cert)) => cert.encrypt(data, &mechanism),
            Some(Object::Key(key)) => key.encrypt(data, &mechanism),
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

// These tests exercise the stub backend semantics (deterministic key discovery and
// cipher outputs), which only exists on platforms without a real backend.
#[cfg(all(test, not(any(target_os = "macos", target_os = "windows"))))]
mod tests {
    use super::*;
    use crate::util::serialize_uint;

    /// Open a session and find the single private-key object the stub backend provides.
    fn find_key_handle(manager: &mut Manager) -> CK_OBJECT_HANDLE {
        let search_session = manager.open_session().expect("open_session failed");
        manager
            .start_search(
                search_session,
                &[(CKA_CLASS, serialize_uint(CKO_PRIVATE_KEY).unwrap())],
            )
            .expect("start_search failed");
        let handles = manager.search(search_session, 10).expect("search failed");
        manager.clear_search(search_session).unwrap();
        assert_eq!(handles.len(), 1);
        handles[0]
    }

    #[test]
    fn close_session_clears_decrypt_operation() {
        let mut manager = Manager::new();
        let key_handle = find_key_handle(&mut manager);
        let session = manager.open_session().unwrap();
        manager
            .start_decrypt(session, key_handle, RsaCipherMechanism::Pkcs1v15)
            .expect("start_decrypt failed");
        // Closing the session must terminate the active operation.
        manager.close_session(session).unwrap();
        assert_eq!(
            manager.get_decrypted_length(session, &[0x5A; 128]),
            Err(CryptoError::OperationFailed)
        );
        assert_eq!(
            manager.decrypt(session, &[0x5A; 128]),
            Err(CryptoError::OperationFailed)
        );
    }

    #[test]
    fn close_session_clears_encrypt_operation() {
        let mut manager = Manager::new();
        let key_handle = find_key_handle(&mut manager);
        let session = manager.open_session().unwrap();
        manager
            .start_encrypt(session, key_handle, RsaCipherMechanism::Pkcs1v15)
            .expect("start_encrypt failed");
        manager.close_session(session).unwrap();
        assert_eq!(
            manager.get_encrypted_length(session, &[0x5A; 128]),
            Err(CryptoError::OperationFailed)
        );
        assert_eq!(
            manager.encrypt(session, &[0x5A; 128]),
            Err(CryptoError::OperationFailed)
        );
    }

    #[test]
    fn decrypt_operation_survives_failed_length_query() {
        let mut manager = Manager::new();
        let key_handle = find_key_handle(&mut manager);
        let session = manager.open_session().unwrap();
        manager
            .start_decrypt(session, key_handle, RsaCipherMechanism::Pkcs1v15)
            .unwrap();
        // The stub backend reports BufferTooSmall for short inputs; a failed length query must
        // not consume the operation.
        assert_eq!(
            manager.get_decrypted_length(session, &[0xEE; 32]),
            Err(CryptoError::BufferTooSmall(128))
        );
        assert_eq!(
            manager.decrypt(session, &[0x5A; 128]).unwrap(),
            vec![0xAB; 128]
        );
    }
}

// S/MIME regression tests: exercise the real Windows CNG backend (certificate enumeration,
// attribute serialization/matching, RSA PKCS#1/PSS signatures and RSA PKCS#1/OAEP
// encrypt-decrypt roundtrips) against deterministic self-signed test certificates provisioned by
// scripts/provision-smime-test-certs.ps1. These tests are the automated replacement for manual
// Thunderbird smoke-testing of historical regressions (issuer/serial matching, CK_BBOOL
// encoding, buffer-too-small retry semantics).
#[cfg(all(test, target_os = "windows"))]
mod smime_regression_tests {
    use super::*;
    use crate::util::serialize_uint;
    use sha2::{Digest, Sha256};

    /// Friendly-name / subject markers of the certificates created by
    /// scripts/provision-smime-test-certs.ps1. They appear verbatim inside the DER-encoded
    /// issuer strings, which is how the tests locate "their" objects in a real store.
    const MARKER_RSA: &[u8] = b"osclientcerts-smime-rsa";
    const MARKER_EC: &[u8] = b"osclientcerts-smime-ec";

    /// SHA-256 DigestInfo prefix (RFC 8017): SEQ(SEQ(OID 2.16.840.1.101.3.4.2.1, NULL), OCTET(32))
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    /// Finds the certificate object whose issuer contains `marker`; returns its handle and the
    /// CKA_ID value shared with the corresponding private key.
    fn find_marker_cert(
        manager: &mut Manager,
        session: CK_SESSION_HANDLE,
        marker: &[u8],
    ) -> (CK_OBJECT_HANDLE, Vec<u8>) {
        manager
            .start_search(
                session,
                &[(CKA_CLASS, serialize_uint(CKO_CERTIFICATE).unwrap())],
            )
            .expect("start_search failed");
        let handles = manager.search(session, 100).expect("search failed");
        manager.clear_search(session).unwrap();
        let mut found = None;
        for handle in handles {
            let values = manager
                .get_attributes(handle, vec![CKA_ISSUER, CKA_ID])
                .expect("get_attributes failed");
            if values[0]
                .as_ref()
                .is_some_and(|issuer| issuer.windows(marker.len()).any(|w| w == marker))
            {
                assert!(found.is_none(), "multiple objects matched {:?}", marker);
                found = Some((handle, values[1].clone().expect("CKA_ID missing")));
            }
        }
        found
            .expect("regression certificate not found - run scripts/provision-smime-test-certs.ps1")
    }

    /// Finds the single private key matching the given certificate's CKA_ID (the same linkage
    /// NSS uses to pair an S/MIME certificate with its private key).
    fn find_key_for_cert(
        manager: &mut Manager,
        session: CK_SESSION_HANDLE,
        cert_id: Vec<u8>,
    ) -> CK_OBJECT_HANDLE {
        manager
            .start_search(
                session,
                &[
                    (CKA_CLASS, serialize_uint(CKO_PRIVATE_KEY).unwrap()),
                    (CKA_ID, cert_id),
                ],
            )
            .expect("start_search key failed");
        let handles = manager.search(session, 10).expect("key search failed");
        manager.clear_search(session).unwrap();
        assert_eq!(
            handles.len(),
            1,
            "expected exactly one key for the regression certificate"
        );
        handles[0]
    }

    #[test]
    fn smime_rsa_cert_discovery_and_attributes() {
        let mut manager = Manager::new();
        let session = manager.open_session().unwrap();
        let (cert_handle, _id) = find_marker_cert(&mut manager, session, MARKER_RSA);
        let values = manager
            .get_attributes(
                cert_handle,
                vec![
                    CKA_CLASS,
                    CKA_CERTIFICATE_TYPE,
                    CKA_TOKEN,
                    CKA_SERIAL_NUMBER,
                    CKA_VALUE,
                ],
            )
            .expect("cert get_attributes failed");
        assert_eq!(
            values[0].as_deref(),
            Some(serialize_uint(CKO_CERTIFICATE).unwrap().as_slice())
        );
        assert_eq!(
            values[1].as_deref(),
            Some(serialize_uint(CKC_X_509).unwrap().as_slice())
        );
        assert_eq!(values[2].as_deref(), Some([CK_TRUE as u8].as_slice()));
        let serial = values[3].as_ref().expect("serial number missing");
        assert!(!serial.is_empty());
        let der = values[4].as_ref().expect("certificate value missing");
        assert_eq!(der[0], 0x30, "certificate should be a DER SEQUENCE");
    }

    #[test]
    fn smime_key_matches_certificate_by_id() {
        let mut manager = Manager::new();
        let session = manager.open_session().unwrap();
        let (_cert_handle, cert_id) = find_marker_cert(&mut manager, session, MARKER_RSA);
        let key_handle = find_key_for_cert(&mut manager, session, cert_id);
        let values = manager
            .get_attributes(key_handle, vec![CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS])
            .expect("key get_attributes failed");
        assert_eq!(
            values[0].as_deref(),
            Some(serialize_uint(CKO_PRIVATE_KEY).unwrap().as_slice())
        );
        assert_eq!(
            values[1].as_deref(),
            Some(serialize_uint(CKK_RSA).unwrap().as_slice())
        );
        // The provider parses the modulus out of the SPKI; it must be a full 2048-bit integer.
        assert_eq!(values[2].as_ref().map(Vec::len), Some(256));
    }

    #[test]
    fn smime_rsa_pkcs1_signature_structure() {
        let mut manager = Manager::new();
        let session = manager.open_session().unwrap();
        let (_cert_handle, cert_id) = find_marker_cert(&mut manager, session, MARKER_RSA);
        let key_handle = find_key_for_cert(&mut manager, session, cert_id);

        // NSS signs DigestInfo (not a bare hash) with CKM_RSA_PKCS; CNG with a null padding-info
        // algorithm embeds this blob verbatim into the EMSA-PKCS1-v1_5 message.
        let digest = Sha256::digest(b"smime regression pkcs1").to_vec();
        let digest_info = SHA256_DIGEST_INFO_PREFIX
            .iter()
            .copied()
            .chain(digest)
            .collect::<Vec<u8>>();

        manager.start_sign(session, key_handle, None).unwrap();
        let len = manager.get_signature_length(session, &digest_info).unwrap();
        assert_eq!(len, 256);
        let signature = manager.sign(session, &digest_info).unwrap();

        // Structural EMSA-PKCS1-v1_5 check: 00 01 FF..FF 00 || DigestInfo.
        assert_eq!(signature.len(), 256);
        assert_eq!(signature[0], 0x00);
        assert_eq!(signature[1], 0x01);
        let padding_end = signature[2..].iter().position(|&b| b != 0xFF).unwrap() + 2;
        assert!(padding_end >= 10, "insufficient PS padding");
        assert_eq!(signature[padding_end], 0x00);
        let rebuilt = SHA256_DIGEST_INFO_PREFIX
            .iter()
            .copied()
            .chain(Sha256::digest(b"smime regression pkcs1"))
            .collect::<Vec<u8>>();
        assert_eq!(
            &signature[signature.len() - rebuilt.len()..],
            rebuilt.as_slice()
        );
    }

    #[test]
    fn smime_rsa_pss_signature_structure() {
        let mut manager = Manager::new();
        let session = manager.open_session().unwrap();
        let (_cert_handle, cert_id) = find_marker_cert(&mut manager, session, MARKER_RSA);
        let key_handle = find_key_for_cert(&mut manager, session, cert_id);

        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let digest = Sha256::digest(b"smime regression pss").to_vec();

        manager
            .start_sign(session, key_handle, Some(params))
            .unwrap();
        let len = manager.get_signature_length(session, &digest).unwrap();
        assert_eq!(len, 256);
        let signature = manager.sign(session, &digest).unwrap();
        assert_eq!(signature.len(), 256);
        // PSS-encoded messages always end with the fixed trailer byte 0xBC.
        assert_eq!(*signature.last().unwrap(), 0xBC);
    }

    #[test]
    fn smime_rsa_pkcs1_encrypt_decrypt_roundtrip() {
        let mut manager = Manager::new();
        let session = manager.open_session().unwrap();
        let (_cert_handle, cert_id) = find_marker_cert(&mut manager, session, MARKER_RSA);
        let key_handle = find_key_for_cert(&mut manager, session, cert_id);

        let plaintext = vec![0xA5_u8; 100];
        manager
            .start_encrypt(session, key_handle, RsaCipherMechanism::Pkcs1v15)
            .unwrap();
        let ciphertext = manager.encrypt(session, &plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        manager
            .start_decrypt(session, key_handle, RsaCipherMechanism::Pkcs1v15)
            .unwrap();
        let decrypted = manager.decrypt(session, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn smime_rsa_oaep_sha256_roundtrip_with_label() {
        let mut manager = Manager::new();
        let session = manager.open_session().unwrap();
        let (_cert_handle, cert_id) = find_marker_cert(&mut manager, session, MARKER_RSA);
        let key_handle = find_key_for_cert(&mut manager, session, cert_id);

        let label = b"smime-regression".to_vec();
        let plaintext = vec![0x37_u8; 100];
        manager
            .start_encrypt(
                session,
                key_handle,
                RsaCipherMechanism::Oaep {
                    hash_alg: CKM_SHA256,
                    label: label.clone(),
                },
            )
            .unwrap();
        let ciphertext = manager.encrypt(session, &plaintext).unwrap();
        manager
            .start_decrypt(
                session,
                key_handle,
                RsaCipherMechanism::Oaep {
                    hash_alg: CKM_SHA256,
                    label,
                },
            )
            .unwrap();
        let decrypted = manager.decrypt(session, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn smime_ecdsa_signature_structure() {
        let mut manager = Manager::new();
        let session = manager.open_session().unwrap();
        let (_cert_handle, cert_id) = find_marker_cert(&mut manager, session, MARKER_EC);
        let key_handle = find_key_for_cert(&mut manager, session, cert_id);

        // ECDSA over P-256 signs the bare SHA-256 digest.
        let digest = Sha256::digest(b"smime regression ecdsa").to_vec();
        manager.start_sign(session, key_handle, None).unwrap();
        let len = manager.get_signature_length(session, &digest).unwrap();
        assert!(len >= 64, "ECDSA signature cannot be shorter than r||s");
        let signature = manager.sign(session, &digest).unwrap();
        // NSS-style DER encoding: SEQUENCE { r INTEGER, s INTEGER } (~70-72 bytes for P-256).
        assert_eq!(signature[0], 0x30);
        assert!((68..=73).contains(&signature.len()));
    }

    #[test]
    fn smime_close_session_terminates_real_operation() {
        let mut manager = Manager::new();
        let session = manager.open_session().unwrap();
        let (_cert_handle, cert_id) = find_marker_cert(&mut manager, session, MARKER_RSA);
        let key_handle = find_key_for_cert(&mut manager, session, cert_id);
        manager
            .start_decrypt(session, key_handle, RsaCipherMechanism::Pkcs1v15)
            .unwrap();
        manager.close_session(session).unwrap();
        let result = manager.decrypt(session, &[0x00; 256]);
        assert!(matches!(result, Err(CryptoError::OperationFailed)));
    }
}
