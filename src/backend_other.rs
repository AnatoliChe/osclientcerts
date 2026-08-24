/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! A stub backend used when compiling for platforms that have no real backend implementation
//! (i.e. any platform other than macOS and Windows). Its purpose is to make the rest of the crate
//! (the manager, the PKCS #11 FFI layer) compile on ordinary development hosts so that unit tests
//! can run there. The cryptographic behavior is deterministic fake data designed to exercise
//! caller-side state machines (buffer-too-small retries, operation lifetime, ...); it performs no
//! real cryptography.

#![allow(dead_code)]

use pkcs11::types::*;

use crate::util::{serialize_uint, CryptoError};

pub use crate::mechanism::RsaCipherMechanism;

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

/// The size (in bytes) of plaintext/ciphertext produced by the stub operations.
const STUB_OUTPUT_LEN: usize = 128;
/// Inputs shorter than this make length queries fail with `BufferTooSmall`, which lets tests
/// exercise the retry path of `C_Decrypt` / `C_Encrypt`.
const STUB_SHORT_INPUT_LEN: usize = 64;

fn stub_output_len(input: &[u8]) -> Result<usize, CryptoError> {
    if input.len() < STUB_SHORT_INPUT_LEN {
        return Err(CryptoError::BufferTooSmall(STUB_OUTPUT_LEN));
    }
    Ok(STUB_OUTPUT_LEN)
}

fn stub_cipher(input: &[u8], fill: u8) -> Result<Vec<u8>, CryptoError> {
    Ok(vec![fill; stub_output_len(input)?])
}

#[derive(Clone)]
struct Attrs(Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>);

impl Attrs {
    fn get(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(attr_type, _)| *attr_type == attribute)
            .map(|(_, value)| value.as_slice())
    }

    fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        attrs
            .iter()
            .all(|(attr_type, value)| self.get(*attr_type) == Some(value.as_slice()))
    }
}

pub struct Cert {
    attrs: Attrs,
}

impl Cert {
    pub fn class(&self) -> &[u8] {
        self.attrs.get(CKA_CLASS).unwrap()
    }

    pub fn token(&self) -> &[u8] {
        self.attrs.get(CKA_TOKEN).unwrap()
    }

    pub fn label(&self) -> &[u8] {
        self.attrs.get(CKA_LABEL).unwrap()
    }

    pub fn id(&self) -> &[u8] {
        self.attrs.get(CKA_ID).unwrap()
    }

    pub fn issuer(&self) -> &[u8] {
        self.attrs.get(CKA_ISSUER).unwrap()
    }

    pub fn serial_number(&self) -> &[u8] {
        self.attrs.get(CKA_SERIAL_NUMBER).unwrap()
    }

    pub fn encrypt_length(
        &self,
        data: &[u8],
        _mechanism: &RsaCipherMechanism,
    ) -> Result<usize, CryptoError> {
        stub_output_len(data)
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        _mechanism: &RsaCipherMechanism,
    ) -> Result<Vec<u8>, CryptoError> {
        stub_cipher(data, 0xCD)
    }
}

pub struct Key {
    attrs: Attrs,
}

impl Key {
    pub fn id(&self) -> &[u8] {
        self.attrs.get(CKA_ID).unwrap()
    }

    pub fn get_signature_length(
        &self,
        _data: &[u8],
        _params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<usize, CryptoError> {
        Ok(64)
    }

    pub fn sign(
        &self,
        _data: &[u8],
        _params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0x11; 64])
    }

    pub fn decrypt_length(
        &self,
        data: &[u8],
        _mechanism: &RsaCipherMechanism,
    ) -> Result<usize, CryptoError> {
        stub_output_len(data)
    }

    pub fn decrypt(
        &self,
        data: &[u8],
        _mechanism: &RsaCipherMechanism,
    ) -> Result<Vec<u8>, CryptoError> {
        stub_cipher(data, 0xAB)
    }

    pub fn encrypt_length(
        &self,
        data: &[u8],
        _mechanism: &RsaCipherMechanism,
    ) -> Result<usize, CryptoError> {
        // Encryption always uses the certificate public key, mirroring the real backends.
        stub_output_len(data)
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        _mechanism: &RsaCipherMechanism,
    ) -> Result<Vec<u8>, CryptoError> {
        stub_cipher(data, 0xCD)
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
            Object::Cert(cert) => cert.attrs.matches(attrs),
            Object::Key(key) => key.attrs.matches(attrs),
        }
    }

    pub fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        match self {
            Object::Cert(cert) => cert.attrs.get(attribute),
            Object::Key(key) => key.attrs.get(attribute),
        }
    }
}

fn cert_attrs() -> Attrs {
    Attrs(vec![
        (CKA_CLASS, serialize_uint(CKO_CERTIFICATE).unwrap()),
        (CKA_TOKEN, vec![1]),
        (CKA_LABEL, b"test-cert".to_vec()),
        (CKA_ID, vec![0x42]),
        (CKA_VALUE, vec![0x30, 0x00]),
        (CKA_ISSUER, b"CN=Test CA".to_vec()),
        (CKA_SERIAL_NUMBER, vec![0x03, 0x02, 0x01]),
        (CKA_SUBJECT, b"CN=Test Cert".to_vec()),
    ])
}

fn key_attrs() -> Attrs {
    Attrs(vec![
        (CKA_CLASS, serialize_uint(CKO_PRIVATE_KEY).unwrap()),
        (CKA_TOKEN, vec![1]),
        (CKA_ID, vec![0x42]),
        (CKA_PRIVATE, vec![1]),
        (CKA_KEY_TYPE, serialize_uint(CKK_RSA).unwrap()),
        (
            CKA_MODULUS,
            (0u8..16).map(|i| 0xA0 + i).collect::<Vec<u8>>(),
        ),
    ])
}

pub fn list_objects() -> Vec<Object> {
    vec![Object::Cert(Cert { attrs: cert_attrs() }), Object::Key(Key { attrs: key_attrs() })]
}
