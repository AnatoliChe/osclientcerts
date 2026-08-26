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

use crate::util::{CryptoError, serialize_uint};

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
    CKA_SIGN,
    CKA_DECRYPT,
    CKA_SENSITIVE,
    CKA_EXTRACTABLE,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_LOCAL,
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

/// A stand-in for the Windows backend's `Trust` (Windows-root-trusted-CA email trust record).
/// This stub backend never constructs one -- it exists only so shared code in `manager.rs` that
/// matches on all three `Object` variants compiles the same way on every platform.
pub struct Trust {
    attrs: Attrs,
}

impl Trust {
    pub fn issuer(&self) -> &[u8] {
        self.attrs.get(CKA_ISSUER).unwrap()
    }

    pub fn serial_number(&self) -> &[u8] {
        self.attrs.get(CKA_SERIAL_NUMBER).unwrap()
    }

    pub fn id(&self) -> Vec<u8> {
        let mut id = self.issuer().to_vec();
        id.extend_from_slice(self.serial_number());
        id
    }
}

/// A helper enum that represents the types of PKCS #11 objects we support: certificates, keys,
/// and (Windows-only) trust records.
pub enum Object {
    Cert(Cert),
    Key(Key),
    Trust(Trust),
}

impl Object {
    pub fn matches(&self, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        match self {
            Object::Cert(cert) => cert.attrs.matches(attrs),
            Object::Key(key) => key.attrs.matches(attrs),
            Object::Trust(trust) => trust.attrs.matches(attrs),
        }
    }

    pub fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        match self {
            Object::Cert(cert) => cert.attrs.get(attribute),
            Object::Key(key) => key.attrs.get(attribute),
            Object::Trust(trust) => trust.attrs.get(attribute),
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
        (CKA_LABEL, b"test-cert".to_vec()),
        (CKA_SUBJECT, b"CN=Test Cert".to_vec()),
        (CKA_ISSUER, b"CN=Test CA".to_vec()),
        (CKA_SERIAL_NUMBER, vec![0x03, 0x02, 0x01]),
        (CKA_PRIVATE, vec![1]),
        (CKA_KEY_TYPE, serialize_uint(CKK_RSA).unwrap()),
        (
            CKA_MODULUS,
            (0u8..16).map(|i| 0xA0 + i).collect::<Vec<u8>>(),
        ),
        (CKA_SIGN, vec![1]),
        (CKA_DECRYPT, vec![1]),
        (CKA_SENSITIVE, vec![1]),
        (CKA_EXTRACTABLE, vec![0]),
        (CKA_ALWAYS_AUTHENTICATE, vec![0]),
        (CKA_LOCAL, vec![1]),
    ])
}

#[cfg(not(feature = "nss-regression"))]
pub fn list_objects() -> Vec<Object> {
    vec![
        Object::Cert(Cert {
            attrs: cert_attrs(),
        }),
        Object::Key(Key { attrs: key_attrs() }),
    ]
}

/// Builds `Object`s (certificates and `CKO_NSS_TRUST` records) from a generated test-case
/// directory instead of the fixed stub data above, so the NSS regression harness
/// (`tests/nss-regression/`) can load real certificate chains -- with varying signature
/// algorithms and, for negative-control cases, deliberately malformed trust attributes -- into
/// this crate's actual, unmodified PKCS #11 object/attribute code and check how a real NSS build
/// resolves trust and validates signatures against it. This is the only way to catch bugs that
/// live in how NSS itself interprets our PKCS #11 objects (as opposed to bugs in this crate's own
/// state machines, which the stub backend above already covers): the two real bugs this harness
/// was built to catch (a missing `CKA_NSS_CERT_SHA1_HASH` silently discarding trust grants, and
/// `C_GetAttributeValue` not updating `ulValueLen`) were both invisible to unit tests against the
/// stub backend and were only found by loading a module into a real, from-source NSS build.
#[cfg(feature = "nss-regression")]
mod nss_regression {
    use super::{Attrs, Cert, Object, Trust};
    use crate::util::{
        CKA_NSS_CERT_SHA1_HASH, CKA_NSS_TRUST_CLIENT_AUTH, CKA_NSS_TRUST_CODE_SIGNING,
        CKA_NSS_TRUST_EMAIL_PROTECTION, CKA_NSS_TRUST_SERVER_AUTH, CKA_NSS_TRUST_STEP_UP_APPROVED,
        CKO_NSS_TRUST, CKT_NSS_TRUST_UNKNOWN, CKT_NSS_TRUSTED_DELEGATOR, serialize_uint,
    };
    use pkcs11::types::*;
    use std::{env, fs, path::Path};

    /// The manifest is a sequence of `key=value` blocks separated by blank lines, e.g.:
    ///
    /// ```text
    /// kind=cert
    /// label=root
    /// id=root
    /// der=root.der
    /// issuer=root.issuer.der
    /// subject=root.subject.der
    /// serial=root.serial.bin
    ///
    /// kind=trust
    /// issuer=root.issuer.der
    /// serial=root.serial.bin
    /// sha1=root.sha1.bin
    /// ```
    ///
    /// A `trust` block that omits `sha1=` reproduces the historical missing-hash bug (the trust
    /// grant should then be silently ignored by NSS); `email_protection=unknown` (instead of the
    /// default, which grants trust) reproduces "no trust asserted" for comparison. File paths are
    /// relative to the manifest's own directory. See `tests/nss-regression/generate_chains.py`,
    /// which writes these directories.
    fn parse_manifest(text: &str) -> Vec<Vec<(String, String)>> {
        text.split("\n\n")
            .map(|block| {
                block
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(|line| {
                        let (key, value) = line.split_once('=').unwrap_or_else(|| {
                            panic!("nss-regression: malformed manifest line: {line}")
                        });
                        (key.trim().to_string(), value.trim().to_string())
                    })
                    .collect::<Vec<_>>()
            })
            .filter(|block: &Vec<_>| !block.is_empty())
            .collect()
    }

    struct Block(Vec<(String, String)>);

    impl Block {
        fn get(&self, key: &str) -> Option<&str> {
            self.0
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }

        fn require(&self, key: &str) -> &str {
            self.get(key)
                .unwrap_or_else(|| panic!("nss-regression: manifest block missing '{key}'"))
        }
    }

    fn read_file(dir: &Path, name: &str) -> Vec<u8> {
        fs::read(dir.join(name))
            .unwrap_or_else(|e| panic!("nss-regression: failed to read '{name}': {e}"))
    }

    pub fn list_objects() -> Vec<Object> {
        let dir = env::var("OSCLIENTCERTS_NSS_REGRESSION_DIR").expect(
            "OSCLIENTCERTS_NSS_REGRESSION_DIR must point to a generated test-case directory \
             (see tests/nss-regression/) when built with the nss-regression feature",
        );
        let dir = Path::new(&dir);
        let manifest_text = fs::read_to_string(dir.join("manifest.txt"))
            .unwrap_or_else(|e| panic!("nss-regression: failed to read manifest.txt: {e}"));

        parse_manifest(&manifest_text)
            .into_iter()
            .map(Block)
            .map(|block| match block.require("kind") {
                "cert" => Object::Cert(Cert {
                    attrs: Attrs(vec![
                        (CKA_CLASS, serialize_uint(CKO_CERTIFICATE).unwrap()),
                        (CKA_TOKEN, vec![CK_TRUE]),
                        (CKA_LABEL, block.require("label").as_bytes().to_vec()),
                        (CKA_ID, block.require("id").as_bytes().to_vec()),
                        (CKA_VALUE, read_file(dir, block.require("der"))),
                        (CKA_ISSUER, read_file(dir, block.require("issuer"))),
                        (CKA_SERIAL_NUMBER, read_file(dir, block.require("serial"))),
                        (CKA_SUBJECT, read_file(dir, block.require("subject"))),
                    ]),
                }),
                "trust" => {
                    let email_protection = if block.get("email_protection") == Some("unknown") {
                        CKT_NSS_TRUST_UNKNOWN
                    } else {
                        CKT_NSS_TRUSTED_DELEGATOR
                    };
                    let mut attrs = vec![
                        (CKA_CLASS, serialize_uint(CKO_NSS_TRUST).unwrap()),
                        (CKA_TOKEN, vec![CK_TRUE]),
                        (CKA_ISSUER, read_file(dir, block.require("issuer"))),
                        (CKA_SERIAL_NUMBER, read_file(dir, block.require("serial"))),
                        (
                            CKA_NSS_TRUST_SERVER_AUTH,
                            serialize_uint(CKT_NSS_TRUST_UNKNOWN).unwrap(),
                        ),
                        (
                            CKA_NSS_TRUST_CLIENT_AUTH,
                            serialize_uint(CKT_NSS_TRUST_UNKNOWN).unwrap(),
                        ),
                        (
                            CKA_NSS_TRUST_CODE_SIGNING,
                            serialize_uint(CKT_NSS_TRUST_UNKNOWN).unwrap(),
                        ),
                        (
                            CKA_NSS_TRUST_EMAIL_PROTECTION,
                            serialize_uint(email_protection).unwrap(),
                        ),
                        (CKA_NSS_TRUST_STEP_UP_APPROVED, vec![CK_FALSE]),
                    ];
                    if let Some(sha1_file) = block.get("sha1") {
                        attrs.push((CKA_NSS_CERT_SHA1_HASH, read_file(dir, sha1_file)));
                    }
                    Object::Trust(Trust {
                        attrs: Attrs(attrs),
                    })
                }
                other => panic!("nss-regression: unknown object kind '{other}'"),
            })
            .collect()
    }
}

#[cfg(feature = "nss-regression")]
pub use nss_regression::list_objects;
