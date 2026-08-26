/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use byteorder::{BigEndian, NativeEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryInto;

// NSS-specific (vendor) PKCS #11 object class, attribute types and trust values. These are not
// part of the base PKCS #11 spec covered by the `pkcs11` crate; the numeric values are taken
// directly from NSS's own `security/nss/lib/util/pkcs11n.h`. They're used to build synthetic
// `CKO_NSS_TRUST` objects -- by `backend_windows` for real Windows-root-trusted CAs, and by
// `backend_other` under the `nss-regression` feature to synthesize trust objects for the NSS
// regression harness (see `tests/nss-regression/`). Both consumers are conditional (target_os =
// "windows", or the nss-regression feature), so on a plain non-Windows build these are unused;
// `#![allow(dead_code)]` covers that rather than cfg-gating every constant individually.
#[allow(dead_code)]
mod nss_trust {
    use pkcs11::types::{
        CK_ATTRIBUTE_TYPE, CK_OBJECT_CLASS, CK_ULONG, CKA_VENDOR_DEFINED, CKO_VENDOR_DEFINED,
    };

    /// Not exported by the `pkcs11` crate (it has no notion of trust objects at all).
    #[allow(non_camel_case_types)]
    pub type CK_TRUST = CK_ULONG;

    pub const NSSCK_VENDOR_NSS: CK_ATTRIBUTE_TYPE = 0x4E53_4350; // "NSCP"
    pub const CKO_NSS: CK_OBJECT_CLASS = CKO_VENDOR_DEFINED | (NSSCK_VENDOR_NSS as CK_OBJECT_CLASS);
    pub const CKO_NSS_TRUST: CK_OBJECT_CLASS = CKO_NSS + 3;
    pub const CKA_NSS: CK_ATTRIBUTE_TYPE = CKA_VENDOR_DEFINED | NSSCK_VENDOR_NSS;
    pub const CKA_NSS_TRUST_BASE: CK_ATTRIBUTE_TYPE = CKA_NSS + 0x2000;
    pub const CKA_NSS_TRUST_SERVER_AUTH: CK_ATTRIBUTE_TYPE = CKA_NSS_TRUST_BASE + 8;
    pub const CKA_NSS_TRUST_CLIENT_AUTH: CK_ATTRIBUTE_TYPE = CKA_NSS_TRUST_BASE + 9;
    pub const CKA_NSS_TRUST_CODE_SIGNING: CK_ATTRIBUTE_TYPE = CKA_NSS_TRUST_BASE + 10;
    pub const CKA_NSS_TRUST_EMAIL_PROTECTION: CK_ATTRIBUTE_TYPE = CKA_NSS_TRUST_BASE + 11;
    pub const CKA_NSS_TRUST_STEP_UP_APPROVED: CK_ATTRIBUTE_TYPE = CKA_NSS_TRUST_BASE + 16;
    pub const CKA_NSS_CERT_SHA1_HASH: CK_ATTRIBUTE_TYPE = CKA_NSS_TRUST_BASE + 100;
    pub const CKT_VENDOR_DEFINED: CK_TRUST = 0x8000_0000;
    pub const CKT_NSS: CK_TRUST = CKT_VENDOR_DEFINED | (NSSCK_VENDOR_NSS as CK_TRUST);
    pub const CKT_NSS_TRUSTED_DELEGATOR: CK_TRUST = CKT_NSS + 2;
    pub const CKT_NSS_TRUST_UNKNOWN: CK_TRUST = CKT_NSS + 5;
}
#[allow(unused_imports)]
pub use nss_trust::*;

/// Formats a byte slice as a lowercase hexadecimal string (for diagnostic logging).
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Accessing fields of packed structs is unsafe (it may be undefined behavior if the field isn't
/// aligned). Since we're implementing a PKCS#11 module, we already have to trust the caller not to
/// give us bad data, so normally we would deal with this by adding an unsafe block. If we do that,
/// though, the compiler complains that the unsafe block is unnecessary. Thus, we use this macro to
/// annotate the unsafe block to silence the compiler.
macro_rules! unsafe_packed_field_access {
    ($e:expr) => {{
        #[allow(unused_unsafe)]
        let tmp = unsafe { $e };
        tmp
    }};
}

#[cfg(target_os = "macos")]
pub const OID_BYTES_SECP256R1: &[u8] =
    &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
#[cfg(target_os = "macos")]
pub const OID_BYTES_SECP384R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
#[cfg(target_os = "macos")]
pub const OID_BYTES_SECP521R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

// This is a helper function to take a value and lay it out in memory how
// PKCS#11 is expecting it.
pub fn serialize_uint<T: TryInto<u64>>(value: T) -> Result<Vec<u8>, ()> {
    let value_size = std::mem::size_of::<T>();
    let mut value_buf = Vec::with_capacity(value_size);
    let value_as_u64 = value.try_into().map_err(|_| ())?;
    value_buf
        .write_uint::<NativeEndian>(value_as_u64, value_size)
        .map_err(|_| ())?;
    Ok(value_buf)
}

/// An error that can occur while performing a cryptographic operation via the OS. This carries
/// enough information to both log a useful diagnostic and map the failure onto the appropriate
/// The maximum total amount of data (in bytes) that may be accumulated across the multipart
/// updates of a single operation. RSA and ECDSA operations require the complete message anyway,
/// and real-world messages are tiny compared to this bound; it only exists so that a hostile or
/// buggy caller cannot exhaust memory by streaming updates.
pub const MAX_TOTAL_OPERATION_DATA_LEN: usize = 64 * 1024;

/// PKCS#11 return code for the calling application.
// Some variants are only constructed by platform backends other than the one being compiled.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// A generic failure with no more specific information available.
    OperationFailed,
    /// The certificate or key involved cannot perform the requested operation (wrong type,
    /// missing private key, not acquired, ...).
    InvalidKey,
    /// The input data is invalid for the operation (e.g. an encrypted blob does not decrypt to
    /// something with valid padding).
    InvalidData,
    /// The accumulated input data of a multipart operation exceeds the supported bound.
    DataTooLarge,
    /// The caller-supplied output buffer is too small; the payload is the required length in
    /// bytes.
    BufferTooSmall(usize),
    /// A Windows API returned the given error code (e.g. a SECURITY_STATUS from CNG/NCrypt).
    Windows(u32),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptoError::OperationFailed => write!(f, "operation failed"),
            CryptoError::InvalidKey => write!(f, "invalid key"),
            CryptoError::InvalidData => write!(f, "invalid data"),
            CryptoError::DataTooLarge => write!(f, "data too large"),
            CryptoError::BufferTooSmall(len) => {
                write!(f, "buffer too small (need {} bytes)", len)
            }
            CryptoError::Windows(status) => write!(f, "windows error {:#010x}", status),
        }
    }
}

impl From<()> for CryptoError {
    fn from(_: ()) -> CryptoError {
        CryptoError::OperationFailed
    }
}

/// Windows CNG SECURITY_STATUS values we want to distinguish when mapping errors onto PKCS#11
/// return codes. See winerror.h.
#[cfg(target_os = "windows")]
const NTE_BAD_KEY: u32 = 0x8009_0003;
#[cfg(target_os = "windows")]
const NTE_BAD_DATA: u32 = 0x8009_0005;
#[cfg(target_os = "windows")]
const NTE_BAD_ALGID: u32 = 0x8009_0008;
#[cfg(target_os = "windows")]
const NTE_BAD_FLAGS: u32 = 0x8009_0009;
#[cfg(target_os = "windows")]
const NTE_BAD_KEY_STATE: u32 = 0x8009_000B;
#[cfg(target_os = "windows")]
const NTE_NO_KEY: u32 = 0x8009_000D;
#[cfg(target_os = "windows")]
const NTE_PERM: u32 = 0x8009_0010;
#[cfg(target_os = "windows")]
const NTE_BAD_KEYSET: u32 = 0x8009_0016;
#[cfg(target_os = "windows")]
const NTE_INVALID_PARAMETER: u32 = 0x8009_0027;
#[cfg(target_os = "windows")]
const NTE_BUFFER_TOO_SMALL: u32 = 0x8009_0028;
#[cfg(target_os = "windows")]
const NTE_NOT_SUPPORTED: u32 = 0x8009_0029;

/// Log the given error with context and convert it into a PKCS#11 return code so that the
/// application (e.g. NSS in Thunderbird) can react appropriately.
pub fn crypto_error_to_rv(context: &str, err: &CryptoError) -> crate::pkcs11::types::CK_RV {
    use crate::pkcs11::types::*;
    let rv = match err {
        CryptoError::OperationFailed => CKR_FUNCTION_FAILED,
        CryptoError::InvalidKey => CKR_KEY_HANDLE_INVALID,
        CryptoError::InvalidData => CKR_ENCRYPTED_DATA_INVALID,
        CryptoError::DataTooLarge => CKR_DATA_LEN_RANGE,
        CryptoError::BufferTooSmall(_) => CKR_BUFFER_TOO_SMALL,
        CryptoError::Windows(status) => match *status {
            #[cfg(target_os = "windows")]
            NTE_NO_KEY | NTE_BAD_KEY | NTE_BAD_KEYSET | NTE_BAD_KEY_STATE | NTE_PERM => {
                CKR_KEY_HANDLE_INVALID
            }
            #[cfg(target_os = "windows")]
            NTE_BAD_DATA => CKR_ENCRYPTED_DATA_INVALID,
            #[cfg(target_os = "windows")]
            NTE_INVALID_PARAMETER | NTE_BAD_FLAGS => CKR_ARGUMENTS_BAD,
            #[cfg(target_os = "windows")]
            NTE_BUFFER_TOO_SMALL => CKR_BUFFER_TOO_SMALL,
            #[cfg(target_os = "windows")]
            NTE_BAD_ALGID | NTE_NOT_SUPPORTED => CKR_FUNCTION_NOT_SUPPORTED,
            _ => CKR_DEVICE_ERROR,
        },
    };
    error!("{}: {} (CK_RV {})", context, err, rv);
    rv
}

/// Given a slice of DER bytes representing an RSA public key, extracts the bytes of the modulus
/// as an unsigned integer. Also verifies that the public exponent is present (again as an
/// unsigned integer). Finally verifies that reading these values consumes the entirety of the
/// slice.
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
// Upstream helper, currently unused (RSA public keys are parsed by CNG); retained for the
// planned PKCS #11 multipart work.
#[allow(dead_code)]
pub fn read_rsa_modulus(public_key: &[u8]) -> Result<Vec<u8>, ()> {
    let mut sequence = Sequence::new(public_key)?;
    let modulus_value = sequence.read_unsigned_integer()?;
    let _exponent = sequence.read_unsigned_integer()?;
    if !sequence.at_end() {
        return Err(());
    }
    Ok(modulus_value.to_vec())
}

/// Given a slice of DER bytes representing an ECDSA signature, extracts the bytes of `r` and `s`
/// as unsigned integers. Also verifies that this consumes the entirety of the slice.
///   Ecdsa-Sig-Value  ::=  SEQUENCE  {
///        r     INTEGER,
///        s     INTEGER  }
#[cfg(target_os = "macos")]
pub fn read_ec_sig_point<'a>(signature: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), ()> {
    let mut sequence = Sequence::new(signature)?;
    let r = sequence.read_unsigned_integer()?;
    let s = sequence.read_unsigned_integer()?;
    if !sequence.at_end() {
        return Err(());
    }
    Ok((r, s))
}

/// Helper macro for reading some bytes from a slice while checking the slice is long enough.
/// Returns a pair consisting of a slice of the bytes read and a slice of the rest of the bytes
/// from the original slice.
macro_rules! try_read_bytes {
    ($data:ident, $len:expr) => {{
        if $data.len() < $len {
            return Err(());
        }
        $data.split_at($len)
    }};
}

/// ASN.1 tag identifying an integer.
#[allow(dead_code)]
const INTEGER: u8 = 0x02;
/// ASN.1 tag identifying a sequence.
#[allow(dead_code)]
const SEQUENCE: u8 = 0x10;
/// ASN.1 tag modifier identifying an item as constructed.
#[allow(dead_code)]
const CONSTRUCTED: u8 = 0x20;

/// A helper struct for reading items from a DER SEQUENCE (in this case, all sequences are
/// assumed to be CONSTRUCTED).
#[allow(dead_code)]
struct Sequence<'a> {
    /// The contents of the SEQUENCE.
    contents: Der<'a>,
}

#[allow(dead_code)]
impl<'a> Sequence<'a> {
    fn new(input: &'a [u8]) -> Result<Sequence<'a>, ()> {
        let mut der = Der::new(input);
        let sequence_bytes = der.read(SEQUENCE | CONSTRUCTED)?;
        // We're assuming we want to consume the entire input for now.
        if !der.at_end() {
            return Err(());
        }
        Ok(Sequence {
            contents: Der::new(sequence_bytes),
        })
    }

    // TODO: we're not exhaustively validating this integer
    fn read_unsigned_integer(&mut self) -> Result<&'a [u8], ()> {
        let bytes = self.contents.read(INTEGER)?;
        if bytes.is_empty() {
            return Err(());
        }
        // There may be a leading zero (we should also check that the first bit
        // of the rest of the integer is set).
        if bytes[0] == 0 && bytes.len() > 1 {
            let (_, integer) = bytes.split_at(1);
            Ok(integer)
        } else {
            Ok(bytes)
        }
    }

    fn at_end(&self) -> bool {
        self.contents.at_end()
    }
}

/// A helper struct for reading DER data. The contents are treated like a cursor, so its position
/// is updated as data is read.
#[allow(dead_code)]
struct Der<'a> {
    contents: &'a [u8],
}

#[allow(dead_code)]
impl<'a> Der<'a> {
    fn new(contents: &'a [u8]) -> Der<'a> {
        Der { contents }
    }

    // In theory, a caller could encounter an error and try another operation, in which case we may
    // be in an inconsistent state. As long as this implementation isn't exposed to code that would
    // use it incorrectly (i.e. it stays in this module and we only expose a stateless API), it
    // should be safe.
    fn read(&mut self, tag: u8) -> Result<&'a [u8], ()> {
        let contents = self.contents;
        let (tag_read, rest) = try_read_bytes!(contents, 1);
        if tag_read[0] != tag {
            return Err(());
        }
        let (length1, rest) = try_read_bytes!(rest, 1);
        let (length, to_read_from) = if length1[0] < 0x80 {
            (length1[0] as usize, rest)
        } else if length1[0] == 0x81 {
            let (length, rest) = try_read_bytes!(rest, 1);
            if length[0] < 0x80 {
                return Err(());
            }
            (length[0] as usize, rest)
        } else if length1[0] == 0x82 {
            let (lengths, rest) = try_read_bytes!(rest, 2);
            let length = (&mut &lengths[..])
                .read_u16::<BigEndian>()
                .map_err(|_| ())?;
            if length < 256 {
                return Err(());
            }
            (length as usize, rest)
        } else {
            return Err(());
        };
        let (contents, rest) = try_read_bytes!(to_read_from, length);
        self.contents = rest;
        Ok(contents)
    }

    fn at_end(&self) -> bool {
        self.contents.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_test_empty_input() {
        let input = Vec::new();
        let mut der = Der::new(&input);
        assert!(der.read(INTEGER).is_err());
    }

    #[test]
    fn der_test_no_length() {
        let input = vec![INTEGER];
        let mut der = Der::new(&input);
        assert!(der.read(INTEGER).is_err());
    }

    #[test]
    fn der_test_empty_sequence() {
        let input = vec![SEQUENCE, 0];
        let mut der = Der::new(&input);
        let read_result = der.read(SEQUENCE);
        assert!(read_result.is_ok());
        let sequence_bytes = read_result.unwrap();
        assert_eq!(sequence_bytes.len(), 0);
        assert!(der.at_end());
    }

    #[test]
    fn der_test_not_at_end() {
        let input = vec![SEQUENCE, 0, 1];
        let mut der = Der::new(&input);
        let read_result = der.read(SEQUENCE);
        assert!(read_result.is_ok());
        let sequence_bytes = read_result.unwrap();
        assert_eq!(sequence_bytes.len(), 0);
        assert!(!der.at_end());
    }

    #[test]
    fn der_test_wrong_tag() {
        let input = vec![SEQUENCE, 0];
        let mut der = Der::new(&input);
        assert!(der.read(INTEGER).is_err());
    }

    #[test]
    fn der_test_truncated_two_byte_length() {
        let input = vec![SEQUENCE, 0x81];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_truncated_three_byte_length() {
        let input = vec![SEQUENCE, 0x82, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_truncated_data() {
        let input = vec![SEQUENCE, 20, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_sequence() {
        let input = vec![
            SEQUENCE, 20, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 0, 0,
        ];
        let mut der = Der::new(&input);
        let result = der.read(SEQUENCE);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 0, 0]
        );
        assert!(der.at_end());
    }

    #[test]
    fn der_test_not_shortest_two_byte_length_encoding() {
        let input = vec![SEQUENCE, 0x81, 1, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_not_shortest_three_byte_length_encoding() {
        let input = vec![SEQUENCE, 0x82, 0, 1, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_indefinite_length_unsupported() {
        let input = vec![SEQUENCE, 0x80, 1, 2, 3, 0x00, 0x00];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_input_too_long() {
        // This isn't valid DER (the contents of the SEQUENCE are truncated), but it demonstrates
        // that we don't try to read too much if we're given a long length (and also that we don't
        // support lengths 2^16 and up).
        let input = vec![SEQUENCE, 0x83, 0x01, 0x00, 0x01, 1, 1, 1, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn empty_input_fails() {
        let empty = Vec::new();
        assert!(read_rsa_modulus(&empty).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn empty_input_fails_ec() {
        let empty = Vec::new();
        assert!(read_ec_sig_point(&empty).is_err());
    }

    #[test]
    fn empty_sequence_fails() {
        let empty = vec![SEQUENCE | CONSTRUCTED];
        assert!(read_rsa_modulus(&empty).is_err());
    }

    #[test]
    fn test_read_rsa_modulus() {
        let rsa_key = include_bytes!("../test/rsa.bin");
        let result = read_rsa_modulus(rsa_key);
        assert!(result.is_ok());
        let modulus = result.unwrap();
        assert_eq!(modulus, include_bytes!("../test/modulus.bin").to_vec());
    }

    #[test]
    fn crypto_error_to_rv_mapping() {
        use crate::pkcs11::types::*;

        assert_eq!(
            crypto_error_to_rv("test", &CryptoError::OperationFailed),
            CKR_FUNCTION_FAILED
        );
        assert_eq!(
            crypto_error_to_rv("test", &CryptoError::InvalidKey),
            CKR_KEY_HANDLE_INVALID
        );
        assert_eq!(
            crypto_error_to_rv("test", &CryptoError::InvalidData),
            CKR_ENCRYPTED_DATA_INVALID
        );
        assert_eq!(
            crypto_error_to_rv("test", &CryptoError::BufferTooSmall(7)),
            CKR_BUFFER_TOO_SMALL
        );

        // On Windows builds, specific CNG SECURITY_STATUS values map to specific PKCS#11 return
        // codes. On other platforms (e.g. the Linux test host), all Windows errors fall back to
        // CKR_DEVICE_ERROR.
        #[cfg(target_os = "windows")]
        {
            assert_eq!(
                crypto_error_to_rv("test", &CryptoError::Windows(NTE_BAD_DATA)),
                CKR_ENCRYPTED_DATA_INVALID
            );
            assert_eq!(
                crypto_error_to_rv("test", &CryptoError::Windows(NTE_NO_KEY)),
                CKR_KEY_HANDLE_INVALID
            );
            assert_eq!(
                crypto_error_to_rv("test", &CryptoError::Windows(NTE_BAD_ALGID)),
                CKR_FUNCTION_NOT_SUPPORTED
            );
            assert_eq!(
                crypto_error_to_rv("test", &CryptoError::Windows(NTE_INVALID_PARAMETER)),
                CKR_ARGUMENTS_BAD
            );
            assert_eq!(
                crypto_error_to_rv("test", &CryptoError::Windows(NTE_BUFFER_TOO_SMALL)),
                CKR_BUFFER_TOO_SMALL
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(
                crypto_error_to_rv("test", &CryptoError::Windows(0xDEADBEEF)),
                CKR_DEVICE_ERROR
            );
        }
    }
}
