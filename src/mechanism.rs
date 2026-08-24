/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Platform-neutral handling of RSA encryption/decryption mechanisms. This module is compiled for
//! every target (including test hosts) so that mechanism parsing logic can be unit-tested without
//! access to OS crypto APIs.

use pkcs11::types::*;

// The following arrays represent the identifiers "SHA1", "SHA256", "SHA384", and "SHA512",
// respectively, as NUL-terminated UTF-16 strings (the form CNG expects for algorithm identifiers).
// They are only referenced by the Windows backend, hence the allow.
#[allow(dead_code)]
pub const SHA1_ALGORITHM_STRING: &[u16] = &[83, 72, 65, 49, 0];
#[allow(dead_code)]
pub const SHA256_ALGORITHM_STRING: &[u16] = &[83, 72, 65, 50, 53, 54, 0];
#[allow(dead_code)]
pub const SHA384_ALGORITHM_STRING: &[u16] = &[83, 72, 65, 51, 56, 52, 0];
#[allow(dead_code)]
pub const SHA512_ALGORITHM_STRING: &[u16] = &[83, 72, 65, 53, 49, 50, 0];

/// An owned representation of the mechanism used for an RSA encryption or decryption operation.
/// This mirrors what was parsed from the PKCS #11 `C_*Init` call (raw pointers are converted to
/// owned data so this type can safely cross threads).
#[derive(Debug, PartialEq, Eq)]
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
    /// Map a PKCS #11 hash algorithm identifier onto its CNG algorithm identifier string. Only the
    /// Windows backend calls this (the stub backend performs no real crypto).
    #[allow(dead_code)]
    pub(crate) fn hash_algorithm_string(
        hash_alg: CK_MECHANISM_TYPE,
    ) -> Result<&'static [u16], ()> {
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

/// Parse the mechanism of an RSA encryption or decryption operation into its owned representation
/// (`RsaCipherMechanism`). Returns an appropriate PKCS#11 return value on failure. RSA PKCS#1 v1.5
/// (`CKM_RSA_PKCS`) and RSA-OAEP (`CKM_RSA_PKCS_OAEP`) are supported.
pub fn parse_rsa_cipher_mechanism(
    function_name: &str,
    mechanism: &CK_MECHANISM,
) -> Result<RsaCipherMechanism, CK_RV> {
    let mechanism_type = unsafe_packed_field_access!(mechanism.mechanism);
    if mechanism_type == CKM_RSA_PKCS {
        let parameter_len = unsafe_packed_field_access!(mechanism.ulParameterLen);
        if parameter_len != 0 || !mechanism.pParameter.is_null() {
            error!(
                "{}: unexpected mechanism parameters, len {}",
                function_name, parameter_len
            );
            return Err(CKR_ARGUMENTS_BAD);
        }
        return Ok(RsaCipherMechanism::Pkcs1v15);
    }
    if mechanism_type != CKM_RSA_PKCS_OAEP {
        error!(
            "{}: unsupported mechanism: {}",
            function_name, mechanism_type
        );
        return Err(CKR_MECHANISM_INVALID);
    }
    let parameter_len = unsafe_packed_field_access!(mechanism.ulParameterLen);
    if parameter_len as usize != std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
        || mechanism.pParameter.is_null()
    {
        error!(
            "{}: invalid OAEP mechanism parameters, len {}",
            function_name, parameter_len
        );
        return Err(CKR_ARGUMENTS_BAD);
    }
    // CK_RSA_PKCS_OAEP_PARAMS is packed, so copy its fields into local variables before using
    // them (taking references to fields of packed structs is not allowed).
    let params = unsafe { *(mechanism.pParameter as *const CK_RSA_PKCS_OAEP_PARAMS) };
    let source = params.source;
    if source != CKZ_DATA_SPECIFIED {
        // CNG only supports labels passed directly in the parameters; there is no support for
        // other encoding parameter sources (e.g. object handles or callbacks).
        error!(
            "{}: unsupported OAEP source type: {}",
            function_name, source
        );
        return Err(CKR_ARGUMENTS_BAD);
    }
    let hash_alg = params.hashAlg;
    let expected_mgf = match hash_alg {
        CKM_SHA_1 => CKG_MGF1_SHA1,
        CKM_SHA256 => CKG_MGF1_SHA256,
        CKM_SHA384 => CKG_MGF1_SHA384,
        CKM_SHA512 => CKG_MGF1_SHA512,
        _ => {
            // This includes SHA-224, which CNG does not implement.
            error!(
                "{}: unsupported OAEP hash algorithm: {}",
                function_name, hash_alg
            );
            return Err(CKR_MECHANISM_INVALID);
        }
    };
    let mgf = params.mgf;
    if mgf != expected_mgf {
        // CNG derives the MGF1 hash function from the digest algorithm identifier, so we cannot
        // support an MGF that differs from the digest.
        error!(
            "{}: unsupported OAEP MGF: {} (CNG requires MGF1 with the same hash)",
            function_name, mgf
        );
        return Err(CKR_MECHANISM_INVALID);
    }
    let label_len = params.ulSourceDataLen;
    let label_ptr = params.pSourceData;
    let label = if label_len == 0 || label_ptr.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(label_ptr as *const u8, label_len as usize) }.to_vec()
    };
    debug!(
        "{}: OAEP parameters: hash {}, label {} bytes",
        function_name, hash_alg, label.len()
    );
    Ok(RsaCipherMechanism::Oaep { hash_alg, label })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper that builds a `CK_MECHANISM` pointing at the given parameters (or null).
    fn make_mechanism(
        mechanism_type: CK_MECHANISM_TYPE,
        params: Option<&CK_RSA_PKCS_OAEP_PARAMS>,
    ) -> CK_MECHANISM {
        match params {
            Some(params) => CK_MECHANISM {
                mechanism: mechanism_type,
                pParameter: params as *const CK_RSA_PKCS_OAEP_PARAMS as CK_VOID_PTR,
                ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
            },
            None => CK_MECHANISM {
                mechanism: mechanism_type,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        }
    }

    fn make_oaep_params(
        hash_alg: CK_MECHANISM_TYPE,
        mgf: CK_RSA_PKCS_MGF_TYPE,
        label: &[u8],
    ) -> CK_RSA_PKCS_OAEP_PARAMS {
        CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: hash_alg,
            mgf,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: if label.is_empty() {
                std::ptr::null_mut()
            } else {
                label.as_ptr() as CK_VOID_PTR
            },
            ulSourceDataLen: label.len() as CK_ULONG,
        }
    }

    #[test]
    fn pkcs1_v15_no_params_parses() {
        // Test 1 of the requested set: RSA-PKCS mechanism parsing (no parameters).
        let mechanism = make_mechanism(CKM_RSA_PKCS, None);
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Ok(RsaCipherMechanism::Pkcs1v15)
        );
    }

    #[test]
    fn pkcs1_v15_with_params_rejected() {
        let params = make_oaep_params(CKM_SHA256, CKG_MGF1_SHA256, &[]);
        let mut mechanism = make_mechanism(CKM_RSA_PKCS, Some(&params));
        mechanism.ulParameterLen = std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG;
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Err(CKR_ARGUMENTS_BAD)
        );
    }

    #[test]
    fn oaep_sha1_parses() {
        let params = make_oaep_params(CKM_SHA_1, CKG_MGF1_SHA1, b"label-one");
        let mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, Some(&params));
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Ok(RsaCipherMechanism::Oaep {
                hash_alg: CKM_SHA_1,
                label: b"label-one".to_vec(),
            })
        );
    }

    #[test]
    fn oaep_sha256_parses_with_label() {
        let params = make_oaep_params(CKM_SHA256, CKG_MGF1_SHA256, b"TLS 1.3");
        let mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, Some(&params));
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Ok(RsaCipherMechanism::Oaep {
                hash_alg: CKM_SHA256,
                label: b"TLS 1.3".to_vec(),
            })
        );
    }

    #[test]
    fn oaep_sha384_parses_without_label() {
        let params = make_oaep_params(CKM_SHA384, CKG_MGF1_SHA384, &[]);
        let mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, Some(&params));
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Ok(RsaCipherMechanism::Oaep {
                hash_alg: CKM_SHA384,
                label: Vec::new(),
            })
        );
    }

    #[test]
    fn oaep_sha512_parses() {
        let params = make_oaep_params(CKM_SHA512, CKG_MGF1_SHA512, &[9; 200]);
        let mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, Some(&params));
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Ok(RsaCipherMechanism::Oaep {
                hash_alg: CKM_SHA512,
                label: vec![9; 200],
            })
        );
    }

    #[test]
    fn oaep_mismatched_mgf_rejected() {
        // SHA-256 digest paired with an SHA-1 MGF - valid PKCS #11, but CNG cannot do it.
        let params = make_oaep_params(CKM_SHA256, CKG_MGF1_SHA1, &[]);
        let mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, Some(&params));
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Err(CKR_MECHANISM_INVALID)
        );
    }

    #[test]
    fn oaep_unsupported_hash_rejected() {
        // SHA-224 is not implemented by Windows CNG.
        let params = make_oaep_params(CKM_SHA224, CKG_MGF1_SHA224, &[]);
        let mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, Some(&params));
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Err(CKR_MECHANISM_INVALID)
        );
    }

    #[test]
    fn oaep_invalid_source_rejected() {
        let mut params = make_oaep_params(CKM_SHA256, CKG_MGF1_SHA256, &[]);
        params.source = 2; // not CKZ_DATA_SPECIFIED
        let mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, Some(&params));
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Err(CKR_ARGUMENTS_BAD)
        );
    }

    #[test]
    fn oaep_wrong_parameter_length_rejected() {
        let params = make_oaep_params(CKM_SHA256, CKG_MGF1_SHA256, &[]);
        let mut mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, Some(&params));
        mechanism.ulParameterLen += 1;
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Err(CKR_ARGUMENTS_BAD)
        );
    }

    #[test]
    fn oaep_null_parameter_pointer_rejected() {
        let mut mechanism = make_mechanism(CKM_RSA_PKCS_OAEP, None);
        // Non-zero length advertised, but no parameter buffer given.
        mechanism.ulParameterLen = std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG;
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Err(CKR_ARGUMENTS_BAD)
        );
    }

    #[test]
    fn unsupported_mechanism_rejected() {
        let mechanism = make_mechanism(CKM_SHA256_RSA_PKCS, None);
        assert_eq!(
            parse_rsa_cipher_mechanism("test", &mechanism),
            Err(CKR_MECHANISM_INVALID)
        );
    }
}
