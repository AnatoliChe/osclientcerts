# osclientcerts — Windows CNG PKCS#11 Provider

A standalone Windows PKCS#11 provider based on Mozilla's historical `osclientcerts` project, extended for use with Thunderbird/NSS and Windows CNG-backed certificates and private keys.

[![Rust checks](https://github.com/AnatoliChe/osclientcerts/actions/workflows/rust.yml/badge.svg)](https://github.com/AnatoliChe/osclientcerts/actions/workflows/rust.yml)
[![Windows build](https://github.com/AnatoliChe/osclientcerts/actions/workflows/windows.yml/badge.svg)](https://github.com/AnatoliChe/osclientcerts/actions/workflows/windows.yml)

> **Project status:** working. The provider builds as a standalone Windows x64 DLL and implements RSA signing, encryption and decryption (PKCS#1 v1.5 and OAEP) as well as RSA-PSS and ECDSA signing on top of the original signing-only upstream code - each operation in both single-shot and multipart form. Real-world Thunderbird S/MIME interoperability (signing, sending encrypted mail and decrypting received mail with non-exportable CNG keys) has been validated. The provider is covered by a two-tier test suite that runs in CI on every push: a platform-neutral unit test suite (mechanism parsing, PKCS#11 operation state machines, error-code mapping, hostile-input guards at the C ABI boundary) and a Windows-only S/MIME regression suite that runs against real Windows CNG keys provisioned on the CI runner.
>
> Release history: [CHANGELOG.md](CHANGELOG.md)
> Developer documentation (architecture, building, tests, CI): [DEVELOPMENT.md](DEVELOPMENT.md)
> Troubleshooting S/MIME (combined provider + Thunderbird logs): [DEBUGGING.md](DEBUGGING.md)

## Goal

The project aims to make certificates and **non-exportable private keys stored in the Windows certificate/CNG infrastructure** available to applications through the standard PKCS#11 interface — including hardware-backed keys when exposed through the Windows CNG/NCRYPT interface.

The primary use case is S/MIME in Thunderbird:

```text
Thunderbird
    │
    ▼
NSS / PKCS#11
    │
    ▼
osclientcerts.dll
    │
    ├── enumerate certificates
    ├── expose private-key objects
    ├── sign
    ├── decrypt
    └── encrypt
    │
    ▼
Windows certificate store / CNG
    │
    ├── CertOpenStore / CertFindCertificateInStore
    ├── CryptAcquireCertificatePrivateKey
    ├── NCryptSignHash
    ├── NCryptDecrypt
    └── BCryptEncrypt
```

The private key itself is not exported from Windows. The provider obtains a Windows key handle and asks the Windows cryptographic subsystem to perform the operation.

## Background

The project started from the historical Mozilla repository:

- **Original:** https://github.com/mozkeeler/osclientcerts
- **Fork:** https://github.com/AnatoliChe/osclientcerts
- **Mozilla/Firefox source:** https://github.com/mozilla-firefox/firefox
- **Historical p11-capi project:** https://github.com/risacher/p11-capi/

The original `osclientcerts` implementation already provided a useful Windows backend for certificate enumeration and signing. It was therefore used as the base instead of extracting the modern Firefox `osclientcerts` crate.

The modern Firefox implementation is tightly coupled to Gecko/XPCOM and is not a convenient standalone DLL. The current project intentionally keeps the provider independent of the Firefox runtime.

## Supported key types

### RSA

RSA keys are currently used for:

- PKCS#1 v1.5 signing
- RSA-PSS signing
- RSA PKCS#1 v1.5 decryption
- RSA PKCS#1 v1.5 encryption using the certificate public key
- RSA-OAEP decryption
- RSA-OAEP encryption using the certificate public key

### EC

EC keys are supported for signing through Windows CNG and `NCryptSignHash`.

EC decryption is not implemented.

## Supported PKCS#11 mechanisms

The provider currently advertises:

| Mechanism | Operation | Windows implementation | Status |
|---|---|---|---|
| `CKM_RSA_PKCS` | Sign | `NCryptSignHash` | Supported |
| `CKM_RSA_PKCS` | Decrypt | `NCryptDecrypt` + `NCRYPT_PAD_PKCS1_FLAG` | Implemented and validated with Thunderbird S/MIME |
| `CKM_RSA_PKCS` | Encrypt | `BCryptEncrypt` + RSA PKCS#1 padding | Implemented |
| `CKM_RSA_PKCS_PSS` | Sign | `NCryptSignHash` + PSS | Supported |
| `CKM_RSA_PKCS_OAEP` | Decrypt | `NCryptDecrypt` + `NCRYPT_PAD_OAEP_FLAG` | Implemented (not yet validated with Thunderbird) |
| `CKM_RSA_PKCS_OAEP` | Encrypt | `BCryptEncrypt` + `BCRYPT_OAEP_PADDING_INFO` | Implemented (not yet validated with Thunderbird) |
| `CKM_ECDSA` | Sign | `NCryptSignHash` | Supported |

(`CKM_RSA_PKCS_OAEP` is advertised as of version 0.3.0.)

RSA-OAEP restrictions imposed by Windows CNG:

- The MGF1 hash function must be the same as the digest algorithm (`CKG_MGF1_SHA1` for
  `CKM_SHA_1`, and so on). Requests that specify a different MGF are rejected with
  `CKR_MECHANISM_INVALID`.
- Supported digest algorithms: SHA-1, SHA-256, SHA-384, SHA-512. SHA-224 is not implemented by
  CNG.
- Only the `CKZ_DATA_SPECIFIED` encoding parameter source is supported; the optional label is
  passed to CNG via `BCRYPT_OAEP_PADDING_INFO.pbLabel`.

All supported operations are available both as single-shot calls and as buffered multipart
operations (see below).

### Multipart operations

The multipart families `C_SignUpdate`/`C_SignFinal`, `C_EncryptUpdate`/`C_EncryptFinal`, and
`C_DecryptUpdate`/`C_DecryptFinal` are implemented. Because RSA and ECDSA operations require the
complete message in one call, update parts are buffered per session and the underlying operation
runs once at the `*Final` step. PKCS#11 semantics are preserved:

- a length query (`*Final` with a null output pointer) does not consume the pending operation;
- `CKR_BUFFER_TOO_SMALL` reports the required size and leaves the operation active for a retry;
- closing a session discards any buffered parts along with the operation;
- the total data accumulated per operation is bounded (64 KiB); exceeding the bound fails the
  update with `CKR_DATA_LEN_RANGE`.

The FFI boundary validates all caller-supplied counts, lengths, and pointer/length consistency
and returns `CKR_ARGUMENTS_BAD` for malformed arguments rather than dereferencing them.

## Windows certificate and key discovery

The Windows backend currently searches the current user's personal certificate store (`My`) for certificates that have private keys.

Each certificate is exposed as a PKCS#11 certificate object. The associated private key is exposed as a PKCS#11 private-key object using the same certificate-derived identifier.

The identifier is derived from the certificate DER data using SHA-256.

For private keys, the backend obtains the key handle with:

```text
CryptAcquireCertificatePrivateKey(
    ...,
    CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
    ...
)
```

This means the current implementation deliberately requires the key to be accessible through Windows CNG/NCRYPT.

## Current limitations

The current provider is intentionally narrow.

- Windows CNG/NCRYPT keys are supported; legacy CAPI/CSP private-key providers are not currently supported.
- RSA PKCS#1 v1.5 and RSA-OAEP are the supported decryption mechanisms. For RSA-OAEP, CNG requires
  MGF1 to use the same hash as the digest algorithm (SHA-1/SHA-256/SHA-384/SHA-512 only), and only
  `CKZ_DATA_SPECIFIED` labels are supported.
- EC decryption is not implemented.
- The provider currently focuses on the Windows user's `My` certificate store.

## Thunderbird installing

The provider is intended to be loaded by Thunderbird as a PKCS#11 security module.

The basic workflow is:

1. Download a pre-built `osclientcerts.dll` from the
   [releases page](https://github.com/AnatoliChe/osclientcerts/releases) (or build it yourself -
   see [DEVELOPMENT.md](DEVELOPMENT.md)).
2. Copy it to a stable Windows path.
3. Add it through Thunderbird's certificate/security-device management UI
   (Settings → Privacy & Security → Certificates → Security Devices → Load).
4. Verify that certificates from the Windows store are visible.
5. If the certificate chain is issued by a CA that isn't one of the public CAs Mozilla ships
   trust for (e.g. an internal/corporate CA), import and trust that CA in **Thunderbird's own**
   certificate store too -- see "Certificate trust: Windows vs. Thunderbird" below. This is
   required for S/MIME **signing** even when messages aren't encrypted.
6. Select an appropriate certificate for S/MIME signing/encryption.
7. Test opening an S/MIME message encrypted for the corresponding certificate, and sending a
   signed message.
8. Collect provider/NSS logs if signing or decryption fails.

Note that Thunderbird keeps the DLL loaded (and locked) while it runs: after rebuilding the DLL,
remove and re-add the module in the Security Devices dialog, or simply restart Thunderbird with
the updated file at the same path.

If decryption or signing fails, see [DEBUGGING.md](DEBUGGING.md) for collecting provider and
Thunderbird logs.

### Certificate trust: Windows vs. Thunderbird

This provider only bridges Windows' certificate store and private keys into PKCS#11; it does not
bridge certificate **trust**. Windows and Thunderbird each keep their own, independent trust
store, and both need to consider the relevant CA trusted:

- **Windows** needs to trust the certificate chain for `CryptAcquireCertificatePrivateKey`/CNG to
  work at all (this is usually already the case for a corporate machine joined to the domain that
  issued the certificate, e.g. via Active Directory Certificate Services group policy).
- **Thunderbird** (via NSS) keeps a *separate* certificate/trust database and does not consult
  Windows' trust store. For an internal/corporate CA, this normally needs to be set up manually:
  Settings → Privacy & Security → Manage Certificates → **Authorities** → Import the issuing CA
  (export it from Windows first, e.g. via `certmgr.msc` → Intermediate/Trusted Root Certification
  Authorities → Export, DER/CER), then edit its trust settings and check **"This certificate can
  identify mail users"**. Repeat for every CA in the chain if there's more than one level.

  This step is required for **signing**, not just for decrypting/verifying other people's
  messages: every outgoing signed S/MIME message includes a signed attribute referencing the
  sender's own certificate for encrypted replies, and building that attribute requires the
  sender's certificate to verify as trusted in Thunderbird's own store first. Without it, sending
  a signed message fails silently (no error dialog, nothing logged by this module) -- see
  [DEBUGGING.md](DEBUGGING.md#smime-signing-failures) for how to diagnose it.

  **Gotcha:** importing the CA while this module is already loaded as a Security Device can
  silently fail to set the trust flag, because Thunderbird already "knows" the CA as the issuer of
  certificates coming from this module and skips the import. If the CA doesn't show up as
  importable, or the import doesn't seem to stick, unload the module first (Security Devices →
  select it → Unload), do the import + trust step above, then reload the module.

## Debug logging

The provider uses `log` and `env_logger`.

For example:

```text
RUST_LOG=osclientcerts=debug
```

Important: on Windows a GUI application's stderr is not visible anywhere by default. To see the
provider logs, launch Thunderbird from a console so its stderr is attached to that console:

```bat
cd "C:\Program Files\Mozilla Thunderbird"
set RUST_LOG=osclientcerts=debug
thunderbird.exe
```

(PowerShell users: `$env:RUST_LOG="osclientcerts=debug"` instead of `set`.)

The diagnostic output is intended to reveal:

- PKCS#11 calls
- selected mechanisms
- object handles
- encryption/decryption sizes
- signing/decryption operations
- Windows CNG status codes (hexadecimal `SECURITY_STATUS` values)

For diagnosing S/MIME problems you can capture the provider log together with Thunderbird's own
NSS/PSM logs (`MOZ_LOG`) using a small `.bat` launcher - see [DEBUGGING.md](DEBUGGING.md).

## License

The project is based on Mozilla's `osclientcerts` and remains licensed under the Mozilla Public License 2.0 (MPL-2.0).

See [`LICENSE`](LICENSE).
