# osclientcerts — Windows CNG PKCS#11 Provider

A standalone Windows PKCS#11 provider based on Mozilla's historical `osclientcerts` project, extended for use with Thunderbird/NSS and Windows CNG-backed certificates and private keys.

> **Project status:** experimental. The provider builds as a standalone Windows x64 DLL and implements RSA encryption/decryption in addition to the original signing functionality. Real-world Thunderbird/S/MIME interoperability is the next validation stage.

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

## Architecture

The provider consists of three main layers.

### PKCS#11 entry points

`src/lib.rs` implements the PKCS#11 module interface and exposes the standard `C_GetFunctionList` entry point.

The application talks to the provider through operations such as:

```text
C_Initialize
C_GetSlotList
C_GetTokenInfo
C_GetMechanismList
C_GetMechanismInfo
C_OpenSession
C_FindObjectsInit
C_FindObjects
C_GetAttributeValue
C_SignInit / C_Sign
C_EncryptInit / C_Encrypt
C_DecryptInit / C_Decrypt
C_Finalize
```

The provider currently exposes a single virtual PKCS#11 slot containing the Windows-backed objects.

### Manager layer

`src/manager.rs` owns PKCS#11 session state, object handles and active cryptographic operations.

A single `Manager` thread is used because the Windows APIs involved are not assumed to be safe to call concurrently from arbitrary PKCS#11 threads.

The manager tracks separate operation state for:

```text
signs
encrypts
decrypts
```

Cryptographic failures are propagated through `CryptoError` instead of being reduced immediately to a generic `CKR_GENERAL_ERROR`.

### Windows backend

`src/backend_windows.rs` performs the actual Windows cryptographic operations.

The backend currently uses:

```text
CertOpenStore
CertFindCertificateInStore
CryptAcquireCertificatePrivateKey
NCryptSignHash
NCryptDecrypt
CryptImportPublicKeyInfoEx2
BCryptEncrypt
```

The Windows implementation targets CNG/NCRYPT-backed private keys. Legacy CryptoAPI/CAPI-only private-key handling is currently out of scope.

## Supported key types

### RSA

RSA keys are currently used for:

- PKCS#1 v1.5 signing
- RSA-PSS signing
- RSA PKCS#1 v1.5 decryption
- RSA PKCS#1 v1.5 encryption using the certificate public key

### EC

EC keys are supported for signing through Windows CNG and `NCryptSignHash`.

EC decryption is not implemented.

## Supported PKCS#11 mechanisms

The provider currently advertises:

| Mechanism | Operation | Windows implementation | Status |
|---|---|---|---|
| `CKM_RSA_PKCS` | Sign | `NCryptSignHash` | Supported |
| `CKM_RSA_PKCS` | Decrypt | `NCryptDecrypt` + `NCRYPT_PAD_PKCS1_FLAG` | Implemented; Thunderbird/S/MIME validation pending |
| `CKM_RSA_PKCS` | Encrypt | `BCryptEncrypt` + RSA PKCS#1 padding | Implemented |
| `CKM_RSA_PKCS_PSS` | Sign | `NCryptSignHash` + PSS | Supported |
| `CKM_ECDSA` | Sign | `NCryptSignHash` | Supported |

(`CKM_RSA_PKCS_OAEP` is not implemented and therefore not advertised.)

The provider currently does not implement streaming RSA operations through:

```text
C_EncryptUpdate / C_EncryptFinal
C_DecryptUpdate / C_DecryptFinal
```

RSA encryption/decryption is implemented as a single-shot operation through `C_Encrypt` / `C_Decrypt`.

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

## Modern Rust compatibility

The historical project used old dependencies that no longer build cleanly with current Rust toolchains.

The fork has been updated to modernize the dependency stack while keeping the original provider architecture.

Current relevant dependencies include:

```text
Rust edition: 2018
pkcs11:      0.5
bindgen:     0.72
winapi:      0.3
sha2:        0.8
```

The migration also replaces legacy `static mut` reference patterns with safer raw-pointer/address-of handling where required by newer Rust versions.

## Native Windows build

The crate can be built natively on Windows with a Rust MSVC toolchain and Visual Studio Build Tools:

```bash
cargo build --release
```

Expected output:

```text
target/release/osclientcerts.dll
```

## Linux → Windows cross-build

The development environment used for this project builds the Windows DLL on Linux inside Docker.

The cross toolchain is based on:

```text
Debian 12
Clang / clang-cl
LLD / lld-link
Windows SDK 10.0.26100.0
MSVC headers and libraries
Rust x86_64-pc-windows-msvc
```

The Docker image used by the current development environment is:

```text
mozilla-win-cross-builder
```

The image contains the Rust toolchain and mounted Mozilla/MSVC/Windows SDK artifacts used by the cross-build scripts.

Because Windows SDK headers assume a case-insensitive filesystem, the Linux build creates a compatibility mirror with include-name aliases such as:

```text
Windows.h / windows.h
WinUser.h / winuser.h
PropIdl.h / propidl.h
DriverSpecs.h / driverspecs.h
```

This is required for bindgen and Clang to process the Windows SDK correctly on a case-sensitive Linux filesystem.

## Development workflow notes

The repository itself contains only the Rust crate. The Linux/Docker cross-build and diagnostic
scripts used during development (`build-fork-osclientcerts.sh`, store-inspection and patching
helpers, Firefox/xul investigation scripts) live in the surrounding development workspace and are
not part of this repository. The primary cross-build entry point produces:

```text
out/osclientcerts.dll
```

from the crate sources using the Docker-based toolchain described above.

## Important upstream/research repositories

### Mozilla historical osclientcerts

https://github.com/mozkeeler/osclientcerts

The original standalone project and the primary source for the current architecture.

### Mozilla Firefox

https://github.com/mozilla-firefox/firefox

Used for comparison with the modern in-tree implementation and to understand the current Mozilla code and Windows certificate integration.

### p11-capi

https://github.com/risacher/p11-capi/

Historical Windows PKCS#11 provider based on CryptoAPI. A prebuilt DLL was tested with Thunderbird during the investigation. It was able to expose certificates but did not solve the S/MIME decryption problem, so it remains a reference implementation rather than the current base.

## Current project status

```text
[done] Historical standalone osclientcerts source identified
[done] Fork created
[done] Windows certificate enumeration retained
[done] Windows CNG private-key discovery retained
[done] RSA signing
[done] RSA-PSS signing
[done] ECDSA signing
[done] RSA PKCS#1 v1.5 encryption
[done] RSA PKCS#1 v1.5 decryption path
[done] C_GetMechanismInfo implementation
[done] Improved PKCS#11 return-code handling
[done] Modern Rust / pkcs11 / bindgen compatibility updates
[done] Standalone Windows x64 DLL builds from Linux/Docker
[pending] Real Thunderbird S/MIME decryption validation
[pending] Capture and analyze NSS/PKCS#11 operation traces
[pending] Add RSA-OAEP if Thunderbird/NSS requires it
[pending] Validate additional Windows CNG key providers/HSMs
[pending] Consider legacy CAPI/CSP support if required
[pending] Production hardening and broader PKCS#11 compatibility
```

## Current limitations

The current provider is intentionally narrow.

- Windows CNG/NCRYPT keys are supported; legacy CAPI/CSP private-key providers are not currently supported.
- RSA PKCS#1 v1.5 is the current decryption mechanism.
- RSA-OAEP is not implemented.
- EC decryption is not implemented.
- Multi-part `C_EncryptUpdate` / `C_EncryptFinal` and `C_DecryptUpdate` / `C_DecryptFinal` are not implemented.
- The provider currently focuses on the Windows user's `My` certificate store.
- Real Thunderbird/NSS S/MIME interoperability remains the key validation target.

## Thunderbird testing

The provider is intended to be loaded by Thunderbird as a PKCS#11 security module.

The basic workflow is:

1. Build `osclientcerts.dll`.
2. Copy it to a stable Windows path.
3. Add it through Thunderbird's certificate/security-device management UI
   (Settings → Privacy & Security → Certificates → Security Devices → Load).
4. Verify that certificates from the Windows store are visible.
5. Select an appropriate certificate for S/MIME signing/encryption.
6. Test opening an S/MIME message encrypted for the corresponding certificate.
7. Collect provider/NSS logs if decryption fails.

Note that Thunderbird keeps the DLL loaded (and locked) while it runs: after rebuilding the DLL,
remove and re-add the module in the Security Devices dialog, or simply restart Thunderbird with
the updated file at the same path.

The most useful diagnostics are the provider logs around:

```text
C_GetMechanismInfo
C_DecryptInit
C_Decrypt
NCryptDecrypt
```

The Windows `SECURITY_STATUS` returned by `NCryptDecrypt` should be preserved when diagnosing failures.

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

## Design principles

The project follows a few deliberate constraints:

1. **Do not export private keys.**
2. **Use Windows CNG for private-key operations.**
3. **Keep the provider independent of the Gecko runtime.**
4. **Expose only the PKCS#11 interface needed by NSS.**
5. **Prefer real Windows cryptographic operations over copying key material into user-space.**
6. **Add new mechanisms only when an actual NSS/Thunderbird use case requires them.**

## License

The project is based on Mozilla's `osclientcerts` and remains licensed under the Mozilla Public License 2.0 (MPL-2.0).

See [`LICENSE`](LICENSE).
