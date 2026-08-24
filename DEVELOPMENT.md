# Development guide

Developer and maintainer documentation for the osclientcerts Windows CNG PKCS#11 provider.
For an overview, supported mechanisms, Thunderbird setup and limitations see the
[README](README.md).

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
scripts used during development (store-inspection and patching helpers, Firefox/xul investigation
scripts) live in the surrounding development workspace and are not part of this repository. The
cross-build entry point produces:

```text
out/osclientcerts.dll
```

from the crate sources using the Docker-based toolchain described above.

## Unit tests

The crate includes a unit test suite that runs on an ordinary development host (Linux) inside the
same Docker image used for the Windows cross-build. To make this possible, the RSA cipher
mechanism parsing lives in a platform-neutral module (`src/mechanism.rs`), and a deterministic
stub backend (`src/backend_other.rs`, compiled only for platforms without a real backend) lets the
manager and the PKCS#11 FFI layer be exercised end-to-end without OS crypto APIs:

```text
test-fork-osclientcerts.sh   # cargo test --release in the Docker image
```

Current coverage (40 tests):

- `src/mechanism.rs` - OAEP/PKCS#1 mechanism parsing: SHA-1/256/384/512 parameter sets, label
  handling, mismatched MGF rejection, unsupported digest rejection, invalid source rejection,
  malformed parameter length/pointer rejection.
- `src/lib.rs` (FFI level) - `C_GetMechanismInfo` for `CKM_RSA_PKCS` and `CKM_RSA_PKCS_OAEP`;
  OAEP accepted by `C_DecryptInit` while bad MGF is rejected; `CKR_BUFFER_TOO_SMALL` from
  `C_Decrypt` / `C_Encrypt` does not terminate the active operation (PKCS#11 retry semantics);
  closing a session terminates active decrypt/encrypt operations.
- `src/manager.rs` - session-close cleanup of decrypt/encrypt state; failed length queries do not
  consume operations.
- `src/util.rs` - `CryptoError` to `CK_RV` mapping (platform-specific CNG status mappings are
  asserted on Windows builds), DER helpers.

The stub backend intentionally fails length queries for inputs shorter than 64 bytes with
`CryptoError::BufferTooSmall(128)` and returns fixed-pattern output otherwise, which makes the
buffer-retry state machines deterministically testable.

Note: plaintext/ciphertext size boundaries (RSA PKCS#1 v1.5 `k-11`, OAEP `k-2-2hLen`) are enforced
inside Windows CNG, not in this provider, so they cannot be unit-tested at the provider layer.

## Continuous integration

GitHub Actions run on every push to `trunk` and on pull requests:

| Workflow | Runner | Checks |
|---|---|---|
| `.github/workflows/rust.yml` | `ubuntu-latest` | `cargo fmt --all -- --check`; `cargo test --all-targets`; `cargo clippy --all-targets --all-features -- -D warnings` |
| `.github/workflows/windows.yml` | `windows-latest` | Native MSVC build of `osclientcerts.dll` (uploaded as a workflow artifact); `cargo test --all-targets` on the host target; on a pushed `v*` tag the DLL is attached to a GitHub release |

Notes:

- The unit tests that depend on the stub backend's deterministic behavior run only on
  non-Windows/non-macOS targets; the mechanism-parsing and error-mapping tests run everywhere,
  including the Windows runner.
- The native Windows runner build uses whatever MSVC/Rust versions GitHub installs, so its
  artifact is convenient but **not** the canonical release binary. Release DLLs are built with the
  pinned Docker toolchain described above; CI release automation exists as a fallback/convenience.
- Dependabot keeps Cargo dependencies (weekly) and GitHub Actions (monthly) up to date via PRs;
  updates are proposed, never auto-merged, because a crate update can change ABI, MSRV, FFI types
  or bindgen behavior.

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
[done] Real Thunderbird S/MIME decryption validation
[done] Capture and analyze NSS/PKCS#11 operation traces
[done] PKCS#11-compliant CKR_BUFFER_TOO_SMALL handling for sign/encrypt/decrypt
[done] Cleanup of active operations on session close
[done] RSA-OAEP encryption and decryption (CKM_RSA_PKCS_OAEP)
[done] Rust edition 2024
[done] Unit test suite running in CI on every push
[done] CI: automated Windows DLL build artifacts on GitHub Actions
[pending] Validate RSA-OAEP with Thunderbird/NSS end-to-end
[pending] Validate additional Windows CNG key providers/HSMs
[pending] Consider legacy CAPI/CSP support if required
[pending] Production hardening and broader PKCS#11 compatibility
```

## Design principles

The project follows a few deliberate constraints:

1. **Do not export private keys.**
2. **Use Windows CNG for private-key operations.**
3. **Keep the provider independent of the Gecko runtime.**
4. **Expose only the PKCS#11 interface needed by NSS.**
5. **Prefer real Windows cryptographic operations over copying key material into user-space.**
6. **Add new mechanisms only when an actual NSS/Thunderbird use case requires them.**
