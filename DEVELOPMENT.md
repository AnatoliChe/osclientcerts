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
Rust edition: 2024
pkcs11:      0.5   (0.5.0)
bindgen:     0.72  (0.72.1)
winapi:      0.3   (0.3.9)
sha2:        0.8   (0.8.2)
byteorder:   1.3
env_logger:  0.6   (default-features = false, see below)
log:         0.4
lazy_static: 1
```

### Dependency version policy

Several dependency lines look old next to edition 2024 - this is deliberate:

- **Upstream parity.** The dependency set is inherited from Mozilla's original project; keeping
  the same major/minor lines minimizes divergence from upstream when porting fixes.
- **`winapi` 0.3 is not an "old version"** - it is the final published line of an archived crate
  (its successor is `windows-sys`). "Updating" would mean rewriting all FFI declarations in the
  Windows backend, which carries real regression risk for zero user-visible benefit; it is
  deliberately deferred.
- **`env_logger` stays on 0.6 with `default-features = false`** so the `regex` engine is not
  compiled into the DLL (binary size). Newer majors would require re-validating size and logging
  behavior.
- **`sha2` is used for a single fixed purpose** (SHA-256 over certificate DER for `CKA_ID`
  derivation), so there has been no motivation to take on API churn from the 0.10 refactor.

Dependency updates arrive as weekly Dependabot proposals and are reviewed individually - never
auto-merged, because a crate update can change ABI, MSRV, FFI types or bindgen behavior. Any
accepted update changes the shipped DLL and therefore goes through the normal release process.

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

Current coverage (40 tests on Linux; the Windows runner additionally executes a
Windows-only regression suite, see below):

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

### S/MIME regression tests (Windows runner only)

`src/manager.rs` also contains a `cfg(all(test, target_os = "windows"))` suite that runs against
the **real** CNG backend inside the CI Windows job. Self-signed RSA-2048 and ECDSA P-256 marker
certificates (`osclientcerts-smime-rsa`, `osclientcerts-smime-ec`, non-exportable keys) are
provisioned by `scripts/provision-smime-test-certs.ps1` before the test step. The tests cover the
historical regression classes listed above at a higher level:

- discovery of both certificates and their attributes (`CKA_CLASS`, `CKA_TOKEN`, issuer/serial,
  DER `CKA_VALUE`);
- private-key-to-certificate linkage via `CKA_ID`;
- RSA PKCS#1 v1.5 signatures over NSS-style `DigestInfo` (modulus-size output plus determinism,
  which pins down both mechanism and input);
- RSA-PSS signatures (SHA-256, MGF1, 32-byte salt; randomized per signature);
- ECDSA P-256 signatures returned as raw `r || s` per the PKCS#11 `CKM_ECDSA` spec;
- RSA PKCS#1 v1.5 and OAEP (SHA-256, label) encrypt/decrypt roundtrips;
- closing a session terminates an in-progress real signing operation;
- store-level private-key association for both provisioned certificates, verified directly via
  crypt32 (`CryptAcquireCertificatePrivateKey` with `CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG`) without
  involving the provider: the certificate must exist in `CurrentUser\My`, carry an accessible
  private key, and that key must be reported as `CERT_NCRYPT_KEY_SPEC` (CNG/NCrypt), guarding
  against provisioning changes that would leave a certificate without a discoverable CNG key.

Because signatures are opaque values (the result of the private-key operation), structural checks
rely on mechanism-level properties - deterministic vs randomized encodings and exact output sizes -
rather than byte layouts of encoded messages.

### Multipart operations

The provider supports the multipart families `C_EncryptUpdate`/`C_EncryptFinal`,
`C_DecryptUpdate`/`C_DecryptFinal`, and `C_SignUpdate`/`C_SignFinal`. Because RSA (and ECDSA)
private-key operations require the complete message in one call, update parts are **buffered** in
the per-session operation state and the underlying operation runs once at the `*Final` step.
Semantics follow the PKCS #11 specification:

- a length query (`*Final` with a null output pointer) determines the required output size without
  consuming the operation;
- `CKR_BUFFER_TOO_SMALL` on a real `*Final` attempt reports the required size and leaves the
  operation active for a retry;
- closing a session discards any buffered parts along with the operation;
- the total amount of buffered data per operation is bounded
  (`MAX_TOTAL_OPERATION_DATA_LEN`, 64 KiB); exceeding it fails the update with `CKR_DATA_LEN_RANGE`.

Stub-backend tests verify that multipart results equal single-shot results over the concatenated
input, that buffer-too-small retries preserve the pending operation, and that abandoned sessions
cannot be finished. The Windows S/MIME suite adds an end-to-end check against real CNG: a
multipart RSA PKCS#1 v1.5 signature must be byte-identical to the deterministic single-shot
signature over the same DigestInfo.

### Hostile-input tests (FFI boundary, all platforms)

The exported `C_*` functions are the library's attack surface: any process that loads the DLL can
pass arbitrary values through the C ABI. `src/lib.rs` contains a
`cfg(test) mod ffi_hardening_tests` suite (platform-neutral, runs in both CI jobs) that calls the
exported functions directly with hostile arguments and asserts they return error codes instead of
crashing:

- `C_GetAttributeValue` / `C_FindObjectsInit`: null template pointers and absurd template counts;
- `C_FindObjectsInit`: attribute entries with a null value pointer but non-zero length, or with
  lengths above the sane bound; plus graceful handling of legal-but-unusual templates
  (zero-count match-all searches, unsupported attribute types, duplicate types);
- `C_Encrypt` / `C_Decrypt` / `C_Sign`: oversized input buffers;
- `C_EncryptUpdate` / `C_DecryptUpdate` / `C_SignUpdate`: null parts with non-zero lengths and
  oversized parts, exactly as for their single-shot counterparts.

The corresponding bounds live in constants next to the FFI layer (`MAX_TEMPLATE_COUNT = 128`,
`MAX_ATTRIBUTE_VALUE_LEN = 64 KiB`, `MAX_DATA_LEN = 64 KiB`, `MAX_OAEP_LABEL_LEN = 8 KiB`) and
every violation returns `CKR_ARGUMENTS_BAD`. RSA-OAEP mechanism-parameter parsing is hardened and
unit-tested separately in `src/mechanism.rs` (wrong parameter length, null parameter pointer,
unsupported hash/MGF/source combinations, inconsistent label pointer/length pairs, oversized
labels).

Threat-model note: these guards defend everything that is *definable* in-process - counts,
lengths, and null/non-null consistency. A caller passing a **valid-looking but invalid** non-null
pointer cannot be defended against by any in-process check (that remains part of the C calling
contract); the tests therefore only exercise inputs where validation happens before the first
dereference.

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
