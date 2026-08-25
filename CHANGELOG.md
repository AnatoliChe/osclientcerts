# Changelog

All notable changes to this project are documented in this file. Pre-built DLLs for every release
are published on the GitHub
[releases page](https://github.com/AnatoliChe/osclientcerts/releases).

## 0.3.10 - 2026-08-25

- Private key objects now expose `CKA_LABEL`, `CKA_SUBJECT`, `CKA_ISSUER`, and
  `CKA_SERIAL_NUMBER` derived from the associated certificate. Without these attributes, NSS
  couldn't match private keys to certificates during CMS signing, causing
  `nsCMSEncoder::Finish - can't finish encoder`.

## 0.3.9 - 2026-08-25

- Private key objects now report `CKA_SIGN=TRUE`, `CKA_DECRYPT=TRUE`, `CKA_SENSITIVE=TRUE`,
  `CKA_EXTRACTABLE=FALSE`, `CKA_ALWAYS_AUTHENTICATE=FALSE`, and `CKA_LOCAL=TRUE`. Without
  `CKA_SIGN`, NSS never called `C_SignInit`/`C_Sign`, preventing email signing.

## 0.3.8 - 2026-08-25

- Module lifecycle: `C_Initialize` on an already-initialized module now returns
  `CKR_CRYPTOKI_ALREADY_INITIALIZED`; `C_Finalize` without a prior successful initialization
  returns `CKR_CRYPTOKI_NOT_INITIALIZED`. `C_Finalize` now fully clears the manager proxy slot
  so that a subsequent `C_Initialize` starts from a clean state instead of replacing a lingering
  stopped proxy.
- `C_GetSessionInfo` implemented: returns slot ID, session state (RO vs RW public session), and
  flags (`CKF_SERIAL_SESSION` set unconditionally). `C_OpenSession` now enforces that
  `CKF_SERIAL_SESSION` is set in the caller-supplied flags.
- Windows CNG S/MIME suite: added multipart encrypt/decrypt roundtrip tests for RSA PKCS#1
  v1.5 and OAEP-SHA256, covering the full path from manager-level update buffering through
  `C_EncryptFinal`/`C_DecryptFinal` into real CNG.

## 0.3.7 - 2026-08-25

- `C_EncryptUpdate` and `C_DecryptUpdate` now follow the standard output convention explicitly:
  on success they store zero into the caller's output-length slot (previously the slot was left
  untouched, so a caller reading it per specification would see stale data), a null length
  pointer is rejected with `CKR_ARGUMENTS_BAD`, and any output buffer including a null one is
  accepted. Three tests added.

## 0.3.6 - 2026-08-25

- Soundness: caller-supplied input buffers are now converted to slices through a single
  `input_slice` helper that accepts a null pointer only for zero-length buffers. Previously the
  multipart update functions and search-template attribute handling could pass a null pointer to
  `slice::from_raw_parts` with a zero length, which violates the function's safety contract even
  though no dereference occurs. No behavior change beyond this formal fix; two tests added.

## 0.3.5 - 2026-08-25

- Added multipart operation support: `C_SignUpdate`/`C_SignFinal`,
  `C_EncryptUpdate`/`C_EncryptFinal`, and `C_DecryptUpdate`/`C_DecryptFinal` are now implemented
  instead of returning `CKR_FUNCTION_NOT_SUPPORTED`. Update parts are buffered per session and the
  RSA/ECDSA operation runs once at the `*Final` step; length queries do not consume the pending
  operation and `CKR_BUFFER_TOO_SMALL` retries preserve it.
- The total data accumulated per multipart operation is bounded (64 KiB); exceeding the bound
  fails the update with `CKR_DATA_LEN_RANGE`.
- New tests (12): stub-backend equivalence of multipart and single-shot results for sign,
  encrypt, and decrypt; buffer-too-small retry and session-teardown semantics for pending
  multipart operations; argument guards for the update functions; and a Windows S/MIME test
  proving a real-CNG multipart RSA PKCS#1 v1.5 signature is byte-identical to the single-shot one.

## 0.3.4 - 2026-08-24

- Hardened the C ABI boundary against hostile or buggy callers: `C_FindObjectsInit` and
  `C_GetAttributeValue` now reject absurd template counts, `C_FindObjectsInit` rejects
  inconsistent (`null` pointer with non-zero length) or oversized attribute values,
  `C_Encrypt`/`C_Decrypt`/`C_Sign` reject oversized input buffers, RSA-OAEP parsing bounds the
  label length and requires the label pointer/length pair to be consistent. All violations return
  `CKR_ARGUMENTS_BAD`.
- Added a platform-neutral hostile-input test suite (13 tests, runs in both CI jobs) covering the
  guards above plus graceful handling of zero-count, unsupported-type, and duplicate-attribute
  search templates.
- Corrected the `C_GetMechanismList` doc comment to also list RSA-OAEP.

## 0.3.3 - 2026-08-24

- Internal quality release; no functional changes to the provider.
- Codebase formatted with `rustfmt` (edition 2024 defaults) and made clean under
  `cargo clippy --all-targets --all-features -- -D warnings`.
- CI quality gates on every push/PR: rustfmt check, unit tests, clippy (Linux) and a native MSVC
  Windows build with tests plus automated DLL artifacts/tag releases (Windows).
- Dependabot enabled for Cargo dependencies (weekly PRs) and GitHub Actions versions (monthly).
- The DLL in this release is rebuilt from the reformatted sources; behavior is identical to 0.3.2.

## 0.3.2 - 2026-08-24

- Added a unit test suite (40 tests) that runs on the Linux build host inside the existing Docker
  image (`cargo test`): OAEP/PKCS#1 mechanism parsing, `C_GetMechanismInfo` advertisement,
  PKCS#11 buffer-too-small retry semantics for decrypt/encrypt, session-close operation cleanup,
  and error-code mapping.
- Refactored RSA cipher mechanism parsing into the platform-neutral `src/mechanism.rs` module and
  added a deterministic stub backend (`src/backend_other.rs`) so the manager and FFI layers
  compile and run on non-Windows/non-macOS hosts. No changes to Windows runtime behavior.

## 0.3.1 - 2026-08-23

- Modernized the crate to Rust edition 2024 (up from 2018, inherited from the 2018-era upstream
  project). Required mechanical changes: `#[unsafe(no_mangle)]` for the exported
  `C_GetFunctionList` and an `unsafe extern "C"` block. No functional changes; PKCS#11 behavior is
  identical to 0.3.0.
- Updated crate metadata (repository URL, authors, description) to reflect this fork.

## 0.3.0 - 2026-08-23

- Added RSA-OAEP support (`CKM_RSA_PKCS_OAEP`) for encryption (`C_EncryptInit` / `C_Encrypt` via
  `BCryptEncrypt` with `BCRYPT_OAEP_PADDING_INFO`) and decryption (`C_DecryptInit` / `C_Decrypt`
  via `NCryptDecrypt` with `NCRYPT_PAD_OAEP_FLAG`).
- OAEP parameters are validated at init time: the digest must be SHA-1, SHA-256, SHA-384 or
  SHA-512; MGF1 must use the same hash (a Windows CNG limitation); only `CKZ_DATA_SPECIFIED`
  encoding parameter sources are accepted, and an optional label is passed through to CNG.
- Invalid or unsupported OAEP parameter combinations are rejected up front with
  `CKR_MECHANISM_INVALID` / `CKR_ARGUMENTS_BAD` instead of failing later inside CNG.

## 0.2.0 - 2026-08-23

- First release validated end-to-end with Thunderbird: S/MIME signing, encryption and decryption of
  real messages using non-exportable Windows CNG keys.
- Fixed PKCS#11 semantics: `CKR_BUFFER_TOO_SMALL` returned from `C_Sign` / `C_Encrypt` / `C_Decrypt`
  no longer terminates the active operation; the caller can retry with a larger buffer as the
  specification requires.
- Active operations (search/sign/encrypt/decrypt state) are now cleaned up when their session is
  closed via `C_CloseSession` or `C_CloseAllSessions`.
- Fixed token-object matching so NSS can resolve certificates by issuer/serial and locate private
  keys during S/MIME recipient lookup: boolean attributes are compared in single-byte CK_BBOOL form
  and certificate serial numbers are stored big-endian, matching NSS search templates.
- Added diagnostic logging of enumerated objects (label, id, issuer, serial).

## 0.1.4-fork.1 - 2026-08-23 / 0.1.4-fork.2 - 2026-08-23 / 0.1.4-fork.3 - 2026-08-23

- Early development builds of the fork: restored standalone Windows x64 cross-builds from Linux,
  fixed CNG key discovery and RSA signing against modern toolchains. Superseded by 0.2.0.
