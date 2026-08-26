# NSS regression harness

Loads this crate's real, unmodified PKCS #11 object/attribute code into a real, from-source NSS
build and checks how NSS resolves S/MIME email trust against several generated certificate chains.

## Why this exists

The crate's normal unit tests (`cargo test`) run against `backend_other.rs`'s fixed stub objects --
they check this crate's own state machines (buffer-too-small retries, operation lifetimes, ...) but
never touch a real NSS. That's a blind spot: the two real bugs that blocked S/MIME signing in this
project both lived in how a real NSS build *interprets* the PKCS #11 objects we hand it, not in our
own logic:

- a `CKO_NSS_TRUST` object missing `CKA_NSS_CERT_SHA1_HASH` was silently discarded by NSS's
  `nssTrust_Create` (a positive trust grant requires the hash; only `Unknown`/`NotTrusted` records
  may omit it) -- see the `Trust` doc comment in `src/backend_windows.rs`.
- `C_GetAttributeValue` wasn't updating `ulValueLen` to the actual value length when the caller's
  buffer was larger than needed, so NSS's fixed 64-byte hash-attribute buffer read 44 bytes of
  stack garbage appended to our real 20-byte SHA-1 hash.

Neither was visible to `cargo test`; both were only found by loading a real module into a real,
locally built NSS and watching `vfychain` resolve (or fail to resolve) trust. This harness
automates exactly that, with generated chains instead of hand-picked real certificates, so it can
run in CI/locally without depending on anyone's production certificates.

## How it works

1. `generate_chains.py` (needs the `cryptography` package) generates a handful of `cases/<name>/`
   directories, each a synthetic (root CA, leaf) certificate chain plus a `manifest.txt` and an
   `expect.txt` (`trusted` or `untrusted`).
2. `src/backend_other.rs`'s `nss-regression` Cargo feature (`cargo build --release --features
   nss-regression`) makes `backend_other::list_objects()` read a case's `manifest.txt` (via the
   `OSCLIENTCERTS_NSS_REGRESSION_DIR` environment variable, read at *runtime*, not compile time --
   one build serves every case) instead of returning its normal fixed stub objects, and builds
   `Cert`/`Trust` PKCS #11 objects from it -- including a synthetic `CKO_NSS_TRUST` object shaped
   exactly like the one `backend_windows.rs` emits for a real Windows-trusted root.
3. `run_cases.sh` loads the built `libosclientcerts.so` into a throwaway NSS database (`modutil`)
   for each case and runs `vfychain -u 5` (certUsageEmailRecipient -- the same usage
   `NSS_CMSSignerInfo_AddSMIMEEncKeyPrefs` checks before S/MIME signing) against the leaf
   certificate, comparing the result to `expect.txt`.

## Cases

| Case | Chain | Trust grant | Expected |
| --- | --- | --- | --- |
| `rsa-pkcs1-sha256` | RSA-2048, PKCS#1 v1.5/SHA-256 | full (with SHA-1 hash) | trusted |
| `rsa-pss-sha256` | RSA-2048, leaf signed RSA-PSS/SHA-256 | full | trusted |
| `ecdsa-p256` | ECDSA P-256/SHA-256 | full | trusted |
| `ecdsa-p384` | ECDSA P-384/SHA-384 | full | trusted |
| `missing-sha1-hash` | same as `rsa-pkcs1-sha256` | `CKA_NSS_CERT_SHA1_HASH` omitted | untrusted |
| `no-trust-object` | same as `rsa-pkcs1-sha256` | no trust object at all | untrusted |

The last two are negative controls: they reproduce the historical bug shape and the baseline
"nothing asserts trust" case, so a future change that accidentally grants trust unconditionally, or
that silently breaks the hash requirement again, would flip one of these from `untrusted` to
`trusted` and fail loudly. (Sensitivity was verified by hand: temporarily reintroducing the old
`ulValueLen` bug in `src/lib.rs` flips all four positive cases to `FAIL` while the two negative
controls stay `PASS`, confirming the harness actually catches it.)

## Running it

This is slow (building NSS from source takes a few minutes the first time) and isn't part of the
fast per-push CI. Run it manually before a release, or after touching `src/backend_windows.rs`'s
`Trust`, `src/backend_other.rs`, `src/util.rs`'s `CKA_NSS_*`/`CKT_NSS_*` constants, or
`src/lib.rs`'s `C_GetAttributeValue`:

```sh
# from within the fork-osclientcerts repo:
./scripts/nss-regression-test.sh
```

It reuses an existing NSS checkout/build at `../firefox/security` (Mozilla's `security/` layout) if
present, otherwise clones and builds `https://github.com/mozilla/nss` into
`fork-osclientcerts/.nss-regression-cache/` on first run. See the script's header comment for the
`NSS_SECURITY_DIR`/`NSS_CORES`/`DOCKER_IMAGE` overrides.

CI has the same thing as a manual-only workflow: `.github/workflows/nss-regression.yml`, triggered
from the Actions tab or `gh workflow run nss-regression.yml`.
