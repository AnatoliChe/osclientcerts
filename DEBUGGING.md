# Debugging

How to capture diagnostic logs from the provider and Thunderbird when S/MIME operations fail.

For basic provider logging (`RUST_LOG=osclientcerts=debug`, launching from a console so stderr is
visible) see the [Debug logging section in the README](README.md#debug-logging). This document
covers capturing the provider log and Thunderbird's own logs at the same time, which is what you
usually need to diagnose S/MIME signing or decryption failures.

## Collecting combined provider and Thunderbird logs

For diagnosing S/MIME problems it is useful to capture both the provider log (stderr, redirected to
a file) and Thunderbird's own NSS/PSM logging (`MOZ_LOG` / `MOZ_LOG_FILE`). A convenient way is a
small `.bat` launcher. Logs are written to `%TEMP%\TBLog` (the per-user temporary directory), so no
admin rights or fixed paths are required:

```bat
@echo off
if not exist "%TEMP%\TBLog" mkdir "%TEMP%\TBLog"

rem Make sure we start a fresh TB process (env vars only reach a new process):
taskkill /IM thunderbird.exe >nul 2>&1
timeout /t 2 /nobreak >nul

cd /d "C:\Program Files\Mozilla Thunderbird"

rem Provider log (env_logger -> stderr), redirected to a file below:
set RUST_LOG=osclientcerts=debug

rem NSS/PSM/S/MIME logs; %%PID%% passes literal %PID% which TB substitutes:
set MOZ_LOG=pipnss:5,smime:5,certverifier:5,timestamp
set MOZ_LOG_FILE=%TEMP%\TBLog\tb-nss-%%PID%%.log

thunderbird.exe > "%TEMP%\TBLog\osclientcerts.log" 2>&1
```

Notes:

- The provider log ends up in `%TEMP%\TBLog\osclientcerts.log`; the Thunderbird logs in
  `%TEMP%\TBLog\tb-nss-<pid>.log` (one per process).
- Paths with `%TEMP%` may contain spaces (e.g. `C:\Users\...\AppData\Local\Temp`), which is why the
  `mkdir` and redirection targets are quoted.
- In a `.bat` file `%%PID%%` is required so that cmd passes the literal `%PID%` placeholder through;
  Thunderbird replaces it with the actual process id.
- `taskkill` guards against the common pitfall of attaching environment variables to an
  already-running Thunderbird instance: a second launch just opens a window of the existing process
  and exits, so no logs are produced.
- `pipnss` shows PKCS#11 module loading and token operations, `smime` shows CMS parsing and the
  S/MIME decrypt path (including whether NSS finds a matching recipient certificate before ever
  calling into the module), `certverifier` shows chain validation.
- Save the file in ANSI encoding if it contains non-ASCII characters; cmd on localized Windows does
  not read UTF-8 batch files correctly.

## What to look for

The most useful provider log lines around an S/MIME decrypt failure:

```text
C_GetMechanismInfo
C_DecryptInit
C_Decrypt
NCryptDecrypt
```

The Windows `SECURITY_STATUS` returned by `NCryptDecrypt` (logged in hexadecimal) should be
preserved when diagnosing failures: it distinguishes key-not-found, padding errors and access
denied (e.g. a PIN prompt that was cancelled on a hardware token).

## S/MIME signing failures

Signing failures tend to look nothing like decrypt failures: there is usually no error and no
failed PKCS#11 call at all. Include `CMS:5` in `MOZ_LOG` (the actual Gecko log module backing the
`D/CMS ...` lines is named `smime`, but the `CMS:5` category has also been seen to be needed for
some of the more specific `nsCMSMessage::*` failure messages to show up -- include both):

```text
set MOZ_LOG=pipnss:5,smime:5,CMS:5,certverifier:5,timestamp
```

Without a specific reason logged, you'll just see:

```text
D/CMS nsCMSMessage::CreateSigned
D/CMS nsCMSEncoder::Start
D/CMS nsCMSEncoder::Finish
D/CMS nsCMSEncoder::Finish - can't finish encoder
```

With `CMS:5` enabled, the actual reason can show up right after `CreateSigned` instead, e.g.:

```text
D/CMS nsCMSMessage::CreateSigned
D/CMS nsCMSMessage::CreateSigned - can't add smime enc key prefs
```

### `can't add smime enc key prefs`

Confirmed root cause (2026-08-25 reproduction, both with the certificate's own KeyUsage/EKU fine
and with Thunderbird's `cert9.db` wiped so no stale/duplicate cert entries were in play -- see
below): this comes from `NSS_CMSSignerInfo_AddSMIMEEncKeyPrefs()`
(`security/nss/lib/smime/cmssiginfo.c`):

```c
SECStatus
NSS_CMSSignerInfo_AddSMIMEEncKeyPrefs(NSSCMSSignerInfo *signerinfo, CERTCertificate *cert, CERTCertDBHandle *certdb)
{
    /* verify this cert for encryption */
    if (CERT_VerifyCert(certdb, cert, PR_TRUE, certUsageEmailRecipient, PR_Now(), ...) != SECSuccess) {
        return SECFailure;
    }
    ...
```

Every outgoing *signed* S/MIME message (regardless of whether it's also encrypted) gets an
`SMIMEEncryptionKeyPreference` signed attribute added, telling the recipient which certificate to
use when replying encrypted. Adding it requires the sender's own certificate to pass a full chain
verification with usage `certUsageEmailRecipient` -- **before any private-key operation**, which
is why `C_SignInit` is never called and this module never sees an error: the failure is entirely
on the NSS/Thunderbird side, in NSS's own (separate from the OS) certificate trust store.

This is expected for certificates from an internal/corporate CA (recognizable by `ldap:///CN=...`
CRL Distribution Point / Authority Information Access URLs, i.e. Active Directory Certificate
Services) that Windows trusts (so `CryptAcquireCertificatePrivateKey`/CNG and Thunderbird's
"Test" button work fine) but that Thunderbird's own NSS trust store does not, since Thunderbird
does not consult the Windows trusted-root store for this check.

Fix (not in this module -- in Thunderbird's certificate store):

1. Settings -> Privacy & Security -> Manage Certificates -> **Authorities** tab.
2. Check whether the issuing CA (and any root above it) is listed. If not, export it from Windows
   (`certmgr.msc` -> Intermediate/Trusted Root Certification Authorities -> Export, DER/CER) and
   **Import** it here.
3. Open its trust settings and check **"This certificate can identify mail users"** -- this is
   exactly the trust bit `certUsageEmailRecipient` checks. Repeat for every CA in the chain.
4. If the CDP/AIA URLs are `ldap://` (AD CS), NSS's own revocation checking may not be able to
   fetch them at all; if the error persists after fixing trust, check whether it's now a
   revocation-check failure rather than a trust failure.

This was reproduced with `cert9.db` deleted entirely (so there was no possibility of a
stale/duplicate cached cert pointing PK11 at the wrong slot -- an earlier, now-ruled-out theory)
and with `KeyUsage=[digitalSignature|keyEncipherment]` confirmed present on the certificate in
use, so those are not the cause here; this CA-trust check is.

and the *first* thing to check in the provider log is whether `C_SignInit` appears at all:

- **If `C_SignInit` *does* appear but returns an error, or `C_Sign`/`NCryptSignHash` fails**, that
  is a module-side (or CNG-side) problem; the existing `error!` logging around `NCryptSignHash`
  (module) will show the Windows `SECURITY_STATUS`.

- **If `C_SignInit`/`C_Sign` never appear in the provider log for that send attempt** (search for
  them; with `RUST_LOG=osclientcerts=debug` they're always logged), NSS decided not to use this
  module's key before ever calling into it. Two known causes, in order of how likely they are to
  be it:

  **1. A stale/duplicate NSS certificate cache entry pointing at the wrong PKCS#11 slot (most
  likely).** Traced directly in the NSS source (`security/nss/lib/`): the signing path
  (`NSS_CMSSignerInfo_Sign` in `smime/cmssiginfo.c`) finds the private key via
  `PK11_FindKeyByAnyCert(cert, ...)` (`pk11wrap/pk11cert.c`), which calls
  `PK11_FindObjectForCert()`. That function's first move is:

  ```c
  if (cert->slot) {
      certHandle = PK11_FindCertInSlot(cert->slot, cert, wincx);
      if (certHandle != CK_INVALID_HANDLE) {
          *pSlot = PK11_ReferenceSlot(cert->slot);
          return certHandle;
      }
  }
  ```

  i.e. if the in-memory `CERTCertificate` object already has a `slot` attached (from wherever NSS
  first resolved this certificate -- e.g. a copy that ended up cached in Thunderbird's own
  `cert9.db`/"Software Security Device" the same certificate is *also* sitting in, separately from
  this module's token), it looks for the private key **only on that cached slot** and never falls
  back to searching every loaded PKCS#11 module (ours included). If that cached slot has no
  private key for the cert, `PK11_MatchItem(..., CKO_PRIVATE_KEY)` comes back empty,
  `PK11_FindKeyByAnyCert` returns `NULL`, and `NSS_CMSSignerInfo_Sign` bails out via its `loser:`
  label -- before ever touching a PKCS#11 module for the actual sign operation. This matches the
  symptom exactly: zero errors, `C_FindObjectsInit`/`C_GetAttributeValue` still happening
  constantly in the log for the background cert-list scan, but `C_SignInit` never called for the
  send attempt itself. Decryption is unaffected because the recipient-key lookup for an incoming
  message goes through a fresh issuer+serial search across all slots rather than a cached
  `CERTCertificate->slot`, so it isn't vulnerable to this.

  To check: open Thunderbird's Certificate Manager (Settings -> Privacy & Security -> Manage
  Certificates) -> "Your Certificates", find the certificate configured for signing, and see
  whether it's listed more than once -- once under this module's security device/token, and again
  under "Software Security Device" (NSS's internal database). If it appears twice, delete the
  "Software Security Device" copy (it has no private key and is the one poisoning `cert->slot`);
  keep the one exposed by this module. A more drastic fallback if that doesn't turn up a duplicate
  is renaming/backing up the profile's `cert9.db` so NSS rebuilds its internal cert cache from
  scratch (this also clears any manually-set trust bits on other certificates, so back it up
  first).

  **2. Certificate `KeyUsage` doesn't include `digitalSignature`.** `list_objects()` (called
  whenever the module rescans the certificate store) logs a `KeyUsage=[...] EKU=[...]` line for
  every certificate it finds, at `warn!` level if `digitalSignature` is missing:

  ```text
  [WARN  osclientcerts::backend_windows] cert "...": KeyUsage=[keyEncipherment] does NOT include
  digitalSignature -- NSS will silently refuse to use this key for S/MIME signing even though it
  may work fine for decryption; EKU=[1.3.6.1.5.5.7.3.4 (emailProtection)]
  ```

  Note this is *not* enforced in the version of `NSS_CMSSignerInfo_Sign` checked against
  (`security/nss/lib/smime/cmssiginfo.c` in this tree has no `CERT_CheckKeyUsage` call at all), so
  don't assume it's the cause without seeing the warning for the actual certificate in use --
  check cause 1 first.

Also useful: `manager.rs`'s `start_sign` now logs the PKCS#11 key handle and key ID NSS asked to
sign with (`start_sign: session ..., key handle ..., id ...`), and `Key::matches` (used by
`C_FindObjectsInit`/`C_FindObjects` to locate the private key object) logs which attribute
comparison failed when a search comes up empty. If NSS is searching for a private key using
different attributes than what the module stored (e.g. after a certificate is renewed but the
private key's cached label/subject is stale), those log lines will show the mismatch directly.
