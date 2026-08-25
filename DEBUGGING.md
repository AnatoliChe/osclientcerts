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
set MOZ_LOG=pipnss:5,CMS:5,certverifier:5,psm:5,smime:5,timestamp
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
- `CMS:5` is a separate log category from `smime:5` (both back lines printed with the `D/CMS`
  prefix) and is needed to see some of the more specific `nsCMSMessage::*` failure reasons -- with
  only `smime:5`/`pipnss:5`/`certverifier:5`, a signing failure may show up only as the generic
  `nsCMSEncoder::Finish - can't finish encoder` with no indication of why; adding `CMS:5` can turn
  that into a specific line such as `nsCMSMessage::CreateSigned - can't add smime enc key prefs`
  (see "S/MIME signing failures" below). Include both. `psm:5` (Personal Security Manager, the
  Thunderbird/Firefox component that owns the S/MIME cert selection and NSS trust checks) was also
  enabled when this specific reason first showed up; its individual contribution wasn't isolated
  from `CMS:5`, but it's cheap to leave on.
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
failed PKCS#11 call at all. The first thing to check in the provider log is whether `C_SignInit`
appears at all for the send attempt (with `RUST_LOG=osclientcerts=debug` it's always logged):

- **If `C_SignInit` appears but returns an error, or `C_Sign`/`NCryptSignHash` fails**, that is a
  module-side (or CNG-side) problem; the `error!` logging around `NCryptSignHash` shows the
  Windows `SECURITY_STATUS`.
- **If `C_SignInit`/`C_Sign` never appear at all**, NSS decided not to use this module's key
  before ever calling into it -- nothing will show up as a module error, because the module was
  never asked. With just `smime:5`, you'll typically only see the generic:

  ```text
  D/CMS nsCMSMessage::CreateSigned
  D/CMS nsCMSEncoder::Start
  D/CMS nsCMSEncoder::Finish
  D/CMS nsCMSEncoder::Finish - can't finish encoder
  ```

  Adding `CMS:5` to `MOZ_LOG` (see above) can reveal the actual reason right after
  `CreateSigned` instead, e.g.:

  ```text
  D/CMS nsCMSMessage::CreateSigned
  D/CMS nsCMSMessage::CreateSigned - can't add smime enc key prefs
  ```

  A confirmed cause of exactly this message: every outgoing *signed* S/MIME message (regardless of
  whether it's also encrypted) gets an `SMIMEEncryptionKeyPreference` attribute added to the
  signature, telling the recipient which certificate to use when replying encrypted. Adding it
  requires the sender's own certificate to pass a full chain verification for
  `certUsageEmailRecipient` -- **in Thunderbird's own NSS certificate store, before any
  private-key operation**. This is why `C_SignInit` is never called and it looks like nothing
  happened: the failure is entirely on the NSS/Thunderbird side.

  This shows up for certificates from an internal/corporate CA that Windows trusts (so
  `CryptAcquireCertificatePrivateKey`/CNG and Thunderbird's "Test" button work fine) but that
  hasn't been imported and marked trusted in Thunderbird's own certificate store -- see
  [the installation notes in the README](README.md#thunderbird-installing) for the fix.
