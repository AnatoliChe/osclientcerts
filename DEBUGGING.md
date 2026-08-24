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
