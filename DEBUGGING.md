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
  Thunderbird's own NSS certificate store doesn't consider trusted for email. As of this version,
  the provider itself bridges this automatically for CAs present in Windows' "Trusted Root
  Certification Authorities" store (see "Certificate trust: Windows vs. Thunderbird" in
  [README.md](README.md#thunderbird-installing)) -- check the provider log for `granting NSS
  email trust to Windows-trusted root CA "..."`. If that line is missing for your CA, either it
  isn't in the Windows ROOT store specifically, or its EKU excludes email protection (both logged
  at `debug` level); either way, the manual Thunderbird import documented in the README is the
  fallback.

## S/MIME signature verification failures ("invalid signature" on *incoming* mail)

This is a different failure from the signing case above: Thunderbird shows the sender's
certificate chain as fully resolved and trusted, but still flags the message's digital signature
itself as invalid -- with no PKCS#11 error, because **this module is never involved**. Verifying
someone else's incoming signature is done entirely by NSS's own CMS code, using NSS's own crypto;
this provider only ever supplies the *local* user's own certificates/keys (for the reverse
direction: signing outgoing mail and decrypting mail addressed to them). If you're chasing this
kind of failure suspecting the provider, it's very likely the wrong place to look -- confirm the
actual cause below before spending time on the module's own logs.

First, capture `MOZ_LOG=pipnss:5,CMS:5,certverifier:5,psm:5,smime:5,timestamp` as described above
and open the message. The `certverifier`/`NSSCertDBTrustDomain` lines will show the chain
resolving cleanly (that's a separate check from the signature itself); look right after that for a
line from `nsCMSMessage::CommonVerifySignature`. A generic reason string there (e.g. "unsupported
digest algo") does not necessarily mean the algorithm is exotic or actually unsupported by NSS's
crypto engine -- **check the actual `digestAlgorithm`/`signatureAlgorithm` OIDs before assuming
anything.** The single most common real-world cause of exactly this symptom is mundane: since
**Thunderbird 115.0** (October 2023), Thunderbird deliberately rejects S/MIME signatures that use
SHA-1 as the message digest, regardless of whether the signature is otherwise cryptographically
valid -- see [Thunderbird 115 and Signatures Using The Obsolete SHA-1
Algorithm](https://blog.thunderbird.net/2023/10/thunderbird-115-and-signatures-using-the-obsolete-sha-1-algorithm/).
This is a deliberate Thunderbird-side policy check, not an NSS crypto-engine limitation and not
something this module can influence.

To check whether this is the cause:

- For a `multipart/signed` message, view the message source (`Ctrl+U`) and look for `micalg=` in
  the `Content-Type` header of the signed part; `sha-1`/`sha1` confirms it.
- For an opaque signed message (`application/pkcs7-mime; smime-type=signed-data`, content embedded
  in the CMS structure rather than a separate MIME part) there's no `micalg=` header to check;
  decode the CMS structure instead, e.g. `openssl cms -inform DER -in message.p7s -cmsout -noout
  -print` (works even without decrypting, if the message isn't also encrypted) and look at
  `signerInfos[].digestAlgorithm`.
- If the message is also encrypted (`smime-type=enveloped-data` wrapping a signed layer inside),
  you need the recipient's private key to get to the inner `SignerInfo` at all. On Windows this
  works even for a non-exportable CNG-backed key, since decryption happens through the CSP/KSP
  rather than by extracting key material -- from PowerShell:
  ```powershell
  Add-Type -AssemblyName System.Security
  $env = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
  $env.Decode([System.IO.File]::ReadAllBytes("message.p7m"))
  $env.Decrypt()  # finds the matching cert in CurrentUser\My and uses CNG automatically
  [System.IO.File]::WriteAllBytes("inner.bin", $env.ContentInfo.Content)
  ```
  then inspect `inner.bin` the same way as the opaque case above (strip the outer MIME headers
  first if `Content-Transfer-Encoding: base64` wraps another `application/pkcs7-mime` part).

If the digest is indeed SHA-1, the two options are: get the sender's CA to reissue their signing
certificate against a template that hashes with SHA-256 or better (the correct long-term fix --
check what hash algorithm the issuing CA's certificate template actually signs with, since this can
silently be SHA-1 even on an otherwise modern CA), or, only as a temporary workaround and not
recommended for routine use, `mail.smime.accept_insecure_sha1_message_signatures` in
`about:config`. Independently verifying the signature outside Thunderbird -- e.g. `openssl cms
-verify -in inner.bin -inform DER -CAfile root.pem` succeeding, or NSS's own `cmsutil -D` against a
throwaway database with the chain imported -- is a good way to confirm the signature is
cryptographically fine and this really is a policy rejection rather than a genuinely bad signature,
before concluding it's a Thunderbird policy issue rather than something else entirely.

## Signing works, then silently stops after some time (outgoing mail)

Symptom: S/MIME signing on outgoing mail worked fine, then at some point stops -- composing a
signed message produces no error, the message just never gets signed/sent. `RUST_LOG=osclientcerts=debug`
shows `C_SignInit` is never called at all (the module was never asked). Restarting Thunderbird does
**not** fix it. Re-selecting the same certificate in Account Settings > End-To-End Encryption does
fix it, without reinstalling anything or resetting the profile.

Root cause: NSS caches the signer's certificate from any verified S/MIME signature into its own
persistent `cert9.db`, including messages signed by a local identity itself (e.g. a Sent-folder
item or a self-addressed test getting processed/verified like any other signed message). This
produces a second, keyless copy of that identity's certificate in `cert9.db`, alongside the live,
key-bearing object this module serves from the OS certificate store. At some point, whatever
resolves `mail.identity.<id>.signing_cert_name` (a plain nickname string, matched via
`CERT_FindCertByNickname`) can end up resolving to the keyless cached copy instead of the live one,
and signing then fails silently rather than falling through or producing a diagnosable error. This
lives entirely in NSS/Thunderbird's own certificate database handling -- this module never writes
to `cert9.db` and has no way to prevent NSS from caching what it sees.

Recommended fix: install
[`tools/thunderbird-cert-cleanup/`](../tools/thunderbird-cert-cleanup), a small internal
Thunderbird add-on that finds and removes exactly this stale duplicate automatically (at
Thunderbird shutdown, and again -- automatically retrying the send -- the moment a signing
failure actually happens), so signing self-heals before anyone notices it broke for long. It does
*not* go
through the "Delete or Distrust" UI/API -- `nsIX509CertDB.getCerts()` (the only cert-listing API
exposed to a Thunderbird add-on) silently deduplicates a cert9.db row with the live token object
representing the same certificate, so it never even shows the duplicate as a separate entry while
this module is loaded, i.e. exactly when you'd need to find and delete it. The add-on instead reads
`cert9.db` directly and compares raw certificate bytes against what this module currently serves --
see its README for the full mechanism and how it's confirmed safe.

To fix a single occurrence by hand instead: open Certificate Manager, find the tab that lists
certificates *without* an associated private key (labeled "Other People's Certificates" or similar
depending on version), and look for an entry matching your own signing identity's subject/email --
if it's there, that's the stale duplicate. Deleting it (select it -> "Delete or Distrust") restores
signing immediately, without touching Account Settings or restarting. This has been confirmed to
work manually, but it's a one-off fix for whatever's stuck right now -- the add-on is what stops it
from recurring.
