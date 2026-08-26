# cert9.db cleanup (Thunderbird add-on)

## What it does

S/MIME **signing** on outgoing mail can silently stop working after Thunderbird has been running
for a while: composing a signed message produces no error, the message just never gets
signed/sent, and neither restarting Thunderbird nor reinstalling anything fixes it. The cause is
NSS caching a second, keyless copy of your own signing certificate into its `cert9.db` (it does
this for certificates it sees in *any* verified S/MIME signature, including your own past signed
messages) -- Thunderbird can end up resolving your signing identity to that dead copy instead of
the real one. See ["Signing works, then silently stops after some
time"](../../DEBUGGING.md#signing-works-then-silently-stops-after-some-time-outgoing-mail) in
`DEBUGGING.md` for the full investigation.

This add-on finds and removes exactly that stale copy automatically -- at startup and every 30
minutes -- so the problem self-heals before you notice it. It never touches any other certificate
(correspondents' certificates NSS legitimately caches while verifying their signatures are left
alone; see "How it decides what to delete" below for exactly why that's safe).

## Installing

### Quick test (one machine, temporary)

1. Download the latest `cert-cleanup.xpi` from this repo's [Releases
   page](https://github.com/AnatoliChe/osclientcerts/releases) (look for a `tools-cert-cleanup-v*`
   tag).
2. In Thunderbird: `Ctrl+Shift+A` (Add-ons and Themes) → gear icon ⚙ → **Debug Add-ons**.
3. **Load Temporary Add-on...** → select the downloaded `.xpi`.

It runs immediately; check the Browser Console (`Ctrl+Shift+J` -- a separate window from the
per-addon "Inspect" console, which won't show this add-on's privileged-side logging) for
`certCleanup:` lines. A temporary add-on disappears on the next restart -- use this only to verify
it works before deploying it for real, below.

### Real deployment (Enterprise Policy, persists, auto-updates)

This is an internal tool, not published on addons.thunderbird.net -- install it via [Enterprise
Policy](https://mozilla.github.io/policy-templates/). On each machine (or via your existing
GPO/Intune `policies.json` delivery), create/edit `policies.json` in Thunderbird's install
directory under `distribution\` (e.g. `C:\Program Files\Thunderbird\distribution\policies.json`):

```json
{
  "policies": {
    "ExtensionSettings": {
      "cert-cleanup@osclientcerts.dev": {
        "installation_mode": "force_installed",
        "install_url": "https://github.com/AnatoliChe/osclientcerts/releases/download/tools-cert-cleanup-v0.2.1/cert-cleanup.xpi"
      }
    }
  }
}
```

Restart Thunderbird -- it installs automatically, no prompts. Verify: `Ctrl+Shift+A` should list
**"OS Client Certs -- cert9.db cleanup"**, marked as managed by policy (can't be removed manually
while the policy file is in place).

That `install_url` is a real GitHub Release asset -- this is what "installing from git" means in
practice: point the policy at the `.xpi` published on this repo's Releases page (built by
[`.github/workflows/tools-cert-cleanup-release.yml`](../../.github/workflows/tools-cert-cleanup-release.yml)
whenever a `tools-cert-cleanup-vX.Y.Z` tag is pushed, the same pattern the main DLL release uses for
`vX.Y.Z` tags). No separate hosting needed.

For multiple machines, deploy the same `policies.json` however your org already pushes files/config
(SCCM, Intune, a login script, GPO file deployment, ...) -- there's nothing add-on-specific about
that part.

#### Keeping it updated automatically

`manifest.json` sets `browser_specific_settings.gecko.update_url` to a raw GitHub URL for
[`updates.json`](updates.json) in this same directory. Thunderbird periodically checks that URL on
its own once the add-on is installed (`force_installed` via policy already keeps it from being
removed; the `update_url` is what lets it pick up new versions without re-pushing policy). When
cutting a new version:

1. Bump `version` in `manifest.json`.
2. Add a new entry to the top of `updates.json`'s `updates` array with the new version and the
   `tools-cert-cleanup-vX.Y.Z` release's `.xpi` download URL (old entries can stay; Thunderbird
   picks the newest compatible one).
3. Tag `tools-cert-cleanup-vX.Y.Z` and push -- CI builds and attaches the `.xpi` to the release.
4. Commit the `updates.json` change to `trunk` (the `update_url` is read live from `trunk`, not
   from the tag).

## How it decides what to delete

An earlier version of this add-on detected duplicates via `nsIX509CertDB.getCerts()` (grouping by
issuer+serial and looking for more than one record). **That doesn't work**: Gecko's
`nsNSSCertificateDB::GetCerts()` calls `PK11_ListCerts(PK11CertListUnique, ...)` internally
(confirmed against NSS's `lib/pk11wrap` and `security/manager/ssl/nsNSSCertificateDB.cpp`), which
silently merges a persisted, keyless `cert9.db` row with a live token object representing the same
certificate -- so `getCerts()` never shows the duplicate as a second entry while the provider is
loaded, which is exactly when you'd want to detect and remove it. Confirmed directly against a real
profile: its `cert9.db` had a persisted row for the signing identity's own certificate the entire
time signing was broken (and after, since nothing had removed it), yet `getCerts()` only ever
reported one record for it. NSS does have a non-deduplicating list type (`PK11CertListAll`), but no
JS-facing API exposes it.

So instead:

1. Ask NSS for the deduplicated view (`nsIX509CertDB.getCerts()`) and keep only the records on the
   `OS Client Cert Token` (the PKCS #11 token label this provider reports -- see
   `TOKEN_LABEL_BYTES` in `../../src/lib.rs`). These are confirmed-live, key-bearing certificates.
2. Open `cert9.db` directly, read-write, via
   [`Sqlite.sys.mjs`](https://searchfox.org/mozilla-central/source/toolkit/modules/Sqlite.sys.mjs)
   (`openNotExclusive: true`) -- Gecko's sanctioned module for opening additional, concurrent
   connections to a Firefox/Thunderbird-managed sqlite database (the same mechanism other in-process
   code uses for shared databases like `places.sqlite`). This is not "editing the file behind
   Thunderbird's back"; it's a second connection through the same safe machinery NSS's own
   connection uses.
3. For each live certificate, query `cert9.db`'s own table (`nssPublic`, one row per PKCS #11
   object, columns named `a` + the attribute type in hex -- confirmed against NSS's
   `lib/softoken/sdb.c`) for a `CKO_CERTIFICATE` row (`a0`) whose DER (`a11`) is byte-for-byte
   identical to that live certificate's DER (`nsIX509Cert.getRawDER()`). Delete any match.

Step 3 can only ever find genuine duplicates: PKCS #11 objects belonging to an *external* token
like ours are never themselves written to `cert9.db`, so a `cert9.db` row whose DER matches one of
our live certificates cannot be that live certificate -- it can only be a stale, cached copy. This
also means the tool never touches another correspondent's certificate that NSS legitimately cached
while verifying their signature (those have no live counterpart on our token at all).

## Building from source

```sh
./build.sh
```

Produces `dist/cert-cleanup.xpi`. Requires `zip`.

## Notes

- Runs automatically on startup and every 30 minutes (`browser.alarms`); shows a notification
  only when it actually removed something, so it's not silent if it does act, but also isn't
  noisy on every normal startup.
- `strict_min_version` in `manifest.json` is a conservative floor (128.0) -- lower or raise it to
  match whatever Thunderbird version your org actually deploys.
- This uses a [WebExtension
  Experiment](https://webextension-api.thunderbird.net/en/mv3/guides/experiments.html) (privileged
  API access beyond the normal sandbox) because `nsIX509CertDB` isn't exposed through the standard
  WebExtension API surface. Experiments are explicitly supported for exactly this kind of internal,
  non-AMO-distributed use.
