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

This add-on finds and removes exactly that stale copy automatically -- **at Thunderbird shutdown,
and again as soon as a compose window opens** (new message, reply, or forward) -- without ever
touching any other certificate (correspondents' certificates NSS legitimately caches while
verifying their signatures are left alone; see "How it decides what to delete" below for exactly
why that's safe, and "Why cleanup runs at shutdown and when composing" for why it runs at those two
moments specifically, and what it costs to run at the second one).

## Installing

### Quick test (one machine, temporary)

1. Download the latest `cert-cleanup.xpi` from this repo's [Releases
   page](https://github.com/AnatoliChe/osclientcerts/releases) (look for a `tools-cert-cleanup-v*`
   tag).
2. In Thunderbird: `Ctrl+Shift+A` (Add-ons and Themes) → gear icon ⚙ → **Debug Add-ons**.
3. **Load Temporary Add-on...** → select the downloaded `.xpi`.

It only actually removes anything at shutdown or when a compose window opens (see "Why cleanup runs
at shutdown and when composing" below), so to see it act: open the Browser Console *first*
(`Ctrl+Shift+J` -- a separate window from the per-addon "Inspect" console, which won't show this
add-on's privileged-side logging), load the add-on, then either open a compose window (reply,
forward, or new message) or quit Thunderbird normally. The shutdown blocker this add-on registers
runs early enough in Gecko's shutdown sequence (`quit-application`, before windows close) that
`certCleanup:` lines still show up in that open console window as the quit proceeds. A temporary
add-on disappears on the next restart -- use this only to verify it works before deploying it for
real, below.

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
        "install_url": "https://github.com/AnatoliChe/osclientcerts/releases/download/tools-cert-cleanup-v0.5.0/cert-cleanup.xpi"
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
2. Open `cert9.db` directly, **read-only**, via
   [`Sqlite.sys.mjs`](https://searchfox.org/mozilla-central/source/toolkit/modules/Sqlite.sys.mjs)
   (`openNotExclusive: true, readOnly: true`) -- Gecko's sanctioned module for opening additional,
   concurrent connections to a Firefox/Thunderbird-managed sqlite database (the same mechanism
   other in-process code uses for shared databases like `places.sqlite`).
3. For each live certificate, query `cert9.db`'s own table (`nssPublic`, one row per PKCS #11
   object, columns named `a` + the attribute type in hex -- confirmed against NSS's
   `lib/softoken/sdb.c`) for a `CKO_CERTIFICATE` row (`a0`) whose DER (`a11`) is byte-for-byte
   identical to that live certificate's DER (`nsIX509Cert.getRawDER()`).
4. For each match, delete it through `nsIX509CertDB` itself rather than SQL: `constructX509()`
   builds a transient, in-memory certificate object from the duplicate's DER (not tied to any
   token/slot), and `deleteCertificate()` on that object resolves and removes the matching
   persisted record through NSS's own softoken code path (`PK11_DeleteTokenCertAndKey` /
   `SEC_DeletePermCertificate` -- confirmed against `nsNSSCertificateDB::DeleteCertificate`), the
   same path "Delete or Distrust" in Certificate Manager uses.

Step 3 can only ever find genuine duplicates: PKCS #11 objects belonging to an *external* token
like ours are never themselves written to `cert9.db`, so a `cert9.db` row whose DER matches one of
our live certificates cannot be that live certificate -- it can only be a stale, cached copy. This
also means the tool never touches another correspondent's certificate that NSS legitimately cached
while verifying their signature (those have no live counterpart on our token at all).

**Why step 4 changed in 0.3.0:** through 0.2.2, deletion was also done via a raw
`DELETE FROM nssPublic ...` on the same connection used for detection. Routing the delete through
`nsIX509CertDB.deleteCertificate()` instead lets NSS's own code perform and account for the
deletion. If that resolution ever targeted our *live* token object instead of the `cert9.db`
duplicate, the call would simply fail rather than corrupt anything: osclientcerts' own
`C_DestroyObject` is an unconditional `CKR_FUNCTION_NOT_SUPPORTED` stub, so an attempt to destroy
anything on our external token is a safe no-op.

## Why cleanup runs at shutdown and when composing

0.2.x and 0.3.x ran this pass periodically during the session (on startup, then every 30 minutes).
**Both the raw-SQL delete (through 0.2.2) and the official `nsIX509CertDB.deleteCertificate()` path
(0.3.0/0.3.1) broke S/MIME decryption for the rest of that Thunderbird session** once they actually
removed a duplicate -- confirmed in production testing via `RUST_LOG=osclientcerts=debug`: every
decrypt attempt afterward returned `CKR_FUNCTION_NOT_SUPPORTED` from `C_DecryptInit`/`C_UnwrapKey`,
and critically, with no `C_OpenSession` preceding those calls at all -- meaning Gecko had stopped
calling into the module for that operation entirely, rather than the module itself failing. This
wasn't a timing issue (a startup delay in 0.2.2 didn't help; the break still happened, just later,
at whatever point the delayed run actually deleted something) and it wasn't specific to the digest
algorithm of the message being read (reproduced with both SHA-1- and SHA-256-signed test messages).

It also isn't reproducible at the raw NSS/softoken/libsmime level: a from-source NSS build,
exercised directly via a small C harness that holds an `NSS_InitReadWrite` session open across an
external modification to the same `cert9.db` (mirroring what a second `Sqlite.sys.mjs` connection
or an external `certutil -D` does), survives every combination tried -- raw SQL delete, official
`certutil -D`, from a fresh process or an already-open one, checking both plain `PK11`
cert/key lookup and a real `NSS_CMSDecoder` envelope decrypt. All of it kept working. So whatever
goes stale lives in Gecko's C++ layer above NSS (the mail/PSM code that resolves a decryption
candidate for a specific message), not in NSS itself, and not in anything this add-on does
directly -- which also means it's not something this add-on can safely work around by changing
*how* it deletes, only *when*.

0.4.0's fix was architectural: **only clean up at shutdown.** Whatever goes stale in Gecko's cache
doesn't matter if the process exits shortly after -- there's no more of that session left for it to
affect -- and the next launch does a completely fresh `NSS_Init` that simply reads the
already-cleaned file from disk. This is implemented as an `AsyncShutdown.appShutdownConfirmed`
blocker (topic `quit-application`, the earliest well-known Gecko shutdown phase, registered once
when the Experiment script loads) rather than a `browser.alarms` timer -- see
`experiments/certCleanup/implementation.js`. A blocker, rather than a fire-and-forget observer
callback, is what guarantees the async `cert9.db` work actually finishes before Thunderbird tears
down further. Its one downside: on a machine that's rarely fully quit (put to sleep, or Thunderbird
left running for days), the duplicate -- and the outgoing-signing bug it causes -- can persist for
that whole stretch.

**0.5.0 adds a second trigger**, in `background.js`: `browser.windows.onCreated`, filtered to
`window.type === "messageCompose"`, runs the same cleanup as soon as any compose window opens (new
message, reply, or forward) -- i.e. right before the moment signing would actually matter, rather
than waiting for the next full restart. This still goes through `nsIX509CertDB.deleteCertificate()`
(same as the shutdown path -- see "How it decides what to delete" above), which means it still hits
the same Gecko-layer staleness described above: opening a compose window while a duplicate exists
**breaks decryption of other messages in the list** for as long as that compose window (or the rest
of that session, if you don't send) is open. Confirmed recovery path: sending the message you were
composing restores decryption immediately, presumably because a real send exercises the same
resolve-decryption-candidate code path that got stuck. Whether closing the compose window *without*
sending also recovers it is not yet confirmed. Extensive attempts to avoid the breakage altogether
-- targeted lookups instead of a full listing, avoiding file/SQL access, PKCS#11 module
reload/token logout, and even synthesizing a real sign+encrypt operation through
`nsIMsgComposeSecure` before deleting -- were all tried and none prevented it; see the git history
of the `experiment/cert-cleanup-mid-session` branch for the full investigation.

This is an accepted tradeoff, not an oversight: fixing signing right before it's needed, at the
cost of a self-recovering decryption glitch during that same compose session, was judged better
than leaving signing silently broken until the next full restart. The shutdown trigger stays in
place alongside it (in case a compose window is never opened before the next quit, or the
compose-time trigger's own dedup finds nothing to do yet).

## Building from source

```sh
./build.sh
```

Produces `dist/cert-cleanup.xpi`. Requires `zip`.

## Notes

- Runs once per Thunderbird shutdown, and once per compose window opened (see "Why cleanup runs at
  shutdown and when composing" above) -- not on a timer, not otherwise periodically. No
  notification on completion in either case: at shutdown there's no one left to usefully notify,
  and at compose-open a popup would be more disruptive than useful. Console logging
  (`certCleanup: removed N stale certificate record(s)`) is the only visible signal, and only
  fires when it actually found and removed something.
- `strict_min_version` in `manifest.json` is a conservative floor (128.0) -- lower or raise it to
  match whatever Thunderbird version your org actually deploys.
- This uses a [WebExtension
  Experiment](https://webextension-api.thunderbird.net/en/mv3/guides/experiments.html) (privileged
  API access beyond the normal sandbox) because `nsIX509CertDB` isn't exposed through the standard
  WebExtension API surface. Experiments are explicitly supported for exactly this kind of internal,
  non-AMO-distributed use.
