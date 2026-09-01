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

This add-on auto-removes exactly that stale copy, using three **proactive** triggers (see "How
and when it runs" below) and no reactive failure-handling/retry. It never touches any other
certificate (correspondents' certificates NSS legitimately caches while verifying their
signatures are left alone; see "How it decides what to delete" below).

## Installing

### Quick test (one machine, temporary)

1. Download the latest `cert-cleanup.xpi` from this repo's [Releases
   page](https://github.com/AnatoliChe/osclientcerts/releases) (look for a `tools-cert-cleanup-v*`
   tag).
2. In Thunderbird: `Ctrl+Shift+A` (Add-ons and Themes) → gear icon ⚙ → **Debug Add-ons**.
3. **Load Temporary Add-on...** → select the downloaded `.xpi`.

To see it act, open the Browser Console *first* (`Ctrl+Shift+J` -- a separate window from the
per-addon "Inspect" console, which won't show this add-on's privileged-side logging), load the
add-on, then either open a new compose window, or send a signed message, or quit Thunderbird
normally. The shutdown blocker this add-on registers runs early enough in Gecko's shutdown
sequence (`quit-application`, before windows close) that `certCleanup:` lines still show up in
that open console window as the quit proceeds. A temporary add-on disappears on the next restart
-- use this only to verify it works before deploying it for real, below.

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
        "install_url": "https://github.com/AnatoliChe/osclientcerts/releases/download/tools-cert-cleanup-v0.8.0/cert-cleanup.xpi"
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

1. Bump `version` in `manifest.json` (and `VERSION` in `implementation.js`).
2. Add a new entry to the top of `updates.json`'s `updates` array with the new version and the
   `tools-cert-cleanup-vX.Y.Z` release's `.xpi` download URL (old entries can stay; Thunderbird
   picks the newest compatible one).
3. Tag `tools-cert-cleanup-vX.Y.Z` and push -- CI builds and attaches the `.xpi` to the release.
4. Commit the `updates.json` change to `trunk` (the `update_url` is read live from `trunk`, not
   from the tag).

## How it decides what to delete

An earlier version of this add-on (0.1.x/0.2.x) detected duplicates via `nsIX509CertDB.getCerts()`
and tried to delete through it mid-session. Both approaches are gone. Two independent facts led to
the current design:

- **Reading (not deleting) through NSS mid-session breaks decryption.** Through the 0.6.4.x test
  series, bisection proved that *any* `nsIX509CertDB` call on the send path -- even a plain
  `getCerts()` with nothing to delete -- corrupts S/MIME decryption of incoming mail for the rest
  of that session. So the send path of this add-on touches **no NSS API at all**.
- **The duplicate is findable by pure SQL.** `cert9.db`'s `nssPublic` table (one row per PKCS #11
  object, columns named `a` + the attribute type in hex -- confirmed against NSS's
  `lib/softoken/sdb.c`) stores the certificate's email address in the `CKA_NSS_EMAIL` attribute
  (value `0xCE534352`), in the column `ace534352`. The signing identity's email is available from
  the compose window (`gCurrentIdentity.email`), so a persistent duplicate can be located with no
  NSS involvement.

So the send path:

1. Take the signing identity's email from the compose window.
2. Open `cert9.db` directly via
   [`Sqlite.sys.mjs`](https://searchfox.org/mozilla-central/source/toolkit/modules/Sqlite.sys.mjs)
   (`openNotExclusive: true`).
3. Select and delete only rows that are `CKO_CERTIFICATE` (`hex(a0) = '00000001'`) **and** whose
   `ace534352` matches the email case-insensitively (`LOWER(ace534352) = LOWER(:email)`, with the
   email encoded as a plain ASCII byte array). The `CKO_NSS_SMIME` rows (`hex(a0) = 0xCE534352`)
   that NSS uses for S/MIME bookkeeping are deliberately never touched.

Step 3 can only ever find genuine stale duplicates: PKCS #11 objects belonging to an *external*
token like ours are never themselves written to `cert9.db`, so a persisted `CKO_CERTIFICATE` row
carrying the user's own signing-certificate email cannot be the live certificate -- it is the stale
cached copy. The tool never touches a correspondent's certificate that NSS legitimately cached
while verifying their signature (those carry the correspondent's email, not the identities').

`doCleanupFin()` (used only at shutdown, where disturbing in-process NSS state is harmless because
the process exits right after) also runs a full pass that re-lists the provider's certificates and
removes stale copies through the official `nsIX509CertDB` softoken path
(`PK11_DeleteTokenCertAndKey` / `SEC_DeletePermCertificate`).

## How and when it runs (proactive only)

0.2.x/0.3.x ran periodically mid-session; 0.4.0 moved cleanup to shutdown. 0.5.x/0.6.x tried
proactive and then reactive (failed-send + auto-retry) triggers that rebuilt Gecko's `CertVerifier`
after an NSS-touching cleanup. The 0.6.4.x test series then proved the NSS-touching cleanup itself
was the problem -- reading incoming mail corrupts even when nothing is deleted -- and that the real
fix is to *not touch NSS at all* on the paths where correctness matters.

**v0.8.0 is the validated proactive-only architecture.** Three triggers, all proactive, with no
reactive failure-handling and no retry:

1. **Compose window opens** -> unconditionally rebuild Gecko's `CertVerifier` singleton
   (`reinitCertVerifier()`), refreshing the intra-process caches (`mOCSPCache`/`mSignatureCache`/
   `mTrustCache`) that hold stale cert state. It does this well before any send, so it can never
   collide with a synchronous crypto operation the way it did when tried immediately around a send.
2. **Send button/menu clicked**, intercepted *before* the real send starts -> `doCleanup()` only
   (the pure-SQL, NSS-free delete above). No reinit, no NSS API, so reading incoming mail is never
   disturbed. The original send then proceeds exactly once.
3. **App shutdown** -> `doCleanupFin()` (the full pass), removing whatever duplicate accumulated in
   a session where no send/read ever exercised the relevant path.

This replaces every reactive/retry design tried on the experiment branch
(`experiment/cert-cleanup-mid-session`): those needed to recreate `nsIMsgComposeSecure` and rewarm
the `checkRecipientCerts()` cache to avoid corrupting a retried send, but `checkRecipientCerts()`
is itself a genuine NSS-touching disturbance that kept breaking reading even when every step
completed successfully (confirmed via a complete, gapless log capture, 2026-09-01). The proactive
design sidesteps both problems: cleanup runs *before* the only `BeginCryptoEncapsulation()` call
this window will ever make, so there is no same-window-retry corruption risk and no need for
`recreateComposeSecure()`/`checkRecipientCerts()` at all; and `reinitCertVerifier()` only ever
runs at window-open, well before any send, so it can never disturb a send.

## Building from source

```sh
./build.sh
```

Produces `dist/cert-cleanup.xpi`. Requires `zip`.

## Notes

- Runs at compose-window-open (reinit only), before each send (NSS-free SQL delete), and at
  Thunderbird shutdown (full delete) -- not on a timer, not otherwise periodically.
- `strict_min_version` in `manifest.json` is a conservative floor (128.0) -- lower or raise it to
  match whatever Thunderbird version your org actually deploys.
- This uses a [WebExtension
  Experiment](https://webextension-api.thunderbird.net/en/mv3/guides/experiments.html) (privileged
  API access beyond the normal sandbox) because `nsIX509CertDB` isn't exposed through the standard
  WebExtension API surface. Experiments are explicitly supported for exactly this kind of internal,
  non-AMO-distributed use.
