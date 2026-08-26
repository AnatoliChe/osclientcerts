# cert9.db cleanup (Thunderbird add-on)

Removes stale, keyless duplicate copies of an OS Client Certs signing certificate that NSS
sometimes caches into `cert9.db` from verified S/MIME signatures. This is what causes S/MIME
*signing* (not decryption) to silently stop working after a while, with no PKCS #11 error and no
specific reason in `MOZ_LOG` -- see the "Signing works, then silently stops after some time" case
in [`../../DEBUGGING.md`](../../DEBUGGING.md) for the full investigation and root cause. The fix
that was found to work is: delete the duplicate, keyless copy of the identity's own certificate
from Certificate Manager (it shows up under the tab for certificates without a private key). This
add-on automates exactly that deletion using the same NSS API Certificate Manager's own "Delete or
Distrust" button uses (`nsIX509CertDB.deleteCertificate`) -- nothing here touches `cert9.db`
directly as a file, so there's no risk of it racing Thunderbird's own open connection to it (unlike
editing the SQLite file from a separate process while Thunderbird is running).

## How it decides what to delete

1. Ask NSS for every certificate record it knows about, across every token and its own internal
   database (`nsIX509CertDB.getCerts()`).
2. Group them by issuer name + serial number -- i.e. by the real-world certificate they represent,
   regardless of which token/database record happens to represent it.
3. For any group that contains a record on the `OS Client Cert Token` (the PKCS #11 token label
   this provider reports -- see `TOKEN_LABEL_BYTES` in `../../src/lib.rs`), every *other* record in
   that group is a stale duplicate: something else NSS knows about the same certificate, but not
   the live, key-bearing one the provider serves. Those are deleted.
4. A group with no record on `OS Client Cert Token` is left alone entirely (nothing to do with this
   provider's identities -- most commonly, some other correspondent's certificate NSS cached while
   verifying their signature, which is the normal, needed behavior).

This only ever deletes a record when the real, working copy is confirmed still present, so it can't
remove the certificate you actually need.

## Building

```sh
./build.sh
```

Produces `dist/cert-cleanup.xpi`. Requires `zip`.

## Trying it locally

Thunderbird → Settings → General → Config Editor (or `about:debugging`) → "This Thunderbird" → "Load
Temporary Add-on..." → pick `manifest.json` directly (no need to build the `.xpi` first). Runs
immediately (`runtime.onInstalled`); check the Browser Console for `certCleanup:` log lines. A
temporary add-on is removed on restart -- for anything beyond a one-off test, deploy it properly
(below).

## Deploying (Enterprise Policy)

This is an internal tool, not meant for addons.thunderbird.net -- install it via [Enterprise
Policy](https://mozilla.github.io/policy-templates/) (`policies.json`, or the equivalent GPO/Intune
delivery your org already uses for `policies.json`):

```json
{
  "policies": {
    "ExtensionSettings": {
      "cert-cleanup@osclientcerts.dev": {
        "installation_mode": "force_installed",
        "install_url": "https://github.com/AnatoliChe/osclientcerts/releases/download/tools-cert-cleanup-v0.1.1/cert-cleanup.xpi"
      }
    }
  }
}
```

That `install_url` is a real GitHub Release asset -- this is what "installing from git" means in
practice: point the policy at the `.xpi` published on this repo's Releases page (built by
[`.github/workflows/tools-cert-cleanup-release.yml`](../../.github/workflows/tools-cert-cleanup-release.yml)
whenever a `tools-cert-cleanup-vX.Y.Z` tag is pushed, the same pattern the main DLL release uses for
`vX.Y.Z` tags). No separate hosting needed.

### Keeping it updated automatically

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

## Notes

- Runs automatically on startup and once every 24 hours (`browser.alarms`); shows a notification
  only when it actually removed something, so it's not silent if it does act, but also isn't
  noisy on every normal startup.
- `strict_min_version` in `manifest.json` is a conservative floor (128.0) -- lower or raise it to
  match whatever Thunderbird version your org actually deploys.
- This uses a [WebExtension
  Experiment](https://webextension-api.thunderbird.net/en/mv3/guides/experiments.html) (privileged
  API access beyond the normal sandbox) because `nsIX509CertDB` isn't exposed through the standard
  WebExtension API surface. Experiments are explicitly supported for exactly this kind of internal,
  non-AMO-distributed use.
