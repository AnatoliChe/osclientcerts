# forward-decrypt (Thunderbird add-on)

## What it does

When you forward an S/MIME **encrypted** message in Thunderbird, the default behavior is to
attach the raw encrypted blob (`smime.p7m`) and leave the compose body empty. The recipient
of your forward receives an unreadable attachment — they can't decrypt it with your key.

This add-on automatically:

1. **Detects** when a forward compose window opens for an S/MIME-encrypted message.
2. **Decrypts** the original message using your S/MIME certificates (same ones the cert9.db
   cleanup add-on protects).
3. **Replaces** the empty body with the decrypted content (plain text or HTML, matching
   your compose format).
4. **Re-adds** the real attachments from the original message (skipping inline images that
   rely on `cid:` references, which cannot be preserved).
5. **Enables S/MIME encryption** on the forward, so the new recipients also receive the
    message encrypted (and signed, if your identity supports it).
6. For **embedded `message/rfc822` containers** (e.g. messages forwarded via another system
    that wraps the S/MIME content inside an `rfc822` envelope): intercepts the forward and
    instead opens a **reply** on the container, clears the recipient fields, and leaves that
    reply as the compose window. A reply is the only way Thunderbird materializes the *full*
    decrypted content of such a container (text + inline images + file attachments) that the
    WebExtension `messages`/`compose` APIs cannot otherwise address.

You then add your new recipients and hit Send — the message goes out encrypted with your
identity's certificate, just like composing from scratch.

## Installing

### Quick test (one machine, temporary)

1. Download the latest `forward-decrypt.xpi` from this repo's [Releases
   page](https://github.com/AnatoliChe/osclientcerts/releases) (look for a
   `tools-forward-decrypt-v*` tag).
2. In Thunderbird: `Ctrl+Shift+A` (Add-ons and Themes) → gear icon ⚙ → **Debug Add-ons**.
3. **Load Temporary Add-on...** → select the downloaded `.xpi`.

### Real deployment (Enterprise Policy, persists, auto-updates)

This is an internal tool, not published on addons.thunderbird.net — install it via [Enterprise
Policy](https://thunderbird.readthedocs.io/en/latest/policies.html) the same way as the
cert9.db cleanup add-on. The `update_url` in the manifest points to this repository's trunk
branch, and new releases are tagged and uploaded as GitHub Releases.

## How it works

The stable release is **0.4.1**. The add-on registers its privileged intercept during
Thunderbird startup and uses these WebExtension listeners:

| Event                  | Purpose                                                              |
| ---------------------- | -------------------------------------------------------------------- |
| `tabs.onCreated`       | Triggers when any compose tab opens (type `messageCompose`).         |
| `compose.onAttachmentAdded` | Catches late-arriving `smime.p7m` attachments and removes them. |

When a compose tab opens, the add-on:

1. Polls `compose.getComposeDetails(tabId)` until the details are available (TB may load the
   compose window asynchronously).
2. Checks `details.type === "forward"` and that `relatedMessageId` is set.
3. Fetches the raw (encrypted) message with `messages.getFull(messageId, { decrypt: false })`
   to verify the root `Content-Type` is `application/pkcs7-mime` with
   `smime-type=enveloped-data` (S/MIME encryption, not just signing).
4. Fetches the decrypted message with `messages.getFull(messageId)` to verify
   `decryptionStatus === "success"` (the key is available).
5. Fetches the decrypted text parts via `messages.listInlineTextParts(messageId)`.
6. Fetches the decrypted attachments via `messages.listAttachments(messageId)` and
   `messages.getAttachmentFile(messageId, partName)`.
7. Removes any existing `smime.p7m` / `smime.p7s` attachments from the compose window.
8. Sets the compose body (respecting the compose format — plain text or HTML) with a
   forwarded-message header block (Subject, Date, From, To).
9. Forces `selectedEncryptionTechnology` to `{ name: "S/MIME", encryptBody: true,
   signMessage: true }`.
10. Adds the decrypted file attachments.

### Embedded `message/rfc822` containers

Some setups (mail relays, conversion gateways, Outlook interop) wrap the S/MIME content
inside a `message/rfc822` envelope before delivery. In that case the root Content-Type is
`message/rfc822` rather than `application/pkcs7-mime`, and the standard decryption APIs
(`messages.getFull`, `listInlineTextParts`, `listAttachments`) do not surface the decrypted
inner content at all.

The add-on ships a privileged `ForwardIntercept` Experiment API
(`experiment_apis`, supported in Manifest V3). It is always enabled and, at the moment a *forward* of an
embedded container is initiated, **redirects the compose type to a Reply before the compose
window is created**. The result is a single reply window with the full decrypted content and
**no empty Forward-window flash**. The reply window still gets its recipients cleared and its
`Re:` → `Fwd:` subject retitled by the background script, exactly as below.

The redirected compose waits for Thunderbird's `ComposeBodyReady` notification, then
extracts and adds the decrypted standalone attachments. This adapts to fast and slow
machines without a fixed startup delay.

The Experiment is loaded by its `startup` lifecycle event and wakes the MV3 background
before the first Forward command. Thunderbird may later suspend and recreate that background
page; the privileged API therefore keeps one shared redirect state across background contexts.
This preserves the captured message URI, redirect marker, readiness promise, and installed
`ComposeMessage` wrapper after long idle periods. Startup scanning and `tabs.onCreated`
cannot process the same compose tab twice.

Two delayed sweeps (3 s and 8 s) handle the case where TB adds the `smime.p7m` attachment
asynchronously after the initial pass. The `smime.p7m` envelope attachment is also removed
**immediately** when caught by `onAttachmentAdded`, regardless of the tab's processing state.

## Permissions

| Permission      | Why it is needed                                                            |
| --------------- | --------------------------------------------------------------------------- |
| `compose`       | Read/write compose window content, attachments, and encryption settings.    |
| `messagesRead`  | Read the original message's headers, decrypted body, and attachments.       |
| `tabs`          | Detect compose windows (`tab.type === "messageCompose"`).                   |
| `storage`       | Store the debug logging toggle (options page).                              |

The `ForwardIntercept` Experiment API is declared under `experiment_apis`.
Including an Experiment replaces Thunderbird's per-permission prompt with a single
"full, unrestricted access" install prompt, and it runs with access to the main process.
The Experiment is the supported implementation for embedded S/MIME containers and is
enabled automatically.

## Limitations

- **Inline images** in a *top-level* S/MIME message (root `application/pkcs7-mime`) that are
  referenced via `cid:` in the HTML body cannot be preserved when the standard forward is
  rebuilt: they are skipped to avoid broken image references. This affects messages with
  embedded screenshots or logos. (Embedded `message/rfc822` containers that go through the
  reply rebuild do keep their inline images.)
- For **embedded `message/rfc822` containers**, the forward becomes a **reply** with cleared
  recipients rather than a plain "Fwd:" window. The subject is retitled `Re:` → `Fwd:`, but
  the reply attribution header still differs slightly from a true forward. This is the only
  way to preserve the full decrypted content (text + inline images + attachments) of such a
  container — the WebExtension `messages`/`compose` APIs do not address the inner CMS parts.
  `ForwardIntercept` redirects the forward at compose-open time (single window, no flash).
- **Forward as attachment** (`.eml` mode) is not handled — the add-on only operates on
  inline forwards (the default).
- The forwarded message does not include the original's cryptographic signature envelope.
  The new message is signed and encrypted under *your* identity's certificate, which is the
  correct behavior for a forward.
- The recipient must have your S/MIME certificate in their trust store (or their mail client
  must support S/MIME with your certificate) to decrypt the forwarded message. This is
  inherent to S/MIME and not a limitation of this add-on.

## Building

```bash
./build.sh
# → dist/forward-decrypt.xpi
```

Run the local checks before publishing:

```bash
node --check background.js
node --check api/ForwardIntercept/implementation.js
./node_modules/.bin/jest --runInBand
unzip -t dist/forward-decrypt.xpi
```

### Automated regression tests

The Jest suite contains both API-flow tests and a behavioural Thunderbird
Experiment harness. The harness executes `implementation.js` with mocked
Thunderbird parent-process services and covers lifecycle failures which are not
visible to ordinary WebExtension mocks:

- startup wakes the MV3 background before the first Forward command;
- repeated `getAPI()` calls reuse state after background suspension;
- a mail window is patched only once, so duplicate initialization cannot open
  multiple compose windows;
- Reply is left unchanged while Forward is redirected exactly once;
- `ComposeBodyReady` and compose-window closure finish the readiness wait;
- add-on shutdown restores the original `ComposeMessage` function and
  invalidates Thunderbird's startup cache.

`.github/workflows/tools-forward-decrypt-test.yml` runs these tests, syntax
checks, XPI assembly, and archive validation for pull requests, `trunk`, and all
`tools-forward-decrypt-*` development branches. The release workflow repeats
the same checks before it is allowed to upload an XPI, so a failing regression
test blocks publication.

Release tags use `tools-forward-decrypt-vX.Y.Z`. GitHub Actions builds and attaches
`forward-decrypt.xpi`; `updates.json` is the Enterprise Policy auto-update feed.

## See also

- [cert9.db cleanup add-on](../thunderbird-cert-cleanup/) — keeps the S/MIME signing
  certificate healthy so that outgoing signing and encryption work in the first place.
- Bug 217979: [Forward encrypted message → smime.p7m attached](https://bugzilla.mozilla.org/show_bug.cgi?id=217979)
- Bug 1942038: [S/MIME signed forward → empty write window (132.0b2)](https://bugzilla.mozilla.org/show_bug.cgi?id=1942038)
