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
   that wraps the S/MIME content inside an `rfc822` envelope): pulls the decrypted body
   from a temporary reply window and applies it to the forward. Inline images and separate
   file attachments from inside such containers are not recoverable via the WebExtension API
   (only text).

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

The add-on registers two event listeners:

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

For this case the add-on opens a temporary **reply** window on the container (TB's reply
path does materialize the decrypted body), copies its HTML/plain body into the user's
forward window via `setComposeDetails`, and closes the reply window. Inline images from
inside the container cannot be recovered this way — they remain as `imap://`-based `src`
references that break for the recipient — but the **full decrypted text** is transferred.

The `experiments` checkbox in the add-on options (Off by default) additionally keeps the
diagnostic reply/forward windows open for inspection. This is only for debugging and is
safe — the add-on's own guard sets (`selfOpenedTabIds`, `handledEmbeddedMessageIds`,
`embeddedExperimentRunning`) prevent the re-entrancy cascade that once caused thousands
of compose windows to open.

Two delayed sweeps (3 s and 8 s) handle the case where TB adds the `smime.p7m` attachment
asynchronously after the initial pass. The `smime.p7m` envelope attachment is also removed
**immediately** when caught by `onAttachmentAdded`, regardless of the tab's processing state.

## Permissions

| Permission      | Why it is needed                                                            |
| --------------- | --------------------------------------------------------------------------- |
| `compose`       | Read/write compose window content, attachments, and encryption settings.    |
| `messagesRead`  | Read the original message's headers, decrypted body, and attachments.       |
| `tabs`          | Detect compose windows (`tab.type === "messageCompose"`).                   |
| `storage`       | Store the debug and experiment toggles (options page).                      |

No host permissions, no Experiment, no native messaging. The add-on is entirely
JavaScript WebExtension code.

## Limitations

- **Inline images** in the original message that are referenced via `cid:` in the HTML body
  cannot be preserved when re-adding them as regular attachments. They are skipped to avoid
  broken image references. This affects messages with embedded screenshots or logos.
- For **embedded `message/rfc822` containers**: only the decrypted text body is transferred
  (via the reply-to-forward technique). Inline images remain as `imap://`-based `src`
  references that will break for the recipient. Separate file attachments inside such
  containers (e.g. a `.txt` file) are also not recoverable — the WebExtension messages API
  does not address the inner CMS parts. A full solution would require a privileged Experiment
  that decrypts the CMS blob with the user's private key.
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

## See also

- [cert9.db cleanup add-on](../thunderbird-cert-cleanup/) — keeps the S/MIME signing
  certificate healthy so that outgoing signing and encryption work in the first place.
- Bug 217979: [Forward encrypted message → smime.p7m attached](https://bugzilla.mozilla.org/show_bug.cgi?id=217979)
- Bug 1942038: [S/MIME signed forward → empty write window (132.0b2)](https://bugzilla.mozilla.org/show_bug.cgi?id=1942038)
