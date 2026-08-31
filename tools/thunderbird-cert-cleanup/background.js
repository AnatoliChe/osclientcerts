/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// BEFORE-SEND-TRIGGER BUILD, not for production. Otherwise identical to
// trunk's production implementation.js (Sqlite.sys.mjs-based detection,
// nsIX509CertDB deletion, AsyncShutdown.appShutdownConfirmed blocker at
// shutdown -- all unchanged). The trigger under test this time:
// browser.compose.onBeforeSend, which fires when the user clicks Send, and
// (per the Thunderbird WebExtensions docs) is a user-input event handler
// whose async listener is awaited before the send actually proceeds -- so
// this runs cleanup as late as possible, right before Thunderbird's own
// sign/encrypt pipeline for the outgoing message, instead of at
// compose-window-open (which leaves reading broken for the whole time the
// compose window stays open). The goal is to shrink the known
// getCerts()-breaks-reading window down to roughly the duration of the send
// itself, since a real send is also the one thing confirmed to *recover*
// reading afterward.
//
// Requires the "compose" permission (see manifest.json) for onBeforeSend to
// be available at all.

const VERSION = browser.runtime.getManifest().version;

console.log(`certCleanup v${VERSION} BEFORE-SEND-TRIGGER: background page loaded`);

async function runCleanup(reason) {
  console.log(`certCleanup v${VERSION} BEFORE-SEND-TRIGGER (${reason}): starting`);
  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} BEFORE-SEND-TRIGGER (${reason}): call failed`, e);
    return;
  }
  console.log(
    `certCleanup v${VERSION} BEFORE-SEND-TRIGGER (${reason}): done, ${deleted.length} deleted -- Thunderbird's own send/sign/encrypt should run next`
  );
}

browser.compose.onBeforeSend.addListener(async (tab, details) => {
  console.log(`certCleanup v${VERSION} BEFORE-SEND-TRIGGER: onBeforeSend fired for tab ${tab.id}`);
  await runCleanup("before-send");
  // Returning nothing (undefined) tells Thunderbird to proceed with the
  // send unmodified -- we're not cancelling or editing the message, just
  // running cleanup first and letting the send continue right after.
});
