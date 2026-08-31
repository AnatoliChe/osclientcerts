/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// COMPOSE-WINDOW-TRIGGER BUILD, not for production. Otherwise identical to
// trunk's production implementation.js (Sqlite.sys.mjs-based detection,
// nsIX509CertDB deletion, AsyncShutdown.appShutdownConfirmed blocker at
// shutdown -- all unchanged). The ONE change under test: this file also
// calls browser.certCleanup.cleanup() as soon as the user opens a new
// message-compose window, instead of only at Thunderbird shutdown. This
// tests what actually happens to mid-session reading when cleanup runs at
// the moment compose starts, rather than periodically or via a synthetic
// nsIMsgComposeSecure call.
//
// browser.windows.onCreated fires with the new Window object; a standalone
// compose window has Window.type === "messageCompose" (confirmed against
// https://webextension-api.thunderbird.net/en/latest/windows.html). The
// compose namespace itself has no window/tab-opened event, so this is the
// earliest reliable signal available to a WebExtension.

const VERSION = browser.runtime.getManifest().version;

console.log(`certCleanup v${VERSION} COMPOSE-WINDOW-TRIGGER: background page loaded`);

async function runCleanup(reason) {
  console.log(`certCleanup v${VERSION} COMPOSE-WINDOW-TRIGGER (${reason}): starting`);
  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} COMPOSE-WINDOW-TRIGGER (${reason}): call failed`, e);
    return;
  }
  console.log(
    `certCleanup v${VERSION} COMPOSE-WINDOW-TRIGGER (${reason}): done, ${deleted.length} deleted -- now try reading encrypted mail`
  );
}

browser.windows.onCreated.addListener((window) => {
  console.log(
    `certCleanup v${VERSION} COMPOSE-WINDOW-TRIGGER: windows.onCreated fired, type=${window.type}`
  );
  if (window.type === "messageCompose") {
    runCleanup("compose-window-opened");
  }
});
