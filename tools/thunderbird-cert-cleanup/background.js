/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// SYNTH-SIGN-ENCRYPT BUILD, not for production. Calls
// browser.certCleanup.cleanup() once, 10 seconds after startup. That
// implementation.js function does the same dbkey-based lookup as 0.4.14
// (which still broke reading on its own), then synthesizes a real
// sign+encrypt operation through nsIMsgComposeSecure, addressed to the
// identity's own email and written to a throwaway temp file (never sent).
// Tests whether a *real* PK11 crypto operation through the token -- not
// just another lookup -- is what recovers reading, matching what the user
// found happens after a real compose+send. See implementation.js for why.

const VERSION = browser.runtime.getManifest().version;
const STARTUP_DELAY_MS = 10000;

console.log(`certCleanup v${VERSION} SYNTH-SIGN-ENCRYPT: background page loaded`);

async function runCleanup(reason) {
  console.log(`certCleanup v${VERSION} SYNTH-SIGN-ENCRYPT (${reason}): starting`);
  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} SYNTH-SIGN-ENCRYPT (${reason}): call failed`, e);
    return;
  }
  console.log(
    `certCleanup v${VERSION} SYNTH-SIGN-ENCRYPT (${reason}): done, ${deleted.length} deleted -- now try reading encrypted mail`
  );
}

browser.runtime.onStartup.addListener(() => {
  console.log(`certCleanup v${VERSION} SYNTH-SIGN-ENCRYPT: onStartup fired, scheduling in ${STARTUP_DELAY_MS}ms`);
  setTimeout(() => runCleanup("startup+10s"), STARTUP_DELAY_MS);
});
browser.runtime.onInstalled.addListener(() => {
  console.log(`certCleanup v${VERSION} SYNTH-SIGN-ENCRYPT: onInstalled fired, scheduling in ${STARTUP_DELAY_MS}ms`);
  setTimeout(() => runCleanup("install+10s"), STARTUP_DELAY_MS);
});
