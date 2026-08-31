/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// GETCERTS-PLUS-LOGOUT CONTROL BUILD, not for production. Calls
// browser.certCleanup.cleanup() once, 10 seconds after startup; that
// implementation.js function calls nsIX509CertDB.getCerts(), then
// nsIPK11Token.logoutAndDropAuthenticatedResources() on our token. See
// implementation.js for why.

const VERSION = browser.runtime.getManifest().version;
const STARTUP_DELAY_MS = 10000;

console.log(`certCleanup v${VERSION} GETCERTS+LOGOUT: background page loaded`);

async function runCleanup(reason) {
  console.log(`certCleanup v${VERSION} GETCERTS+LOGOUT (${reason}): starting`);
  try {
    await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} GETCERTS+LOGOUT (${reason}): call failed`, e);
    return;
  }
  console.log(`certCleanup v${VERSION} GETCERTS+LOGOUT (${reason}): done -- now try reading encrypted mail`);
}

browser.runtime.onStartup.addListener(() => {
  console.log(`certCleanup v${VERSION} GETCERTS+LOGOUT: onStartup fired, scheduling in ${STARTUP_DELAY_MS}ms`);
  setTimeout(() => runCleanup("startup+10s"), STARTUP_DELAY_MS);
});
browser.runtime.onInstalled.addListener(() => {
  console.log(`certCleanup v${VERSION} GETCERTS+LOGOUT: onInstalled fired, scheduling in ${STARTUP_DELAY_MS}ms`);
  setTimeout(() => runCleanup("install+10s"), STARTUP_DELAY_MS);
});
