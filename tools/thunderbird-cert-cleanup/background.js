/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// NO-OP EXPERIMENT BUILD, not for production. Logs a single line 10 seconds
// after startup and does nothing else at all -- does not call
// browser.certCleanup.cleanup(), does not touch cert9.db, does not touch
// certificates in any way. See implementation.js for why this build exists.

const VERSION = browser.runtime.getManifest().version;
const STARTUP_DELAY_MS = 10000;

console.log(`certCleanup v${VERSION} NO-OP: background page loaded`);

browser.runtime.onStartup.addListener(() => {
  console.log(`certCleanup v${VERSION} NO-OP: onStartup fired, will say hello in ${STARTUP_DELAY_MS}ms`);
  setTimeout(() => {
    console.log(`certCleanup v${VERSION} NO-OP: hello (startup+10s) -- nothing else was touched`);
  }, STARTUP_DELAY_MS);
});
browser.runtime.onInstalled.addListener(() => {
  console.log(`certCleanup v${VERSION} NO-OP: onInstalled fired, will say hello in ${STARTUP_DELAY_MS}ms`);
  setTimeout(() => {
    console.log(`certCleanup v${VERSION} NO-OP: hello (install+10s) -- nothing else was touched`);
  }, STARTUP_DELAY_MS);
});
