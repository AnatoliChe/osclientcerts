/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// DBKEY-LOOKUP BUILD, not for production. Calls
// browser.certCleanup.cleanup() once, 10 seconds after startup; that
// implementation.js function resolves our own certificate(s) via each mail
// identity's signing_cert_dbkey/encryption_cert_dbkey preference and
// nsIX509CertDB.findCertByDBKey() -- the same targeted lookup Thunderbird's
// own compose-security code uses -- never calling getCerts(). See
// implementation.js for why.

const VERSION = browser.runtime.getManifest().version;
const STARTUP_DELAY_MS = 10000;

console.log(`certCleanup v${VERSION} DBKEY-LOOKUP: background page loaded`);

async function runCleanup(reason) {
  console.log(`certCleanup v${VERSION} DBKEY-LOOKUP (${reason}): starting`);
  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} DBKEY-LOOKUP (${reason}): call failed`, e);
    return;
  }
  console.log(
    `certCleanup v${VERSION} DBKEY-LOOKUP (${reason}): done, ${deleted.length} deleted -- now try reading encrypted mail`
  );
}

browser.runtime.onStartup.addListener(() => {
  console.log(`certCleanup v${VERSION} DBKEY-LOOKUP: onStartup fired, scheduling in ${STARTUP_DELAY_MS}ms`);
  setTimeout(() => runCleanup("startup+10s"), STARTUP_DELAY_MS);
});
browser.runtime.onInstalled.addListener(() => {
  console.log(`certCleanup v${VERSION} DBKEY-LOOKUP: onInstalled fired, scheduling in ${STARTUP_DELAY_MS}ms`);
  setTimeout(() => runCleanup("install+10s"), STARTUP_DELAY_MS);
});
