/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// EXPERIMENT BUILD (experiment/cert-cleanup-mid-session branch), not for
// production. Trunk's 0.4.0 moved cleanup to Thunderbird shutdown because
// every mid-session deletion mechanism tried in 0.2.x/0.3.x broke S/MIME
// decryption for the rest of that session -- see the README's "Why cleanup
// only runs at shutdown". This build deliberately goes back to running
// cleanup *during* the session (immediately, then every 5 minutes) to test
// whether that corruption is actually the NSS race fixed by bugs 2056775
// and 2056786 in NSS 3.128 (2026-08-26) -- if a Thunderbird build with NSS
// >= 3.128 can run this mid-session without breaking reading, that's strong
// evidence the corruption was exactly that upstream race, now fixed.

const CLEANUP_ALARM_NAME = "cert-cleanup-experiment-periodic";
const CLEANUP_PERIOD_MINUTES = 5;

const VERSION = browser.runtime.getManifest().version;

async function runCleanup(reason) {
  console.log(`certCleanup v${VERSION} EXPERIMENT (${reason}): starting`);

  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} EXPERIMENT (${reason}): cleanup call failed`, e);
    return;
  }

  if (deleted.length === 0) {
    console.log(`certCleanup v${VERSION} EXPERIMENT (${reason}): nothing to clean up`);
    return;
  }

  console.log(
    `certCleanup v${VERSION} EXPERIMENT (${reason}): removed ${deleted.length} stale certificate record(s) -- now try reading/sending mail and watch for breakage`,
    deleted
  );
}

browser.runtime.onInstalled.addListener(() => runCleanup("install"));
browser.runtime.onStartup.addListener(() => runCleanup("startup"));

browser.alarms.create(CLEANUP_ALARM_NAME, {
  periodInMinutes: CLEANUP_PERIOD_MINUTES,
});
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === CLEANUP_ALARM_NAME) {
    runCleanup("scheduled");
  }
});
