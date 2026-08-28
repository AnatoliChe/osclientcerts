/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const CLEANUP_ALARM_NAME = "cert-cleanup-periodic";
const CLEANUP_PERIOD_MINUTES = 30;
const STARTUP_ALARM_NAME = "cert-cleanup-startup-delay";
// NSS opens cert9.db read-write within milliseconds of Thunderbird's process
// start (confirmed via MOZ_LOG=pipnss:5 -- "initialized NSS in r/w mode"
// appears ~20ms after nsNSSComponent::ctor). Running our own cert9.db access
// that early, concurrently with NSS's own startup-time DB access, corrupted
// S/MIME decryption for the rest of the session in testing (force_installed
// via policy runs onStartup essentially at process launch; a temporary
// add-on loaded well into an already-running session never hit this, which
// is why it always looked fine there). Delaying the first run past this
// startup window avoids the race; the DB is a normal, unhurried target for
// the rest of the session after that.
const STARTUP_DELAY_MINUTES = 2;

// Read from manifest.json rather than hardcoded here, so it can never drift
// out of sync with the actual installed version -- log it on every run so
// it's unambiguous from the console output alone which build is actually
// executing (WebExtension Experiments can otherwise keep a stale cached copy
// running across a reload; see onShutdown() in experiments/certCleanup/
// implementation.js).
const VERSION = browser.runtime.getManifest().version;

async function runCleanup(reason) {
  console.log(`certCleanup v${VERSION} (${reason}): starting`);

  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} (${reason}): cleanup call failed`, e);
    return;
  }

  if (deleted.length === 0) {
    console.log(`certCleanup v${VERSION} (${reason}): nothing to clean up`);
    return;
  }

  console.log(
    `certCleanup v${VERSION} (${reason}): removed ${deleted.length} stale certificate record(s)`,
    deleted
  );
  try {
    await browser.notifications.create({
      type: "basic",
      title: "OS Client Certs cleanup",
      message:
        deleted.length === 1
          ? "Removed a stale cached certificate record. If S/MIME signing was failing, it should work again now."
          : `Removed ${deleted.length} stale cached certificate records. If S/MIME signing was failing, it should work again now.`,
    });
  } catch (e) {
    // Notifications are a courtesy, not load-bearing; don't let a failure here
    // hide that the cleanup itself succeeded.
    console.error("certCleanup: notification failed", e);
  }
}

function scheduleStartupCleanup() {
  browser.alarms.create(STARTUP_ALARM_NAME, {
    delayInMinutes: STARTUP_DELAY_MINUTES,
  });
}

browser.runtime.onInstalled.addListener(scheduleStartupCleanup);
browser.runtime.onStartup.addListener(scheduleStartupCleanup);

browser.alarms.create(CLEANUP_ALARM_NAME, {
  periodInMinutes: CLEANUP_PERIOD_MINUTES,
});
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === STARTUP_ALARM_NAME) {
    runCleanup("startup, delayed");
  } else if (alarm.name === CLEANUP_ALARM_NAME) {
    runCleanup("scheduled");
  }
});
