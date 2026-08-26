/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const DAILY_ALARM_NAME = "cert-cleanup-daily";

async function runCleanup(reason) {
  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup (${reason}): cleanup call failed`, e);
    return;
  }

  if (deleted.length === 0) {
    console.log(`certCleanup (${reason}): nothing to clean up`);
    return;
  }

  console.log(
    `certCleanup (${reason}): removed ${deleted.length} stale certificate record(s)`,
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

browser.runtime.onInstalled.addListener(() => runCleanup("install"));
browser.runtime.onStartup.addListener(() => runCleanup("startup"));

browser.alarms.create(DAILY_ALARM_NAME, { periodInMinutes: 24 * 60 });
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === DAILY_ALARM_NAME) {
    runCleanup("scheduled");
  }
});
