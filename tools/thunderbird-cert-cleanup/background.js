/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// TRIGGER-SELECTOR BUILD, not for production. The trigger logic lives
// entirely in the privileged Experiment side -- see
// experiments/certCleanup/implementation.js. Which of the four trigger
// events (compose window open, Send button click, send failure, send
// success) actually run cleanup is configurable from the add-on's options
// page (options.html/options.js), persisted in browser.storage.local, and
// pushed into the Experiment via certCleanup.configure(). App shutdown
// always runs cleanup too, independent of this configuration.
//
// certCleanup.activate() is called once at startup, purely to guarantee
// getAPI() has actually run (see implementation.js and schema.json for
// why) -- nothing else here would ever touch the API otherwise.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION}: background page loaded`);

// Keep in sync with activeTriggers' initial value in
// experiments/certCleanup/implementation.js and options.js.
const DEFAULT_TRIGGERS = {
  windowOpen: false,
  sendButtonClick: false,
  sendError: true,
  sendSuccess: false,
};

async function applyStoredTriggers() {
  const stored = await browser.storage.local.get("triggers");
  const triggers = { ...DEFAULT_TRIGGERS, ...(stored.triggers || {}) };
  await browser.certCleanup.configure(triggers);
  console.log(`certCleanup v${VERSION}: triggers configured`, triggers);
}

browser.certCleanup
  .activate()
  .then(applyStoredTriggers)
  .then(() => {
    console.log(`certCleanup v${VERSION}: activated`);
  })
  .catch((e) => {
    console.error(`certCleanup v${VERSION}: activate() failed`, e);
  });

// Live-reconfigure without needing a restart whenever the options page
// changes the saved triggers.
browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.triggers) {
    return;
  }
  const triggers = { ...DEFAULT_TRIGGERS, ...(changes.triggers.newValue || {}) };
  browser.certCleanup.configure(triggers).catch((e) => {
    console.error(`certCleanup v${VERSION}: configure() on storage change failed`, e);
  });
});
