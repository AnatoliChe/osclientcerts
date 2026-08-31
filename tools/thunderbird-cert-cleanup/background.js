/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// SEND-BUTTON-TRIGGER BUILD, not for production. All of the trigger logic
// (the Send toolbar button and File > Send Now / Send Later menu items in
// the compose window) lives in the privileged Experiment side -- see
// experiments/certCleanup/implementation.js, whose getAPI() sets up a
// domwindowopened observer and hooks each compose window directly, since
// that's not something the WebExtension compose API exposes an event for.
//
// certCleanup.activate() is called once, purely to guarantee getAPI() has
// actually run: Thunderbird can load an Experiment's parent script lazily,
// on first access to its API, rather than eagerly with the add-on. Since
// this Experiment's real job is registering listeners rather than answering
// calls, nothing else here would ever touch the API otherwise -- confirmed
// the hard way: without a call like this, implementation.js's setup never
// ran at all, silently, no log line, nothing.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION} SEND-BUTTON-TRIGGER: background page loaded`);

browser.certCleanup
  .activate()
  .then(() => {
    console.log(`certCleanup v${VERSION} SEND-BUTTON-TRIGGER: activated`);
  })
  .catch((e) => {
    console.error(`certCleanup v${VERSION} SEND-BUTTON-TRIGGER: activate() failed`, e);
  });
