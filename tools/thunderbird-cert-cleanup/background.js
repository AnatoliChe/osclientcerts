/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// ON-COMPOSE-ERROR-TRIGGER BUILD, not for production. The trigger logic
// lives entirely in the privileged Experiment side -- see
// experiments/certCleanup/implementation.js, which registers an
// nsIMsgComposeStateListener on each compose window and runs cleanup only
// when ComposeProcessDone reports an actual failure. That's not something
// the WebExtension compose API can see (browser.compose.onAfterSend
// structurally never fires for this kind of failure -- see
// implementation.js for why, confirmed against comm-central's own source).
//
// certCleanup.activate() is still called once at startup, purely to
// guarantee getAPI() has actually run (see implementation.js and
// schema.json for why) -- nothing else here would ever touch the API
// otherwise.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION} ON-COMPOSE-ERROR-TRIGGER: background page loaded`);

browser.certCleanup
  .activate()
  .then(() => {
    console.log(`certCleanup v${VERSION} ON-COMPOSE-ERROR-TRIGGER: activated`);
  })
  .catch((e) => {
    console.error(`certCleanup v${VERSION} ON-COMPOSE-ERROR-TRIGGER: activate() failed`, e);
  });
