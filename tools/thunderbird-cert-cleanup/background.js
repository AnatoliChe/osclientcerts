/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// REINIT-CERTVERIFIER-EXPERIMENT BUILD, not for production. The trigger logic lives
// entirely in the privileged Experiment side -- see
// experiments/certCleanup/implementation.js, which runs cleanup on new
// compose window open and on app shutdown, and additionally rebuilds
// Gecko's CertVerifier singleton from scratch after a cleanup pass that
// actually removed something.
//
// certCleanup.activate() is still called once at startup, purely to
// guarantee getAPI() has actually run (see implementation.js and
// schema.json for why) -- nothing else here would ever touch the API
// otherwise.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION} REINIT-CERTVERIFIER-EXPERIMENT: background page loaded`);

browser.certCleanup
  .activate()
  .then(() => {
    console.log(`certCleanup v${VERSION} REINIT-CERTVERIFIER-EXPERIMENT: activated`);
  })
  .catch((e) => {
    console.error(`certCleanup v${VERSION} REINIT-CERTVERIFIER-EXPERIMENT: activate() failed`, e);
  });
