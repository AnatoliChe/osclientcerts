/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// ON-COMPOSE-ERROR-TRIGGER + REINIT-CERTVERIFIER BUILD, not for production.
// The trigger logic lives entirely in the privileged Experiment side -- see
// experiments/certCleanup/implementation.js, which runs cleanup only on an
// actual send failure (nsIMsgComposeStateListener.ComposeProcessDone) or at
// app shutdown, and rebuilds Gecko's CertVerifier singleton from scratch
// after a cleanup pass that actually removed something -- confirmed
// (v0.4.34, on this branch's earlier proactive-compose-open trigger build)
// to make reading self-heal after every send, not just the first per
// session.
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
