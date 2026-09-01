/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// PROACTIVE-ONLY BUILD, not for production. The trigger logic lives
// entirely in the privileged Experiment side -- see
// experiments/certCleanup/implementation.js, which uses three proactive
// triggers and no reactive failure-handling/retry at all: a new compose
// window unconditionally rebuilds Gecko's CertVerifier singleton; the
// Send button/menu, intercepted before the real send starts, only removes
// a stale cert9.db duplicate (no reinit); app shutdown removes a stale
// duplicate the same way. Cleanup always runs before this window's only
// send attempt, so there's no same-window-retry risk and no need to touch
// nsIMsgComposeSecure at all.
//
// certCleanup.activate() is called once at startup, purely to guarantee
// getAPI() has actually run (see implementation.js and schema.json for
// why) -- nothing else here would ever touch the API otherwise.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION}: background page loaded`);

browser.certCleanup.activate().catch((e) => {
  console.error(`certCleanup v${VERSION}: activate() failed`, e);
});
