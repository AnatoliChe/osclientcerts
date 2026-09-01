/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// FRESH-GSMFIELDS-RETRY BUILD, not for production. The trigger logic lives
// entirely in the privileged Experiment side -- see
// experiments/certCleanup/implementation.js, which runs cleanup only on an
// actual send failure (nsIMsgComposeStateListener.ComposeProcessDone) or at
// app shutdown, and rebuilds Gecko's CertVerifier singleton from scratch
// after a cleanup pass that actually removed something. The retry after a
// failure uses a freshly recreated nsIMsgComposeSecure instance instead of
// reusing the failed attempt's, which is what actually fixes (not just
// works around) the duplicate-RecipientInfo corruption bug found
// 2026-09-01.
//
// certCleanup.activate() is called once at startup, purely to guarantee
// getAPI() has actually run (see implementation.js and schema.json for
// why) -- nothing else here would ever touch the API otherwise.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION}: background page loaded`);

browser.certCleanup.activate().catch((e) => {
  console.error(`certCleanup v${VERSION}: activate() failed`, e);
});
