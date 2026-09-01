/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Cleanup runs from two places, both in the privileged Experiment side (see
// experiments/certCleanup/implementation.js): the
// AsyncShutdown.appShutdownConfirmed blocker, and an nsIMsgComposeStateListener
// on each compose window that reacts to a failed send (cleans up, then
// automatically retries). Since 0.7.0, a cleanup pass that actually removes
// something is also followed by rebuilding Gecko's CertVerifier singleton
// (reinitCertVerifier() in implementation.js), which is what makes this
// self-heal reliably instead of only on the first occurrence per session.
// See README.md ("Why cleanup runs at shutdown and on a failed send") for
// why.
//
// certCleanup.activate() is called once at startup purely to guarantee
// getAPI() has actually run: Thunderbird can load an Experiment's parent
// script lazily, on first access to its API, rather than eagerly with the
// add-on, and this file otherwise never touches the API at all -- without
// this call, implementation.js's setup would silently never run.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION}: background page loaded`);

browser.certCleanup.activate().catch((e) => {
  console.error(`certCleanup v${VERSION}: activate() failed`, e);
});
