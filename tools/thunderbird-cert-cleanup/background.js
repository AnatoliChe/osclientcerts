/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Cleanup no longer runs on any schedule from here -- see the
// AsyncShutdown.appShutdownConfirmed blocker in
// experiments/certCleanup/implementation.js, which is what actually removes
// stale cert9.db duplicates, and only at Thunderbird shutdown. This file's
// only job is to give the extension a background context (required for its
// Experiment API to be registered at all) and to log its own version for
// diagnostics.
const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION}: background page loaded`);
