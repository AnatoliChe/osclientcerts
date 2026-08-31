/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// NO-OP EXPERIMENT BUILD (experiment/cert-cleanup-mid-session branch), not
// for production. Absolute minimal control test: this Experiment does
// nothing at all -- no cert9.db access, no getCerts(), no AsyncShutdown
// blocker, nothing -- to isolate whether merely having this kind of
// WebExtension Experiment loaded and running *any* code ~10s after startup
// is enough to break reading encrypted mail, independent of anything
// cert-related. Every previous build (including 0.4.8, which touched
// cert9.db only via a plain read-only file read that found nothing) still
// broke reading; this build exists to find out whether it's specifically
// our cert-related code at fault, or something else entirely coinciding
// with this extension's presence/timing.

const { ExtensionCommon } = ChromeUtils.importESModule(
  "resource://gre/modules/ExtensionCommon.sys.mjs"
);

console.log("certCleanup: implementation.js loaded (no-op build)");

var certCleanup = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    return {
      certCleanup: {
        // No-op: intentionally does nothing. background.js does not call
        // this at all in this build -- see its own top-level comment.
        async cleanup() {
          return [];
        },
      },
    };
  }

  onShutdown(isAppShutdown) {
    if (isAppShutdown) {
      return;
    }
    Services.obs.notifyObservers(null, "startupcache-invalidate", null);
  }
};
