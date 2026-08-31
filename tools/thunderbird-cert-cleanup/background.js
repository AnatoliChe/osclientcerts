/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Cleanup runs from two places: the AsyncShutdown.appShutdownConfirmed
// blocker in experiments/certCleanup/implementation.js (registered at module
// load, independent of this file), and the windows.onCreated listener below.
// See "Why cleanup runs at shutdown and when composing" in README.md for why
// both exist and the trade-off the compose-time trigger accepts.
const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION}: background page loaded`);

// A standalone compose window has Window.type === "messageCompose" (added in
// Thunderbird 70) -- this fires for new messages, replies, and forwards
// alike, as soon as the window is created, which is the earliest signal a
// WebExtension has for "the user is about to compose a message" (the
// `compose` namespace itself has no window-opened event of its own).
browser.windows.onCreated.addListener(async (window) => {
  if (window.type !== "messageCompose") {
    return;
  }
  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION}: cleanup on compose-window-open failed`, e);
    return;
  }
  if (deleted.length > 0) {
    console.log(
      `certCleanup v${VERSION} (compose-window-open): removed ${deleted.length} stale certificate record(s)`,
      deleted
    );
  }
});
