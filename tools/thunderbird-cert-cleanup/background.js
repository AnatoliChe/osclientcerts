/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// ON-SEND-ERROR-TRIGGER BUILD, not for production. Every trigger tried so
// far on this branch ran cleanup proactively -- on every compose-window-open
// or every send -- which disrupts reading even on runs that find nothing to
// delete (getCerts() alone is enough; see implementation.js). This build
// only runs cleanup reactively, when browser.compose.onAfterSend reports a
// send actually failed (sendInfo.error is set): the send that just failed
// can't be un-failed by cleanup running after the fact, but the user can
// retry once it's done, and this cuts how often the known
// reading-disruption side effect happens down to only when there's a real
// problem to fix, instead of on every window/send regardless.
//
// certCleanup.activate() is still called once at startup, purely to
// guarantee getAPI() has actually run (see implementation.js and
// schema.json for why) -- registering the shutdown blocker doesn't happen
// on its own otherwise.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION} ON-SEND-ERROR-TRIGGER: background page loaded`);

browser.certCleanup
  .activate()
  .then(() => {
    console.log(`certCleanup v${VERSION} ON-SEND-ERROR-TRIGGER: activated`);
  })
  .catch((e) => {
    console.error(`certCleanup v${VERSION} ON-SEND-ERROR-TRIGGER: activate() failed`, e);
  });

browser.compose.onAfterSend.addListener(async (tab, sendInfo) => {
  if (!sendInfo.error) {
    return;
  }
  console.log(
    `certCleanup v${VERSION} ON-SEND-ERROR-TRIGGER: send failed (${sendInfo.error}), running cleanup`
  );
  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} ON-SEND-ERROR-TRIGGER: cleanup call failed`, e);
    return;
  }
  console.log(
    `certCleanup v${VERSION} ON-SEND-ERROR-TRIGGER: done, ${deleted.length} deleted -- try resending, and check whether reading encrypted mail still works`
  );
});
