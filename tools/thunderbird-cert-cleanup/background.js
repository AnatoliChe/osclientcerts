/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// EXPERIMENT BUILD (experiment/cert-cleanup-mid-session branch), not for
// production. Minimal, single-shot test: run cleanup exactly once, 10
// seconds after Thunderbird starts, then do nothing else. No periodic
// timer. This isolates one question: does a single mid-session cert9.db
// delete (implementation.js still also reloads the osclientcerts PKCS#11
// module afterward -- see reloadOwnModule() there) block reading encrypted
// mail for the rest of the session, on this build. Trunk's 0.4.0 moved
// cleanup to shutdown-only because earlier mid-session attempts (without
// the module reload) broke this reliably -- see the README's "Why cleanup
// only runs at shutdown".

const VERSION = browser.runtime.getManifest().version;
const STARTUP_DELAY_MS = 10000;

async function runCleanup(reason) {
  console.log(`certCleanup v${VERSION} EXPERIMENT (${reason}): starting`);

  let deleted;
  try {
    deleted = await browser.certCleanup.cleanup();
  } catch (e) {
    console.error(`certCleanup v${VERSION} EXPERIMENT (${reason}): cleanup call failed`, e);
    return;
  }

  if (deleted.length === 0) {
    console.log(`certCleanup v${VERSION} EXPERIMENT (${reason}): nothing to clean up`);
    return;
  }

  console.log(
    `certCleanup v${VERSION} EXPERIMENT (${reason}): removed ${deleted.length} stale certificate record(s) -- now try reading encrypted mail and watch for breakage`,
    deleted
  );
}

browser.runtime.onStartup.addListener(() => {
  setTimeout(() => runCleanup("startup+10s"), STARTUP_DELAY_MS);
});
// onInstalled also fires for "Load Temporary Add-on" (no separate
// onStartup event in that case, since Thunderbird was already running) --
// cover that path too so the temporary-load workflow used for this testing
// actually exercises the delay instead of silently doing nothing.
browser.runtime.onInstalled.addListener(() => {
  setTimeout(() => runCleanup("install+10s"), STARTUP_DELAY_MS);
});
