/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// SIGN-CHECKBOX-TRIGGER BUILD, not for production. The trigger under test
// this time (the Security > "Digitally Sign This Message" checkbox in the
// compose window) is hooked entirely from the privileged Experiment side
// (see experiments/certCleanup/implementation.js -- it registers a
// domwindowopened observer and hooks each compose window directly), since
// that's not something the WebExtension compose API exposes an event for.
// This file's only remaining job is to call certCleanup.ping() once at
// startup: Experiment "parent" scripts may load lazily on first API access
// rather than eagerly with the add-on, and this file otherwise never
// touches the certCleanup API at all -- without this call, implementation.js
// (and therefore its domwindowopened observer registration) might never
// run in the first place.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION} SIGN-CHECKBOX-TRIGGER: background page loaded`);

browser.certCleanup
  .ping()
  .then(() => {
    console.log(`certCleanup v${VERSION} SIGN-CHECKBOX-TRIGGER: ping() succeeded`);
  })
  .catch((e) => {
    console.error(`certCleanup v${VERSION} SIGN-CHECKBOX-TRIGGER: ping() failed`, e);
  });
