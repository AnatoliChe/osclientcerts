/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// SIGN-CHECKBOX-TRIGGER BUILD, not for production. The trigger under test
// this time (the Security > "Digitally Sign This Message" checkbox in the
// compose window) is hooked entirely from the privileged Experiment side
// (see experiments/certCleanup/implementation.js -- it monkey-patches the
// compose window's own toggleGlobalSignMessage() function directly), since
// that's not something the WebExtension compose API exposes an event for.
// This file has nothing left to trigger; it just confirms the add-on loaded.

const VERSION = browser.runtime.getManifest().version;
console.log(`certCleanup v${VERSION} SIGN-CHECKBOX-TRIGGER: background page loaded`);
