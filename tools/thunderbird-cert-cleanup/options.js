/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Keep in sync with DEFAULT_TRIGGERS in background.js and activeTriggers'
// initial value in experiments/certCleanup/implementation.js.
const DEFAULT_TRIGGERS = {
  windowOpen: false,
  sendButtonClick: false,
  sendError: true,
  sendSuccess: false,
};

const CHECKBOX_IDS = Object.keys(DEFAULT_TRIGGERS);

async function load() {
  const stored = await browser.storage.local.get("triggers");
  const triggers = { ...DEFAULT_TRIGGERS, ...(stored.triggers || {}) };
  for (const id of CHECKBOX_IDS) {
    document.getElementById(id).checked = !!triggers[id];
  }
}

function save() {
  const triggers = {};
  for (const id of CHECKBOX_IDS) {
    triggers[id] = document.getElementById(id).checked;
  }
  // background.js listens for this via browser.storage.onChanged and
  // pushes it into the privileged Experiment immediately -- no separate
  // "Save" button, changes take effect on the next trigger event.
  browser.storage.local.set({ triggers });
}

document.addEventListener("DOMContentLoaded", () => {
  load();
  for (const id of CHECKBOX_IDS) {
    document.getElementById(id).addEventListener("change", save);
  }
});
