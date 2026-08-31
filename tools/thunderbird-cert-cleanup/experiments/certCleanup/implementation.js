/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// GETCERTS-PLUS-LOGOUT CONTROL BUILD (experiment/cert-cleanup-mid-session
// branch), not for production. 0.4.10 (getCerts() alone, no cert9.db
// access at all) still broke reading encrypted mail. This build calls
// getCerts() and then immediately calls nsIPK11Token.
// logoutAndDropAuthenticatedResources() on the "OS Client Cert Token" slot,
// to test whether that recovers/avoids whatever getCerts() disturbs.
// logoutAndDropAuthenticatedResources() is the same kind of operation a
// "Log Out" action in Certificate Manager's Device Manager would perform on
// a token -- explicitly drops cached/authenticated state for that slot,
// lighter-weight than a full PKCS#11 module unload+reload.

const { ExtensionCommon } = ChromeUtils.importESModule(
  "resource://gre/modules/ExtensionCommon.sys.mjs"
);

const OS_CLIENT_CERTS_TOKEN_NAME = "OS Client Cert Token";

console.log("certCleanup: implementation.js loaded (getCerts+logout build)");

// Robust against API drift: this branch has now seen listModules()/
// listSlots() behave as (a) a classic nsISimpleEnumerator (no for-of
// support, needs hasMoreElements()/getNext()), (b) something that doesn't
// support hasMoreElements() either, and (c) a Promise -- on three different
// Thunderbird Daily nightly builds. The exact XPCOM binding for these
// methods is apparently still in flux upstream. Handle whichever shape
// shows up, await-ing first if it's a Promise.
async function enumerate(result) {
  if (result == null) {
    return [];
  }
  if (typeof result.then === "function") {
    return enumerate(await result);
  }
  if (typeof result.hasMoreElements === "function") {
    const items = [];
    while (result.hasMoreElements()) {
      items.push(result.getNext());
    }
    return items;
  }
  if (typeof result[Symbol.iterator] === "function") {
    return Array.from(result);
  }
  if (typeof result.length === "number") {
    return Array.from({ length: result.length }, (_, i) => result[i]);
  }
  console.log("certCleanup: enumerate() got an unrecognized shape: " + result);
  return [];
}

async function findOwnSlot() {
  const moduleDB = Cc["@mozilla.org/security/pkcs11moduledb;1"].getService(
    Ci.nsIPKCS11ModuleDB
  );
  const modules = await enumerate(moduleDB.listModules());
  console.log("certCleanup: findOwnSlot: " + modules.length + " module(s)");
  for (const module of modules) {
    const mod = module.QueryInterface(Ci.nsIPKCS11Module);
    const slots = await enumerate(mod.listSlots());
    console.log(
      "certCleanup: findOwnSlot: module '" + mod.name + "' has " +
        slots.length + " slot(s)"
    );
    for (const slot of slots) {
      const s = slot.QueryInterface(Ci.nsIPKCS11Slot);
      console.log("certCleanup: findOwnSlot: slot tokenName='" + s.tokenName + "'");
      if (s.tokenName === OS_CLIENT_CERTS_TOKEN_NAME) {
        return s;
      }
    }
  }
  return null;
}

async function doCleanup() {
  console.log("certCleanup: doCleanup starting (getCerts + logout, no file access)");
  const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
    Ci.nsIX509CertDB
  );

  const certs = certDB.getCerts();
  const liveCerts = certs.filter(
    (cert) => (cert.tokenName || "").trim() === OS_CLIENT_CERTS_TOKEN_NAME
  );
  console.log(
    "certCleanup: getCerts() returned " + certs.length +
      " total, " + liveCerts.length + " on token '" +
      OS_CLIENT_CERTS_TOKEN_NAME + "'"
  );

  const slot = await findOwnSlot();
  if (!slot) {
    console.log("certCleanup: could not find our slot, skipping logout");
    return [];
  }
  try {
    // Same API-drift defensiveness as enumerate(): getToken() might also be
    // a Promise on this build.
    let tokenResult = slot.getToken();
    if (tokenResult && typeof tokenResult.then === "function") {
      tokenResult = await tokenResult;
    }
    const token = tokenResult.QueryInterface(Ci.nsIPK11Token);
    console.log(
      "certCleanup: calling logoutAndDropAuthenticatedResources() on token '" +
        token.tokenName + "'"
    );
    let logoutResult = token.logoutAndDropAuthenticatedResources();
    if (logoutResult && typeof logoutResult.then === "function") {
      await logoutResult;
    }
    console.log("certCleanup: logoutAndDropAuthenticatedResources() returned");
  } catch (e) {
    Cu.reportError("certCleanup: logout failed: " + e);
  }

  console.log("certCleanup: doCleanup finished");
  return [];
}

var certCleanup = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    return {
      certCleanup: {
        cleanup: doCleanup,
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
