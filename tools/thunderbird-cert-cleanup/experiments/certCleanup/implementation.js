/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// GETCERTS-ONLY CONTROL BUILD (experiment/cert-cleanup-mid-session branch),
// not for production. Calls nsIX509CertDB.getCerts() and filters for our
// live certs -- nothing else. No cert9.db file access of any kind (no
// Sqlite.sys.mjs, no nsIFileInputStream, nothing). 0.4.9 (touches nothing
// cert-related at all) did NOT break reading; 0.4.8 (getCerts() + a plain
// read-only file read that found nothing) DID break reading. This build
// isolates which half of that is responsible: getCerts() itself, or the
// file read.

const { ExtensionCommon } = ChromeUtils.importESModule(
  "resource://gre/modules/ExtensionCommon.sys.mjs"
);

const OS_CLIENT_CERTS_TOKEN_NAME = "OS Client Cert Token";

console.log("certCleanup: implementation.js loaded (getCerts-only build)");

async function doCleanup() {
  console.log("certCleanup: doCleanup starting (getCerts-only, no file access)");
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
  console.log("certCleanup: doCleanup finished -- no file access attempted");
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
