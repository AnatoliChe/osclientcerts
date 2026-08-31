/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// DBKEY-LOOKUP BUILD (experiment/cert-cleanup-mid-session branch), not for
// production. Every build so far that called nsIX509CertDB.getCerts()
// mid-session broke reading encrypted mail afterward -- even a build that
// called *only* getCerts() and touched nothing else. But the user found
// that composing and sending a signed+encrypted message *recovers* reading
// in the same session. Thunderbird's own compose-security code
// (mailnews/extensions/smime/nsMsgComposeSecure.cpp, MimeCryptoHackCerts())
// never calls getCerts() to find the identity's own certificate -- it reads
// the "signing_cert_dbkey"/"encryption_cert_dbkey" identity preferences
// (set once, when the user picks a certificate in Account Settings) and
// resolves them with nsIX509CertDB.findCertByDBKey(), a single targeted
// lookup, not a full multi-slot enumeration.
//
// This build does the same thing instead of getCerts(): reads those dbkey
// prefs from every mail identity via MailServices.accounts.allIdentities
// (a plain Array<nsIMsgIdentity>, not PKCS#11-related, so none of the
// nsISimpleEnumerator/Promise API-drift pain seen with
// nsIPKCS11ModuleDB.listModules() on this branch applies to it) and calls
// findCertByDBKey() for each one -- never calling getCerts() at all. If
// this build doesn't break reading, that confirms getCerts()'s full
// enumeration specifically is what corrupts things, not any access to our
// token whatsoever -- and this becomes the real fix, not just a control
// build.

const { ExtensionCommon } = ChromeUtils.importESModule(
  "resource://gre/modules/ExtensionCommon.sys.mjs"
);

console.log("certCleanup: implementation.js loaded (dbkey-lookup build)");

// Plain XPCOM file read (nsIFileInputStream + nsIBinaryInputStream), not
// Sqlite.sys.mjs -- confirmed safe on its own in 0.4.8 (only getCerts(),
// not this, broke reading in that build).
function readFileBytes(file) {
  const stream = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(
    Ci.nsIFileInputStream
  );
  stream.init(file, -1, -1, 0);
  const binStream = Cc["@mozilla.org/binaryinputstream;1"].createInstance(
    Ci.nsIBinaryInputStream
  );
  binStream.setInputStream(stream);
  const bytes = binStream.readByteArray(binStream.available());
  binStream.close();
  return new Uint8Array(bytes);
}

function containsSubsequence(haystack, needle) {
  if (needle.length === 0 || needle.length > haystack.length) {
    return false;
  }
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return true;
  }
  return false;
}

// Finds our own live certificate(s) the same way Thunderbird's own
// compose-security code does when it's about to sign/encrypt: read the
// per-identity dbkey preference(s), resolve each with findCertByDBKey().
// No getCerts() call anywhere in this path.
function findLiveCertsViaIdentities(certDB) {
  const { MailServices } = ChromeUtils.importESModule(
    "resource:///modules/MailServices.sys.mjs"
  );

  const liveCerts = [];
  const seenDbKeys = new Set();
  const identities = MailServices.accounts.allIdentities;
  console.log("certCleanup: " + identities.length + " mail identity(ies)");
  for (const identity of identities) {
    for (const attr of ["signing_cert_dbkey", "encryption_cert_dbkey"]) {
      let dbKey;
      try {
        dbKey = identity.getCharAttribute(attr);
      } catch (e) {
        continue;
      }
      if (!dbKey || seenDbKeys.has(dbKey)) {
        continue;
      }
      seenDbKeys.add(dbKey);
      let cert;
      try {
        cert = certDB.findCertByDBKey(dbKey);
      } catch (e) {
        console.log(
          "certCleanup: findCertByDBKey failed for " + attr + ": " + e
        );
        continue;
      }
      if (cert) {
        console.log(
          "certCleanup: resolved " + attr + " -> subject=" + cert.subjectName
        );
        liveCerts.push(cert);
      }
    }
  }
  return liveCerts;
}

async function doCleanup() {
  console.log("certCleanup: doCleanup starting (dbkey lookup, no getCerts())");
  const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
    Ci.nsIX509CertDB
  );

  const liveCerts = findLiveCertsViaIdentities(certDB);
  if (liveCerts.length === 0) {
    console.log("certCleanup: no live certs resolved via identity dbkeys, nothing to do");
    return [];
  }

  const profileDir = Services.dirsvc.get("ProfD", Ci.nsIFile);
  const dbFile = profileDir.clone();
  dbFile.append("cert9.db");
  const dbBytes = readFileBytes(dbFile);
  console.log("certCleanup: read " + dbBytes.length + " bytes from cert9.db");

  const deleted = [];
  for (const liveCert of liveCerts) {
    const derArray = liveCert.getRawDER();
    const der = Uint8Array.from(derArray);
    console.log("certCleanup: scanning for subject=" + liveCert.subjectName);
    const found = containsSubsequence(dbBytes, der);
    console.log("certCleanup: " + (found ? "found" : "not found") + " in cert9.db");
    if (!found) {
      continue;
    }
    try {
      const tempCert = certDB.constructX509(derArray);
      certDB.deleteCertificate(tempCert);
      deleted.push({
        subjectName: liveCert.subjectName,
        issuerName: liveCert.issuerName,
        serialNumber: liveCert.serialNumber,
      });
    } catch (e) {
      Cu.reportError(
        "certCleanup: deleteCertificate failed for subject=" +
          liveCert.subjectName + ": " + e
      );
    }
  }

  console.log("certCleanup: doCleanup finished, " + deleted.length + " deleted");
  return deleted;
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
