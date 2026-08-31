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
function findLiveCertsViaIdentities(certDB, identities) {
  const liveCerts = [];
  const seenDbKeys = new Set();
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

// Synthesizes a real sign+encrypt operation through nsIMsgComposeSecure --
// the exact same crypto pipeline a real compose+send goes through
// (mailnews/compose/src/MimeMessage.sys.mjs's real production call
// sequence, confirmed against that source) -- addressed to the identity's
// own email, written to a throwaway temp file, never touching nsIMsgSend
// (the actual SMTP-sending component) at all. The user found that
// composing and sending a real signed+encrypted message recovers reading
// after our lookups break it; this tests whether a *real* PK11 sign/
// encrypt operation through the token (as opposed to a mere certificate
// lookup, which we already know doesn't help) is what actually does the
// recovering, by triggering the same kind of operation synthetically.
async function synthesizeSignEncrypt(identity) {
  const compFields = Cc[
    "@mozilla.org/messengercompose/composefields;1"
  ].createInstance(Ci.nsIMsgCompFields);
  const composeSecure = Cc[
    "@mozilla.org/messengercompose/composesecure;1"
  ].createInstance(Ci.nsIMsgComposeSecure);
  compFields.composeSecure = composeSecure;
  composeSecure.signMessage = true;
  composeSecure.requireEncryptMessage = true;
  composeSecure.signFormat = "multipart";
  compFields.to = identity.email;

  if (!composeSecure.requiresCryptoEncapsulation(identity, compFields)) {
    console.log(
      "certCleanup: synthesizeSignEncrypt: requiresCryptoEncapsulation() " +
        "said no (no cert configured for this identity?), skipping"
    );
    return false;
  }

  const tmpFile = Services.dirsvc.get("TmpD", Ci.nsIFile);
  tmpFile.append("certcleanup-synth.eml");
  tmpFile.createUnique(Ci.nsIFile.NORMAL_FILE_TYPE, 0o600);

  const rawStream = Cc[
    "@mozilla.org/network/file-output-stream;1"
  ].createInstance(Ci.nsIFileOutputStream);
  rawStream.init(tmpFile, -1, -1, 0);
  const bufStream = Cc[
    "@mozilla.org/network/buffered-output-stream;1"
  ].createInstance(Ci.nsIBufferedOutputStream);
  bufStream.init(rawStream, 16 * 1024);

  const sendReport = Cc[
    "@mozilla.org/messengercompose/sendreport;1"
  ].createInstance(Ci.nsIMsgSendReport);

  try {
    const outputStream = bufStream.QueryInterface(Ci.nsIOutputStream);
    console.log(
      "certCleanup: synthesizeSignEncrypt: about to call beginCryptoEncapsulation with:\n" +
        "  outputStream=" + outputStream + " (typeof " + typeof outputStream + ")\n" +
        "  recipients=" + JSON.stringify(compFields.to) + " (typeof " + typeof compFields.to + ")\n" +
        "  compFields=" + compFields + "\n" +
        "  headers=\"\"\n" +
        "  identity=" + identity + ", identity.email=" + JSON.stringify(identity.email) + "\n" +
        "  sendReport=" + sendReport + "\n" +
        "  isDraft=true"
    );
    composeSecure.beginCryptoEncapsulation(
      outputStream,
      compFields.to,
      compFields,
      "",
      identity,
      sendReport,
      true // aIsDraft -- this is never actually sent or saved as a real message
    );
    const body = "certCleanup synthetic message, not sent.\r\n";
    composeSecure.mimeCryptoWriteBlock(body, body.length);
    composeSecure.finishCryptoEncapsulation(false, sendReport);
    console.log("certCleanup: synthesizeSignEncrypt: finishCryptoEncapsulation done");
    return true;
  } catch (e) {
    Cu.reportError("certCleanup: synthesizeSignEncrypt failed: " + e);
    return false;
  } finally {
    bufStream.close();
    rawStream.close();
    try {
      tmpFile.remove(false);
    } catch (e) {
      // Not load-bearing; leaving a stray temp file behind isn't harmful.
    }
  }
}

async function doCleanup() {
  console.log("certCleanup: doCleanup starting (dbkey lookup, no getCerts())");
  const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
    Ci.nsIX509CertDB
  );
  const { MailServices } = ChromeUtils.importESModule(
    "resource:///modules/MailServices.sys.mjs"
  );
  const identities = MailServices.accounts.allIdentities;
  console.log("certCleanup: " + identities.length + " mail identity(ies)");

  const liveCerts = findLiveCertsViaIdentities(certDB, identities);
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

  // Recovery step: the user found that a real compose+send (real
  // sign/encrypt through the token) recovers reading after our lookups
  // above break it -- but a mere additional certificate *lookup*
  // (findCertByDBKey, tested in this same build without this step) did
  // not. This synthesizes that same real sign+encrypt operation, silently,
  // to test whether it's specifically the crypto operation (not just
  // another lookup) that recovers things. Runs regardless of whether we
  // found anything to delete, since a bare lookup alone was already shown
  // to break reading.
  if (identities.length > 0) {
    try {
      await synthesizeSignEncrypt(identities[0]);
    } catch (e) {
      Cu.reportError("certCleanup: synthesizeSignEncrypt threw: " + e);
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
