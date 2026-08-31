/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Privileged WebExtension Experiment implementation. Runs in the parent process
// with full access to Gecko's internal APIs (Cc/Ci), unlike the sandboxed
// background script. See ../../README.md for why this exists and how it's used.
//
// ExtensionCommon is not a predefined global in this scope (unlike Cc/Ci/Cu,
// which are) -- it must be imported explicitly, same as any other privileged
// Gecko module.
const { ExtensionCommon } = ChromeUtils.importESModule(
  "resource://gre/modules/ExtensionCommon.sys.mjs"
);
const { AsyncShutdown } = ChromeUtils.importESModule(
  "resource://gre/modules/AsyncShutdown.sys.mjs"
);

// The PKCS#11 token label the osclientcerts provider reports via C_GetTokenInfo
// (see TOKEN_LABEL_BYTES in fork-osclientcerts/src/lib.rs).
const OS_CLIENT_CERTS_TOKEN_NAME = "OS Client Cert Token";

// Unconditional, logged the moment this privileged script loads (not
// gated on getAPI() being called, which happens separately per
// background-page context). Confirms the Experiment itself initialized,
// independent of whether background.js's own top-level log shows up.
console.log("certCleanup: implementation.js loaded");

// EXPERIMENTAL (experiment/cert-cleanup-mid-session branch): after deleting a
// duplicate, force a full unload+reload of our own PKCS#11 module -- the
// same operation the "Unload"/"Load" buttons in Certificate Manager's
// Device Manager perform (nsIPKCS11ModuleDB.deleteModule/addModule; see
// security/manager/pki/resources/content/{device_manager,load_device}.js).
// That's a full C_Finalize/C_Initialize cycle for the module, which should
// force NSS/Gecko to fully re-resolve everything on our slot from scratch,
// on the theory that whatever Gecko-level state goes stale after a
// mid-session delete (see the long comment in doCleanup() below) is tied to
// the slot/module and gets rebuilt cleanly by a reload. Untested hypothesis
// -- that's what this branch exists to find out.
// nsISimpleEnumerator doesn't support for-of in this (Experiment/addon_parent)
// scope -- confirmed via "TypeError: ... is not iterable" in testing, unlike
// the privileged chrome-document scope device_manager.js runs in, which gets
// that sugar. Plain hasMoreElements()/getNext() works everywhere.
function enumerate(enumerator) {
  const items = [];
  while (enumerator.hasMoreElements()) {
    items.push(enumerator.getNext());
  }
  return items;
}

// Plain XPCOM file read (nsIFileInputStream + nsIBinaryInputStream), not
// Sqlite.sys.mjs. See the long comment in doCleanup() below for why: a
// *second connection* to cert9.db (even strictly read-only) while NSS
// holds it open broke S/MIME decryption in production testing, even when
// literally nothing was found/deleted -- so avoid opening any second
// connection to the file at all. A plain file read has no notion of a
// database "connection" or lock negotiation with NSS's own open handle,
// just an ordinary shared-read file open.
function readFileBytes(file) {
  const stream = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(
    Ci.nsIFileInputStream
  );
  // -1, -1, 0: default read-only open flags/permissions (see nsIFileInputStream.idl).
  stream.init(file, -1, -1, 0);
  const binStream = Cc["@mozilla.org/binaryinputstream;1"].createInstance(
    Ci.nsIBinaryInputStream
  );
  binStream.setInputStream(stream);
  const bytes = binStream.readByteArray(binStream.available());
  binStream.close();
  return new Uint8Array(bytes);
}

// Plain byte-subsequence search. A full X.509 DER certificate is a large
// (roughly 1-2KB), highly structured, effectively-unique byte sequence --
// finding it verbatim anywhere in cert9.db is exactly as strong a signal
// as finding it in a specific column of a specific row would be, without
// needing to parse cert9.db's SQL structure at all.
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

function reloadOwnModule() {
  const moduleDB = Cc["@mozilla.org/security/pkcs11moduledb;1"].getService(
    Ci.nsIPKCS11ModuleDB
  );

  let targetModule = null;
  for (const module of enumerate(moduleDB.listModules())) {
    const mod = module.QueryInterface(Ci.nsIPKCS11Module);
    for (const slot of enumerate(mod.listSlots())) {
      if (slot.QueryInterface(Ci.nsIPKCS11Slot).tokenName === OS_CLIENT_CERTS_TOKEN_NAME) {
        targetModule = mod;
        break;
      }
    }
    if (targetModule) {
      break;
    }
  }
  if (!targetModule) {
    console.log(
      "certCleanup: reloadOwnModule found no loaded module exposing token '" +
        OS_CLIENT_CERTS_TOKEN_NAME + "', skipping reload"
    );
    return;
  }

  const name = targetModule.name;
  const libPath = targetModule.libName;
  console.log(
    "certCleanup: reloading PKCS#11 module '" + name + "' (" + libPath + ")"
  );
  // Same call shape load_device.js uses for a normal "Load" (mechanismFlags
  // and cipherFlags both 0 -- let NSS use its defaults).
  moduleDB.deleteModule(name);
  moduleDB.addModule(name, libPath, 0, 0);
  console.log("certCleanup: PKCS#11 module '" + name + "' reloaded");
}

// Runs the actual detect-and-delete pass. See the long comment inline below
// for why detection reads cert9.db directly but deletion goes through
// nsIX509CertDB, and why this whole pass is only ever run at shutdown -- not
// periodically during the session -- as of 0.4.0.
async function doCleanup() {
  console.log("certCleanup: doCleanup starting");
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
  if (liveCerts.length === 0) {
    // The provider isn't loaded (or has no certs) right now -- don't touch
    // cert9.db at all, since we have no way to confirm which of its rows, if
    // any, are safe to remove.
    console.log("certCleanup: no live certs found, skipping cert9.db entirely");
    return [];
  }

  // certDB.getCerts() is *not* a plain listing: Gecko's
  // nsNSSCertificateDB::GetCerts() calls PK11_ListCerts(PK11CertListUnique,
  // ...) (confirmed against NSS's own lib/pk11wrap and
  // security/manager/ssl/nsNSSCertificateDB.cpp), which silently merges a
  // persisted, keyless cert9.db row with a live token object representing
  // the same certificate -- so getCerts() never shows the duplicate as a
  // second entry while the provider is loaded, which is exactly when you'd
  // want to detect and remove it. NSS has a non-deduplicating list type
  // (PK11CertListAll), but no JS-facing API exposes it.
  //
  // So: *read* cert9.db's raw bytes directly instead (readFileBytes() above
  // -- plain nsIFileInputStream, not a database connection of any kind) and
  // search for each live certificate's exact DER byte sequence
  // (containsSubsequence() above). PKCS #11 objects belonging to an
  // *external* token like ours are never themselves written to cert9.db, so
  // finding a live certificate's DER anywhere in the file means a stale,
  // keyless, NSS-cached copy exists there -- it cannot be that live
  // certificate itself.
  //
  // This used to go through Sqlite.sys.mjs (a proper SQL query against the
  // `nssPublic` table, matching on the CKA_CLASS/CKA_VALUE columns
  // specifically), which is more precise in principle. It's gone as of this
  // build: opening a *second connection* to cert9.db via Sqlite.sys.mjs --
  // even strictly read-only (`readOnly: true`), even when the resulting
  // query found nothing to delete -- reproducibly broke S/MIME decryption
  // for the rest of the session in production testing on Windows. Zero
  // writes, zero deletions, yet the very next message failed to decrypt
  // right after the read-only connection closed. Not reproducible at the
  // raw NSS/softoken level on Linux (a from-source NSS build survived the
  // same kind of concurrent access cleanly via a custom C harness) --
  // Windows' mandatory file locking (LockFile/UnlockFile) differs
  // fundamentally from POSIX advisory locking, and SQLite's Windows VFS
  // backend negotiates locks through it; a from-Linux repro was never going
  // to catch a Windows-specific lock interaction between our connection and
  // NSS's own already-open one. A plain file read has no such negotiation
  // with NSS's handle at all, hence this rewrite.
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
    console.log(
      "certCleanup: found stale cert9.db copy of live cert subject=" +
        liveCert.subjectName
    );
    // Delete via nsIX509CertDB: constructX509() builds a transient,
    // in-memory certificate object from the duplicate's DER (not tied to
    // any token/slot), and deleteCertificate() on that object resolves and
    // removes the matching persisted record through NSS's own softoken
    // code path (PK11_DeleteTokenCertAndKey / SEC_DeletePermCertificate --
    // confirmed against nsNSSCertificateDB::DeleteCertificate), the same
    // path "Delete or Distrust" in Certificate Manager uses -- using NSS's
    // own already-open handle to cert9.db, not a new connection. If that
    // resolution ever targeted our *live* token object instead of the
    // cert9.db duplicate, the call would simply fail rather than corrupt
    // anything: osclientcerts' own C_DestroyObject is an unconditional
    // CKR_FUNCTION_NOT_SUPPORTED stub (see src/lib.rs), so an attempt to
    // destroy anything on our external token is a safe no-op.
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
  if (deleted.length > 0) {
    try {
      reloadOwnModule();
    } catch (e) {
      Cu.reportError("certCleanup: reloadOwnModule failed: " + e);
    }
  }

  return deleted;
}

const SHUTDOWN_BLOCKER_NAME =
  "certCleanup: remove stale cert9.db duplicates before quit";

async function onQuitApplication() {
  try {
    const deleted = await doCleanup();
    if (deleted.length > 0) {
      console.log(
        "certCleanup (quit-application): removed " + deleted.length +
          " stale certificate record(s)",
        deleted
      );
    }
  } catch (e) {
    Cu.reportError("certCleanup: cleanup on quit failed: " + e);
  }
}

// The earliest well-known Gecko shutdown phase (ShutdownPhase::
// AppShutdownConfirmed, topic "quit-application"), registered once when this
// script first loads (module-level code in an Experiment script runs once
// per load of the extension, independent of how many times getAPI() is
// called for background-page contexts). Blocking here, rather than doing a
// fire-and-forget cleanup, guarantees our async cert9.db work finishes
// before Thunderbird tears down further -- see the long comment in
// doCleanup() for why shutdown, and not any point during the session, is
// where this needs to run.
AsyncShutdown.appShutdownConfirmed.addBlocker(
  SHUTDOWN_BLOCKER_NAME,
  onQuitApplication
);

var certCleanup = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    return {
      certCleanup: {
        // Exposed for manual/on-demand use (e.g. from the Browser Console
        // while testing), but background.js does not call this on any
        // schedule -- see onQuitApplication above for the only place
        // cleanup actually runs in normal use.
        cleanup: doCleanup,
      },
    };
  }

  // Without this, Thunderbird can keep running a previously-loaded version of
  // this Experiment's code after the add-on is updated or reloaded (a
  // documented footgun -- see "Managing your Experiment's lifecycle" in the
  // Thunderbird WebExtension Experiments guide). Invalidating the startup
  // cache on every unload is the recommended fix.
  onShutdown(isAppShutdown) {
    if (isAppShutdown) {
      // The app itself is quitting: our AsyncShutdown blocker above (an
      // earlier phase than extension teardown) has already run and resolved
      // by the time this fires, so there's nothing left to do here.
      return;
    }
    // The extension is being disabled/reloaded/uninstalled -- not app
    // shutdown -- so the blocker registered above would otherwise leak
    // (and, worse, keep referencing this soon-to-be-stale script) across
    // the reload.
    AsyncShutdown.appShutdownConfirmed.removeBlocker(onQuitApplication);
    Services.obs.notifyObservers(null, "startupcache-invalidate", null);
  }
};
