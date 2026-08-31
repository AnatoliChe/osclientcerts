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

// cert9.db's SQL schema (table `nssPublic`, one row per PKCS #11 object,
// columns named "a" + the attribute type in hex -- confirmed against a real
// profile's cert9.db and against NSS's own lib/softoken/sdb.c, which builds
// column names via `sqlite3_mprintf("a%x", template[i].type)`). CKA_CLASS is
// attribute 0x0; CKA_VALUE (the DER-encoded certificate) is 0x11.
const CKA_CLASS_COLUMN = "a0";
const CKA_VALUE_COLUMN = "a11";
const CKO_CERTIFICATE_BYTES = new Uint8Array([0, 0, 0, 1]);

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
  // So: *read* cert9.db directly instead, via Sqlite.sys.mjs (Gecko's
  // sanctioned module for opening additional, concurrent, read-only
  // connections to a Firefox/Thunderbird-managed sqlite database -- the same
  // mechanism other in-process code uses for shared databases like
  // places.sqlite). A row here is a genuine persisted duplicate by
  // construction: PKCS #11 objects belonging to an *external* token like
  // ours are never themselves written to cert9.db, so any CKO_CERTIFICATE
  // row whose DER byte-for-byte matches one of our live certificates cannot
  // be that live certificate -- it can only be a stale, keyless, NSS-cached
  // copy.
  const { Sqlite } = ChromeUtils.importESModule(
    "resource://gre/modules/Sqlite.sys.mjs"
  );
  const profileDir = Services.dirsvc.get("ProfD", Ci.nsIFile);
  const dbFile = profileDir.clone();
  dbFile.append("cert9.db");

  const deleted = [];
  let conn;
  try {
    console.log("certCleanup: opening read-only Sqlite.sys.mjs connection to " + dbFile.path);
    conn = await Sqlite.openConnection({
      path: dbFile.path,
      openNotExclusive: true,
      readOnly: true,
    });
    console.log("certCleanup: connection opened");
    for (const liveCert of liveCerts) {
      const derArray = liveCert.getRawDER();
      const der = Uint8Array.from(derArray);
      console.log("certCleanup: querying for subject=" + liveCert.subjectName);
      const rows = await conn.execute(
        "SELECT id FROM nssPublic WHERE " +
          CKA_CLASS_COLUMN + " = :cls AND " + CKA_VALUE_COLUMN + " = :der",
        { cls: CKO_CERTIFICATE_BYTES, der }
      );
      console.log("certCleanup: query returned " + rows.length + " row(s)");
      if (rows.length === 0) {
        continue;
      }
      console.log(
        "certCleanup: found " + rows.length +
          " stale cert9.db row(s) duplicating live cert subject=" +
          liveCert.subjectName
      );
      // Delete via nsIX509CertDB, not a second write connection: through
      // 0.2.2, deletion also went through this same Sqlite.sys.mjs
      // connection (a raw `DELETE FROM nssPublic ...`). In production
      // testing that write -- and, as it turned out, *any* mechanism that
      // removes the duplicate mid-session, including this official API --
      // left something in Gecko's C++ layer above NSS unable to resolve the
      // recipient for S/MIME decryption for the rest of that Thunderbird
      // session (confirmed via RUST_LOG=osclientcerts=debug: later
      // C_DecryptInit/C_UnwrapKey calls returned CKR_FUNCTION_NOT_SUPPORTED
      // without even a preceding C_OpenSession, meaning Gecko had stopped
      // calling into the module at all -- independently reproduced as safe
      // at the raw NSS/softoken level via a from-source NSS build, so the
      // stale state lives above NSS, not in it). That's *why* this whole
      // pass now only ever runs at shutdown (see AsyncShutdown blocker
      // below): whatever goes stale doesn't matter if the process is about
      // to exit anyway, and the next session starts with a clean read of
      // the already-fixed file. constructX509() builds a transient,
      // in-memory certificate object from the duplicate's DER (not tied to
      // any token/slot), and deleteCertificate() on that object resolves
      // and removes the matching persisted record through NSS's own
      // softoken code path (PK11_DeleteTokenCertAndKey /
      // SEC_DeletePermCertificate -- confirmed against
      // nsNSSCertificateDB::DeleteCertificate), the same path "Delete or
      // Distrust" in Certificate Manager uses. If that resolution ever
      // targeted our *live* token object instead of the cert9.db
      // duplicate, the call would simply fail rather than corrupt
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
          rowCount: rows.length,
        });
      } catch (e) {
        Cu.reportError(
          "certCleanup: deleteCertificate failed for subject=" +
            liveCert.subjectName + ": " + e
        );
      }
    }
  } catch (e) {
    Cu.reportError("certCleanup: cert9.db access failed: " + e);
  } finally {
    if (conn) {
      await conn.close();
      console.log("certCleanup: connection closed");
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
