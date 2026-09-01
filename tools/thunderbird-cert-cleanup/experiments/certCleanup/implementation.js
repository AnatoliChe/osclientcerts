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

// Runs the actual detect-and-delete pass. See the long comment inline below
// for why detection reads cert9.db directly but deletion goes through
// nsIX509CertDB.
async function doCleanup() {
  const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
    Ci.nsIX509CertDB
  );

  const certs = certDB.getCerts();
  const liveCerts = certs.filter(
    (cert) => (cert.tokenName || "").trim() === OS_CLIENT_CERTS_TOKEN_NAME
  );
  if (liveCerts.length === 0) {
    // The provider isn't loaded (or has no certs) right now -- don't touch
    // cert9.db at all, since we have no way to confirm which of its rows, if
    // any, are safe to remove.
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
    conn = await Sqlite.openConnection({
      path: dbFile.path,
      openNotExclusive: true,
      readOnly: true,
    });
    for (const liveCert of liveCerts) {
      const derArray = liveCert.getRawDER();
      const der = Uint8Array.from(derArray);
      const rows = await conn.execute(
        "SELECT id FROM nssPublic WHERE " +
          CKA_CLASS_COLUMN + " = :cls AND " + CKA_VALUE_COLUMN + " = :der",
        { cls: CKO_CERTIFICATE_BYTES, der }
      );
      if (rows.length === 0) {
        continue;
      }
      console.log(
        "certCleanup: found " + rows.length +
          " stale cert9.db row(s) duplicating live cert subject=" +
          liveCert.subjectName
      );
      // Delete via nsIX509CertDB, not a second write connection (see
      // reinitInternalToken() below for the other half of this build's
      // experiment: every mechanism tried to *remove* the duplicate --
      // including this one -- has independently been observed to leave
      // something in Gecko's C++ layer above NSS unable to resolve the
      // recipient for S/MIME decryption for the rest of that Thunderbird
      // session. constructX509() builds a transient, in-memory certificate
      // object from the duplicate's DER (not tied to any token/slot), and
      // deleteCertificate() on that object resolves and removes the
      // matching persisted record through NSS's own softoken code path
      // (PK11_DeleteTokenCertAndKey / SEC_DeletePermCertificate -- confirmed
      // against nsNSSCertificateDB::DeleteCertificate), the same path
      // "Delete or Distrust" in Certificate Manager uses. If that
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
    }
  }

  return deleted;
}

// REINIT-TOKEN-EXPERIMENT BUILD, not for production.
//
// Everything tried on this branch and on experiment/dll-native-cert9-cleanup
// so far has been about *how* the duplicate gets removed -- nsIX509CertDB,
// a raw Sqlite.sys.mjs write, even a native Rust thread with zero
// Gecko/JS/XPCOM involvement. All of them broke S/MIME decryption for the
// rest of the session regardless of mechanism, which means the corruption
// isn't about which layer performs the write. Working theory: the live
// NSS/softoken instance in this same process already has the deleted row
// cached in memory (STAN's nssTrustDomain cert cache -- see
// security/nss/lib/certdb/stanpcertdb.c's nssTrustDomain_AddCertToCache),
// and that in-memory cache is what actually goes stale, independent of who
// touched the file underneath it.
//
// This build tests whether explicitly telling NSS to drop and re-establish
// its session on the *internal* soft token (the one backing cert9.db, not
// our own external module) forces that cache to refresh, instead of
// relying on it happening as an incidental side effect of a subsequent
// send (the "self-heals on the first occurrence per session, but not the
// second" pattern from v0.6.0/v0.4.29). nsIPKCS11Token.logout()/.login()
// (security/manager/ssl/nsIPKCS11Token.idl) is the only Gecko-exposed,
// documented mechanism for this short of a full NSS_Shutdown+reinit (which
// Gecko doesn't support doing mid-session at all). logout() is a thin
// wrapper over PK11_Logout(slot) (security/manager/ssl/PKCS11Token.cpp) --
// this is a real, existing API, but nothing in its documented behavior
// guarantees it drops STAN's cert object cache specifically (that's the
// actual, unverified hypothesis this build exists to test).
async function reinitInternalToken() {
  try {
    const moduleDB = Cc["@mozilla.org/security/pkcs11moduledb;1"].getService(
      Ci.nsIPKCS11ModuleDB
    );
    const modules = await moduleDB.listModules();
    for (const module of modules) {
      for (const slot of module.slots) {
        const token = slot.getToken();
        if (!token.isInternalKeyToken) {
          continue;
        }
        console.log("certCleanup: reinitializing internal PKCS#11 token (logout+login)");
        await token.logout();
        await token.login();
        return true;
      }
    }
    console.error("certCleanup: internal PKCS#11 token not found, nothing to reinit");
    return false;
  } catch (e) {
    Cu.reportError("certCleanup: reinitInternalToken failed: " + e);
    return false;
  }
}

// Runs a cleanup pass and, only if it actually removed something, follows up
// with reinitInternalToken() -- no point risking a token logout/login cycle
// (and Cu.reportError noise) on a pass that found nothing stale.
async function cleanupAndReinit(label) {
  const deleted = await doCleanup();
  if (deleted.length === 0) {
    console.log(`certCleanup (${label}): nothing to clean up`);
    return deleted;
  }
  console.log(
    `certCleanup (${label}): removed ${deleted.length} stale certificate record(s), reinitializing internal token`,
    deleted
  );
  await reinitInternalToken();
  return deleted;
}

function isComposeWindow(win) {
  return win.document.documentElement.getAttribute("windowtype") === "msgcompose";
}

// win.__certCleanupHooked guards against running this twice for the same
// compose window (e.g. a second "load"-adjacent observer notification for
// the same window).
function hookComposeWindow(win) {
  if (win.__certCleanupHooked) {
    return;
  }
  win.__certCleanupHooked = true;
  console.log("certCleanup: new compose window opened, running cleanup");
  cleanupAndReinit("on-compose-open").catch((e) => {
    Cu.reportError("certCleanup: cleanup on compose-open failed: " + e);
  });
}

function onWindowOpened(win) {
  win.addEventListener(
    "load",
    function onLoad() {
      win.removeEventListener("load", onLoad);
      if (isComposeWindow(win)) {
        hookComposeWindow(win);
      }
    },
    { once: true }
  );
}

const domWindowOpenedObserver = {
  observe(subject, topic) {
    if (topic === "domwindowopened") {
      // "domwindowopened"'s subject is already the raw Window object in JS.
      onWindowOpened(subject);
    }
  },
};

// Registers both triggers for this build -- new compose window open, and
// the earliest well-known Gecko shutdown phase (ShutdownPhase::
// AppShutdownConfirmed, topic "quit-application") -- plus hooks any compose
// window(s) already open when this runs. Called once from getAPI() below
// (see the comment there for why module-level top-level code isn't the
// right place for this), guarded so a second getAPI() call for another
// context can't register everything twice.
let initialized = false;
function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  registerShutdownBlocker();
  Services.obs.addObserver(domWindowOpenedObserver, "domwindowopened");
  for (const win of Services.wm.getEnumerator("msgcompose")) {
    hookComposeWindow(win);
  }
}

const SHUTDOWN_BLOCKER_NAME =
  "certCleanup: remove stale cert9.db duplicates before quit";

async function onQuitApplication() {
  try {
    await cleanupAndReinit("quit-application");
  } catch (e) {
    Cu.reportError("certCleanup: cleanup on quit failed: " + e);
  }
}

// Registers the earliest well-known Gecko shutdown phase (ShutdownPhase::
// AppShutdownConfirmed, topic "quit-application"). Blocking here, rather
// than doing a fire-and-forget cleanup, guarantees our async cert9.db work
// finishes before Thunderbird tears down further.
function registerShutdownBlocker() {
  AsyncShutdown.appShutdownConfirmed.addBlocker(
    SHUTDOWN_BLOCKER_NAME,
    onQuitApplication
  );
}

var certCleanup = class extends ExtensionCommon.ExtensionAPI {
  // getAPI() is Thunderbird's documented entry point for a privileged
  // Experiment to become available to a WebExtension context -- unlike bare
  // module-level top-level code, it's guaranteed to run as soon as the
  // add-on actually needs this API, which is the right place for one-time
  // setup like the shutdown blocker (module-level code turned out to be
  // unreliable here in an earlier build on this branch: Experiment "parent"
  // scripts can be loaded lazily on first real API access rather than
  // eagerly with the add-on, so with no WebExtension-side code touching
  // this API at all, nothing ever triggered the script to load in the
  // first place).
  getAPI(context) {
    initialize();
    return {
      certCleanup: {
        // Called once by background.js at startup. By the time this
        // resolves, getAPI() above has already run initialize() -- see
        // schema.json for why background.js needs to make this call at all
        // rather than relying on getAPI() running on its own.
        activate: async () => {},
        // Exposed for manual/on-demand use (e.g. from the Browser Console
        // while testing), but not called from background.js on any
        // schedule -- see hookComposeWindow above and onQuitApplication
        // below for the only two places cleanup actually runs.
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
    // shutdown -- so anything registered in initialize() above would
    // otherwise leak (and, worse, keep referencing this soon-to-be-stale
    // script) across the reload.
    AsyncShutdown.appShutdownConfirmed.removeBlocker(onQuitApplication);
    Services.obs.removeObserver(domWindowOpenedObserver, "domwindowopened");
    Services.obs.notifyObservers(null, "startupcache-invalidate", null);
  }
};
