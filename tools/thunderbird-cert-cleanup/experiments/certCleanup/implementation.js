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
// nsIX509CertDB, and why this whole pass is only ever run at shutdown -- not
// periodically during the session -- as of 0.4.0.
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
    }
  }

  return deleted;
}

// ON-COMPOSE-ERROR-TRIGGER BUILD, not for production. Every trigger tried
// so far ran cleanup *proactively*, on every compose-window-open or every
// send, whether or not a duplicate actually existed -- confirmed to disrupt
// reading even on a run that found nothing to delete (getCerts() alone is
// enough). v0.4.25 tried running *reactively* instead, via
// browser.compose.onAfterSend, but that WebExtension event structurally
// cannot see this failure: comm-central's MsgComposeCommands.js
// (CompleteGenericSendMessage) `return`s from its catch block on a send
// failure *before* ever reaching the `window.dispatchEvent(new
// CustomEvent("aftersend"))` call that onAfterSend is built on -- confirmed
// against the actual source, and against a real profile where three failed
// sends in a row never fired onAfterSend once.
//
// This build hooks lower, at the same layer Thunderbird's own compose
// window code uses to observe its own send outcome: nsIMsgComposeStateListener
// (nsIMsgCompose.idl), registered via gMsgCompose.RegisterStateListener()
// -- the exact same public, documented interface
// mail/components/compose/content/MsgComposeCommands.js registers its own
// stateListener through. ComposeProcessDone(aResult) fires with the actual
// nsresult of the compose/send process (NS_OK on success, the real failure
// code otherwise -- including a finishCryptoEncapsulation failure), driven
// by nsMsgCompose's own internal completion notification rather than the
// JS-level try/catch that swallows the exception in
// CompleteGenericSendMessage. No monkey-patching of internal functions
// required.
function isComposeWindow(win) {
  return win.document.documentElement.getAttribute("windowtype") === "msgcompose";
}

function onComposeProcessDone(aResult) {
  if (aResult === 0) {
    // NS_OK. Not using Cr.NS_OK to avoid depending on whether Cr
    // (Components.results) is available as a predefined global here the
    // same way Cc/Ci/Cu are -- NS_OK's value (0) is stable across all of
    // Gecko and won't change.
    return;
  }
  console.log(
    `certCleanup ON-COMPOSE-ERROR-TRIGGER: ComposeProcessDone failed (0x${(aResult >>> 0).toString(16)}), running cleanup`
  );
  doCleanup()
    .then((deleted) => {
      console.log(
        `certCleanup ON-COMPOSE-ERROR-TRIGGER: done, ${deleted.length} deleted -- try resending, and check whether reading encrypted mail still works`
      );
    })
    .catch((e) => {
      Cu.reportError("certCleanup ON-COMPOSE-ERROR-TRIGGER: cleanup failed: " + e);
    });
}

function hookComposeWindow(win) {
  if (win.__certCleanupHooked) {
    return;
  }
  win.__certCleanupHooked = true;
  if (!win.gMsgCompose || typeof win.gMsgCompose.RegisterStateListener !== "function") {
    console.error(
      "certCleanup ON-COMPOSE-ERROR-TRIGGER: gMsgCompose.RegisterStateListener not available on this compose window"
    );
    return;
  }
  // All four nsIMsgComposeStateListener methods must exist as callable
  // functions even though only ComposeProcessDone matters here: this is a
  // [scriptable] XPCOM interface, and Thunderbird's C++ side may call any
  // of them without checking first.
  win.gMsgCompose.RegisterStateListener({
    NotifyComposeFieldsReady() {},
    ComposeProcessDone(aResult) {
      onComposeProcessDone(aResult);
    },
    SaveInFolderDone(folderName) {},
    NotifyComposeBodyReady() {},
  });
  console.log("certCleanup ON-COMPOSE-ERROR-TRIGGER: registered nsIMsgComposeStateListener");
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

// Registers the send-failure hook for every current and future compose
// window, and the earliest well-known Gecko shutdown phase (ShutdownPhase::
// AppShutdownConfirmed, topic "quit-application"). Called once from
// getAPI() below (see the comment there for why module-level top-level
// code isn't the right place for this), guarded so a second getAPI() call
// for another context can't register everything twice.
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

// Registers the earliest well-known Gecko shutdown phase (ShutdownPhase::
// AppShutdownConfirmed, topic "quit-application"). Blocking here, rather
// than doing a fire-and-forget cleanup, guarantees our async cert9.db work
// finishes before Thunderbird tears down further -- see the long comment in
// doCleanup() for why shutdown is one of the two points this needs to run.
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
        // schedule -- see onComposeProcessDone above and onQuitApplication
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
