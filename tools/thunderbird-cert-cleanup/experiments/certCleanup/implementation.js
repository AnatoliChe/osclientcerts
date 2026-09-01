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
// setTimeout/clearTimeout are Window/Worker globals, not available in this
// privileged Experiment script's own top-level scope. Timer.sys.mjs is
// Gecko's own polyfill for exactly this situation -- needed by
// reinitCertVerifier()'s own bookkeeping below.
const { setTimeout, clearTimeout } = ChromeUtils.importESModule(
  "resource://gre/modules/Timer.sys.mjs"
);

// PROACTIVE-ONLY BUILD, not for production. Three triggers, all proactive,
// no reactive failure-handling and no retry at all:
//   1. Compose window open -> reinitCertVerifier() (unconditional, no
//      cert9.db read/delete).
//   2. Send button/menu click, intercepted *before* the actual send starts
//      -> doCleanup() only (find+delete a stale duplicate), no reinit,
//      then the original send proceeds exactly once.
//   3. App shutdown -> doCleanup() only.
//
// Replaces every reactive/retry design tried on this branch since
// 2026-09-01 (v0.5.0 through v0.5.5): those all needed
// recreateComposeSecure() (a fresh nsIMsgComposeSecure + checkRecipientCerts()
// cache rewarm) to avoid corrupting a retried send, but checkRecipientCerts()
// is itself a genuine NSS-touching disturbance that kept breaking reading
// even when every step (including a *correctly firing* delayed
// reinitCertVerifier()) completed successfully -- confirmed via a complete,
// gapless log capture (2026-09-01). This design sidesteps both problems at
// once: cleanup runs *before* the only BeginCryptoEncapsulation() call this
// window will ever make, so there's no same-window-retry corruption risk
// and no need for recreateComposeSecure()/checkRecipientCerts() at all;
// reinitCertVerifier() only ever runs at window-open, well before any send
// is attempted, so it can never collide with a synchronous crypto operation
// the way it did when tried immediately before/after a send (v0.5.1: broke
// the send itself with a cold CertVerifier).

// Kept in sync with manifest.json's "version" by hand -- this privileged
// script has no equivalent of background.js's browser.runtime.getManifest()
// (that's a WebExtension-context API, not available here), so there's no
// way to read it back automatically.
const VERSION = "0.6.4.0";

// Every action this build takes is logged through these two: each line
// carries the version, a Date.now() timestamp (so it lines up with
// MOZ_LOG's `timestamp` output), the specific step, and -- for logError --
// the error and its stack if it has one.
function logInfo(step, detail) {
  console.log(
    `certCleanup v${VERSION} [${Date.now()}] ${step}` +
      (detail !== undefined ? `: ${detail}` : "")
  );
}
function logError(step, err) {
  console.error(
    `certCleanup v${VERSION} [${Date.now()}] ${step} FAILED: ${err}` +
      (err && err.stack ? `\n${err.stack}` : "")
  );
}

// Proves this script parsed and evaluated at all: if this line is missing
// from a log capture, the problem is upstream of this script (e.g. the
// experiment_apis schema failing validation, or the script failing to
// parse) rather than in any of the logic below.
logInfo("implementation.js: evaluated");

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
  logInfo("doCleanup: starting");
  const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
    Ci.nsIX509CertDB
  );

  // TEST BUILD 0.6.4.0: bisection experiment -- the hypothesis is that the
  // mere acquisition of the nsIX509CertDB service alone (before any getCerts())
  // already breaks subsequent reading of incoming mail. So: obtain the service,
  // log that we did, and return without touching getCerts(), cert9.db, or
  // deleteCertificate() at all. Nothing else in this file runs on the send
  // path beyond this return (see hookSendButton).
  logInfo("doCleanup: TEST 0.6.4.0: certDB service acquired, returning without touching anything else");
  return [];
  let certs;
  try {
    certs = certDB.getCerts();
    logInfo("doCleanup: certDB.getCerts() returned", `${certs.length} total cert(s)`);
  } catch (e) {
    logError("doCleanup: certDB.getCerts()", e);
    return [];
  }
  // Beyond tokenName, also require an email address (cert.getEmailAddresses(),
  // the nsIX509Cert method -- there is NO property named "emailAddresses",
  // only the method and the AString "emailAddress" attribute -- Gecko/NSS
  // populates it from *both* the Subject DN's PKCS#9
  // emailAddress attribute and any SAN rfc822Name/directoryName entries --
  // see nsNSSCertificate::GetEmailAddresses / NSS's CERT_GetFirstEmailAddress
  // in alg1485.c). A stale cert9.db duplicate can only ever cause the
  // original signing-confusion bug (P1) for a certificate someone might
  // actually sign with -- and our own Rust module's CERT_FIND_HAS_PRIVATE_KEY
  // filter (backend_windows.rs) only checks for a CERT_KEY_PROV_INFO_PROP_ID
  // property, not a genuinely usable key, so a chain-only helper cert (a CA)
  // can show up here as "live" without ever being signable. S/MIME requires
  // an email address on any cert actually used to sign/encrypt (RFC 5750);
  // a CA cert essentially never has one. Filtering here is a zero-cost, local
  // check (no extra cert9.db/NSS touch) that also reduces how many separate
  // SQL lookups doCleanup() makes against cert9.db per pass.
  const liveCerts = certs.filter(
    (cert) =>
      (cert.tokenName || "").trim() === OS_CLIENT_CERTS_TOKEN_NAME &&
      cert.getEmailAddresses().length > 0
  );
  logInfo(
    "doCleanup: filtered to live certs on our token with an email address",
    `${liveCerts.length} of ${certs.length}`
  );
  if (liveCerts.length === 0) {
    // The provider isn't loaded (or has no certs) right now -- don't touch
    // cert9.db at all, since we have no way to confirm which of its rows, if
    // any, are safe to remove.
    logInfo("doCleanup: no live certs on our token, nothing to check, returning");
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
  logInfo("doCleanup: cert9.db path", dbFile.path);

  const deleted = [];
  let conn;
  try {
    logInfo("doCleanup: opening cert9.db (openNotExclusive, readOnly)");
    conn = await Sqlite.openConnection({
      path: dbFile.path,
      openNotExclusive: true,
      readOnly: true,
    });
    logInfo("doCleanup: cert9.db opened");
    for (const liveCert of liveCerts) {
      logInfo("doCleanup: checking live cert", `subject=${liveCert.subjectName}`);
      const derArray = liveCert.getRawDER();
      const der = Uint8Array.from(derArray);
      logInfo("doCleanup: querying nssPublic for a matching duplicate row");
      let rows;
      try {
        rows = await conn.execute(
          "SELECT id FROM nssPublic WHERE " +
            CKA_CLASS_COLUMN + " = :cls AND " + CKA_VALUE_COLUMN + " = :der",
          { cls: CKO_CERTIFICATE_BYTES, der }
        );
      } catch (e) {
        logError(`doCleanup: SELECT for subject=${liveCert.subjectName}`, e);
        continue;
      }
      if (rows.length === 0) {
        logInfo(
          "doCleanup: no duplicate row found",
          `subject=${liveCert.subjectName}`
        );
        continue;
      }
      logInfo(
        "doCleanup: found duplicate row(s)",
        `${rows.length} row(s), subject=${liveCert.subjectName}`
      );
      // Delete via nsIX509CertDB, not a second write connection.
      // constructX509() builds a transient, in-memory certificate object
      // from the duplicate's DER (not tied to any token/slot), and
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
      logInfo(
        "doCleanup: attempting deleteCertificate()",
        `subject=${liveCert.subjectName}`
      );
      try {
        const tempCert = certDB.constructX509(derArray);
        certDB.deleteCertificate(tempCert);
        logInfo(
          "doCleanup: deleteCertificate() succeeded",
          `subject=${liveCert.subjectName}, ${rows.length} row(s)`
        );
        deleted.push({
          subjectName: liveCert.subjectName,
          issuerName: liveCert.issuerName,
          serialNumber: liveCert.serialNumber,
          rowCount: rows.length,
        });
      } catch (e) {
        logError(
          `doCleanup: deleteCertificate() for subject=${liveCert.subjectName}`,
          e
        );
      }
    }
  } catch (e) {
    logError("doCleanup: cert9.db access", e);
  } finally {
    if (conn) {
      logInfo("doCleanup: closing cert9.db connection");
      await conn.close();
      logInfo("doCleanup: cert9.db connection closed");
    }
  }

  logInfo("doCleanup: done", `${deleted.length} record(s) deleted`);
  return deleted;
}

// Rebuilds Gecko's process-lifetime CertVerifier singleton
// (mozilla::psm::CertVerifier, security/certverifier/CertVerifier.h --
// holds mOCSPCache/mSignatureCache/mTrustCache). Mechanism:
// nsNSSComponent::UpdateCertVerifierWithEnterpriseRoots()
// (security/manager/ssl/nsNSSComponent.cpp:1120) replaces
// mDefaultCertVerifier with a brand-new SharedCertVerifier (same config,
// but a fresh object -- so all three caches start empty), and runs
// whenever the security.enterprise_roots.enabled pref transitions false ->
// true (nsNSSComponent.cpp:1731, via BackgroundImportEnterpriseCertsTask,
// completion signaled by the "psm:enterprise-certs-imported" observer
// topic). The reverse transition (true -> false) only unloads enterprise
// roots and does *not* rebuild the verifier, so to guarantee a rebuild
// regardless of the pref's starting value, this forces it to false first
// (a synchronous, effect-free no-op if it was already false) before
// setting it to true and waiting for the rebuild, then restores whatever
// value it started with. The only side effect is a brief, in-memory-only
// (not persisted to any file) import of the OS's enterprise root CAs for
// the time this takes -- a real, supported Gecko feature, not a hack --
// reverted immediately after.
function nowMs() {
  return Date.now();
}

// No-effect-observed timeout: if "psm:enterprise-certs-imported" never
// fires (task failure, task never dispatched, topic name changed upstream,
// etc.), this would otherwise hang forever inside `await` with no further
// log line -- indistinguishable from "still running" versus "silently
// stuck". This turns that into an explicit, timestamped failure instead.
const REINIT_TIMEOUT_MS = 8000;

function waitForObserverTopic(topic, timeoutMs) {
  logInfo("waitForObserverTopic: registering observer", `topic="${topic}", timeout=${timeoutMs}ms`);
  return new Promise((resolve, reject) => {
    let timer;
    const observer = {
      observe() {
        clearTimeout(timer);
        Services.obs.removeObserver(observer, topic);
        logInfo("waitForObserverTopic: topic fired", `topic="${topic}"`);
        resolve();
      },
    };
    Services.obs.addObserver(observer, topic);
    timer = setTimeout(() => {
      Services.obs.removeObserver(observer, topic);
      const err = new Error(
        `TIMED OUT after ${timeoutMs}ms waiting for observer topic "${topic}" -- it never fired`
      );
      logError("waitForObserverTopic", err);
      reject(err);
    }, timeoutMs);
  });
}

const ENTERPRISE_ROOTS_PREF = "security.enterprise_roots.enabled";

async function reinitCertVerifier() {
  logInfo("reinitCertVerifier: starting");
  try {
    const original = Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false);
    logInfo("reinitCertVerifier: read current pref value", `${ENTERPRISE_ROOTS_PREF}=${original}`);
    if (original) {
      // Force a false->true transition below even if already true, since
      // only that direction rebuilds CertVerifier.
      logInfo("reinitCertVerifier: pref already true, forcing to false first");
      Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, false);
      logInfo(
        "reinitCertVerifier: set pref to false",
        `readback=${Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false)}`
      );
    }
    const imported = waitForObserverTopic(
      "psm:enterprise-certs-imported",
      REINIT_TIMEOUT_MS
    );
    logInfo("reinitCertVerifier: setting pref to true (triggers the rebuild)");
    Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, true);
    logInfo(
      "reinitCertVerifier: set pref to true",
      `readback=${Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false)}, awaiting rebuild completion`
    );
    await imported;
    logInfo("reinitCertVerifier: rebuild completion observed");
    if (!original) {
      logInfo("reinitCertVerifier: restoring pref to false (original value)");
      Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, false);
      logInfo(
        "reinitCertVerifier: restored pref to false",
        `readback=${Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false)}`
      );
    }
    logInfo("reinitCertVerifier: SUCCESS");
    return true;
  } catch (e) {
    logError("reinitCertVerifier", e);
    return false;
  }
}

function isComposeWindow(win) {
  return win.document.documentElement.getAttribute("windowtype") === "msgcompose";
}

// TRIGGER 2: Send button/menu click, intercepted *before* the send actually
// starts. This is the only place a stale duplicate gets deleted mid-session
// -- and since it runs before this window's *only* BeginCryptoEncapsulation()
// call, there's no same-window-retry risk (see the file-level comment
// above) and no need to warm any cache afterward: the original send simply
// proceeds once, exactly as if the user had clicked Send on a window that
// never had a stale duplicate in the first place.
const SEND_COMMAND_IDS = new Set([
  "button-send",
  "cmd_sendButton",
  "cmd_sendNow",
  "cmd_sendLater",
  "menu-item-send-now",
]);

function commandIdToDeliverMode(id) {
  return id === "cmd_sendLater"
    ? Ci.nsIMsgCompDeliverMode.Later
    : Ci.nsIMsgCompDeliverMode.Now;
}

function hookSendButton(win) {
  win.document.addEventListener(
    "command",
    (event) => {
      if (win.__certCleanupInterceptingSend) {
        return;
      }
      const id = event.target && event.target.id;
      if (!SEND_COMMAND_IDS.has(id)) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      const msgType = commandIdToDeliverMode(id);
      win.__certCleanupInterceptingSend = true;
      logInfo("hookSendButton: intercepted send-button click", `id="${id}", msgType=${msgType}`);
      doCleanup()
        .then((deleted) => {
          logInfo(
            "hookSendButton: cleanup done, proceeding with the original send",
            `${deleted.length} record(s) deleted`
          );
        })
        .catch((e) => {
          logError("hookSendButton: doCleanup()", e);
        })
        .then(() => {
          win.__certCleanupInterceptingSend = false;
          if (typeof win.GenericSendMessage !== "function") {
            logError("hookSendButton", "win.GenericSendMessage not found, can't proceed with the send");
            return;
          }
          logInfo("hookSendButton: calling GenericSendMessage()", `msgType=${msgType}`);
          win.GenericSendMessage(msgType);
        });
    },
    true // capturing, so this sees the click before Thunderbird's own handler
  );
  logInfo("hookSendButton: hooked");
}

function hookComposeWindow(win) {
  if (win.__certCleanupHooked) {
    logInfo("hookComposeWindow: already hooked, skipping");
    return;
  }
  win.__certCleanupHooked = true;
  logInfo("hookComposeWindow: starting to hook a new compose window");
  hookSendButton(win);

  // TRIGGER 1: compose window open -> unconditional reinitCertVerifier(),
  // no cert9.db read at all. This runs well before any send is attempted,
  // so it can never collide with a synchronous crypto operation.
  logInfo("hookComposeWindow: reinitializing CertVerifier (unconditional, on window open)");
  reinitCertVerifier()
    .then((ok) => {
      logInfo("hookComposeWindow: reinitCertVerifier() returned", ok);
    })
    .catch((e) => {
      logError("hookComposeWindow: reinitCertVerifier()", e);
    });
}

function onWindowOpened(win) {
  win.addEventListener(
    "load",
    function onLoad() {
      win.removeEventListener("load", onLoad);
      if (isComposeWindow(win)) {
        logInfo("onWindowOpened: new compose window loaded");
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

// Registers the compose-window-open hook for every current and future
// compose window, and the earliest well-known Gecko shutdown phase
// (ShutdownPhase::AppShutdownConfirmed, topic "quit-application"). Called
// once from getAPI() below (see the comment there for why module-level
// top-level code isn't the right place for this), guarded so a second
// getAPI() call for another context can't register everything twice.
let initialized = false;
function initialize() {
  if (initialized) {
    logInfo("initialize: already initialized, skipping");
    return;
  }
  initialized = true;
  logInfo("initialize: starting");
  registerShutdownBlocker();
  Services.obs.addObserver(domWindowOpenedObserver, "domwindowopened");
  logInfo("initialize: domwindowopened observer registered");
  const existing = [...Services.wm.getEnumerator("msgcompose")];
  logInfo("initialize: hooking already-open compose window(s)", `${existing.length} found`);
  for (const win of existing) {
    hookComposeWindow(win);
  }
  logInfo("initialize: done");
}

const SHUTDOWN_BLOCKER_NAME =
  "certCleanup: remove stale cert9.db duplicates before quit";

// TRIGGER 3: app shutdown -> doCleanup() only, no reinit needed (whatever
// might go stale in Gecko's cache doesn't matter if the process exits
// shortly after -- the original 0.4.0 rationale).
async function onQuitApplication() {
  logInfo("onQuitApplication: starting (shutdown blocker fired)");
  try {
    const deleted = await doCleanup();
    logInfo("onQuitApplication: done", `${deleted.length} record(s) deleted`);
  } catch (e) {
    logError("onQuitApplication", e);
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
  logInfo("registerShutdownBlocker: registered", `name="${SHUTDOWN_BLOCKER_NAME}"`);
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
    logInfo("getAPI: called");
    initialize();
    return {
      certCleanup: {
        // Called once by background.js at startup. By the time this
        // resolves, getAPI() above has already run initialize() -- see
        // schema.json for why background.js needs to make this call at all
        // rather than relying on getAPI() running on its own.
        activate: async () => {
          logInfo("activate: called");
        },
        // Exposed for manual/on-demand use (e.g. from the Browser Console
        // while testing), but not called from background.js on any
        // schedule -- see hookComposeWindow, hookSendButton, and
        // onQuitApplication above for the only places cleanup/reinit
        // actually run.
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
    logInfo("onShutdown: called", `isAppShutdown=${isAppShutdown}`);
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
    logInfo("onShutdown: teardown complete");
  }
};
