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
// privileged Experiment script's own top-level scope (confirmed via a real
// console-export log: an earlier build on this branch threw
// "ReferenceError: setTimeout is not defined" from inside
// waitForObserverTopic below). Timer.sys.mjs is Gecko's own polyfill for
// exactly this situation. Note this is only needed for reinitCertVerifier()'s
// own bookkeeping below -- hookComposeWindow's gMsgCompose poll further down
// uses `win.setTimeout`, which is fine as-is since `win` is a real DOM
// window with its own native timers.
const { setTimeout, clearTimeout } = ChromeUtils.importESModule(
  "resource://gre/modules/Timer.sys.mjs"
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
      // reinitCertVerifier() below for the other half of this build's fix:
      // every mechanism tried to *remove* the duplicate -- including this
      // one -- independently left something in Gecko's C++ layer above NSS
      // unable to resolve the recipient for S/MIME decryption for the rest
      // of that Thunderbird session, until reinitCertVerifier() below).
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

// REINIT-CERTVERIFIER-EXPERIMENT: after a cleanup pass removes a stale
// cert9.db row, rebuild Gecko's process-lifetime CertVerifier singleton
// (mozilla::psm::CertVerifier, security/certverifier/CertVerifier.h --
// holds mOCSPCache/mSignatureCache/mTrustCache) instead of relying on an
// incidental subsequent send to mask the problem.
//
// CONFIRMED WORKING (2026-09-01, on the proactive compose-open trigger
// build of this branch): before this, every mechanism tried -- raw SQL
// delete, nsIX509CertDB.deleteCertificate(), a native Rust DLL thread with
// zero Gecko/JS/XPCOM involvement, and explicitly logging the *internal*
// PK11 token out and back in (nsIPKCS11Token.logout()/.login(), which
// rules out NSS's own PK11/softoken/STAN cache as the culprit since that's
// exactly the layer it operates on) -- showed the same "self-heals on the
// first occurrence per session, never on the second" signature. This
// mechanism is the first one that changed that: self-heal now works after
// *every* send, not just the first.
//
// Mechanism: nsNSSComponent::UpdateCertVerifierWithEnterpriseRoots()
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
//
// CertVerifier::ClearTrustCache() exists in the C++ class but isn't
// exposed to JS (only ClearOCSPCache() is, via
// nsIX509CertDB.clearOCSPCache() -- OCSP/revocation-only). Exposing it
// would mean patching and rebuilding Thunderbird itself, not viable
// against a stock downloaded Daily build -- this pref-toggle approach
// needs no patching at all.
//
// Logged timestamps use Date.now() (ms since epoch) rather than
// console.log's own displayed time, so they can be lined up against
// MOZ_LOG's `timestamp` output when cross-referencing the two logs by
// hand. (An earlier build on this branch used
// performance.timeOrigin + performance.now() here instead -- `performance`
// is a Window/Worker global, not available in this scope, and crashed
// reinitCertVerifier() on its very first line, before its own try/catch,
// silently disabling the whole mechanism for an entire test session
// without producing any visibly-alarming error. Confirmed via a real
// console-export log. Fixed by switching to Date.now().)
function nowMs() {
  return Date.now();
}

// No-effect-observed timeout: if "psm:enterprise-certs-imported" never
// fires (task failure, task never dispatched, topic name changed upstream,
// etc.), this function would otherwise hang forever inside `await` with no
// further log line -- indistinguishable from "still running" versus
// "silently stuck". This turns that into an explicit, timestamped failure
// instead.
const REINIT_TIMEOUT_MS = 8000;

function waitForObserverTopic(topic, timeoutMs) {
  console.log(`certCleanup: [${nowMs()}] waiting for observer topic "${topic}"`);
  return new Promise((resolve, reject) => {
    let timer;
    const observer = {
      observe() {
        clearTimeout(timer);
        Services.obs.removeObserver(observer, topic);
        console.log(`certCleanup: [${nowMs()}] observer topic "${topic}" fired`);
        resolve();
      },
    };
    Services.obs.addObserver(observer, topic);
    timer = setTimeout(() => {
      Services.obs.removeObserver(observer, topic);
      reject(
        new Error(
          `certCleanup: [${nowMs()}] TIMED OUT after ${timeoutMs}ms waiting for observer topic "${topic}" -- it never fired`
        )
      );
    }, timeoutMs);
  });
}

const ENTERPRISE_ROOTS_PREF = "security.enterprise_roots.enabled";

async function reinitCertVerifier() {
  const startedAt = nowMs();
  console.log(`certCleanup: [${startedAt}] reinitCertVerifier: starting`);
  try {
    const original = Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false);
    console.log(
      `certCleanup: [${nowMs()}] reinitCertVerifier: ${ENTERPRISE_ROOTS_PREF} currently ${original}`
    );
    if (original) {
      // Force a false->true transition below even if already true, since
      // only that direction rebuilds CertVerifier.
      Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, false);
      console.log(
        `certCleanup: [${nowMs()}] reinitCertVerifier: forced ${ENTERPRISE_ROOTS_PREF}=false first ` +
          `(readback: ${Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false)})`
      );
    }

    const imported = waitForObserverTopic(
      "psm:enterprise-certs-imported",
      REINIT_TIMEOUT_MS
    );
    Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, true);
    console.log(
      `certCleanup: [${nowMs()}] reinitCertVerifier: set ${ENTERPRISE_ROOTS_PREF}=true ` +
        `(readback: ${Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false)}), ` +
        `awaiting rebuild completion (timeout ${REINIT_TIMEOUT_MS}ms)`
    );
    await imported;

    if (!original) {
      Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, false);
      console.log(
        `certCleanup: [${nowMs()}] reinitCertVerifier: restored ${ENTERPRISE_ROOTS_PREF}=false ` +
          `(readback: ${Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false)})`
      );
    }
    console.log(
      `certCleanup: [${nowMs()}] reinitCertVerifier: SUCCESS (started ${startedAt}, ` +
        `final ${ENTERPRISE_ROOTS_PREF}=${Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false)}, ` +
        `matches original=${original}: ${Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false) === original})`
    );
    return true;
  } catch (e) {
    // Was previously easy to miss: Cu.reportError logs to the Browser
    // Console's error stream, which is easy to lose among the various
    // unrelated warnings/errors Thunderbird itself prints (e.g. the
    // pre-existing msgHdrViewSMIMEOverlay.js encryptionStatus crash). Also
    // logging via console.error with an explicit FAILURE marker and the
    // stack (if any) makes this impossible to mistake for a benign line
    // when scanning the log.
    console.error(
      `certCleanup: [${nowMs()}] reinitCertVerifier: FAILURE (started ${startedAt}): ${e}` +
        (e && e.stack ? `\n${e.stack}` : "")
    );
    Cu.reportError("certCleanup: reinitCertVerifier failed: " + e);
    return false;
  }
}

// Runs a cleanup pass and, only if it actually removed something, follows up
// with reinitCertVerifier() -- no point risking the enterprise-roots pref
// toggle (and its side effects) on a pass that found nothing stale.
async function cleanupAndReinit(label) {
  const deleted = await doCleanup();
  if (deleted.length === 0) {
    console.log(`certCleanup (${label}): nothing to clean up`);
    return deleted;
  }
  console.log(
    `certCleanup (${label}): removed ${deleted.length} stale certificate record(s), reinitializing CertVerifier`,
    deleted
  );
  const reinitOk = await reinitCertVerifier();
  console.log(`certCleanup (${label}): reinitCertVerifier returned ${reinitOk}`);
  return deleted;
}

// ON-COMPOSE-ERROR-TRIGGER, now paired with reinitCertVerifier() above.
// Every *proactive* trigger tried (cleanup on every compose-window-open or
// every send, whether or not a duplicate actually existed) disrupts reading
// even on a run that finds nothing to delete (getCerts() alone is enough).
// This trigger instead runs reactively, only on an actual send failure.
//
// browser.compose.onAfterSend structurally cannot see this failure:
// comm-central's MsgComposeCommands.js (CompleteGenericSendMessage)
// `return`s from its catch block on a send failure *before* ever reaching
// the `window.dispatchEvent(new CustomEvent("aftersend"))` call that
// onAfterSend is built on -- confirmed against the actual source, and
// against a real profile where three failed sends in a row never fired
// onAfterSend once.
//
// This hooks lower instead, at the same layer Thunderbird's own compose
// window code uses to observe its own send outcome:
// nsIMsgComposeStateListener (nsIMsgCompose.idl), registered via
// gMsgCompose.RegisterStateListener() -- the exact same public, documented
// interface mail/components/compose/content/MsgComposeCommands.js
// registers its own stateListener through. ComposeProcessDone(aResult)
// fires with the actual nsresult of the compose/send process (NS_OK on
// success, the real failure code otherwise -- including a
// finishCryptoEncapsulation failure), driven by nsMsgCompose's own
// internal completion notification rather than the JS-level try/catch that
// swallows the exception in CompleteGenericSendMessage.
//
// After cleanup + reinit, the send is retried automatically, once. Two
// obstacles to a fully automatic retry, both handled below:
//   1. The failure also pops a modal "couldn't send" alert
//      (MessageSend.sys.mjs's sendReport.displayReport(), a
//      Services.prompt.alert() call) that blocks further interaction with
//      the compose window until dismissed. Auto-closed via the same
//      domwindowopened observer already used to find compose windows,
//      matched by the dialog's stable id (commonDialogWindow) and its
//      .opener being a compose window we're tracking (Services.ww.openWindow
//      sets .opener to the parentWindow argument -- confirmed against
//      toolkit/components/prompts/src/Prompter.sys.mjs).
//   2. GenericSendMessage(msgType)'s msgType isn't included in
//      ComposeProcessDone's own callback, so it's recorded separately by
//      lightly wrapping GenericSendMessage (recording the argument only,
//      not changing its behavior) whenever the user (or our own retry)
//      calls it.
const hookedComposeWindows = new Set();

function isComposeWindow(win) {
  return win.document.documentElement.getAttribute("windowtype") === "msgcompose";
}

function isCommonDialogFrom(win, composeWindows) {
  try {
    return (
      win.document.documentElement.id === "commonDialogWindow" &&
      composeWindows.has(win.opener)
    );
  } catch (e) {
    return false;
  }
}

// win.__certCleanupHandling tracks "a failure on this window is currently
// being cleaned up and retried". Always cleared on every exit path (not
// just the success path), since production testing on an earlier build
// found ComposeProcessDone firing *twice* for one real failure (a
// duplicate nsIMsgComposeStateListener registration -- see
// registerStateListener's own guard below), which could otherwise leave
// this flag stuck and silently block cleanup on a later, genuinely new
// failure on the same window.
function onComposeProcessDone(win, aResult) {
  if (aResult === 0) {
    // NS_OK. Not using Cr.NS_OK to avoid depending on whether Cr
    // (Components.results) is available as a predefined global here the
    // same way Cc/Ci/Cu are -- NS_OK's value (0) is stable across all of
    // Gecko and won't change.
    win.__certCleanupHandling = false;
    return;
  }
  if (win.__certCleanupHandling) {
    // Either a duplicate notification of the failure already being
    // handled, or the retry itself also failed -- can't tell which from
    // here, but either way don't start an overlapping cleanup/retry cycle.
    console.error(
      `certCleanup: ComposeProcessDone failed again while already handling a failure on this window (0x${(aResult >>> 0).toString(16)}), not retrying again`
    );
    win.__certCleanupHandling = false;
    return;
  }
  win.__certCleanupHandling = true;
  console.log(
    `certCleanup: send failed (0x${(aResult >>> 0).toString(16)}), running cleanup`
  );
  cleanupAndReinit("on-send-failure")
    .then(() => {
      console.log("certCleanup: retrying send");
      const msgType = win.__certCleanupLastMsgType ?? Ci.nsIMsgCompDeliverMode.Now;
      return win.GenericSendMessage(msgType);
    })
    .catch((e) => {
      win.__certCleanupHandling = false;
      Cu.reportError("certCleanup: cleanup/retry after a failed send failed: " + e);
    });
}

// win.gMsgCompose isn't necessarily ready by the window's "load" event --
// confirmed in production testing: RegisterStateListener was unavailable at
// that point, meaning gMsgCompose's own async setup hadn't finished yet.
// Polled instead of guessing a more specific ready signal to hook: up to
// 5 seconds, every 100ms, which comfortably covers real-world compose
// window startup and fails loudly (one clear log line) if it never shows up.
const GMSGCOMPOSE_POLL_INTERVAL_MS = 100;
const GMSGCOMPOSE_POLL_MAX_ATTEMPTS = 50;

function registerStateListener(win) {
  // Guards specifically against a second RegisterStateListener call on this
  // window, independent of hookComposeWindow's own __certCleanupHooked
  // guard: production testing observed ComposeProcessDone firing twice for
  // one real failure, consistent with two separate listener objects having
  // ended up registered on the same window (root cause not fully pinned
  // down -- possibly this Experiment's parent script re-evaluating and
  // re-running its window-hooking loop, since MV3 background contexts can
  // be non-persistent and reload). This check is cheap insurance regardless
  // of the exact cause.
  if (win.__certCleanupStateListenerRegistered) {
    return;
  }
  win.__certCleanupStateListenerRegistered = true;
  // All four nsIMsgComposeStateListener methods must exist as callable
  // functions even though only ComposeProcessDone matters here: this is a
  // [scriptable] XPCOM interface, and Thunderbird's C++ side may call any
  // of them without checking first.
  win.gMsgCompose.RegisterStateListener({
    NotifyComposeFieldsReady() {},
    ComposeProcessDone(aResult) {
      onComposeProcessDone(win, aResult);
    },
    SaveInFolderDone(folderName) {},
    NotifyComposeBodyReady() {},
  });
}

function wrapGenericSendMessage(win) {
  if (typeof win.GenericSendMessage !== "function") {
    console.error(
      "certCleanup ON-COMPOSE-ERROR-TRIGGER: GenericSendMessage not found on this compose window, can't track/retry send mode"
    );
    return;
  }
  const original = win.GenericSendMessage;
  win.GenericSendMessage = function (msgType, ...rest) {
    win.__certCleanupLastMsgType = msgType;
    return original.call(this, msgType, ...rest);
  };
}

function hookComposeWindow(win) {
  if (win.__certCleanupHooked) {
    return;
  }
  win.__certCleanupHooked = true;
  hookedComposeWindows.add(win);
  win.addEventListener("unload", () => hookedComposeWindows.delete(win), { once: true });
  wrapGenericSendMessage(win);
  let attemptsLeft = GMSGCOMPOSE_POLL_MAX_ATTEMPTS;
  const tryRegister = () => {
    if (win.gMsgCompose && typeof win.gMsgCompose.RegisterStateListener === "function") {
      registerStateListener(win);
      return;
    }
    attemptsLeft -= 1;
    if (attemptsLeft <= 0) {
      console.error(
        "certCleanup ON-COMPOSE-ERROR-TRIGGER: gMsgCompose.RegisterStateListener never became available on this compose window"
      );
      return;
    }
    win.setTimeout(tryRegister, GMSGCOMPOSE_POLL_INTERVAL_MS);
  };
  tryRegister();
}

function onWindowOpened(win) {
  win.addEventListener(
    "load",
    function onLoad() {
      win.removeEventListener("load", onLoad);
      if (isComposeWindow(win)) {
        hookComposeWindow(win);
        return;
      }
      if (isCommonDialogFrom(win, hookedComposeWindows)) {
        console.log(
          "certCleanup ON-COMPOSE-ERROR-TRIGGER: auto-dismissing the send-failure alert dialog"
        );
        win.close();
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
