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

// Proves this script parsed and evaluated at all -- diagnostic added
// 2026-09-01 after a report that neither the compose-window-open trigger
// nor the (unconditional) shutdown cleanup ran. If this line is missing
// from the console, the problem is upstream of this script (e.g. the
// experiment_apis schema failing validation) rather than in the trigger
// logic below.
console.log("certCleanup: implementation.js evaluated");

// TRIGGER-SELECTOR BUILD, not for production.
//
// Which of the four possible trigger events actually run cleanup, settable
// live from the add-on's options page (options.html/options.js) via
// browser.storage.local -- see configure() below and schema.json.
// Unconfigured default matches this branch's previously-shipped behavior
// (react to a send failure only).
let activeTriggers = {
  windowOpen: false,
  sendButtonClick: false,
  sendError: true,
  sendSuccess: false,
};

function setTriggers(triggers) {
  Object.assign(activeTriggers, triggers || {});
  console.log("certCleanup: active triggers now " + JSON.stringify(activeTriggers));
}

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

// Rebuilds Gecko's process-lifetime CertVerifier singleton
// (mozilla::psm::CertVerifier, security/certverifier/CertVerifier.h --
// holds mOCSPCache/mSignatureCache/mTrustCache) after a cleanup pass
// removes a stale cert9.db row, instead of relying on an incidental
// subsequent send to mask the problem.
//
// CONFIRMED WORKING (2026-09-01, on this branch's proactive compose-open
// trigger build): before this, every mechanism tried -- raw SQL delete,
// nsIX509CertDB.deleteCertificate(), a native Rust DLL thread with zero
// Gecko/JS/XPCOM involvement, and explicitly logging the *internal* PK11
// token out and back in (nsIPKCS11Token.logout()/.login(), which rules out
// NSS's own PK11/softoken/STAN cache as the culprit since that's exactly
// the layer it operates on) -- showed the same "self-heals on the first
// occurrence per session, never on the second" signature. This mechanism
// is the first one that changed that: self-heal now works after *every*
// send, not just the first.
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
// Logged timestamps use Date.now() (ms since epoch) rather than
// console.log's own displayed time, so they can be lined up against
// MOZ_LOG's `timestamp` output when cross-referencing the two logs by
// hand.
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
  return new Promise((resolve, reject) => {
    let timer;
    const observer = {
      observe() {
        clearTimeout(timer);
        Services.obs.removeObserver(observer, topic);
        resolve();
      },
    };
    Services.obs.addObserver(observer, topic);
    timer = setTimeout(() => {
      Services.obs.removeObserver(observer, topic);
      reject(
        new Error(
          `certCleanup: TIMED OUT after ${timeoutMs}ms waiting for observer topic "${topic}" -- it never fired`
        )
      );
    }, timeoutMs);
  });
}

const ENTERPRISE_ROOTS_PREF = "security.enterprise_roots.enabled";

async function reinitCertVerifier() {
  try {
    const original = Services.prefs.getBoolPref(ENTERPRISE_ROOTS_PREF, false);
    if (original) {
      // Force a false->true transition below even if already true, since
      // only that direction rebuilds CertVerifier.
      Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, false);
    }
    const imported = waitForObserverTopic(
      "psm:enterprise-certs-imported",
      REINIT_TIMEOUT_MS
    );
    Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, true);
    await imported;
    if (!original) {
      Services.prefs.setBoolPref(ENTERPRISE_ROOTS_PREF, false);
    }
    console.log(`certCleanup: [${nowMs()}] reinitCertVerifier: SUCCESS`);
    return true;
  } catch (e) {
    console.error(`certCleanup: [${nowMs()}] reinitCertVerifier: FAILURE: ${e}`);
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

function isComposeWindow(win) {
  return win.document.documentElement.getAttribute("windowtype") === "msgcompose";
}

// TRIGGER: send failure. Detecting it at all needs to bypass
// browser.compose.onAfterSend: that WebExtension event structurally cannot
// see this failure. comm-central's MsgComposeCommands.js
// (CompleteGenericSendMessage) `return`s from its catch block on a send
// failure *before* ever reaching the `window.dispatchEvent(new
// CustomEvent("aftersend"))` call that onAfterSend is built on -- confirmed
// against the actual source, and against a real profile where three failed
// sends in a row never fired onAfterSend once. This hooks lower instead, at
// the same layer Thunderbird's own compose window code uses to observe its
// own send outcome: nsIMsgComposeStateListener (nsIMsgCompose.idl),
// registered via gMsgCompose.RegisterStateListener() -- the exact same
// public, documented interface MsgComposeCommands.js registers its own
// listener through. ComposeProcessDone(aResult) fires with the actual
// nsresult of the compose/send process (NS_OK on success, the real failure
// code otherwise -- including a finishCryptoEncapsulation failure), driven
// by nsMsgCompose's own internal completion notification rather than the
// JS-level try/catch that swallows the exception in
// CompleteGenericSendMessage.
//
// IMPORTANT: this does NOT auto-dismiss the failure dialog or auto-retry
// the send, unlike earlier builds on this branch (v0.4.26 through 0.4.35).
// Investigation of a real sent message (2026-09-01) found that retrying via
// win.GenericSendMessage() a second time on the *same* compose window
// reuses that window's nsIMsgComposeSecure instance (JS-visible as
// gSMFields in MsgComposeCommands.js, created once at window-open time and
// never recreated) -- and nsMsgComposeSecure.cpp's MimeCryptoHackCerts()
// appends to its mCerts member (mCerts.AppendElement(cert)) without ever
// clearing it between calls. A failed attempt followed by our own retry
// therefore left the actual sent message encrypted with *duplicate*
// RecipientInfo entries for every recipient (confirmed via ASN.1 inspection
// of the resulting smime.p7m: 4 RecipientInfo instead of 2, two distinct
// identities each appearing twice) -- and, worse, nobody could decrypt that
// message at all, not even the sender's own Sent copy. nsIMsgComposeSecure
// exposes no reset/clear method, and per its own IDL doc comment ("related
// to exactly one email message while the user is composing it") a same-
// window resend was arguably never a supported operation in the first
// place -- this is very likely a real, previously-unnoticed Thunderbird bug
// that a normal user manually clicking Send again on the same failed
// window would also hit, not something specific to this add-on's retry.
// Cleanup here only fixes cert9.db (and CertVerifier's cache) for whatever
// the *next* send attempt turns out to be -- the current failure is left
// for the user to see and act on normally (close/reopen the compose
// window, or a new message).
function onComposeProcessDone(win, aResult) {
  if (aResult === 0) {
    // NS_OK. Not using Cr.NS_OK to avoid depending on whether Cr
    // (Components.results) is available as a predefined global here the
    // same way Cc/Ci/Cu are -- NS_OK's value (0) is stable across all of
    // Gecko and won't change.
    if (activeTriggers.sendSuccess) {
      console.log("certCleanup: send succeeded, running cleanup");
      cleanupAndReinit("on-send-success").catch((e) => {
        Cu.reportError("certCleanup: cleanup on send-success failed: " + e);
      });
    }
    return;
  }
  if (!activeTriggers.sendError) {
    return;
  }
  console.log(
    `certCleanup: send failed (0x${(aResult >>> 0).toString(16)}), running cleanup (no retry -- see comment above)`
  );
  cleanupAndReinit("on-send-failure").catch((e) => {
    Cu.reportError("certCleanup: cleanup on send-failure failed: " + e);
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

// TRIGGER: Send button/menu click, intercepted *before* the send actually
// starts -- cleanup (and, if needed, CertVerifier reinit) run first, then
// this replays the original action once cleanup finishes. Because this
// runs before Thunderbird's own nsIMsgComposeSecure (gSMFields) for this
// window has been touched by any attempt yet, it doesn't carry the same
// same-window-retry risk documented on onComposeProcessDone above: there's
// only ever one BeginCryptoEncapsulation() call on this window's
// gSMFields for this send, not two.
//
// Historical note: an earlier trigger placed this close to the send itself
// (v0.4.19/v0.4.24 on this branch, before reinitCertVerifier() existed)
// was found to self-heal *worse* than other trigger placements -- the
// reading glitch stopped self-healing on that same send and needed a full
// restart, apparently because there was no normal Thunderbird activity
// happening between the disruptive delete and the send to let Gecko
// re-resolve things cleanly in between. reinitCertVerifier() may or may not
// change that outcome -- this build makes the option available again to
// test that specifically, it does not assume the answer.
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
      if (!activeTriggers.sendButtonClick || win.__certCleanupInterceptingSend) {
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
      console.log(`certCleanup: intercepted send-button click (${id}), running cleanup first`);
      cleanupAndReinit("on-send-button")
        .catch((e) => {
          Cu.reportError("certCleanup: cleanup on send-button failed: " + e);
        })
        .then(() => {
          win.__certCleanupInterceptingSend = false;
          return win.GenericSendMessage(msgType);
        });
    },
    true // capturing, so this sees the click before Thunderbird's own handler
  );
}

function hookComposeWindow(win) {
  if (win.__certCleanupHooked) {
    return;
  }
  win.__certCleanupHooked = true;
  console.log(`certCleanup: hookComposeWindow, activeTriggers.windowOpen=${activeTriggers.windowOpen}`);
  hookSendButton(win);
  let attemptsLeft = GMSGCOMPOSE_POLL_MAX_ATTEMPTS;
  const tryRegister = () => {
    if (win.gMsgCompose && typeof win.gMsgCompose.RegisterStateListener === "function") {
      registerStateListener(win);
      return;
    }
    attemptsLeft -= 1;
    if (attemptsLeft <= 0) {
      console.error(
        "certCleanup: gMsgCompose.RegisterStateListener never became available on this compose window"
      );
      return;
    }
    win.setTimeout(tryRegister, GMSGCOMPOSE_POLL_INTERVAL_MS);
  };
  tryRegister();

  // TRIGGER: compose window open, proactive -- runs before any send is
  // attempted at all, so it never touches this window's
  // nsIMsgComposeSecure/gSMFields instance and can't interact with the
  // same-window-retry issue documented on onComposeProcessDone above.
  if (activeTriggers.windowOpen) {
    console.log("certCleanup: new compose window opened, running cleanup");
    cleanupAndReinit("on-window-open").catch((e) => {
      Cu.reportError("certCleanup: cleanup on window-open failed: " + e);
    });
  }
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

// Registers hooks for every current and future compose window, and the
// earliest well-known Gecko shutdown phase (ShutdownPhase::
// AppShutdownConfirmed, topic "quit-application"). Called once from
// getAPI() below (see the comment there for why module-level top-level
// code isn't the right place for this), guarded so a second getAPI() call
// for another context can't register everything twice.
let initialized = false;
function initialize() {
  if (initialized) {
    console.log("certCleanup: initialize() called again, already initialized");
    return;
  }
  initialized = true;
  registerShutdownBlocker();
  Services.obs.addObserver(domWindowOpenedObserver, "domwindowopened");
  let alreadyOpenCount = 0;
  for (const win of Services.wm.getEnumerator("msgcompose")) {
    hookComposeWindow(win);
    alreadyOpenCount += 1;
  }
  console.log(
    `certCleanup: initialize() done -- shutdown blocker registered, ` +
      `domwindowopened observer registered, ${alreadyOpenCount} already-open compose window(s) hooked`
  );
}

const SHUTDOWN_BLOCKER_NAME =
  "certCleanup: remove stale cert9.db duplicates before quit";

// TRIGGER: app shutdown. Always runs, independent of activeTriggers --
// there's no send in flight to interact badly with, and the original
// (0.4.0) rationale still applies: whatever might go stale in Gecko's
// cache doesn't matter if the process exits shortly after.
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
  // setup like the listeners above (module-level code is unreliable here:
  // Experiment "parent" scripts can be loaded lazily on first real API
  // access rather than eagerly with the add-on, so with no WebExtension-side
  // code touching this API at all, nothing would trigger the script to load
  // in the first place -- see background.js's activate() call).
  getAPI(context) {
    console.log("certCleanup: getAPI() called");
    initialize();
    return {
      certCleanup: {
        // Called once by background.js at startup. By the time this
        // resolves, getAPI() above has already run initialize() -- see
        // schema.json for why background.js needs to make this call at all
        // rather than relying on getAPI() running on its own.
        activate: async () => {},
        // Sets which trigger events are active (see activeTriggers above).
        // Called by background.js once at startup with whatever's saved in
        // storage.local, and again whenever the options page changes it.
        configure: async (triggers) => {
          setTriggers(triggers);
        },
        // Exposed for manual/on-demand use (e.g. from the Browser Console
        // while testing), but not called from background.js on any
        // schedule -- see onComposeProcessDone, hookComposeWindow, and
        // onQuitApplication above for where cleanup actually runs.
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
