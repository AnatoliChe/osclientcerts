/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Privileged WebExtension Experiment implementation. Runs in the parent process
// with full access to Gecko's internal APIs (Cc/Ci), unlike the sandboxed
// background script. See ../../README.md for why this exists and how it's used.
//
// Logged unconditionally, as the literal first statement in the file, before
// anything else runs: Experiment scripts are known to sometimes keep running
// a stale cached copy across an in-place update (see onShutdown below) --
// if this line is ever missing from the console, the version actually
// executing is not the one just installed, full stop, before debugging
// anything else in this file.
console.log("certCleanup: implementation.js module evaluation starting");

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

// SIGN-CHECKBOX-TRIGGER BUILD, not for production. Tests a third trigger
// point, after compose-window-open (v0.4.18) and compose.onBeforeSend
// (v0.4.19): the Security > "Digitally Sign This Message" checkbox in the
// compose window itself. Known reliability caveats, accepted for this
// experiment: (1) never fires at all for an identity with "always sign" as
// its default, since the checkbox starts checked and the user never
// touches it; (2) fires whenever the user happens to toggle it, which could
// be before or after Thunderbird's own recipient-cert resolution -- unlike
// compose-window-open, timing here is not guaranteed to be earlier than
// that resolution.
//
// v0.4.20 hooked only the compose window's global `toggleGlobalSignMessage`
// by monkey-patching it, and never fired at all -- no log line, not even
// "hooked...". Root cause not confirmed (candidates: onOpenWindow/
// docShell.domWindow throwing silently, or the menu checkbox's oncommand
// resolving toggleGlobalSignMessage before our patch replaces the global).
// This build is defensive about it instead of guessing further:
//   1. Window discovery via nsIObserverService "domwindowopened" (gives the
//      raw Window directly, no .docShell.domWindow indirection) instead of
//      nsIWindowMediator.addListener.
//   2. PRIMARY trigger: a capturing "command" event listener on the
//      document, matching by element id against every checkbox confirmed in
//      comm-central's messengercompose.xhtml/MsgComposeCommands.js that can
//      toggle signing (menu_securitySign_Menubar, menu_securitySign_Toolbar,
//      button-signing). This doesn't depend on any particular JS function
//      name or wiring, just the DOM "command" event XUL menuitems/
//      toolbarbuttons always dispatch when activated.
//   3. SECONDARY trigger, kept as a fallback and to cross-check: still
//      monkey-patches toggleGlobalSignMessage() if present.
//   4. Every step logs explicitly, including inside try/catch around
//      anything that touches privileged window internals, so a silent
//      failure this time still leaves a trail in the console.
const SIGN_CHECKBOX_IDS = new Set([
  "menu_securitySign_Menubar",
  "menu_securitySign_Toolbar",
  "button-signing",
]);

function isComposeWindow(win) {
  try {
    return win.document.documentElement.getAttribute("windowtype") === "msgcompose";
  } catch (e) {
    console.error("certCleanup SIGN-CHECKBOX-TRIGGER: isComposeWindow check failed: " + e);
    return false;
  }
}

function onSignTriggered(reason) {
  console.log(`certCleanup SIGN-CHECKBOX-TRIGGER (${reason}): running cleanup`);
  doCleanup()
    .then((deleted) => {
      console.log(
        `certCleanup SIGN-CHECKBOX-TRIGGER (${reason}): done, ${deleted.length} deleted -- now try reading encrypted mail`
      );
    })
    .catch((e) => {
      Cu.reportError(`certCleanup SIGN-CHECKBOX-TRIGGER (${reason}): cleanup failed: ` + e);
    });
}

function hookComposeWindow(win) {
  if (win.__certCleanupSignHooked) {
    return;
  }
  win.__certCleanupSignHooked = true;
  console.log("certCleanup SIGN-CHECKBOX-TRIGGER: hookComposeWindow running for a msgcompose window");

  // Primary: direct DOM "command" event, id-matched. XUL menuitems and
  // toolbarbuttons dispatch this on activation regardless of what JS
  // function ends up handling it internally.
  try {
    win.document.addEventListener(
      "command",
      (event) => {
        const id = event.target && event.target.id;
        if (SIGN_CHECKBOX_IDS.has(id)) {
          console.log(`certCleanup SIGN-CHECKBOX-TRIGGER: command event from #${id}`);
          onSignTriggered("command-event:" + id);
        }
      },
      true // capture, so this still sees the event even if something else stops propagation
    );
    console.log("certCleanup SIGN-CHECKBOX-TRIGGER: attached document-level command listener");
  } catch (e) {
    console.error("certCleanup SIGN-CHECKBOX-TRIGGER: failed to attach command listener: " + e);
  }

  // Secondary/fallback: monkey-patch the global function directly, in case
  // the id-matched command listener above misses something (e.g. a
  // keyboard shortcut that calls the function without going through one of
  // the known elements).
  try {
    if (typeof win.toggleGlobalSignMessage === "function") {
      const original = win.toggleGlobalSignMessage;
      win.toggleGlobalSignMessage = function (...args) {
        const result = original.apply(this, args);
        onSignTriggered("toggleGlobalSignMessage-patch");
        return result;
      };
      console.log("certCleanup SIGN-CHECKBOX-TRIGGER: also patched toggleGlobalSignMessage");
    } else {
      console.log(
        "certCleanup SIGN-CHECKBOX-TRIGGER: toggleGlobalSignMessage not found on this window (relying on command listener only)"
      );
    }
  } catch (e) {
    console.error("certCleanup SIGN-CHECKBOX-TRIGGER: failed to patch toggleGlobalSignMessage: " + e);
  }
}

function maybeHookNewWindow(subject) {
  try {
    // "domwindowopened"'s subject is already the raw Window object in JS.
    const win = subject;
    win.addEventListener(
      "load",
      function onLoad() {
        win.removeEventListener("load", onLoad);
        console.log(
          `certCleanup SIGN-CHECKBOX-TRIGGER: domwindowopened+load fired, windowtype=${
            win.document?.documentElement?.getAttribute("windowtype")
          }`
        );
        if (isComposeWindow(win)) {
          hookComposeWindow(win);
        }
      },
      { once: true }
    );
  } catch (e) {
    console.error("certCleanup SIGN-CHECKBOX-TRIGGER: maybeHookNewWindow failed: " + e);
  }
}

const domWindowOpenedObserver = {
  observe(subject, topic) {
    if (topic === "domwindowopened") {
      maybeHookNewWindow(subject);
    }
  },
};

try {
  Services.obs.addObserver(domWindowOpenedObserver, "domwindowopened");
  console.log("certCleanup SIGN-CHECKBOX-TRIGGER: domwindowopened observer registered");
} catch (e) {
  // Deliberately not swallowed further up: if this throws, everything below
  // it in the file (the AsyncShutdown blocker, the ExtensionAPI class
  // itself) would otherwise silently never load either.
  console.error("certCleanup SIGN-CHECKBOX-TRIGGER: FAILED to register domwindowopened observer: " + e);
}

// Also hook any compose windows already open when the add-on loads/reloads.
try {
  for (const win of Services.wm.getEnumerator("msgcompose")) {
    hookComposeWindow(win);
  }
} catch (e) {
  console.error("certCleanup SIGN-CHECKBOX-TRIGGER: enumerating existing compose windows failed: " + e);
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
        // No-op; see schema.json for why background.js calls this once at
        // startup (forces this script to load if Thunderbird would
        // otherwise only load it lazily on first real API access).
        ping: async () => {
          console.log("certCleanup: ping() called, implementation.js is loaded and responsive");
        },
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
    Services.obs.removeObserver(domWindowOpenedObserver, "domwindowopened");
    Services.obs.notifyObservers(null, "startupcache-invalidate", null);
  }
};
