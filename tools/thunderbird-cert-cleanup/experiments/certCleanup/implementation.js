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

var certCleanup = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    return {
      certCleanup: {
        async cleanup() {
          // Logged from this side too (not just background.js) so a stale
          // cached Experiment implementation -- the exact problem
          // onShutdown() below addresses -- would be visible as a version
          // mismatch between the two log lines instead of silently running.
          console.log(
            "certCleanup: implementation.js version " + context.extension.version
          );

          const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
            Ci.nsIX509CertDB
          );

          const certs = certDB.getCerts();
          const liveCerts = certs.filter(
            (cert) => (cert.tokenName || "").trim() === OS_CLIENT_CERTS_TOKEN_NAME
          );
          if (liveCerts.length === 0) {
            // The provider isn't loaded (or has no certs) right now -- don't
            // touch cert9.db at all, since we have no way to confirm which of
            // its rows, if any, are safe to remove.
            return [];
          }

          // certDB.getCerts() is *not* a plain listing: Gecko's
          // nsNSSCertificateDB::GetCerts() calls
          // PK11_ListCerts(PK11CertListUnique, ...) (confirmed against NSS's
          // own lib/pk11wrap and security/manager/ssl/nsNSSCertificateDB.cpp),
          // which silently merges a persisted, keyless cert9.db row with a
          // live token object representing the same certificate. That merge
          // is exactly why our own certificate's stale duplicate never shows
          // up as a second entry above, even when one genuinely exists in
          // cert9.db right now. NSS has a non-deduplicating list type
          // (PK11CertListAll), but no JS-facing API exposes it.
          //
          // So: read cert9.db directly instead, via Sqlite.sys.mjs (Gecko's
          // sanctioned module for opening additional, concurrent connections
          // to a Firefox/Thunderbird-managed sqlite database -- the same
          // mechanism other in-process code uses for shared databases like
          // places.sqlite; openNotExclusive avoids fighting NSS's own already
          // -open connection to this same file). A row here is a genuine
          // persisted duplicate by construction: PKCS #11 objects belonging to
          // an *external* token like ours are never themselves written to
          // cert9.db, so any CKO_CERTIFICATE row whose DER byte-for-byte
          // matches one of our live certificates cannot be that live
          // certificate -- it can only be a stale, keyless, NSS-cached copy.
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
            });
            for (const liveCert of liveCerts) {
              const der = Uint8Array.from(liveCert.getRawDER());
              const rows = await conn.execute(
                "SELECT id FROM nssPublic WHERE " +
                  CKA_CLASS_COLUMN + " = :cls AND " + CKA_VALUE_COLUMN + " = :der",
                { cls: CKO_CERTIFICATE_BYTES, der }
              );
              for (const row of rows) {
                const rowId = row.getResultByName("id");
                console.log(
                  "certCleanup: found stale cert9.db row id=" + rowId +
                    " duplicating live cert subject=" + liveCert.subjectName
                );
                await conn.execute("DELETE FROM nssPublic WHERE id = :id", {
                  id: rowId,
                });
                deleted.push({
                  subjectName: liveCert.subjectName,
                  issuerName: liveCert.issuerName,
                  serialNumber: liveCert.serialNumber,
                  rowId,
                });
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
        },
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
      return;
    }
    Services.obs.notifyObservers(null, "startupcache-invalidate", null);
  }
};
