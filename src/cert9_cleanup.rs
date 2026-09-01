/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! EXPERIMENTAL. Native, in-process, out-of-band cleanup of the stale
//! keyless duplicate certificate NSS caches into `cert9.db` (see
//! `tools/thunderbird-cert-cleanup/README.md` for the full background on
//! the underlying bug this works around: NSS caches the signer's own
//! certificate into its persistent `cert9.db` on any verified S/MIME
//! signature, including the user's own just-sent signed messages).
//!
//! Everything tried before this went through some Gecko-side JS mechanism
//! -- `nsIX509CertDB`, or a second `Sqlite.sys.mjs` connection -- to remove
//! that duplicate, and *every one* of those, regardless of which specific
//! API was used, broke S/MIME decryption of other messages for the rest of
//! that Thunderbird session. That corruption was root-caused (via a
//! from-source NSS build exercised directly, entirely outside Gecko) to
//! NOT be reproducible at the raw NSS/softoken level: an external process
//! modifying `cert9.db` underneath a live `NSS_InitReadWrite` session
//! survives every combination tried. So the corruption specifically
//! requires going through Gecko's own C++ layer above NSS -- which this
//! module is not part of, despite loading into the same OS process as a
//! PKCS#11 provider.
//!
//! This module exists to test the resulting, previously-untried
//! hypothesis: deleting the duplicate via a connection Gecko never opens,
//! sees, or reacts to (opened directly from this Rust code, with no
//! Gecko/XPCOM/JS involved at any point) might avoid whatever Gecko-side
//! invalidation is actually responsible for the corruption, simply because
//! Gecko is never told anything happened.

use log::{debug, error, info};
use rusqlite::{Connection, OpenFlags};
use std::path::PathBuf;
use std::sync::Once;
use std::time::Duration;

use crate::backend_windows::{list_objects, Object};

/// CKO_CERTIFICATE, as stored in cert9.db's own `nssPublic` table (column
/// `a0`, one row per PKCS #11 object -- confirmed against a real profile's
/// cert9.db and against NSS's own `lib/softoken/sdb.c`, and already relied
/// on by `tools/thunderbird-cert-cleanup`'s JS implementation).
const CKO_CERTIFICATE_BYTES: [u8; 4] = [0, 0, 0, 1];

/// Interval between passes. Not tied to any specific Gecko event, unlike
/// every JS-based trigger tried before this module: MOZ_LOG (CMS category)
/// analysis of a real send showed the duplicate-causing self-verification
/// of a just-sent message happens well under a second after signing, so a
/// short, unconditional poll catches it quickly without needing to
/// synchronize with any particular Thunderbird operation at all.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Env var that, if set, names the profile directory directly and skips
/// `profiles.ini` parsing entirely. Needed for setups `profiles.ini`
/// doesn't (reliably) describe -- e.g. a Daily/Nightly build run from its
/// own install with a profile not registered in the default
/// `%APPDATA%\Thunderbird\profiles.ini`, multiple profiles running at
/// once, or a `-profile <path>` launch override. Same naming convention as
/// this crate's existing `OSCLIENTCERTS_NSS_REGRESSION_DIR` (see
/// Cargo.toml). Since this is read by a DLL loaded into thunderbird.exe,
/// it must be set in the environment *before* Thunderbird starts (a
/// permanent Windows user/system environment variable, or a launcher
/// script that does `set OSCLIENTCERTS_PROFILE_DIR=...` before invoking
/// thunderbird.exe) -- setting it after the process is already running has
/// no effect.
const PROFILE_DIR_OVERRIDE_ENV_VAR: &str = "OSCLIENTCERTS_PROFILE_DIR";

/// Locates the active Thunderbird profile directory. Checks
/// `OSCLIENTCERTS_PROFILE_DIR` first (see above); otherwise reads
/// `profiles.ini`, the same file Thunderbird itself uses to find its own
/// default profile -- there is no other way to learn this from a PKCS #11
/// module, which has no Gecko API access (unlike the WebExtension-based
/// cleanup tool, which just asks `Services.dirsvc` for `ProfD`).
///
/// The `profiles.ini` fallback handles both the modern format (an
/// `[InstallXXXXXXXX]` section with its own `Default=<path>`, which takes
/// precedence when present) and the legacy format (a `[ProfileN]` section
/// with `Default=1`, falling back to the first `[ProfileN]` section if
/// none is marked default).
///
/// Known limitation of the `profiles.ini` fallback: always picks *a*
/// default profile, not necessarily the one actually running this process
/// -- doesn't handle multiple simultaneously-running profiles or a
/// `-profile <path>` command-line override on its own. Use
/// `OSCLIENTCERTS_PROFILE_DIR` for those cases.
fn find_profile_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var(PROFILE_DIR_OVERRIDE_ENV_VAR) {
        debug!("cert9_cleanup: using {} = {}", PROFILE_DIR_OVERRIDE_ENV_VAR, dir);
        return Some(PathBuf::from(dir));
    }

    let appdata = std::env::var("APPDATA").ok()?;
    let thunderbird_dir = PathBuf::from(&appdata).join("Thunderbird");
    let ini_path = thunderbird_dir.join("profiles.ini");
    let contents = std::fs::read_to_string(&ini_path).ok()?;

    #[derive(Default)]
    struct Section {
        name: String,
        path: Option<String>,
        is_relative: bool,
        is_default: bool,
    }

    let mut sections: Vec<Section> = Vec::new();
    let mut current: Option<Section> = None;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            current = Some(Section {
                name: name.to_string(),
                is_relative: true,
                ..Default::default()
            });
            continue;
        }
        let Some(section) = current.as_mut() else {
            continue;
        };
        if let Some(value) = line.strip_prefix("Default=") {
            if section.name.starts_with("Install") {
                // The modern format's install-section Default is itself the
                // relative profile path, not a "1"/"0" flag.
                section.path = Some(value.trim().to_string());
                section.is_default = true;
            } else {
                section.is_default = value.trim() == "1";
            }
        } else if let Some(value) = line.strip_prefix("Path=") {
            section.path = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("IsRelative=") {
            section.is_relative = value.trim() == "1";
        }
    }
    if let Some(section) = current.take() {
        sections.push(section);
    }

    // Prefer an Install-section default (modern format) over a
    // Profile-section default over just the first profile listed.
    let chosen = sections
        .iter()
        .find(|s| s.name.starts_with("Install") && s.path.is_some())
        .or_else(|| sections.iter().find(|s| s.name.starts_with("Profile") && s.is_default))
        .or_else(|| sections.iter().find(|s| s.name.starts_with("Profile") && s.path.is_some()))?;

    let path = chosen.path.as_ref()?;
    if chosen.is_relative {
        Some(thunderbird_dir.join(path))
    } else {
        Some(PathBuf::from(path))
    }
}

fn open_cert9_db(path: &std::path::Path) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Gecko/NSS may hold a brief write transaction of its own; wait rather
    // than failing immediately on the first contended access, same
    // reasoning as Sqlite.sys.mjs's openNotExclusive on the JS side.
    conn.busy_timeout(Duration::from_millis(2000))?;
    Ok(conn)
}

fn run_pass() {
    let Some(profile_dir) = find_profile_dir() else {
        debug!("cert9_cleanup: could not determine Thunderbird profile directory");
        return;
    };
    let db_path = profile_dir.join("cert9.db");
    if !db_path.exists() {
        debug!("cert9_cleanup: no cert9.db at {}", db_path.display());
        return;
    }

    let live_certs: Vec<Vec<u8>> = list_objects()
        .into_iter()
        .filter_map(|object| match object {
            Object::Cert(cert) => Some(cert.value().to_vec()),
            _ => None,
        })
        .collect();
    if live_certs.is_empty() {
        return;
    }

    let conn = match open_cert9_db(&db_path) {
        Ok(conn) => conn,
        Err(e) => {
            error!("cert9_cleanup: failed to open cert9.db: {}", e);
            return;
        }
    };

    for der in &live_certs {
        let result = conn.execute(
            "DELETE FROM nssPublic WHERE a0 = ?1 AND a11 = ?2",
            rusqlite::params![&CKO_CERTIFICATE_BYTES[..], der.as_slice()],
        );
        match result {
            Ok(0) => {}
            Ok(rows) => {
                info!(
                    "cert9_cleanup: removed {} stale cert9.db row(s) (native, out-of-band)",
                    rows
                );
            }
            Err(e) => {
                error!("cert9_cleanup: DELETE failed: {}", e);
            }
        }
    }
}

static SPAWN_ONCE: Once = Once::new();

/// Starts the background cleanup thread, if it isn't already running.
/// Idempotent: C_Initialize can legitimately be called more than once over
/// this module's lifetime in the same process (e.g. after a C_Finalize),
/// and this must not spawn a second thread each time.
pub fn spawn_background_thread() {
    SPAWN_ONCE.call_once(|| {
        std::thread::spawn(|| {
            info!("cert9_cleanup: background thread started");
            loop {
                run_pass();
                std::thread::sleep(POLL_INTERVAL);
            }
        });
    });
}
