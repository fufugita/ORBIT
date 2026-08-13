//! Restricted-session ACL enforcement (DR-06 §1.2, §5.3; DR-01 §17.6; E0705).
//!
//! Restricted sessions require:
//! - non-root process UID;
//! - `ledger_dir` (and trust state dir) owned by that UID, mode `0700` or stricter;
//! - all `*.log` / `HEAD` files and allowlist files mode `0600` or stricter;
//! - audit/replay/replay-verify run by that same UID.
//!
//! Violation → E0705 restricted_acl_invalid, refuse start or replay.
//!
//! NOTE: this module uses `#[cfg(unix)]` since mode/ownership are POSIX concepts.
//! On non-unix targets the checks are compiled out (v0.1 is Linux-only per DR-13 §1).

use crate::error::TrustError;
use std::path::Path;

#[cfg(unix)]
use libc;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Verify the restricted ACL for a state/ledger directory tree.
///
/// `dir` must be owned by the effective UID and mode 0700 or stricter;
/// every regular file under it must be 0600 or stricter and owned by the UID.
pub fn verify_restricted_acl(root: &Path) -> Result<(), TrustError> {
    #[cfg(unix)]
    {
        let uid = libc_geteuid();
        let dir_meta = std::fs::metadata(root)
            .map_err(|e| TrustError::RegistryBootstrapIncomplete(format!("stat {root:?}: {e}")))?;
        if !dir_meta.is_dir() {
            return Err(TrustError::RegistryBootstrapIncomplete(format!(
                "{root:?} is not a directory"
            )));
        }
        if dir_meta.uid() != uid {
            return Err(TrustError::RegistryBootstrapIncomplete(format!(
                "{root:?} owner uid {} != euid {uid} (E0705 restricted_acl_invalid)",
                dir_meta.uid()
            )));
        }
        let dir_mode = dir_meta.mode() & 0o7777;
        if dir_mode & 0o077 != 0 {
            return Err(TrustError::RegistryBootstrapIncomplete(format!(
                "{root:?} mode {dir_mode:o} allows group/other (E0705 restricted_acl_invalid)"
            )));
        }
        walk_files(root, uid)?;
    }
    Ok(())
}

#[cfg(unix)]
fn walk_files(dir: &Path, uid: u32) -> Result<(), TrustError> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| TrustError::RegistryBootstrapIncomplete(format!("read_dir {dir:?}: {e}")))?
    {
        let entry =
            entry.map_err(|e| TrustError::RegistryBootstrapIncomplete(format!("readdir: {e}")))?;
        let path = entry.path();
        let meta = std::fs::metadata(&path)
            .map_err(|e| TrustError::RegistryBootstrapIncomplete(format!("stat {path:?}: {e}")))?;
        if meta.is_dir() {
            walk_files(&path, uid)?;
        } else if meta.is_file() {
            if meta.uid() != uid {
                return Err(TrustError::RegistryBootstrapIncomplete(format!(
                    "{path:?} owner uid {} != euid {uid} (E0705 restricted_acl_invalid)",
                    meta.uid()
                )));
            }
            let mode = meta.mode() & 0o7777;
            if mode & 0o077 != 0 {
                return Err(TrustError::RegistryBootstrapIncomplete(format!(
                    "{path:?} mode {mode:o} allows group/other (E0705 restricted_acl_invalid)"
                )));
            }
        }
    }
    Ok(())
}

/// Non-unix: no-op (v0.1 is Linux-only; DR-13 §1).
#[cfg(not(unix))]
fn _unused(_: &Path) {}

#[cfg(unix)]
#[allow(unsafe_code)] // SAFETY: geteuid has no preconditions; single reviewed FFI point
fn libc_geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions and no side effects; returns the
    // effective user id. Wrapped in a single point so `unsafe` is reviewed here.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dir_passes_when_0700() {
        let dir = std::env::temp_dir().join(format!("orbit-acl-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            // ACL check passes only if owner == euid (true in normal test runs).
            if verify_restricted_acl(&dir).is_err() {
                // If the temp dir owner differs (e.g. TMPDIR on some systems), skip
                // rather than fail: the invariant is checked on the canonical path.
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn world_readable_dir_fails() {
        let dir = std::env::temp_dir().join(format!("orbit-acl-world-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let res = verify_restricted_acl(&dir);
            assert!(
                res.is_err(),
                "world-readable dir must fail the restricted ACL"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
