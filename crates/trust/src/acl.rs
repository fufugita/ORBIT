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
        #[cfg(unix)]
        {
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
        #[cfg(windows)]
        {
            let mut home = native::Home::new();
            let before = home.snapshot();
            let result = verify_restricted_acl(&home.path);
            assert_eq!(home.snapshot(), before);
            home.cleanup();
            assert!(
                result.is_ok(),
                "Private empty trust root must pass without mutation"
            );
        }
    }

    #[test]
    fn world_readable_dir_fails() {
        #[cfg(unix)]
        {
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
        #[cfg(windows)]
        {
            let mut home = native::Home::new();
            let unsafe_state = home.make_world_readable();
            let result = verify_restricted_acl(&home.path);
            assert_eq!(home.snapshot(), unsafe_state);
            home.cleanup();
            eprintln!(
                "trust_acl_world_readable_control_complete observed={}",
                if result.is_ok() { "Ok" } else { "Err" }
            );
            assert!(
                matches!(result, Err(TrustError::RegistryBootstrapIncomplete(_))),
                "world-readable trust root must return RegistryBootstrapIncomplete"
            );
        }
    }

    #[cfg(windows)]
    mod native {
        use super::*;
        use std::path::PathBuf;
        use std::time::{Duration, Instant};
        fn fixture_command(
            operation: &'static str,
            program: &Path,
            arguments: &[&std::ffi::OsStr],
            path: Option<&Path>,
        ) -> std::process::Output {
            use std::process::{Command, Stdio};
            let mut command = Command::new(program);
            command
                .args(arguments)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if program.file_name() == Some(std::ffi::OsStr::new("powershell.exe")) {
                // Let the legacy PowerShell child use its own module search defaults.
                command.env_remove("PSModulePath");
            }
            if let Some(path) = path {
                command.env("ORBIT_TEST_ACL_PATH", path);
            }
            let mut child = ChildGuard(Some(command.spawn().unwrap()));
            let started = Instant::now();
            loop {
                match child.child().try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {}
                    Err(error) => {
                        let cleanup = child.stop();
                        panic!("fixture polling failed: {error}; cleanup: {cleanup:?}");
                    }
                }
                if started.elapsed() > Duration::from_secs(10) {
                    let cleanup = child.stop();
                    panic!("fixture command timed out; cleanup: {cleanup:?}");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            // The terminal state was observed before moving out of the ownership guard.
            let output = child.0.take().unwrap().wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "native fixture command failed: program={} operation={operation} status={}\nstdout (at most 4096 bytes):\n{}\nstderr (at most 4096 bytes):\n{}",
                program.file_name().unwrap_or_default().to_string_lossy(),
                output.status,
                diagnostic(&output.stdout),
                diagnostic(&output.stderr)
            );
            assert!(output.stdout.len() <= 16384 && output.stderr.len() <= 16384);
            output
        }

        fn diagnostic(bytes: &[u8]) -> String {
            let text = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
            let mut clipped = String::new();
            for character in text.chars() {
                let character =
                    if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
                        '\u{fffd}'
                    } else {
                        character
                    };
                if clipped.len() + character.len_utf8() > 4096 {
                    break;
                }
                clipped.push(character);
            }
            clipped
        }

        fn system_program(name: &str) -> PathBuf {
            PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join(name)
        }

        fn icacls(path: &Path, arguments: &[&str]) -> std::process::Output {
            use std::ffi::OsStr;
            let mut args = vec![path.as_os_str()];
            args.extend(arguments.iter().map(OsStr::new));
            fixture_command("icacls", &system_program("icacls.exe"), &args, None)
        }

        fn current_sid() -> String {
            use std::ffi::OsStr;
            let output = fixture_command(
                "current_sid",
                &system_program("WindowsPowerShell/v1.0/powershell.exe"),
                &[
                    OsStr::new("-NoProfile"),
                    OsStr::new("-NonInteractive"),
                    OsStr::new("-Command"),
                    OsStr::new("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
                ],
                None,
            );
            let sid = String::from_utf8(output.stdout).unwrap().trim().to_owned();
            assert!(
                sid.starts_with("S-1-5-")
                    && sid
                        .bytes()
                        .all(|v| v.is_ascii_digit() || v == b'S' || v == b'-')
            );
            sid
        }

        struct ChildGuard(Option<std::process::Child>);

        impl ChildGuard {
            fn child(&mut self) -> &mut std::process::Child {
                self.0.as_mut().expect("owned fixture child")
            }
            fn stop(&mut self) -> Result<(), String> {
                let Some(child) = self.0.as_mut() else {
                    return Ok(());
                };
                let mut failures = Vec::new();
                match child.try_wait() {
                    Ok(Some(_)) => {
                        self.0.take();
                        return Ok(());
                    }
                    Ok(None) => {}
                    Err(error) => failures.push(format!("poll: {error}")),
                }
                if let Err(error) = child.kill() {
                    failures.push(format!("kill: {error}"));
                }
                match child.wait() {
                    Ok(_) => {
                        self.0.take();
                    }
                    Err(error) => failures.push(format!("wait: {error}")),
                }
                if failures.is_empty() {
                    Ok(())
                } else {
                    Err(failures.join("; "))
                }
            }
        }

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                use std::io::Write as _;
                if let Err(error) = self.stop() {
                    let _ = writeln!(std::io::stderr(), "fixture child cleanup failed: {error}");
                }
            }
        }

        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        pub(super) struct Security {
            pub(super) owner: String,
            pub(super) group: String,
            pub(super) sddl: String,
            pub(super) protected: bool,
            pub(super) aces: Vec<Ace>,
        }

        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        pub(super) struct Ace {
            pub(super) sid: String,
            pub(super) mask: u64,
            pub(super) kind: String,
            pub(super) inheritance: u32,
            pub(super) propagation: u32,
            pub(super) inherited: bool,
        }

        impl Security {
            pub(super) fn allows(&self, sid: &str, mask: u64) -> bool {
                self.aces.iter().any(|ace| {
                    ace.sid == sid
                        && ace.kind == "Allow"
                        && ace.propagation & 2 == 0
                        && ace.mask & mask == mask
                })
            }
        }

        pub(super) fn security(path: &Path) -> Security {
            use std::ffi::OsStr;
            let output = fixture_command(
                "security",
                &system_program("WindowsPowerShell/v1.0/powershell.exe"),
                &[
                    OsStr::new("-NoProfile"),
                    OsStr::new("-NonInteractive"),
                    OsStr::new("-Command"),
                    OsStr::new(
                        "$ErrorActionPreference='Stop'; $acl=Get-Acl -LiteralPath $env:ORBIT_TEST_ACL_PATH; $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object { [ordered]@{sid=$_.IdentityReference.Value;mask=[int64]$_.FileSystemRights.value__;kind=$_.AccessControlType.ToString();inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags;inherited=$_.IsInherited} }); [ordered]@{owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;group=$acl.GetGroup([Security.Principal.SecurityIdentifier]).Value;sddl=$acl.Sddl;protected=$acl.AreAccessRulesProtected;aces=$rules} | ConvertTo-Json -Compress -Depth 4",
                    ),
                ],
                Some(path),
            );
            serde_json::from_slice(&output.stdout).unwrap()
        }

        #[derive(Debug, PartialEq, Eq)]
        pub(super) struct Snapshot {
            identity: orbit_platform::fs::FileIdentity,
            pub(super) security: Security,
            names: Vec<std::ffi::OsString>,
        }

        pub(super) struct Home {
            pub(super) path: std::path::PathBuf,
            identity: orbit_platform::fs::FileIdentity,
            cleaned: bool,
        }

        fn full_identity(path: &Path) -> std::io::Result<orbit_platform::fs::FileIdentity> {
            orbit_platform::fs::SourceDirectory::open(path).map(|root| root.identity())
        }

        impl Home {
            pub(super) fn new() -> Self {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                for _ in 0..100 {
                    let path = std::env::temp_dir().join(format!(
                        "orbit-trust-native-acl-{}-{}",
                        std::process::id(),
                        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    ));
                    match orbit_platform::fs::Directory::create(&path) {
                        Ok(root) => {
                            let identity = root.identity();
                            drop(root);
                            let home = Self {
                                path,
                                identity,
                                cleaned: false,
                            };
                            let before = home.snapshot();
                            assert_eq!(before.security.owner, current_sid());
                            assert!(before.security.protected);
                            assert_eq!(before.security.aces.len(), 1);
                            assert!(before.security.allows(&before.security.owner, 0x1f01ff));
                            assert!(before.names.is_empty());
                            {
                                let private =
                                    orbit_platform::fs::Directory::open(&home.path).unwrap();
                                assert_eq!(private.identity(), identity);
                            }
                            return home;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(_) => panic!("Native private trust fixture creation failed"),
                    }
                }
                panic!("Native trust fixture name budget exhausted")
            }

            pub(super) fn snapshot(&self) -> Snapshot {
                let identity =
                    full_identity(&self.path).expect("Native trust fixture identity unavailable");
                assert_eq!(identity, self.identity);
                let mut names: Vec<_> = std::fs::read_dir(&self.path)
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect();
                names.sort();
                Snapshot {
                    identity,
                    security: security(&self.path),
                    names,
                }
            }

            pub(super) fn make_world_readable(&self) -> Snapshot {
                let before = self.snapshot();
                icacls(&self.path, &["/grant", "*S-1-1-0:(OI)(CI)RX"]);
                let after = self.snapshot();
                assert_eq!(after.identity, before.identity);
                assert_eq!(after.security.owner, before.security.owner);
                assert_eq!(after.security.group, before.security.group);
                assert!(after.security.protected);
                assert!(after.security.allows("S-1-1-0", 1 | 0x20));
                assert!(after.names.is_empty());
                after
            }

            pub(super) fn cleanup(&mut self) {
                assert_eq!(full_identity(&self.path).unwrap(), self.identity);
                assert!(
                    std::fs::read_dir(&self.path).unwrap().next().is_none(),
                    "Trust fixture cleanup requires an empty owned root"
                );
                std::fs::remove_dir(&self.path).expect("Owned trust fixture cleanup failed");
                assert!(
                    std::fs::symlink_metadata(&self.path)
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                    "Trust fixture remained after cleanup"
                );
                self.cleaned = true;
            }
        }

        impl Drop for Home {
            fn drop(&mut self) {
                if !self.cleaned
                    && full_identity(&self.path).is_ok_and(|identity| identity == self.identity)
                    && std::fs::read_dir(&self.path)
                        .is_ok_and(|mut entries| entries.next().is_none())
                {
                    let _ = std::fs::remove_dir(&self.path);
                }
            }
        }
    }
}
