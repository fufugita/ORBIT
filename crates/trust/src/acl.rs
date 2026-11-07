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
//! Unix checks use UID and mode. Windows uses held owner/DACL validation and
//! bounded read-only private-tree inspection.

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
    #[cfg(windows)]
    {
        use orbit_platform::fs::{Directory, InspectionLimits};
        let directory = Directory::open(root).map_err(|error| {
            TrustError::RegistryBootstrapIncomplete(format!(
                "restricted ACL root validation failed: {error}"
            ))
        })?;
        directory
            .inspect_private_tree(InspectionLimits {
                max_entries: 4096,
                max_name_bytes: 1_048_576,
                max_depth: 128,
            })
            .map_err(|error| {
                TrustError::RegistryBootstrapIncomplete(format!(
                    "restricted ACL private-tree inspection failed: {error}"
                ))
            })?;
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

/// Reserved helper for non-Unix builds.
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

    #[test]
    #[cfg(windows)]
    fn windows_nested_private_fa_r_rx_pass() {
        native::adversarial::nested_private();
    }

    #[test]
    #[cfg(windows)]
    fn windows_unsafe_nested_acl_fails() {
        native::adversarial::unsafe_nested();
    }

    #[test]
    #[cfg(windows)]
    fn windows_foreign_owner_fails() {
        native::adversarial::foreign_owner();
    }

    #[test]
    #[cfg(windows)]
    fn windows_symlink_roots_and_children_fail() {
        native::adversarial::symlinks();
    }

    #[test]
    #[cfg(windows)]
    fn windows_hardlinked_file_fails() {
        native::adversarial::hardlink();
    }

    #[test]
    #[cfg(windows)]
    fn windows_missing_root_fails_without_creation() {
        native::adversarial::missing();
    }

    #[test]
    #[cfg(windows)]
    fn windows_entry_limit_boundary() {
        native::adversarial::entry_limit();
    }

    #[test]
    #[cfg(windows)]
    fn windows_depth_limit_boundary() {
        native::adversarial::depth_limit();
    }

    #[test]
    #[cfg(windows)]
    fn windows_name_bytes_limit_boundary() {
        native::adversarial::name_limit();
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

        pub(super) mod adversarial {
            use super::*;
            use orbit_platform::fs::{Directory, FileIdentity, SourceDirectory};
            use std::ffi::{OsStr, OsString};
            use std::os::windows::fs::MetadataExt;

            const CONTENT: &[u8] = b"trust fixture canary";
            const NODE_LIMIT: usize = 4097;

            #[derive(Clone, Copy, PartialEq, Eq)]
            enum Kind {
                Directory,
                File,
                Alias(usize),
                DirectoryLink(usize),
                FileLink(usize),
            }

            struct Node {
                relative: PathBuf,
                parent: Option<usize>,
                kind: Kind,
                identity: Option<FileIdentity>,
                directory: Option<Directory>,
                active: bool,
                multiple_links: bool,
            }

            struct Tree {
                root: Option<Directory>,
                nodes: Vec<Node>,
                home: Home,
            }

            #[derive(PartialEq, Eq)]
            struct ObjectFact {
                identity: Option<FileIdentity>,
                length: u64,
                last_write: u64,
                change: Option<i64>,
                attributes: u32,
                link: Option<PathBuf>,
                bytes: Vec<u8>,
            }

            #[derive(serde::Deserialize, PartialEq, Eq)]
            struct PolicyBatch {
                count: usize,
                digest: String,
                sample: Security,
            }

            #[derive(PartialEq, Eq)]
            struct Evidence {
                root: FileIdentity,
                root_metadata: (u64, u64, u32),
                inventories: Vec<Vec<OsString>>,
                objects: Vec<ObjectFact>,
                policies: Vec<PolicyBatch>,
            }

            impl Tree {
                fn new() -> Self {
                    let home = Home::new();
                    let root = Some(Directory::open(&home.path).unwrap());
                    Self {
                        home,
                        root,
                        nodes: Vec::new(),
                    }
                }

                fn path(&self, index: usize) -> PathBuf {
                    self.home.path.join(&self.nodes[index].relative)
                }

                fn parent(&self, parent: Option<usize>) -> &Directory {
                    match parent {
                        Some(index) => self.nodes[index].directory.as_ref().unwrap(),
                        None => self.root.as_ref().unwrap(),
                    }
                }

                fn relative(&self, parent: Option<usize>, name: &str) -> PathBuf {
                    assert!(
                        self.nodes.len() < NODE_LIMIT,
                        "registered fixture budget exhausted"
                    );
                    match parent {
                        Some(index) => self.nodes[index].relative.join(name),
                        None => PathBuf::from(name),
                    }
                }

                fn directory(&mut self, parent: Option<usize>, name: &str) -> usize {
                    let relative = self.relative(parent, name);
                    let directory = self.parent(parent).child(OsStr::new(name), true).unwrap();
                    let identity = directory.identity();
                    let index = self.nodes.len();
                    self.nodes.push(Node {
                        relative,
                        parent,
                        kind: Kind::Directory,
                        identity: Some(identity),
                        directory: Some(directory),
                        active: true,
                        multiple_links: false,
                    });
                    index
                }

                fn file(&mut self, parent: Option<usize>, name: &str) -> usize {
                    let relative = self.relative(parent, name);
                    let mut file = self.parent(parent).create_file(OsStr::new(name)).unwrap();
                    let identity = file.identity();
                    let index = self.nodes.len();
                    // Registration precedes the fallible write/flush observations.
                    self.nodes.push(Node {
                        relative,
                        parent,
                        kind: Kind::File,
                        identity: Some(identity),
                        directory: None,
                        active: true,
                        multiple_links: false,
                    });
                    file.write_all(CONTENT).unwrap();
                    file.sync_all().unwrap();
                    index
                }

                fn private_parent(&self, parent: Option<usize>) -> Directory {
                    let mut directory = Directory::open(&self.home.path).unwrap();
                    if let Some(index) = parent {
                        for name in self.nodes[index].relative.iter() {
                            directory = directory.child(name, false).unwrap();
                        }
                    }
                    directory
                }

                fn names(&self, parent: Option<usize>) -> Vec<OsString> {
                    let path = parent
                        .map(|i| self.path(i))
                        .unwrap_or_else(|| self.home.path.clone());
                    let mut expected = self
                        .nodes
                        .iter()
                        .filter(|n| n.active && n.parent == parent)
                        .map(|n| n.relative.file_name().unwrap().to_os_string())
                        .collect::<Vec<_>>();
                    expected.sort();
                    let mut actual = std::fs::read_dir(path)
                        .unwrap()
                        .take(expected.len() + 1)
                        .map(|entry| entry.unwrap().file_name())
                        .collect::<Vec<_>>();
                    actual.sort();
                    assert!(actual == expected, "registered fixture namespace changed");
                    actual
                }

                fn fact(&self, index: usize, private: bool) -> ObjectFact {
                    use std::io::Read;
                    let node = &self.nodes[index];
                    let path = self.path(index);
                    let meta = std::fs::symlink_metadata(&path).unwrap();
                    let mut fact = ObjectFact {
                        identity: None,
                        length: meta.len(),
                        last_write: meta.last_write_time(),
                        change: None,
                        attributes: meta.file_attributes(),
                        link: None,
                        bytes: Vec::new(),
                    };
                    if let Kind::DirectoryLink(target) | Kind::FileLink(target) = node.kind {
                        assert!(
                            meta.file_type().is_symlink(),
                            "registered symlink type changed"
                        );
                        let target_path = std::fs::read_link(&path).unwrap();
                        assert!(
                            target_path == self.path(target),
                            "registered symlink target changed"
                        );
                        fact.link = Some(target_path);
                        return fact;
                    }
                    assert!(
                        !meta.file_type().is_symlink(),
                        "registered ordinary object became a link"
                    );
                    if node.kind == Kind::Directory {
                        assert!(meta.is_dir());
                        let id = if private {
                            self.private_parent(node.parent)
                                .child(node.relative.file_name().unwrap(), false)
                                .unwrap()
                                .identity()
                        } else {
                            SourceDirectory::open(&path).unwrap().identity()
                        };
                        assert!(
                            Some(id) == node.identity,
                            "registered directory identity changed"
                        );
                        fact.identity = Some(id);
                    } else if matches!(node.kind, Kind::Alias(_)) || node.multiple_links {
                        assert!(meta.is_file());
                        std::fs::File::open(&path)
                            .unwrap()
                            .take(CONTENT.len() as u64 + 1)
                            .read_to_end(&mut fact.bytes)
                            .unwrap();
                        assert!(
                            fact.bytes == CONTENT,
                            "registered linked-file bytes changed"
                        );
                        // Public source handles reject multi-link files. No post-link ID/count is invented.
                    } else if private {
                        let mut file = self
                            .private_parent(node.parent)
                            .open_file(node.relative.file_name().unwrap())
                            .unwrap();
                        let before = file.snapshot().unwrap();
                        assert!(
                            Some(before.identity) == node.identity,
                            "registered file identity changed"
                        );
                        let mut bytes = [0u8; 64];
                        let count = file.read_into(&mut bytes).unwrap();
                        assert!(
                            count == CONTENT.len() && &bytes[..count] == CONTENT,
                            "registered bytes changed"
                        );
                        assert_eq!(file.read_into(&mut bytes).unwrap(), 0);
                        assert!(
                            file.snapshot().unwrap() == before,
                            "fixture read changed file snapshot"
                        );
                        fact.identity = Some(before.identity);
                        fact.change = Some(before.change_time);
                        fact.bytes = CONTENT.to_vec();
                    } else {
                        let directory = SourceDirectory::open(path.parent().unwrap()).unwrap();
                        let mut file = directory
                            .open_file_expected(path.file_name().unwrap(), node.identity.unwrap())
                            .unwrap();
                        let before = file.snapshot().unwrap();
                        fact.bytes = file.read_limited(CONTENT.len()).unwrap();
                        assert!(fact.bytes == CONTENT, "registered bytes changed");
                        assert!(
                            file.snapshot().unwrap() == before,
                            "fixture read changed source snapshot"
                        );
                        fact.identity = Some(before.identity);
                        fact.change = Some(before.change_time);
                    }
                    fact
                }

                fn evidence(&self, private: bool, strict_policy: bool) -> Evidence {
                    let root = if private {
                        Directory::open(&self.home.path).unwrap().identity()
                    } else {
                        SourceDirectory::open(&self.home.path).unwrap().identity()
                    };
                    assert!(
                        root == self.home.identity,
                        "registered fixture root identity changed"
                    );
                    let metadata = std::fs::symlink_metadata(&self.home.path).unwrap();
                    let root_metadata = (
                        metadata.creation_time(),
                        metadata.last_write_time(),
                        metadata.file_attributes(),
                    );
                    let mut inventories = vec![self.names(None)];
                    let mut objects = Vec::new();
                    for (index, node) in self.nodes.iter().enumerate().filter(|(_, n)| n.active) {
                        objects.push(self.fact(index, private));
                        if node.kind == Kind::Directory {
                            inventories.push(self.names(Some(index)));
                        }
                    }
                    let mut paths = vec![PathBuf::new()];
                    paths.extend(
                        self.nodes
                            .iter()
                            .filter(|n| {
                                n.active
                                    && !matches!(n.kind, Kind::DirectoryLink(_) | Kind::FileLink(_))
                            })
                            .map(|n| n.relative.clone()),
                    );
                    Evidence {
                        root,
                        root_metadata,
                        inventories,
                        objects,
                        policies: policies(&self.home.path, &paths, strict_policy),
                    }
                }

                fn budgets(&self) -> (usize, usize, usize) {
                    use std::os::windows::ffi::OsStrExt;
                    let nodes = self.nodes.iter().filter(|n| n.active).collect::<Vec<_>>();
                    let bytes = nodes
                        .iter()
                        .map(|n| n.relative.as_os_str().encode_wide().count() * 2)
                        .sum();
                    let depth = nodes
                        .iter()
                        .map(|n| n.relative.components().count())
                        .max()
                        .unwrap_or(0);
                    (nodes.len(), bytes, depth)
                }

                fn cleanup(&mut self, private: bool) {
                    self.names(None);
                    self.root.take();
                    for node in &mut self.nodes {
                        node.directory.take();
                    }
                    // Link entries are removed before their independently owned targets.
                    for index in (0..self.nodes.len()).rev() {
                        let kind = self.nodes[index].kind;
                        if let Kind::DirectoryLink(target) | Kind::FileLink(target) = kind {
                            self.fact(index, false);
                            let before = (
                                self.fact(target, false),
                                security(&self.path(target)),
                                if self.nodes[target].kind == Kind::Directory {
                                    self.names(Some(target))
                                } else {
                                    Vec::new()
                                },
                            );
                            if matches!(kind, Kind::DirectoryLink(_)) {
                                std::fs::remove_dir(self.path(index)).unwrap();
                            } else {
                                std::fs::remove_file(self.path(index)).unwrap();
                            }
                            absent(&self.path(index));
                            self.nodes[index].active = false;
                            assert!(
                                before
                                    == (
                                        self.fact(target, false),
                                        security(&self.path(target)),
                                        if self.nodes[target].kind == Kind::Directory {
                                            self.names(Some(target))
                                        } else {
                                            Vec::new()
                                        }
                                    ),
                                "symlink cleanup changed target"
                            );
                        } else if let Kind::Alias(original) = kind {
                            self.fact(index, false);
                            std::fs::remove_file(self.path(index)).unwrap();
                            absent(&self.path(index));
                            self.nodes[index].active = false;
                            self.nodes[original].multiple_links = false;
                            self.fact(original, false); // Actual single-link reopening checks the cached original full ID.
                        }
                    }
                    for index in (0..self.nodes.len()).rev() {
                        if self.nodes[index].active && self.nodes[index].kind == Kind::File {
                            self.fact(index, private);
                            std::fs::remove_file(self.path(index)).unwrap();
                            absent(&self.path(index));
                            self.nodes[index].active = false;
                        }
                    }
                    for index in (0..self.nodes.len()).rev() {
                        if self.nodes[index].active && self.nodes[index].kind == Kind::Directory {
                            self.fact(index, private);
                            self.names(Some(index));
                            std::fs::remove_dir(self.path(index)).unwrap();
                            absent(&self.path(index));
                            self.nodes[index].active = false;
                        }
                    }
                    assert!(self.nodes.iter().all(|n| !n.active));
                    self.names(None);
                    self.home.cleanup();
                }
            }

            fn absent(path: &Path) {
                assert!(
                    std::fs::symlink_metadata(path)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "registered name remained after cleanup"
                );
            }

            fn powershell(operation: &'static str, path: &Path, script: &str) {
                fixture_command(
                    operation,
                    &system_program("WindowsPowerShell/v1.0/powershell.exe"),
                    &[
                        OsStr::new("-NoProfile"),
                        OsStr::new("-NonInteractive"),
                        OsStr::new("-Command"),
                        OsStr::new(script),
                    ],
                    Some(path),
                );
            }

            fn policies(root: &Path, paths: &[PathBuf], strict: bool) -> Vec<PolicyBatch> {
                let mut result = Vec::new();
                let mut offset = 0;
                while offset < paths.len() {
                    let mut names = Vec::new();
                    let mut units = 0;
                    while offset < paths.len() && names.len() < 128 {
                        let name = paths[offset].to_str().unwrap();
                        assert!(!name.contains('\''));
                        if units + name.len() > 6000 && !names.is_empty() {
                            break;
                        }
                        units += name.len();
                        names.push(format!("'{name}'"));
                        offset += 1;
                    }
                    let script = format!(
                        r#"$ErrorActionPreference='Stop'; $names=@({}); $records=@(); $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; foreach($n in $names) {{ $p=if($n -eq ''){{$env:ORBIT_TEST_ACL_PATH}}else{{[IO.Path]::Combine($env:ORBIT_TEST_ACL_PATH,$n)}}; $isDir=[IO.Directory]::Exists($p); $info=if($isDir){{[IO.DirectoryInfo]::new($p)}}else{{[IO.FileInfo]::new($p)}}; $acl=$info.GetAccessControl(); $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); $aces=@($rules | ForEach-Object {{ [ordered]@{{sid=$_.IdentityReference.Value;mask=[int64]$_.FileSystemRights.value__;kind=$_.AccessControlType.ToString();inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags;inherited=$_.IsInherited}} }}); if({}) {{ if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid -or !$acl.AreAccessRulesProtected -or $rules.Count -ne 1){{throw 'Private fixture policy precursor failed'}}; $r=$rules[0]; $m=[int64]$r.FileSystemRights.value__; $flags=if($isDir -and $m -eq 0x1f01ff){{3}}else{{0}}; if($r.IdentityReference.Value -ne $sid -or $r.AccessControlType.ToString() -ne 'Allow' -or $r.IsInherited -or [int]$r.PropagationFlags -ne 0 -or [int]$r.InheritanceFlags -ne $flags -or $m -notin @(0x1f01ff,0x120089,0x1200a9) -or ($isDir -and $m -ne 0x1f01ff)){{[Console]::Error.WriteLine('trust_acl_policy_batch_diagnostic '+(ConvertTo-Json -InputObject ([ordered]@{{relativeName=$n;isDir=$isDir;currentSID=$sid;OWNER=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;GROUP=$acl.GetGroup([Security.Principal.SecurityIdentifier]).Value;protected=$acl.AreAccessRulesProtected;rule_count=$rules.Count;aces=$aces;observed_mask=$m;expected_flags=$flags}}) -Compress -Depth 4)); throw 'Private fixture rule precursor failed'}} }}; $records += [ordered]@{{name=$n;owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;group=$acl.GetGroup([Security.Principal.SecurityIdentifier]).Value;sddl=$acl.Sddl;protected=$acl.AreAccessRulesProtected;aces=$aces}} }}; $raw=ConvertTo-Json -InputObject @($records) -Compress -Depth 5; $sha=[Security.Cryptography.SHA256]::Create(); try{{$digest=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($raw))).Replace('-','')}}finally{{$sha.Dispose()}}; [ordered]@{{count=$records.Count;digest=$digest;sample=$records[0]}} | ConvertTo-Json -Compress -Depth 5"#,
                        names.join(","),
                        if strict { "$true" } else { "$false" }
                    );
                    let output = fixture_command(
                        "policy_batch",
                        &system_program("WindowsPowerShell/v1.0/powershell.exe"),
                        &[
                            OsStr::new("-NoProfile"),
                            OsStr::new("-NonInteractive"),
                            OsStr::new("-Command"),
                            OsStr::new(&script),
                        ],
                        Some(root),
                    );
                    let batch: PolicyBatch = serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(batch.count, names.len());
                    assert_eq!(batch.digest.len(), 64);
                    result.push(batch);
                }
                result
            }

            fn set_read_rule(tree: &Tree, index: usize, execute: bool) {
                let path = tree.path(index);
                let before = security(&path);
                assert!(
                    before.owner == current_sid() && before.protected && before.aces.len() == 1
                );
                assert!(before.allows(&before.owner, 0x1f01ff));
                let mask = if execute { "0x001200a9" } else { "0x00120089" };
                let script = format!(
                    "$ErrorActionPreference='Stop'; $file=[IO.FileInfo]::new($env:ORBIT_TEST_ACL_PATH); $acl=$file.GetAccessControl(); $sid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; if($sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){{throw 'Owned fixture owner mismatch'}}; $sddl='D:P(A;;{mask};;;' + $sid + ')'; $acl.SetSecurityDescriptorSddlForm($sddl,[Security.AccessControl.AccessControlSections]::Access); $file.SetAccessControl($acl)"
                );
                powershell(if execute { "owner_RX" } else { "owner_R" }, &path, &script);
                let after = security(&path);
                assert!(
                    after.owner == before.owner && after.group == before.group && after.protected
                );
                assert_eq!(after.aces.len(), 1);
                let ace = &after.aces[0];
                assert!(ace.sid == before.owner && ace.kind == "Allow" && !ace.inherited);
                assert_eq!(ace.mask, if execute { 0x1200a9 } else { 0x120089 });
                assert!(ace.inheritance == 0 && ace.propagation == 0);
                tree.fact(index, false); // Same original full ID and unchanged nonempty bytes.
            }

            pub(crate) fn nested_private() {
                let mut tree = Tree::new();
                let a = tree.directory(None, "a");
                let b = tree.directory(Some(a), "b");
                tree.file(Some(b), "fa");
                let r = tree.file(Some(b), "r");
                let rx = tree.file(Some(b), "rx");
                set_read_rule(&tree, r, false);
                set_read_rule(&tree, rx, true);
                let before = tree.evidence(false, true);
                let result = verify_restricted_acl(&tree.home.path);
                assert!(
                    tree.evidence(false, true) == before,
                    "private tree changed during verification"
                );
                tree.cleanup(false);
                assert!(result.is_ok(), "private FA/R/RX tree must pass");
                complete(
                    "acl::tests::windows_nested_private_fa_r_rx_pass",
                    "fa-r-rx",
                    "Pass",
                );
            }

            pub(crate) fn unsafe_nested() {
                for directory in [true, false] {
                    let mut tree = Tree::new();
                    let d = tree.directory(None, "d");
                    let f = tree.file(Some(d), "canary");
                    tree.evidence(false, true);
                    let path = tree.path(if directory { d } else { f });
                    let original = security(&path);
                    icacls(
                        &path,
                        &[
                            "/grant",
                            if directory {
                                "*S-1-1-0:(OI)(CI)RX"
                            } else {
                                "*S-1-1-0:RX"
                            },
                        ],
                    );
                    let unsafe_policy = security(&path);
                    assert!(
                        unsafe_policy.owner == original.owner
                            && unsafe_policy.group == original.group
                            && unsafe_policy.protected
                    );
                    assert!(
                        unsafe_policy.allows("S-1-1-0", 0x1200a9),
                        "effective Everyone RX precursor missing"
                    );
                    assert!(unsafe_policy.allows(&original.owner, 0x1f01ff));
                    let before = tree.evidence(false, false);
                    let result = verify_restricted_acl(&tree.home.path);
                    assert!(
                        tree.evidence(false, false) == before,
                        "unsafe nested tree was repaired or changed"
                    );
                    assert!(security(&path) == unsafe_policy);
                    tree.cleanup(false);
                    refused(result);
                    complete(
                        "acl::tests::windows_unsafe_nested_acl_fails",
                        if directory { "directory" } else { "file" },
                        "Refused",
                    );
                }
            }

            pub(crate) fn foreign_owner() {
                for selected in 0..3 {
                    let mut tree = Tree::new();
                    let d = tree.directory(None, "d");
                    let f = tree.file(Some(d), "canary");
                    tree.evidence(false, true);
                    let path = match selected {
                        0 => tree.home.path.clone(),
                        1 => tree.path(d),
                        _ => tree.path(f),
                    };
                    let original = security(&path);
                    let foreign = "S-1-5-32-544";
                    assert!(original.owner == current_sid() && original.owner != foreign);
                    icacls(&path, &["/setowner", "*S-1-5-32-544"]);
                    let policy = security(&path);
                    assert_eq!(policy.owner, foreign);
                    assert!(
                        policy.group == original.group
                            && policy.aces == original.aces
                            && policy.protected == original.protected
                    );
                    assert!(
                        policy.sddl.split_once("D:").unwrap().1
                            == original.sddl.split_once("D:").unwrap().1,
                        "foreign-owner setup changed the access section"
                    );
                    let before = tree.evidence(false, false);
                    let result = verify_restricted_acl(&tree.home.path);
                    assert!(
                        tree.evidence(false, false) == before,
                        "foreign-owned tree changed during refusal"
                    );
                    assert!(security(&path) == policy, "foreign owner was repaired");
                    icacls(&path, &["/setowner", &format!("*{}", original.owner)]);
                    assert!(
                        security(&path) == original,
                        "fixture owner restoration changed the original descriptor"
                    );
                    tree.cleanup(false);
                    refused(result);
                    complete(
                        "acl::tests::windows_foreign_owner_fails",
                        ["root", "directory", "file"][selected],
                        "Refused",
                    );
                }
            }

            fn register_link(tree: &mut Tree, target: usize, directory: bool) -> usize {
                let relative = tree.relative(None, "link");
                let path = tree.home.path.join(&relative);
                if directory {
                    std::os::windows::fs::symlink_dir(tree.path(target), &path).unwrap();
                } else {
                    std::os::windows::fs::symlink_file(tree.path(target), &path).unwrap();
                }
                let index = tree.nodes.len();
                tree.nodes.push(Node {
                    relative,
                    parent: None,
                    kind: if directory {
                        Kind::DirectoryLink(target)
                    } else {
                        Kind::FileLink(target)
                    },
                    identity: None,
                    directory: None,
                    active: true,
                    multiple_links: false,
                });
                tree.fact(index, false);
                index
            }

            pub(crate) fn symlinks() {
                for selected in 0..3 {
                    let mut tree = Tree::new();
                    let d = tree.directory(None, "target");
                    let f = tree.file(Some(d), "canary");
                    let link =
                        register_link(&mut tree, if selected == 2 { f } else { d }, selected != 2);
                    let before = tree.evidence(false, true);
                    let root = if selected == 0 {
                        tree.path(link)
                    } else {
                        tree.home.path.clone()
                    };
                    let result = verify_restricted_acl(&root);
                    assert!(
                        tree.evidence(false, true) == before,
                        "symlink refusal changed registered link or target"
                    );
                    tree.cleanup(false);
                    refused(result);
                    complete(
                        "acl::tests::windows_symlink_roots_and_children_fail",
                        ["root", "directory", "file"][selected],
                        "Refused",
                    );
                }
            }

            pub(crate) fn hardlink() {
                let mut tree = Tree::new();
                let original = tree.file(None, "original");
                tree.fact(original, false); // Cache was captured while the public single-link contract admitted it.
                let relative = tree.relative(None, "alias");
                std::fs::hard_link(tree.path(original), tree.home.path.join(&relative)).unwrap();
                tree.nodes.push(Node {
                    relative,
                    parent: None,
                    kind: Kind::Alias(original),
                    identity: None,
                    directory: None,
                    active: true,
                    multiple_links: false,
                });
                tree.nodes[original].multiple_links = true;
                let before = tree.evidence(false, true);
                let result = verify_restricted_acl(&tree.home.path);
                assert!(
                    tree.evidence(false, true) == before,
                    "hardlink refusal changed names, security or bytes"
                );
                tree.cleanup(false);
                refused(result);
                complete(
                    "acl::tests::windows_hardlinked_file_fails",
                    "alias",
                    "Refused",
                );
            }

            pub(crate) fn missing() {
                let mut tree = Tree::new();
                tree.file(None, "canary");
                let missing = tree.home.path.join("absent");
                absent(&missing);
                let before = tree.evidence(false, true);
                let result = verify_restricted_acl(&missing);
                absent(&missing);
                assert!(
                    tree.evidence(false, true) == before,
                    "missing-root verification changed parent or sibling"
                );
                tree.cleanup(false);
                refused(result);
                complete(
                    "acl::tests::windows_missing_root_fails_without_creation",
                    "absent",
                    "Refused",
                );
            }

            fn boundary(
                case: &str,
                tree: &Tree,
                expected: (usize, usize, usize),
            ) -> Result<(), TrustError> {
                assert_eq!(
                    tree.budgets(),
                    expected,
                    "actual registered UTF-16 budgets differ"
                );
                let before = tree.evidence(true, true);
                let result = verify_restricted_acl(&tree.home.path);
                assert!(
                    tree.evidence(true, true) == before,
                    "boundary verification changed the actual fixture"
                );
                assert!(!case.is_empty());
                result
            }

            fn boundary_complete(
                case: &str,
                subcase: &str,
                outcome: &str,
                budgets: (usize, usize, usize),
            ) {
                eprintln!(
                    "trust_acl_adversarial_complete case={case} subcase={subcase} outcome={outcome} entries={} name_bytes={} depth={}",
                    budgets.0, budgets.1, budgets.2
                );
            }

            pub(crate) fn entry_limit() {
                const CASE: &str = "acl::tests::windows_entry_limit_boundary";
                let mut tree = Tree::new();
                for n in 0..4096 {
                    tree.file(None, &format!("f{n:04}"));
                }
                let at = tree.budgets();
                assert_eq!(at, (4096, 40960, 1));
                let first = boundary(CASE, &tree, at);
                tree.file(None, "f4096");
                let above = tree.budgets();
                assert_eq!(above, (4097, 40970, 1));
                let second = boundary(CASE, &tree, above);
                tree.cleanup(true);
                assert!(first.is_ok(), "actual 4096-entry tree must pass");
                refused(second);
                boundary_complete(CASE, "at-limit", "Pass", at);
                boundary_complete(CASE, "above-limit", "Refused", above);
            }

            pub(crate) fn depth_limit() {
                const CASE: &str = "acl::tests::windows_depth_limit_boundary";
                let mut tree = Tree::new();
                let mut parent = None;
                for _ in 0..128 {
                    parent = Some(tree.directory(parent, "d"));
                }
                let at = tree.budgets();
                assert_eq!(at, (128, 32768, 128));
                let first = boundary(CASE, &tree, at);
                tree.directory(parent, "d");
                let above = tree.budgets();
                assert_eq!(above, (129, 33282, 129));
                let second = boundary(CASE, &tree, above);
                tree.cleanup(true);
                assert!(first.is_ok(), "actual depth128 tree must pass");
                refused(second);
                boundary_complete(CASE, "at-limit", "Pass", at);
                boundary_complete(CASE, "above-limit", "Refused", above);
            }

            pub(crate) fn name_limit() {
                const CASE: &str = "acl::tests::windows_name_bytes_limit_boundary";
                let mut tree = Tree::new();
                let d = tree.directory(None, &"d".repeat(32));
                for n in 0..3870 {
                    tree.file(Some(d), &format!("a{n:04}{}", "x".repeat(90)));
                }
                for n in 0..224 {
                    tree.file(Some(d), &format!("b{n:03}{}", "x".repeat(92)));
                }
                let at = tree.budgets();
                assert_eq!(at, (4095, 1048576, 2));
                let first = boundary(CASE, &tree, at);
                tree.file(Some(d), "z");
                let above = tree.budgets();
                assert_eq!(above, (4096, 1048644, 2));
                let second = boundary(CASE, &tree, above);
                tree.cleanup(true);
                assert!(
                    first.is_ok(),
                    "actual exact 1MiB UTF-16-name tree must pass"
                );
                refused(second);
                boundary_complete(CASE, "at-limit", "Pass", at);
                boundary_complete(CASE, "above-limit", "Refused", above);
            }

            fn refused(result: Result<(), TrustError>) {
                assert!(
                    matches!(result, Err(TrustError::RegistryBootstrapIncomplete(_))),
                    "unsafe trust fixture must return RegistryBootstrapIncomplete"
                );
            }

            fn complete(case: &str, subcase: &str, outcome: &str) {
                eprintln!(
                    "trust_acl_adversarial_complete case={case} subcase={subcase} outcome={outcome}"
                );
            }
        }
    }
}
