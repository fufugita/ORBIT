#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

mod accounting_inspection {
    use orbit_adapter::types::ProviderUsage;
    use orbit_cli::context_history::{
        InspectionQualification, context_journal, inspect_accounting, inspect_accounting_detailed,
    };
    use orbit_cli::sessions::{SessionLease, SessionLeaseError};
    use orbit_engine::compaction::{
        AccountingBaseline, AccountingDelta, AccountingKnownness, AccountingRevision,
        AccountingTotals, AttemptIntent, AttemptPurpose, CompactionJournal, HistoryError,
        KnownPricedSubtotals, RequestAccountingReceipt,
    };
    use orbit_engine::context_budget::BudgetIdentity;
    use orbit_engine::{ProviderKind, TurnConfig};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const OWNER: &str = "inspection-owner";
    const CHILD_A: &str = "00000000000000000000000001";
    const CHILD_B: &str = "00000000000000000000000002";

    // Dispatch verifies inherited descriptors and the private /etc guard.
    fn dispatch_isolated(exact: &str) -> bool {
        let isolated = std::env::var_os("ORBIT_ACTIVATION_ISOLATED");
        let depth = std::env::var_os("ORBIT_ACTIVATION_RUNNER_DEPTH");
        if isolated.as_deref() == Some(std::ffi::OsStr::new("1")) {
            assert_eq!(
                depth.as_deref(),
                Some(std::ffi::OsStr::new("1")),
                "invalid isolated runner depth"
            );
            return true;
        }
        assert!(
            isolated.is_none() && depth.is_none(),
            "malformed isolation dispatch controls"
        );
        let required =
            std::env::var("ORBIT_REQUIRE_CONTEXT_SESSION_ISOLATION").as_deref() == Ok("1");
        let output = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/context_session_isolation.py"
            ))
            .arg("--binary")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", exact, "--timeout", "180"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("tracked isolation runner did not start");
        assert!(
            output.stdout.len() <= 512 * 1024 && output.stderr.len() <= 64 * 1024,
            "runner receipt output bound"
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!(
                "invalid isolation runner receipt, exit {:?}",
                output.status.code()
            )
        });
        assert_eq!(report["schema"], "orbit.context-session-isolation/v1");
        assert_eq!(report["test_filter"], exact);
        let visible = json!({"schema":report["schema"],"test_filter":exact,"status":report["status"],
            "test_started":report["test_started"],"reason":report["reason"],"harness":report["harness"],
            "binary_sha256":report["binary_sha256"],"binary_metadata_and_hash_unchanged":report["binary_metadata_and_hash_unchanged"],
            "host_managed_path_metadata_unchanged":report["host_managed_path_metadata_unchanged"],"owned_fixture_removed":report["owned_fixture_removed"]});
        // Direct Write bypasses libtest's println capture. A returning NOTRUN
        // wrapper must stay visible and must not count as an inner pass.
        let line = format!("ORBIT_CONTEXT_SESSION_ISOLATION {visible}\n");
        std::io::Write::write_all(&mut std::io::stdout().lock(), line.as_bytes()).unwrap();
        match report["status"].as_str() {
            Some("TEST_PASSED") => {
                assert_eq!(output.status.code(), Some(0));
                assert_eq!(report["test_started"], true);
                assert_eq!(report["harness"]["passed"], 1);
                assert_eq!(report["harness"]["failed"], 0);
                assert_eq!(report["harness"]["ignored"], 0);
                for field in [
                    "binary_metadata_and_hash_unchanged",
                    "host_managed_path_metadata_unchanged",
                    "owned_fixture_removed",
                    "binary_postcheck_inside",
                ] {
                    assert_eq!(report[field], true);
                }
            }
            Some("NOTRUN") => {
                assert_eq!(output.status.code(), Some(77));
                assert_eq!(report["test_started"], false);
                assert!(
                    !required,
                    "NOTRUN: this infrastructure-required job needs namespace capability"
                );
            }
            Some("TEST_FAILED") | Some("INFRA_FAILURE") => {
                panic!(
                    "isolated test did not pass: {} / {} / {}",
                    report["status"], report["stdout_excerpt"], report["stderr_excerpt"]
                );
            }
            _ => panic!("unknown isolation runner status"),
        }
        false
    }

    fn require_private_system_fixture() {
        // Check descriptors/namespace identity BEFORE opening managed content,
        // creating a fixture, spawning a provider or starting any caller.
        let descriptor = |name: &str| {
            let value: u32 = std::env::var(name)
                .expect("isolated runner descriptor missing")
                .parse()
                .unwrap();
            assert!(value < 4096);
            fs::metadata(format!("/proc/self/fd/{value}")).unwrap()
        };
        let parent_mount = descriptor("ORBIT_ACTIVATION_PARENT_MOUNT_FD");
        let parent_user = descriptor("ORBIT_ACTIVATION_PARENT_USER_FD");
        let own_mount = fs::metadata("/proc/self/ns/mnt").unwrap();
        let own_user = fs::metadata("/proc/self/ns/user").unwrap();
        assert_ne!(
            (parent_mount.dev(), parent_mount.ino()),
            (own_mount.dev(), own_mount.ino())
        );
        assert_ne!(
            (parent_user.dev(), parent_user.ino()),
            (own_user.dev(), own_user.ino())
        );
        let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
        assert!(mounts.lines().any(
            |line| line.split_whitespace().nth(4) == Some("/etc") && line.contains(" - tmpfs ")
        ));
        let expected = std::env::var("ORBIT_ACTIVATION_MANAGED_MARKER").unwrap();
        assert!(expected.starts_with("ORBIT_ACTIVATION_MANAGED_") && expected.len() <= 128);
        assert!(
            expected
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        let path = Path::new("/etc/orbit/ORBIT.md");
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(metadata.len() <= 128);
        assert_eq!(fs::read(path).unwrap(), expected.as_bytes());
        assert_eq!(fs::read_dir("/etc/orbit").unwrap().count(), 1);
        let root =
            PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").expect("private root missing"));
        assert!(root.is_absolute());
        assert_eq!(root.canonicalize().unwrap(), root);
        assert!(
            root.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("oc-")
        );
        assert_eq!(fs::symlink_metadata(&root).unwrap().mode() & 0o777, 0o700);
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
        ] {
            let path = PathBuf::from(std::env::var_os(name).expect("private user path missing"));
            assert!(path.is_absolute() && path.starts_with(&root) && path != root);
            assert_eq!(path.canonicalize().unwrap(), path);
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        assert!(std::env::current_dir().unwrap().starts_with(&root));
        for name in [
            "ORBIT_HOME",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_BASE_URL",
            "OPENAI_BASE_URL",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert!(
                std::env::var_os(name).is_none(),
                "runner did not clear an inherited provider setting"
            );
        }
    }

    macro_rules! isolated {
        ($name:ident) => {
            if !dispatch_isolated(concat!("accounting_inspection::", stringify!($name))) {
                return;
            }
            require_private_system_fixture();
        };
    }

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            require_private_system_fixture();
            let root = std::env::temp_dir().join(format!("inspection-{}", ulid::Ulid::new()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let home = root.join("home");
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
            Self { root, home }
        }
        fn lease(&self, owner: &str) -> SessionLease {
            SessionLease::acquire(&self.home, owner, "inspection-fixture").unwrap()
        }
        fn owner(&self, owner: &str) -> PathBuf {
            self.home.join("context-history").join(owner)
        }
        fn accounting(&self, owner: &str) -> PathBuf {
            self.owner(owner).join("accounting.json")
        }
        fn lock(&self, owner: &str) -> PathBuf {
            self.owner(owner).join(".history.lock")
        }
        fn journal(&self, owner: &str, child: Option<&str>) -> Arc<dyn CompactionJournal> {
            context_journal(&self.home, owner, child).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    }
    fn bounded_file(path: &Path) -> Vec<u8> {
        let before = fs::symlink_metadata(path).unwrap();
        assert!(before.is_file() && before.len() <= 256 * 1024);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .unwrap();
        assert_eq!(
            (
                file.metadata().unwrap().dev(),
                file.metadata().unwrap().ino()
            ),
            (before.dev(), before.ino())
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len() as u64, before.len());
        assert_eq!(
            (
                fs::symlink_metadata(path).unwrap().dev(),
                fs::symlink_metadata(path).unwrap().ino()
            ),
            (before.dev(), before.ino())
        );
        bytes
    }
    #[derive(Debug, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        size: u64,
        modified: (i64, i64),
        changed: (i64, i64),
        digest: Vec<u8>,
    }
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Stamp> {
        let mut found = BTreeMap::new();
        let mut pending = vec![root.to_owned()];
        let mut bytes = 0usize;
        while let Some(path) = pending.pop() {
            assert!(found.len() < 96);
            let metadata = fs::symlink_metadata(&path).unwrap();
            let content = if metadata.is_file() {
                let data = bounded_file(&path);
                bytes = bytes.checked_add(data.len()).unwrap();
                assert!(bytes <= 2 * 1024 * 1024);
                data
            } else if metadata.file_type().is_symlink() {
                fs::read_link(&path)
                    .unwrap()
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else if metadata.is_dir() {
                for entry in fs::read_dir(&path).unwrap() {
                    pending.push(entry.unwrap().path());
                }
                Vec::new()
            } else {
                Vec::new()
            };
            found.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                Stamp {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    mode: metadata.mode(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    links: metadata.nlink(),
                    size: metadata.len(),
                    modified: (metadata.mtime(), metadata.mtime_nsec()),
                    changed: (metadata.ctime(), metadata.ctime_nsec()),
                    digest: Sha256::digest(content).to_vec(),
                },
            );
        }
        // Access times are excluded because the test's own full byte snapshots
        // read each regular file. Identity, content and mutation times stay exact.
        found
    }
    fn read_only(
        f: &Fixture,
        owner: &str,
        child: Option<&str>,
    ) -> Result<orbit_cli::context_history::AccountingInspection, HistoryError> {
        let before = snapshot(&f.root);
        let result = inspect_accounting(&f.home, owner, child);
        assert_eq!(snapshot(&f.root), before);
        result
    }
    fn intent(
        owner: &str,
        child: Option<&str>,
        request: &str,
        purpose: AttemptPurpose,
    ) -> AttemptIntent {
        let config = TurnConfig {
            provider_id: "metadata-only".into(),
            gate: "http://127.0.0.1:9".into(),
            model: "synthetic".into(),
            kind: ProviderKind::OpenAiCompatible,
            credential_env: None,
            pricing: None,
            max_output_tokens: 32,
            sampling: None,
            effort: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        };
        AttemptIntent {
            owner_session_id: owner.into(),
            child_id: child.map(str::to_owned),
            request_id: request.into(),
            purpose,
            budget: BudgetIdentity::for_config(&config, "inspection-metadata", "inspection-policy")
                .unwrap(),
        }
    }
    fn usage() -> ProviderUsage {
        ProviderUsage {
            input_tokens: 19,
            output_tokens: 5,
            cache_read_tokens: 3,
            cache_write_tokens: 2,
            reasoning_tokens: 4,
        }
    }
    fn known(request: &str, purpose: AttemptPurpose) -> RequestAccountingReceipt {
        RequestAccountingReceipt {
            request_id: request.into(),
            purpose,
            totals: AccountingTotals {
                input_tokens: 19,
                output_tokens: 5,
                cost_microcents: Some(7),
            },
            usage: Some(usage()),
            knownness: AccountingKnownness::Known,
            completed: true,
        }
    }
    fn digest(value: &str) {
        assert!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
    #[allow(unsafe_code)]
    fn flock(file: &File, mode: i32) -> std::io::Result<()> {
        // SAFETY: the caller owns this live descriptor; flock retains no pointer.
        if unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    struct AccessWatch(File);
    impl AccessWatch {
        #[allow(unsafe_code)]
        fn new(paths: &[&Path]) -> Self {
            // SAFETY: flags are valid; successful fresh FD ownership transfers
            // exactly once to File. Watch paths are terminated private paths.
            let descriptor = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            assert!(descriptor >= 0);
            let file = unsafe { File::from_raw_fd(descriptor) };
            for path in paths {
                let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                assert!(
                    unsafe {
                        libc::inotify_add_watch(
                            file.as_raw_fd(),
                            path.as_ptr(),
                            libc::IN_ACCESS | libc::IN_OPEN,
                        )
                    } >= 0
                );
            }
            Self(file)
        }
        fn drain(&mut self) -> usize {
            let mut total = 0;
            let mut buffer = [0u8; 4096];
            loop {
                match self.0.read(&mut buffer) {
                    Ok(0) => return total,
                    Ok(count) => {
                        total += count;
                        assert!(total <= 16 * 1024);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return total,
                    Err(error) => panic!("owned access-watch read failed: {error}"),
                }
            }
        }
    }

    #[test]
    fn fresh_zero_and_legacy_unknown_are_visible_validated_without_any_mutation() {
        isolated!(fresh_zero_and_legacy_unknown_are_visible_validated_without_any_mutation);
        let f = Fixture::new();
        let _fresh_lease = f.lease(OWNER);
        let _legacy_lease = f.lease("legacy-owner");
        let fresh = f
            .journal(OWNER, None)
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let legacy = f
            .journal("legacy-owner", None)
            .initialize_accounting(AccountingBaseline::UnknownLegacy)
            .unwrap();
        for (owner, expected) in [(OWNER, fresh), ("legacy-owner", legacy)] {
            let view = read_only(&f, owner, None).unwrap();
            assert_eq!(view.checkpoint, expected);
            assert_eq!(
                view.qualification,
                InspectionQualification::VisibleValidated
            );
            assert!(view.pending_receipt.is_none() && view.last_receipt.is_none());
            digest(&view.inspection_digest);
            assert_eq!(read_only(&f, owner, None).unwrap(), view);
        }
        assert_eq!(
            read_only(&f, OWNER, None).unwrap().checkpoint.totals,
            AccountingDelta::known_zero()
        );
        assert_eq!(
            read_only(&f, "legacy-owner", None)
                .unwrap()
                .checkpoint
                .totals,
            AccountingDelta::unknown_legacy()
        );
    }

    #[test]
    fn prior_final_and_pending_provisional_five_counters_remain_separate() {
        isolated!(prior_final_and_pending_provisional_five_counters_remain_separate);
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        let journal = f.journal(OWNER, None);
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let paid = journal
            .begin_attempt(
                AccountingRevision(0),
                &intent(OWNER, None, "paid", AttemptPurpose::Chunk),
            )
            .unwrap();
        let final_receipt = known("paid", AttemptPurpose::Chunk);
        journal.settle_attempt(&paid, &final_receipt).unwrap();
        let settled = read_only(&f, OWNER, None).unwrap();
        assert_eq!(settled.checkpoint.revision, AccountingRevision(2));
        assert_eq!(settled.last_receipt, Some(final_receipt.clone()));
        assert!(settled.pending_receipt.is_none());
        assert_eq!(settled.checkpoint.totals.housekeeping, final_receipt.totals);
        let request = intent(OWNER, None, "pending", AttemptPurpose::Ordinary);
        let reference = journal
            .begin_attempt(AccountingRevision(2), &request)
            .unwrap();
        let begun = read_only(&f, OWNER, None).unwrap();
        assert_eq!(begun.checkpoint.revision, AccountingRevision(3));
        assert_eq!(
            begun.checkpoint.pending.as_ref().unwrap().reference,
            reference
        );
        assert_eq!(begun.checkpoint.pending.as_ref().unwrap().intent, request);
        assert!(!begun.checkpoint.pending.as_ref().unwrap().uncertain);
        assert!(begun.pending_receipt.is_none());
        assert_eq!(begun.last_receipt, Some(final_receipt.clone()));
        let provisional = RequestAccountingReceipt {
            request_id: "pending".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: Some(usage()),
            knownness: AccountingKnownness::Uncertain,
            completed: false,
        };
        let checkpoint = journal.settle_attempt(&reference, &provisional).unwrap();
        drop(journal);
        let view = read_only(&f, OWNER, None).unwrap();
        assert_eq!(view.checkpoint, checkpoint);
        assert_eq!(view.checkpoint.revision, AccountingRevision(4));
        assert_eq!(view.pending_receipt, Some(provisional));
        assert_eq!(view.last_receipt, Some(final_receipt));
        assert!(view.checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(
            view.checkpoint.totals.knownness,
            AccountingKnownness::Uncertain
        );
        assert_eq!(view.checkpoint.totals.ordinary.input_tokens, 0);
        assert_eq!(view.checkpoint.totals.ordinary.output_tokens, 0);
        assert_eq!(view.checkpoint.totals.housekeeping.input_tokens, 19);
        assert_eq!(view.checkpoint.totals.housekeeping.output_tokens, 5);
        assert_eq!(
            view.checkpoint.known_priced_subtotals,
            Some(KnownPricedSubtotals {
                ordinary_microcents: 0,
                housekeeping_microcents: 7
            })
        );
        assert_ne!(settled.inspection_digest, begun.inspection_digest);
        assert_ne!(begun.inspection_digest, view.inspection_digest);
    }

    #[test]
    fn missing_usage_and_proven_not_sent_receipts_do_not_turn_into_uncertain_usage() {
        isolated!(missing_usage_and_proven_not_sent_receipts_do_not_turn_into_uncertain_usage);
        for absent_usage in [false, true] {
            let f = Fixture::new();
            let _lease = f.lease(OWNER);
            let journal = f.journal(OWNER, None);
            journal
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap();
            let reference = journal
                .begin_attempt(
                    AccountingRevision(0),
                    &intent(OWNER, None, "one", AttemptPurpose::Ordinary),
                )
                .unwrap();
            let receipt = RequestAccountingReceipt {
                request_id: "one".into(),
                purpose: AttemptPurpose::Ordinary,
                totals: if absent_usage {
                    AccountingTotals {
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microcents: None,
                    }
                } else {
                    AccountingTotals::known_zero()
                },
                usage: None,
                knownness: if absent_usage {
                    AccountingKnownness::UnknownUsage
                } else {
                    AccountingKnownness::Known
                },
                completed: absent_usage,
            };
            let expected = journal.settle_attempt(&reference, &receipt).unwrap();
            let view = read_only(&f, OWNER, None).unwrap();
            assert_eq!(view.checkpoint, expected);
            assert_eq!(view.last_receipt, Some(receipt));
            assert!(view.checkpoint.pending.is_none() && view.pending_receipt.is_none());
            assert_eq!(
                view.checkpoint.totals.knownness,
                if absent_usage {
                    AccountingKnownness::UnknownUsage
                } else {
                    AccountingKnownness::Known
                }
            );
        }
    }

    #[test]
    fn digest_is_stable_and_binds_owner_child_scope_and_container_revision() {
        isolated!(digest_is_stable_and_binds_owner_child_scope_and_container_revision);
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        let _other = f.lease("other-owner");
        let owner = f.journal(OWNER, None);
        owner
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        // Metadata-only child setup does not claim AgentRun lifecycle ownership.
        let child_a = f.journal(OWNER, Some(CHILD_A));
        child_a
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        f.journal(OWNER, Some(CHILD_B))
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        f.journal("other-owner", None)
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let root = read_only(&f, OWNER, None).unwrap();
        let a = read_only(&f, OWNER, Some(CHILD_A)).unwrap();
        let b = read_only(&f, OWNER, Some(CHILD_B)).unwrap();
        assert_eq!(a.checkpoint.child_id.as_deref(), Some(CHILD_A));
        assert_eq!(b.checkpoint.child_id.as_deref(), Some(CHILD_B));
        assert_ne!(root.inspection_digest, a.inspection_digest);
        assert_ne!(a.inspection_digest, b.inspection_digest);
        assert_ne!(
            root.inspection_digest,
            read_only(&f, "other-owner", None)
                .unwrap()
                .inspection_digest
        );
        assert_eq!(read_only(&f, OWNER, Some(CHILD_A)).unwrap(), a);
        let reference = child_a
            .begin_attempt(
                AccountingRevision(0),
                &intent(OWNER, Some(CHILD_A), "child-paid", AttemptPurpose::Ordinary),
            )
            .unwrap();
        let receipt = known("child-paid", AttemptPurpose::Ordinary);
        child_a.settle_attempt(&reference, &receipt).unwrap();
        let after = read_only(&f, OWNER, Some(CHILD_A)).unwrap();
        assert_eq!(after.checkpoint.revision, AccountingRevision(2));
        assert_ne!(after.inspection_digest, a.inspection_digest);
        // The opaque token binds the complete canonical container, including siblings.
        let root_after = read_only(&f, OWNER, None).unwrap();
        assert_eq!(root_after.checkpoint, root.checkpoint);
        assert_ne!(root_after.inspection_digest, root.inspection_digest);
        child_a.settle_attempt(&reference, &receipt).unwrap();
        assert_eq!(read_only(&f, OWNER, Some(CHILD_A)).unwrap(), after);
        assert_eq!(
            read_only(&f, OWNER, Some("00000000000000000000000003")),
            Err(HistoryError::Missing)
        );
    }

    #[test]
    fn absent_homes_layout_entries_and_untracked_namespaces_are_never_created() {
        isolated!(absent_homes_layout_entries_and_untracked_namespaces_are_never_created);
        let f = Fixture::new();
        let missing = f.root.join("absent").join("home");
        let before = snapshot(&f.root);
        assert_eq!(
            inspect_accounting(&missing, OWNER, None),
            Err(HistoryError::Missing)
        );
        assert!(!missing.exists());
        assert_eq!(snapshot(&f.root), before);
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::Missing));
        let _lease = f.lease(OWNER);
        drop(f.journal(OWNER, None));
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::Missing));
        assert!(!f.accounting(OWNER).exists());
        fs::remove_file(f.lock(OWNER)).unwrap();
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::Missing));
        assert!(!f.lock(OWNER).exists());
        assert_eq!(
            read_only(&f, OWNER, Some(CHILD_A)),
            Err(HistoryError::Missing)
        );
    }

    #[test]
    fn unsafe_and_dangling_scope_paths_are_refused_without_following_or_repair() {
        isolated!(unsafe_and_dangling_scope_paths_are_refused_without_following_or_repair);
        let f = Fixture::new();
        let before = snapshot(&f.root);
        for owner in ["../escape", "", "a/b", "owner.json", "."] {
            assert_eq!(read_only(&f, owner, None), Err(HistoryError::InvalidRecord));
        }
        assert_eq!(
            read_only(&f, OWNER, Some("not-a-canonical-child")),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(snapshot(&f.root), before);
        let absent = f.root.join("not-there");
        let linked = f.root.join("dangling-home");
        symlink(&absent, &linked).unwrap();
        let before = snapshot(&f.root);
        assert_eq!(
            inspect_accounting(&linked.join("nested"), OWNER, None),
            Err(HistoryError::Unsafe)
        );
        assert_eq!(snapshot(&f.root), before);
        assert!(!absent.exists());
        symlink(&absent, f.home.join("context-history")).unwrap();
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::Unsafe));
        assert!(!absent.exists());
    }

    #[test]
    fn missing_or_dangling_lock_with_present_data_is_unsafe_and_never_manufactured() {
        isolated!(missing_or_dangling_lock_with_present_data_is_unsafe_and_never_manufactured);
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        f.journal(OWNER, None)
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        fs::remove_file(f.lock(OWNER)).unwrap();
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::Unsafe));
        assert!(!f.lock(OWNER).exists());
        let absent = f.root.join("missing-lock-target");
        symlink(&absent, f.lock(OWNER)).unwrap();
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::Unsafe));
        assert!(!absent.exists());
        assert!(
            fs::symlink_metadata(f.lock(OWNER))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn shared_reader_uses_existing_writer_inode_and_short_writer_returns_busy() {
        isolated!(shared_reader_uses_existing_writer_inode_and_short_writer_returns_busy);
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        f.journal(OWNER, None)
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let before = snapshot(&f.root);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(f.lock(OWNER))
            .unwrap();
        flock(&file, libc::LOCK_SH).unwrap();
        let shared = read_only(&f, OWNER, None).unwrap();
        assert!(matches!(
            context_journal(&f.home, OWNER, None),
            Err(HistoryError::Busy)
        ));
        flock(&file, libc::LOCK_UN).unwrap();
        flock(&file, libc::LOCK_EX).unwrap();
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::Busy));
        flock(&file, libc::LOCK_UN).unwrap();
        assert_eq!(read_only(&f, OWNER, None).unwrap(), shared);
        assert_eq!(snapshot(&f.root), before);
    }

    #[test]
    fn existing_links_and_public_modes_are_refused_without_repair() {
        isolated!(existing_links_and_public_modes_are_refused_without_repair);
        for kind in [
            "accounting-link",
            "accounting-hardlink",
            "accounting-public",
            "lock-public",
            "owner-public",
        ] {
            let f = Fixture::new();
            let _lease = f.lease(OWNER);
            f.journal(OWNER, None)
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap();
            match kind {
                "accounting-link" => {
                    let absent = f.root.join("absent-accounting");
                    fs::remove_file(f.accounting(OWNER)).unwrap();
                    symlink(absent, f.accounting(OWNER)).unwrap();
                }
                "accounting-hardlink" => {
                    fs::hard_link(f.accounting(OWNER), f.root.join("retained-accounting-link"))
                        .unwrap();
                }
                "accounting-public" => {
                    fs::set_permissions(f.accounting(OWNER), fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                "lock-public" => {
                    fs::set_permissions(f.lock(OWNER), fs::Permissions::from_mode(0o644)).unwrap();
                }
                "owner-public" => {
                    fs::set_permissions(f.owner(OWNER), fs::Permissions::from_mode(0o755)).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                read_only(&f, OWNER, None),
                Err(HistoryError::Unsafe),
                "{kind}"
            );
        }
    }

    #[test]
    fn a_real_busy_session_lease_does_not_block_inert_pending_inspection() {
        isolated!(a_real_busy_session_lease_does_not_block_inert_pending_inspection);
        let f = Fixture::new();
        let lease = f.lease(OWNER);
        let journal = f.journal(OWNER, None);
        journal
            .initialize_accounting(AccountingBaseline::UnknownLegacy)
            .unwrap();
        journal
            .begin_attempt(
                AccountingRevision(0),
                &intent(OWNER, None, "begun", AttemptPurpose::Ordinary),
            )
            .unwrap();
        assert!(
            matches!(SessionLease::acquire(&f.home, OWNER, "competing"), Err(SessionLeaseError::Busy { session_id }) if session_id == OWNER)
        );
        let view = read_only(&f, OWNER, None).unwrap();
        assert_eq!(view.checkpoint.baseline, AccountingBaseline::UnknownLegacy);
        assert_eq!(view.checkpoint.revision, AccountingRevision(1));
        assert_eq!(
            view.checkpoint
                .pending
                .as_ref()
                .unwrap()
                .reference
                .request_id,
            "begun"
        );
        assert!(view.pending_receipt.is_none());
        assert!(matches!(
            SessionLease::acquire(&f.home, OWNER, "still-competing"),
            Err(SessionLeaseError::Busy { .. })
        ));
        drop(lease);
        assert!(SessionLease::acquire(&f.home, OWNER, "released").is_ok());
    }

    #[test]
    fn canonical_corruption_and_oversize_are_refused_without_rewrite_or_zero_fallback() {
        isolated!(canonical_corruption_and_oversize_are_refused_without_rewrite_or_zero_fallback);
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        f.journal(OWNER, None)
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let canonical = bounded_file(&f.accounting(OWNER));
        let mut altered = canonical.clone();
        altered.push(b'\n');
        fs::write(f.accounting(OWNER), &altered).unwrap();
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::InvalidRecord));
        fs::write(f.accounting(OWNER), b"{malformed").unwrap();
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::InvalidRecord));
        fs::write(f.accounting(OWNER), canonical).unwrap();
        File::options()
            .write(true)
            .open(f.accounting(OWNER))
            .unwrap()
            .set_len(128 * 1024 + 1)
            .unwrap();
        assert_eq!(read_only(&f, OWNER, None), Err(HistoryError::TooLarge));
    }

    #[test]
    fn stage_and_unexpected_owner_entries_refuse_without_touching_private_bytes() {
        isolated!(stage_and_unexpected_owner_entries_refuse_without_touching_private_bytes);
        for (name, expected) in [
            (".stage-synthetic", HistoryError::Uncertain),
            ("unexpected", HistoryError::Unsafe),
        ] {
            let f = Fixture::new();
            let _lease = f.lease(OWNER);
            f.journal(OWNER, None)
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap();
            private_file(&f.owner(OWNER).join(name), b"PRIVATE_INERT_STAGING_BODY");
            assert_eq!(read_only(&f, OWNER, None), Err(expected));
        }
    }

    #[test]
    fn inspection_never_opens_archive_config_or_saved_snapshot_bodies() {
        isolated!(inspection_never_opens_archive_config_or_saved_snapshot_bodies);
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        let expected = f
            .journal(OWNER, None)
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let archive = f
            .owner(OWNER)
            .join("archives")
            .join(format!("compact-{CHILD_A}.json"));
        let config = f.home.join("providers.toml");
        let saved = f.home.join("sessions").join(format!("{OWNER}.json"));
        for path in [&archive, &config, &saved] {
            private_file(path, b"PRIVATE_INVALID_BODY_MUST_NOT_BE_READ");
        }
        let before = snapshot(&f.root);
        let mut watch = AccessWatch::new(&[&archive, &config, &saved]);
        for path in [&archive, &config, &saved] {
            assert!(!bounded_file(path).is_empty());
        }
        assert!(
            watch.drain() > 0,
            "actual file reads must produce access-watch events"
        );
        let view = inspect_accounting(&f.home, OWNER, None).unwrap();
        assert_eq!(view.checkpoint, expected);
        assert_eq!(
            watch.drain(),
            0,
            "inspection opened or read an unrelated private body"
        );
        drop(watch);
        assert_eq!(snapshot(&f.root), before);
        // Positive distinction: the ordinary full journal does validate archives.
        assert!(context_journal(&f.home, OWNER, None).is_err());
    }
    #[test]
    fn detailed_public_companion_retains_legacy_receipt_scope_digest_and_readonly_behavior() {
        isolated!(
            detailed_public_companion_retains_legacy_receipt_scope_digest_and_readonly_behavior
        );
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        let journal = f.journal(OWNER, None);
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let reference = journal
            .begin_attempt(
                AccountingRevision(0),
                &intent(OWNER, None, "paid", AttemptPurpose::Ordinary),
            )
            .unwrap();
        let receipt = known("paid", AttemptPurpose::Ordinary);
        journal.settle_attempt(&reference, &receipt).unwrap();
        let before = snapshot(&f.root);
        let legacy = read_only(&f, OWNER, None).unwrap();
        let detailed = inspect_accounting_detailed(&f.home, OWNER, None).unwrap();
        assert!(detailed.checkpoint.legacy_equivalent(&legacy.checkpoint));
        assert_eq!(detailed.last_legacy_receipt, Some(receipt));
        assert_eq!(detailed.pending_receipt, legacy.pending_receipt);
        assert_eq!(detailed.inspection_digest, legacy.inspection_digest);
        assert_eq!(
            detailed.qualification,
            InspectionQualification::VisibleValidated
        );
        assert_eq!(
            inspect_accounting_detailed(&f.home, OWNER, Some(CHILD_A)),
            Err(HistoryError::Missing)
        );
        assert_eq!(snapshot(&f.root), before);
        // The detailed reader uses the same existing short lock and unsafe-path
        // checks, without creating an alternate inspection lock or store.
        let lock = File::open(
            f.home
                .join("context-history")
                .join(OWNER)
                .join(".history.lock"),
        )
        .unwrap();
        flock(&lock, libc::LOCK_EX).unwrap();
        assert_eq!(
            inspect_accounting_detailed(&f.home, OWNER, None),
            Err(HistoryError::Busy)
        );
        drop(lock);
        assert_eq!(snapshot(&f.root), before);
        assert_eq!(
            inspect_accounting_detailed(&f.home, OWNER, None).unwrap(),
            detailed
        );
    }

    #[test]
    fn detailed_none_writers_keep_root_child_receipts_and_inspection_strictly_separate() {
        isolated!(detailed_none_writers_keep_root_child_receipts_and_inspection_strictly_separate);
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        let root = f.journal(OWNER, None);
        let child = f.journal(OWNER, Some(CHILD_A));
        root.initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        child
            .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let root_reference = root
            .begin_attempt_detailed(
                AccountingRevision(0),
                &intent(OWNER, None, "root-final", AttemptPurpose::Ordinary),
                None,
            )
            .unwrap();
        let receipt = known("root-final", AttemptPurpose::Ordinary);
        let root_settled = root
            .settle_attempt_detailed(&root_reference, &receipt)
            .unwrap();
        let root_digest_before_child = inspect_accounting_detailed(&f.home, OWNER, None)
            .unwrap()
            .inspection_digest;
        let child_reference = child
            .begin_attempt_detailed(
                AccountingRevision(0),
                &intent(OWNER, Some(CHILD_A), "child-pending", AttemptPurpose::Chunk),
                None,
            )
            .unwrap();
        let uncertain = RequestAccountingReceipt {
            request_id: "child-pending".into(),
            purpose: AttemptPurpose::Chunk,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: Some(usage()),
            knownness: AccountingKnownness::Uncertain,
            completed: false,
        };
        let child_pending = child
            .settle_attempt_detailed(&child_reference, &uncertain)
            .unwrap();
        let before = snapshot(&f.root);
        let root_view = inspect_accounting_detailed(&f.home, OWNER, None).unwrap();
        let child_view = inspect_accounting_detailed(&f.home, OWNER, Some(CHILD_A)).unwrap();
        assert_eq!(root_view.checkpoint, root_settled);
        assert_eq!(root_view.last_legacy_receipt, Some(receipt));
        assert!(root_view.pending_receipt.is_none());
        assert_eq!(child_view.checkpoint, child_pending);
        assert_eq!(child_view.pending_receipt, Some(uncertain));
        assert!(child_view.last_legacy_receipt.is_none());
        assert_eq!(
            child_view.checkpoint.totals().ordinary,
            AccountingTotals::known_zero()
        );
        assert_eq!(
            child_view.checkpoint.known_priced_subtotals(),
            Some(KnownPricedSubtotals::known_zero())
        );
        assert_eq!(child_view.checkpoint.child_id(), Some(CHILD_A));
        assert_eq!(root_view.checkpoint.child_id(), None);
        assert_ne!(root_view.inspection_digest, child_view.inspection_digest);
        assert_ne!(root_view.inspection_digest, root_digest_before_child);
        assert!(
            root_view
                .checkpoint
                .legacy_equivalent(&inspect_accounting(&f.home, OWNER, None).unwrap().checkpoint)
        );
        assert!(
            child_view.checkpoint.legacy_equivalent(
                &inspect_accounting(&f.home, OWNER, Some(CHILD_A))
                    .unwrap()
                    .checkpoint
            )
        );
        assert_eq!(
            inspect_accounting_detailed(&f.home, OWNER, Some(CHILD_B)),
            Err(HistoryError::Missing)
        );
        assert_eq!(snapshot(&f.root), before);
    }

    #[test]
    fn retained_refusal_detailed_inspection_is_inert_and_does_not_qualify_a_sibling() {
        isolated!(retained_refusal_detailed_inspection_is_inert_and_does_not_qualify_a_sibling);
        use orbit_engine::compaction::AttemptRef;
        use orbit_engine::retry::{
            DetailedLastSettlement, OrdinaryAttemptBindingRecord, RefusalRecord, RefusalRollup,
        };
        fn scalar(value: impl serde::Serialize) -> String {
            serde_json::to_string(&value).unwrap()
        }
        fn object(fields: &[(&str, String)]) -> String {
            format!(
                "{{{}}}",
                fields
                    .iter()
                    .map(|(key, value)| format!("{}:{value}", scalar(key)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        let f = Fixture::new();
        let _lease = f.lease(OWNER);
        let root = f.journal(OWNER, None);
        root.initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let refused_intent = intent(OWNER, None, "snapshot-refusal", AttemptPurpose::Ordinary);
        let attempt = AttemptRef {
            revision: AccountingRevision(1),
            request_id: refused_intent.request_id.clone(),
            intent_digest: refused_intent.digest().unwrap(),
        };
        let binding = OrdinaryAttemptBindingRecord::new(
            refused_intent.request_id.clone(),
            "decision".into(),
            "attempt".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
        )
        .unwrap();
        let refused =
            RefusalRecord::new(refused_intent, attempt, binding, "9".repeat(64), 503, 0).unwrap();
        let rollup = RefusalRollup::first(refused.clone()).unwrap();
        // Encode only the established private snapshot schema. The checked U2
        // record constructors supply all digests; this is not a live issuer.
        let intent = refused.intent();
        let binding = refused.binding();
        let budget = object(&[
            ("binding_digest", scalar(&intent.budget.binding_digest)),
            (
                "metadata_revision",
                scalar(&intent.budget.metadata_revision),
            ),
            ("policy_revision", scalar(&intent.budget.policy_revision)),
        ]);
        let intent = object(&[
            ("owner_session_id", scalar(&intent.owner_session_id)),
            ("child_id", scalar(&intent.child_id)),
            ("request_id", scalar(&intent.request_id)),
            ("purpose", scalar("ordinary")),
            ("budget", budget),
        ]);
        let reference = object(&[
            ("revision", scalar(refused.attempt().revision.0)),
            ("request_id", scalar(&refused.attempt().request_id)),
            ("intent_digest", scalar(&refused.attempt().intent_digest)),
        ]);
        let binding = object(&[
            ("request_id", scalar(binding.request_id())),
            ("decision_id", scalar(binding.decision_id())),
            ("attempt_id", scalar(binding.attempt_id())),
            ("provider_digest", scalar(binding.provider_digest())),
            ("model_digest", scalar(binding.model_digest())),
            ("route_digest", scalar(binding.route_digest())),
            ("body_digest", scalar(binding.body_digest())),
            (
                "adapter_identity_sha256",
                scalar(binding.adapter_identity_sha256()),
            ),
            ("policy_digest", scalar(binding.policy_digest())),
            ("digest", scalar(binding.digest())),
        ]);
        let record = object(&[
            ("intent", intent),
            ("attempt", reference.clone()),
            ("binding", binding),
            ("observation_digest", scalar(refused.observation_digest())),
            ("status", scalar(refused.status())),
            ("response_body_bytes", scalar(refused.response_body_bytes())),
            ("digest", scalar(refused.digest())),
        ]);
        let last = object(&[("reference", reference), ("refused", record.clone())]);
        let retained = object(&[
            ("count", scalar(rollup.count())),
            ("chain_digest", scalar(rollup.chain_digest())),
            (
                "previous_chain_digest",
                scalar(rollup.previous_chain_digest()),
            ),
            ("latest", record),
        ]);
        let mut raw = String::from_utf8(bounded_file(&f.accounting(OWNER))).unwrap();
        assert_eq!(raw.matches("\"revision\":0").count(), 1);
        raw = raw
            .replacen("\"revision\":0", "\"revision\":2", 1)
            .replacen("\"cost_microcents\":0", "\"cost_microcents\":null", 1)
            .replacen(
                "\"knownness\":\"known\"",
                "\"knownness\":\"unknown_usage\"",
                1,
            )
            .replacen("\"last\":null", &format!("\"last\":{last}"), 1);
        let end = raw.rfind("}]}").unwrap();
        raw.insert_str(end, &format!(",\"refusals\":{retained}"));
        assert!(raw.len() < 128 * 1024);
        fs::write(f.accounting(OWNER), raw.as_bytes()).unwrap();
        let child = f.journal(OWNER, Some(CHILD_A));
        let child_zero = child
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let before = snapshot(&f.root);
        let root_view = inspect_accounting_detailed(&f.home, OWNER, None).unwrap();
        assert_eq!(
            root_view.qualification,
            InspectionQualification::VisibleValidated
        );
        assert_eq!(root_view.checkpoint.refusals(), Some(&rollup));
        assert!(
            matches!(root_view.checkpoint.last_settlement(), Some(DetailedLastSettlement::FinalRefusal(record)) if record == &refused)
        );
        assert!(root_view.pending_receipt.is_none() && root_view.last_legacy_receipt.is_none());
        assert_eq!(root_view.checkpoint.totals().ordinary.cost_microcents, None);
        assert_eq!(
            root_view.checkpoint.totals().knownness,
            AccountingKnownness::UnknownUsage
        );
        assert_eq!(
            inspect_accounting(&f.home, OWNER, None),
            Err(HistoryError::InvalidRecord)
        );
        let child_view = inspect_accounting_detailed(&f.home, OWNER, Some(CHILD_A)).unwrap();
        assert!(child_view.checkpoint.legacy_equivalent(&child_zero));
        assert!(child_view.checkpoint.refusals().is_none());
        assert_eq!(
            inspect_accounting(&f.home, OWNER, Some(CHILD_A))
                .unwrap()
                .checkpoint,
            child_zero
        );
        assert_ne!(root_view.inspection_digest, child_view.inspection_digest);
        assert_eq!(
            inspect_accounting_detailed(&f.home, OWNER, None).unwrap(),
            root_view
        );
        assert_eq!(snapshot(&f.root), before);
    }
}
