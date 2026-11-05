use orbit_platform::fs::validate_component;
use std::ffi::OsStr;

#[test]
fn ambiguous_components_are_rejected() {
    for name in [
        "", ".", "..", "a/b", "a\\b", "a:b", "name.", "name ", "CON", "nul.txt",
    ] {
        assert!(
            validate_component(OsStr::new(name)).is_err(),
            "accepted {name:?}"
        );
    }
    validate_component(OsStr::new("session-雪 01.json")).unwrap();
}

#[test]
fn lock_namespace_is_reserved_consistently() {
    use orbit_platform::fs::{validate_data_component, validate_lock_component};
    for name in ["transaction.lock", "OTHER.LOCK", ".lease.lock"] {
        validate_lock_component(OsStr::new(name)).unwrap();
        assert!(validate_data_component(OsStr::new(name)).is_err());
    }
    assert!(validate_lock_component(OsStr::new("ordinary.json")).is_err());
    validate_data_component(OsStr::new("ordinary.json")).unwrap();
}

#[cfg(windows)]
mod windows {
    use orbit_platform::fs::{
        Directory, EnumerationLimits, InspectionLimits, LockMode, PrivateFileAccess, RemovalState,
    };
    use std::ffi::OsStr;
    use std::fs;
    use std::os::windows::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    struct Home {
        base: PathBuf,
        directory: Option<Directory>,
    }
    impl Home {
        fn new() -> Self {
            static SERIAL: AtomicU64 = AtomicU64::new(0);
            let base = std::env::temp_dir().join(format!(
                "orbit-fs-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&base).unwrap();
            let directory = Directory::create(&base.join("private 雪 space")).unwrap();
            Self {
                base,
                directory: Some(directory),
            }
        }
        fn path(&self) -> PathBuf {
            self.base.join("private 雪 space")
        }
        fn dir(&self) -> &Directory {
            self.directory.as_ref().unwrap()
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            drop(self.directory.take());
            fs::remove_dir_all(&self.base).unwrap();
        }
    }
    fn read(directory: &Directory, name: &str) -> Vec<u8> {
        directory
            .open_file(OsStr::new(name))
            .unwrap()
            .read_limited(1024)
            .unwrap()
    }
    fn command(program: &str) -> PathBuf {
        Path::new(&std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join(program)
    }

    fn tree_snapshot(root: &Path) -> Vec<(PathBuf, bool, Vec<u8>)> {
        fn visit(root: &Path, current: &Path, entries: &mut Vec<(PathBuf, bool, Vec<u8>)>) {
            for item in fs::read_dir(current).unwrap() {
                let item = item.unwrap();
                let path = item.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let reparse = metadata.file_attributes() & 0x400 != 0;
                if reparse {
                    entries.push((relative, true, Vec::new()));
                } else if metadata.is_dir() {
                    entries.push((relative, true, Vec::new()));
                    visit(root, &path, entries);
                } else {
                    entries.push((relative, false, fs::read(&path).unwrap()));
                }
            }
        }
        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    fn run_icacls(path: &Path, args: &[&str]) -> String {
        let output = Command::new(command("icacls.exe"))
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "icacls {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    fn current_sid() -> String {
        let output = Command::new(command("whoami.exe"))
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "whoami failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let row = String::from_utf8_lossy(&output.stdout);
        let sid = row
            .trim()
            .split(',')
            .nth(1)
            .expect("whoami CSV must include a SID")
            .trim_matches('"');
        assert!(sid.starts_with("S-1-"), "invalid current SID: {sid}");
        sid.to_owned()
    }

    #[test]
    fn unicode_private_create_reopen_and_read_bounds() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("entry 雪.json")).unwrap();
        file.write_all(b"private state").unwrap();
        file.sync_all().unwrap();
        let identity = file.identity();
        drop(file);
        let directory = Directory::open(&home.path()).unwrap();
        let mut file = directory.open_file(OsStr::new("entry 雪.json")).unwrap();
        assert_eq!(file.identity(), identity);
        assert!(file.read_limited(3).is_err());
        assert_eq!(file.read_limited(1024).unwrap(), b"private state");
    }

    #[test]
    fn absolute_drive_and_verbatim_aliases_keep_identity() {
        let home = Home::new();
        let alias = PathBuf::from(format!("\\\\?\\{}", home.path().display()));
        assert_eq!(
            Directory::open(&alias).unwrap().identity(),
            home.dir().identity()
        );
        for path in [
            "relative\\state",
            "C:state",
            "\\\\server\\share\\state",
            "\\\\?\\UNC\\server\\share\\state",
            "\\\\.\\C:\\state",
        ] {
            assert!(Directory::open(Path::new(path)).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn held_root_and_ancestor_cannot_be_swapped() {
        let home = Home::new();
        assert!(fs::rename(home.path(), home.base.join("replacement")).is_err());
        assert!(fs::rename(&home.base, home.base.with_extension("swapped")).is_err());
        home.dir().check().unwrap();
    }

    #[test]
    fn file_keeps_ancestor_handles_after_directory_drop() {
        let mut home = Home::new();
        let file = home.dir().create_file(OsStr::new("held")).unwrap();
        drop(home.directory.take());
        assert!(fs::rename(home.path(), home.base.join("replacement")).is_err());
        drop(file);
    }

    #[test]
    fn hardlinks_and_junctions_are_rejected() {
        let home = Home::new();
        drop(home.dir().create_file(OsStr::new("original")).unwrap());
        fs::hard_link(home.path().join("original"), home.path().join("alias")).unwrap();
        assert!(home.dir().open_file(OsStr::new("original")).is_err());
        assert!(home.dir().open_file(OsStr::new("alias")).is_err());
        let outside = home.base.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("canary"), b"unchanged").unwrap();
        let junction = home.path().join("junction");
        let output = Command::new(command("cmd.exe"))
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(home.dir().child(OsStr::new("junction"), false).is_err());
        assert!(Directory::open(&junction).is_err());
        assert_eq!(fs::read(outside.join("canary")).unwrap(), b"unchanged");
    }

    #[test]
    fn file_symlink_is_not_followed() {
        let home = Home::new();
        let outside = home.base.join("outside-file");
        fs::write(&outside, b"unchanged").unwrap();
        std::os::windows::fs::symlink_file(&outside, home.path().join("link")).unwrap();
        assert!(home.dir().open_file(OsStr::new("link")).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"unchanged");
    }

    #[test]
    fn permissive_dacl_is_rejected_by_held_and_reopened_checks() {
        let home = Home::new();
        let output = Command::new(command("icacls.exe"))
            .arg(home.path())
            .args(["/grant", "*S-1-1-0:(F)"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(home.dir().check().is_err());
        assert!(Directory::open(&home.path()).is_err());
    }

    #[test]
    fn wrong_owner_is_rejected() {
        let home = Home::new();
        let output = Command::new(command("icacls.exe"))
            .arg(home.path())
            .args(["/setowner", "*S-1-5-32-544"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture must actually change owner: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(home.dir().check().is_err());
        assert!(Directory::open(&home.path()).is_err());
    }

    #[test]
    fn publication_does_not_clobber_and_replace_retains_original() {
        let home = Home::new();
        let mut original = home.dir().create_file(OsStr::new("record")).unwrap();
        original.write_all(b"original").unwrap();
        let expected = original.identity();
        drop(original);
        let mut candidate = home.dir().create_file(OsStr::new("candidate")).unwrap();
        candidate.write_all(b"replacement").unwrap();
        assert!(
            home.dir()
                .publish_new(&candidate, OsStr::new("record"))
                .is_err()
        );
        assert_eq!(read(home.dir(), "record"), b"original");
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let receipt = home
            .dir()
            .replace(&candidate, OsStr::new("record"), expected, &lock)
            .unwrap();
        drop(candidate);
        assert_eq!(read(home.dir(), "record"), b"replacement");
        let backup = receipt.original_backup.unwrap();
        assert_eq!(
            home.dir()
                .open_file(&backup)
                .unwrap()
                .read_limited(1024)
                .unwrap(),
            b"original"
        );
    }

    #[test]
    fn replacement_requires_expected_identity_and_exclusive_lock() {
        let home = Home::new();
        let original = home.dir().create_file(OsStr::new("record")).unwrap();
        let mut wrong = original.identity();
        wrong.file[0] ^= 1;
        drop(original);
        let candidate = home.dir().create_file(OsStr::new("candidate")).unwrap();
        let shared = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Shared)
            .unwrap();
        assert!(
            home.dir()
                .replace(&candidate, OsStr::new("record"), wrong, &shared)
                .is_err()
        );
        drop(shared);
        let exclusive = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        assert!(
            home.dir()
                .replace(&candidate, OsStr::new("record"), wrong, &exclusive)
                .is_err()
        );
        assert_eq!(read(home.dir(), "record"), b"");
    }

    fn child_lock(path: &Path, mode: &str, expected: bool) {
        child_lock_kind(path, mode, expected, false);
    }
    fn child_lock_kind(path: &Path, mode: &str, expected: bool, existing_only: bool) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows::lock_child", "--nocapture"])
            .env("ORBIT_FS_LOCK_ROOT", path)
            .env("ORBIT_FS_LOCK_MODE", mode)
            .env(
                "ORBIT_FS_LOCK_EXISTING_ONLY",
                if existing_only { "yes" } else { "no" },
            )
            .env("ORBIT_FS_LOCK_EXPECT", if expected { "yes" } else { "no" })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("owned lock child exceeded deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.trim() == "test windows::lock_child ... ok"),
            "owned child did not execute its named test: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Subprocess entry; the parent tests exercise both successful and denied
    // second-process locks. This helper is not counted as a foundation case.
    #[test]
    fn lock_child() {
        let Some(path) = std::env::var_os("ORBIT_FS_LOCK_ROOT") else {
            return;
        };
        let directory = Directory::open(Path::new(&path)).unwrap();
        let mode = if std::env::var("ORBIT_FS_LOCK_MODE").unwrap() == "shared" {
            LockMode::Shared
        } else {
            LockMode::Exclusive
        };
        let acquired = if std::env::var("ORBIT_FS_LOCK_EXISTING_ONLY").as_deref() == Ok("yes") {
            directory
                .open_lock_existing(OsStr::new("stable.lock"), mode)
                .is_ok()
        } else {
            directory.try_lock(OsStr::new("stable.lock"), mode).is_ok()
        };
        assert_eq!(
            acquired,
            std::env::var("ORBIT_FS_LOCK_EXPECT").unwrap() == "yes"
        );
    }

    #[test]
    fn exclusive_lock_excludes_other_processes_and_releases() {
        let home = Home::new();
        let held = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
            .unwrap();
        child_lock(&home.path(), "shared", false);
        child_lock(&home.path(), "exclusive", false);
        assert!(
            fs::rename(
                home.path().join("stable.lock"),
                home.path().join("swapped.lock")
            )
            .is_err()
        );
        drop(held);
        child_lock(&home.path(), "exclusive", true);
    }

    #[test]
    fn missing_existing_lock_does_not_create_state() {
        let home = Home::new();
        let inventory = || {
            let mut names: Vec<_> = fs::read_dir(home.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let before = inventory();
        let error_kind = match home
            .dir()
            .open_lock_existing(OsStr::new("status.lock"), LockMode::Shared)
        {
            Ok(lock) => {
                drop(lock);
                None
            }
            Err(error) => Some(error.kind()),
        };
        assert_eq!(
            inventory(),
            before,
            "an existing-only lock request must not create state"
        );
        assert_eq!(error_kind, Some(std::io::ErrorKind::NotFound));
    }

    #[test]
    fn existing_lock_fixed_buffer_snapshot_and_cursor() {
        let home = Home::new();
        let initial = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
            .unwrap();
        let lock_identity = initial.identity();
        let mut seed = home.dir().create_file(OsStr::new("record.json")).unwrap();
        seed.write_all(b"credential-12345").unwrap();
        seed.sync_all().unwrap();
        let identity = seed.identity();
        drop(seed);
        drop(initial);
        let held = home
            .dir()
            .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
            .unwrap();
        assert_eq!(held.identity(), lock_identity);
        held.check().unwrap();
        let mut file = home.dir().open_file(OsStr::new("record.json")).unwrap();
        let before = file.snapshot().unwrap();
        assert_eq!(before.identity, identity);
        assert_eq!(before.length, 16);
        let mut buffer = [0u8; 8];
        assert_eq!(file.read_into(&mut buffer[..4]).unwrap(), 4);
        assert_eq!(&buffer[..4], b"cred");
        assert_eq!(file.read_into(&mut buffer[4..]).unwrap(), 4);
        assert_eq!(&buffer, b"credenti");
        // One extra caller-owned byte detects overflow of an eight-byte limit.
        let mut extra = [0u8; 1];
        assert_eq!(file.read_into(&mut extra).unwrap(), 1);
        assert_eq!(extra, [b'a']);
        assert_eq!(file.snapshot().unwrap(), before);
        held.check().unwrap();
        buffer.fill(0);
        extra.fill(0);
    }

    #[test]
    fn file_snapshot_detects_content_change() {
        let home = Home::new();
        let mut seed = home.dir().create_file(OsStr::new("record.json")).unwrap();
        seed.write_all(b"before").unwrap();
        seed.sync_all().unwrap();
        let identity = seed.identity();
        drop(seed);
        let file = home.dir().open_file(OsStr::new("record.json")).unwrap();
        let before = file.snapshot().unwrap();
        let held = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
            .unwrap();
        let mut update = home
            .dir()
            .open_for_update(OsStr::new("record.json"), identity, &held)
            .unwrap();
        update.append_all(b" after").unwrap();
        update.sync_all().unwrap();
        drop(update);
        let after = file.snapshot().unwrap();
        assert_eq!(before.identity, after.identity);
        assert_eq!(before.length, 6);
        assert_eq!(after.length, 12);
        assert_ne!(before, after);
        assert!(after.last_write_time > 0 && after.change_time > 0);
    }

    #[test]
    fn existing_lock_rejects_nonempty_and_unsafe_without_repair() {
        let home = Home::new();
        drop(
            home.dir()
                .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
                .unwrap(),
        );
        fs::write(home.path().join("stable.lock"), b"invalid lock").unwrap();
        assert!(
            home.dir()
                .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
                .is_err()
        );
        assert!(
            home.dir()
                .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
                .is_err()
        );
        assert_eq!(
            fs::read(home.path().join("stable.lock")).unwrap(),
            b"invalid lock"
        );
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 1);

        let unsafe_home = Home::new();
        drop(
            unsafe_home
                .dir()
                .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
                .unwrap(),
        );
        let path = unsafe_home.path().join("stable.lock");
        assert!(
            Command::new(command("icacls.exe"))
                .arg(&path)
                .args(["/grant", "*S-1-1-0:(R)"])
                .output()
                .unwrap()
                .status
                .success()
        );
        let before = Command::new(command("icacls.exe"))
            .arg(&path)
            .output()
            .unwrap();
        assert!(before.status.success());
        assert!(
            unsafe_home
                .dir()
                .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
                .is_err()
        );
        let after = Command::new(command("icacls.exe"))
            .arg(&path)
            .output()
            .unwrap();
        assert!(after.status.success());
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn existing_only_locks_observe_cross_process_contention() {
        let home = Home::new();
        let initial = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
            .unwrap();
        let identity = initial.identity();
        drop(initial);
        let held = home
            .dir()
            .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
            .unwrap();
        child_lock_kind(&home.path(), "shared", true, true);
        child_lock_kind(&home.path(), "exclusive", false, true);
        assert!(
            fs::rename(
                home.path().join("stable.lock"),
                home.path().join("moved.lock")
            )
            .is_err()
        );
        held.check().unwrap();
        drop(held);
        child_lock_kind(&home.path(), "exclusive", true, true);
        let reopened = home
            .dir()
            .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
            .unwrap();
        assert_eq!(reopened.identity(), identity);
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 1);
    }

    #[test]
    fn shared_readers_coexist_but_exclude_writer() {
        let home = Home::new();
        let held = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Shared)
            .unwrap();
        child_lock(&home.path(), "shared", true);
        child_lock(&home.path(), "exclusive", false);
        drop(held);
        child_lock(&home.path(), "exclusive", true);
    }

    #[test]
    fn locked_update_has_explicit_cursor_append_length_and_truncate() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("ledger")).unwrap();
        file.write_all(b"abc").unwrap();
        let expected = file.identity();
        drop(file);
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let mut update = home
            .dir()
            .open_for_update(OsStr::new("ledger"), expected, &lock)
            .unwrap();
        assert_eq!(update.length().unwrap(), 3);
        assert_eq!(update.seek(std::io::SeekFrom::Start(1)).unwrap(), 1);
        update.write_all(b"Z").unwrap();
        update.append_all(b"de").unwrap();
        assert_eq!(update.position().unwrap(), 5);
        update.truncate(2).unwrap();
        assert_eq!(update.position().unwrap(), 5);
        assert_eq!(update.length().unwrap(), 2);
        update.sync_all().unwrap();
        assert_eq!(update.read_limited(10).unwrap(), b"aZ");
        drop(update);
        let mut ordinary = home.dir().open_file(OsStr::new("ledger")).unwrap();
        assert!(ordinary.write_all(b"unsafe").is_err());
        assert_eq!(ordinary.read_limited(10).unwrap(), b"aZ");
    }

    #[test]
    fn lifecycle_rejects_wrong_identity_shared_and_foreign_guards() {
        let home = Home::new();
        let other = Home::new();
        let file = home.dir().create_file(OsStr::new("record")).unwrap();
        let expected = file.identity();
        drop(file);
        let shared = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Shared)
            .unwrap();
        assert!(
            home.dir()
                .open_for_update(OsStr::new("record"), expected, &shared)
                .is_err()
        );
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("record"), expected, &shared)
                .is_err()
        );
        drop(shared);
        let foreign = other
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        assert!(
            home.dir()
                .open_for_update(OsStr::new("record"), expected, &foreign)
                .is_err()
        );
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("record"), expected, &foreign)
                .is_err()
        );
        let own = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let mut wrong = expected;
        wrong.file[0] ^= 1;
        assert!(
            home.dir()
                .open_for_update(OsStr::new("record"), wrong, &own)
                .is_err()
        );
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("record"), wrong, &own)
                .is_err()
        );
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("record"))
                .unwrap()
                .identity(),
            expected
        );
    }

    #[test]
    fn checked_backup_restore_and_cleanup_preserve_identity() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("retained")).unwrap();
        file.write_all(b"original").unwrap();
        let expected = file.identity();
        drop(file);
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let held = home
            .dir()
            .open_for_rename(OsStr::new("retained"), expected, &lock)
            .unwrap();
        let receipt = home
            .dir()
            .restore_backup(held, OsStr::new("record"))
            .unwrap();
        assert_eq!(receipt.identity, expected);
        assert_eq!(read(home.dir(), "record"), b"original");
        let held = home
            .dir()
            .open_for_rename(OsStr::new("record"), expected, &lock)
            .unwrap();
        let removed = home.dir().remove_file(held).unwrap();
        assert_eq!(removed.identity, expected);
        assert_eq!(removed.state, RemovalState::DispositionAcknowledged);
        assert!(home.dir().open_file(OsStr::new("record")).is_err());
    }

    #[test]
    fn restore_refuses_occupied_target_and_reparse_sources() {
        let home = Home::new();
        let file = home.dir().create_file(OsStr::new("retained")).unwrap();
        let expected = file.identity();
        drop(file);
        drop(home.dir().create_file(OsStr::new("occupied")).unwrap());
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let held = home
            .dir()
            .open_for_rename(OsStr::new("retained"), expected, &lock)
            .unwrap();
        assert!(
            home.dir()
                .restore_backup(held, OsStr::new("occupied"))
                .is_err()
        );
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("retained"))
                .unwrap()
                .identity(),
            expected
        );
        let outside = home.base.join("outside");
        fs::write(&outside, b"canary").unwrap();
        std::os::windows::fs::symlink_file(&outside, home.path().join("link")).unwrap();
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("link"), expected, &lock)
                .is_err()
        );
        assert_eq!(fs::read(outside).unwrap(), b"canary");
    }

    #[test]
    fn enumeration_is_bounded_and_revalidates_entries() {
        let home = Home::new();
        let a = home.dir().create_file(OsStr::new("entry 雪")).unwrap();
        let expected = a.identity();
        drop(a);
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Shared)
            .unwrap();
        let entries = home
            .dir()
            .enumerate(
                EnumerationLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                },
                &lock,
            )
            .unwrap();
        assert_eq!(entries.len(), 2); // The stable lock is visible but cannot be mutated as data.
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.name == "entry 雪")
                .unwrap()
                .identity,
            expected
        );
        assert!(
            home.dir()
                .enumerate(
                    EnumerationLimits {
                        max_entries: 1,
                        max_name_bytes: 1024
                    },
                    &lock
                )
                .is_err()
        );
        assert!(
            home.dir()
                .enumerate(
                    EnumerationLimits {
                        max_entries: 8,
                        max_name_bytes: 1
                    },
                    &lock
                )
                .is_err()
        );
        drop(lock);
        fs::hard_link(home.path().join("entry 雪"), home.path().join("alias")).unwrap();
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Shared)
            .unwrap();
        assert!(
            home.dir()
                .enumerate(
                    EnumerationLimits {
                        max_entries: 8,
                        max_name_bytes: 1024
                    },
                    &lock
                )
                .is_err()
        );
    }

    #[test]
    fn empty_child_cleanup_refuses_live_anchors_nonempty_and_wrong_identity() {
        let home = Home::new();
        let child = home.dir().child(OsStr::new("child"), true).unwrap();
        let expected = child.identity();
        let file = child.create_file(OsStr::new("held")).unwrap();
        let held_id = file.identity();
        drop(file);
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        assert!(
            home.dir()
                .remove_empty_child(OsStr::new("child"), expected, &lock)
                .is_err()
        );
        let inner_lock = child
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let held = child
            .open_for_rename(OsStr::new("held"), held_id, &inner_lock)
            .unwrap();
        child.remove_file(held).unwrap();
        drop(inner_lock);
        drop(child);
        // A stable lock intentionally makes this directory nonempty.
        assert!(
            home.dir()
                .remove_empty_child(OsStr::new("child"), expected, &lock)
                .is_err()
        );
        let empty = home.dir().child(OsStr::new("empty"), true).unwrap();
        let empty_id = empty.identity();
        drop(empty);
        let mut wrong = empty_id;
        wrong.file[0] ^= 1;
        assert!(
            home.dir()
                .remove_empty_child(OsStr::new("empty"), wrong, &lock)
                .is_err()
        );
        assert_eq!(
            home.dir()
                .remove_empty_child(OsStr::new("empty"), empty_id, &lock)
                .unwrap()
                .identity,
            empty_id
        );
    }

    #[test]
    fn stable_lock_names_cannot_enter_data_mutation_routes() {
        let home = Home::new();
        assert!(
            home.dir()
                .try_lock(OsStr::new("not-reserved"), LockMode::Exclusive)
                .is_err()
        );
        let held = home
            .dir()
            .try_lock(OsStr::new("first.lock"), LockMode::Exclusive)
            .unwrap();
        let other = home
            .dir()
            .try_lock(OsStr::new("OTHER.LOCK"), LockMode::Exclusive)
            .unwrap();
        let snapshot = home
            .dir()
            .enumerate(
                EnumerationLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                },
                &held,
            )
            .unwrap();
        let lock_id = snapshot
            .iter()
            .find(|entry| entry.name == "OTHER.LOCK")
            .unwrap()
            .identity;
        assert!(home.dir().create_file(OsStr::new("OTHER.LOCK")).is_err());
        assert!(
            home.dir()
                .open_for_update(OsStr::new("OTHER.LOCK"), lock_id, &held)
                .is_err()
        );
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("OTHER.LOCK"), lock_id, &held)
                .is_err()
        );
        let file = home.dir().create_file(OsStr::new("candidate")).unwrap();
        assert!(
            home.dir()
                .publish_new(&file, OsStr::new("OTHER.LOCK"))
                .is_err()
        );
        assert!(
            home.dir()
                .replace(&file, OsStr::new("OTHER.LOCK"), lock_id, &held)
                .is_err()
        );
        drop(other);
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("OTHER.LOCK"), lock_id, &held)
                .is_err()
        );
    }

    #[test]
    fn inspection_empty_root_is_no_effect() {
        let home = Home::new();
        let before = tree_snapshot(&home.path());
        let inspected = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .unwrap();
        assert_eq!(inspected.root_identity, home.dir().identity());
        assert!(inspected.entries.is_empty());
        assert_eq!(tree_snapshot(&home.path()), before);
        assert!(!home.path().join("inspection.lock").exists());
    }

    #[test]
    fn inspection_observes_existing_shared_lock_and_nested_files() {
        let home = Home::new();
        let nested = home.dir().child(OsStr::new("nested"), true).unwrap();
        let mut full = nested.create_file(OsStr::new("full.json")).unwrap();
        full.write_all(b"full control fixture").unwrap();
        let full_identity = full.identity();
        drop(full);

        let sid = current_sid();
        let mut read_only = home.dir().create_file(OsStr::new("read-only.dat")).unwrap();
        read_only.write_all(b"read-only fixture").unwrap();
        let read_only_identity = read_only.identity();
        drop(read_only);
        let read_only_rule = format!("*{sid}:(R)");
        run_icacls(
            &home.path().join("read-only.dat"),
            &["/grant:r", &read_only_rule],
        );

        let mut read_execute = home
            .dir()
            .create_file(OsStr::new("read-execute.dat"))
            .unwrap();
        read_execute.write_all(b"read-execute fixture").unwrap();
        let read_execute_identity = read_execute.identity();
        drop(read_execute);
        let read_execute_rule = format!("*{sid}:(RX)");
        run_icacls(
            &home.path().join("read-execute.dat"),
            &["/grant:r", &read_execute_rule],
        );

        let seed = home
            .dir()
            .try_lock(OsStr::new("existing.lock"), LockMode::Exclusive)
            .unwrap();
        let lock_identity = seed.identity();
        drop(seed);
        let shared = home
            .dir()
            .open_lock_existing(OsStr::new("existing.lock"), LockMode::Shared)
            .unwrap();
        assert_eq!(shared.identity(), lock_identity);
        shared.check().unwrap();

        let before = tree_snapshot(&home.path());
        let inspected = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .unwrap();
        assert_eq!(inspected.root_identity, home.dir().identity());
        assert_eq!(inspected.entries.len(), 5);
        let get = |name: &str| {
            inspected
                .entries
                .iter()
                .find(|entry| entry.relative_path == Path::new(name))
                .unwrap_or_else(|| panic!("missing inspected entry {name}"))
        };
        assert!(get("nested").directory);
        assert_eq!(get("nested").identity, nested.identity());
        assert_eq!(get("nested").file_access, None);
        assert_eq!(get("nested").snapshot, None);

        let full_entry = get("nested/full.json");
        assert_eq!(full_entry.identity, full_identity);
        assert_eq!(full_entry.file_access, Some(PrivateFileAccess::FullControl));
        assert_eq!(full_entry.snapshot.unwrap().length, 20);

        let read_only_entry = get("read-only.dat");
        assert_eq!(read_only_entry.identity, read_only_identity);
        assert_eq!(
            read_only_entry.file_access,
            Some(PrivateFileAccess::ReadOnly)
        );
        assert_eq!(read_only_entry.snapshot.unwrap().length, 17);

        let read_execute_entry = get("read-execute.dat");
        assert_eq!(read_execute_entry.identity, read_execute_identity);
        assert_eq!(
            read_execute_entry.file_access,
            Some(PrivateFileAccess::ReadExecute)
        );
        assert_eq!(read_execute_entry.snapshot.unwrap().length, 20);

        let lock_entry = get("existing.lock");
        assert_eq!(lock_entry.identity, lock_identity);
        assert_eq!(lock_entry.file_access, Some(PrivateFileAccess::FullControl));
        assert_eq!(lock_entry.snapshot.unwrap().length, 0);
        assert_eq!(tree_snapshot(&home.path()), before);
        shared.check().unwrap();
    }

    #[test]
    fn inspection_rejects_permissive_and_wrong_owner_entries_without_repair() {
        let home = Home::new();
        let nested = home.dir().child(OsStr::new("nested"), true).unwrap();
        drop(nested.create_file(OsStr::new("private.dat")).unwrap());
        let nested_path = home.path().join("nested");
        let permissive_acl = run_icacls(&nested_path, &["/grant", "*S-1-1-0:(F)"]);
        let before = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 4,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);
        assert_eq!(run_icacls(&nested_path, &[]), permissive_acl);
        drop(home);

        let home = Home::new();
        let mut record = home
            .dir()
            .create_file(OsStr::new("wrong-owner.dat"))
            .unwrap();
        record.write_all(b"owner fixture").unwrap();
        drop(record);
        let record_path = home.path().join("wrong-owner.dat");
        run_icacls(&record_path, &["/setowner", "*S-1-5-32-544"]);
        let owner_before = run_icacls(&record_path, &["/getowner"]);
        let before = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 4,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);
        assert_eq!(run_icacls(&record_path, &["/getowner"]), owner_before);
    }

    #[test]
    fn inspection_rejects_reparse_and_hardlink_entries() {
        let home = Home::new();
        let mut original = home.dir().create_file(OsStr::new("original.dat")).unwrap();
        original.write_all(b"hardlink fixture").unwrap();
        drop(original);
        fs::hard_link(
            home.path().join("original.dat"),
            home.path().join("alias.dat"),
        )
        .unwrap();
        let before = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 4,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);

        let home = Home::new();
        let outside = home.base.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("canary"), b"unchanged").unwrap();
        let junction = home.path().join("junction");
        let output = Command::new(command("cmd.exe"))
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let before = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 4,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);
        assert_eq!(fs::read(outside.join("canary")).unwrap(), b"unchanged");
    }

    #[test]
    fn inspection_limits_reject_extra_entry_path_and_depth_without_changes() {
        let home = Home::new();
        drop(home.dir().create_file(OsStr::new("a")).unwrap());
        let one_entry = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 1,
                max_name_bytes: 2,
                max_depth: 1,
            })
            .unwrap();
        assert_eq!(one_entry.entries.len(), 1);

        drop(home.dir().create_file(OsStr::new("b")).unwrap());
        let before = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 1,
                    max_name_bytes: 1024,
                    max_depth: 1,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 3,
                    max_depth: 1,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);

        let child = home.dir().child(OsStr::new("nested"), true).unwrap();
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 1,
                })
                .is_ok()
        );
        drop(child.create_file(OsStr::new("leaf")).unwrap());
        let before_nested = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 1,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before_nested);
    }

    #[test]
    fn inspection_holds_root_and_ancestors_while_walking() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("record")).unwrap();
        file.write_all(b"stable").unwrap();
        drop(file);
        let before = tree_snapshot(&home.path());
        let inspected = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .unwrap();
        assert_eq!(inspected.root_identity, home.dir().identity());
        assert!(fs::rename(home.path(), home.base.join("replacement")).is_err());
        assert!(fs::rename(&home.base, home.base.with_extension("swapped")).is_err());
        assert_eq!(tree_snapshot(&home.path()), before);
    }

    #[test]
    fn published_candidate_cannot_be_republished_without_a_guard() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("candidate")).unwrap();
        file.write_all(b"published").unwrap();
        let expected = file.identity();
        home.dir().publish_new(&file, OsStr::new("record")).unwrap();
        assert!(home.dir().publish_new(&file, OsStr::new("moved")).is_err());
        assert!(file.write_all(b"unlocked").is_err());
        drop(file);
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("record"))
                .unwrap()
                .identity(),
            expected
        );
        assert_eq!(read(home.dir(), "record"), b"published");
        assert!(home.dir().open_file(OsStr::new("moved")).is_err());
    }

    #[test]
    fn simultaneous_publication_preserves_the_only_successful_name() {
        let home = Home::new();
        for round in 0..8 {
            let file = home
                .dir()
                .create_file(OsStr::new(&format!("candidate-{round}")))
                .unwrap();
            let expected = file.identity();
            let left = format!("left-{round}");
            let right = format!("right-{round}");
            let barrier = std::sync::Barrier::new(2);
            let (a, b) = std::thread::scope(|scope| {
                let first = scope.spawn(|| {
                    barrier.wait();
                    home.dir().publish_new(&file, OsStr::new(&left))
                });
                let second = scope.spawn(|| {
                    barrier.wait();
                    home.dir().publish_new(&file, OsStr::new(&right))
                });
                (first.join().unwrap(), second.join().unwrap())
            });
            assert_ne!(
                a.is_ok(),
                b.is_ok(),
                "expected exactly one publication: {a:?}, {b:?}"
            );
            let (winner, loser) = if a.is_ok() {
                (&left, &right)
            } else {
                (&right, &left)
            };
            drop(file);
            assert_eq!(
                home.dir().open_file(OsStr::new(winner)).unwrap().identity(),
                expected
            );
            assert!(home.dir().open_file(OsStr::new(loser)).is_err());
        }
    }

    #[test]
    fn ntfs_short_alias_cannot_bypass_reserved_lock_policy() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let home = Home::new();
        drop(
            home.dir()
                .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
                .unwrap(),
        );
        let guard = home
            .dir()
            .try_lock(OsStr::new("guard.lock"), LockMode::Exclusive)
            .unwrap();
        let entries = home
            .dir()
            .enumerate(
                EnumerationLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                },
                &guard,
            )
            .unwrap();
        let expected = entries
            .iter()
            .find(|entry| entry.name == "transaction.lock")
            .unwrap()
            .identity;
        let long: Vec<u16> = home
            .path()
            .join("transaction.lock")
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut short = vec![0u16; 32768];
        let length = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetShortPathNameW(
                long.as_ptr(),
                short.as_mut_ptr(),
                short.len() as u32,
            )
        };
        assert!(
            length > 0 && (length as usize) < short.len(),
            "8.3 fixture lookup failed: {}",
            std::io::Error::last_os_error()
        );
        let short = PathBuf::from(std::ffi::OsString::from_wide(&short[..length as usize]));
        let alias = short.file_name().unwrap();
        assert!(
            orbit_platform::fs::validate_data_component(alias).is_ok(),
            "fixture did not create an actual 8.3 alias: {alias:?}"
        );
        assert!(home.dir().open_file(alias).is_err());
        assert!(home.dir().open_for_update(alias, expected, &guard).is_err());
        assert!(home.dir().open_for_rename(alias, expected, &guard).is_err());
        assert!(home.dir().try_lock(alias, LockMode::Exclusive).is_err());
        drop(guard);
        drop(
            home.dir()
                .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
                .unwrap(),
        );
    }
}
