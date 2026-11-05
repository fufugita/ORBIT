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
    use orbit_platform::fs::{Directory, EnumerationLimits, LockMode, RemovalState};
    use std::ffi::OsStr;
    use std::fs;
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
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows::lock_child", "--nocapture"])
            .env("ORBIT_FS_LOCK_ROOT", path)
            .env("ORBIT_FS_LOCK_MODE", mode)
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
        let acquired = directory.try_lock(OsStr::new("stable.lock"), mode).is_ok();
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
