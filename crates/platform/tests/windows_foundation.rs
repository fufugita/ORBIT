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

#[cfg(windows)]
mod windows {
    use orbit_platform::fs::{Directory, LockMode};
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
}
