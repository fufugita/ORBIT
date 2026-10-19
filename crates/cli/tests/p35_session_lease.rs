#![cfg(unix)]

use orbit_cli::sessions::{SessionFile, SessionLease, SessionLeaseError};
use std::fs;
#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "linux")]
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-lease-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildOwner(Child);

impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
struct PreExecBarrier {
    release: Option<OwnedFd>,
    spawning: Option<JoinHandle<io::Result<Child>>>,
}

#[cfg(target_os = "linux")]
impl PreExecBarrier {
    fn release_and_reap(&mut self) -> Result<(), String> {
        // Always unblock spawn before joining, including during unwinding.
        if let Some(release) = self.release.take() {
            let _ = fs::File::from(release).write_all(b"R");
        }
        if let Some(spawning) = self.spawning.take() {
            let mut child = spawning
                .join()
                .map_err(|_| "spawn thread panicked".to_owned())?
                .map_err(|error| format!("child did not exec: {error}"))?;
            let _ = child.kill();
            child.wait().map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for PreExecBarrier {
    fn drop(&mut self) {
        let _ = self.release_and_reap();
    }
}

#[cfg(target_os = "linux")]
fn cloexec_pipe() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe2 initializes exactly these two slots on success. Both FDs
    // transfer immediately into unique owners, and neither crosses exec.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0,
        "pipe creation failed: {}",
        io::Error::last_os_error()
    );
    unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    }
}

fn sample(id: &str, model: &str) -> SessionFile {
    SessionFile::from_chat(id, model, "http://127.0.0.1:1", "fixture", &[], 1, 2, 3, 4)
}

fn session_path(home: &Path, id: &str) -> PathBuf {
    home.join("sessions").join(format!("{id}.json"))
}

fn child(home: &Path, id: &str, action: &str) -> ChildOwner {
    ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ownership_child", "--nocapture"])
            .env("ORBIT_LEASE_CHILD_HOME", home)
            .env("ORBIT_LEASE_CHILD_ID", id)
            .env("ORBIT_LEASE_CHILD_ACTION", action)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn wait_ready(home: &Path, process: &mut ChildOwner) {
    let until = Instant::now() + Duration::from_secs(5);
    while !home.join("ready").exists() {
        assert!(Instant::now() < until, "child never claimed its lease");
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "child exited before ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn ownership_child() {
    let Some(home) = std::env::var_os("ORBIT_LEASE_CHILD_HOME") else {
        return;
    };
    let id = std::env::var("ORBIT_LEASE_CHILD_ID").unwrap();
    let home = PathBuf::from(home);
    let action = std::env::var("ORBIT_LEASE_CHILD_ACTION").unwrap();
    let lease = match SessionLease::acquire(&home, &id, "fixture-child") {
        Ok(lease) => lease,
        Err(SessionLeaseError::Busy { .. }) => std::process::exit(21),
        Err(error) => panic!("unexpected child lease refusal: {error}"),
    };
    lease.save(&sample(&id, "child-model")).unwrap();
    if action == "try" {
        return;
    }
    fs::write(home.join("ready"), b"owned").unwrap();
    while !home.join("release").exists() {
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(lease);
}

#[test]
fn ownership_competing_process_cannot_load_or_overwrite() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "headless").unwrap();
    lease.save(&sample("session-a", "parent-model")).unwrap();
    let before = fs::read(session_path(&home.0, "session-a")).unwrap();
    let mut competing = child(&home.0, "session-a", "try");
    assert_eq!(competing.0.wait().unwrap().code(), Some(21));
    assert_eq!(
        fs::read(session_path(&home.0, "session-a")).unwrap(),
        before
    );
    assert_eq!(lease.load().unwrap().model, "parent-model");
}

#[test]
fn ownership_release_allows_another_process() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "headless").unwrap();
    lease.save(&sample("session-a", "parent-model")).unwrap();
    drop(lease);
    let mut next = child(&home.0, "session-a", "try");
    assert!(next.0.wait().unwrap().success());
    let (lease, saved) = SessionLease::acquire_and_load(&home.0, "session-a", "tui").unwrap();
    assert_eq!(saved.model, "child-model");
    assert_eq!(lease.session_id(), "session-a");
}

#[test]
fn ownership_distinct_sessions_can_be_owned_together() {
    let home = Home::new();
    let first = SessionLease::acquire(&home.0, "session-a", "tui").unwrap();
    let second = SessionLease::acquire(&home.0, "session-b", "daemon").unwrap();
    first.save(&sample("session-a", "model-a")).unwrap();
    second.save(&sample("session-b", "model-b")).unwrap();
    assert_eq!(first.load().unwrap().model, "model-a");
    assert_eq!(second.load().unwrap().model, "model-b");
}

#[test]
fn busy_switch_keeps_original_guard_and_saved_state() {
    let home = Home::new();
    let original = SessionLease::acquire(&home.0, "original", "tui").unwrap();
    original.save(&sample("original", "model-a")).unwrap();
    let busy = SessionLease::acquire(&home.0, "target", "daemon").unwrap();
    busy.save(&sample("target", "model-b")).unwrap();
    let before = fs::read(session_path(&home.0, "original")).unwrap();
    assert!(matches!(
        SessionLease::acquire_and_load(&home.0, "target", "tui"),
        Err(SessionLeaseError::Busy { .. })
    ));
    assert!(matches!(
        SessionLease::acquire(&home.0, "original", "daemon"),
        Err(SessionLeaseError::Busy { .. })
    ));
    assert_eq!(original.load().unwrap().model, "model-a");
    assert_eq!(fs::read(session_path(&home.0, "original")).unwrap(), before);
}

#[test]
fn invalid_switch_keeps_original_and_releases_candidate() {
    let home = Home::new();
    let original = SessionLease::acquire(&home.0, "original", "tui").unwrap();
    original.save(&sample("original", "model-a")).unwrap();
    fs::write(session_path(&home.0, "target"), b"malformed").unwrap();
    fs::set_permissions(
        session_path(&home.0, "target"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(matches!(
        SessionLease::acquire_and_load(&home.0, "target", "tui"),
        Err(SessionLeaseError::InvalidData(_))
    ));
    let target = SessionLease::acquire(&home.0, "target", "daemon").unwrap();
    assert_eq!(original.load().unwrap().model, "model-a");
    assert!(matches!(
        SessionLease::acquire(&home.0, "original", "daemon"),
        Err(SessionLeaseError::Busy { .. })
    ));
    drop(target);
}

#[test]
fn valid_switch_acquires_and_validates_before_releasing_original() {
    let home = Home::new();
    let mut original = SessionLease::acquire(&home.0, "original", "tui").unwrap();
    original.save(&sample("original", "model-a")).unwrap();
    let target = SessionLease::acquire(&home.0, "target", "tui").unwrap();
    target.save(&sample("target", "model-b")).unwrap();
    drop(target);
    let (candidate, saved) = SessionLease::acquire_and_load(&home.0, "target", "tui").unwrap();
    assert_eq!(saved.model, "model-b");
    assert!(matches!(
        SessionLease::acquire(&home.0, "original", "daemon"),
        Err(SessionLeaseError::Busy { .. })
    ));
    original = candidate;
    assert_eq!(original.session_id(), "target");
    assert!(SessionLease::acquire(&home.0, "original", "daemon").is_ok());
    assert!(matches!(
        SessionLease::acquire(&home.0, "target", "daemon"),
        Err(SessionLeaseError::Busy { .. })
    ));
}

#[test]
fn crash_releases_os_lock_with_stale_metadata_remaining() {
    let home = Home::new();
    let mut process = child(&home.0, "session-a", "hold");
    wait_ready(&home.0, &mut process);
    assert!(matches!(
        SessionLease::acquire(&home.0, "session-a", "daemon"),
        Err(SessionLeaseError::Busy { .. })
    ));
    process.0.kill().unwrap();
    assert!(!process.0.wait().unwrap().success());
    let (lease, saved) = SessionLease::acquire_and_load(&home.0, "session-a", "daemon").unwrap();
    assert_eq!(saved.model, "child-model");
    assert_eq!(lease.kind(), "daemon");
}

#[test]
fn stale_metadata_cannot_override_a_live_os_lock() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "daemon").unwrap();
    let lock = home.0.join("sessions/.leases/session-a.lock");
    let inode = fs::metadata(&lock).unwrap().ino();
    fs::write(&lock, br#"{"pid":999999,"kind":"stale"}"#).unwrap();
    assert!(matches!(
        SessionLease::acquire(&home.0, "session-a", "tui"),
        Err(SessionLeaseError::Busy { .. })
    ));
    assert_eq!(fs::metadata(&lock).unwrap().ino(), inode);
    drop(lease);
    let _next = SessionLease::acquire(&home.0, "session-a", "tui").unwrap();
    assert_eq!(fs::metadata(&lock).unwrap().ino(), inode);
}

#[test]
#[cfg(target_os = "linux")]
fn release_is_immediate_while_a_child_inherits_the_pre_exec_descriptor() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "daemon").unwrap();
    lease.save(&sample("session-a", "parent-model")).unwrap();
    let session_before = fs::read(session_path(&home.0, "session-a")).unwrap();
    let lock = home.0.join("sessions/.leases/session-a.lock");
    let inode_before = fs::metadata(&lock).unwrap().ino();
    let (ready_read, ready_write) = cloexec_pipe();
    let (release_read, release_write) = cloexec_pipe();
    let spawning = std::thread::spawn(move || {
        let ready = ready_write.as_raw_fd();
        let release = release_read.as_raw_fd();
        let mut command = Command::new("/bin/true");
        // SAFETY: the closure captures only raw FD numbers. Between fork and
        // exec it uses stack data and async-signal-safe syscalls exclusively;
        // it does not allocate, acquire Rust locks or run Rust destructors.
        unsafe {
            command.pre_exec(move || {
                if libc::write(ready, b"F".as_ptr().cast(), 1) != 1 {
                    libc::_exit(121);
                }
                let mut poll = libc::pollfd {
                    fd: release,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // A failed parent must never leave this child stuck in spawn.
                if libc::poll(&mut poll, 1, 10_000) != 1 || poll.revents & libc::POLLIN == 0 {
                    libc::_exit(122);
                }
                let mut byte = 0_u8;
                if libc::read(release, (&mut byte as *mut u8).cast(), 1) != 1 || byte != b'R' {
                    libc::_exit(123);
                }
                Ok(())
            });
        }
        let child = command.spawn();
        drop((ready_write, release_read));
        child
    });
    let mut barrier = PreExecBarrier {
        release: Some(release_write),
        spawning: Some(spawning),
    };
    let mut poll = libc::pollfd {
        fd: ready_read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll points to one initialized descriptor held by ready_read.
    let fork_announced = unsafe { libc::poll(&mut poll, 1, 5_000) } == 1
        && poll.revents & libc::POLLIN != 0
        && fs::File::from(ready_read)
            .read_exact(&mut [0_u8; 1])
            .is_ok();
    let live_parent_refused = matches!(
        SessionLease::acquire(&home.0, "session-a", "tui"),
        Err(SessionLeaseError::Busy { .. })
    );
    drop(lease);
    // Deliberately no retry or sleep: the pre-exec child still holds every
    // inherited CLOEXEC descriptor when the former owner relinquishes its lease.
    let reacquired = SessionLease::acquire_and_load(&home.0, "session-a", "tui");
    let inode_after = fs::metadata(&lock).map(|metadata| metadata.ino());
    let session_after = fs::read(session_path(&home.0, "session-a"));
    let cleanup = barrier.release_and_reap();

    // Release the barrier and reap the child before any assertion can fail.
    assert!(cleanup.is_ok(), "pre-exec cleanup failed: {cleanup:?}");
    assert!(fork_announced, "child never reached the pre-exec barrier");
    assert!(live_parent_refused, "live parent lost exclusive ownership");
    let (next, saved) = reacquired.expect("dropping the owner must release an inherited OS lock");
    assert_eq!(next.session_id(), "session-a");
    assert_eq!(next.kind(), "tui");
    assert_eq!(saved.model, "parent-model");
    assert_eq!(inode_after.unwrap(), inode_before);
    assert_eq!(session_after.unwrap(), session_before);
}

#[test]
fn invalid_identity_and_kind_refuse_before_creating_paths() {
    let home = Home::new();
    for id in [
        "",
        "../escape",
        "/absolute",
        ".",
        "a/b",
        "a.json.json",
        "snow☃",
    ] {
        assert!(
            matches!(
                SessionLease::acquire(&home.0, id, "tui"),
                Err(SessionLeaseError::InvalidIdentity(_))
            ),
            "accepted {id:?}"
        );
    }
    assert!(matches!(
        SessionLease::acquire(&home.0, &"a".repeat(129), "tui"),
        Err(SessionLeaseError::InvalidIdentity(_))
    ));
    assert!(SessionLease::acquire(&home.0, "valid", "bad\nkind").is_err());
    assert!(!home.0.join("sessions").exists());
}

#[test]
fn symlink_home_and_storage_directories_are_refused() {
    let home = Home::new();
    let outside = Home::new();
    let home_link = home.0.join("linked-home");
    symlink(&outside.0, &home_link).unwrap();
    assert!(matches!(
        SessionLease::acquire(&home_link, "session-a", "tui"),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    symlink(&outside.0, home.0.join("sessions")).unwrap();
    assert!(matches!(
        SessionLease::acquire(&home.0, "session-a", "tui"),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    assert!(!outside.0.join(".leases").exists());
}

#[test]
fn symlink_lock_and_session_files_are_refused() {
    let home = Home::new();
    let outside = Home::new();
    let setup = SessionLease::acquire(&home.0, "setup", "tui").unwrap();
    drop(setup);
    let target = outside.0.join("target");
    fs::write(&target, b"untouched").unwrap();
    symlink(&target, home.0.join("sessions/.leases/session-a.lock")).unwrap();
    assert!(matches!(
        SessionLease::acquire(&home.0, "session-a", "tui"),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    let lease = SessionLease::acquire(&home.0, "session-b", "tui").unwrap();
    symlink(&target, session_path(&home.0, "session-b")).unwrap();
    assert!(matches!(
        lease.load(),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    assert!(matches!(
        lease.save(&sample("session-b", "changed")),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    assert_eq!(fs::read(&target).unwrap(), b"untouched");
}

#[test]
fn matching_identity_and_schema_are_required_for_load_and_save() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "tui").unwrap();
    lease.save(&sample("session-a", "original")).unwrap();
    let before = fs::read(session_path(&home.0, "session-a")).unwrap();
    assert!(matches!(
        lease.save(&sample("session-b", "wrong")),
        Err(SessionLeaseError::InvalidData(_))
    ));
    let mut unknown = sample("session-a", "wrong");
    unknown.schema = "orbit.session/unknown".into();
    assert!(matches!(
        lease.save(&unknown),
        Err(SessionLeaseError::InvalidData(_))
    ));
    assert_eq!(
        fs::read(session_path(&home.0, "session-a")).unwrap(),
        before
    );
    let wrong_id = serde_json::to_vec(&sample("other", "wrong")).unwrap();
    fs::write(session_path(&home.0, "session-a"), wrong_id).unwrap();
    assert!(matches!(
        lease.load(),
        Err(SessionLeaseError::InvalidData(_))
    ));
}

#[test]
fn legacy_schema_and_exact_effort_choice_remain_readable() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a.json", "tui").unwrap();
    let mut value = serde_json::to_value(sample("session-a", "model-a")).unwrap();
    value.as_object_mut().unwrap().remove("effort");
    value.as_object_mut().unwrap().remove("cost_microcents");
    fs::write(
        session_path(&home.0, "session-a"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        session_path(&home.0, "session-a"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let old = lease.load().unwrap();
    assert!(old.effort.is_none());
    assert_eq!(old.cost_microcents, 0);
    let choice = orbit_adapter::types::EffortSetting::Default;
    lease.save(&old.with_effort(Some(choice.clone()))).unwrap();
    assert_eq!(lease.load().unwrap().effort, Some(choice));
}

#[test]
fn leased_storage_is_private_and_path_replacement_preserves_saved_bytes() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "daemon").unwrap();
    lease.save(&sample("session-a", "original")).unwrap();
    for directory in [home.0.join("sessions"), home.0.join("sessions/.leases")] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for file in [
        session_path(&home.0, "session-a"),
        home.0.join("sessions/.leases/session-a.lock"),
    ] {
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let before = fs::read(session_path(&home.0, "session-a")).unwrap();
    fs::rename(home.0.join("sessions"), home.0.join("moved-sessions")).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(home.0.join("sessions"))
        .unwrap();
    assert!(matches!(
        lease.save(&sample("session-a", "new")),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    assert_eq!(
        fs::read(home.0.join("moved-sessions/session-a.json")).unwrap(),
        before
    );
    assert!(!session_path(&home.0, "session-a").exists());
}

#[test]
fn hard_linked_session_and_lock_files_are_refused() {
    let home = Home::new();
    let outside = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "tui").unwrap();
    lease.save(&sample("session-a", "original")).unwrap();
    fs::hard_link(
        session_path(&home.0, "session-a"),
        outside.0.join("session-link"),
    )
    .unwrap();
    assert!(matches!(
        lease.load(),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    assert!(matches!(
        lease.save(&sample("session-a", "new")),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    fs::hard_link(
        home.0.join("sessions/.leases/session-a.lock"),
        outside.0.join("lock-link"),
    )
    .unwrap();
    drop(lease);
    assert!(matches!(
        SessionLease::acquire(&home.0, "session-a", "daemon"),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    let saved: SessionFile =
        serde_json::from_slice(&fs::read(outside.0.join("session-link")).unwrap()).unwrap();
    assert_eq!(saved.model, "original");
}

#[test]
fn changed_private_directory_mode_refuses_access_and_preserves_data() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "tui").unwrap();
    lease.save(&sample("session-a", "original")).unwrap();
    let before = fs::read(session_path(&home.0, "session-a")).unwrap();
    fs::set_permissions(
        home.0.join("sessions/.leases"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(matches!(
        lease.load(),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    assert!(matches!(
        lease.save(&sample("session-a", "new")),
        Err(SessionLeaseError::UnsafePath(_))
    ));
    assert_eq!(
        fs::read(session_path(&home.0, "session-a")).unwrap(),
        before
    );
}

#[test]
fn oversized_saved_file_refuses_before_content_allocation() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "session-a", "tui").unwrap();
    lease.save(&sample("session-a", "original")).unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(session_path(&home.0, "session-a"))
        .unwrap();
    file.set_len(64 * 1024 * 1024 + 1).unwrap();
    assert!(matches!(
        lease.load(),
        Err(SessionLeaseError::InvalidData(_))
    ));
    assert!(matches!(
        lease.save(&sample("session-a", "new")),
        Err(SessionLeaseError::InvalidData(_))
    ));
    assert_eq!(
        fs::metadata(session_path(&home.0, "session-a"))
            .unwrap()
            .len(),
        64 * 1024 * 1024 + 1
    );
}

#[test]
fn optional_load_distinguishes_absence_and_create_only_preserves_the_first_snapshot() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "new-session", "headless").unwrap();
    assert!(lease.load_optional().unwrap().is_none());
    let first = sample("new-session", "first-model");
    lease.save_if_absent(&first).unwrap();
    let path = session_path(&home.0, "new-session");
    let before = fs::read(&path).unwrap();
    assert_eq!(lease.load_optional().unwrap().unwrap().model, "first-model");
    assert!(matches!(
        lease.save_if_absent(&sample("new-session", "replacement")),
        Err(SessionLeaseError::AlreadyExists { session_id }) if session_id == "new-session"
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    let metadata = fs::metadata(path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(fs::read_dir(home.0.join("sessions")).unwrap().count(), 2);
}

#[test]
fn optional_load_never_turns_present_invalid_data_into_absence() {
    let mut invalid_schema = sample("bad-session", "original");
    invalid_schema.schema = "unsupported.schema".into();
    let invalid_id = sample("different-session", "original");
    for bytes in [
        b"{broken".to_vec(),
        vec![0xff, 0xfe],
        serde_json::to_vec(&invalid_schema).unwrap(),
        serde_json::to_vec(&invalid_id).unwrap(),
    ] {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "bad-session", "headless").unwrap();
        lease.save(&sample("bad-session", "original")).unwrap();
        let path = session_path(&home.0, "bad-session");
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            lease.load_optional(),
            Err(SessionLeaseError::InvalidData(_))
        ));
        assert!(
            lease
                .save_if_absent(&sample("bad-session", "replacement"))
                .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn optional_load_and_create_only_refuse_unsafe_present_targets() {
    for kind in ["dangling-link", "hard-link", "socket", "public-file"] {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "unsafe-session", "headless").unwrap();
        let path = session_path(&home.0, "unsafe-session");
        let outside = home.0.join("outside");
        let socket = match kind {
            "dangling-link" => {
                symlink(&outside, &path).unwrap();
                None
            }
            "hard-link" => {
                lease.save(&sample("unsafe-session", "original")).unwrap();
                fs::hard_link(&path, &outside).unwrap();
                None
            }
            "socket" => Some(std::os::unix::net::UnixListener::bind(&path).unwrap()),
            "public-file" => {
                lease.save(&sample("unsafe-session", "original")).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                None
            }
            _ => unreachable!(),
        };
        let before = fs::symlink_metadata(&path).unwrap();
        assert!(
            lease.load_optional().is_err(),
            "unsafe target {kind} became absent"
        );
        assert!(
            lease
                .save_if_absent(&sample("unsafe-session", "replacement"))
                .is_err()
        );
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (after.ino(), after.mode(), after.nlink()),
            (before.ino(), before.mode(), before.nlink())
        );
        if kind == "hard-link" {
            assert_eq!(fs::read(&outside).unwrap(), fs::read(&path).unwrap());
        }
        if kind == "dangling-link" {
            assert!(!outside.exists());
        }
        drop(socket);
    }
}

#[test]
fn optional_absence_and_create_only_require_the_original_private_parent() {
    for replace in [false, true] {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "parent-session", "headless").unwrap();
        let sessions = home.0.join("sessions");
        let moved = home.0.join("original-sessions");
        fs::rename(&sessions, &moved).unwrap();
        if replace {
            fs::DirBuilder::new().mode(0o700).create(&sessions).unwrap();
        }
        assert!(lease.load_optional().is_err());
        assert!(
            lease
                .save_if_absent(&sample("parent-session", "replacement"))
                .is_err()
        );
        assert!(!moved.join("parent-session.json").exists());
        assert!(!sessions.join("parent-session.json").exists());
    }
}

#[test]
fn create_only_concurrent_writers_publish_one_complete_snapshot_without_clobbering() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "racing-session", "headless").unwrap();
    let barrier = std::sync::Barrier::new(4);
    let outcomes = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..4)
            .map(|index| {
                let lease = &lease;
                let barrier = &barrier;
                scope.spawn(move || {
                    let model = format!("complete-writer-{index}");
                    let candidate = sample("racing-session", &model);
                    barrier.wait();
                    (model, lease.save_if_absent(&candidate))
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    let winners: Vec<_> = outcomes
        .iter()
        .filter(|(_, result)| result.is_ok())
        .collect();
    assert_eq!(winners.len(), 1);
    for (_, result) in outcomes.iter().filter(|(_, result)| result.is_err()) {
        // The short link/unlink publication interval may also be safely refused
        // as a non-single-link target by a concurrent reader of the same lease.
        assert!(
            matches!(result, Err(SessionLeaseError::AlreadyExists { session_id }) if session_id == "racing-session")
                || matches!(result, Err(SessionLeaseError::UnsafePath(_)))
        );
    }
    assert_eq!(lease.load().unwrap().model, winners[0].0);
    let path = session_path(&home.0, "racing-session");
    let before = fs::read(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
    let entries: Vec<_> = fs::read_dir(home.0.join("sessions"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 2);
    assert!(
        !entries
            .iter()
            .any(|entry| entry.to_string_lossy().ends_with(".tmp"))
    );
    assert!(
        lease
            .save_if_absent(&sample("racing-session", "late-writer"))
            .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn create_only_validates_identity_schema_and_watermark_before_publication() {
    let home = Home::new();
    let lease = SessionLease::acquire(&home.0, "validated-session", "headless").unwrap();
    let mut bad_schema = sample("validated-session", "model");
    bad_schema.schema = "unknown".into();
    for candidate in [sample("wrong-session", "model"), bad_schema] {
        assert!(matches!(
            lease.save_if_absent(&candidate),
            Err(SessionLeaseError::InvalidData(_))
        ));
        assert!(lease.load_optional().unwrap().is_none());
    }
    let mut candidate = sample("validated-session", "model");
    candidate.accounting_watermark =
        Some(orbit_cli::session_accounting::SessionAccountingWatermark {
            owner_session_id: "foreign-session".into(),
            child_id: None,
            revision: 0,
            known_input_tokens: 0,
            known_output_tokens: 0,
            known_ordinary_microcents: 0,
            known_housekeeping_microcents: 0,
            full_cost_status: orbit_cli::session_accounting::FullCostStatus::Known,
        });
    assert!(matches!(
        lease.save_if_absent(&candidate),
        Err(SessionLeaseError::InvalidData(_))
    ));
    assert!(lease.load_optional().unwrap().is_none());
}
