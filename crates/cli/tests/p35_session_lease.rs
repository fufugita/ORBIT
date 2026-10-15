#![cfg(unix)]

use orbit_cli::sessions::{SessionFile, SessionLease, SessionLeaseError};
use std::fs;
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
