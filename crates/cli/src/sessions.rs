//! Session persistence for the interactive harness.
//!
//! Each REPL invocation writes its conversation transcript + cumulative usage
//! to `$ORBIT_HOME/sessions/<session_id>.json` after every turn (append-safe
//! rewrite of the JSON file). `/sessions` lists them; `/resume <id>` loads a
//! transcript back into the conversation so a session continues across
//! invocations.

use orbit_adapter::types::{ChatMessage, EffortSetting};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A persisted chat session (one file under `$ORBIT_HOME/sessions/`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFile {
    pub schema: String,
    pub session_id: String,
    pub model: String,
    pub gate: String,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<EffortSetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_origin: Option<crate::phase_routing::SelectionOrigin>,
    pub transcript: Vec<orbit_adapter::types::ChatMessage>,
    pub turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub cost_microcents: u64,
    pub updated_at: String,
}

impl SessionFile {
    pub fn to_transcript(&self) -> Vec<ChatMessage> {
        self.transcript.clone()
    }

    /// Build a session file from live REPL state.
    #[allow(clippy::too_many_arguments)] // session identity + counters
    pub fn from_chat(
        session_id: &str,
        model: &str,
        gate: &str,
        provider: &str,
        transcript: &[ChatMessage],
        turns: u64,
        input_tokens: u64,
        output_tokens: u64,
        cost_microcents: u64,
    ) -> Self {
        Self {
            schema: "orbit.session/v1".into(),
            session_id: session_id.into(),
            model: model.into(),
            gate: gate.into(),
            provider: provider.into(),
            effort: None,
            selection_origin: None,
            transcript: transcript.to_vec(),
            turns,
            input_tokens,
            output_tokens,
            cost_microcents,
            updated_at: crate::timestamp_now(),
        }
    }

    /// Retain the operator's selection, including an explicit model-default reset.
    pub fn with_effort(mut self, effort: Option<EffortSetting>) -> Self {
        self.effort = effort;
        self
    }

    pub fn with_selection_origin(mut self, origin: crate::phase_routing::SelectionOrigin) -> Self {
        self.selection_origin = Some(origin);
        self
    }
}

/// Unknown legacy or external provenance retains the saved identity as a pin.
pub fn model_origin(saved: Option<&SessionFile>) -> crate::phase_routing::SelectionOrigin {
    crate::phase_routing::SelectionOrigin::restored(saved.and_then(|file| file.selection_origin))
}

/// Read provenance through checked descriptors without taking a second live lease.
pub fn read_selection_origin(
    home: &Path,
    id: &str,
) -> Result<crate::phase_routing::SelectionOrigin, String> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid session identity".into());
    }
    let path = sessions_dir(home).join(format!("{id}.json"));
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(model_origin(None));
        }
        Err(error) => return Err(error.kind().to_string()),
        Ok(_) => {}
    }
    let directory = crate::customization::Directory::open(&sessions_dir(home), true)
        .map_err(|e| e.to_string())?;
    let bytes = crate::customization::read_regular(
        &directory
            .io()
            .map_err(|e| e.to_string())?
            .join(format!("{id}.json")),
        64 * 1024 * 1024,
        true,
    )
    .map_err(|e| e.to_string())?;
    let saved: SessionFile =
        serde_json::from_slice(&bytes).map_err(|_| "invalid saved session provenance")?;
    if saved.session_id != id {
        return Err("saved session identity mismatch".into());
    }
    directory.check().map_err(|e| e.to_string())?;
    Ok(model_origin(Some(&saved)))
}

/// Startup choices outrank saved choices. A different selected model must use
/// its own defaults rather than inheriting a prior model's explicit setting.
pub fn startup_effort(
    selected: Option<EffortSetting>,
    saved: Option<&SessionFile>,
    model: &str,
    provider: &str,
) -> Option<EffortSetting> {
    selected.or_else(|| {
        saved
            .filter(|s| s.model == model && s.provider == provider)
            .and_then(|s| s.effort.clone())
    })
}

/// The sessions directory under a home dir.
pub fn sessions_dir(home: &Path) -> PathBuf {
    home.join("sessions")
}

/// Refusal reasons for a live session ownership claim.
#[derive(Debug, thiserror::Error)]
pub enum SessionLeaseError {
    #[error("session {session_id} is already owned by another live frontend")]
    Busy { session_id: String },
    #[error("invalid session identity: {0}")]
    InvalidIdentity(String),
    #[error("unsafe session storage: {0}")]
    UnsafePath(String),
    #[error("invalid saved session: {0}")]
    InvalidData(String),
    #[error("session storage IO: {0}")]
    Io(String),
    #[error("session snapshot was published, but durable storage could not be confirmed: {0}")]
    PublicationUncertain(String),
}

/// An exclusive, non-cloneable ownership claim held for a live session's lifetime.
/// The lock inode remains on disk after release; PID metadata is descriptive only.
pub struct SessionLease {
    session_id: String,
    kind: String,
    #[cfg(unix)]
    storage: leased_storage::Storage,
}

impl std::fmt::Debug for SessionLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLease")
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl SessionLease {
    pub fn acquire(home: &Path, id: &str, kind: &str) -> Result<Self, SessionLeaseError> {
        let id = id.strip_suffix(".json").unwrap_or(id);
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(SessionLeaseError::InvalidIdentity(
                "use 1–128 ASCII letters, digits, '-' or '_'".into(),
            ));
        }
        if kind.is_empty()
            || kind.len() > 64
            || !kind
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(SessionLeaseError::InvalidIdentity(
                "invalid owner kind".into(),
            ));
        }
        #[cfg(unix)]
        {
            Ok(Self {
                session_id: id.to_owned(),
                kind: kind.to_owned(),
                storage: leased_storage::Storage::acquire(home, id, kind)?,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = home;
            Err(SessionLeaseError::Io(
                "live session ownership requires Unix".into(),
            ))
        }
    }

    /// Acquire and validate a candidate while the caller still holds its old lease.
    /// Any error drops only the candidate; callers replace live state after success.
    pub fn acquire_and_load(
        home: &Path,
        id: &str,
        kind: &str,
    ) -> Result<(Self, SessionFile), SessionLeaseError> {
        let lease = Self::acquire(home, id, kind)?;
        let saved = lease.load()?;
        Ok((lease, saved))
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Absolute home identity captured when this live ownership claim was acquired.
    pub fn home(&self) -> &Path {
        #[cfg(unix)]
        {
            self.storage.home()
        }
        #[cfg(not(unix))]
        {
            unreachable!("live session leases cannot be acquired on this platform")
        }
    }

    pub fn load(&self) -> Result<SessionFile, SessionLeaseError> {
        #[cfg(unix)]
        {
            let raw = self.storage.load(&self.session_id)?;
            let session: SessionFile = serde_json::from_slice(&raw)
                .map_err(|e| SessionLeaseError::InvalidData(e.to_string()))?;
            self.validate_session(&session)?;
            Ok(session)
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "live session ownership requires Unix".into(),
            ))
        }
    }

    pub fn save(&self, session: &SessionFile) -> Result<(), SessionLeaseError> {
        self.validate_session(session)?;
        #[cfg(unix)]
        {
            let raw = serde_json::to_vec_pretty(session)
                .map_err(|e| SessionLeaseError::InvalidData(e.to_string()))?;
            self.storage.save(&self.session_id, &raw)
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "live session ownership requires Unix".into(),
            ))
        }
    }

    fn validate_session(&self, session: &SessionFile) -> Result<(), SessionLeaseError> {
        if session.session_id != self.session_id {
            return Err(SessionLeaseError::InvalidData(
                "saved identity differs from held lease".into(),
            ));
        }
        if session.schema != "orbit.session/v1" {
            return Err(SessionLeaseError::InvalidData(
                "unsupported session schema".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
#[allow(unsafe_code)] // FD-relative Unix storage operations are isolated here.
mod leased_storage {
    use super::SessionLeaseError;
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};

    const MAX_SESSION_BYTES: u64 = 64 * 1024 * 1024;

    pub(super) struct Storage {
        path: PathBuf,
        home: File,
        sessions: File,
        leases: File,
        lock: File,
        #[cfg(test)]
        fail_before_rename: std::cell::Cell<bool>,
        #[cfg(test)]
        fail_directory_sync: std::cell::Cell<bool>,
    }

    fn io(error: std::io::Error) -> SessionLeaseError {
        SessionLeaseError::Io(error.to_string())
    }

    fn name(value: &OsStr) -> Result<CString, SessionLeaseError> {
        CString::new(value.as_bytes())
            .map_err(|_| SessionLeaseError::UnsafePath("NUL in path".into()))
    }

    fn open_at(dir: &File, value: &OsStr, flags: i32) -> Result<File, std::io::Error> {
        let value = CString::new(value.as_bytes())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: the directory FD and terminated filename live through this call.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                value.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a successful openat returns an owned FD.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn path_error(error: std::io::Error) -> SessionLeaseError {
        match error.raw_os_error() {
            Some(libc::ELOOP | libc::ENOTDIR) => {
                SessionLeaseError::UnsafePath("symlink or wrong path type".into())
            }
            _ => io(error),
        }
    }

    fn directory_at(dir: &File, value: &OsStr, create: bool) -> Result<File, SessionLeaseError> {
        match open_at(dir, value, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(file) => Ok(file),
            Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => {
                let value_c = name(value)?;
                // SAFETY: same owned directory and terminated filename as openat.
                let made = unsafe { libc::mkdirat(dir.as_raw_fd(), value_c.as_ptr(), 0o700) };
                if made < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(io(error));
                    }
                }
                let file =
                    open_at(dir, value, libc::O_RDONLY | libc::O_DIRECTORY).map_err(path_error)?;
                dir.sync_all().map_err(io)?;
                Ok(file)
            }
            Err(e) => Err(path_error(e)),
        }
    }

    fn home_directory(path: &Path, create: bool) -> Result<File, SessionLeaseError> {
        let mut directory = File::open(if path.is_absolute() { "/" } else { "." }).map_err(io)?;
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(value) => directory = directory_at(&directory, value, create)?,
                _ => {
                    return Err(SessionLeaseError::UnsafePath(
                        "parent traversal in home path".into(),
                    ));
                }
            }
        }
        let metadata = directory.metadata().map_err(io)?;
        // SAFETY: geteuid has no arguments or pointers.
        let owner = unsafe { libc::geteuid() };
        if metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
            return Err(SessionLeaseError::UnsafePath(
                "home must be owned and not writable by other users".into(),
            ));
        }
        Ok(directory)
    }

    fn private_directory(file: &File) -> Result<(), SessionLeaseError> {
        let metadata = file.metadata().map_err(io)?;
        // SAFETY: geteuid has no arguments or pointers.
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(SessionLeaseError::UnsafePath(
                "directory is not owned by this user".into(),
            ));
        }
        // SAFETY: fchmod operates on this owned directory FD.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn private_file(file: &File, max_bytes: u64) -> Result<(), SessionLeaseError> {
        let metadata = file.metadata().map_err(io)?;
        // SAFETY: geteuid has no arguments or pointers.
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(SessionLeaseError::UnsafePath(
                "file must be private, regular, owned and singly linked".into(),
            ));
        }
        if metadata.len() > max_bytes {
            return Err(SessionLeaseError::InvalidData(
                "file exceeds storage byte bound".into(),
            ));
        }
        Ok(())
    }

    fn same_inode(first: &File, second: &File) -> Result<bool, SessionLeaseError> {
        let first = first.metadata().map_err(io)?;
        let second = second.metadata().map_err(io)?;
        Ok(first.dev() == second.dev() && first.ino() == second.ino())
    }

    impl Storage {
        pub(super) fn home(&self) -> &Path {
            &self.path
        }

        pub(super) fn acquire(
            path: &Path,
            id: &str,
            kind: &str,
        ) -> Result<Self, SessionLeaseError> {
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir().map_err(io)?.join(path)
            };
            let home = home_directory(&path, true)?;
            let sessions = directory_at(&home, OsStr::new("sessions"), true)?;
            private_directory(&sessions)?;
            let leases = directory_at(&sessions, OsStr::new(".leases"), true)?;
            private_directory(&leases)?;
            let mut lock = open_at(
                &leases,
                OsStr::new(&format!("{id}.lock")),
                libc::O_RDWR | libc::O_CREAT,
            )
            .map_err(path_error)?;
            private_file(&lock, 16 * 1024)?;
            // SAFETY: lock owns the FD for the lifetime of this storage handle.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
                let error = std::io::Error::last_os_error();
                return if error.kind() == std::io::ErrorKind::WouldBlock {
                    Err(SessionLeaseError::Busy {
                        session_id: id.into(),
                    })
                } else {
                    Err(io(error))
                };
            }
            let storage = Self {
                path,
                home,
                sessions,
                leases,
                lock: lock.try_clone().map_err(io)?,
                #[cfg(test)]
                fail_before_rename: std::cell::Cell::new(false),
                #[cfg(test)]
                fail_directory_sync: std::cell::Cell::new(false),
            };
            storage.verify_location(id)?;
            let metadata =
                serde_json::json!({"session_id":id,"kind":kind,"pid":std::process::id()});
            let bytes = serde_json::to_vec(&metadata)
                .map_err(|e| SessionLeaseError::InvalidData(e.to_string()))?;
            lock.set_len(0).map_err(io)?;
            lock.seek(SeekFrom::Start(0)).map_err(io)?;
            lock.write_all(&bytes).map_err(io)?;
            lock.sync_all().map_err(io)?;
            storage.leases.sync_all().map_err(io)?;
            Ok(storage)
        }

        fn verify_location(&self, id: &str) -> Result<(), SessionLeaseError> {
            let home = home_directory(&self.path, false)?;
            let sessions = directory_at(&home, OsStr::new("sessions"), false)?;
            if !same_inode(&home, &self.home)? || !same_inode(&sessions, &self.sessions)? {
                return Err(SessionLeaseError::UnsafePath(
                    "storage path changed while session was owned".into(),
                ));
            }
            let leases = directory_at(&sessions, OsStr::new(".leases"), false)?;
            let lock = open_at(&leases, OsStr::new(&format!("{id}.lock")), libc::O_RDONLY)
                .map_err(path_error)?;
            private_file(&lock, 16 * 1024)?;
            for directory in [&sessions, &leases] {
                let metadata = directory.metadata().map_err(io)?;
                if metadata.mode() & 0o777 != 0o700 {
                    return Err(SessionLeaseError::UnsafePath(
                        "storage directory is no longer private".into(),
                    ));
                }
            }
            if !same_inode(&leases, &self.leases)? || !same_inode(&lock, &self.lock)? {
                return Err(SessionLeaseError::UnsafePath(
                    "storage path changed while session was owned".into(),
                ));
            }
            Ok(())
        }

        pub(super) fn load(&self, id: &str) -> Result<Vec<u8>, SessionLeaseError> {
            self.verify_location(id)?;
            let file = open_at(
                &self.sessions,
                OsStr::new(&format!("{id}.json")),
                libc::O_RDONLY,
            )
            .map_err(path_error)?;
            private_file(&file, MAX_SESSION_BYTES)?;
            let mut raw = Vec::new();
            file.take(MAX_SESSION_BYTES + 1)
                .read_to_end(&mut raw)
                .map_err(io)?;
            if raw.len() as u64 > MAX_SESSION_BYTES {
                return Err(SessionLeaseError::InvalidData(
                    "session exceeds storage byte bound".into(),
                ));
            }
            Ok(raw)
        }

        pub(super) fn save(&self, id: &str, raw: &[u8]) -> Result<(), SessionLeaseError> {
            if raw.len() as u64 > MAX_SESSION_BYTES {
                return Err(SessionLeaseError::InvalidData(
                    "session exceeds storage byte bound".into(),
                ));
            }
            self.verify_location(id)?;
            let target = format!("{id}.json");
            match open_at(&self.sessions, OsStr::new(&target), libc::O_RDONLY) {
                Ok(file) => private_file(&file, MAX_SESSION_BYTES)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(path_error(error)),
            }
            let temporary = format!(".{id}-{}.tmp", ulid::Ulid::new());
            let mut file = open_at(
                &self.sessions,
                OsStr::new(&temporary),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(path_error)?;
            let result = (|| {
                file.write_all(raw).map_err(io)?;
                file.sync_all().map_err(io)?;
                self.verify_location(id)?;
                #[cfg(test)]
                if self.fail_before_rename.replace(false) {
                    return Err(SessionLeaseError::Io(
                        "injected pre-publication failure".into(),
                    ));
                }
                let temporary = name(OsStr::new(&temporary))?;
                let target = name(OsStr::new(&target))?;
                // SAFETY: both names are bounded local names under the same held directory FD.
                if unsafe {
                    libc::renameat(
                        self.sessions.as_raw_fd(),
                        temporary.as_ptr(),
                        self.sessions.as_raw_fd(),
                        target.as_ptr(),
                    )
                } < 0
                {
                    return Err(io(std::io::Error::last_os_error()));
                }
                #[cfg(test)]
                if self.fail_directory_sync.replace(false) {
                    return Err(SessionLeaseError::PublicationUncertain(
                        "injected post-rename directory sync failure".into(),
                    ));
                }
                self.sessions
                    .sync_all()
                    .map_err(|e| SessionLeaseError::PublicationUncertain(e.to_string()))
            })();
            if result.is_err() {
                let temporary = name(OsStr::new(&temporary))?;
                // SAFETY: cleanup removes only the unique temp entry this operation created.
                unsafe {
                    libc::unlinkat(self.sessions.as_raw_fd(), temporary.as_ptr(), 0);
                }
            }
            result
        }

        #[cfg(test)]
        pub(super) fn inject_prepublication_failure(&self) {
            self.fail_before_rename.set(true);
        }

        #[cfg(test)]
        pub(super) fn inject_directory_sync_failure(&self) {
            self.fail_directory_sync.set(true);
        }
    }
}

#[cfg(all(test, unix))]
mod lease_durability_tests {
    use super::{SessionFile, SessionLease, SessionLeaseError};

    fn sample(model: &str) -> SessionFile {
        SessionFile::from_chat(
            "saved",
            model,
            "http://127.0.0.1:1",
            "fixture",
            &[],
            1,
            2,
            3,
            4,
        )
    }

    #[test]
    fn prepublication_failure_preserves_bytes_and_removes_temporary_file() {
        let home = std::env::temp_dir().join(format!("orbit-lease-sync-{}", ulid::Ulid::new()));
        let lease = SessionLease::acquire(&home, "saved", "fixture").unwrap();
        lease.save(&sample("original")).unwrap();
        let path = home.join("sessions/saved.json");
        let before = std::fs::read(&path).unwrap();
        lease.storage.inject_prepublication_failure();
        assert!(matches!(
            lease.save(&sample("changed")),
            Err(SessionLeaseError::Io(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(lease.load().unwrap().model, "original");
        assert!(
            std::fs::read_dir(home.join("sessions"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
        drop(lease);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn post_rename_sync_failure_reports_published_uncertain_bytes() {
        let home = std::env::temp_dir().join(format!("orbit-lease-sync-{}", ulid::Ulid::new()));
        let lease = SessionLease::acquire(&home, "saved", "fixture").unwrap();
        lease.save(&sample("original")).unwrap();
        let path = home.join("sessions/saved.json");
        let before = std::fs::read(&path).unwrap();
        lease.storage.inject_directory_sync_failure();
        let failure = lease.save(&sample("changed")).unwrap_err();
        assert!(matches!(
            failure,
            SessionLeaseError::PublicationUncertain(_)
        ));
        assert!(failure.to_string().contains("was published"));
        assert_ne!(std::fs::read(&path).unwrap(), before);
        assert_eq!(lease.load().unwrap().model, "changed");
        assert!(
            std::fs::read_dir(home.join("sessions"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
        drop(lease);
        std::fs::remove_dir_all(home).unwrap();
    }
}

/// Save a session (rewrite the JSON file; append-safe by write-temp+rename).
///
/// Security posture (DR-06 §1.2, same as the ledger writer): sessions dir
/// 0700, session files 0600. A session JSON carries the full transcript —
/// prompts, tool results, pasted text — and must not leak to local users
/// through the default umask. The modes are re-forced on every save so a
/// tree left loose by an older build is corrected on first touch.
pub fn save_session(home: &Path, s: &SessionFile) -> Result<(), String> {
    let dir = sessions_dir(home);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod 0700 {dir:?}: {e}"))?;
    }
    let json = serde_json::to_string_pretty(s).map_err(|e| format!("serialize: {e}"))?;
    let path = dir.join(format!("{}.json", s.session_id));
    let tmp = dir.join(format!(".{}.tmp", s.session_id));
    std::fs::write(&tmp, json).map_err(|e| format!("write {tmp:?}: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename -> {path:?}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {path:?}: {e}"))?;
    }
    Ok(())
}

/// Load a session by id (without the `.json` suffix, or with).
pub fn load_session(home: &Path, session_id: &str) -> Result<SessionFile, String> {
    let id = session_id.trim_end_matches(".json");
    let path = sessions_dir(home).join(format!("{id}.json"));
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {path:?}: {e}"))
}

/// Fork a session: copy its history into a NEW session id and save it
/// (roadmap §Sessions: `--fork-session` / `/branch`). The original is
/// untouched; the fork carries its own identity and a fresh updated_at.
pub fn fork_session(home: &Path, session_id: &str) -> Result<SessionFile, String> {
    let mut src = load_session(home, session_id)?;
    let new_id = orbit_gateway::new_session_id();
    src.session_id = new_id.clone();
    src.updated_at = crate::timestamp_now();
    // The fork's JSONL transcript (if one exists) is copied too, so
    // `--resume <fork>` and the TUI's event-sourced view agree with the
    // JSON file.
    let jsonl_src = home.join("projects").join(format!("{session_id}.jsonl"));
    if jsonl_src.exists() {
        let jsonl_dst = home.join("projects").join(format!("{new_id}.jsonl"));
        std::fs::copy(&jsonl_src, &jsonl_dst).map_err(|e| format!("copy transcript: {e}"))?;
    }
    save_session(home, &src)?;
    Ok(src)
}

/// List persisted sessions, most-recently-updated first.
pub fn list_sessions(home: &Path) -> Result<Vec<SessionFile>, String> {
    let dir = sessions_dir(home);
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read {dir:?}: {e}"))? {
        let entry = entry.map_err(|e| format!("entry: {e}"))?;
        if entry
            .path()
            .extension()
            .map(|e| e == "json")
            .unwrap_or(false)
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let id = name.trim_end_matches(".json");
            if let Ok(s) = load_session(home, id) {
                out.push(s);
            }
        }
    }
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_adapter::types::ChatRole;

    fn test_home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orbit-sessions-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample(id: &str) -> SessionFile {
        SessionFile::from_chat(
            id,
            "model-a",
            "http://127.0.0.1:8088",
            "mock",
            &[
                ChatMessage {
                    role: ChatRole::User,
                    content: "hello".into(),
                    tool_calls: None,
                    tool_call_id: None,
                    tool_result: None,
                    blocks: None,
                    origin_model: None,
                    origin_provider: None,
                },
                ChatMessage {
                    role: ChatRole::Assistant,
                    content: "world".into(),
                    tool_calls: None,
                    tool_call_id: None,
                    tool_result: None,
                    blocks: None,
                    origin_model: None,
                    origin_provider: None,
                },
            ],
            1,
            2,
            3,
            42,
        )
    }

    #[test]
    fn save_then_load_roundtrip() {
        let home = test_home("roundtrip");
        let s = sample("session-1");
        save_session(&home, &s).unwrap();
        let loaded = load_session(&home, "session-1").unwrap();
        assert_eq!(loaded.session_id, "session-1");
        assert_eq!(loaded.turns, 1);
        assert_eq!(loaded.input_tokens, 2);
        assert_eq!(loaded.to_transcript().len(), 2);
    }

    #[test]
    fn effort_selection_reset_and_legacy_sessions_remain_distinct() {
        use orbit_adapter::types::EffortValue;
        let home = test_home("effort-selection");
        for choice in [
            EffortSetting::Default,
            EffortSetting::Value(EffortValue::Level("high".into())),
        ] {
            let session = sample("selection").with_effort(Some(choice.clone()));
            save_session(&home, &session).unwrap();
            assert_eq!(
                load_session(&home, "selection").unwrap().effort,
                Some(choice)
            );
            let fork = fork_session(&home, "selection").unwrap();
            assert_eq!(fork.effort, session.effort);
        }
        let mut legacy = serde_json::to_value(sample("legacy")).unwrap();
        legacy.as_object_mut().unwrap().remove("effort");
        assert!(
            serde_json::from_value::<SessionFile>(legacy)
                .unwrap()
                .effort
                .is_none()
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn startup_reset_wins_saved_value_and_mismatched_model_drops_saved_selection() {
        use orbit_adapter::types::EffortValue;
        let saved = sample("saved").with_effort(Some(EffortSetting::Value(EffortValue::Level(
            "high".into(),
        ))));
        assert_eq!(
            startup_effort(
                Some(EffortSetting::Default),
                Some(&saved),
                "model-a",
                "mock"
            ),
            Some(EffortSetting::Default)
        );
        assert_eq!(
            startup_effort(None, Some(&saved), "model-a", "mock"),
            saved.effort
        );
        assert_eq!(startup_effort(None, Some(&saved), "model-b", "mock"), None);
        assert_eq!(
            startup_effort(None, Some(&saved), "model-a", "other-provider"),
            None
        );
    }

    #[test]
    fn list_sessions_reads_all_json_files() {
        let home = test_home("list");
        save_session(&home, &sample("session-1")).unwrap();
        save_session(&home, &sample("session-2")).unwrap();
        let list = list_sessions(&home).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|s| s.session_id == "session-1"));
        assert!(list.iter().any(|s| s.session_id == "session-2"));
    }

    #[test]
    fn tool_message_roundtrips() {
        let mut s = sample("session-tool");
        s.transcript.push(ChatMessage {
            role: ChatRole::Tool,
            content: "{\"ok\":true}".into(),
            tool_calls: None,
            tool_call_id: Some("call-1".into()),
            tool_result: Some("{\"ok\":true}".into()),
            blocks: None,
            origin_model: None,
            origin_provider: None,
        });
        let restored = s.to_transcript();
        assert_eq!(restored.len(), 3);
        assert_eq!(restored[2].role, ChatRole::Tool);
        assert_eq!(restored[2].tool_call_id.as_deref(), Some("call-1"));
    }

    #[test]
    fn fork_copies_history_under_a_new_id_and_leaves_the_original() {
        let home = std::env::temp_dir().join(format!("orbit-fork-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&home);
        let src = sample("session-src");
        save_session(&home, &src).unwrap();

        let fork = fork_session(&home, "session-src").unwrap();
        assert_ne!(fork.session_id, "session-src");
        assert_eq!(fork.transcript.len(), src.transcript.len());
        assert_eq!(fork.model, src.model);

        // The original is untouched and both load independently.
        let back = load_session(&home, "session-src").unwrap();
        assert_eq!(back.transcript.len(), src.transcript.len());
        let fork_loaded = load_session(&home, &fork.session_id).unwrap();
        assert_eq!(fork_loaded.transcript.len(), src.transcript.len());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Security (DR-06 §1.2): a session JSON carries the full transcript,
    /// so the sessions dir is 0700 and the file 0600. A loose tree left by
    /// an older build is tightened on the next save.
    #[cfg(unix)]
    #[test]
    fn session_files_and_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let home = test_home("perms");
        let dir = sessions_dir(&home);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A pre-existing loose file that save must tighten.
        let loose = dir.join("session-old.json");
        std::fs::write(&loose, "{}").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();

        save_session(&home, &sample("session-perms")).unwrap();

        let d = std::fs::metadata(&dir).unwrap();
        assert_eq!(
            d.permissions().mode() & 0o777,
            0o700,
            "sessions dir must be 0700"
        );
        let f = std::fs::metadata(dir.join("session-perms.json")).unwrap();
        assert_eq!(
            f.permissions().mode() & 0o777,
            0o600,
            "session file must be 0600"
        );

        // The stale loose file is not saved-over, but the dir is now 0700,
        // so it is unreachable to other users regardless of its own mode.
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn fork_copies_the_jsonl_transcript_when_one_exists() {
        let home = std::env::temp_dir().join(format!("orbit-fork2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(home.join("projects"));
        // No JSON session file: fork reports the failure honestly.
        assert!(fork_session(&home, "session-jsonl").is_err());
        // With one, the JSONL sidecar is copied alongside.
        let _ = std::fs::create_dir_all(home.join("sessions"));
        std::fs::write(
            home.join("projects/session-jsonl.jsonl"),
            "{\"kind\":\"user_prompt\",\"text\":\"hi\"}\n",
        )
        .unwrap();
        save_session(&home, &sample("session-jsonl")).unwrap();
        let fork = fork_session(&home, "session-jsonl").unwrap();
        let copied = home
            .join("projects")
            .join(format!("{}.jsonl", fork.session_id));
        assert!(copied.exists(), "the fork's JSONL transcript is copied");
        let _ = std::fs::remove_dir_all(&home);
    }
}
