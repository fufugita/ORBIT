//! Durable, session-owned agent conversations and explicitly delivered messages.
//!
//! A run lease prevents two processes from executing one agent at once. A separate
//! short state lock allows messages to arrive while that lease is held. No method
//! invokes a provider, restores permissions, or schedules background execution.

use orbit_adapter::types::{ChatMessage, EffortSetting};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use ulid::Ulid;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

const SCHEMA: &str = "orbit.agent.v1";
const MAX_AGENTS: usize = 64;
const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 256;
const MAX_NAME_CHARS: usize = 64;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_INBOX_MESSAGES: usize = 64;
const MAX_INBOX_BYTES: usize = 512 * 1024;
const STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Idle,
    Running,
    Completed,
    Cancelled,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMessage {
    pub message_id: String,
    pub sender_agent_id: Option<String>,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshot {
    pub agent_id: String,
    pub owner_session_id: String,
    pub parent_agent_id: Option<String>,
    pub name: Option<String>,
    pub agent_type: String,
    /// Opaque, fully qualified model specification; the runtime resolves it.
    pub model: String,
    #[serde(default)]
    pub effort: Option<EffortSetting>,
    pub transcript: Vec<ChatMessage>,
    pub report: String,
    pub turns: u64,
    pub status: AgentStatus,
    pub active_run_id: Option<String>,
    pub inbox: Vec<AgentMessage>,
}

/// Discovery metadata; transcripts and message contents are deliberately absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    pub agent_id: String,
    pub owner_session_id: String,
    pub parent_agent_id: Option<String>,
    pub name: Option<String>,
    pub agent_type: String,
    pub model: String,
    #[serde(default)]
    pub effort: Option<EffortSetting>,
    pub status: AgentStatus,
    pub turns: u64,
    pub pending_messages: usize,
    pub active_run_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSnapshot {
    schema: String,
    snapshot: AgentSnapshot,
}

#[derive(Serialize)]
struct StoredSnapshotRef<'a> {
    schema: &'static str,
    snapshot: &'a AgentSnapshot,
}

#[derive(Debug, Clone)]
pub struct AgentStore {
    directory: PathBuf,
    owner_session_id: String,
}

/// A lease on one explicit execution. Dropping an unfinished run preserves its
/// inbox and best-effort marks it interrupted without waiting for the state lock.
#[derive(Debug)]
pub struct AgentRun {
    store: AgentStore,
    snapshot: AgentSnapshot,
    lease: Option<File>,
    interrupted_previous_run: bool,
    finished: bool,
}

impl AgentStore {
    pub fn new(home: &Path, owner_session_id: &str) -> Result<Self, String> {
        validate_field(owner_session_id, "owner session ID")?;
        let home = std::path::absolute(home).map_err(|e| format!("agent home: {e}"))?;
        reject_symlink_ancestors(&home)?;
        create_directory_tree(&home)?;
        reject_symlink_ancestors(&home)?;
        let agents = home.join("agents");
        private_directory(&agents)?;
        let directory = agents.join(hex::encode(Sha256::digest(owner_session_id.as_bytes())));
        private_directory(&directory)?;
        let store = Self {
            directory,
            owner_session_id: owner_session_id.to_owned(),
        };
        // Keep this inode stable across snapshot replacements and process restarts.
        let _ = store.open_lock(".state.lock")?;
        Ok(store)
    }

    pub fn create(
        &self,
        agent_type: &str,
        name: Option<&str>,
        model: &str,
        parent_agent_id: Option<&str>,
    ) -> Result<AgentSnapshot, String> {
        self.create_with_effort(agent_type, name, model, None, parent_agent_id)
    }

    pub fn create_with_effort(
        &self,
        agent_type: &str,
        name: Option<&str>,
        model: &str,
        effort: Option<EffortSetting>,
        parent_agent_id: Option<&str>,
    ) -> Result<AgentSnapshot, String> {
        validate_field(agent_type, "agent type")?;
        validate_field(model, "model")?;
        validate_name(name)?;
        if let Some(parent) = parent_agent_id {
            validate_id(parent, "parent agent ID")?;
        }
        let _state = self.lock_state(STATE_LOCK_TIMEOUT)?;
        if self.record_ids()?.len() >= MAX_AGENTS {
            return Err("agent limit reached (64 per owner)".to_owned());
        }
        if let Some(parent) = parent_agent_id {
            self.load_unlocked(parent)?;
        }
        let snapshot = AgentSnapshot {
            agent_id: Ulid::new().to_string(),
            owner_session_id: self.owner_session_id.clone(),
            parent_agent_id: parent_agent_id.map(str::to_owned),
            name: name.map(str::to_owned),
            agent_type: agent_type.to_owned(),
            model: model.to_owned(),
            effort,
            transcript: Vec::new(),
            report: String::new(),
            turns: 0,
            status: AgentStatus::Idle,
            active_run_id: None,
            inbox: Vec::new(),
        };
        self.save_unlocked(&snapshot)?;
        Ok(snapshot)
    }

    /// Return at most 64 agents sorted by their stable ID.
    pub fn list(&self) -> Result<Vec<AgentSummary>, String> {
        let _state = self.lock_state(STATE_LOCK_TIMEOUT)?;
        self.record_ids()?
            .into_iter()
            .map(|id| {
                let snapshot = self.load_unlocked(&id)?;
                Ok(AgentSummary {
                    agent_id: snapshot.agent_id,
                    owner_session_id: snapshot.owner_session_id,
                    parent_agent_id: snapshot.parent_agent_id,
                    name: snapshot.name,
                    agent_type: snapshot.agent_type,
                    model: snapshot.model,
                    effort: snapshot.effort,
                    status: snapshot.status,
                    turns: snapshot.turns,
                    pending_messages: snapshot.inbox.len(),
                    active_run_id: snapshot.active_run_id,
                })
            })
            .collect()
    }

    pub fn load(&self, id: &str) -> Result<AgentSnapshot, String> {
        validate_id(id, "agent ID")?;
        let _state = self.lock_state(STATE_LOCK_TIMEOUT)?;
        self.load_unlocked(id)
    }

    /// Claim an explicit run without waiting on another run. Inbox messages are
    /// captured but remain durable until `finish` commits the updated transcript.
    pub fn begin(&self, id: &str, model_override: Option<&str>) -> Result<AgentRun, String> {
        self.begin_resolved(id, |snapshot| {
            let model = model_override.unwrap_or(&snapshot.model).to_owned();
            let effort = if model == snapshot.model {
                snapshot.effort.clone()
            } else {
                None
            };
            Ok((model, effort))
        })
    }

    /// Resolve and validate against the leased snapshot before marking a run started.
    /// The resolver performs no provider calls and cannot acknowledge the inbox.
    pub fn begin_resolved(
        &self,
        id: &str,
        resolve: impl FnOnce(&AgentSnapshot) -> Result<(String, Option<EffortSetting>), String>,
    ) -> Result<AgentRun, String> {
        validate_id(id, "agent ID")?;
        let _state = self.lock_state(STATE_LOCK_TIMEOUT)?;
        let mut snapshot = self.load_unlocked(id)?;
        let lease = self.open_lock(&format!("{id}.run.lock"))?;
        match lease.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err("agent already has an active run".to_owned());
            }
            Err(TryLockError::Error(e)) => return Err(format!("acquire agent run lease: {e}")),
        }
        let interrupted_previous_run = matches!(
            snapshot.status,
            AgentStatus::Running | AgentStatus::Interrupted
        );
        let (model, effort) = resolve(&snapshot)?;
        validate_field(&model, "model")?;
        if let Some(EffortSetting::Value(value)) = &effort {
            value.validate()?;
        }
        snapshot.model = model;
        snapshot.effort = effort;
        snapshot.status = AgentStatus::Running;
        snapshot.active_run_id = Some(Ulid::new().to_string());
        self.save_unlocked(&snapshot)?;
        Ok(AgentRun {
            store: self.clone(),
            snapshot,
            lease: Some(lease),
            interrupted_previous_run,
            finished: false,
        })
    }

    /// Queue a message only. Delivery occurs on a later explicit `begin`.
    pub fn enqueue(
        &self,
        id: &str,
        text: &str,
        sender_agent_id: Option<&str>,
    ) -> Result<AgentMessage, String> {
        validate_id(id, "agent ID")?;
        validate_message_text(text)?;
        if let Some(sender) = sender_agent_id {
            validate_id(sender, "sender agent ID")?;
        }
        let _state = self.lock_state(STATE_LOCK_TIMEOUT)?;
        let mut snapshot = self.load_unlocked(id)?;
        if let Some(sender) = sender_agent_id {
            self.load_unlocked(sender)?;
        }
        if snapshot.inbox.len() >= MAX_INBOX_MESSAGES
            || inbox_bytes(&snapshot.inbox).saturating_add(text.len()) > MAX_INBOX_BYTES
        {
            return Err("agent inbox limit reached (64 messages or 512 KiB of text)".to_owned());
        }
        let message = AgentMessage {
            message_id: Ulid::new().to_string(),
            sender_agent_id: sender_agent_id.map(str::to_owned),
            text: text.to_owned(),
        };
        snapshot.inbox.push(message.clone());
        self.save_unlocked(&snapshot)?;
        Ok(message)
    }

    fn open_lock(&self, name: &str) -> Result<File, String> {
        reject_symlink_ancestors(&self.directory)?;
        open_private_file(&self.directory.join(name), true, false)
    }

    fn lock_state(&self, timeout: Duration) -> Result<File, String> {
        let file = self.open_lock(".state.lock")?;
        let start = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(TryLockError::WouldBlock) if start.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(TryLockError::WouldBlock) => {
                    return Err("agent state is busy; retry the operation".to_owned());
                }
                Err(TryLockError::Error(e)) => return Err(format!("lock agent state: {e}")),
            }
        }
    }

    fn record_ids(&self) -> Result<Vec<String>, String> {
        reject_symlink_ancestors(&self.directory)?;
        let entries = fs::read_dir(&self.directory).map_err(|e| format!("list agents: {e}"))?;
        let mut ids = Vec::new();
        for (count, entry) in entries.enumerate() {
            // Bound corrupted directories too, including abandoned temp files.
            if count >= 512 {
                return Err("agent directory contains too many entries".to_owned());
            }
            let entry = entry.map_err(|e| format!("list agents: {e}"))?;
            if entry
                .file_type()
                .map_err(|e| format!("inspect agent entry: {e}"))?
                .is_symlink()
            {
                return Err("agent store rejects symbolic links".to_owned());
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| "agent directory contains an invalid filename".to_owned())?;
            if let Some(id) = name.strip_suffix(".json") {
                validate_id(id, "stored agent ID")?;
                ids.push(id.to_owned());
                if ids.len() > MAX_AGENTS {
                    return Err("agent directory exceeds the owner agent limit".to_owned());
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn load_unlocked(&self, id: &str) -> Result<AgentSnapshot, String> {
        validate_id(id, "agent ID")?;
        reject_symlink_ancestors(&self.directory)?;
        let file = open_private_file(&self.directory.join(format!("{id}.json")), false, false)?;
        if file
            .metadata()
            .map_err(|e| format!("inspect agent snapshot: {e}"))?
            .len()
            > MAX_SNAPSHOT_BYTES as u64
        {
            return Err("agent snapshot exceeds 32 MiB".to_owned());
        }
        let mut bytes = Vec::new();
        file.take(MAX_SNAPSHOT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read agent snapshot: {e}"))?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err("agent snapshot exceeds 32 MiB".to_owned());
        }
        let record: StoredSnapshot =
            serde_json::from_slice(&bytes).map_err(|e| format!("corrupt agent snapshot: {e}"))?;
        if record.schema != SCHEMA {
            return Err("unsupported agent snapshot schema".to_owned());
        }
        self.validate_snapshot(&record.snapshot, id)?;
        Ok(record.snapshot)
    }

    fn validate_snapshot(&self, snapshot: &AgentSnapshot, id: &str) -> Result<(), String> {
        validate_id(&snapshot.agent_id, "stored agent ID")?;
        if snapshot.agent_id != id || snapshot.owner_session_id != self.owner_session_id {
            return Err("agent snapshot identity or owner mismatch".to_owned());
        }
        validate_field(&snapshot.owner_session_id, "owner session ID")?;
        validate_field(&snapshot.agent_type, "agent type")?;
        validate_field(&snapshot.model, "model")?;
        if let Some(EffortSetting::Value(value)) = &snapshot.effort {
            value.validate()?;
        }
        validate_name(snapshot.name.as_deref())?;
        if let Some(parent) = &snapshot.parent_agent_id {
            validate_id(parent, "parent agent ID")?;
        }
        if let Some(run_id) = &snapshot.active_run_id {
            validate_id(run_id, "active run ID")?;
        }
        if (snapshot.status == AgentStatus::Running) != snapshot.active_run_id.is_some() {
            return Err("agent snapshot has inconsistent run state".to_owned());
        }
        if snapshot.inbox.len() > MAX_INBOX_MESSAGES
            || inbox_bytes(&snapshot.inbox) > MAX_INBOX_BYTES
        {
            return Err("agent snapshot exceeds inbox bounds".to_owned());
        }
        let mut message_ids = HashSet::new();
        for message in &snapshot.inbox {
            validate_id(&message.message_id, "message ID")?;
            if !message_ids.insert(&message.message_id) {
                return Err("agent inbox contains duplicate message IDs".to_owned());
            }
            validate_message_text(&message.text)?;
            if let Some(sender) = &message.sender_agent_id {
                validate_id(sender, "sender agent ID")?;
            }
        }
        Ok(())
    }

    fn save_unlocked(&self, snapshot: &AgentSnapshot) -> Result<(), String> {
        self.validate_snapshot(snapshot, &snapshot.agent_id)?;
        reject_symlink_ancestors(&self.directory)?;
        let destination = self.directory.join(format!("{}.json", snapshot.agent_id));
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            validate_regular_file(&metadata)?;
        }
        let mut bytes = BoundedBytes(Vec::new());
        serde_json::to_writer(
            &mut bytes,
            &StoredSnapshotRef {
                schema: SCHEMA,
                snapshot,
            },
        )
        .map_err(|e| format!("serialize agent snapshot (maximum 32 MiB): {e}"))?;
        let temporary = self
            .directory
            .join(format!(".{}.{}.tmp", snapshot.agent_id, Ulid::new()));
        let result = (|| {
            let mut file = open_private_file(&temporary, true, true)?;
            file.write_all(&bytes.0)
                .map_err(|e| format!("write agent snapshot: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("sync agent snapshot: {e}"))?;
            reject_symlink_ancestors(&self.directory)?;
            if let Ok(metadata) = fs::symlink_metadata(&destination) {
                validate_regular_file(&metadata)?;
            }
            fs::rename(&temporary, &destination)
                .map_err(|e| format!("replace agent snapshot: {e}"))?;
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| format!("sync agent directory: {e}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

impl AgentRun {
    pub fn snapshot(&self) -> &AgentSnapshot {
        &self.snapshot
    }

    pub fn messages(&self) -> &[AgentMessage] {
        &self.snapshot.inbox
    }

    pub fn interrupted_previous_run(&self) -> bool {
        self.interrupted_previous_run
    }

    /// Commit the result and acknowledge only messages captured at `begin` in
    /// one atomic replacement. Messages that arrived during the run remain queued.
    pub fn finish(
        mut self,
        transcript: Vec<ChatMessage>,
        report: String,
        status: AgentStatus,
        turns: u64,
    ) -> Result<AgentSnapshot, String> {
        if matches!(status, AgentStatus::Idle | AgentStatus::Running) {
            return Err(
                "an agent run must finish with a terminal or interrupted status".to_owned(),
            );
        }
        let _state = self.store.lock_state(STATE_LOCK_TIMEOUT)?;
        let mut latest = self.store.load_unlocked(&self.snapshot.agent_id)?;
        if latest.status != AgentStatus::Running
            || latest.active_run_id != self.snapshot.active_run_id
        {
            return Err("agent run no longer owns the saved state".to_owned());
        }
        let acknowledged: HashSet<&str> = self
            .messages()
            .iter()
            .map(|message| message.message_id.as_str())
            .collect();
        latest
            .inbox
            .retain(|message| !acknowledged.contains(message.message_id.as_str()));
        latest.transcript = transcript;
        latest.report = report;
        latest.status = status;
        latest.turns = turns;
        latest.active_run_id = None;
        self.store.save_unlocked(&latest)?;
        self.finished = true;
        // Release state before the lease. The saved result is visible to the next run.
        drop(_state);
        self.lease.take();
        Ok(latest)
    }
}

impl Drop for AgentRun {
    fn drop(&mut self) {
        if self.finished || self.lease.is_none() {
            return;
        }
        let Ok(_state) = self.store.lock_state(Duration::ZERO) else {
            return;
        };
        let Ok(mut latest) = self.store.load_unlocked(&self.snapshot.agent_id) else {
            return;
        };
        if latest.status == AgentStatus::Running
            && latest.active_run_id == self.snapshot.active_run_id
        {
            latest.status = AgentStatus::Interrupted;
            latest.active_run_id = None;
            let _ = self.store.save_unlocked(&latest);
        }
    }
}

fn validate_field(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > MAX_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{field} must be nonempty, at most 256 bytes, and contain no controls"
        ));
    }
    Ok(())
}

fn validate_name(name: Option<&str>) -> Result<(), String> {
    if let Some(name) = name {
        if name.trim().is_empty()
            || name.chars().count() > MAX_NAME_CHARS
            || name.chars().any(char::is_control)
        {
            return Err(
                "agent name must be nonempty, at most 64 characters, and contain no controls"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn validate_id(id: &str, field: &str) -> Result<(), String> {
    if id.len() != 26 || !Ulid::from_string(id).is_ok_and(|value| value.to_string() == id) {
        return Err(format!("{field} must be a canonical ULID"));
    }
    Ok(())
}

fn validate_message_text(text: &str) -> Result<(), String> {
    if text.trim().is_empty() || text.len() > MAX_MESSAGE_BYTES {
        return Err("agent message must be nonempty and at most 16 KiB".to_owned());
    }
    Ok(())
}

fn inbox_bytes(messages: &[AgentMessage]) -> usize {
    messages.iter().fold(0usize, |total, message| {
        total.saturating_add(message.text.len())
    })
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("agent store rejects symbolic links".to_owned());
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err("agent store directory path contains a non-directory".to_owned());
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("inspect agent directory: {e}")),
        }
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<(), String> {
    reject_symlink_ancestors(path)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("create agent directory: {e}")),
    }
    reject_symlink_ancestors(path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("protect agent directory: {e}"))?;
    // Another initializer or a failed earlier attempt may have created the
    // entry without syncing it. Existing entries need the same durability step.
    sync_directory_parent(path)
}

fn create_directory_tree(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) => sync_directory_parent(&current)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Create in order so every new ancestor's name is durable before
                // creating descendants. Existing home ancestors keep their modes.
                private_directory(&current)?;
            }
            Err(e) => return Err(format!("inspect agent home: {e}")),
        }
    }
    Ok(())
}

fn sync_directory_parent(path: &Path) -> Result<(), String> {
    // An absolute root has no containing entry to synchronize.
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    reject_symlink_ancestors(parent)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| format!("sync agent directory parent: {e}"))
}

fn validate_regular_file(metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("agent store requires regular files and rejects symbolic links".to_owned());
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err("agent store rejects multiply linked files".to_owned());
    }
    Ok(())
}

fn open_private_file(path: &Path, create: bool, exclusive: bool) -> Result<File, String> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_regular_file(&metadata)?;
            Some(metadata)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("inspect agent file: {e}")),
    };
    let mut options = OpenOptions::new();
    options.read(true).write(create);
    if exclusive {
        options.create_new(true);
    } else {
        options.create(create);
    }
    #[cfg(unix)]
    options.mode(0o600);
    // O_NOFOLLOW on Linux closes the final-component check/open race without
    // unsafe code or another dependency. Parent directories are private and checked.
    #[cfg(target_os = "linux")]
    options.custom_flags(0o400000);
    let file = options
        .open(path)
        .map_err(|e| format!("open agent file: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("inspect open agent file: {e}"))?;
    validate_regular_file(&metadata)?;
    #[cfg(unix)]
    if before
        .as_ref()
        .is_some_and(|before| before.dev() != metadata.dev() || before.ino() != metadata.ino())
    {
        return Err("agent file changed while opening".to_owned());
    }
    #[cfg(not(unix))]
    let _ = before;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("protect agent file: {e}"))?;
    Ok(file)
}

struct BoundedBytes(Vec<u8>);

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_SNAPSHOT_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("agent snapshot exceeds 32 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct TestHome(PathBuf);

    impl TestHome {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("orbit-agent-store-{}", Ulid::new())))
        }

        fn store(&self, owner: &str) -> AgentStore {
            AgentStore::new(&self.0, owner).unwrap()
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn create(store: &AgentStore) -> AgentSnapshot {
        store
            .create("research", Some("Research notes"), "mock/first", None)
            .unwrap()
    }

    #[test]
    fn restart_roundtrips_transcript_and_model_override() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = create(&store);
        let mut response = crate::assistant_message("result");
        response.origin_model = Some("mock/second".to_owned());
        let transcript = vec![crate::user_message("first prompt"), response];
        let run = store.begin(&agent.agent_id, Some("mock/second")).unwrap();
        assert!(!run.interrupted_previous_run());
        assert_eq!(run.snapshot().model, "mock/second");
        let active_run_id = run.snapshot().active_run_id.clone();
        assert_eq!(
            store.load(&agent.agent_id).unwrap().status,
            AgentStatus::Running
        );
        run.finish(
            transcript.clone(),
            "result".to_owned(),
            AgentStatus::Completed,
            2,
        )
        .unwrap();
        drop(store);
        let reopened = home.store("owner");
        let loaded = reopened.load(&agent.agent_id).unwrap();
        assert_eq!(loaded.model, "mock/second");
        assert_eq!(loaded.name.as_deref(), Some("Research notes"));
        assert_eq!(loaded.turns, 2);
        assert_eq!(loaded.status, AgentStatus::Completed);
        assert_eq!(loaded.active_run_id, None);
        assert_eq!(
            serde_json::to_value(&loaded.transcript).unwrap(),
            serde_json::to_value(&transcript).unwrap()
        );
        let next = reopened.begin(&agent.agent_id, None).unwrap();
        assert_eq!(next.snapshot().transcript.len(), 2);
        assert_ne!(next.snapshot().active_run_id, active_run_id);
        assert!(!next.interrupted_previous_run());
    }

    #[test]
    fn owner_namespace_and_relationships_are_isolated() {
        let home = TestHome::new();
        let first = home.store("../../raw-owner");
        let second = home.store("another-owner");
        assert_eq!(first.directory.file_name().unwrap().len(), 64);
        assert!(!first.directory.to_string_lossy().contains("raw-owner"));
        let parent = create(&first);
        let other = create(&second);
        assert!(second.load(&parent.agent_id).is_err());
        assert!(second
            .create("research", None, "mock/model", Some(&parent.agent_id))
            .is_err());
        assert!(second
            .enqueue(&other.agent_id, "message", Some(&parent.agent_id))
            .is_err());
        let child = first
            .create("research", None, "mock/model", Some(&parent.agent_id))
            .unwrap();
        assert_eq!(
            child.parent_agent_id.as_deref(),
            Some(parent.agent_id.as_str())
        );
        let message = first
            .enqueue(&child.agent_id, "message", Some(&parent.agent_id))
            .unwrap();
        assert_eq!(
            message.sender_agent_id.as_deref(),
            Some(parent.agent_id.as_str())
        );
        fs::copy(
            first.directory.join(format!("{}.json", parent.agent_id)),
            second.directory.join(format!("{}.json", parent.agent_id)),
        )
        .unwrap();
        assert!(second
            .load(&parent.agent_id)
            .unwrap_err()
            .contains("owner mismatch"));
        for id in [
            "../outside",
            "/tmp/outside",
            "00",
            "0000000000000000000000000/",
            "zzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(first.load(id).is_err());
            assert!(first.begin(id, None).is_err());
            assert!(first.enqueue(id, "message", None).is_err());
        }
        assert!(first.load(&parent.agent_id.to_lowercase()).is_err());
    }

    #[test]
    fn enqueue_during_run_is_preserved_and_captured_messages_ack_once() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = create(&store);
        let old = store.enqueue(&agent.agent_id, "before run", None).unwrap();
        let run = store.begin(&agent.agent_id, None).unwrap();
        assert_eq!(run.messages(), std::slice::from_ref(&old));
        assert_eq!(
            store.load(&agent.agent_id).unwrap().inbox,
            vec![old.clone()]
        );
        let peer = home.store("owner");
        assert!(peer
            .begin(&agent.agent_id, None)
            .unwrap_err()
            .contains("active run"));
        let new = peer.enqueue(&agent.agent_id, "during run", None).unwrap();
        let result = run
            .finish(
                vec![crate::user_message(old.text)],
                "done".to_owned(),
                AgentStatus::Completed,
                1,
            )
            .unwrap();
        assert_eq!(result.inbox, vec![new.clone()]);
        assert_eq!(result.transcript[0].content, "before run");
        let reopened = home.store("owner");
        let second = reopened.begin(&agent.agent_id, None).unwrap();
        assert_eq!(second.messages(), std::slice::from_ref(&new));
        let final_state = second
            .finish(
                vec![
                    crate::user_message("before run"),
                    crate::user_message("during run"),
                ],
                "done".to_owned(),
                AgentStatus::Completed,
                2,
            )
            .unwrap();
        assert!(final_state.inbox.is_empty());
        assert!(reopened
            .begin(&agent.agent_id, None)
            .unwrap()
            .messages()
            .is_empty());
    }

    #[test]
    fn cancelled_failed_and_dropped_runs_release_leases() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = create(&store);
        for status in [
            AgentStatus::Cancelled,
            AgentStatus::Failed,
            AgentStatus::Interrupted,
        ] {
            let run = store.begin(&agent.agent_id, None).unwrap();
            let state = run
                .finish(
                    vec![crate::user_message("prompt")],
                    "stopped".to_owned(),
                    status,
                    1,
                )
                .unwrap();
            assert_eq!(state.status, status);
            assert!(state.active_run_id.is_none());
        }
        let message = store
            .enqueue(&agent.agent_id, "keep until committed", None)
            .unwrap();
        let run = store.begin(&agent.agent_id, None).unwrap();
        drop(run);
        let state = store.load(&agent.agent_id).unwrap();
        assert_eq!(state.status, AgentStatus::Interrupted);
        assert_eq!(state.inbox, vec![message]);
        let resumed = store.begin(&agent.agent_id, None).unwrap();
        assert!(resumed.interrupted_previous_run());
    }

    #[test]
    fn drop_does_not_wait_for_state_lock_and_stale_running_can_resume() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = create(&store);
        let run = store.begin(&agent.agent_id, None).unwrap();
        let state_lock = store.lock_state(Duration::ZERO).unwrap();
        let start = Instant::now();
        drop(run);
        assert!(start.elapsed() < Duration::from_millis(250));
        drop(state_lock);
        assert_eq!(
            store.load(&agent.agent_id).unwrap().status,
            AgentStatus::Running
        );
        let resumed = store.begin(&agent.agent_id, None).unwrap();
        assert!(resumed.interrupted_previous_run());
        assert!(resumed.snapshot().transcript.is_empty());
    }

    #[test]
    fn process_probe() {
        let Ok(home) = std::env::var("ORBIT_AGENT_STORE_TEST_HOME") else {
            return;
        };
        let id = std::env::var("ORBIT_AGENT_STORE_TEST_ID").unwrap();
        let store = AgentStore::new(Path::new(&home), "owner").unwrap();
        match std::env::var("ORBIT_AGENT_STORE_TEST_MODE")
            .unwrap()
            .as_str()
        {
            "busy" => assert!(store.begin(&id, None).unwrap_err().contains("active run")),
            "crash" => {
                let _run = store.begin(&id, None).unwrap();
                // Simulate process loss after Running is persisted, before finish/Drop.
                std::process::exit(0);
            }
            mode => panic!("unknown test mode {mode}"),
        }
    }

    fn subprocess(home: &TestHome, id: &str, mode: &str) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "agent_store::tests::process_probe",
                "--nocapture",
            ])
            .env("ORBIT_AGENT_STORE_TEST_HOME", &home.0)
            .env("ORBIT_AGENT_STORE_TEST_ID", id)
            .env("ORBIT_AGENT_STORE_TEST_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn run_lease_is_cross_process_and_crash_keeps_pending_messages() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = create(&store);
        let run = store.begin(&agent.agent_id, None).unwrap();
        subprocess(&home, &agent.agent_id, "busy");
        run.finish(Vec::new(), String::new(), AgentStatus::Completed, 0)
            .unwrap();
        let message = store
            .enqueue(&agent.agent_id, "unknown delivery", None)
            .unwrap();
        subprocess(&home, &agent.agent_id, "crash");
        let loaded = home.store("owner").load(&agent.agent_id).unwrap();
        assert_eq!(loaded.status, AgentStatus::Running);
        assert_eq!(loaded.inbox, vec![message.clone()]);
        let resumed = store.begin(&agent.agent_id, None).unwrap();
        assert!(resumed.interrupted_previous_run());
        assert_eq!(resumed.messages(), std::slice::from_ref(&message));
    }

    #[test]
    fn concurrent_sends_do_not_lose_messages_and_queue_bounds_hold() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = create(&store);
        let handles: Vec<_> = (0..8)
            .map(|sender| {
                let store = store.clone();
                let id = agent.agent_id.clone();
                std::thread::spawn(move || {
                    for number in 0..8 {
                        store
                            .enqueue(&id, &format!("sender {sender} message {number}"), None)
                            .unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let loaded = store.load(&agent.agent_id).unwrap();
        assert_eq!(loaded.inbox.len(), 64);
        assert_eq!(
            loaded
                .inbox
                .iter()
                .map(|message| &message.text)
                .collect::<HashSet<_>>()
                .len(),
            64
        );
        assert!(store.enqueue(&agent.agent_id, "overflow", None).is_err());
        let another = create(&store);
        for _ in 0..32 {
            store
                .enqueue(&another.agent_id, &"x".repeat(MAX_MESSAGE_BYTES), None)
                .unwrap();
        }
        assert!(store
            .enqueue(&another.agent_id, "byte overflow", None)
            .is_err());
        assert!(store.enqueue(&another.agent_id, " ", None).is_err());
        assert!(store
            .enqueue(&another.agent_id, &"x".repeat(MAX_MESSAGE_BYTES + 1), None)
            .is_err());
    }

    #[test]
    fn field_and_agent_limits_are_enforced_and_list_is_sorted_metadata() {
        let home = TestHome::new();
        assert!(AgentStore::new(&home.0, "").is_err());
        assert!(AgentStore::new(&home.0, &"x".repeat(257)).is_err());
        let store = home.store("owner");
        for name in ["", "\ncontrol", &"x".repeat(65)] {
            assert!(store
                .create("research", Some(name), "mock/model", None)
                .is_err());
        }
        assert!(store.create("", None, "mock/model", None).is_err());
        assert!(store
            .create("research", None, &"x".repeat(257), None)
            .is_err());
        assert!(store
            .create("research", None, "mock/\nmodel", None)
            .is_err());
        store
            .create("research", Some(&"é".repeat(64)), "mock/model", None)
            .unwrap();
        for _ in 1..MAX_AGENTS {
            create(&store);
        }
        assert!(store.create("research", None, "mock/model", None).is_err());
        let list = store.list().unwrap();
        assert_eq!(list.len(), MAX_AGENTS);
        assert!(list
            .windows(2)
            .all(|pair| pair[0].agent_id < pair[1].agent_id));
        let serialized = serde_json::to_value(&list[0]).unwrap();
        assert!(serialized.get("transcript").is_none());
        assert!(serialized.get("inbox").is_none());
    }

    #[test]
    fn corrupt_schema_identity_and_oversized_snapshots_are_rejected() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = create(&store);
        let path = store.directory.join(format!("{}.json", agent.agent_id));
        let original = fs::read(&path).unwrap();
        for (field, value) in [
            ("schema", "unknown"),
            ("agent_id", "00000000000000000000000000"),
            ("owner_session_id", "another-owner"),
        ] {
            let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
            if field == "schema" {
                record[field] = value.into();
            } else {
                record["snapshot"][field] = value.into();
            }
            fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(store.load(&agent.agent_id).is_err());
            assert!(store.list().is_err());
        }
        fs::write(&path, b"{broken").unwrap();
        assert!(store.load(&agent.agent_id).unwrap_err().contains("corrupt"));
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(MAX_SNAPSHOT_BYTES as u64 + 1).unwrap();
        assert!(store.load(&agent.agent_id).unwrap_err().contains("32 MiB"));
    }

    #[test]
    fn failed_oversized_finish_does_not_ack_messages_or_replace_transcript() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = create(&store);
        let message = store.enqueue(&agent.agent_id, "keep", None).unwrap();
        let run = store.begin(&agent.agent_id, None).unwrap();
        assert!(run
            .finish(
                vec![crate::user_message("uncommitted")],
                "x".repeat(MAX_SNAPSHOT_BYTES + 1),
                AgentStatus::Completed,
                1
            )
            .is_err());
        let loaded = store.load(&agent.agent_id).unwrap();
        assert_eq!(loaded.status, AgentStatus::Interrupted);
        assert!(loaded.transcript.is_empty());
        assert!(loaded.report.is_empty());
        assert_eq!(loaded.inbox, vec![message]);
        assert!(store.begin(&agent.agent_id, None).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn namespace_files_are_private_and_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let home = TestHome::new();
        let nested_home = home.0.join("missing/parent/home");
        let nested_store = AgentStore::new(&nested_home, "nested-owner").unwrap();
        let nested_agent = create(&nested_store);
        assert!(AgentStore::new(&nested_home, "nested-owner")
            .unwrap()
            .load(&nested_agent.agent_id)
            .is_ok());
        for path in [
            home.0.join("missing"),
            home.0.join("missing/parent"),
            nested_home,
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let store = home.store("owner");
        let agent = create(&store);
        let run = store.begin(&agent.agent_id, None).unwrap();
        for path in [home.0.join("agents"), store.directory.clone()] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for path in [
            store.directory.join(".state.lock"),
            store.directory.join(format!("{}.json", agent.agent_id)),
            store.directory.join(format!("{}.run.lock", agent.agent_id)),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(run);
        let linked_home = home.0.join("linked");
        symlink(&home.0, &linked_home).unwrap();
        assert!(AgentStore::new(&linked_home, "owner").is_err());
        let record_path = store.directory.join(format!("{}.json", agent.agent_id));
        fs::remove_file(&record_path).unwrap();
        let unrelated = home.0.join("unrelated");
        fs::write(&unrelated, b"do not touch").unwrap();
        symlink(&unrelated, &record_path).unwrap();
        assert!(store.load(&agent.agent_id).is_err());
        assert!(store.list().is_err());
        assert_eq!(fs::read(&unrelated).unwrap(), b"do not touch");
        fs::remove_file(store.directory.join(".state.lock")).unwrap();
        symlink(&unrelated, store.directory.join(".state.lock")).unwrap();
        assert!(store
            .enqueue(&agent.agent_id, "do not write", None)
            .is_err());
        assert_eq!(fs::read(&unrelated).unwrap(), b"do not touch");
    }
    #[test]
    fn legacy_effort_and_saved_reset_roundtrip() {
        let home = TestHome::new();
        let store = home.store("owner");
        let agent = store
            .create_with_effort(
                "research",
                None,
                "mock/first",
                Some(EffortSetting::Default),
                None,
            )
            .unwrap();
        assert_eq!(
            store.list().unwrap()[0].effort,
            Some(EffortSetting::Default)
        );
        let path = store.directory.join(format!("{}.json", agent.agent_id));
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        legacy["snapshot"].as_object_mut().unwrap().remove("effort");
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(store.load(&agent.agent_id).unwrap().effort, None);
        let run = store
            .begin_resolved(&agent.agent_id, |leased| {
                assert_eq!(leased.effort, None);
                Ok((leased.model.clone(), Some(EffortSetting::Default)))
            })
            .unwrap();
        run.finish(Vec::new(), "done".into(), AgentStatus::Completed, 1)
            .unwrap();
        assert_eq!(
            home.store("owner").load(&agent.agent_id).unwrap().effort,
            Some(EffortSetting::Default)
        );
    }

    #[test]
    fn leased_effort_is_authority_and_invalid_resolution_never_starts() {
        use orbit_adapter::types::EffortValue;
        let home = TestHome::new();
        let store = home.store("owner");
        let stale = store
            .create_with_effort(
                "research",
                None,
                "mock/first",
                Some(EffortSetting::Value(EffortValue::Level("high".into()))),
                None,
            )
            .unwrap();
        store
            .begin_resolved(&stale.agent_id, |leased| {
                Ok((leased.model.clone(), Some(EffortSetting::Default)))
            })
            .unwrap()
            .finish(Vec::new(), "first".into(), AgentStatus::Completed, 1)
            .unwrap();
        store
            .enqueue(&stale.agent_id, "keep pending", None)
            .unwrap();
        let result = store.begin_resolved(&stale.agent_id, |leased| {
            assert_ne!(leased.effort, stale.effort);
            assert_eq!(leased.effort, Some(EffortSetting::Default));
            Err("unsupported choice".into())
        });
        assert!(result.is_err());
        let current = store.load(&stale.agent_id).unwrap();
        assert_eq!(current.status, AgentStatus::Completed);
        assert!(current.active_run_id.is_none());
        assert_eq!(current.inbox.len(), 1);
        assert_eq!(current.effort, Some(EffortSetting::Default));
        assert!(
            store.begin(&stale.agent_id, None).is_ok(),
            "failed resolution releases lease"
        );
    }
}
