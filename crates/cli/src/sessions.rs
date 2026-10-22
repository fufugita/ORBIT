//! Session persistence for the interactive harness.
//!
//! Each REPL invocation writes its conversation transcript + cumulative usage
//! to `$ORBIT_HOME/sessions/<session_id>.json` after every turn (append-safe
//! rewrite of the JSON file). `/sessions` lists them; `/resume <id>` loads a
//! transcript back into the conversation so a session continues across
//! invocations.

pub use crate::session_accounting::{FullCostStatus, SessionAccountingWatermark};
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
    /// Canonical tool workspace. Missing metadata is an unbound legacy session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<PathBuf>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounting_watermark: Option<SessionAccountingWatermark>,
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
            workspace: None,
            effort: None,
            selection_origin: None,
            transcript: transcript.to_vec(),
            turns,
            input_tokens,
            output_tokens,
            cost_microcents,
            accounting_watermark: None,
            updated_at: crate::timestamp_now(),
        }
    }

    /// Bind a newly constructed snapshot. Persisted legacy adoption is separate.
    pub fn bind_workspace(&mut self, workspace: &Path) -> Result<(), SessionLeaseError> {
        let workspace = canonical_workspace(workspace)?;
        if self
            .workspace
            .as_ref()
            .is_some_and(|saved| saved != &workspace)
        {
            return Err(SessionLeaseError::InvalidData(
                "session workspace cannot be rebound".into(),
            ));
        }
        self.workspace = Some(workspace);
        Ok(())
    }

    pub fn in_workspace(mut self, workspace: &Path) -> Result<Self, SessionLeaseError> {
        self.bind_workspace(workspace)?;
        Ok(self)
    }

    /// Admit execution only in the directory whose tools own this history.
    pub fn require_workspace(&self, workspace: &Path) -> Result<(), SessionLeaseError> {
        let workspace = canonical_workspace(workspace)?;
        match &self.workspace {
            Some(saved) if saved == &workspace => Ok(()),
            Some(_) => Err(SessionLeaseError::InvalidData(
                "session belongs to another workspace; open its original directory to resume"
                    .into(),
            )),
            None => Err(SessionLeaseError::InvalidData(format!(
                "session workspace is unknown; inspect it first, then run orbit --resume {} --adopt-workspace in the intended directory",
                self.session_id,
            ))),
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

/// Resolve an existing directory once; never change the process working directory.
pub fn canonical_workspace(workspace: &Path) -> Result<PathBuf, SessionLeaseError> {
    let canonical = std::fs::canonicalize(workspace)
        .map_err(|_| SessionLeaseError::InvalidData("workspace directory is unavailable".into()))?;
    if !canonical.is_dir() {
        return Err(SessionLeaseError::InvalidData(
            "workspace must be an existing directory".into(),
        ));
    }
    Ok(canonical)
}

pub fn current_workspace() -> Result<PathBuf, SessionLeaseError> {
    canonical_workspace(
        &std::env::current_dir().map_err(|_| {
            SessionLeaseError::InvalidData("workspace directory is unavailable".into())
        })?,
    )
}

/// Checked read-only preflight, before creating a candidate lease or changing live state.
fn read_workspace_session(home: &Path, id: &str) -> Result<SessionFile, SessionLeaseError> {
    let id = id.strip_suffix(".json").unwrap_or(id);
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SessionLeaseError::InvalidIdentity(
            "invalid session identity".into(),
        ));
    }
    let directory = crate::customization::Directory::open(&sessions_dir(home), true)
        .map_err(|error| SessionLeaseError::UnsafePath(error.to_string()))?;
    let bytes = crate::customization::read_regular(
        &directory
            .io()
            .map_err(|error| SessionLeaseError::UnsafePath(error.to_string()))?
            .join(format!("{id}.json")),
        64 * 1024 * 1024,
        true,
    )
    .map_err(|error| SessionLeaseError::Io(error.to_string()))?;
    let saved: SessionFile = serde_json::from_slice(&bytes)
        .map_err(|_| SessionLeaseError::InvalidData("invalid saved session".into()))?;
    if saved.session_id != id || saved.schema != "orbit.session/v1" {
        return Err(SessionLeaseError::InvalidData(
            "saved session identity or schema mismatch".into(),
        ));
    }
    directory
        .check()
        .map_err(|error| SessionLeaseError::UnsafePath(error.to_string()))?;
    Ok(saved)
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
    #[error("session {session_id} already has a saved snapshot")]
    AlreadyExists { session_id: String },
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
    workspace_binding: std::sync::Mutex<Option<Option<PathBuf>>>,
    #[cfg(unix)]
    storage: leased_storage::Storage,
}

/// Small saved-history facts; selection and transcript remain only in raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionRecoveryFacts {
    pub(crate) turns: u64,
    pub(crate) watermark_revision: Option<u64>,
    pub(crate) watermark_full_cost_status: Option<FullCostStatus>,
}

/// Inert exact snapshot tied to the lifetime of its original ownership claim.
pub(crate) struct SessionRecoveryCapture<'lease> {
    lease: &'lease SessionLease,
    #[cfg(unix)]
    snapshot: leased_storage::RecoveryFile,
    facts: SessionRecoveryFacts,
}

/// Optional existing root JSONL, never decoded or opened through Transcript.
pub(crate) struct LegacyRecoveryCapture<'lease> {
    lease: &'lease SessionLease,
    #[cfg(unix)]
    source: leased_storage::RecoveryLegacy,
}
impl LegacyRecoveryCapture<'_> {
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        #[cfg(unix)]
        {
            self.source.bytes()
        }
        #[cfg(not(unix))]
        {
            unreachable!("recovery requires Unix ownership")
        }
    }
    pub(crate) fn sha256(&self) -> Option<&str> {
        #[cfg(unix)]
        {
            self.source.sha256()
        }
        #[cfg(not(unix))]
        {
            unreachable!("recovery requires Unix ownership")
        }
    }
    pub(crate) fn verify_unchanged(&self, lease: &SessionLease) -> Result<(), SessionLeaseError> {
        if !std::ptr::eq(self.lease, lease) {
            return Err(SessionLeaseError::UnsafePath(
                "recovery requires the original held lease".into(),
            ));
        }
        #[cfg(unix)]
        {
            lease
                .storage
                .verify_recovery_legacy(lease.session_id(), &self.source)
                .map_err(recovery_capture_error)
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "recovery requires Unix ownership".into(),
            ))
        }
    }
}

impl SessionRecoveryCapture<'_> {
    pub(crate) fn owner_session_id(&self) -> &str {
        self.lease.session_id()
    }
    pub(crate) fn facts(&self) -> &SessionRecoveryFacts {
        &self.facts
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        #[cfg(unix)]
        {
            self.snapshot.bytes()
        }
        #[cfg(not(unix))]
        {
            unreachable!("recovery requires Unix ownership")
        }
    }
    pub(crate) fn sha256(&self) -> &str {
        #[cfg(unix)]
        {
            self.snapshot.sha256()
        }
        #[cfg(not(unix))]
        {
            unreachable!("recovery requires Unix ownership")
        }
    }
    pub(crate) fn verify_unchanged(&self, lease: &SessionLease) -> Result<(), SessionLeaseError> {
        if !std::ptr::eq(self.lease, lease) {
            return Err(SessionLeaseError::UnsafePath(
                "recovery requires the original held lease".into(),
            ));
        }
        #[cfg(unix)]
        {
            lease
                .storage
                .verify_recovery_file(lease.session_id(), &self.snapshot)
                .map_err(recovery_capture_error)
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "recovery requires Unix ownership".into(),
            ))
        }
    }
}

// Capture diagnostics never contain source bytes, JSON parser details or paths.
fn recovery_capture_error(error: SessionLeaseError) -> SessionLeaseError {
    match error {
        SessionLeaseError::UnsafePath(_) | SessionLeaseError::InvalidIdentity(_) => {
            SessionLeaseError::UnsafePath("recovery source identity is unsafe or changed".into())
        }
        SessionLeaseError::InvalidData(_) => SessionLeaseError::InvalidData(
            "recovery snapshot is invalid, changed or exceeds its bound".into(),
        ),
        _ => SessionLeaseError::Io("recovery source is unavailable".into()),
    }
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
                workspace_binding: std::sync::Mutex::new(None),
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

    /// Preflight before lease acquisition, then recheck under exclusive ownership.
    pub fn acquire_for_workspace(
        home: &Path,
        id: &str,
        kind: &str,
        workspace: &Path,
    ) -> Result<(Self, SessionFile), SessionLeaseError> {
        read_workspace_session(home, id)?.require_workspace(workspace)?;
        let (lease, saved) = Self::acquire_and_load(home, id, kind)?;
        saved.require_workspace(workspace)?;
        Ok((lease, saved))
    }

    /// A standalone frontend may create an absent ID, but never adopt existing history.
    pub fn acquire_new_or_for_workspace(
        home: &Path,
        id: &str,
        kind: &str,
        workspace: &Path,
    ) -> Result<Self, SessionLeaseError> {
        let workspace = canonical_workspace(workspace)?;
        let id = id.strip_suffix(".json").unwrap_or(id);
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(SessionLeaseError::InvalidIdentity(
                "invalid session identity".into(),
            ));
        }
        let path =
            sessions_dir(home).join(format!("{}.json", id.strip_suffix(".json").unwrap_or(id)));
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Self::acquire_for_workspace(home, id, kind, &workspace)
                    .map(|(lease, _)| lease);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(SessionLeaseError::Io(error.to_string())),
        }
        let lease = Self::acquire(home, id, kind)?;
        if let Some(saved) = lease.load_optional()? {
            saved.require_workspace(&workspace)?;
        }
        Ok(lease)
    }

    /// Only explicit startup adoption may acquire an unbound legacy snapshot.
    pub fn acquire_for_adoption(
        home: &Path,
        id: &str,
        kind: &str,
    ) -> Result<(Self, SessionFile), SessionLeaseError> {
        let check = |saved: &SessionFile| {
            if saved.workspace.is_some() {
                Err(SessionLeaseError::InvalidData("only an unbound legacy session can be adopted; bound sessions cannot be rebound".into()))
            } else {
                Ok(())
            }
        };
        check(&read_workspace_session(home, id)?)?;
        let (lease, saved) = Self::acquire_and_load(home, id, kind)?;
        check(&saved)?;
        Ok((lease, saved))
    }

    /// Explicit, stable-source legacy binding. Ordinary saves cannot adopt.
    pub fn adopt_workspace(
        &self,
        expected: &SessionFile,
        workspace: &Path,
    ) -> Result<SessionFile, SessionLeaseError> {
        let workspace = canonical_workspace(workspace)?;
        self.validate_session(expected)?;
        self.remember_workspace(&expected.workspace)?;
        if expected.workspace.is_some() {
            return Err(SessionLeaseError::InvalidData(
                "only an unbound legacy session can be adopted".into(),
            ));
        }
        #[cfg(unix)]
        {
            let captured = self.capture_for_recovery()?;
            let current: SessionFile = serde_json::from_slice(captured.bytes())
                .map_err(|_| SessionLeaseError::InvalidData("invalid saved session".into()))?;
            let current_value = serde_json::to_value(&current)
                .map_err(|error| SessionLeaseError::InvalidData(error.to_string()))?;
            let expected_value = serde_json::to_value(expected)
                .map_err(|error| SessionLeaseError::InvalidData(error.to_string()))?;
            if current_value != expected_value {
                return Err(SessionLeaseError::InvalidData(
                    "session changed before workspace adoption".into(),
                ));
            }
            let mut value: serde_json::Value = serde_json::from_slice(captured.bytes())
                .map_err(|_| SessionLeaseError::InvalidData("invalid saved session".into()))?;
            value
                .as_object_mut()
                .ok_or_else(|| SessionLeaseError::InvalidData("invalid saved session".into()))?
                .insert(
                    "workspace".into(),
                    serde_json::to_value(&workspace)
                        .map_err(|error| SessionLeaseError::InvalidData(error.to_string()))?,
                );
            let raw = serde_json::to_vec_pretty(&value)
                .map_err(|error| SessionLeaseError::InvalidData(error.to_string()))?;
            self.storage
                .save_matching_snapshot(&self.session_id, &raw, &captured.snapshot)?;
            let adopted: SessionFile = serde_json::from_value(value)
                .map_err(|error| SessionLeaseError::InvalidData(error.to_string()))?;
            adopted.require_workspace(&workspace)?;
            *self.workspace_binding.lock().map_err(|_| {
                SessionLeaseError::PublicationUncertain(
                    "workspace binding state unavailable".into(),
                )
            })? = Some(adopted.workspace.clone());
            Ok(adopted)
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "workspace adoption requires Unix ownership".into(),
            ))
        }
    }

    fn remember_workspace(&self, workspace: &Option<PathBuf>) -> Result<(), SessionLeaseError> {
        let mut binding = self.workspace_binding.lock().map_err(|_| {
            SessionLeaseError::InvalidData("session workspace state unavailable".into())
        })?;
        if binding
            .as_ref()
            .is_some_and(|original| original != workspace)
        {
            return Err(SessionLeaseError::InvalidData(
                "session workspace changed while owned".into(),
            ));
        }
        *binding = Some(workspace.clone());
        Ok(())
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

    /// Check held ownership without reading a snapshot or changing storage.
    pub(crate) fn verify_for_recovery(&self) -> Result<(), SessionLeaseError> {
        #[cfg(unix)]
        {
            self.storage
                .check_recovery_lease(&self.session_id)
                .map_err(recovery_capture_error)
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "recovery requires Unix ownership".into(),
            ))
        }
    }

    /// Preserve one existing private snapshot exactly; no chmod/save/reserialize.
    pub(crate) fn capture_for_recovery(
        &self,
    ) -> Result<SessionRecoveryCapture<'_>, SessionLeaseError> {
        #[cfg(unix)]
        {
            let snapshot = self
                .storage
                .capture_recovery_file(&self.session_id)
                .map_err(recovery_capture_error)?;
            let saved: SessionFile = serde_json::from_slice(snapshot.bytes())
                .map_err(|_| SessionLeaseError::InvalidData("invalid recovery snapshot".into()))?;
            self.validate_session(&saved)
                .map_err(recovery_capture_error)?;
            let facts = SessionRecoveryFacts {
                turns: saved.turns,
                watermark_revision: saved
                    .accounting_watermark
                    .as_ref()
                    .map(|value| value.revision),
                watermark_full_cost_status: saved
                    .accounting_watermark
                    .as_ref()
                    .map(|value| value.full_cost_status),
            };
            drop(saved);
            self.verify_for_recovery()?;
            Ok(SessionRecoveryCapture {
                lease: self,
                snapshot,
                facts,
            })
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "recovery requires Unix ownership".into(),
            ))
        }
    }

    pub(crate) fn capture_legacy_for_recovery(
        &self,
    ) -> Result<LegacyRecoveryCapture<'_>, SessionLeaseError> {
        #[cfg(unix)]
        {
            let source = self
                .storage
                .capture_recovery_legacy(&self.session_id)
                .map_err(recovery_capture_error)?;
            Ok(LegacyRecoveryCapture {
                lease: self,
                source,
            })
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "recovery requires Unix ownership".into(),
            ))
        }
    }

    pub fn load(&self) -> Result<SessionFile, SessionLeaseError> {
        #[cfg(unix)]
        {
            let raw = self.storage.load(&self.session_id)?;
            let session: SessionFile = serde_json::from_slice(&raw)
                .map_err(|e| SessionLeaseError::InvalidData(e.to_string()))?;
            self.validate_session(&session)?;
            self.remember_workspace(&session.workspace)?;
            Ok(session)
        }
        #[cfg(not(unix))]
        {
            Err(SessionLeaseError::Io(
                "live session ownership requires Unix".into(),
            ))
        }
    }

    /// Only a positively absent target below the still-verified held directory
    /// is None. Present unsafe or invalid snapshots remain errors.
    pub fn load_optional(&self) -> Result<Option<SessionFile>, SessionLeaseError> {
        #[cfg(unix)]
        {
            self.storage
                .load_optional(&self.session_id)?
                .map(|raw| {
                    let session: SessionFile = serde_json::from_slice(&raw)
                        .map_err(|e| SessionLeaseError::InvalidData(e.to_string()))?;
                    self.validate_session(&session)?;
                    self.remember_workspace(&session.workspace)?;
                    Ok(session)
                })
                .transpose()
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
            let mut candidate = session.clone();
            self.load_optional()?;
            let original = self
                .workspace_binding
                .lock()
                .map_err(|_| {
                    SessionLeaseError::InvalidData("session workspace state unavailable".into())
                })?
                .clone();
            if let Some(original) = original {
                match (&original, &candidate.workspace) {
                    (Some(original), Some(next)) if original != next => {
                        return Err(SessionLeaseError::InvalidData(
                            "session workspace cannot be rebound".into(),
                        ));
                    }
                    (Some(original), None) => candidate.workspace = Some(original.clone()),
                    (None, Some(_)) => {
                        return Err(SessionLeaseError::InvalidData(
                            "legacy workspace requires explicit adoption".into(),
                        ));
                    }
                    _ => {}
                }
            }
            self.validate_session(&candidate)?;
            self.remember_workspace(&candidate.workspace)?;
            let raw = serde_json::to_vec_pretty(&candidate)
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

    /// Publish a new snapshot without replacing any existing target.
    pub fn save_if_absent(&self, session: &SessionFile) -> Result<(), SessionLeaseError> {
        self.validate_session(session)?;
        self.remember_workspace(&session.workspace)?;
        #[cfg(unix)]
        {
            let raw = serde_json::to_vec_pretty(session)
                .map_err(|e| SessionLeaseError::InvalidData(e.to_string()))?;
            self.storage.save_if_absent(&self.session_id, &raw)
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
        if session.workspace.as_ref().is_some_and(|workspace| {
            !workspace.is_absolute()
                || workspace.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
        }) {
            return Err(SessionLeaseError::InvalidData(
                "saved workspace is not canonical".into(),
            ));
        }
        if let Some(watermark) = &session.accounting_watermark {
            crate::session_accounting::validate_root_watermark(watermark, &self.session_id)
                .map_err(|message| SessionLeaseError::InvalidData(message.into()))?;
        }
        Ok(())
    }
}

#[cfg(unix)]
#[allow(unsafe_code)] // FD-relative Unix storage operations are isolated here.
mod leased_storage {
    use super::SessionLeaseError;
    use sha2::{Digest, Sha256};
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};

    const MAX_SESSION_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_RECOVERY_LEGACY_BYTES: u64 = 32 * 1024 * 1024;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecoveryStamp {
        device: u64,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        bytes: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    impl RecoveryStamp {
        fn of(file: &File) -> Result<Self, SessionLeaseError> {
            let value = file.metadata().map_err(io)?;
            Ok(Self {
                device: value.dev(),
                inode: value.ino(),
                mode: value.mode(),
                uid: value.uid(),
                gid: value.gid(),
                links: value.nlink(),
                bytes: value.len(),
                modified: (value.mtime(), value.mtime_nsec()),
                changed: (value.ctime(), value.ctime_nsec()),
            })
        }
    }

    pub(super) struct RecoveryFile {
        file: File,
        stamp: RecoveryStamp,
        bytes: Vec<u8>,
        sha256: String,
    }
    impl RecoveryFile {
        pub(super) fn bytes(&self) -> &[u8] {
            &self.bytes
        }
        pub(super) fn sha256(&self) -> &str {
            &self.sha256
        }
    }

    pub(super) struct RecoveryLegacy {
        directory: Option<File>,
        directory_stamp: Option<RecoveryStamp>,
        file: Option<RecoveryFile>,
    }
    impl RecoveryLegacy {
        pub(super) fn bytes(&self) -> Option<&[u8]> {
            self.file.as_ref().map(RecoveryFile::bytes)
        }
        pub(super) fn sha256(&self) -> Option<&str> {
            self.file.as_ref().map(RecoveryFile::sha256)
        }
    }

    fn verify_recovery_contents(
        file: &mut File,
        saved: &RecoveryFile,
        maximum: u64,
    ) -> Result<(), SessionLeaseError> {
        if RecoveryStamp::of(&saved.file)? != saved.stamp || RecoveryStamp::of(file)? != saved.stamp
        {
            return Err(SessionLeaseError::UnsafePath(
                "recovery source identity changed".into(),
            ));
        }
        let mut digest = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(io)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| SessionLeaseError::InvalidData("recovery source bound".into()))?;
            if total > maximum || total > saved.stamp.bytes {
                return Err(SessionLeaseError::InvalidData(
                    "recovery source changed".into(),
                ));
            }
            digest.update(&buffer[..count]);
        }
        if total != saved.stamp.bytes
            || hex::encode(digest.finalize()) != saved.sha256
            || RecoveryStamp::of(file)? != saved.stamp
            || RecoveryStamp::of(&saved.file)? != saved.stamp
        {
            return Err(SessionLeaseError::InvalidData(
                "recovery source changed".into(),
            ));
        }
        Ok(())
    }

    pub(super) struct Storage {
        path: PathBuf,
        home: File,
        sessions: File,
        leases: File,
        lock: File,
        owner_pid: u32,
        #[cfg(test)]
        fail_before_rename: std::cell::Cell<bool>,
        #[cfg(test)]
        fail_directory_sync: std::cell::Cell<bool>,
    }

    impl Drop for Storage {
        fn drop(&mut self) {
            // A concurrent fork can retain this open-file description until
            // exec. Release ownership now instead of waiting for every copy
            // to close. A forked copy must not unlock its live parent's lease.
            if self.owner_pid == std::process::id() {
                // SAFETY: the owned lock FD is still live throughout Drop.
                let _ = unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
            }
        }
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

        pub(super) fn check_recovery_lease(&self, id: &str) -> Result<(), SessionLeaseError> {
            if self.owner_pid != std::process::id() {
                return Err(SessionLeaseError::UnsafePath(
                    "recovery lease belongs to another process".into(),
                ));
            }
            self.verify_location(id)
        }

        fn recovery_snapshot(&self, id: &str) -> Result<File, SessionLeaseError> {
            self.check_recovery_lease(id)?;
            let file = open_at(
                &self.sessions,
                OsStr::new(&format!("{id}.json")),
                libc::O_RDONLY,
            )
            .map_err(path_error)?;
            private_file(&file, MAX_SESSION_BYTES)?;
            Ok(file)
        }

        pub(super) fn capture_recovery_file(
            &self,
            id: &str,
        ) -> Result<RecoveryFile, SessionLeaseError> {
            let file = self.recovery_snapshot(id)?;
            let stamp = RecoveryStamp::of(&file)?;
            let mut bytes = Vec::new();
            (&file)
                .take(MAX_SESSION_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(io)?;
            if bytes.len() as u64 != stamp.bytes || RecoveryStamp::of(&file)? != stamp {
                return Err(SessionLeaseError::InvalidData(
                    "recovery snapshot changed or exceeds its bound".into(),
                ));
            }
            let path = self.recovery_snapshot(id)?;
            if RecoveryStamp::of(&path)? != stamp {
                return Err(SessionLeaseError::UnsafePath(
                    "recovery snapshot path changed".into(),
                ));
            }
            self.check_recovery_lease(id)?;
            let sha256 = hex::encode(Sha256::digest(&bytes));
            Ok(RecoveryFile {
                file,
                stamp,
                bytes,
                sha256,
            })
        }

        pub(super) fn verify_recovery_file(
            &self,
            id: &str,
            saved: &RecoveryFile,
        ) -> Result<(), SessionLeaseError> {
            let mut file = self.recovery_snapshot(id)?;
            verify_recovery_contents(&mut file, saved, MAX_SESSION_BYTES)?;
            if RecoveryStamp::of(&self.recovery_snapshot(id)?)? != saved.stamp {
                return Err(SessionLeaseError::InvalidData(
                    "recovery snapshot changed".into(),
                ));
            }
            self.check_recovery_lease(id)
        }

        fn recovery_projects(&self, id: &str) -> Result<Option<File>, SessionLeaseError> {
            self.check_recovery_lease(id)?;
            let file = match open_at(
                &self.home,
                OsStr::new("projects"),
                libc::O_RDONLY | libc::O_DIRECTORY,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.check_recovery_lease(id)?;
                    return Ok(None);
                }
                Err(error) => return Err(path_error(error)),
            };
            let metadata = file.metadata().map_err(io)?;
            if !metadata.is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(SessionLeaseError::UnsafePath(
                    "legacy source directory is not private".into(),
                ));
            }
            Ok(Some(file))
        }

        pub(super) fn capture_recovery_legacy(
            &self,
            id: &str,
        ) -> Result<RecoveryLegacy, SessionLeaseError> {
            let Some(directory) = self.recovery_projects(id)? else {
                let result = RecoveryLegacy {
                    directory: None,
                    directory_stamp: None,
                    file: None,
                };
                self.verify_recovery_legacy(id, &result)?;
                return Ok(result);
            };
            let name = format!("{id}.jsonl");
            let file = match open_at(&directory, OsStr::new(&name), libc::O_RDONLY) {
                Ok(file) => Some(file),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(path_error(error)),
            };
            let file = file
                .map(|file| {
                    private_file(&file, MAX_RECOVERY_LEGACY_BYTES)?;
                    let stamp = RecoveryStamp::of(&file)?;
                    let mut bytes = Vec::new();
                    (&file)
                        .take(MAX_RECOVERY_LEGACY_BYTES + 1)
                        .read_to_end(&mut bytes)
                        .map_err(io)?;
                    if bytes.len() as u64 != stamp.bytes || RecoveryStamp::of(&file)? != stamp {
                        return Err(SessionLeaseError::InvalidData(
                            "legacy source changed or exceeds its bound".into(),
                        ));
                    }
                    let path = open_at(&directory, OsStr::new(&name), libc::O_RDONLY)
                        .map_err(path_error)?;
                    private_file(&path, MAX_RECOVERY_LEGACY_BYTES)?;
                    if RecoveryStamp::of(&path)? != stamp {
                        return Err(SessionLeaseError::UnsafePath(
                            "legacy source path changed".into(),
                        ));
                    }
                    let sha256 = hex::encode(Sha256::digest(&bytes));
                    Ok(RecoveryFile {
                        file,
                        stamp,
                        bytes,
                        sha256,
                    })
                })
                .transpose()?;
            let directory_stamp = Some(RecoveryStamp::of(&directory)?);
            let result = RecoveryLegacy {
                directory: Some(directory),
                directory_stamp,
                file,
            };
            // Initial capture already read the present raw file once. Identity
            // and positive absence are rechecked without a second body read.
            self.check_recovery_legacy_identity(id, &result)?;
            Ok(result)
        }

        fn check_recovery_legacy_identity(
            &self,
            id: &str,
            saved: &RecoveryLegacy,
        ) -> Result<Option<File>, SessionLeaseError> {
            let current = self.recovery_projects(id)?;
            let directory = match (&saved.directory, current) {
                (None, None) => return Ok(None),
                (Some(old), Some(current)) if same_inode(old, &current)? => current,
                _ => {
                    return Err(SessionLeaseError::UnsafePath(
                        "legacy source directory changed".into(),
                    ));
                }
            };
            let recorded = saved.directory_stamp.as_ref().ok_or_else(|| {
                SessionLeaseError::UnsafePath("legacy source directory identity missing".into())
            })?;
            for observed in [
                RecoveryStamp::of(&directory)?,
                RecoveryStamp::of(saved.directory.as_ref().ok_or_else(|| {
                    SessionLeaseError::UnsafePath("legacy source directory identity missing".into())
                })?)?,
            ] {
                if (
                    observed.device,
                    observed.inode,
                    observed.mode,
                    observed.uid,
                    observed.gid,
                    observed.links,
                ) != (
                    recorded.device,
                    recorded.inode,
                    recorded.mode,
                    recorded.uid,
                    recorded.gid,
                    recorded.links,
                ) {
                    return Err(SessionLeaseError::UnsafePath(
                        "legacy source directory identity changed".into(),
                    ));
                }
            }
            let current = match open_at(
                &directory,
                OsStr::new(&format!("{id}.jsonl")),
                libc::O_RDONLY,
            ) {
                Ok(file) => Some(file),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(path_error(error)),
            };
            match (&saved.file, current) {
                (None, None) => {
                    self.check_recovery_lease(id)?;
                    Ok(None)
                }
                (Some(old), Some(current)) => {
                    private_file(&current, MAX_RECOVERY_LEGACY_BYTES)?;
                    if RecoveryStamp::of(&current)? != old.stamp
                        || RecoveryStamp::of(&old.file)? != old.stamp
                    {
                        return Err(SessionLeaseError::UnsafePath(
                            "legacy source identity changed".into(),
                        ));
                    }
                    self.check_recovery_lease(id)?;
                    Ok(Some(current))
                }
                _ => Err(SessionLeaseError::InvalidData(
                    "legacy source presence changed".into(),
                )),
            }
        }

        pub(super) fn verify_recovery_legacy(
            &self,
            id: &str,
            saved: &RecoveryLegacy,
        ) -> Result<(), SessionLeaseError> {
            if let Some(mut file) = self.check_recovery_legacy_identity(id, saved)? {
                let original = saved.file.as_ref().ok_or_else(|| {
                    SessionLeaseError::InvalidData("legacy source presence changed".into())
                })?;
                verify_recovery_contents(&mut file, original, MAX_RECOVERY_LEGACY_BYTES)?;
                self.check_recovery_legacy_identity(id, saved)?;
            }
            self.check_recovery_lease(id)
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
            let lock = open_at(
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
            let mut storage = Self {
                path,
                home,
                sessions,
                leases,
                lock,
                owner_pid: std::process::id(),
                #[cfg(test)]
                fail_before_rename: std::cell::Cell::new(false),
                #[cfg(test)]
                fail_directory_sync: std::cell::Cell::new(false),
            };
            storage.verify_location(id)?;
            let metadata = serde_json::json!({"session_id":id,"kind":kind,"pid":storage.owner_pid});
            let bytes = serde_json::to_vec(&metadata)
                .map_err(|e| SessionLeaseError::InvalidData(e.to_string()))?;
            storage.lock.set_len(0).map_err(io)?;
            storage.lock.seek(SeekFrom::Start(0)).map_err(io)?;
            storage.lock.write_all(&bytes).map_err(io)?;
            storage.lock.sync_all().map_err(io)?;
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
            self.load_optional(id)?
                .ok_or_else(|| io(std::io::Error::from_raw_os_error(libc::ENOENT)))
        }

        pub(super) fn load_optional(&self, id: &str) -> Result<Option<Vec<u8>>, SessionLeaseError> {
            self.verify_location(id)?;
            let file = match open_at(
                &self.sessions,
                OsStr::new(&format!("{id}.json")),
                libc::O_RDONLY,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.verify_location(id)?;
                    return Ok(None);
                }
                Err(error) => return Err(path_error(error)),
            };
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
            self.verify_location(id)?;
            Ok(Some(raw))
        }

        pub(super) fn save(&self, id: &str, raw: &[u8]) -> Result<(), SessionLeaseError> {
            self.publish_snapshot(id, raw, false, None)
        }

        pub(super) fn save_if_absent(&self, id: &str, raw: &[u8]) -> Result<(), SessionLeaseError> {
            self.publish_snapshot(id, raw, true, None)
        }

        pub(super) fn save_matching_snapshot(
            &self,
            id: &str,
            raw: &[u8],
            expected: &RecoveryFile,
        ) -> Result<(), SessionLeaseError> {
            self.publish_snapshot(id, raw, false, Some(expected))
        }

        fn publish_snapshot(
            &self,
            id: &str,
            raw: &[u8],
            create_only: bool,
            expected: Option<&RecoveryFile>,
        ) -> Result<(), SessionLeaseError> {
            if raw.len() as u64 > MAX_SESSION_BYTES {
                return Err(SessionLeaseError::InvalidData(
                    "session exceeds storage byte bound".into(),
                ));
            }
            self.verify_location(id)?;
            let target = format!("{id}.json");
            match open_at(&self.sessions, OsStr::new(&target), libc::O_RDONLY) {
                Ok(file) => {
                    private_file(&file, MAX_SESSION_BYTES)?;
                    if create_only {
                        return Err(SessionLeaseError::AlreadyExists {
                            session_id: id.into(),
                        });
                    }
                }
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
            let mut published = false;
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
                if let Some(expected) = expected {
                    self.verify_recovery_file(id, expected)?;
                }
                let temporary = name(OsStr::new(&temporary))?;
                let target = name(OsStr::new(&target))?;
                if create_only {
                    // SAFETY: both terminated names use the same held directory.
                    // linkat never replaces an existing destination.
                    if unsafe {
                        libc::linkat(
                            self.sessions.as_raw_fd(),
                            temporary.as_ptr(),
                            self.sessions.as_raw_fd(),
                            target.as_ptr(),
                            0,
                        )
                    } < 0
                    {
                        let error = std::io::Error::last_os_error();
                        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                            SessionLeaseError::AlreadyExists {
                                session_id: id.into(),
                            }
                        } else {
                            path_error(error)
                        });
                    }
                    published = true;
                    // SAFETY: remove only this operation's still-owned temporary link.
                    if unsafe { libc::unlinkat(self.sessions.as_raw_fd(), temporary.as_ptr(), 0) }
                        < 0
                    {
                        return Err(io(std::io::Error::last_os_error()));
                    }
                } else {
                    // SAFETY: both bounded local names use the held directory FD.
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
                    published = true;
                }
                #[cfg(test)]
                if self.fail_directory_sync.replace(false) {
                    return Err(SessionLeaseError::PublicationUncertain(
                        "injected post-rename directory sync failure".into(),
                    ));
                }
                self.sessions
                    .sync_all()
                    .map_err(|e| SessionLeaseError::PublicationUncertain(e.to_string()))?;
                self.verify_location(id)
            })();
            if result.is_err() {
                let temporary = name(OsStr::new(&temporary))?;
                // SAFETY: cleanup removes only the unique temp entry this operation created.
                unsafe {
                    libc::unlinkat(self.sessions.as_raw_fd(), temporary.as_ptr(), 0);
                }
            }
            result.map_err(|error| {
                if published && !matches!(error, SessionLeaseError::PublicationUncertain(_)) {
                    SessionLeaseError::PublicationUncertain(error.to_string())
                } else {
                    error
                }
            })
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

/// Save through the same owned storage and immutable workspace policy as live sessions.
pub fn save_session(home: &Path, session: &SessionFile) -> Result<(), String> {
    SessionLease::acquire(home, &session.session_id, "session-save")
        .and_then(|lease| lease.save(session))
        .map_err(|error| error.to_string())
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
    let workspace = current_workspace().map_err(|error| error.to_string())?;
    let (source_lease, mut src) =
        SessionLease::acquire_for_workspace(home, session_id, "session-fork", &workspace)
            .map_err(|error| error.to_string())?;
    let new_id = orbit_gateway::new_session_id();
    src.session_id = new_id.clone();
    src.accounting_watermark = None;
    src.updated_at = crate::timestamp_now();
    // The fork's JSONL transcript (if one exists) is copied too, so
    // `--resume <fork>` and the TUI's event-sourced view agree with the
    // JSON file.
    let jsonl_src = home
        .join("projects")
        .join(format!("{}.jsonl", source_lease.session_id()));
    if jsonl_src.exists() {
        let jsonl_dst = home.join("projects").join(format!("{new_id}.jsonl"));
        std::fs::copy(&jsonl_src, &jsonl_dst).map_err(|e| format!("copy transcript: {e}"))?;
    }
    save_session(home, &src)?;
    Ok(src)
}

/// The latest eligible history, excluding foreign and unbound legacy sessions.
pub fn latest_for_workspace(home: &Path, workspace: &Path) -> Result<Option<SessionFile>, String> {
    let workspace = canonical_workspace(workspace).map_err(|error| error.to_string())?;
    Ok(list_sessions(home)?
        .into_iter()
        .find(|saved| saved.require_workspace(&workspace).is_ok()))
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
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).unwrap();
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
        .in_workspace(&current_workspace().unwrap())
        .unwrap()
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
        let home = test_home("fork-history");
        let src = sample("session-src");
        save_session(&home, &src).unwrap();

        let fork = fork_session(&home, "session-src").unwrap();
        assert_ne!(fork.session_id, "session-src");
        assert_eq!(fork.transcript.len(), src.transcript.len());
        assert_eq!(fork.model, src.model);
        assert_eq!(fork.workspace, src.workspace);
        assert_eq!(
            load_session(&home, &fork.session_id).unwrap().workspace,
            src.workspace
        );

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
        let home = test_home("fork-jsonl");
        std::fs::create_dir_all(home.join("projects")).unwrap();
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

#[cfg(all(test, unix))]
mod create_only_durability_tests {
    use super::{SessionFile, SessionLease, SessionLeaseError};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    struct Home(std::path::PathBuf);
    impl Home {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("orbit-create-only-fault-{}", ulid::Ulid::new()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn sample(model: &str) -> SessionFile {
        SessionFile::from_chat(
            "new-session",
            model,
            "http://127.0.0.1:1",
            "fixture",
            &[],
            0,
            0,
            0,
            0,
        )
    }

    #[test]
    fn staged_create_only_failure_keeps_absence_and_removes_the_owned_stage() {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "new-session", "fixture").unwrap();
        lease.storage.inject_prepublication_failure();
        assert!(matches!(
            lease.save_if_absent(&sample("staged")),
            Err(SessionLeaseError::Io(_))
        ));
        assert!(lease.load_optional().unwrap().is_none());
        let entries: Vec<_> = std::fs::read_dir(home.0.join("sessions"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, [std::ffi::OsString::from(".leases")]);
        lease
            .save_if_absent(&sample("retry-before-publication"))
            .unwrap();
        assert_eq!(lease.load().unwrap().model, "retry-before-publication");
        assert_eq!(
            std::fs::metadata(home.0.join("sessions/new-session.json"))
                .unwrap()
                .nlink(),
            1
        );
    }

    #[test]
    fn published_create_only_sync_failure_is_uncertain_and_cannot_be_overwritten_on_retry() {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "new-session", "fixture").unwrap();
        lease.storage.inject_directory_sync_failure();
        assert!(matches!(
            lease.save_if_absent(&sample("published")),
            Err(SessionLeaseError::PublicationUncertain(_))
        ));
        let path = home.0.join("sessions/new-session.json");
        let visible = std::fs::read(&path).unwrap();
        assert_eq!(lease.load().unwrap().model, "published");
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
        assert!(matches!(
            lease.save_if_absent(&sample("replacement")),
            Err(SessionLeaseError::AlreadyExists { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), visible);
        assert!(
            !std::fs::read_dir(home.0.join("sessions"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
        drop(lease);
        let lease = SessionLease::acquire(&home.0, "new-session", "fixture").unwrap();
        assert_eq!(lease.load().unwrap().model, "published");
        assert!(matches!(
            lease.save_if_absent(&sample("after-restart")),
            Err(SessionLeaseError::AlreadyExists { .. })
        ));
        assert_eq!(std::fs::read(path).unwrap(), visible);
    }
}

#[cfg(all(test, unix))]
mod recovery_capture_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};

    struct Home(PathBuf);
    impl Home {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("orbit-recovery-snapshot-{}", ulid::Ulid::new()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn snapshot(&self) -> PathBuf {
            self.0.join("sessions/source.json")
        }
        fn legacy(&self) -> PathBuf {
            self.0.join("projects/source.jsonl")
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn write(path: &Path, raw: &[u8]) {
        std::fs::write(path, raw).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn stamp(path: &Path) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
        let m = std::fs::symlink_metadata(path).unwrap();
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }
    fn saved() -> SessionFile {
        let mut value = SessionFile::from_chat(
            "source",
            "inert-model",
            "http://127.0.0.1:1/private",
            "inert-provider",
            &[orbit_engine::user_message("saved original")],
            3,
            0,
            0,
            0,
        );
        value.accounting_watermark = Some(SessionAccountingWatermark {
            owner_session_id: "source".into(),
            child_id: None,
            revision: 0,
            known_input_tokens: 0,
            known_output_tokens: 0,
            known_ordinary_microcents: 0,
            known_housekeeping_microcents: 0,
            full_cost_status: FullCostStatus::Known,
        });
        value
    }

    #[test]
    fn snapshot_capture_keeps_exact_noncanonical_raw_bytes_and_small_watermark_facts() {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "source", "recovery-fixture").unwrap();
        lease.save(&saved()).unwrap();
        let raw = format!(" \n{}\n ", serde_json::to_string(&saved()).unwrap()).into_bytes();
        write(&home.snapshot(), &raw);
        let before = stamp(&home.snapshot());
        let lock_before = std::fs::read(home.0.join("sessions/.leases/source.lock")).unwrap();
        let capture = lease.capture_for_recovery().unwrap();
        assert_eq!(capture.owner_session_id(), "source");
        assert_eq!(capture.bytes(), raw);
        assert_eq!(capture.sha256(), hex::encode(Sha256::digest(&raw)));
        assert_eq!(
            capture.facts(),
            &SessionRecoveryFacts {
                turns: 3,
                watermark_revision: Some(0),
                watermark_full_cost_status: Some(FullCostStatus::Known)
            }
        );
        capture.verify_unchanged(&lease).unwrap();
        assert_eq!(stamp(&home.snapshot()), before);
        assert_eq!(std::fs::read(home.snapshot()).unwrap(), raw);
        assert_eq!(
            std::fs::read(home.0.join("sessions/.leases/source.lock")).unwrap(),
            lock_before
        );
    }

    #[test]
    fn snapshot_capture_missing_invalid_public_linked_and_oversize_sources_never_change_them() {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "source", "recovery-fixture").unwrap();
        assert!(lease.capture_for_recovery().is_err());
        assert!(!home.snapshot().exists());
        write(
            &home.snapshot(),
            b"{\"schema\":\"wrong\",\"private\":\"INVALID_RECOVERY_BODY\"}",
        );
        let before = stamp(&home.snapshot());
        let error = lease.capture_for_recovery().err().unwrap().to_string();
        assert!(error.len() <= 512 && !error.contains("INVALID_RECOVERY_BODY"));
        assert_eq!(stamp(&home.snapshot()), before);
        let malformed = std::fs::read(home.snapshot()).unwrap();
        assert!(lease.save(&saved()).is_err());
        assert_eq!(stamp(&home.snapshot()), before);
        assert_eq!(std::fs::read(home.snapshot()).unwrap(), malformed);
        write(&home.snapshot(), &serde_json::to_vec(&saved()).unwrap());
        std::fs::set_permissions(home.snapshot(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = stamp(&home.snapshot());
        assert!(lease.capture_for_recovery().is_err());
        assert_eq!(stamp(&home.snapshot()), before);
        std::fs::set_permissions(home.snapshot(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(home.snapshot(), home.0.join("linked-snapshot")).unwrap();
        assert!(lease.capture_for_recovery().is_err());
        assert_eq!(
            std::fs::symlink_metadata(home.snapshot()).unwrap().nlink(),
            2
        );
        std::fs::remove_file(home.0.join("linked-snapshot")).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(home.snapshot())
            .unwrap();
        file.set_len(64 * 1024 * 1024 + 1).unwrap();
        let before = stamp(&home.snapshot());
        assert!(lease.capture_for_recovery().is_err());
        assert_eq!(stamp(&home.snapshot()), before);
    }

    #[test]
    fn snapshot_verification_rejects_replacement_in_place_change_and_another_lease() {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "source", "recovery-fixture").unwrap();
        lease.save(&saved()).unwrap();
        let capture = lease.capture_for_recovery().unwrap();
        let other = SessionLease::acquire(&home.0, "other", "recovery-fixture").unwrap();
        assert!(capture.verify_unchanged(&other).is_err());
        let bytes = capture.bytes().to_vec();
        std::fs::rename(home.snapshot(), home.0.join("original-snapshot")).unwrap();
        write(&home.snapshot(), &bytes);
        assert!(capture.verify_unchanged(&lease).is_err());
        assert_eq!(
            std::fs::read(home.0.join("original-snapshot")).unwrap(),
            bytes
        );
        let changed = lease.capture_for_recovery().unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(home.snapshot())
            .unwrap()
            .write_all(b" ")
            .unwrap();
        assert!(changed.verify_unchanged(&lease).is_err());
    }

    #[test]
    fn legacy_capture_preserves_malformed_raw_bytes_without_decoding_or_mutation() {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "source", "recovery-fixture").unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(home.0.join("projects"))
            .unwrap();
        let raw = b"not json\n\xff\x00inert legacy original\n";
        write(&home.legacy(), raw);
        let before = stamp(&home.legacy());
        let capture = lease.capture_legacy_for_recovery().unwrap();
        assert_eq!(capture.bytes(), Some(raw.as_slice()));
        assert_eq!(
            capture.sha256(),
            Some(hex::encode(Sha256::digest(raw)).as_str())
        );
        capture.verify_unchanged(&lease).unwrap();
        assert_eq!(stamp(&home.legacy()), before);
        assert_eq!(std::fs::read(home.legacy()).unwrap(), raw);
    }

    #[test]
    fn legacy_positive_absence_is_noncreating_and_presence_change_is_not_absence() {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "source", "recovery-fixture").unwrap();
        let absent = lease.capture_legacy_for_recovery().unwrap();
        assert!(absent.bytes().is_none() && absent.sha256().is_none());
        absent.verify_unchanged(&lease).unwrap();
        assert!(!home.0.join("projects").exists());
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(home.0.join("projects"))
            .unwrap();
        assert!(absent.verify_unchanged(&lease).is_err());
        let empty = lease.capture_legacy_for_recovery().unwrap();
        assert!(empty.bytes().is_none());
        empty.verify_unchanged(&lease).unwrap();
        write(&home.legacy(), b"newly present");
        assert!(empty.verify_unchanged(&lease).is_err());
    }

    #[test]
    fn legacy_unsafe_sources_and_replaced_directory_are_refused_without_cleanup() {
        let home = Home::new();
        let lease = SessionLease::acquire(&home.0, "source", "recovery-fixture").unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(home.0.join("projects"))
            .unwrap();
        let target = home.0.join("absent-target");
        symlink(&target, home.legacy()).unwrap();
        let before = stamp(&home.legacy());
        assert!(lease.capture_legacy_for_recovery().is_err());
        assert_eq!(stamp(&home.legacy()), before);
        assert!(!target.exists());
        std::fs::remove_file(home.legacy()).unwrap();
        write(&home.legacy(), b"old raw");
        std::fs::set_permissions(home.legacy(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(lease.capture_legacy_for_recovery().is_err());
        assert_eq!(
            std::fs::symlink_metadata(home.legacy()).unwrap().mode() & 0o777,
            0o644
        );
        std::fs::set_permissions(home.legacy(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(home.legacy(), home.0.join("legacy-link")).unwrap();
        assert!(lease.capture_legacy_for_recovery().is_err());
        std::fs::remove_file(home.0.join("legacy-link")).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(home.legacy())
            .unwrap();
        file.set_len(32 * 1024 * 1024 + 1).unwrap();
        assert!(lease.capture_legacy_for_recovery().is_err());
        file.set_len(0).unwrap();
        drop(file);
        write(&home.legacy(), b"old raw");
        let capture = lease.capture_legacy_for_recovery().unwrap();
        std::fs::rename(home.0.join("projects"), home.0.join("original-projects")).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(home.0.join("projects"))
            .unwrap();
        write(&home.legacy(), b"old raw");
        assert!(capture.verify_unchanged(&lease).is_err());
        assert_eq!(
            std::fs::read(home.0.join("original-projects/source.jsonl")).unwrap(),
            b"old raw"
        );
    }
}
