//! One owned session shared by local transports and browser adapters.

use crate::sessions::{SessionFile, SessionLease, SessionLeaseError};
use crate::tool_runtime::{ApprovalChannel, ApprovalRequest, ApprovalVerdict, AutoGrants};
use crate::tui_worker::TuiTurnConfig;
use orbit_adapter::types::{ChatMessage, ChatRole, EffortSetting};
use orbit_provider_http::CancelToken;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_PROMPT_BYTES: usize = 64 * 1024;
const MAX_SUBSCRIBERS: usize = 16;
const MAX_EVENT_BYTES: usize = 32 * 1024;
const MAX_REQUESTS: usize = 256;
const MAX_RECOVERY_BYTES: usize = 96 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum OwnerError {
    #[error("another client already controls this session")]
    ControllerBusy,
    #[error("a controlling client is required")]
    NotController,
    #[error("session is busy or stopping")]
    Busy,
    #[error("invalid owner action: {0}")]
    Invalid(String),
    #[error("local protocol: {0}")]
    Protocol(String),
    #[error("owned session: {0}")]
    Runtime(String),
    #[error(transparent)]
    Storage(#[from] SessionLeaseError),
}

impl OwnerError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::ControllerBusy => "controller_busy",
            Self::NotController => "not_controller",
            Self::Busy => "busy",
            Self::Invalid(_) => "invalid",
            Self::Protocol(_) => "protocol",
            Self::Runtime(_) => "runtime",
            Self::Storage(SessionLeaseError::PublicationUncertain(_)) => "publication_uncertain",
            Self::Storage(_) => "storage",
        }
    }
}

#[derive(Clone)]
pub struct OwnerConfig {
    pub turn: TuiTurnConfig,
    pub working_dir: PathBuf,
    pub replay_capacity: usize,
}

impl OwnerConfig {
    pub fn new(turn: TuiTurnConfig, working_dir: PathBuf) -> Self {
        Self {
            turn,
            working_dir,
            replay_capacity: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCursor {
    pub instance: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerEvent {
    pub cursor: EventCursor,
    pub kind: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnState {
    Idle,
    Running,
    Interrupted,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Accepted,
    Running,
    Completed,
    Failed,
    Interrupted,
    Unknown,
}

impl RequestState {
    fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecord {
    pub payload_digest: String,
    pub state: RequestState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerSnapshot {
    pub cursor: EventCursor,
    pub session_id: String,
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub selection_origin: crate::phase_routing::SelectionOrigin,
    #[serde(default)]
    pub last_route: Option<Value>,
    pub effort: Option<EffortSetting>,
    pub effort_status: String,
    pub supported_efforts: Option<Vec<orbit_adapter::types::EffortValue>>,
    pub resolved_effort: Option<orbit_adapter::types::EffortValue>,
    pub permission_mode: orbit_tools::permissions::PermissionMode,
    pub state: TurnState,
    pub messages: Vec<Value>,
    pub partial_response: String,
    pub pending_approvals: Vec<Value>,
    pub current_request: Option<String>,
    pub requests: BTreeMap<String, RequestRecord>,
    pub turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microcents: u64,
}

fn control_settings(snapshot: &OwnerSnapshot) -> Value {
    json!({"model":snapshot.model,"provider":snapshot.provider,"session_id":snapshot.session_id,
        "effort":snapshot.effort,"effort_status":snapshot.effort_status,
        "supported_efforts":snapshot.supported_efforts,"resolved_effort":snapshot.resolved_effort,
        "selection_origin":snapshot.selection_origin,"last_route":snapshot.last_route})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recovery {
    pub snapshot: Option<OwnerSnapshot>,
    pub events: Vec<OwnerEvent>,
    pub cursor: EventCursor,
}

pub struct OwnerSubscription {
    pub recovery: Recovery,
    events: mpsc::Receiver<OwnerEvent>,
    _registration: SubscriptionRegistration,
}

struct SubscriptionRegistration {
    hub: Weak<Mutex<Hub>>,
    id: String,
}
impl Drop for SubscriptionRegistration {
    fn drop(&mut self) {
        if let Some(hub) = self.hub.upgrade()
            && let Ok(mut hub) = hub.lock()
        {
            hub.subscribers.retain(|(id, _)| *id != self.id);
        }
    }
}

impl OwnerSubscription {
    pub fn recv_timeout(&self, timeout: Duration) -> Result<OwnerEvent, mpsc::RecvTimeoutError> {
        self.events.recv_timeout(timeout)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalChoice {
    AllowOnce,
    AllowSession,
    AllowRuleSession,
    AllowRuleAlways,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerAction {
    Prompt {
        request_id: String,
        text: String,
    },
    Approval {
        call_id: String,
        verdict: ApprovalChoice,
        note: Option<String>,
    },
    Cancel,
    Stop,
    ListModels,
    ListSessions,
    Effort,
    Routing,
    RouteAuto,
    SetEffort {
        choice: EffortSetting,
    },
    SetModel {
        model: String,
        provider: Option<String>,
    },
    SetMode {
        mode: String,
    },
    Resume {
        session_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAck {
    pub request_id: Option<String>,
    pub state: String,
    pub duplicate: bool,
}

struct ApprovalResponse {
    verdict: ApprovalVerdict,
    note: Option<String>,
}
struct Hub {
    snapshot: OwnerSnapshot,
    replay: VecDeque<OwnerEvent>,
    capacity: usize,
    subscribers: Vec<(String, mpsc::SyncSender<OwnerEvent>)>,
    controller: Option<String>,
    approvals: HashMap<String, mpsc::SyncSender<ApprovalResponse>>,
    cancel: Option<CancelToken>,
    stopping: bool,
    masks: Vec<String>,
    home: PathBuf,
    configuring: bool,
    pane_agents: BTreeMap<String, orbit_frontend_protocol::customization::PaneAgent>,
}

impl Hub {
    fn emit(&mut self, kind: &str, payload: Value) {
        self.snapshot.cursor.sequence += 1;
        let mut payload = safe_json(payload, &self.masks);
        if serde_json::to_vec(&payload).map_or(true, |bytes| bytes.len() > MAX_EVENT_BYTES) {
            payload = json!({"truncated":true,"message":"event exceeds display limit"});
        }
        let event = OwnerEvent {
            cursor: self.snapshot.cursor.clone(),
            kind: kind.into(),
            payload,
        };
        self.replay.push_back(event.clone());
        while self.replay.len() > self.capacity {
            self.replay.pop_front();
        }
        self.subscribers
            .retain(|(_, subscriber)| subscriber.try_send(event.clone()).is_ok());
    }
}

pub(crate) fn scan_display(text: &str) -> String {
    if text.len() > 64 * 1024 {
        return "[truncated: display text exceeds limit]".into();
    }
    // Keep assignment and PEM context, then scan every token span. A harmless
    // short prefix must not conceal a later real token from the common scanner.
    let scanned = orbit_tools::scan::scan_result(text);
    let mut safe = String::with_capacity(scanned.text.len());
    for span in scanned.text.split_inclusive(|character: char| {
        !(character.is_ascii_alphanumeric() || character == '_' || character == '-')
    }) {
        safe.push_str(&orbit_tools::scan::scan_result(span).text);
    }
    orbit_hud_tui::safe_text(&safe)
}

fn safe_text(text: &str, masks: &[String]) -> String {
    if text.len() > 64 * 1024 {
        return "[truncated: display text exceeds limit]".into();
    }
    let mut text = text.to_owned();
    for mask in masks.iter().filter(|mask| !mask.is_empty()) {
        text = text.replace(mask, "[redacted:configuration]");
    }
    let text = scan_display(&text);
    if text.len() <= 4096 {
        text
    } else {
        let mut end = 4096;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{} [truncated]", &text[..end])
    }
}

fn safe_json(value: Value, masks: &[String]) -> Value {
    match value {
        Value::String(text) => Value::String(safe_text(&text, masks)),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .take(128)
                .map(|value| safe_json(value, masks))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .take(64)
                .map(|(key, value)| (safe_text(&key, masks), safe_json(value, masks)))
                .collect(),
        ),
        other => other,
    }
}

fn visible_messages(transcript: &[ChatMessage], masks: &[String]) -> Vec<Value> {
    let mut messages = transcript.iter().filter_map(|message| match message.role {
        ChatRole::User => Some(json!({"role":"user","text":safe_text(&message.content,masks)})),
        ChatRole::Assistant if message.tool_calls.is_some() => message.tool_calls.as_ref().and_then(|calls| calls.first()).map(|call| json!({"role":"tool","text":safe_text(&format!("[tool] {}",call.name),masks)})),
        ChatRole::Assistant if !message.content.is_empty() => Some(json!({"role":"assistant","text":safe_text(&message.content,masks)})),
        _ => None,
    }).rev().take(128).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>();
    let mut bytes = messages
        .iter()
        .map(|message| {
            serde_json::to_vec(message).map_or(MAX_RECOVERY_BYTES, |encoded| encoded.len())
        })
        .sum::<usize>();
    let mut omitted = false;
    while bytes > 48 * 1024 && !messages.is_empty() {
        let removed = messages.remove(0);
        bytes =
            bytes.saturating_sub(serde_json::to_vec(&removed).map_or(0, |encoded| encoded.len()));
        omitted = true;
    }
    if omitted || transcript.len() > 128 {
        messages.insert(0,json!({"role":"status","text":"Showing the latest saved conversation.","truncated":true}));
    }
    messages
}

fn configured_turn(config: &TuiTurnConfig) -> Result<orbit_engine::TurnConfig, OwnerError> {
    let declared =
        crate::config::ProvidersConfig::load(&config.home).map_err(OwnerError::Invalid)?;
    let mut turn = crate::checked_model_turn(
        &config.home,
        &config.model,
        Some(&config.provider_id),
        declared.provider.is_empty().then_some(config.gate.as_str()),
        true,
    )
    .map_err(OwnerError::Invalid)?;
    if let Some(effort) = &config.effort {
        crate::apply_effort_setting(&config.home, &mut turn, effort)
            .map_err(OwnerError::Invalid)?;
    }
    turn.validate_effort().map_err(OwnerError::Invalid)?;
    Ok(turn)
}

enum Work {
    Prompt {
        request_id: String,
        text: String,
        reply: mpsc::SyncSender<Result<ActionAck, OwnerError>>,
    },
    Configure {
        action: OwnerAction,
        reply: mpsc::SyncSender<Result<ActionAck, OwnerError>>,
    },
    Stop,
}

#[derive(Clone)]
pub struct OwnerHandle {
    hub: Arc<Mutex<Hub>>,
    commands: mpsc::SyncSender<Work>,
}

impl OwnerHandle {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Hub>, OwnerError> {
        self.hub
            .lock()
            .map_err(|_| OwnerError::Runtime("session state poisoned".into()))
    }
    pub fn snapshot(&self) -> Result<OwnerSnapshot, OwnerError> {
        Ok(self.lock()?.snapshot.clone())
    }
    /// The session label and facts are projected from one held owner lock.
    pub fn pane_context_with_session(
        &self,
    ) -> Result<(String, orbit_frontend_protocol::customization::PaneContext), OwnerError> {
        let hub = self.lock()?;
        let context = orbit_frontend_protocol::customization::PaneContext {
            routing: hub
                .snapshot
                .last_route
                .as_ref()
                .map(|route| vec![safe_text(&route.to_string(), &hub.masks)])
                .unwrap_or_default(),
            input_tokens: hub.snapshot.input_tokens,
            output_tokens: hub.snapshot.output_tokens,
            cost_microcents: hub.snapshot.cost_microcents,
            agents: hub.pane_agents.values().take(32).cloned().collect(),
            permission_mode: Some(
                match hub.snapshot.permission_mode {
                    orbit_tools::permissions::PermissionMode::Default => "default",
                    orbit_tools::permissions::PermissionMode::AcceptEdits => "acceptEdits",
                    orbit_tools::permissions::PermissionMode::Plan => "plan",
                    orbit_tools::permissions::PermissionMode::DontAsk => "dontAsk",
                    orbit_tools::permissions::PermissionMode::Bypass => "bypass",
                }
                .into(),
            ),
            controller: false,
        };
        Ok((hub.snapshot.session_id.clone(), context))
    }
    pub fn pane_context(
        &self,
    ) -> Result<orbit_frontend_protocol::customization::PaneContext, OwnerError> {
        self.pane_context_with_session().map(|(_, context)| context)
    }
    pub fn is_stopping(&self) -> bool {
        self.lock().map_or(true, |hub| hub.stopping)
    }
    pub fn subscribe(&self, cursor: Option<&EventCursor>) -> Result<OwnerSubscription, OwnerError> {
        let mut hub = self.lock()?;
        if hub.subscribers.len() >= MAX_SUBSCRIBERS {
            return Err(OwnerError::Busy);
        }
        let valid = cursor.is_some_and(|cursor| {
            cursor.instance == hub.snapshot.cursor.instance
                && cursor.sequence <= hub.snapshot.cursor.sequence
                && hub
                    .replay
                    .front()
                    .map_or(cursor.sequence == hub.snapshot.cursor.sequence, |first| {
                        cursor.sequence.saturating_add(1) >= first.cursor.sequence
                    })
        });
        let mut recovery = Recovery {
            snapshot: (!valid).then(|| hub.snapshot.clone()),
            events: if valid {
                hub.replay
                    .iter()
                    .filter(|event| event.cursor.sequence > cursor.unwrap().sequence)
                    .cloned()
                    .collect()
            } else {
                vec![]
            },
            cursor: hub.snapshot.cursor.clone(),
        };
        if serde_json::to_vec(&recovery.events)
            .map_or(true, |bytes| bytes.len() > MAX_RECOVERY_BYTES)
        {
            recovery.snapshot = Some(hub.snapshot.clone());
            recovery.events.clear();
        }
        let (sender, events) = mpsc::sync_channel(hub.capacity);
        let id = ulid::Ulid::new().to_string();
        hub.subscribers.push((id.clone(), sender));
        Ok(OwnerSubscription {
            recovery,
            events,
            _registration: SubscriptionRegistration {
                hub: Arc::downgrade(&self.hub),
                id,
            },
        })
    }
    pub fn claim_controller(&self) -> Result<ControllerLease, OwnerError> {
        let mut hub = self.lock()?;
        if hub.stopping {
            return Err(OwnerError::Busy);
        }
        if hub.controller.is_some() {
            return Err(OwnerError::ControllerBusy);
        }
        let token = ulid::Ulid::new().to_string();
        hub.controller = Some(token.clone());
        Ok(ControllerLease {
            handle: self.clone(),
            token,
        })
    }
    fn stop(&self) {
        if let Ok(mut hub) = self.lock() {
            hub.stopping = true;
            hub.snapshot.state = TurnState::Stopping;
            if let Some(cancel) = &hub.cancel {
                cancel.cancel();
            }
            let _ = self.commands.try_send(Work::Stop);
        }
    }
}

pub struct ControllerLease {
    handle: OwnerHandle,
    token: String,
}
impl ControllerLease {
    /// Authorize a local frontend operation without emitting events or provider work.
    pub fn check(&self) -> Result<(), OwnerError> {
        let hub = self.handle.lock()?;
        if hub.controller.as_deref() != Some(&self.token) {
            return Err(OwnerError::NotController);
        }
        if hub.stopping {
            return Err(OwnerError::Busy);
        }
        Ok(())
    }
    pub fn send(&mut self, action: OwnerAction) -> Result<ActionAck, OwnerError> {
        let mut hub = self.handle.lock()?;
        if hub.controller.as_deref() != Some(&self.token) {
            return Err(OwnerError::NotController);
        }
        if hub.stopping {
            return Err(OwnerError::Busy);
        }
        match action {
            OwnerAction::Prompt { request_id, text } => {
                if request_id.is_empty()
                    || request_id.len() > 128
                    || !request_id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                    || text.trim().is_empty()
                    || text.len() > MAX_PROMPT_BYTES
                {
                    return Err(OwnerError::Invalid(
                        "invalid request identity or prompt size".into(),
                    ));
                }
                let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
                if let Some(record) = hub.snapshot.requests.get(&request_id) {
                    if record.payload_digest != digest {
                        return Err(OwnerError::Invalid(
                            "request identity was reused with a different payload".into(),
                        ));
                    }
                    return Ok(ActionAck {
                        request_id: Some(request_id),
                        state: record.state.label().into(),
                        duplicate: true,
                    });
                }
                if hub.snapshot.state == TurnState::Running || hub.configuring {
                    return Err(OwnerError::Busy);
                }
                if hub.snapshot.requests.len() >= MAX_REQUESTS {
                    return Err(OwnerError::Invalid(
                        "request history is full; start a new session".into(),
                    ));
                }
                hub.snapshot.requests.insert(
                    request_id.clone(),
                    RequestRecord {
                        payload_digest: digest,
                        state: RequestState::Accepted,
                    },
                );
                let cancel = CancelToken::new();
                hub.cancel = Some(cancel);
                hub.snapshot.state = TurnState::Running;
                hub.snapshot.current_request = Some(request_id.clone());
                hub.snapshot.partial_response.clear();
                let (reply, answer) = mpsc::sync_channel(1);
                if self
                    .handle
                    .commands
                    .try_send(Work::Prompt {
                        request_id: request_id.clone(),
                        text,
                        reply,
                    })
                    .is_err()
                {
                    hub.snapshot.requests.remove(&request_id);
                    hub.snapshot.state = TurnState::Idle;
                    hub.cancel = None;
                    return Err(OwnerError::Busy);
                }
                drop(hub);
                await_ack(answer)
            }
            OwnerAction::Approval {
                call_id,
                verdict,
                note,
            } => {
                if note.as_ref().is_some_and(|note| note.len() > 4096) {
                    return Err(OwnerError::Invalid("denial note exceeds limit".into()));
                }
                let sender = hub
                    .approvals
                    .remove(&call_id)
                    .ok_or_else(|| OwnerError::Invalid("stale or unknown approval ID".into()))?;
                let verdict = match verdict {
                    ApprovalChoice::AllowOnce => ApprovalVerdict::AllowOnce,
                    ApprovalChoice::AllowSession => ApprovalVerdict::AllowSession,
                    ApprovalChoice::AllowRuleSession => ApprovalVerdict::AllowRuleSession,
                    ApprovalChoice::AllowRuleAlways => ApprovalVerdict::AllowRuleAlways,
                    ApprovalChoice::Deny => ApprovalVerdict::Deny,
                };
                sender
                    .try_send(ApprovalResponse { verdict, note })
                    .map_err(|_| OwnerError::Invalid("approval already resolved".into()))?;
                Ok(ActionAck {
                    request_id: None,
                    state: "approval_resolved".into(),
                    duplicate: false,
                })
            }
            OwnerAction::Cancel => {
                if let Some(cancel) = &hub.cancel {
                    cancel.cancel();
                }
                Ok(ActionAck {
                    request_id: hub.snapshot.current_request.clone(),
                    state: "cancelling".into(),
                    duplicate: false,
                })
            }
            OwnerAction::Stop => {
                drop(hub);
                self.handle.stop();
                Ok(ActionAck {
                    request_id: None,
                    state: "stopping".into(),
                    duplicate: false,
                })
            }
            OwnerAction::ListModels => {
                let providers =
                    crate::config::ProvidersConfig::load(&hub.home).map_err(OwnerError::Invalid)?;
                let models = providers
                    .all_models()
                    .into_iter()
                    .take(128)
                    .map(|(provider, model)| json!({"provider":provider,"model":model}))
                    .collect::<Vec<_>>();
                hub.emit("models", json!({"models":models}));
                Ok(ActionAck {
                    request_id: None,
                    state: "models".into(),
                    duplicate: false,
                })
            }
            OwnerAction::ListSessions => {
                let sessions=crate::sessions::list_sessions(&hub.home).map_err(OwnerError::Invalid)?.into_iter().take(128).map(|session|json!({"session_id":session.session_id,"model":session.model,"provider":session.provider,"turns":session.turns,"updated_at":session.updated_at})).collect::<Vec<_>>();
                hub.emit("sessions", json!({"sessions":sessions}));
                Ok(ActionAck {
                    request_id: None,
                    state: "sessions".into(),
                    duplicate: false,
                })
            }
            OwnerAction::Effort => {
                let status = hub.snapshot.effort_status.clone();
                let selected = hub.snapshot.effort.clone();
                let settings = control_settings(&hub.snapshot);
                hub.emit(
                    "effort",
                    json!({"text":status,"selected":selected,"settings":settings}),
                );
                Ok(ActionAck {
                    request_id: None,
                    state: "effort".into(),
                    duplicate: false,
                })
            }
            OwnerAction::Routing => {
                let origin = hub.snapshot.selection_origin;
                let decision = hub.snapshot.last_route.clone();
                hub.emit(
                    "routing",
                    json!({"selection_origin":origin,"last_route":decision}),
                );
                Ok(ActionAck {
                    request_id: None,
                    state: "routing".into(),
                    duplicate: false,
                })
            }
            action @ (OwnerAction::SetEffort { .. }
            | OwnerAction::SetModel { .. }
            | OwnerAction::SetMode { .. }
            | OwnerAction::RouteAuto
            | OwnerAction::Resume { .. }) => {
                if hub.snapshot.state == TurnState::Running || hub.configuring {
                    return Err(OwnerError::Busy);
                }
                hub.configuring = true;
                let (reply, answer) = mpsc::sync_channel(1);
                if self
                    .handle
                    .commands
                    .try_send(Work::Configure { action, reply })
                    .is_err()
                {
                    hub.configuring = false;
                    return Err(OwnerError::Busy);
                }
                drop(hub);
                await_ack(answer)
            }
        }
    }
}

fn await_ack(
    answer: mpsc::Receiver<Result<ActionAck, OwnerError>>,
) -> Result<ActionAck, OwnerError> {
    answer.recv_timeout(Duration::from_secs(10)).map_err(|_| {
        OwnerError::Runtime(
            "action outcome is unknown; inspect the session without resubmitting".into(),
        )
    })?
}
impl Drop for ControllerLease {
    fn drop(&mut self) {
        if let Ok(mut hub) = self.handle.lock()
            && hub.controller.as_deref() == Some(&self.token)
        {
            hub.controller = None;
        }
    }
}

pub struct OwnerRuntime {
    handle: OwnerHandle,
    worker: Option<JoinHandle<Result<(), OwnerError>>>,
}
impl OwnerRuntime {
    pub fn start(config: OwnerConfig, lease: SessionLease) -> Result<Self, OwnerError> {
        let configured_home = if config.turn.home.is_absolute() {
            config.turn.home.clone()
        } else {
            std::env::current_dir()
                .map_err(|error| OwnerError::Invalid(error.to_string()))?
                .join(&config.turn.home)
        };
        if config.turn.session_id != lease.session_id()
            || configured_home.components().collect::<PathBuf>()
                != lease.home().components().collect::<PathBuf>()
            || !(1..=1024).contains(&config.replay_capacity)
        {
            return Err(OwnerError::Invalid(
                "lease identity or replay capacity mismatch".into(),
            ));
        }
        if config.turn.model.is_empty()
            || config.turn.model.len() > 512
            || config.turn.provider_id.is_empty()
            || config.turn.provider_id.len() > 512
            || config.turn.gate.len() > 4096
        {
            return Err(OwnerError::Invalid(
                "configuration identity exceeds protocol limits".into(),
            ));
        }
        let turn = configured_turn(&config.turn)?;
        let mut masks = vec![config.turn.gate.clone(), turn.gate.clone()];
        if let Some(value) = turn
            .credential_env
            .as_ref()
            .and_then(|name| std::env::var(name).ok())
            .filter(|value| !value.is_empty())
        {
            masks.push(value);
        }
        let snapshot = OwnerSnapshot {
            cursor: EventCursor {
                instance: ulid::Ulid::new().to_string(),
                sequence: 0,
            },
            session_id: config.turn.session_id.clone(),
            provider: config.turn.provider_id.clone(),
            model: config.turn.model.clone(),
            selection_origin: crate::sessions::read_selection_origin(
                lease.home(),
                lease.session_id(),
            )
            .map_err(OwnerError::Invalid)?,
            last_route: None,
            effort: config.turn.effort.clone(),
            effort_status: crate::effort_status(&config.turn.home, &turn),
            supported_efforts: turn.supported_efforts.clone(),
            resolved_effort: turn.effort.clone(),
            permission_mode: config.turn.scope.mode,
            state: TurnState::Idle,
            messages: visible_messages(&config.turn.initial_transcript, &masks),
            partial_response: String::new(),
            pending_approvals: vec![],
            current_request: None,
            requests: BTreeMap::new(),
            turns: config.turn.initial_turns,
            input_tokens: config.turn.initial_input_tokens,
            output_tokens: config.turn.initial_output_tokens,
            cost_microcents: config.turn.initial_cost_microcents,
        };
        let (commands, receiver) = mpsc::sync_channel(1);
        let handle = OwnerHandle {
            hub: Arc::new(Mutex::new(Hub {
                snapshot,
                replay: VecDeque::new(),
                capacity: config.replay_capacity,
                subscribers: vec![],
                controller: None,
                approvals: HashMap::new(),
                cancel: None,
                stopping: false,
                masks,
                home: config.turn.home.clone(),
                configuring: false,
                pane_agents: BTreeMap::new(),
            })),
            commands,
        };
        let request_store = request_storage::RequestStore::new(lease.home(), lease.session_id())?;
        let saved = request_store.load(lease.session_id())?;
        {
            let mut hub = handle.lock()?;
            hub.snapshot.current_request = saved.current_request;
            hub.snapshot.requests = saved.requests;
            for record in hub.snapshot.requests.values_mut() {
                if matches!(record.state, RequestState::Accepted | RequestState::Running) {
                    record.state = RequestState::Interrupted;
                }
            }
            if hub.snapshot.requests.values().any(|record| {
                matches!(
                    record.state,
                    RequestState::Interrupted | RequestState::Unknown
                )
            }) {
                hub.snapshot.state = TurnState::Interrupted;
            }
        }
        save_live(
            &lease,
            &config.turn,
            &config.turn.initial_transcript,
            &handle.snapshot()?,
        )?;
        request_store.save(&handle.snapshot()?)?;
        let worker_handle = handle.clone();
        let worker = std::thread::Builder::new()
            .name("orbit-session-owner".into())
            .spawn(move || {
                let completion = worker_handle.clone();
                let result = owner_loop(config, lease, request_store, worker_handle, receiver);
                if let Err(error) = &result
                    && let Ok(mut hub) = completion.lock()
                {
                    hub.stopping = true;
                    hub.snapshot.state = TurnState::Interrupted;
                    if let Some(cancel) = &hub.cancel {
                        cancel.cancel();
                    }
                    hub.emit("error", json!({"message":error.to_string()}));
                }
                result
            })
            .map_err(|error| OwnerError::Runtime(error.to_string()))?;
        Ok(Self {
            handle,
            worker: Some(worker),
        })
    }
    pub fn handle(&self) -> OwnerHandle {
        self.handle.clone()
    }
    pub fn shutdown(mut self) -> Result<(), OwnerError> {
        self.handle.stop();
        self.join()
    }
    pub fn wait(mut self) -> Result<(), OwnerError> {
        self.join()
    }
    fn join(&mut self) -> Result<(), OwnerError> {
        let until = Instant::now() + Duration::from_secs(10);
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            if Instant::now() >= until {
                return Err(OwnerError::Runtime(
                    "owner cleanup is still running after deadline".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| OwnerError::Runtime("owner worker panicked".into()))?,
            None => Ok(()),
        }
    }
}
impl Drop for OwnerRuntime {
    fn drop(&mut self) {
        self.handle.stop();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedRequests {
    schema: String,
    session_id: String,
    current_request: Option<String>,
    requests: BTreeMap<String, RequestRecord>,
}

#[cfg(unix)]
#[allow(unsafe_code)] // Atomic FD-relative request records under the held session lease.
mod request_storage {
    use super::*;
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    const MAX_BYTES: u64 = 256 * 1024;

    pub(super) struct RequestStore {
        directory: File,
        path: PathBuf,
        file_name: String,
        owner: u32,
    }
    fn error(error: std::io::Error) -> OwnerError {
        OwnerError::Runtime(format!("request records: {error}"))
    }
    fn open_at(directory: &File, name: &str, flags: i32) -> Result<File, std::io::Error> {
        let name =
            CString::new(name).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: terminated bounded local name and owned directory descriptor.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful openat returned a newly owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn validate(file: &File, owner: u32) -> Result<(), OwnerError> {
        let metadata = file.metadata().map_err(error)?;
        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(OwnerError::Invalid(
                "request record is not private, owned, regular and singly linked".into(),
            ));
        }
        if metadata.len() > MAX_BYTES {
            return Err(OwnerError::Invalid(
                "request record exceeds byte bound".into(),
            ));
        }
        Ok(())
    }
    impl RequestStore {
        pub(super) fn new(home: &Path, id: &str) -> Result<Self, OwnerError> {
            let path = home.join("sessions/.requests");
            for ancestor in path.ancestors() {
                if std::fs::symlink_metadata(ancestor)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    return Err(OwnerError::Invalid("symlink in request record path".into()));
                }
            }
            if !path.exists() {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .map_err(error)?;
                File::open(home.join("sessions"))
                    .and_then(|directory| directory.sync_all())
                    .map_err(error)?;
            }
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
                .map_err(error)?;
            let owner = std::fs::metadata(home).map_err(error)?.uid();
            let metadata = directory.metadata().map_err(error)?;
            if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o777 != 0o700 {
                return Err(OwnerError::Invalid(
                    "request record directory must be private and owned".into(),
                ));
            }
            Ok(Self {
                directory,
                path,
                file_name: format!("{id}.json"),
                owner,
            })
        }
        fn location(&self) -> Result<(), OwnerError> {
            let current = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&self.path)
                .map_err(error)?;
            let first = self.directory.metadata().map_err(error)?;
            let second = current.metadata().map_err(error)?;
            if first.dev() != second.dev()
                || first.ino() != second.ino()
                || second.mode() & 0o777 != 0o700
                || second.uid() != self.owner
            {
                return Err(OwnerError::Invalid(
                    "request record directory changed while owned".into(),
                ));
            }
            Ok(())
        }
        pub(super) fn load(&self, id: &str) -> Result<SavedRequests, OwnerError> {
            self.location()?;
            let file = match open_at(&self.directory, &self.file_name, libc::O_RDONLY) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(SavedRequests {
                        schema: "orbit.owner.requests/v1".into(),
                        session_id: id.into(),
                        current_request: None,
                        requests: BTreeMap::new(),
                    });
                }
                Err(failure) => return Err(error(failure)),
            };
            validate(&file, self.owner)?;
            let mut bytes = vec![];
            file.take(MAX_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(error)?;
            if bytes.len() as u64 > MAX_BYTES {
                return Err(OwnerError::Invalid(
                    "request record exceeds byte bound".into(),
                ));
            }
            let saved: SavedRequests = serde_json::from_slice(&bytes)
                .map_err(|error| OwnerError::Invalid(format!("invalid request record: {error}")))?;
            if saved.schema != "orbit.owner.requests/v1"
                || saved.session_id != id
                || saved.requests.len() > MAX_REQUESTS
                || saved
                    .current_request
                    .as_ref()
                    .is_some_and(|id| !saved.requests.contains_key(id))
            {
                return Err(OwnerError::Invalid(
                    "request record schema, identity or size mismatch".into(),
                ));
            }
            for (id, record) in &saved.requests {
                if id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                    || record.payload_digest.len() != 64
                    || !record
                        .payload_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(OwnerError::Invalid(
                        "invalid durable request identity or digest".into(),
                    ));
                }
            }
            Ok(saved)
        }
        pub(super) fn save(&self, snapshot: &OwnerSnapshot) -> Result<(), OwnerError> {
            self.location()?;
            let saved = SavedRequests {
                schema: "orbit.owner.requests/v1".into(),
                session_id: snapshot.session_id.clone(),
                current_request: snapshot.current_request.clone(),
                requests: snapshot.requests.clone(),
            };
            let bytes = serde_json::to_vec(&saved)
                .map_err(|error| OwnerError::Invalid(error.to_string()))?;
            if bytes.len() as u64 > MAX_BYTES {
                return Err(OwnerError::Invalid(
                    "request record exceeds byte bound".into(),
                ));
            }
            match open_at(&self.directory, &self.file_name, libc::O_RDONLY) {
                Ok(file) => validate(&file, self.owner)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(failure) => return Err(error(failure)),
            }
            let temporary = format!(".requests-{}.tmp", ulid::Ulid::new());
            let mut file = open_at(
                &self.directory,
                &temporary,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(error)?;
            let result = (|| {
                file.write_all(&bytes).map_err(error)?;
                file.sync_all().map_err(error)?;
                self.location()?;
                let source = CString::new(temporary.as_str())
                    .map_err(|error| OwnerError::Invalid(error.to_string()))?;
                let target = CString::new(self.file_name.as_str())
                    .map_err(|error| OwnerError::Invalid(error.to_string()))?;
                // SAFETY: owned directory and terminated locally generated names.
                if unsafe {
                    libc::renameat(
                        self.directory.as_raw_fd(),
                        source.as_ptr(),
                        self.directory.as_raw_fd(),
                        target.as_ptr(),
                    )
                } < 0
                {
                    return Err(error(std::io::Error::last_os_error()));
                }
                self.directory.sync_all().map_err(|error| {
                    OwnerError::Storage(SessionLeaseError::PublicationUncertain(format!(
                        "request records were published: {error}"
                    )))
                })
            })();
            if result.is_err() {
                let temporary = CString::new(temporary)
                    .map_err(|error| OwnerError::Invalid(error.to_string()))?;
                // SAFETY: cleanup removes only the unique temporary entry this operation created.
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), temporary.as_ptr(), 0);
                }
            }
            result
        }
    }
}

fn save_live(
    lease: &SessionLease,
    config: &TuiTurnConfig,
    transcript: &[ChatMessage],
    snapshot: &OwnerSnapshot,
) -> Result<(), OwnerError> {
    lease
        .save(
            &SessionFile::from_chat(
                &config.session_id,
                &config.model,
                &config.gate,
                &config.provider_id,
                transcript,
                snapshot.turns,
                snapshot.input_tokens,
                snapshot.output_tokens,
                snapshot.cost_microcents,
            )
            .with_effort(config.effort.clone())
            .with_selection_origin(snapshot.selection_origin),
        )
        .map_err(OwnerError::Storage)
}

fn masks_for(config: &TuiTurnConfig, turn: &orbit_engine::TurnConfig) -> Vec<String> {
    let mut masks = vec![config.gate.clone(), turn.gate.clone()];
    if let Some(value) = turn
        .credential_env
        .as_ref()
        .and_then(|name| std::env::var(name).ok())
        .filter(|value| !value.is_empty())
    {
        masks.push(value);
    }
    masks
}

fn apply_identity(
    snapshot: &mut OwnerSnapshot,
    config: &TuiTurnConfig,
    turn: &orbit_engine::TurnConfig,
) {
    snapshot.session_id = config.session_id.clone();
    snapshot.provider = config.provider_id.clone();
    snapshot.model = config.model.clone();
    snapshot.effort = config.effort.clone();
    snapshot.effort_status = crate::effort_status(&config.home, turn);
    snapshot.supported_efforts = turn.supported_efforts.clone();
    snapshot.resolved_effort = turn.effort.clone();
    snapshot.permission_mode = config.scope.mode;
}

fn configure_owned(
    action: OwnerAction,
    config: &mut OwnerConfig,
    lease: &mut SessionLease,
    store: &mut request_storage::RequestStore,
    transcript: &mut Vec<ChatMessage>,
    grants: &mut AutoGrants,
    handle: &OwnerHandle,
) -> Result<ActionAck, OwnerError> {
    if let OwnerAction::Resume { session_id } = action {
        if session_id.strip_suffix(".json").unwrap_or(&session_id) == lease.session_id() {
            return Ok(ActionAck {
                request_id: None,
                state: "resumed".into(),
                duplicate: false,
            });
        }
        let (candidate_lease, saved) =
            SessionLease::acquire_and_load(lease.home(), &session_id, "daemon")?;
        let saved_origin = crate::sessions::model_origin(Some(&saved));
        let mut candidate = config.clone();
        candidate.turn.session_id = saved.session_id.clone();
        candidate.turn.model = saved.model;
        candidate.turn.provider_id = saved.provider;
        candidate.turn.gate = saved.gate;
        candidate.turn.effort = saved.effort;
        let turn = configured_turn(&candidate.turn)?;
        let masks = masks_for(&candidate.turn, &turn);
        let candidate_store = request_storage::RequestStore::new(
            candidate_lease.home(),
            candidate_lease.session_id(),
        )?;
        let saved_requests = candidate_store.load(candidate_lease.session_id())?;
        let mut snapshot = handle.snapshot()?;
        apply_identity(&mut snapshot, &candidate.turn, &turn);
        snapshot.selection_origin = saved_origin;
        snapshot.last_route = None;
        snapshot.turns = saved.turns;
        snapshot.input_tokens = saved.input_tokens;
        snapshot.output_tokens = saved.output_tokens;
        snapshot.cost_microcents = saved.cost_microcents;
        snapshot.messages = visible_messages(&saved.transcript, &masks);
        snapshot.partial_response.clear();
        snapshot.pending_approvals.clear();
        snapshot.current_request = saved_requests.current_request;
        snapshot.requests = saved_requests.requests;
        for record in snapshot.requests.values_mut() {
            if matches!(record.state, RequestState::Accepted | RequestState::Running) {
                record.state = RequestState::Interrupted;
            }
        }
        snapshot.state = if snapshot.requests.values().any(|record| {
            matches!(
                record.state,
                RequestState::Interrupted | RequestState::Unknown
            )
        }) {
            TurnState::Interrupted
        } else {
            TurnState::Idle
        };
        candidate_store.save(&snapshot)?;
        *lease = candidate_lease;
        *store = candidate_store;
        *config = candidate;
        *transcript = saved.transcript;
        *grants = AutoGrants::new();
        let mut hub = handle.lock()?;
        hub.snapshot = snapshot;
        hub.pane_agents.clear();
        hub.masks = masks;
        let identity = json!({"model":hub.snapshot.model,"provider":hub.snapshot.provider,"session_id":hub.snapshot.session_id});
        hub.emit("identity", identity);
        let messages = hub.snapshot.messages.clone();
        let turns = hub.snapshot.turns;
        let projection = json!({"messages":messages,"turns":turns,
            "input_tokens":hub.snapshot.input_tokens,"output_tokens":hub.snapshot.output_tokens,
            "cost_microcents":hub.snapshot.cost_microcents,"state":hub.snapshot.state,
            "settings":control_settings(&hub.snapshot)});
        hub.emit("transcript", projection);
        return Ok(ActionAck {
            request_id: None,
            state: "resumed".into(),
            duplicate: false,
        });
    }
    let mut candidate = config.clone();
    let mut origin = handle.snapshot()?.selection_origin;
    match action {
        OwnerAction::SetEffort { choice } => candidate.turn.effort = Some(choice),
        OwnerAction::SetModel { model, provider } => {
            let providers = crate::config::ProvidersConfig::load(&candidate.turn.home)
                .map_err(OwnerError::Invalid)?;
            let selected =
                crate::resolve_selected_model(&providers, &model, provider.as_deref(), false)
                    .map_err(OwnerError::Invalid)?;
            candidate.turn.model = selected.raw_model;
            candidate.turn.provider_id = selected.provider_id;
            candidate.turn.gate = selected.url;
            origin = crate::phase_routing::SelectionOrigin::Interactive;
        }
        OwnerAction::RouteAuto => {
            let providers = crate::config::ProvidersConfig::load(&candidate.turn.home)
                .map_err(OwnerError::Invalid)?;
            crate::phase_routing::validate_settings(&providers, &providers.phase_settings())
                .map_err(OwnerError::Invalid)?;
            origin = crate::phase_routing::SelectionOrigin::Default;
        }
        OwnerAction::SetMode { mode } => {
            candidate.turn.scope.mode = orbit_tools::permissions::PermissionMode::from_config(&mode)
                .ok_or_else(|| OwnerError::Invalid("unknown permission mode".into()))?
        }
        _ => {
            return Err(OwnerError::Invalid(
                "unsupported configuration action".into(),
            ));
        }
    }
    let turn = configured_turn(&candidate.turn)?;
    let mut snapshot = handle.snapshot()?;
    apply_identity(&mut snapshot, &candidate.turn, &turn);
    snapshot.selection_origin = origin;
    snapshot.last_route = None;
    let masks = masks_for(&candidate.turn, &turn);
    snapshot.messages = visible_messages(transcript, &masks);
    let saved = save_live(lease, &candidate.turn, transcript, &snapshot);
    let published = matches!(
        &saved,
        Err(OwnerError::Storage(
            SessionLeaseError::PublicationUncertain(_)
        ))
    );
    if saved.is_ok() || published {
        *config = candidate;
        let mut hub = handle.lock()?;
        hub.snapshot = snapshot;
        hub.masks = masks;
        let identity = json!({"model":hub.snapshot.model,"provider":hub.snapshot.provider,"session_id":hub.snapshot.session_id});
        hub.emit("identity", identity);
        let selected = hub.snapshot.effort.clone();
        let status = hub.snapshot.effort_status.clone();
        let settings = control_settings(&hub.snapshot);
        hub.emit(
            "effort",
            json!({"selected":selected,"text":status,"settings":settings}),
        );
    }
    saved?;
    Ok(ActionAck {
        request_id: None,
        state: "settings_saved".into(),
        duplicate: false,
    })
}

fn display_piece(hub: &mut Hub, text: &str) {
    let text = safe_text(text, &hub.masks);
    hub.snapshot.partial_response.push_str(&text);
    if hub.snapshot.partial_response.len() > 8192 {
        hub.snapshot.partial_response = safe_text(&hub.snapshot.partial_response, &[]);
    }
    if !text.is_empty() {
        hub.emit("text_delta", json!({"text":text}));
    }
}

#[derive(Default)]
struct DisplayStream {
    line: String,
    dropping_line: bool,
    private_key: bool,
    dropped_tail: String,
    dropped_begin: bool,
}
impl DisplayStream {
    fn push(&mut self, hub: &mut Hub, text: &str) {
        for character in text.chars() {
            if self.dropping_line {
                // Keep only a tiny rolling marker window while discarding
                // oversized bytes. A header after the limit (or split at it)
                // must still suppress the following private-key body lines.
                self.dropped_tail.push(character);
                while self.dropped_tail.len() > 64 {
                    let first = self
                        .dropped_tail
                        .chars()
                        .next()
                        .expect("nonempty marker tail")
                        .len_utf8();
                    self.dropped_tail.drain(..first);
                }
                if self.dropped_tail.ends_with("-----BEGIN") {
                    self.dropped_begin = true;
                }
                if self.dropped_begin && self.dropped_tail.ends_with("PRIVATE KEY-----") {
                    self.private_key = true;
                    self.dropped_begin = false;
                }
                if self.private_key && self.dropped_tail.ends_with("-----END") {
                    self.private_key = false;
                }
                if character == '\n' {
                    self.dropping_line = false;
                    self.dropped_tail.clear();
                    self.dropped_begin = false;
                }
                continue;
            }
            self.line.push(character);
            if character == '\n' {
                self.flush(hub);
            } else if self.line.len() > 16 * 1024 {
                self.private_key |=
                    self.line.contains("-----BEGIN") && self.line.contains("PRIVATE KEY-----");
                self.dropped_begin = self.line.contains("-----BEGIN") && !self.private_key;
                let mut start = self.line.len().saturating_sub(64);
                while !self.line.is_char_boundary(start) {
                    start += 1;
                }
                self.dropped_tail = self.line[start..].to_owned();
                self.line.clear();
                self.dropping_line = true;
                display_piece(hub, "[redacted:oversized display line]\n");
            }
        }
    }
    fn flush(&mut self, hub: &mut Hub) {
        let line = std::mem::take(&mut self.line);
        if line.is_empty() {
            return;
        }
        if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
            self.private_key = true;
            display_piece(hub, "[redacted:private key]\n");
            return;
        }
        if self.private_key {
            if line.contains("-----END") {
                self.private_key = false;
            }
            return;
        }
        display_piece(hub, &line);
    }
}

fn session_context(config: &OwnerConfig, handle: &OwnerHandle) -> orbit_tools::ToolContext {
    let cx = orbit_tools::ToolContext::new(
        config.turn.home.clone(),
        config.turn.session_id.clone(),
        config.working_dir.clone(),
    );
    let events = handle.clone();
    cx.set_ledger_sink(Some(Arc::new(move |note:&orbit_tools::LedgerNote|{
        if let Ok(mut hub)=events.lock(){hub.emit("activity",json!({"kind":note.kind,"target":note.target,"fact":note.fact,"digest":note.digest}));}
    })));
    let events = handle.clone();
    cx.set_ext(crate::tool_runtime::SubagentObserver(Arc::new(
        move |update: &crate::tool_runtime::SubagentUpdate| {
            if let Ok(mut hub) = events.lock() {
                use crate::tool_runtime::SubagentUpdate as U;
                match update {
                    U::Started {
                        id,
                        name,
                        model,
                        task,
                    } => {
                        if hub.pane_agents.len() < 32 || hub.pane_agents.contains_key(id) {
                            let agent = orbit_frontend_protocol::customization::PaneAgent {
                                id: safe_text(id, &hub.masks),
                                name: safe_text(name, &hub.masks),
                                state: "running".into(),
                            };
                            hub.pane_agents.insert(id.clone(), agent);
                        }
                        hub.emit(
                            "subagent_started",
                            json!({"agent_id":id,"name":name,"model":model,"task":task}),
                        );
                    }
                    U::Progress { id, action } => {
                        hub.emit("subagent_progress", json!({"agent_id":id,"action":action}))
                    }
                    U::Finished { id, ok, report } => {
                        if let Some(agent) = hub.pane_agents.get_mut(id) {
                            agent.state = if *ok { "done" } else { "failed" }.into();
                        }
                        hub.emit(
                            "subagent_finished",
                            json!({"agent_id":id,"ok":ok,"report":report}),
                        );
                    }
                }
            }
        },
    )));
    cx
}

fn owner_loop(
    mut config: OwnerConfig,
    mut lease: SessionLease,
    mut store: request_storage::RequestStore,
    handle: OwnerHandle,
    receiver: mpsc::Receiver<Work>,
) -> Result<(), OwnerError> {
    let mut transcript = config.turn.initial_transcript.clone();
    let mut grants = AutoGrants::new();
    let mut cx = session_context(&config, &handle);
    loop {
        if handle.is_stopping() {
            break;
        }
        let work = match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(work) => work,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let (request_id, text, reply) = match work {
            Work::Stop => break,
            Work::Configure { action, reply } => {
                let old_id = config.turn.session_id.clone();
                let result = configure_owned(
                    action,
                    &mut config,
                    &mut lease,
                    &mut store,
                    &mut transcript,
                    &mut grants,
                    &handle,
                );
                if config.turn.session_id != old_id {
                    cx = session_context(&config, &handle);
                }
                if let Ok(mut hub) = handle.lock() {
                    hub.configuring = false;
                }
                let _ = reply.try_send(result);
                continue;
            }
            Work::Prompt {
                request_id,
                text,
                reply,
            } => (request_id, text, reply),
        };
        let mut intent = transcript.clone();
        intent.push(ChatMessage {
            role: ChatRole::User,
            content: text.clone(),
            tool_calls: None,
            tool_call_id: None,
            tool_result: None,
            blocks: None,
            origin_model: None,
            origin_provider: None,
        });
        let accepted = configured_turn(&config.turn).and_then(|base| {
            let origin = handle.snapshot()?.selection_origin;
            let (turn, decision) =
                crate::try_phase_turn_config(&config.turn.home, &base, &text, origin)
                    .map_err(OwnerError::Invalid)?;
            let compaction = crate::try_role_turn_config(&config.turn.home, &turn, "compaction")
                .map_err(OwnerError::Invalid)?;
            let mut options = orbit_engine::TurnOptions {
                max_attempts: 1,
                compaction_config: Some(compaction),
                session_id: config.turn.session_id.clone(),
                request_stem: format!("orbit-owned-{request_id}"),
                ..Default::default()
            };
            let cancelled = handle
                .lock()?
                .cancel
                .as_ref()
                .is_some_and(CancelToken::is_cancelled);
            let notices = if cancelled {
                Ok(Vec::new())
            } else {
                crate::model_limits::apply_turn_budgets(&config.turn.home, &turn, &mut options)
            };
            store.save(&handle.snapshot()?)?;
            save_live(&lease, &config.turn, &intent, &handle.snapshot()?)?;
            Ok((base, turn, decision, options, notices))
        });
        let (base_turn, turn, decision, mut options, notices) = match accepted {
            Ok(turn) => turn,
            Err(error) => {
                let mut hub = handle.lock()?;
                if let Some(record) = hub.snapshot.requests.get_mut(&request_id) {
                    record.state = RequestState::Unknown;
                }
                hub.snapshot.state = TurnState::Interrupted;
                hub.cancel = None;
                hub.emit(
                    "error",
                    json!({"message":error.to_string(),"request_id":request_id}),
                );
                drop(hub);
                let _ = store.save(&handle.snapshot()?);
                let _ = reply.try_send(Err(error));
                continue;
            }
        };
        let notices = match notices {
            Ok(notices) => notices,
            Err(error) => {
                // Admission failed locally: no engine/provider attempt occurred.
                // Retain intent once and publish a known terminal request so a
                // reconnect cannot replay it or confuse it with uncertain egress.
                transcript = intent;
                let interrupted;
                {
                    let mut hub = handle.lock()?;
                    interrupted = hub.cancel.as_ref().is_some_and(CancelToken::is_cancelled);
                    hub.snapshot.turns = hub.snapshot.turns.saturating_add(1);
                    hub.snapshot.messages = visible_messages(&transcript, &hub.masks);
                }
                let mut terminal = handle.snapshot()?;
                let saved = save_live(&lease, &config.turn, &transcript, &terminal);
                if let Some(record) = terminal.requests.get_mut(&request_id) {
                    record.state = if saved.is_err() {
                        RequestState::Unknown
                    } else if interrupted {
                        RequestState::Interrupted
                    } else {
                        RequestState::Failed
                    };
                }
                let saved_request = store.save(&terminal);
                let publication_error = saved.and(saved_request).err();
                let state = if publication_error.is_some() {
                    "unknown"
                } else if interrupted {
                    "interrupted"
                } else {
                    "failed"
                };
                {
                    let mut hub = handle.lock()?;
                    if let Some(record) = hub.snapshot.requests.get_mut(&request_id) {
                        record.state = if publication_error.is_some() {
                            RequestState::Unknown
                        } else if interrupted {
                            RequestState::Interrupted
                        } else {
                            RequestState::Failed
                        };
                    }
                    hub.snapshot.partial_response.clear();
                    hub.snapshot.pending_approvals.clear();
                    hub.approvals.clear();
                    hub.cancel = None;
                    hub.snapshot.state = if hub.stopping {
                        TurnState::Stopping
                    } else if publication_error.is_some() {
                        TurnState::Interrupted
                    } else {
                        TurnState::Idle
                    };
                    hub.emit(
                        "error",
                        json!({"type":"error","message":error.to_string(),"request_id":request_id}),
                    );
                    hub.emit(
                        "turn_ended",
                        json!({"type":"turn_ended","ok":false,"interrupted":interrupted,
                        "rounds":0,"input_tokens":0,"output_tokens":0,"cost_microcents":0}),
                    );
                    if let Some(error) = &publication_error {
                        hub.emit(
                            "error",
                            json!({"message":error.to_string(),"request_id":request_id}),
                        );
                    }
                    let finished = json!({"request_id":request_id,"turns":hub.snapshot.turns,
                        "input_tokens":hub.snapshot.input_tokens,"output_tokens":hub.snapshot.output_tokens,
                        "cost_microcents":hub.snapshot.cost_microcents});
                    hub.emit("request_finished", finished);
                }
                let ack = match publication_error {
                    Some(error) => Err(error),
                    None => Ok(ActionAck {
                        request_id: Some(request_id.clone()),
                        state: state.into(),
                        duplicate: false,
                    }),
                };
                let _ = reply.try_send(ack);
                continue;
            }
        };
        {
            let mut hub = handle.lock()?;
            hub.masks = masks_for(&config.turn, &base_turn);
            for mask in masks_for(&config.turn, &turn) {
                if !hub.masks.contains(&mask) {
                    hub.masks.push(mask);
                }
            }
            apply_identity(&mut hub.snapshot, &config.turn, &base_turn);
            if let Some(decision) = decision {
                let value = safe_json(json!(decision), &hub.masks);
                hub.snapshot.last_route = Some(value.clone());
                hub.emit("routing", value);
            }
            if let Some(record) = hub.snapshot.requests.get_mut(&request_id) {
                record.state = RequestState::Running;
            }
            hub.snapshot.messages = visible_messages(&intent, &hub.masks);
            let message = hub.snapshot.messages.last().cloned();
            hub.emit(
                "request_accepted",
                json!({"request_id":request_id,"message":message}),
            );
        }
        let _ = reply.try_send(Ok(ActionAck {
            request_id: Some(request_id.clone()),
            state: "accepted".into(),
            duplicate: false,
        }));
        {
            let mut hub = handle.lock()?;
            for text in notices {
                hub.emit("status", json!({"text":text}));
            }
        }
        let cancel = handle
            .lock()?
            .cancel
            .clone()
            .ok_or_else(|| OwnerError::Runtime("missing turn cancellation scope".into()))?;
        crate::tool_runtime::remember_effort_setting(
            &cx,
            if turn.provider_id == base_turn.provider_id && turn.model == base_turn.model {
                &config.turn.effort
            } else {
                &None
            },
        );
        let mut executor = OwnedExecutor {
            config: &config.turn,
            handle: handle.clone(),
            cx: cx.clone(),
            grants: std::mem::take(&mut grants),
        };
        let mut definitions = crate::tools::session_tool_definitions_with_context(
            &config.turn.home,
            &cx,
            config.turn.scope.allowlist.as_deref(),
        );
        definitions.retain(|definition| {
            !config.turn.scope.disallowlist.contains(&definition.name)
                && config
                    .turn
                    .scope
                    .allowlist
                    .as_ref()
                    .is_none_or(|allow| allow.contains(&definition.name))
        });
        options.tools = definitions;
        let mut cot = orbit_hud_tui::CotStripper::new();
        let mut display = DisplayStream::default();
        let mut events = |event: orbit_frontend_protocol::FrontendEvent| {
            let Ok(mut hub) = handle.lock() else { return };
            match event {
                orbit_frontend_protocol::FrontendEvent::TextDelta { text } => {
                    display.push(&mut hub, &cot.push(&text));
                }
                event => {
                    if matches!(
                        event,
                        orbit_frontend_protocol::FrontendEvent::ResponseFinished { .. }
                            | orbit_frontend_protocol::FrontendEvent::TurnEnded { .. }
                    ) {
                        display.flush(&mut hub);
                    }
                    let payload = serde_json::to_value(&event).unwrap_or(Value::Null);
                    let kind = payload
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("status")
                        .to_owned();
                    hub.emit(&kind, payload);
                }
            }
        };
        let report = orbit_engine::run_turn(
            &config.turn.home,
            &turn,
            &options,
            &text,
            &mut transcript,
            &mut executor,
            &cancel,
            &mut events,
        );
        {
            let mut hub = handle.lock()?;
            display.flush(&mut hub);
        }
        grants = executor.grants;
        {
            let mut hub = handle.lock()?;
            hub.snapshot.turns = hub.snapshot.turns.saturating_add(1);
            if let Ok(report) = &report {
                hub.snapshot.input_tokens = hub
                    .snapshot
                    .input_tokens
                    .saturating_add(report.input_tokens);
                hub.snapshot.output_tokens = hub
                    .snapshot
                    .output_tokens
                    .saturating_add(report.output_tokens);
                hub.snapshot.cost_microcents = hub
                    .snapshot
                    .cost_microcents
                    .saturating_add(report.cost_microcents);
            }
            hub.snapshot.messages = visible_messages(&transcript, &hub.masks);
            if let Some(scan) = orbit_engine::automation::scan_attestation(&transcript)
                && scan.claimed_pass
                && scan.exit_code != 0
            {
                hub.emit("status",json!({"text":format!("UNVERIFIED CLAIM: \"{}\" exited {} at turn time — the claim is not attested",scan.command,scan.exit_code)}));
            }
            hub.snapshot.partial_response.clear();
            hub.snapshot.pending_approvals.clear();
            hub.approvals.clear();
            hub.cancel = None;
        }
        let saved = save_live(&lease, &config.turn, &transcript, &handle.snapshot()?);
        {
            let mut hub = handle.lock()?;
            if let Some(record) = hub.snapshot.requests.get_mut(&request_id) {
                record.state = if saved.is_err() {
                    RequestState::Unknown
                } else if report.as_ref().is_ok_and(|report| report.interrupted) {
                    RequestState::Interrupted
                } else if report.as_ref().is_ok_and(|report| report.ok) {
                    RequestState::Completed
                } else {
                    RequestState::Unknown
                };
            }
        }
        let saved_request = store.save(&handle.snapshot()?);
        let mut hub = handle.lock()?;
        if let Err(error) = report {
            hub.emit("error", json!({"message":error}));
        }
        if let Err(error) = saved {
            hub.emit("error", json!({"message":error.to_string()}));
        }
        if let Err(error) = saved_request {
            if let Some(record) = hub.snapshot.requests.get_mut(&request_id) {
                record.state = RequestState::Unknown;
            }
            hub.emit("error", json!({"message":error.to_string()}));
        }
        hub.snapshot.state = if hub.stopping {
            TurnState::Stopping
        } else {
            TurnState::Idle
        };
        let finished = json!({"request_id":request_id,"turns":hub.snapshot.turns,
            "input_tokens":hub.snapshot.input_tokens,"output_tokens":hub.snapshot.output_tokens,
            "cost_microcents":hub.snapshot.cost_microcents});
        hub.emit("request_finished", finished);
        if hub.stopping {
            break;
        }
    }
    let mut hub = handle.lock()?;
    hub.stopping = true;
    hub.snapshot.state = TurnState::Stopped;
    hub.emit("stopped", json!({}));
    Ok(())
}

struct OwnedApproval {
    handle: OwnerHandle,
    cancel: Option<CancelToken>,
    note: Option<String>,
}
impl ApprovalChannel for OwnedApproval {
    fn ask(&mut self, request: &ApprovalRequest, _auto: bool) -> ApprovalVerdict {
        if request.call_id.is_empty() || request.call_id.len() > 128 {
            return ApprovalVerdict::Deny;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        if let Ok(mut hub) = self.handle.lock() {
            if hub.approvals.len() >= 8 {
                return ApprovalVerdict::Deny;
            }
            let mut card = safe_json(
                json!({"call_id":request.call_id,"tool_name":request.tool_name,"summary":request.summary,"risk":request.risk.level(),"preview":request.preview.iter().take(8).map(|line|{let mut end=line.len().min(512);while !line.is_char_boundary(end){end-=1;}&line[..end]}).collect::<Vec<_>>(),"grant":request.grant.as_ref().map(|grant|json!({"rule":grant.rule,"can_save":grant.can_save}))}),
                &hub.masks,
            );
            if serde_json::to_vec(&card).map_or(true, |bytes| bytes.len() > 8 * 1024) {
                card = json!({"call_id":request.call_id,"tool_name":"tool","summary":"Approval preview exceeds display limit","risk":request.risk.level(),"truncated":true});
            }
            hub.approvals.insert(request.call_id.clone(), sender);
            hub.snapshot.pending_approvals.push(card.clone());
            hub.emit("approval_requested", card);
        } else {
            return ApprovalVerdict::Deny;
        }
        loop {
            if self.cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
                break;
            }
            match receiver.recv_timeout(Duration::from_millis(25)) {
                Ok(answer) => {
                    self.note = answer.note;
                    self.clear(&request.call_id);
                    return answer.verdict;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
        }
        self.clear(&request.call_id);
        ApprovalVerdict::Deny
    }
    fn take_note(&mut self) -> Option<String> {
        self.note.take()
    }
}
impl OwnedApproval {
    fn clear(&self, id: &str) {
        if let Ok(mut hub) = self.handle.lock() {
            hub.approvals.remove(id);
            hub.snapshot
                .pending_approvals
                .retain(|card| card["call_id"] != id);
            hub.emit("approval_resolved", json!({"call_id":id}));
        }
    }
}

struct OwnedExecutor<'a> {
    config: &'a TuiTurnConfig,
    handle: OwnerHandle,
    cx: orbit_tools::ToolContext,
    grants: AutoGrants,
}
impl orbit_engine::ToolExecutor for OwnedExecutor<'_> {
    fn begin_turn(&mut self, config: &orbit_engine::TurnConfig) {
        crate::tool_runtime::remember_turn_config(&self.cx, config);
    }
    fn begin_cancel_scope(&mut self, cancel: &CancelToken) {
        crate::tool_runtime::begin_cancel_scope(&self.cx, cancel);
    }
    fn end_cancel_scope(&mut self) {
        self.cx.pop_cancel_check();
    }
    fn execute(
        &mut self,
        calls: &[orbit_engine::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        let config = self.config.clone();
        let handle = self.handle.clone();
        let cx = self.cx.clone();
        let read_only = move |call: orbit_engine::PendingToolCall| {
            execute_owned(&config, &handle, &cx, &call, &mut AutoGrants::new())
        };
        crate::tool_runtime::run_round_parallel(
            &self.cx,
            calls,
            |call| execute_owned(self.config, &self.handle, &self.cx, call, &mut self.grants),
            read_only,
            |_| {},
        )
    }
}
fn execute_owned(
    config: &TuiTurnConfig,
    handle: &OwnerHandle,
    cx: &orbit_tools::ToolContext,
    call: &orbit_engine::PendingToolCall,
    grants: &mut AutoGrants,
) -> orbit_engine::ToolRoundResult {
    let mut channel = OwnedApproval {
        handle: handle.clone(),
        cancel: handle.lock().ok().and_then(|hub| hub.cancel.clone()),
        note: None,
    };
    let decision = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
    let (content, change) = crate::tool_runtime::execute_call(
        &config.home,
        &config.session_id,
        &decision,
        call,
        config.auto_tools,
        true,
        &mut channel,
        grants,
        &config.scope,
        cx,
    )
    .unwrap_or_else(|error| (json!({"ok":false,"error":error}).to_string(), None));
    if let Some(change) = change
        && let Ok(mut hub) = handle.lock()
    {
        hub.emit("file_changed",json!({"path":change.path,"added":change.added,"removed":change.removed,"checkpoint_id":change.checkpoint_id,"hunks":change.hunks}));
    }
    orbit_engine::ToolRoundResult {
        call_id: call.id.clone(),
        content,
    }
}

#[cfg(unix)]
pub use transport::UnixServer;

#[cfg(unix)]
pub(crate) fn local_connect(socket: &Path) -> Result<std::os::unix::net::UnixStream, OwnerError> {
    transport::connect(socket)
}

#[cfg(unix)]
pub fn run_server(
    config: OwnerConfig,
    lease: SessionLease,
    socket: &Path,
    shutdown: &CancelToken,
) -> Result<(), OwnerError> {
    let runtime = OwnerRuntime::start(config, lease)?;
    let server = UnixServer::bind(socket, runtime.handle())?;
    let result = server.run(shutdown);
    runtime.shutdown()?;
    result
}

#[cfg(unix)]
#[allow(unsafe_code)] // Peer credentials and safe private Unix endpoint ownership only.
mod transport {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{
        DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
    };
    use std::os::unix::net::{UnixListener, UnixStream};
    const MAX_FRAME: usize = 256 * 1024;

    pub struct UnixServer {
        listener: UnixListener,
        path: PathBuf,
        identity: (u64, u64),
        _lock: File,
        handle: OwnerHandle,
    }
    fn error(error: std::io::Error) -> OwnerError {
        OwnerError::Protocol(error.to_string())
    }
    fn private_path(path: &Path) -> Result<(), OwnerError> {
        for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
            if let Ok(metadata) = std::fs::symlink_metadata(ancestor)
                && metadata.file_type().is_symlink()
            {
                return Err(OwnerError::Protocol("symlink in endpoint path".into()));
            }
        }
        Ok(())
    }
    fn owned(metadata: &std::fs::Metadata) -> bool {
        // SAFETY: geteuid has no arguments or memory access.
        metadata.uid() == unsafe { libc::geteuid() }
    }
    fn peer(stream: &UnixStream) -> Result<(), OwnerError> {
        // SAFETY: zero initializes the C credential value before getsockopt fills it.
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: the owned FD, credential pointer and matching initialized size are valid.
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(error(std::io::Error::last_os_error()));
        }
        // SAFETY: geteuid has no arguments or memory access.
        if length as usize != std::mem::size_of::<libc::ucred>()
            || credentials.uid != unsafe { libc::geteuid() }
        {
            return Err(OwnerError::NotController);
        }
        Ok(())
    }
    fn connect_deadline(path: &Path) -> std::io::Result<UnixStream> {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: zero initializes a sockaddr before the bounded path is copied.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid Unix endpoint path length",
            ));
        }
        address.sun_family = libc::AF_UNIX as _;
        for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
            *target = *byte as _;
        }
        // SAFETY: socket returns a fresh descriptor with no borrowed memory.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: ownership of this fresh valid descriptor is transferred once.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Unix connect deadline exceeded",
                ));
            }
            // SAFETY: the owned socket and initialized, terminated sockaddr are valid.
            let connected = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            };
            if connected == 0 {
                let stream = UnixStream::from(fd);
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            let failure = std::io::Error::last_os_error();
            match failure.raw_os_error() {
                Some(libc::EAGAIN | libc::EINTR) => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Some(libc::EINPROGRESS | libc::EALREADY) => {}
                _ => return Err(failure),
            }
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Unix connect deadline exceeded",
                    ));
                }
                let mut pollfd = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: poll receives one live, correctly-sized descriptor entry.
                let ready = unsafe {
                    libc::poll(
                        &mut pollfd,
                        1,
                        remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
                    )
                };
                if ready < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                if ready == 0 {
                    continue;
                }
                let mut status: libc::c_int = 0;
                let mut size = std::mem::size_of_val(&status) as libc::socklen_t;
                // SAFETY: the initialized integer/status length match SO_ERROR's ABI.
                if unsafe {
                    libc::getsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&mut status as *mut libc::c_int).cast(),
                        &mut size,
                    )
                } < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if status != 0 {
                    return Err(std::io::Error::from_raw_os_error(status));
                }
                let stream = UnixStream::from(fd);
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
        }
    }
    pub(super) fn connect(path: &Path) -> Result<UnixStream, OwnerError> {
        private_path(path)?;
        let metadata = std::fs::symlink_metadata(path).map_err(error)?;
        let parent = std::fs::symlink_metadata(
            path.parent()
                .ok_or_else(|| OwnerError::Protocol("socket has no parent".into()))?,
        )
        .map_err(error)?;
        if !metadata.file_type().is_socket()
            || !owned(&metadata)
            || metadata.mode() & 0o777 != 0o600
            || !parent.is_dir()
            || !owned(&parent)
            || parent.mode() & 0o777 != 0o700
        {
            return Err(OwnerError::Protocol(
                "endpoint is not a private owned Unix socket".into(),
            ));
        }
        let stream = connect_deadline(path).map_err(error)?;
        peer(&stream)?;
        Ok(stream)
    }
    impl UnixServer {
        pub fn bind(path: &Path, handle: OwnerHandle) -> Result<Self, OwnerError> {
            private_path(path)?;
            let parent = path.parent().ok_or_else(|| {
                OwnerError::Protocol("socket requires private parent directory".into())
            })?;
            if !parent.exists() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(error)?;
            }
            private_path(parent)?;
            let parent_metadata = std::fs::symlink_metadata(parent).map_err(error)?;
            if !parent_metadata.is_dir()
                || !owned(&parent_metadata)
                || parent_metadata.mode() & 0o777 != 0o700
            {
                return Err(OwnerError::Protocol(
                    "socket directory must be owned and 0700".into(),
                ));
            }
            let lock_path = parent.join(format!(
                ".{}.lock",
                path.file_name()
                    .ok_or_else(|| OwnerError::Protocol("invalid socket name".into()))?
                    .to_string_lossy()
            ));
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(lock_path)
                .map_err(error)?;
            let metadata = lock.metadata().map_err(error)?;
            if !metadata.is_file()
                || !owned(&metadata)
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0
            {
                return Err(OwnerError::Protocol("unsafe endpoint lock".into()));
            }
            lock.try_lock().map_err(|_| OwnerError::Busy)?;
            if let Ok(metadata) = std::fs::symlink_metadata(path) {
                if !metadata.file_type().is_socket() || !owned(&metadata) {
                    return Err(OwnerError::Protocol("unsafe existing endpoint".into()));
                }
                match connect_deadline(path) {
                    Ok(_) => return Err(OwnerError::Busy),
                    Err(failure)
                        if matches!(
                            failure.kind(),
                            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                        ) => {}
                    Err(failure) => return Err(error(failure)),
                }
                let current = std::fs::symlink_metadata(path).map_err(error)?;
                if (metadata.dev(), metadata.ino()) != (current.dev(), current.ino())
                    || !current.file_type().is_socket()
                {
                    return Err(OwnerError::Protocol(
                        "endpoint changed during stale check".into(),
                    ));
                }
                std::fs::remove_file(path).map_err(error)?;
            }
            let listener = UnixListener::bind(path).map_err(error)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(error)?;
            listener.set_nonblocking(true).map_err(error)?;
            let metadata = std::fs::symlink_metadata(path).map_err(error)?;
            Ok(Self {
                listener,
                path: path.into(),
                identity: (metadata.dev(), metadata.ino()),
                _lock: lock,
                handle,
            })
        }
        pub fn run(self, shutdown: &CancelToken) -> Result<(), OwnerError> {
            let mut clients: Vec<JoinHandle<()>> = vec![];
            while !shutdown.is_cancelled() && !self.handle.is_stopping() {
                clients.retain(|client| !client.is_finished());
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        if clients.len() < 16 {
                            let handle = self.handle.clone();
                            clients.push(std::thread::spawn(move || {
                                let _ = connection(stream, handle);
                            }));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(failure) => return Err(error(failure)),
                }
            }
            self.handle.stop();
            Ok(())
        }
    }
    impl Drop for UnixServer {
        fn drop(&mut self) {
            if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
                metadata.file_type().is_socket()
                    && (metadata.dev(), metadata.ino()) == self.identity
            }) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    fn connection(stream: UnixStream, handle: OwnerHandle) -> Result<(), OwnerError> {
        peer(&stream)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(error)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(error)?;
        let mut reader = BufReader::new(stream);
        let mut hello = false;
        let mut controller: Option<ControllerLease> = None;
        while !handle.is_stopping() {
            let Some(bytes) = read_frame(&mut reader, &handle)? else {
                break;
            };
            let request: Value = serde_json::from_slice(&bytes)
                .map_err(|error| OwnerError::Protocol(error.to_string()))?;
            let result = (|| -> Result<Value, OwnerError> {
                if request.get("version").and_then(Value::as_u64) != Some(1) {
                    return Err(OwnerError::Protocol("unsupported protocol version".into()));
                }
                let request = &request["request"];
                match request["type"].as_str() {
                    Some("hello") if !hello => {
                        if request
                            .get("controlling")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            controller = Some(handle.claim_controller()?);
                        }
                        hello = true;
                        let cursor = request
                            .get("cursor")
                            .filter(|value| !value.is_null())
                            .map(|value| serde_json::from_value::<EventCursor>(value.clone()))
                            .transpose()
                            .map_err(|error| OwnerError::Protocol(error.to_string()))?;
                        let recovery = handle.subscribe(cursor.as_ref())?.recovery;
                        serde_json::to_value(recovery)
                            .map_err(|error| OwnerError::Protocol(error.to_string()))
                    }
                    _ if !hello => {
                        Err(OwnerError::Protocol("hello required before actions".into()))
                    }
                    Some("status") => serde_json::to_value(handle.snapshot()?)
                        .map_err(|error| OwnerError::Protocol(error.to_string())),
                    Some("subscribe") => {
                        let cursor = request
                            .get("cursor")
                            .filter(|value| !value.is_null())
                            .map(|value| serde_json::from_value::<EventCursor>(value.clone()))
                            .transpose()
                            .map_err(|error| OwnerError::Protocol(error.to_string()))?;
                        serde_json::to_value(handle.subscribe(cursor.as_ref())?.recovery)
                            .map_err(|error| OwnerError::Protocol(error.to_string()))
                    }
                    Some("action") => {
                        let action =
                            serde_json::from_value::<OwnerAction>(request["action"].clone())
                                .map_err(|error| OwnerError::Protocol(error.to_string()))?;
                        serde_json::to_value(
                            controller
                                .as_mut()
                                .ok_or(OwnerError::NotController)?
                                .send(action)?,
                        )
                        .map_err(|error| OwnerError::Protocol(error.to_string()))
                    }
                    _ => Err(OwnerError::Protocol("unknown protocol action".into())),
                }
            })();
            let response = match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(error) => {
                    json!({"ok":false,"code":error.code(),"error":safe_text(&error.to_string(),&handle.lock()?.masks)})
                }
            };
            let encoded = serde_json::to_vec(&response)
                .map_err(|error| OwnerError::Protocol(error.to_string()))?;
            if encoded.len() > MAX_FRAME {
                return Err(OwnerError::Protocol("response exceeds frame bound".into()));
            }
            reader.get_mut().write_all(&encoded).map_err(error)?;
            reader.get_mut().write_all(b"\n").map_err(error)?;
        }
        Ok(())
    }

    fn read_frame(
        reader: &mut BufReader<UnixStream>,
        handle: &OwnerHandle,
    ) -> Result<Option<Vec<u8>>, OwnerError> {
        let mut deadline: Option<Instant> = None;
        let mut bytes = vec![];
        loop {
            if handle.is_stopping() {
                return Ok(None);
            }
            let remaining = deadline.map_or(Duration::from_millis(100), |until| {
                until.saturating_duration_since(Instant::now())
            });
            if remaining.is_zero() {
                return Err(OwnerError::Protocol("frame deadline exceeded".into()));
            }
            reader
                .get_mut()
                .set_read_timeout(Some(remaining.min(Duration::from_millis(100))))
                .map_err(error)?;
            let buffer = match reader.fill_buf() {
                Ok(buffer) => buffer,
                Err(failure)
                    if matches!(
                        failure.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(failure) => return Err(error(failure)),
            };
            if buffer.is_empty() {
                return if bytes.is_empty() {
                    Ok(None)
                } else {
                    Err(OwnerError::Protocol("incomplete frame".into()))
                };
            }
            deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(2));
            let newline = buffer.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(buffer.len(), |index| index + 1);
            if bytes.len() + count > MAX_FRAME {
                return Err(OwnerError::Protocol("frame exceeds byte bound".into()));
            }
            bytes.extend_from_slice(&buffer[..count]);
            reader.consume(count);
            if newline.is_some() {
                return Ok(Some(bytes));
            }
        }
    }
}
