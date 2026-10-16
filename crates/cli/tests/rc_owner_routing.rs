#![cfg(unix)]

use orbit_adapter::types::{EffortSetting, EffortValue};
use orbit_cli::daemon::{
    ControllerLease, EventCursor, OwnerAction, OwnerConfig, OwnerError, OwnerEvent, OwnerHandle,
    OwnerRuntime, OwnerSnapshot, RequestState, TurnState,
};
use orbit_cli::phase_routing::SelectionOrigin;
use orbit_cli::sessions::{self, SessionFile, SessionLease};
use orbit_cli::tool_runtime::PermissionScope;
use orbit_cli::tui_worker::TuiTurnConfig;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PROMPT: &str = "implement comprehensive parser";
const SESSION: &str = "routing-owner";
const RAW_A: &str = "model-a";
const RAW_B: &str = "vendor/model-b";

fn private_directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn write_private(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn low() -> Option<EffortSetting> {
    Some(EffortSetting::Value(EffortValue::Level("low".into())))
}

struct CapturedProvider {
    directory: PathBuf,
    process: Child,
    gate: String,
}
impl CapturedProvider {
    fn new(directory: PathBuf) -> Self {
        private_directory(&directory);
        let mut process = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/p35_provider.py"
            ))
            .arg(&directory)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdout(Stdio::null())
            .stderr(fs::File::create(directory.join("provider.stderr")).unwrap())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let gate = loop {
            // The existing fixture publishes ready.json in one write; retry a
            // partial write instead of treating pathname existence as readiness.
            if let Some(gate) = fs::read(directory.join("ready.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|ready| ready["gate"].as_str().map(str::to_owned))
            {
                break gate;
            }
            assert!(
                process.try_wait().unwrap().is_none(),
                "captured provider stopped: {}",
                fs::read_to_string(directory.join("provider.stderr")).unwrap_or_default()
            );
            if Instant::now() >= deadline {
                let _ = process.kill();
                let _ = process.wait();
                panic!("captured provider did not become ready within five seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            url::Url::parse(&gate).unwrap().host_str(),
            Some("127.0.0.1")
        );
        Self {
            directory,
            process,
            gate,
        }
    }
    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.directory.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn request_metadata(&self) -> Vec<Value> {
        fs::read_to_string(self.directory.join("requests.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn mode(&self, value: Value) {
        write_private(&self.directory.join("mode.json"), value.to_string());
    }
    fn wait_calls(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.calls().len() < expected {
            assert!(Instant::now() < deadline, "captured POST was not received");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn stop(&mut self) {
        if matches!(self.process.try_wait(), Ok(None)) {
            let _ = self.process.kill();
        }
        let _ = self.process.wait();
    }
    fn port(&self) -> u16 {
        url::Url::parse(&self.gate).unwrap().port().unwrap()
    }
}
impl Drop for CapturedProvider {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    a: CapturedProvider,
    b: CapturedProvider,
    providers: String,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-owner-routing-{}", ulid::Ulid::new()));
        private_directory(&root);
        let home = root.join("home");
        let workspace = root.join("workspace");
        private_directory(&home);
        private_directory(&workspace);
        let a = CapturedProvider::new(root.join("provider-a"));
        let b = CapturedProvider::new(root.join("provider-b"));
        let providers = format!(
            r#"
[[provider]]
name='provider_a'
url={gate_a:?}
[[provider.models]]
id='model-a'
max_output_tokens=1111
supported_efforts=['low']
default_effort='low'
[[provider]]
name='provider_b'
url={gate_b:?}
[[provider.models]]
id='vendor/model-b'
max_output_tokens=733
supported_efforts=['medium']
default_effort='medium'
[roles]
main='provider_a/model-a'
[routing.phases.coding]
hard='provider_b/vendor/model-b'
"#,
            gate_a = a.gate,
            gate_b = b.gate
        );
        write_private(&home.join("providers.toml"), &providers);
        Self {
            root,
            home,
            workspace,
            a,
            b,
            providers,
        }
    }
    fn turn(&self, saved: &SessionFile, scope: PermissionScope) -> TuiTurnConfig {
        TuiTurnConfig {
            home: self.home.clone(),
            session_id: saved.session_id.clone(),
            gate: saved.gate.clone(),
            model: saved.model.clone(),
            effort: saved.effort.clone(),
            provider_id: saved.provider.clone(),
            auto_tools: false,
            scope,
            initial_transcript: saved.transcript.clone(),
            initial_turns: saved.turns,
            initial_input_tokens: saved.input_tokens,
            initial_output_tokens: saved.output_tokens,
            initial_cost_microcents: saved.cost_microcents,
        }
    }
    fn start(&self, origin: Option<SelectionOrigin>, effort: Option<EffortSetting>) -> Owned {
        self.start_scoped(origin, effort, PermissionScope::default())
    }
    fn start_scoped(
        &self,
        origin: Option<SelectionOrigin>,
        effort: Option<EffortSetting>,
        scope: PermissionScope,
    ) -> Owned {
        let lease = SessionLease::acquire(&self.home, SESSION, "routing-test").unwrap();
        let mut saved =
            SessionFile::from_chat(SESSION, RAW_A, &self.a.gate, "provider_a", &[], 0, 0, 0, 0)
                .with_effort(effort);
        if let Some(origin) = origin {
            saved = saved.with_selection_origin(origin);
        }
        lease.save(&saved).unwrap();
        let config = OwnerConfig::new(self.turn(&saved, scope), self.workspace.clone());
        Owned::new(OwnerRuntime::start(config, lease).unwrap())
    }
    fn restart(&self) -> Owned {
        let (lease, saved) =
            SessionLease::acquire_and_load(&self.home, SESSION, "routing-test").unwrap();
        let config = OwnerConfig::new(
            self.turn(&saved, PermissionScope::default()),
            self.workspace.clone(),
        );
        Owned::new(OwnerRuntime::start(config, lease).unwrap())
    }
    fn saved(&self) -> SessionFile {
        sessions::load_session(&self.home, SESSION).unwrap()
    }
    fn egress(&self) -> Vec<(String, u16)> {
        let (records, _) = orbit_ledger::verify_ledger(&self.home.join("ledger")).unwrap();
        records
            .into_iter()
            .filter_map(|item| match item.record.event {
                orbit_ledger::LedgerEvent::EgressIntent(intent) => Some(intent.destinations),
                _ => None,
            })
            .flatten()
            .map(|destination| {
                assert_eq!(destination.host, "127.0.0.1");
                (destination.provider_id, destination.port)
            })
            .collect()
    }
    fn assert_no_calls(&self) {
        assert!(self.a.calls().is_empty());
        assert!(self.b.calls().is_empty());
        assert!(self.egress().is_empty());
    }
    fn assert_base(&self, owner: &Owned, origin: SelectionOrigin, effort: Option<EffortSetting>) {
        let snapshot = owner.snapshot();
        assert_eq!(snapshot.provider, "provider_a");
        assert_eq!(snapshot.model, RAW_A);
        assert_eq!(snapshot.selection_origin, origin);
        assert_eq!(snapshot.effort, effort);
        let saved = self.saved();
        assert_eq!(saved.provider, "provider_a");
        assert_eq!(saved.model, RAW_A);
        assert_eq!(saved.gate, self.a.gate);
        assert_eq!(saved.selection_origin, Some(origin));
        assert_eq!(saved.effort, effort);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Providers must terminate before their capture directories disappear.
        self.a.stop();
        self.b.stop();
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Owned {
    runtime: Option<OwnerRuntime>,
    controller: Option<ControllerLease>,
    handle: OwnerHandle,
    initial_cursor: EventCursor,
}
impl Owned {
    fn new(runtime: OwnerRuntime) -> Self {
        let handle = runtime.handle();
        let initial_cursor = handle.snapshot().unwrap().cursor;
        let controller = handle.claim_controller().unwrap();
        Self {
            runtime: Some(runtime),
            controller: Some(controller),
            handle,
            initial_cursor,
        }
    }
    fn send(&mut self, action: OwnerAction) -> Result<orbit_cli::daemon::ActionAck, OwnerError> {
        self.controller.as_mut().unwrap().send(action)
    }
    fn prompt(&mut self, id: &str, text: &str) {
        let ack = self
            .send(OwnerAction::Prompt {
                request_id: id.into(),
                text: text.into(),
            })
            .unwrap();
        assert_eq!(ack.request_id.as_deref(), Some(id));
        assert!(!ack.duplicate);
        self.finished(id);
    }
    fn finished(&self, id: &str) -> OwnerSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = self.snapshot();
            if snapshot.state == TurnState::Idle
                && snapshot.requests.get(id).is_some_and(|record| {
                    !matches!(record.state, RequestState::Accepted | RequestState::Running)
                })
            {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "owner did not finish: {snapshot:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn snapshot(&self) -> OwnerSnapshot {
        self.handle.snapshot().unwrap()
    }
    fn events(&self) -> Vec<OwnerEvent> {
        let subscription = self.handle.subscribe(Some(&self.initial_cursor)).unwrap();
        assert!(
            subscription.recovery.snapshot.is_none(),
            "fresh test replay unexpectedly lost"
        );
        subscription.recovery.events.clone()
    }
    fn decisions(&self) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|event| event.kind == "routing" && event.payload.get("source").is_some())
            .map(|event| event.payload)
            .collect()
    }
    fn shutdown(mut self) {
        self.controller.take();
        self.runtime.take().unwrap().shutdown().unwrap();
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        self.controller.take();
        if let Some(runtime) = self.runtime.take()
            && let Err(error) = runtime.shutdown()
            && !std::thread::panicking()
        {
            panic!("owner cleanup failed: {error}");
        }
    }
}

fn assert_pin(origin: SelectionOrigin) {
    let f = Fixture::new();
    let mut owner = f.start(Some(origin), low());
    owner.prompt("pinned-turn", PROMPT);
    assert_eq!(f.a.calls().len(), 1);
    assert!(f.b.calls().is_empty());
    assert_eq!(f.a.calls()[0]["model"], RAW_A);
    assert_eq!(f.a.calls()[0]["reasoning_effort"], "low");
    assert_eq!(f.egress(), vec![("provider_a".into(), f.a.port())]);
    f.assert_base(&owner, origin, low());
    let route = owner.snapshot().last_route.unwrap();
    assert_eq!(route["source"], "explicit");
    assert_eq!(route["raw_model"], RAW_A);
    assert!(
        route["suppressed_reason"]
            .as_str()
            .unwrap()
            .contains("/route auto")
    );
    assert_eq!(owner.decisions().len(), 1);
}

#[test]
fn owner_identity_default_routes_once_to_declared_provider() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Default), None);
    let config = orbit_cli::config::ProvidersConfig::load(&f.home).unwrap();
    let base = orbit_cli::phase_routing::resolve_model(&config, RAW_A, Some("provider_a")).unwrap();
    let preview = orbit_cli::phase_routing::preview(
        &config,
        &config.phase_settings(),
        &base,
        SelectionOrigin::Default,
        PROMPT,
        None,
    )
    .unwrap();
    f.assert_no_calls();
    owner.prompt("auto-one", PROMPT);
    assert!(f.a.calls().is_empty());
    assert_eq!(f.b.calls().len(), 1);
    assert_eq!(f.b.calls()[0]["model"], preview.raw_model);
    assert_eq!(f.egress(), vec![(preview.provider_id.clone(), f.b.port())]);
    assert_eq!(
        owner.snapshot().last_route.unwrap(),
        serde_json::to_value(preview).unwrap()
    );
    assert_eq!(owner.decisions().len(), 1);
    f.assert_base(&owner, SelectionOrigin::Default, None);
}

#[test]
fn owner_identity_role_origin_remains_automatic() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Role), None);
    owner.prompt("role-auto", PROMPT);
    assert!(f.a.calls().is_empty());
    assert_eq!(f.b.calls().len(), 1);
    assert_eq!(
        owner.snapshot().last_route.unwrap()["source"],
        "phase_difficulty"
    );
    f.assert_base(&owner, SelectionOrigin::Role, None);
}

#[test]
fn owner_identity_flag_equal_to_default_still_pins() {
    assert_pin(SelectionOrigin::Flag);
}
#[test]
fn environment_origin_equal_to_default_still_pins() {
    assert_pin(SelectionOrigin::Environment);
}
#[test]
fn interactive_origin_equal_to_default_still_pins() {
    assert_pin(SelectionOrigin::Interactive);
}
#[test]
fn saved_explicit_origin_equal_to_default_still_pins() {
    assert_pin(SelectionOrigin::SavedExplicit);
}
#[test]
fn agent_explicit_origin_equal_to_default_still_pins() {
    assert_pin(SelectionOrigin::AgentExplicit);
}

#[test]
fn owner_identity_legacy_saved_none_is_conservatively_explicit() {
    let f = Fixture::new();
    let mut owner = f.start(None, low());
    assert_eq!(
        owner.snapshot().selection_origin,
        SelectionOrigin::SavedExplicit
    );
    owner.prompt("legacy-pin", PROMPT);
    assert_eq!(f.a.calls().len(), 1);
    assert!(f.b.calls().is_empty());
    f.assert_base(&owner, SelectionOrigin::SavedExplicit, low());
    assert_eq!(owner.decisions()[0]["source"], "explicit");
}

#[test]
fn owner_identity_route_auto_persists_clear_with_zero_settings_calls() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Flag), low());
    let ack = owner.send(OwnerAction::RouteAuto).unwrap();
    assert_eq!(ack.state, "settings_saved");
    f.assert_no_calls();
    f.assert_base(&owner, SelectionOrigin::Default, low());
    assert!(owner.snapshot().last_route.is_none());
    owner.prompt("cleared-pin", PROMPT);
    assert_eq!(f.b.calls().len(), 1);
    assert!(f.a.calls().is_empty());
    assert_eq!(f.b.calls()[0]["reasoning_effort"], "medium");
    f.assert_base(&owner, SelectionOrigin::Default, low());
}

#[test]
fn owner_identity_qualified_hot_switch_preserves_raw_slashes() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Default), None);
    owner
        .send(OwnerAction::SetModel {
            model: "provider_b/vendor/model-b".into(),
            provider: None,
        })
        .unwrap();
    f.assert_no_calls();
    let switched = owner.snapshot();
    assert_eq!(switched.provider, "provider_b");
    assert_eq!(switched.model, RAW_B);
    assert_eq!(switched.selection_origin, SelectionOrigin::Interactive);
    owner.prompt("hot-switch", "hello there");
    assert!(f.a.calls().is_empty());
    assert_eq!(f.b.calls().len(), 1);
    assert_eq!(f.b.calls()[0]["model"], RAW_B);
    assert_eq!(f.b.calls()[0]["max_tokens"], 733);
    assert_eq!(f.b.calls()[0]["reasoning_effort"], "medium");
    assert_eq!(f.egress(), vec![("provider_b".into(), f.b.port())]);
    let saved = f.saved();
    assert_eq!(saved.model, RAW_B);
    assert_eq!(saved.gate, f.b.gate);
    assert_eq!(saved.selection_origin, Some(SelectionOrigin::Interactive));
}

#[test]
fn routed_caps_and_default_effort_do_not_replace_base_choice() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Default), low());
    owner.prompt("routed-caps", PROMPT);
    let call = &f.b.calls()[0];
    assert_eq!(call["model"], RAW_B);
    assert_eq!(call["max_tokens"], 733);
    assert_eq!(call["reasoning_effort"], "medium");
    assert!(call.get("phase").is_none());
    assert!(call.get("difficulty").is_none());
    assert!(f.a.calls().is_empty());
    f.assert_base(&owner, SelectionOrigin::Default, low());
    assert_eq!(
        owner.snapshot().resolved_effort,
        Some(EffortValue::Level("low".into()))
    );
    assert_eq!(
        owner.snapshot().supported_efforts,
        Some(vec![EffortValue::Level("low".into())])
    );
    assert!(f.saved().transcript.iter().any(|message| {
        message.role.as_str() == "assistant"
            && message.content.contains("owned fixture reply")
            && message.blocks.is_none()
            && message.origin_model.is_none()
    }));
    assert_eq!(f.egress(), vec![("provider_b".into(), f.b.port())]);
}

#[test]
fn automatic_origin_survives_restart_without_replaying_old_prompt() {
    let f = Fixture::new();
    let mut first = f.start(Some(SelectionOrigin::Default), low());
    first.prompt("before-restart", PROMPT);
    first.shutdown();
    let mut resumed = f.restart();
    assert_eq!(f.b.calls().len(), 1);
    assert_eq!(
        resumed.snapshot().selection_origin,
        SelectionOrigin::Default
    );
    assert!(resumed.snapshot().last_route.is_none());
    let duplicate = resumed
        .send(OwnerAction::Prompt {
            request_id: "before-restart".into(),
            text: PROMPT.into(),
        })
        .unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(f.b.calls().len(), 1);
    resumed.prompt("after-restart", PROMPT);
    assert_eq!(f.b.calls().len(), 2);
    assert!(f.a.calls().is_empty());
    assert_eq!(f.egress().len(), 2);
    assert_eq!(resumed.decisions().len(), 1);
    f.assert_base(&resumed, SelectionOrigin::Default, low());
}

#[test]
fn interactive_pin_to_same_default_is_durable_across_restart() {
    let f = Fixture::new();
    let mut first = f.start(Some(SelectionOrigin::Default), None);
    first
        .send(OwnerAction::SetModel {
            model: "provider_a/model-a".into(),
            provider: None,
        })
        .unwrap();
    f.assert_no_calls();
    assert_eq!(
        f.saved().selection_origin,
        Some(SelectionOrigin::Interactive)
    );
    first.shutdown();
    let mut resumed = f.restart();
    f.assert_no_calls();
    resumed.prompt("restart-pinned", PROMPT);
    assert_eq!(f.a.calls().len(), 1);
    assert!(f.b.calls().is_empty());
    f.assert_base(&resumed, SelectionOrigin::Interactive, None);
}

#[test]
fn sequential_prompts_route_once_each_and_duplicate_cannot_dispatch() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Default), low());
    owner.prompt("sequential-hard", PROMPT);
    owner.prompt("sequential-normal", "hello there");
    assert_eq!(f.b.calls().len(), 1);
    assert_eq!(f.a.calls().len(), 1);
    assert_eq!(
        f.egress(),
        vec![
            ("provider_b".into(), f.b.port()),
            ("provider_a".into(), f.a.port())
        ]
    );
    assert_eq!(owner.decisions().len(), 2);
    assert_eq!(owner.snapshot().last_route.unwrap()["source"], "base");
    let duplicate = owner
        .send(OwnerAction::Prompt {
            request_id: "sequential-hard".into(),
            text: PROMPT.into(),
        })
        .unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.state, "completed");
    assert_eq!(f.b.calls().len(), 1);
    assert_eq!(owner.decisions().len(), 2);
    f.assert_base(&owner, SelectionOrigin::Default, low());
}

#[test]
fn invalid_configured_target_refuses_before_post_and_recovers_with_new_identity() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Default), None);
    write_private(
        &f.home.join("providers.toml"),
        f.providers.replace(
            "hard='provider_b/vendor/model-b'",
            "hard='provider_b/missing'",
        ),
    );
    let error = owner
        .send(OwnerAction::Prompt {
            request_id: "bad-target".into(),
            text: PROMPT.into(),
        })
        .unwrap_err();
    assert!(error.to_string().contains("model") || error.to_string().contains("routing"));
    f.assert_no_calls();
    assert!(owner.snapshot().last_route.is_none());
    assert_ne!(
        owner.snapshot().requests["bad-target"].state,
        RequestState::Completed
    );
    write_private(&f.home.join("providers.toml"), &f.providers);
    let duplicate = owner
        .send(OwnerAction::Prompt {
            request_id: "bad-target".into(),
            text: PROMPT.into(),
        })
        .unwrap();
    assert!(duplicate.duplicate);
    f.assert_no_calls();
    owner.prompt("repaired-new-id", PROMPT);
    assert_eq!(f.b.calls().len(), 1);
    assert!(f.a.calls().is_empty());
    assert_eq!(owner.decisions().len(), 1);
}

#[test]
fn routing_and_settings_queries_do_not_call_or_change_selection() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Flag), low());
    for action in [
        OwnerAction::Routing,
        OwnerAction::Effort,
        OwnerAction::ListModels,
        OwnerAction::ListSessions,
    ] {
        owner.send(action).unwrap();
    }
    f.assert_no_calls();
    f.assert_base(&owner, SelectionOrigin::Flag, low());
    assert!(owner.snapshot().last_route.is_none());
    assert!(owner.decisions().is_empty());
    assert!(
        owner
            .events()
            .iter()
            .any(|event| event.kind == "routing" && event.payload["selection_origin"] == "flag")
    );
}

#[test]
fn cancelling_routed_provider_headers_keeps_origin_effort_and_no_replay() {
    let f = Fixture::new();
    f.b.mode(json!({"blocked":true}));
    let mut owner = f.start(Some(SelectionOrigin::Default), low());
    owner
        .send(OwnerAction::Prompt {
            request_id: "cancel-routed".into(),
            text: PROMPT.into(),
        })
        .unwrap();
    f.b.wait_calls(1);
    let before = Instant::now();
    owner.send(OwnerAction::Cancel).unwrap();
    let snapshot = owner.finished("cancel-routed");
    assert!(
        before.elapsed() < Duration::from_secs(2),
        "routed provider cancellation exceeded bound"
    );
    assert_eq!(
        snapshot.requests["cancel-routed"].state,
        RequestState::Interrupted
    );
    let duplicate = owner
        .send(OwnerAction::Prompt {
            request_id: "cancel-routed".into(),
            text: PROMPT.into(),
        })
        .unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.state, "interrupted");
    assert_eq!(f.b.calls().len(), 1);
    assert!(f.a.calls().is_empty());
    f.assert_base(&owner, SelectionOrigin::Default, low());
    assert_eq!(owner.decisions().len(), 1);
    let durable: Value = serde_json::from_slice(
        &fs::read(f.home.join("sessions/.requests/routing-owner.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(durable["requests"]["cancel-routed"]["state"], "interrupted");
}

#[test]
fn routed_tool_round_keeps_inherited_read_denial() {
    let f = Fixture::new();
    let protected = "routed-policy-protected-content";
    write_private(&f.workspace.join("note.txt"), protected);
    f.b.mode(json!({"tool":"Read","arguments":{"file_path":"note.txt"}}));
    let scope = PermissionScope::from_flags(Some("plan"), None, Some("Read"));
    let mut owner = f.start_scoped(Some(SelectionOrigin::Default), None, scope);
    owner.prompt("scope-routed", PROMPT);
    assert!(f.a.calls().is_empty());
    let calls = f.b.calls();
    assert_eq!(calls.len(), 2);
    assert!(
        !calls[0]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["function"]["name"] == "Read")
    );
    let tool = calls[1]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .unwrap();
    let result: Value = serde_json::from_str(tool["content"].as_str().unwrap()).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["denied"], true);
    assert!(!serde_json::to_string(&calls).unwrap().contains(protected));
    assert_eq!(
        owner.snapshot().permission_mode,
        orbit_tools::permissions::PermissionMode::Plan
    );
    assert_eq!(owner.decisions().len(), 1);
    let (records, _) = orbit_ledger::verify_ledger(&f.home.join("ledger")).unwrap();
    assert!(records.iter().any(|record|matches!(&record.record.event,orbit_ledger::LedgerEvent::ToolResult(result) if result.tool_name=="Read" && result.status=="denied")));
}

#[test]
fn invalid_hot_switch_retains_pin_and_next_turn_uses_original_provider() {
    let f = Fixture::new();
    let mut owner = f.start(Some(SelectionOrigin::Flag), low());
    let before = fs::read(f.home.join("sessions/routing-owner.json")).unwrap();
    assert!(
        owner
            .send(OwnerAction::SetModel {
                model: "provider_b/missing".into(),
                provider: None
            })
            .is_err()
    );
    f.assert_no_calls();
    assert_eq!(
        fs::read(f.home.join("sessions/routing-owner.json")).unwrap(),
        before
    );
    f.assert_base(&owner, SelectionOrigin::Flag, low());
    owner.prompt("after-bad-switch", PROMPT);
    assert_eq!(f.a.calls().len(), 1);
    assert!(f.b.calls().is_empty());
    assert_eq!(owner.decisions()[0]["source"], "explicit");
}

const SAVED_OWNER_RAW: &str = "family/shared-notools";
const SAVED_OWNER_A: &str = "synthetic-owner-private-a-51e420";
const SAVED_OWNER_B: &str = "synthetic-owner-private-b-829f13";
const SAVED_OWNER_B_NEXT: &str = "synthetic-owner-private-b-next-45f43c";

struct SavedOwnerFixture {
    fixture: Fixture,
    env_b: String,
    revision_b: orbit_adapter::provider_credentials::ProviderCredentialRevision,
}

impl SavedOwnerFixture {
    fn new() -> Self {
        use orbit_adapter::provider_credentials::{ExpectedRevision, ProviderCredentialStore};
        let fixture = Fixture::new();
        let env_a = format!("ORBIT_OWNER_SAVE_A_{}", ulid::Ulid::new());
        let env_b = format!("ORBIT_OWNER_SAVE_B_{}", ulid::Ulid::new());
        assert!(std::env::var_os(&env_a).is_none());
        assert!(std::env::var_os(&env_b).is_none());
        let config = format!(
            "[[provider]]\nname='provider_a'\nurl={:?}\nenv={env_a:?}\n\
             [[provider.models]]\nid={SAVED_OWNER_RAW:?}\ncontext_window=65536\ncontext_limits={{input_tokens=65536}}\nmax_output_tokens=1111\n\
             [[provider]]\nname='provider_b'\nurl={:?}\nenv={env_b:?}\n\
             [[provider.models]]\nid={SAVED_OWNER_RAW:?}\ncontext_window=131072\ncontext_limits={{input_tokens=131072}}\nmax_output_tokens=733\n\
             supported_efforts=['medium','high']\ndefault_effort='medium'\n\
             [roles]\nmain='provider_a/{SAVED_OWNER_RAW}'\n\
             [routing.phases.coding]\ndefault='provider_b/{SAVED_OWNER_RAW}'\nhard='provider_b/{SAVED_OWNER_RAW}'\n\
             [routing.phase_keywords]\nclear=true\ncoding=['implement']\n",
            fixture.a.gate, fixture.b.gate
        );
        write_private(&fixture.home.join("providers.toml"), config);
        let store = ProviderCredentialStore::new(&fixture.home).unwrap();
        store
            .save(
                &Self::identity(&fixture, "provider_a", &env_a),
                orbit_adapter::SecretBytes::new(SAVED_OWNER_A.as_bytes().to_vec()),
                ExpectedRevision::Absent,
            )
            .unwrap();
        let revision_b = store
            .save(
                &Self::identity(&fixture, "provider_b", &env_b),
                orbit_adapter::SecretBytes::new(SAVED_OWNER_B.as_bytes().to_vec()),
                ExpectedRevision::Absent,
            )
            .unwrap()
            .revision;
        Self {
            fixture,
            env_b,
            revision_b,
        }
    }

    fn identity(
        fixture: &Fixture,
        provider_id: &str,
        env: &str,
    ) -> orbit_adapter::provider_credentials::ProviderAuthIdentity {
        let config = orbit_cli::config::ProvidersConfig::load(&fixture.home).unwrap();
        let provider = config
            .provider
            .iter()
            .find(|p| p.name == provider_id)
            .unwrap();
        let endpoint = orbit_cli::config::validate_provider_endpoint(&provider.url).unwrap();
        orbit_adapter::provider_credentials::ProviderAuthIdentity::new(
            provider_id,
            &provider.kind,
            endpoint.as_str(),
            Some(env),
        )
        .unwrap()
    }

    fn start(&self, explicit: Option<&str>, effort: Option<EffortSetting>) -> Owned {
        let f = &self.fixture;
        let config = orbit_cli::config::ProvidersConfig::load(&f.home).unwrap();
        let spec = explicit.unwrap_or(&config.roles.main);
        let mut turn = orbit_cli::checked_model_turn(&f.home, spec, None, None, false).unwrap();
        if let Some(setting) = &effort {
            orbit_cli::apply_effort_setting(&f.home, &mut turn, setting).unwrap();
        }
        let origin = if explicit.is_some() {
            SelectionOrigin::Flag
        } else {
            SelectionOrigin::Default
        };
        let saved = SessionFile::from_chat(
            SESSION,
            &turn.model,
            &turn.gate,
            &turn.provider_id,
            &[],
            0,
            0,
            0,
            0,
        )
        .with_effort(effort)
        .with_selection_origin(origin);
        let lease = SessionLease::acquire(&f.home, SESSION, "saved-auth-test").unwrap();
        lease.save(&saved).unwrap();
        Owned::new(
            OwnerRuntime::start(
                OwnerConfig::new(
                    f.turn(&saved, PermissionScope::default()),
                    f.workspace.clone(),
                ),
                lease,
            )
            .unwrap(),
        )
    }

    fn assert_call(
        &self,
        provider: &CapturedProvider,
        index: usize,
        key: &str,
        max: u64,
        effort: Option<&str>,
    ) {
        let calls = provider.calls();
        let headers = provider.request_metadata();
        assert_eq!(calls.len(), headers.len(), "one metadata record per POST");
        let body = &calls[index];
        assert_eq!(headers[index]["method"], "POST");
        assert_eq!(headers[index]["path"], "/v1/chat/completions");
        assert_eq!(
            headers[index]["authorization"],
            json!([format!("Bearer {key}")])
        );
        assert_eq!(headers[index]["x_api_key"], json!([]));
        assert_eq!(body["model"], SAVED_OWNER_RAW);
        assert_eq!(body["max_tokens"], max);
        match effort {
            Some(value) => assert_eq!(body["reasoning_effort"], value),
            None => assert!(body.get("reasoning_effort").is_none()),
        }
        assert!(body.get("context_window").is_none());
        assert!(body.get("window_tokens").is_none());
        assert!(!body.to_string().contains(key));
    }

    fn assert_usage(owner: &Owned, expected: u64) {
        let usage: Vec<_> = owner
            .events()
            .into_iter()
            .filter(|event| event.kind == "usage")
            .collect();
        assert_eq!(
            usage.len(),
            1,
            "one real engine usage event for the one completion"
        );
        assert_eq!(usage[0].payload["window_tokens"], expected);
    }

    fn assert_public_state_has_no_keys(&self, owner: &Owned) {
        let public = format!("{:?}\n{:?}", owner.snapshot(), owner.events());
        for key in [SAVED_OWNER_A, SAVED_OWNER_B, SAVED_OWNER_B_NEXT] {
            assert!(!public.contains(key));
        }
        fn visit(path: &Path, keys: &[&str]) {
            if path.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    visit(&entry.unwrap().path(), keys);
                }
            } else {
                let bytes = fs::read(path).unwrap();
                for key in keys {
                    assert!(
                        !bytes.windows(key.len()).any(|w| w == key.as_bytes()),
                        "secret copied outside private store: {}",
                        path.display()
                    );
                }
            }
        }
        for relative in ["providers.toml", "sessions", "ledger"] {
            let path = self.fixture.home.join(relative);
            if path.exists() {
                visit(&path, &[SAVED_OWNER_A, SAVED_OWNER_B, SAVED_OWNER_B_NEXT]);
            }
        }
    }
}

#[test]
fn saved_private_default_owner_uses_exact_key_output_and_context_with_unknown_effort() {
    let f = SavedOwnerFixture::new();
    let mut owner = f.start(None, None);
    f.fixture.assert_no_calls();
    owner.prompt("saved-default", "observe this workspace");
    assert_eq!(
        owner.snapshot().requests["saved-default"].state,
        RequestState::Completed
    );
    assert_eq!(f.fixture.a.calls().len(), 1);
    assert!(f.fixture.b.calls().is_empty());
    f.assert_call(&f.fixture.a, 0, SAVED_OWNER_A, 1111, None);
    SavedOwnerFixture::assert_usage(&owner, 65536);
    assert_eq!(owner.snapshot().supported_efforts, None);
    assert_eq!(owner.snapshot().resolved_effort, None);
    assert_eq!(f.fixture.saved().provider, "provider_a");
    assert_eq!(f.fixture.saved().model, SAVED_OWNER_RAW);
    assert_eq!(f.fixture.saved().effort, None);
    f.assert_public_state_has_no_keys(&owner);
    owner.shutdown();
    let mut resumed = f.fixture.restart();
    assert_eq!(
        f.fixture.a.calls().len(),
        1,
        "unknown-effort restart is offline"
    );
    assert_eq!(resumed.snapshot().supported_efforts, None);
    assert_eq!(resumed.snapshot().resolved_effort, None);
    resumed.prompt("saved-default-resumed", "observe the next file");
    assert_eq!(
        resumed.snapshot().requests["saved-default-resumed"].state,
        RequestState::Completed
    );
    assert_eq!(f.fixture.a.calls().len(), 2);
    assert!(f.fixture.b.calls().is_empty());
    f.assert_call(&f.fixture.a, 1, SAVED_OWNER_A, 1111, None);
    SavedOwnerFixture::assert_usage(&resumed, 65536);
    assert_eq!(f.fixture.saved().effort, None);
    f.assert_public_state_has_no_keys(&resumed);
}

#[test]
fn saved_private_explicit_owner_override_resolves_duplicate_raw_model_to_b_key_and_caps() {
    let f = SavedOwnerFixture::new();
    let high = Some(EffortSetting::Value(EffortValue::Level("high".into())));
    let mut owner = f.start(Some("provider_b/family/shared-notools"), high.clone());
    f.fixture.assert_no_calls();
    owner.prompt("saved-explicit", PROMPT);
    assert_eq!(
        owner.snapshot().requests["saved-explicit"].state,
        RequestState::Completed
    );
    assert!(f.fixture.a.calls().is_empty());
    assert_eq!(f.fixture.b.calls().len(), 1);
    f.assert_call(&f.fixture.b, 0, SAVED_OWNER_B, 733, Some("high"));
    SavedOwnerFixture::assert_usage(&owner, 131072);
    assert_eq!(owner.snapshot().selection_origin, SelectionOrigin::Flag);
    assert_eq!(f.fixture.saved().provider, "provider_b");
    assert_eq!(f.fixture.saved().effort, high);
    f.assert_public_state_has_no_keys(&owner);
}

#[test]
fn saved_private_routed_owner_uses_target_key_caps_context_and_default_effort_once() {
    let f = SavedOwnerFixture::new();
    let mut owner = f.start(None, None);
    owner.prompt("saved-routed", PROMPT);
    assert_eq!(
        owner.snapshot().requests["saved-routed"].state,
        RequestState::Completed
    );
    assert!(f.fixture.a.calls().is_empty());
    assert_eq!(f.fixture.b.calls().len(), 1);
    f.assert_call(&f.fixture.b, 0, SAVED_OWNER_B, 733, Some("medium"));
    SavedOwnerFixture::assert_usage(&owner, 131072);
    assert_eq!(owner.decisions().len(), 1);
    assert_eq!(
        owner.snapshot().last_route.unwrap()["provider_id"],
        "provider_b"
    );
    assert_eq!(f.fixture.saved().provider, "provider_a");
    assert_eq!(f.fixture.saved().model, SAVED_OWNER_RAW);
    assert_eq!(f.fixture.saved().effort, None);
    f.assert_public_state_has_no_keys(&owner);
}

#[test]
fn saved_private_resumed_owner_reresolves_rotated_key_and_retains_explicit_effort_reset() {
    use orbit_adapter::provider_credentials::{ExpectedRevision, ProviderCredentialStore};
    let f = SavedOwnerFixture::new();
    let mut first = f.start(
        Some("provider_b/family/shared-notools"),
        Some(EffortSetting::Default),
    );
    first.prompt("saved-before-restart", "observe first");
    assert_eq!(
        first.snapshot().requests["saved-before-restart"].state,
        RequestState::Completed
    );
    first.shutdown();
    ProviderCredentialStore::new(&f.fixture.home)
        .unwrap()
        .save(
            &SavedOwnerFixture::identity(&f.fixture, "provider_b", &f.env_b),
            orbit_adapter::SecretBytes::new(SAVED_OWNER_B_NEXT.as_bytes().to_vec()),
            ExpectedRevision::Exact(f.revision_b),
        )
        .unwrap();
    let mut resumed = f.fixture.restart();
    assert_eq!(f.fixture.b.calls().len(), 1, "restart is offline");
    assert_eq!(resumed.snapshot().effort, Some(EffortSetting::Default));
    resumed.prompt("saved-after-restart", PROMPT);
    assert_eq!(
        resumed.snapshot().requests["saved-after-restart"].state,
        RequestState::Completed
    );
    assert!(f.fixture.a.calls().is_empty());
    assert_eq!(f.fixture.b.calls().len(), 2);
    f.assert_call(&f.fixture.b, 0, SAVED_OWNER_B, 733, Some("medium"));
    f.assert_call(&f.fixture.b, 1, SAVED_OWNER_B_NEXT, 733, Some("medium"));
    SavedOwnerFixture::assert_usage(&resumed, 131072);
    assert_eq!(f.fixture.saved().provider, "provider_b");
    assert_eq!(f.fixture.saved().effort, Some(EffortSetting::Default));
    assert_eq!(
        resumed.snapshot().supported_efforts,
        Some(vec![
            EffortValue::Level("medium".into()),
            EffortValue::Level("high".into())
        ])
    );
    f.assert_public_state_has_no_keys(&resumed);
}

#[cfg(all(target_os = "linux", feature = "tui"))]
mod context_frontend_tests {
    use super::*;
    use orbit_adapter::SecretBytes;
    use orbit_adapter::provider_credentials::{
        ExpectedRevision, ProviderAuthIdentity, ProviderCredentialStore,
    };
    use orbit_adapter::types::{ChatMessage, ChatRole, ContentBlock};
    use orbit_cli::attach::AttachClient;
    use orbit_cli::daemon::UnixServer;
    use orbit_cli::setup::{SetupRequest, apply_setup, plan_setup};
    use orbit_hud_tui::ApprovalRegistry;
    use orbit_hud_tui::bus::Bus;
    use orbit_hud_tui::msg::Msg;
    use orbit_hud_tui::worker::{WorkerCommand, WorkerCtx};
    use std::sync::mpsc;

    const RAW: &str = "family/shared-notools";
    const QUERY: &str = "scope=frontend-fixture&escaped=left%2Fright";
    const KEY_A: &str = "synthetic-context-parent-key";
    const KEY_B: &str = "synthetic-context-selected-key";
    const KEY_C: &str = "synthetic-context-summary-key";
    const IMAGE: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aJYkAAAAASUVORK5CYII=";

    #[derive(Debug, Clone, Copy)]
    enum Entry {
        Headless,
        Repl,
        Tui,
        Owner,
        Attach,
    }
    const ENTRIES: [Entry; 5] = [
        Entry::Headless,
        Entry::Repl,
        Entry::Tui,
        Entry::Owner,
        Entry::Attach,
    ];

    struct ContextFixture {
        fixture: Fixture,
        summary: CapturedProvider,
        envs: [String; 3],
    }
    impl ContextFixture {
        fn new(limits: Option<Value>, output: u32, summary_limits: Value) -> Self {
            let fixture = Fixture::new();
            let summary = CapturedProvider::new(fixture.root.join("context-summary"));
            let plan = plan_setup(&fixture.home, &SetupRequest::default()).unwrap();
            apply_setup(&plan).unwrap();
            assert!(fixture.home.join("trust/manifest.json").is_file());
            let envs = ["A", "B", "C"]
                .map(|suffix| format!("ORBIT_CONTEXT_FRONTEND_{suffix}_{}", ulid::Ulid::new()));
            let result = Self {
                fixture,
                summary,
                envs,
            };
            result.configure(limits, output, summary_limits, None);
            let config = orbit_cli::config::ProvidersConfig::load(&result.fixture.home).unwrap();
            let store = ProviderCredentialStore::new(&result.fixture.home).unwrap();
            for (provider, key) in config.provider.iter().zip([KEY_A, KEY_B, KEY_C]) {
                let endpoint =
                    orbit_cli::config::validate_provider_endpoint(&provider.url).unwrap();
                let identity = ProviderAuthIdentity::new(
                    &provider.name,
                    &provider.kind,
                    endpoint.as_str(),
                    provider.env.as_deref(),
                )
                .unwrap();
                assert!(std::env::var_os(provider.env.as_ref().unwrap()).is_none());
                store
                    .save(
                        &identity,
                        SecretBytes::new(key.as_bytes().to_vec()),
                        ExpectedRevision::Absent,
                    )
                    .unwrap();
            }
            result
        }
        fn configure(
            &self,
            limits: Option<Value>,
            output: u32,
            summary_limits: Value,
            legacy: Option<u64>,
        ) {
            let provider = |name: &str,
                            gate: &str,
                            env: &str,
                            output: u32,
                            limits: Option<Value>,
                            effort: &str,
                            legacy: Option<u64>| {
                json!({
                    "name":name,"kind":"openai-compatible","url":format!("{gate}/tenant/v1?{QUERY}"),"env":env,
                    "models":[{"id":RAW,"max_output_tokens":output,"context_window":legacy,"context_limits":limits,
                        "supported_efforts":["low","high"],"default_effort":effort}]
                })
            };
            let document = json!({"provider":[
                provider("provider_a",&self.fixture.a.gate,&self.envs[0],1024,Some(json!({"input_tokens":1_000_000})),"low",None),
                provider("provider_b",&self.fixture.b.gate,&self.envs[1],output,limits,"high",legacy),
                provider("provider_c",&self.summary.gate,&self.envs[2],1024,Some(summary_limits),"low",None)
            ],"roles":{"main":format!("provider_a/{RAW}"),"compaction":format!("provider_c/{RAW}")}});
            let config: orbit_cli::config::ProvidersConfig =
                serde_json::from_value(document).unwrap();
            write_private(
                &self.fixture.home.join("providers.toml"),
                toml::to_string(&config).unwrap(),
            );
        }
        fn seed(&self, history: &[ChatMessage]) {
            let config = orbit_cli::config::ProvidersConfig::load(&self.fixture.home).unwrap();
            let provider = config
                .provider
                .iter()
                .find(|provider| provider.name == "provider_b")
                .unwrap();
            let saved = SessionFile::from_chat(
                SESSION,
                RAW,
                &provider.url,
                "provider_b",
                history,
                0,
                0,
                0,
                0,
            )
            .with_selection_origin(SelectionOrigin::SavedExplicit);
            let lease = SessionLease::acquire(&self.fixture.home, SESSION, "context-seed").unwrap();
            lease.save(&saved).unwrap();
        }
        fn run(&self, entry: Entry, prompt: &str) -> Capture {
            match entry {
                Entry::Headless => self.process(false, prompt),
                Entry::Repl => self.process(true, prompt),
                Entry::Tui => self.tui(prompt),
                Entry::Owner => {
                    let mut owner = self.fixture.restart();
                    let result = owner.send(OwnerAction::Prompt {
                        request_id: "context-turn".into(),
                        text: prompt.into(),
                    });
                    if result.is_ok() {
                        owner.finished("context-turn");
                    }
                    let mut events: Vec<_> = owner.events().into_iter().map(owner_event).collect();
                    if let Err(error) = result {
                        events.push(json!({"type":"error","message":error.to_string()}));
                    }
                    owner.shutdown();
                    Capture {
                        events,
                        text: String::new(),
                    }
                }
                Entry::Attach => self.attach(prompt),
            }
        }
        fn process(&self, repl: bool, prompt: &str) -> Capture {
            let mut command = self.command(env!("CARGO_BIN_EXE_orbit"));
            let input = if repl {
                command.args(["--no-tui", "--resume", SESSION]);
                format!("{prompt}\nexit\n")
            } else {
                command.args([
                    "-p",
                    prompt,
                    "--resume",
                    SESSION,
                    "--output-format",
                    "stream-json",
                ]);
                String::new()
            };
            let output = bounded_process(command, &self.fixture.root, &input);
            let events = output
                .0
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            Capture {
                events,
                text: format!("{}\n{}", output.0, output.1),
            }
        }
        fn command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
            let mut command = Command::new(executable);
            command
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("LANG", "C.UTF-8")
                .env("ORBIT_HOME", &self.fixture.home)
                .current_dir(&self.fixture.workspace);
            command
        }
        fn tui(&self, prompt: &str) -> Capture {
            self.tui_mode(prompt, false)
        }
        fn tui_mode(&self, prompt: &str, plan: bool) -> Capture {
            let result = self.fixture.root.join("tui-result.json");
            let mut command = self.command(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "context_frontend_tests::tui_child_dispatch",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ORBIT_CONTEXT_TEST_RESULT", &result)
                .env("ORBIT_CONTEXT_TEST_PROMPT", prompt)
                .env("ORBIT_CONTEXT_TEST_PLAN", if plan { "1" } else { "0" });
            let output = bounded_process(command, &self.fixture.root, "");
            let events: Vec<Value> =
                serde_json::from_slice(&fs::read(result).unwrap_or_else(|_| {
                    panic!("TUI fixture did not finish: {} {}", output.0, output.1)
                }))
                .unwrap();
            Capture {
                events,
                text: format!("{}\n{}", output.0, output.1),
            }
        }
        fn attach(&self, prompt: &str) -> Capture {
            let (lease, saved) =
                SessionLease::acquire_and_load(&self.fixture.home, SESSION, "context-attach")
                    .unwrap();
            let runtime = OwnerRuntime::start(
                OwnerConfig::new(
                    self.fixture.turn(&saved, PermissionScope::default()),
                    self.fixture.workspace.clone(),
                ),
                lease,
            )
            .unwrap();
            let handle = runtime.handle();
            let cursor = handle.snapshot().unwrap().cursor;
            let socket = self.fixture.home.join("run/context.sock");
            let server = UnixServer::bind(&socket, handle.clone()).unwrap();
            let stop = orbit_provider_http::CancelToken::new();
            let shutdown = stop.clone();
            let thread = std::thread::spawn(move || server.run(&shutdown));
            let serving = Serving {
                runtime: Some(runtime),
                stop,
                thread: Some(thread),
            };
            let mut client = AttachClient::connect(&socket, true, Some(&cursor)).unwrap();
            let ack = client.send(OwnerAction::Prompt {
                request_id: "context-attach".into(),
                text: prompt.into(),
            });
            if ack.is_ok() {
                wait_owner_finished(&handle, "context-attach");
            }
            let mut events: Vec<_> = client
                .logs(Some(&cursor))
                .unwrap()
                .events
                .into_iter()
                .map(owner_event)
                .collect();
            if let Err(error) = ack {
                events.push(json!({"type":"error","message":error.to_string()}));
            }
            drop(client);
            drop(serving);
            Capture {
                events,
                text: String::new(),
            }
        }
        fn calls(&self) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
            (
                self.fixture.a.calls(),
                self.fixture.b.calls(),
                self.summary.calls(),
            )
        }
        fn assert_call(
            &self,
            provider: &CapturedProvider,
            key: &str,
            output: u64,
            effort: &str,
            no_tools: bool,
        ) {
            let calls = provider.calls();
            let headers = provider.request_metadata();
            assert_eq!(calls.len(), 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(
                headers[0]["path"],
                format!("/tenant/v1/chat/completions?{QUERY}")
            );
            assert_eq!(
                headers[0]["authorization"],
                json!([format!("Bearer {key}")])
            );
            assert_eq!(headers[0]["x_api_key"], json!([]));
            assert_eq!(calls[0]["model"], RAW);
            assert_eq!(calls[0]["max_tokens"], output);
            assert_eq!(calls[0]["reasoning_effort"], effort);
            if no_tools {
                assert!(
                    calls[0]
                        .get("tools")
                        .is_none_or(|tools| tools.as_array().is_some_and(Vec::is_empty))
                );
            }
            assert!(calls[0].get("context_window").is_none());
            assert!(calls[0].get("window_tokens").is_none());
        }
        fn assert_no_calls(&self) {
            let (a, b, c) = self.calls();
            assert!(
                a.is_empty() && b.is_empty() && c.is_empty(),
                "unexpected POST: A={} B={} C={}",
                a.len(),
                b.len(),
                c.len()
            );
            assert!(self.fixture.egress().is_empty());
        }
    }
    impl Drop for ContextFixture {
        fn drop(&mut self) {
            self.summary.stop();
        }
    }
    struct Serving {
        runtime: Option<OwnerRuntime>,
        stop: orbit_provider_http::CancelToken,
        thread: Option<std::thread::JoinHandle<Result<(), OwnerError>>>,
    }
    impl Drop for Serving {
        fn drop(&mut self) {
            self.stop.cancel();
            if let Some(thread) = self.thread.take() {
                let result = thread.join();
                if !std::thread::panicking() {
                    result
                        .expect("attach server thread")
                        .expect("attach server completion");
                }
            }
            if let Some(runtime) = self.runtime.take() {
                let result = runtime.shutdown();
                if !std::thread::panicking() {
                    result.expect("attach owner shutdown");
                }
            }
        }
    }

    struct Capture {
        events: Vec<Value>,
        text: String,
    }
    fn owner_event(event: OwnerEvent) -> Value {
        match event.payload {
            Value::Object(mut payload) => {
                payload
                    .entry("type".to_owned())
                    .or_insert(Value::String(event.kind));
                Value::Object(payload)
            }
            payload => json!({"type":event.kind,"payload":payload}),
        }
    }
    impl Capture {
        fn statuses(&self) -> String {
            let events = self
                .events
                .iter()
                .filter(|event| event["type"] == "status")
                .filter_map(|event| event["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let plain = self
                .text
                .lines()
                .filter(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower.contains("fallback")
                        || lower.contains("context budget")
                        || lower.contains("legacy")
                        || lower.contains("media")
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("{events}\n{plain}")
        }
        fn assert_safe(&self, f: &ContextFixture) {
            let statuses = self.statuses();
            for value in [KEY_A, KEY_B, KEY_C, QUERY]
                .into_iter()
                .chain(f.envs.iter().map(String::as_str))
            {
                assert!(
                    !statuses.contains(value),
                    "status leaked a credential/binding value"
                );
            }
        }
        fn assert_budget_refusal(&self) {
            let errors = self
                .events
                .iter()
                .filter(|event| event["type"] == "error")
                .filter_map(|event| event["message"].as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let actual = format!("{errors}\n{}", self.text).to_ascii_lowercase();
            assert!(
                actual.contains("context budget") || actual.contains("context limit required"),
                "fixture must reach actual budget refusal"
            );
        }
        fn meter(&self, window: u64, reserve: u64, compact_at: u64) {
            let usage: Vec<_> = self
                .events
                .iter()
                .filter(|event| event["type"] == "usage")
                .collect();
            assert_eq!(
                usage.len(),
                1,
                "one ordinary completion has one real usage event"
            );
            assert_eq!(usage[0]["window_tokens"], window);
            assert_eq!(usage[0]["breakdown"]["reserve"], reserve);
            assert_eq!(usage[0]["breakdown"]["compact_at"], compact_at);
        }
    }
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    fn bounded_process(mut command: Command, root: &Path, input: &str) -> (String, String) {
        let id = ulid::Ulid::new().to_string();
        let stdin = root.join(format!("{id}.in"));
        let stdout = root.join(format!("{id}.out"));
        let stderr = root.join(format!("{id}.err"));
        for (path, bytes) in [
            (&stdin, input.as_bytes()),
            (&stdout, b"".as_slice()),
            (&stderr, b"".as_slice()),
        ] {
            write_private(path, bytes);
        }
        let mut child = ChildGuard(
            command
                .stdin(fs::File::open(stdin).unwrap())
                .stdout(fs::File::options().write(true).open(&stdout).unwrap())
                .stderr(fs::File::options().write(true).open(&stderr).unwrap())
                .spawn()
                .unwrap(),
        );
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            if child.0.try_wait().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < end, "frontend fixture timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        (
            fs::read_to_string(stdout).unwrap(),
            fs::read_to_string(stderr).unwrap(),
        )
    }
    fn wait_owner_finished(handle: &OwnerHandle, id: &str) {
        let end = Instant::now() + Duration::from_secs(8);
        loop {
            let snapshot = handle.snapshot().unwrap();
            if snapshot.state == TurnState::Idle
                && snapshot.requests.get(id).is_some_and(|request| {
                    !matches!(
                        request.state,
                        RequestState::Accepted | RequestState::Running
                    )
                })
            {
                break;
            }
            assert!(Instant::now() < end, "owner fixture did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn text(role: ChatRole, content: String) -> ChatMessage {
        ChatMessage {
            role,
            content,
            tool_calls: None,
            tool_call_id: None,
            tool_result: None,
            blocks: None,
            origin_model: None,
            origin_provider: None,
        }
    }
    fn old_history() -> Vec<ChatMessage> {
        let mut history: Vec<_> = (0..32)
            .map(|index| {
                text(
                    if index % 2 == 0 {
                        ChatRole::User
                    } else {
                        ChatRole::Assistant
                    },
                    format!("OLD-{index}:{}", "x".repeat(12_000)),
                )
            })
            .collect();
        for index in 0..6 {
            history.push(text(
                if index % 2 == 0 {
                    ChatRole::User
                } else {
                    ChatRole::Assistant
                },
                format!("VERBATIM-TAIL-{index}"),
            ));
        }
        history
    }
    fn selected_refusal(entry: Entry) {
        let f = ContextFixture::new(
            Some(json!({"input_tokens":1})),
            1024,
            json!({"input_tokens":50_000}),
        );
        f.seed(&[]);
        let result = f.run(entry, "inspect this bounded request");
        f.assert_no_calls();
        result.assert_budget_refusal();
        result.assert_safe(&f);
    }
    #[test]
    fn context_frontend_headless_selected_typed_limit_refuses_before_post() {
        selected_refusal(Entry::Headless);
    }
    #[test]
    fn context_frontend_repl_selected_typed_limit_refuses_before_post() {
        selected_refusal(Entry::Repl);
    }
    #[test]
    fn context_frontend_tui_selected_typed_limit_refuses_before_post() {
        selected_refusal(Entry::Tui);
    }
    #[test]
    fn context_frontend_owner_selected_typed_limit_refuses_before_post() {
        selected_refusal(Entry::Owner);
    }
    #[test]
    fn context_frontend_attach_selected_typed_limit_refuses_before_post() {
        selected_refusal(Entry::Attach);
    }

    #[test]
    fn context_frontend_fit_exact_selected_binding_and_actual_output_meter() {
        for entry in ENTRIES {
            let f = ContextFixture::new(
                Some(json!({"combined_tokens":128_000})),
                32_000,
                json!({"input_tokens":50_000}),
            );
            f.seed(&[]);
            let result = f.run(entry, "inspect this request");
            let (a, b, c) = f.calls();
            assert!(a.is_empty() && c.is_empty());
            assert_eq!(b.len(), 1);
            f.assert_call(&f.fixture.b, KEY_B, 32_000, "high", false);
            result.assert_safe(&f);
            if !matches!(entry, Entry::Repl) {
                result.meter(128_000, 32_000, 83_200);
            }
        }
    }
    #[test]
    fn context_frontend_summary_role_own_typed_limit_prevents_summary_and_ordinary_post() {
        for entry in ENTRIES {
            let f = ContextFixture::new(
                Some(json!({"input_tokens":64_000})),
                32_000,
                json!({"input_tokens":1}),
            );
            f.seed(&old_history());
            let result = f.run(entry, "continue from the retained tail");
            f.assert_no_calls();
            result.assert_budget_refusal();
            result.assert_safe(&f);
        }
    }
    #[test]
    fn context_frontend_summary_then_continuation_keep_exact_keys_outputs_efforts_and_tail() {
        for entry in ENTRIES {
            let f = ContextFixture::new(
                Some(json!({"input_tokens":64_000})),
                32_000,
                json!({"input_tokens":50_000}),
            );
            f.seed(&old_history());
            let result = f.run(entry, "continue from the retained tail");
            let (a, b, c) = f.calls();
            assert!(a.is_empty());
            assert_eq!(b.len(), 1);
            assert_eq!(c.len(), 1);
            f.assert_call(&f.summary, KEY_C, 1024, "low", true);
            f.assert_call(&f.fixture.b, KEY_B, 32_000, "high", false);
            let body = b[0].to_string();
            assert!(!body.contains("OLD-0:"));
            for index in 1..6 {
                assert!(body.contains(&format!("VERBATIM-TAIL-{index}")));
            }
            assert!(body.contains("continue from the retained tail"));
            result.assert_safe(&f);
            if !matches!(entry, Entry::Repl) {
                result.meter(64_000, 0, 57_600);
            }
        }
    }
    #[test]
    fn context_frontend_unknown_fallback_is_visible_numeric_and_makes_one_ordinary_post() {
        for entry in ENTRIES {
            let f = ContextFixture::new(None, 1024, json!({"input_tokens":50_000}));
            f.seed(&[]);
            let result = f.run(entry, "inspect one request");
            let (a, b, c) = f.calls();
            assert!(a.is_empty() && c.is_empty());
            assert_eq!(b.len(), 1);
            let status = result.statuses().to_ascii_lowercase();
            assert!(status.contains("fallback"));
            assert!(status.contains("64000") || status.contains("64,000"));
            result.assert_safe(&f);
            if !matches!(entry, Entry::Repl) {
                result.meter(64_000, 1024, 56_576);
            }
        }
    }
    #[test]
    fn context_frontend_ambiguous_legacy_value_gets_actionable_notice_and_fallback_meter() {
        for entry in ENTRIES {
            let f = ContextFixture::new(None, 1024, json!({"input_tokens":50_000}));
            f.configure(None, 1024, json!({"input_tokens":50_000}), Some(200_000));
            f.seed(&[]);
            let result = f.run(entry, "inspect ambiguous legacy context");
            let (a, b, c) = f.calls();
            assert!(a.is_empty() && c.is_empty());
            assert_eq!(b.len(), 1);
            assert!(result.statuses().contains("context_limits.input_tokens"));
            result.assert_safe(&f);
            if !matches!(entry, Entry::Repl) {
                result.meter(64_000, 1024, 56_576);
            }
        }
    }
    #[test]
    fn context_frontend_actual_output_above_old_reserve_refuses_fixed_oversize_request() {
        for entry in ENTRIES {
            let f = ContextFixture::new(
                Some(json!({"combined_tokens":65_536})),
                64_000,
                json!({"input_tokens":50_000}),
            );
            f.seed(&[]);
            let result = f.run(
                entry,
                &format!("bounded current intent {}", "z".repeat(16_000)),
            );
            f.assert_no_calls();
            result.assert_budget_refusal();
            result.assert_safe(&f);
        }
    }
    fn media_case(strict: bool) {
        for entry in ENTRIES {
            let mut limits = json!({"input_tokens":64_000});
            if strict {
                limits["media_policy"] = json!("refuse");
            }
            let f = ContextFixture::new(Some(limits), 1024, json!({"input_tokens":50_000}));
            let mut image = text(ChatRole::User, "inspect saved image".into());
            image.blocks = Some(vec![
                ContentBlock::Text {
                    text: "inspect saved image".into(),
                },
                ContentBlock::Image {
                    data: IMAGE.into(),
                    media_type: "image/png".into(),
                },
            ]);
            f.seed(&[image]);
            let result = f.run(entry, "describe the saved image");
            if strict {
                f.assert_no_calls();
                result.assert_budget_refusal();
            } else {
                let (a, b, c) = f.calls();
                assert!(a.is_empty() && c.is_empty());
                assert_eq!(b.len(), 1);
                let expected = format!("data:image/png;base64,{IMAGE}");
                assert!(b[0]["messages"].as_array().unwrap().iter().any(|message| {
                    message["content"].as_array().is_some_and(|blocks| {
                        blocks
                            .iter()
                            .any(|block| block["image_url"]["url"] == expected)
                    })
                }));
                let status = result.statuses().to_ascii_lowercase();
                assert!(status.contains("unknown") && status.contains("media"));
            }
            result.assert_safe(&f);
        }
    }
    #[test]
    fn context_frontend_unknown_media_warns_and_preserves_supported_image_wire() {
        media_case(false);
    }
    #[test]
    fn context_frontend_strict_media_refuses_before_provider_io() {
        media_case(true);
    }

    // The real public TUI spawner runs in a fresh test process so cwd, startup
    // instructions and the global ask channel cannot leak between fixtures.
    #[test]
    #[ignore = "invoked by context_frontend_tests parents in a fresh process"]
    fn tui_child_dispatch() {
        let home = PathBuf::from(std::env::var_os("ORBIT_HOME").unwrap());
        let output = PathBuf::from(std::env::var_os("ORBIT_CONTEXT_TEST_RESULT").unwrap());
        let prompt = std::env::var("ORBIT_CONTEXT_TEST_PROMPT").unwrap();
        let (lease, saved) = SessionLease::acquire_and_load(&home, SESSION, "context-tui").unwrap();
        let config = TuiTurnConfig {
            home: home.clone(),
            session_id: saved.session_id.clone(),
            gate: saved.gate,
            model: saved.model,
            provider_id: saved.provider,
            effort: saved.effort,
            auto_tools: false,
            scope: PermissionScope::default(),
            initial_transcript: saved.transcript,
            initial_turns: saved.turns,
            initial_input_tokens: saved.input_tokens,
            initial_output_tokens: saved.output_tokens,
            initial_cost_microcents: saved.cost_microcents,
        };
        let (bus, sender) = Bus::new();
        let (commands, command_rx) = mpsc::channel();
        let cancel = orbit_cli::tui_worker::make_spawner_owned(config, lease)(
            WorkerCtx {
                sender,
                approvals: ApprovalRegistry::new(),
                command_rx,
            },
            commands.clone(),
        )
        .unwrap();
        let command = if std::env::var("ORBIT_CONTEXT_TEST_PLAN").as_deref() == Ok("1") {
            WorkerCommand::PlanPrompt(prompt)
        } else {
            WorkerCommand::Prompt(prompt)
        };
        commands.send(command).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        let mut events = Vec::new();
        let mut done = false;
        while Instant::now() < end && !done {
            match bus.try_recv() {
                Some(Msg::Status(text)) => events.push(json!({"type":"status","text":text})),
                Some(Msg::BackendError(message)) => events.push(json!({"type":"error","message":message})),
                Some(Msg::Usage {used_tokens,window_tokens,breakdown}) => events.push(json!({"type":"usage","used_tokens":used_tokens,"window_tokens":window_tokens,"breakdown":breakdown})),
                Some(Msg::PlanReady(text)) => events.push(json!({"type":"plan_ready","text":text})),
                Some(Msg::ResponseFinished {..}) => done=true,
                Some(_) => {}, None => std::thread::sleep(Duration::from_millis(2)),
            }
        }
        if !done {
            cancel();
        }
        assert!(done, "TUI worker did not finish bounded fixture");
        drop(commands);
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            match SessionLease::acquire(&home, SESSION, "context-tui-closed") {
                Ok(lease) => {
                    drop(lease);
                    break;
                }
                Err(_) => {
                    assert!(
                        Instant::now() < end,
                        "TUI worker retained lease after command EOF"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        while let Some(msg) = bus.try_recv() {
            if let Msg::PlanReady(text) = &msg {
                events.push(json!({"type":"plan_ready","text":text}));
            }
            if let Msg::Usage {
                used_tokens,
                window_tokens,
                breakdown,
            } = msg
            {
                events.push(json!({"type":"usage","used_tokens":used_tokens,"window_tokens":window_tokens,"breakdown":breakdown}));
            }
        }
        write_private(&output, serde_json::to_vec(&events).unwrap());
    }

    fn strict_missing_limit_preserves_durable_intent(entry: Entry) {
        const CURRENT: &str = "strict-local-budget-current-intent-63b2a1";
        let f = ContextFixture::new(
            Some(json!({"unknown_policy":"require-limit"})),
            1024,
            json!({"input_tokens":50_000}),
        );
        let original = vec![
            text(ChatRole::User, "strict-local-budget-original-user".into()),
            text(
                ChatRole::Assistant,
                "strict-local-budget-original-assistant".into(),
            ),
        ];
        f.seed(&original);
        let before = f.fixture.saved();
        assert_eq!(before.to_transcript(), original);
        let result = f.run(entry, CURRENT);
        result.assert_budget_refusal();
        result.assert_safe(&f);
        f.assert_no_calls();

        let mut expected = original;
        expected.push(text(ChatRole::User, CURRENT.into()));
        {
            // Every public entry helper has completed its real shutdown. Reacquire
            // the actual lease rather than inferring release from a visible error.
            let (lease, saved) = SessionLease::acquire_and_load(
                &f.fixture.home,
                SESSION,
                "context-local-refusal-check",
            )
            .expect("local budget refusal must release the session lease");
            assert_eq!(
                saved.to_transcript(),
                expected,
                "local budget refusal must persist all source messages and the current prompt exactly once"
            );
            assert_eq!(saved.model, before.model);
            assert_eq!(saved.provider, before.provider);
            assert_eq!(saved.gate, before.gate);
            assert_eq!(saved.selection_origin, before.selection_origin);
            assert_eq!(saved.effort, before.effort);
            drop(lease);
        }

        if matches!(entry, Entry::Owner | Entry::Attach) {
            let request_id = if matches!(entry, Entry::Owner) {
                "context-turn"
            } else {
                "context-attach"
            };
            // A fresh controller must recover a known terminal local failure.
            // Serialized state avoids depending on any additive enum variant.
            let mut restarted = f.fixture.restart();
            let snapshot = restarted.snapshot();
            assert_eq!(snapshot.state, TurnState::Idle);
            assert_eq!(snapshot.requests.len(), 1);
            assert_eq!(
                serde_json::to_value(
                    snapshot
                        .requests
                        .get(request_id)
                        .expect("local refusal request record must survive restart")
                        .state
                )
                .unwrap(),
                json!("failed"),
                "a known local refusal is not unknown, interrupted or still running"
            );
            let ack = restarted
                .send(OwnerAction::Prompt {
                    request_id: request_id.into(),
                    text: CURRENT.into(),
                })
                .expect("same request retry must recover the stored terminal acknowledgement");
            assert!(
                ack.duplicate,
                "local refusal retry must not create a second turn"
            );
            assert_eq!(ack.request_id.as_deref(), Some(request_id));
            assert_eq!(ack.state, "failed");
            assert_eq!(restarted.snapshot().requests.len(), 1);
            assert_eq!(restarted.snapshot().state, TurnState::Idle);
            restarted.shutdown();
            f.assert_no_calls();
            let (lease, saved) = SessionLease::acquire_and_load(
                &f.fixture.home,
                SESSION,
                "context-local-refusal-retry-check",
            )
            .unwrap();
            assert_eq!(
                saved.to_transcript(),
                expected,
                "deduplicated retry must not append or replay the refused prompt"
            );
            drop(lease);
        }
    }

    #[test]
    fn context_frontend_headless_strict_missing_limit_retains_prompt_and_releases_lease() {
        strict_missing_limit_preserves_durable_intent(Entry::Headless);
    }

    #[test]
    fn context_frontend_repl_strict_missing_limit_retains_prompt_and_releases_lease() {
        strict_missing_limit_preserves_durable_intent(Entry::Repl);
    }

    #[test]
    fn context_frontend_tui_strict_missing_limit_retains_prompt_and_releases_lease() {
        strict_missing_limit_preserves_durable_intent(Entry::Tui);
    }

    #[test]
    fn context_frontend_owner_strict_missing_limit_retains_prompt_and_terminal_dedup() {
        strict_missing_limit_preserves_durable_intent(Entry::Owner);
    }

    #[test]
    fn context_frontend_attach_strict_missing_limit_retains_prompt_and_terminal_dedup() {
        strict_missing_limit_preserves_durable_intent(Entry::Attach);
    }

    #[test]
    fn context_frontend_tui_plan_local_refusal_preserves_intent_without_plan_ready() {
        let f = ContextFixture::new(
            Some(json!({"unknown_policy":"require-limit"})),
            1024,
            json!({"input_tokens":50_000}),
        );
        let original = vec![
            text(ChatRole::User, "original plan context".into()),
            text(ChatRole::Assistant, "original answer".into()),
        ];
        f.seed(&original);
        let prompt = "prepare the bounded implementation plan";
        let result = f.tui_mode(prompt, true);
        result.assert_budget_refusal();
        f.assert_no_calls();
        assert!(
            !result
                .events
                .iter()
                .any(|event| event["type"] == "plan_ready"),
            "a refused plan must not be offered for execution"
        );
        let (lease, saved) =
            SessionLease::acquire_and_load(&f.fixture.home, SESSION, "plan-refusal-check").unwrap();
        let mut expected = original;
        expected.push(text(ChatRole::User, prompt.into()));
        assert_eq!(saved.to_transcript(), expected);
        drop(lease);
    }

    fn direct_ask(
        f: &ContextFixture,
        prompt: &str,
    ) -> Result<orbit_cli::TurnOutcome, (&'static str, String)> {
        let config = orbit_cli::checked_model_turn(
            &f.fixture.home,
            &format!("provider_b/{RAW}"),
            None,
            None,
            false,
        )
        .unwrap();
        orbit_cli::run_turn_with_tools(
            &f.fixture.home,
            &config.provider_id,
            &config.gate,
            &config.model,
            config.credential_env.as_deref(),
            None,
            prompt,
            None,
            None,
            orbit_provider_http::CancelToken::new(),
            vec![],
            "direct-context-ask",
        )
    }
    #[test]
    fn context_ask_oldapi_selected_limit_refuses_before_single_dispatch() {
        let f = ContextFixture::new(
            Some(json!({"input_tokens":1})),
            1024,
            json!({"input_tokens":50_000}),
        );
        let result = direct_ask(&f, "preserve the one-shot request contract");
        f.assert_no_calls();
        let (_, message) = result.expect_err("direct ask must enforce selected input policy");
        assert!(message.contains("context budget"));
    }
    #[test]
    fn context_ask_oldapi_requested_output_above_combined_limit_refuses() {
        let f = ContextFixture::new(
            Some(json!({"combined_tokens":512})),
            1024,
            json!({"input_tokens":50_000}),
        );
        let result = direct_ask(&f, "inspect one request");
        f.assert_no_calls();
        assert!(result.unwrap_err().1.contains("context budget"));
    }
    #[test]
    fn context_ask_oldapi_strict_missing_limit_refuses_without_dispatch() {
        let f = ContextFixture::new(
            Some(json!({"unknown_policy":"require-limit"})),
            1024,
            json!({"input_tokens":50_000}),
        );
        let result = direct_ask(&f, "inspect one request");
        f.assert_no_calls();
        assert!(result.unwrap_err().1.contains("context limit required"));
    }
    #[test]
    fn context_ask_oldapi_fitting_single_dispatch_keeps_exact_request_controls() {
        let f = ContextFixture::new(
            Some(json!({"combined_tokens":128_000})),
            1024,
            json!({"unknown_policy":"require-limit"}),
        );
        let outcome = direct_ask(&f, "inspect one request").unwrap();
        let (a, b, c) = f.calls();
        assert!(a.is_empty() && c.is_empty());
        assert_eq!(
            b.len(),
            1,
            "one-shot ask must not invoke its unused summary role"
        );
        f.assert_call(&f.fixture.b, KEY_B, 1024, "high", true);
        assert_eq!(outcome.output, "owned fixture reply");
    }

    #[test]
    fn context_ask_oldapi_returns_tool_call_without_executing_or_followup() {
        let f = ContextFixture::new(
            Some(json!({"combined_tokens":128_000})),
            1024,
            json!({"unknown_policy":"require-limit"}),
        );
        let target = f
            .fixture
            .workspace
            .join("one-shot-tool-must-not-execute.txt");
        f.fixture.b.mode(
            json!({"tool":"Write","arguments":{"file_path":target,"content":"unexpected effect"}}),
        );
        let config = orbit_cli::checked_model_turn(
            &f.fixture.home,
            &format!("provider_b/{RAW}"),
            None,
            None,
            false,
        )
        .unwrap();
        let tools = orbit_tools::tool_definitions()
            .into_iter()
            .filter(|tool| tool.name == "Write")
            .collect();
        let result = orbit_cli::run_turn_with_tools(
            &f.fixture.home,
            &config.provider_id,
            &config.gate,
            &config.model,
            config.credential_env.as_deref(),
            None,
            "inspect one tool proposal",
            None,
            None,
            orbit_provider_http::CancelToken::new(),
            tools,
            "single-dispatch-tools",
        )
        .unwrap();
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].name, "Write");
        assert_eq!(f.fixture.b.calls().len(), 1);
        assert!(f.fixture.a.calls().is_empty() && f.summary.calls().is_empty());
        assert!(
            !target.exists(),
            "single-dispatch ask only returns proposed tools"
        );
    }
    #[test]
    fn context_ask_binary_fallback_notice_is_visible_without_summary_resolution() {
        let f = ContextFixture::new(None, 1024, json!({"unknown_policy":"require-limit"}));
        let mut command = f.command(env!("CARGO_BIN_EXE_orbit"));
        command.args([
            "ask",
            "inspect one request",
            "--model",
            &format!("provider_b/{RAW}"),
        ]);
        let (stdout, stderr) = bounded_process(command, &f.fixture.root, "");
        let value: Value =
            serde_json::from_str(&stdout).expect("ask preserves its JSON stdout contract");
        assert_eq!(value["output"], "owned fixture reply", "{stdout} {stderr}");
        assert_eq!(f.fixture.b.calls().len(), 1);
        assert!(f.fixture.a.calls().is_empty() && f.summary.calls().is_empty());
        let notices = value["context_notices"]
            .as_array()
            .expect("actual ask must report fallback policy");
        assert!(notices.iter().any(|n| {
            n.as_str()
                .is_some_and(|s| s.contains("fallback") && s.contains("64000"))
        }));
        for secret in [KEY_A, KEY_B, KEY_C, QUERY] {
            assert!(!stdout.contains(secret) && !stderr.contains(secret));
        }
    }

    #[test]
    fn context_ask_detailed_failed_media_request_retains_unknown_cost_warning() {
        let f = ContextFixture::new(
            Some(json!({"input_tokens":128_000})),
            1024,
            json!({"unknown_policy":"require-limit"}),
        );
        f.fixture.b.mode(json!({"disconnect":true}));
        let mut message = text(ChatRole::User, "inspect image".into());
        message.blocks = Some(vec![
            ContentBlock::Text {
                text: "inspect image".into(),
            },
            ContentBlock::Image {
                data: IMAGE.into(),
                media_type: "image/png".into(),
            },
        ]);
        let config = orbit_cli::checked_model_turn(
            &f.fixture.home,
            &format!("provider_b/{RAW}"),
            None,
            None,
            false,
        )
        .unwrap();
        let failure = orbit_cli::run_turn_with_tools_detailed(
            &f.fixture.home,
            &config.provider_id,
            &config.gate,
            &config.model,
            config.credential_env.as_deref(),
            None,
            "inspect image",
            Some(vec![message]),
            None,
            orbit_provider_http::CancelToken::new(),
            vec![],
            "failed-media-ask",
        )
        .unwrap_err();
        assert_eq!(
            f.fixture.b.calls().len(),
            1,
            "failed ask must not retry an uncertain request"
        );
        assert!(f.fixture.a.calls().is_empty() && f.summary.calls().is_empty());
        assert!(
            failure.context_notices.iter().any(|notice| {
                let notice = notice.to_ascii_lowercase();
                notice.contains("unknown")
                    && (notice.contains("media") || notice.contains("opaque"))
            }),
            "failed request must retain the preflight unknown-media warning"
        );
        assert!(
            std::fs::read_dir(&f.fixture.workspace)
                .unwrap()
                .next()
                .is_none()
        );
        for secret in [KEY_A, KEY_B, KEY_C, QUERY] {
            assert!(
                !failure
                    .context_notices
                    .iter()
                    .any(|notice| notice.contains(secret))
            );
        }
    }
}
