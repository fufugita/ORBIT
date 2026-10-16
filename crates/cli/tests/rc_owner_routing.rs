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
             [[provider.models]]\nid={SAVED_OWNER_RAW:?}\ncontext_window=65536\nmax_output_tokens=1111\n\
             [[provider]]\nname='provider_b'\nurl={:?}\nenv={env_b:?}\n\
             [[provider.models]]\nid={SAVED_OWNER_RAW:?}\ncontext_window=131072\nmax_output_tokens=733\n\
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
