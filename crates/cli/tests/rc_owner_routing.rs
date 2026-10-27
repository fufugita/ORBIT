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
        saved.bind_workspace(&self.workspace).unwrap();
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
    fn prompt_uncertain(&mut self, id: &str, text: &str) {
        let ack = self
            .send(OwnerAction::Prompt {
                request_id: id.into(),
                text: text.into(),
            })
            .unwrap();
        assert_eq!(ack.request_id.as_deref(), Some(id));
        assert!(!ack.duplicate);
        self.finished_uncertain(id);
    }
    fn finished_uncertain(&self, id: &str) -> OwnerSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = self.snapshot();
            if snapshot.state == TurnState::Interrupted
                && snapshot
                    .requests
                    .get(id)
                    .is_some_and(|record| record.state == RequestState::Unknown)
            {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "owner did not preserve explicit request uncertainty: {snapshot:?}"
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
    let snapshot = owner.finished_uncertain("cancel-routed");
    assert!(
        before.elapsed() < Duration::from_secs(2),
        "routed provider cancellation exceeded bound"
    );
    assert_eq!(
        snapshot.requests["cancel-routed"].state,
        RequestState::Unknown
    );
    let duplicate = owner
        .send(OwnerAction::Prompt {
            request_id: "cancel-routed".into(),
            text: PROMPT.into(),
        })
        .unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.state, "unknown");
    assert_eq!(f.b.calls().len(), 1);
    assert!(f.a.calls().is_empty());
    f.assert_base(&owner, SelectionOrigin::Default, low());
    assert_eq!(owner.decisions().len(), 1);
    let durable: Value = serde_json::from_slice(
        &fs::read(f.home.join("sessions/.requests/routing-owner.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(durable["requests"]["cancel-routed"]["state"], "unknown");
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
        let saved = saved.in_workspace(&f.workspace).unwrap();
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
            let saved = saved.in_workspace(&self.fixture.workspace).unwrap();
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
            let errors = result
                .events
                .iter()
                .filter(|event| event["type"] == "error")
                .filter_map(|event| event["message"].as_str())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                format!("{errors}\n{}", result.text)
                    .contains("context summary cannot fit its independently selected budget"),
                "fixture must reach the independently selected summary budget refusal for {entry:?}"
            );
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
                Some(Msg::BackendNotice(message)) => events.push(json!({"type":"notice","message":message})),
                Some(Msg::OrdinaryTurnEnded { .. }) => panic!("legacy unbound observer received a managed ordinary result"),
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
            if let Msg::BackendNotice(message) = &msg {
                events.push(json!({"type":"notice","message":message}));
            }
            assert!(
                !matches!(&msg, Msg::OrdinaryTurnEnded { .. }),
                "unbound tail received a managed result"
            );
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

#[cfg(target_os = "linux")]
mod caller_journal_activation {
    use super::*;
    use orbit_adapter::types::ChatMessage;
    use orbit_cli::context_history::{context_journal, load_compaction_source};
    use orbit_engine::{
        AccountingBaseline, AccountingKnownness, AttemptPurpose, CompactionJournal,
    };
    use orbit_hud_tui::msg::{OrdinaryEnd, OrdinaryPublication, ProjectionReason};
    use orbit_hud_tui::worker::{CancelHandle, ForegroundOperation, WorkerCommand, WorkerCtx};
    use orbit_hud_tui::{ApprovalRegistry, bus::Bus, msg::Msg};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::MetadataExt;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };

    const MAX_BODY: usize = 4 * 1024 * 1024;
    const MAX_REQUESTS: usize = 4;
    const ANSWER: &str = "actual caller answer";
    const SUMMARY: &str = "private summary of closed historical work";

    fn dispatch_isolated(exact: &str) -> bool {
        let isolated = std::env::var_os("ORBIT_ACTIVATION_ISOLATED");
        let depth = std::env::var_os("ORBIT_ACTIVATION_RUNNER_DEPTH");
        if isolated.as_deref() == Some(std::ffi::OsStr::new("1")) {
            assert_eq!(
                depth.as_deref(),
                Some(std::ffi::OsStr::new("1")),
                "invalid isolated runner depth"
            );
            return true;
        }
        assert!(
            isolated.is_none() && depth.is_none(),
            "malformed isolation dispatch controls"
        );
        let required =
            std::env::var("ORBIT_REQUIRE_CONTEXT_SESSION_ISOLATION").as_deref() == Ok("1");
        let output = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/context_session_isolation.py"
            ))
            .arg("--binary")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", exact, "--timeout", "45"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("tracked isolation runner did not start");
        assert!(
            output.stdout.len() <= 512 * 1024 && output.stderr.len() <= 64 * 1024,
            "runner receipt output bound"
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!(
                "invalid isolation runner receipt, exit {:?}",
                output.status.code()
            )
        });
        assert_eq!(report["schema"], "orbit.context-session-isolation/v1");
        assert_eq!(report["test_filter"], exact);
        let visible = json!({"schema":report["schema"],"test_filter":exact,"status":report["status"],
            "test_started":report["test_started"],"reason":report["reason"],"harness":report["harness"],
            "binary_sha256":report["binary_sha256"],"binary_metadata_and_hash_unchanged":report["binary_metadata_and_hash_unchanged"],
            "host_managed_path_metadata_unchanged":report["host_managed_path_metadata_unchanged"],"owned_fixture_removed":report["owned_fixture_removed"]});
        // Direct Write bypasses libtest's println capture. A returning NOTRUN
        // wrapper must stay visible and must not count as an inner pass.
        let line = format!("ORBIT_CONTEXT_SESSION_ISOLATION {visible}\n");
        std::io::Write::write_all(&mut std::io::stdout().lock(), line.as_bytes()).unwrap();
        match report["status"].as_str() {
            Some("TEST_PASSED") => {
                assert_eq!(output.status.code(), Some(0));
                assert_eq!(report["test_started"], true);
                assert_eq!(report["harness"]["passed"], 1);
                assert_eq!(report["harness"]["failed"], 0);
                assert_eq!(report["harness"]["ignored"], 0);
                for field in [
                    "binary_metadata_and_hash_unchanged",
                    "host_managed_path_metadata_unchanged",
                    "owned_fixture_removed",
                    "binary_postcheck_inside",
                ] {
                    assert_eq!(report[field], true);
                }
            }
            Some("NOTRUN") => {
                assert_eq!(output.status.code(), Some(77));
                assert_eq!(report["test_started"], false);
                assert!(
                    !required,
                    "NOTRUN: this infrastructure-required job needs namespace capability"
                );
            }
            Some("TEST_FAILED") | Some("INFRA_FAILURE") => {
                panic!(
                    "isolated test did not pass: {} / {} / {}",
                    report["status"], report["stdout_excerpt"], report["stderr_excerpt"]
                );
            }
            _ => panic!("unknown isolation runner status"),
        }
        false
    }

    fn require_private_system_fixture() {
        // Check descriptors/namespace identity BEFORE opening managed content,
        // creating a fixture, spawning a provider or starting any caller.
        let descriptor = |name: &str| {
            let value: u32 = std::env::var(name)
                .expect("isolated runner descriptor missing")
                .parse()
                .unwrap();
            assert!(value < 4096);
            fs::metadata(format!("/proc/self/fd/{value}")).unwrap()
        };
        let parent_mount = descriptor("ORBIT_ACTIVATION_PARENT_MOUNT_FD");
        let parent_user = descriptor("ORBIT_ACTIVATION_PARENT_USER_FD");
        let own_mount = fs::metadata("/proc/self/ns/mnt").unwrap();
        let own_user = fs::metadata("/proc/self/ns/user").unwrap();
        assert_ne!(
            (parent_mount.dev(), parent_mount.ino()),
            (own_mount.dev(), own_mount.ino())
        );
        assert_ne!(
            (parent_user.dev(), parent_user.ino()),
            (own_user.dev(), own_user.ino())
        );
        let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
        assert!(mounts.lines().any(
            |line| line.split_whitespace().nth(4) == Some("/etc") && line.contains(" - tmpfs ")
        ));
        let expected = std::env::var("ORBIT_ACTIVATION_MANAGED_MARKER").unwrap();
        assert!(expected.starts_with("ORBIT_ACTIVATION_MANAGED_") && expected.len() <= 128);
        assert!(
            expected
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        let path = Path::new("/etc/orbit/ORBIT.md");
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(metadata.len() <= 128);
        assert_eq!(fs::read(path).unwrap(), expected.as_bytes());
        assert_eq!(fs::read_dir("/etc/orbit").unwrap().count(), 1);
        let root =
            PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").expect("private root missing"));
        assert!(root.is_absolute());
        assert_eq!(root.canonicalize().unwrap(), root);
        assert!(
            root.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("oc-")
        );
        assert_eq!(fs::symlink_metadata(&root).unwrap().mode() & 0o777, 0o700);
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
        ] {
            let path = PathBuf::from(std::env::var_os(name).expect("private user path missing"));
            assert!(path.is_absolute() && path.starts_with(&root) && path != root);
            assert_eq!(path.canonicalize().unwrap(), path);
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        assert!(std::env::current_dir().unwrap().starts_with(&root));
        for name in [
            "ORBIT_HOME",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_BASE_URL",
            "OPENAI_BASE_URL",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert!(
                std::env::var_os(name).is_none(),
                "runner did not clear an inherited provider setting"
            );
        }
    }

    struct Cwd(PathBuf);
    impl Cwd {
        fn enter(path: &Path) -> Self {
            let old = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self(old)
        }
    }
    impl Drop for Cwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    struct Captured {
        target: String,
        headers: Vec<(String, String)>,
        body: Value,
    }

    struct Response {
        body: String,
        pause: bool,
    }
    impl Response {
        fn text(text: &str, reason: &str, usage: Option<Value>) -> Self {
            let mut event =
                json!({"choices":[{"index":0,"delta":{"content":text},"finish_reason":reason}]});
            if let Some(usage) = usage {
                event["usage"] = usage;
            }
            Self {
                body: format!("data: {event}\n\ndata: [DONE]\n\n"),
                pause: false,
            }
        }
        fn complete(text: &str) -> Self {
            Self::text(
                text,
                "stop",
                Some(json!({"prompt_tokens":11,"completion_tokens":7,"total_tokens":18})),
            )
        }
    }

    struct Wire {
        url: String,
        authority: String,
        requests: Arc<Mutex<Vec<Captured>>>,
        connections: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
        watchdog: Option<std::sync::mpsc::Sender<()>>,
        watchdog_thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Wire {
        fn new(responses: Vec<Response>) -> Self {
            Self::with_held_headers(responses, false)
        }
        fn with_held_headers(responses: Vec<Response>, hold_headers: bool) -> Self {
            let (watchdog, receive) = std::sync::mpsc::channel();
            let watchdog_thread = std::thread::spawn(move || {
                if matches!(
                    receive.recv_timeout(Duration::from_secs(25)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    eprintln!("compaction fixture watchdog expired");
                    std::process::exit(91);
                }
            });
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let authority = listener.local_addr().unwrap().to_string();
            let url = format!("http://{authority}/tenant/v1?scope=compaction");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = requests.clone();
            let connections = Arc::new(AtomicUsize::new(0));
            let accepted = connections.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let thread = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(20);
                let mut responses = responses.into_iter();
                loop {
                    if Instant::now() >= deadline {
                        return Err("listener deadline");
                    }
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            if accepted.fetch_add(1, Ordering::SeqCst) >= MAX_REQUESTS {
                                return Err("request bound");
                            }
                            socket
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .map_err(|_| "read timeout")?;
                            socket
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .map_err(|_| "write timeout")?;
                            let request = read_request(&mut socket)?;
                            captured.lock().map_err(|_| "capture lock")?.push(request);
                            if hold_headers {
                                while !stopping.load(Ordering::SeqCst) {
                                    if Instant::now() >= deadline {
                                        return Err("held headers deadline");
                                    }
                                    std::thread::sleep(Duration::from_millis(2));
                                }
                                continue;
                            }
                            let response = responses.next().ok_or("unexpected extra request")?;
                            let length = if response.pause {
                                response.body.len() + 1_000_000
                            } else {
                                response.body.len()
                            };
                            if let Err(error) = write!(
                                socket,
                                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{}",
                                response.body
                            ) {
                                if response.pause
                                    && matches!(
                                        error.kind(),
                                        std::io::ErrorKind::BrokenPipe
                                            | std::io::ErrorKind::ConnectionReset
                                    )
                                {
                                    continue;
                                }
                                return Err("response write");
                            }
                            socket.flush().map_err(|_| "response flush")?;
                            while response.pause && !stopping.load(Ordering::SeqCst) {
                                if Instant::now() >= deadline {
                                    return Err("paused response deadline");
                                }
                                let mut byte = [0];
                                match socket.read(&mut byte) {
                                    Ok(0) => break,
                                    Ok(_) => {}
                                    Err(e)
                                        if matches!(
                                            e.kind(),
                                            std::io::ErrorKind::WouldBlock
                                                | std::io::ErrorKind::TimedOut
                                        ) => {}
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if stopping.load(Ordering::SeqCst) {
                                return Ok(());
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => return Err("listener accept"),
                    }
                }
            });
            Self {
                url,
                authority,
                requests,
                connections,
                stop,
                thread: Some(thread),
                watchdog: Some(watchdog),
                watchdog_thread: Some(watchdog_thread),
            }
        }
        fn finish(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .expect("fixture thread panic")
                    .expect("bounded fixture failure");
            }
            assert_eq!(
                self.connections.load(Ordering::SeqCst),
                self.requests.lock().unwrap().len()
            );
        }
    }
    impl Drop for Wire {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            if let Some(done) = self.watchdog.take() {
                let _ = done.send(());
            }
            if let Some(thread) = self.watchdog_thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn read_request(socket: &mut TcpStream) -> Result<Captured, &'static str> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 16 * 1024 || Instant::now() >= deadline {
                return Err("header bound");
            }
            let mut byte = [0];
            match socket.read(&mut byte) {
                Ok(1) => header.push(byte[0]),
                Ok(_) => return Err("incomplete header"),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Err("header read"),
            }
        }
        let header = std::str::from_utf8(&header).map_err(|_| "header encoding")?;
        let mut lines = header.lines();
        let target = lines.next().ok_or("request line")?.to_owned();
        let mut headers = Vec::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or("header form")?;
            headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
        }
        let lengths: Vec<_> = headers
            .iter()
            .filter(|(name, _)| name == "content-length")
            .collect();
        if lengths.len() != 1 {
            return Err("single content length required");
        }
        let size = lengths[0]
            .1
            .parse::<usize>()
            .map_err(|_| "content length")?;
        if size == 0 || size > MAX_BODY {
            return Err("body bound");
        }
        let mut bytes = vec![0; size];
        let mut offset = 0;
        while offset < bytes.len() {
            if Instant::now() >= deadline {
                return Err("body deadline");
            }
            match socket.read(&mut bytes[offset..]) {
                Ok(0) => return Err("incomplete body"),
                Ok(count) => offset += count,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Err("body read"),
            }
        }
        let body = serde_json::from_slice(&bytes).map_err(|_| "body JSON")?;
        Ok(Captured {
            target,
            headers,
            body,
        })
    }

    fn configure(f: &Fixture, wire: &Wire, selected_input: u64) {
        let model = |id: &str, input: u64, price: u64| {
            json!({
                "id":id, "max_output_tokens":73, "context_limits":{"input_tokens":input},
                "pricing":{"input_per_million_microdollars":0,"output_per_million_microdollars":0,
                    "cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,
                    "reasoning_per_million_microdollars":0,"request_flat_microdollars":price},
                "billing":{"version":2,"input_per_million_microdollars":0,
                    "output_per_million_microdollars":0,"cache_read_per_million_microdollars":0,
                    "cache_write_per_million_microdollars":0,"request_flat_microdollars":price,
                    "reasoning_counter_basis":"included_in_output","reasoning_rate_policy":"output_rate"}
            })
        };
        let document = json!({"provider":[{"name":"provider_a","kind":"openai-compatible","url":wire.url,
            "models":[model(RAW_A,selected_input,5),model("summary-model",64_000,7)]}],
            "roles":{"main":format!("provider_a/{RAW_A}"),"compaction":"provider_a/summary-model"}});
        let parsed: orbit_cli::config::ProvidersConfig = serde_json::from_value(document).unwrap();
        write_private(
            &f.home.join("providers.toml"),
            toml::to_string(&parsed).unwrap(),
        );
    }
    fn seed(
        f: &Fixture,
        wire: &Wire,
        session: &str,
        source: &[ChatMessage],
        prefix: (u64, u64, u64),
    ) {
        let saved = SessionFile::from_chat(
            session,
            RAW_A,
            &wire.url,
            "provider_a",
            source,
            0,
            prefix.0,
            prefix.1,
            prefix.2,
        )
        .with_selection_origin(SelectionOrigin::SavedExplicit);
        let saved = saved.in_workspace(&f.workspace).unwrap();
        let lease = SessionLease::acquire(&f.home, session, "activation-seed").unwrap();
        lease.save(&saved).unwrap();
    }
    fn history() -> Vec<ChatMessage> {
        let mut messages = Vec::new();
        for index in 0..3 {
            messages.push(orbit_engine::user_message(format!(
                "{}old user {index}",
                "u".repeat(12_000)
            )));
            messages.push(orbit_engine::assistant_message(format!(
                "{}old answer {index}",
                "a".repeat(12_000)
            )));
        }
        for index in 0..2 {
            messages.push(orbit_engine::user_message(format!(
                "exact recent question {index}"
            )));
            messages.push(orbit_engine::assistant_message(format!(
                "exact recent answer {index}"
            )));
        }
        messages
    }
    fn journal(f: &Fixture, session: &str) -> Arc<dyn CompactionJournal> {
        context_journal(&f.home, session, None).unwrap()
    }
    fn saved(f: &Fixture, session: &str) -> SessionFile {
        sessions::load_session(&f.home, session).unwrap()
    }
    fn assert_known(
        f: &Fixture,
        session: &str,
        revision: u64,
        prefix: (u64, u64, u64),
        calls: u64,
    ) {
        let checkpoint = journal(f, session).accounting_checkpoint().unwrap();
        assert_eq!(checkpoint.owner_session_id, session);
        assert_eq!(checkpoint.child_id, None);
        assert_eq!(checkpoint.baseline, AccountingBaseline::UnknownLegacy);
        assert_eq!(checkpoint.revision.0, revision);
        assert_eq!(checkpoint.totals.ordinary.input_tokens, 11 * calls);
        assert_eq!(checkpoint.totals.ordinary.output_tokens, 7 * calls);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .ordinary_microcents,
            5 * calls
        );
        assert!(checkpoint.pending.is_none());
        let saved = saved(f, session);
        assert_eq!(
            (
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (
                prefix.0 + 11 * calls,
                prefix.1 + 7 * calls,
                prefix.2 + 5 * calls
            )
        );
        let watermark = saved.accounting_watermark.unwrap();
        assert_eq!(watermark.owner_session_id, session);
        assert_eq!(watermark.revision, revision);
        assert_eq!(watermark.known_ordinary_microcents, 5 * calls);
    }
    fn assert_wire(wire: &Wire, expected: usize) {
        let requests = wire.requests.lock().unwrap();
        assert_eq!(requests.len(), expected);
        for request in requests.iter() {
            assert_eq!(
                request.target,
                "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
            );
            assert_eq!(
                request
                    .headers
                    .iter()
                    .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                    .collect::<Vec<_>>(),
                [wire.authority.as_str()]
            );
            assert!(
                !request
                    .headers
                    .iter()
                    .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
            );
            assert_eq!(request.body["max_tokens"], 73);
        }
    }

    struct Tui {
        bus: Bus,
        commands: Option<mpsc::Sender<WorkerCommand>>,
        cancel: CancelHandle,
    }
    impl Tui {
        fn start(f: &Fixture, session: &str) -> Self {
            let (lease, saved) =
                SessionLease::acquire_and_load(&f.home, session, "activation-tui").unwrap();
            let (bus, sender) = Bus::new();
            let (commands, command_rx) = mpsc::channel();
            let cancel = orbit_cli::tui_worker::make_spawner_owned(
                f.turn(&saved, PermissionScope::default()),
                lease,
            )(
                WorkerCtx {
                    sender,
                    approvals: ApprovalRegistry::new(),
                    command_rx,
                },
                commands.clone(),
            )
            .unwrap();
            Self {
                bus,
                commands: Some(commands),
                cancel,
            }
        }
        fn run(
            &self,
            command: WorkerCommand,
            cancel_after_post: Option<(&Wire, usize)>,
        ) -> Vec<Value> {
            self.commands.as_ref().unwrap().send(command).unwrap();
            if let Some((wire, count)) = cancel_after_post {
                let end = Instant::now() + Duration::from_secs(5);
                while wire.requests.lock().unwrap().len() < count {
                    assert!(
                        Instant::now() < end,
                        "actual TUI POST missing before cancel"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                (self.cancel)();
            }
            let end = Instant::now() + Duration::from_secs(10);
            let mut events = Vec::new();
            let mut done = false;
            while Instant::now() < end && !done {
                match self.bus.try_recv() {
                    Some(Msg::BackendError(message)) => {
                        events.push(json!({"type":"error","message":message}))
                    }
                    Some(Msg::BackendNotice(message)) => {
                        events.push(json!({"type":"notice","message":message}))
                    }
                    Some(Msg::OrdinaryTurnEnded { .. }) => {
                        panic!("legacy unbound observer received a managed ordinary result")
                    }
                    Some(Msg::Status(text)) => events.push(json!({"type":"status","text":text})),
                    Some(Msg::PlanReady(text)) => {
                        events.push(json!({"type":"plan_ready","text":text}))
                    }
                    Some(Msg::ResponseFinished {
                        output,
                        input_tokens,
                        output_tokens,
                        cost_microcents,
                    }) => {
                        events.push(json!({"type":"finished","output":output,"input_tokens":input_tokens,"output_tokens":output_tokens,"cost_microcents":cost_microcents}));
                        done = true;
                    }
                    Some(_) => {}
                    None => std::thread::sleep(Duration::from_millis(2)),
                }
            }
            assert!(done, "actual TUI terminal response missing");
            events
        }
        fn run_bound(
            &self,
            command: WorkerCommand,
            cancel_after_post: Option<(&Wire, usize)>,
        ) -> Vec<Msg> {
            let deadline = Instant::now() + Duration::from_secs(5);
            let binding = loop {
                match self.bus.try_recv() {
                    Some(Msg::SessionProjection(view))
                        if matches!(view.reason, ProjectionReason::Initial) =>
                    {
                        break view.binding;
                    }
                    Some(Msg::BackendError(_) | Msg::BackendNotice(_)) => {
                        panic!("managed outcome fixture startup failed")
                    }
                    Some(Msg::OrdinaryTurnEnded { .. }) => {
                        panic!("ordinary result before actual Initial binding")
                    }
                    _ => {}
                }
                assert!(Instant::now() < deadline, "actual Initial binding absent");
                std::thread::sleep(Duration::from_millis(2));
            };
            let operation =
                ForegroundOperation::new(binding.clone(), command.foreground_kind().unwrap(), 1)
                    .unwrap();
            self.commands
                .as_ref()
                .unwrap()
                .send(WorkerCommand::Bound {
                    operation: operation.clone(),
                    command: Box::new(command),
                })
                .unwrap();
            if let Some((wire, count)) = cancel_after_post {
                let deadline = Instant::now() + Duration::from_secs(5);
                while wire.requests.lock().unwrap().len() < count {
                    assert!(
                        Instant::now() < deadline,
                        "actual POST missing before managed cancellation"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                (self.cancel)();
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut ends, mut finishes) = (0, 0);
            let mut events = Vec::new();
            loop {
                if let Some(message) = self.bus.try_recv() {
                    let terminal = match &message {
                        Msg::OrdinaryTurnEnded {
                            operation: observed,
                            ..
                        } => {
                            assert_eq!(observed, &operation);
                            assert_eq!(
                                (ends, finishes),
                                (0, 0),
                                "end must be unique and precede finish"
                            );
                            ends += 1;
                            false
                        }
                        Msg::ResponseFinished { .. } => {
                            assert_eq!((ends, finishes), (1, 0));
                            finishes += 1;
                            false
                        }
                        Msg::SessionProjection(view)
                            if matches!(&view.reason,
                            ProjectionReason::Operation { operation: observed } if observed == &operation) =>
                        {
                            assert_eq!(view.binding, binding);
                            assert_eq!(
                                (ends, finishes),
                                (1, 1),
                                "checked projection must follow the original finish"
                            );
                            true
                        }
                        Msg::BackendNotice(_) => {
                            panic!("unexpected publication/control notice in normal managed case")
                        }
                        _ => false,
                    };
                    events.push(message);
                    if terminal {
                        return events;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "matching managed settlement absent"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        fn wait_plan(&self) -> Value {
            let end = Instant::now() + Duration::from_secs(3);
            loop {
                match self.bus.try_recv() {
                    Some(Msg::PlanReady(text)) => return json!({"type":"plan_ready","text":text}),
                    Some(Msg::BackendNotice(_)) => {
                        panic!("unexpected notice while waiting for an unbound plan")
                    }
                    Some(Msg::OrdinaryTurnEnded { .. }) => {
                        panic!("unbound plan received a managed result")
                    }
                    _ => {}
                }
                assert!(
                    Instant::now() < end,
                    "successful plan was not offered for approval"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        fn close(mut self, f: &Fixture, session: &str) {
            self.commands.take();
            let end = Instant::now() + Duration::from_secs(3);
            loop {
                if let Ok(lease) = SessionLease::acquire(&f.home, session, "activation-closed") {
                    drop(lease);
                    while let Some(message) = self.bus.try_recv() {
                        assert!(
                            !matches!(
                                message,
                                Msg::OrdinaryTurnEnded { .. }
                                    | Msg::ResponseFinished { .. }
                                    | Msg::BackendNotice(_)
                            ),
                            "duplicate terminal or unexpected notice after worker EOF"
                        );
                    }
                    return;
                }
                assert!(Instant::now() < end, "TUI retained session lease after EOF");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
    impl Drop for Tui {
        fn drop(&mut self) {
            (self.cancel)();
            self.commands.take();
        }
    }

    #[test]
    fn actual_bound_tui_length_end_is_failed_before_finished_and_checked_projection() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_bound_tui_length_end_is_failed_before_finished_and_checked_projection",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::text(
            "retained useful partial",
            "length",
            Some(json!({"prompt_tokens":11,"completion_tokens":7,"total_tokens":18})),
        )]);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (10, 20, 30));
        let tui = Tui::start(&f, SESSION);
        let events = tui.run_bound(
            WorkerCommand::Prompt("bounded partial request".into()),
            None,
        );
        let ends = events
            .iter()
            .filter_map(|message| match message {
                Msg::OrdinaryTurnEnded {
                    end, publication, ..
                } => Some((end, publication)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            matches!(ends.as_slice(), [(OrdinaryEnd::Failed(reason), OrdinaryPublication::Saved)] if !reason.is_empty())
        );
        assert!(
            !events
                .iter()
                .any(|message| matches!(message, Msg::BackendError(_))),
            "length must be classified from the actual typed end without callback Error"
        );
        let retained = saved(&f, SESSION);
        assert_eq!(retained.turns, 1);
        assert_eq!(retained.transcript.len(), 2);
        assert_eq!(retained.transcript[0].content, "bounded partial request");
        assert_eq!(retained.transcript[1].content, "retained useful partial");
        assert_known(&f, SESSION, 2, (10, 20, 30), 1);
        assert!(
            events
                .iter()
                .any(|message| matches!(message, Msg::ResponseFinished {
            input_tokens, output_tokens, cost_microcents, ..
        } if (*input_tokens, *output_tokens, *cost_microcents) ==
             (retained.input_tokens, retained.output_tokens, retained.cost_microcents)))
        );
        tui.close(&f, SESSION);
        wire.finish();
        assert_wire(&wire, 1);
    }

    #[test]
    fn actual_bound_tui_completed_and_cancelled_ends_preserve_saved_facts() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_bound_tui_completed_and_cancelled_ends_preserve_saved_facts",
        ) {
            return;
        }
        require_private_system_fixture();
        for mode in ["prompt", "plan", "cancel"] {
            let f = Fixture::new();
            let _cwd = Cwd::enter(&f.workspace);
            let mut wire = if mode == "cancel" {
                Wire::with_held_headers(vec![], true)
            } else {
                Wire::new(vec![Response::complete("bounded successful result")])
            };
            configure(&f, &wire, 64_000);
            seed(&f, &wire, SESSION, &[], (0, 0, 0));
            let tui = Tui::start(&f, SESSION);
            let command = if mode == "plan" {
                WorkerCommand::PlanPrompt("bounded ordinary plan".into())
            } else {
                WorkerCommand::Prompt("bounded ordinary prompt".into())
            };
            let events = tui.run_bound(command, (mode == "cancel").then_some((&wire, 1)));
            let ends = events
                .iter()
                .filter_map(|message| match message {
                    Msg::OrdinaryTurnEnded {
                        end, publication, ..
                    } => Some((end, publication)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if mode == "cancel" {
                assert!(matches!(
                    ends.as_slice(),
                    [(
                        OrdinaryEnd::Cancelled,
                        OrdinaryPublication::BlockedOrUncertain
                    )]
                ));
                let checkpoint = journal(&f, SESSION).accounting_checkpoint().unwrap();
                assert!(checkpoint.pending.as_ref().unwrap().uncertain);
                assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Uncertain);
                assert_eq!(
                    saved(&f, SESSION)
                        .accounting_watermark
                        .unwrap()
                        .full_cost_status,
                    orbit_cli::session_accounting::FullCostStatus::Uncertain
                );
                assert!(
                    !events
                        .iter()
                        .any(|message| matches!(message, Msg::PlanReady(_)))
                );
            } else {
                assert!(matches!(
                    ends.as_slice(),
                    [(OrdinaryEnd::Completed, OrdinaryPublication::Saved)]
                ));
                assert_known(&f, SESSION, 2, (0, 0, 0), 1);
                assert_eq!(
                    saved(&f, SESSION).transcript.last().unwrap().content,
                    "bounded successful result"
                );
                assert_eq!(
                    events
                        .iter()
                        .filter(|message| matches!(message, Msg::PlanReady(_)))
                        .count(),
                    usize::from(mode == "plan")
                );
            }
            tui.close(&f, SESSION);
            wire.finish();
            assert_wire(&wire, 1);
        }
    }

    #[test]
    fn actual_tui_prompt_journals_work_and_restart_projects_the_known_charge_once() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_tui_prompt_journals_work_and_restart_projects_the_known_charge_once",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![
            Response::complete(ANSWER),
            Response::complete("second answer"),
        ]);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (10, 20, 30));
        let tui = Tui::start(&f, SESSION);
        let events = tui.run(WorkerCommand::Prompt("first TUI intent".into()), None);
        assert_eq!(
            events
                .iter()
                .filter(|event| event["type"] == "finished")
                .count(),
            1
        );
        assert_known(&f, SESSION, 2, (10, 20, 30), 1);
        tui.close(&f, SESSION);
        let first = saved(&f, SESSION).transcript;
        let tui = Tui::start(&f, SESSION);
        tui.run(WorkerCommand::Prompt("second TUI intent".into()), None);
        tui.close(&f, SESSION);
        assert_known(&f, SESSION, 4, (10, 20, 30), 2);
        assert!(saved(&f, SESSION).transcript.starts_with(&first));
        wire.finish();
        assert_wire(&wire, 2);
    }

    #[test]
    fn actual_tui_successful_plan_is_billed_and_saved_before_any_approval() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_tui_successful_plan_is_billed_and_saved_before_any_approval",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        const PLAN: &str = "1. Inspect the synthetic file.\nPLAN READY";
        const PROMPT: &str = "prepare a synthetic plan";
        let mut wire = Wire::new(vec![Response::complete(PLAN)]);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (0, 0, 0));
        let tui = Tui::start(&f, SESSION);
        let events = tui.run(WorkerCommand::PlanPrompt(PROMPT.into()), None);
        let plan = events
            .iter()
            .find(|event| event["type"] == "plan_ready")
            .cloned()
            .unwrap_or_else(|| tui.wait_plan());
        assert_eq!(plan["text"], PLAN);
        // No approval/execution command has been sent, and the worker still owns
        // the session. Provider billing and its watermark must already be durable.
        assert_known(&f, SESSION, 2, (0, 0, 0), 1);
        let observed = saved(&f, SESSION);
        assert_eq!(
            observed
                .transcript
                .iter()
                .filter(
                    |message| message.role == orbit_adapter::types::ChatRole::User
                        && message.content == PROMPT
                )
                .count(),
            1
        );
        assert_eq!(
            observed
                .transcript
                .iter()
                .filter(
                    |message| message.role == orbit_adapter::types::ChatRole::Assistant
                        && message.content == PLAN
                )
                .count(),
            1
        );
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        tui.close(&f, SESSION);
        wire.finish();
        assert_wire(&wire, 1);
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
    }

    #[test]
    fn actual_tui_paid_summary_then_failed_ordinary_retains_cost_and_halts_replay() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_tui_paid_summary_then_failed_ordinary_retains_cost_and_halts_replay",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let malformed = Response {
            body: "data: {invalid-json}\n\n".into(),
            pause: false,
        };
        let mut wire = Wire::new(vec![
            Response::complete(SUMMARY),
            malformed,
            Response::complete("must not be called"),
        ]);
        configure(&f, &wire, 10_000);
        let original = history();
        seed(&f, &wire, SESSION, &original, (0, 0, 0));
        let tui = Tui::start(&f, SESSION);
        let events = tui.run(
            WorkerCommand::Prompt("retain this failed current intent".into()),
            None,
        );
        assert!(!events.iter().any(|event| event["type"] == "plan_ready"));
        let checkpoint = journal(&f, SESSION).accounting_checkpoint().unwrap();
        assert_eq!(checkpoint.revision.0, 4);
        assert_eq!(checkpoint.totals.housekeeping.input_tokens, 11);
        assert_eq!(checkpoint.totals.housekeeping.output_tokens, 7);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .housekeeping_microcents,
            7
        );
        assert_eq!(
            checkpoint.pending.as_ref().unwrap().intent.purpose,
            AttemptPurpose::Ordinary
        );
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        let durable = saved(&f, SESSION);
        assert_eq!(
            (
                durable.input_tokens,
                durable.output_tokens,
                durable.cost_microcents
            ),
            (11, 7, 7)
        );
        assert_eq!(
            durable
                .accounting_watermark
                .as_ref()
                .unwrap()
                .full_cost_status,
            orbit_cli::session_accounting::FullCostStatus::Uncertain
        );
        assert_eq!(
            durable
                .transcript
                .iter()
                .filter(|message| message.content == "retain this failed current intent")
                .count(),
            1
        );
        let archive_dir = f
            .home
            .join("context-history")
            .join(SESSION)
            .join("archives");
        let files: Vec<_> = fs::read_dir(archive_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1);
        let record = files[0].file_stem().unwrap().to_str().unwrap();
        let mut archived = original;
        archived.push(orbit_engine::user_message(
            "retain this failed current intent",
        ));
        assert_eq!(
            load_compaction_source(&f.home, SESSION, None, record).unwrap(),
            archived
        );
        let bytes = fs::read(
            f.home
                .join("context-history")
                .join(SESSION)
                .join("accounting.json"),
        )
        .unwrap();
        tui.run(
            WorkerCommand::Prompt("new intent cannot replay uncertain work".into()),
            None,
        );
        assert_eq!(
            fs::read(
                f.home
                    .join("context-history")
                    .join(SESSION)
                    .join("accounting.json")
            )
            .unwrap(),
            bytes
        );
        tui.close(&f, SESSION);
        wire.finish();
        assert_wire(&wire, 2);
        let calls = wire.requests.lock().unwrap();
        assert_eq!(calls[0].body["model"], "summary-model");
        assert_eq!(calls[1].body["model"], RAW_A);
    }

    #[test]
    fn actual_tui_cancel_after_accepted_post_is_uncertain_and_refuses_next_turn() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_tui_cancel_after_accepted_post_is_uncertain_and_refuses_next_turn",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::with_held_headers(vec![], true);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (0, 0, 0));
        let tui = Tui::start(&f, SESSION);
        tui.run(
            WorkerCommand::Prompt("cancel this actual TUI request".into()),
            Some((&wire, 1)),
        );
        let checkpoint = journal(&f, SESSION).accounting_checkpoint().unwrap();
        assert_eq!(checkpoint.revision.0, 2);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Uncertain);
        let saved = saved(&f, SESSION);
        assert_eq!(saved.cost_microcents, 0);
        assert_eq!(
            saved.accounting_watermark.unwrap().full_cost_status,
            orbit_cli::session_accounting::FullCostStatus::Uncertain
        );
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(|message| message.content == "cancel this actual TUI request")
                .count(),
            1
        );
        tui.run(
            WorkerCommand::Prompt("no automatic retry after cancel".into()),
            None,
        );
        assert_eq!(
            journal(&f, SESSION).accounting_checkpoint().unwrap(),
            checkpoint
        );
        tui.close(&f, SESSION);
        wire.finish();
        assert_wire(&wire, 1);
    }

    #[test]
    fn actual_owner_journals_qualified_work_and_controller_replacement_does_not_rebill() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_owner_journals_qualified_work_and_controller_replacement_does_not_rebill",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let mut wire = Wire::new(vec![
            Response::complete(ANSWER),
            Response::complete("after restart"),
        ]);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (10, 20, 30));
        let mut owner = f.restart();
        owner.prompt("owner-first", "owner first intent");
        assert_known(&f, SESSION, 2, (10, 20, 30), 1);
        owner.controller.take();
        owner.controller = Some(owner.handle.claim_controller().unwrap());
        let duplicate = owner
            .send(OwnerAction::Prompt {
                request_id: "owner-first".into(),
                text: "owner first intent".into(),
            })
            .unwrap();
        assert!(duplicate.duplicate);
        assert_known(&f, SESSION, 2, (10, 20, 30), 1);
        owner.shutdown();
        let mut owner = f.restart();
        owner.prompt("owner-second", "owner second intent");
        assert_known(&f, SESSION, 4, (10, 20, 30), 2);
        owner.shutdown();
        wire.finish();
        assert_wire(&wire, 2);
    }

    #[test]
    fn actual_owner_cancelled_wire_attempt_is_durable_and_cannot_be_resubmitted() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_owner_cancelled_wire_attempt_is_durable_and_cannot_be_resubmitted",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let mut wire = Wire::with_held_headers(vec![], true);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (0, 0, 0));
        let mut owner = f.restart();
        owner
            .send(OwnerAction::Prompt {
                request_id: "owner-cancel".into(),
                text: "owner cancellation intent".into(),
            })
            .unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while wire.requests.lock().unwrap().is_empty() {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(2));
        }
        owner.send(OwnerAction::Cancel).unwrap();
        owner.finished_uncertain("owner-cancel");
        let checkpoint = journal(&f, SESSION).accounting_checkpoint().unwrap();
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        let durable = saved(&f, SESSION);
        assert_eq!(
            durable.accounting_watermark.unwrap().full_cost_status,
            orbit_cli::session_accounting::FullCostStatus::Uncertain
        );
        assert_eq!(
            durable
                .transcript
                .iter()
                .filter(|message| message.content == "owner cancellation intent")
                .count(),
            1
        );
        let before_refusal = saved(&f, SESSION);
        let previous_requests = owner.snapshot().requests;
        let accounting_path = f
            .home
            .join("context-history")
            .join(SESSION)
            .join("accounting.json");
        let accounting_bytes = fs::read(&accounting_path).unwrap();
        let egress_before = f.egress();
        let assert_pending_refusal = |error: OwnerError| match error {
            OwnerError::Accounting(
                orbit_cli::session_accounting::AccountingError::InvalidState(reason),
            ) => assert_eq!(
                reason,
                "a pending uncertain request requires explicit inspection before admission",
            ),
            other => panic!("wrong pending admission refusal: {other:?}"),
        };
        let refusal = owner
            .send(OwnerAction::Prompt {
                request_id: "owner-after-cancel".into(),
                text: "refuse next request".into(),
            })
            .expect_err("pending accounting must refuse fresh provider admission");
        assert_pending_refusal(refusal);
        let terminal = owner.finished_uncertain("owner-after-cancel");
        assert_eq!(terminal.requests.len(), previous_requests.len() + 1);
        for (id, prior) in &previous_requests {
            let retained = &terminal.requests[id];
            assert_eq!(retained.payload_digest, prior.payload_digest);
            assert_eq!(retained.state, prior.state);
        }
        assert_eq!(
            terminal.requests["owner-cancel"].state,
            RequestState::Unknown
        );
        let after_refusal = saved(&f, SESSION);
        let mut expected_history = before_refusal.transcript.clone();
        expected_history.push(orbit_engine::user_message("refuse next request"));
        assert_eq!(after_refusal.transcript, expected_history);
        assert_eq!(
            after_refusal.turns,
            before_refusal.turns.checked_add(1).unwrap()
        );
        assert_eq!(
            (
                after_refusal.input_tokens,
                after_refusal.output_tokens,
                after_refusal.cost_microcents
            ),
            (
                before_refusal.input_tokens,
                before_refusal.output_tokens,
                before_refusal.cost_microcents
            ),
        );
        assert_eq!(
            after_refusal.accounting_watermark,
            before_refusal.accounting_watermark
        );
        assert_eq!(after_refusal.model, before_refusal.model);
        assert_eq!(after_refusal.provider, before_refusal.provider);
        assert_eq!(after_refusal.gate, before_refusal.gate);
        assert_eq!(after_refusal.effort, before_refusal.effort);
        assert_eq!(
            after_refusal.selection_origin,
            before_refusal.selection_origin
        );
        assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
        assert_eq!(f.egress(), egress_before);
        let session_path = f.home.join("sessions").join(format!("{SESSION}.json"));
        let refused_session_bytes = fs::read(&session_path).unwrap();
        let duplicate = owner
            .send(OwnerAction::Prompt {
                request_id: "owner-after-cancel".into(),
                text: "refuse next request".into(),
            })
            .unwrap();
        assert_eq!(duplicate.request_id.as_deref(), Some("owner-after-cancel"));
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.state, "unknown");
        assert_eq!(fs::read(&session_path).unwrap(), refused_session_bytes);
        assert_eq!(
            journal(&f, SESSION).accounting_checkpoint().unwrap(),
            checkpoint
        );
        owner.shutdown();
        let requests_path = f
            .home
            .join("sessions/.requests")
            .join(format!("{SESSION}.json"));
        let requests_bytes = fs::read(&requests_path).unwrap();
        assert_eq!(fs::read(&session_path).unwrap(), refused_session_bytes);
        let (lease, restored) =
            SessionLease::acquire_and_load(&f.home, SESSION, "pending-owner-restart-refusal")
                .unwrap();
        let config = OwnerConfig::new(
            f.turn(&restored, PermissionScope::default()),
            f.workspace.clone(),
        );
        let refusal = match OwnerRuntime::start(config, lease) {
            Err(error) => error,
            Ok(runtime) => {
                runtime.shutdown().unwrap();
                panic!("pending accounting unexpectedly admitted a restarted owner");
            }
        };
        assert_pending_refusal(refusal);
        let released =
            SessionLease::acquire(&f.home, SESSION, "pending-owner-restart-released").unwrap();
        drop(released);
        assert_eq!(fs::read(&session_path).unwrap(), refused_session_bytes);
        assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
        assert_eq!(fs::read(&requests_path).unwrap(), requests_bytes);
        assert_eq!(
            journal(&f, SESSION).accounting_checkpoint().unwrap(),
            checkpoint
        );
        assert_eq!(f.egress(), egress_before);
        wire.finish();
        assert_wire(&wire, 1);
    }

    #[test]
    fn actual_owner_failed_second_attempt_preserves_the_paid_prefix_and_pending_admission_halt() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_owner_failed_second_attempt_preserves_the_paid_prefix_and_pending_admission_halt",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let malformed = Response {
            body: "data: {invalid-json}\n\n".into(),
            pause: false,
        };
        let mut wire = Wire::new(vec![
            Response::complete(ANSWER),
            malformed,
            Response::complete("must not retry"),
        ]);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (0, 0, 0));
        let mut owner = f.restart();
        owner.prompt("owner-paid-prefix", "first paid owner intent");
        assert_known(&f, SESSION, 2, (0, 0, 0), 1);
        owner.prompt_uncertain("owner-failed", "preserve this failed owner intent");
        let checkpoint = journal(&f, SESSION).accounting_checkpoint().unwrap();
        assert_eq!(checkpoint.revision.0, 4);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .ordinary_microcents,
            5
        );
        assert_eq!(
            (
                checkpoint.totals.ordinary.input_tokens,
                checkpoint.totals.ordinary.output_tokens
            ),
            (11, 7)
        );
        let durable = saved(&f, SESSION);
        assert_eq!(
            (
                durable.input_tokens,
                durable.output_tokens,
                durable.cost_microcents
            ),
            (11, 7, 5)
        );
        assert_eq!(
            durable.accounting_watermark.unwrap().full_cost_status,
            orbit_cli::session_accounting::FullCostStatus::Uncertain
        );
        assert_eq!(
            durable
                .transcript
                .iter()
                .filter(|message| message.content == "preserve this failed owner intent")
                .count(),
            1
        );
        let before_refusal = saved(&f, SESSION);
        let previous_requests = owner.snapshot().requests;
        let accounting_path = f
            .home
            .join("context-history")
            .join(SESSION)
            .join("accounting.json");
        let accounting_bytes = fs::read(&accounting_path).unwrap();
        let egress_before = f.egress();
        let assert_pending_refusal = |error: OwnerError| match error {
            OwnerError::Accounting(
                orbit_cli::session_accounting::AccountingError::InvalidState(reason),
            ) => assert_eq!(
                reason,
                "a pending uncertain request requires explicit inspection before admission",
            ),
            other => panic!("wrong pending admission refusal: {other:?}"),
        };
        let refusal = owner
            .send(OwnerAction::Prompt {
                request_id: "owner-blocked-after-failure".into(),
                text: "no new request after uncertainty".into(),
            })
            .expect_err("pending accounting must refuse fresh provider admission");
        assert_pending_refusal(refusal);
        let terminal = owner.finished_uncertain("owner-blocked-after-failure");
        assert_eq!(terminal.requests.len(), previous_requests.len() + 1);
        for (id, prior) in &previous_requests {
            let retained = &terminal.requests[id];
            assert_eq!(retained.payload_digest, prior.payload_digest);
            assert_eq!(retained.state, prior.state);
        }
        assert_eq!(
            terminal.requests["owner-failed"].state,
            RequestState::Unknown
        );
        let after_refusal = saved(&f, SESSION);
        let mut expected_history = before_refusal.transcript.clone();
        expected_history.push(orbit_engine::user_message(
            "no new request after uncertainty",
        ));
        assert_eq!(after_refusal.transcript, expected_history);
        assert_eq!(
            after_refusal.turns,
            before_refusal.turns.checked_add(1).unwrap()
        );
        assert_eq!(
            (
                after_refusal.input_tokens,
                after_refusal.output_tokens,
                after_refusal.cost_microcents
            ),
            (
                before_refusal.input_tokens,
                before_refusal.output_tokens,
                before_refusal.cost_microcents
            ),
        );
        assert_eq!(
            after_refusal.accounting_watermark,
            before_refusal.accounting_watermark
        );
        assert_eq!(after_refusal.model, before_refusal.model);
        assert_eq!(after_refusal.provider, before_refusal.provider);
        assert_eq!(after_refusal.gate, before_refusal.gate);
        assert_eq!(after_refusal.effort, before_refusal.effort);
        assert_eq!(
            after_refusal.selection_origin,
            before_refusal.selection_origin
        );
        assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
        assert_eq!(f.egress(), egress_before);
        let session_path = f.home.join("sessions").join(format!("{SESSION}.json"));
        let refused_session_bytes = fs::read(&session_path).unwrap();
        let duplicate = owner
            .send(OwnerAction::Prompt {
                request_id: "owner-blocked-after-failure".into(),
                text: "no new request after uncertainty".into(),
            })
            .unwrap();
        assert_eq!(
            duplicate.request_id.as_deref(),
            Some("owner-blocked-after-failure")
        );
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.state, "unknown");
        assert_eq!(fs::read(&session_path).unwrap(), refused_session_bytes);
        assert_eq!(
            journal(&f, SESSION).accounting_checkpoint().unwrap(),
            checkpoint
        );
        owner.shutdown();
        let requests_path = f
            .home
            .join("sessions/.requests")
            .join(format!("{SESSION}.json"));
        let requests_bytes = fs::read(&requests_path).unwrap();
        assert_eq!(fs::read(&session_path).unwrap(), refused_session_bytes);
        let (lease, restored) =
            SessionLease::acquire_and_load(&f.home, SESSION, "pending-owner-restart-refusal")
                .unwrap();
        let config = OwnerConfig::new(
            f.turn(&restored, PermissionScope::default()),
            f.workspace.clone(),
        );
        let refusal = match OwnerRuntime::start(config, lease) {
            Err(error) => error,
            Ok(runtime) => {
                runtime.shutdown().unwrap();
                panic!("pending accounting unexpectedly admitted a restarted owner");
            }
        };
        assert_pending_refusal(refusal);
        let released =
            SessionLease::acquire(&f.home, SESSION, "pending-owner-restart-released").unwrap();
        drop(released);
        assert_eq!(fs::read(&session_path).unwrap(), refused_session_bytes);
        assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
        assert_eq!(fs::read(&requests_path).unwrap(), requests_bytes);
        assert_eq!(
            journal(&f, SESSION).accounting_checkpoint().unwrap(),
            checkpoint
        );
        assert_eq!(f.egress(), egress_before);
        wire.finish();
        assert_wire(&wire, 2);
    }

    #[test]
    fn actual_owner_session_switch_preserves_independent_anchors_and_returned_totals() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_owner_session_switch_preserves_independent_anchors_and_returned_totals",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let mut wire = Wire::new(vec![
            Response::complete("first"),
            Response::complete("other"),
            Response::complete("back"),
        ]);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (10, 20, 30));
        seed(&f, &wire, "switch-target", &[], (100, 200, 300));
        let mut owner = f.restart();
        owner.prompt("switch-first", "first owned intent");
        assert_known(&f, SESSION, 2, (10, 20, 30), 1);
        owner
            .send(OwnerAction::Resume {
                session_id: "switch-target".into(),
            })
            .unwrap();
        assert_eq!(owner.snapshot().session_id, "switch-target");
        owner.prompt("switch-other", "other owned intent");
        assert_known(&f, "switch-target", 2, (100, 200, 300), 1);
        owner
            .send(OwnerAction::Resume {
                session_id: SESSION.into(),
            })
            .unwrap();
        assert_eq!(owner.snapshot().session_id, SESSION);
        owner.prompt("switch-back", "back to first owner");
        assert_known(&f, SESSION, 4, (10, 20, 30), 2);
        assert_known(&f, "switch-target", 2, (100, 200, 300), 1);
        owner.shutdown();
        wire.finish();
        assert_wire(&wire, 3);
    }

    #[test]
    fn actual_tui_session_switch_preserves_each_namespace_and_legacy_prefix() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_tui_session_switch_preserves_each_namespace_and_legacy_prefix",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![
            Response::complete("first"),
            Response::complete("other"),
            Response::complete("back"),
        ]);
        configure(&f, &wire, 64_000);
        seed(&f, &wire, SESSION, &[], (10, 20, 30));
        seed(&f, &wire, "switch-target", &[], (100, 200, 300));
        let tui = Tui::start(&f, SESSION);
        tui.run(WorkerCommand::Prompt("first TUI owned intent".into()), None);
        assert_known(&f, SESSION, 2, (10, 20, 30), 1);
        tui.commands
            .as_ref()
            .unwrap()
            .send(WorkerCommand::ResumeSession("switch-target".into()))
            .unwrap();
        tui.run(WorkerCommand::Prompt("other TUI intent".into()), None);
        assert_known(&f, "switch-target", 2, (100, 200, 300), 1);
        tui.commands
            .as_ref()
            .unwrap()
            .send(WorkerCommand::ResumeSession(SESSION.into()))
            .unwrap();
        tui.run(WorkerCommand::Prompt("back TUI intent".into()), None);
        assert_known(&f, SESSION, 4, (10, 20, 30), 2);
        assert_known(&f, "switch-target", 2, (100, 200, 300), 1);
        tui.close(&f, SESSION);
        wire.finish();
        assert_wire(&wire, 3);
    }

    #[test]
    fn actual_tui_prompt_turn_counter_overflow_retains_intent_without_dispatch() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_tui_prompt_turn_counter_overflow_retains_intent_without_dispatch",
        ) {
            return;
        }
        require_private_system_fixture();
        const INTENT: &str = "exact plain prompt intent at exhausted turn counter";
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::complete(
            "a refused counter must not call this provider",
        )]);
        configure(&f, &wire, 64_000);
        let prior = vec![
            orbit_engine::user_message("previous durable question"),
            orbit_engine::assistant_message("previous durable answer"),
        ];
        seed(&f, &wire, SESSION, &prior, (10, 20, 30));
        let before = {
            let lease = SessionLease::acquire(&f.home, SESSION, "overflow-seed").unwrap();
            let mut original = lease.load().unwrap();
            original.turns = u64::MAX;
            lease.save(&original).unwrap();
            let adapter = orbit_cli::session_accounting::prepare_root(
                &lease,
                &mut original,
                orbit_cli::session_accounting::RootOrigin::RestoredOrLegacy,
            )
            .unwrap();
            adapter.namespace().checkpoint().unwrap()
        };
        assert!(before.pending.is_none());
        assert_eq!(before.revision.0, 0);
        let mut tui = Tui::start(&f, SESSION);
        let events = tui.run(WorkerCommand::Prompt(INTENT.into()), None);
        // Wait for actual worker EOF before checking the complete terminal bus,
        // so a late empty PlanReady or duplicate finish cannot escape detection.
        tui.commands.take();
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(lease) = SessionLease::acquire(&f.home, SESSION, "overflow-closed") {
                drop(lease);
                break;
            }
            assert!(
                Instant::now() < end,
                "overflow refusal retained the worker lease"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let mut finished = events
            .iter()
            .filter(|event| event["type"] == "finished")
            .count();
        let mut errors = events
            .iter()
            .filter(|event| event["type"] == "error")
            .map(|event| event["message"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let mut plans = events
            .iter()
            .filter(|event| event["type"] == "plan_ready")
            .count();
        while let Some(message) = tui.bus.try_recv() {
            match message {
                Msg::ResponseFinished { .. } => finished += 1,
                Msg::BackendError(message) => errors.push(message),
                Msg::BackendNotice(_) => {
                    panic!("overflow refusal emitted a storage/control notice")
                }
                Msg::OrdinaryTurnEnded { .. } => {
                    panic!("unbound overflow received a managed result")
                }
                Msg::PlanReady(_) => plans += 1,
                _ => {}
            }
        }
        drop(tui);
        wire.finish();
        assert_wire(&wire, 0);
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        assert_eq!(finished, 1);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("session turn count overflows"));
        assert_eq!(plans, 0);
        let retained = saved(&f, SESSION);
        assert_eq!(retained.turns, u64::MAX);
        assert_eq!(
            (
                retained.input_tokens,
                retained.output_tokens,
                retained.cost_microcents
            ),
            (10, 20, 30)
        );
        assert_eq!(
            journal(&f, SESSION).accounting_checkpoint().unwrap(),
            before
        );
        let mut expected = prior;
        expected.push(orbit_engine::user_message(INTENT));
        assert_eq!(retained.transcript, expected);
        assert_eq!(
            retained
                .transcript
                .iter()
                .filter(|message| message.content == INTENT)
                .count(),
            1
        );
    }

    #[test]
    fn actual_tui_plan_prompt_turn_counter_overflow_retains_intent_without_dispatch() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_tui_plan_prompt_turn_counter_overflow_retains_intent_without_dispatch",
        ) {
            return;
        }
        require_private_system_fixture();
        const INTENT: &str = "exact plain plan_prompt intent at exhausted turn counter";
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::complete(
            "a refused counter must not call this provider",
        )]);
        configure(&f, &wire, 64_000);
        let prior = vec![
            orbit_engine::user_message("previous durable question"),
            orbit_engine::assistant_message("previous durable answer"),
        ];
        seed(&f, &wire, SESSION, &prior, (10, 20, 30));
        let before = {
            let lease = SessionLease::acquire(&f.home, SESSION, "overflow-seed").unwrap();
            let mut original = lease.load().unwrap();
            original.turns = u64::MAX;
            lease.save(&original).unwrap();
            let adapter = orbit_cli::session_accounting::prepare_root(
                &lease,
                &mut original,
                orbit_cli::session_accounting::RootOrigin::RestoredOrLegacy,
            )
            .unwrap();
            adapter.namespace().checkpoint().unwrap()
        };
        assert!(before.pending.is_none());
        assert_eq!(before.revision.0, 0);
        let mut tui = Tui::start(&f, SESSION);
        let events = tui.run(WorkerCommand::PlanPrompt(INTENT.into()), None);
        // Wait for actual worker EOF before checking the complete terminal bus,
        // so a late empty PlanReady or duplicate finish cannot escape detection.
        tui.commands.take();
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(lease) = SessionLease::acquire(&f.home, SESSION, "overflow-closed") {
                drop(lease);
                break;
            }
            assert!(
                Instant::now() < end,
                "overflow refusal retained the worker lease"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let mut finished = events
            .iter()
            .filter(|event| event["type"] == "finished")
            .count();
        let mut errors = events
            .iter()
            .filter(|event| event["type"] == "error")
            .map(|event| event["message"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let mut plans = events
            .iter()
            .filter(|event| event["type"] == "plan_ready")
            .count();
        while let Some(message) = tui.bus.try_recv() {
            match message {
                Msg::ResponseFinished { .. } => finished += 1,
                Msg::BackendError(message) => errors.push(message),
                Msg::BackendNotice(_) => {
                    panic!("overflow refusal emitted a storage/control notice")
                }
                Msg::OrdinaryTurnEnded { .. } => {
                    panic!("unbound overflow received a managed result")
                }
                Msg::PlanReady(_) => plans += 1,
                _ => {}
            }
        }
        drop(tui);
        wire.finish();
        assert_wire(&wire, 0);
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        assert_eq!(finished, 1);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("session turn count overflows"));
        assert_eq!(plans, 0);
        let retained = saved(&f, SESSION);
        assert_eq!(retained.turns, u64::MAX);
        assert_eq!(
            (
                retained.input_tokens,
                retained.output_tokens,
                retained.cost_microcents
            ),
            (10, 20, 30)
        );
        assert_eq!(
            journal(&f, SESSION).accounting_checkpoint().unwrap(),
            before
        );
        let mut expected = prior;
        expected.push(orbit_engine::user_message(INTENT));
        assert_eq!(retained.transcript, expected);
        assert_eq!(
            retained
                .transcript
                .iter()
                .filter(|message| message.content == INTENT)
                .count(),
            1
        );
    }
    struct CliResult {
        status: std::process::ExitStatus,
        stdout: String,
        stderr: String,
    }
    impl CliResult {
        fn json(&self) -> Value {
            let values: Vec<Value> = self
                .stdout
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .filter(|value: &Value| value["schema"] == "orbit.cli/v1")
                .collect();
            assert_eq!(
                values.len(),
                1,
                "one invocation summary is required: {}",
                self.stderr
            );
            values.into_iter().next().unwrap()
        }
    }
    struct CliProcess(std::process::Child);
    impl Drop for CliProcess {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    fn accounting_cli(
        f: &Fixture,
        args: &[&str],
        input: &str,
        interrupt: Option<(&Wire, usize)>,
    ) -> CliResult {
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        const CAPTURE_LIMIT: u64 = 2 * 1024 * 1024;
        let id = ulid::Ulid::new().to_string();
        let stdin = f.root.join(format!("{id}.stdin"));
        let stdout = f.root.join(format!("{id}.stdout"));
        let stderr = f.root.join(format!("{id}.stderr"));
        for (path, bytes) in [
            (&stdin, input.as_bytes()),
            (&stdout, b"".as_slice()),
            (&stderr, b"".as_slice()),
        ] {
            write_private(path, bytes);
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_orbit"));
        command
            .args(args)
            .arg("--home")
            .arg(&f.home)
            .arg("--bare")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .current_dir(&f.workspace)
            .stdin(fs::File::open(&stdin).unwrap())
            .stdout(fs::File::options().write(true).open(&stdout).unwrap())
            .stderr(fs::File::options().write(true).open(&stderr).unwrap())
            .process_group(0);
        for name in [
            "HOME",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
        ] {
            command.env(name, std::env::var_os(name).unwrap());
        }
        let mut child = CliProcess(command.spawn().unwrap());
        if let Some((wire, count)) = interrupt {
            let end = Instant::now() + Duration::from_secs(5);
            while wire.requests.lock().unwrap().len() < count {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "CLI exited before the intended actual POST"
                );
                assert!(
                    Instant::now() < end,
                    "no actual POST at the interrupt boundary"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(child.0.try_wait().unwrap().is_none());
            assert!(
                Command::new("/bin/kill")
                    .args(["-KILL", &child.0.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let end = Instant::now() + Duration::from_secs(15);
        let status = loop {
            for path in [&stdout, &stderr] {
                assert!(
                    fs::metadata(path).unwrap().len() <= CAPTURE_LIMIT,
                    "CLI capture bound"
                );
            }
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < end, "bounded CLI process did not finish");
            std::thread::sleep(Duration::from_millis(2));
        };
        let lengths = [
            fs::metadata(&stdout).unwrap().len(),
            fs::metadata(&stderr).unwrap().len(),
        ];
        assert!(
            lengths.iter().all(|length| *length <= CAPTURE_LIMIT),
            "final CLI capture bound"
        );
        assert!(
            lengths[0].checked_add(lengths[1]).unwrap() <= 2 * CAPTURE_LIMIT,
            "final aggregate CLI capture bound"
        );
        let read_capture = |path: &std::path::Path| {
            let mut bytes = Vec::new();
            fs::File::open(path)
                .unwrap()
                .take(CAPTURE_LIMIT + 1)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(
                bytes.len() as u64 <= CAPTURE_LIMIT,
                "bounded final CLI capture read overflow"
            );
            String::from_utf8(bytes).expect("CLI capture must be UTF-8")
        };
        let stdout = read_capture(&stdout);
        let stderr = read_capture(&stderr);
        assert!(
            stdout.len().checked_add(stderr.len()).unwrap() as u64 <= 2 * CAPTURE_LIMIT,
            "read aggregate CLI capture bound"
        );
        CliResult {
            status,
            stdout,
            stderr,
        }
    }
    fn headless_home(f: &Fixture, wire: &Wire) -> PathBuf {
        let plan =
            orbit_cli::setup::plan_setup(&f.home, &orbit_cli::setup::SetupRequest::default())
                .unwrap();
        orbit_cli::setup::apply_setup(&plan).unwrap();
        configure(f, wire, 64_000);
        let schema = f.root.join("answer.schema.json");
        write_private(&schema,json!({"type":"object","required":["answer"],"properties":{"answer":{"type":"integer"}}}).to_string());
        schema
    }
    fn headless_sessions(f: &Fixture) -> Vec<SessionFile> {
        sessions::list_sessions(&f.home).unwrap()
    }
    fn headless_checkpoint(f: &Fixture, id: &str) -> orbit_engine::AccountingCheckpoint {
        let _lease = SessionLease::acquire(&f.home, id, "headless-inspection").unwrap();
        journal(f, id).accounting_checkpoint().unwrap()
    }
    fn assert_headless_known(
        f: &Fixture,
        id: &str,
        revision: u64,
        input: u64,
        output: u64,
        known_cost: u64,
    ) {
        let checkpoint = headless_checkpoint(f, id);
        assert_eq!(checkpoint.revision.0, revision);
        assert_eq!(checkpoint.owner_session_id, id);
        assert_eq!(checkpoint.child_id, None);
        assert!(checkpoint.pending.is_none());
        assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Known);
        assert_eq!(checkpoint.totals.ordinary.cost_microcents, Some(known_cost));
        assert_eq!(
            (
                checkpoint.totals.housekeeping.input_tokens,
                checkpoint.totals.housekeeping.output_tokens,
                checkpoint.totals.housekeeping.cost_microcents
            ),
            (0, 0, Some(0))
        );
        assert_eq!(
            (
                checkpoint.totals.ordinary.input_tokens,
                checkpoint.totals.ordinary.output_tokens
            ),
            (input, output)
        );
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .ordinary_microcents,
            known_cost
        );
        let saved = saved(f, id);
        assert_eq!(
            (
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (input, output, known_cost)
        );
        assert_eq!(
            saved.accounting_watermark.as_ref().unwrap().revision,
            revision
        );
        assert_eq!(
            saved
                .accounting_watermark
                .as_ref()
                .unwrap()
                .owner_session_id,
            id
        );
        let events = orbit_ledger::verify_ledger(&f.home.join("ledger"))
            .unwrap()
            .0;
        let ids: Vec<_> = events
            .into_iter()
            .filter_map(|record| match record.record.event {
                orbit_ledger::LedgerEvent::EgressIntent(event) if event.session_id == id => {
                    Some(event.decision_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(ids.len() as u64, revision / 2);
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            ids.len()
        );
        if let Some(last) = checkpoint.last_settlement {
            assert_eq!(last.reference.request_id, *ids.last().unwrap());
        }
    }
    fn assert_schema_wire(wire: &Wire, count: usize) {
        assert_wire(wire, count);
        let requests = wire.requests.lock().unwrap();
        for request in requests.iter() {
            assert_eq!(request.body["model"], RAW_A);
        }
        if count > 1 {
            let first = &requests[0].body["messages"];
            let repair = &requests[1].body;
            assert!(repair.get("tools").is_none());
            assert!(repair.get("tool_choice").is_none());
            let first = first.as_array().unwrap();
            let second = repair["messages"].as_array().unwrap();
            assert_eq!(&second[..first.len()], first.as_slice());
            assert!(
                second.last().unwrap()["content"]
                    .as_str()
                    .unwrap()
                    .starts_with("Your previous reply did not match the required JSON schema:")
            );
            assert!(
                second.last().unwrap()["content"]
                    .as_str()
                    .unwrap()
                    .contains("Reply with ONLY valid JSON")
            );
        }
    }

    #[test]
    fn actual_headless_schema_repair_saves_both_distinct_bills_and_observed_history() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_schema_repair_saves_both_distinct_bills_and_observed_history",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let first = r#"{"answer":"wrong type"}"#;
        let answer = r#"{"answer":42}"#;
        let mut wire = Wire::new(vec![Response::complete(first), Response::complete(answer)]);
        let schema = headless_home(&f, &wire);
        let result = accounting_cli(
            &f,
            &[
                "-p",
                "produce the synthetic answer",
                "--json-schema",
                schema.to_str().unwrap(),
                "--output-format",
                "json",
            ],
            "",
            None,
        );
        wire.finish();
        assert!(result.status.success(), "{}", result.stderr);
        let summary = result.json();
        assert_eq!(summary["status"], "ok");
        assert_eq!(summary["final_text"], answer);
        assert_eq!(
            summary["usage"],
            json!({"input_tokens":22,"output_tokens":14})
        );
        assert_eq!(summary["cost_microcents"], 10);
        assert_eq!(summary["rounds"], 2);
        assert_eq!(summary["full_cost_status"], "known");
        let sessions = headless_sessions(&f);
        assert_eq!(sessions.len(), 1);
        let saved = &sessions[0];
        assert_eq!(saved.turns, 1);
        assert_headless_known(&f, &saved.session_id, 4, 22, 14, 10);
        assert_eq!(
            headless_checkpoint(&f, &saved.session_id).baseline,
            AccountingBaseline::FreshKnownZero
        );
        assert_eq!(saved.transcript.len(), 4);
        assert_eq!(saved.transcript[0].content, "produce the synthetic answer");
        assert_eq!(saved.transcript[1].content, first);
        assert_eq!(saved.transcript[3].content, answer);
        assert_schema_wire(&wire, 2);
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
    }

    #[test]
    fn actual_headless_final_invalid_repair_keeps_both_paid_replies_and_does_not_repair_twice() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_final_invalid_repair_keeps_both_paid_replies_and_does_not_repair_twice",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let first = r#"{"answer":"first invalid"}"#;
        let last = r#"{"answer":"still invalid"}"#;
        let mut wire = Wire::new(vec![
            Response::complete(first),
            Response::complete(last),
            Response::complete("must not repair a second time"),
        ]);
        let schema = headless_home(&f, &wire);
        let result = accounting_cli(
            &f,
            &[
                "-p",
                "invalid repair fixture",
                "--json-schema",
                schema.to_str().unwrap(),
                "--output-format",
                "json",
            ],
            "",
            None,
        );
        wire.finish();
        assert_eq!(result.status.code(), Some(1));
        let summary = result.json();
        assert_eq!(summary["status"], "error");
        assert_eq!(summary["cost_microcents"], 10);
        assert_eq!(
            summary["usage"],
            json!({"input_tokens":22,"output_tokens":14})
        );
        assert!(
            result
                .stderr
                .contains("schema repair did not produce valid output")
        );
        let sessions = headless_sessions(&f);
        assert_eq!(sessions.len(), 1);
        let saved = &sessions[0];
        assert_headless_known(&f, &saved.session_id, 4, 22, 14, 10);
        assert_eq!(saved.transcript.len(), 4);
        assert_eq!(saved.transcript[1].content, first);
        assert_eq!(saved.transcript[3].content, last);
        assert_schema_wire(&wire, 2);
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
    }

    #[test]
    fn actual_headless_failed_repair_retains_the_first_bill_and_pending_resume_refusal() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_failed_repair_retains_the_first_bill_and_pending_resume_refusal",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let malformed = Response {
            body: "data: {invalid-json}\n\n".into(),
            pause: false,
        };
        let mut wire = Wire::new(vec![
            Response::complete(r#"{"answer":"invalid"}"#),
            malformed,
            Response::complete("must not replay"),
        ]);
        let schema = headless_home(&f, &wire);
        let result = accounting_cli(
            &f,
            &[
                "-p",
                "repair failure current intent",
                "--json-schema",
                schema.to_str().unwrap(),
                "--output-format",
                "json",
            ],
            "",
            None,
        );
        assert_eq!(result.status.code(), Some(1));
        let summary = result.json();
        assert_eq!(summary["status"], "error");
        assert_eq!(summary["cost_microcents"], 5);
        assert_eq!(
            summary["usage"],
            json!({"input_tokens":11,"output_tokens":7})
        );
        assert_eq!(summary["full_cost_status"], "uncertain");
        let saved = headless_sessions(&f).remove(0);
        let checkpoint = headless_checkpoint(&f, &saved.session_id);
        assert_eq!(checkpoint.revision.0, 4);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .ordinary_microcents,
            5
        );
        assert_eq!(
            (
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (11, 7, 5)
        );
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(|message| message.content == "repair failure current intent")
                .count(),
            1
        );
        let before = fs::read(
            f.home
                .join("sessions")
                .join(format!("{}.json", saved.session_id)),
        )
        .unwrap();
        let refused = accounting_cli(
            &f,
            &[
                "-p",
                "do not replay uncertain repair",
                "--resume",
                &saved.session_id,
                "--output-format",
                "json",
            ],
            "",
            None,
        );
        assert_eq!(refused.status.code(), Some(1));
        assert_eq!(headless_checkpoint(&f, &saved.session_id), checkpoint);
        assert_eq!(
            fs::read(
                f.home
                    .join("sessions")
                    .join(format!("{}.json", saved.session_id))
            )
            .unwrap(),
            before
        );
        wire.finish();
        assert_schema_wire(&wire, 2);
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
    }

    #[test]
    fn actual_headless_repair_cannot_execute_a_provider_returned_write_tool() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_repair_cannot_execute_a_provider_returned_write_tool",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let destination = f.workspace.join("forbidden-repair-write.txt");
        let event = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"repair-write","type":"function","function":{"name":"Write","arguments":json!({"file_path":destination,"content":"forbidden effect"}).to_string()}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7}});
        let tool = Response {
            body: format!("data: {event}\n\ndata: [DONE]\n\n"),
            pause: false,
        };
        let mut wire = Wire::new(vec![
            Response::complete(r#"{"answer":"invalid"}"#),
            tool,
            Response::complete("must not make a third POST"),
        ]);
        let schema = headless_home(&f, &wire);
        let result = accounting_cli(
            &f,
            &[
                "-p",
                "repair with no tool effects",
                "--json-schema",
                schema.to_str().unwrap(),
                "--output-format",
                "json",
                "--auto-tools",
            ],
            "",
            None,
        );
        wire.finish();
        assert!(!result.status.success());
        let summary = result.json();
        assert_ne!(summary["status"], "ok");
        assert_eq!(summary["cost_microcents"], 10);
        assert_eq!(
            summary["usage"],
            json!({"input_tokens":22,"output_tokens":14})
        );
        let saved = headless_sessions(&f).remove(0);
        assert_headless_known(&f, &saved.session_id, 4, 22, 14, 10);
        assert!(!destination.exists());
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        assert_schema_wire(&wire, 2);
    }

    #[test]
    fn actual_headless_schema_repair_reuses_the_fixed_invocation_spend_remainder() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_schema_repair_reuses_the_fixed_invocation_spend_remainder",
        ) {
            return;
        }
        require_private_system_fixture();
        for (limit, posts, cost, exit) in [("7", 1, 5, 1), ("10", 2, 10, 0)] {
            let f = Fixture::new();
            let mut wire = Wire::new(vec![
                Response::complete(r#"{"answer":"invalid"}"#),
                Response::complete(r#"{"answer":42}"#),
            ]);
            let schema = headless_home(&f, &wire);
            let result = accounting_cli(
                &f,
                &[
                    "-p",
                    "bounded repair allowance",
                    "--json-schema",
                    schema.to_str().unwrap(),
                    "--output-format",
                    "json",
                    "--max-cost",
                    limit,
                ],
                "",
                None,
            );
            wire.finish();
            assert_eq!(result.status.code(), Some(exit));
            let summary = result.json();
            assert_eq!(summary["cost_microcents"], cost);
            let saved = headless_sessions(&f).remove(0);
            assert_headless_known(
                &f,
                &saved.session_id,
                posts * 2,
                posts * 11,
                posts * 7,
                cost,
            );
            assert_wire(&wire, posts as usize);
            if posts == 2 {
                assert_schema_wire(&wire, 2);
            } else {
                assert_eq!(summary["status"], "error");
            }
            assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        }
    }

    #[test]
    fn actual_headless_failed_first_call_never_enters_schema_repair() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_failed_first_call_never_enters_schema_repair",
        ) {
            return;
        }
        require_private_system_fixture();
        for known_length in [false, true] {
            let f = Fixture::new();
            let first = if known_length {
                Response::text(
                    "{\"answer\":",
                    "length",
                    Some(json!({"prompt_tokens":11,"completion_tokens":7})),
                )
            } else {
                Response {
                    body: "data: {invalid-json}\n\n".into(),
                    pause: false,
                }
            };
            let mut wire = Wire::new(vec![
                first,
                Response::complete("must not enter schema repair"),
            ]);
            let schema = headless_home(&f, &wire);
            let result = accounting_cli(
                &f,
                &[
                    "-p",
                    "failed first schema call",
                    "--json-schema",
                    schema.to_str().unwrap(),
                    "--output-format",
                    "json",
                ],
                "",
                None,
            );
            wire.finish();
            assert_eq!(result.status.code(), Some(1));
            let summary = result.json();
            assert_ne!(summary["status"], "ok");
            assert!(
                !result
                    .stderr
                    .contains("schema validation failed, repairing once")
            );
            let saved = headless_sessions(&f).remove(0);
            let checkpoint = headless_checkpoint(&f, &saved.session_id);
            assert_eq!(checkpoint.revision.0, 2);
            if known_length {
                assert_headless_known(&f, &saved.session_id, 2, 11, 7, 5);
            } else {
                assert!(checkpoint.pending.as_ref().unwrap().uncertain);
                assert_eq!(saved.cost_microcents, 0);
            }
            assert_eq!(
                saved
                    .transcript
                    .iter()
                    .filter(|message| message.content == "failed first schema call")
                    .count(),
                1
            );
            assert_wire(&wire, 1);
            assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        }
    }

    #[test]
    fn actual_headless_sigkill_first_or_repair_keeps_pending_truth_and_never_replays() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_sigkill_first_or_repair_keeps_pending_truth_and_never_replays",
        ) {
            return;
        }
        require_private_system_fixture();
        use std::os::unix::process::ExitStatusExt;
        for during_repair in [false, true] {
            let f = Fixture::new();
            let prefix = json!({"choices":[{"index":0,"delta":{"content":"incomplete private response"},"finish_reason":null}]});
            let paused = Response {
                body: format!("data: {prefix}\n\n"),
                pause: true,
            };
            let mut replies = Vec::new();
            if during_repair {
                replies.push(Response::complete(r#"{"answer":"invalid"}"#));
            }
            replies.push(paused);
            replies.push(Response::complete("must not replay"));
            let mut wire = Wire::new(replies);
            let schema = headless_home(&f, &wire);
            let posts = if during_repair { 2 } else { 1 };
            let result = accounting_cli(
                &f,
                &[
                    "-p",
                    "interrupted schema invocation",
                    "--json-schema",
                    schema.to_str().unwrap(),
                    "--output-format",
                    "json",
                ],
                "",
                Some((&wire, posts)),
            );
            // SIGKILL deliberately bypasses graceful cancellation. The current
            // request must retain begun-only truth, with any prior bill unchanged.
            assert_eq!(result.status.signal(), Some(9));
            let saved = headless_sessions(&f).remove(0);
            let checkpoint = headless_checkpoint(&f, &saved.session_id);
            assert_eq!(checkpoint.revision.0, if during_repair { 3 } else { 1 });
            assert!(checkpoint.pending.is_some());
            assert_eq!(
                checkpoint
                    .known_priced_subtotals
                    .unwrap()
                    .ordinary_microcents,
                if during_repair { 5 } else { 0 }
            );
            let reference = checkpoint.pending.as_ref().unwrap().reference.clone();
            let refused = accounting_cli(
                &f,
                &[
                    "-p",
                    "must not replay interrupted request",
                    "--resume",
                    &saved.session_id,
                    "--output-format",
                    "json",
                ],
                "",
                None,
            );
            assert_eq!(refused.status.code(), Some(1));
            assert_eq!(headless_checkpoint(&f, &saved.session_id), checkpoint);
            assert_eq!(
                headless_checkpoint(&f, &saved.session_id)
                    .pending
                    .unwrap()
                    .reference,
                reference
            );
            wire.finish();
            assert_wire(&wire, posts);
            assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        }
    }

    #[test]
    fn actual_headless_resume_and_fork_preserve_authoritative_owner_watermarks() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_resume_and_fork_preserve_authoritative_owner_watermarks",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let mut wire = Wire::new(vec![
            Response::complete("first"),
            Response::complete("resumed"),
            Response::complete("forked"),
        ]);
        headless_home(&f, &wire);
        let first = accounting_cli(
            &f,
            &["-p", "fresh authority", "--output-format", "json"],
            "",
            None,
        );
        assert!(first.status.success());
        let id = headless_sessions(&f).remove(0).session_id;
        assert_headless_known(&f, &id, 2, 11, 7, 5);
        let second = accounting_cli(
            &f,
            &[
                "-p",
                "resumed authority",
                "--resume",
                &id,
                "--output-format",
                "json",
            ],
            "",
            None,
        );
        assert!(second.status.success());
        assert_eq!(second.json()["cost_microcents"], 5);
        assert_headless_known(&f, &id, 4, 22, 14, 10);
        let source = saved(&f, &id);
        let source_bytes = fs::read(f.home.join("sessions").join(format!("{id}.json"))).unwrap();
        let source_checkpoint = headless_checkpoint(&f, &id);
        let fork = accounting_cli(
            &f,
            &[
                "-p",
                "forked authority",
                "--resume",
                &id,
                "--fork-session",
                "--output-format",
                "json",
            ],
            "",
            None,
        );
        assert!(fork.status.success(), "{}", fork.stderr);
        assert_eq!(fork.json()["cost_microcents"], 5);
        let all = headless_sessions(&f);
        assert_eq!(all.len(), 2);
        let fork = all.iter().find(|saved| saved.session_id != id).unwrap();
        assert_eq!(
            (fork.input_tokens, fork.output_tokens, fork.cost_microcents),
            (33, 21, 15)
        );
        assert!(fork.transcript.starts_with(&source.transcript));
        let checkpoint = headless_checkpoint(&f, &fork.session_id);
        assert_eq!(checkpoint.baseline, AccountingBaseline::UnknownLegacy);
        assert_eq!(checkpoint.revision.0, 2);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .ordinary_microcents,
            5
        );
        assert_eq!(
            fork.accounting_watermark.as_ref().unwrap().owner_session_id,
            fork.session_id
        );
        assert_eq!(fork.accounting_watermark.as_ref().unwrap().revision, 2);
        assert_eq!(headless_checkpoint(&f, &id), source_checkpoint);
        assert_eq!(
            fs::read(f.home.join("sessions").join(format!("{id}.json"))).unwrap(),
            source_bytes
        );
        wire.finish();
        assert_wire(&wire, 3);
    }

    #[test]
    fn actual_plain_repl_controls_and_failed_resume_preserve_each_accounting_anchor() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_plain_repl_controls_and_failed_resume_preserve_each_accounting_anchor",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let mut wire = Wire::new(vec![
            Response::complete("first session"),
            Response::complete("other session"),
        ]);
        headless_home(&f, &wire);
        assert!(
            accounting_cli(
                &f,
                &["-p", "first control session", "--output-format", "json"],
                "",
                None
            )
            .status
            .success()
        );
        let first = headless_sessions(&f).remove(0).session_id;
        assert!(
            accounting_cli(
                &f,
                &["-p", "second control session", "--output-format", "json"],
                "",
                None
            )
            .status
            .success()
        );
        let second = headless_sessions(&f)
            .into_iter()
            .find(|saved| saved.session_id != first)
            .unwrap()
            .session_id;
        let first_checkpoint = headless_checkpoint(&f, &first);
        let second_checkpoint = headless_checkpoint(&f, &second);
        let first_anchor = saved(&f, &first).accounting_watermark;
        let second_anchor = saved(&f, &second).accounting_watermark;
        let input = format!(
            "/usage\n/model provider_a/{RAW_A}\n/effort default\n/route auto\n/resume {second}\n/usage\n/resume nonexistent-accounting-session\n/route\nexit\n"
        );
        let result = accounting_cli(&f, &["chat", "--no-tui", "--resume", &first], &input, None);
        assert!(result.status.success(), "{}", result.stderr);
        let summary = result.json();
        assert_eq!(summary["command"], "chat");
        assert_eq!(summary["session"], second);
        assert_eq!(
            summary["usage"],
            json!({"input_tokens":11,"output_tokens":7})
        );
        assert_eq!(summary["cost_microcents"], 5);
        assert!(
            result
                .stderr
                .contains("cannot resume nonexistent-accounting-session")
        );
        assert_eq!(headless_checkpoint(&f, &first), first_checkpoint);
        assert_eq!(headless_checkpoint(&f, &second), second_checkpoint);
        assert_eq!(saved(&f, &first).accounting_watermark, first_anchor);
        assert_eq!(saved(&f, &second).accounting_watermark, second_anchor);
        assert_eq!(
            saved(&f, &first).effort,
            Some(orbit_adapter::types::EffortSetting::Default)
        );
        assert_eq!(
            saved(&f, &first).selection_origin,
            Some(SelectionOrigin::Default)
        );
        wire.finish();
        assert_wire(&wire, 2);
    }

    #[test]
    fn actual_headless_resumed_schema_call_gets_one_new_allowance_shared_with_its_repair() {
        if !dispatch_isolated(
            "caller_journal_activation::actual_headless_resumed_schema_call_gets_one_new_allowance_shared_with_its_repair",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let mut wire = Wire::new(vec![
            Response::complete("old paid work"),
            Response::complete(r#"{"answer":"invalid"}"#),
            Response::complete("must not reset the allowance"),
        ]);
        let schema = headless_home(&f, &wire);
        let first = accounting_cli(
            &f,
            &["-p", "older invocation", "--output-format", "json"],
            "",
            None,
        );
        assert!(first.status.success());
        let id = headless_sessions(&f).remove(0).session_id;
        assert_headless_known(&f, &id, 2, 11, 7, 5);
        let resumed = accounting_cli(
            &f,
            &[
                "-p",
                "new bounded invocation",
                "--resume",
                &id,
                "--json-schema",
                schema.to_str().unwrap(),
                "--output-format",
                "json",
                "--max-cost",
                "7",
            ],
            "",
            None,
        );
        wire.finish();
        assert_eq!(resumed.status.code(), Some(1));
        let summary = resumed.json();
        assert_eq!(summary["status"], "error");
        // Existing spend5 does not consume this invocation's7, so its first5 bill
        // is admitted; that same invocation then has2, which cannot buy repair5.
        assert_eq!(summary["cost_microcents"], 5);
        assert_eq!(
            summary["usage"],
            json!({"input_tokens":11,"output_tokens":7})
        );
        assert_headless_known(&f, &id, 4, 22, 14, 10);
        assert_wire(&wire, 2);
        let durable = saved(&f, &id);
        assert_eq!(durable.turns, 2);
        assert_eq!(
            durable
                .transcript
                .iter()
                .filter(|message| message.content == "new bounded invocation")
                .count(),
            1
        );
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
    }
}
