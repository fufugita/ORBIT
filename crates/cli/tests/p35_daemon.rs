#![cfg(unix)]

pub use orbit_cli::{
    apply_effort_setting, checked_model_turn, config, context_window_for_turn, effort_status,
    model_limits, parse_effort_setting, phase_routing, resolve_selected_model, route_command,
    sessions, tool_runtime, tools, try_engine_turn_config, try_phase_turn_config,
    try_role_turn_config, tui_worker,
};
#[path = "../src/attach.rs"]
pub mod attach;
#[path = "../src/daemon.rs"]
pub mod daemon;

use daemon::{OwnerAction, OwnerConfig, OwnerRuntime, TurnState, UnixServer};
use sessions::SessionLease;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    root: PathBuf,
    provider: Child,
    config: OwnerConfig,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-owner-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let mut provider = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/p35_provider.py"
            ))
            .arg(&root)
            .stdout(Stdio::null())
            .stderr(fs::File::create(root.join("provider.stderr")).unwrap())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while !root.join("ready.json").exists() {
            assert!(Instant::now() < until);
            assert!(
                provider.try_wait().unwrap().is_none(),
                "fixture provider failed: {}",
                fs::read_to_string(root.join("provider.stderr")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("ready.json")).unwrap()).unwrap();
        let gate = ready["gate"].as_str().unwrap().to_owned();
        fs::write(root.join("providers.toml"), format!("[[provider]]\nname=\"fixture\"\nurl={gate:?}\n[[provider.models]]\nid=\"model-a\"\nsupported_efforts=[\"low\",\"high\"]\ndefault_effort=\"low\"\n[[provider.models]]\nid=\"model-b\"\nsupported_efforts=[\"low\",\"high\"]\ndefault_effort=\"high\"\n")).unwrap();
        let turn = tui_worker::TuiTurnConfig {
            home: root.clone(),
            session_id: "owned".into(),
            gate,
            model: "model-a".into(),
            effort: None,
            provider_id: "fixture".into(),
            auto_tools: false,
            scope: tool_runtime::PermissionScope::default(),
            initial_transcript: vec![],
            initial_turns: 0,
            initial_input_tokens: 0,
            initial_output_tokens: 0,
            initial_cost_microcents: 0,
        };
        Self {
            config: OwnerConfig::new(turn, root.clone()),
            root,
            provider,
        }
    }
    fn start(&self) -> OwnerRuntime {
        let lease = SessionLease::acquire(&self.root, "owned", "daemon").unwrap();
        let mut config = self.config.clone();
        if self.root.join("sessions/owned.json").exists() {
            let saved = lease.load().unwrap();
            config.turn.model = saved.model;
            config.turn.provider_id = saved.provider;
            config.turn.gate = saved.gate;
            config.turn.effort = saved.effort;
            config.turn.initial_transcript = saved.transcript;
            config.turn.initial_turns = saved.turns;
            config.turn.initial_input_tokens = saved.input_tokens;
            config.turn.initial_output_tokens = saved.output_tokens;
            config.turn.initial_cost_microcents = saved.cost_microcents;
        }
        OwnerRuntime::start(config, lease).unwrap()
    }
    fn calls(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.root.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn socket(&self) -> PathBuf {
        self.root.join("run/owner.sock")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.provider.kill();
        let _ = self.provider.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn wait_done(handle: &daemon::OwnerHandle) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = handle.snapshot().unwrap();
        if snapshot.state == TurnState::Idle && snapshot.turns > 0 {
            break;
        }
        assert!(Instant::now() < until, "owner did not finish: {snapshot:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn rpc(stream: &mut BufReader<UnixStream>, action: serde_json::Value) -> serde_json::Value {
    let request = serde_json::json!({"version":1,"request":action});
    writeln!(stream.get_mut(), "{request}").unwrap();
    let mut line = String::new();
    stream.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn local_turn_one_prompt_uses_existing_engine_and_saves_reply() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "request-one".into(),
            text: "local prompt".into(),
        })
        .unwrap();
    wait_done(&handle);
    assert_eq!(fixture.calls().len(), 1);
    assert_eq!(fixture.calls()[0]["model"], "model-a");
    let snapshot = handle.snapshot().unwrap();
    assert_eq!(snapshot.turns, 1);
    assert!(
        serde_json::to_string(&snapshot.messages)
            .unwrap()
            .contains("owned fixture reply")
    );
    let saved = sessions::load_session(&fixture.root, "owned").unwrap();
    assert!(
        saved
            .transcript
            .iter()
            .any(|message| message.content == "owned fixture reply")
    );
    drop(controller);
    runtime.shutdown().unwrap();
}

#[test]
fn local_turn_second_controller_is_refused_before_provider_dispatch() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let _controller = runtime.handle().claim_controller().unwrap();
    assert!(runtime.handle().claim_controller().is_err());
    assert_eq!(fixture.calls().len(), 0);
    runtime.shutdown().unwrap();
}

#[test]
fn local_turn_private_socket_and_read_only_client_cannot_submit() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let server = UnixServer::bind(&fixture.socket(), runtime.handle()).unwrap();
    let stop = orbit_provider_http::CancelToken::new();
    let stop_thread = stop.clone();
    let serving = std::thread::spawn(move || server.run(&stop_thread));
    assert_eq!(
        fs::metadata(fixture.socket().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(fixture.socket()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut stream = BufReader::new(daemon::local_connect(&fixture.socket()).unwrap());
    assert!(
        rpc(
            &mut stream,
            serde_json::json!({"type":"hello","controlling":false})
        )["ok"]
            .as_bool()
            .unwrap()
    );
    assert!(!rpc(&mut stream, serde_json::json!({"type":"action","action":{"type":"prompt","request_id":"read-only","text":"refused"}}))["ok"].as_bool().unwrap());
    assert!(
        rpc(&mut stream, serde_json::json!({"type":"status"}))["ok"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(fixture.calls().len(), 0);
    drop(stream);
    stop.cancel();
    serving.join().unwrap().unwrap();
    runtime.shutdown().unwrap();
}

#[test]
fn local_turn_symlink_endpoint_is_refused_without_touching_target() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(fixture.socket().parent().unwrap())
        .unwrap();
    let target = fixture.root.join("untouched");
    fs::write(&target, "original").unwrap();
    symlink(&target, fixture.socket()).unwrap();
    assert!(UnixServer::bind(&fixture.socket(), runtime.handle()).is_err());
    assert_eq!(fs::read_to_string(target).unwrap(), "original");
    assert_eq!(fixture.calls().len(), 0);
    runtime.shutdown().unwrap();
}

#[test]
fn local_turn_live_endpoint_is_never_unlinked_by_another_server() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let first = UnixServer::bind(&fixture.socket(), runtime.handle()).unwrap();
    let inode = fs::metadata(fixture.socket()).unwrap().ino();
    assert!(UnixServer::bind(&fixture.socket(), runtime.handle()).is_err());
    assert_eq!(fs::metadata(fixture.socket()).unwrap().ino(), inode);
    assert_eq!(fixture.calls().len(), 0);
    drop(first);
    runtime.shutdown().unwrap();
}

fn wait_pending(handle: &daemon::OwnerHandle) -> String {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = handle.snapshot().unwrap();
        if let Some(card) = snapshot.pending_approvals.first() {
            return card["call_id"].as_str().unwrap().to_owned();
        }
        assert!(Instant::now() < until, "approval did not appear");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn reconnect_detach_preserves_running_provider_turn_and_identity() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode.json"), r#"{"blocked":true}"#).unwrap();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "running-key".into(),
            text: "blocked prompt".into(),
        })
        .unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while fixture.calls().is_empty() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(controller);
    let snapshot = handle.subscribe(None).unwrap().recovery.snapshot.unwrap();
    assert_eq!(snapshot.state, TurnState::Running);
    assert_eq!(snapshot.current_request.as_deref(), Some("running-key"));
    assert_eq!(snapshot.provider, "fixture");
    assert_eq!(snapshot.model, "model-a");
    let mut next = handle.claim_controller().unwrap();
    let duplicate = next
        .send(OwnerAction::Prompt {
            request_id: "running-key".into(),
            text: "blocked prompt".into(),
        })
        .unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(fixture.calls().len(), 1);
    fs::write(fixture.root.join("release"), b"finish").unwrap();
    wait_done(&handle);
    assert_eq!(fixture.calls().len(), 1);
    runtime.shutdown().unwrap();
}

#[test]
fn stable_request_identity_deduplicates_completion_and_rejects_payload_conflict() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "stable-key".into(),
            text: "first intent".into(),
        })
        .unwrap();
    wait_done(&handle);
    assert!(
        controller
            .send(OwnerAction::Prompt {
                request_id: "stable-key".into(),
                text: "first intent".into()
            })
            .unwrap()
            .duplicate
    );
    assert!(
        controller
            .send(OwnerAction::Prompt {
                request_id: "stable-key".into(),
                text: "different intent".into()
            })
            .is_err()
    );
    assert_eq!(fixture.calls().len(), 1);
    assert_eq!(handle.snapshot().unwrap().turns, 1);
    runtime.shutdown().unwrap();
}

#[test]
fn restart_preserves_saved_conversation_and_durable_request_claim() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let mut controller = runtime.handle().claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "saved-key".into(),
            text: "saved prompt".into(),
        })
        .unwrap();
    wait_done(&runtime.handle());
    drop(controller);
    runtime.shutdown().unwrap();
    let runtime = fixture.start();
    let snapshot = runtime.handle().snapshot().unwrap();
    assert_eq!(snapshot.turns, 1);
    assert!(
        serde_json::to_string(&snapshot.messages)
            .unwrap()
            .contains("saved prompt")
    );
    let mut controller = runtime.handle().claim_controller().unwrap();
    assert!(
        controller
            .send(OwnerAction::Prompt {
                request_id: "saved-key".into(),
                text: "saved prompt".into()
            })
            .unwrap()
            .duplicate
    );
    assert_eq!(fixture.calls().len(), 1);
    runtime.shutdown().unwrap();
}

#[test]
fn approval_reconnect_keeps_exact_pending_id_and_independent_actions() {
    let fixture = Fixture::new();
    let output = fixture.root.join("approved.txt");
    fs::write(
        fixture.root.join("mode.json"),
        serde_json::json!({"tool":"Write","arguments":{"file_path":output,"content":"approved"}})
            .to_string(),
    )
    .unwrap();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "approval-key".into(),
            text: "write with approval".into(),
        })
        .unwrap();
    let id = wait_pending(&handle);
    assert!(!output.exists());
    drop(controller);
    let mut controller = handle.claim_controller().unwrap();
    assert_eq!(wait_pending(&handle), id);
    assert!(
        controller
            .send(OwnerAction::Approval {
                call_id: "stale".into(),
                verdict: daemon::ApprovalChoice::AllowOnce,
                note: None
            })
            .is_err()
    );
    controller.send(OwnerAction::ListModels).unwrap();
    assert_eq!(wait_pending(&handle), id);
    assert!(!output.exists());
    controller
        .send(OwnerAction::Approval {
            call_id: id,
            verdict: daemon::ApprovalChoice::AllowOnce,
            note: None,
        })
        .unwrap();
    wait_done(&handle);
    assert_eq!(fs::read_to_string(output).unwrap(), "approved");
    assert_eq!(fixture.calls().len(), 2);
    assert!(handle.snapshot().unwrap().pending_approvals.is_empty());
    runtime.shutdown().unwrap();
}

#[test]
fn atomic_snapshot_subscription_observes_boundary_events_once() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let cursor = handle.snapshot().unwrap().cursor;
    let mut controller = handle.claim_controller().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_barrier = barrier.clone();
    let prompt = std::thread::spawn(move || {
        worker_barrier.wait();
        controller
            .send(OwnerAction::Prompt {
                request_id: "race-key".into(),
                text: "race prompt".into(),
            })
            .unwrap();
    });
    barrier.wait();
    let subscription = handle.subscribe(Some(&cursor)).unwrap();
    let mut events = subscription.recovery.events.clone();
    while !events.iter().any(|event| event.kind == "request_finished") {
        events.push(subscription.recv_timeout(Duration::from_secs(5)).unwrap());
    }
    prompt.join().unwrap();
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.cursor.sequence, cursor.sequence + index as u64 + 1);
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == "request_finished")
            .count(),
        1
    );
    assert_eq!(fixture.calls().len(), 1);
    runtime.shutdown().unwrap();
}

#[test]
fn expired_replay_cursor_requires_fresh_snapshot() {
    let mut fixture = Fixture::new();
    fixture.config.replay_capacity = 2;
    let runtime = fixture.start();
    let handle = runtime.handle();
    let cursor = handle.snapshot().unwrap().cursor;
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "overflow-key".into(),
            text: "overflow prompt".into(),
        })
        .unwrap();
    wait_done(&handle);
    let subscription = handle.subscribe(Some(&cursor)).unwrap();
    assert!(subscription.recovery.snapshot.is_some());
    assert!(subscription.recovery.events.is_empty());
    assert!(subscription.recovery.cursor.sequence > 2);
    assert!(
        serde_json::to_string(&subscription.recovery.snapshot)
            .unwrap()
            .contains("owned fixture reply")
    );
    runtime.shutdown().unwrap();
}

#[test]
fn model_effort_settings_validate_save_and_restore_without_provider_calls() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::SetEffort {
            choice: orbit_cli::parse_effort_setting("high").unwrap(),
        })
        .unwrap();
    let selected = handle.snapshot().unwrap();
    let saved_bytes = fs::read(fixture.root.join("sessions/owned.json")).unwrap();
    assert!(selected.effort_status.contains("high"));
    assert!(
        controller
            .send(OwnerAction::SetEffort {
                choice: orbit_cli::parse_effort_setting("unsupported").unwrap()
            })
            .is_err()
    );
    assert_eq!(handle.snapshot().unwrap().effort, selected.effort);
    assert!(
        controller
            .send(OwnerAction::SetModel {
                model: "missing".into(),
                provider: None
            })
            .is_err()
    );
    assert_eq!(handle.snapshot().unwrap().model, "model-a");
    assert_eq!(
        fs::read(fixture.root.join("sessions/owned.json")).unwrap(),
        saved_bytes
    );
    controller
        .send(OwnerAction::SetModel {
            model: "model-b".into(),
            provider: Some("fixture".into()),
        })
        .unwrap();
    assert_eq!(handle.snapshot().unwrap().model, "model-b");
    assert_eq!(
        sessions::load_session(&fixture.root, "owned")
            .unwrap()
            .model,
        "model-b"
    );
    assert_eq!(fixture.calls().len(), 0);
    drop(controller);
    runtime.shutdown().unwrap();
    let runtime = fixture.start();
    assert_eq!(runtime.handle().snapshot().unwrap().model, "model-b");
    assert_eq!(runtime.handle().snapshot().unwrap().effort, selected.effort);
    assert_eq!(fixture.calls().len(), 0);
    let mut controller = runtime.handle().claim_controller().unwrap();
    controller
        .send(OwnerAction::SetEffort {
            choice: orbit_adapter::types::EffortSetting::Default,
        })
        .unwrap();
    assert_eq!(
        runtime.handle().snapshot().unwrap().effort,
        Some(orbit_adapter::types::EffortSetting::Default)
    );
    runtime.shutdown().unwrap();
}

#[test]
fn display_events_redact_split_secret_and_configuration_before_visibility() {
    let fixture = Fixture::new();
    let secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
    let second_secret = "sk-zyxwvutsrqponmlkjihgfedcba9876543210";
    fs::write(
        fixture.root.join("mode.json"),
        serde_json::json!({"chunks":["sk-abc","defghijklmnopqrstuvwxyz0123456789 sk-zyx","wvutsrqponmlkjihgfedcba9876543210"]}).to_string(),
    )
    .unwrap();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let subscription = handle.subscribe(None).unwrap();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "secret-key".into(),
            text: "redact output".into(),
        })
        .unwrap();
    let mut text = String::new();
    loop {
        let event = subscription.recv_timeout(Duration::from_secs(5)).unwrap();
        if event.kind == "text_delta" {
            text.push_str(event.payload["text"].as_str().unwrap());
        }
        if event.kind == "request_finished" {
            break;
        }
    }
    assert!(
        !text.contains(secret),
        "raw split token crossed event boundary"
    );
    assert!(text.contains("redacted"));
    assert!(!text.contains(second_secret));
    let public = serde_json::to_string(&handle.snapshot().unwrap()).unwrap();
    assert!(!public.contains(secret));
    assert!(!public.contains(second_secret));
    assert!(!public.contains(&fixture.config.turn.gate));
    runtime.shutdown().unwrap();
}

#[test]
fn unknown_protocol_version_rejects_before_controller_or_dispatch() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let server = UnixServer::bind(&fixture.socket(), runtime.handle()).unwrap();
    let stop = orbit_provider_http::CancelToken::new();
    let stopping = stop.clone();
    let serving = std::thread::spawn(move || server.run(&stopping));
    let mut stream = BufReader::new(UnixStream::connect(fixture.socket()).unwrap());
    writeln!(
        stream.get_mut(),
        "{}",
        serde_json::json!({"version":999,"request":{"type":"hello","controlling":true}})
    )
    .unwrap();
    let mut line = String::new();
    stream.read_line(&mut line).unwrap();
    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["ok"], false);
    assert!(runtime.handle().claim_controller().is_ok());
    assert_eq!(fixture.calls().len(), 0);
    drop(stream);
    stop.cancel();
    serving.join().unwrap().unwrap();
    runtime.shutdown().unwrap();
}

#[test]
fn explicit_cancel_ends_pending_approval_without_executing_tool() {
    let fixture = Fixture::new();
    let output = fixture.root.join("cancelled.txt");
    fs::write(
        fixture.root.join("mode.json"),
        serde_json::json!({"tool":"Write","arguments":{"file_path":output,"content":"refused"}})
            .to_string(),
    )
    .unwrap();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "cancel-key".into(),
            text: "cancel approval".into(),
        })
        .unwrap();
    wait_pending(&handle);
    controller.send(OwnerAction::Cancel).unwrap();
    wait_done(&handle);
    assert!(!output.exists());
    assert!(handle.snapshot().unwrap().pending_approvals.is_empty());
    runtime.shutdown().unwrap();
}

#[test]
fn mismatched_lease_home_refuses_before_configuration_or_provider_effects() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let lease = SessionLease::acquire(&other.root, "owned", "daemon").unwrap();
    assert!(OwnerRuntime::start(fixture.config.clone(), lease).is_err());
    assert_eq!(fixture.calls().len(), 0);
    assert_eq!(other.calls().len(), 0);
    assert!(!fixture.root.join("sessions/owned.json").exists());
    assert!(!other.root.join("sessions/owned.json").exists());
}

#[test]
fn daemon_child() {
    let Some(root) = std::env::var_os("ORBIT_OWNER_CHILD_HOME") else {
        return;
    };
    let root = PathBuf::from(root);
    if std::env::var("ORBIT_OWNER_SOCKET_CHECK").as_deref() == Ok("client") {
        let failure = daemon::local_connect(&root.join("run/owner.sock")).unwrap_err();
        assert!(failure.to_string().contains("deadline"));
        return;
    }
    let providers = config::ProvidersConfig::load(&root).unwrap();
    let provider = &providers.provider[0];
    let turn = tui_worker::TuiTurnConfig {
        home: root.clone(),
        session_id: "owned".into(),
        gate: provider.url.clone(),
        model: "model-a".into(),
        effort: None,
        provider_id: "fixture".into(),
        auto_tools: false,
        scope: tool_runtime::PermissionScope::default(),
        initial_transcript: vec![],
        initial_turns: 0,
        initial_input_tokens: 0,
        initial_output_tokens: 0,
        initial_cost_microcents: 0,
    };
    let runtime = OwnerRuntime::start(
        OwnerConfig::new(turn, root.clone()),
        SessionLease::acquire(&root, "owned", "daemon").unwrap(),
    )
    .unwrap();
    if std::env::var("ORBIT_OWNER_SOCKET_CHECK").as_deref() == Ok("probe") {
        let failure = UnixServer::bind(&root.join("run/owner.sock"), runtime.handle())
            .err()
            .expect("saturated endpoint must refuse bind");
        assert!(failure.to_string().contains("deadline"));
        runtime.shutdown().unwrap();
        return;
    }
    let mut controller = runtime.handle().claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "crash-key".into(),
            text: "crash prompt".into(),
        })
        .unwrap();
    fs::write(root.join("child-ready"), b"accepted").unwrap();
    loop {
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn process_crash_restart_labels_unknown_work_and_never_resubmits() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode.json"), r#"{"blocked":true}"#).unwrap();
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "daemon_child", "--nocapture"])
            .env("ORBIT_OWNER_CHILD_HOME", &fixture.root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let until = Instant::now() + Duration::from_secs(5);
    while !fixture.root.join("child-ready").exists() || fixture.calls().is_empty() {
        assert!(Instant::now() < until);
        assert!(child.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    let runtime = fixture.start();
    let handle = runtime.handle();
    let snapshot = handle.snapshot().unwrap();
    assert_eq!(snapshot.state, TurnState::Interrupted);
    assert_eq!(
        snapshot.requests["crash-key"].state,
        daemon::RequestState::Interrupted
    );
    assert!(
        serde_json::to_string(&snapshot.messages)
            .unwrap()
            .contains("crash prompt")
    );
    let mut controller = handle.claim_controller().unwrap();
    let repeated = controller
        .send(OwnerAction::Prompt {
            request_id: "crash-key".into(),
            text: "crash prompt".into(),
        })
        .unwrap();
    assert!(repeated.duplicate);
    assert_eq!(repeated.state, "interrupted");
    assert_eq!(fixture.calls().len(), 1);
    assert!(
        controller
            .send(OwnerAction::Prompt {
                request_id: "crash-key".into(),
                text: "other prompt".into()
            })
            .is_err()
    );
    assert_eq!(fixture.calls().len(), 1);
    runtime.shutdown().unwrap();
}

#[test]
fn malformed_durable_claims_refuse_startup_without_dispatch() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    runtime.shutdown().unwrap();
    let claims = fixture.root.join("sessions/.requests/owned.json");
    fs::write(&claims, b"malformed").unwrap();
    let lease = SessionLease::acquire(&fixture.root, "owned", "daemon").unwrap();
    assert!(OwnerRuntime::start(fixture.config.clone(), lease).is_err());
    assert_eq!(fixture.calls().len(), 0);
    assert_eq!(fs::read(claims).unwrap(), b"malformed");
}

#[test]
fn lost_provider_response_is_unknown_and_never_replayed() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root.join("mode.json"),
        serde_json::json!({"disconnect":true}).to_string(),
    )
    .unwrap();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    let prompt = || OwnerAction::Prompt {
        request_id: "lost-response".into(),
        text: "accepted but lost response".into(),
    };
    controller.send(prompt()).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = handle.snapshot().unwrap();
        if snapshot.state == TurnState::Idle
            && snapshot.requests["lost-response"].state == daemon::RequestState::Unknown
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "unknown outcome not retained: {snapshot:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fixture.calls().len(), 1);
    let duplicate = controller.send(prompt()).unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.state, "unknown");
    assert_eq!(fixture.calls().len(), 1);
    drop(controller);
    runtime.shutdown().unwrap();
    let runtime = fixture.start();
    let mut controller = runtime.handle().claim_controller().unwrap();
    assert!(controller.send(prompt()).unwrap().duplicate);
    assert_eq!(fixture.calls().len(), 1);
    runtime.shutdown().unwrap();
}

#[test]
fn partial_protocol_frame_has_absolute_deadline_and_cannot_claim_control() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let server = UnixServer::bind(&fixture.socket(), runtime.handle()).unwrap();
    let stop = orbit_provider_http::CancelToken::new();
    let stopping = stop.clone();
    let serving = std::thread::spawn(move || server.run(&stopping));
    let mut stream = UnixStream::connect(fixture.socket()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    stream.write_all(b"{").unwrap();
    let started = Instant::now();
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(300));
        if stream.write_all(b" ").is_err() {
            break;
        }
    }
    let mut byte = [0];
    assert!(matches!(
        std::io::Read::read(&mut stream, &mut byte),
        Ok(0) | Err(_)
    ));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(runtime.handle().claim_controller().is_ok());
    assert_eq!(fixture.calls().len(), 0);
    stop.cancel();
    serving.join().unwrap().unwrap();
    runtime.shutdown().unwrap();
}

#[test]
fn symlinked_request_record_refuses_startup_preserving_authority() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    runtime.shutdown().unwrap();
    let session = fixture.root.join("sessions/owned.json");
    let prior = fs::read(&session).unwrap();
    let claims = fixture.root.join("sessions/.requests/owned.json");
    fs::remove_file(&claims).unwrap();
    let outside = fixture.root.join("unrelated.txt");
    fs::write(&outside, b"unrelated").unwrap();
    symlink(&outside, &claims).unwrap();
    let lease = SessionLease::acquire(&fixture.root, "owned", "daemon").unwrap();
    assert!(OwnerRuntime::start(fixture.config.clone(), lease).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"unrelated");
    assert_eq!(fs::read(&session).unwrap(), prior);
    assert_eq!(fixture.calls().len(), 0);
}

#[test]
fn read_history_survives_a_later_prompt_edit() {
    let mut fixture = Fixture::new();
    fixture.config.turn.auto_tools = true;
    let file = fixture.root.join("editing.txt");
    fs::write(&file, "before\n").unwrap();
    let mode = fixture.root.join("mode.json");
    fs::write(
        &mode,
        serde_json::json!({"tool":"Read","arguments":{"file_path":file}}).to_string(),
    )
    .unwrap();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "read-history".into(),
            text: "read the file".into(),
        })
        .unwrap();
    wait_done(&handle);
    assert_eq!(fixture.calls().len(), 2);
    fs::write(&mode,serde_json::json!({"tool":"Edit","arguments":{"file_path":file,"old_string":"before","new_string":"after"}}).to_string()).unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "edit-history".into(),
            text: "edit the read file".into(),
        })
        .unwrap();
    wait_done(&handle);
    assert_eq!(fixture.calls().len(), 4);
    assert_eq!(fs::read_to_string(&file).unwrap(), "after\n");
    assert!(
        fixture.calls()[3]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message["role"] == "tool"
                && message["content"]
                    .as_str()
                    .is_some_and(|content| content.contains("after") || content.contains("ok")))
    );
    runtime.shutdown().unwrap();
}

#[test]
fn resume_acquires_candidate_before_swapping_and_preserves_saved_identity() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let mut saved = sessions::load_session(&fixture.root, "owned").unwrap();
    saved.session_id = "candidate".into();
    saved.turns = 7;
    saved.effort = Some(orbit_cli::parse_effort_setting("high").unwrap());
    let candidate = SessionLease::acquire(&fixture.root, "candidate", "test").unwrap();
    candidate.save(&saved).unwrap();
    let old_bytes = fs::read(fixture.root.join("sessions/owned.json")).unwrap();
    let mut controller = handle.claim_controller().unwrap();
    assert!(
        controller
            .send(OwnerAction::Resume {
                session_id: "candidate".into()
            })
            .is_err()
    );
    assert_eq!(handle.snapshot().unwrap().session_id, "owned");
    assert_eq!(
        fs::read(fixture.root.join("sessions/owned.json")).unwrap(),
        old_bytes
    );
    assert!(SessionLease::acquire(&fixture.root, "owned", "test").is_err());
    assert_eq!(fixture.calls().len(), 0);
    drop(candidate);
    controller
        .send(OwnerAction::Resume {
            session_id: "candidate".into(),
        })
        .unwrap();
    let snapshot = handle.snapshot().unwrap();
    assert_eq!(snapshot.session_id, "candidate");
    assert_eq!(snapshot.turns, 7);
    assert_eq!(snapshot.effort, saved.effort);
    assert!(SessionLease::acquire(&fixture.root, "candidate", "test").is_err());
    assert!(SessionLease::acquire(&fixture.root, "owned", "test").is_ok());
    controller
        .send(OwnerAction::Prompt {
            request_id: "resumed-prompt".into(),
            text: "continue candidate".into(),
        })
        .unwrap();
    wait_done(&handle);
    assert_eq!(fixture.calls().len(), 1);
    assert_eq!(fixture.calls()[0]["reasoning_effort"], "high");
    let persisted = sessions::load_session(&fixture.root, "candidate").unwrap();
    assert_eq!(persisted.turns, 8);
    assert_eq!(persisted.effort, saved.effort);
    assert_eq!(
        fs::read(fixture.root.join("sessions/owned.json")).unwrap(),
        old_bytes
    );
    runtime.shutdown().unwrap();
}

#[allow(unsafe_code)]
fn saturate_backlog(
    listener: &std::os::unix::net::UnixListener,
    socket: &std::path::Path,
) -> Vec<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: adjust only this fixture's owned listening socket to a known
    // small queue; the platform's standard-library default may be thousands.
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
    let bytes = socket.as_os_str().as_bytes();
    // SAFETY: the initialized local sockaddr has a bounded terminated path.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    assert!(bytes.len() < address.sun_path.len());
    address.sun_family = libc::AF_UNIX as _;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    let mut connections = vec![];
    for _ in 0..16 {
        // SAFETY: transfer each fresh valid socket once to its OwnedFd guard.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        assert!(raw >= 0);
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        // SAFETY: the owned socket and local bounded sockaddr are valid.
        if unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                std::mem::size_of_val(&address) as _,
            )
        } == 0
        {
            connections.push(fd);
            continue;
        }
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        assert!(!connections.is_empty());
        return connections;
    }
    panic!("listener backlog did not reach saturation");
}

#[test]
fn saturated_endpoint_connect_and_stale_probe_refuse_under_independent_watchdog() {
    let fixture = Fixture::new();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(fixture.socket().parent().unwrap())
        .unwrap();
    let listener = std::os::unix::net::UnixListener::bind(fixture.socket()).unwrap();
    fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o600)).unwrap();
    let metadata = fs::metadata(fixture.socket()).unwrap();
    let _connections = saturate_backlog(&listener, &fixture.socket());
    for action in ["client", "probe"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "daemon_child", "--nocapture"])
            .env("ORBIT_OWNER_CHILD_HOME", &fixture.root)
            .env("ORBIT_OWNER_SOCKET_CHECK", action)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(4);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{action} exceeded independent four-second watchdog");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "{action} failed: {:?}",
            child.wait_with_output().unwrap()
        );
        let current = fs::metadata(fixture.socket()).unwrap();
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (current.dev(), current.ino())
        );
        assert_eq!(fixture.calls().len(), 0);
    }
    drop(listener);
}

#[test]
fn display_preserves_short_prefix_but_redacts_later_real_same_family_tokens() {
    let fixture = Fixture::new();
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    fs::write(
        fixture.root.join("mode.json"),
        serde_json::json!({"chunks":["ghp_short ",secret," ",secret,"\n"]}).to_string(),
    )
    .unwrap();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let subscription = handle.subscribe(None).unwrap();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "short-prefix".into(),
            text: "show scanned reply".into(),
        })
        .unwrap();
    let mut visible = String::new();
    loop {
        let event = subscription.recv_timeout(Duration::from_secs(5)).unwrap();
        visible.push_str(&serde_json::to_string(&event).unwrap());
        if event.kind == "request_finished" {
            break;
        }
    }
    assert!(visible.contains("ghp_short"));
    assert!(visible.contains("redacted"));
    assert!(!visible.contains(secret));
    let snapshot = serde_json::to_string(&handle.snapshot().unwrap()).unwrap();
    assert!(snapshot.contains("ghp_short"));
    assert!(!snapshot.contains(secret));
    assert_eq!(fixture.calls().len(), 1);
    runtime.shutdown().unwrap();
}

#[test]
fn streamed_assignment_and_pem_context_is_scanned_before_any_visible_event() {
    let fixture = Fixture::new();
    let secret = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgH";
    fs::write(fixture.root.join("mode.json"),serde_json::json!({"pause_after":0,"chunks":["ordinary first line\nAPI_","KEY","= ",secret,"\n-----BEGIN RSA PRIVATE KEY-----\n","MIIEprivatebody\n","-----END RSA PRIVATE KEY-----\n","ordinary final line"]}).to_string()).unwrap();
    let runtime = fixture.start();
    let handle = runtime.handle();
    let subscription = handle.subscribe(None).unwrap();
    let mut controller = handle.claim_controller().unwrap();
    controller
        .send(OwnerAction::Prompt {
            request_id: "assignment-context".into(),
            text: "show context-aware reply".into(),
        })
        .unwrap();
    let mut visible = String::new();
    let mut text = String::new();
    let mut first_line = false;
    loop {
        let event = subscription.recv_timeout(Duration::from_secs(5)).unwrap();
        let encoded = serde_json::to_string(&event).unwrap();
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("MIIEprivatebody"));
        visible.push_str(&encoded);
        if event.kind == "text_delta" {
            text.push_str(event.payload["text"].as_str().unwrap());
            if !first_line && text.contains("ordinary first line") {
                assert_eq!(handle.snapshot().unwrap().state, TurnState::Running);
                first_line = true;
                fs::write(fixture.root.join("stream_release"), b"continue").unwrap();
            }
        }
        if event.kind == "request_finished" {
            break;
        }
    }
    assert!(first_line);
    assert!(visible.contains("redacted"));
    assert!(text.contains("ordinary first line"));
    assert!(text.contains("ordinary final line"));
    let snapshot = serde_json::to_string(&handle.snapshot().unwrap()).unwrap();
    assert!(!snapshot.contains(secret));
    assert!(!snapshot.contains("MIIEprivatebody"));
    assert_eq!(fixture.calls().len(), 1);
    runtime.shutdown().unwrap();
}

#[test]
fn dropped_line_pem_markers_preserve_context_across_limit_and_delta_boundaries() {
    let body = "MIIEoverflowBodySyntheticBase64abcdefgh0123456789";
    for (name, prefix, header) in [
        (
            "after-limit",
            "x".repeat(16 * 1024 + 257),
            vec!["-----BE", "GIN RSA PRI", "VATE KEY-----\n"],
        ),
        (
            "across-limit",
            "x".repeat(16 * 1024 - 5),
            vec!["-----B", "EGIN RSA PRI", "VATE KEY-----\n"],
        ),
    ] {
        let fixture = Fixture::new();
        let mut chunks = vec!["ordinary before\n".to_owned(), prefix];
        chunks.extend(header.into_iter().map(str::to_owned));
        chunks.push(format!("{body}\n"));
        chunks.push("-----END RSA PRIVATE KEY-----\nordinary after".into());
        fs::write(
            fixture.root.join("mode.json"),
            serde_json::json!({"chunks":chunks}).to_string(),
        )
        .unwrap();
        let runtime = fixture.start();
        let handle = runtime.handle();
        let cursor = handle.snapshot().unwrap().cursor;
        let subscription = handle.subscribe(None).unwrap();
        let mut controller = handle.claim_controller().unwrap();
        controller
            .send(OwnerAction::Prompt {
                request_id: name.into(),
                text: "display bounded private-key context".into(),
            })
            .unwrap();
        let mut live = String::new();
        loop {
            let event = subscription.recv_timeout(Duration::from_secs(5)).unwrap();
            let encoded = serde_json::to_string(&event).unwrap();
            assert!(!encoded.contains(body), "{name} leaked in {}", event.kind);
            assert!(
                !serde_json::to_string(&handle.snapshot().unwrap())
                    .unwrap()
                    .contains(body)
            );
            if event.kind == "text_delta" {
                live.push_str(event.payload["text"].as_str().unwrap());
            }
            if event.kind == "request_finished" {
                break;
            }
        }
        assert!(live.contains("oversized display line"));
        assert!(live.contains("ordinary before"));
        assert!(live.contains("ordinary after"));
        let recovery = handle.subscribe(Some(&cursor)).unwrap().recovery;
        assert!(!serde_json::to_string(&recovery).unwrap().contains(body));
        let mut plain = vec![];
        attach::render_recovery(&recovery, &mut plain).unwrap();
        attach::render_snapshot(&handle.snapshot().unwrap(), &mut plain).unwrap();
        let plain = String::from_utf8(plain).unwrap();
        assert!(!plain.contains(body));
        assert!(plain.contains("ordinary after"));
        assert_eq!(fixture.calls().len(), 1);
        runtime.shutdown().unwrap();
    }
}
