#![cfg(unix)]

pub use orbit_cli::{
    apply_effort_setting, checked_model_turn, config, context_window_for_turn, effort_status,
    model_limits, parse_effort_setting, phase_routing, provider_policies, resolve_selected_model,
    route_command, session_accounting, session_config, sessions, tool_runtime, tools,
    try_engine_turn_config, try_phase_turn_config, try_role_turn_config,
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
        let turn = session_config::SessionTurnConfig {
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
    let turn = session_config::SessionTurnConfig {
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
    let session_path = fixture.root.join("sessions/owned.json");
    let claims_path = fixture.root.join("sessions/.requests/owned.json");
    let accounting_path = fixture.root.join("context-history/owned/accounting.json");
    let session_bytes = fs::read(&session_path).unwrap();
    let claims_bytes = fs::read(&claims_path).unwrap();
    let accounting_bytes = fs::read(&accounting_path).unwrap();
    let (inspection, saved) =
        SessionLease::acquire_and_load(&fixture.root, "owned", "crash-inspection").unwrap();
    assert_eq!(
        saved.transcript,
        vec![orbit_engine::user_message("crash prompt")]
    );
    assert_eq!(
        (
            saved.input_tokens,
            saved.output_tokens,
            saved.cost_microcents
        ),
        (0, 0, 0)
    );
    assert_eq!(saved.accounting_watermark.as_ref().unwrap().revision, 0);
    assert_eq!(
        saved
            .accounting_watermark
            .as_ref()
            .unwrap()
            .full_cost_status,
        session_accounting::FullCostStatus::UnknownLegacy
    );
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
    assert_eq!(claims["schema"], "orbit.owner.requests/v1");
    assert_eq!(claims["session_id"], "owned");
    assert_eq!(claims["current_request"], "crash-key");
    assert_eq!(claims["requests"].as_object().unwrap().len(), 1);
    assert!(matches!(
        claims["requests"]["crash-key"]["state"].as_str(),
        Some("accepted" | "running")
    ));
    assert_eq!(
        claims["requests"]["crash-key"]["payload_digest"],
        format!(
            "{:x}",
            <sha2::Sha256 as sha2::Digest>::digest(b"crash prompt")
        )
    );
    let journal =
        orbit_cli::context_history::context_journal(&fixture.root, "owned", None).unwrap();
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.owner_session_id, "owned");
    assert_eq!(checkpoint.child_id, None);
    assert_eq!(checkpoint.revision.0, 1);
    assert_eq!(
        checkpoint.totals.knownness,
        orbit_engine::AccountingKnownness::UnknownLegacy
    );
    assert_eq!(
        (
            checkpoint.totals.ordinary.input_tokens,
            checkpoint.totals.ordinary.output_tokens
        ),
        (0, 0)
    );
    assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
    assert_eq!(
        checkpoint.known_priced_subtotals,
        Some(orbit_engine::KnownPricedSubtotals::known_zero())
    );
    assert!(checkpoint.last_settlement.is_none());
    let pending = checkpoint.pending.as_ref().unwrap();
    assert!(
        !pending.uncertain,
        "abrupt death cannot fabricate a settlement receipt"
    );
    assert_eq!(pending.intent.owner_session_id, "owned");
    assert_eq!(pending.intent.child_id, None);
    assert_eq!(
        pending.intent.purpose,
        orbit_engine::AttemptPurpose::Ordinary
    );
    let ids: Vec<_> = orbit_ledger::verify_ledger(&fixture.root.join("ledger"))
        .unwrap()
        .0
        .into_iter()
        .filter_map(|record| match record.record.event {
            orbit_ledger::LedgerEvent::EgressIntent(event) => {
                assert_eq!(event.session_id, "owned");
                Some(event.decision_id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 1);
    assert_eq!(pending.reference.request_id, ids[0]);
    let stored: serde_json::Value = serde_json::from_slice(&accounting_bytes).unwrap();
    assert_eq!(stored["entries"].as_array().unwrap().len(), 1);
    assert!(stored["entries"][0]["pending"]["uncertain_receipt"].is_null());
    drop(inspection);
    for _ in 0..2 {
        let lease = SessionLease::acquire(&fixture.root, "owned", "crash-restart-refusal").unwrap();
        let refusal = match OwnerRuntime::start(fixture.config.clone(), lease) {
            Err(error) => error,
            Ok(runtime) => {
                runtime.shutdown().unwrap();
                panic!("pending crash work unexpectedly admitted a new owner");
            }
        };
        match refusal {
            daemon::OwnerError::Accounting(session_accounting::AccountingError::InvalidState(
                reason,
            )) => assert_eq!(
                reason,
                "a pending uncertain request requires explicit inspection before admission"
            ),
            other => panic!("wrong crash accounting refusal: {other:?}"),
        }
        assert_eq!(fs::read(&session_path).unwrap(), session_bytes);
        assert_eq!(fs::read(&claims_path).unwrap(), claims_bytes);
        assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
        assert_eq!(journal.accounting_checkpoint().unwrap(), checkpoint);
        assert_eq!(fixture.calls().len(), 1);
    }
    let released = SessionLease::acquire(&fixture.root, "owned", "crash-refusal-released").unwrap();
    drop(released);
    // Metadata-only inspection/recovery of this pending owner remains separate.
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
        if snapshot.state == TurnState::Interrupted
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
    let session_path = fixture.root.join("sessions/owned.json");
    let claims_path = fixture.root.join("sessions/.requests/owned.json");
    let accounting_path = fixture.root.join("context-history/owned/accounting.json");
    let journal =
        orbit_cli::context_history::context_journal(&fixture.root, "owned", None).unwrap();
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.owner_session_id, "owned");
    assert_eq!(checkpoint.child_id, None);
    assert_eq!(checkpoint.revision.0, 2);
    assert_eq!(
        checkpoint.totals.knownness,
        orbit_engine::AccountingKnownness::Uncertain
    );
    assert!(checkpoint.pending.as_ref().unwrap().uncertain);
    assert_eq!(
        (
            checkpoint.totals.ordinary.input_tokens,
            checkpoint.totals.ordinary.output_tokens
        ),
        (0, 0)
    );
    assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
    assert_eq!(
        checkpoint.known_priced_subtotals,
        Some(orbit_engine::KnownPricedSubtotals::known_zero())
    );
    let saved = sessions::load_session(&fixture.root, "owned").unwrap();
    assert_eq!(
        saved.transcript,
        vec![orbit_engine::user_message("accepted but lost response")]
    );
    assert_eq!(
        saved
            .accounting_watermark
            .as_ref()
            .unwrap()
            .full_cost_status,
        session_accounting::FullCostStatus::Uncertain
    );
    let session_bytes = fs::read(&session_path).unwrap();
    let claims_bytes = fs::read(&claims_path).unwrap();
    let accounting_bytes = fs::read(&accounting_path).unwrap();
    let duplicate = controller.send(prompt()).unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.state, "unknown");
    assert_eq!(fixture.calls().len(), 1);
    drop(controller);
    runtime.shutdown().unwrap();
    assert_eq!(fs::read(&session_path).unwrap(), session_bytes);
    assert_eq!(fs::read(&claims_path).unwrap(), claims_bytes);
    assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
    let lease = SessionLease::acquire(&fixture.root, "owned", "lost-restart-refusal").unwrap();
    let refusal = match OwnerRuntime::start(fixture.config.clone(), lease) {
        Err(error) => error,
        Ok(runtime) => {
            runtime.shutdown().unwrap();
            panic!("pending lost response unexpectedly admitted a new owner");
        }
    };
    match refusal {
        daemon::OwnerError::Accounting(session_accounting::AccountingError::InvalidState(
            reason,
        )) => assert_eq!(
            reason,
            "a pending uncertain request requires explicit inspection before admission"
        ),
        other => panic!("wrong lost-response accounting refusal: {other:?}"),
    }
    let released = SessionLease::acquire(&fixture.root, "owned", "lost-refusal-released").unwrap();
    drop(released);
    assert_eq!(fs::read(&session_path).unwrap(), session_bytes);
    assert_eq!(fs::read(&claims_path).unwrap(), claims_bytes);
    assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
    assert_eq!(journal.accounting_checkpoint().unwrap(), checkpoint);
    assert_eq!(fixture.calls().len(), 1);
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
    let source = sessions::load_session(&fixture.root, "owned").unwrap();
    let permission = handle.snapshot().unwrap().permission_mode;
    let source_journal =
        orbit_cli::context_history::context_journal(&fixture.root, "owned", None).unwrap();
    let source_checkpoint = source_journal.accounting_checkpoint().unwrap();
    let source_accounting_path = fixture.root.join("context-history/owned/accounting.json");
    let source_accounting_bytes = fs::read(&source_accounting_path).unwrap();
    let mut saved = sessions::SessionFile::from_chat(
        "candidate",
        &source.model,
        &source.gate,
        &source.provider,
        &source.transcript,
        7,
        source.input_tokens,
        source.output_tokens,
        source.cost_microcents,
    )
    .with_effort(Some(orbit_cli::parse_effort_setting("high").unwrap()));
    saved.workspace = source.workspace.clone();
    saved.selection_origin = source.selection_origin;
    assert!(saved.accounting_watermark.is_none());
    let candidate = SessionLease::acquire(&fixture.root, "candidate", "test").unwrap();
    candidate.save(&saved).unwrap();
    let old_bytes = fs::read(fixture.root.join("sessions/owned.json")).unwrap();
    let candidate_path = fixture.root.join("sessions/candidate.json");
    let candidate_bytes = fs::read(&candidate_path).unwrap();
    let candidate_accounting_path = fixture
        .root
        .join("context-history/candidate/accounting.json");
    assert!(!candidate_accounting_path.exists());
    let before_swap = serde_json::to_value(handle.snapshot().unwrap()).unwrap();
    let mut controller = handle.claim_controller().unwrap();
    match controller.send(OwnerAction::Resume {
        session_id: "candidate".into(),
    }) {
        Err(daemon::OwnerError::Storage(sessions::SessionLeaseError::Busy { session_id })) => {
            assert_eq!(session_id, "candidate")
        }
        other => panic!("held candidate must refuse Busy before swap: {other:?}"),
    }
    assert_eq!(
        serde_json::to_value(handle.snapshot().unwrap()).unwrap(),
        before_swap
    );
    assert_eq!(fs::read(&candidate_path).unwrap(), candidate_bytes);
    assert!(!candidate_accounting_path.exists());
    assert_eq!(
        source_journal.accounting_checkpoint().unwrap(),
        source_checkpoint
    );
    assert_eq!(
        fs::read(&source_accounting_path).unwrap(),
        source_accounting_bytes
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
    assert_eq!(snapshot.provider, saved.provider);
    assert_eq!(snapshot.model, saved.model);
    assert_eq!(snapshot.selection_origin, source.selection_origin.unwrap());
    assert_eq!(snapshot.permission_mode, permission);
    assert_eq!(
        (
            snapshot.input_tokens,
            snapshot.output_tokens,
            snapshot.cost_microcents
        ),
        (
            saved.input_tokens,
            saved.output_tokens,
            saved.cost_microcents
        )
    );
    let candidate_journal =
        orbit_cli::context_history::context_journal(&fixture.root, "candidate", None).unwrap();
    let anchored = candidate_journal.accounting_checkpoint().unwrap();
    assert_eq!(anchored.owner_session_id, "candidate");
    assert_eq!(anchored.child_id, None);
    assert_eq!(
        anchored.baseline,
        orbit_engine::AccountingBaseline::UnknownLegacy
    );
    assert_eq!(anchored.revision.0, 0);
    let candidate_saved = sessions::load_session(&fixture.root, "candidate").unwrap();
    assert_eq!(candidate_saved.transcript, saved.transcript);
    assert_eq!(candidate_saved.selection_origin, saved.selection_origin);
    assert_eq!(
        candidate_saved
            .accounting_watermark
            .as_ref()
            .unwrap()
            .owner_session_id,
        "candidate"
    );
    assert_eq!(
        candidate_saved
            .accounting_watermark
            .as_ref()
            .unwrap()
            .full_cost_status,
        session_accounting::FullCostStatus::UnknownLegacy
    );
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
    assert_eq!(persisted.model, saved.model);
    assert_eq!(persisted.provider, saved.provider);
    assert_eq!(persisted.gate, saved.gate);
    assert_eq!(persisted.selection_origin, saved.selection_origin);
    assert_eq!(
        (
            persisted.input_tokens,
            persisted.output_tokens,
            persisted.cost_microcents
        ),
        (
            saved.input_tokens.checked_add(2).unwrap(),
            saved.output_tokens.checked_add(3).unwrap(),
            saved.cost_microcents
        )
    );
    let checkpoint = candidate_journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.owner_session_id, "candidate");
    assert_eq!(checkpoint.child_id, None);
    assert_eq!(
        checkpoint.baseline,
        orbit_engine::AccountingBaseline::UnknownLegacy
    );
    assert_eq!(checkpoint.revision.0, 2);
    assert!(checkpoint.pending.is_none());
    assert_eq!(
        persisted
            .accounting_watermark
            .as_ref()
            .unwrap()
            .owner_session_id,
        "candidate"
    );
    assert_eq!(
        source_journal.accounting_checkpoint().unwrap(),
        source_checkpoint
    );
    assert_eq!(
        fs::read(&source_accounting_path).unwrap(),
        source_accounting_bytes
    );
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

#[cfg(target_os = "linux")]
mod manual_baseline_support {
    use super::manual_baseline_owner_api as owner_api;
    use serde_json::{Value, json};
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    pub(super) fn dispatch_isolated(exact: &str) -> bool {
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

    pub(super) fn require_private_system_fixture() {
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

    pub(super) struct LegacySeed {
        pub journal_path: PathBuf,
        pub journal_bytes: Vec<u8>,
        pub saved_path: PathBuf,
    }

    pub(super) fn seed_legacy(home: &Path, config: &owner_api::OwnerConfig) -> LegacySeed {
        use orbit_cli::context_history::context_journal;
        use orbit_cli::session_accounting::{RootOrigin, prepare_root};
        use orbit_cli::sessions::{SessionFile, SessionLease};
        use orbit_engine::{
            AccountingBaseline, AccountingKnownness, AccountingTotals, AttemptIntent,
            AttemptPurpose, RequestAccountingReceipt,
        };
        let id = &config.turn.session_id;
        let lease = SessionLease::acquire(home, id, "manual-baseline-seed").unwrap();
        let mut saved = SessionFile::from_chat(
            id,
            &config.turn.model,
            &config.turn.gate,
            &config.turn.provider_id,
            &[
                orbit_engine::user_message("legacy retained original"),
                orbit_engine::assistant_message("legacy retained answer"),
            ],
            3,
            100,
            40,
            60,
        );
        saved.bind_workspace(&config.working_dir).unwrap();
        lease.save(&saved).unwrap();
        let accounting = prepare_root(&lease, &mut saved, RootOrigin::RestoredOrLegacy).unwrap();
        let journal = context_journal(home, id, None).unwrap();
        assert_eq!(
            journal.accounting_checkpoint().unwrap().baseline,
            AccountingBaseline::UnknownLegacy
        );
        let selected = orbit_cli::try_engine_turn_config(
            home,
            &config.turn.provider_id,
            &config.turn.gate,
            &config.turn.model,
            None,
            None,
        )
        .unwrap();
        for (purpose, input, output, cost, request_id) in [
            (AttemptPurpose::Ordinary, 7, 2, 5, "manual-seed-ordinary"),
            (AttemptPurpose::Chunk, 3, 1, 4, "manual-seed-chunk"),
        ] {
            let intent = AttemptIntent {
                owner_session_id: id.clone(),
                child_id: None,
                request_id: request_id.into(),
                purpose,
                budget: orbit_engine::context_budget::BudgetIdentity::for_config(
                    &selected,
                    "manual-baseline",
                    "manual-baseline",
                )
                .unwrap(),
            };
            let reference = journal
                .begin_attempt(journal.accounting_checkpoint().unwrap().revision, &intent)
                .unwrap();
            journal
                .settle_attempt(
                    &reference,
                    &RequestAccountingReceipt {
                        request_id: request_id.into(),
                        purpose,
                        totals: AccountingTotals {
                            input_tokens: input,
                            output_tokens: output,
                            cost_microcents: Some(cost),
                        },
                        usage: Some(orbit_adapter::types::ProviderUsage {
                            input_tokens: input,
                            output_tokens: output,
                            ..Default::default()
                        }),
                        knownness: AccountingKnownness::Known,
                        completed: true,
                    },
                )
                .unwrap();
            if purpose == AttemptPurpose::Ordinary {
                accounting.persist(&lease, &mut saved).unwrap();
            }
        }
        // One settlement is saved, the other is journal-only catch-up. Startup
        // must derive the fixed legacy prefix, without doubling either bill.
        assert_eq!(
            lease.load().unwrap().accounting_watermark.unwrap().revision,
            2
        );
        assert_eq!(journal.accounting_checkpoint().unwrap().revision.0, 4);
        let requests = home.join("sessions/.requests");
        fs::DirBuilder::new().mode(0o700).create(&requests).unwrap();
        let old = json!({
            "schema":"orbit.owner.requests/v1", "session_id":id,
            "current_request":"old-prompt",
            "requests":{"old-prompt":{
                "payload_digest":"0123456789abcdef".repeat(4), "state":"completed"
            }}
        });
        let old_path = requests.join(format!("{id}.json"));
        fs::write(&old_path, serde_json::to_vec(&old).unwrap()).unwrap();
        fs::set_permissions(&old_path, fs::Permissions::from_mode(0o600)).unwrap();
        let journal_path = home
            .join("context-history")
            .join(id)
            .join("accounting.json");
        let journal_bytes = fs::read(&journal_path).unwrap();
        drop(journal);
        drop(accounting);
        drop(lease);
        LegacySeed {
            journal_path,
            journal_bytes,
            saved_path: home.join("sessions").join(format!("{id}.json")),
        }
    }

    pub(super) fn assert_legacy_controls(snapshot: &Value) {
        assert_eq!(snapshot["turns"], 3);
        assert_eq!(snapshot["input_tokens"], 110);
        assert_eq!(snapshot["output_tokens"], 43);
        assert_eq!(snapshot["cost_microcents"], 69);
        assert_eq!(snapshot["requests"]["old-prompt"]["state"], "completed");
        assert_eq!(
            snapshot["requests"]["old-prompt"]["payload_digest"],
            "0123456789abcdef".repeat(4),
        );
        // Old record has no action-kind field; its new default must remain
        // omitted. This assertion requires no RequestKind Rust API.
        assert!(snapshot["requests"]["old-prompt"].get("kind").is_none());
    }

    pub(super) fn assert_cold_accounting(snapshot: &Value) {
        let accounting = snapshot
            .get("accounting")
            .and_then(Value::as_object)
            .expect("cold owner snapshot must retain non-content full-cost certainty");
        assert_eq!(accounting.len(), 2);
        assert_eq!(accounting.get("revision"), Some(&json!(4)));
        assert_eq!(
            accounting.get("full_cost_status"),
            Some(&json!("unknown_legacy"))
        );
        assert!(
            !serde_json::to_string(accounting)
                .unwrap()
                .contains("legacy retained")
        );
    }

    pub(super) fn assert_saved_legacy(home: &Path, id: &str, seed: &LegacySeed) {
        use orbit_cli::session_accounting::FullCostStatus;
        let saved = orbit_cli::sessions::load_session(home, id).unwrap();
        assert_eq!(
            (
                saved.turns,
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (3, 110, 43, 69)
        );
        let watermark = saved.accounting_watermark.unwrap();
        assert_eq!(watermark.revision, 4);
        assert_eq!(watermark.full_cost_status, FullCostStatus::UnknownLegacy);
        assert_eq!(
            (
                watermark.known_ordinary_microcents,
                watermark.known_housekeeping_microcents
            ),
            (5, 4)
        );
        assert_eq!(fs::read(&seed.journal_path).unwrap(), seed.journal_bytes);
        assert!(seed.saved_path.is_file());
    }

    pub(super) fn terminal(
        handle: &owner_api::OwnerHandle,
        request_id: &str,
    ) -> Option<owner_api::OwnerSnapshot> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = handle.snapshot().unwrap();
            if snapshot.requests.get(request_id).is_some_and(|record| {
                !matches!(
                    record.state,
                    owner_api::RequestState::Accepted | owner_api::RequestState::Running
                )
            }) {
                return Some(snapshot);
            }
            if Instant::now() >= until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn missing_accounting_control(snapshot: &Value) {
        let mut legacy = snapshot.clone();
        legacy.as_object_mut().unwrap().remove("accounting");
        let decoded: owner_api::OwnerSnapshot = serde_json::from_value(legacy).unwrap();
        let encoded = serde_json::to_value(decoded).unwrap();
        assert!(
            encoded.get("accounting").is_none_or(Value::is_null),
            "missing peer metadata cannot become Known accounting"
        );
    }
}

#[cfg(target_os = "linux")]
use self::daemon as manual_baseline_owner_api;

#[cfg(target_os = "linux")]
mod manual_owner_baseline {
    use super::manual_baseline_support::*;
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_unix_compact_accepts_no_history_without_prompt_turn_or_post() {
        if !dispatch_isolated(
            "manual_owner_baseline::raw_unix_compact_accepts_no_history_without_prompt_turn_or_post",
        ) {
            return;
        }
        require_private_system_fixture();
        let fixture = Fixture::new();
        let runtime = fixture.start();
        let handle = runtime.handle();
        let before = sessions::load_session(&fixture.root, "owned").unwrap();
        let journal =
            orbit_cli::context_history::context_journal(&fixture.root, "owned", None).unwrap();
        let before_revision = journal.accounting_checkpoint().unwrap().revision.0;
        let server = UnixServer::bind(&fixture.socket(), handle.clone()).unwrap();
        let stop = orbit_provider_http::CancelToken::new();
        let serving_stop = stop.clone();
        let serving = std::thread::spawn(move || server.run(&serving_stop));
        let socket = daemon::local_connect(&fixture.socket()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut stream = BufReader::new(socket);
        let hello = rpc(&mut stream, json!({"type":"hello","controlling":true}));
        let unknown = rpc(
            &mut stream,
            json!({"type":"action","action":{"type":"still_unknown_manual_action"}}),
        );
        let reply = rpc(
            &mut stream,
            json!({"type":"action","action":{
                "type":"compact","request_id":"manual-empty"
            }}),
        );
        let ended = if reply["ok"] == true {
            terminal(&handle, "manual-empty")
        } else {
            None
        };
        let duplicate = if ended.is_some() {
            Some(rpc(
                &mut stream,
                json!({"type":"action","action":{
                    "type":"compact","request_id":"manual-empty"
                }}),
            ))
        } else {
            None
        };
        let snapshot = serde_json::to_value(handle.snapshot().unwrap()).unwrap();
        let saved = sessions::load_session(&fixture.root, "owned").unwrap();
        let after_revision = journal.accounting_checkpoint().unwrap().revision.0;
        drop(stream);
        stop.cancel();
        serving.join().unwrap().unwrap();
        runtime.shutdown().unwrap();
        let calls = fixture.calls();
        // All assertions on the desired new behavior follow owned cleanup.
        assert_eq!(hello["ok"], true);
        assert_eq!(unknown["ok"], false);
        assert!(
            calls.is_empty(),
            "manual no-op must not enter an ordinary provider turn"
        );
        assert_eq!(before.turns, 0);
        assert!(before.transcript.is_empty());
        assert_eq!(saved.turns, 0);
        assert!(saved.transcript.is_empty());
        assert_eq!(snapshot["turns"], 0);
        assert_eq!(snapshot["messages"], json!([]));
        assert_eq!(after_revision, before_revision);
        assert_eq!(before_revision, 0);
        assert_eq!(
            reply["ok"], true,
            "existing raw Unix action should reach shared manual no-op: {reply}"
        );
        assert_eq!(reply["value"]["request_id"], "manual-empty");
        assert!(
            ended.is_some(),
            "accepted manual action needs a bounded terminal request"
        );
        assert_eq!(snapshot["requests"]["manual-empty"]["state"], "completed");
        let duplicate = duplicate.unwrap();
        assert_eq!(duplicate["ok"], true);
        assert_eq!(duplicate["value"]["duplicate"], true);
    }

    #[test]
    fn legacy_known_subset_survives_cold_expired_and_restarted_owner_snapshots() {
        if !dispatch_isolated(
            "manual_owner_baseline::legacy_known_subset_survives_cold_expired_and_restarted_owner_snapshots",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut fixture = Fixture::new();
        fixture.config.replay_capacity = 1;
        let seed = seed_legacy(&fixture.root, &fixture.config);
        let runtime = fixture.start();
        let handle = runtime.handle();
        let initial = handle.snapshot().unwrap().cursor;
        let cold = serde_json::to_value(handle.subscribe(None).unwrap().recovery).unwrap();
        let live = serde_json::to_value(handle.snapshot().unwrap()).unwrap();
        let mut controller = handle.claim_controller().unwrap();
        controller.send(OwnerAction::Effort).unwrap();
        controller.send(OwnerAction::Effort).unwrap();
        let expired =
            serde_json::to_value(handle.subscribe(Some(&initial)).unwrap().recovery).unwrap();
        let first_saved = fs::read(&seed.saved_path).unwrap();
        drop(controller);
        runtime.shutdown().unwrap();
        let runtime = fixture.start();
        let restarted =
            serde_json::to_value(runtime.handle().subscribe(None).unwrap().recovery).unwrap();
        let second_saved = fs::read(&seed.saved_path).unwrap();
        runtime.shutdown().unwrap();
        assert!(fixture.calls().is_empty());
        assert_eq!(cold["events"], json!([]));
        assert_eq!(expired["events"], json!([]));
        assert_eq!(restarted["events"], json!([]));
        for snapshot in [
            &live,
            &cold["snapshot"],
            &expired["snapshot"],
            &restarted["snapshot"],
        ] {
            assert_legacy_controls(snapshot);
            missing_accounting_control(snapshot);
        }
        let first: sessions::SessionFile = serde_json::from_slice(&first_saved).unwrap();
        let second: sessions::SessionFile = serde_json::from_slice(&second_saved).unwrap();
        assert_eq!(
            (
                first.input_tokens,
                first.output_tokens,
                first.cost_microcents
            ),
            (110, 43, 69)
        );
        assert_eq!(
            (
                second.input_tokens,
                second.output_tokens,
                second.cost_microcents
            ),
            (110, 43, 69)
        );
        assert_saved_legacy(&fixture.root, "owned", &seed);
        // Current source reaches these runtime assertions with correct durable
        // numeric controls but omits the proposed metadata from serialization.
        for snapshot in [
            &live,
            &cold["snapshot"],
            &expired["snapshot"],
            &restarted["snapshot"],
        ] {
            assert_cold_accounting(snapshot);
        }
    }
}

#[cfg(target_os = "linux")]
mod manual_owner_capability {
    use super::manual_baseline_owner_api as owner_api;
    use super::manual_baseline_support::*;
    use super::*;
    use serde_json::{Value, json};

    const SUMMARY: &str = "manual captured short summary";
    const MAIN_KEY: &str = "synthetic-manual-owner-main";
    const SUMMARY_KEY: &str = "synthetic-manual-owner-summary";

    fn prepare(f: &mut Fixture) -> Vec<orbit_adapter::types::ChatMessage> {
        use orbit_adapter::provider_credentials::{
            ExpectedRevision, ProviderAuthIdentity, ProviderCredentialStore,
        };
        let base = f.config.turn.gate.clone();
        let main_env = format!("ORBIT_MANUAL_MAIN_{}", ulid::Ulid::new());
        let summary_env = format!("ORBIT_MANUAL_SUMMARY_{}", ulid::Ulid::new());
        assert!(std::env::var_os(&main_env).is_none() && std::env::var_os(&summary_env).is_none());
        let pricing = "input_per_million_microdollars=0\noutput_per_million_microdollars=0\ncache_read_per_million_microdollars=0\ncache_write_per_million_microdollars=0\nreasoning_per_million_microdollars=0\n";
        let config = format!(
            "[[provider]]\nname='manual_main'\nurl={:?}\nenv={main_env:?}\n[[provider.models]]\nid='family/shared-manual'\nmax_output_tokens=73\ncontext_limits={{input_tokens=8192}}\nsupported_efforts=['low','high']\ndefault_effort='low'\n[provider.models.pricing]\n{pricing}request_flat_microdollars=91\n[[provider]]\nname='manual_summary'\nurl={:?}\nenv={summary_env:?}\n[[provider.models]]\nid='family/shared-manual'\nmax_output_tokens=37\ncontext_limits={{input_tokens=65536}}\nsupported_efforts=['medium','high']\ndefault_effort='medium'\n[provider.models.pricing]\n{pricing}request_flat_microdollars=17\n[roles]\nmain='manual_main/family/shared-manual'\ncompaction='manual_summary/family/shared-manual'\n[routing.phases.coding]\ndefault='manual_summary/family/shared-manual'\nhard='manual_summary/family/shared-manual'\n[routing.phase_keywords]\nclear=true\ncoding=['compact']\n",
            format!("{base}/main/v1?binding=main"),
            format!("{base}/summary/v1?binding=summary")
        );
        let config = config.replace(
            "request_flat_microdollars=17\n[roles]",
            "request_flat_microdollars=17\n[provider.models.billing]\nversion=2\ninput_per_million_microdollars=0\noutput_per_million_microdollars=0\ncache_read_per_million_microdollars=0\ncache_write_per_million_microdollars=0\nrequest_flat_microdollars=17\nreasoning_counter_basis='included_in_output'\nreasoning_rate_policy='output_rate'\n[roles]",
        );
        fs::write(f.root.join("providers.toml"), config).unwrap();
        let configured = orbit_cli::config::ProvidersConfig::load(&f.root).unwrap();
        let store = ProviderCredentialStore::new(&f.root).unwrap();
        for (provider, key) in configured.provider.iter().zip([MAIN_KEY, SUMMARY_KEY]) {
            let identity = ProviderAuthIdentity::new(
                &provider.name,
                &provider.kind,
                &provider.url,
                provider.env.as_deref(),
            )
            .unwrap();
            store
                .save(
                    &identity,
                    orbit_adapter::SecretBytes::new(key.as_bytes().to_vec()),
                    ExpectedRevision::Absent,
                )
                .unwrap();
        }
        f.config.turn.model = "family/shared-manual".into();
        f.config.turn.provider_id = "manual_main".into();
        f.config.turn.gate = configured.provider[0].url.clone();
        f.config.turn.effort =
            Some(serde_json::from_value(json!({"mode":"value","value":"high"})).unwrap());
        let mut source = vec![orbit_adapter::types::ChatMessage {
            role: orbit_adapter::types::ChatRole::System,
            ..orbit_engine::user_message("private immutable fixture system")
        }];
        for i in 0..6 {
            source.push(orbit_engine::user_message(format!(
                "OLD-{i}-USER {} OLD-{i}-LATE",
                "u".repeat(12000)
            )));
            source.push(orbit_engine::assistant_message(format!(
                "OLD-{i}-ANSWER {} OLD-{i}-ANSWER-LATE",
                "a".repeat(12000)
            )));
        }
        for i in 0..3 {
            source.push(orbit_engine::user_message(format!("EXACT-TAIL-{i}")));
            source.push(orbit_engine::assistant_message(format!("EXACT-ANSWER-{i}")));
        }
        let lease = SessionLease::acquire(
            &f.root,
            &f.config.turn.session_id,
            "manual-capability-fresh",
        )
        .unwrap();
        let mut seed = sessions::SessionFile::from_chat(
            &f.config.turn.session_id,
            &f.config.turn.model,
            &f.config.turn.gate,
            &f.config.turn.provider_id,
            &source,
            0,
            0,
            0,
            0,
        )
        .with_effort(f.config.turn.effort.clone())
        .with_selection_origin(orbit_cli::phase_routing::SelectionOrigin::Flag);
        seed.bind_workspace(&f.config.working_dir).unwrap();
        let accounting = orbit_cli::session_accounting::prepare_root(
            &lease,
            &mut seed,
            orbit_cli::session_accounting::RootOrigin::FreshCandidate,
        )
        .unwrap();
        assert_eq!(
            accounting.namespace().checkpoint().unwrap().baseline,
            orbit_engine::AccountingBaseline::FreshKnownZero
        );
        seed.turns = 7;
        accounting.persist(&lease, &mut seed).unwrap();
        drop(accounting);
        drop(lease);
        source
    }
    fn mode(f: &Fixture, value: Value) {
        fs::write(
            f.root.join("mode.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }
    fn captured_rows(path: &std::path::Path, limit: u64, allow_missing: bool) -> Vec<Value> {
        use std::io::Read;
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
                return Vec::new();
            }
            Err(error) => panic!("owned provider capture could not be opened: {error}"),
        };
        let mut bytes = Vec::new();
        file.take(limit.checked_add(1).unwrap())
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(
            bytes.len() as u64 <= limit,
            "owned provider capture byte bound"
        );
        let text = std::str::from_utf8(&bytes).unwrap();
        let mut rows = Vec::new();
        for line in text.lines() {
            assert!(rows.len() < 10, "owned provider capture record bound");
            rows.push(serde_json::from_str(line).unwrap());
        }
        rows
    }
    fn bounded_calls(f: &Fixture) -> Vec<Value> {
        captured_rows(&f.root.join("calls.jsonl"), 8 * 1024 * 1024, true)
    }
    fn checkpoint(f: &Fixture) -> orbit_engine::AccountingCheckpoint {
        orbit_cli::context_history::context_journal(&f.root, &f.config.turn.session_id, None)
            .unwrap()
            .accounting_checkpoint()
            .unwrap()
    }
    fn ended(handle: &owner_api::OwnerHandle, id: &str) -> owner_api::OwnerSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = handle.snapshot().unwrap();
            if snapshot.requests.get(id).is_some_and(|record| {
                !matches!(
                    record.state,
                    owner_api::RequestState::Accepted | owner_api::RequestState::Running
                )
            }) && matches!(
                snapshot.state,
                TurnState::Idle | TurnState::Interrupted | TurnState::Stopped
            ) {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "manual request did not reach a bounded terminal state: {snapshot:?}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn assert_active_uncertainty(f: &Fixture, snapshot: &Value) {
        let checkpoint = checkpoint(f);
        assert!(checkpoint.pending.is_some());
        if let Some(accounting) = snapshot.get("accounting").filter(|value| !value.is_null()) {
            assert_eq!(accounting["revision"], checkpoint.revision.0);
            assert_eq!(accounting["full_cost_status"], "uncertain");
        }
        assert_eq!(snapshot["input_tokens"], 0);
        assert_eq!(snapshot["output_tokens"], 0);
        assert_eq!(snapshot["cost_microcents"], 0);
    }
    fn assert_summary_wire(f: &Fixture, count: usize) {
        let calls = bounded_calls(f);
        assert_eq!(calls.len(), count);
        for call in &calls {
            assert_eq!(call["model"], "family/shared-manual");
            assert_eq!(call["max_tokens"], 37);
            assert_eq!(call["reasoning_effort"], "medium");
            assert!(call.get("tools").is_none());
            assert!((serde_json::to_vec(call).unwrap().len() as u64).div_ceil(4) <= 65536);
        }
        let requests = captured_rows(&f.root.join("requests.jsonl"), 64 * 1024, false);
        assert_eq!(requests.len(), count);
        for request in requests {
            assert_eq!(
                request["path"],
                "/summary/v1/chat/completions?binding=summary"
            );
            assert_eq!(
                request["authorization"],
                json!([format!("Bearer {SUMMARY_KEY}")])
            );
            assert_eq!(request["x_api_key"], json!([]));
        }
    }
    fn assert_archive(
        f: &Fixture,
        original: &[orbit_adapter::types::ChatMessage],
    ) -> sessions::SessionFile {
        let saved = sessions::load_session(&f.root, &f.config.turn.session_id).unwrap();
        let directory = f
            .root
            .join("context-history")
            .join(&f.config.turn.session_id)
            .join("archives");
        let entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        let id = entries[0].file_stem().unwrap().to_str().unwrap();
        let recovered = orbit_cli::context_history::load_compaction_source(
            &f.root,
            &f.config.turn.session_id,
            None,
            id,
        )
        .unwrap();
        assert_eq!(recovered, original);
        assert_eq!(saved.transcript[0], original[0]);
        assert_eq!(
            saved.transcript[1],
            orbit_engine::user_message("[Earlier conversation summary: historical data]")
        );
        assert_eq!(
            saved.transcript[2],
            orbit_engine::assistant_message(SUMMARY)
        );
        assert!(original.ends_with(&saved.transcript[3..]));
        assert_eq!(
            &saved.transcript[saved.transcript.len() - 4..],
            &original[original.len() - 4..]
        );
        assert_eq!(saved.turns, 7);
        assert_eq!(saved.model, "family/shared-manual");
        assert_eq!(saved.provider, "manual_main");
        assert_eq!(saved.effort, f.config.turn.effort);
        assert_eq!(
            (
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (2, 3, 17)
        );
        let checkpoint = checkpoint(f);
        assert_eq!(checkpoint.revision.0, 2);
        assert!(checkpoint.pending.is_none());
        assert_eq!(
            checkpoint.totals.ordinary,
            orbit_engine::AccountingTotals::known_zero()
        );
        assert_eq!(checkpoint.totals.housekeeping.input_tokens, 2);
        assert_eq!(checkpoint.totals.housekeeping.output_tokens, 3);
        assert_eq!(checkpoint.totals.housekeeping.cost_microcents, Some(17));
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .housekeeping_microcents,
            17
        );
        saved
    }
    #[test]
    fn paid_manual_applies_once_and_reopens_with_exact_public_original_and_current_cold_bill() {
        if !dispatch_isolated(
            "manual_owner_capability::paid_manual_applies_once_and_reopens_with_exact_public_original_and_current_cold_bill",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut f = Fixture::new();
        let original = prepare(&mut f);
        mode(&f, json!({"reply":SUMMARY}));
        let runtime = f.start();
        let handle = runtime.handle();
        let mut controller = handle.claim_controller().unwrap();
        let ack = controller
            .send(OwnerAction::Compact {
                request_id: "manual-paid".into(),
            })
            .unwrap();
        assert_eq!(ack.request_id.as_deref(), Some("manual-paid"));
        let terminal = ended(&handle, "manual-paid");
        assert_eq!(
            terminal.requests["manual-paid"].state,
            owner_api::RequestState::Completed
        );
        assert_eq!(terminal.turns, 7);
        assert_eq!(terminal.model, "family/shared-manual");
        assert_eq!(terminal.provider, "manual_main");
        assert!(terminal.last_route.is_none());
        let metadata = terminal.accounting.as_ref().unwrap();
        assert_eq!(metadata.revision, 2);
        assert_eq!(
            metadata.full_cost_status,
            session_accounting::FullCostStatus::Known
        );
        let duplicate = controller
            .send(OwnerAction::Compact {
                request_id: "manual-paid".into(),
            })
            .unwrap();
        assert!(duplicate.duplicate);
        assert_summary_wire(&f, 1);
        let saved = assert_archive(&f, &original);
        let encoded = serde_json::to_value(&terminal).unwrap();
        assert_eq!(encoded["requests"]["manual-paid"]["kind"], "compact");
        use sha2::Digest;
        assert_eq!(
            encoded["requests"]["manual-paid"]["payload_digest"],
            format!("{:x}", sha2::Sha256::digest(b"orbit-owner-compact-v1\0"))
        );
        assert!(!encoded.to_string().contains(SUMMARY_KEY));
        let journal_bytes = fs::read(
            f.root
                .join("context-history")
                .join(&f.config.turn.session_id)
                .join("accounting.json"),
        )
        .unwrap();
        let initial = terminal.cursor;
        drop(controller);
        runtime.shutdown().unwrap();
        let runtime = f.start();
        let handle = runtime.handle();
        let cold = handle.subscribe(None).unwrap().recovery.snapshot.unwrap();
        let expired = handle
            .subscribe(Some(&initial))
            .unwrap()
            .recovery
            .snapshot
            .unwrap();
        for snapshot in [cold, expired] {
            assert_eq!(snapshot.turns, 7);
            assert_eq!(
                (
                    snapshot.input_tokens,
                    snapshot.output_tokens,
                    snapshot.cost_microcents
                ),
                (2, 3, 17)
            );
            assert_eq!(snapshot.accounting.as_ref().unwrap().revision, 2);
            assert_eq!(
                snapshot.accounting.as_ref().unwrap().full_cost_status,
                session_accounting::FullCostStatus::Known
            );
        }
        let mut controller = handle.claim_controller().unwrap();
        assert!(
            controller
                .send(OwnerAction::Compact {
                    request_id: "manual-paid".into()
                })
                .unwrap()
                .duplicate
        );
        assert_eq!(
            sessions::load_session(&f.root, &f.config.turn.session_id)
                .unwrap()
                .transcript,
            saved.transcript
        );
        assert_eq!(
            fs::read(
                f.root
                    .join("context-history")
                    .join(&f.config.turn.session_id)
                    .join("accounting.json")
            )
            .unwrap(),
            journal_bytes
        );
        controller.send(OwnerAction::Stop).unwrap();
        assert!(
            controller
                .send(OwnerAction::Compact {
                    request_id: "manual-paid".into()
                })
                .unwrap()
                .duplicate
        );
        assert!(
            controller
                .send(OwnerAction::Compact {
                    request_id: "new-while-stopping".into()
                })
                .is_err()
        );
        drop(controller);
        runtime.shutdown().unwrap();
        assert_summary_wire(&f, 1);
    }

    #[test]
    fn unix_manual_ack_is_early_same_connection_can_cancel_and_duplicate_precedes_busy() {
        if !dispatch_isolated(
            "manual_owner_capability::unix_manual_ack_is_early_same_connection_can_cancel_and_duplicate_precedes_busy",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut f = Fixture::new();
        let original = prepare(&mut f);
        mode(&f, json!({"blocked":true,"reply":SUMMARY}));
        let runtime = f.start();
        let handle = runtime.handle();
        let server = UnixServer::bind(&f.socket(), handle.clone()).unwrap();
        let stop = orbit_provider_http::CancelToken::new();
        let serving_stop = stop.clone();
        let serving = std::thread::spawn(move || server.run(&serving_stop));
        let socket = daemon::local_connect(&f.socket()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut stream = BufReader::new(socket);
        assert_eq!(
            rpc(&mut stream, json!({"type":"hello","controlling":true}))["ok"],
            true
        );
        let start = Instant::now();
        let accepted = rpc(
            &mut stream,
            json!({"type":"action","action":{"type":"compact","request_id":"blocked-manual"}}),
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(accepted["ok"], true);
        assert_eq!(accepted["value"]["state"], "accepted");
        let deadline = Instant::now() + Duration::from_secs(3);
        while bounded_calls(&f).is_empty() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_active_uncertainty(
            &f,
            &serde_json::to_value(handle.snapshot().unwrap()).unwrap(),
        );
        let recovery = handle.subscribe(None).unwrap().recovery;
        assert_active_uncertainty(
            &f,
            &serde_json::to_value(recovery.snapshot.unwrap()).unwrap(),
        );
        let duplicate = rpc(
            &mut stream,
            json!({"type":"action","action":{"type":"compact","request_id":"blocked-manual"}}),
        );
        assert_eq!(duplicate["value"]["duplicate"], true);
        let busy = rpc(
            &mut stream,
            json!({"type":"action","action":{"type":"compact","request_id":"new-busy"}}),
        );
        assert_eq!(busy["ok"], false);
        assert!(!handle.snapshot().unwrap().requests.contains_key("new-busy"));
        let collision = rpc(
            &mut stream,
            json!({"type":"action","action":{"type":"prompt","request_id":"blocked-manual","text":"different kind"}}),
        );
        assert_eq!(collision["ok"], false);
        let cancel_start = Instant::now();
        assert_eq!(
            rpc(
                &mut stream,
                json!({"type":"action","action":{"type":"cancel"}})
            )["ok"],
            true
        );
        assert!(cancel_start.elapsed() < Duration::from_secs(2));
        let terminal = ended(&handle, "blocked-manual");
        assert_eq!(terminal.state, TurnState::Interrupted);
        assert_eq!(
            terminal.requests["blocked-manual"].state,
            owner_api::RequestState::Unknown
        );
        assert_eq!(
            terminal.accounting.as_ref().unwrap().full_cost_status,
            session_accounting::FullCostStatus::Uncertain
        );
        let checkpoint = checkpoint(&f);
        assert_eq!(checkpoint.revision.0, 2);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(checkpoint.totals.housekeeping.cost_microcents, None);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .housekeeping_microcents,
            0
        );
        let saved = sessions::load_session(&f.root, &f.config.turn.session_id).unwrap();
        assert_eq!(saved.transcript, original);
        assert_eq!(saved.turns, 7);
        assert_eq!(
            (
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (0, 0, 0)
        );
        assert!(
            rpc(
                &mut stream,
                json!({"type":"action","action":{"type":"compact","request_id":"blocked-manual"}})
            )["value"]["duplicate"]
                .as_bool()
                .unwrap()
        );
        drop(stream);
        stop.cancel();
        serving.join().unwrap().unwrap();
        runtime.shutdown().unwrap();
        assert_summary_wire(&f, 1);
    }

    #[test]
    fn prompt_digest_and_default_kind_stay_compatible_and_cross_kind_ids_are_refused() {
        if !dispatch_isolated(
            "manual_owner_capability::prompt_digest_and_default_kind_stay_compatible_and_cross_kind_ids_are_refused",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let runtime = f.start();
        let handle = runtime.handle();
        let mut controller = handle.claim_controller().unwrap();
        controller
            .send(OwnerAction::Prompt {
                request_id: "existing-prompt".into(),
                text: "exact original prompt payload".into(),
            })
            .unwrap();
        wait_done(&handle);
        let before = serde_json::to_value(handle.snapshot().unwrap()).unwrap();
        use sha2::Digest;
        assert_eq!(
            before["requests"]["existing-prompt"]["payload_digest"],
            format!(
                "{:x}",
                sha2::Sha256::digest(b"exact original prompt payload")
            )
        );
        assert!(before["requests"]["existing-prompt"].get("kind").is_none());
        assert!(matches!(
            controller.send(OwnerAction::Compact {
                request_id: "existing-prompt".into()
            }),
            Err(owner_api::OwnerError::Invalid(_))
        ));
        controller
            .send(OwnerAction::Compact {
                request_id: "compact-noop".into(),
            })
            .unwrap();
        let after = ended(&handle, "compact-noop");
        assert_eq!(
            after.requests["compact-noop"].kind,
            owner_api::RequestKind::Compact
        );
        assert!(matches!(
            controller.send(OwnerAction::Prompt {
                request_id: "compact-noop".into(),
                text: "different action".into()
            }),
            Err(owner_api::OwnerError::Invalid(_))
        ));
        assert_eq!(
            serde_json::to_value(&after.requests["existing-prompt"]).unwrap(),
            before["requests"]["existing-prompt"]
        );
        drop(controller);
        runtime.shutdown().unwrap();
        assert_eq!(bounded_calls(&f).len(), 1);
    }

    #[test]
    fn invalid_manual_ids_extra_fields_and_read_only_or_foreign_controller_have_zero_effect() {
        if !dispatch_isolated(
            "manual_owner_capability::invalid_manual_ids_extra_fields_and_read_only_or_foreign_controller_have_zero_effect",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let runtime = f.start();
        let handle = runtime.handle();
        let initial = serde_json::to_value(handle.snapshot().unwrap()).unwrap();
        let server = UnixServer::bind(&f.socket(), handle.clone()).unwrap();
        let stop = orbit_provider_http::CancelToken::new();
        let serving_stop = stop.clone();
        let serving = std::thread::spawn(move || server.run(&serving_stop));
        let connect = || {
            let socket = daemon::local_connect(&f.socket()).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            BufReader::new(socket)
        };
        let mut reader = connect();
        assert_eq!(
            rpc(&mut reader, json!({"type":"hello","controlling":false}))["ok"],
            true
        );
        assert_eq!(
            rpc(
                &mut reader,
                json!({"type":"action","action":{"type":"compact","request_id":"read-only"}})
            )["ok"],
            false
        );
        drop(reader);
        let mut controller = connect();
        assert_eq!(
            rpc(&mut controller, json!({"type":"hello","controlling":true}))["ok"],
            true
        );
        let mut foreign = connect();
        assert_eq!(
            rpc(&mut foreign, json!({"type":"hello","controlling":true}))["ok"],
            false
        );
        drop(foreign);
        for action in [
            json!({"type":"compact","request_id":""}),
            json!({"type":"compact","request_id":"x".repeat(129)}),
            json!({"type":"compact","request_id":"spaces invalid"}),
            json!({"type":"compact","request_id":"unicode-λ"}),
            json!({"type":"compact","request_id":"extra","text":"not instructions"}),
            json!({"type":"compact"}),
        ] {
            assert_eq!(
                rpc(&mut controller, json!({"type":"action","action":action}))["ok"],
                false
            );
        }
        let snapshot = serde_json::to_value(handle.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot["requests"], initial["requests"]);
        assert_eq!(snapshot["turns"], initial["turns"]);
        drop(controller);
        stop.cancel();
        serving.join().unwrap().unwrap();
        runtime.shutdown().unwrap();
        assert!(bounded_calls(&f).is_empty());
        assert_eq!(checkpoint(&f).revision.0, 0);
    }

    #[test]
    fn lost_manual_ack_keeps_durable_intent_and_reconnect_reuses_exact_id_without_replay() {
        if !dispatch_isolated(
            "manual_owner_capability::lost_manual_ack_keeps_durable_intent_and_reconnect_reuses_exact_id_without_replay",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut f = Fixture::new();
        let original = prepare(&mut f);
        mode(&f, json!({"reply":SUMMARY}));
        let runtime = f.start();
        let handle = runtime.handle();
        let server = UnixServer::bind(&f.socket(), handle.clone()).unwrap();
        let stop = orbit_provider_http::CancelToken::new();
        let serving_stop = stop.clone();
        let serving = std::thread::spawn(move || server.run(&serving_stop));
        let socket = daemon::local_connect(&f.socket()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut stream = BufReader::new(socket);
        assert_eq!(
            rpc(&mut stream, json!({"type":"hello","controlling":true}))["ok"],
            true
        );
        writeln!(stream.get_mut(),"{}",json!({"version":1,"request":{"type":"action","action":{"type":"compact","request_id":"ack-lost"}}})).unwrap();
        stream.get_mut().flush().unwrap();
        let terminal = ended(&handle, "ack-lost");
        assert_eq!(
            terminal.requests["ack-lost"].state,
            owner_api::RequestState::Completed
        );
        drop(stream);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut controller = loop {
            match handle.claim_controller() {
                Ok(controller) => break controller,
                Err(owner_api::OwnerError::ControllerBusy) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("controller reacquisition: {error}"),
            }
        };
        let duplicate = controller
            .send(OwnerAction::Compact {
                request_id: "ack-lost".into(),
            })
            .unwrap();
        assert!(duplicate.duplicate);
        drop(controller);
        stop.cancel();
        serving.join().unwrap().unwrap();
        runtime.shutdown().unwrap();
        assert_summary_wire(&f, 1);
        assert_archive(&f, &original);
    }

    #[test]
    fn corrupt_checkpoint_after_known_manual_bill_clears_live_certainty_without_rebilling() {
        if !dispatch_isolated(
            "manual_owner_capability::corrupt_checkpoint_after_known_manual_bill_clears_live_certainty_without_rebilling",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut f = Fixture::new();
        prepare(&mut f);
        mode(&f, json!({"reply":SUMMARY}));
        let runtime = f.start();
        let handle = runtime.handle();
        let mut controller = handle.claim_controller().unwrap();
        controller
            .send(OwnerAction::Compact {
                request_id: "known-first".into(),
            })
            .unwrap();
        let known = ended(&handle, "known-first");
        assert_eq!(
            known.accounting.as_ref().unwrap().full_cost_status,
            session_accounting::FullCostStatus::Known
        );
        let saved = sessions::load_session(&f.root, &f.config.turn.session_id).unwrap();
        fs::write(
            f.root
                .join("context-history")
                .join(&f.config.turn.session_id)
                .join("accounting.json"),
            b"{",
        )
        .unwrap();
        controller
            .send(OwnerAction::Compact {
                request_id: "inspection-fails".into(),
            })
            .unwrap();
        let failed = ended(&handle, "inspection-fails");
        assert!(failed.accounting.is_none());
        assert_eq!(
            (
                failed.input_tokens,
                failed.output_tokens,
                failed.cost_microcents
            ),
            (2, 3, 17)
        );
        assert_eq!(
            failed.requests["inspection-fails"].state,
            owner_api::RequestState::Unknown
        );
        assert!(
            handle
                .subscribe(None)
                .unwrap()
                .recovery
                .snapshot
                .unwrap()
                .accounting
                .is_none()
        );
        let after = sessions::load_session(&f.root, &f.config.turn.session_id).unwrap();
        assert_eq!(after.transcript, saved.transcript);
        drop(controller);
        runtime.shutdown().unwrap();
        assert_summary_wire(&f, 1);
    }

    #[test]
    fn cold_unknown_usage_and_unpriced_metadata_remain_distinct_and_catch_up_once() {
        if !dispatch_isolated(
            "manual_owner_capability::cold_unknown_usage_and_unpriced_metadata_remain_distinct_and_catch_up_once",
        ) {
            return;
        }
        require_private_system_fixture();
        for unknown_usage in [false, true] {
            let mut f = Fixture::new();
            prepare(&mut f);
            let journal = orbit_cli::context_history::context_journal(
                &f.root,
                &f.config.turn.session_id,
                None,
            )
            .unwrap();
            let selected = orbit_cli::try_engine_turn_config(
                &f.root,
                &f.config.turn.provider_id,
                &f.config.turn.gate,
                &f.config.turn.model,
                None,
                None,
            )
            .unwrap();
            let intent = orbit_engine::AttemptIntent {
                owner_session_id: f.config.turn.session_id.clone(),
                child_id: None,
                request_id: "metadata-only-settlement".into(),
                purpose: orbit_engine::AttemptPurpose::Chunk,
                budget: orbit_engine::context_budget::BudgetIdentity::for_config(
                    &selected,
                    "manual-metadata",
                    "manual-metadata",
                )
                .unwrap(),
            };
            let reference = journal
                .begin_attempt(journal.accounting_checkpoint().unwrap().revision, &intent)
                .unwrap();
            journal
                .settle_attempt(
                    &reference,
                    &orbit_engine::RequestAccountingReceipt {
                        request_id: intent.request_id.clone(),
                        purpose: intent.purpose,
                        totals: orbit_engine::AccountingTotals {
                            input_tokens: if unknown_usage { 0 } else { 2 },
                            output_tokens: if unknown_usage { 0 } else { 3 },
                            cost_microcents: None,
                        },
                        usage: if unknown_usage {
                            None
                        } else {
                            Some(orbit_adapter::types::ProviderUsage {
                                input_tokens: 2,
                                output_tokens: 3,
                                ..Default::default()
                            })
                        },
                        knownness: if unknown_usage {
                            orbit_engine::AccountingKnownness::UnknownUsage
                        } else {
                            orbit_engine::AccountingKnownness::Known
                        },
                        completed: true,
                    },
                )
                .unwrap();
            let before = journal.accounting_checkpoint().unwrap();
            drop(journal);
            for _ in 0..2 {
                let runtime = f.start();
                let snapshot = runtime
                    .handle()
                    .subscribe(None)
                    .unwrap()
                    .recovery
                    .snapshot
                    .unwrap();
                let accounting = snapshot.accounting.unwrap();
                assert_eq!(accounting.revision, 2);
                assert_eq!(
                    accounting.full_cost_status,
                    if unknown_usage {
                        session_accounting::FullCostStatus::UnknownUsage
                    } else {
                        session_accounting::FullCostStatus::Unpriced
                    }
                );
                assert_eq!(snapshot.cost_microcents, 0);
                assert_eq!(snapshot.input_tokens, if unknown_usage { 0 } else { 2 });
                runtime.shutdown().unwrap();
                assert_eq!(checkpoint(&f), before);
            }
            assert!(bounded_calls(&f).is_empty());
        }
    }

    #[test]
    fn running_prompt_does_not_publish_stale_known_metadata_while_actual_request_is_pending() {
        if !dispatch_isolated(
            "manual_owner_capability::running_prompt_does_not_publish_stale_known_metadata_while_actual_request_is_pending",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        mode(&f, json!({"blocked":true}));
        let runtime = f.start();
        let handle = runtime.handle();
        let mut controller = handle.claim_controller().unwrap();
        controller
            .send(OwnerAction::Prompt {
                request_id: "metadata-held-prompt".into(),
                text: "plain controlled prompt".into(),
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while bounded_calls(&f).is_empty() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_active_uncertainty(
            &f,
            &serde_json::to_value(handle.snapshot().unwrap()).unwrap(),
        );
        assert_active_uncertainty(
            &f,
            &serde_json::to_value(handle.subscribe(None).unwrap().recovery.snapshot.unwrap())
                .unwrap(),
        );
        controller.send(OwnerAction::Cancel).unwrap();
        let terminal = ended(&handle, "metadata-held-prompt");
        assert_eq!(
            terminal.requests["metadata-held-prompt"].state,
            owner_api::RequestState::Unknown
        );
        assert_eq!(
            terminal.accounting.as_ref().unwrap().full_cost_status,
            session_accounting::FullCostStatus::Uncertain
        );
        drop(controller);
        runtime.shutdown().unwrap();
        assert_eq!(bounded_calls(&f).len(), 1);
    }
}

#[cfg(target_os = "linux")]
mod refusal_policy_owner {
    use super::manual_baseline_support::{dispatch_isolated, require_private_system_fixture};
    use super::*;
    use orbit_cli::context_history::{DetailedAccountingInspection, inspect_accounting_detailed};
    use orbit_engine::retry::{DetailedLastSettlement, adapter_identity_digest};
    use orbit_engine::{
        AccountingBaseline, AccountingKnownness, AccountingTotals, KnownPricedSubtotals,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread::{self, JoinHandle};

    const ANSWER: &str = "owned qualified reply";
    const MAX_REQUESTS: usize = 4;
    const MAX_BODY: usize = 4 * 1024 * 1024;

    struct Hold {
        ready: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }
    struct Control {
        ready: mpsc::Receiver<()>,
        release: mpsc::SyncSender<()>,
    }
    impl Control {
        fn wait(&self) {
            self.ready
                .recv_timeout(Duration::from_secs(3))
                .expect("owned body hold");
        }
        fn release(self) {
            self.release.send(()).unwrap();
        }
    }
    struct Reply {
        status: u16,
        body: Vec<u8>,
        hold: Option<Hold>,
        incomplete: bool,
    }
    impl Reply {
        fn reject(status: u16) -> Self {
            Self {
                status,
                body: b"controlled final rejection".to_vec(),
                hold: None,
                incomplete: false,
            }
        }
        fn paid() -> Self {
            Self {
                status: 200,
                body: format!("data: {}\n\ndata: [DONE]\n\n", json!({"choices":[{"index":0,"delta":{"content":ANSWER},"finish_reason":"stop"}],"usage":{"prompt_tokens":14,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":5}}})).into_bytes(),
                hold: None,
                incomplete: false,
            }
        }
        fn partial() -> Self {
            Self {
                status: 200,
                body:
                    b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n"
                        .to_vec(),
                hold: None,
                incomplete: true,
            }
        }
        fn held(mut self) -> (Self, Control) {
            let (ready, observed) = mpsc::sync_channel(1);
            let (release, waiting) = mpsc::sync_channel(1);
            self.hold = Some(Hold {
                ready,
                release: waiting,
            });
            (
                self,
                Control {
                    ready: observed,
                    release,
                },
            )
        }
    }
    #[derive(Clone)]
    struct Capture {
        target: String,
        body: Value,
    }
    struct Wire {
        authority: String,
        captures: Arc<Mutex<Vec<Capture>>>,
        stop: Arc<AtomicBool>,
        barriers: mpsc::Sender<mpsc::SyncSender<usize>>,
        worker: Option<JoinHandle<Result<(), &'static str>>>,
        watchdog_done: Option<mpsc::SyncSender<()>>,
        watchdog: Option<JoinHandle<()>>,
    }
    impl Wire {
        fn new(replies: Vec<Reply>) -> Self {
            assert!(replies.len() <= MAX_REQUESTS);
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let authority = listener.local_addr().unwrap().to_string();
            let captures = Arc::new(Mutex::new(Vec::new()));
            let observed = captures.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let (barriers, requests) = mpsc::channel::<mpsc::SyncSender<usize>>();
            let (watchdog_done, watchdog_rx) = mpsc::sync_channel(1);
            let watchdog = thread::spawn(move || {
                if watchdog_rx.recv_timeout(Duration::from_secs(25))
                    == Err(mpsc::RecvTimeoutError::Timeout)
                {
                    eprintln!("owned refusal owner fixture watchdog");
                    std::process::exit(91);
                }
            });
            let worker = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(20);
                let mut replies = replies.into_iter();
                let mut connections = 0;
                loop {
                    if Instant::now() >= deadline {
                        return Err("listener deadline");
                    }
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            connections += 1;
                            if connections > MAX_REQUESTS {
                                return Err("request limit");
                            }
                            socket
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .map_err(|_| "read timeout")?;
                            socket
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .map_err(|_| "write timeout")?;
                            let capture = read_request(&mut socket)?;
                            observed.lock().map_err(|_| "capture lock")?.push(capture);
                            let reply = replies.next().ok_or("unexpected request or replay")?;
                            let content_type = if reply.status == 200 {
                                "text/event-stream"
                            } else {
                                "application/json"
                            };
                            write!(socket, "HTTP/1.1 {} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.status, reply.body.len() + usize::from(reply.incomplete)).map_err(|_| "response headers")?;
                            if let Some(hold) = reply.hold {
                                let end = reply.body.len().saturating_sub(1);
                                socket
                                    .write_all(&reply.body[..end])
                                    .map_err(|_| "held response prefix")?;
                                socket.flush().map_err(|_| "held flush")?;
                                hold.ready.send(()).map_err(|_| "hold notice")?;
                                hold.release
                                    .recv_timeout(Duration::from_secs(3))
                                    .map_err(|_| "hold deadline")?;
                                let written = socket.write_all(&reply.body[end..]);
                                if !reply.incomplete {
                                    written.map_err(|_| "held final byte")?;
                                }
                            } else {
                                socket.write_all(&reply.body).map_err(|_| "response body")?;
                            }
                            let _ = socket.flush();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            while let Ok(reply) = requests.try_recv() {
                                reply.send(connections).map_err(|_| "barrier receiver")?;
                            }
                            if stopping.load(Ordering::SeqCst) {
                                return Ok(());
                            }
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => return Err("listener accept"),
                    }
                }
            });
            Self {
                authority,
                captures,
                stop,
                barriers,
                worker: Some(worker),
                watchdog_done: Some(watchdog_done),
                watchdog: Some(watchdog),
            }
        }
        fn barrier(&self) -> usize {
            let (tx, rx) = mpsc::sync_channel(1);
            self.barriers.send(tx).unwrap();
            rx.recv_timeout(Duration::from_secs(3))
                .expect("owned listener poll barrier")
        }
        fn captures(&self) -> Vec<Capture> {
            self.captures.lock().unwrap().clone()
        }
        fn close(&mut self) -> Result<(), &'static str> {
            self.stop.store(true, Ordering::SeqCst);
            let result = self
                .worker
                .take()
                .map_or(Ok(()), |worker| worker.join().expect("owned wire panic"));
            if let Some(done) = self.watchdog_done.take() {
                let _ = done.try_send(());
            }
            if let Some(watchdog) = self.watchdog.take() {
                watchdog.join().unwrap();
            }
            result
        }
        fn finish(&mut self) {
            self.close().expect("owned response fixture failed");
        }
    }
    impl Drop for Wire {
        fn drop(&mut self) {
            let _ = self.close();
        }
    }
    fn read_request(socket: &mut TcpStream) -> Result<Capture, &'static str> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 16 * 1024 || Instant::now() >= deadline {
                return Err("header bound");
            }
            let mut byte = [0];
            match socket.read(&mut byte) {
                Ok(1) => header.push(byte[0]),
                Ok(_) => return Err("short header"),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Err("header read"),
            }
        }
        let header = std::str::from_utf8(&header).map_err(|_| "header UTF-8")?;
        let mut lines = header.lines();
        let target = lines.next().ok_or("missing target")?.to_owned();
        let mut length = None;
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or("header separator")?;
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err("transfer encoding");
            }
            if name.eq_ignore_ascii_case("content-length") {
                if length.is_some() {
                    return Err("duplicate content length");
                }
                length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| "content length")?,
                );
            }
            if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-api-key")
            {
                return Err("ambient credential on owned request");
            }
        }
        let length = length
            .filter(|value| *value > 0 && *value <= MAX_BODY)
            .ok_or("body bound")?;
        let mut body = vec![0; length];
        let mut offset = 0;
        while offset < length {
            if Instant::now() >= deadline {
                return Err("body read deadline");
            }
            match socket.read(&mut body[offset..]) {
                Ok(0) => return Err("short body"),
                Ok(count) => offset += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Err("body read"),
            }
        }
        Ok(Capture {
            target,
            body: serde_json::from_slice(&body).map_err(|_| "body JSON")?,
        })
    }
    fn private_write(path: &Path, bytes: impl AsRef<[u8]>) {
        let temporary = path.with_extension(format!("{}.tmp", ulid::Ulid::new()));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .unwrap();
        file.write_all(bytes.as_ref()).unwrap();
        drop(file);
        fs::rename(temporary, path).unwrap();
    }
    struct Owned {
        root: PathBuf,
        home: PathBuf,
        config: OwnerConfig,
        wire: Wire,
    }
    impl Owned {
        fn new(replies: Vec<Reply>, routing: bool) -> Self {
            require_private_system_fixture();
            let root = PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").unwrap())
                .join(format!("ro-{}", &ulid::Ulid::new().to_string()[14..]));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let home = root.join("h");
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
            let plan =
                orbit_cli::setup::plan_setup(&home, &orbit_cli::setup::SetupRequest::default())
                    .unwrap();
            orbit_cli::setup::apply_setup(&plan).unwrap();
            let wire = Wire::new(replies);
            let model = |id: &str| json!({"id":id,"max_output_tokens":73,"context_limits":{"input_tokens":128000},"pricing":{"input_per_million_microdollars":0,"output_per_million_microdollars":0,"cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,"reasoning_per_million_microdollars":0,"request_flat_microdollars":13},"billing":{"version":2,"input_per_million_microdollars":0,"output_per_million_microdollars":0,"cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,"request_flat_microdollars":13,"reasoning_counter_basis":"included_in_output","reasoning_rate_policy":"output_rate"}});
            let mut value = json!({"provider":[{"name":"base","kind":"openai-compatible","url":format!("http://{}/a/v1?route=base&raw=%2F",wire.authority),"models":[model("model-a")]},{"name":"selected","kind":"openai-compatible","url":format!("http://{}/b/v1?route=final&raw=%2F",wire.authority),"models":[model("model-b")]}],"roles":{"main":"base/model-a"}});
            if routing {
                value["routing"] = json!({"phases":{"coding":{"default":"selected/model-b","hard":"selected/model-b"}},"phase_keywords":{"clear":true,"coding":["selected-route"]}});
            }
            let configured: config::ProvidersConfig = serde_json::from_value(value).unwrap();
            private_write(
                &home.join("providers.toml"),
                toml::to_string(&configured).unwrap(),
            );
            let turn = session_config::SessionTurnConfig {
                home: home.clone(),
                session_id: "owned".into(),
                gate: configured.provider[0].url.clone(),
                model: "model-a".into(),
                effort: None,
                provider_id: "base".into(),
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
                home,
                wire,
            }
        }
        fn selected(&self, selected: bool) -> orbit_engine::TurnConfig {
            let provider = if selected { "selected" } else { "base" };
            let model = if selected { "model-b" } else { "model-a" };
            let config = config::ProvidersConfig::load(&self.home).unwrap();
            phase_routing::resolve_model(&config, model, Some(provider))
                .unwrap()
                .turn_config(None)
                .unwrap()
        }
        fn policy(&self, selected: bool, id: &str) {
            let turn = self.selected(selected);
            let document = toml::to_string(&json!({"version":1,"final_rejection":[{"id":id,"provider":turn.provider_id,"model":turn.model,"endpoint":turn.gate,"adapter_identity_sha256":adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),"statuses":[500,503],"scope":"ordinary","generation":"final_rejection","billing":"unknown","allow_uncapped_retry":true,"max_attempts":2}]})).unwrap();
            private_write(&self.home.join("provider-policies.toml"), document);
            assert!(
                provider_policies::load_for_config(&self.home, &turn)
                    .unwrap()
                    .is_some()
            );
        }
        fn start(&self, fresh: bool) -> OwnerRuntime {
            let lease = SessionLease::acquire(&self.home, "owned", "refusal-owner").unwrap();
            let mut config = self.config.clone();
            if fresh {
                let mut saved = sessions::SessionFile::from_chat(
                    "owned",
                    "model-a",
                    &config.turn.gate,
                    "base",
                    &[],
                    0,
                    0,
                    0,
                    0,
                )
                .with_selection_origin(phase_routing::SelectionOrigin::Default);
                saved.bind_workspace(&config.working_dir).unwrap();
                let accounting = session_accounting::prepare_root(
                    &lease,
                    &mut saved,
                    session_accounting::RootOrigin::FreshCandidate,
                )
                .unwrap();
                assert_eq!(
                    accounting
                        .namespace()
                        .checkpoint_detailed()
                        .unwrap()
                        .baseline(),
                    AccountingBaseline::FreshKnownZero
                );
                assert_eq!(saved.accounting_watermark.as_ref().unwrap().revision, 0);
                drop(accounting);
            } else {
                let saved = lease.load().unwrap();
                config.turn.provider_id = saved.provider;
                config.turn.model = saved.model;
                config.turn.gate = saved.gate;
                config.turn.effort = saved.effort;
            }
            OwnerRuntime::start(config, lease).unwrap()
        }
        fn inspect(&self) -> DetailedAccountingInspection {
            inspect_accounting_detailed(&self.home, "owned", None).unwrap()
        }
        fn saved(&self) -> sessions::SessionFile {
            sessions::load_session(&self.home, "owned").unwrap()
        }
        fn accounting_bytes(&self) -> Vec<u8> {
            fs::read(self.home.join("context-history/owned/accounting.json")).unwrap()
        }
        fn decisions(&self) -> Vec<String> {
            orbit_ledger::verify_ledger(&self.home.join("ledger"))
                .unwrap()
                .0
                .into_iter()
                .filter_map(|entry| match entry.record.event {
                    orbit_ledger::LedgerEvent::EgressIntent(intent) => {
                        assert_eq!(intent.session_id, "owned");
                        Some(intent.decision_id)
                    }
                    _ => None,
                })
                .collect()
        }
        fn wire(&self, count: usize, selected: bool) {
            assert_eq!(self.wire.barrier(), count);
            let captures = self.wire.captures();
            assert_eq!(captures.len(), count);
            let target = if selected {
                "/b/v1/chat/completions?route=final&raw=%2F"
            } else {
                "/a/v1/chat/completions?route=base&raw=%2F"
            };
            for capture in captures {
                assert_eq!(capture.target, format!("POST {target} HTTP/1.1"));
                assert_eq!(
                    capture.body["model"],
                    if selected { "model-b" } else { "model-a" }
                );
                assert_eq!(capture.body["max_tokens"], 73);
            }
        }
        fn qualified(&self, snapshot: &daemon::OwnerSnapshot, successes: u64, refusals: u64) {
            let observed = self.inspect();
            let checkpoint = &observed.checkpoint;
            assert_eq!(checkpoint.owner_session_id(), "owned");
            assert_eq!(checkpoint.child_id(), None);
            assert_eq!(checkpoint.baseline(), AccountingBaseline::FreshKnownZero);
            assert!(checkpoint.pending().is_none());
            assert_eq!(checkpoint.refusals().unwrap().count(), refusals);
            assert_eq!(
                checkpoint.totals().knownness,
                AccountingKnownness::UnknownUsage
            );
            assert_eq!(
                checkpoint.totals().ordinary,
                AccountingTotals {
                    input_tokens: 11 * successes,
                    output_tokens: 7 * successes,
                    cost_microcents: None
                }
            );
            assert_eq!(
                checkpoint.totals().housekeeping,
                AccountingTotals::known_zero()
            );
            assert_eq!(
                checkpoint.known_priced_subtotals(),
                Some(KnownPricedSubtotals {
                    ordinary_microcents: 13 * successes,
                    housekeeping_microcents: 0
                })
            );
            let saved = self.saved();
            assert_eq!(
                (
                    saved.input_tokens,
                    saved.output_tokens,
                    saved.cost_microcents
                ),
                (11 * successes, 7 * successes, 13 * successes)
            );
            assert_eq!(
                (
                    snapshot.input_tokens,
                    snapshot.output_tokens,
                    snapshot.cost_microcents
                ),
                (11 * successes, 7 * successes, 13 * successes)
            );
            let anchor = saved.accounting_watermark.as_ref().unwrap();
            assert_eq!(
                anchor.full_cost_status,
                session_accounting::FullCostStatus::UnknownUsage
            );
            assert_eq!(anchor.revision, checkpoint.revision().0);
            assert_eq!(
                (
                    anchor.known_input_tokens,
                    anchor.known_output_tokens,
                    anchor.known_ordinary_microcents,
                    anchor.known_housekeeping_microcents
                ),
                (11 * successes, 7 * successes, 13 * successes, 0)
            );
            let projection = snapshot.accounting.as_ref().unwrap();
            assert_eq!(projection.revision, anchor.revision);
            assert_eq!(
                projection.full_cost_status,
                session_accounting::FullCostStatus::UnknownUsage
            );
            if successes > 0 {
                let receipt = observed.last_legacy_receipt.as_ref().unwrap();
                assert!(receipt.completed);
                assert_eq!(receipt.knownness, AccountingKnownness::Known);
                assert_eq!(
                    receipt.usage.unwrap(),
                    orbit_adapter::types::ProviderUsage {
                        input_tokens: 11,
                        output_tokens: 7,
                        cache_read_tokens: 3,
                        cache_write_tokens: 0,
                        reasoning_tokens: 5
                    }
                );
                assert_eq!(receipt.totals.cost_microcents, Some(13));
                assert_ne!(
                    checkpoint
                        .refusals()
                        .unwrap()
                        .latest()
                        .binding()
                        .request_id(),
                    receipt.request_id
                );
            }
            let ids = self.decisions();
            assert_eq!(ids.len() as u64, successes + refusals);
            assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), ids.len());
            let refusal = checkpoint.refusals().unwrap().latest();
            assert_eq!(refusal.intent().owner_session_id, "owned");
            assert_eq!(refusal.intent().child_id, None);
            assert_eq!(refusal.intent().request_id, refusal.binding().request_id());
            assert!(ids.iter().any(|id| id == refusal.binding().decision_id()));
            assert_eq!(
                refusal.binding().adapter_identity_sha256(),
                adapter_identity_digest(&orbit_provider_http::openai::openai_identity())
            );
        }
        fn uncertain(&self, snapshot: &daemon::OwnerSnapshot) {
            let observed = self.inspect();
            assert!(observed.checkpoint.pending().unwrap().uncertain);
            assert!(observed.checkpoint.refusals().is_none());
            assert_eq!(
                observed.pending_receipt.unwrap().knownness,
                AccountingKnownness::Uncertain
            );
            assert_eq!(
                snapshot.requests.values().last().unwrap().state,
                daemon::RequestState::Unknown
            );
            assert_eq!(
                snapshot.accounting.as_ref().unwrap().full_cost_status,
                session_accounting::FullCostStatus::Uncertain
            );
            assert_eq!(
                (
                    snapshot.input_tokens,
                    snapshot.output_tokens,
                    snapshot.cost_microcents
                ),
                (0, 0, 0)
            );
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.wire.close();
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn terminal(handle: &daemon::OwnerHandle, id: &str) -> daemon::OwnerSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = handle.snapshot().unwrap();
            if snapshot.requests.get(id).is_some_and(|record| {
                !matches!(
                    record.state,
                    daemon::RequestState::Accepted | daemon::RequestState::Running
                )
            }) && matches!(
                snapshot.state,
                TurnState::Idle | TurnState::Interrupted | TurnState::Stopped
            ) {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "owned retry did not finish: {snapshot:?}"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn prompt(controller: &mut daemon::ControllerLease, id: &str, text: &str) -> daemon::ActionAck {
        controller
            .send(OwnerAction::Prompt {
                request_id: id.into(),
                text: text.into(),
            })
            .unwrap()
    }
    fn events_through_finish(subscription: &daemon::OwnerSubscription) -> Vec<daemon::OwnerEvent> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut events = subscription.recovery.events.clone();
        while !events.iter().any(|event| event.kind == "request_finished") {
            assert!(events.len() < 256, "owned event bound");
            events.push(
                subscription
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .expect("owned finish event"),
            );
        }
        events
    }
    fn one_outer_turn(events: &[daemon::OwnerEvent], retried: bool) {
        for (kind, count) in [
            ("request_accepted", 1),
            ("request_finished", 1),
            ("retrying", usize::from(retried)),
        ] {
            assert_eq!(
                events.iter().filter(|event| event.kind == kind).count(),
                count,
                "{kind}"
            );
        }
        if retried {
            let retry = events
                .iter()
                .find(|event| event.kind == "retrying")
                .unwrap();
            assert_eq!(retry.payload["attempt"], 1);
            assert!((1000..=1249).contains(&retry.payload["retry_in_ms"].as_u64().unwrap()));
        }
    }
    fn one_user(saved: &sessions::SessionFile, text: &str) {
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(
                    |message| message.role == orbit_adapter::types::ChatRole::User
                        && message.content == text
                )
                .count(),
            1
        );
    }

    #[test]
    fn owned_matching_policy_retries_one_request_and_keeps_unknown_bill() {
        if !dispatch_isolated(
            "refusal_policy_owner::owned_matching_policy_retries_one_request_and_keeps_unknown_bill",
        ) {
            return;
        }
        for status in [500, 503] {
            let mut f = Owned::new(vec![Reply::reject(status), Reply::paid()], false);
            f.policy(false, "owner-matching");
            let runtime = f.start(true);
            let handle = runtime.handle();
            let subscription = handle.subscribe(None).unwrap();
            let mut controller = handle.claim_controller().unwrap();
            assert!(handle.claim_controller().is_err());
            assert!(matches!(
                SessionLease::acquire(&f.home, "owned", "second-owner"),
                Err(sessions::SessionLeaseError::Busy { .. })
            ));
            f.wire(0, false);
            assert!(!prompt(&mut controller, "matching", "one owned prompt").duplicate);
            let events = events_through_finish(&subscription);
            let snapshot = terminal(&handle, "matching");
            assert_eq!(
                snapshot.requests["matching"].state,
                daemon::RequestState::Completed
            );
            assert_eq!(snapshot.turns, 1);
            one_outer_turn(&events, true);
            one_user(&f.saved(), "one owned prompt");
            f.qualified(&snapshot, 1, 1);
            assert_eq!(
                f.inspect().checkpoint.refusals().unwrap().latest().status(),
                status
            );
            f.wire(2, false);
            drop(controller);
            runtime.shutdown().unwrap();
            f.wire.finish();
        }
        for unmatched in [false, true] {
            let mut f = Owned::new(vec![Reply::reject(503)], false);
            if unmatched {
                f.policy(true, "different-route");
            }
            let runtime = f.start(true);
            let handle = runtime.handle();
            let subscription = handle.subscribe(None).unwrap();
            let mut controller = handle.claim_controller().unwrap();
            prompt(&mut controller, "no-policy", "ordinary conservative prompt");
            let events = events_through_finish(&subscription);
            let snapshot = terminal(&handle, "no-policy");
            one_outer_turn(&events, false);
            f.uncertain(&snapshot);
            one_user(&f.saved(), "ordinary conservative prompt");
            f.wire(1, false);
            drop(controller);
            runtime.shutdown().unwrap();
            f.wire.finish();
        }
    }

    #[test]
    fn owned_policy_reload_uses_final_route_only_at_next_prompt() {
        if !dispatch_isolated(
            "refusal_policy_owner::owned_policy_reload_uses_final_route_only_at_next_prompt",
        ) {
            return;
        }
        for phase in [false, true] {
            for final_policy in [false, true] {
                let (held, control) = Reply::reject(503).held();
                let mut f = Owned::new(
                    if final_policy {
                        vec![held, Reply::paid(), Reply::paid()]
                    } else {
                        vec![held]
                    },
                    phase,
                );
                f.policy(final_policy, "selected-owner-policy");
                let runtime = f.start(true);
                let handle = runtime.handle();
                let mut controller = handle.claim_controller().unwrap();
                if !phase {
                    controller
                        .send(OwnerAction::SetModel {
                            model: "model-b".into(),
                            provider: Some("selected".into()),
                        })
                        .unwrap();
                    assert!(handle.snapshot().unwrap().selection_origin.is_explicit());
                }
                let subscription = handle.subscribe(None).unwrap();
                prompt(
                    &mut controller,
                    "selected-first",
                    "selected-route implement comprehensive parser",
                );
                control.wait();
                // No complete final rejection exists yet. Removing the file must
                // not rewrite the immutable binding of this already admitted turn.
                fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
                control.release();
                let events = events_through_finish(&subscription);
                let snapshot = terminal(&handle, "selected-first");
                one_outer_turn(&events, final_policy);
                if final_policy {
                    assert_eq!(
                        snapshot.requests["selected-first"].state,
                        daemon::RequestState::Completed
                    );
                    f.qualified(&snapshot, 1, 1);
                    let old = f.inspect().checkpoint.refusals().unwrap().clone();
                    let old_ids = f.decisions();
                    prompt(
                        &mut controller,
                        "selected-next",
                        "selected-route a new explicit prompt",
                    );
                    let next = terminal(&handle, "selected-next");
                    assert_eq!(
                        next.requests["selected-next"].state,
                        daemon::RequestState::Completed
                    );
                    f.qualified(&next, 2, 1);
                    assert_eq!(f.inspect().checkpoint.refusals(), Some(&old));
                    assert_eq!(&f.decisions()[..2], old_ids.as_slice());
                    one_user(&f.saved(), "selected-route implement comprehensive parser");
                    one_user(&f.saved(), "selected-route a new explicit prompt");
                    f.wire(3, true);
                } else {
                    f.uncertain(&snapshot);
                    f.wire(1, true);
                }
                drop(controller);
                runtime.shutdown().unwrap();
                f.wire.finish();
            }
        }
        for unsafe_file in [false, true] {
            let mut f = Owned::new(vec![], false);
            let runtime = f.start(true);
            let handle = runtime.handle();
            let before = f.accounting_bytes();
            if unsafe_file {
                f.policy(false, "unsafe");
                fs::set_permissions(
                    f.home.join("provider-policies.toml"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            } else {
                private_write(
                    &f.home.join("provider-policies.toml"),
                    b"version=1\nPRIVATE_VALUE=[",
                );
            }
            let policy = fs::read(f.home.join("provider-policies.toml")).unwrap();
            let mut controller = handle.claim_controller().unwrap();
            let error = controller
                .send(OwnerAction::Prompt {
                    request_id: "invalid-policy".into(),
                    text: "retained local intent".into(),
                })
                .unwrap_err()
                .to_string();
            assert!(!error.contains("PRIVATE_VALUE"));
            let snapshot = terminal(&handle, "invalid-policy");
            assert_eq!(
                snapshot.requests["invalid-policy"].state,
                daemon::RequestState::Unknown
            );
            assert_eq!(snapshot.state, TurnState::Interrupted);
            assert_eq!(snapshot.turns, 1);
            assert_eq!(f.accounting_bytes(), before);
            assert_eq!(
                fs::read(f.home.join("provider-policies.toml")).unwrap(),
                policy
            );
            one_user(&f.saved(), "retained local intent");
            assert!(f.decisions().is_empty());
            f.wire(0, false);
            drop(controller);
            runtime.shutdown().unwrap();
            f.wire.finish();
        }
    }

    struct SocketServer {
        stop: orbit_provider_http::CancelToken,
        worker: Option<JoinHandle<Result<(), daemon::OwnerError>>>,
        socket: PathBuf,
    }
    impl SocketServer {
        fn start(f: &Owned, handle: daemon::OwnerHandle) -> Self {
            let socket = f.root.join("s");
            let server = UnixServer::bind(&socket, handle).unwrap();
            let stop = orbit_provider_http::CancelToken::new();
            let stopping = stop.clone();
            let worker = thread::spawn(move || server.run(&stopping));
            Self {
                stop,
                worker: Some(worker),
                socket,
            }
        }
        fn connect(&self) -> BufReader<UnixStream> {
            let stream = daemon::local_connect(&self.socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            BufReader::new(stream)
        }
    }
    impl Drop for SocketServer {
        fn drop(&mut self) {
            self.stop.cancel();
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap().unwrap();
            }
        }
    }

    #[test]
    fn owned_refusal_restart_and_attach_replay_never_resubmit() {
        if !dispatch_isolated(
            "refusal_policy_owner::owned_refusal_restart_and_attach_replay_never_resubmit",
        ) {
            return;
        }
        let mut f = Owned::new(
            vec![Reply::reject(503), Reply::paid(), Reply::paid()],
            false,
        );
        f.config.replay_capacity = 2;
        f.policy(false, "restart-policy");
        let runtime = f.start(true);
        let handle = runtime.handle();
        let old_cursor = handle.snapshot().unwrap().cursor;
        let mut controller = handle.claim_controller().unwrap();
        prompt(&mut controller, "stable", "one stable original");
        let snapshot = terminal(&handle, "stable");
        f.qualified(&snapshot, 1, 1);
        let saved = f.saved();
        let original = f.accounting_bytes();
        let ids = f.decisions();
        assert!(prompt(&mut controller, "stable", "one stable original").duplicate);
        assert!(
            controller
                .send(OwnerAction::Prompt {
                    request_id: "stable".into(),
                    text: "conflicting replacement".into()
                })
                .is_err()
        );
        assert!(SessionLease::acquire(&f.home, "owned", "borrowed-owner").is_err());
        drop(controller);
        let mut controller = handle.claim_controller().unwrap();
        assert!(prompt(&mut controller, "stable", "one stable original").duplicate);
        drop(controller);
        let expired = handle.subscribe(Some(&old_cursor)).unwrap().recovery;
        assert!(expired.snapshot.is_some());
        assert!(expired.events.is_empty());
        f.qualified(expired.snapshot.as_ref().unwrap(), 1, 1);
        {
            let server = SocketServer::start(&f, handle.clone());
            let mut stream = server.connect();
            assert_eq!(
                rpc(&mut stream, json!({"type":"hello","controlling":true}))["ok"],
                true
            );
            let replay = rpc(&mut stream, json!({"type":"subscribe","cursor":old_cursor}));
            assert_eq!(replay["ok"], true);
            let remote: daemon::Recovery = serde_json::from_value(replay["value"].clone()).unwrap();
            assert!(remote.events.is_empty());
            f.qualified(remote.snapshot.as_ref().unwrap(), 1, 1);
            let duplicate = rpc(
                &mut stream,
                json!({"type":"action","action":{"type":"prompt","request_id":"stable","text":"one stable original"}}),
            );
            assert_eq!(duplicate["value"]["duplicate"], true);
            let conflict = rpc(
                &mut stream,
                json!({"type":"action","action":{"type":"prompt","request_id":"stable","text":"different"}}),
            );
            assert_eq!(conflict["ok"], false);
            drop(stream);
        }
        assert_eq!(f.accounting_bytes(), original);
        f.wire(2, false);
        runtime.shutdown().unwrap();
        let restarted = f.start(false);
        let handle = restarted.handle();
        let cold = handle.subscribe(Some(&old_cursor)).unwrap().recovery;
        assert!(cold.events.is_empty());
        f.qualified(cold.snapshot.as_ref().unwrap(), 1, 1);
        assert_ne!(cold.cursor.instance, old_cursor.instance);
        assert_eq!(f.saved().transcript, saved.transcript);
        assert_eq!(f.accounting_bytes(), original);
        let mut controller = handle.claim_controller().unwrap();
        assert!(prompt(&mut controller, "stable", "one stable original").duplicate);
        assert!(
            controller
                .send(OwnerAction::Prompt {
                    request_id: "stable".into(),
                    text: "different after restart".into()
                })
                .is_err()
        );
        f.wire(2, false);
        fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
        prompt(
            &mut controller,
            "new-after-restart",
            "new explicit continuation",
        );
        let next = terminal(&handle, "new-after-restart");
        assert_eq!(
            next.requests["new-after-restart"].state,
            daemon::RequestState::Completed
        );
        f.qualified(&next, 2, 1);
        assert_eq!(&f.decisions()[..2], ids.as_slice());
        one_user(&f.saved(), "one stable original");
        one_user(&f.saved(), "new explicit continuation");
        assert_eq!(next.turns, 2);
        f.wire(3, false);
        drop(controller);
        restarted.shutdown().unwrap();
        f.wire.finish();
    }

    #[test]
    fn owned_cancel_after_refusal_ack_keeps_settled_request_without_replay() {
        if !dispatch_isolated(
            "refusal_policy_owner::owned_cancel_after_refusal_ack_keeps_settled_request_without_replay",
        ) {
            return;
        }
        {
            let mut f = Owned::new(vec![Reply::reject(503)], false);
            f.policy(false, "cancel-policy");
            let runtime = f.start(true);
            let handle = runtime.handle();
            let subscription = handle.subscribe(None).unwrap();
            let mut controller = handle.claim_controller().unwrap();
            prompt(
                &mut controller,
                "cancel-settled",
                "cancel after real refusal",
            );
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut events = Vec::new();
            loop {
                let event = subscription
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .expect("actual retry event");
                let retry = event.kind == "retrying";
                events.push(event);
                assert!(events.len() <= 256);
                if retry {
                    break;
                }
            }
            let observed_at = Instant::now();
            let settled = f.inspect();
            assert!(settled.checkpoint.pending().is_none());
            assert!(matches!(
                settled.checkpoint.last_settlement(),
                Some(DetailedLastSettlement::FinalRefusal(_))
            ));
            assert_eq!(settled.checkpoint.refusals().unwrap().count(), 1);
            assert!(
                observed_at.elapsed() < Duration::from_millis(700),
                "missed actual backoff cancellation window"
            );
            controller.send(OwnerAction::Cancel).unwrap();
            let snapshot = terminal(&handle, "cancel-settled");
            events.extend(events_through_finish(&subscription));
            one_outer_turn(&events, true);
            assert_eq!(
                snapshot.requests["cancel-settled"].state,
                daemon::RequestState::Interrupted
            );
            f.qualified(&snapshot, 0, 1);
            assert_eq!(f.inspect().checkpoint, settled.checkpoint);
            assert!(f.inspect().last_legacy_receipt.is_none());
            one_user(&f.saved(), "cancel after real refusal");
            f.wire(1, false);
            assert!(
                prompt(
                    &mut controller,
                    "cancel-settled",
                    "cancel after real refusal"
                )
                .duplicate
            );
            f.wire(1, false);
            drop(controller);
            runtime.shutdown().unwrap();
            f.wire.finish();
        }
        {
            let (partial, control) = Reply::partial().held();
            let mut f = Owned::new(vec![partial], false);
            f.policy(false, "pending-control");
            let runtime = f.start(true);
            let handle = runtime.handle();
            let mut controller = handle.claim_controller().unwrap();
            prompt(
                &mut controller,
                "cancel-pending",
                "cancel an actual admitted stream",
            );
            control.wait();
            let pending = f.inspect();
            assert!(pending.checkpoint.pending().is_some());
            assert!(pending.checkpoint.refusals().is_none());
            controller.send(OwnerAction::Cancel).unwrap();
            control.release();
            let snapshot = terminal(&handle, "cancel-pending");
            f.uncertain(&snapshot);
            one_user(&f.saved(), "cancel an actual admitted stream");
            f.wire(1, false);
            drop(controller);
            runtime.shutdown().unwrap();
            f.wire.finish();
        }
    }
}
