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

use attach::AttachClient;
use daemon::{OwnerAction, OwnerConfig, OwnerRuntime, TurnState, UnixServer};
use sessions::SessionLease;
use std::fs;
use std::io::{Cursor, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
        let root = std::env::temp_dir().join(format!("orbit-attach-{}", ulid::Ulid::new()));
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
                "{}",
                fs::read_to_string(root.join("provider.stderr")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("ready.json")).unwrap()).unwrap();
        let gate = ready["gate"].as_str().unwrap().to_owned();
        fs::write(root.join("providers.toml"),format!("[[provider]]\nname=\"fixture\"\nurl={gate:?}\n[[provider.models]]\nid=\"model-a\"\nsupported_efforts=[\"low\"]\ndefault_effort=\"low\"\n")).unwrap();
        fs::set_permissions(
            root.join("providers.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
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
    fn socket(&self) -> PathBuf {
        self.root.join("run/owner.sock")
    }
    fn calls(&self) -> usize {
        fs::read_to_string(self.root.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .count()
    }
    fn serve(&self) -> Serving {
        let runtime = OwnerRuntime::start(
            self.config.clone(),
            SessionLease::acquire(&self.root, "owned", "daemon").unwrap(),
        )
        .unwrap();
        let server = UnixServer::bind(&self.socket(), runtime.handle()).unwrap();
        let stop = orbit_provider_http::CancelToken::new();
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || server.run(&thread_stop));
        Serving {
            runtime: Some(runtime),
            stop,
            thread: Some(thread),
        }
    }
    fn wait_calls(&self, count: usize) {
        let until = Instant::now() + Duration::from_secs(5);
        while self.calls() < count {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.provider.kill();
        let _ = self.provider.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Serving {
    runtime: Option<OwnerRuntime>,
    stop: orbit_provider_http::CancelToken,
    thread: Option<std::thread::JoinHandle<Result<(), daemon::OwnerError>>>,
}
impl Serving {
    fn handle(&self) -> daemon::OwnerHandle {
        self.runtime.as_ref().unwrap().handle()
    }
}
impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(runtime) = self.runtime.take() {
            let _ = runtime.shutdown();
        }
    }
}
fn wait_done(handle: &daemon::OwnerHandle) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = handle.snapshot().unwrap();
        if snapshot.state == TurnState::Idle && snapshot.turns > 0 {
            break;
        }
        assert!(Instant::now() < until, "{snapshot:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn reconnect(socket: &std::path::Path) -> AttachClient {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match AttachClient::connect(socket, true, None) {
            Ok(client) => return client,
            Err(daemon::OwnerError::ControllerBusy) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) => panic!("{error}"),
        }
    }
}

#[test]
fn unix_attach_plain_view_one_prompt_saved_reply_and_bounded_logs() {
    let fixture = Fixture::new();
    let serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    let cursor = client.recovery.cursor.clone();
    let mut output = vec![];
    attach::render_recovery(&client.recovery, &mut output).unwrap();
    assert!(
        String::from_utf8(output.clone())
            .unwrap()
            .contains("Session owned")
    );
    client.prompt("attached prompt".into()).unwrap();
    wait_done(&serving.handle());
    assert_eq!(fixture.calls(), 1);
    let recovery = client.logs(Some(&cursor)).unwrap();
    assert!(
        recovery
            .events
            .iter()
            .any(|event| event.kind == "request_finished")
    );
    attach::render_recovery(&recovery, &mut output).unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("owned fixture reply")
    );
    assert!(
        client
            .snapshot()
            .unwrap()
            .messages
            .iter()
            .any(|message| message["text"] == "owned fixture reply")
    );
    assert!(
        sessions::load_session(&fixture.root, "owned")
            .unwrap()
            .transcript
            .iter()
            .any(|message| message.content == "owned fixture reply")
    );
}

#[test]
fn unix_attach_detach_and_reconnect_never_cancel_or_duplicate_running_turn() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode.json"), r#"{"blocked":true}"#).unwrap();
    let serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    client
        .send(OwnerAction::Prompt {
            request_id: "detach-key".into(),
            text: "running attached turn".into(),
        })
        .unwrap();
    fixture.wait_calls(1);
    drop(client);
    let mut next = reconnect(&fixture.socket());
    assert_eq!(next.snapshot().unwrap().state, TurnState::Running);
    assert!(
        next.send(OwnerAction::Prompt {
            request_id: "detach-key".into(),
            text: "running attached turn".into()
        })
        .unwrap()
        .duplicate
    );
    assert_eq!(fixture.calls(), 1);
    fs::write(fixture.root.join("release"), b"finish").unwrap();
    wait_done(&serving.handle());
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn unix_attach_single_controller_and_read_only_status_are_distinct() {
    let fixture = Fixture::new();
    let _serving = fixture.serve();
    let _controller = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    assert!(matches!(
        AttachClient::connect(&fixture.socket(), true, None),
        Err(daemon::OwnerError::ControllerBusy)
    ));
    let mut status = AttachClient::connect(&fixture.socket(), false, None).unwrap();
    assert_eq!(status.snapshot().unwrap().state, TurnState::Idle);
    assert!(matches!(
        status.prompt("not allowed".into()),
        Err(daemon::OwnerError::NotController)
    ));
    assert_eq!(fixture.calls(), 0);
}

#[test]
fn unix_attach_explicit_cancel_then_stop_joins_and_removes_socket() {
    let fixture = Fixture::new();
    let target = fixture.root.join("cancelled.txt");
    fs::write(
        fixture.root.join("mode.json"),
        serde_json::json!({"tool":"Write","arguments":{"file_path":target,"content":"refused"}})
            .to_string(),
    )
    .unwrap();
    let mut serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    client.prompt("cancel pending approval".into()).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while client.snapshot().unwrap().pending_approvals.is_empty() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut visible = vec![];
    attach::render_recovery(&client.refresh().unwrap(), &mut visible).unwrap();
    assert!(String::from_utf8(visible).unwrap().contains("Tool: Write"));
    client.send(OwnerAction::Cancel).unwrap();
    wait_done(&serving.handle());
    assert!(!target.exists());
    assert!(client.snapshot().unwrap().pending_approvals.is_empty());
    client.send(OwnerAction::Stop).unwrap();
    drop(client);
    serving.thread.take().unwrap().join().unwrap().unwrap();
    serving.runtime.take().unwrap().wait().unwrap();
    assert!(!fixture.socket().exists());
    assert!(SessionLease::acquire(&fixture.root, "owned", "daemon").is_ok());
}

#[test]
fn unix_attach_plain_effort_query_set_and_reset_are_saved_without_requests() {
    use orbit_adapter::types::{EffortSetting, EffortValue};
    let fixture = Fixture::new();
    let serving = fixture.serve();
    let mut output = vec![];
    attach::run_with_io(
        &fixture.socket(),
        &mut Cursor::new(b"/effort\n/effort low\n/detach\n"),
        &mut output,
    )
    .unwrap();
    let expected = Some(EffortSetting::Value(EffortValue::Level("low".into())));
    assert_eq!(serving.handle().snapshot().unwrap().effort, expected);
    assert_eq!(
        sessions::load_session(&fixture.root, "owned")
            .unwrap()
            .effort,
        expected
    );
    assert!(String::from_utf8(output).unwrap().contains("low"));
    attach::run_with_io(
        &fixture.socket(),
        &mut Cursor::new(b"/effort default\n/detach\n"),
        &mut vec![],
    )
    .unwrap();
    assert_eq!(
        serving.handle().snapshot().unwrap().effort,
        Some(EffortSetting::Default)
    );
    assert_eq!(
        sessions::load_session(&fixture.root, "owned")
            .unwrap()
            .effort,
        Some(EffortSetting::Default)
    );
    assert_eq!(fixture.calls(), 0);
}

#[test]
fn unix_attach_plain_invalid_effort_preserves_owner_and_saved_settings() {
    let fixture = Fixture::new();
    let serving = fixture.serve();
    let before = fs::read(fixture.root.join("sessions/owned.json")).unwrap();
    assert!(
        attach::run_with_io(
            &fixture.socket(),
            &mut Cursor::new(b"/effort high\n"),
            &mut vec![]
        )
        .is_err()
    );
    let snapshot = serving.handle().snapshot().unwrap();
    assert!(snapshot.effort.is_none());
    assert_eq!(snapshot.model, "model-a");
    assert_eq!(snapshot.provider, "fixture");
    assert_eq!(
        fs::read(fixture.root.join("sessions/owned.json")).unwrap(),
        before
    );
    assert_eq!(fixture.calls(), 0);
}

#[test]
fn unix_attach_plain_lists_render_actual_model_and_saved_session_data() {
    let fixture = Fixture::new();
    let _serving = fixture.serve();
    let mut output = vec![];
    attach::run_with_io(
        &fixture.socket(),
        &mut Cursor::new(b"/models\n/sessions\n/detach\n"),
        &mut output,
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    let models: serde_json::Value = serde_json::from_str(
        output
            .lines()
            .find_map(|line| line.strip_prefix("models: "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        models["models"],
        serde_json::json!([{"model":"model-a","provider":"fixture"}])
    );
    let sessions: serde_json::Value = serde_json::from_str(
        output
            .lines()
            .find_map(|line| line.strip_prefix("sessions: "))
            .unwrap(),
    )
    .unwrap();
    assert!(
        sessions["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|session| session["session_id"] == "owned" && session["model"] == "model-a")
    );
    assert_eq!(fixture.calls(), 0);
}

#[test]
fn unix_attach_setting_refusal_keeps_stream_usable_for_status_and_valid_action() {
    use orbit_adapter::types::{EffortSetting, EffortValue};
    let fixture = Fixture::new();
    let _serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    assert!(matches!(
        client.send(OwnerAction::SetEffort {
            choice: EffortSetting::Value(EffortValue::Level("high".into()))
        }),
        Err(daemon::OwnerError::Invalid(_))
    ));
    assert_eq!(client.snapshot().unwrap().model, "model-a");
    client
        .send(OwnerAction::SetEffort {
            choice: EffortSetting::Value(EffortValue::Level("low".into())),
        })
        .unwrap();
    assert_eq!(
        client.snapshot().unwrap().resolved_effort,
        Some(EffortValue::Level("low".into()))
    );
    assert_eq!(fixture.calls(), 0);
}

#[test]
fn unix_attach_pending_headers_cancel_is_interrupted_saved_and_never_retried() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode.json"), r#"{"blocked":true}"#).unwrap();
    let serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    let action = || OwnerAction::Prompt {
        request_id: "header-cancel".into(),
        text: "cancel before headers".into(),
    };
    client.send(action()).unwrap();
    fixture.wait_calls(1);
    client.send(OwnerAction::Cancel).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let snapshot = client.snapshot().unwrap();
        if snapshot.state == TurnState::Interrupted {
            assert_eq!(
                snapshot.requests["header-cancel"].state,
                daemon::RequestState::Unknown
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "header cancellation is not bounded: {snapshot:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let journal =
        orbit_cli::context_history::context_journal(&fixture.root, "owned", None).unwrap();
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.owner_session_id, "owned");
    assert_eq!(checkpoint.child_id, None);
    assert_eq!(checkpoint.revision.0, 2);
    assert!(checkpoint.pending.as_ref().unwrap().uncertain);
    assert_eq!(
        checkpoint.totals.knownness,
        orbit_engine::AccountingKnownness::Uncertain
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
    let saved = sessions::load_session(&fixture.root, "owned").unwrap();
    assert_eq!(
        saved.transcript,
        vec![orbit_engine::user_message("cancel before headers")]
    );
    assert_eq!(
        saved
            .accounting_watermark
            .as_ref()
            .unwrap()
            .full_cost_status,
        session_accounting::FullCostStatus::Uncertain
    );
    let session_path = fixture.root.join("sessions/owned.json");
    let accounting_path = fixture.root.join("context-history/owned/accounting.json");
    let session_bytes = fs::read(&session_path).unwrap();
    let accounting_bytes = fs::read(&accounting_path).unwrap();
    let duplicate = client.send(action()).unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.state, "unknown");
    assert_eq!(fs::read(&session_path).unwrap(), session_bytes);
    assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
    assert_eq!(journal.accounting_checkpoint().unwrap(), checkpoint);
    let claims: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.root.join("sessions/.requests/owned.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(claims["requests"]["header-cancel"]["state"], "unknown");
    assert_eq!(fixture.calls(), 1);
    assert_eq!(serving.handle().snapshot().unwrap().turns, 1);
}

#[test]
fn unix_attach_partial_stream_cancel_preserves_text_and_reports_interruption() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root.join("mode.json"),
        r#"{"chunks":["visible partial reply\n","unreachable suffix"],"pause_after":0}"#,
    )
    .unwrap();
    let _serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    client
        .send(OwnerAction::Prompt {
            request_id: "partial-cancel".into(),
            text: "cancel partial stream".into(),
        })
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !client
        .snapshot()
        .unwrap()
        .partial_response
        .contains("visible partial reply")
    {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    client.send(OwnerAction::Cancel).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while client.snapshot().unwrap().state == TurnState::Running {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        client.snapshot().unwrap().requests["partial-cancel"].state,
        daemon::RequestState::Unknown
    );
    assert_eq!(client.snapshot().unwrap().state, TurnState::Interrupted);
    let recovery = client.refresh().unwrap();
    assert!(
        recovery
            .events
            .iter()
            .any(|event| event.kind == "turn_ended"
                && event.payload["ok"] == false
                && event.payload["interrupted"] == true)
    );
    let saved = sessions::load_session(&fixture.root, "owned").unwrap();
    let partial = saved
        .transcript
        .iter()
        .find(|message| message.role == orbit_adapter::types::ChatRole::Assistant)
        .unwrap();
    assert_eq!(partial.content, "visible partial reply\n");
    assert!(partial.tool_calls.is_none() && partial.blocks.is_none());
    assert_eq!(
        saved
            .transcript
            .iter()
            .filter(
                |message| message.role == orbit_adapter::types::ChatRole::User
                    && message.content == "cancel partial stream"
            )
            .count(),
        1
    );
    assert!(
        !serde_json::to_string(&saved.transcript)
            .unwrap()
            .contains("unreachable suffix")
    );
    assert_eq!(
        saved
            .accounting_watermark
            .as_ref()
            .unwrap()
            .full_cost_status,
        session_accounting::FullCostStatus::Uncertain
    );
    let journal =
        orbit_cli::context_history::context_journal(&fixture.root, "owned", None).unwrap();
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.owner_session_id, "owned");
    assert_eq!(checkpoint.child_id, None);
    assert_eq!(checkpoint.revision.0, 2);
    assert!(checkpoint.pending.as_ref().unwrap().uncertain);
    assert_eq!(
        checkpoint.totals.knownness,
        orbit_engine::AccountingKnownness::Uncertain
    );
    assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
    assert_eq!(
        checkpoint.known_priced_subtotals,
        Some(orbit_engine::KnownPricedSubtotals::known_zero())
    );
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn unix_attach_plain_input_detach_leaves_provider_work_running() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode.json"), r#"{"blocked":true}"#).unwrap();
    let serving = fixture.serve();
    let mut input = Cursor::new(b"plain fixture prompt\n/detach\n");
    let mut output = vec![];
    attach::run_with_io(&fixture.socket(), &mut input, &mut output).unwrap();
    fixture.wait_calls(1);
    assert_eq!(
        serving.handle().snapshot().unwrap().state,
        TurnState::Running
    );
    assert!(String::from_utf8(output).unwrap().contains("Request"));
    fs::write(fixture.root.join("release"), b"finish").unwrap();
    wait_done(&serving.handle());
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn unix_attach_broken_output_disconnects_only_client() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode.json"), r#"{"blocked":true}"#).unwrap();
    let serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    client.prompt("broken view fixture".into()).unwrap();
    fixture.wait_calls(1);
    assert!(attach::render_snapshot(&client.snapshot().unwrap(), &mut Broken).is_err());
    drop(client);
    let mut next = reconnect(&fixture.socket());
    assert_eq!(next.snapshot().unwrap().state, TurnState::Running);
    assert_eq!(fixture.calls(), 1);
    fs::write(fixture.root.join("release"), b"finish").unwrap();
    wait_done(&serving.handle());
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn unix_attach_reconnect_closes_old_controller_stream_first() {
    let fixture = Fixture::new();
    let serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    client.prompt("reconnect fixture".into()).unwrap();
    wait_done(&serving.handle());
    let mut reconnected = client.reconnect().unwrap();
    assert_eq!(reconnected.snapshot().unwrap().turns, 1);
    assert_eq!(fixture.calls(), 1);
    assert!(attach::status(&fixture.socket()).is_ok());
}

#[test]
fn unix_attach_plain_render_covers_short_prefix_and_split_assignment() {
    let fixture = Fixture::new();
    let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let assignment = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgH";
    fs::write(fixture.root.join("mode.json"),serde_json::json!({"chunks":["ghp_short ",token," ",token,"\nAPI_","KEY= ",assignment,"\npublic final"]}).to_string()).unwrap();
    let serving = fixture.serve();
    let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
    client
        .prompt("render scanned streamed output".into())
        .unwrap();
    wait_done(&serving.handle());
    let recovery = client.refresh().unwrap();
    let encoded = serde_json::to_string(&recovery).unwrap();
    assert!(!encoded.contains(token));
    assert!(!encoded.contains(assignment));
    let mut output = vec![];
    attach::render_recovery(&recovery, &mut output).unwrap();
    attach::render_snapshot(&client.snapshot().unwrap(), &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("ghp_short"));
    assert!(output.contains("public final"));
    assert!(output.contains("redacted"));
    assert!(!output.contains(token));
    assert!(!output.contains(assignment));
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn unix_attach_truncated_then_delayed_ack_poisons_stream_and_reconnects_without_replay() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    let fixture = Fixture::new();
    fs::write(fixture.root.join("mode.json"), r#"{"blocked":true}"#).unwrap();
    let serving = fixture.serve();
    let directory = fixture.root.join("proxy");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory.join("proxy.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let target = fixture.socket();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished = done.clone();
    let proxy = std::thread::spawn(move || {
        let mut unexpected = 0;
        for attempt in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut peer = BufReader::new(stream);
            let mut owner = BufReader::new(daemon::local_connect(&target).unwrap());
            let mut hello = String::new();
            assert!(peer.read_line(&mut hello).unwrap() > 0);
            owner.get_mut().write_all(hello.as_bytes()).unwrap();
            let mut response = String::new();
            owner.read_line(&mut response).unwrap();
            peer.get_mut().write_all(response.as_bytes()).unwrap();
            if attempt == 0 {
                let mut prompt = String::new();
                assert!(peer.read_line(&mut prompt).unwrap() > 0);
                owner.get_mut().write_all(prompt.as_bytes()).unwrap();
                response.clear();
                owner.read_line(&mut response).unwrap();
                peer.get_mut().write_all(b"{\"ok\":\n").unwrap();
                std::thread::sleep(Duration::from_millis(100));
                let _ = peer.get_mut().write_all(response.as_bytes());
                let mut later = String::new();
                if peer.read_line(&mut later).unwrap_or(0) > 0 {
                    unexpected += 1;
                }
                drop(owner);
                finished.store(true, std::sync::atomic::Ordering::SeqCst);
            } else {
                loop {
                    let mut request = String::new();
                    if peer.read_line(&mut request).unwrap() == 0 {
                        break;
                    }
                    owner.get_mut().write_all(request.as_bytes()).unwrap();
                    response.clear();
                    owner.read_line(&mut response).unwrap();
                    peer.get_mut().write_all(response.as_bytes()).unwrap();
                }
            }
        }
        unexpected
    });
    let mut client = AttachClient::connect(&socket, true, None).unwrap();
    let action = || OwnerAction::Prompt {
        request_id: "uncertain-ack".into(),
        text: "one accepted prompt".into(),
    };
    assert!(
        client
            .send(action())
            .unwrap_err()
            .to_string()
            .contains("outcome is unknown")
    );
    assert!(
        client
            .send(OwnerAction::Cancel)
            .unwrap_err()
            .to_string()
            .contains("reconnect explicitly")
    );
    assert!(client.snapshot().is_err());
    fixture.wait_calls(1);
    let until = Instant::now() + Duration::from_secs(3);
    while !done.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    loop {
        match serving.handle().claim_controller() {
            Ok(controller) => {
                drop(controller);
                break;
            }
            Err(_) => {
                assert!(Instant::now() < until);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let mut client = client.reconnect().unwrap();
    let snapshot = client.snapshot().unwrap();
    assert_eq!(snapshot.state, TurnState::Running);
    assert_eq!(
        snapshot.requests["uncertain-ack"].state,
        daemon::RequestState::Running
    );
    assert!(client.send(action()).unwrap().duplicate);
    assert_eq!(fixture.calls(), 1);
    drop(client);
    assert_eq!(proxy.join().unwrap(), 0);
    fs::write(fixture.root.join("release"), b"finish").unwrap();
    wait_done(&serving.handle());
    assert_eq!(fixture.calls(), 1);
}

#[cfg(unix)]
mod context_attach_renderer_tests {
    use super::*;
    use daemon::{EventCursor, OwnerEvent, Recovery};
    use serde_json::{Value, json};

    fn cursor(sequence: u64) -> EventCursor {
        EventCursor {
            instance: "attach-context-renderer".into(),
            sequence,
        }
    }
    fn event(sequence: u64, kind: &str, payload: Value) -> OwnerEvent {
        OwnerEvent {
            cursor: cursor(sequence),
            kind: kind.into(),
            payload,
        }
    }
    fn render(events: Vec<OwnerEvent>) -> String {
        let recovery = Recovery {
            snapshot: None,
            events,
            cursor: cursor(99),
        };
        let mut visible = Vec::new();
        attach::render_recovery(&recovery, &mut visible).unwrap();
        String::from_utf8(visible).unwrap()
    }
    fn has_number(text: &str, value: u64) -> bool {
        let expected = value.to_string();
        text.replace(',', "")
            .split(|character: char| !character.is_ascii_digit())
            .any(|number| number == expected.as_str())
    }

    #[test]
    fn attach_actual_owner_recovery_usage_reaches_plain_renderer_with_exact_reserve_and_trigger() {
        let fixture = Fixture::new();
        let mut config = orbit_cli::config::ProvidersConfig::load(&fixture.root).unwrap();
        config.provider[0].models[0].context_window = None;
        config.provider[0].models[0].max_output_tokens = Some(32_000);
        config.provider[0].models[0].context_limits =
            Some(serde_json::from_value(json!({"combined_tokens":128_000})).unwrap());
        config.save_atomic(&fixture.root).unwrap();
        let serving = fixture.serve();
        let mut client = AttachClient::connect(&fixture.socket(), true, None).unwrap();
        let before = client.recovery.cursor.clone();
        client.prompt("attached context estimate".into()).unwrap();
        wait_done(&serving.handle());
        let recovery = client.logs(Some(&before)).unwrap();
        let usage: Vec<_> = recovery
            .events
            .iter()
            .filter(|event| event.kind == "usage")
            .collect();
        assert_eq!(
            usage.len(),
            1,
            "requires accepted owner typed Usage before testing renderer"
        );
        assert_eq!(usage[0].payload["window_tokens"], 128_000);
        assert_eq!(usage[0].payload["breakdown"]["reserve"], 32_000);
        assert_eq!(usage[0].payload["breakdown"]["compact_at"], 83_200);
        let mut output = Vec::new();
        attach::render_recovery(&recovery, &mut output).unwrap();
        let visible = String::from_utf8(output).unwrap();
        assert!(visible.to_ascii_lowercase().contains("estimate"));
        for value in [128_000, 32_000, 83_200] {
            assert!(
                has_number(&visible, value),
                "missing actual Usage number {value}"
            );
        }
        assert!(visible.contains("owned fixture reply"));
        assert_eq!(fixture.calls(), 1);
    }

    #[test]
    fn attach_actual_recovery_zero_breakdown_and_compaction_render_without_summary_content() {
        let hidden = "private-summary-must-not-render";
        let visible = render(vec![
            event(
                1,
                "usage",
                json!({"used_tokens":0,"window_tokens":64_000,"breakdown":{"system":0,"memory":0,"tools":0,"messages":0,"reserve":0,"compact_at":0}}),
            ),
            event(
                2,
                "compacting",
                json!({"used_tokens":100_000,"window_tokens":128_000}),
            ),
            event(
                3,
                "compacted",
                json!({"after_tokens":2234,"summary":format!("{hidden} <img src=x onerror=alert(1)>\u{1b}[31m")}),
            ),
        ]);
        let lower = visible.to_ascii_lowercase();
        assert!(lower.contains("estimate"));
        assert!(has_number(&visible, 64_000));
        assert!(
            visible
                .split(|character: char| !character.is_ascii_digit())
                .filter(|number| *number == "0")
                .count()
                >= 3,
            "zero occupancy/reserve/trigger must not be omitted"
        );
        assert!(lower.contains("compacting"));
        assert!(lower.contains("compacted"));
        assert!(has_number(&visible, 2234));
        assert!(!visible.contains(hidden));
        assert!(!visible.contains("<img"));
        assert!(!visible.contains('\u{1b}'));
    }

    #[test]
    fn attach_malformed_optional_usage_cannot_invent_zero_capacity_or_echo_raw_values() {
        let poison = "fixture-binding-query-should-not-render";
        let visible = render(vec![
            event(
                1,
                "usage",
                json!({"used_tokens":"not-numeric","window_tokens":poison,"breakdown":{"reserve":-1,"compact_at":1.5}}),
            ),
            event(2, "status", json!({"text":"safe context notice"})),
        ]);
        assert!(visible.contains("safe context notice"));
        assert!(!visible.contains(poison));
        assert!(!visible.contains("not-numeric"));
        assert!(!visible.contains("0 / 0"));
        assert!(!visible.contains("reserve 0"));
    }
}
