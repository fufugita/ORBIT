#![cfg(unix)]

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use orbit_cli::{
    daemon::{EventCursor, OwnerConfig, OwnerRuntime, TurnState},
    sessions::{self, SessionLease},
    tool_runtime::PermissionScope,
    tui_worker::TuiTurnConfig,
};
use orbit_web::{BridgeState, router};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tower::ServiceExt;

struct Fixture {
    root: PathBuf,
    provider: Child,
    config: OwnerConfig,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-browser-{}", ulid::Ulid::new()));
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
        let ready: Value = loop {
            assert!(Instant::now() < until);
            assert!(provider.try_wait().unwrap().is_none());
            if let Ok(bytes) = fs::read(root.join("ready.json"))
                && let Ok(ready) = serde_json::from_slice::<Value>(&bytes)
            {
                break ready;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let gate = ready["gate"].as_str().unwrap().to_owned();
        fs::write(root.join("providers.toml"),format!("[[provider]]\nname=\"fixture\"\nurl={gate:?}\n[[provider.models]]\nid=\"vendor/model-a\"\nsupported_efforts=[\"low\",\"high\",\"false\"]\ndefault_effort=\"low\"\n[[provider.models]]\nid=\"model-b\"\nsupported_efforts=[\"high\"]\ndefault_effort=\"high\"\n[[provider.models]]\nid=\"unknown\"\n[[provider.models]]\nid=\"unsupported\"\nsupported_efforts=[]\n")).unwrap();
        let turn = TuiTurnConfig {
            home: root.clone(),
            session_id: "browser-owned".into(),
            gate,
            model: "vendor/model-a".into(),
            provider_id: "fixture".into(),
            effort: None,
            auto_tools: false,
            scope: PermissionScope::default(),
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
        let lease = SessionLease::acquire(&self.root, "browser-owned", "browser").unwrap();
        let mut config = self.config.clone();
        if self.root.join("sessions/browser-owned.json").exists() {
            let saved = lease.load().unwrap();
            config.turn.model = saved.model;
            config.turn.provider_id = saved.provider;
            config.turn.gate = saved.gate;
            config.turn.effort = saved.effort;
            config.turn.initial_transcript = saved.transcript;
            config.turn.initial_turns = saved.turns;
        }
        OwnerRuntime::start(config, lease).unwrap()
    }
    fn bridge(&self, runtime: &OwnerRuntime) -> BridgeState {
        BridgeState::from_owner(runtime.handle(), None).unwrap()
    }
    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn mode(&self, value: Value) {
        fs::write(self.root.join("mode.json"), value.to_string()).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.provider.kill();
        let _ = self.provider.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn wait_for(state: &BridgeState, predicate: impl Fn(&orbit_cli::daemon::OwnerSnapshot) -> bool) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = state.snapshot().unwrap();
        if predicate(&snapshot) {
            return;
        }
        assert!(Instant::now() < until, "{snapshot:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn choice(value: Value) -> Value {
    json!({"type":"set_effort","choice":{"mode":"value","value":value}})
}

#[test]
fn owner_query_actual_choices_are_typed_and_send_zero_provider_calls() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    let reply = client.send(json!({"type":"effort"})).unwrap();
    assert_eq!(
        reply["snapshot"]["supported_efforts"],
        json!(["low", "high", "false"])
    );
    assert_eq!(reply["snapshot"]["resolved_effort"], "low");
    assert!(reply["snapshot"]["effort"].is_null());
    assert!(fixture.calls().is_empty());
    drop(client);
    runtime.shutdown().unwrap();
}
#[test]
fn owner_query_one_prompt_uses_shared_engine_and_saves_once() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    client
        .send(json!({"type":"prompt","request_id":"browser-one","text":"local browser prompt"}))
        .unwrap();
    wait_for(&state, |snapshot| {
        snapshot.turns == 1 && snapshot.state == TurnState::Idle
    });
    assert_eq!(fixture.calls().len(), 1);
    assert_eq!(fixture.calls()[0]["model"], "vendor/model-a");
    let saved = sessions::load_session(&fixture.root, "browser-owned").unwrap();
    assert!(
        saved
            .transcript
            .iter()
            .any(|message| message.content == "owned fixture reply")
    );
    drop(client);
    runtime.shutdown().unwrap();
}
#[test]
fn owner_query_holds_full_lifetime_session_lease() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    assert!(SessionLease::acquire(&fixture.root, "browser-owned", "other").is_err());
    let client = state.claim_controller().unwrap();
    drop(client);
    assert!(SessionLease::acquire(&fixture.root, "browser-owned", "other").is_err());
    runtime.shutdown().unwrap();
    assert!(SessionLease::acquire(&fixture.root, "browser-owned", "other").is_ok());
    assert!(fixture.calls().is_empty());
}
#[test]
fn owner_query_second_controller_refused_and_detach_does_not_cancel() {
    let fixture = Fixture::new();
    fixture.mode(json!({"blocked":true}));
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    assert!(state.claim_controller().is_err());
    client
        .send(json!({"type":"prompt","request_id":"detached","text":"continue detached"}))
        .unwrap();
    drop(client);
    wait_for(&state, |snapshot| snapshot.state == TurnState::Running);
    let until = Instant::now() + Duration::from_secs(5);
    while fixture.calls().is_empty() {
        assert!(
            Instant::now() < until,
            "provider never captured the detached prompt"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut next = state.claim_controller().unwrap();
    assert_eq!(
        state.snapshot().unwrap().current_request.as_deref(),
        Some("detached")
    );
    next.send(json!({"type":"cancel"})).unwrap();
    drop(next);
    runtime.shutdown().unwrap();
    assert_eq!(fixture.calls().len(), 1);
}
#[test]
fn owner_query_pending_approval_recovers_exact_id_and_rejects_stale() {
    let fixture = Fixture::new();
    fixture.mode(json!({"tool":"Bash","arguments":{"command":"printf browser-fixture"}}));
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    client
        .send(json!({"type":"prompt","request_id":"approval","text":"request local tool"}))
        .unwrap();
    wait_for(&state, |snapshot| !snapshot.pending_approvals.is_empty());
    let first = state.snapshot().unwrap();
    let id = first.pending_approvals[0]["call_id"].clone();
    drop(client);
    let subscription = runtime.handle().subscribe(None).unwrap();
    assert_eq!(
        subscription.recovery.snapshot.unwrap().pending_approvals[0]["call_id"],
        id
    );
    let mut next = state.claim_controller().unwrap();
    assert!(
        next.send(json!({"type":"approval","call_id":"stale","verdict":"deny","note":null}))
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap().pending_approvals.len(), 1);
    next.send(json!({"type":"approval","call_id":id,"verdict":"deny","note":"fixture refusal"}))
        .unwrap();
    wait_for(&state, |snapshot| snapshot.turns == 1);
    assert_eq!(fixture.calls().len(), 2);
    drop(next);
    runtime.shutdown().unwrap();
}
#[test]
fn effort_set_and_reset_save_provenance_without_provider_requests() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    let high = client.send(choice(json!("high"))).unwrap();
    assert_eq!(
        high["snapshot"]["effort"],
        json!({"mode":"value","value":"high"})
    );
    assert_eq!(high["snapshot"]["resolved_effort"], "high");
    let reset = client
        .send(json!({"type":"set_effort","choice":{"mode":"default"}}))
        .unwrap();
    assert_eq!(reset["snapshot"]["effort"], json!({"mode":"default"}));
    assert_eq!(reset["snapshot"]["resolved_effort"], "low");
    let saved = sessions::load_session(&fixture.root, "browser-owned").unwrap();
    assert_eq!(
        serde_json::to_value(saved.effort).unwrap(),
        json!({"mode":"default"})
    );
    assert!(fixture.calls().is_empty());
    drop(client);
    runtime.shutdown().unwrap();
}
#[test]
fn effort_invalid_preserves_exact_saved_and_live_state() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    let before = serde_json::to_value(state.snapshot().unwrap()).unwrap();
    let saved = fs::read(fixture.root.join("sessions/browser-owned.json")).unwrap();
    assert!(client.send(choice(json!("impossible"))).is_err());
    assert_eq!(
        serde_json::to_value(state.snapshot().unwrap()).unwrap(),
        before
    );
    assert_eq!(
        fs::read(fixture.root.join("sessions/browser-owned.json")).unwrap(),
        saved
    );
    assert!(fixture.calls().is_empty());
    drop(client);
    runtime.shutdown().unwrap();
}
#[test]
fn effort_boolean_and_same_spelling_string_remain_distinct() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    assert!(client.send(choice(json!(false))).is_err());
    let selected = client.send(choice(json!("false"))).unwrap();
    assert_eq!(selected["snapshot"]["resolved_effort"], json!("false"));
    assert!(fixture.calls().is_empty());
    drop(client);
    runtime.shutdown().unwrap();
}
#[test]
fn effort_unknown_and_unsupported_are_distinct_and_reset_allowed() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    let unknown = client
        .send(json!({"type":"set_model","provider":"fixture","model":"unknown"}))
        .unwrap();
    assert!(unknown["snapshot"]["supported_efforts"].is_null());
    assert!(client.send(choice(json!("high"))).is_err());
    let unsupported = client
        .send(json!({"type":"set_model","provider":"fixture","model":"unsupported"}))
        .unwrap();
    assert_eq!(unsupported["snapshot"]["supported_efforts"], json!([]));
    client
        .send(json!({"type":"set_effort","choice":{"mode":"default"}}))
        .unwrap();
    assert!(fixture.calls().is_empty());
    drop(client);
    runtime.shutdown().unwrap();
}
#[test]
fn effort_reload_restores_exact_provider_raw_model_and_choice() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    client.send(choice(json!("high"))).unwrap();
    drop(client);
    runtime.shutdown().unwrap();
    let reloaded = fixture.start();
    let snapshot = reloaded.handle().snapshot().unwrap();
    assert_eq!(snapshot.provider, "fixture");
    assert_eq!(snapshot.model, "vendor/model-a");
    assert_eq!(
        serde_json::to_value(snapshot.effort).unwrap(),
        json!({"mode":"value","value":"high"})
    );
    assert_eq!(
        snapshot.resolved_effort,
        Some(orbit_adapter::types::EffortValue::Level("high".into()))
    );
    assert!(fixture.calls().is_empty());
    reloaded.shutdown().unwrap();
}
#[test]
fn reconnect_duplicate_prompt_keeps_one_provider_request() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    let prompt =
        json!({"type":"prompt","request_id":"stable-browser-id","text":"one local request"});
    client.send(prompt.clone()).unwrap();
    wait_for(&state, |snapshot| snapshot.turns == 1);
    drop(client);
    let mut reconnected = state.claim_controller().unwrap();
    let reply = reconnected.send(prompt).unwrap();
    assert_eq!(reply["ack"]["duplicate"], true);
    assert_eq!(fixture.calls().len(), 1);
    drop(reconnected);
    runtime.shutdown().unwrap();
}
#[test]
fn malformed_or_oversized_actions_never_dispatch() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    for value in [
        json!({"type":"prompt","request_id":"","text":"invalid identity"}),
        json!({"type":"effort","unexpected":true}),
        json!({"type":"set_effort","choice":{"mode":"value","value":123}}),
        json!({"type":"prompt","request_id":"large","text":"x".repeat(71*1024)}),
    ] {
        assert!(client.send(value.clone()).is_err(), "accepted {value}");
    }
    assert!(fixture.calls().is_empty());
    assert_eq!(state.snapshot().unwrap().turns, 0);
    drop(client);
    runtime.shutdown().unwrap();
}
#[tokio::test]
async fn transport_sse_initial_recovery_is_coherent_and_read_only() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/events")
                .header("host", "127.0.0.1:1234")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let frame = futures::StreamExt::next(&mut stream)
        .await
        .unwrap()
        .unwrap();
    let frame = String::from_utf8(frame.to_vec()).unwrap();
    assert!(frame.contains("event: recovery"));
    let data = frame
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    let recovery: Value = serde_json::from_str(data).unwrap();
    assert_eq!(recovery["snapshot"]["cursor"], recovery["cursor"]);
    assert_eq!(recovery["snapshot"]["model"], "vendor/model-a");
    assert!(state.claim_controller().is_ok());
    assert!(fixture.calls().is_empty());
    drop(stream);
    runtime.shutdown().unwrap();
}
#[tokio::test]
async fn transport_token_and_cross_origin_refusals_precede_subscription() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state =
        BridgeState::from_owner(runtime.handle(), Some("fixture-browser-token".into())).unwrap();
    for (uri, origin, want) in [
        ("/events", None, StatusCode::UNAUTHORIZED),
        ("/events?token=wrong", None, StatusCode::UNAUTHORIZED),
        (
            "/events?token=fixture-browser-token",
            Some("https://elsewhere.invalid"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut request = Request::builder().uri(uri).header("host", "127.0.0.1:1234");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = router(state.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), want);
    }
    assert!(runtime.handle().subscribe(None).is_ok());
    assert!(fixture.calls().is_empty());
    runtime.shutdown().unwrap();
}

#[tokio::test]
async fn tokenless_matching_foreign_host_and_origin_cannot_subscribe() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture
        .bridge(&runtime)
        .with_bound_address("127.0.0.1:1234".parse().unwrap());
    for host in [
        "attacker.invalid:1234",
        "127.0.0.1.attacker.invalid:1234",
        "user@127.0.0.1:1234",
    ] {
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .header("host", host)
                    .header("origin", format!("http://{host}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "accepted matching foreign authority {host}"
        );
    }
    assert!(fixture.calls().is_empty());
    runtime.shutdown().unwrap();
}

#[tokio::test]
async fn tokenless_loopback_authority_must_match_actual_bound_port() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture
        .bridge(&runtime)
        .with_bound_address("127.0.0.1:1234".parse().unwrap());
    for host in ["127.0.0.1:4321", "localhost:4321", "[::1]:4321"] {
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .header("host", host)
                    .header("origin", format!("http://{host}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "accepted wrong listening port {host}"
        );
    }
    assert!(fixture.calls().is_empty());
    runtime.shutdown().unwrap();
}

#[tokio::test]
async fn tokenless_actual_loopback_authorities_allow_read_only_subscription() {
    let fixture = Fixture::new();
    let runtime = fixture.start();
    let state = fixture
        .bridge(&runtime)
        .with_bound_address("127.0.0.1:1234".parse().unwrap());
    for host in ["127.0.0.1:1234", "localhost:1234", "[::1]:1234"] {
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .header("host", host)
                    .header("origin", format!("http://{host}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "refused local browser {host}"
        );
        drop(response);
    }
    assert!(fixture.calls().is_empty());
    runtime.shutdown().unwrap();
}
#[test]
fn reconnect_expired_cursor_requires_fresh_snapshot() {
    let mut fixture = Fixture::new();
    fixture.config.replay_capacity = 1;
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let initial = state.snapshot().unwrap().cursor;
    let mut client = state.claim_controller().unwrap();
    client.send(json!({"type":"effort"})).unwrap();
    client.send(json!({"type":"effort"})).unwrap();
    let recovered = runtime.handle().subscribe(Some(&initial)).unwrap();
    assert!(recovered.recovery.snapshot.is_some());
    assert!(recovered.recovery.events.is_empty());
    let current = state.snapshot().unwrap().cursor;
    let replay = runtime
        .handle()
        .subscribe(Some(&EventCursor {
            instance: current.instance,
            sequence: current.sequence - 1,
        }))
        .unwrap();
    assert_eq!(replay.recovery.events.len(), 1);
    assert!(replay.recovery.snapshot.is_none());
    assert!(fixture.calls().is_empty());
    drop(client);
    runtime.shutdown().unwrap();
}
#[test]
fn owner_display_recovery_never_exposes_hostile_tool_output_or_credentials() {
    let fixture = Fixture::new();
    fixture.mode(json!({"reply":"safe public line\nAPI_KEY = sk-1234567890123456789012345678901234567890\n<script>alert(1)</script>"}));
    let runtime = fixture.start();
    let state = fixture.bridge(&runtime);
    let mut client = state.claim_controller().unwrap();
    client
        .send(json!({"type":"prompt","request_id":"display","text":"local display fixture"}))
        .unwrap();
    wait_for(&state, |snapshot| snapshot.turns == 1);
    let encoded =
        serde_json::to_string(&runtime.handle().subscribe(None).unwrap().recovery).unwrap();
    assert!(!encoded.contains("sk-1234567890123456789012345678901234567890"));
    assert!(encoded.contains("safe public line"));
    drop(client);
    runtime.shutdown().unwrap();
}

#[cfg(unix)]
mod context_browser_tests {
    use super::*;
    use orbit_adapter::types::{ChatMessage, ChatRole};

    fn configure(
        f: &mut Fixture,
        main_limit: Option<Value>,
        summary_limit: Option<Value>,
        history: Vec<ChatMessage>,
    ) {
        let mut config = orbit_cli::config::ProvidersConfig::load(&f.root).unwrap();
        config.provider[0].models[0].context_window = None;
        config.provider[0].models[0].max_output_tokens = Some(1024);
        config.provider[0].models[0].context_limits =
            main_limit.map(|value| serde_json::from_value(value).unwrap());
        config.provider[0].models[1].context_window = None;
        config.provider[0].models[1].max_output_tokens = Some(512);
        config.provider[0].models[1].context_limits =
            summary_limit.map(|value| serde_json::from_value(value).unwrap());
        config.roles.compaction = "fixture/model-b".into();
        config.save_atomic(&f.root).unwrap();
        f.config.turn.initial_transcript = history;
    }
    fn prompt(client: &mut orbit_web::BridgeController) {
        client.send(json!({"type":"prompt","request_id":"budget-browser","text":"continue this bounded request"})).unwrap();
    }
    fn assert_budget_refusal(runtime: &OwnerRuntime, cursor: &EventCursor) {
        let recovery = runtime.handle().subscribe(Some(cursor)).unwrap().recovery;
        assert!(
            recovery.events.iter().any(|event| event.kind == "error"
                && event.payload["message"]
                    .as_str()
                    .is_some_and(|message| message
                        .to_ascii_lowercase()
                        .contains("context budget"))),
            "browser fixture must reach actual budget refusal"
        );
    }
    #[test]
    fn browser_actual_controller_selected_budget_refuses_before_post() {
        let mut f = Fixture::new();
        configure(
            &mut f,
            Some(json!({"input_tokens":1})),
            Some(json!({"input_tokens":50_000})),
            vec![],
        );
        let runtime = f.start();
        let cursor = runtime.handle().snapshot().unwrap().cursor;
        let state = f.bridge(&runtime);
        let mut client = state.claim_controller().unwrap();
        prompt(&mut client);
        wait_for(&state, |snapshot| {
            snapshot.state == TurnState::Idle && snapshot.turns == 1
        });
        assert!(f.calls().is_empty());
        assert_budget_refusal(&runtime, &cursor);
        drop(client);
        runtime.shutdown().unwrap();
    }
    #[test]
    fn browser_actual_controller_summary_budget_refuses_before_both_posts() {
        let mut f = Fixture::new();
        let history = (0..38)
            .map(|index| ChatMessage {
                role: if index % 2 == 0 {
                    ChatRole::User
                } else {
                    ChatRole::Assistant
                },
                content: if index < 32 {
                    format!("OLD-{index}:{}", "x".repeat(12_000))
                } else {
                    format!("TAIL-{index}")
                },
                tool_calls: None,
                tool_call_id: None,
                tool_result: None,
                blocks: None,
                origin_model: None,
                origin_provider: None,
            })
            .collect();
        configure(
            &mut f,
            Some(json!({"input_tokens":64_000})),
            Some(json!({"input_tokens":1})),
            history,
        );
        let runtime = f.start();
        let cursor = runtime.handle().snapshot().unwrap().cursor;
        let state = f.bridge(&runtime);
        let mut client = state.claim_controller().unwrap();
        prompt(&mut client);
        wait_for(&state, |snapshot| {
            snapshot.state == TurnState::Idle && snapshot.turns == 1
        });
        assert!(f.calls().is_empty());
        assert_budget_refusal(&runtime, &cursor);
        drop(client);
        runtime.shutdown().unwrap();
    }
    #[tokio::test]
    async fn browser_actual_sse_preserves_safe_fallback_notice_and_exact_usage() {
        let mut f = Fixture::new();
        configure(&mut f, None, Some(json!({"input_tokens":50_000})), vec![]);
        let runtime = f.start();
        let state = f.bridge(&runtime);
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .header("host", "127.0.0.1:1234")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let mut client = state.claim_controller().unwrap();
        prompt(&mut client);
        let end = Instant::now() + Duration::from_secs(5);
        let mut buffered = String::new();
        let mut events = Vec::new();
        let mut done = false;
        while !done {
            let remaining = end.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "browser SSE fixture deadline");
            let chunk = tokio::time::timeout(remaining, futures::StreamExt::next(&mut stream))
                .await
                .expect("browser SSE fixture deadline")
                .expect("browser SSE ended early")
                .unwrap();
            buffered.push_str(std::str::from_utf8(&chunk).unwrap());
            while let Some(cut) = buffered.find("\n\n") {
                let frame = buffered[..cut].to_owned();
                buffered.drain(..cut + 2);
                let kind = frame.lines().find_map(|line| line.strip_prefix("event: "));
                let Some(data) = frame.lines().find_map(|line| line.strip_prefix("data: ")) else {
                    continue;
                };
                let value: Value = serde_json::from_str(data).unwrap();
                if let Some(kind) = kind {
                    events.push((kind.to_owned(), value));
                    if kind == "turn_ended" {
                        done = true;
                    }
                }
            }
        }
        let statuses = events
            .iter()
            .filter(|(kind, _)| kind == "status")
            .filter_map(|(_, value)| value["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(statuses.to_ascii_lowercase().contains("fallback"));
        assert!(statuses.contains("64000") || statuses.contains("64,000"));
        assert!(!statuses.contains(&f.config.turn.gate));
        let usage: Vec<_> = events.iter().filter(|(kind, _)| kind == "usage").collect();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].1["window_tokens"], 64_000);
        assert_eq!(usage[0].1["breakdown"]["reserve"], 1024);
        assert_eq!(usage[0].1["breakdown"]["compact_at"], 56_576);
        assert_eq!(f.calls().len(), 1);
        drop(client);
        drop(stream);
        runtime.shutdown().unwrap();
    }
}
