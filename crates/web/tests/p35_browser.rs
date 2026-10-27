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
    os::unix::fs::{DirBuilderExt, PermissionsExt},
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
        fs::set_permissions(
            root.join("providers.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
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
    fn price_default_model_for_test(&self) {
        let path = self.root.join("providers.toml");
        let current = fs::read_to_string(&path).unwrap();
        let marker = "id=\"vendor/model-a\"\n";
        assert!(current.contains(marker));
        let replacement = format!(
            "{marker}[provider.models.billing]\nversion=2\ninput_per_million_microdollars=0\noutput_per_million_microdollars=0\nrequest_flat_microdollars=17\nreasoning_counter_basis=\"included_in_output\"\nreasoning_rate_policy=\"output_rate\"\n"
        );
        let configured = current.replacen(marker, &replacement, 1);
        let duplicate = format!(
            "\n[[provider]]\nname=\"shadow\"\nurl={:?}\n[[provider.models]]\nid=\"vendor/model-a\"\n[provider.models.billing]\nversion=2\ninput_per_million_microdollars=0\noutput_per_million_microdollars=0\nrequest_flat_microdollars=99\nreasoning_counter_basis=\"included_in_output\"\nreasoning_rate_policy=\"output_rate\"\n",
            "http://127.0.0.1:1"
        );
        fs::write(&path, format!("{duplicate}{configured}")).unwrap();
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
    fixture.price_default_model_for_test();
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
    let snapshot = state.snapshot().unwrap();
    assert_eq!(snapshot.provider, "fixture");
    assert_eq!(snapshot.cost_microcents, 17);
    assert_eq!(
        snapshot.accounting.unwrap().full_cost_status,
        orbit_cli::session_accounting::FullCostStatus::Known
    );
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
        let history: Vec<ChatMessage> = (0..38)
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
            history.clone(),
        );
        let runtime = f.start();
        let initial_saved = sessions::load_session(&f.root, "browser-owned").unwrap();
        let initial_checkpoint =
            orbit_cli::context_history::context_journal(&f.root, "browser-owned", None)
                .unwrap()
                .accounting_checkpoint()
                .unwrap();
        assert_eq!(
            initial_checkpoint.baseline,
            orbit_engine::AccountingBaseline::UnknownLegacy
        );
        assert_eq!(initial_checkpoint.owner_session_id, "browser-owned");
        assert!(initial_checkpoint.child_id.is_none());
        assert_eq!(initial_checkpoint.revision.0, 0);
        assert!(initial_checkpoint.pending.is_none());
        assert_eq!(
            initial_checkpoint.totals,
            orbit_engine::AccountingDelta::unknown_legacy()
        );
        assert_eq!(
            initial_checkpoint.known_priced_subtotals,
            Some(orbit_engine::KnownPricedSubtotals::known_zero())
        );
        let cursor = runtime.handle().snapshot().unwrap().cursor;
        let state = f.bridge(&runtime);
        let mut client = state.claim_controller().unwrap();
        prompt(&mut client);
        wait_for(&state, |snapshot| {
            snapshot.state == TurnState::Idle && snapshot.turns == 1
        });
        assert!(f.calls().is_empty());
        let recovery = runtime.handle().subscribe(Some(&cursor)).unwrap().recovery;
        let snapshot = runtime.handle().snapshot().unwrap();
        assert_eq!(snapshot.state, TurnState::Idle);
        assert_eq!(snapshot.turns, 1);
        assert_eq!(
            snapshot.requests["budget-browser"].state,
            orbit_cli::daemon::RequestState::Failed
        );
        assert_eq!(
            (
                snapshot.input_tokens,
                snapshot.output_tokens,
                snapshot.cost_microcents
            ),
            (0, 0, 0)
        );
        drop(client);
        runtime.shutdown().unwrap();
        let lease =
            SessionLease::acquire(&f.root, "browser-owned", "inspect-browser-budget").unwrap();
        let saved = lease.load().unwrap();
        let mut expected = history;
        expected.push(ChatMessage {
            role: ChatRole::User,
            content: "continue this bounded request".into(),
            tool_calls: None,
            tool_call_id: None,
            tool_result: None,
            blocks: None,
            origin_model: None,
            origin_provider: None,
        });
        assert_eq!(saved.transcript, expected);
        assert_eq!(saved.turns, 1);
        assert_eq!(
            (
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (0, 0, 0)
        );
        assert_eq!(
            (&saved.model, &saved.provider, &saved.gate, &saved.effort),
            (
                &initial_saved.model,
                &initial_saved.provider,
                &initial_saved.gate,
                &initial_saved.effort
            )
        );
        let journal =
            orbit_cli::context_history::context_journal(&f.root, "browser-owned", None).unwrap();
        let checkpoint = journal.accounting_checkpoint().unwrap();
        assert_eq!(checkpoint, initial_checkpoint);
        let watermark = saved.accounting_watermark.as_ref().unwrap();
        assert_eq!(watermark.owner_session_id, "browser-owned");
        assert!(watermark.child_id.is_none());
        assert_eq!(watermark.revision, checkpoint.revision.0);
        assert_eq!(
            watermark.full_cost_status,
            orbit_cli::session_accounting::FullCostStatus::UnknownLegacy
        );
        let config = orbit_cli::config::ProvidersConfig::load(&f.root).unwrap();
        assert_eq!(config.provider[0].models[0].max_output_tokens, Some(1024));
        assert_eq!(config.provider[0].models[1].max_output_tokens, Some(512));
        assert_eq!(
            serde_json::to_value(config.provider[0].models[0].context_limits).unwrap(),
            json!({"input_tokens":64_000})
        );
        assert_eq!(
            serde_json::to_value(config.provider[0].models[1].context_limits).unwrap(),
            json!({"input_tokens":1})
        );
        assert_eq!(config.roles.compaction, "fixture/model-b");
        assert!(f.calls().is_empty());
        assert!(
            recovery.events.iter().any(|event| event.kind == "error"
                && event.payload["message"].as_str()
                    == Some("context summary cannot fit its independently selected budget")),
            "browser must reach the exact independent summary-budget refusal: {:?}",
            recovery
                .events
                .iter()
                .filter(|event| event.kind == "error")
                .map(|event| &event.payload)
                .collect::<Vec<_>>()
        );
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
use orbit_cli::daemon as manual_baseline_owner_api;

#[cfg(target_os = "linux")]
mod manual_browser_baseline {
    use super::manual_baseline_support::*;
    use super::*;

    #[test]
    fn raw_browser_compact_accepts_no_history_without_prompt_turn_or_post() {
        if !dispatch_isolated(
            "manual_browser_baseline::raw_browser_compact_accepts_no_history_without_prompt_turn_or_post",
        ) {
            return;
        }
        require_private_system_fixture();
        let fixture = Fixture::new();
        let runtime = fixture.start();
        let handle = runtime.handle();
        let state = fixture.bridge(&runtime);
        let journal =
            orbit_cli::context_history::context_journal(&fixture.root, "browser-owned", None)
                .unwrap();
        let before_revision = journal.accounting_checkpoint().unwrap().revision.0;
        let mut client = state.claim_controller().unwrap();
        let unknown = client.send(json!({"type":"still_unknown_manual_action"}));
        let reply = client.send(json!({"type":"compact","request_id":"browser-manual-empty"}));
        let ended = if reply.is_ok() {
            terminal(&handle, "browser-manual-empty")
        } else {
            None
        };
        let duplicate = if ended.is_some() {
            Some(client.send(json!({"type":"compact","request_id":"browser-manual-empty"})))
        } else {
            None
        };
        let snapshot = serde_json::to_value(state.snapshot().unwrap()).unwrap();
        let saved = sessions::load_session(&fixture.root, "browser-owned").unwrap();
        let after_revision = journal.accounting_checkpoint().unwrap().revision.0;
        drop(client);
        runtime.shutdown().unwrap();
        assert!(unknown.is_err());
        assert!(fixture.calls().is_empty());
        assert_eq!(saved.turns, 0);
        assert!(saved.transcript.is_empty());
        assert_eq!(snapshot["turns"], 0);
        assert_eq!(snapshot["messages"], json!([]));
        assert_eq!(before_revision, 0);
        assert_eq!(after_revision, before_revision);
        assert!(
            reply.is_ok(),
            "existing BridgeController JSON should reach shared manual no-op: {reply:?}"
        );
        let reply = reply.unwrap();
        assert_eq!(reply["ack"]["request_id"], "browser-manual-empty");
        assert!(
            ended.is_some(),
            "manual browser action must finish without a user turn"
        );
        assert_eq!(
            snapshot["requests"]["browser-manual-empty"]["state"],
            "completed"
        );
        let duplicate = duplicate.unwrap().unwrap();
        assert_eq!(duplicate["ack"]["duplicate"], true);
    }

    async fn sse_recovery(state: BridgeState, uri: &str) -> Value {
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("host", "127.0.0.1:1234")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            futures::StreamExt::next(&mut stream),
        )
        .await
        .expect("initial SSE recovery timed out")
        .unwrap()
        .unwrap();
        assert!(frame.len() <= 128 * 1024);
        let frame = String::from_utf8(frame.to_vec()).unwrap();
        assert!(frame.contains("event: recovery"));
        let data = frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        let recovery = serde_json::from_str(data).unwrap();
        drop(stream);
        recovery
    }

    #[tokio::test]
    async fn legacy_known_subset_reaches_cold_and_expired_browser_sse_after_restart() {
        if !dispatch_isolated(
            "manual_browser_baseline::legacy_known_subset_reaches_cold_and_expired_browser_sse_after_restart",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut fixture = Fixture::new();
        fixture.config.replay_capacity = 1;
        let seed = seed_legacy(&fixture.root, &fixture.config);
        let runtime = fixture.start();
        let state = fixture.bridge(&runtime);
        let initial = state.snapshot().unwrap().cursor;
        let live = serde_json::to_value(state.snapshot().unwrap()).unwrap();
        let cold = sse_recovery(state.clone(), "/events").await;
        let mut client = state.claim_controller().unwrap();
        let ack = client.send(json!({"type":"effort"})).unwrap();
        client.send(json!({"type":"effort"})).unwrap();
        let expired_uri = format!(
            "/events?instance={}&sequence={}",
            initial.instance, initial.sequence
        );
        let expired = sse_recovery(state.clone(), &expired_uri).await;
        drop(client);
        drop(state);
        runtime.shutdown().unwrap();
        let runtime = fixture.start();
        let state = fixture.bridge(&runtime);
        let restarted = sse_recovery(state.clone(), "/events").await;
        let restarted_live = serde_json::to_value(state.snapshot().unwrap()).unwrap();
        drop(state);
        runtime.shutdown().unwrap();
        assert!(fixture.calls().is_empty());
        assert_eq!(cold["events"], json!([]));
        assert_eq!(expired["events"], json!([]));
        assert_eq!(restarted["events"], json!([]));
        for recovery in [&cold, &expired, &restarted] {
            assert_eq!(recovery["snapshot"]["cursor"], recovery["cursor"]);
        }
        for snapshot in [
            &live,
            &ack["snapshot"],
            &cold["snapshot"],
            &expired["snapshot"],
            &restarted["snapshot"],
            &restarted_live,
        ] {
            assert_legacy_controls(snapshot);
            missing_accounting_control(snapshot);
        }
        assert_saved_legacy(&fixture.root, "browser-owned", &seed);
        for snapshot in [
            &live,
            &ack["snapshot"],
            &cold["snapshot"],
            &expired["snapshot"],
            &restarted["snapshot"],
            &restarted_live,
        ] {
            assert_cold_accounting(snapshot);
        }
    }
}

#[cfg(target_os = "linux")]
mod manual_browser_capability {
    use super::manual_baseline_owner_api as owner_api;
    use super::manual_baseline_support::*;
    use super::*;

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
            "[[provider]]\nname='manual_main'\nurl={:?}\nenv={main_env:?}\n[[provider.models]]\nid='family/shared-manual'\nmax_output_tokens=73\ncontext_limits={{input_tokens=8192}}\nsupported_efforts=['low','high']\ndefault_effort='low'\n[provider.models.pricing]\n{pricing}request_flat_microdollars=91\n[[provider]]\nname='manual_summary'\nurl={:?}\nenv={summary_env:?}\n[[provider.models]]\nid='family/shared-manual'\nmax_output_tokens=37\ncontext_limits={{input_tokens=65536}}\nsupported_efforts=['medium','high']\ndefault_effort='medium'\n[provider.models.pricing]\n{pricing}request_flat_microdollars=17\n[provider.models.billing]\nversion=2\ninput_per_million_microdollars=0\noutput_per_million_microdollars=0\ncache_read_per_million_microdollars=0\ncache_write_per_million_microdollars=0\nrequest_flat_microdollars=17\nreasoning_counter_basis='included_in_output'\nreasoning_rate_policy='output_rate'\n[roles]\nmain='manual_main/family/shared-manual'\ncompaction='manual_summary/family/shared-manual'\n[routing.phases.coding]\ndefault='manual_summary/family/shared-manual'\nhard='manual_summary/family/shared-manual'\n[routing.phase_keywords]\nclear=true\ncoding=['compact']\n",
            format!("{base}/main/v1?binding=main"),
            format!("{base}/summary/v1?binding=summary")
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
    async fn recovery(state: BridgeState, uri: &str) -> Value {
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("host", "127.0.0.1:1234")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            futures::StreamExt::next(&mut stream),
        )
        .await
        .expect("manual recovery deadline")
        .unwrap()
        .unwrap();
        assert!(frame.len() <= 128 * 1024);
        let frame = std::str::from_utf8(&frame).unwrap();
        let data = frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        serde_json::from_str(data).unwrap()
    }
    fn upgrade(
        address: std::net::SocketAddr,
        query: &str,
        origin: &str,
    ) -> (std::net::TcpStream, String) {
        use std::io::{Read, Write};
        let mut socket =
            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(socket,"GET /actions{query} HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").unwrap();
        socket.flush().unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            assert!(headers.len() < 16384);
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            headers.push(byte[0]);
        }
        (socket, String::from_utf8(headers).unwrap())
    }
    fn ws_send(socket: &mut std::net::TcpStream, value: Value) {
        use std::io::Write;
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(bytes.len() < 65536);
        let mut frame = vec![0x81];
        if bytes.len() < 126 {
            frame.push(0x80 | bytes.len() as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        let mask = [0x52, 0x38, 0x19, 0x71];
        frame.extend_from_slice(&mask);
        frame.extend(bytes.iter().enumerate().map(|(i, byte)| byte ^ mask[i % 4]));
        socket.write_all(&frame).unwrap();
        socket.flush().unwrap();
    }
    fn ws_read(socket: &mut std::net::TcpStream) -> Value {
        use std::io::Read;
        let mut header = [0; 2];
        socket.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 0x81);
        assert_eq!(header[1] & 0x80, 0);
        let length = match header[1] & 0x7f {
            126 => {
                let mut bytes = [0; 2];
                socket.read_exact(&mut bytes).unwrap();
                u16::from_be_bytes(bytes) as u64
            }
            127 => {
                let mut bytes = [0; 8];
                socket.read_exact(&mut bytes).unwrap();
                u64::from_be_bytes(bytes)
            }
            n => u64::from(n),
        };
        assert!(length <= 128 * 1024);
        let mut bytes = vec![0; length as usize];
        socket.read_exact(&mut bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_websocket_manual_action_and_actual_sse_apply_once_with_exact_archive() {
        if !dispatch_isolated(
            "manual_browser_capability::authenticated_websocket_manual_action_and_actual_sse_apply_once_with_exact_archive",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut f = Fixture::new();
        let original = prepare(&mut f);
        mode(&f, json!({"reply":SUMMARY}));
        let runtime = f.start();
        let handle = runtime.handle();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = BridgeState::from_owner(
            handle.clone(),
            Some("synthetic-manual-browser-token".into()),
        )
        .unwrap()
        .with_bound_address(address);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server_state = state.clone();
        let serving = tokio::spawn(async move {
            axum::serve(listener, router(server_state))
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap()
        });
        for (query, origin, status) in [
            ("", format!("http://{address}"), "401"),
            ("?token=wrong", format!("http://{address}"), "401"),
            (
                "?token=synthetic-manual-browser-token",
                "https://elsewhere.invalid".into(),
                "403",
            ),
        ] {
            let (socket, headers) = upgrade(address, query, &origin);
            assert!(
                headers.starts_with(&format!("HTTP/1.1 {status}")),
                "{headers}"
            );
            drop(socket);
        }
        assert!(bounded_calls(&f).is_empty());
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/events?token=synthetic-manual-browser-token")
                    .header("host", address.to_string())
                    .header("origin", format!("http://{address}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let (mut socket, headers) = upgrade(
            address,
            "?token=synthetic-manual-browser-token",
            &format!("http://{address}"),
        );
        assert!(headers.starts_with("HTTP/1.1 101"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=")
        );
        assert_eq!(ws_read(&mut socket)["type"], "controller_ready");
        let (foreign, refused) = upgrade(
            address,
            "?token=synthetic-manual-browser-token",
            &format!("http://{address}"),
        );
        assert!(refused.starts_with("HTTP/1.1 409"));
        drop(foreign);
        for action in [
            json!({"type":"compact"}),
            json!({"type":"compact","request_id":"invalid-fields","text":"not a model prompt"}),
        ] {
            ws_send(&mut socket, action);
            assert_eq!(ws_read(&mut socket)["type"], "action_error");
        }
        assert!(bounded_calls(&f).is_empty());
        ws_send(
            &mut socket,
            json!({"type":"compact","request_id":"actual-browser-manual"}),
        );
        let ack = ws_read(&mut socket);
        assert_eq!(ack["ack"]["request_id"], "actual-browser-manual");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buffer = String::new();
        let mut events = Vec::new();
        let mut received = 0usize;
        let mut done = false;
        while !done {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero());
            let chunk = tokio::time::timeout(remaining, futures::StreamExt::next(&mut stream))
                .await
                .expect("manual SSE deadline")
                .unwrap()
                .unwrap();
            received = received.checked_add(chunk.len()).unwrap();
            assert!(received <= 512 * 1024);
            buffer.push_str(std::str::from_utf8(&chunk).unwrap());
            while let Some(cut) = buffer.find("\n\n") {
                let frame = buffer[..cut].to_owned();
                buffer.drain(..cut + 2);
                let kind = frame.lines().find_map(|line| line.strip_prefix("event: "));
                if let Some(data) = frame.lines().find_map(|line| line.strip_prefix("data: ")) {
                    let value: Value = serde_json::from_str(data).unwrap();
                    if kind == Some("request_finished")
                        && value["request_id"] == "actual-browser-manual"
                    {
                        done = true;
                    }
                    assert!(events.len() < 64);
                    events.push((kind.map(str::to_owned), value));
                }
            }
        }
        let terminal = ended(&handle, "actual-browser-manual");
        assert_eq!(terminal.turns, 7);
        assert_eq!(
            terminal.requests["actual-browser-manual"].state,
            owner_api::RequestState::Completed
        );
        assert_eq!(terminal.accounting.as_ref().unwrap().revision, 2);
        assert_eq!(
            terminal.accounting.as_ref().unwrap().full_cost_status,
            orbit_cli::session_accounting::FullCostStatus::Known
        );
        assert!(!events.iter().any(|(kind, _)| matches!(
            kind.as_deref(),
            Some("text_delta" | "turn_ended" | "response_finished" | "tool_call_started")
        )));
        for (kind, value) in &events {
            if kind.as_deref() == Some("compacted") {
                assert_eq!(value["summary"], "");
            }
        }
        ws_send(
            &mut socket,
            json!({"type":"compact","request_id":"actual-browser-manual"}),
        );
        assert_eq!(ws_read(&mut socket)["ack"]["duplicate"], true);
        drop(socket);
        drop(stream);
        drop(state);
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("browser server shutdown deadline")
            .unwrap();
        runtime.shutdown().unwrap();
        assert_summary_wire(&f, 1);
        assert_archive(&f, &original);
    }

    #[test]
    fn running_bridge_manual_cancel_keeps_live_uncertainty_and_blocks_busy_and_cross_kind_replay() {
        if !dispatch_isolated(
            "manual_browser_capability::running_bridge_manual_cancel_keeps_live_uncertainty_and_blocks_busy_and_cross_kind_replay",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut f = Fixture::new();
        let original = prepare(&mut f);
        mode(&f, json!({"blocked":true,"reply":SUMMARY}));
        let runtime = f.start();
        let handle = runtime.handle();
        let state = f.bridge(&runtime);
        let mut client = state.claim_controller().unwrap();
        let started = Instant::now();
        let ack = client
            .send(json!({"type":"compact","request_id":"browser-held"}))
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(ack["ack"]["state"], "accepted");
        let deadline = Instant::now() + Duration::from_secs(3);
        while bounded_calls(&f).is_empty() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_active_uncertainty(
            &f,
            &serde_json::to_value(state.snapshot().unwrap()).unwrap(),
        );
        assert_active_uncertainty(
            &f,
            &serde_json::to_value(handle.subscribe(None).unwrap().recovery.snapshot.unwrap())
                .unwrap(),
        );
        assert!(state.claim_controller().is_err());
        assert_eq!(
            client
                .send(json!({"type":"compact","request_id":"browser-held"}))
                .unwrap()["ack"]["duplicate"],
            true
        );
        assert!(
            client
                .send(json!({"type":"compact","request_id":"browser-busy-new"}))
                .is_err()
        );
        assert!(
            client
                .send(json!({"type":"prompt","request_id":"browser-held","text":"foreign kind"}))
                .is_err()
        );
        assert!(
            !state
                .snapshot()
                .unwrap()
                .requests
                .contains_key("browser-busy-new")
        );
        let start = Instant::now();
        client.send(json!({"type":"cancel"})).unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        let terminal = ended(&handle, "browser-held");
        assert_eq!(terminal.state, TurnState::Interrupted);
        assert_eq!(
            terminal.requests["browser-held"].state,
            owner_api::RequestState::Unknown
        );
        assert_eq!(
            terminal.accounting.unwrap().full_cost_status,
            orbit_cli::session_accounting::FullCostStatus::Uncertain
        );
        assert!(checkpoint(&f).pending.unwrap().uncertain);
        assert_eq!(
            sessions::load_session(&f.root, &f.config.turn.session_id)
                .unwrap()
                .transcript,
            original
        );
        drop(client);
        drop(state);
        runtime.shutdown().unwrap();
        assert_summary_wire(&f, 1);
    }

    #[test]
    fn browser_strict_manual_id_and_extra_field_refusals_do_not_create_requests_or_prompts() {
        if !dispatch_isolated(
            "manual_browser_capability::browser_strict_manual_id_and_extra_field_refusals_do_not_create_requests_or_prompts",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        let runtime = f.start();
        let state = f.bridge(&runtime);
        let before = serde_json::to_value(state.snapshot().unwrap()).unwrap();
        let mut client = state.claim_controller().unwrap();
        for action in [
            json!({"type":"compact"}),
            json!({"type":"compact","request_id":""}),
            json!({"type":"compact","request_id":"x".repeat(129)}),
            json!({"type":"compact","request_id":"space invalid"}),
            json!({"type":"compact","request_id":"unicode-λ"}),
            json!({"type":"compact","request_id":"extra","text":"untrusted prompt"}),
            json!({"type":"compact","request_id":"extra","force":true}),
        ] {
            assert!(client.send(action).is_err());
        }
        let after = serde_json::to_value(state.snapshot().unwrap()).unwrap();
        assert_eq!(after["requests"], before["requests"]);
        assert_eq!(after["messages"], before["messages"]);
        assert_eq!(after["turns"], before["turns"]);
        drop(client);
        drop(state);
        runtime.shutdown().unwrap();
        assert!(bounded_calls(&f).is_empty());
        assert_eq!(checkpoint(&f).revision.0, 0);
    }

    #[tokio::test]
    async fn paid_manual_cold_expired_and_restarted_sse_preserve_exact_once_known_bill() {
        if !dispatch_isolated(
            "manual_browser_capability::paid_manual_cold_expired_and_restarted_sse_preserve_exact_once_known_bill",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut f = Fixture::new();
        let original = prepare(&mut f);
        f.config.replay_capacity = 1;
        mode(&f, json!({"reply":SUMMARY}));
        let runtime = f.start();
        let state = f.bridge(&runtime);
        let initial = state.snapshot().unwrap().cursor;
        let mut client = state.claim_controller().unwrap();
        client
            .send(json!({"type":"compact","request_id":"browser-paid-cold"}))
            .unwrap();
        ended(&runtime.handle(), "browser-paid-cold");
        let cold = recovery(state.clone(), "/events").await;
        let expired = recovery(
            state.clone(),
            &format!(
                "/events?instance={}&sequence={}",
                initial.instance, initial.sequence
            ),
        )
        .await;
        drop(client);
        drop(state);
        runtime.shutdown().unwrap();
        let before = checkpoint(&f);
        let runtime = f.start();
        let state = f.bridge(&runtime);
        let restarted = recovery(state.clone(), "/events").await;
        drop(state);
        runtime.shutdown().unwrap();
        for recovery in [cold, expired, restarted] {
            let snapshot = &recovery["snapshot"];
            assert_eq!(snapshot["cursor"], recovery["cursor"]);
            assert_eq!(snapshot["turns"], 7);
            assert_eq!(snapshot["input_tokens"], 2);
            assert_eq!(snapshot["output_tokens"], 3);
            assert_eq!(snapshot["cost_microcents"], 17);
            assert_eq!(
                snapshot["accounting"],
                json!({"revision":2,"full_cost_status":"known"})
            );
            assert_eq!(snapshot["requests"]["browser-paid-cold"]["kind"], "compact");
        }
        assert_eq!(checkpoint(&f), before);
        assert_summary_wire(&f, 1);
        assert_archive(&f, &original);
    }

    #[tokio::test]
    async fn failed_browser_journal_inspection_clears_prior_known_metadata_from_cold_sse() {
        if !dispatch_isolated(
            "manual_browser_capability::failed_browser_journal_inspection_clears_prior_known_metadata_from_cold_sse",
        ) {
            return;
        }
        require_private_system_fixture();
        let mut f = Fixture::new();
        prepare(&mut f);
        mode(&f, json!({"reply":SUMMARY}));
        let runtime = f.start();
        let state = f.bridge(&runtime);
        let mut client = state.claim_controller().unwrap();
        client
            .send(json!({"type":"compact","request_id":"first-known"}))
            .unwrap();
        ended(&runtime.handle(), "first-known");
        assert_eq!(
            state
                .snapshot()
                .unwrap()
                .accounting
                .unwrap()
                .full_cost_status,
            orbit_cli::session_accounting::FullCostStatus::Known
        );
        fs::write(
            f.root
                .join("context-history")
                .join(&f.config.turn.session_id)
                .join("accounting.json"),
            b"{",
        )
        .unwrap();
        client
            .send(json!({"type":"compact","request_id":"bad-inspection"}))
            .unwrap();
        let failed = ended(&runtime.handle(), "bad-inspection");
        assert!(failed.accounting.is_none());
        let cold = recovery(state.clone(), "/events").await;
        assert!(
            cold["snapshot"]
                .get("accounting")
                .is_none_or(Value::is_null)
        );
        assert_eq!(cold["snapshot"]["cost_microcents"], 17);
        assert_eq!(cold["snapshot"]["turns"], 7);
        drop(client);
        drop(state);
        runtime.shutdown().unwrap();
        assert_summary_wire(&f, 1);
    }
}
