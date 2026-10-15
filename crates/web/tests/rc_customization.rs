#![cfg(unix)]
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use orbit_cli::{
    customization::LocalProfileHost,
    daemon::{OwnerConfig, OwnerRuntime},
    sessions::SessionLease,
    tool_runtime::PermissionScope,
    tui_worker::TuiTurnConfig,
};
use orbit_frontend_protocol::customization::*;
use orbit_web::{BridgeState, router};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tower::ServiceExt;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    work: PathBuf,
    provider: Child,
    config: OwnerConfig,
    host: Arc<LocalProfileHost>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-web-customize-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let home = root.join("home");
        let work = root.join("work");
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&work).unwrap();
        let mut provider = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/p35_provider.py"
            ))
            .arg(&root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let ready: Value = loop {
            assert!(Instant::now() < until);
            assert!(provider.try_wait().unwrap().is_none());
            if let Ok(bytes) = fs::read(root.join("ready.json"))
                && let Ok(value) = serde_json::from_slice(&bytes)
            {
                break value;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let gate = ready["gate"].as_str().unwrap().to_owned();
        fs::write(home.join("providers.toml"),format!("[[provider]]\nname=\"fixture\"\nurl={gate:?}\n[[provider.models]]\nid=\"local\"\nsupported_efforts=[\"low\",\"high\"]\ndefault_effort=\"low\"\n")).unwrap();
        let turn = TuiTurnConfig {
            home: home.clone(),
            session_id: "customization-session".into(),
            gate,
            model: "local".into(),
            provider_id: "fixture".into(),
            effort: None,
            auto_tools: false,
            scope: PermissionScope::default(),
            initial_transcript: vec![],
            initial_turns: 0,
            initial_input_tokens: 55,
            initial_output_tokens: 21,
            initial_cost_microcents: 100,
        };
        let config = OwnerConfig::new(turn, work.clone());
        let host = Arc::new(LocalProfileHost {
            home: home.clone(),
            workspace: work.clone(),
            scope: PermissionScope::default(),
        });
        let profile = Profile {
            panes: vec![
                PaneDef {
                    id: "notes".into(),
                    title: "Named notes".into(),
                    surfaces: vec![Surface::Browser, Surface::Terminal],
                    source: PaneSource::MarkdownFile {
                        path: "notes.md".into(),
                    },
                    actions: vec![
                        PaneAction::Refresh,
                        PaneAction::InsertPrompt {
                            text: "review evidence".into(),
                        },
                        PaneAction::FocusConversation,
                        PaneAction::OwnerCancel,
                    ],
                },
                PaneDef {
                    id: "usage".into(),
                    title: "Actual usage".into(),
                    surfaces: vec![Surface::Browser],
                    source: PaneSource::Snapshot {
                        snapshot: SnapshotKind::Usage,
                    },
                    actions: vec![PaneAction::Refresh],
                },
            ],
            ..Profile::default()
        };
        fs::write(work.join("notes.md"), "FIRST LOCAL NOTES").unwrap();
        let before = host.load().unwrap();
        host.replace(profile, &before.revision).unwrap();
        Self {
            root,
            home,
            work,
            provider,
            config,
            host,
        }
    }
    fn start(&self) -> OwnerRuntime {
        let lease = SessionLease::acquire(&self.home, "customization-session", "browser").unwrap();
        OwnerRuntime::start(self.config.clone(), lease).unwrap()
    }
    fn state(&self, runtime: &OwnerRuntime) -> BridgeState {
        BridgeState::from_owner(runtime.handle(), Some("fixture-token".into()))
            .unwrap()
            .with_bound_address("127.0.0.1:4173".parse().unwrap())
            .with_customization(self.host.clone())
    }
    fn calls(&self) -> String {
        fs::read_to_string(self.root.join("calls.jsonl")).unwrap_or_default()
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.home.join("customization.json")).unwrap()
    }
    fn action(&self, state: &BridgeState, command: ProfileCommand) -> Value {
        json!({"type":"customize","command":command,"expected_revision":state.customization_snapshot().unwrap()["resolved"]["revision"]})
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.provider.kill();
        let _ = self.provider.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}
async fn get(state: BridgeState, uri: &str, origin: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().uri(uri).header("Host", "127.0.0.1:4173");
    if let Some(origin) = origin {
        req = req.header("Origin", origin);
    }
    let response = router(state)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body)
}
#[tokio::test]
async fn authenticated_profile_get_is_readonly_and_returns_actual_panes() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let before = f.bytes();
    let mut controller = state.claim_controller().unwrap();
    let (status, body) = get(
        state.clone(),
        "/customization?token=fixture-token",
        Some("http://127.0.0.1:4173"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["resolved"]["profile"]["theme"], "orbit");
    assert!(
        value["panes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["text"] == "FIRST LOCAL NOTES")
    );
    assert_eq!(f.bytes(), before);
    assert!(f.calls().is_empty());
    controller.send(json!({"type":"effort"})).unwrap();
    drop(controller);
    runtime.shutdown().unwrap();
}
#[tokio::test]
async fn missing_wrong_token_and_foreign_origin_cannot_read_profile() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let before = f.bytes();
    for uri in ["/customization", "/customization?token=wrong"] {
        assert_eq!(
            get(state.clone(), uri, None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        get(
            state,
            "/customization?token=fixture-token",
            Some("http://foreign.invalid")
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.bytes(), before);
    assert!(f.calls().is_empty());
    runtime.shutdown().unwrap();
}
#[test]
fn checked_browser_theme_persists_and_preserves_owner_identity() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let before = state.snapshot().unwrap();
    let mut controller = state.claim_controller().unwrap();
    let reply = controller
        .send(f.action(
            &state,
            ProfileCommand::Theme {
                name: "paper".into(),
            },
        ))
        .unwrap();
    assert_eq!(reply["resolved"]["profile"]["theme"], "paper");
    assert_eq!(reply["palette"]["bg"], "#f5f3eb");
    assert_eq!(f.host.load().unwrap().profile.theme, "paper");
    let after = state.snapshot().unwrap();
    assert_eq!(
        (after.model, after.provider, after.effort),
        (before.model, before.provider, before.effort)
    );
    assert!(f.calls().is_empty());
    drop(controller);
    runtime.shutdown().unwrap();
}
#[test]
fn stale_browser_revision_cannot_overwrite_concurrent_cli_change() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let mut controller = state.claim_controller().unwrap();
    let stale = f.action(
        &state,
        ProfileCommand::Theme {
            name: "paper".into(),
        },
    );
    let mut profile = f.host.load().unwrap();
    profile.profile.density = Density::Compact;
    f.host.replace(profile.profile, &profile.revision).unwrap();
    let before = f.bytes();
    assert!(controller.send(stale).is_err());
    assert_eq!(f.bytes(), before);
    assert!(f.calls().is_empty());
    drop(controller);
    runtime.shutdown().unwrap();
}
#[test]
fn nested_unit_unknown_fields_are_rejected_before_store_or_owner_change() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let mut controller = state.claim_controller().unwrap();
    let before = f.bytes();
    let cursor = state.snapshot().unwrap().cursor;
    for value in [
        json!({"type":"customize","command":{"kind":"reload","extra":true},"expected_revision":null}),
        json!({"type":"pane_refresh","pane_id":"notes","revision":"x","extra":true}),
    ] {
        assert!(controller.send(value).is_err());
    }
    assert_eq!(f.bytes(), before);
    assert_eq!(state.snapshot().unwrap().cursor, cursor);
    assert!(f.calls().is_empty());
    drop(controller);
    runtime.shutdown().unwrap();
}
#[test]
fn invalid_font_and_color_leave_exact_profile_bytes_unchanged() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let mut controller = state.claim_controller().unwrap();
    let before = f.bytes();
    for (key, value) in [
        ("browser.font_family", "mono;url(https://foreign.invalid)"),
        ("browser.font_size_px", "25"),
        ("token_overrides.ink", "red;display:none"),
    ] {
        assert!(
            controller
                .send(f.action(
                    &state,
                    ProfileCommand::Set {
                        key: key.into(),
                        value: value.into()
                    }
                ))
                .is_err()
        );
    }
    assert_eq!(f.bytes(), before);
    assert!(f.calls().is_empty());
    drop(controller);
    runtime.shutdown().unwrap();
}
#[test]
fn pane_refresh_reads_changed_workspace_file_and_real_owner_usage() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let mut controller = state.claim_controller().unwrap();
    fs::write(f.work.join("notes.md"), "SECOND LOCAL NOTES").unwrap();
    let revision = f.host.load().unwrap().revision;
    let reply = controller
        .send(json!({"type":"pane_refresh","pane_id":"notes","revision":revision}))
        .unwrap();
    let panes = reply["panes"].as_array().unwrap();
    assert!(panes.iter().any(|p| p["text"] == "SECOND LOCAL NOTES"));
    let usage = panes.iter().find(|p| p["id"] == "usage").unwrap();
    assert!(usage["text"].as_str().unwrap().contains("55"));
    assert!(f.calls().is_empty());
    drop(controller);
    runtime.shutdown().unwrap();
}
#[test]
fn declared_insert_action_returns_only_literal_draft_and_never_submits_prompt() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let mut controller = state.claim_controller().unwrap();
    let revision = f.host.load().unwrap().revision;
    let reply = controller
        .send(json!({"type":"pane_action","pane_id":"notes","action_index":1,"revision":revision}))
        .unwrap();
    assert_eq!(
        reply["effect"],
        json!({"kind":"insert_draft","text":"review evidence"})
    );
    assert!(state.snapshot().unwrap().requests.is_empty());
    assert!(f.calls().is_empty());
    drop(controller);
    runtime.shutdown().unwrap();
}
#[test]
fn undeclared_index_and_stale_action_declaration_cannot_dispatch() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let mut controller = state.claim_controller().unwrap();
    let revision = f.host.load().unwrap().revision;
    assert!(controller
        .send(json!({"type":"pane_action","pane_id":"notes","action_index":99,"revision":revision}))
        .is_err());
    let mut changed = f.host.load().unwrap();
    changed.profile.panes[0].actions.clear();
    f.host.replace(changed.profile, &changed.revision).unwrap();
    let before = f.bytes();
    assert!(
        controller
            .send(
                json!({"type":"pane_action","pane_id":"notes","action_index":1,"revision":revision})
            )
            .is_err()
    );
    assert_eq!(f.bytes(), before);
    assert!(f.calls().is_empty());
    drop(controller);
    runtime.shutdown().unwrap();
}
#[test]
fn reconnect_fetches_current_profile_and_exclusive_controller_without_changing_owner() {
    let f = Fixture::new();
    let runtime = f.start();
    let state = f.state(&runtime);
    let mut first = state.claim_controller().unwrap();
    assert!(state.claim_controller().is_err());
    first
        .send(f.action(
            &state,
            ProfileCommand::Theme {
                name: "midnight".into(),
            },
        ))
        .unwrap();
    drop(first);
    let current = state.customization_snapshot().unwrap();
    let mut second = state.claim_controller().unwrap();
    let reply = second
        .send(f.action(&state, ProfileCommand::Reload))
        .unwrap();
    assert_eq!(
        current["resolved"]["revision"],
        reply["resolved"]["revision"]
    );
    assert_eq!(reply["resolved"]["profile"]["theme"], "midnight");
    assert_eq!(state.snapshot().unwrap().model, "local");
    assert!(f.calls().is_empty());
    drop(second);
    runtime.shutdown().unwrap();
}
#[test]
fn missing_and_symlinked_file_sources_are_visible_without_leaking_file_contents() {
    let f = Fixture::new();
    fs::remove_file(f.work.join("notes.md")).unwrap();
    let runtime = f.start();
    let state = f.state(&runtime);
    let mut controller = state.claim_controller().unwrap();
    let revision = f.host.load().unwrap().revision;
    let reply = controller
        .send(json!({"type":"pane_refresh","pane_id":"notes","revision":revision}))
        .unwrap();
    assert!(
        reply["panes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == "notes" && p["state"] == "missing")
    );
    fs::write(f.root.join("outside.txt"), "NEVER DISPLAY OUTSIDE").unwrap();
    std::os::unix::fs::symlink(f.root.join("outside.txt"), f.work.join("notes.md")).unwrap();
    let reply = controller
        .send(json!({"type":"pane_refresh","pane_id":"notes","revision":revision}))
        .unwrap();
    assert!(!reply.to_string().contains("NEVER DISPLAY OUTSIDE"));
    assert!(f.calls().is_empty());
    drop(controller);
    runtime.shutdown().unwrap();
}
#[test]
fn hostile_pane_text_remains_display_data_and_secret_fields_are_scanned() {
    let f = Fixture::new();
    let secret = "fixture-assignment-secret-123456";
    let mut resolved = f.host.load().unwrap();
    resolved.profile.name = format!("SAFE=ok API_KEY={secret}");
    resolved.profile.panes[0]
        .actions
        .push(PaneAction::InsertPrompt {
            text: format!("SAFE=ok API_KEY={secret}"),
        });
    f.host
        .replace(resolved.profile, &resolved.revision)
        .unwrap();
    let stored = f.bytes();
    fs::write(
        f.work.join("notes.md"),
        format!("<img src=x onerror=alert(1)>\nSAFE=ok API_KEY={secret}"),
    )
    .unwrap();
    let runtime = f.start();
    let state = f.state(&runtime);
    let reply = state.customization_snapshot().unwrap();
    let text = reply["panes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "notes")
        .unwrap()["text"]
        .as_str()
        .unwrap();
    assert!(text.contains("<img"));
    assert!(!reply.to_string().contains(secret));
    assert_eq!(f.bytes(), stored);
    assert!(f.calls().is_empty());
    runtime.shutdown().unwrap();
}
#[tokio::test]
async fn malformed_stored_profile_returns_visible_get_error_and_preserves_bytes() {
    let f = Fixture::new();
    fs::write(f.home.join("customization.json"), b"{broken").unwrap();
    fs::set_permissions(
        f.home.join("customization.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let runtime = f.start();
    let state = f.state(&runtime);
    let before = f.bytes();
    let (status, body) = get(state, "/customization?token=fixture-token", None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!body.is_empty());
    assert_eq!(f.bytes(), before);
    assert!(f.calls().is_empty());
    runtime.shutdown().unwrap();
}
