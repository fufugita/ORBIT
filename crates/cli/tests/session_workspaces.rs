#![cfg(unix)]

use orbit_cli::daemon::{OwnerAction, OwnerConfig, OwnerRuntime};
use orbit_cli::sessions::{self, SessionFile, SessionLease};
use orbit_cli::tui_worker::TuiTurnConfig;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    a: PathBuf,
    b: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-workspaces-{}", ulid::Ulid::new()));
        private_dir(&root);
        let home = root.join("home");
        let a = root.join("project-a");
        let b = root.join("project-b");
        for directory in [&home, &a, &b] {
            private_dir(directory);
        }
        let plan = orbit_cli::setup::plan_setup(&home, &Default::default()).unwrap();
        orbit_cli::setup::apply_setup(&plan).unwrap();
        fs::write(home.join("providers.toml"), "[[provider]]\nname='fixture'\nurl='http://127.0.0.1:1'\n[[provider.models]]\nid='model-a'\n[roles]\nmain='fixture/model-a'\n").unwrap();
        fs::set_permissions(
            home.join("providers.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Self { root, home, a, b }
    }

    fn seed(&self, id: &str, workspace: Option<&Path>) -> SessionFile {
        let mut saved = SessionFile::from_chat(
            id,
            "model-a",
            "http://127.0.0.1:1",
            "fixture",
            &[
                orbit_engine::user_message("retained question"),
                orbit_engine::assistant_message("retained answer"),
            ],
            3,
            13,
            7,
            11,
        );
        if let Some(workspace) = workspace {
            saved.bind_workspace(workspace).unwrap();
        }
        SessionLease::acquire(&self.home, id, "workspace-fixture")
            .unwrap()
            .save(&saved)
            .unwrap();
        saved
    }

    fn turn(&self, id: &str) -> TuiTurnConfig {
        TuiTurnConfig {
            home: self.home.clone(),
            session_id: id.into(),
            gate: "http://127.0.0.1:1".into(),
            model: "model-a".into(),
            provider_id: "fixture".into(),
            effort: None,
            auto_tools: false,
            scope: Default::default(),
            initial_transcript: vec![],
            initial_turns: 0,
            initial_input_tokens: 0,
            initial_output_tokens: 0,
            initial_cost_microcents: 0,
        }
    }

    fn cli(&self, directory: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_orbit"))
            .env_clear()
            .env("HOME", &self.home)
            .env("ORBIT_HOME", &self.home)
            .current_dir(directory)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn bytes(&self, id: &str) -> Vec<u8> {
        fs::read(self.home.join("sessions").join(format!("{id}.json"))).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn private_dir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn value(saved: &SessionFile) -> Value {
    serde_json::to_value(saved).unwrap()
}

#[test]
fn legacy_unknown_and_bound_workspace_roundtrip_remain_distinct() {
    let f = Fixture::new();
    let legacy = f.seed("legacy", None);
    let raw = value(&legacy);
    assert!(raw.get("workspace").is_none());
    let decoded: SessionFile = serde_json::from_value(raw).unwrap();
    assert!(decoded.workspace.is_none());
    let bound = f.seed("bound", Some(&f.a));
    let decoded: SessionFile = serde_json::from_value(value(&bound)).unwrap();
    assert_eq!(decoded.workspace, Some(fs::canonicalize(&f.a).unwrap()));
    assert!(decoded.require_workspace(&f.a).is_ok());
    assert!(decoded.require_workspace(&f.b).is_err());
    std::os::unix::fs::symlink(&f.a, f.root.join("alias-a")).unwrap();
    assert!(decoded.require_workspace(&f.root.join("alias-a")).is_ok());
    assert!(
        sessions::list_sessions(&f.home)
            .unwrap()
            .iter()
            .any(|saved| saved.session_id == "legacy")
    );
}

#[test]
fn ordinary_save_preserves_binding_and_refuses_rebinding_or_implicit_adoption() {
    let f = Fixture::new();
    let mut bound = f.seed("bound", Some(&f.a));
    let lease = SessionLease::acquire(&f.home, "bound", "workspace-save").unwrap();
    bound.workspace = None;
    bound.turns += 1;
    lease.save(&bound).unwrap();
    let saved = lease.load().unwrap();
    assert_eq!(saved.workspace, Some(fs::canonicalize(&f.a).unwrap()));
    assert_eq!(saved.turns, 4);
    let before = f.bytes("bound");
    bound.workspace = Some(fs::canonicalize(&f.b).unwrap());
    assert!(lease.save(&bound).is_err());
    assert_eq!(f.bytes("bound"), before);
    fs::remove_file(f.home.join("sessions/bound.json")).unwrap();
    bound.workspace = None;
    lease.save(&bound).unwrap();
    assert_eq!(
        lease.load().unwrap().workspace,
        Some(fs::canonicalize(&f.a).unwrap())
    );
    drop(lease);
    let mut legacy = f.seed("legacy", None);
    let before = f.bytes("legacy");
    legacy.bind_workspace(&f.a).unwrap();
    assert!(sessions::save_session(&f.home, &legacy).is_err());
    assert_eq!(f.bytes("legacy"), before);
}

#[test]
fn workspace_admission_refuses_before_candidate_lease_and_keeps_local_history_available() {
    let f = Fixture::new();
    f.seed("foreign", Some(&f.a));
    f.seed("legacy", None);
    f.seed("local", Some(&f.b));
    for id in ["foreign", "legacy"] {
        let before = f.bytes(id);
        let lock = f.home.join("sessions/.leases").join(format!("{id}.lock"));
        let before_lock = fs::read(&lock).unwrap();
        let error = SessionLease::acquire_for_workspace(&f.home, id, "resume", &f.b).unwrap_err();
        assert!(error.to_string().contains(if id == "legacy" {
            "--adopt-workspace"
        } else {
            "another workspace"
        }));
        assert_eq!(f.bytes(id), before);
        assert!(!f.home.join("context-history").join(id).exists());
        assert_eq!(fs::read(lock).unwrap(), before_lock);
        assert!(SessionLease::acquire(&f.home, id, "still-available").is_ok());
    }
    let (_, local) = SessionLease::acquire_for_workspace(&f.home, "local", "resume", &f.b).unwrap();
    assert_eq!(local.session_id, "local");
}

#[test]
fn continue_selects_older_local_history_over_newer_foreign_or_unknown_history() {
    let f = Fixture::new();
    for (id, workspace, date) in [
        ("local", Some(f.b.as_path()), "2026-01-01T00:00:00Z"),
        ("foreign", Some(f.a.as_path()), "2026-03-01T00:00:00Z"),
        ("legacy", None, "2026-04-01T00:00:00Z"),
    ] {
        let mut saved = f.seed(id, workspace);
        saved.updated_at = date.into();
        sessions::save_session(&f.home, &saved).unwrap();
    }
    assert_eq!(
        sessions::latest_for_workspace(&f.home, &f.b)
            .unwrap()
            .unwrap()
            .session_id,
        "local"
    );
    let empty = f.root.join("empty-project");
    private_dir(&empty);
    assert!(
        sessions::latest_for_workspace(&f.home, &empty)
            .unwrap()
            .is_none()
    );
}

#[test]
fn cli_continue_admits_older_local_history_instead_of_newer_foreign_or_unknown() {
    let f = Fixture::new();
    for (id, workspace, date) in [
        ("local", Some(f.b.as_path()), "2026-01-01T00:00:00Z"),
        ("foreign", Some(f.a.as_path()), "2026-03-01T00:00:00Z"),
        ("legacy", None, "2026-04-01T00:00:00Z"),
    ] {
        let mut saved = f.seed(id, workspace);
        saved.updated_at = date.into();
        sessions::save_session(&f.home, &saved).unwrap();
    }
    let before_ids: std::collections::BTreeSet<_> = sessions::list_sessions(&f.home)
        .unwrap()
        .into_iter()
        .map(|saved| saved.session_id)
        .collect();
    let local = sessions::load_session(&f.home, "local").unwrap();
    let foreign = f.bytes("foreign");
    let legacy = f.bytes("legacy");

    let output = f.cli(&f.b, &["chat", "--continue", "--no-tui"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let after_ids: std::collections::BTreeSet<_> = sessions::list_sessions(&f.home)
        .unwrap()
        .into_iter()
        .map(|saved| saved.session_id)
        .collect();
    assert_eq!(after_ids, before_ids);
    assert_eq!(f.bytes("foreign"), foreign);
    assert_eq!(f.bytes("legacy"), legacy);
    for id in ["foreign", "legacy"] {
        assert!(!f.home.join("context-history").join(id).exists());
        assert!(!f.home.join("projects").join(format!("{id}.jsonl")).exists());
    }
    assert!(
        f.home
            .join("context-history/local/accounting.json")
            .is_file()
    );
    let resumed = sessions::load_session(&f.home, "local").unwrap();
    assert_eq!(resumed.session_id, local.session_id);
    assert_eq!(resumed.workspace, Some(fs::canonicalize(&f.b).unwrap()));
    assert_eq!(resumed.transcript, local.transcript);
    assert_eq!(
        (
            resumed.turns,
            resumed.input_tokens,
            resumed.output_tokens,
            resumed.cost_microcents
        ),
        (
            local.turns,
            local.input_tokens,
            local.output_tokens,
            local.cost_microcents
        )
    );
    assert!(resumed.accounting_watermark.is_some());
}

#[test]
fn cli_continue_without_local_history_starts_one_fresh_workspace_session() {
    let f = Fixture::new();
    f.seed("foreign", Some(&f.a));
    f.seed("legacy", None);
    let before_ids: std::collections::BTreeSet<_> = sessions::list_sessions(&f.home)
        .unwrap()
        .into_iter()
        .map(|saved| saved.session_id)
        .collect();
    let foreign = f.bytes("foreign");
    let legacy = f.bytes("legacy");

    let output = f.cli(&f.b, &["chat", "--continue", "--no-tui"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("No saved session in this workspace; starting a new session.")
    );
    assert_eq!(f.bytes("foreign"), foreign);
    assert_eq!(f.bytes("legacy"), legacy);
    for id in ["foreign", "legacy"] {
        assert!(!f.home.join("context-history").join(id).exists());
        assert!(!f.home.join("projects").join(format!("{id}.jsonl")).exists());
    }
    let after_ids: std::collections::BTreeSet<_> = sessions::list_sessions(&f.home)
        .unwrap()
        .into_iter()
        .map(|saved| saved.session_id)
        .collect();
    assert!(before_ids.is_subset(&after_ids));
    assert_eq!(after_ids.len(), before_ids.len() + 1);
    let new_ids: Vec<_> = after_ids.difference(&before_ids).cloned().collect();
    assert_eq!(new_ids.len(), 1);
    let fresh = sessions::load_session(&f.home, &new_ids[0]).unwrap();
    assert_eq!(fresh.session_id, new_ids[0]);
    assert_eq!(fresh.workspace, Some(fs::canonicalize(&f.b).unwrap()));
    assert!(fresh.transcript.is_empty());
    assert_eq!(
        (
            fresh.turns,
            fresh.input_tokens,
            fresh.output_tokens,
            fresh.cost_microcents
        ),
        (0, 0, 0, 0)
    );
    assert!(fresh.accounting_watermark.is_some());
    assert!(
        f.home
            .join("context-history")
            .join(&fresh.session_id)
            .join("accounting.json")
            .is_file()
    );
}

#[test]
fn explicit_legacy_adoption_preserves_identity_transcript_accounting_and_unknown_fields() {
    let f = Fixture::new();
    let legacy = f.seed("legacy", None);
    let path = f.home.join("sessions/legacy.json");
    let mut document = value(&legacy);
    document["future_metadata"] = serde_json::json!({"keep":true});
    fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let (lease, before) = SessionLease::acquire_for_adoption(&f.home, "legacy", "adopt").unwrap();
    let adopted = lease.adopt_workspace(&before, &f.b).unwrap();
    let mut after: Value = serde_json::from_slice(&f.bytes("legacy")).unwrap();
    assert_eq!(
        after.as_object_mut().unwrap().remove("workspace"),
        Some(serde_json::to_value(fs::canonicalize(&f.b).unwrap()).unwrap())
    );
    assert_eq!(after, document);
    assert!(adopted.require_workspace(&f.b).is_ok());
    assert!(lease.adopt_workspace(&adopted, &f.a).is_err());
    drop(lease);
    assert!(SessionLease::acquire_for_adoption(&f.home, "legacy", "rebind").is_err());
}

#[test]
fn adoption_rejects_stale_expected_source_without_overwriting_concurrent_state() {
    let f = Fixture::new();
    f.seed("legacy", None);
    let (lease, stale) = SessionLease::acquire_for_adoption(&f.home, "legacy", "adopt").unwrap();
    let mut concurrent = stale.clone();
    concurrent
        .transcript
        .push(orbit_engine::user_message("newer retained work"));
    lease.save(&concurrent).unwrap();
    let before = f.bytes("legacy");
    assert!(lease.adopt_workspace(&stale, &f.b).is_err());
    assert_eq!(f.bytes("legacy"), before);
    assert!(lease.load().unwrap().workspace.is_none());
}

#[test]
fn headless_resume_fork_and_manual_compact_refuse_foreign_and_unknown_history_unchanged() {
    let f = Fixture::new();
    for (id, workspace) in [("foreign", Some(f.a.as_path())), ("legacy", None)] {
        f.seed(id, workspace);
        let before = f.bytes(id);
        for args in [
            vec!["-p", "must not execute", "--resume", id],
            vec!["-p", "must not execute", "--resume", id, "--fork-session"],
            vec!["compact", "--session", id, "--json"],
        ] {
            let output = f.cli(&f.b, &args);
            assert!(!output.status.success());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains(if id == "legacy" {
                    "--adopt-workspace"
                } else {
                    "another workspace"
                }),
                "{error}"
            );
            assert_eq!(f.bytes(id), before);
            assert!(!f.home.join("projects").exists());
            assert!(!f.home.join("context-history").exists());
        }
    }
}

#[test]
fn startup_adoption_is_explicit_and_foreign_bound_history_cannot_be_rebound() {
    let f = Fixture::new();
    f.seed("foreign", Some(&f.a));
    let before = f.bytes("foreign");
    let output = f.cli(
        &f.b,
        &[
            "-p",
            "must not execute",
            "--resume",
            "foreign",
            "--adopt-workspace",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be rebound"));
    assert_eq!(f.bytes("foreign"), before);
    for args in [
        vec!["-p", "must not execute", "--adopt-workspace"],
        vec![
            "-p",
            "must not execute",
            "--resume",
            "foreign",
            "--adopt-workspace",
            "--fork-session",
        ],
        vec!["-p", "must not execute", "--continue", "--adopt-workspace"],
    ] {
        let output = f.cli(&f.b, &args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("requires one explicit --resume"));
    }
    assert!(!f.home.join("context-history").exists());
}

#[test]
fn explicit_startup_adoption_and_same_workspace_resume_preserve_saved_history() {
    let f = Fixture::new();
    let before = f.seed("legacy", None);
    let first = f.cli(
        &f.b,
        &[
            "chat",
            "--resume",
            "legacy",
            "--adopt-workspace",
            "--no-tui",
        ],
    );
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let adopted = sessions::load_session(&f.home, "legacy").unwrap();
    assert_eq!(adopted.workspace, Some(fs::canonicalize(&f.b).unwrap()));
    assert_eq!(adopted.session_id, before.session_id);
    assert_eq!(adopted.transcript, before.transcript);
    assert_eq!(
        (
            adopted.turns,
            adopted.input_tokens,
            adopted.output_tokens,
            adopted.cost_microcents
        ),
        (
            before.turns,
            before.input_tokens,
            before.output_tokens,
            before.cost_microcents
        )
    );
    let second = f.cli(&f.b, &["chat", "--resume", "legacy", "--no-tui"]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let resumed = sessions::load_session(&f.home, "legacy").unwrap();
    assert_eq!(resumed.transcript, before.transcript);
    assert_eq!(resumed.workspace, adopted.workspace);
}

#[test]
fn adoption_does_not_waive_pending_accounting_or_change_its_transcript() {
    let f = Fixture::new();
    f.seed("legacy", None);
    let (lease, mut saved) =
        SessionLease::acquire_and_load(&f.home, "legacy", "pending-fixture").unwrap();
    let accounting = orbit_cli::session_accounting::prepare_root(
        &lease,
        &mut saved,
        orbit_cli::session_accounting::RootOrigin::RestoredOrLegacy,
    )
    .unwrap();
    let selected =
        orbit_cli::checked_model_turn(&f.home, "model-a", Some("fixture"), None, true).unwrap();
    let journal = orbit_cli::context_history::context_journal(&f.home, "legacy", None).unwrap();
    let revision = accounting.namespace().checkpoint().unwrap().revision;
    journal
        .begin_attempt(
            revision,
            &orbit_engine::AttemptIntent {
                owner_session_id: "legacy".into(),
                child_id: None,
                request_id: "pending-request".into(),
                purpose: orbit_engine::AttemptPurpose::Ordinary,
                budget: orbit_engine::context_budget::BudgetIdentity::for_config(
                    &selected,
                    "workspace-fixture",
                    "workspace-fixture",
                )
                .unwrap(),
            },
        )
        .unwrap();
    let journal_path = f.home.join("context-history/legacy/accounting.json");
    let before_journal = fs::read(&journal_path).unwrap();
    let before = sessions::load_session(&f.home, "legacy").unwrap();
    drop(accounting);
    drop(lease);
    let output = f.cli(
        &f.b,
        &[
            "chat",
            "--resume",
            "legacy",
            "--adopt-workspace",
            "--no-tui",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pending"));
    let after = sessions::load_session(&f.home, "legacy").unwrap();
    assert_eq!(after.workspace, Some(fs::canonicalize(&f.b).unwrap()));
    assert_eq!(after.transcript, before.transcript);
    assert_eq!(after.accounting_watermark, before.accounting_watermark);
    assert_eq!(
        (
            after.turns,
            after.input_tokens,
            after.output_tokens,
            after.cost_microcents
        ),
        (
            before.turns,
            before.input_tokens,
            before.output_tokens,
            before.cost_microcents
        )
    );
    assert_eq!(fs::read(journal_path).unwrap(), before_journal);
}

#[test]
fn daemon_resume_refuses_workspace_changes_without_swapping_owner_or_creating_candidate_state() {
    let f = Fixture::new();
    let foreign = f.seed("foreign", Some(&f.a));
    f.seed("legacy", None);
    let lease = SessionLease::acquire(&f.home, "local", "workspace-owner").unwrap();
    let runtime =
        OwnerRuntime::start(OwnerConfig::new(f.turn("local"), f.b.clone()), lease).unwrap();
    let handle = runtime.handle();
    let mut controller = handle.claim_controller().unwrap();
    let before = serde_json::to_value(handle.snapshot().unwrap()).unwrap();
    for id in ["foreign", "legacy"] {
        let bytes = f.bytes(id);
        let error = controller
            .send(OwnerAction::Resume {
                session_id: id.into(),
            })
            .unwrap_err();
        assert!(error.to_string().contains(if id == "legacy" {
            "--adopt-workspace"
        } else {
            "another workspace"
        }));
        assert_eq!(
            serde_json::to_value(handle.snapshot().unwrap()).unwrap(),
            before
        );
        assert_eq!(f.bytes(id), bytes);
        assert!(!f.home.join("context-history").join(id).exists());
        assert!(SessionLease::acquire(&f.home, id, "candidate-remains-free").is_ok());
    }
    assert_eq!(
        value(&sessions::load_session(&f.home, "foreign").unwrap()),
        value(&foreign)
    );
    assert!(SessionLease::acquire(&f.home, "local", "current-remains-owned").is_err());
    drop(controller);
    runtime.shutdown().unwrap();
    assert_eq!(
        sessions::load_session(&f.home, "local").unwrap().workspace,
        Some(fs::canonicalize(&f.b).unwrap())
    );
}

#[test]
fn daemon_start_refuses_unknown_and_foreign_history_before_accounting_activation() {
    let f = Fixture::new();
    for (id, workspace) in [("foreign", Some(f.a.as_path())), ("legacy", None)] {
        f.seed(id, workspace);
        let before = f.bytes(id);
        let lease = SessionLease::acquire(&f.home, id, "workspace-owner").unwrap();
        let result = OwnerRuntime::start(OwnerConfig::new(f.turn(id), f.b.clone()), lease);
        let error = result.err().expect("foreign or unknown owner must refuse");
        assert!(error.to_string().contains(if id == "legacy" {
            "--adopt-workspace"
        } else {
            "another workspace"
        }));
        assert_eq!(f.bytes(id), before);
        assert!(!f.home.join("context-history").exists());
    }
}

#[test]
#[ignore = "isolated workspace fixture child"]
fn tui_startup_child() {
    let Some(home) = std::env::var_os("ORBIT_WORKSPACE_CHILD_HOME") else {
        return;
    };
    let id = std::env::var("ORBIT_WORKSPACE_CHILD_ID").unwrap();
    let (bus, sender) = orbit_hud_tui::bus::Bus::new();
    let (commands, command_rx) = std::sync::mpsc::channel();
    let config = TuiTurnConfig {
        home: PathBuf::from(home),
        session_id: id,
        gate: "http://127.0.0.1:1".into(),
        model: "model-a".into(),
        provider_id: "fixture".into(),
        effort: None,
        auto_tools: false,
        scope: Default::default(),
        initial_transcript: vec![],
        initial_turns: 0,
        initial_input_tokens: 0,
        initial_output_tokens: 0,
        initial_cost_microcents: 0,
    };
    if std::env::var("ORBIT_WORKSPACE_CHILD_MODE").as_deref() == Ok("resume") {
        let local = TuiTurnConfig {
            session_id: "local".into(),
            ..config.clone()
        };
        let cancel = orbit_cli::tui_worker::make_spawner(local)(
            orbit_hud_tui::worker::WorkerCtx {
                sender,
                approvals: orbit_hud_tui::ApprovalRegistry::new(),
                command_rx,
            },
            commands.clone(),
        )
        .expect("fresh local worker starts");
        commands
            .send(orbit_hud_tui::worker::WorkerCommand::ResumeSession(
                config.session_id.clone(),
            ))
            .unwrap();
        commands
            .send(orbit_hud_tui::worker::WorkerCommand::ListSessions)
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut refused = false;
        let mut fenced = false;
        while std::time::Instant::now() < deadline {
            match bus.try_recv() {
                Some(orbit_hud_tui::msg::Msg::Status(text)) => {
                    refused |=
                        text.contains("another workspace") || text.contains("--adopt-workspace");
                }
                Some(orbit_hud_tui::msg::Msg::SessionsListed(rows)) => {
                    assert!(rows.iter().any(|row| row.current && row.id == "local"));
                    assert!(rows.iter().all(|row| !row.current || row.id == "local"));
                    fenced = true;
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(2)),
            }
        }
        assert!(
            refused && fenced,
            "resume refusal and current owner list must both arrive"
        );
        assert!(SessionLease::acquire(&config.home, "local", "must-remain-owned").is_err());
        assert!(
            SessionLease::acquire(&config.home, &config.session_id, "candidate-remains-free")
                .is_ok()
        );
        drop(commands);
        drop(cancel);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if SessionLease::acquire(&config.home, "local", "worker-finished").is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "owned worker did not release"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        return;
    }
    let result = orbit_cli::tui_worker::make_spawner(config)(
        orbit_hud_tui::worker::WorkerCtx {
            sender,
            approvals: orbit_hud_tui::ApprovalRegistry::new(),
            command_rx,
        },
        commands,
    );
    let error = result
        .err()
        .expect("workspace mismatch must refuse before worker spawn");
    assert!(
        error.contains("another workspace") || error.contains("--adopt-workspace"),
        "{error}"
    );
    assert!(bus.try_recv().is_none());
}

#[test]
fn tui_resume_refuses_unknown_and_foreign_history_without_swapping_identity_or_candidate_state() {
    for legacy in [false, true] {
        let f = Fixture::new();
        let id = if legacy { "legacy" } else { "foreign" };
        f.seed(id, (!legacy).then_some(f.a.as_path()));
        let before = f.bytes(id);
        let output = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("HOME", &f.home)
            .env("ORBIT_HOME", &f.home)
            .env("ORBIT_WORKSPACE_CHILD_HOME", &f.home)
            .env("ORBIT_WORKSPACE_CHILD_ID", id)
            .env("ORBIT_WORKSPACE_CHILD_MODE", "resume")
            .current_dir(&f.b)
            .args(["--exact", "tui_startup_child", "--ignored", "--nocapture"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(f.bytes(id), before);
        assert!(!f.home.join("context-history").join(id).exists());
        assert!(!f.home.join("projects").join(format!("{id}.jsonl")).exists());
        let local = sessions::load_session(&f.home, "local").unwrap();
        assert_eq!(local.workspace, Some(fs::canonicalize(&f.b).unwrap()));
        assert!(local.transcript.is_empty());
    }
}

#[test]
fn tui_startup_refuses_unknown_and_foreign_history_without_transcript_effects() {
    let f = Fixture::new();
    for (id, workspace) in [("foreign", Some(f.a.as_path())), ("legacy", None)] {
        f.seed(id, workspace);
        let before = f.bytes(id);
        let output = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("HOME", &f.home)
            .env("ORBIT_HOME", &f.home)
            .env("ORBIT_WORKSPACE_CHILD_HOME", &f.home)
            .env("ORBIT_WORKSPACE_CHILD_ID", id)
            .current_dir(&f.b)
            .args(["--exact", "tui_startup_child", "--ignored", "--nocapture"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(f.bytes(id), before);
        assert!(!f.home.join("projects").exists());
        assert!(!f.home.join("context-history").exists());
    }
}
