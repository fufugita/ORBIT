#![cfg(unix)]

pub mod tool_runtime {
    pub use orbit_cli::tool_runtime::*;
}
#[path = "../src/lsp.rs"]
mod lsp;

use lsp::{DiagnosticStatus, Freshness, LspDiagnosticsArgs};
use orbit_cli::tool_runtime::PermissionScope;
use orbit_tools::ToolContext;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct Fixture {
    base: PathBuf,
    home: PathBuf,
    work: PathBuf,
    cx: ToolContext,
}

impl Fixture {
    fn new(mode: &str) -> Self {
        let base = std::env::temp_dir().join(format!("orbit-p35-lsp-{}", ulid::Ulid::new()));
        let home = base.join("home");
        let work = base.join("work");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("file.rs"), "fn main() { let x = 1; }\n").unwrap();
        let cx = ToolContext::new(home.clone(), "lsp-owner".into(), work.clone());
        let f = Self {
            base,
            home,
            work,
            cx,
        };
        f.config(mode, 600);
        f
    }
    fn config(&self, mode: &str, timeout: u64) {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/fixtures/p35_lsp_server.py");
        std::fs::write(self.home.join("lsp.toml"), format!(
            "enabled = true\n[[servers]]\nname = 'fixture'\ncommand = 'python3'\nargs = [{:?}, {:?}, {:?}]\nlanguage_id = 'rust'\nextensions = ['rs']\nworkspace_root = {:?}\ntimeout_ms = {timeout}\n",
            script.to_string_lossy(), mode, self.base.join("frames.jsonl").to_string_lossy(), self.work.to_string_lossy()
        )).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            self.home.join("lsp.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    fn args(&self) -> LspDiagnosticsArgs {
        LspDiagnosticsArgs {
            file_path: "file.rs".into(),
            server: None,
        }
    }
    fn run(&self) -> Result<lsp::DiagnosticReport, lsp::LspError> {
        lsp::diagnostics(
            &self.home,
            &self.cx,
            &PermissionScope::default(),
            &self.args(),
        )
    }
    fn frames(&self) -> Vec<Value> {
        std::fs::read_to_string(self.base.join("frames.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }
    fn assert_not_launched(&self) {
        assert!(
            self.frames().is_empty(),
            "refusal must precede launch and content"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn permitted_pull_receives_correlated_diagnostics_and_closes() {
    let f = Fixture::new("pull");
    let r = f.run().unwrap();
    assert_eq!(r.status, DiagnosticStatus::Received);
    assert_eq!(r.freshness, Freshness::Confirmed);
    assert_eq!(r.diagnostics[0].message, "pull issue");
    assert_eq!(r.diagnostics[0].severity, Some(1));
    assert_eq!(r.position_encoding, "utf-16");
    let frames = f.frames();
    let methods: Vec<_> = frames.iter().filter_map(|v| v["method"].as_str()).collect();
    assert_eq!(
        methods,
        [
            "initialize",
            "initialized",
            "textDocument/didOpen",
            "textDocument/diagnostic",
            "textDocument/didClose",
            "shutdown",
            "exit"
        ]
    );
    assert_eq!(
        frames
            .iter()
            .find(|v| v["method"] == "textDocument/didOpen")
            .unwrap()["params"]["textDocument"]["text"],
        "fn main() { let x = 1; }\n"
    );
}
#[test]
fn permitted_pull_disabled_never_launches() {
    let f = Fixture::new("pull");
    std::fs::write(f.home.join("lsp.toml"), "enabled = false\n").unwrap();
    assert!(lsp::availability(&f.home, &f.cx).unwrap().is_none());
    assert!(f.run().is_err());
    f.assert_not_launched();
}
#[test]
fn permitted_pull_unconfigured_never_launches() {
    let f = Fixture::new("pull");
    std::fs::remove_file(f.home.join("lsp.toml")).unwrap();
    assert!(lsp::availability(&f.home, &f.cx).unwrap().is_none());
    assert!(f.run().is_err());
    f.assert_not_launched();
}
#[test]
fn permitted_pull_outside_scope_never_launches() {
    let f = Fixture::new("pull");
    std::fs::write(f.base.join("outside.rs"), "secret document").unwrap();
    let args = LspDiagnosticsArgs {
        file_path: f.base.join("outside.rs").to_string_lossy().into(),
        server: None,
    };
    assert!(lsp::diagnostics(&f.home, &f.cx, &PermissionScope::default(), &args).is_err());
    f.assert_not_launched();
}
#[test]
fn permitted_pull_denied_file_never_launches() {
    let f = Fixture::new("pull");
    std::fs::write(f.work.join("secrets.rs"), "API_KEY=private").unwrap();
    let args = LspDiagnosticsArgs {
        file_path: "secrets.rs".into(),
        server: None,
    };
    let error = lsp::diagnostics(&f.home, &f.cx, &PermissionScope::default(), &args).unwrap_err();
    assert!(matches!(&error, lsp::LspError::Denied(reason) if reason.contains("deny-read")));
    f.assert_not_launched();
}
#[test]
fn scope_exclusion_never_launches() {
    let f = Fixture::new("pull");
    let scope = PermissionScope {
        allowlist: Some(vec!["Read".into()]),
        ..Default::default()
    };
    assert!(lsp::diagnostics(&f.home, &f.cx, &scope, &f.args()).is_err());
    f.assert_not_launched();
}
#[test]
fn read_deny_rule_never_launches() {
    let f = Fixture::new("pull");
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\ndeny = ['Read(*)']\n",
    )
    .unwrap();
    assert!(f.run().is_err());
    f.assert_not_launched();
}
#[test]
fn untrusted_project_cannot_activate_launch() {
    let f = Fixture::new("pull");
    let local = f.work.join(".orbit");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::rename(f.home.join("lsp.toml"), local.join("lsp.toml")).unwrap();
    assert!(lsp::availability(&f.home, &f.cx).unwrap().is_none());
    assert!(f.run().is_err());
    f.assert_not_launched();
}
#[test]
fn overlapping_home_requires_existing_folder_trust() {
    let mut f = Fixture::new("pull");
    let local = f.work.join(".orbit");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::rename(f.home.join("lsp.toml"), local.join("lsp.toml")).unwrap();
    f.home = local;
    assert!(lsp::availability(&f.home, &f.cx).unwrap().is_none());
    f.assert_not_launched();
    orbit_tools::permissions::FolderTrust::new(f.home.clone())
        .trust(&f.work)
        .unwrap();
    assert!(f.run().is_ok());
}
#[test]
fn received_empty_is_distinct_from_silence() {
    let f = Fixture::new("empty");
    let r = f.run().unwrap();
    assert_eq!(r.status, DiagnosticStatus::Received);
    assert!(r.diagnostics.is_empty());
    f.config("silent", 150);
    let r = f.run().unwrap();
    assert_eq!(r.status, DiagnosticStatus::Unavailable);
    assert!(r.diagnostics.is_empty());
}
#[test]
fn exact_version_push_is_confirmed() {
    let f = Fixture::new("push");
    let r = f.run().unwrap();
    assert_eq!(r.status, DiagnosticStatus::Received);
    assert_eq!(r.freshness, Freshness::Confirmed);
    assert_eq!(r.diagnostics[0].message, "push issue");
}
#[test]
fn push_empty_is_received() {
    let f = Fixture::new("push_empty");
    let r = f.run().unwrap();
    assert_eq!(r.status, DiagnosticStatus::Received);
    assert!(r.diagnostics.is_empty());
}
#[test]
fn mismatched_version_is_stale() {
    let f = Fixture::new("push_stale");
    let r = f.run().unwrap();
    assert_eq!(r.status, DiagnosticStatus::Stale);
    assert!(r.diagnostics.is_empty());
}
#[test]
fn unversioned_push_is_unconfirmed() {
    let f = Fixture::new("push_unversioned");
    let r = f.run().unwrap();
    assert_eq!(r.status, DiagnosticStatus::Received);
    assert_eq!(r.freshness, Freshness::Unconfirmed);
}
#[test]
fn other_uri_cannot_confirm_current_file() {
    let f = Fixture::new("push_wrong_uri");
    f.config("push_wrong_uri", 150);
    assert_eq!(f.run().unwrap().status, DiagnosticStatus::Unavailable);
}
#[test]
fn wrong_response_id_does_not_become_clean() {
    let f = Fixture::new("wrong_id");
    f.config("wrong_id", 150);
    assert_eq!(f.run().unwrap().status, DiagnosticStatus::Unavailable);
}
#[test]
fn negotiated_utf8_positions_are_preserved() {
    let f = Fixture::new("utf8");
    assert_eq!(f.run().unwrap().position_encoding, "utf-8");
}
#[test]
fn malformed_frames_and_utf8_are_errors() {
    for mode in ["bad_frame", "bad_utf8", "oversize"] {
        let f = Fixture::new(mode);
        assert!(f.run().is_err(), "{mode}");
    }
}
#[test]
fn malformed_result_and_range_are_errors() {
    for mode in ["malformed_result", "invalid_range"] {
        let f = Fixture::new(mode);
        assert!(f.run().is_err(), "{mode}");
    }
}
#[test]
fn diagnostics_count_is_bounded_and_explicitly_truncated() {
    let f = Fixture::new("many");
    let r = f.run().unwrap();
    assert_eq!(r.diagnostics.len(), 100);
    assert!(r.truncated);
}
#[test]
fn server_requested_edits_are_rejected_and_never_applied() {
    let f = Fixture::new("server_action");
    assert_eq!(f.run().unwrap().status, DiagnosticStatus::Received);
    assert_eq!(
        std::fs::read_to_string(f.work.join("file.rs")).unwrap(),
        "fn main() { let x = 1; }\n"
    );
    let frames = f.frames();
    assert!(frames
        .iter()
        .any(|v| v["id"] == 99 && v["error"]["code"] == -32601));
}
#[test]
fn output_is_scanned_and_controls_removed() {
    let f = Fixture::new("secret");
    let r = f.run().unwrap();
    let serialized = serde_json::to_string(&r).unwrap();
    assert!(!serialized.contains("abcdefghijklmnopqrstuvwxyz1234567890"));
    assert!(!r.diagnostics[0].message.contains('\u{1b}'));
    assert!(!r.redactions.is_empty());
}
#[test]
fn cancellation_before_spawn_transmits_nothing() {
    let f = Fixture::new("pull");
    let cancel = Arc::new(AtomicBool::new(true));
    let c = cancel.clone();
    f.cx.push_cancel_check(Arc::new(move || c.load(Ordering::SeqCst)));
    assert!(matches!(f.run(), Err(lsp::LspError::Cancelled)));
    f.assert_not_launched();
}
#[test]
fn cancellation_during_initialize_reaps_child() {
    let f = Fixture::new("initialize_silent");
    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    f.cx.push_cancel_check(Arc::new(move || c.load(Ordering::SeqCst)));
    std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            cancel.store(true, Ordering::SeqCst);
        });
        let start = std::time::Instant::now();
        assert!(matches!(f.run(), Err(lsp::LspError::Cancelled)));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    });
    let pid = f.frames()[0]["spawn"].as_u64().unwrap();
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
}
#[test]
fn availability_and_tool_schema_do_not_launch_or_accept_launch_arguments() {
    let f = Fixture::new("pull");
    assert_eq!(
        lsp::availability(&f.home, &f.cx)
            .unwrap()
            .unwrap()
            .servers
            .len(),
        1
    );
    let def = lsp::tool_definition();
    assert_eq!(def.name, "LspDiagnostics");
    assert_eq!(def.parameters["additionalProperties"], false);
    assert!(serde_json::from_value::<LspDiagnosticsArgs>(
        serde_json::json!({"file_path":"file.rs","command":"other"})
    )
    .is_err());
    f.assert_not_launched();
}

#[test]
fn relative_read_deny_is_enforced_before_launch() {
    let f = Fixture::new("pull");
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\ndeny = ['Read(file.rs)']\n",
    )
    .unwrap();
    assert!(f.run().is_err());
    f.assert_not_launched();
}

#[test]
fn symlink_escape_never_launches() {
    let f = Fixture::new("pull");
    std::fs::write(f.base.join("outside.rs"), "outside scope").unwrap();
    std::fs::remove_file(f.work.join("file.rs")).unwrap();
    std::os::unix::fs::symlink(f.base.join("outside.rs"), f.work.join("file.rs")).unwrap();
    assert!(f.run().is_err());
    f.assert_not_launched();
}

#[test]
fn oversized_document_never_launches() {
    let f = Fixture::new("pull");
    std::fs::write(f.work.join("file.rs"), vec![b'x'; 1024 * 1024 + 1]).unwrap();
    assert!(f.run().is_err());
    f.assert_not_launched();
}

#[test]
fn cancellation_during_document_write_reaps_child() {
    let f = Fixture::new("open_unread");
    f.config("open_unread", 2000);
    std::fs::write(f.work.join("file.rs"), vec![b'x'; 1024 * 1024]).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    f.cx.push_cancel_check(Arc::new(move || c.load(Ordering::SeqCst)));
    std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            cancel.store(true, Ordering::SeqCst);
        });
        let start = std::time::Instant::now();
        assert!(matches!(f.run(), Err(lsp::LspError::Cancelled)));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    });
    let pid = f.frames()[0]["spawn"].as_u64().unwrap();
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
}

#[test]
fn cancellation_during_diagnostics_read_reaps_child() {
    let f = Fixture::new("silent");
    f.config("silent", 2000);
    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    f.cx.push_cancel_check(Arc::new(move || c.load(Ordering::SeqCst)));
    std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            cancel.store(true, Ordering::SeqCst);
        });
        assert!(matches!(f.run(), Err(lsp::LspError::Cancelled)));
    });
    let pid = f.frames()[0]["spawn"].as_u64().unwrap();
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
}

#[test]
fn silent_shutdown_cleanup_is_bounded_and_reaped() {
    let f = Fixture::new("close_silent");
    let start = std::time::Instant::now();
    assert_eq!(f.run().unwrap().status, DiagnosticStatus::Received);
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
    let pid = f.frames()[0]["spawn"].as_u64().unwrap();
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
}

#[test]
fn returned_json_is_bounded_when_a_message_is_large() {
    let f = Fixture::new("large_message");
    let r = f.run().unwrap();
    assert_eq!(r.status, DiagnosticStatus::Received);
    assert!(r.truncated);
    assert!(serde_json::to_vec(&r).unwrap().len() <= 64 * 1024);
}

#[test]
fn invalid_configuration_never_launches() {
    let f = Fixture::new("pull");
    std::fs::write(
        f.home.join("lsp.toml"),
        "enabled = true\ncommand = 'untrusted'\n",
    )
    .unwrap();
    assert!(lsp::availability(&f.home, &f.cx).is_err());
    assert!(f.run().is_err());
    f.assert_not_launched();
}

#[test]
fn swapped_document_parent_never_sends_outside_content() {
    let f = Fixture::new("pull");
    let sub = f.work.join("sub");
    let outside = f.base.join("outside");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(sub.join("file.rs"), "permitted document").unwrap();
    std::fs::write(outside.join("file.rs"), "outside private document").unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = calls.clone();
    let saved = f.work.join("original-sub");
    f.cx.push_cancel_check(Arc::new(move || {
        if c.fetch_add(1, Ordering::SeqCst) == 1 {
            std::fs::rename(&sub, &saved).unwrap();
            std::os::unix::fs::symlink(&outside, &sub).unwrap();
        }
        false
    }));
    let args = LspDiagnosticsArgs {
        file_path: "sub/file.rs".into(),
        server: None,
    };
    assert!(matches!(
        lsp::diagnostics(&f.home, &f.cx, &PermissionScope::default(), &args),
        Err(lsp::LspError::Denied(_))
    ));
    f.assert_not_launched();
}

#[test]
fn review_inherited_read_path_denies_before_launch_even_in_bypass() {
    let f = Fixture::new("pull");
    for entry in [
        "Read(file.rs)".to_string(),
        "Read(*)".to_string(),
        format!("Read({})", f.work.join("file.rs").display()),
    ] {
        let scope = PermissionScope {
            mode: orbit_tools::permissions::PermissionMode::Bypass,
            disallowlist: vec![entry.clone()],
            ..Default::default()
        };
        assert!(
            matches!(lsp::diagnostics(&f.home, &f.cx, &scope, &f.args()), Err(lsp::LspError::Denied(reason)) if reason.contains("permission rule")),
            "{entry}"
        );
        f.assert_not_launched();
    }
}

#[test]
fn review_inherited_diagnostics_path_denies_before_launch() {
    let f = Fixture::new("pull");
    for entry in ["LspDiagnostics(file.rs)", "LspDiagnostics(*)"] {
        let scope = PermissionScope {
            disallowlist: vec![entry.into()],
            ..Default::default()
        };
        assert!(
            matches!(lsp::diagnostics(&f.home, &f.cx, &scope, &f.args()), Err(lsp::LspError::Denied(reason)) if reason.contains("permission rule"))
        );
        f.assert_not_launched();
    }
}

#[test]
fn review_inherited_nonmatching_path_rule_keeps_permitted_diagnostics() {
    let f = Fixture::new("pull");
    let scope = PermissionScope {
        disallowlist: vec!["Read(other.rs)".into()],
        ..Default::default()
    };
    assert_eq!(
        lsp::diagnostics(&f.home, &f.cx, &scope, &f.args())
            .unwrap()
            .status,
        DiagnosticStatus::Received
    );
    assert!(f
        .frames()
        .iter()
        .any(|v| v["method"] == "textDocument/didOpen"));
}

#[test]
fn review_fifo_document_open_is_bounded_by_an_independent_child_watchdog() {
    const ENV: &str = "ORBIT_TEST_LSP_FIFO_ROOT";
    if let Some(base) = std::env::var_os(ENV) {
        let base = PathBuf::from(base);
        let home = base.join("home");
        let work = base.join("work");
        let cx = ToolContext::new(home.clone(), "fifo-probe".into(), work.clone());
        let f = Fixture {
            base,
            home,
            work,
            cx,
        };
        let start = std::time::Instant::now();
        assert!(
            matches!(f.run(), Err(lsp::LspError::Denied(reason)) if reason.contains("regular file"))
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        f.assert_not_launched();
        return;
    }
    let f = Fixture::new("pull");
    std::fs::remove_file(f.work.join("file.rs")).unwrap();
    use std::os::unix::{ffi::OsStrExt, process::CommandExt};
    let path = std::ffi::CString::new(f.work.join("file.rs").as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated private temporary path, owner-only mode.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "review_fifo_document_open_is_bounded_by_an_independent_child_watchdog",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENV, &f.base)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: this watchdog child was assigned a distinct owned group.
            unsafe {
                libc::killpg(child.id() as i32, libc::SIGKILL);
            }
            let _ = child.wait();
            panic!("FIFO diagnostics blocked beyond the child watchdog deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn review_repeated_same_family_tokens_are_all_redacted() {
    let f = Fixture::new("two_tokens");
    let r = f.run().unwrap();
    let bytes = serde_json::to_string(&r).unwrap();
    for token in [
        "ghp_abcdefghijklmnopQRSTUVWX0123456789",
        "ghp_ZYXWVUTSRQponmlkjihg9876543210abcd",
    ] {
        assert!(!bytes.contains(token));
    }
    assert!(r.diagnostics[0].message.contains("redacted"));
    assert!(r.diagnostics[0]
        .code
        .as_ref()
        .unwrap()
        .as_str()
        .unwrap()
        .contains("redacted"));
    assert!(r.diagnostics[0]
        .source
        .as_ref()
        .unwrap()
        .contains("redacted"));
    assert!(!r.redactions.is_empty());
}

#[test]
fn review_short_prefix_does_not_conceal_a_later_real_token() {
    let f = Fixture::new("short_prefix");
    let r = f.run().unwrap();
    assert!(!serde_json::to_string(&r)
        .unwrap()
        .contains("ghp_abcdefghijklmnopQRSTUVWX0123456789"));
    assert!(r.diagnostics[0].message.contains("ghp_short"));
    assert!(!r.redactions.is_empty());
}

#[test]
fn review_helpers_are_terminated_after_server_leader_exits() {
    if helper_child_probe("review_helpers_are_terminated_after_server_leader_exits") {
        return;
    }
    let f = Fixture::new("helper_exit");
    let mut unrelated = std::process::Command::new("python3")
        .args(["-c", "import time; time.sleep(30)"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert_eq!(f.run().unwrap().status, DiagnosticStatus::Received);
    assert_owned_processes_gone(&f);
    let leader = f.frames().iter().find_map(|v| v["spawn"].as_i64()).unwrap();
    // SAFETY: query only the live unrelated child owned by this test.
    assert_ne!(
        unsafe { libc::getpgid(unrelated.id() as i32) } as i64,
        leader
    );
    assert!(
        unrelated.try_wait().unwrap().is_none(),
        "unrelated process was terminated"
    );
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}

fn assert_owned_processes_gone(f: &Fixture) {
    let frames = f.frames();
    let leader = frames.iter().find_map(|v| v["spawn"].as_u64()).unwrap();
    let observed = frames.iter().find(|v| v["helper"].is_u64()).unwrap();
    let helper = observed["helper"].as_u64().unwrap();
    assert_eq!(observed["helper_parent"], leader);
    assert_eq!(observed["helper_group"], leader);
    assert!(observed["helper_state"]
        .as_str()
        .is_some_and(|state| state.starts_with('R') || state.starts_with('S')));
    assert!(
        !PathBuf::from(format!("/proc/{leader}")).exists(),
        "server leader was not reaped"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1000);
    loop {
        if !PathBuf::from(format!("/proc/{helper}")).exists() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "server helper {helper} did not terminate and get reaped by the jail: {:?}",
            std::fs::read_to_string(format!("/proc/{helper}/status"))
                .unwrap_or_default()
                .lines()
                .filter(|line| line.starts_with("State:") || line.starts_with("PPid:"))
                .collect::<Vec<_>>()
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn review_exited_leader_helpers_are_cleaned_on_protocol_failure() {
    if helper_child_probe("review_exited_leader_helpers_are_cleaned_on_protocol_failure") {
        return;
    }
    let f = Fixture::new("helper_early_exit");
    assert!(matches!(f.run(), Err(lsp::LspError::Io(_))));
    assert_owned_processes_gone(&f);
}

#[test]
fn review_server_helpers_are_cleaned_on_diagnostics_timeout() {
    if helper_child_probe("review_server_helpers_are_cleaned_on_diagnostics_timeout") {
        return;
    }
    let f = Fixture::new("helper_timeout");
    f.config("helper_timeout", 150);
    assert_eq!(f.run().unwrap().status, DiagnosticStatus::Unavailable);
    assert_owned_processes_gone(&f);
}

#[test]
fn review_server_helpers_are_cleaned_on_diagnostics_cancellation() {
    if helper_child_probe("review_server_helpers_are_cleaned_on_diagnostics_cancellation") {
        return;
    }
    let f = Fixture::new("helper_cancel");
    f.config("helper_cancel", 2000);
    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    f.cx.push_cancel_check(Arc::new(move || c.load(Ordering::SeqCst)));
    std::thread::scope(|s| {
        s.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                let text = std::fs::read_to_string(f.base.join("frames.jsonl")).unwrap_or_default();
                if text
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .any(|v| v["method"] == "textDocument/diagnostic")
                {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "diagnostic request was never sent"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            cancel.store(true, Ordering::SeqCst);
        });
        assert!(matches!(f.run(), Err(lsp::LspError::Cancelled)));
    });
    assert_owned_processes_gone(&f);
}

fn helper_child_probe(name: &str) -> bool {
    const ENV: &str = "ORBIT_TEST_LSP_HELPER_CHILD";
    if std::env::var_os(ENV).is_some() {
        return false;
    }
    // All application assertions run unchanged in the exact child test. Its
    // private fixture supervisor only reaps dead orphans, supplying the init
    // behavior absent from the PID jail's non-reaping runner process.
    use std::os::unix::process::CommandExt;
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/fixtures/p35_lsp_server.py");
    let mut child = std::process::Command::new("python3")
        .arg(script)
        .args(["--supervise", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(ENV, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            use std::io::Read;
            let mut errors = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .take(16 * 1024)
                .read_to_string(&mut errors)
                .unwrap();
            assert!(status.success(), "helper probe {name} failed: {errors}");
            return true;
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: this watchdog supervises its own distinct child group.
            unsafe {
                libc::killpg(child.id() as i32, libc::SIGKILL);
            }
            let _ = child.wait();
            panic!("helper probe {name} exceeded its watchdog deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
