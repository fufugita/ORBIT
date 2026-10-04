//! Phase 0 scenario suite (REPAIR_GUIDE.md): each test drives the REAL
//! `orbit` binary against `scripts/scripted_mock.py` and asserts on the
//! events, the fixture files and the mock's request log. Every scenario
//! here fails on the documented finding until that finding is fixed.
//!
//! Rules (guide §2): the binary is the one built by this invocation —
//! never a stale `target/release` (Q2); the mock binds port 0 and dies
//! on drop (Q3); one scenario per documented finding.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use tempfile::TempDir;

/// The scripted mock, killed on drop.
struct Mock {
    child: Child,
    port: u16,
    log: PathBuf,
    #[allow(dead_code)]
    dir: TempDir,
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Mock {
    /// Start `scripts/scripted_mock.py` on a free port with `script`
    /// (JSON value) and a fresh request log.
    fn start(script: &serde_json::Value, wire: &str) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let script_path = dir.path().join("script.json");
        std::fs::write(
            &script_path,
            serde_json::to_string(script).expect("serialize script"),
        )
        .expect("write script");
        let log = dir.path().join("req.jsonl");
        let port_out = dir.path().join("port");
        let child = Command::new("python3")
            .arg(repo_path("scripts/scripted_mock.py"))
            .arg("--port")
            .arg("0")
            .arg("--bind-out")
            .arg(&port_out)
            .arg("--script")
            .arg(&script_path)
            .arg("--log")
            .arg(&log)
            .arg("--wire")
            .arg(wire)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scripted_mock.py (python3 required)");
        let mut mock = Mock { child, port: 0, log, dir };
        for _ in 0..80 {
            if let Ok(s) = std::fs::read_to_string(&port_out) {
                mock.port = s.trim().parse().expect("port number");
                break;
            }
            if mock.child.try_wait().ok().flatten().is_some() {
                panic!("scripted_mock.py exited early");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_ne!(mock.port, 0, "mock never reported its port");
        mock
    }

    /// The parsed request-log lines (what ORBIT actually sent).
    fn requests(&self) -> Vec<serde_json::Value> {
        let raw = std::fs::read_to_string(&self.log).unwrap_or_default();
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

/// A fresh ORBIT home, initialised, whose only provider is the mock.
struct Home {
    #[allow(dead_code)]
    dir: TempDir,
    path: PathBuf,
}

impl Home {
    fn init(mock: &Mock, wire: &str, extra_model: &str) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_path_buf();
        let kind = match wire {
            "anthropic" => "anthropic",
            _ => "openai-compatible",
        };
        let toml = format!(
            "[[provider]]\nname = \"mock\"\nkind = \"{kind}\"\nurl = \"http://127.0.0.1:{}\"\n\n\
             [[provider.models]]\nid = \"mock-model\"\n{extra_model}\n",
            mock.port
        );
        std::fs::write(path.join("providers.toml"), toml).expect("write providers.toml");
        let out = Command::new(orbit_binary())
            .arg("--home")
            .arg(&path)
            .arg("init")
            .output()
            .expect("orbit init");
        assert!(
            out.status.success(),
            "orbit init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Home { dir, path }
    }
}

/// The orbit binary built by THIS invocation (Q2): debug under
/// `cargo test`, never a stale release.
fn orbit_binary() -> PathBuf {
    // The integration test runs with CWD = the test package; find the
    // workspace root via CARGO_MANIFEST_DIR.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let root = Path::new(&manifest)
        .parent()
        .expect("workspace root")
        .to_path_buf();
    // Prefer the profile cargo is building now.
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let bin = root.join("target").join(&profile).join("orbit");
    if bin.exists() {
        return bin;
    }
    // PROFILE is only set for build scripts; fall back to debug when
    // it is absent (cargo test builds debug by default) — and never
    // prefer release (Q2).
    root.join("target").join("debug").join("orbit")
}

fn repo_path(rel: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    Path::new(&manifest)
        .parent()
        .expect("workspace root")
        .join(rel)
}

/// A git fixture repo: a failing test the model must fix.
struct Fixture {
    #[allow(dead_code)]
    dir: TempDir,
    path: PathBuf,
}

impl Fixture {
    fn failing_test() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_path_buf();
        std::fs::write(
            path.join("calc.py"),
            "def add(a, b):\n    return a - b\n",
        )
        .expect("write calc.py");
        std::fs::write(
            path.join("test_calc.py"),
            "from calc import add\nassert add(2, 3) == 5\nprint(\"ok: 1 passed\")\n",
        )
        .expect("write test_calc.py");
        let _ = Command::new("git").arg("init").arg("-q").current_dir(&path).status();
        Fixture { dir, path }
    }

    fn read(path: &Path, file: &str) -> String {
        std::fs::read_to_string(path.join(file)).unwrap_or_default()
    }
}

/// Run `orbit -p` in `cwd` against `mock`, returning the stream-json
/// events and the exit code.
fn run_p(
    mock: &Mock,
    home: &Home,
    cwd: &Path,
    prompt: &str,
    extra: &[&str],
) -> (Vec<serde_json::Value>, i32) {
    let mut cmd = Command::new(orbit_binary());
    cmd.arg("-p")
        .arg(prompt)
        .arg("--home")
        .arg(&home.path)
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{}", mock.port))
        .arg("--model")
        .arg("mock-model")
        .arg("--output-format")
        .arg("stream-json")
        .args(extra)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().expect("run orbit -p");
    let mut events = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            events.push(v);
        }
    }
    // Panic output lands on stderr; surface it for debugging.
    if out.status.code() == Some(101) {
        eprintln!("orbit panicked:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    (events, out.status.code().unwrap_or(-1))
}

/// Count events of a type, e.g. `turn_ended`.
fn count(events: &[serde_json::Value], ty: &str) -> usize {
    events
        .iter()
        .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some(ty))
        .count()
}

// ── F1: fix the failing test ───────────────────────────────────────
// Fails on 1310e73: B2 (Edit refused; the file never changes).
#[test]
fn scenario_f1_fix_the_test() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [{"name": "Glob", "args": {"pattern": "**/*.py"}}]},
            {"tools": [{"name": "Read", "args": {"file_path": "calc.py"}}]},
            {"tools": [{"name": "Edit", "args": {
                "file_path": "calc.py",
                "old_string": "return a - b",
                "new_string": "return a + b"}}]},
            {"tools": [{"name": "Bash", "args": {
                "command": "python3 test_calc.py",
                "description": "run the test"}}]},
            {"text": "Fixed: add() subtracted. The test passes now."}]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();

    let (events, _code) = run_p(&mock, &home, &fix.path, "make the tests pass", &["--auto-tools"]);

    // The file was actually fixed.
    assert_eq!(
        Fixture::read(&fix.path, "calc.py"),
        "def add(a, b):\n    return a + b\n",
        "Edit must change the file (B2)"
    );
    // Exactly one turn_ended (no leaked fake turns, B6).
    assert_eq!(count(&events, "turn_ended"), 1, "one turn_ended");
    // No tool result says the call was refused.
    for e in &events {
        if let Some(t) = e.get("type").and_then(|t| t.as_str()) {
            if t.contains("tool") {
                let text = e.to_string();
                assert!(
                    !text.contains("refused"),
                    "tool event carries a refusal: {text}"
                );
            }
        }
    }
}

// ── W2: write the same new path twice ──────────────────────────────
// Fails on 1310e73: B2 (the second Write is refused).
#[test]
fn scenario_w2_write_twice() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [{"name": "Write", "args": {
                "file_path": "made.txt", "content": "first"}}]},
            {"tools": [{"name": "Write", "args": {
                "file_path": "made.txt", "content": "second"}}]},
            {"text": "written twice"}]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();

    let (_events, _code) = run_p(&mock, &home, &fix.path, "write the file twice", &["--auto-tools"]);

    assert_eq!(
        Fixture::read(&fix.path, "made.txt"),
        "second",
        "the second Write over the read file must succeed (B2)"
    );
}

// ── T3: every advertised tool runs ─────────────────────────────────
// Fails on 1310e73: B3 (TaskCreate/TaskList/Skill/WebFetch/Task answer
// "unknown tool").
#[test]
fn scenario_t3_every_advertised_tool() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [
                {"name": "TaskCreate", "args": {"title": "Fix add"}},
                {"name": "TaskList", "args": {}},
                {"name": "Skill", "args": {"name": "anything"}},
                {"name": "WebFetch", "args": {
                    "url": "http://127.0.0.1:1/", "prompt": "summarize"}},
                {"name": "Task", "args": {
                    "agent": "Explore",
                    "prompt": "SUBAGENT: list the python files"}}]},
            {"text": "done"}],
        "SUBAGENT": [
            {"tools": [{"name": "Glob", "args": {"pattern": "*.py"}}]},
            {"text": "SUB-REPORT: calc.py"}]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();

    let (events, _code) = run_p(&mock, &home, &fix.path, "run all tools", &["--auto-tools"]);

    // The refusal text rides the tool result back to the provider, so
    // assert on both the event stream and the mock's request log.
    let joined = events
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let logged = serde_json::to_string(&mock.requests()).expect("requests");
    for text in [&joined, &logged] {
        assert!(
            !text.contains("unknown tool"),
            "no advertised tool may answer 'unknown tool' (B3):\n{text}"
        );
    }
    // And no advertised call may be refused/denied as a class: tools
    // can fail legitimately (Skill: no such skill; WebFetch: offline)
    // but nothing may be refused as unrunnable. The refusal phrases
    // checked below are the deny-by-default/permission failures.
    for e in &events {
        if e.get("type").and_then(|t| t.as_str()) == Some("tool_finished_full") {
            let text = e.to_string();
            for banned in ["unknown tool", "deny-by-default", "not allowed"] {
                assert!(
                    !text.contains(banned),
                    "tool result carries a refusal: {text}"
                );
            }
        }
    }
}

// ── U1: Grep over non-ASCII text ──────────────────────────────────
// Fails on 1310e73: B1 (panic; exit 101).
#[test]
fn scenario_u1_grep_non_ascii() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [{"name": "Grep", "args": {"pattern": "caf"}}]},
            {"text": "found it"}]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();
    std::fs::write(fix.path.join("notes.txt"), "see \u{a7}3.2 \u{2014} the caf\u{e9}\n").unwrap();

    let (events, code) = run_p(&mock, &home, &fix.path, "grep for caf", &["--auto-tools"]);

    assert_ne!(code, 101, "Grep must not panic on non-ASCII (B1)");
    assert_eq!(count(&events, "turn_ended"), 1, "the turn completes");
}

// ── H1: a 400 carries the provider's message ───────────────────────
// Fails on 1310e73: E1 (reported as "requires authentication").
#[test]
fn scenario_h1_http_400_message() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"status": 400,
             "body": "{\"error\":{\"message\":\"prompt is too long: 250000 tokens > 200000 maximum\"}}"}
        ]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();

    let (events, _code) = run_p(&mock, &home, &fix.path, "anything", &["--auto-tools"]);
    let joined = events
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("prompt is too long"),
        "the provider's 400 message must surface (E1):\n{joined}"
    );
    assert!(
        !joined.contains("requires authentication"),
        "a 400 is not an authentication problem (E1):\n{joined}"
    );
}

// ── H2: 500 is retried, then the turn succeeds ─────────────────────
// Fails on 1310e73: E2 (the turn fails on the 500).
#[test]
fn scenario_h2_http_500_retried() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"status": 500},
            {"text": "after retry"}]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();

    let (events, _code) = run_p(&mock, &home, &fix.path, "try twice", &["--auto-tools"]);
    assert_eq!(
        count(&events, "turn_ended"),
        1,
        "500 then success must complete the turn (E2)"
    );
    assert!(mock.requests().len() >= 2, "the request was retried");
}

// ── R1: a multi-line deny array blocks the command ─────────────────
// Fails on 1310e73: S1 (the array parses empty; the command runs).
#[test]
fn scenario_r1_multiline_deny() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [{"name": "Bash", "args": {
                "command": "echo pwned > ran.txt", "description": "x"}}]},
            {"text": "ran"}]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();
    // The multi-line form the subset parser drops.
    std::fs::write(
        home.path.join("settings.toml"),
        "[permissions]\ndeny = [\n  \"Bash(echo *)\",\n]\n",
    )
    .unwrap();

    let (_events, _code) = run_p(&mock, &home, &fix.path, "run it", &["--auto-tools"]);
    assert!(
        !fix.path.join("ran.txt").exists(),
        "a multi-line deny rule must block the command (S1)"
    );
}

// ── A1: the Anthropic wire ─────────────────────────────────────────
// Fails on 1310e73: B7 (temperature sent; thinking dropped;
// input_tokens read as 0).
#[test]
#[ignore] // requires the B7 adapter fixes; enable in Phase 3
fn scenario_a1_anthropic_wire() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"thinking": true, "ptok": 100,
             "tools": [{"name": "Glob", "args": {"pattern": "*.py"}}]},
            {"text": "ok"}]
    });
    let mock = Mock::start(&script, "anthropic");
    let home = Home::init(&mock, "anthropic", "");
    let fix = Fixture::failing_test();

    let (events, _code) = run_p(&mock, &home, &fix.path, "use tools", &["--auto-tools"]);

    let reqs = mock.requests();
    // 1. No temperature with thinking on.
    let body = reqs[0]["body"].as_object().expect("request body");
    assert!(
        body.get("temperature").is_none(),
        "no temperature with thinking (B7)"
    );
    // 2. The thinking block is replayed verbatim in round 2.
    let round2 = serde_json::to_string(&reqs[1]["body"]["messages"]).expect("messages");
    assert!(
        round2.contains("sig-main-0"),
        "round 2 replays the signed thinking (B7)"
    );
    // 3. input_tokens parsed from message_start.
    let ended: Vec<_> = events
        .iter()
        .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("turn_ended"))
        .collect();
    assert!(
        !ended.is_empty() && ended[0]["input_tokens"].as_u64().unwrap_or(0) >= 100,
        "input_tokens parsed from message_start.usage (B7)"
    );
}
