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
        let mut mock = Mock {
            child,
            port: 0,
            log,
            dir,
        };
        for _ in 0..80 {
            if let Ok(s) = std::fs::read_to_string(&port_out) {
                // The mock writes the file once the port is bound; an
                // empty read raced the write — retry, don't parse "".
                if let Ok(p) = s.trim().parse() {
                    mock.port = p;
                    break;
                }
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
        std::fs::write(path.join("calc.py"), "def add(a, b):\n    return a - b\n")
            .expect("write calc.py");
        std::fs::write(
            path.join("test_calc.py"),
            "from calc import add\nassert add(2, 3) == 5\nprint(\"ok: 1 passed\")\n",
        )
        .expect("write test_calc.py");
        let _ = Command::new("git")
            .arg("init")
            .arg("-q")
            .current_dir(&path)
            .status();
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

    let (events, _code) = run_p(
        &mock,
        &home,
        &fix.path,
        "make the tests pass",
        &["--auto-tools"],
    );

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

    let (_events, _code) = run_p(
        &mock,
        &home,
        &fix.path,
        "write the file twice",
        &["--auto-tools"],
    );

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
    std::fs::write(
        fix.path.join("notes.txt"),
        "see \u{a7}3.2 \u{2014} the caf\u{e9}\n",
    )
    .unwrap();

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

// ── P1: the permission matrix ──────────────────────────────────────
// Fails on 1310e73-era code: B4 (two contradicting layers — read-only
// tools ask, --allowedTools without --auto-tools is refused, acceptEdits
// denies everything, bypass ignores deny rules).

#[test]
fn scenario_p1_permission_matrix() {
    let read_then_write: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [
                {"name": "Read", "args": {"file_path": "calc.py"}},
                {"name": "Write", "args": {"file_path": "out.txt", "content": "x"}}]},
            {"text": "done"}]
    });

    // (a) default headless: Read (read-only, in the working dir) RUNS;
    // Write is denied with a visible reason, and out.txt never appears.
    {
        let fix = Fixture::failing_test();
        let mock = Mock::start(&read_then_write, "openai");
        let home = Home::init(&mock, "openai", "");
        let (events, _c) = run_p(&mock, &home, &fix.path, "go", &[]);
        let log = serde_json::to_string(&mock.requests()).unwrap();
        assert!(
            log.contains("calc.py"),
            "default headless: Read must run without asking (B4)"
        );
        assert!(
            !fix.path.join("out.txt").exists(),
            "default headless: Write must be denied (B4)"
        );
        assert!(
            log.contains("denied")
                || log.contains("--allowedTools")
                || log.contains("--auto-tools"),
            "a headless denial must carry a visible reason (C4/B4)"
        );
        let _ = events;
    }

    // (b) --allowedTools Read works WITHOUT --auto-tools: Read runs,
    // Write (not listed) is denied.
    {
        let fix = Fixture::failing_test();
        let mock = Mock::start(&read_then_write, "openai");
        let home = Home::init(&mock, "openai", "");
        let (events, _c) = run_p(&mock, &home, &fix.path, "go", &["--allowedTools", "Read"]);
        let log = serde_json::to_string(&mock.requests()).unwrap();
        assert!(
            log.contains("calc.py"),
            "--allowedTools Read must allow Read without --auto-tools (B4)"
        );
        assert!(
            !fix.path.join("out.txt").exists(),
            "an unlisted write tool must stay denied (B4)"
        );
        let _ = events;
    }

    // (c) acceptEdits headless: Write inside the working directory RUNS.
    {
        let fix = Fixture::failing_test();
        let mock = Mock::start(&read_then_write, "openai");
        let home = Home::init(&mock, "openai", "");
        let (_events, _c) = run_p(
            &mock,
            &home,
            &fix.path,
            "go",
            &["--permission-mode", "acceptEdits"],
        );
        assert!(
            fix.path.join("out.txt").exists(),
            "acceptEdits must let Write run in the working directory (B4)"
        );
    }

    // (d) plan mode headless: read-only runs, writes denied.
    {
        let fix = Fixture::failing_test();
        let mock = Mock::start(&read_then_write, "openai");
        let home = Home::init(&mock, "openai", "");
        let (_events, _c) = run_p(
            &mock,
            &home,
            &fix.path,
            "go",
            &["--permission-mode", "plan"],
        );
        let log = serde_json::to_string(&mock.requests()).unwrap();
        assert!(log.contains("calc.py"), "plan mode: Read runs (B4)");
        assert!(
            !fix.path.join("out.txt").exists(),
            "plan mode: Write is denied (B4)"
        );
    }

    // (e) deny rules bind even under --auto-tools (bypass runs
    // everything EXCEPT deny rules).
    {
        let fix = Fixture::failing_test();
        let mock = Mock::start(&read_then_write, "openai");
        let home = Home::init(&mock, "openai", "");
        std::fs::write(
            home.path.join("settings.toml"),
            "[permissions]\ndeny = [\n  \"Write\",\n]\n",
        )
        .unwrap();
        let (_events, _c) = run_p(&mock, &home, &fix.path, "go", &["--auto-tools"]);
        assert!(
            !fix.path.join("out.txt").exists(),
            "a deny rule must bind even under --auto-tools (B4)"
        );
    }
}

// ── D1: the deny-read list is bypassed by a symlink and by Bash ────
// Fails on 1310e73-era code: S2 (is_deny_read matches the path string
// as given; a symlink or `cat` through Bash sidesteps it).
#[test]
fn scenario_d1_deny_read_bypass() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [
                {"name": "Read", "args": {"file_path": "secret_link.txt"}},
                {"name": "Bash", "args": {
                    "command": "cat ~/.ssh/d1_probe", "description": "read it via shell"}}]},
            {"text": "done"}]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();

    // A real secret outside the fixture, plus a symlink to it.
    let ssh_dir = home.path.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let secret = ssh_dir.join("d1_probe");
    std::fs::write(&secret, "SECRET-D1").unwrap();
    let link_path = fix.path.join("secret_link.txt");
    let _ = std::os::unix::fs::symlink(&secret, &link_path);

    // Run with HOME set to the temp home so the default deny-read
    // list (~/.ssh) covers the probe file.
    let mut cmd = Command::new(orbit_binary());
    cmd.arg("-p")
        .arg("read it")
        .arg("--home")
        .arg(&home.path)
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{}", mock.port))
        .arg("--model")
        .arg("mock-model")
        .arg("--auto-tools")
        .arg("--output-format")
        .arg("stream-json")
        .env("HOME", home.path)
        .current_dir(&fix.path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().expect("run orbit -p");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    // Neither the symlink Read nor the Bash cat may leak the secret.
    assert!(
        !stdout.contains("SECRET-D1"),
        "the secret leaked through a tool (S2): {stdout}"
    );
    let logged = serde_json::to_string(&mock.requests()).unwrap();
    assert!(
        !logged.contains("SECRET-D1"),
        "the secret leaked to the provider (S2)"
    );
}

// ── X2: no sandbox → Bash must not run unsandboxed in headless ────
// Fails today: S3 (bwrap missing + --auto-tools → unsandboxed run,
// nothing tells the operator).
#[test]
fn scenario_x2_no_sandbox_headless_bash_refused() {
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [{"name": "Bash", "args": {
                "command": "echo pwned > x2ran.txt", "description": "x"}}]},
            {"text": "ran"}]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();

    let out = Command::new(orbit_binary())
        .arg("-p")
        .arg("run it")
        .arg("--home")
        .arg(&home.path)
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{}", mock.port))
        .arg("--model")
        .arg("mock-model")
        .arg("--auto-tools")
        .arg("--output-format")
        .arg("stream-json")
        .env("ORBIT_TEST_SANDBOX_OFF", "1")
        .current_dir(&fix.path)
        .output()
        .expect("run orbit -p");
    let _ = out;

    assert!(
        !fix.path.join("x2ran.txt").exists(),
        "headless Bash must not run unsandboxed when the sandbox is unavailable (S3)"
    );
    let logged = serde_json::to_string(&mock.requests()).unwrap();
    assert!(
        logged.contains("sandbox is unavailable"),
        "the refusal must reach the provider (S3)"
    );
}

// ── Gate 5: one session, every extension ───────────────────────────
// MD gate 5: "One session uses an Explore subagent, a tool from a
// stdio MCP server, a SKILL.md copied unchanged from a Claude Code
// project, and a PreToolUse hook that blocks `git push`. The
// subagent's approval request appears in the main session, and each
// extension shows in the TUI and in the ledger."
#[test]
fn gate5_one_session_every_extension() {
    // The script: round 0 loads the skill, round 1 runs the MCP tool,
    // round 2 spawns the Explore subagent (its own conversation, keyed
    // by the prompt), round 3 tries git push (the hook blocks), round
    // 4 finishes. The subagent conversation: report text.
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [{"name": "Skill", "args": {"name": "review-checklist"}}]},
            {"tools": [{"name": "mcp__demo__echo", "args": {"text": "hi"}}]},
            {"tools": [{"name": "Task", "args": {
                "agent": "Explore",
                "prompt": "SURROGATE: list the files in this crate and report"}}]},
            {"tools": [{"name": "Bash", "args": {
                "command": "git push origin main", "description": "push"}}]},
            {"text": "all extensions exercised"}
        ],
        "SURROGATE:": [
            {"tools": [{"name": "Glob", "args": {"pattern": "*.py"}}]},
            {"text": "found 2 python files: calc.py, test_calc.py"}
        ]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();

    // The Claude Code skill, copied unchanged: frontmatter + body.
    let skills_dir = fix.path.join(".orbit/skills/review-checklist");
    std::fs::create_dir_all(&skills_dir).unwrap();
    std::fs::write(
        skills_dir.join("SKILL.md"),
        "---\nname: review-checklist\ndescription: A checklist for reviewing changes\n---\n# Review checklist\n\n1. Tests pass\n2. No secrets in the diff\n",
    )
    .unwrap();

    // The stdio MCP server: a tiny python JSON-RPC echo.
    let mcp_server = fix.path.join("mcp_echo.py");
    std::fs::write(
        &mcp_server,
        r#"#!/usr/bin/env python3
import json, sys
def send(o): sys.stdout.write(json.dumps(o)+"\n"); sys.stdout.flush()
for line in sys.stdin:
    try: req = json.loads(line)
    except Exception: continue
    m = req.get("method","")
    if m == "initialize":
        send({"jsonrpc":"2.0","id":req["id"],"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"demo","version":"1"}}})
    elif m == "notifications/initialized":
        pass
    elif m == "tools/list":
        send({"jsonrpc":"2.0","id":req["id"],"result":{"tools":[{"name":"echo","description":"echo the text","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}]}})
    elif m == "tools/call":
        arg = req["params"]["arguments"].get("text","")
        send({"jsonrpc":"2.0","id":req["id"],"result":{"content":[{"type":"text","text":"echo: "+arg}]}})
    else:
        send({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32601,"message":"no such method"}})
"#)
    .unwrap();
    let orbit_dir = fix.path.join(".orbit");
    std::fs::create_dir_all(&orbit_dir).unwrap();
    std::fs::write(
        orbit_dir.join("mcp.json"),
        serde_json::json!({
            "servers": {"demo": {"command": "python3", "args": [mcp_server.to_string_lossy()]}}
        })
        .to_string(),
    )
    .unwrap();

    // The PreToolUse hook that blocks git push: exit 2 on push.
    let hook = fix.path.join("block_push.sh");
    std::fs::write(
        &hook,
        "#!/bin/bash\ninput=$(cat)\ncase \"$input\" in *push*) echo \"no push in tests\" >&2; exit 2;; esac\nexit 0\n",
    )
    .unwrap();
    let mut st = std::fs::metadata(&hook).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    st.set_mode(0o755);
    std::fs::set_permissions(&hook, st).unwrap();
    // Project-scope hooks need folder trust: write settings + trust.
    std::fs::write(
        orbit_dir.join("settings.toml"),
        format!(
            "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"{}\"\n",
            hook.to_string_lossy()
        ),
    )
    .unwrap();
    // Trust the fixture folder so project-scope skills/MCP/hooks load
    // (FolderTrust: a marker file named by the sha256 of the path).
    let cwd_real = std::fs::canonicalize(&fix.path).unwrap();
    {
        use sha2::Digest;
        let digest = hex::encode(sha2::Sha256::digest(cwd_real.to_string_lossy().as_bytes()));
        let marker = home.path.join("trust/folders").join(digest);
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(
            &marker,
            serde_json::json!({"path": cwd_real.to_string_lossy(), "trusted_at": "0"}).to_string(),
        )
        .unwrap();
    }

    let (events, exit_code) = run_p(
        &mock,
        &home,
        &fix.path,
        "use every extension",
        &["--auto-tools"],
    );
    let _ = exit_code; // printed in the hook assertion's diagnostic

    let all = serde_json::to_string(&events).unwrap_or_default();
    // What actually reached the model: the mock's request log.
    let reqs = mock.requests();
    let reqs_all = serde_json::to_string(&reqs).unwrap_or_default();
    // Diagnostic probe: run the hook script exactly as run_hook does,
    // so a CI-only failure shows whether the hook itself works there.
    let hook_probe = std::process::Command::new("bash")
        .arg("-c")
        .arg(
            "input=$(cat); case \"$input\" in *push*) echo 'no push in tests' >&2; exit 2;; esac; exit 0",
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            if let Some(mut si) = c.stdin.take() {
                let _ = si.write_all(br#"{"tool":"Bash","arguments":{"command":"git push origin main"}}"#);
            }
            c.wait_with_output()
        })
        .map(|o| format!("exit-sig {:?} stderr {:?}", o.status.code(), String::from_utf8_lossy(&o.stderr)))
        .unwrap_or_else(|e| format!("probe spawn failed: {e}"));

    // 1. The skill loaded: its BODY reached the model as the Skill
    //    tool's result (Claude Code format, unchanged).
    assert!(
        reqs_all.contains("Review checklist"),
        "the SKILL.md body must reach the model: {reqs_all:.400}"
    );

    // 2. The MCP tool ran through the stdio server: the tool result
    //    (the server's echo) reached the model.
    assert!(
        reqs_all.contains("echo: hi"),
        "the stdio MCP tool's result must reach the model: {reqs_all:.400}"
    );

    // 3. The Explore subagent ran (its report text returns as the Task
    //    result).
    assert!(
        reqs_all.contains("found 2 python files"),
        "the subagent's report must come back to the main session: {reqs_all:.400}"
    );

    // 4. The PreToolUse hook blocked git push: the Bash result the
    //    model sees says so.
    assert!(
        reqs_all.contains("no push in tests") || reqs_all.contains("blocked by hook"),
        "the PreToolUse hook must block git push (exit {exit_code}, probe: {hook_probe}): {reqs_all:.2000}\n--- events: {all:.4000}"
    );

    // 5. The turn completed despite the blocked push (the hook result
    //    is a tool error the model sees, not a turn failure).
    let ended_ok = events.iter().any(|e| {
        e.get("type").and_then(|t| t.as_str()) == Some("turn_ended")
            && e.get("ok").and_then(|o| o.as_bool()) == Some(true)
    });
    assert!(ended_ok, "the turn ends ok: {all:.300}");

    // 6. Each extension shows in the ledger: the verify listing has
    //    the Skill, mcp__demo__echo, Task and Bash calls.
    let out = Command::new(orbit_binary())
        .arg("--home")
        .arg(&home.path)
        .arg("verify-ledger")
        .output()
        .expect("verify-ledger");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    let calls = v
        .get("calls")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let tools: Vec<&str> = calls
        .iter()
        .filter_map(|c| c.get("tool").and_then(|t| t.as_str()))
        .collect();
    for expected in ["Skill", "mcp__demo__echo", "Task", "Bash"] {
        assert!(
            tools.contains(&expected),
            "the ledger must show {expected}: {tools:?}"
        );
    }
}

// ── Gate 4: /rewind restores files to their recorded digests ───────
// MD gate 4: "/rewind to an earlier prompt restores every file to its
// recorded digest and the conversation to that point." The checkpoint
// store is the mechanism; the test drives a real session that edits a
// file, then restores the turn's checkpoint and checks the digest.
#[test]
fn gate4_rewind_restores_recorded_digests() {
    // The script: round 0 edits calc.py (the Write snapshots the
    // pre-edit bytes into the turn's checkpoint), round 1 finishes.
    let script: serde_json::Value = serde_json::json!({
        "main": [
            {"tools": [{"name": "Read", "args": {"file_path": "calc.py"}}]},
            {"tools": [{"name": "Edit", "args": {
                "file_path": "calc.py",
                "old_string": "return a - b",
                "new_string": "return a + b"}}]},
            {"text": "fixed"}
        ]
    });
    let mock = Mock::start(&script, "openai");
    let home = Home::init(&mock, "openai", "");
    let fix = Fixture::failing_test();
    let before = Fixture::read(&fix.path, "calc.py");

    let (events, _code) = run_p(&mock, &home, &fix.path, "fix it", &["--auto-tools"]);
    let after = Fixture::read(&fix.path, "calc.py");
    assert_ne!(before, after, "the Edit must change the file first");

    // The session wrote a checkpoint before the first write of the
    // turn; its snapshot holds the pre-edit bytes.
    // Find the session that owns the snapshots.
    let sessions_dir = home.path.join("sessions");
    let mut found: Option<(std::path::PathBuf, String)> = None;
    for entry in std::fs::read_dir(&sessions_dir).unwrap().flatten() {
        if entry.path().join("snapshots").exists() {
            found = Some((
                entry.path(),
                entry.file_name().to_string_lossy().into_owned(),
            ));
            break;
        }
    }
    let (_sess_dir, session_id) = found.expect("a session with snapshots");
    let cps = orbit_engine::transcript::Checkpoints::new(&home.path, &session_id);
    let list = cps.list();
    assert!(!list.is_empty(), "a checkpoint must open at the write turn");

    // Restore: every file in the manifest returns to its digest.
    use sha2::Digest;
    let cp_id = &list[0];
    let snaps = home
        .path
        .join("sessions")
        .join(&session_id)
        .join("snapshots");
    let restored = cps.restore(cp_id).expect("restore");
    assert_eq!(restored.len(), 1, "the edited file: {restored:?}");
    let content = Fixture::read(&fix.path, "calc.py");
    let digest = hex::encode(sha2::Sha256::digest(content.as_bytes()));
    // The manifest's recorded sha256.
    let manifest = std::fs::read_to_string(snaps.join(cp_id).join("manifest.jsonl")).unwrap();
    let recorded: Vec<String> = manifest
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("sha256").and_then(|h| h.as_str()).map(String::from))
        .collect();
    assert!(
        recorded.contains(&digest),
        "restored bytes must match the recorded digest: {digest} vs {recorded:?}"
    );
    assert_eq!(content, before, "the file returns to its pre-edit bytes");
    let _ = events;
}
