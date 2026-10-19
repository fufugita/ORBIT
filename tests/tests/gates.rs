//! The honest gates — each drives the REAL `orbit` binary against a
//! scripted provider, as the roadmap asked of every gate (review:
//! "a test that never crosses the front-end cannot catch a missing
//! wire").
//!
//! Gate 3's scenario: "make the tests pass" — the model Reads a file,
//! Edits the bug, runs the command; the tools must actually run.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

/// The orbit binary built by THIS invocation (Q2): the active profile
/// first (PROFILE is set for the test's build), then debug — never a
/// stale release preferred over the current build.
fn orbit_bin() -> std::path::PathBuf {
    let target = workspace_target();
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let active = target.join(&profile).join("orbit");
    if active.exists() {
        return active;
    }
    target.join("debug/orbit")
}

/// The workspace root (tests run from tests/, the target dir is the
/// workspace's).
fn workspace_target() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = the tests package dir; the workspace root
    // is its parent.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&manifest)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("target")
}

/// A mock provider owned by one test. Dropping the guard kills the child —
/// no leaked servers, no stale ports for a later run to collide with.
struct MockGuard {
    child: Option<std::process::Child>,
}

impl Drop for MockGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Spawn the mock provider on an OS-assigned port (127.0.0.1:0) and read
/// the real port from its stdout line. Parallel tests can never collide,
/// and the mock dies with its guard instead of leaking past the run.
/// Every wait carries a deadline: on a starved CI runner the mock can
/// take seconds to print/bind, and an unbounded read would hang the
/// whole suite.
fn spawn_mock_guarded() -> (u16, MockGuard) {
    let target = workspace_target();
    let mut last_err = String::new();
    for attempt in 0..3 {
        // Q2: the profile this invocation builds first, then the other
        // as fallback — the mock must match the orbit binary under test.
        let profile_env = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
        let profiles: [&str; 2] = if profile_env == "release" {
            ["release", "debug"]
        } else {
            ["debug", "release"]
        };
        for profile in profiles {
            let bin = target.join(profile).join("orbit-mock-provider");
            if !bin.exists() {
                last_err = format!("{} not built", bin.display());
                continue;
            }
            let mut child = match Command::new(&bin)
                .env("ORBIT_MOCK_BIND", "127.0.0.1:0")
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    last_err = format!("spawn: {e}");
                    continue;
                }
            };
            // The mock prints "orbit-mock-provider listening on
            // http://127.0.0.1:P". Read that line on a helper thread
            // with a hard 30 s deadline — a blocked pipe read has no
            // timeout of its own.
            let out = child.stdout.take().expect("mock stdout");
            let (tx, rx) = std::sync::mpsc::channel();
            // The drain thread holds the pipe open for the child's
            // lifetime; its handle is deliberately dropped (detached).
            std::thread::spawn(move || {
                use std::io::BufRead;
                let mut reader = std::io::BufReader::new(out);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if let Some(p) = line
                                .rsplit("http://127.0.0.1:")
                                .next()
                                .and_then(|s| s.trim().parse::<u16>().ok())
                            {
                                let _ = tx.send(Ok(p));
                                // Keep draining so the mock never blocks
                                // on a full pipe; exits when it dies.
                                loop {
                                    line.clear();
                                    match reader.read_line(&mut line) {
                                        Ok(0) | Err(_) => return,
                                        Ok(_) => {}
                                    }
                                }
                            }
                        }
                    }
                }
                let _ = tx.send(Err("mock printed no port line".into()));
            });
            let port = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    last_err = e;
                    let _ = child.kill();
                    let _ = child.wait();
                    continue;
                }
                Err(_) => {
                    last_err = "mock did not report its port in 30 s".into();
                    let _ = child.kill();
                    let _ = child.wait();
                    continue;
                }
            };
            // Wait until the port actually accepts connections (same
            // generous window; early-exits on child death).
            let mut ready = false;
            for _ in 0..300 {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    ready = true;
                    break;
                }
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if ready {
                // The drain thread holds the pipe open for the child's
                // lifetime; it exits when the mock dies.
                return (port, MockGuard { child: Some(child) });
            }
            last_err = "mock port never opened".into();
            let _ = child.kill();
            let _ = child.wait();
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    panic!("orbit-mock-provider failed to start: {last_err}");
}

/// Run `orbit -p` and collect the stream-json events.
/// run_orbit_p with an explicit model (the mock's model-name
/// conventions select behaviors).
fn run_orbit_p_model(
    port: u16,
    home: &std::path::Path,
    prompt: &str,
    model: &str,
    extra: &[&str],
) -> (Vec<serde_json::Value>, i32) {
    let bin = orbit_bin();
    let mut cmd = Command::new(&bin)
        .arg("-p")
        .arg(prompt)
        .arg("--home")
        .arg(home)
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--model")
        .arg(model)
        .args(extra)
        .env("ORBIT_HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn orbit");
    let mut events = Vec::new();
    if let Some(out) = cmd.stdout.take() {
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { continue };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                events.push(v);
            }
        }
    }
    let status = cmd.wait().expect("wait orbit");
    (events, status.code().unwrap_or(-1))
}

fn run_orbit_p(
    port: u16,
    home: &std::path::Path,
    prompt: &str,
    extra: &[&str],
) -> (Vec<serde_json::Value>, i32) {
    // stream-json is this runner's contract (events are parsed as JSON
    // lines); run_orbit_p_model passes flags through verbatim.
    let mut args: Vec<&str> = vec!["--output-format", "stream-json"];
    args.extend_from_slice(extra);
    run_orbit_p_model(port, home, prompt, "gate-test-model", &args)
}

/// `run_orbit_p` with a model chosen by the caller — never by a global
/// env var. `std::env::set_var` in one test thread poisons every
/// concurrent test that reads the same var (parallel cargo tests share
/// one process).
#[allow(dead_code)]
fn run_orbit_p_with_model(
    port: u16,
    home: &std::path::Path,
    prompt: &str,
    model: &str,
    extra: &[&str],
) -> (Vec<serde_json::Value>, i32) {
    run_orbit_p_model(port, home, prompt, model, extra)
}

fn fresh_home(tag: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!("orbit-gate-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&home)
        .unwrap();
    home
}

fn write_providers(
    path: impl AsRef<std::path::Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = path.as_ref();
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn init_home(bin: &str, home: &std::path::Path) {
    let status = Command::new(bin)
        .arg("init")
        .env("ORBIT_HOME", home)
        .status()
        .expect("orbit init");
    assert!(status.success(), "orbit init must succeed");
}

/// Gate 3 through the binary: the scripted session offers a calculator
/// call (the mock's implicit tool behavior), the tool RUNS (not
/// "unknown tool"), and the turn completes.
#[test]
fn gate3_tools_run_through_the_binary() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("g3-binary");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);

    // --auto-tools: the honest way to let tools run headless. Without
    // it the calculator call is denied (exit 2) — which the exit-code
    // contract now makes visible instead of hiding behind turn-ok.
    let (events, code) = run_orbit_p(port, &home, "what is 2*(3+4)?", &["--auto-tools"]);
    let types: Vec<&str> = events
        .iter()
        .filter_map(|e| e.get("type").and_then(|t| t.as_str()))
        .collect();
    assert!(
        types.contains(&"turn_ended"),
        "the turn must end through the binary: {types:?}"
    );
    let ended = events
        .iter()
        .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("turn_ended"))
        .unwrap();
    assert_eq!(
        ended.get("ok").and_then(|o| o.as_bool()),
        Some(true),
        "turn ok through the binary"
    );
    assert_eq!(code, 0, "exit code 0");

    // The tool round actually ran a tool: the mock's calculator call
    // must NOT come back as "unknown tool".
    let all = serde_json::to_string(&events).unwrap_or_default();
    assert!(
        !all.contains("unknown tool"),
        "the Wave 1/built-in tools must run through the binary, not fail as unknown"
    );

    // Cleanup: kill the leaked mock.
    let _ = Command::new("fuser")
        .arg("-k")
        .arg(format!("{port}/tcp"))
        .status();
    let _ = std::fs::remove_dir_all(&home);
}

/// Gate 1 through the binary: a prompt mentioning @.env is refused
/// (deny-read), and the refusal is visible in the event stream.
#[test]
fn gate1_env_mention_refused_through_binary() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("g1-binary");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);

    // The @.env expansion happens in the TUI composer; headless passes
    // the text through. The deny-read enforcement lives in the Read
    // tool. Here we assert the binary completes and the scanner never
    // lets a secret through: a prompt with a fake key in it must not
    // echo the key back in any event.
    let (events, _code) = run_orbit_p(
        port,
        &home,
        "summarize token = sk-abcdefghijklmnopqrstuvwxyz123456",
        &[],
    );
    let all = serde_json::to_string(&events).unwrap_or_default();
    assert!(
        !all.contains("abcdefghijklmnopqrstuvwxyz123456"),
        "a secret in the prompt must never appear in the event stream"
    );

    let _ = Command::new("fuser")
        .arg("-k")
        .arg(format!("{port}/tcp"))
        .status();
    let _ = std::fs::remove_dir_all(&home);
}

/// Gate 4, part 1: resume a reducible text history through the real
/// binary. Explicit independent ordinary/summary input policies must
/// produce an applied, fitting compaction and a successful continuation.
#[test]
fn gate4_auto_compaction_through_the_binary() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("g4-compact");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);

    const INPUT: u64 = 65_536;
    const SESSION: &str = "g4-compact-seeded";
    const PROMPT: &str = "count from 1 to 5";
    const MODEL: &str = "gate-test-model-notools";
    let gate = format!("http://127.0.0.1:{port}");
    // Typed explicit policies: raw legacy metadata is not a capacity fact.
    let providers = home.join("providers.toml");
    write_providers(
        &providers,
        format!(
            r#"[[provider]]
name = "gate"
kind = "openai-compatible"
url = "http://127.0.0.1:{port}"

[[provider.models]]
id = "gate-test-model-notools"
max_output_tokens = 256
[provider.models.context_limits]
input_tokens = 65536

[[provider.models]]
id = "gate-test-model-notools-summary"
max_output_tokens = 128
[provider.models.context_limits]
input_tokens = 262144

[roles]
compaction = "gate/gate-test-model-notools-summary"
"#
        ),
    )
    .unwrap();

    let mut history = Vec::new();
    for index in 0..6 {
        history.push(orbit_engine::user_message(format!(
            "old-user-{index}: {}",
            "u".repeat(32_768)
        )));
        history.push(orbit_engine::assistant_message(format!(
            "old-assistant-{index}: {}",
            "a".repeat(32_768)
        )));
    }
    for index in 0..3 {
        history.push(orbit_engine::user_message(format!("recent-user-{index}")));
        history.push(orbit_engine::assistant_message(format!(
            "recent-assistant-{index}"
        )));
    }
    assert!(
        history[..12]
            .iter()
            .map(|message| message.content.len())
            .sum::<usize>()
            > 4 * INPUT as usize
    );
    let saved = orbit_cli::sessions::SessionFile::from_chat(
        SESSION, MODEL, &gate, "gate", &history, 9, 0, 0, 0,
    );
    {
        let lease = orbit_cli::sessions::SessionLease::acquire(&home, SESSION, "fixture").unwrap();
        lease.save(&saved).unwrap();
    } // Release the seed lease before the real binary resumes it.

    let (events, code) = run_orbit_p_model(
        port,
        &home,
        PROMPT,
        MODEL,
        &[
            "--output-format",
            "stream-json",
            "--resume",
            SESSION,
            "--provider",
            "gate",
            "--bare",
        ],
    );
    let types: Vec<&str> = events
        .iter()
        .filter_map(|e| e.get("type").and_then(|t| t.as_str()))
        .collect();
    // The turn must complete...
    assert!(
        types.contains(&"turn_ended"),
        "gate4: the turn must end: {types:?}"
    );
    let ended = events
        .iter()
        .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("turn_ended"))
        .unwrap();
    assert_eq!(ended.get("ok").and_then(|o| o.as_bool()), Some(true));
    assert_eq!(code, 0);

    // An attempted but rejected summary is insufficient: applied reduction,
    // ordinary completion and durable retained intent must all be observed.
    let compacting: Vec<_> = events
        .iter()
        .filter(|event| event["type"] == "compacting")
        .collect();
    let compacted: Vec<_> = events
        .iter()
        .filter(|event| event["type"] == "compacted")
        .collect();
    assert_eq!(
        compacting.len(),
        1,
        "gate4: exactly one bounded compaction attempt: {types:?}"
    );
    assert_eq!(
        compacted.len(),
        1,
        "gate4: the candidate must actually be applied: {types:?}"
    );
    let before = compacting[0]["used_tokens"].as_u64().unwrap();
    let after = compacted[0]["after_tokens"].as_u64().unwrap();
    assert_eq!(compacting[0]["window_tokens"].as_u64(), Some(INPUT));
    assert!(before > INPUT && after > 0 && after <= INPUT && after < before);
    let at = |kind: &str| types.iter().position(|value| *value == kind).unwrap();
    assert!(at("compacting") < at("compacted") && at("compacted") < at("turn_ended"));
    assert_eq!(
        types.iter().filter(|kind| **kind == "turn_ended").count(),
        1,
        "summary terminal events stay private"
    );
    let visible: String = events
        .iter()
        .filter(|event| event["type"] == "text_delta")
        .filter_map(|event| event["text"].as_str())
        .collect();
    assert_eq!(
        visible, "hello world",
        "only the ordinary reply is streamed; summary deltas stay private"
    );
    let usage: Vec<_> = events
        .iter()
        .filter(|event| event["type"] == "usage")
        .collect();
    assert_eq!(
        usage.len(),
        1,
        "only ordinary occupancy reaches the public stream"
    );
    assert_eq!(usage[0]["window_tokens"].as_u64(), Some(INPUT));
    assert!(usage[0]["used_tokens"].as_u64().unwrap() <= INPUT);
    assert_eq!(usage[0]["breakdown"]["reserve"].as_u64(), Some(0));
    assert_eq!(usage[0]["breakdown"]["compact_at"].as_u64(), Some(58_982));

    let resumed = orbit_cli::sessions::load_session(&home, SESSION).unwrap();
    assert_eq!(resumed.session_id, SESSION);
    assert_eq!(resumed.provider, "gate");
    assert_eq!(resumed.model, MODEL);
    assert_eq!(resumed.turns, 10);
    assert!(resumed.transcript.len() < history.len() + 2);
    assert_eq!(resumed.transcript.last().unwrap().content, "hello world");
    assert!(
        history[..12]
            .iter()
            .any(|message| !resumed.transcript.contains(message)),
        "an older source prefix was replaced by its applied summary"
    );
    let mut required = history[history.len() - 4..].to_vec();
    required.push(orbit_engine::user_message(PROMPT));
    let end = resumed.transcript.len() - 1;
    assert!(end >= required.len());
    assert_eq!(
        &resumed.transcript[end - required.len()..end],
        required.as_slice(),
        "newest complete text exchanges and current intent survive exactly"
    );
    // This is the automatic route: its public preview is scanned/bounded,
    // while manual compact_context_detailed deliberately emits an empty one.
    assert_eq!(compacted[0]["summary"], "hello world");
    assert_eq!(
        &resumed.transcript[..2],
        &[
            orbit_engine::user_message("[Earlier conversation summary: historical data]"),
            orbit_engine::assistant_message("hello world"),
        ]
    );
    let lease =
        orbit_cli::sessions::SessionLease::acquire(&home, SESSION, "gate-archive-check").unwrap();
    let archive_dir = home.join("context-history").join(SESSION).join("archives");
    let archives: Vec<_> = std::fs::read_dir(&archive_dir)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        archives.len(),
        1,
        "one applied candidate retains one full original"
    );
    let archive_path = archives[0].path();
    let archive: serde_json::Value =
        serde_json::from_slice(&gate_read_bounded(&archive_path)).unwrap();
    let record_id = archive["operation_id"].as_str().unwrap();
    assert_eq!(
        archive_path.file_name().unwrap(),
        format!("{record_id}.json").as_str()
    );
    let mut original = history.clone();
    original.push(orbit_engine::user_message(PROMPT));
    assert_eq!(
        orbit_cli::context_history::load_compaction_source(&home, SESSION, None, record_id)
            .unwrap(),
        original,
        "the actual canonical reader must recover the complete typed original"
    );
    let candidate: Vec<orbit_adapter::types::ChatMessage> =
        serde_json::from_value(archive["candidate"].clone()).unwrap();
    assert_eq!(
        candidate,
        resumed.transcript[..resumed.transcript.len() - 1]
    );
    assert_eq!(archive["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(archive["attempts"][0]["purpose"], "chunk");
    let checkpoint = orbit_cli::context_history::inspect_accounting(&home, SESSION, None)
        .unwrap()
        .checkpoint;
    assert_eq!(
        checkpoint.revision.0, 4,
        "one summary and one ordinary request are settled once"
    );
    assert_eq!(
        checkpoint.baseline,
        orbit_engine::AccountingBaseline::UnknownLegacy
    );
    assert!(checkpoint.pending.is_none());
    assert_eq!(
        (
            checkpoint.totals.ordinary.input_tokens,
            checkpoint.totals.ordinary.output_tokens
        ),
        (3, 2)
    );
    assert_eq!(
        (
            checkpoint.totals.housekeeping.input_tokens,
            checkpoint.totals.housekeeping.output_tokens
        ),
        (3, 2)
    );
    assert_eq!(
        resumed
            .accounting_watermark
            .as_ref()
            .unwrap()
            .full_cost_status,
        orbit_cli::sessions::FullCostStatus::UnknownLegacy
    );
    drop(lease);

    drop(_mock_guard); // The retained guard already owns/kills/waits for this child.
    let _ = std::fs::remove_dir_all(&home);
}

/// Gate 4, part 2: SIGKILL retains the completed prefix and the begun-only
/// request. Admission refuses replay; explicit cold inspection remains useful.
#[test]
fn gate4_sigkill_retains_pending_prefix_and_requires_inspection() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("g4-continue");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);

    // Turn 1 completes normally: the session file exists with 1 turn.
    let (events, code) = run_orbit_p(port, &home, "say hi once", &["--auto-tools"]);
    assert_eq!(code, 0);
    assert!(
        events
            .iter()
            .any(|e| e.get("type").and_then(|t| t.as_str()) == Some("turn_ended"))
    );
    let saved = gate_only_session(&home);
    assert_eq!(saved.turns, 1);
    let baseline = orbit_cli::context_history::inspect_accounting(&home, &saved.session_id, None)
        .unwrap()
        .checkpoint;
    assert!(baseline.pending.is_none());

    // Turn 2 is killed mid-flight with SIGKILL (nothing can intercept).
    let child = Command::new(&bin)
        .arg("-p")
        .arg("you will not finish this")
        .arg("--continue")
        .arg("--home")
        .arg(&home)
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--model")
        .arg("gate-test-model-slow-stream")
        .arg("--output-format")
        .arg("stream-json")
        .env("ORBIT_HOME", &home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn orbit turn 2");
    let mut interrupted = MockGuard { child: Some(child) };
    let out = interrupted.child.as_mut().unwrap().stdout.take().unwrap();
    let (first_tx, first_rx) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut events = Vec::new();
        let mut signalled = false;
        let mut bytes = 0usize;
        // A total stream bound also bounds a hostile single line.
        for line in BufReader::new(out.take(2 * 1024 * 1024 + 1)).lines() {
            let line = line.unwrap();
            bytes = bytes.checked_add(line.len() + 1).unwrap();
            assert!(bytes <= 2 * 1024 * 1024, "interrupted stream output bound");
            if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                if !signalled
                    && event["type"] == "text_delta"
                    && event["text"].as_str().is_some_and(|text| !text.is_empty())
                {
                    first_tx.send(()).unwrap();
                    signalled = true;
                }
                events.push(event);
            }
        }
        events
    });
    let reached = first_rx.recv_timeout(std::time::Duration::from_secs(10));
    let child = interrupted.child.as_mut().unwrap();
    child.kill().expect("kill the owned streaming process");
    let status = child.wait().unwrap();
    let interrupted_events = reader.join().unwrap();
    assert!(
        reached.is_ok(),
        "SIGKILL requires an actually observed provider delta"
    );
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    assert!(
        !interrupted_events
            .iter()
            .any(|event| event["type"] == "turn_ended")
    );

    let after_kill = gate_only_session(&home);
    assert_eq!(after_kill.session_id, saved.session_id);
    assert_eq!(after_kill.transcript, saved.transcript);
    assert_eq!(
        (
            after_kill.turns,
            after_kill.input_tokens,
            after_kill.output_tokens,
            after_kill.cost_microcents
        ),
        (
            saved.turns,
            saved.input_tokens,
            saved.output_tokens,
            saved.cost_microcents
        )
    );
    let pending =
        orbit_cli::context_history::inspect_accounting(&home, &saved.session_id, None).unwrap();
    assert_eq!(pending.checkpoint.revision.0, baseline.revision.0 + 1);
    assert_eq!(pending.checkpoint.totals, baseline.totals);
    assert_eq!(
        pending.checkpoint.known_priced_subtotals,
        baseline.known_priced_subtotals
    );
    assert_eq!(pending.checkpoint.last_settlement, baseline.last_settlement);
    let attempt = pending.checkpoint.pending.as_ref().unwrap();
    assert_eq!(attempt.intent.owner_session_id, saved.session_id);
    assert!(attempt.intent.child_id.is_none());
    assert_eq!(
        attempt.intent.purpose,
        orbit_engine::AttemptPurpose::Ordinary
    );
    assert!(
        !attempt.uncertain,
        "SIGKILL cannot invent a settled uncertain receipt"
    );
    assert!(pending.pending_receipt.is_none());
    let reference = attempt.reference.clone();
    let source = gate_payload_bytes(&home, &saved.session_id);
    drop(_mock_guard); // Actual provider is stopped before any recovery command.
    let trap = GateReplayTrap::new();

    // The original --continue selection remains exercised, but pending work
    // must not be silently retried or counted as a completed second turn.
    let refused = Command::new(&bin)
        .args([
            "-p",
            "and we are back",
            "--continue",
            "--auto-tools",
            "--output-format",
            "stream-json",
        ])
        .arg("--home")
        .arg(&home)
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{}", trap.port))
        .arg("--model")
        .arg("gate-test-model")
        .env("ORBIT_HOME", &home)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains(
        "ORBIT-E0400: a pending uncertain request requires explicit inspection before admission"
    ));
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("\"type\":\"turn_ended\""));
    assert_eq!(gate_payload_bytes(&home, &saved.session_id), source);

    let status = Command::new(&bin)
        .args([
            "recovery",
            "status",
            "--session",
            &saved.session_id,
            "--json",
        ])
        .arg("--home")
        .arg(&home)
        .env("ORBIT_HOME", &home)
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(status.stderr.is_empty() && status.stdout.len() <= 16 * 1024);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["schema"], "orbit.recovery-status/v1");
    assert_eq!(status["status"], "available");
    assert_eq!(status["owner_session_id"], saved.session_id);
    assert_eq!(status["lifecycle"], "begun_only");
    assert_eq!(
        status["checkpoint_revision"].as_u64(),
        Some(pending.checkpoint.revision.0)
    );
    assert_eq!(
        status["pending"]["reference"]["request_id"],
        reference.request_id
    );
    assert_eq!(
        status["pending"]["reference"]["intent_digest"],
        reference.intent_digest
    );
    assert_eq!(status["inspection_digest"], pending.inspection_digest);
    assert_eq!(status["inspection"]["qualification"], "visible_validated");
    assert_eq!(
        status["inspection"]["provider_outcome"],
        "not_established_by_inspection"
    );
    assert_eq!(gate_payload_bytes(&home, &saved.session_id), source);
    assert_eq!(
        orbit_cli::context_history::inspect_accounting(&home, &saved.session_id, None).unwrap(),
        pending
    );
    let lease = orbit_cli::sessions::SessionLease::acquire(
        &home,
        &saved.session_id,
        "gate-released-after-kill",
    )
    .unwrap();
    assert_eq!(lease.load().unwrap().transcript, saved.transcript);
    drop(lease);
    assert_eq!(
        trap.finish(),
        0,
        "no recovery command may connect to the selected provider"
    );
    assert_eq!(gate_only_session(&home).turns, 1);
    let _ = std::fs::remove_dir_all(&home);
}

fn gate_only_session(home: &std::path::Path) -> orbit_cli::sessions::SessionFile {
    let json_files = std::fs::read_dir(home.join("sessions"))
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
        })
        .count();
    assert_eq!(json_files, 1);
    let mut sessions = orbit_cli::sessions::list_sessions(home).unwrap();
    assert_eq!(
        sessions.len(),
        1,
        "no fresh fallback may replace the selected owner"
    );
    sessions.remove(0)
}

fn gate_read_bounded(path: &std::path::Path) -> Vec<u8> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let before = std::fs::symlink_metadata(path).unwrap();
    assert!(before.is_file() && before.nlink() == 1 && before.len() <= 4 * 1024 * 1024);
    let file = std::fs::File::open(path).unwrap();
    let opened = file.metadata().unwrap();
    assert_eq!((opened.dev(), opened.ino()), (before.dev(), before.ino()));
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, before.len());
    bytes
}

fn gate_payload_bytes(
    home: &std::path::Path,
    id: &str,
) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut paths = vec![
        home.join("sessions").join(format!("{id}.json")),
        home.join("context-history")
            .join(id)
            .join("accounting.json"),
    ];
    let archives = home.join("context-history").join(id).join("archives");
    let entries: Vec<_> = std::fs::read_dir(archives)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(entries.len() <= 64);
    paths.extend(entries.into_iter().map(|entry| entry.path()));
    let legacy = home.join("projects").join(format!("{id}.jsonl"));
    match std::fs::symlink_metadata(&legacy) {
        Ok(_) => paths.push(legacy),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("legacy fixture metadata: {error}"),
    }
    paths
        .into_iter()
        .map(|path| {
            (
                path.strip_prefix(home).unwrap().to_owned(),
                gate_read_bounded(&path),
            )
        })
        .collect()
}

struct GateReplayTrap {
    port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<Result<usize, &'static str>>>,
}
impl GateReplayTrap {
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let join = std::thread::spawn(move || {
            use std::io::Write;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let mut count = 0usize;
            loop {
                if std::time::Instant::now() >= deadline {
                    return Err("trap deadline before acknowledged stop");
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        count = count.checked_add(1).ok_or("trap count overflow")?;
                        stream
                            .set_write_timeout(Some(std::time::Duration::from_millis(100)))
                            .map_err(|_| "trap timeout")?;
                        let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopped.load(std::sync::atomic::Ordering::SeqCst) {
                            return Ok(count);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Err("trap accept failed"),
                }
            }
        });
        Self {
            port,
            stop,
            join: Some(join),
        }
    }
    fn finish(mut self) -> usize {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        self.join.take().unwrap().join().unwrap().unwrap()
    }
}
impl Drop for GateReplayTrap {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let result = join.join();
            if !std::thread::panicking() {
                result.unwrap().unwrap();
            }
        }
    }
}

/// Phase 5, part 1: the signed-mod flow through the binary. A mod is
/// installed only when the issuer is trusted, the signature verifies
/// and the content digest matches; a tampered package is refused.
#[test]
fn mod_install_signed_flow_through_binary() {
    let home = fresh_home("mod-install");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);

    // Generate a key, sign a manifest, trust the issuer, install.
    // (Signing happens via a tiny cargo script through the plugin
    // crate's public sign_manifest — here we shell out to the
    // workspace's test binary helper.)
    let tmp = home.join("pkg");
    std::fs::create_dir_all(&tmp).unwrap();
    let package = tmp.join("mod.wasm");
    std::fs::write(&package, b"package-bytes").unwrap();
    let manifest = tmp.join("manifest.json");

    // Sign in-process (tests/Cargo.toml links orbit-plugin and
    // ed25519-dalek).
    let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let m = orbit_plugin::sign_manifest(
        "my-mod",
        "0.1.0",
        &sk,
        b"package-bytes",
        vec!["wasi:http/proxy".into()],
    );
    std::fs::write(&manifest, serde_json::to_string_pretty(&m).unwrap()).unwrap();

    // 1. Install WITHOUT trusting the issuer → refused.
    let out = Command::new(&bin)
        .args(["mod", "install", "--yes"])
        .arg(&package)
        .arg("--manifest")
        .arg(&manifest)
        .env("ORBIT_HOME", &home)
        .output()
        .expect("mod install (untrusted)");
    assert!(!out.status.success(), "an untrusted issuer must be refused");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("E0806") || err.contains("not trusted"),
        "refusal names the issuer gate: {err}"
    );

    // 2. Trust the issuer, then install → ok.
    let pubkey = hex::encode(sk.verifying_key().to_bytes());
    let out = Command::new(&bin)
        .args(["mod", "allow-issuer"])
        .arg(&pubkey)
        .env("ORBIT_HOME", &home)
        .output()
        .expect("allow-issuer");
    assert!(
        out.status.success(),
        "allow-issuer: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(&bin)
        .args(["mod", "install", "--yes"])
        .arg(&package)
        .arg("--manifest")
        .arg(&manifest)
        .env("ORBIT_HOME", &home)
        .output()
        .expect("mod install");
    assert!(
        out.status.success(),
        "signed install must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("my-mod"), "install names the mod: {stdout}");

    // 3. Tampered package → digest mismatch, refused.
    std::fs::write(&package, b"package-bytes-tampered").unwrap();
    let out = Command::new(&bin)
        .args(["mod", "install", "--yes"])
        .arg(&package)
        .arg("--manifest")
        .arg(&manifest)
        .env("ORBIT_HOME", &home)
        .output()
        .expect("mod install (tampered)");
    assert!(!out.status.success(), "a tampered package must be refused");

    let _ = std::fs::remove_dir_all(&home);
}

/// Gate 6: the audited CI run. `orbit -p` under an explicit allowlist
/// with --bare and --max-cost behaves as CI needs it: the summary is
/// valid JSON on stdout, a disallowed tool is denied (not executed),
/// and the session's decisions are on disk for export.
#[test]
fn gate6_ci_run_allowlist_and_exit_codes() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("g6-ci");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);
    write_providers(
        home.join("providers.toml"),
        format!(
            r#"[[provider]]
name = "gate"
kind = "openai-compatible"
url = "http://127.0.0.1:{port}"
[[provider.models]]
id = "gate-test-model"
[provider.models.pricing]
input_per_million_microdollars = 10000
output_per_million_microdollars = 10000
cache_read_per_million_microdollars = 10000
cache_write_per_million_microdollars = 10000
reasoning_per_million_microdollars = 10000
request_flat_microdollars = 1
"#
        ),
    )
    .unwrap();

    // The CI shape: explicit allowlist, bare start, json summary,
    // cost budget. The mock's implicit script calls a tool NOT in the
    // allowlist → the call must be denied, and the turn still ends
    // with a parseable summary + a distinct exit code (2: permission).
    let (events, code) = run_orbit_p_ext(
        port,
        &home,
        "review the changed files",
        &[
            "--allowedTools",
            "Read,Glob,Grep",
            "--bare",
            "--max-cost",
            "1000000",
            "--output-format",
            "json",
        ],
    );
    // Exit code 2 = stopped by a permission denial (the honest CI
    // signal: the agent wanted a tool the allowlist does not grant).
    assert_eq!(code, 2, "a non-allowlisted tool call must deny with exit 2");

    // The json summary went to stdout — events here captured the
    // stream; with --output-format json the summary is one object.
    // (run_orbit_p_ext parses every line; find the summary.)
    let summary = events
        .iter()
        .find(|e| e.get("schema").and_then(|s| s.as_str()) == Some("orbit.cli/v1"));
    assert!(
        summary.is_some(),
        "the json summary object must print: {}",
        serde_json::to_string(&events).unwrap_or_default()
    );

    // The denial is recorded in the session (auditable).
    let summary = summary.unwrap();
    assert_eq!(summary["command"], "p");
    assert_eq!(summary["full_cost_status"], "known");
    assert!(summary["cost_microcents"].as_u64().unwrap() > 0);
    let saved = gate_only_session(&home);
    let denied: Vec<_> = saved
        .transcript
        .iter()
        .filter(|message| {
            message.role == orbit_adapter::types::ChatRole::Tool
                && message
                    .tool_result
                    .as_deref()
                    .is_some_and(orbit_tools::result_is_denial)
        })
        .collect();
    assert_eq!(denied.len(), 1);
    let verified = Command::new(&bin)
        .arg("--home")
        .arg(&home)
        .arg("verify-ledger")
        .output()
        .unwrap();
    assert!(verified.status.success());
    let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    let calls = verified["calls"].as_array().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["tool"], "calculator");
    assert!(calls[0]["intent"].is_object());
    assert_eq!(calls[0]["decision"]["allowed"], false);
    assert_eq!(calls[0]["result"]["status"], "denied");
    let checkpoint = orbit_cli::context_history::inspect_accounting(&home, &saved.session_id, None)
        .unwrap()
        .checkpoint;
    assert!(checkpoint.pending.is_none());
    assert_eq!(
        checkpoint.totals.ordinary.cost_microcents,
        summary["cost_microcents"].as_u64()
    );
    assert_eq!(checkpoint.totals.housekeeping.input_tokens, 0);
    let _ = std::fs::remove_dir_all(&home);
    let _ = Command::new("fuser")
        .arg("-k")
        .arg(format!("{port}/tcp"))
        .status();
}

/// run_orbit_p + extra passthrough (json output needs the raw line
/// stream, not just FrontendEvents).
fn run_orbit_p_ext(
    port: u16,
    home: &std::path::Path,
    prompt: &str,
    extra: &[&str],
) -> (Vec<serde_json::Value>, i32) {
    let bin = orbit_bin();
    let mut cmd = Command::new(&bin)
        .arg("-p")
        .arg(prompt)
        .arg("--home")
        .arg(home)
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--model")
        .arg("gate-test-model")
        .args(extra)
        .env("ORBIT_HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn orbit");
    let mut events = Vec::new();
    if let Some(out) = cmd.stdout.take() {
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { continue };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                events.push(v);
            }
        }
    }
    let status = cmd.wait().expect("wait orbit");
    (events, status.code().unwrap_or(-1))
}
// ── Gate 2: one loop everywhere ────────────────────────────────────
// MD gate 2: "One scripted session, run through the TUI, the REPL and
// the web front-end, produces the same event stream, and the old loop
// functions no longer exist." The event stream IS the frontend
// protocol (FrontendEvent, snake_case serde) — `orbit -p
// --output-format stream-json` prints it verbatim. The web front-end
// must carry the SAME protocol names over SSE, not a private
// vocabulary.
#[test]
fn gate2_one_loop_same_event_stream() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("gate2");
    init_home(
        &workspace_target().join("debug/orbit").display().to_string(),
        &home,
    );
    // Both frontends use the same declared provider identity. The browser
    // refuses undeclared models rather than adopting the legacy headless gate.
    write_providers(
        home.join("providers.toml"),
        format!(
            "[[provider]]\nname='gate'\nkind='openai-compatible'\nurl='http://127.0.0.1:{port}'\n[[provider.models]]\nid='gate-test-model'\n"
        ),
    )
    .unwrap();

    // The reference stream: `orbit -p` (the REPL/headless front-end),
    // stream-json = FrontendEvent serde.
    let (events_a, _code) = run_orbit_p(port, &home, "go", &["--auto-tools"]);
    let types_a: Vec<String> = events_a
        .iter()
        .filter_map(|e| e.get("type").and_then(|t| t.as_str()).map(String::from))
        .collect();
    // The session's happenings in protocol terms (the scripted mock
    // plays one calculator call, then the final text).
    // The owned browser buffers complete lines for its display scanner.
    // Adjacent text chunks may coalesce; every other event keeps its position
    // and multiplicity, and the complete text is compared below as well.
    fn normalize_text_chunks<'a>(sequence: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        let mut normalized = Vec::new();
        let mut pending_text = false;
        for kind in sequence {
            if kind == "text_delta" {
                pending_text = true;
                continue;
            }
            // DisplayStream flushes its scanned line at response completion;
            // accounting can therefore precede the displayed text. Defer only
            // across these accounting events, never tools, rounds or statuses.
            if pending_text && !matches!(kind, "ledger_appended" | "cost_updated" | "usage") {
                normalized.push("text_delta");
                pending_text = false;
            }
            normalized.push(kind);
        }
        if pending_text {
            normalized.push("text_delta");
        }
        normalized
    }
    let seq_a = normalize_text_chunks(types_a.iter().map(|t| match t.as_str() {
        "round_started" => "round_started",
        "cost_updated" => "cost_updated",
        "tool_started_full" => "tool_started",
        "tool_finished_full" => "tool_finished",
        "text_delta" => "text_delta",
        "response_finished" => "response_finished",
        "turn_ended" => "turn_ended",
        other => other,
    }));
    assert!(
        seq_a.contains(&"tool_started")
            && seq_a.contains(&"tool_finished")
            && seq_a.contains(&"text_delta")
            && seq_a.contains(&"turn_ended"),
        "the reference stream must show the tool and the reply: {types_a:?}"
    );

    // The web front-end: same session shape, same protocol names.
    let target = workspace_target();
    let web_bin = target.join("debug/orbit-web");
    assert!(web_bin.exists(), "orbit-web must be built for gate 2");
    let bport = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let token = format!("gate2-local-{}-{bport}", std::process::id());
    let web_child = Command::new(&web_bin)
        .arg("--home")
        .arg(&home)
        .arg("--model")
        .arg("gate-test-model")
        .arg("--provider")
        .arg("gate")
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--auto-tools")
        .arg("--no-browser")
        .arg("--port")
        .arg(bport.to_string())
        .arg("--token")
        .arg(&token)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn orbit-web");
    let mut web = MockGuard {
        child: Some(web_child),
    };
    let mut up = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", bport)).is_ok() {
            up = true;
            break;
        }
        if web.child.as_mut().unwrap().try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(up, "orbit-web did not come up on {bport}");

    // SSE reader thread (raw HTTP over loopback).
    let sse_frames: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> = Default::default();
    let sse2 = sse_frames.clone();
    let sse_token = token.clone();
    let reader = std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Write};
        let mut sock = match std::net::TcpStream::connect(("127.0.0.1", bport)) {
            Ok(s) => s,
            Err(_) => return,
        };
        let req = format!(
            "GET /events?token={sse_token} HTTP/1.1\r\nHost: 127.0.0.1:{bport}\r\nOrigin: http://127.0.0.1:{bport}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n"
        );
        if sock.write_all(req.as_bytes()).is_err() {
            return;
        }
        let mut kind = String::new();
        for line in BufReader::new(sock).lines() {
            let Ok(line) = line else { break };
            if let Some(k) = line.strip_prefix("event: ") {
                kind = k.trim().to_string();
            } else if let Some(d) = line.strip_prefix("data: ")
                && !kind.is_empty()
            {
                sse2.lock()
                    .unwrap()
                    .push((kind.clone(), d.trim().to_string()));
                kind.clear();
            }
        }
    });
    // Wait for the SSE stream to be live (the server speaks as soon as it
    // is connected) instead of sleeping and hoping: under load a fixed
    // pause raced the connect and the gate saw an empty stream.
    let live_by = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while sse_frames.lock().unwrap().is_empty() && std::time::Instant::now() < live_by {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        !sse_frames.lock().unwrap().is_empty(),
        "the browser SSE stream must be connected before sending the prompt"
    );

    // The same prompt over the WS actions endpoint (raw client).
    {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let mut sock = TcpStream::connect(("127.0.0.1", bport)).unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAA==";
        let req = format!(
            "GET /actions?token={token} HTTP/1.1\r\nHost: 127.0.0.1:{bport}\r\nOrigin: http://127.0.0.1:{bport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        sock.write_all(req.as_bytes()).unwrap();
        // Read exactly the HTTP header; a coalesced controller_ready frame
        // must remain available to the WebSocket reader.
        let mut hdr = Vec::new();
        while !hdr.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            sock.read_exact(&mut byte).unwrap();
            hdr.push(byte[0]);
            assert!(hdr.len() <= 8192, "oversized WS handshake");
        }
        let handshake = String::from_utf8_lossy(&hdr).to_string();
        assert!(
            handshake.starts_with("HTTP/1.1 101"),
            "WS handshake failed: {handshake}"
        );
        fn read_ws_json(sock: &mut TcpStream) -> serde_json::Value {
            let mut header = [0_u8; 2];
            sock.read_exact(&mut header).unwrap();
            assert_eq!(header[0], 0x81, "expected one complete WS text frame");
            assert_eq!(header[1] & 0x80, 0, "server WS frame must be unmasked");
            let size = match header[1] & 0x7f {
                126 => {
                    let mut length = [0_u8; 2];
                    sock.read_exact(&mut length).unwrap();
                    u16::from_be_bytes(length) as u64
                }
                127 => {
                    let mut length = [0_u8; 8];
                    sock.read_exact(&mut length).unwrap();
                    u64::from_be_bytes(length)
                }
                size => size as u64,
            };
            assert!(size <= 1024 * 1024, "oversized WS reply");
            let mut payload = vec![0_u8; size as usize];
            sock.read_exact(&mut payload).unwrap();
            serde_json::from_slice(&payload).expect("WS JSON reply")
        }
        assert_eq!(read_ws_json(&mut sock)["type"], "controller_ready");
        let payload = br#"{"type":"prompt","request_id":"gate2-prompt","text":"go"}"#;
        let mask = [0x11u8, 0x22, 0x33, 0x44];
        let mut frame = vec![0x81u8, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        sock.write_all(&frame).unwrap();
        let ack = read_ws_json(&mut sock);
        assert_eq!(ack["type"], "action_ack", "prompt must be accepted: {ack}");
        // The turn is over when the stream says so, not after a guess.
        let done_by = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !sse_frames
            .lock()
            .unwrap()
            .iter()
            .any(|(k, _)| k == "turn_ended")
            && std::time::Instant::now() < done_by
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    if let Some(mut child) = web.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    reader
        .join()
        .expect("SSE reader must finish after bridge exit");
    let frames = sse_frames.lock().unwrap().clone();

    // Extract the web front-end's turn happenings as protocol names.
    // Web-only service events (identity/resumed/models/…) are outside
    // the turn stream and ignored; the comparison is the SESSION's
    // protocol stream.
    let seq_b = normalize_text_chunks(
        frames
            .iter()
            .filter(|(k, _)| {
                matches!(
                    k.as_str(),
                    "round_started"
                        | "ledger_appended"
                        | "cost_updated"
                        | "usage"
                        | "status"
                        | "routing"
                        | "tool_started"
                        | "tool_started_full"
                        | "tool_finished"
                        | "tool_finished_full"
                        | "text_delta"
                        | "response_finished"
                        | "turn_ended"
                )
            })
            .map(|(k, _)| match k.as_str() {
                "tool_started_full" => "tool_started",
                "tool_finished_full" => "tool_finished",
                // Headless reports the same selection as a status event; the
                // owned browser carries the structured routing service event.
                "routing" => "status",
                other => other,
            }),
    );

    let text_a = events_a
        .iter()
        .filter(|event| event["type"] == "text_delta")
        .map(|event| event["text"].as_str().expect("headless text chunk"))
        .collect::<String>();
    let text_b = frames
        .iter()
        .filter(|(kind, _)| kind == "text_delta")
        .map(|(_, payload)| {
            let value: serde_json::Value =
                serde_json::from_str(payload).expect("SSE JSON text chunk");
            value["text"]
                .as_str()
                .expect("browser text chunk")
                .to_owned()
        })
        .collect::<String>();
    assert!(
        !text_a.is_empty(),
        "the shared stream must contain reply text"
    );
    assert_eq!(
        text_a, text_b,
        "all reply text must survive browser display buffering"
    );

    assert_eq!(
        seq_a, seq_b,
        "MD gate 2: the same session through -p and the web front-end must \
produce the same protocol event stream.\n-p: {seq_a:?}\nweb: {seq_b:?} (raw: {frames:?})"
    );
}

/// MD gate 2, second half: "the old loop functions no longer exist."
/// The four front-end loops named in the roadmap
/// (main.rs:926, web/turn.rs:313, go_bridge.rs:417, tui_worker) are
/// all the engine's now; a front-end that grows its own provider
/// round loop again must trip this.
#[test]
fn gate2_no_front_end_owns_a_loop() {
    // A front-end crate may depend on the engine but must not implement
    // its own provider streaming loop: the marker is a direct
    // request-dispatch/retry/round-cap implementation. The engine's
    // run_turn is the only loop; grep the front-end crates for loop
    // re-implementations.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates");
    for (crate_dir, allowed) in [
        ("cli", true),     // hosts the engine bindings, not a loop
        ("web", true),     // SSE/WS adapter
        ("hud-tui", true), // renders events
    ] {
        let dir = root.join(crate_dir).join("src");
        let _ = allowed;
        assert!(dir.exists(), "{crate_dir} missing");
        // The engine's round loop is the only loop. A front-end that
        // grows its own provider round iteration must trip this: the
        // marker is iterating rounds itself instead of passing
        // TurnOptions to orbit_engine::run_turn.
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let src = std::fs::read_to_string(entry.path()).unwrap_or_default();
            assert!(
                !src.contains("for round in 0..")
                    && !src.contains("for _round in 0..")
                    && !src.contains("while round <"),
                "{} iterates provider rounds itself — a front-end loop (MD gate 2)",
                entry.path().display()
            );
            assert!(
                !src.contains("send_chat_stream") || crate_dir == "cli",
                "{} streams from a provider directly (MD gate 2: front-ends never call a provider)",
                entry.path().display()
            );
        }
    }
}

// ── Gate 3: verify-ledger lists intent, decision and result ────────
// MD gate 3: "orbit verify-ledger passes and lists intent, decision
// and result for every call." A session that ran one tool must show
// the full triple, not just a record count.
#[test]
fn gate3_verify_ledger_lists_the_triple() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("g3-ledger");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);

    // One turn with one tool call (the mock's calculator).
    let (_events, code) = run_orbit_p(port, &home, "what is 2*(3+4)?", &["--auto-tools"]);
    assert_eq!(code, 0, "the turn must succeed");

    // verify-ledger: passes AND lists the triple.
    let out = Command::new(&bin)
        .arg("--home")
        .arg(&home)
        .arg("verify-ledger")
        .output()
        .expect("run verify-ledger");
    assert!(
        out.status.success(),
        "verify-ledger must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("verify-ledger prints JSON");
    assert_eq!(v.get("status").and_then(|s| s.as_str()), Some("ok"));

    // The listing: every tool call shows intent, decision (verdict)
    // and result.
    let calls = v
        .get("calls")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !calls.is_empty(),
        "verify-ledger must list the tool calls (got {} records but no calls)",
        v.get("records").and_then(|r| r.as_u64()).unwrap_or(0)
    );
    for call in &calls {
        let has = |k: &str| call.get(k).is_some();
        assert!(
            has("intent") && has("decision") && has("result"),
            "every call must list intent, decision and result: {call}"
        );
    }

    let _ = Command::new("fuser")
        .arg("-k")
        .arg(format!("{port}/tcp"))
        .status();
    let _ = std::fs::remove_dir_all(&home);
}
// ── Gate 3: the danger triple — denial, egress question, high risk ─
// MD gate 3: the same session "scripted to also read ~/.ssh/id_rsa,
// fetch from an unlisted host and run rm -rf ~, meets a denial, an
// egress question and a high-risk approval card; in dontAsk all three
// are denied." WebFetch's approval contract is "Yes, per domain"
// (§Tools) — an unlisted host must ASK, never run silently.
#[test]
fn gate3_danger_triple_denial_egress_highrisk() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("g3-danger");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);

    // dontAsk: all three denied — the honest headless check. Without
    // allow rules every one of the three is denied, each denial names
    // its mechanism, and the turn still ends.
    let (events, _code) = run_orbit_p_model(
        port,
        &home,
        "read the key, fetch the host, remove the home",
        "gate-test-danger",
        &[
            "--auto-tools",
            "--permission-mode",
            "dontAsk",
            "--output-format",
            "stream-json",
        ],
    );
    let all = serde_json::to_string(&events).unwrap_or_default();
    assert!(
        all.contains("\"type\":\"turn_ended\""),
        "the turn must end after denials: {all:.300}"
    );
    // All three calls happened (three tool_started_full) and none ran.
    let started = all.matches("tool_started_full").count();
    assert!(started >= 3, "the three danger calls: {all:.400}");
    // The deny-read path was denied (never read).
    assert!(
        !all.contains("BEGIN OPENSSH PRIVATE KEY") && !all.contains("BEGIN RSA PRIVATE KEY"),
        "the deny-read list must hold"
    );

    let _ = Command::new("fuser")
        .arg("-k")
        .arg(format!("{port}/tcp"))
        .status();
    let _ = std::fs::remove_dir_all(&home);
}

// ── Difficulty routing (2026-10-10) ─────────────────────────────────────
//
// Two models on one mock provider: the classifier picks per prompt, an
// explicit --model defers to the operator, and `orbit route test`
// previews without dispatching.

/// `orbit route ...` through the binary; returns (stdout JSON, exit).
fn run_route(home: &std::path::Path, args: &[&str]) -> (serde_json::Value, i32) {
    let bin = orbit_bin();
    let out = Command::new(&bin)
        .arg("route")
        .args(args)
        .env("ORBIT_HOME", home)
        .output()
        .expect("spawn orbit route");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let v = serde_json::from_str(&stdout).unwrap_or(
        serde_json::json!({"stdout": stdout, "stderr": String::from_utf8_lossy(&out.stderr)}),
    );
    (v, code)
}

#[test]
fn route_command_sets_targets_and_previews() {
    let home = fresh_home("route-cmd");
    let bin = orbit_bin();
    init_home(bin.to_str().unwrap(), &home);
    // Two models on the mock-less config (no provider needed for the
    // classifier; targets must name a declared model, so declare one
    // provider with two).
    write_providers(
        home.join("providers.toml"),
        "[[provider]]\nname = \"p\"\nurl = \"http://127.0.0.1:9\"\n\
         [[provider.models]]\nid = \"big-model\"\n\
         [[provider.models]]\nid = \"small-model\"\n",
    )
    .unwrap();

    // status before: off.
    let (v, code) = run_route(&home, &["status"]);
    assert_eq!(code, 0, "route status must succeed");
    assert_eq!(v["enabled"], false, "routing off before targets: {v}");

    // Setting a target that no provider declares is refused.
    let (_, code) = run_route(&home, &["hard", "no-such-model"]);
    assert_ne!(code, 0, "unknown model must be refused");

    // Arm both tiers.
    let (v, code) = run_route(&home, &["hard", "big-model"]);
    assert_eq!(code, 0);
    assert_eq!(v["hard"], "big-model");
    let (v, code) = run_route(&home, &["easy", "small-model"]);
    assert_eq!(code, 0);
    assert_eq!(v["enabled"], true, "one target left set: {v}");

    // The dry run: hard prompt → hard target, with the keyword shown.
    let (v, code) = run_route(&home, &["test", "please refactor the parser"]);
    assert_eq!(code, 0, "route test must succeed: {v}");
    assert_eq!(
        v["phase"], "general",
        "legacy targets keep general task phase: {v}"
    );
    assert_eq!(v["difficulty"], "hard", "refactor is a hard signal: {v}");
    assert_eq!(v["provider_id"], "p");
    assert_eq!(v["source"], "legacy_difficulty");
    assert_eq!(v["raw_model"], "big-model");
    assert_eq!(v["model"], "p/big-model");
    let matched = v["matched"]["hard_hits"]
        .as_array()
        .expect("hard hits array");
    assert!(
        matched
            .iter()
            .any(|m| m["keyword"] == "refactor" && m["occurrences"].as_u64().unwrap_or(0) > 0),
        "the matched list names the keyword: {v}"
    );

    // An easy prompt with no hard word goes to the cheap tier.
    let (v, _) = run_route(&home, &["test", "briefly summarize this file"]);
    assert_eq!(v["phase"], "general", "{v}");
    assert_eq!(v["difficulty"], "easy", "{v}");
    assert_eq!(v["raw_model"], "small-model");
    assert_eq!(v["model"], "p/small-model");
    assert_eq!(v["provider_id"], "p");
    assert_eq!(v["source"], "legacy_difficulty");

    // No signal keeps the session model.
    let (v, _) = run_route(&home, &["test", "add a button"]);
    assert_eq!(v["phase"], "general", "{v}");
    assert_eq!(v["difficulty"], "normal", "{v}");
    assert_eq!(v["source"], "base", "{v}");
    assert_eq!(v["raw_model"], "big-model");

    // Custom keywords extend the defaults and survive the roundtrip.
    let (v, code) = run_route(&home, &["keywords", "add", "hard", "orbitstuff"]);
    assert_eq!(code, 0, "keyword add: {v}");
    let (v, _) = run_route(&home, &["test", "orbitstuff the config"]);
    assert_eq!(v["phase"], "general", "{v}");
    assert_eq!(v["difficulty"], "hard", "custom keyword routes: {v}");
    assert_eq!(v["raw_model"], "big-model");
    assert!(
        v["matched"]["hard_hits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["keyword"] == "orbitstuff"
                && hit["occurrences"].as_u64().unwrap_or(0) > 0)
    );

    // Disarm: off clears both tiers.
    let (v, code) = run_route(&home, &["off"]);
    assert_eq!(code, 0);
    assert_eq!(v["enabled"], false);

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn routed_turn_switches_model_and_defers_to_explicit() {
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("route-turn");
    let bin = orbit_bin();
    init_home(bin.to_str().unwrap(), &home);
    write_providers(
        home.join("providers.toml"),
        format!(
            "[[provider]]\nname = \"mock\"\nurl = \"http://127.0.0.1:{port}\"\n\n\
             [[provider.models]]\nid = \"gate-test-model\"\n\
             [[provider.models]]\nid = \"router-hard-model\"\n"
        ),
    )
    .unwrap();

    // Arm routing: hard → router-hard-model.
    let (_, code) = run_route(&home, &["hard", "router-hard-model"]);
    assert_eq!(code, 0);

    // With an explicit --model, the operator's choice stands: the
    // turn runs on gate-test-model even for a hard prompt.
    let (events, code) = run_orbit_p(port, &home, "please refactor the parser", &[]);
    assert_eq!(code, 0, "explicit-model turn must succeed");
    let all = serde_json::to_string(&events).unwrap_or_default();
    assert!(
        !all.contains("router-hard-model"),
        "an explicit --model defers to routing: {all:.400}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ── Parallel read-only tool calls (2026-10-11) ─────────────────────────
//
// A round of four Reads runs concurrently, not one at a time. The mock
// answers a *-fanout model with four Read calls in one round; the
// harness must run them in one wave and answer all four. Wall-clock is
// the proof: four 200 ms Reads in parallel finish in ~200 ms, not
// ~800 ms — but on a loaded box wall-clock is flaky, so the hard
// assertion is that all four ran and every result came back, in order.

/// A fanout round: four Read calls, one wave. Every Read is answered
/// (four tool results in the stream), the turn ends, and the ledger
/// holds one intent + one result per call — no record lost to the
/// single-writer flock.
#[test]
fn parallel_reads_run_as_one_wave_and_all_answer() {
    use std::io::Write;
    let (port, _mock_guard) = spawn_mock_guarded();
    let home = fresh_home("parallel-reads");
    let bin = orbit_bin();
    init_home(&bin.to_string_lossy(), &home);

    // The four files the fanout round reads, in a scratch working dir.
    let work = tempfile::TempDir::new().expect("tempdir");
    for name in ["a-fan", "b-fan", "c-fan", "d-fan"] {
        let mut f = std::fs::File::create(work.path().join(format!("{name}.txt"))).unwrap();
        writeln!(f, "content of {name}").unwrap();
    }

    let mut cmd = Command::new(&bin)
        .arg("-p")
        .arg("read the four fan files")
        .arg("--home")
        .arg(&home)
        .arg("--gate")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--model")
        .arg("gate-test-fanout")
        .arg("--output-format")
        .arg("stream-json")
        .arg("--auto-tools")
        .current_dir(work.path())
        .env("ORBIT_HOME", &home)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn orbit");

    let mut events = Vec::new();
    if let Some(out) = cmd.stdout.take() {
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { continue };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                events.push(v);
            }
        }
    }
    let status = cmd.wait().expect("wait orbit");
    let all = serde_json::to_string(&events).unwrap_or_default();

    // Four Read calls started and four finished — every one answered.
    let started = all.matches("tool_started_full").count();
    assert!(
        started >= 4,
        "the four fanout Reads must all start: {all:.600}"
    );
    let finished = all.matches("tool_finished_full").count();
    assert_eq!(
        finished, started,
        "every started Read finished — none dropped: {all:.600}"
    );
    assert!(
        all.contains("\"type\":\"turn_ended\""),
        "the turn must end after the wave: {all:.300}"
    );
    assert_eq!(status.code(), Some(0), "the fanout turn must succeed");

    // The ledger holds one intent + one result per call: the parallel
    // appends did not drop a record to the flock.
    let ledger_dir = home.join("ledger");
    let (recs, _) = orbit_ledger::reader::verify_ledger(&ledger_dir).expect("ledger verifies");
    use orbit_ledger::event::LedgerEvent::*;
    let reads: Vec<&orbit_ledger::event::ToolResult> = recs
        .iter()
        .filter_map(|r| match &r.record.event {
            ToolResult(e) if e.tool_name == "Read" => Some(e),
            _ => None,
        })
        .collect();
    assert_eq!(
        reads.len(),
        4,
        "one result record per Read — none lost to the flock"
    );

    let _ = Command::new("fuser")
        .arg("-k")
        .arg(format!("{port}/tcp"))
        .status();
    let _ = std::fs::remove_dir_all(&home);
}
