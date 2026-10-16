#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const TEST_COMMAND: &str = "python3 test_once.py";

fn private_directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn write_private(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    provider: Child,
}

impl Fixture {
    fn new(exit_code: i32) -> Self {
        let root = std::env::temp_dir().join(format!("orbit-attestation-{}", ulid::Ulid::new()));
        private_directory(&root);
        let home = root.join("home");
        let workspace = root.join("workspace");
        let provider_dir = root.join("provider");
        for path in [&home, &workspace, &provider_dir] {
            private_directory(path);
        }
        write_private(
            &workspace.join("test_once.py"),
            format!(
                "from pathlib import Path\nwith Path('effects').open('a') as marker:\n    marker.write('executed\\n')\nprint('fixture completed')\nraise SystemExit({exit_code})\n"
            ),
        );
        write_private(
            &provider_dir.join("mode.json"),
            json!({
                "tool": "Bash",
                "arguments": {"command": TEST_COMMAND, "timeout": 5},
                "reply": "The tests pass."
            })
            .to_string(),
        );
        let provider = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/p35_provider.py"
            ))
            .arg(&provider_dir)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(provider_dir.join("stderr")).unwrap())
            .spawn()
            .unwrap();
        let mut fixture = Self {
            root,
            home,
            workspace,
            provider,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let gate = loop {
            if let Some(gate) = fs::read(provider_dir.join("ready.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|ready| ready["gate"].as_str().map(str::to_owned))
            {
                break gate;
            }
            assert!(fixture.provider.try_wait().unwrap().is_none());
            assert!(
                Instant::now() < deadline,
                "owned provider readiness timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            url::Url::parse(&gate).unwrap().host_str(),
            Some("127.0.0.1")
        );
        let output = fixture.run(&["setup", "--no-provider", "--json"]);
        assert_success(&output);
        write_private(
            &fixture.home.join("providers.toml"),
            format!(
                "[[provider]]\nname='fixture'\nurl={gate:?}\n[[provider.models]]\nid='attestation'\n[roles]\nmain='fixture/attestation'\n"
            ),
        );
        fixture
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let stdout_path = self.root.join("command.stdout");
        let stderr_path = self.root.join("command.stderr");
        let mut child = Command::new(env!("CARGO_BIN_EXE_orbit"))
            .env_clear()
            .env("HOME", &self.home)
            .env("ORBIT_HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.root.join("xdg-config"))
            .env("XDG_CACHE_HOME", self.root.join("xdg-cache"))
            .env("XDG_DATA_HOME", self.root.join("xdg-data"))
            .env("CODEX_HOME", self.root.join("codex"))
            .env("CLAUDE_CONFIG_DIR", self.root.join("claude"))
            .env("HERMES_HOME", self.root.join("hermes"))
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .current_dir(&self.workspace)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout_path).unwrap())
            .stderr(fs::File::create(&stderr_path).unwrap())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "headless fixture timed out: {}",
                    fs::read_to_string(&stderr_path).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: fs::read(stdout_path).unwrap(),
            stderr: fs::read(stderr_path).unwrap(),
        }
    }

    fn headless(&self) -> Output {
        self.headless_scoped("Bash(python3 test_once.py)", "json")
    }

    fn headless_scoped(&self, scope: &str, format: &str) -> Output {
        self.run(&[
            "-p",
            "Run the provided fixture command once and report its recorded result.",
            "--bare",
            "--allowedTools",
            scope,
            "--output-format",
            format,
            "--max-turns",
            "3",
        ])
    }

    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("provider/calls.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.provider.kill();
        let _ = self.provider.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {}; stdout: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn one_effect_headless_pass_uses_recorded_result_without_a_second_execution() {
    let fixture = Fixture::new(0);
    let output = fixture.headless();
    assert_success(&output);
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    let calls = fixture.calls();
    assert_eq!(calls.len(), 2, "one tool request and one final reply");
    let messages = calls[1]["messages"].as_array().unwrap();
    let results: Vec<_> = messages
        .iter()
        .filter(|message| message["role"] == "tool")
        .collect();
    assert_eq!(
        results.len(),
        1,
        "the original tool result must be captured"
    );
    assert_eq!(results[0]["tool_call_id"], "fixture-call");
    let result: Value = serde_json::from_str(results[0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(result["ok"], true, "the permitted original command ran");
    assert_eq!(result["exit_code"], 0);
    assert_eq!(
        fs::read_to_string(fixture.workspace.join("effects")).unwrap(),
        "executed\n",
        "reporting the captured pass must not execute the shell command a second time"
    );
    assert_eq!(summary["rta"]["attested"], true);
    assert_eq!(summary["rta"]["command"], TEST_COMMAND);
    assert_eq!(summary["rta"]["evidence"], "recorded_tool_result");
    assert_eq!(summary["rta"]["recorded_exit_code"], 0);
    assert!(
        summary["rta"].get("at").is_none(),
        "no new execution timestamp"
    );
}

#[test]
fn failed_original_command_stays_unverified_and_executes_once() {
    let fixture = Fixture::new(7);
    let output = fixture.headless();
    assert_success(&output);
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fixture.calls().len(), 2);
    assert_eq!(
        fs::read_to_string(fixture.workspace.join("effects")).unwrap(),
        "executed\n"
    );
    assert_eq!(summary["rta"]["attested"], false);
    assert_eq!(summary["rta"]["command"], TEST_COMMAND);
    assert_eq!(summary["rta"]["recorded_exit_code"], 7);
    assert!(summary["rta"].get("at").is_none());
}

#[test]
fn denied_original_command_never_executes_even_when_provider_claims_pass() {
    let fixture = Fixture::new(0);
    let output = fixture.headless_scoped("Read", "json");
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fixture.calls().len(), 2);
    assert!(!fixture.workspace.join("effects").exists());
    assert_eq!(summary["rta"]["attested"], false);
    assert_eq!(summary["rta"]["recorded_exit_code"], -1);
}

#[test]
fn command_shaped_read_cannot_supply_a_bash_attestation() {
    let fixture = Fixture::new(0);
    write_private(
        &fixture.root.join("provider/mode.json"),
        json!({
            "tool": "Read",
            "arguments": {"command": TEST_COMMAND, "file_path": "test_once.py"},
            "reply": "The tests pass."
        })
        .to_string(),
    );
    let output = fixture.headless_scoped("Read", "json");
    assert_success(&output);
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fixture.calls().len(), 2);
    assert!(!fixture.workspace.join("effects").exists());
    assert!(summary["rta"].is_null());
}

#[test]
fn streaming_verdict_describes_captured_completion_without_retesting() {
    let fixture = Fixture::new(0);
    let output = fixture.headless_scoped("Bash(python3 test_once.py)", "stream-json");
    assert_success(&output);
    assert_eq!(fixture.calls().len(), 2);
    assert_eq!(
        fs::read_to_string(fixture.workspace.join("effects")).unwrap(),
        "executed\n"
    );
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events
            .iter()
            .any(|event| event["text"]
                == "rta: recorded Bash command exited 0 (captured tool result)")
    );
}

#[test]
fn denied_stream_verdict_does_not_invent_an_execution_or_exit_status() {
    let fixture = Fixture::new(0);
    let output = fixture.headless_scoped("Read", "stream-json");
    assert_eq!(output.status.code(), Some(2));
    assert!(!fixture.workspace.join("effects").exists());
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let status = events
        .iter()
        .filter_map(|event| event["text"].as_str())
        .find(|text| text.starts_with("rta: "))
        .expect("an unverified evidence status");
    assert!(status.contains("has no unique completed Bash result"));
    assert!(!status.contains("exited -1"));
}
