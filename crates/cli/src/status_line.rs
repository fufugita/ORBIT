//! A custom status line: the operator's own command decides what the
//! terminal chat's bottom bar says beside the activity.
//!
//! `status_line = "<command>"` at the top of `settings.toml` (or of the file
//! named with `--settings`). With the Claude Code switch on, the
//! `statusLine` command of `~/.claude/settings.json` is used when ORBIT's
//! own setting is absent, so an existing script keeps working. An explicit
//! empty native setting disables that fallback; removing it restores inheritance.
//!
//! The command gets one JSON object on standard input and the first line it
//! prints is shown. It runs after each command the session handles, off the
//! worker's thread, and is stopped after [`TIMEOUT`]. Colour escapes are
//! removed: the bar draws plain text in its own palette. A command that
//! fails or prints nothing clears the line.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

/// How long the command may take.
pub const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CHARS: usize = 200;

/// A top-level `key = "value"` of a settings file. The file is read as the
/// TOML it is, so a quoted value, an escape or a trailing comment mean what
/// they mean everywhere else; one that does not parse has no setting.
fn top_level(text: &str, key: &str) -> Option<String> {
    toml::from_str::<toml::Table>(text)
        .ok()?
        .get(key)?
        .as_str()
        .map(str::trim)
        .map(str::to_owned)
}

/// Claude Code's `statusLine: {"type": "command", "command": "…"}`.
fn claude_command(text: &str) -> Option<String> {
    let root: serde_json::Value = serde_json::from_str(text).ok()?;
    let line = root.get("statusLine")?;
    if line.get("type").and_then(serde_json::Value::as_str) != Some("command") {
        return None;
    }
    line.get("command")?
        .as_str()
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .map(str::to_owned)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    SettingsFlag,
    OrbitHome,
    ClaudeCompatibility,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::SettingsFlag => "--settings",
            Self::OrbitHome => "ORBIT home settings.toml",
            Self::ClaudeCompatibility => "Claude compatibility settings",
        }
    }
}

/// Effective configuration before bare-mode suppression. Empty means disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    pub command: String,
    pub source: Source,
}

fn from_sources(
    flag: Option<String>,
    native: Option<String>,
    compatibility: Option<String>,
) -> Option<Configuration> {
    [
        (flag, Source::SettingsFlag),
        (native, Source::OrbitHome),
        (compatibility, Source::ClaudeCompatibility),
    ]
    .into_iter()
    .find_map(|(command, source)| command.map(|command| Configuration { command, source }))
}

/// Inspect configuration without executing a command, including in bare mode.
pub fn configured(home: &Path) -> Option<Configuration> {
    let flag = orbit_tools::executor::extra_settings_file();
    let read = |path: &Path| {
        std::fs::metadata(path)
            .ok()
            .filter(|meta| meta.is_file() && meta.len() <= 256 * 1024)
            .and_then(|_| std::fs::read_to_string(path).ok())
    };
    let flag_command = flag.as_ref().and_then(|file| {
        let text = read(file)?;
        if orbit_tools::executor::is_json(file) {
            claude_command(&text)
        } else {
            top_level(&text, "status_line")
        }
    });
    let native_command =
        read(&home.join("settings.toml")).and_then(|text| top_level(&text, "status_line"));
    let compatibility_command = if orbit_engine::hooks::claude_compat(home) {
        orbit_engine::hooks::claude_config_dir()
            .and_then(|dir| read(&dir.join("settings.json")))
            .and_then(|text| claude_command(&text))
    } else {
        None
    };
    from_sources(flag_command, native_command, compatibility_command)
}

/// The command to run now. Bare mode and an explicit off setting run nothing.
pub fn command(home: &Path) -> Option<String> {
    if crate::tools::bare_mode() {
        return None;
    }
    configured(home)
        .map(|configuration| configuration.command)
        .filter(|command| !command.is_empty())
}

/// What the session looks like to the command.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub session_id: String,
    pub model: String,
    pub provider: String,
    pub permission_mode: String,
    pub current_dir: String,
    pub project_dir: String,
    pub turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// The session's known priced subtotal, in micro-dollars.
    pub cost_microdollars: u64,
}

impl Snapshot {
    /// The JSON the command reads: Claude Code's field names where the two
    /// overlap, so its scripts work unchanged.
    pub fn payload(&self) -> serde_json::Value {
        serde_json::json!({
            "hook_event_name": "Status",
            "session_id": self.session_id,
            "cwd": self.current_dir,
            "model": {
                "id": self.model,
                "display_name": self.model,
                "provider": self.provider,
            },
            "workspace": {
                "current_dir": self.current_dir,
                "project_dir": self.project_dir,
            },
            "version": env!("CARGO_PKG_VERSION"),
            "permission_mode": self.permission_mode,
            "cost": { "total_cost_usd": self.cost_microdollars as f64 / 1_000_000.0 },
            "turns": self.turns,
            "tokens": { "input": self.input_tokens, "output": self.output_tokens },
        })
    }
}

/// Plain text for the bar: the first line, without escape sequences or
/// control characters, bounded.
pub fn clean(output: &str) -> String {
    let line = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI: ESC [ … final byte; OSC: ESC ] … BEL or ESC \.
            match chars.next() {
                Some('[') => {
                    for d in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(d) = chars.next() {
                        if d == '\u{7}' {
                            break;
                        }
                        if d == '\u{1b}' {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out.trim().chars().take(MAX_CHARS).collect()
}

/// Run the command once and return what it wants shown. Empty when it
/// failed, timed out or printed nothing.
pub fn run(command: &str, snapshot: &Snapshot) -> String {
    if command.trim().is_empty() || crate::tools::bare_mode() {
        return String::new();
    }
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let Ok(mut child) = Command::new("bash")
        .arg("-c")
        .arg(command)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return String::new();
    };
    if let Some(mut stdin) = child.stdin.take() {
        let body = snapshot.payload().to_string();
        std::thread::spawn(move || {
            let _ = stdin.write_all(body.as_bytes());
        });
    }
    let stdout = child.stdout.take();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut kept = Vec::new();
        if let Some(stdout) = stdout {
            let _ = stdout.take(16 * 1024).read_to_end(&mut kept);
        }
        let _ = done.send(kept);
    });
    let deadline = std::time::Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                // The whole group: the shell and whatever it started.
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = child.kill();
                break None;
            }
        }
    };
    let _ = child.wait();
    if !status.is_some_and(|status| status.success()) {
        return String::new();
    }
    finished
        .recv_timeout(Duration::from_secs(1))
        .map(|bytes| clean(&String::from_utf8_lossy(&bytes)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_setting_is_a_top_level_key_and_claudes_is_a_command_object() {
        assert_eq!(
            top_level(
                "# mine\nstatus_line = \"~/bin/line.sh\"\n[permissions]\n",
                "status_line"
            ),
            Some("~/bin/line.sh".into())
        );
        assert_eq!(
            top_level("[x]\nstatus_line = \"late\"\n", "status_line"),
            None
        );
        assert_eq!(
            top_level("status_line = \"\"\n", "status_line"),
            Some(String::new())
        );
        assert_eq!(top_level("# status_line = \"off\"\n", "status_line"), None);
        // Real TOML: a trailing comment and an escaped quote mean what they say.
        assert_eq!(
            top_level("status_line = \"echo \\\"hi\\\"\" # mine\n", "status_line"),
            Some("echo \"hi\"".into())
        );
        assert_eq!(top_level("status_line = 3\n", "status_line"), None);
        assert_eq!(
            top_level("status_line = \"x\"\n[broken\n", "status_line"),
            None
        );
        assert_eq!(
            claude_command(
                r#"{"statusLine": {"type": "command", "command": " ~/.claude/line.sh "}}"#
            ),
            Some("~/.claude/line.sh".into())
        );
        assert_eq!(
            claude_command(r#"{"statusLine": {"type": "static", "command": "x"}}"#),
            None
        );
        assert_eq!(
            claude_command(r#"{"statusLine": {"type": "command"}}"#),
            None
        );
        assert_eq!(claude_command("{}"), None);
    }

    #[test]
    fn explicit_off_stops_compatibility_fallback_and_reset_restores_inheritance() {
        let compatibility = Some("compatibility-script".to_owned());
        let native_off = top_level("status_line = \"\"\n", "status_line");
        assert_eq!(
            from_sources(None, native_off, compatibility.clone()),
            Some(Configuration {
                command: String::new(),
                source: Source::OrbitHome
            })
        );
        assert_eq!(
            from_sources(None, None, compatibility.clone()),
            Some(Configuration {
                command: "compatibility-script".into(),
                source: Source::ClaudeCompatibility
            })
        );
        // An explicit --settings value keeps its normal higher priority.
        assert_eq!(
            from_sources(
                Some("flag-script".into()),
                Some(String::new()),
                compatibility
            ),
            Some(Configuration {
                command: "flag-script".into(),
                source: Source::SettingsFlag
            })
        );
        assert_eq!(run("", &Snapshot::default()), "");
    }

    #[test]
    fn output_is_one_plain_bounded_line() {
        assert_eq!(
            clean("\n  \u{1b}[1;32mmain\u{1b}[0m · 3 files\nsecond line\n"),
            "main · 3 files"
        );
        assert_eq!(
            clean("\u{1b}]8;;https://x.example\u{7}link\u{1b}]8;;\u{7} ok"),
            "link ok"
        );
        assert_eq!(clean("a\tb\u{0}c"), "abc");
        assert_eq!(clean(""), "");
        assert_eq!(clean(&"x".repeat(500)).chars().count(), MAX_CHARS);
    }

    #[test]
    fn the_command_reads_the_session_and_its_first_line_is_shown() {
        let snapshot = Snapshot {
            session_id: "s-1".into(),
            model: "big".into(),
            provider: "p".into(),
            permission_mode: "default".into(),
            current_dir: "/w/src".into(),
            project_dir: "/w".into(),
            turns: 4,
            input_tokens: 10,
            output_tokens: 20,
            cost_microdollars: 1_500_000,
        };
        let payload = snapshot.payload();
        assert_eq!(payload["model"]["display_name"], "big");
        assert_eq!(payload["workspace"]["project_dir"], "/w");
        assert_eq!(payload["cost"]["total_cost_usd"], 1.5);
        // No JSON tool is assumed on the machine: the script greps.
        let shown = run(
            r#"input=$(cat); echo "$input" | grep -q '"current_dir":"/w/src"' && printf '\033[36m%s\033[0m\n' "src · turn 4""#,
            &snapshot,
        );
        assert_eq!(shown, "src · turn 4");
        assert_eq!(
            run("echo nope; exit 3", &snapshot),
            "",
            "a failing command clears the line"
        );
        assert_eq!(run("true", &snapshot), "");
        let started = std::time::Instant::now();
        assert_eq!(run("sleep 30; echo late", &snapshot), "");
        assert!(started.elapsed() < TIMEOUT + Duration::from_secs(3));
    }
}
