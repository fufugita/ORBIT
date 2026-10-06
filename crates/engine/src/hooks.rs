//! Hooks (roadmap phase 5, §Extensibility) — v1 events.
//!
//! A hook gets JSON on stdin. Exit code 2 blocks the action and feeds
//! stderr to the model; JSON on stdout can allow, deny, ask or rewrite
//! the tool input. Default timeout 60 s. Deny and ask rules still
//! apply when a hook says allow. Project hooks run only in trusted
//! folders.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The v1 hook events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    PostToolUseFailure,
    Stop,
    SubagentStart,
    SubagentStop,
    PreCompact,
    PostCompact,
    Notification,
    SessionEnd,
}

impl HookEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookEvent::SessionStart => "SessionStart",
            HookEvent::UserPromptSubmit => "UserPromptSubmit",
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PermissionRequest => "PermissionRequest",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::PostToolUseFailure => "PostToolUseFailure",
            HookEvent::Stop => "Stop",
            HookEvent::SubagentStart => "SubagentStart",
            HookEvent::SubagentStop => "SubagentStop",
            HookEvent::PreCompact => "PreCompact",
            HookEvent::PostCompact => "PostCompact",
            HookEvent::Notification => "Notification",
            HookEvent::SessionEnd => "SessionEnd",
        }
    }
}

/// One configured hook: the event it listens to + the command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub event: String,
    pub command: String,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// A hook's decision output.
#[derive(Debug, Clone, Default)]
pub struct HookOutcome {
    /// Exit code (2 = block).
    pub exit_code: i32,
    /// stderr fed to the model when blocked.
    pub stderr: String,
    /// Parsed stdout decision, when the hook spoke JSON.
    pub decision: Option<HookDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HookDecision {
    Allow,
    Deny {
        reason: String,
    },
    Ask {
        reason: String,
    },
    /// Rewrite the tool input before execution.
    Rewrite {
        input: serde_json::Value,
    },
}

/// The loaded hooks for a session (user scope + trusted project scope).
#[derive(Debug, Clone, Default)]
pub struct Hooks {
    pub hooks: Vec<HookConfig>,
    /// Project hooks loaded only when the folder is trusted.
    pub project_trusted: bool,
}

/// Is the current folder trusted for project-scope hooks? (E9: the
/// engine fires lifecycle hooks itself now, so the trust check lives
/// with the loader.) Same FolderTrust scheme the CLI uses.
pub fn project_trusted(home: &Path) -> bool {
    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };
    orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(&cwd)
}

impl Hooks {
    /// Load hooks from the settings scopes.
    pub fn load(home: &Path, project_trusted: bool) -> Self {
        let mut hooks = Vec::new();
        // User scope: $ORBIT_HOME/settings.toml [[hooks]] entries.
        if let Ok(text) = std::fs::read_to_string(home.join("settings.toml")) {
            hooks.extend(parse_hooks_toml(&text));
        }
        // Project scope (trusted only).
        if project_trusted {
            if let Ok(text) = std::fs::read_to_string(".orbit/settings.toml") {
                hooks.extend(parse_hooks_toml(&text));
            }
        }
        Hooks {
            hooks,
            project_trusted,
        }
    }

    fn matching(&self, event: HookEvent) -> Vec<&HookConfig> {
        self.hooks
            .iter()
            .filter(|h| h.event == event.as_str())
            .collect()
    }

    /// Fire every hook for an event. Returns outcomes in order; an
    /// empty vec when no hook matches. Blocking semantics are applied
    /// by the caller (the first block wins).
    pub fn fire(&self, event: HookEvent, payload: &serde_json::Value) -> Vec<HookOutcome> {
        self.matching(event)
            .iter()
            .map(|h| {
                // The payload carries the event name (E9): a hook
                // listening to several events can tell them apart.
                let mut body = payload.as_object().cloned().unwrap_or_default();
                body.insert("hook_event_name".into(), serde_json::json!(event.as_str()));
                run_hook(h, &serde_json::Value::Object(body))
            })
            .collect()
    }
}

/// Run one hook: JSON on stdin, exit code + stdout JSON decide.
fn run_hook(cfg: &HookConfig, payload: &serde_json::Value) -> HookOutcome {
    let timeout = Duration::from_secs(cfg.timeout_secs.unwrap_or(60));
    use std::process::{Command, Stdio};
    let mut child = match Command::new("bash")
        .arg("-c")
        .arg(&cfg.command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return HookOutcome {
                exit_code: -1,
                stderr: format!("hook spawn failed: {e}"),
                decision: None,
            }
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(payload.to_string().as_bytes());
    }
    // Wait with timeout (poll try_wait).
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break None,
        }
    };
    let output = child.wait_with_output().ok();
    let code = match status {
        Some(s) => s.code().unwrap_or(-1),
        None => -2, // timeout
    };
    let stdout = output
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let stderr = output
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
        .unwrap_or_default();
    let decision = serde_json::from_str::<HookDecision>(stdout.trim()).ok();
    HookOutcome {
        exit_code: code,
        stderr,
        decision,
    }
}

/// Parse `[[hooks]]` entries from the settings TOML subset: lines
/// event = "..." / command = "..." inside hooks tables.
fn parse_hooks_toml(text: &str) -> Vec<HookConfig> {
    let mut out = Vec::new();
    let mut current: Option<HookConfig> = None;
    let mut in_hooks = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[hooks]]" {
            if let Some(c) = current.take() {
                out.push(c);
            }
            in_hooks = true;
            current = Some(HookConfig {
                event: String::new(),
                command: String::new(),
                timeout_secs: None,
            });
            continue;
        }
        if line.starts_with('[') {
            // leaving the hooks table
            if let Some(c) = current.take() {
                if in_hooks && !c.event.is_empty() && !c.command.is_empty() {
                    out.push(c);
                }
            }
            in_hooks = false;
            continue;
        }
        if !in_hooks {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim();
            let value = line[eq + 1..].trim().trim_matches('"');
            if let Some(c) = current.as_mut() {
                match key {
                    "event" => c.event = value.to_string(),
                    "command" => c.command = value.to_string(),
                    "timeout_secs" => c.timeout_secs = value.parse().ok(),
                    _ => {}
                }
            }
        }
    }
    if let Some(c) = current.take() {
        if !c.event.is_empty() && !c.command.is_empty() {
            out.push(c);
        }
    }
    out
}

/// Convenience: did any hook block (exit 2 or a Deny decision)?
pub fn blocked(outcomes: &[HookOutcome]) -> Option<String> {
    for o in outcomes {
        if o.exit_code == 2 {
            return Some(if o.stderr.is_empty() {
                "blocked by hook".into()
            } else {
                o.stderr.clone()
            });
        }
        if let Some(HookDecision::Deny { reason }) = &o.decision {
            return Some(reason.clone());
        }
    }
    None
}

/// Test helper: a hooks dir path builder.
#[allow(dead_code)]
fn test_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("orbit-hooks-{name}-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hooks_from_settings() {
        let text = r#"
# settings
[[hooks]]
event = "PreToolUse"
command = "check.sh"

[[hooks]]
event = "Stop"
command = "notify.sh"
timeout_secs = 5
"#;
        let hooks = parse_hooks_toml(text);
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0].event, "PreToolUse");
        assert_eq!(hooks[1].timeout_secs, Some(5));
    }

    #[test]
    fn exit_two_blocks() {
        let outcomes = vec![HookOutcome {
            exit_code: 2,
            stderr: "no push".into(),
            decision: None,
        }];
        assert_eq!(blocked(&outcomes), Some("no push".into()));
        let ok = vec![HookOutcome {
            exit_code: 0,
            stderr: String::new(),
            decision: None,
        }];
        assert_eq!(blocked(&ok), None);
    }

    #[test]
    fn a_blocking_hook_stops_git_push() {
        // End-to-end: a PreToolUse hook that exits 2 on git push.
        let hooks = Hooks {
            hooks: vec![HookConfig {
                event: "PreToolUse".into(),
                command: r#"if echo "$HOOK_STDIN" | grep -q "git push"; then echo "no force pushes" >&2; exit 2; fi"#.into(),
                timeout_secs: Some(10),
            }],
            project_trusted: true,
        };
        // NOTE: the hook reads JSON on STDIN, not env; the shell here
        // greps the payload passed via stdin. Fire it for real:
        let outcomes = hooks.fire(
            HookEvent::PreToolUse,
            &serde_json::json!({"tool": "Bash", "command": "git push --force origin main"}),
        );
        // The run_hook pipes the payload to stdin; the demo command
        // greps $HOOK_STDIN which is empty — use a stdin-grepping cmd:
        let _ = outcomes;
        let hooks = Hooks {
            hooks: vec![HookConfig {
                event: "PreToolUse".into(),
                command: "grep -q 'git push' && { echo 'no force pushes' >&2; exit 2; } || true"
                    .into(),
                timeout_secs: Some(10),
            }],
            project_trusted: true,
        };
        let outcomes = hooks.fire(
            HookEvent::PreToolUse,
            &serde_json::json!({"tool": "Bash", "command": "git push --force origin main"}),
        );
        assert_eq!(
            blocked(&outcomes),
            Some("no force pushes\n".into()),
            "the hook must block git push"
        );
    }
}
