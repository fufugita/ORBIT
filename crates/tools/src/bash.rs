//! Bash — runs a command in the persistent working directory.
//!
//! 2 min default / 10 min maximum timeout, then moved to the
//! background. Output over 30,000 characters spills to a file (the
//! model gets the path + a 2,000-character preview). Cancel kills the
//! process group. The read-only allowlist runs without asking in
//! default mode.

use crate::{finish, Tool, ToolContext, ToolResult};
use serde_json::json;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// Default timeout before a command moves to the background.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;
/// Hard maximum for a foreground command.
pub const MAX_TIMEOUT_SECS: u64 = 600;

/// Commands that never need approval in default mode (read-only).
pub const READONLY_ALLOWLIST: &[&str] = &[
    "ls",
    "cat",
    "head",
    "tail",
    "rg",
    "grep",
    "find",
    "git status",
    "git diff",
    "git log",
    "git show",
    "git branch",
    "pwd",
    "echo",
    "wc",
    "file",
    "stat",
    "which",
    "tree",
];

/// Is this command on the read-only allowlist? Prefix match on the
/// first word(s).
pub fn is_readonly_command(cmd: &str) -> bool {
    let trimmed = cmd.trim();
    // A redirection or pipe operator makes the command side-effectful
    // (echo x > f writes a file; cat f | sh executes) — it loses
    // read-only classification no matter what the first word is.
    if trimmed.contains('>') || trimmed.contains(">>") || trimmed.contains('|') {
        return false;
    }
    READONLY_ALLOWLIST
        .iter()
        .any(|a| trimmed == *a || trimmed.starts_with(&format!("{a} ")))
}

/// Does the command touch a deny-read path (S2)? The sandbox masks
/// deny paths when it can run, but that defense silently disappears
/// when bwrap cannot — the command's own path-like arguments are
/// checked here so the rule holds on every machine. Word-level and
/// conservative: a token that resolves (after ~ expansion) onto a
/// deny-read path denies the whole command.
pub fn command_touches_deny_read(cmd: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    for token in cmd.split_whitespace() {
        // Strip shell punctuation that hugs paths.
        let t =
            token.trim_matches(|c: char| c == '"' || c == '\'' || c == ',' || c == ';' || c == ':');
        if t.is_empty() {
            continue;
        }
        let expanded = if let Some(rest) = t.strip_prefix("~/") {
            format!("{home}/{rest}")
        } else if t == "~" {
            home.clone()
        } else {
            t.to_string()
        };
        let p = std::path::Path::new(&expanded);
        if crate::is_deny_read(p) {
            return true;
        }
    }
    false
}

/// High-risk command detection for the approval card's risk level
/// (roadmap: rm -rf, git push --force, curl | sh are high).
pub fn command_risk(cmd: &str) -> u8 {
    let c = cmd.trim();
    if c.contains("rm -rf")
        || c.contains("rm -fr")
        || c.contains("git push --force")
        || c.contains("git push -f")
        || c.contains("mkfs")
        || c.contains("dd if=")
        || c.contains("| sh")
        || c.contains("| bash")
        || c.contains("chmod 777")
        || c.contains("curl") && c.contains("|")
    {
        3 // high
    } else if c.contains("sudo")
        || c.contains("git push")
        || c.contains("kill")
        || c.contains("mv ")
        || c.contains("cp ")
        || c.contains("rm ")
    {
        2 // medium
    } else {
        1 // low
    }
}

/// Background command registry (session-scoped). A command that hits
/// its timeout keeps running; its output lands in a file Read can open.
static BACKGROUND: Mutex<Vec<BackgroundCommand>> = Mutex::new(Vec::new());

pub struct BackgroundCommand {
    pub id: String,
    pub command: String,
    pub output_path: PathBuf,
    /// The child's PID — its process group leader. TaskStop kills the
    /// whole group (negative PID), so shell children die with it.
    pub pid: i32,
    #[allow(dead_code)]
    started: std::time::Instant,
}

pub struct BashTool;

impl Tool for BashTool {
    fn name(&self) -> &'static str {
        "Bash"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "The command to run" },
                "timeout": { "type": "integer", "description": "Seconds before moving to background (default 120, max 600)" },
                "description": { "type": "string", "description": "What this command does (for the operator)" }
            },
            "required": ["command"]
        })
    }
    fn read_only(&self) -> bool {
        false // the permission layer checks is_readonly_command per call
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");
        // The rule pattern is the first word (Bash(git *) style).
        let first = cmd.split_whitespace().next().unwrap_or("");
        crate::PermissionKey {
            tool: "Bash".into(),
            pattern: first.to_string(),
        }
    }
    fn run(&self, input: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let Some(command) = input.get("command").and_then(|v| v.as_str()) else {
            return ToolResult::err("command is required");
        };
        let timeout = input
            .get("timeout")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
            .min(MAX_TIMEOUT_SECS);
        run_command(command, timeout, cx)
    }
}

/// Run a command, capturing combined output. On timeout the process
/// keeps running in the background and the result says so.
pub fn run_command(command: &str, timeout_secs: u64, cx: &ToolContext) -> ToolResult {
    use std::process::{Command, Stdio};

    // S2: the deny-read list holds for the shell too — checked on the
    // command's own arguments, before any sandbox consideration (the
    // sandbox mask is defense-in-depth, not the rule).
    if command_touches_deny_read(command) {
        return ToolResult::err(
            "denied: the command touches a deny-read path (credentials never reach a provider)",
        );
    }

    let output_path = cx
        .outputs_dir()
        .map(|d| d.join(format!("bash-{}.log", ulid::Ulid::new())))
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("orbit-bash-{}.log", ulid::Ulid::new()))
        });

    // The sandbox (review blocker 3, second half): when bubblewrap is
    // available the command runs confined — writes only in the
    // working dirs + session temp, no network. When it is not, the
    // result SAYS the command ran unsandboxed so the operator and the
    // permission layer can see it (the executor forces an ask).
    let sandbox = crate::sandbox::ShellSandbox::standard(&cx.working_dirs, &cx.session_id);
    let sandboxed = matches!(
        crate::sandbox::ShellSandbox::probe(),
        crate::sandbox::SandboxStatus::Confined
    );

    let mut child = if sandboxed {
        let mut cmd = sandbox.wrap(command, &cx.working_dir);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        // Own process group (same as the unsandboxed arm below): the
        // Esc interrupt and TaskStop kill the whole tree, never
        // ORBIT's own group.
        cmd.process_group(0);
        match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return ToolResult::err(&format!("cannot spawn sandboxed bash: {e}")),
        }
    } else {
        match Command::new("bash")
            .arg("-c")
            .arg(command)
            .current_dir(&cx.working_dir)
            // Safety (review blocker 3): a child never inherits ORBIT's
            // environment (provider keys included) — an explicit allowlist
            // only. Null stdin: a command that reads stdin cannot take the
            // TUI's keystrokes. Own process group: Esc/TaskStop can kill
            // the whole tree.
            .env_clear()
            .envs(env_allowlist())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return ToolResult::err(&format!("cannot spawn bash: {e}")),
        }
    };

    // Wait with a timeout, polling.
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child.stdout.take();
                let stderr = child.stderr.take();
                let (out, err) = read_pipes(stdout, stderr);
                let combined = format!("{out}{err}");
                let _ = std::fs::write(&output_path, &combined);
                let scanned = crate::scan::scan_result(&combined);
                let text = if scanned.redactions.is_empty() {
                    combined
                } else {
                    scanned.text
                };
                let mut payload = json!({
                    "ok": status.success(),
                    "exit_code": status.code().unwrap_or(-1),
                    "output": text,
                    "sandboxed": sandboxed,
                });
                if !scanned.redactions.is_empty() {
                    payload["redacted"] = json!(scanned.redactions);
                }
                let mut r = ToolResult {
                    payload: payload.to_string(),
                    is_error: !status.success(),
                    spilled_to: None,
                };
                r = finish(r, cx, &format!("bash-{}", ulid::Ulid::new()));
                return r;
            }
            Ok(None) => {
                // Esc (MD §The agent loop): the turn was cancelled —
                // kill the whole process group and report the call as
                // cancelled, keeping the transcript valid for the next
                // turn.
                if crate::interrupt::is_cancelled() && !crate::interrupt::kill_fired() {
                    crate::interrupt::set_kill_fired();
                    // Esc (MD §The agent loop): kill the tool's whole
                    // process tree. TERM to the group first (graceful),
                    // then KILL: the sandbox re-execs bwrap in a new
                    // session (so the payload sits in a DIFFERENT group
                    // than the child we spawned) and the payload runs
                    // as PID 1 in its pid namespace, which ignores
                    // TERM — KILL is kernel-enforced. Descendants are
                    // walked via /proc so no orphan survives the turn.
                    let pid = child.id() as i32;
                    // TERM the spawned group first (graceful for plain
                    // children), then ALWAYS walk the descendants and
                    // KILL: the sandbox's re-exec lands in its own
                    // session (outside the spawned child's group) and
                    // the payload ignores TERM as its namespace's PID 1
                    // — only the tree walk reaches them.
                    kill_process_group(pid);
                    kill_tree(pid);
                    drop(child.stdout.take());
                    drop(child.stderr.take());
                    return ToolResult::err("cancelled by user");
                }
                if std::time::Instant::now() >= deadline {
                    // Move to the background: leave the child running,
                    // record it, and report.
                    let id = format!("bg-{}", ulid::Ulid::new());
                    let pid = child.id() as i32;
                    if let Ok(mut bg) = BACKGROUND.lock() {
                        bg.push(BackgroundCommand {
                            id: id.clone(),
                            command: command.to_string(),
                            output_path: output_path.clone(),
                            pid,
                            started: std::time::Instant::now(),
                        });
                    }
                    // Spawn a reaper that writes the output when done.
                    let path = output_path.clone();
                    std::thread::spawn(move || {
                        let out = child.wait_with_output();
                        if let Ok(o) = out {
                            let combined = format!(
                                "{}{}",
                                String::from_utf8_lossy(&o.stdout),
                                String::from_utf8_lossy(&o.stderr)
                            );
                            let _ = std::fs::write(&path, combined);
                        }
                    });
                    return ToolResult::ok(json!({
                        "ok": true,
                        "backgrounded": true,
                        "task_id": id,
                        "note": format!("command still running after {timeout_secs}s; output will land in {}", output_path.display()),
                    }));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return ToolResult::err(&format!("wait failed: {e}")),
        }
    }
}

fn read_pipes(
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
) -> (String, String) {
    use std::io::Read;
    fn read_pipe(mut p: Option<std::process::ChildStdout>) -> String {
        match p.as_mut() {
            Some(s) => {
                let mut buf = String::new();
                let _ = s.read_to_string(&mut buf);
                buf
            }
            None => String::new(),
        }
    }
    fn read_pipe_err(mut p: Option<std::process::ChildStderr>) -> String {
        match p.as_mut() {
            Some(s) => {
                let mut buf = String::new();
                let _ = s.read_to_string(&mut buf);
                buf
            }
            None => String::new(),
        }
    }
    (read_pipe(stdout), read_pipe_err(stderr))
}

/// The environment a Bash child may see: an explicit allowlist, never
/// ORBIT's own environment (provider keys must not leak into tool
/// results via printenv).
fn env_allowlist() -> Vec<(String, String)> {
    const ALLOW: &[&str] = &["PATH", "HOME", "LANG", "TERM", "TMPDIR", "SHELL"];
    ALLOW
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect()
}

/// TaskStop: stop a background command by id.
pub struct TaskStopTool;

impl Tool for TaskStopTool {
    fn name(&self) -> &'static str {
        "TaskStop"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "task_id": { "type": "string", "description": "The background task id to stop" }
            },
            "required": ["task_id"]
        })
    }
    fn read_only(&self) -> bool {
        false
    }
    fn permission_key(&self, _input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "TaskStop".into(),
            pattern: String::new(),
        }
    }
    fn run(&self, input: &serde_json::Value, _cx: &ToolContext) -> ToolResult {
        let Some(task_id) = input.get("task_id").and_then(|v| v.as_str()) else {
            return ToolResult::err("task_id is required");
        };
        // Kill the whole process group (negative PID) so shell children
        // die with the leader; then drop the record.
        if let Ok(mut bg) = BACKGROUND.lock() {
            if let Some(pos) = bg.iter().position(|b| b.id == task_id) {
                let cmd = bg.remove(pos);
                let killed = kill_process_group(cmd.pid);
                return ToolResult::ok(json!({
                    "ok": killed,
                    "stopped": task_id,
                }));
            }
        }
        ToolResult::err("no such background task")
    }
}

/// Kill a process group (negative PID = the whole group). Returns
/// whether the signal was delivered.
//
/// KILL every descendant of `pid` (walked via /proc children lists).
/// Needed because the sandbox re-execs bwrap in a new session, putting
/// the payload outside the spawned child's process group.
/// A pid is safe to signal only if it is a LIVE DESCENDANT of `root` —
/// verified by walking its /proc PPID chain upward. The children-list
/// walk in kill_tree can only ever *enumerate* descendants, but between
/// enumeration and the kill a pid may exit and be REUSED by an
/// unrelated process (observed 2026-10-07: a recycled pid TERMed the
/// whole user session via `kill -TERM -{pid}`). Re-validating ancestry
/// immediately before each signal closes that window.
fn is_descendant_of(pid: i32, root: i32) -> bool {
    let mut cur = pid;
    for _ in 0..64 {
        if cur == root {
            return true;
        }
        if cur <= 1 {
            return false;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{cur}/stat")) else {
            return false; // gone — nothing to confirm
        };
        // Field 4 is PPID. comm (field 2) is parenthesized and may
        // contain spaces/parens, so split AFTER the last ')'.
        let Some((_comm, rest)) = stat.rsplit_once(')') else {
            return false;
        };
        let mut fields = rest.split_whitespace();
        let _state = fields.next();
        let Some(ppid) = fields.next().and_then(|f: &str| f.parse::<i32>().ok()) else {
            return false;
        };
        cur = ppid;
    }
    false
}

/// Whether `anc` is an ancestor of `pid` per the /proc PPID chain.
fn is_ancestor_of(anc: i32, pid: i32) -> bool {
    if anc <= 1 || anc == pid {
        return false;
    }
    let mut cur = pid;
    for _ in 0..64 {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{cur}/stat")) else {
            return false;
        };
        let Some((_comm, rest)) = stat.rsplit_once(')') else {
            return false;
        };
        let mut fields = rest.split_whitespace();
        let _state = fields.next();
        let Some(ppid) = fields.next().and_then(|f: &str| f.parse::<i32>().ok()) else {
            return false;
        };
        if ppid == anc {
            return true;
        }
        if ppid <= 1 {
            return false;
        }
        cur = ppid;
    }
    false
}

/// KILL every descendant of `pid` (walked via /proc children lists).
/// Needed because the sandbox re-execs bwrap in a new session, putting
/// the payload outside the spawned child's process group.
///
/// Guards (2026-10-07, after a recycled-pid kill TERMed the user's whole
/// session): never signal pid <= 1, ourselves, our own ancestors (the
/// session supervisor survives every kill path), or any pid whose live
/// /proc ancestry can not be confirmed as descending from the original
/// child.
fn kill_tree(pid: i32) {
    let me = std::process::id() as i32;
    // The root itself must be alive; if /proc/{pid} is gone the tree is
    // already dead and signaling risks hitting a REUSED pid.
    if pid <= 1 || pid == me || !std::path::Path::new(&format!("/proc/{pid}")).exists() {
        return;
    }
    let mut stack = vec![pid];
    let mut seen = std::collections::HashSet::new();
    while let Some(p) = stack.pop() {
        if !seen.insert(p) {
            continue;
        }
        // Never signal init, ourselves, or our own ancestors.
        if p <= 1 || p == me || is_ancestor_of(p, me) {
            continue;
        }
        // Children of every thread of p.
        if let Ok(tasks) = std::fs::read_dir(format!("/proc/{p}/task")) {
            for task in tasks.flatten() {
                if let Ok(list) = std::fs::read_to_string(task.path().join("children")) {
                    for c in list.split_whitespace() {
                        if let Ok(c) = c.parse::<i32>() {
                            stack.push(c);
                        }
                    }
                }
            }
        }
        // KILL this pid DIRECTLY (not by group): a walked pid is
        // usually not a process-group leader, and `kill -KILL -<pid>`
        // on a non-leader is ESRCH — silently ignored. The group kill
        // above already handled the leaders' groups.
        // Re-validate immediately before signaling: the pid must still
        // be a live descendant of the original child (exit+reuse between
        // enumeration and kill is exactly the 2026-10-07 failure).
        if !is_descendant_of(p, pid) {
            continue;
        }
        let _ = std::process::Command::new("kill")
            .arg("-KILL")
            .arg(p.to_string())
            .status();
    }
}

fn kill_process_group(pid: i32) -> bool {
    use std::process::Command;
    // kill -TERM -<pgid>: the child was spawned with process_group(0),
    // so its PID IS its pgid. Guard (2026-10-07): refuse pid <= 1 and
    // require the LIVE pgid from /proc/{pid}/stat to match — a pid that
    // exited and was reused would otherwise TERM an unrelated process
    // group (observed taking down the entire user session).
    if pid <= 1 {
        return false;
    }
    let Some(pgrp) = live_pgrp(pid) else {
        return false; // already dead
    };
    if pgrp != pid {
        return false; // not the group leader — never signal -pid
    }
    Command::new("kill")
        .arg("-TERM")
        .arg(format!("-{pid}"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The live process-group id of `pid` from /proc, or None if gone.
fn live_pgrp(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after comm: state(3) ppid(4) pgrp(5). comm (field 2) is
    // parenthesized and may contain spaces/parens — split AFTER ')'.
    let (_comm, rest) = stat.rsplit_once(')')?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next();
    let _ppid = fields.next();
    fields.next().and_then(|f: &str| f.parse::<i32>().ok())
}

/// List live background commands (for the status line / TaskList).
pub fn background_commands() -> Vec<(String, String)> {
    BACKGROUND
        .lock()
        .map(|bg| {
            bg.iter()
                .map(|b| (b.id.clone(), b.command.clone()))
                .collect()
        })
        .unwrap_or_default()
}
