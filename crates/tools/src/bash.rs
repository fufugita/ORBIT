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

use rustix::process::{Pid, Signal};

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
                "description": { "type": "string", "description": "What this command does (for the operator)" },
                "run_in_background": { "type": "boolean", "description": "Start the command detached and return a task_id at once; stop it with TaskStop (C7 — the flag was advertised by TaskStop but missing from this schema, so a call with it ran in the foreground)" }
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
        // C7: an explicit background run skips the wait entirely — the
        // command is spawned, registered, and the task_id returns at
        // once (the timeout path still auto-backgrounds long commands).
        if input
            .get("run_in_background")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return run_command_backgrounded(command, cx);
        }
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

/// Run a command detached from the start (C7: Bash run_in_background).
/// Same spawn discipline as run_command — sandbox when available,
/// env-allowlist otherwise, own process group — but no wait loop: the
/// task_id returns at once and a reaper thread writes the output when
/// the command finishes. TaskStop kills it by id.
pub fn run_command_backgrounded(command: &str, cx: &ToolContext) -> ToolResult {
    use std::process::{Command, Stdio};

    if command_touches_deny_read(command) {
        return ToolResult::denied(
            "the command touches a deny-read path (credentials never reach a provider)",
        );
    }

    let output_path = cx
        .outputs_dir()
        .map(|d| d.join(format!("bash-{}.log", ulid::Ulid::new())))
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("orbit-bash-{}.log", ulid::Ulid::new()))
        });

    let sandbox = crate::sandbox::ShellSandbox::standard(&cx.working_dirs, &cx.session_id);
    let sandboxed = matches!(
        crate::sandbox::ShellSandbox::probe(),
        crate::sandbox::SandboxStatus::Confined
    );

    let spawn = |cmd: &mut std::process::Command| -> std::io::Result<std::process::Child> {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        cmd.spawn()
    };
    let child = if sandboxed {
        let mut wrapped = sandbox.wrap(command, &cx.working_dir);
        match spawn(&mut wrapped) {
            Ok(c) => c,
            Err(e) => return ToolResult::err(&format!("cannot spawn sandboxed bash: {e}")),
        }
    } else {
        let mut plain = Command::new("bash");
        plain
            .arg("-c")
            .arg(command)
            .current_dir(&cx.working_dir)
            .env_clear()
            .envs(env_allowlist());
        match spawn(&mut plain) {
            Ok(c) => c,
            Err(e) => return ToolResult::err(&format!("cannot spawn bash: {e}")),
        }
    };

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
    let path = output_path.clone();
    std::thread::spawn(move || {
        if let Ok(o) = child.wait_with_output() {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let _ = std::fs::write(&path, combined);
        }
    });
    ToolResult::ok(json!({
        "ok": true,
        "backgrounded": true,
        "task_id": id,
        "note": format!("running detached; output will land in {}", output_path.display()),
        "sandboxed": sandboxed,
    }))
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
/// unrelated process. Re-validating ancestry immediately before each
/// signal closes that window. (Defence in depth: the 2026-10 session
/// kills were not pid reuse but `/usr/bin/kill` mangling a negative
/// operand — see [`send_pid_signal`].)
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
/// Guards: never signal pid <= 1, ourselves, our own ancestors (the
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
        audit_kill("KILL-pid", p, "sent (validated descendant)");
        if let Err(e) = send_pid_signal(p, Signal::KILL) {
            // ESRCH is the normal "already gone"; anything else is news.
            if e.raw_os_error() != Some(rustix::io::Errno::SRCH.raw_os_error()) {
                audit_kill("KILL-pid", p, &format!("failed: {e}"));
            }
        }
    }
}

/// Why a group kill is refused, or `Ok` when `pid` may be signalled.
/// `pid` must be a LIVE DESCENDANT of this process (`me`) that leads its
/// own process group. Being a group leader is not enough — an unrelated
/// leader, or one of our own ancestors (the session manager, the shell,
/// the terminal emulator), would also pass that test and a group signal
/// to it takes the whole session down. Pure: reads /proc, sends nothing.
fn group_kill_verdict(pid: i32, me: i32) -> Result<(), &'static str> {
    if pid <= 1 {
        return Err("pid <= 1");
    }
    if pid == me {
        return Err("our own pid");
    }
    if is_ancestor_of(pid, me) {
        return Err("an ancestor of this process");
    }
    if !is_descendant_of(pid, me) {
        return Err("not a live descendant of this process");
    }
    match live_pgrp(pid) {
        Some(pgrp) if pgrp == pid => Ok(()),
        Some(_) => Err("not a process-group leader"),
        None => Err("already gone"),
    }
}

#[cfg(test)]
fn group_kill_allowed(pid: i32, me: i32) -> bool {
    group_kill_verdict(pid, me).is_ok()
}

/// Append one line per kill decision to `$ORBIT_HOME/kill-audit.log`
/// (falling back to the temp dir): time, who asked, the target, and the
/// verdict. A refusal is as important as a signal — if a session is ever
/// taken down again, this file says whether orbit sent it.
fn audit_kill(action: &str, pid: i32, verdict: &str) {
    use std::io::Write;
    let dir = std::env::var_os("ORBIT_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join("kill-audit.log");
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let me = std::process::id();
    let pgrp = live_pgrp(me as i32).unwrap_or(-1);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(
            f,
            "{secs:.3} orbit_pid={me} orbit_pgrp={pgrp} {action} target={pid} {verdict}"
        );
    }
}

fn kill_process_group(pid: i32) -> bool {
    // The child was spawned with process_group(0), so its PID IS its
    // pgid. Refuse pid <= 1 and require the LIVE pgid from
    // /proc/{pid}/stat to match: a pid that exited and was reused must
    // not carry a group signal to an unrelated group.
    match group_kill_verdict(pid, std::process::id() as i32) {
        Ok(()) => audit_kill("TERM-group", pid, "sent"),
        Err(why) => {
            audit_kill("TERM-group", pid, &format!("refused: {why}"));
            return false;
        }
    }
    match send_group_signal(pid, Signal::TERM) {
        Ok(()) => true,
        Err(e) => {
            audit_kill("TERM-group", pid, &format!("failed: {e}"));
            false
        }
    }
}

/// Signal one process with kill(2) itself.
///
/// Signals never go through `/usr/bin/kill`. procps-ng 4.0.4 (Ubuntu
/// 24.04, Mint 22) reads one digit of a negative operand, so
/// `kill -TERM -1670` is `kill(-1, SIGTERM)` — every process the user
/// owns, the desktop session's manager included — and `-53` is `-5`,
/// some other group. That, not pid reuse, is what took whole sessions
/// down on 2026-10-07 and 2026-10-08. A syscall has no operand parser.
fn send_pid_signal(pid: i32, sig: Signal) -> std::io::Result<()> {
    let pid = signal_target(pid)?;
    rustix::process::kill_process(pid, sig).map_err(std::io::Error::from)
}

/// Signal every member of process group `pgid` with kill(2) itself (see
/// [`send_pid_signal`] for why not `/usr/bin/kill`).
fn send_group_signal(pgid: i32, sig: Signal) -> std::io::Result<()> {
    let pgid = signal_target(pgid)?;
    rustix::process::kill_process_group(pgid, sig).map_err(std::io::Error::from)
}

/// A pid/pgid that may be signalled at all. pid 0 names our own group;
/// as a group, pid 1 is `kill(-1, …)` — every process the caller may
/// signal; pid 1 itself is init. No tool child is any of them.
fn signal_target(raw: i32) -> std::io::Result<Pid> {
    if raw <= 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to signal pid/pgid {raw}"),
        ));
    }
    Pid::from_raw(raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid pid/pgid {raw}"),
        )
    })
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

#[cfg(test)]
mod group_kill_tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    fn me() -> i32 {
        std::process::id() as i32
    }

    fn ppid_of(pid: i32) -> i32 {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let (_, rest) = stat.rsplit_once(')').unwrap();
        rest.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    #[test]
    fn refuses_init_ourselves_and_every_ancestor() {
        assert!(!group_kill_allowed(0, me()));
        assert!(!group_kill_allowed(1, me()));
        assert!(!group_kill_allowed(-5, me()));
        assert!(!group_kill_allowed(me(), me()), "never our own group");
        // Walk up the real ancestry (shell, terminal, session manager…):
        // not one of them may be signalled, whatever it leads.
        let mut cur = me();
        for _ in 0..16 {
            cur = ppid_of(cur);
            if cur <= 1 {
                break;
            }
            assert!(
                !group_kill_allowed(cur, me()),
                "ancestor {cur} must be refused"
            );
        }
    }

    #[test]
    fn refuses_an_unrelated_group_leader() {
        // A process we did not start, even though it is a real, live
        // process: our parent's sibling set is not ours. pid 2 (kthreadd)
        // is unrelated on Linux; either way it must not be allowed.
        assert!(!group_kill_allowed(2, me()));
    }

    #[test]
    fn allows_only_our_own_group_leader_child() {
        // Spawn a harmless sleeper as its own group leader, ask the
        // guard (no signal is sent through it), then end it with the
        // standard library's single-pid kill.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        assert!(group_kill_allowed(pid, me()), "our own group-leader child");
        // The same pid is refused when asked about as someone else's child.
        assert!(!group_kill_allowed(pid, pid + 100_000));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!group_kill_allowed(pid, me()), "gone → refused");
    }

    #[test]
    fn signal_target_refuses_what_is_never_a_tool_child() {
        // pid 0 is our own group; as a group, pid 1 is kill(-1, …) —
        // everything the caller may signal. Refused before any syscall.
        for raw in [i32::MIN, -1500, -5, -1, 0, 1] {
            assert!(signal_target(raw).is_err(), "{raw} must be refused");
            assert!(send_group_signal(raw, Signal::TERM).is_err());
            assert!(send_pid_signal(raw, Signal::KILL).is_err());
        }
        assert!(signal_target(2).is_ok());
    }

    /// No source file in this crate may shell out to a `kill` binary
    /// (see `send_pid_signal`). Reintroducing it is how an Esc — or a
    /// test run — takes the desktop session down, so a test says so.
    #[test]
    fn nothing_in_this_crate_shells_out_to_kill() {
        fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    rs_files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        // Built from parts so this file does not match itself.
        let needles = [
            format!("Command::new(\"{}\")", "kill"),
            format!("Command::new(\"{}\")", "pkill"),
            format!("Command::new(\"{}\")", "killall"),
        ];
        let mut files = Vec::new();
        rs_files(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(!files.is_empty());
        let mut hits = Vec::new();
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap();
            for n in &needles {
                if text.contains(n.as_str()) {
                    hits.push(format!("{}: {n}", f.display()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "signal with kill(2), not a binary: {hits:?}"
        );
    }

    /// The regression behind the October session kills. Signalling a
    /// group by running `kill -TERM -<pgid>` is wrong on procps-ng
    /// 4.0.4 (Ubuntu 24.04, Mint 22): it reads one digit of a negative
    /// operand, so `-1670` becomes `-1` — every process the user owns —
    /// and `-53` becomes `-5`, some other group. The group we mean must
    /// die, and a process outside it must not notice.
    #[test]
    fn a_group_kill_reaches_exactly_that_group() {
        let mut bystander = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut victim = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = victim.id() as i32;

        let sent = kill_process_group(pgid);

        let mut died = false;
        for _ in 0..60 {
            if matches!(victim.try_wait(), Ok(Some(_))) {
                died = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let bystander_alive = matches!(bystander.try_wait(), Ok(None));
        let _ = bystander.kill();
        let _ = bystander.wait();
        let _ = victim.kill();
        let _ = victim.wait();

        assert!(sent, "the TERM must be delivered to group {pgid}");
        assert!(died, "group {pgid} must be dead after the TERM");
        assert!(
            bystander_alive,
            "a process outside group {pgid} must survive it"
        );
    }
}
