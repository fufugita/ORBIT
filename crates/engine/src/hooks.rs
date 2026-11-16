//! Hooks (roadmap phase 5, §Extensibility) — v1 events.
//!
//! A hook gets JSON on stdin. Exit code 2 blocks the action and feeds
//! stderr to the model; JSON on stdout can allow, deny, ask or rewrite
//! the tool input. Default timeout 60 s. Deny and ask rules still
//! apply when a hook says allow. Project hooks run only in trusted
//! folders.
//!
//! Hooks written for Claude Code run unchanged where the features
//! overlap: the payload also carries `tool_name`, `tool_input` and `cwd`,
//! a `matcher` limits a hook to named tools, and stdout may use Claude
//! Code's `hookSpecificOutput` / `decision` JSON. A matcher is a list of
//! names separated by `|` or `,` with `*` (or `.*`) as a wildcard; full
//! regular expressions are not supported.

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
    /// A tool call was refused: by a rule, by the mode, by auto mode's
    /// classifier, or by the operator. Observational.
    PermissionDenied,
    PostToolUse,
    PostToolUseFailure,
    Stop,
    /// The turn ended without a complete reply: a provider or local error,
    /// or filtered, incomplete or truncated output. Observational.
    StopFailure,
    /// A slash command (a command file or a mod command) is about to become
    /// a prompt. Matcher: the command name. Can block.
    UserPromptExpansion,
    /// A round's tool calls have all returned, before the next model
    /// request. Can block, which ends the turn.
    PostToolBatch,
    /// `TaskCreate` is about to add a task. Can block.
    TaskCreated,
    /// `TaskUpdate` is about to mark a task done. Can block.
    TaskCompleted,
    /// An instruction or rule file was read into the session's prompt.
    /// Matcher: the load reason (`session_start`). Observational.
    InstructionsLoaded,
    /// `/add-dir` added a working directory. Matcher: `slash_command`.
    DirectoryAdded,
    /// `/model` is about to switch models. Matcher: the target model.
    /// Can block.
    PreModelSwitch,
    /// The session's model changed. Matcher: the new model.
    PostModelSwitch,
    /// The model's reply for the turn is complete and shown. Observational.
    MessageDisplay,
    /// A setting the session reads was reloaded while it runs. Matcher: the
    /// source (`mods`, `output_style`). Observational.
    ConfigChange,
    /// A watched file changed on disk since the last prompt. The matcher
    /// names the files to watch, literally (`.env|.envrc`). Observational.
    FileChanged,
    /// `--init`, `--init-only` or `--maintenance` at launch, before the
    /// session starts. Matcher: `init` or `maintenance`. Observational.
    Setup,
    /// A background agent finished its turn and is about to wait. A block
    /// sends the reason back and the agent keeps working.
    TeammateIdle,
    /// `/cd` or a worktree tool moved the session's working directory.
    /// Observational.
    CwdChanged,
    /// `EnterWorktree` is about to make a worktree. A hook that prints a
    /// directory on standard output replaces `git worktree add`; a failing
    /// hook fails the tool.
    WorktreeCreate,
    /// `ExitWorktree` is about to remove a worktree. A failing hook keeps
    /// it.
    WorktreeRemove,
    /// An MCP server asked the operator for input. Matcher: the server. A
    /// hook can answer for the operator or decline.
    Elicitation,
    /// The answer to an elicitation, before it goes to the server. Matcher:
    /// the server. A hook can replace it or decline.
    ElicitationResult,
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
            HookEvent::PermissionDenied => "PermissionDenied",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::PostToolUseFailure => "PostToolUseFailure",
            HookEvent::Stop => "Stop",
            HookEvent::StopFailure => "StopFailure",
            HookEvent::UserPromptExpansion => "UserPromptExpansion",
            HookEvent::PostToolBatch => "PostToolBatch",
            HookEvent::TaskCreated => "TaskCreated",
            HookEvent::TaskCompleted => "TaskCompleted",
            HookEvent::InstructionsLoaded => "InstructionsLoaded",
            HookEvent::DirectoryAdded => "DirectoryAdded",
            HookEvent::PreModelSwitch => "PreModelSwitch",
            HookEvent::PostModelSwitch => "PostModelSwitch",
            HookEvent::MessageDisplay => "MessageDisplay",
            HookEvent::ConfigChange => "ConfigChange",
            HookEvent::FileChanged => "FileChanged",
            HookEvent::Setup => "Setup",
            HookEvent::TeammateIdle => "TeammateIdle",
            HookEvent::CwdChanged => "CwdChanged",
            HookEvent::WorktreeCreate => "WorktreeCreate",
            HookEvent::WorktreeRemove => "WorktreeRemove",
            HookEvent::Elicitation => "Elicitation",
            HookEvent::ElicitationResult => "ElicitationResult",
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
    /// Limits the hook to matching tools (tool events) or session sources
    /// (`SessionStart`). Absent, empty or `*` matches everything.
    #[serde(default)]
    pub matcher: Option<String>,
    /// A further condition on tool events, in permission-rule form:
    /// `Bash(git push *)`, `Edit(src/**)`, or a bare tool name. The hook
    /// runs only when the call matches. Claude Code's `if`.
    #[serde(default, rename = "if")]
    pub condition: Option<String>,
    /// Start the hook and do not wait: its exit code and output are
    /// ignored, so it can neither block nor add context. Claude Code's
    /// `async`.
    #[serde(default, rename = "async")]
    pub run_async: bool,
    /// An HTTP hook: the payload is POSTed here instead of running
    /// `command`. Claude Code's `type: "http"`.
    #[serde(default)]
    pub http: Option<HttpHook>,
    /// A hook that is neither a command nor an HTTP call: a model check, an
    /// agent check, or an MCP tool. The front end runs it (see
    /// [`set_handler_runner`]).
    #[serde(default)]
    pub handler: Option<HookHandler>,
}

/// Claude Code's `prompt`, `agent` and `mcp_tool` hook types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HookHandler {
    /// One model request decides: `{"ok": true}` or
    /// `{"ok": false, "reason": "…"}`.
    Prompt {
        prompt: String,
        #[serde(default)]
        model: Option<String>,
    },
    /// The same decision from a subagent that may read and search the
    /// project first.
    Agent {
        prompt: String,
        #[serde(default)]
        model: Option<String>,
    },
    /// Call a tool on a configured MCP server; its text is read like a
    /// command's standard output.
    McpTool {
        server: String,
        tool: String,
        #[serde(default)]
        input: serde_json::Value,
    },
}

impl HookHandler {
    pub fn kind(&self) -> &'static str {
        match self {
            HookHandler::Prompt { .. } => "prompt",
            HookHandler::Agent { .. } => "agent",
            HookHandler::McpTool { .. } => "mcp_tool",
        }
    }

    /// Claude Code's default time limits for these hooks, in seconds.
    fn default_timeout_secs(&self) -> u64 {
        match self {
            HookHandler::Prompt { .. } => 30,
            HookHandler::Agent { .. } => 60,
            HookHandler::McpTool { .. } => 600,
        }
    }
}

/// Runs a [`HookHandler`]: the hook and the event's payload in, the outcome
/// out.
pub type HandlerRunner = dyn Fn(&HookConfig, &serde_json::Value) -> HookOutcome + Send + Sync;

static HANDLER_RUNNER: std::sync::Mutex<Option<std::sync::Arc<HandlerRunner>>> =
    std::sync::Mutex::new(None);

/// Install what runs `prompt`, `agent` and `mcp_tool` hooks. The engine has
/// no model or MCP connection of its own, so the front end that owns them
/// supplies this when a session opens. Without one such a hook reports an
/// error and blocks nothing.
pub fn set_handler_runner(runner: Option<std::sync::Arc<HandlerRunner>>) {
    if let Ok(mut slot) = HANDLER_RUNNER.lock() {
        *slot = runner;
    }
}

thread_local! {
    static SCOPED_HANDLER_RUNNER: std::cell::RefCell<Option<std::sync::Arc<HandlerRunner>>> =
        const { std::cell::RefCell::new(None) };
}

/// Restore the enclosing invocation's runner when this scope ends.
pub struct HandlerRunnerScope {
    previous: Option<std::sync::Arc<HandlerRunner>>,
    // A thread-local scope must be dropped on the thread that opened it.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for HandlerRunnerScope {
    fn drop(&mut self) {
        SCOPED_HANDLER_RUNNER.with(|slot| *slot.borrow_mut() = self.previous.take());
    }
}

/// Bind hooks to the running invocation, retaining the installed session
/// runner for lifecycle hooks fired outside a turn. The runner is captured
/// before a handler moves onto its timeout worker thread.
pub fn handler_runner_scope(runner: std::sync::Arc<HandlerRunner>) -> HandlerRunnerScope {
    HandlerRunnerScope {
        previous: SCOPED_HANDLER_RUNNER.with(|slot| slot.replace(Some(runner))),
        _thread: std::marker::PhantomData,
    }
}

fn current_handler_runner() -> Option<std::sync::Arc<HandlerRunner>> {
    SCOPED_HANDLER_RUNNER
        .with(|slot| slot.borrow().clone())
        .or_else(|| HANDLER_RUNNER.lock().ok().and_then(|slot| slot.clone()))
}

/// A prompt or agent hook's prompt with the event's JSON in place of
/// `$ARGUMENTS`, or appended when the prompt does not name it. `\$` is a
/// literal dollar sign.
pub fn handler_prompt(prompt: &str, payload: &serde_json::Value) -> String {
    let json = payload.to_string();
    let mut out = String::with_capacity(prompt.len() + json.len() + 2);
    let mut used = false;
    let mut rest = prompt;
    while let Some(at) = rest.find('$') {
        let (before, after) = rest.split_at(at);
        if let Some(kept) = before.strip_suffix('\\') {
            out.push_str(kept);
            out.push('$');
            rest = &after[1..];
            continue;
        }
        out.push_str(before);
        match after.strip_prefix("$ARGUMENTS") {
            Some(tail) => {
                out.push_str(&json);
                used = true;
                rest = tail;
            }
            None => {
                out.push('$');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    if !used {
        out.push_str("\n\n");
        out.push_str(&json);
    }
    out
}

/// An `mcp_tool` hook's arguments with `${path}` filled from the event's
/// JSON (`${tool_input.file_path}`). A string that is one placeholder and
/// nothing else takes the value's own type; a path that is not there
/// becomes an empty string.
pub fn handler_input(input: &serde_json::Value, payload: &serde_json::Value) -> serde_json::Value {
    fn lookup<'a>(payload: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
        path.split('.').try_fold(payload, |value, key| match value {
            serde_json::Value::Array(items) => items.get(key.parse::<usize>().ok()?),
            other => other.get(key),
        })
    }
    match input {
        serde_json::Value::String(text) => {
            if let Some(path) = text
                .strip_prefix("${")
                .and_then(|rest| rest.strip_suffix('}'))
                && !path.contains(['$', '{', '}'])
            {
                return lookup(payload, path.trim())
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(""));
            }
            let mut out = String::new();
            let mut rest = text.as_str();
            while let Some(at) = rest.find("${") {
                out.push_str(&rest[..at]);
                let after = &rest[at + 2..];
                let Some(end) = after.find('}') else {
                    out.push_str(&rest[at..]);
                    rest = "";
                    break;
                };
                match lookup(payload, after[..end].trim()) {
                    Some(serde_json::Value::String(found)) => out.push_str(found),
                    Some(found) => out.push_str(&found.to_string()),
                    None => {}
                }
                rest = &after[end + 1..];
            }
            out.push_str(rest);
            serde_json::Value::String(out)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|item| handler_input(item, payload))
                .collect(),
        ),
        serde_json::Value::Object(fields) => serde_json::Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), handler_input(value, payload)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// What a prompt or agent hook's model answered. `{"ok": true}` lets the
/// action through; `{"ok": false, "reason": "…"}` blocks it the way exit
/// code 2 does. Any other answer is a hook error and blocks nothing.
pub fn verdict_outcome(answer: &str) -> HookOutcome {
    let object = answer
        .find('{')
        .zip(answer.rfind('}'))
        .filter(|(start, end)| start < end)
        .and_then(|(start, end)| {
            serde_json::from_str::<serde_json::Value>(&answer[start..=end]).ok()
        });
    let stdout: String = answer.chars().take(4_000).collect();
    match object.as_ref().and_then(|value| value.get("ok")?.as_bool()) {
        Some(true) => HookOutcome {
            exit_code: 0,
            stdout,
            ..HookOutcome::default()
        },
        Some(false) => HookOutcome {
            exit_code: 2,
            stderr: object
                .as_ref()
                .and_then(|value| value.get("reason")?.as_str())
                .map(str::trim)
                .filter(|reason| !reason.is_empty())
                .unwrap_or("the hook's check did not pass")
                .chars()
                .take(2_000)
                .collect(),
            stdout,
            ..HookOutcome::default()
        },
        None => HookOutcome {
            exit_code: 1,
            stderr: "the hook's model did not answer {\"ok\": true} or {\"ok\": false}".into(),
            stdout,
            ..HookOutcome::default()
        },
    }
}

/// What an `mcp_tool` hook's tool returned, read like a command's standard
/// output. A tool error is a hook error and blocks nothing.
pub fn tool_outcome(text: &str, is_error: bool) -> HookOutcome {
    if is_error {
        return HookOutcome {
            exit_code: 1,
            stderr: text.chars().take(2_000).collect(),
            ..HookOutcome::default()
        };
    }
    let (decision, additional_context) = parse_output(text.trim());
    HookOutcome {
        exit_code: 0,
        stderr: String::new(),
        decision,
        additional_context,
        stdout: text.chars().take(64_000).collect(),
    }
}

thread_local! {
    static SUPPRESSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `work` with hooks switched off on this thread. For requests ORBIT
/// makes on its own behalf (a permission classifier, a hook's own model
/// check): the operator's hooks are about their conversation, and a `Stop`
/// hook that asks a model would otherwise fire for its own request without
/// end.
pub fn without_hooks<T>(work: impl FnOnce() -> T) -> T {
    let before = SUPPRESSED.with(|flag| flag.replace(true));
    let result = work();
    SUPPRESSED.with(|flag| flag.set(before));
    result
}

/// Run a `prompt`, `agent` or `mcp_tool` hook through the front end's
/// runner, within the hook's time limit.
fn run_handler(
    cfg: &HookConfig,
    handler: &HookHandler,
    payload: &serde_json::Value,
) -> HookOutcome {
    let runner = current_handler_runner();
    let Some(runner) = runner else {
        return HookOutcome {
            exit_code: 1,
            stderr: format!("no session is open to run a {} hook", handler.kind()),
            ..HookOutcome::default()
        };
    };
    let timeout = Duration::from_secs(
        cfg.timeout_secs
            .unwrap_or_else(|| handler.default_timeout_secs())
            .max(1),
    );
    let (done, finished) = std::sync::mpsc::channel();
    let (cfg, payload) = (cfg.clone(), payload.clone());
    std::thread::spawn(move || {
        let _ = done.send(without_hooks(|| runner(&cfg, &payload)));
    });
    finished
        .recv_timeout(timeout)
        .unwrap_or_else(|_| HookOutcome {
            exit_code: -2,
            stderr: format!("the {} hook did not finish in time", handler.kind()),
            ..HookOutcome::default()
        })
}

/// Where an HTTP hook sends its payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHook {
    /// `https://…`, or `http://` on the loopback interface only.
    pub url: String,
    /// Request headers, values already resolved (see [`http_hook`]).
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
}

/// Build an HTTP hook's target, or say why it is unusable. `$NAME` and
/// `${NAME}` in a header value are replaced from the environment only for
/// names listed in `allowed_env`; any other reference becomes empty, so a
/// settings file cannot read variables it was not granted.
pub fn http_hook(
    url: &str,
    headers: &[(String, String)],
    allowed_env: &[String],
) -> Result<HttpHook, String> {
    let parsed = url::Url::parse(url).map_err(|_| "hook url is not a URL".to_owned())?;
    let loopback = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host == "localhost",
        None => false,
    };
    if !(parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback)) {
        return Err("hook url must be https, or http on localhost".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("hook url must not carry credentials".into());
    }
    let mut resolved = std::collections::BTreeMap::new();
    for (name, value) in headers.iter().take(32) {
        let clean = |text: &str| !text.contains(['\r', '\n', '\0']);
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !clean(value)
        {
            return Err(format!("hook header {name:?} is not usable"));
        }
        let value = expand_allowed_env(value, allowed_env);
        if !clean(&value) {
            return Err(format!("hook header {name:?} is not usable"));
        }
        resolved.insert(name.clone(), value);
    }
    Ok(HttpHook {
        url: parsed.into(),
        headers: resolved,
    })
}

fn expand_allowed_env(value: &str, allowed: &[String]) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let (name, tail) = match after.strip_prefix('{') {
            Some(braced) => match braced.find('}') {
                Some(end) => (&braced[..end], &braced[end + 1..]),
                None => {
                    out.push('$');
                    rest = after;
                    continue;
                }
            },
            None => {
                let end = after
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(after.len());
                (&after[..end], &after[end..])
            }
        };
        if name.is_empty() {
            out.push('$');
            rest = after;
            continue;
        }
        if allowed.iter().any(|granted| granted == name) {
            out.push_str(&std::env::var(name).unwrap_or_default());
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Does a hook's `if` condition accept this payload? `Tool(pattern)` matches
/// the tool name and, with `*` wildcards, the call's main argument (a Bash
/// command, a file path, a URL). Several conditions separated by `|` accept
/// when any does. An event with no tool ignores the condition.
pub fn condition_accepts(condition: Option<&str>, payload: &serde_json::Value) -> bool {
    let condition = condition.map(str::trim).unwrap_or("");
    let Some(tool) = payload.get("tool").and_then(serde_json::Value::as_str) else {
        return true;
    };
    if condition.is_empty() {
        return true;
    }
    let arguments = payload.get("arguments");
    let subject = ["command", "file_path", "path", "url", "pattern", "prompt"]
        .iter()
        .find_map(|key| arguments?.get(*key)?.as_str())
        .unwrap_or("");
    condition.split('|').map(str::trim).any(|rule| {
        let (name, pattern) = match rule.split_once('(') {
            Some((name, rest)) => (name.trim(), rest.strip_suffix(')').unwrap_or(rest).trim()),
            None => (rule, ""),
        };
        !name.is_empty()
            && glob_matches(name, tool)
            && (pattern.is_empty() || pattern == "*" || glob_matches(pattern, subject))
    })
}

static SESSION_CONTEXT: std::sync::Mutex<Option<(String, Option<String>)>> =
    std::sync::Mutex::new(None);

static PERMISSION_MODE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

static WORKING_DIR: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// The prompt the session is working on and the effort it runs at.
static PROMPT_CONTEXT: std::sync::Mutex<Option<(String, Option<String>)>> =
    std::sync::Mutex::new(None);

/// A new prompt has entered the session: every hook payload from here on
/// reports its id (`prompt_id`) and the effort the turn runs at (`effort`,
/// when one is set), until the next prompt. Returns the id.
pub fn begin_prompt(effort: Option<&str>) -> String {
    let id = format!("prompt-{}", ulid::Ulid::new());
    if let Ok(mut slot) = PROMPT_CONTEXT.lock() {
        *slot = Some((id.clone(), effort.map(str::to_owned)));
    }
    id
}

/// The directory every hook payload reports as `cwd` from here on, once
/// `/cd` or a worktree tool has moved the session away from the directory
/// the process runs in. `None` goes back to the process's own.
pub fn set_working_dir(dir: Option<&Path>) {
    if let Ok(mut slot) = WORKING_DIR.lock() {
        *slot = dir.map(Path::to_path_buf);
    }
}

/// The permission mode every hook payload reports from here on
/// (`permission_mode`). A front end sets it at start and on each change.
pub fn set_permission_mode(mode: &str) {
    if let Ok(mut slot) = PERMISSION_MODE.lock() {
        *slot = Some(mode.to_owned());
    }
}

/// The session every hook payload names from here on (`session_id`, and
/// `transcript_path` when the session has a file). A front end sets it when
/// it opens or switches a session.
pub fn set_session_context(session_id: &str, transcript_path: Option<&Path>) {
    if let Ok(mut slot) = SESSION_CONTEXT.lock() {
        *slot = Some((
            session_id.to_owned(),
            transcript_path.map(|path| path.to_string_lossy().into_owned()),
        ));
    }
}

/// `*` matches any run of characters; everything else is literal.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let mut parts: Vec<&str> = parts.collect();
    let Some(last) = parts.pop() else {
        // No wildcard: the whole text must equal the pattern.
        return rest.is_empty();
    };
    for part in parts {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// Does a hook's matcher accept this subject (a tool name or session
/// source)? An event with no subject ignores the matcher.
pub fn matcher_accepts(matcher: Option<&str>, subject: Option<&str>) -> bool {
    let matcher = matcher.map(str::trim).unwrap_or("");
    let Some(subject) = subject else {
        return true;
    };
    if matcher.is_empty() || matcher == "*" {
        return true;
    }
    matcher
        .split(['|', ','])
        .map(|name| name.trim().replace(".*", "*"))
        .any(|name| !name.is_empty() && glob_matches(&name, subject))
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
    /// Text the hook wants the model to see (`additionalContext`).
    pub additional_context: Option<String>,
    /// What the hook printed (bounded).
    pub stdout: String,
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
        // `--settings <file>`: more of the operator's own, for this run.
        // Named explicitly, so Claude Code's JSON form is read without the
        // compatibility switch.
        if let Some(file) = orbit_tools::executor::extra_settings_file()
            && let Some(text) = read_bounded(&file)
        {
            hooks.extend(if orbit_tools::executor::is_json(&file) {
                parse_claude_settings(&text)
            } else {
                parse_hooks_toml(&text)
            });
        }
        // Project scope (trusted only).
        if project_trusted && let Ok(text) = std::fs::read_to_string(".orbit/settings.toml") {
            hooks.extend(parse_hooks_toml(&text));
        }
        // Claude Code's own hook files, when the operator opted in.
        if claude_compat(home) {
            let mut files = Vec::new();
            if let Some(dir) = claude_config_dir() {
                files.push(dir.join("settings.json"));
            }
            if project_trusted {
                files.push(PathBuf::from(".claude/settings.json"));
                files.push(PathBuf::from(".claude/settings.local.json"));
            }
            for file in files {
                if let Some(text) = read_bounded(&file) {
                    hooks.extend(parse_claude_settings(&text));
                }
            }
        }
        Hooks {
            hooks,
            project_trusted,
        }
    }

    fn matching(&self, event: HookEvent, subject: Option<&str>) -> Vec<&HookConfig> {
        self.hooks
            .iter()
            .filter(|h| h.event == event.as_str() && matcher_accepts(h.matcher.as_deref(), subject))
            .collect()
    }

    /// Fire every hook for an event. Returns outcomes in order; an
    /// empty vec when no hook matches. Blocking semantics are applied
    /// by the caller (the first block wins).
    pub fn fire(&self, event: HookEvent, payload: &serde_json::Value) -> Vec<HookOutcome> {
        if SUPPRESSED.with(std::cell::Cell::get) {
            return Vec::new();
        }
        // The payload carries the event name (E9): a hook listening to
        // several events can tell them apart. Claude Code's field names
        // ride along so its hooks read the same payload.
        let mut body = payload.as_object().cloned().unwrap_or_default();
        body.insert("hook_event_name".into(), serde_json::json!(event.as_str()));
        for (ours, theirs) in [("tool", "tool_name"), ("arguments", "tool_input")] {
            if let Some(value) = body.get(ours).cloned() {
                body.entry(theirs).or_insert(value);
            }
        }
        if let Ok(slot) = SESSION_CONTEXT.lock()
            && let Some((session_id, transcript)) = slot.as_ref()
        {
            body.entry("session_id")
                .or_insert_with(|| serde_json::json!(session_id));
            if let Some(transcript) = transcript {
                body.entry("transcript_path")
                    .or_insert_with(|| serde_json::json!(transcript));
            }
        }
        if let Ok(slot) = PERMISSION_MODE.lock()
            && let Some(mode) = slot.as_ref()
        {
            body.entry("permission_mode")
                .or_insert_with(|| serde_json::json!(mode));
        }
        if let Ok(slot) = PROMPT_CONTEXT.lock()
            && let Some((prompt_id, effort)) = slot.as_ref()
        {
            body.entry("prompt_id")
                .or_insert_with(|| serde_json::json!(prompt_id));
            if let Some(effort) = effort {
                body.entry("effort")
                    .or_insert_with(|| serde_json::json!(effort));
            }
        }
        let moved = WORKING_DIR.lock().ok().and_then(|slot| slot.clone());
        if let Some(cwd) = moved.or_else(|| std::env::current_dir().ok()) {
            body.entry("cwd")
                .or_insert_with(|| serde_json::json!(cwd.to_string_lossy()));
        }
        // What a matcher is compared with: the tool, or the event's own
        // subject (how a session started, a command or model name, ...).
        let subject = [
            "tool",
            "source",
            "command_name",
            "model",
            "load_reason",
            "file_name",
            "trigger",
            "mcp_server_name",
            "agent_type",
        ]
        .iter()
        .find_map(|key| body.get(*key).and_then(serde_json::Value::as_str))
        .map(str::to_owned);
        let body = serde_json::Value::Object(body);
        self.matching(event, subject.as_deref())
            .iter()
            .filter(|h| condition_accepts(h.condition.as_deref(), &body))
            .filter_map(|h| {
                if h.run_async {
                    let (hook, body) = ((*h).clone(), body.clone());
                    let runner = current_handler_runner();
                    std::thread::spawn(move || {
                        let _runner_scope = runner.map(handler_runner_scope);
                        let _ = run_hook(&hook, &body);
                    });
                    None
                } else {
                    let outcome = run_hook(h, &body);
                    if outcome.exit_code == -2 {
                        note_hook_problem(format!(
                            "a {} hook ran past its {} s limit and was stopped; what it guards went ahead · {}",
                            event.as_str(),
                            h.timeout_secs
                                .or_else(|| h.handler.as_ref().map(HookHandler::default_timeout_secs))
                                .unwrap_or(60),
                            hook_label(h)
                        ));
                    }
                    Some(outcome)
                }
            })
            .collect()
    }
}

/// Hook trouble the operator has not been told about yet.
static HOOK_PROBLEMS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// A hook's command (or kind), short enough for one line.
fn hook_label(hook: &HookConfig) -> String {
    let text = match (&hook.handler, &hook.http) {
        (Some(handler), _) => format!("{} hook", handler.kind()),
        (None, Some(_)) => "http hook".to_owned(),
        (None, None) => hook.command.clone(),
    };
    let mut label: String = text.chars().filter(|c| !c.is_control()).take(80).collect();
    if text.chars().count() > 80 {
        label.push('…');
    }
    label
}

fn note_hook_problem(problem: String) {
    if let Ok(mut problems) = HOOK_PROBLEMS.lock()
        && !problems.contains(&problem)
        && problems.len() < 16
    {
        problems.push(problem);
    }
}

/// What went wrong with hooks since the last call, for the front end to
/// show: a hook that is stopped at its time limit does not block what it
/// guards, so without a line the operator cannot tell it never finished.
pub fn take_hook_problems() -> Vec<String> {
    HOOK_PROBLEMS
        .lock()
        .map(|mut problems| std::mem::take(&mut *problems))
        .unwrap_or_default()
}

/// Opt-in for reading the operator's own Claude Code configuration (hooks in
/// `settings.json`, and `~/.claude/skills` and `~/.claude/commands`):
/// `ORBIT_CLAUDE_COMPAT=1`, or a top-level `claude_compat = true` in
/// `$ORBIT_HOME/settings.toml`. Off by default: those files were written for
/// another program.
pub fn claude_compat(home: &Path) -> bool {
    match std::env::var("ORBIT_CLAUDE_COMPAT").as_deref() {
        Ok("1") | Ok("true") => return true,
        Ok("0") | Ok("false") => return false,
        _ => {}
    }
    std::fs::read_to_string(home.join("settings.toml")).is_ok_and(|text| claude_compat_key(&text))
        || orbit_tools::executor::extra_settings_file()
            .filter(|file| !orbit_tools::executor::is_json(file))
            .and_then(|file| read_bounded(&file))
            .is_some_and(|text| claude_compat_key(&text))
}

/// `claude_compat = true` before the first table header.
fn claude_compat_key(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .take_while(|line| !line.starts_with('['))
        .filter_map(|line| line.split('#').next()?.split_once('='))
        .any(|(key, value)| key.trim() == "claude_compat" && value.trim() == "true")
}

pub fn claude_config_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR").filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    std::env::home_dir().map(|home| home.join(".claude"))
}

fn read_bounded(path: &Path) -> Option<String> {
    const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
    let meta = std::fs::metadata(path).ok()?;
    (meta.is_file() && meta.len() <= MAX_SETTINGS_BYTES)
        .then(|| std::fs::read_to_string(path).ok())
        .flatten()
}

/// The `hooks` object of a Claude Code `settings.json`:
/// `{"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
/// "command": "...", "timeout": 30}]}]}`. Only `command` handlers are
/// taken; anything else (prompt, agent, HTTP handlers; malformed entries)
/// is skipped. An event ORBIT never fires simply never runs.
pub fn parse_claude_settings(text: &str) -> Vec<HookConfig> {
    const MAX_HOOKS: usize = 256;
    let Ok(root) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(events) = root.get("hooks").and_then(serde_json::Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (event, groups) in events {
        for group in groups.as_array().into_iter().flatten() {
            let matcher = group
                .get("matcher")
                .and_then(serde_json::Value::as_str)
                .filter(|m| !m.is_empty())
                .map(str::to_owned);
            for handler in group
                .get("hooks")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                let kind = handler.get("type").and_then(serde_json::Value::as_str);
                let command = handler
                    .get("command")
                    .and_then(serde_json::Value::as_str)
                    .filter(|c| !c.trim().is_empty());
                // An HTTP handler: url, headers and the variables its header
                // values may read. One with an unusable target is skipped.
                let http = (kind == Some("http"))
                    .then(|| {
                        let strings = |key: &str| -> Vec<String> {
                            handler
                                .get(key)
                                .and_then(serde_json::Value::as_array)
                                .into_iter()
                                .flatten()
                                .filter_map(|v| v.as_str().map(str::to_owned))
                                .collect()
                        };
                        let headers: Vec<(String, String)> = handler
                            .get("headers")
                            .and_then(serde_json::Value::as_object)
                            .into_iter()
                            .flatten()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                            .collect();
                        http_hook(
                            handler.get("url")?.as_str()?,
                            &headers,
                            &strings("allowedEnvVars"),
                        )
                        .ok()
                    })
                    .flatten();
                let words = |key: &str| {
                    handler
                        .get(key)
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|text| !text.is_empty())
                        .map(str::to_owned)
                };
                let special = match kind {
                    Some("prompt") => words("prompt").map(|prompt| HookHandler::Prompt {
                        prompt,
                        model: words("model"),
                    }),
                    Some("agent") => words("prompt").map(|prompt| HookHandler::Agent {
                        prompt,
                        model: words("model"),
                    }),
                    Some("mcp_tool") => words("server").zip(words("tool")).map(|(server, tool)| {
                        HookHandler::McpTool {
                            server,
                            tool,
                            input: handler
                                .get("input")
                                .filter(|input| input.is_object())
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!({})),
                        }
                    }),
                    _ => None,
                };
                let command = match (kind, command, &http, &special) {
                    (Some("command") | None, Some(command), _, _) => command,
                    (Some("http"), _, Some(_), _) => "",
                    (Some("prompt" | "agent" | "mcp_tool"), _, _, Some(_)) => "",
                    _ => continue,
                };
                if out.len() == MAX_HOOKS {
                    return out;
                }
                out.push(HookConfig {
                    event: event.clone(),
                    command: command.to_owned(),
                    timeout_secs: handler
                        .get("timeout")
                        .and_then(serde_json::Value::as_u64)
                        .map(|secs| secs.clamp(1, 600)),
                    matcher: matcher.clone(),
                    condition: handler
                        .get("if")
                        .and_then(serde_json::Value::as_str)
                        .filter(|c| !c.trim().is_empty())
                        .map(str::to_owned),
                    run_async: handler
                        .get("async")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                    http,
                    handler: special,
                });
            }
        }
    }
    out
}

/// Run one hook: JSON on stdin, exit code + stdout JSON decide.
fn run_hook(cfg: &HookConfig, payload: &serde_json::Value) -> HookOutcome {
    if let Some(handler) = &cfg.handler {
        return run_handler(cfg, handler, payload);
    }
    let timeout = Duration::from_secs(cfg.timeout_secs.unwrap_or(60));
    use std::process::{Command, Stdio};
    // Its own process group, so a timeout can stop everything it started.
    use std::os::unix::process::CommandExt;
    let mut program = match &cfg.http {
        // An HTTP hook is one curl POST of the payload: no shell, the URL
        // and headers are arguments, redirects are not followed.
        Some(http) => {
            let mut curl = Command::new("curl");
            curl.args(["--silent", "--show-error", "--fail", "--request", "POST"])
                .args(["--proto", "=https,http"])
                .arg("--max-time")
                .arg(timeout.as_secs().max(1).to_string())
                .args(["--header", "Content-Type: application/json"]);
            for (name, value) in &http.headers {
                curl.arg("--header").arg(format!("{name}: {value}"));
            }
            curl.args(["--data-binary", "@-", "--"]).arg(&http.url);
            curl
        }
        None => {
            let mut shell = Command::new("bash");
            shell.arg("-c").arg(&cfg.command);
            shell
        }
    };
    let mut child = match program
        // Claude Code hooks locate their scripts through this variable.
        .envs(
            std::env::current_dir()
                .ok()
                .filter(|_| std::env::var_os("CLAUDE_PROJECT_DIR").is_none())
                .map(|cwd| ("CLAUDE_PROJECT_DIR", cwd)),
        )
        .process_group(0)
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
                ..HookOutcome::default()
            };
        }
    };
    // Feed stdin and drain both pipes on their own threads. Done inline, a
    // hook that ignores a large payload, or prints more than a pipe holds,
    // would block here or stall until its timeout.
    let stdin = child.stdin.take();
    let body = payload.to_string();
    std::thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(body.as_bytes());
        }
    });
    type Kept = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;
    fn drain<R: std::io::Read + Send + 'static>(
        pipe: Option<R>,
    ) -> (Kept, std::sync::mpsc::Receiver<()>) {
        const KEPT_BYTES: usize = 1024 * 1024;
        let kept = Kept::default();
        let (done, finished) = std::sync::mpsc::channel();
        let sink = kept.clone();
        std::thread::spawn(move || {
            if let Some(mut pipe) = pipe {
                let mut chunk = [0u8; 8192];
                loop {
                    match pipe.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Ok(mut kept) = sink.lock() {
                                let room = KEPT_BYTES.saturating_sub(kept.len());
                                kept.extend_from_slice(&chunk[..n.min(room)]);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
            let _ = done.send(());
        });
        (kept, finished)
    }
    let (stdout, stderr) = (drain(child.stdout.take()), drain(child.stderr.take()));
    // Wait with timeout (poll try_wait).
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    // The whole group: the shell and whatever it left running.
                    let _ = Command::new("kill")
                        .args(["-KILL", "--", &format!("-{}", child.id())])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    let _ = child.kill();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break None,
        }
    };
    let _ = child.wait();
    let code = match status {
        Some(s) => s.code().unwrap_or(-1),
        None => -2, // timeout
    };
    // A process the hook left behind can hold a pipe open: wait briefly for
    // the pipes to close, then use what has arrived.
    let pipes_by = std::time::Instant::now() + Duration::from_secs(2);
    let collect = |(kept, finished): (Kept, std::sync::mpsc::Receiver<()>)| {
        let _ =
            finished.recv_timeout(pipes_by.saturating_duration_since(std::time::Instant::now()));
        kept.lock()
            .map(|kept| String::from_utf8_lossy(&kept).into_owned())
            .unwrap_or_default()
    };
    let (stdout, stderr) = (collect(stdout), collect(stderr));
    let (decision, additional_context) = parse_output(stdout.trim());
    // curl's own exit codes say nothing about blocking (2 is "failed to
    // initialise"): an HTTP hook blocks only through the decision in a
    // successful response body, and any failure is a plain error.
    let code = match (&cfg.http, code) {
        (Some(_), 0) => 0,
        (Some(_), _) => 1,
        (None, code) => code,
    };
    HookOutcome {
        exit_code: code,
        stderr,
        decision,
        additional_context,
        stdout,
    }
}

/// Read a hook's stdout: ORBIT's own decision JSON, or Claude Code's
/// (`hookSpecificOutput`, the older top-level `decision`, `continue`).
fn parse_output(stdout: &str) -> (Option<HookDecision>, Option<String>) {
    if let Ok(decision) = serde_json::from_str::<HookDecision>(stdout) {
        return (Some(decision), None);
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout) else {
        return (None, None);
    };
    let text = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let specific = value
        .get("hookSpecificOutput")
        .unwrap_or(&serde_json::Value::Null);
    let reason = || {
        text(specific, "permissionDecisionReason")
            .or_else(|| text(&value, "reason"))
            .or_else(|| text(&value, "stopReason"))
            .unwrap_or_default()
    };
    let rewritten = specific
        .get("updatedInput")
        .filter(|input| input.is_object());
    let decision = match text(specific, "permissionDecision").as_deref() {
        Some("deny") => Some(HookDecision::Deny { reason: reason() }),
        Some("ask") => Some(HookDecision::Ask { reason: reason() }),
        _ if value.get("continue") == Some(&serde_json::Value::Bool(false)) => {
            Some(HookDecision::Deny { reason: reason() })
        }
        _ if text(&value, "decision").as_deref() == Some("block") => {
            Some(HookDecision::Deny { reason: reason() })
        }
        _ => match rewritten {
            Some(input) => Some(HookDecision::Rewrite {
                input: input.clone(),
            }),
            None => matches!(
                text(specific, "permissionDecision")
                    .or_else(|| text(&value, "decision"))
                    .as_deref(),
                Some("allow" | "approve")
            )
            .then_some(HookDecision::Allow),
        },
    };
    (decision, text(specific, "additionalContext"))
}

/// The tool input a hook asked for instead of the model's; the last
/// rewrite wins.
pub fn rewritten_input(outcomes: &[HookOutcome]) -> Option<serde_json::Value> {
    outcomes.iter().rev().find_map(|o| match &o.decision {
        Some(HookDecision::Rewrite { input }) => Some(input.clone()),
        _ => None,
    })
}

/// Context for the model from `SessionStart` and `UserPromptSubmit` hooks.
/// As in Claude Code, a successful hook's plain-text output counts as
/// context there, alongside any `additionalContext`.
pub fn prompt_context(outcomes: &[HookOutcome]) -> Option<String> {
    let lifted: Vec<HookOutcome> = outcomes
        .iter()
        .map(|o| {
            let plain = o.stdout.trim();
            let mut o = o.clone();
            if o.exit_code == 0
                && o.decision.is_none()
                && o.additional_context.is_none()
                && !plain.is_empty()
                && !plain.starts_with('{')
            {
                o.additional_context = Some(plain.to_owned());
            }
            o
        })
        .collect();
    added_context(&lifted)
}

/// Everything the hooks want the model to see, bounded.
pub fn added_context(outcomes: &[HookOutcome]) -> Option<String> {
    const MAX_BYTES: usize = 8 * 1024;
    let mut joined = outcomes
        .iter()
        .filter_map(|o| o.additional_context.as_deref())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if joined.is_empty() {
        return None;
    }
    if joined.len() > MAX_BYTES {
        let mut cut = MAX_BYTES;
        while !joined.is_char_boundary(cut) {
            cut -= 1;
        }
        joined.truncate(cut);
    }
    Some(joined)
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
                matcher: None,
                condition: None,
                run_async: false,
                http: None,
                handler: None,
            });
            continue;
        }
        if line.starts_with('[') {
            // leaving the hooks table
            if let Some(c) = current.take()
                && in_hooks
                && !c.event.is_empty()
                && (!c.command.is_empty() || c.http.is_some() || c.handler.is_some())
            {
                out.push(c);
            }
            in_hooks = false;
            continue;
        }
        if !in_hooks {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim();
            let raw = line[eq + 1..].trim();
            let value = raw.trim_matches('"');
            if let Some(c) = current.as_mut() {
                match key {
                    // A model check, an agent check, or an MCP tool:
                    //   prompt = "…"            (optional model = "…")
                    //   agent = "…"             (optional model = "…")
                    //   mcp_server = "name", mcp_tool = "tool",
                    //   mcp_input = '{"path": "${tool_input.file_path}"}'
                    "prompt" if !value.is_empty() => {
                        c.handler = Some(HookHandler::Prompt {
                            prompt: value.to_owned(),
                            model: None,
                        });
                    }
                    "agent" if !value.is_empty() => {
                        c.handler = Some(HookHandler::Agent {
                            prompt: value.to_owned(),
                            model: None,
                        });
                    }
                    "model" => {
                        if let Some(
                            HookHandler::Prompt { model, .. } | HookHandler::Agent { model, .. },
                        ) = c.handler.as_mut()
                        {
                            *model = Some(value.to_owned()).filter(|name| !name.is_empty());
                        }
                    }
                    "mcp_server" | "mcp_tool" | "mcp_input" => {
                        let (mut server, mut tool, mut input) = match c.handler.take() {
                            Some(HookHandler::McpTool {
                                server,
                                tool,
                                input,
                            }) => (server, tool, input),
                            _ => (String::new(), String::new(), serde_json::json!({})),
                        };
                        match key {
                            "mcp_server" => server = value.to_owned(),
                            "mcp_tool" => tool = value.to_owned(),
                            _ => {
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(
                                    raw.trim_matches('\''),
                                ) && parsed.is_object()
                                {
                                    input = parsed;
                                }
                            }
                        }
                        c.handler = Some(HookHandler::McpTool {
                            server,
                            tool,
                            input,
                        });
                    }
                    "event" => c.event = value.to_string(),
                    "command" => c.command = value.to_string(),
                    "timeout_secs" => c.timeout_secs = value.parse().ok(),
                    "matcher" => c.matcher = Some(value.to_string()),
                    "if" => c.condition = Some(value.to_string()),
                    "async" => c.run_async = value == "true",
                    // An HTTP hook: `url = "https://…"`, and any number of
                    // `header = "Name: value"` lines (no environment
                    // expansion here: the file is the operator's own).
                    "url" => c.http = http_hook(value, &[], &[]).ok(),
                    "header" => {
                        if let (Some(http), Some((name, text))) =
                            (c.http.as_mut(), value.split_once(':'))
                            && let Ok(checked) = http_hook(
                                &http.url,
                                &[(name.trim().to_owned(), text.trim().to_owned())],
                                &[],
                            )
                        {
                            http.headers.extend(checked.headers);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(c) = current.take()
        && !c.event.is_empty()
        && (!c.command.is_empty() || c.http.is_some() || c.handler.is_some())
    {
        out.push(c);
    }
    out
}

/// The files `FileChanged` hooks ask to have watched: the literal names in
/// their matchers, relative to the working directory. Names with a path
/// separator, `..` or a wildcard are not watched.
pub fn watched_files(hooks: &Hooks) -> Vec<String> {
    let mut names: Vec<String> = hooks
        .hooks
        .iter()
        .filter(|hook| hook.event == HookEvent::FileChanged.as_str())
        .filter_map(|hook| hook.matcher.as_deref())
        .flat_map(|matcher| matcher.split(['|', ',']))
        .map(str::trim)
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 128
                && !name.contains(['/', '\\', '*'])
                && *name != ".."
                && *name != "."
        })
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    names.truncate(32);
    names
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

/// The first hook that wants the operator to confirm the call.
pub fn asks(outcomes: &[HookOutcome]) -> Option<String> {
    outcomes.iter().find_map(|o| match &o.decision {
        Some(HookDecision::Ask { reason }) => Some(if reason.is_empty() {
            "a hook asked for confirmation".to_owned()
        } else {
            reason.clone()
        }),
        _ => None,
    })
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
    fn a_hook_that_ignores_stdin_and_floods_stdout_still_finishes() {
        let cfg = HookConfig {
            event: "PreToolUse".into(),
            command: "head -c 300000 /dev/zero | tr '\\0' x; echo blocked >&2; exit 2".into(),
            timeout_secs: Some(20),
            matcher: None,
            condition: None,
            run_async: false,
            http: None,
            handler: None,
        };
        let started = std::time::Instant::now();
        let outcome = run_hook(&cfg, &serde_json::json!({ "content": "y".repeat(300_000) }));
        assert_eq!(outcome.exit_code, 2);
        assert!(outcome.stderr.contains("blocked"));
        assert!(started.elapsed() < Duration::from_secs(15));
    }

    #[test]
    fn a_timed_out_hook_takes_its_children_with_it() {
        let marker = std::env::temp_dir().join(format!("orbit-hook-orphan-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let cfg = HookConfig {
            event: "Stop".into(),
            command: format!("(sleep 2; touch {}) & sleep 30", marker.display()),
            timeout_secs: Some(1),
            matcher: None,
            condition: None,
            run_async: false,
            http: None,
            handler: None,
        };
        let outcome = run_hook(&cfg, &serde_json::json!({}));
        assert_eq!(outcome.exit_code, -2, "the hook timed out");
        std::thread::sleep(Duration::from_secs(3));
        assert!(!marker.exists(), "the background child was stopped too");
    }

    #[test]
    fn a_hook_that_leaves_a_process_holding_its_pipes_does_not_hang() {
        let cfg = HookConfig {
            event: "Stop".into(),
            command: "sleep 30 & echo '{\"type\":\"allow\"}'".into(),
            timeout_secs: Some(20),
            matcher: None,
            condition: None,
            run_async: false,
            http: None,
            handler: None,
        };
        let started = std::time::Instant::now();
        let outcome = run_hook(&cfg, &serde_json::json!({}));
        assert_eq!(outcome.exit_code, 0);
        assert!(matches!(outcome.decision, Some(HookDecision::Allow)));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

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
    fn matchers_limit_a_hook_to_named_tools() {
        for (matcher, tool, expected) in [
            (None, "Bash", true),
            (Some(""), "Bash", true),
            (Some("*"), "Bash", true),
            (Some("Bash"), "Bash", true),
            (Some("Bash"), "BashOutput", false),
            (Some("Edit|Write"), "Write", true),
            (Some("Edit, Write"), "Read", false),
            (Some("mcp__github__*"), "mcp__github__create_issue", true),
            (Some("mcp__.*__write.*"), "mcp__fs__write_file", true),
            (Some("mcp__.*__write.*"), "mcp__fs__read_file", false),
            (Some("*Edit"), "NotebookEdit", true),
        ] {
            assert_eq!(
                matcher_accepts(matcher, Some(tool)),
                expected,
                "{matcher:?} against {tool}"
            );
        }
        // An event without a subject runs every hook for it.
        assert!(matcher_accepts(Some("Bash"), None));

        let hooks = Hooks {
            hooks: vec![HookConfig {
                event: "PreToolUse".into(),
                command: "echo no >&2; exit 2".into(),
                timeout_secs: Some(10),
                matcher: Some("Write|Edit".into()),
                condition: None,
                run_async: false,
                http: None,
                handler: None,
            }],
            project_trusted: true,
        };
        let fire = |tool: &str| {
            blocked(&hooks.fire(
                HookEvent::PreToolUse,
                &serde_json::json!({ "tool": tool, "arguments": {} }),
            ))
        };
        assert!(fire("Write").is_some());
        assert!(fire("Read").is_none());
    }

    #[test]
    fn the_payload_carries_claude_code_field_names() {
        let hooks = Hooks {
            hooks: vec![HookConfig {
                event: "PreToolUse".into(),
                command: "grep -q '\"tool_name\":\"Bash\"' && exit 2".into(),
                timeout_secs: Some(10),
                matcher: None,
                condition: None,
                run_async: false,
                http: None,
                handler: None,
            }],
            project_trusted: true,
        };
        let outcomes = hooks.fire(
            HookEvent::PreToolUse,
            &serde_json::json!({ "tool": "Bash", "arguments": { "command": "ls" } }),
        );
        assert_eq!(outcomes[0].exit_code, 2, "tool_name reached the hook");
    }

    #[test]
    fn claude_code_output_is_understood() {
        let deny = parse_output(
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"not here"}}"#,
        );
        assert!(matches!(deny.0, Some(HookDecision::Deny { reason }) if reason == "not here"));
        let ask = parse_output(r#"{"hookSpecificOutput":{"permissionDecision":"ask"}}"#);
        assert!(matches!(ask.0, Some(HookDecision::Ask { .. })));
        let rewrite = parse_output(
            r#"{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":{"command":"ls -la"},"additionalContext":"listing only"}}"#,
        );
        assert!(
            matches!(rewrite.0, Some(HookDecision::Rewrite { input }) if input["command"] == "ls -la")
        );
        assert_eq!(rewrite.1.as_deref(), Some("listing only"));
        let block = parse_output(r#"{"decision":"block","reason":"tests fail"}"#);
        assert!(matches!(block.0, Some(HookDecision::Deny { reason }) if reason == "tests fail"));
        let stop = parse_output(r#"{"continue":false,"stopReason":"halt"}"#);
        assert!(matches!(stop.0, Some(HookDecision::Deny { reason }) if reason == "halt"));
        assert!(matches!(
            parse_output(r#"{"decision":"approve"}"#).0,
            Some(HookDecision::Allow)
        ));
        // ORBIT's own schema still parses, and plain text is no decision.
        assert!(matches!(
            parse_output(r#"{"type":"deny","reason":"x"}"#).0,
            Some(HookDecision::Deny { .. })
        ));
        assert!(parse_output("just text").0.is_none());
        assert!(parse_output(r#"{"hookSpecificOutput":{}}"#).0.is_none());

        let outcomes = vec![
            HookOutcome {
                additional_context: Some("one".into()),
                ..HookOutcome::default()
            },
            HookOutcome {
                decision: Some(HookDecision::Rewrite {
                    input: serde_json::json!({ "a": 1 }),
                }),
                additional_context: Some(" two ".into()),
                ..HookOutcome::default()
            },
        ];
        assert_eq!(added_context(&outcomes).as_deref(), Some("one\ntwo"));
        let printed = vec![
            HookOutcome {
                stdout: "agent id: a1\n".into(),
                ..HookOutcome::default()
            },
            HookOutcome {
                exit_code: 1,
                stdout: "ignored: the hook failed".into(),
                ..HookOutcome::default()
            },
        ];
        assert_eq!(prompt_context(&printed).as_deref(), Some("agent id: a1"));
        assert_eq!(added_context(&printed), None);
        assert_eq!(
            rewritten_input(&outcomes),
            Some(serde_json::json!({ "a": 1 }))
        );
    }

    #[test]
    fn exit_two_blocks() {
        let outcomes = vec![HookOutcome {
            exit_code: 2,
            stderr: "no push".into(),
            ..HookOutcome::default()
        }];
        assert_eq!(blocked(&outcomes), Some("no push".into()));
        let ok = vec![HookOutcome {
            exit_code: 0,
            ..HookOutcome::default()
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
                matcher: None,
                condition: None,
                run_async: false,
                http: None,
                handler: None,
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
                matcher: None,
                condition: None,
                run_async: false,
                http: None,
                handler: None,
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

    #[test]
    fn claude_settings_hooks_become_orbit_hooks() {
        let hooks = parse_claude_settings(
            r#"{
              "permissions": {"allow": ["Bash(ls)"]},
              "hooks": {
                "PreToolUse": [
                  {"matcher": "Bash|Edit", "hooks": [
                    {"type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/check.sh", "timeout": 5},
                    {"type": "prompt", "prompt": "  "},
                    {"type": "mcp_tool", "server": "scanner"},
                    {"type": "wasm", "module": "x"},
                    {"type": "command", "command": "  "}
                  ]},
                  {"hooks": [{"command": "echo untyped"}]}
                ],
                "Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "notify", "timeout": 99999}]}],
                "FileChanged": "not a list"
              }
            }"#,
        );
        let seen: Vec<_> = hooks
            .iter()
            .map(|h| {
                (
                    h.event.as_str(),
                    h.command.as_str(),
                    h.matcher.as_deref(),
                    h.timeout_secs,
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                (
                    "PreToolUse",
                    "$CLAUDE_PROJECT_DIR/.claude/check.sh",
                    Some("Bash|Edit"),
                    Some(5)
                ),
                ("PreToolUse", "echo untyped", None, None),
                ("Stop", "notify", None, Some(600)),
            ]
        );
        assert!(parse_claude_settings("not json").is_empty());
        assert!(parse_claude_settings("{}").is_empty());
    }

    #[test]
    fn settings_json_prompt_agent_and_mcp_tool_handlers_are_taken() {
        let hooks = parse_claude_settings(
            r#"{"hooks": {
              "Stop": [{"hooks": [
                {"type": "prompt", "prompt": "Is the work done? $ARGUMENTS", "model": "small", "timeout": 20},
                {"type": "agent", "prompt": "Check the tests ran."}]}],
              "PostToolUse": [{"matcher": "Write|Edit", "hooks": [
                {"type": "mcp_tool", "server": "scanner", "tool": "scan",
                 "input": {"file_path": "${tool_input.file_path}"}}]}]}}"#,
        );
        let kinds: Vec<_> = hooks
            .iter()
            .map(|h| (h.event.as_str(), h.handler.as_ref().unwrap().kind()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("PostToolUse", "mcp_tool"),
                ("Stop", "prompt"),
                ("Stop", "agent"),
            ]
        );
        assert_eq!(
            hooks[1].handler,
            Some(HookHandler::Prompt {
                prompt: "Is the work done? $ARGUMENTS".into(),
                model: Some("small".into()),
            })
        );
        assert_eq!(hooks[1].timeout_secs, Some(20));
        assert!(
            hooks
                .iter()
                .all(|h| h.command.is_empty() && h.http.is_none())
        );
        let toml = parse_hooks_toml(
            "[[hooks]]\nevent = \"Stop\"\nprompt = \"Done? $ARGUMENTS\"\nmodel = \"small\"\n\
             [[hooks]]\nevent = \"Stop\"\nagent = \"Read the log.\"\n\
             [[hooks]]\nevent = \"PostToolUse\"\nmatcher = \"Write\"\nmcp_server = \"scanner\"\n\
             mcp_tool = \"scan\"\nmcp_input = '{\"file_path\": \"${tool_input.file_path}\"}'\n",
        );
        assert_eq!(toml.len(), 3);
        assert_eq!(
            toml[0].handler,
            Some(HookHandler::Prompt {
                prompt: "Done? $ARGUMENTS".into(),
                model: Some("small".into()),
            })
        );
        assert_eq!(toml[1].handler.as_ref().unwrap().kind(), "agent");
        assert_eq!(
            toml[2].handler,
            Some(HookHandler::McpTool {
                server: "scanner".into(),
                tool: "scan".into(),
                input: serde_json::json!({"file_path": "${tool_input.file_path}"}),
            })
        );
    }

    #[test]
    fn a_handler_prompt_takes_the_event_json_where_it_asks_or_at_the_end() {
        let payload = serde_json::json!({"tool": "Bash"});
        assert_eq!(
            handler_prompt("Check $ARGUMENTS now, cost \\$1.00, $HOME", &payload),
            r#"Check {"tool":"Bash"} now, cost $1.00, $HOME"#
        );
        assert_eq!(
            handler_prompt("Is it safe?", &payload),
            "Is it safe?\n\n{\"tool\":\"Bash\"}"
        );
    }

    #[test]
    fn handler_input_fills_placeholders_from_the_event() {
        let payload = serde_json::json!({
            "tool_input": {"file_path": "src/a.rs", "lines": [3, 9], "force": true},
            "cwd": "/w"
        });
        let filled = handler_input(
            &serde_json::json!({
                "path": "${tool_input.file_path}",
                "where": "${cwd}/${tool_input.file_path}",
                "flag": "${tool_input.force}",
                "second": "${tool_input.lines.1}",
                "gone": "${tool_input.nope}",
                "mixed": "a ${tool_input.nope} b ${unclosed",
                "nested": [{"n": 1, "p": "${cwd}"}]
            }),
            &payload,
        );
        assert_eq!(
            filled,
            serde_json::json!({
                "path": "src/a.rs",
                "where": "/w/src/a.rs",
                "flag": true,
                "second": 9,
                "gone": "",
                "mixed": "a  b ${unclosed",
                "nested": [{"n": 1, "p": "/w"}]
            })
        );
    }

    #[test]
    fn a_model_verdict_blocks_only_when_it_says_not_ok() {
        assert_eq!(verdict_outcome(r#"{"ok": true}"#).exit_code, 0);
        let refused = verdict_outcome(
            "Here you go:\n```json\n{\"ok\": false, \"reason\": \"tests not run\"}\n```",
        );
        assert_eq!(refused.exit_code, 2);
        assert_eq!(refused.stderr, "tests not run");
        assert_eq!(blocked(&[refused]), Some("tests not run".into()));
        let bare = verdict_outcome(r#"{"ok": false}"#);
        assert_eq!(bare.stderr, "the hook's check did not pass");
        for unclear in ["yes", "", r#"{"ok": "true"}"#, "{broken"] {
            let outcome = verdict_outcome(unclear);
            assert_eq!(outcome.exit_code, 1, "{unclear}");
            assert_eq!(blocked(&[outcome]), None, "{unclear}");
        }
    }

    #[test]
    fn a_tool_result_is_read_like_standard_output() {
        let denied = tool_outcome(r#"{"decision": "block", "reason": "secret found"}"#, false);
        assert_eq!(blocked(&[denied]), Some("secret found".into()));
        let plain = tool_outcome("scanned 3 files", false);
        assert_eq!(
            (plain.exit_code, plain.stdout.as_str()),
            (0, "scanned 3 files")
        );
        let failed = tool_outcome(r#"{"decision": "block"}"#, true);
        assert_eq!(failed.exit_code, 1);
        assert_eq!(blocked(&[failed]), None, "a tool error blocks nothing");
    }

    #[test]
    fn a_handler_hook_runs_through_the_installed_runner_within_its_time_limit() {
        // The runner is one per process: this is the only test that sets it.
        let hook = |timeout| HookConfig {
            event: "Stop".into(),
            command: String::new(),
            timeout_secs: timeout,
            matcher: None,
            condition: None,
            run_async: false,
            http: None,
            handler: Some(HookHandler::Prompt {
                prompt: "done?".into(),
                model: None,
            }),
        };
        let payload = serde_json::json!({"n": 1});
        let none = run_hook(&hook(None), &payload);
        assert_eq!(none.exit_code, 1);
        assert!(none.stderr.contains("prompt hook"), "{}", none.stderr);
        set_handler_runner(Some(std::sync::Arc::new(|cfg, payload| {
            if cfg.timeout_secs == Some(1) {
                std::thread::sleep(Duration::from_secs(3));
            }
            verdict_outcome(&format!(
                r#"{{"ok": false, "reason": "{} saw {}"}}"#,
                cfg.handler.as_ref().unwrap().kind(),
                payload["n"]
            ))
        })));
        let ran = run_hook(&hook(None), &payload);
        assert_eq!((ran.exit_code, ran.stderr.as_str()), (2, "prompt saw 1"));
        let slow = run_hook(&hook(Some(1)), &payload);
        assert_eq!(slow.exit_code, -2, "a runner past its limit is a timeout");
        assert_eq!(blocked(&[slow]), None);
        set_handler_runner(None);
    }

    #[test]
    fn scoped_handler_runners_restore_the_parent_after_nesting_and_unwinding() {
        let cfg = HookConfig {
            event: "Stop".into(),
            command: String::new(),
            timeout_secs: None,
            matcher: None,
            condition: None,
            run_async: false,
            http: None,
            handler: Some(HookHandler::Prompt {
                prompt: "done?".into(),
                model: None,
            }),
        };
        let named = |name: &'static str| -> std::sync::Arc<HandlerRunner> {
            std::sync::Arc::new(move |_, _| HookOutcome {
                stdout: name.into(),
                ..HookOutcome::default()
            })
        };
        let _parent = handler_runner_scope(named("parent"));
        assert_eq!(run_hook(&cfg, &serde_json::json!({})).stdout, "parent");
        {
            let _child = handler_runner_scope(named("child"));
            assert_eq!(run_hook(&cfg, &serde_json::json!({})).stdout, "child");
        }
        assert_eq!(run_hook(&cfg, &serde_json::json!({})).stdout, "parent");
        let unwound = std::panic::catch_unwind(|| {
            let _child = handler_runner_scope(named("unwinding-child"));
            panic!("leave the child invocation");
        });
        assert!(unwound.is_err());
        assert_eq!(run_hook(&cfg, &serde_json::json!({})).stdout, "parent");
    }

    #[test]
    fn hooks_are_silent_inside_without_hooks_and_back_afterwards() {
        let hooks = Hooks {
            hooks: parse_hooks_toml("[[hooks]]\nevent = \"Stop\"\ncommand = \"exit 2\"\n"),
            project_trusted: false,
        };
        let fire = || hooks.fire(HookEvent::Stop, &serde_json::json!({})).len();
        assert_eq!(fire(), 1);
        assert_eq!(without_hooks(|| without_hooks(fire) + fire()), 0);
        assert_eq!(fire(), 1);
    }

    #[test]
    fn the_new_events_match_on_their_own_subjects() {
        let hooks = Hooks {
            hooks: parse_hooks_toml(
                "[[hooks]]\nevent = \"PreCompact\"\nmatcher = \"manual\"\ncommand = \"echo no >&2; exit 2\"\n\
                 [[hooks]]\nevent = \"Elicitation\"\nmatcher = \"github\"\ncommand = \"exit 2\"\n\
                 [[hooks]]\nevent = \"SubagentStop\"\nmatcher = \"reviewer\"\ncommand = \"exit 2\"\n\
                 [[hooks]]\nevent = \"Setup\"\nmatcher = \"init\"\ncommand = \"exit 2\"\n",
            ),
            project_trusted: false,
        };
        let fired =
            |event, payload: serde_json::Value| blocked(&hooks.fire(event, &payload)).is_some();
        assert!(fired(
            HookEvent::PreCompact,
            serde_json::json!({"trigger": "manual"})
        ));
        assert!(!fired(
            HookEvent::PreCompact,
            serde_json::json!({"trigger": "auto"})
        ));
        assert!(fired(
            HookEvent::Elicitation,
            serde_json::json!({"mcp_server_name": "github"})
        ));
        assert!(!fired(
            HookEvent::Elicitation,
            serde_json::json!({"mcp_server_name": "jira"})
        ));
        assert!(fired(
            HookEvent::SubagentStop,
            serde_json::json!({"agent_type": "reviewer"})
        ));
        assert!(!fired(
            HookEvent::SubagentStop,
            serde_json::json!({"agent_type": "explorer"})
        ));
        assert!(fired(
            HookEvent::Setup,
            serde_json::json!({"trigger": "init"})
        ));
        assert!(!fired(
            HookEvent::Setup,
            serde_json::json!({"trigger": "maintenance"})
        ));
        for (event, name) in [
            (HookEvent::Setup, "Setup"),
            (HookEvent::TeammateIdle, "TeammateIdle"),
            (HookEvent::CwdChanged, "CwdChanged"),
            (HookEvent::WorktreeCreate, "WorktreeCreate"),
            (HookEvent::WorktreeRemove, "WorktreeRemove"),
            (HookEvent::Elicitation, "Elicitation"),
            (HookEvent::ElicitationResult, "ElicitationResult"),
        ] {
            assert_eq!(event.as_str(), name);
        }
    }

    #[test]
    fn claude_files_are_opt_in() {
        assert!(claude_compat_key("claude_compat = true\n[permissions]\n"));
        assert!(claude_compat_key("# note\nclaude_compat=true # yes\n"));
        assert!(!claude_compat_key("claude_compat = false\n"));
        assert!(!claude_compat_key("[permissions]\nclaude_compat = true\n"));
        assert!(!claude_compat_key(""));
    }

    #[test]
    fn a_hook_sees_the_project_directory_claude_code_would_give_it() {
        let cfg = HookConfig {
            event: "Stop".into(),
            command: "printf %s \"$CLAUDE_PROJECT_DIR\"".into(),
            timeout_secs: Some(10),
            matcher: None,
            condition: None,
            run_async: false,
            http: None,
            handler: None,
        };
        let outcome = run_hook(&cfg, &serde_json::json!({}));
        if std::env::var_os("CLAUDE_PROJECT_DIR").is_none() {
            assert_eq!(
                outcome.stdout,
                std::env::current_dir().unwrap().to_string_lossy()
            );
        }
    }

    #[test]
    fn if_conditions_match_the_tool_and_its_main_argument() {
        let bash =
            serde_json::json!({"tool": "Bash", "arguments": {"command": "git push origin main"}});
        let edit =
            serde_json::json!({"tool": "Edit", "arguments": {"file_path": "src/api/users.rs"}});
        assert!(condition_accepts(None, &bash));
        assert!(condition_accepts(Some("Bash(git push *)"), &bash));
        assert!(!condition_accepts(Some("Bash(git commit *)"), &bash));
        assert!(condition_accepts(Some("Bash"), &bash));
        assert!(!condition_accepts(Some("Edit(src/*)"), &bash));
        assert!(condition_accepts(Some("Write(*) | Edit(src/api/*)"), &edit));
        assert!(condition_accepts(
            Some("mcp__*"),
            &serde_json::json!({"tool": "mcp__gh__list"})
        ));
        // No tool in the payload: the condition does not apply.
        assert!(condition_accepts(
            Some("Bash(rm *)"),
            &serde_json::json!({"source": "startup"})
        ));
    }

    #[test]
    fn async_hooks_do_not_block_and_conditions_filter_before_running() {
        let hook = |command: &str, condition: Option<&str>, run_async: bool| HookConfig {
            event: "PreToolUse".into(),
            command: command.into(),
            timeout_secs: Some(10),
            matcher: None,
            condition: condition.map(str::to_owned),
            run_async,
            http: None,
            handler: None,
        };
        let hooks = Hooks {
            hooks: vec![
                hook("sleep 5; exit 2", None, true),
                hook("exit 2", Some("Bash(rm *)"), false),
                hook("echo ran", Some("Bash(ls*)"), false),
            ],
            project_trusted: false,
        };
        let started = std::time::Instant::now();
        let outcomes = hooks.fire(
            HookEvent::PreToolUse,
            &serde_json::json!({"tool": "Bash", "arguments": {"command": "ls -la"}}),
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(4),
            "async is not awaited"
        );
        assert_eq!(
            outcomes.len(),
            1,
            "only the matching synchronous hook reports"
        );
        assert_eq!(blocked(&outcomes), None);
        assert_eq!(outcomes[0].stdout.trim(), "ran");
    }

    #[test]
    fn settings_json_carries_if_and_async_and_toml_reads_them() {
        let hooks = parse_claude_settings(
            r#"{"hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "log", "if": "Bash(git *)", "async": true}]}]}}"#,
        );
        assert_eq!(hooks[0].condition.as_deref(), Some("Bash(git *)"));
        assert!(hooks[0].run_async);
        let toml = parse_hooks_toml(
            "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"check\"\nif = \"Bash(rm *)\"\nasync = true\n",
        );
        assert_eq!(toml[0].condition.as_deref(), Some("Bash(rm *)"));
        assert!(toml[0].run_async);
    }

    #[test]
    fn matchers_compare_with_each_events_own_subject() {
        let hook = |event: &str, matcher: &str| HookConfig {
            event: event.into(),
            command: "echo ran".into(),
            timeout_secs: Some(10),
            matcher: Some(matcher.into()),
            condition: None,
            run_async: false,
            http: None,
            handler: None,
        };
        let hooks = Hooks {
            hooks: vec![
                hook("UserPromptExpansion", "review"),
                hook("PreModelSwitch", "claude-*"),
                hook("InstructionsLoaded", "session_start"),
            ],
            project_trusted: false,
        };
        let ran = |event, payload: serde_json::Value| hooks.fire(event, &payload).len();
        assert_eq!(
            ran(
                HookEvent::UserPromptExpansion,
                serde_json::json!({"command_name": "review"})
            ),
            1
        );
        assert_eq!(
            ran(
                HookEvent::UserPromptExpansion,
                serde_json::json!({"command_name": "deploy"})
            ),
            0
        );
        assert_eq!(
            ran(
                HookEvent::PreModelSwitch,
                serde_json::json!({"model": "claude-opus-5-5"})
            ),
            1
        );
        assert_eq!(
            ran(
                HookEvent::PreModelSwitch,
                serde_json::json!({"model": "gpt"})
            ),
            0
        );
        assert_eq!(
            ran(
                HookEvent::InstructionsLoaded,
                serde_json::json!({"load_reason": "session_start"})
            ),
            1
        );
        assert_eq!(HookEvent::PostToolBatch.as_str(), "PostToolBatch");
    }

    #[test]
    fn every_payload_reports_the_prompt_and_its_effort_once_one_began() {
        let hooks = Hooks {
            hooks: vec![HookConfig {
                event: "MessageDisplay".into(),
                command: "cat".into(),
                timeout_secs: Some(10),
                matcher: None,
                condition: None,
                run_async: false,
                http: None,
                handler: None,
            }],
            project_trusted: false,
        };
        let payload = serde_json::json!({ "message": "done" });
        let id = begin_prompt(Some("high"));
        assert!(id.starts_with("prompt-"));
        let outcomes = hooks.fire(HookEvent::MessageDisplay, &payload);
        let seen: serde_json::Value = serde_json::from_str(&outcomes[0].stdout).unwrap();
        // Another test's prompt may have begun meanwhile (the slot is the
        // process's): what is asserted is that the fields are reported.
        assert!(
            seen["prompt_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("prompt-")),
            "{seen}"
        );
        // A payload that names its own is left as it is.
        let outcomes = hooks.fire(
            HookEvent::MessageDisplay,
            &serde_json::json!({ "prompt_id": "mine", "effort": "low" }),
        );
        let seen: serde_json::Value = serde_json::from_str(&outcomes[0].stdout).unwrap();
        assert_eq!(seen["prompt_id"], "mine");
        assert_eq!(seen["effort"], "low");
        assert_ne!(begin_prompt(None), id);
    }

    #[test]
    fn every_payload_reports_the_permission_mode_once_it_is_set() {
        set_permission_mode("plan");
        let hooks = Hooks {
            hooks: vec![HookConfig {
                event: "MessageDisplay".into(),
                command: "cat".into(),
                timeout_secs: Some(10),
                matcher: None,
                condition: None,
                run_async: false,
                http: None,
                handler: None,
            }],
            project_trusted: false,
        };
        let outcomes = hooks.fire(
            HookEvent::MessageDisplay,
            &serde_json::json!({ "message": "done" }),
        );
        let seen: serde_json::Value = serde_json::from_str(&outcomes[0].stdout).unwrap();
        assert_eq!(seen["permission_mode"], "plan");
        assert_eq!(seen["hook_event_name"], "MessageDisplay");
        assert_eq!(seen["message"], "done");
    }

    #[test]
    fn http_hook_targets_are_checked_and_headers_read_only_granted_variables() {
        assert!(http_hook("https://hooks.example.com/pre", &[], &[]).is_ok());
        assert!(http_hook("http://127.0.0.1:8080/pre", &[], &[]).is_ok());
        assert!(http_hook("http://localhost/pre", &[], &[]).is_ok());
        for bad in [
            "http://hooks.example.com/pre",
            "ftp://127.0.0.1/x",
            "https://user:pw@hooks.example.com/",
            "not a url",
        ] {
            assert!(http_hook(bad, &[], &[]).is_err(), "{bad}");
        }
        let header = |name: &str, value: &str| vec![(name.to_owned(), value.to_owned())];
        assert!(
            http_hook(
                "https://h.example/",
                &header("X-A", "ok\r\nInjected: 1"),
                &[]
            )
            .is_err()
        );
        assert!(http_hook("https://h.example/", &header("Bad Name", "x"), &[]).is_err());
        // PATH is set wherever tests run; only a granted name is read.
        let granted = http_hook(
            "https://h.example/",
            &header("X-Path", "p=${PATH};h=$HOME;lit=$"),
            &["PATH".to_owned()],
        )
        .unwrap();
        let value = &granted.headers["X-Path"];
        assert!(
            value.starts_with("p=") && value.contains(";h=;lit=$"),
            "{value}"
        );
        assert!(value.len() > "p=;h=;lit=$".len(), "PATH was expanded");
    }

    #[test]
    fn settings_json_http_handlers_are_taken_with_their_target() {
        let hooks = parse_claude_settings(
            r#"{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "http", "url": "https://hooks.example.com/pre", "timeout": 5,
                 "headers": {"Authorization": "Bearer $TOKEN_NOT_GRANTED"}},
                {"type": "http", "url": "http://not-loopback.example/"}]}]}}"#,
        );
        assert_eq!(hooks.len(), 1, "an unusable target is skipped");
        let http = hooks[0].http.as_ref().unwrap();
        assert_eq!(http.url, "https://hooks.example.com/pre");
        assert_eq!(http.headers["Authorization"], "Bearer ");
        assert_eq!(hooks[0].timeout_secs, Some(5));
        let toml = parse_hooks_toml(
            "[[hooks]]\nevent = \"Stop\"\nurl = \"http://127.0.0.1:9/stop\"\nheader = \"X-Team: core\"\n",
        );
        assert_eq!(toml.len(), 1);
        assert_eq!(toml[0].http.as_ref().unwrap().headers["X-Team"], "core");
    }

    /// One request answered with `status` and `body`; returns what was sent.
    fn answer_once(
        status: &'static str,
        body: &'static str,
    ) -> (u16, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 4096];
            loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&raw);
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let length = text[..head_end]
                        .to_ascii_lowercase()
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(str::trim)
                                .map(str::to_owned)
                        })
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    if raw.len() >= head_end + 4 + length {
                        break;
                    }
                }
            }
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            String::from_utf8_lossy(&raw).into_owned()
        });
        (port, server)
    }

    #[test]
    fn an_http_hook_posts_the_payload_and_blocks_only_through_its_answer() {
        if std::process::Command::new("curl")
            .arg("--version")
            .output()
            .is_err()
        {
            return; // no curl here: nothing to exercise
        }
        let hook = |port: u16| HookConfig {
            event: "PreToolUse".into(),
            command: String::new(),
            timeout_secs: Some(10),
            matcher: None,
            condition: None,
            run_async: false,
            handler: None,
            http: Some(
                http_hook(
                    &format!("http://127.0.0.1:{port}/pre"),
                    &[("X-Team".to_owned(), "core".to_owned())],
                    &[],
                )
                .unwrap(),
            ),
        };
        let payload =
            serde_json::json!({ "tool": "Bash", "arguments": { "command": "rm -rf build" } });

        let (port, server) = answer_once(
            "200 OK",
            r#"{"decision":"block","reason":"not on Fridays"}"#,
        );
        let outcome = run_hook(&hook(port), &payload);
        let sent = server.join().unwrap();
        assert!(sent.starts_with("POST /pre "), "{sent}");
        assert!(sent.to_ascii_lowercase().contains("x-team: core"));
        assert!(sent.contains("rm -rf build"), "the payload is the body");
        assert_eq!(
            blocked(std::slice::from_ref(&outcome)).as_deref(),
            Some("not on Fridays")
        );

        // A server error is an error, never a block, whatever curl exits with.
        let (port, server) = answer_once(
            "500 Internal Server Error",
            r#"{"decision":"block","reason":"x"}"#,
        );
        let outcome = run_hook(&hook(port), &payload);
        let _ = server.join();
        assert_eq!(outcome.exit_code, 1);
        // Nothing listening: the same.
        let outcome = run_hook(&hook(9), &payload);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(blocked(std::slice::from_ref(&outcome)), None);
    }

    #[test]
    fn file_changed_hooks_name_the_files_to_watch() {
        let hook = |event: &str, matcher: &str| HookConfig {
            event: event.into(),
            command: "true".into(),
            timeout_secs: None,
            matcher: Some(matcher.into()),
            condition: None,
            run_async: false,
            http: None,
            handler: None,
        };
        let hooks = Hooks {
            hooks: vec![
                hook("FileChanged", ".env|.envrc, Cargo.toml"),
                hook("FileChanged", "../secret|src/main.rs|*.rs|.env"),
                hook("PreToolUse", "Bash"),
            ],
            project_trusted: false,
        };
        assert_eq!(watched_files(&hooks), [".env", ".envrc", "Cargo.toml"]);
        // The hook for `.env` runs for `.env` and not for another file.
        let ran = |name: &str| {
            hooks
                .fire(
                    HookEvent::FileChanged,
                    &serde_json::json!({ "file_name": name }),
                )
                .len()
        };
        assert_eq!(ran(".env"), 2);
        assert_eq!(ran("Cargo.toml"), 1);
        assert_eq!(ran("README.md"), 0);
    }
}
