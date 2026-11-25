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
//! names separated by `|` or `,` with `*` (or `.*`) as a wildcard, or a
//! regular expression (see [`matcher_accepts`]).

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The v1 hook events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
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

impl std::str::FromStr for HookEvent {
    type Err = serde::de::value::Error;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::deserialize(serde::de::IntoDeserializer::into_deserializer(name))
    }
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
    /// (`SessionStart`): a list of names or a regular expression, see
    /// [`matcher_accepts`]. Absent, empty or `*` matches everything.
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
    /// The imported plugin this hook came with: its stored copy (`CLAUDE_PLUGIN_ROOT`) and its
    /// private state folder (`CLAUDE_PLUGIN_DATA`). `None` for the operator's own hooks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<PluginOrigin>,
}

/// Where a plugin's hook runs from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginOrigin {
    pub name: String,
    pub root: PathBuf,
    pub data: PathBuf,
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

/// What only a regular expression writes. A matcher with one of these is also
/// searched as one; a name list, its `|` and `,` separators and its `*` and
/// `.*` wildcards use none of them.
const REGEX_SYNTAX: [char; 11] = ['^', '$', '(', ')', '[', ']', '{', '}', '+', '?', '\\'];

/// The longest matcher compiled as a regular expression, and how large its
/// program may get. A project's own settings are read, so neither is the
/// author's to choose.
const MAX_REGEX_MATCHER_BYTES: usize = 1024;
const REGEX_MATCHER_SIZE_LIMIT: usize = 1024 * 1024;
const MAX_REMEMBERED_MATCHERS: usize = 256;

fn has_regex_syntax(matcher: &str) -> bool {
    matcher.contains(REGEX_SYNTAX)
}

type CompiledMatchers = std::collections::HashMap<String, Result<regex::Regex, String>>;

/// The matcher as a regular expression, or why it is not one. Compiling is the
/// costly part and every tool call asks, so the answer is kept.
fn matcher_regex(pattern: &str) -> Result<regex::Regex, String> {
    static COMPILED: std::sync::LazyLock<std::sync::Mutex<CompiledMatchers>> =
        std::sync::LazyLock::new(Default::default);
    let mut known = COMPILED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(answer) = known.get(pattern) {
        return answer.clone();
    }
    let answer = if pattern.len() > MAX_REGEX_MATCHER_BYTES {
        Err(format!("longer than {MAX_REGEX_MATCHER_BYTES} bytes"))
    } else {
        regex::RegexBuilder::new(pattern)
            .size_limit(REGEX_MATCHER_SIZE_LIMIT)
            .build()
            .map_err(|error| regex_reason(&error))
    };
    if known.len() >= MAX_REMEMBERED_MATCHERS {
        known.clear();
    }
    known.insert(pattern.to_owned(), answer.clone());
    answer
}

/// The line of a regex error that says what is wrong: the library's own text
/// is a block that quotes the pattern back.
fn regex_reason(error: &regex::Error) -> String {
    let text = error.to_string();
    text.lines()
        .rev()
        .find_map(|line| line.strip_prefix("error: "))
        .or_else(|| text.lines().next())
        .unwrap_or("not a valid pattern")
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect()
}

/// Does a hook's matcher accept this subject (a tool name or session
/// source)? An event with no subject ignores the matcher.
///
/// A matcher is a list of names (`|` or `,` between them, `*` or `.*` as a
/// wildcard), each compared whole. One that also uses regular-expression
/// syntax is searched as a regular expression too, anywhere in the subject as
/// Claude Code's `RegExp.test` does, so `^…$` pins it. The name list comes
/// first and is unchanged: nothing that matched before stops matching, and a
/// name with a bracket in it (`[id].tsx`) still matches itself.
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
        || (has_regex_syntax(matcher)
            && matcher_regex(matcher).is_ok_and(|pattern| pattern.is_match(subject)))
}

/// Is this matcher also read as a regular expression?
pub fn is_regex_matcher(matcher: &str) -> bool {
    has_regex_syntax(matcher.trim())
}

/// What is wrong with a matcher written as a regular expression, or `None`: a
/// name list is always fine, and so is a pattern that compiles. A pattern that
/// does not compile still matches the plain names in it; telling the operator
/// is the caller's job.
pub fn matcher_problem(matcher: &str) -> Option<String> {
    let matcher = matcher.trim();
    if !has_regex_syntax(matcher) {
        return None;
    }
    matcher_regex(matcher).err()
}

/// Text for one line of hook trouble: no control characters, bounded.
fn tidy(text: &str, limit: usize) -> String {
    let mut tidy: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(limit)
        .collect();
    if text.chars().count() > limit {
        tidy.push('…');
    }
    tidy
}

/// Tell the operator about each hook whose matcher is written as a regular
/// expression and is not one, once per process: the hooks load again for every
/// tool call.
fn report_matcher_problems(hooks: &[HookConfig]) {
    static ANNOUNCED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(Default::default);
    for hook in hooks {
        let Some(matcher) = hook.matcher.as_deref() else {
            continue;
        };
        let Some(reason) = matcher_problem(matcher) else {
            continue;
        };
        let problem = format!(
            "{} hook matcher \"{}\" is not a valid regular expression ({reason}); only its plain names can match, so the hook may never run · {}",
            tidy(&hook.event, 40),
            tidy(matcher.trim(), 80),
            hook_label(hook)
        );
        let mut announced = ANNOUNCED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if announced.len() >= MAX_REMEMBERED_MATCHERS {
            announced.clear();
        }
        if announced.insert(problem.clone()) {
            note_hook_problem(problem);
        }
    }
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
    /// The most text these hooks may add to the model's context at one event, as
    /// `hook_context_max_bytes` in the operator's settings says; `None` is the default.
    /// It travels with the hooks, so every place that fires them applies the same bound.
    pub context_limit: Option<usize>,
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
    /// Load hooks from the settings scopes (the project's from the working
    /// directory, when it is trusted), and tell the operator about a matcher
    /// written as a regular expression that is not one.
    pub fn load(home: &Path, project_trusted: bool) -> Self {
        let loaded = Self::inspect(home, project_trusted.then_some(Path::new(".")));
        report_matcher_problems(&loaded.hooks);
        crate::plugin_hooks::resolve(home)
            .problems
            .into_iter()
            .for_each(note_load_problem);
        context_limit_with_problems(home)
            .1
            .into_iter()
            .for_each(note_load_problem);
        loaded
    }

    /// The hooks a session started in `project` would run (`None`: that folder
    /// is not trusted, so only the operator's own), without telling anyone
    /// about them: for a diagnostic that prints its own findings.
    pub fn inspect(home: &Path, project: Option<&Path>) -> Self {
        let project_trusted = project.is_some();
        if crate::bare_mode() {
            return Self {
                project_trusted,
                ..Self::default()
            };
        }
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
        if let Some(dir) = project
            && let Ok(text) = std::fs::read_to_string(dir.join(".orbit/settings.toml"))
        {
            hooks.extend(parse_hooks_toml(&text));
        }
        // Claude Code's own hook files, when the operator opted in.
        if claude_compat(home) {
            let mut files = Vec::new();
            if let Some(dir) = claude_config_dir() {
                files.push(dir.join("settings.json"));
            }
            if let Some(dir) = project {
                files.push(dir.join(".claude/settings.json"));
                files.push(dir.join(".claude/settings.local.json"));
            }
            for file in files {
                if let Some(text) = read_bounded(&file) {
                    hooks.extend(parse_claude_settings(&text));
                }
            }
        }
        // The command hooks of the imported plugins the operator named in `plugin_hooks`.
        hooks.extend(crate::plugin_hooks::resolve(home).hooks);
        Hooks {
            hooks,
            project_trusted,
            context_limit: Some(context_limit_with_problems(home).0),
        }
    }

    /// The most text hooks may add to the model's context at one event.
    pub fn context_limit(&self) -> usize {
        self.context_limit.unwrap_or(DEFAULT_HOOK_CONTEXT_BYTES)
    }

    /// Everything these hooks want the model to see at one event, within the limit.
    pub fn added_context(&self, outcomes: &[HookOutcome]) -> Option<String> {
        announce_context_cut(bounded_context(outcomes, self.context_limit()))
    }

    /// Context for the model from `SessionStart` and `UserPromptSubmit` hooks.
    /// As in Claude Code, a successful hook's plain-text output counts as
    /// context there, alongside any `additionalContext`.
    pub fn prompt_context(&self, outcomes: &[HookOutcome]) -> Option<String> {
        self.added_context(&lift_plain_output(outcomes))
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
        if crate::bare_mode() || SUPPRESSED.with(std::cell::Cell::get) {
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
                    // Counted here and released when the hook is over, so that a process that
                    // ends next can wait for it (see `finish_async_hooks`).
                    let running = ASYNC_HOOKS.start();
                    std::thread::spawn(move || {
                        let _running = running;
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

/// How long a process that is ending waits for async hooks that are still running.
pub const ASYNC_HOOK_EXIT_GRACE: Duration = Duration::from_secs(5);

/// The async hooks this process has started and not yet seen finish.
struct AsyncHooks {
    running: std::sync::Mutex<usize>,
    idle: std::sync::Condvar,
}

/// One async hook that is running. Dropping it says the hook is over, whether it finished or its
/// thread is unwinding.
struct AsyncHookRun(&'static AsyncHooks);

static ASYNC_HOOKS: AsyncHooks = AsyncHooks::new();

impl AsyncHooks {
    const fn new() -> Self {
        Self {
            running: std::sync::Mutex::new(0),
            idle: std::sync::Condvar::new(),
        }
    }

    /// Never held while anything else runs, so a poisoned lock holds a count that is still right.
    fn count(&self) -> std::sync::MutexGuard<'_, usize> {
        self.running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count one more running hook. The caller does this before the hook's thread exists: counted
    /// by the thread itself, a hook would be missed by a process that ends in the very next
    /// instruction, which is the case that matters.
    fn start(&'static self) -> AsyncHookRun {
        *self.count() += 1;
        AsyncHookRun(self)
    }

    #[cfg(test)]
    fn running(&self) -> usize {
        *self.count()
    }

    /// Wait until no hook is running, or until `grace` has passed.
    fn wait(&self, grace: Duration) -> Option<String> {
        let grace = grace.min(Duration::from_secs(3600));
        let deadline = std::time::Instant::now() + grace;
        let mut running = self.count();
        while *running > 0 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Some(still_running_line(*running, grace));
            }
            running = self
                .idle
                .wait_timeout(running, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        None
    }
}

impl Drop for AsyncHookRun {
    fn drop(&mut self) {
        let mut running = self.0.count();
        *running = running.saturating_sub(1);
        if *running == 0 {
            self.0.idle.notify_all();
        }
    }
}

fn still_running_line(count: usize, grace: Duration) -> String {
    let waited = if grace.subsec_millis() == 0 && grace.as_secs() > 0 {
        format!("{} s", grace.as_secs())
    } else {
        format!("{} ms", grace.as_millis())
    };
    let (hooks, were) = if count == 1 {
        ("hook", "was")
    } else {
        ("hooks", "were")
    };
    format!(
        "{count} async {hooks} {were} still running after {waited}; ORBIT is ending and does not wait longer"
    )
}

/// Wait for the async hooks this process started, up to `grace`. A process that is about to end
/// calls this so it does not end under a hook that has not yet received its payload. Returns a line
/// for the operator when some are still running at the end of the wait.
pub fn finish_async_hooks(grace: Duration) -> Option<String> {
    ASYNC_HOOKS.wait(grace)
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

/// How often a blocking `Stop`, `SubagentStop` or `TeammateIdle` hook may send
/// the model back to work in one turn, until the operator says otherwise.
pub const DEFAULT_STOP_CONTINUATIONS: u32 = 3;

/// The most `stop_hook_max_continuations` can allow. A hook that never lets go
/// still ends, and a typo cannot buy an unbounded run.
pub const STOP_CONTINUATIONS_CEILING: u32 = 1000;

const STOP_LIMIT_KEY: &str = "stop_hook_max_continuations";

/// How often a blocking stop hook may send the model back to work in one
/// turn: `stop_hook_max_continuations`, a top-level key in the operator's own
/// settings (`$ORBIT_HOME/settings.toml`, then the `--settings` file, which
/// wins), or 3. A project's `.orbit/settings.toml` cannot raise it: the limit is
/// what stops a hook from holding the model forever, so it is the operator's
/// to set. A value that cannot be used keeps the default and is reported with
/// the rest of the hook trouble.
pub fn stop_continuation_limit(home: &Path) -> u32 {
    let (value, problems) = operator_number(
        home,
        STOP_LIMIT_KEY,
        i64::from(STOP_CONTINUATIONS_CEILING),
        i64::from(DEFAULT_STOP_CONTINUATIONS),
    );
    problems.into_iter().for_each(note_hook_problem);
    u32::try_from(value).unwrap_or(DEFAULT_STOP_CONTINUATIONS)
}

/// A whole-number setting that only the operator may set, read from the top level of
/// `$ORBIT_HOME/settings.toml` and then of the `--settings` file (which wins), never from a
/// project's settings: `(value, what to tell the operator)`. Nothing is reported from here, so a
/// diagnostic can read the same value quietly.
fn operator_number(home: &Path, key: &str, ceiling: i64, default: i64) -> (i64, Vec<String>) {
    if crate::bare_mode() {
        return (default, Vec::new());
    }
    let user = std::fs::read_to_string(home.join("settings.toml")).ok();
    let extra = orbit_tools::executor::extra_settings_file()
        .filter(|file| !orbit_tools::executor::is_json(file))
        .and_then(|file| read_bounded(&file));
    let mut value = default;
    let mut problems = Vec::new();
    for text in [user, extra].into_iter().flatten() {
        if let Some((setting, problem)) = number_setting(&text, key, ceiling, default) {
            value = setting;
            problems.extend(problem);
        }
    }
    (value, problems)
}

/// What one settings file says about a whole-number setting: `None` when it says nothing,
/// otherwise the value to use and, when it could not be taken as it stands, what to tell the
/// operator. Like `claude_compat`, the key counts only above the first `[table]`: TOML puts a key
/// below one inside that table.
fn number_setting(
    text: &str,
    key: &str,
    ceiling: i64,
    default: i64,
) -> Option<(i64, Option<String>)> {
    let mut at_top = true;
    let mut found = None;
    let mut under_table = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            at_top = false;
            continue;
        }
        let Some((name, raw)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != key {
            continue;
        }
        if at_top {
            found = Some(read_number(raw, key, ceiling, default));
        } else {
            under_table = true;
        }
    }
    found.or_else(|| {
        under_table.then(|| {
            (
                default,
                Some(format!(
                    "{key} is under a [table] in settings.toml, where it is not read; put it above the first [table]"
                )),
            )
        })
    })
}

/// The value after `=`: a whole number from 0 to the ceiling. Above it, the
/// ceiling; anything else, the default. Both come with what to tell the operator.
fn read_number(raw: &str, key: &str, ceiling: i64, default: i64) -> (i64, Option<String>) {
    let value = (raw.len() <= 4096)
        .then(|| toml::from_str::<toml::Table>(&format!("value = {}", raw.trim())).ok())
        .flatten()
        .and_then(|table| table.get("value").and_then(toml::Value::as_integer));
    match value {
        Some(n) if (0..=ceiling).contains(&n) => (n, None),
        Some(n) if n > ceiling => (
            ceiling,
            Some(format!(
                "{key} = {n} is above the largest allowed, {ceiling}; using that"
            )),
        ),
        _ => (
            default,
            Some(format!(
                "{key} must be a whole number from 0 to {ceiling}; the limit stays {default}"
            )),
        ),
    }
}

/// What one settings file says about the Stop limit (see [`number_setting`]).
#[cfg(test)]
fn stop_limit_setting(text: &str) -> Option<(u32, Option<String>)> {
    number_setting(
        text,
        STOP_LIMIT_KEY,
        i64::from(STOP_CONTINUATIONS_CEILING),
        i64::from(DEFAULT_STOP_CONTINUATIONS),
    )
    .map(|(value, problem)| {
        (
            u32::try_from(value).unwrap_or(DEFAULT_STOP_CONTINUATIONS),
            problem,
        )
    })
}

/// A blocking stop hook the turn did not obey: its continuations were used up,
/// or the turn was out of rounds. Without this the turn simply ends and the
/// operator cannot tell that the hook was overruled.
pub fn note_stop_hook_not_obeyed(continued: u32, limit: u32, max_rounds: u32) {
    note_hook_problem(if continued >= limit {
        format!(
            "a stop hook still asked the model to keep working after {continued} continuation{}; the limit is {limit}, so the turn ended ({STOP_LIMIT_KEY} in settings.toml raises it)",
            if continued == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "a stop hook still asked the model to keep working, but the turn had used its {max_rounds} rounds, so it ended"
        )
    });
}

pub fn claude_config_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR").filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    std::env::home_dir().map(|home| home.join(".claude"))
}

pub(crate) fn read_bounded(path: &Path) -> Option<String> {
    const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
    let meta = std::fs::metadata(path).ok()?;
    (meta.is_file() && meta.len() <= MAX_SETTINGS_BYTES)
        .then(|| std::fs::read_to_string(path).ok())
        .flatten()
}

/// Maximum number of handlers the Claude-compatible reader loads from one file.
pub const MAX_CLAUDE_HOOKS_PER_FILE: usize = 256;

/// The `hooks` object of a Claude Code `settings.json`:
/// `{"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
/// "command": "...", "timeout": 30}]}]}`. Unsupported or malformed handlers
/// are skipped. An event ORBIT never fires simply never runs.
pub fn parse_claude_settings(text: &str) -> Vec<HookConfig> {
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
                if out.len() == MAX_CLAUDE_HOOKS_PER_FILE {
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
                    origin: None,
                });
            }
        }
    }
    out
}

/// The session a hook belongs to, under the names the guards written for
/// Claude Code read: `CLAUDE_SESSION_ID`, `CLAUDE_CODE_SESSION_ID`, and
/// `ORBIT_SESSION_ID` for scripts written for ORBIT. It is the payload's
/// `session_id`, so a hook sees the same session in its environment as on
/// standard input. It replaces an inherited value: ORBIT started from another
/// agent's shell would otherwise hand its hooks that agent's session. An id
/// that is not a plain name is not exported, because scripts use it to name files.
fn session_environment(payload: &serde_json::Value) -> Vec<(&'static str, String)> {
    let Some(id) = payload
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| plain_session_id(id))
    else {
        return Vec::new();
    };
    [
        "CLAUDE_SESSION_ID",
        "CLAUDE_CODE_SESSION_ID",
        "ORBIT_SESSION_ID",
    ]
    .into_iter()
    .map(|name| (name, id.to_owned()))
    .collect()
}

/// Letters, digits, `-`, `_` and `.`, one to 128 of them, and not `.` or `..`.
fn plain_session_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && !matches!(id, "." | "..")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
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
    if let Some(origin) = &cfg.origin {
        // A plugin's hook finds its files and its own state folder here. The folder is private and
        // made when a hook first runs: looking at a plugin never creates it.
        {
            use std::os::unix::fs::DirBuilderExt;
            let _ = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&origin.data);
        }
        program
            .env("CLAUDE_PLUGIN_ROOT", &origin.root)
            .env("CLAUDE_PLUGIN_DATA", &origin.data)
            // A Python hook that imports a file beside it would write `__pycache__` into the
            // stored copy, which then no longer verifies and runs none of its hooks. The
            // bytecode goes to the plugin's own state folder instead.
            .env("PYTHONPYCACHEPREFIX", origin.data.join("pycache"));
    }
    let mut child = match program
        // Claude Code hooks locate their scripts through this variable.
        .envs(
            std::env::current_dir()
                .ok()
                .filter(|_| std::env::var_os("CLAUDE_PROJECT_DIR").is_none())
                .map(|cwd| ("CLAUDE_PROJECT_DIR", cwd)),
        )
        // Guards that keep state per session find the session here.
        .envs(session_environment(payload))
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
            // hookify, for one, explains a block only here. Claude Code shows
            // it to the person; here it is also what the model is told, so a block that says
            // why does not leave an empty reason behind.
            .or_else(|| text(&value, "systemMessage"))
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

/// What a hook that exits 0 and prints plain text means: the text is context, as in Claude
/// Code, unless it spoke JSON, decided something or already gave `additionalContext`.
fn lift_plain_output(outcomes: &[HookOutcome]) -> Vec<HookOutcome> {
    outcomes
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
        .collect()
}

/// What `hook_context_max_bytes` allows when the operator has not said.
pub const DEFAULT_HOOK_CONTEXT_BYTES: usize = 8 * 1024;

/// The most `hook_context_max_bytes` can allow: text hooks add to the model's context is
/// text the operator did not write, so there is a bound whatever the setting says.
pub const HOOK_CONTEXT_CEILING: usize = 256 * 1024;

const HOOK_CONTEXT_KEY: &str = "hook_context_max_bytes";

/// How much text hooks may add to the model's context at one event:
/// `hook_context_max_bytes`, a top-level key in the operator's own settings
/// (`$ORBIT_HOME/settings.toml`, then the `--settings` file, which wins), or 8 KiB; 0 means
/// hooks add none. A project's `.orbit/settings.toml` cannot raise it: the text is not the
/// operator's own, and this bound is what keeps one hook from filling the context. A value that
/// cannot be used keeps the default and is reported with the rest of the hook trouble.
pub fn hook_context_limit(home: &Path) -> usize {
    let (limit, problems) = context_limit_with_problems(home);
    problems.into_iter().for_each(note_load_problem);
    limit
}

/// The limit, and what to tell the operator about the setting, without telling anyone.
fn context_limit_with_problems(home: &Path) -> (usize, Vec<String>) {
    let (value, problems) = operator_number(
        home,
        HOOK_CONTEXT_KEY,
        HOOK_CONTEXT_CEILING as i64,
        DEFAULT_HOOK_CONTEXT_BYTES as i64,
    );
    (
        usize::try_from(value).unwrap_or(DEFAULT_HOOK_CONTEXT_BYTES),
        problems,
    )
}

/// What one settings file says about the limit (see [`number_setting`]).
#[cfg(test)]
fn context_limit_setting(text: &str) -> Option<(usize, Option<String>)> {
    number_setting(
        text,
        HOOK_CONTEXT_KEY,
        HOOK_CONTEXT_CEILING as i64,
        DEFAULT_HOOK_CONTEXT_BYTES as i64,
    )
    .map(|(value, problem)| {
        (
            usize::try_from(value).unwrap_or(DEFAULT_HOOK_CONTEXT_BYTES),
            problem,
        )
    })
}

/// A line for the front end to show once: trouble found while loading configuration. It shares
/// the channel hook trouble uses and is told once per process, because what it comes from (the
/// hooks, the prompt) loads again for every tool call and turn.
pub fn note_load_problem(text: String) {
    static TOLD: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(Default::default);
    let mut told = TOLD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if told.len() >= MAX_REMEMBERED_MATCHERS {
        told.clear();
    }
    if told.insert(text.clone()) {
        note_hook_problem(text);
    }
}

/// What hooks added to the model's context at one event, within a limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextCut {
    /// The limit that applied.
    pub limit: usize,
    /// What the hooks wanted to add, in all.
    pub total: usize,
    /// How much each hook that added anything wanted to add, in order.
    pub sizes: Vec<usize>,
}

/// The text hooks add to the model's context, and what the limit took from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedContext {
    pub text: Option<String>,
    pub cut: Option<ContextCut>,
}

/// Everything the hooks want the model to see, within `limit` bytes. What does not fit is cut at
/// a character boundary and the text ends in a line that says so, so the model is not left
/// believing it has the whole of it. A limit of 0 is the operator's choice: nothing is added and
/// nothing is said about it.
pub fn bounded_context(outcomes: &[HookOutcome], limit: usize) -> BoundedContext {
    let parts: Vec<&str> = outcomes
        .iter()
        .filter_map(|o| o.additional_context.as_deref())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .collect();
    if parts.is_empty() {
        return BoundedContext {
            text: None,
            cut: None,
        };
    }
    let joined = parts.join("\n");
    if joined.len() <= limit {
        return BoundedContext {
            text: Some(joined),
            cut: None,
        };
    }
    if limit == 0 {
        return BoundedContext {
            text: None,
            cut: None,
        };
    }
    let cut = ContextCut {
        limit,
        total: joined.len(),
        sizes: parts.iter().map(|part| part.len()).collect(),
    };
    // The marker is part of the limit; a limit too small for it just cuts.
    let marker = format!("\n… (hook context cut at {limit} bytes)");
    let room = if limit > marker.len() {
        limit - marker.len()
    } else {
        limit
    };
    let mut end = room;
    while !joined.is_char_boundary(end) {
        end -= 1;
    }
    let mut text = joined[..end].to_owned();
    if limit > marker.len() {
        text.push_str(&marker);
    }
    BoundedContext {
        text: Some(text),
        cut: Some(cut),
    }
}

/// Tell the operator, once per process, that the limit took some of what hooks added, and hand
/// back the text. Each hook's size is listed in the order the hooks ran: nothing else
/// identifies a hook here, and the order is the order of `/hooks`.
fn announce_context_cut(bounded: BoundedContext) -> Option<String> {
    static TOLD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if let Some(cut) = &bounded.cut
        && !TOLD.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        let sizes = cut
            .sizes
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        note_hook_problem(format!(
            "hook context was cut at {} bytes: {} hook{} wanted to add {} bytes ({sizes}, in the order they ran), so the later text is missing; {HOOK_CONTEXT_KEY} in settings.toml raises the limit",
            cut.limit,
            cut.sizes.len(),
            if cut.sizes.len() == 1 { "" } else { "s" },
            cut.total,
        ));
    }
    bounded.text
}

/// Decode one complete quoted TOML value without changing the legacy line grammar.
/// A malformed or unquoted value keeps its old interpretation at the call site;
/// a parse failure must not remove an operator's guard.
fn quoted_hook_setting(raw: &str) -> Option<String> {
    const MAX_QUOTED_BYTES: usize = 1024 * 1024;
    if raw.len() > MAX_QUOTED_BYTES || !raw.starts_with(['"', '\'']) {
        return None;
    }
    let parsed = toml::from_str::<toml::Table>(&format!("value = {raw}")).ok()?;
    if parsed.len() != 1 {
        return None;
    }
    parsed
        .get("value")
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
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
                origin: None,
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
            let decoded = quoted_hook_setting(raw);
            let value = decoded.as_deref().unwrap_or_else(|| raw.trim_matches('"'));
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
                                let legacy = raw.trim_matches('\'');
                                let parsed = match decoded.as_deref() {
                                    Some(text) => serde_json::from_str::<serde_json::Value>(text)
                                        .or_else(|_| serde_json::from_str(legacy)),
                                    None => serde_json::from_str(legacy),
                                };
                                if let Ok(parsed) = parsed
                                    && parsed.is_object()
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

    #[cfg(unix)]
    #[test]
    fn bare_mode_does_not_load_or_fire_hooks_across_threads() {
        const FIXTURE_DIR: &str = "ORBIT_BARE_HOOK_FIXTURE_DIR";
        if let Some(root) = std::env::var_os(FIXTURE_DIR) {
            let root = PathBuf::from(root);
            let latched = std::env::var("ORBIT_BARE_HOOK_FIXTURE_LATCH").as_deref() == Ok("1");
            let suppressed = std::env::var("ORBIT_BARE").as_deref() == Ok("1") || latched;
            // Construct hooks directly, as if they were loaded before the
            // process selected bare mode. Neither commands nor model/MCP
            // handlers may run, including on another worker thread.
            let command = format!(
                "printf ran > '{}'",
                root.join("preloaded.marker")
                    .display()
                    .to_string()
                    .replace('\'', "'\\''")
            );
            let preloaded = Hooks {
                hooks: vec![
                    serde_json::from_value(serde_json::json!({
                        "event":"Stop", "command":command,
                    }))
                    .unwrap(),
                    serde_json::from_value(serde_json::json!({
                        "event":"Stop", "command":"",
                        "handler":{"type":"prompt", "prompt":"fixture runner"},
                    }))
                    .unwrap(),
                ],
                project_trusted: true,
                context_limit: None,
            };
            let runner_marker = root.join("handler.marker");
            set_handler_runner(Some(std::sync::Arc::new(move |_, _| {
                std::fs::write(&runner_marker, "ran").unwrap();
                HookOutcome::default()
            })));
            if latched {
                assert!(!crate::bare_mode());
                crate::enable_bare_mode();
                crate::enable_bare_mode();
            }
            assert_eq!(crate::bare_mode(), suppressed);
            let loaded = Hooks::load(&root.join("home"), true);
            assert_eq!(loaded.hooks.len(), if suppressed { 0 } else { 4 });
            let (loaded_outcomes, preloaded_outcomes) = std::thread::spawn(move || {
                (
                    loaded.fire(HookEvent::Stop, &serde_json::json!({})),
                    preloaded.fire(HookEvent::Stop, &serde_json::json!({})),
                )
            })
            .join()
            .unwrap();
            assert_eq!(loaded_outcomes.len(), if suppressed { 0 } else { 4 });
            assert_eq!(preloaded_outcomes.len(), if suppressed { 0 } else { 2 });
            for outcome in loaded_outcomes.iter().chain(&preloaded_outcomes) {
                assert_eq!(outcome.exit_code, 0, "{}", outcome.stderr);
            }
            for marker in [
                "native",
                "project",
                "extra",
                "claude",
                "preloaded",
                "handler",
            ] {
                assert_eq!(
                    root.join(format!("{marker}.marker")).exists(),
                    !suppressed,
                    "{marker}"
                );
            }
            return;
        }

        struct FixtureDir(PathBuf);
        impl Drop for FixtureDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture = FixtureDir(test_dir(&format!("bare-{nonce}")));
        for mode in ["full", "env", "latched"] {
            let root = fixture.0.join(mode);
            let project = root.join("project");
            for directory in [
                root.join("home"),
                root.join("claude"),
                project.join(".orbit"),
            ] {
                std::fs::create_dir_all(directory).unwrap();
            }
            let command = |marker: &str| {
                format!(
                    "printf ran > '{}'",
                    root.join(format!("{marker}.marker"))
                        .display()
                        .to_string()
                        .replace('\'', "'\\''")
                )
            };
            let settings = |marker: &str| {
                format!(
                    "[[hooks]]\nevent = \"Stop\"\ncommand = {}\n",
                    serde_json::to_string(&command(marker)).unwrap()
                )
            };
            std::fs::write(root.join("home/settings.toml"), settings("native")).unwrap();
            std::fs::write(project.join(".orbit/settings.toml"), settings("project")).unwrap();
            std::fs::write(root.join("extra.toml"), settings("extra")).unwrap();
            std::fs::write(
                root.join("claude/settings.json"),
                serde_json::to_vec(&serde_json::json!({
                    "hooks":{"Stop":[{"hooks":[{"type":"command", "command":command("claude")}]}]},
                }))
                .unwrap(),
            )
            .unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "hooks::tests::bare_mode_does_not_load_or_fire_hooks_across_threads",
                    "--nocapture",
                ])
                .current_dir(&project)
                .env(FIXTURE_DIR, &root)
                .env("ORBIT_BARE", if mode == "env" { "1" } else { "0" })
                .env(
                    "ORBIT_BARE_HOOK_FIXTURE_LATCH",
                    if mode == "latched" { "1" } else { "0" },
                )
                .env("ORBIT_CLAUDE_COMPAT", "1")
                .env("CLAUDE_CONFIG_DIR", root.join("claude"))
                .env("ORBIT_SETTINGS_FILE", root.join("extra.toml"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "mode={mode}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

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
            origin: None,
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
            origin: None,
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
            origin: None,
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
                origin: None,
            }],
            project_trusted: true,
            context_limit: None,
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

    /// The matchers the operator registered in Claude Code, and ones plugins ship, against
    /// the names each must and must not accept. Claude Code searches a regular expression
    /// anywhere in the name (`new RegExp(matcher).test(name)`), so `^…$` pins one.
    #[test]
    fn regular_expression_matchers_are_searched_anywhere_like_claude_codes() {
        const EGRESS: &str = "WebSearch|WebFetch|mcp__.*(exa|tavily|nimble|brightdata|firecrawl)";
        const SOURCES: &str = "^(startup|resume|clear|compact|fork)$";
        const MEMORY: &str = "Read|^read_file$|^Bash$|^Grep$|^Glob$|^memory_search$|^memory$|^mcp__.+__memory_search$";
        const COMMAND: &str = "^claude-security:claude-security$";
        for (matcher, subject, expected) in [
            (EGRESS, "WebSearch", true),
            (EGRESS, "WebFetch", true),
            (EGRESS, "mcp__tavily__tavily_search", true),
            (EGRESS, "mcp__plugin_exa_exa__web_search_exa", true),
            (EGRESS, "mcp__firecrawl__firecrawl_scrape", true),
            (EGRESS, "mcp__serena__find_symbol", false),
            (EGRESS, "Bash", false),
            (EGRESS, "Write", false),
            (SOURCES, "startup", true),
            (SOURCES, "resume", true),
            (SOURCES, "clear", true),
            (SOURCES, "compact", true),
            (SOURCES, "fork", true),
            (SOURCES, "restart", false),
            (SOURCES, "startup2", false),
            (SOURCES, "pre-startup", false),
            (MEMORY, "Read", true),
            (MEMORY, "Bash", true),
            (MEMORY, "Grep", true),
            (MEMORY, "read_file", true),
            (MEMORY, "mcp__mempalace__memory_search", true),
            (MEMORY, "Write", false),
            // `^Bash$` is pinned, a bare `Read` is searched anywhere.
            (MEMORY, "BashOutput", false),
            (MEMORY, "NotebookRead", true),
            (COMMAND, "claude-security:claude-security", true),
            (COMMAND, "claude-security:threat-model", false),
            // Anchors, groups and case.
            ("^Notebook", "NotebookEdit", true),
            ("^Notebook", "MyNotebook", false),
            ("Edit$", "NotebookEdit", true),
            ("(Bash|Edit)", "NotebookEdit", true),
            ("^bash$", "Bash", false),
            ("^[A-Z][a-z]+$", "Bash", true),
            ("^[A-Z][a-z]+$", "mcp__x", false),
            // A Unicode class is a big program (about 50 KB each): ordinary patterns with several fit.
            (r"^mcp__\w+__\w+$", "mcp__tavily__search", true),
            (r"^mcp__\w+__\w+$", "mcp__tavily", false),
            (r"^\w+\w+\w+\w+\w+\w+$", "NotebookEdit", true),
            (r"^\w+\w+\w+\w+\w+\w+$", "Bash", false),
        ] {
            assert_eq!(
                matcher_accepts(Some(matcher), Some(subject)),
                expected,
                "{matcher:?} against {subject}"
            );
        }
    }

    /// A character only a regular expression uses turns the reading on; the characters of a
    /// plain name list (and `.`, `*`, `,`, `|`) do not, so those lists are not searched.
    #[test]
    fn only_regular_expression_characters_turn_the_regular_expression_reading_on() {
        for c in ['^', '$', '(', ')', '[', ']', '{', '}', '+', '?', '\\'] {
            assert!(is_regex_matcher(&format!("a{c}b")), "{c:?}");
        }
        for c in [
            '.', '*', '|', ',', ' ', '-', '_', ':', '/', '@', '#', '%', '~', '!', '&', '=', '<',
            '>', ';', '\'', '"', 'x', '7',
        ] {
            assert!(!is_regex_matcher(&format!("a{c}b")), "{c:?}");
        }
        assert!(!is_regex_matcher("mcp__*tavily*"));
        assert!(!is_regex_matcher("Web.*|Edit"));
        assert!(
            is_regex_matcher("  ^Bash$  "),
            "the matcher is trimmed first"
        );
        // The same, seen from matching: each of these needs the regular-expression reading.
        for (matcher, subject) in [
            ("^Bash", "BashOutput"),
            ("Bash$", "XBash"),
            ("(Bash)", "XBashY"),
            ("Ba[s]h", "Bash"),
            ("Bas{1}h", "Bash"),
            ("Ba+sh", "Baash"),
            ("Bas?h", "Bah"),
            (r"Notebook\w+", "NotebookEdit"),
            ("Bash]", "XBash]Y"),
            ("Bash}", "XBash}Y"),
        ] {
            assert!(
                matcher_accepts(Some(matcher), Some(subject)),
                "{matcher:?} against {subject}"
            );
        }
    }

    /// Nothing that matched before stops matching, and a plain list is still compared whole.
    #[test]
    fn a_plain_name_list_is_read_as_before_and_literal_names_still_match_themselves() {
        for (matcher, subject, expected) in [
            ("Bash", "BashOutput", false),
            ("Edit|Write", "NotebookEdit", false),
            ("Edit,Write", "Write", true),
            ("Edit, Write", "Read", false),
            ("Web*", "WebFetch", true),
            ("Web*", "Write", false),
            ("Web.*", "WebSearch", true),
            ("mcp__*tavily*", "mcp__tavily__tavily_search", true),
            ("*tavily*", "mcp__exa__search", false),
            ("*Edit", "NotebookEdit", true),
            (".*", "Anything", true),
            ("  Bash  ", "Bash", true),
            // A name that happens to contain regular-expression characters matches itself.
            ("[id].tsx", "[id].tsx", true),
            ("claude-opus-5-5[1m]", "claude-opus-5-5[1m]", true),
            ("file(1).txt", "file(1).txt", true),
            ("c++", "c++", true),
            ("what?", "what?", true),
            ("a$b", "a$b", true),
            // ... even half written, where it is not a regular expression at all.
            ("file[1.txt", "file[1.txt", true),
            ("file[1.txt", "other.txt", false),
        ] {
            assert_eq!(
                matcher_accepts(Some(matcher), Some(subject)),
                expected,
                "{matcher:?} against {subject}"
            );
        }
    }

    #[test]
    fn a_pattern_that_is_not_a_regular_expression_says_why_and_matches_only_its_plain_names() {
        for (matcher, reason) in [
            ("mcp__.*(exa", "unclosed group"),
            ("Bash)", "unopened group"),
            ("Bash[", "unclosed character class"),
            ("^(?!Bash)", "look-around"),
            (r"(Bash)\1", "backreference"),
            ("a{2,1}", "repetition"),
        ] {
            let problem = matcher_problem(matcher)
                .unwrap_or_else(|| panic!("{matcher:?} is not a regular expression"));
            assert!(problem.contains(reason), "{matcher:?}: {problem}");
            assert!(!problem.contains('\n'), "one line: {problem:?}");
        }
        for fine in [
            "",
            "*",
            "Bash",
            "Edit|Write",
            "Edit, Write",
            "mcp__*tavily*",
            "*Edit",
            "Web.*",
            "^(startup|resume)$",
            "[id].tsx",
            "claude-opus-5-5[1m]",
        ] {
            assert_eq!(matcher_problem(fine), None, "{fine:?}");
        }
        // Bounds: a runaway pattern cannot make a matcher expensive. The size limit is ours, not
        // the library's (10 MiB): a program of a few megabytes is refused, one of a few hundred
        // kilobytes is not.
        let long = format!("^({})$", "a".repeat(1100));
        assert!(matcher_problem(&long).unwrap().contains("longer than"));
        let big =
            matcher_problem("((a{100}){100}){10}").expect("a multi-megabyte program is refused");
        assert!(big.contains(&REGEX_MATCHER_SIZE_LIMIT.to_string()), "{big}");
        assert_eq!(matcher_problem("(a{100}){100}"), None);
        // What is left of a broken pattern: its plain names.
        assert!(!matcher_accepts(
            Some("mcp__.*(exa"),
            Some("mcp__exa__search")
        ));
        assert!(matcher_accepts(Some("Read|mcp__.*(exa"), Some("Read")));
        assert!(!matcher_accepts(Some("Read|mcp__.*(exa"), Some("Write")));
    }

    /// The forms an operator writes a pattern in reach the matcher unchanged, and a hook
    /// registered the way Claude Code takes it runs for the names it means.
    #[test]
    fn regular_expression_hooks_load_from_toml_and_claude_settings_and_fire() {
        for quoted in [
            r#""^tool\\d+$""#,
            r"'^tool\d+$'",
            // Not valid TOML ("\d"), kept as written rather than dropping the guard.
            r#""^tool\d+$""#,
        ] {
            let hooks = parse_hooks_toml(&format!(
                "[[hooks]]\nevent = \"PreToolUse\"\nmatcher = {quoted}\ncommand = \"echo no >&2; exit 2\"\n"
            ));
            assert_eq!(hooks[0].matcher.as_deref(), Some(r"^tool\d+$"), "{quoted}");
            let hooks = Hooks {
                hooks,
                project_trusted: false,
                context_limit: None,
            };
            let fires = |tool: &str| {
                blocked(&hooks.fire(
                    HookEvent::PreToolUse,
                    &serde_json::json!({"tool": tool, "arguments": {}}),
                ))
                .is_some()
            };
            assert!(fires("tool42"), "{quoted}");
            assert!(!fires("tool"), "{quoted}");
            assert!(!fires("xtool42"), "{quoted}");
        }

        let hooks = Hooks {
            hooks: parse_claude_settings(
                r#"{"hooks": {
                  "PreToolUse": [{"matcher": "WebSearch|WebFetch|mcp__.*(exa|tavily|nimble|brightdata|firecrawl)",
                    "hooks": [{"type": "command", "command": "echo egress >&2; exit 2"}]}],
                  "SessionStart": [{"matcher": "^(startup|resume|clear|compact|fork)$",
                    "hooks": [{"type": "command", "command": "echo started"}]}]
                }}"#,
            ),
            project_trusted: false,
            context_limit: None,
        };
        let stopped = |tool: &str| {
            blocked(&hooks.fire(
                HookEvent::PreToolUse,
                &serde_json::json!({"tool": tool, "arguments": {}}),
            ))
            .is_some()
        };
        assert!(stopped("mcp__tavily__tavily_search"));
        assert!(stopped("WebFetch"));
        assert!(!stopped("mcp__serena__find_symbol"));
        assert!(!stopped("Bash"));
        let started = |source: &str| {
            hooks
                .fire(
                    HookEvent::SessionStart,
                    &serde_json::json!({"source": source, "frontend": "headless"}),
                )
                .len()
        };
        assert_eq!(started("startup"), 1);
        assert_eq!(started("fork"), 1);
        assert_eq!(started("restart"), 0);
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
                origin: None,
            }],
            project_trusted: true,
            context_limit: None,
        };
        let outcomes = hooks.fire(
            HookEvent::PreToolUse,
            &serde_json::json!({ "tool": "Bash", "arguments": { "command": "ls" } }),
        );
        assert_eq!(outcomes[0].exit_code, 2, "tool_name reached the hook");
    }

    #[test]
    fn native_quoted_values_decode_without_dropping_legacy_hook_guards() {
        assert_eq!(
            quoted_hook_setting(r#""a\"b\\c\n\t\u0041\U0001F600""#).as_deref(),
            Some("a\"b\\c\n\tA😀")
        );
        assert_eq!(quoted_hook_setting(r#"'a\b\n'"#).as_deref(), Some(r"a\b\n"));
        for invalid in [
            "echo unquoted",
            "\"quoted\" trailing",
            "\"quoted\"\nother = 1",
        ] {
            assert!(quoted_hook_setting(invalid).is_none(), "{invalid}");
        }
        let hooks = parse_hooks_toml(
            r#"
[[hooks]]
event = "PreToolUse"
command = "printf \"quoted\"; printf 'one\\two\nnext'; exit 2"
matcher = "R\u0065ad"
if = "Read(./src\\*)"
[[hooks]]
event = 'PostToolUse'
command = 'printf "\n"; exit 2'
[[hooks]]
event = Stop
command = echo legacy >&2; exit 2
[[hooks]]
event = "Stop"
command = "echo incomplete >&2; exit 2
[[hooks]]
event = "Stop"
mcp_server = "scanner"
mcp_tool = "scan"
mcp_input = "{\"path\":\"C:\\\\tmp\"}"
mcp_input = "{"allow":false}"
[[hooks]]
event = "Stop"
mcp_server = "scanner-bad"
mcp_tool = "scan"
mcp_input = "{"allow":false}"
"#,
        );
        assert_eq!(hooks.len(), 6);
        assert_eq!(hooks[0].event, "PreToolUse");
        assert_eq!(
            hooks[0].command,
            "printf \"quoted\"; printf 'one\\two\nnext'; exit 2"
        );
        assert_eq!(hooks[0].matcher.as_deref(), Some("Read"));
        assert_eq!(hooks[0].condition.as_deref(), Some(r"Read(./src\*)"));
        assert_eq!(hooks[1].event, "PostToolUse");
        assert_eq!(hooks[1].command, r#"printf "\n"; exit 2"#);
        assert_eq!(hooks[2].event, "Stop");
        assert_eq!(hooks[2].command, "echo legacy >&2; exit 2");
        assert_eq!(hooks[3].event, "Stop");
        assert_eq!(hooks[3].command, "echo incomplete >&2; exit 2");
        assert!(matches!(
            hooks[4].handler.as_ref(),
            Some(HookHandler::McpTool { server, tool, input })
                if server == "scanner" && tool == "scan"
                    && input["path"] == r"C:\tmp" && input.get("allow").is_none()
        ));
        assert!(matches!(
            hooks[5].handler.as_ref(),
            Some(HookHandler::McpTool { server, tool, input })
                if server == "scanner-bad" && tool == "scan" && input == &serde_json::json!({})
        ));
        let oversized = format!("\"{}; exit 2\"", "x".repeat(1024 * 1024));
        assert!(quoted_hook_setting(&oversized).is_none());
        let retained = parse_hooks_toml(&format!(
            "[[hooks]]\nevent = \"Stop\"\ncommand = {oversized}\n"
        ));
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].command, oversized.trim_matches('"'));
        let guards = Hooks {
            hooks: hooks[2..4].to_vec(),
            project_trusted: false,
            context_limit: None,
        };
        assert_eq!(guards.matching(HookEvent::Stop, None).len(), 2);
    }

    #[test]
    fn a_deny_with_no_reason_takes_the_system_message_as_its_reason() {
        // hookify, for one, explains a block only in `systemMessage`.
        let hookify = parse_output(
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"},"systemMessage":"Dangerous rm"}"#,
        );
        assert!(
            matches!(hookify.0, Some(HookDecision::Deny { reason }) if reason == "Dangerous rm")
        );
        let stop = parse_output(r#"{"decision":"block","systemMessage":"keep going"}"#);
        assert!(matches!(stop.0, Some(HookDecision::Deny { reason }) if reason == "keep going"));
        let ask = parse_output(
            r#"{"hookSpecificOutput":{"permissionDecision":"ask"},"systemMessage":"sure?"}"#,
        );
        assert!(matches!(ask.0, Some(HookDecision::Ask { reason }) if reason == "sure?"));
        // A reason the hook gave wins over the message.
        let both = parse_output(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"R"},"systemMessage":"M"}"#,
        );
        assert!(matches!(both.0, Some(HookDecision::Deny { reason }) if reason == "R"));
        // A message alone decides nothing, and a deny with neither still has no reason.
        assert!(parse_output(r#"{"systemMessage":"careful"}"#).0.is_none());
        let bare = parse_output(r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#);
        assert!(matches!(bare.0, Some(HookDecision::Deny { reason }) if reason.is_empty()));
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
        assert_eq!(
            Hooks::default().added_context(&outcomes).as_deref(),
            Some("one\ntwo")
        );
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
        assert_eq!(
            Hooks::default().prompt_context(&printed).as_deref(),
            Some("agent id: a1")
        );
        assert_eq!(Hooks::default().added_context(&printed), None);
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
                handler: None, origin: None,
            }],
            project_trusted: true,
            context_limit: None,
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
                origin: None,
            }],
            project_trusted: true,
            context_limit: None,
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
            origin: None,
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
            origin: None,
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
            context_limit: None,
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
            context_limit: None,
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
            origin: None,
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
    fn a_hook_is_told_which_session_it_belongs_to() {
        let dir = test_dir("session-environment");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let seen = dir.join("seen");
        let cfg = HookConfig {
            event: "PreToolUse".into(),
            command: format!(
                "printf '%s|%s|%s' \"$CLAUDE_SESSION_ID\" \"$CLAUDE_CODE_SESSION_ID\" \"$ORBIT_SESSION_ID\" > '{}'",
                seen.display()
            ),
            timeout_secs: Some(10),
            matcher: None,
            condition: None,
            run_async: false,
            http: None,
            handler: None,
            origin: None,
        };
        let id = "session-01JTESTSESSIONENVIRONMENT";
        run_hook(&cfg, &serde_json::json!({ "session_id": id }));
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap(),
            format!("{id}|{id}|{id}"),
            "a guard that reads CLAUDE_SESSION_ID gets ORBIT's session, never an inherited one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_plain_session_id_reaches_a_hooks_environment() {
        let exported = |id: &str| {
            session_environment(&serde_json::json!({ "session_id": id }))
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            exported("session-01J9.x_y"),
            [
                "CLAUDE_SESSION_ID=session-01J9.x_y",
                "CLAUDE_CODE_SESSION_ID=session-01J9.x_y",
                "ORBIT_SESSION_ID=session-01J9.x_y"
            ]
        );
        // Scripts name files after the id, so nothing path-like gets through.
        for bad in ["", ".", "..", "a/b", "../x", "a b", "a\nb", "x;y", "é"] {
            assert!(exported(bad).is_empty(), "{bad:?}");
        }
        assert!(exported(&"a".repeat(129)).is_empty());
        assert!(!exported(&"a".repeat(128)).is_empty());
        assert!(session_environment(&serde_json::json!({})).is_empty());
        assert!(session_environment(&serde_json::json!({ "session_id": 7 })).is_empty());
    }

    #[test]
    fn the_stop_limit_is_read_from_the_top_of_a_settings_file() {
        assert_eq!(stop_limit_setting(""), None);
        assert_eq!(stop_limit_setting("claude_compat = true\n"), None);
        for (text, limit) in [
            ("stop_hook_max_continuations = 7\n", 7),
            (
                "# mine\n  stop_hook_max_continuations=12 # plenty\n[[hooks]]\n",
                12,
            ),
            ("stop_hook_max_continuations = 0\n", 0),
            ("stop_hook_max_continuations = 1_000\n", 1000),
            // The last one wins, as in TOML tooling that tolerates repeats.
            (
                "stop_hook_max_continuations = 2\nstop_hook_max_continuations = 5\n",
                5,
            ),
            // A stray copy below a table does not shadow the real one.
            (
                "stop_hook_max_continuations = 4\n[x]\nstop_hook_max_continuations = 9\n",
                4,
            ),
        ] {
            assert_eq!(stop_limit_setting(text), Some((limit, None)), "{text:?}");
        }
    }

    #[test]
    fn a_limit_above_the_ceiling_is_lowered_and_one_that_is_no_number_is_not_used() {
        let (limit, problem) = stop_limit_setting("stop_hook_max_continuations = 5000\n").unwrap();
        assert_eq!(limit, STOP_CONTINUATIONS_CEILING);
        assert!(problem.unwrap().contains("5000"));
        for bad in ["-1", "2.5", "\"many\"", "true", "[3]", "", "1001e0"] {
            let (limit, problem) =
                stop_limit_setting(&format!("stop_hook_max_continuations = {bad}\n")).unwrap();
            assert_eq!(limit, DEFAULT_STOP_CONTINUATIONS, "{bad:?}");
            assert!(problem.unwrap().contains("whole number"), "{bad:?}");
        }
    }

    #[test]
    fn a_limit_under_a_table_is_not_read_and_the_operator_is_told() {
        let (limit, problem) = stop_limit_setting(
            "[[hooks]]\nevent = \"Stop\"\ncommand = \"x\"\nstop_hook_max_continuations = 9\n",
        )
        .unwrap();
        assert_eq!(limit, DEFAULT_STOP_CONTINUATIONS);
        assert!(problem.unwrap().contains("under a [table]"));
    }

    #[test]
    fn the_stop_limit_comes_from_the_homes_settings_and_is_three_without_one() {
        let home = test_dir("stop-limit-home");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        assert_eq!(stop_continuation_limit(&home), DEFAULT_STOP_CONTINUATIONS);
        assert_eq!(DEFAULT_STOP_CONTINUATIONS, 3);
        std::fs::write(
            home.join("settings.toml"),
            "stop_hook_max_continuations = 40\n[[hooks]]\nevent = \"Stop\"\ncommand = \"true\"\n",
        )
        .unwrap();
        assert_eq!(stop_continuation_limit(&home), 40);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn only_the_operators_own_settings_set_the_stop_limit() {
        const FIXTURE_DIR: &str = "ORBIT_STOP_LIMIT_FIXTURE_DIR";
        const WANT: &str = "ORBIT_STOP_LIMIT_FIXTURE_WANT";
        if let Some(root) = std::env::var_os(FIXTURE_DIR) {
            // The child process, started inside a project directory.
            let want: u32 = std::env::var(WANT).unwrap().parse().unwrap();
            assert_eq!(
                stop_continuation_limit(&PathBuf::from(root).join("home")),
                want
            );
            return;
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = test_dir(&format!("stop-limit-scope-{nonce}"));
        let project = root.join("project");
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(project.join(".orbit")).unwrap();
        // A repository asking for a lot, in the folder the process runs in.
        std::fs::write(
            project.join(".orbit/settings.toml"),
            "stop_hook_max_continuations = 500\n",
        )
        .unwrap();
        std::fs::write(
            root.join("extra.toml"),
            "stop_hook_max_continuations = 25\n",
        )
        .unwrap();
        for (home, extra, want) in [
            // The project cannot raise it.
            (None, None, 3),
            // The operator's own settings do.
            (Some(8), None, 8),
            // A `--settings` file is the operator's too, and wins for that run.
            (Some(8), Some("extra.toml"), 25),
        ] {
            let settings = root.join("home/settings.toml");
            match home {
                Some(limit) => std::fs::write(
                    &settings,
                    format!("stop_hook_max_continuations = {limit}\n"),
                )
                .unwrap(),
                None => {
                    let _ = std::fs::remove_file(&settings);
                }
            }
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "hooks::tests::only_the_operators_own_settings_set_the_stop_limit",
                    "--nocapture",
                ])
                .current_dir(&project)
                .env(FIXTURE_DIR, &root)
                .env(WANT, want.to_string())
                .env_remove("ORBIT_BARE")
                .env_remove("ORBIT_SETTINGS_FILE");
            if let Some(extra) = extra {
                child.env("ORBIT_SETTINGS_FILE", root.join(extra));
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "home={home:?} extra={extra:?}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- hook_context_max_bytes: how much text hooks may add to the model's context ----

    #[test]
    fn the_context_limit_setting_is_read_like_the_stop_limit() {
        for (text, want) in [
            ("hook_context_max_bytes = 65536\n", 65_536),
            (
                "# mine\n  hook_context_max_bytes=20_000 # plenty\n[[hooks]]\n",
                20_000,
            ),
            ("hook_context_max_bytes = 0\n", 0),
            (
                "hook_context_max_bytes = 2\nhook_context_max_bytes = 4096\n",
                4096,
            ),
            (
                "hook_context_max_bytes = 4\n[x]\nhook_context_max_bytes = 9\n",
                4,
            ),
        ] {
            let (limit, problem) = context_limit_setting(text).expect(text);
            assert_eq!(limit, want, "{text}");
            assert!(problem.is_none(), "{text}: {problem:?}");
        }
        assert!(context_limit_setting("stop_hook_max_continuations = 4\n").is_none());
        assert!(context_limit_setting("").is_none());
        // A hook's own table can hold a key of the same name; it is not the setting.
        assert!(
            context_limit_setting("[[hooks]]\nevent = \"Stop\"\nhook_context_max_bytes = 9\n")
                .is_some_and(
                    |(limit, problem)| limit == DEFAULT_HOOK_CONTEXT_BYTES && problem.is_some()
                )
        );
    }

    #[test]
    fn a_context_limit_that_cannot_be_used_is_reported_and_keeps_the_default() {
        let (limit, problem) = context_limit_setting("hook_context_max_bytes = 5000000\n").unwrap();
        assert_eq!(limit, HOOK_CONTEXT_CEILING);
        assert!(problem.unwrap().contains("above the largest allowed"));
        for bad in ["\"lots\"", "-1", "1.5", "true", "[1]"] {
            let (limit, problem) =
                context_limit_setting(&format!("hook_context_max_bytes = {bad}\n")).unwrap();
            assert_eq!(limit, DEFAULT_HOOK_CONTEXT_BYTES, "{bad}");
            assert!(
                problem.is_some_and(
                    |p| p.contains("hook_context_max_bytes") && p.contains("whole number")
                ),
                "{bad}"
            );
        }
        let (limit, problem) = context_limit_setting("[x]\nhook_context_max_bytes = 9\n").unwrap();
        assert_eq!(limit, DEFAULT_HOOK_CONTEXT_BYTES);
        assert!(problem.unwrap().contains("above the first [table]"));
    }

    #[test]
    fn the_context_limit_comes_from_the_homes_settings_and_travels_with_the_hooks() {
        let home = test_dir("context-limit-home");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        assert_eq!(hook_context_limit(&home), DEFAULT_HOOK_CONTEXT_BYTES);
        assert_eq!(DEFAULT_HOOK_CONTEXT_BYTES, 8 * 1024);
        assert_eq!(HOOK_CONTEXT_CEILING, 256 * 1024);
        std::fs::write(
            home.join("settings.toml"),
            "hook_context_max_bytes = 65536\n[[hooks]]\nevent = \"SessionStart\"\ncommand = \"true\"\n",
        )
        .unwrap();
        assert_eq!(hook_context_limit(&home), 65_536);
        assert_eq!(Hooks::inspect(&home, None).context_limit(), 65_536);
        assert_eq!(Hooks::default().context_limit(), DEFAULT_HOOK_CONTEXT_BYTES);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn only_the_operators_own_settings_set_the_context_limit() {
        const FIXTURE_DIR: &str = "ORBIT_CONTEXT_LIMIT_FIXTURE_DIR";
        const WANT: &str = "ORBIT_CONTEXT_LIMIT_FIXTURE_WANT";
        if let Some(root) = std::env::var_os(FIXTURE_DIR) {
            let want: usize = std::env::var(WANT).unwrap().parse().unwrap();
            assert_eq!(hook_context_limit(&PathBuf::from(root).join("home")), want);
            return;
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = test_dir(&format!("context-limit-scope-{nonce}"));
        let project = root.join("project");
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(project.join(".orbit")).unwrap();
        // A repository asking for a lot, in the folder the process runs in.
        std::fs::write(
            project.join(".orbit/settings.toml"),
            "hook_context_max_bytes = 200000\n",
        )
        .unwrap();
        std::fs::write(root.join("extra.toml"), "hook_context_max_bytes = 100000\n").unwrap();
        for (home, extra, want) in [
            (None, None, DEFAULT_HOOK_CONTEXT_BYTES),
            (Some(65_536), None, 65_536),
            (Some(65_536), Some("extra.toml"), 100_000),
        ] {
            let settings = root.join("home/settings.toml");
            match home {
                Some(limit) => {
                    std::fs::write(&settings, format!("hook_context_max_bytes = {limit}\n"))
                        .unwrap()
                }
                None => {
                    let _ = std::fs::remove_file(&settings);
                }
            }
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "hooks::tests::only_the_operators_own_settings_set_the_context_limit",
                    "--nocapture",
                ])
                .current_dir(&project)
                .env(FIXTURE_DIR, &root)
                .env(WANT, want.to_string())
                .env_remove("ORBIT_BARE")
                .env_remove("ORBIT_SETTINGS_FILE");
            if let Some(extra) = extra {
                child.env("ORBIT_SETTINGS_FILE", root.join(extra));
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "home={home:?} extra={extra:?}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    fn context_from(text: &str) -> HookOutcome {
        HookOutcome {
            additional_context: Some(text.into()),
            ..HookOutcome::default()
        }
    }

    #[test]
    fn text_over_the_limit_is_cut_with_a_marker_and_described() {
        let outcomes = vec![
            context_from(&"a".repeat(6000)),
            context_from(&"b".repeat(5000)),
            context_from(&"Z".repeat(400)),
        ];
        let bounded = bounded_context(&outcomes, 8192);
        let text = bounded.text.expect("something fits");
        assert!(text.len() <= 8192, "{} bytes", text.len());
        assert!(text.starts_with(&"a".repeat(6000)));
        assert!(
            text.contains('b') && !text.contains('Z'),
            "the third hook did not fit"
        );
        assert!(text.ends_with("(hook context cut at 8192 bytes)"), "{text}");
        let cut = bounded.cut.expect("a cut is described");
        assert_eq!(cut.limit, 8192);
        assert_eq!(cut.sizes, [6000, 5000, 400]);
        assert_eq!(cut.total, 6000 + 1 + 5000 + 1 + 400);
    }

    #[test]
    fn text_within_the_limit_is_untouched() {
        let outcomes = vec![
            context_from("one"),
            context_from(" two "),
            HookOutcome::default(),
        ];
        let bounded = bounded_context(&outcomes, 8192);
        assert_eq!(bounded.text.as_deref(), Some("one\ntwo"));
        assert_eq!(bounded.cut, None);
        // Exactly at the limit is within it.
        assert_eq!(bounded_context(&outcomes, 7).cut, None);
        assert!(bounded_context(&outcomes, 6).cut.is_some());
    }

    #[test]
    fn a_context_cut_never_lands_inside_a_character() {
        let outcomes = vec![context_from(&"—".repeat(5000))];
        for limit in [8192, 8193, 8194, 100, 101, 102, 40, 41, 42] {
            let text = bounded_context(&outcomes, limit)
                .text
                .expect("fits in part");
            assert!(text.len() <= limit, "limit {limit}: {} bytes", text.len());
            assert!(text.starts_with('—'), "limit {limit}");
        }
    }

    #[test]
    fn a_limit_of_zero_adds_nothing_and_says_nothing() {
        let bounded = bounded_context(&[context_from("anything")], 0);
        assert_eq!(bounded.text, None);
        assert_eq!(
            bounded.cut, None,
            "the operator chose this; no notice every prompt"
        );
    }

    #[test]
    fn plain_output_counts_as_context_within_the_hooks_own_limit() {
        let hooks = Hooks {
            context_limit: Some(40),
            ..Hooks::default()
        };
        let printed = vec![HookOutcome {
            stdout: format!("{}\n", "x".repeat(200)),
            ..HookOutcome::default()
        }];
        let text = hooks
            .prompt_context(&printed)
            .expect("plain output is context");
        assert!(text.len() <= 40, "{} bytes", text.len());
        assert!(text.ends_with("(hook context cut at 40 bytes)"), "{text}");
        assert!(
            Hooks::default()
                .prompt_context(&printed)
                .is_some_and(|text| text.len() <= 8192)
        );
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
            origin: None,
        };
        let hooks = Hooks {
            hooks: vec![
                hook("sleep 5; exit 2", None, true),
                hook("exit 2", Some("Bash(rm *)"), false),
                hook("echo ran", Some("Bash(ls*)"), false),
            ],
            project_trusted: false,
            context_limit: None,
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

    /// An async hook that records what it was sent, after a pause: the shape of a hook that is
    /// still starting when the process that fired it is ready to end.
    fn recording_async_hook(command: String) -> Hooks {
        Hooks {
            hooks: vec![HookConfig {
                event: "SessionEnd".into(),
                command,
                timeout_secs: Some(20),
                matcher: None,
                condition: None,
                run_async: true,
                http: None,
                handler: None,
                origin: None,
            }],
            project_trusted: false,
            context_limit: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_process_that_waits_for_async_hooks_lets_them_receive_their_payload() {
        let dir = test_dir("async-payload");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("payload.json");
        let hooks = recording_async_hook(format!("sleep 0.3; cat > '{}'", out.display()));
        // What a process does at its end: fire, wait, leave.
        let outcomes = hooks.fire(
            HookEvent::SessionEnd,
            &serde_json::json!({"reason": "ended"}),
        );
        assert!(outcomes.is_empty(), "an async hook reports no outcome");
        finish_async_hooks(Duration::from_secs(30));
        let body = std::fs::read_to_string(&out).unwrap_or_default();
        let payload: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|error| panic!("the hook's stdin was {body:?}: {error}"));
        assert_eq!(payload["hook_event_name"], "SessionEnd");
        assert_eq!(payload["reason"], "ended");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_async_hook_is_counted_before_fire_returns() {
        // A process that ends in the very next instruction must still see the hook, so it is
        // counted by the caller, not by the thread that has perhaps not started yet.
        let hooks = recording_async_hook("sleep 1".into());
        hooks.fire(HookEvent::SessionEnd, &serde_json::json!({}));
        let left = finish_async_hooks(Duration::from_millis(20));
        assert!(
            left.as_deref()
                .is_some_and(|line| line.contains("async hook")),
            "{left:?}"
        );
    }

    #[test]
    fn waiting_for_async_hooks_ends_at_the_grace_and_says_how_many_are_left() {
        static LOCAL: AsyncHooks = AsyncHooks::new();
        let (first, second) = (LOCAL.start(), LOCAL.start());
        assert_eq!(LOCAL.running(), 2);
        let started = std::time::Instant::now();
        let left = LOCAL.wait(Duration::from_millis(200));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(190) && waited < Duration::from_secs(5),
            "{waited:?}"
        );
        let line = left.expect("two hooks were still running");
        assert!(line.contains("2 async hooks were still running"), "{line}");
        assert!(line.contains("200 ms"), "{line}");
        drop(first);
        let line = LOCAL.wait(Duration::from_millis(50)).expect("one is left");
        assert!(line.contains("1 async hook was still running"), "{line}");
        drop(second);
        assert_eq!(LOCAL.wait(Duration::from_secs(5)), None);
    }

    #[test]
    fn the_wait_ends_when_the_last_async_hook_finishes_not_at_the_grace() {
        static LOCAL: AsyncHooks = AsyncHooks::new();
        let run = LOCAL.start();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(run);
        });
        let started = std::time::Instant::now();
        let left = LOCAL.wait(Duration::from_secs(30));
        let waited = started.elapsed();
        release.join().unwrap();
        assert_eq!(left, None);
        assert!(waited >= Duration::from_millis(150), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
    }

    #[test]
    fn the_line_names_the_wait_in_whole_seconds_when_it_is_whole() {
        let line = still_running_line(1, Duration::from_secs(5));
        assert!(
            line.starts_with("1 async hook was still running after 5 s;"),
            "{line}"
        );
        let line = still_running_line(3, Duration::from_millis(1500));
        assert!(
            line.starts_with("3 async hooks were still running after 1500 ms;"),
            "{line}"
        );
    }

    #[test]
    fn with_no_async_hooks_running_the_wait_is_over_at_once() {
        static LOCAL: AsyncHooks = AsyncHooks::new();
        let started = std::time::Instant::now();
        assert_eq!(LOCAL.wait(Duration::from_secs(30)), None);
        assert_eq!(LOCAL.wait(Duration::MAX), None, "a huge grace is bounded");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn an_async_hook_whose_thread_unwinds_is_not_counted_for_ever() {
        static LOCAL: AsyncHooks = AsyncHooks::new();
        let run = LOCAL.start();
        assert_eq!(LOCAL.running(), 1);
        let crashed = std::thread::spawn(move || {
            let _run = run;
            panic!("a hook's thread failed");
        })
        .join();
        assert!(crashed.is_err());
        assert_eq!(LOCAL.running(), 0);
        assert_eq!(LOCAL.wait(Duration::from_secs(5)), None);
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
            origin: None,
        };
        let hooks = Hooks {
            hooks: vec![
                hook("UserPromptExpansion", "review"),
                hook("PreModelSwitch", "claude-*"),
                hook("InstructionsLoaded", "session_start"),
            ],
            project_trusted: false,
            context_limit: None,
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
                origin: None,
            }],
            project_trusted: false,
            context_limit: None,
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
                origin: None,
            }],
            project_trusted: false,
            context_limit: None,
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
            origin: None,
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
            origin: None,
        };
        let hooks = Hooks {
            hooks: vec![
                hook("FileChanged", ".env|.envrc, Cargo.toml"),
                hook("FileChanged", "../secret|src/main.rs|*.rs|.env"),
                hook("PreToolUse", "Bash"),
            ],
            project_trusted: false,
            context_limit: None,
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
