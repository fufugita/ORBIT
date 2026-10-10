//! orbit-tools — the Wave 1 tool set and the tool contract
//! (roadmap phase 3, §Tools).
//!
//! Every tool implements one trait; every result passes the secret
//! scanner before it enters the transcript. Claude Code's names and
//! argument shapes are used so prompts, skills and agent definitions
//! written for it work unchanged.
//!
//! Wave 1: Read, Write, Edit, Glob, Grep, Bash, TaskStop,
//! AskUserQuestion, ExitPlanMode.
//!
//! Safety posture:
//! - Read-only tools are parallel-safe and allowed in plan mode.
//! - Write/Edit/Bash ask in default mode (the permission layer decides;
//!   this crate classifies).
//! - Results over the inline limit spill to
//!   `$ORBIT_HOME/sessions/<id>/outputs/<call-id>.txt`.

use orbit_adapter::types::ToolDefinition;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub mod agent;
pub mod askuser;
pub mod bash;
pub mod executor;
pub mod fs_tools;
pub mod notebook;
pub mod permissions;
pub mod sandbox;
pub mod scan;
pub mod shellcmd;
pub mod tasks;
pub mod webfetch;
pub mod websearch;

pub use fs_tools::{EditTool, GlobTool, GrepTool, ReadTool, WriteTool};

/// A tool's permission key — what a rule names (roadmap §Permissions):
/// `Bash("cargo test")`, `Edit(/src/**)`, `Read(~/.ssh/**)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionKey {
    pub tool: String,
    /// The argument pattern the rule scopes to (path prefix, command
    /// prefix). Empty = the whole tool.
    pub pattern: String,
}

/// One Wave 1 tool.
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    /// The JSON Schema sent to the model.
    fn input_schema(&self) -> serde_json::Value;
    /// Parallel-safe + plan-mode allowed (reads and searches only).
    fn read_only(&self) -> bool;
    /// The permission key a call with these arguments yields.
    fn permission_key(&self, input: &serde_json::Value) -> PermissionKey;
    /// Execute. Returns the JSON payload for the model (already
    /// scanned by the caller via [`scan::scan_result`]).
    fn run(&self, input: &serde_json::Value, cx: &ToolContext) -> ToolResult;
}

/// Live tool output: called once per complete output line, in arrival
/// order, from a reader thread — never the caller's. Keep it cheap and
/// never block in it.
pub type OutputSink = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

/// One record the session just appended to the ledger, as a front-end's
/// proof surface (the Activity panel, the ledger chip) shows it.
#[derive(Debug, Clone)]
pub struct LedgerNote {
    /// `intent`, `verdict` or `result`.
    pub kind: &'static str,
    /// What it is about: the call's one-line summary (`Edit(calc.py)`).
    pub target: String,
    /// The recorded fact: `allowed — operator approved`, `ok`, …
    pub fact: String,
    /// The record's own hash — the chain head right after this append.
    pub digest: String,
}

/// Called once per ledger record the session appends, on the thread that
/// appended it. Keep it cheap.
pub type LedgerSink = std::sync::Arc<dyn Fn(&LedgerNote) + Send + Sync>;

/// Has this turn been cancelled (Esc)? Polled by long-running tools —
/// Bash — between waits. The engine's turn token sits behind it.
pub type CancelCheck = std::sync::Arc<dyn Fn() -> bool + Send + Sync>;

/// What a tool execution needs: paths, session identity, spill dir.
/// Cloned per tool call; the read-before-edit state is shared (an
/// interior-mutex) so every tool call in a session sees the same map.
#[derive(Clone)]
pub struct ToolContext {
    /// Where a running command's output lines go as they arrive (the
    /// front-end's live terminal). Shared by every clone of the
    /// context; the executor points it at the current call.
    output_sink: std::sync::Arc<std::sync::Mutex<Option<OutputSink>>>,
    /// Where the ledger records this session appends are announced (the
    /// proof surface). Shared by every clone.
    ledger_sink: std::sync::Arc<std::sync::Mutex<Option<LedgerSink>>>,
    /// The cancel checks of the turns running on this context, innermost
    /// last. Per context — not per process — so one session's Esc cannot
    /// reach another's commands. Shared by every clone.
    cancel: std::sync::Arc<std::sync::Mutex<Vec<CancelCheck>>>,
    /// Values a front-end attaches for the code that runs its tools, by
    /// type (the turn's provider configuration, a subagent observer). The
    /// tools crate knows none of these types; it only carries them. Shared
    /// by every clone, so what the session sets, a call sees.
    extensions: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<
                std::any::TypeId,
                std::sync::Arc<dyn std::any::Any + Send + Sync>,
            >,
        >,
    >,
    /// The current turn's checkpoint id (E7): minted once per user
    /// prompt, shared by every Write/Edit in that turn — /rewind
    /// restores a turn, not a single call. Reset by the front-end at
    /// each prompt. Arc so the Clone derive (cheap handle sharing,
    /// like read_hashes) keeps working.
    pub turn_checkpoint: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    pub home: PathBuf,
    pub session_id: String,
    pub working_dir: PathBuf,
    /// Working directories the operator added (`/add-dir`, phase 4).
    pub working_dirs: Vec<PathBuf>,
    /// Read-before-edit state: file path → content hash at last full
    /// read. Shared across the session's tool calls.
    read_hashes: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<PathBuf, String>>>,
}

impl ToolContext {
    pub fn new(home: PathBuf, session_id: String, working_dir: PathBuf) -> Self {
        ToolContext {
            working_dirs: vec![working_dir.clone()],
            home,
            session_id,
            working_dir,
            read_hashes: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            turn_checkpoint: std::sync::Arc::new(std::sync::Mutex::new(None)),
            output_sink: std::sync::Arc::new(std::sync::Mutex::new(None)),
            cancel: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            ledger_sink: std::sync::Arc::new(std::sync::Mutex::new(None)),
            extensions: Default::default(),
        }
    }

    /// Attach `value` to this context, replacing an earlier value of the
    /// same type.
    pub fn set_ext<T: std::any::Any + Send + Sync>(&self, value: T) {
        if let Ok(mut g) = self.extensions.lock() {
            g.insert(std::any::TypeId::of::<T>(), std::sync::Arc::new(value));
        }
    }

    /// The attached value of type `T`, if any.
    pub fn ext<T: std::any::Any + Send + Sync>(&self) -> Option<std::sync::Arc<T>> {
        let g = self.extensions.lock().ok()?;
        let any = g.get(&std::any::TypeId::of::<T>())?.clone();
        any.downcast::<T>().ok()
    }

    /// Announce every ledger record this session appends to `sink`.
    pub fn set_ledger_sink(&self, sink: Option<LedgerSink>) {
        if let Ok(mut g) = self.ledger_sink.lock() {
            *g = sink;
        }
    }

    /// Tell the front-end a record was just appended (no-op without a
    /// sink).
    pub fn note_ledger(&self, note: LedgerNote) {
        let sink = self.ledger_sink.lock().ok().and_then(|g| g.clone());
        if let Some(sink) = sink {
            sink(&note);
        }
    }

    /// A turn starts running tools on this context: its cancel check
    /// becomes the current one. Pair with [`pop_cancel_check`]; a nested
    /// turn pushes its own and pops it, and its parent's is current
    /// again.
    ///
    /// [`pop_cancel_check`]: ToolContext::pop_cancel_check
    pub fn push_cancel_check(&self, check: CancelCheck) {
        if let Ok(mut g) = self.cancel.lock() {
            g.push(check);
        }
    }

    /// The turn that pushed the current check has finished its tools.
    pub fn pop_cancel_check(&self) {
        if let Ok(mut g) = self.cancel.lock() {
            g.pop();
        }
    }

    /// The current cancel check, if a turn is running tools (a handle a
    /// helper thread can poll — a subagent's watcher does).
    pub fn cancel_check(&self) -> Option<CancelCheck> {
        self.cancel.lock().ok().and_then(|g| g.last().cloned())
    }

    /// Whether the current turn was cancelled. A context no turn is
    /// running on is never cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel_check().map(|f| f()).unwrap_or(false)
    }

    /// Route a running command's output lines to `sink` (the live
    /// terminal), or stop routing with `None`.
    pub fn set_output_sink(&self, sink: Option<OutputSink>) {
        if let Ok(mut g) = self.output_sink.lock() {
            *g = sink;
        }
    }

    /// The current live-output sink, if a front-end installed one.
    pub fn output_sink(&self) -> Option<OutputSink> {
        self.output_sink.lock().ok().and_then(|g| g.clone())
    }

    /// The turn's checkpoint id (E7): minted on first write of the
    /// turn, reused by every Write/Edit after it — one checkpoint per
    /// user prompt, so /rewind restores the turn.
    pub fn turn_checkpoint_id(&self) -> String {
        let mut guard = self.turn_checkpoint.lock().expect("checkpoint lock");
        if let Some(id) = guard.as_ref() {
            return id.clone();
        }
        let id = format!("cp-{}", ulid::Ulid::new());
        *guard = Some(id.clone());
        id
    }

    /// Reset at the start of a turn (front-ends call this per prompt).
    pub fn reset_turn_checkpoint(&self) {
        let mut guard = self.turn_checkpoint.lock().expect("checkpoint lock");
        *guard = None;
    }

    /// Record a full read (or an equivalent write) — the file's current
    /// content hash, for read-before-edit.
    pub fn record_read(&self, path: PathBuf, hash: String) {
        if let Ok(mut m) = self.read_hashes.lock() {
            m.insert(path, hash);
        }
    }

    /// Was this file read in full at its CURRENT content? A file edited
    /// on disk after the read (hash mismatch) must be re-read.
    pub fn was_read(&self, path: &Path) -> bool {
        let Ok(m) = self.read_hashes.lock() else {
            return false;
        };
        match m.get(path) {
            Some(recorded) => match std::fs::read(path) {
                Ok(bytes) => {
                    use sha2::Digest;
                    let current = hex::encode(sha2::Sha256::digest(&bytes));
                    &current == recorded
                }
                Err(_) => false,
            },
            None => false,
        }
    }

    /// The outputs dir for this session (created on demand).
    pub fn outputs_dir(&self) -> std::io::Result<PathBuf> {
        let d = self
            .home
            .join("sessions")
            .join(&self.session_id)
            .join("outputs");
        std::fs::create_dir_all(&d)?;
        Ok(d)
    }
}

/// A tool's execution outcome.
#[derive(Debug, Clone)]
pub struct ToolResult {
    /// The JSON payload for the model.
    pub payload: String,
    pub is_error: bool,
    /// Spill file path when the payload exceeded the inline limit.
    pub spilled_to: Option<PathBuf>,
}

impl ToolResult {
    pub fn ok(payload: serde_json::Value) -> Self {
        ToolResult {
            payload: payload.to_string(),
            is_error: false,
            spilled_to: None,
        }
    }
    pub fn err(message: &str) -> Self {
        ToolResult {
            payload: serde_json::json!({ "ok": false, "error": message }).to_string(),
            is_error: true,
            spilled_to: None,
        }
    }
    /// A permission refusal (C4): `denied: true` marks the payload as
    /// policy-said-no — the typed flag exit codes, events and UI
    /// glyphs key on, instead of message substrings.
    pub fn denied(message: &str) -> Self {
        ToolResult {
            payload: serde_json::json!({ "ok": false, "denied": true, "error": message })
                .to_string(),
            is_error: true,
            spilled_to: None,
        }
    }
}

/// Inline limit for tool results; longer payloads spill to a file the
/// model can Read later (roadmap's spanning rule).
pub const INLINE_LIMIT: usize = 30_000;

/// The authoritative tool-result verdict (E4): the TOP-LEVEL `ok` field
/// of the result JSON, parsed once — never a substring search, which
/// fires on any tool whose *output* merely contains the text
/// `"ok":false` (a Read of a JSON fixture, a grep hit). A result that
/// is not valid JSON, or JSON without an `ok` field, is NOT an error:
/// several legacy results are plain strings.
pub fn result_is_error(payload: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        // The ok field's VALUE (true = success); invert for the
        // verdict. A missing field or non-JSON payload is not an
        // error (legacy plain-string results).
        .and_then(|v| v.get("ok").and_then(|f| f.as_bool()))
        .map(|ok| !ok)
        .unwrap_or(false)
}

/// A permission refusal, not a tool failure (C4, same shape as E4):
/// the TOP-LEVEL `denied` flag the verdict layer stamps on a refusal.
/// Distinguishes "the operator/policy said no" (auditable denial) from
/// "the tool ran and failed" — exit codes, events and UI glyphs key on
/// it. A result without the flag is not a denial, whatever its text.
pub fn result_is_denial(payload: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| v.get("denied").and_then(|f| f.as_bool()))
        .unwrap_or(false)
}

/// Extract the refusal reason from a denial payload (for events and
/// stderr). None on a non-denial payload.
pub fn denial_reason(payload: &str) -> Option<String> {
    let v = serde_json::from_str::<serde_json::Value>(payload).ok()?;
    if !result_is_denial(payload) {
        return None;
    }
    v.get("error")
        .and_then(|e| e.as_str())
        .map(str::to_string)
        .or_else(|| Some("denied".into()))
}

/// Wrap a result payload: inline when short, spilled when long.
pub fn finish(mut result: ToolResult, cx: &ToolContext, call_id: &str) -> ToolResult {
    if result.payload.len() > INLINE_LIMIT {
        if let Ok(dir) = cx.outputs_dir() {
            let path = dir.join(format!("{call_id}.txt"));
            if std::fs::write(&path, &result.payload).is_ok() {
                let preview = result.payload.chars().take(2_000).collect::<String>();
                result.payload = serde_json::json!({
                    // E4: the spill wrapper's verdict is the typed one
                    // (the payload's own top-level ok, parsed — never
                    // a substring of the preview).
                    "ok": !result_is_error(&result.payload) && !result.is_error,
                    "note": "result too long for inline display",
                    "spilled_to": path.to_string_lossy(),
                    "preview": preview,
                })
                .to_string();
                result.spilled_to = Some(path);
            }
        }
    }
    result
}

/// The registry: every Wave 1 tool.
pub fn registry() -> Vec<Box<dyn Tool>> {
    vec![
        Box::new(ReadTool),
        Box::new(WriteTool),
        Box::new(EditTool),
        Box::new(GlobTool),
        Box::new(GrepTool),
        Box::new(bash::BashTool),
        Box::new(bash::TaskStopTool),
        Box::new(tasks::TaskCreateTool),
        Box::new(tasks::TaskUpdateTool),
        Box::new(tasks::TaskListTool),
        Box::new(webfetch::WebFetchTool),
        Box::new(askuser::AskUserQuestionTool),
        Box::new(askuser::ExitPlanModeTool),
        Box::new(agent::AgentTool),
        Box::new(websearch::WebSearchTool),
        Box::new(notebook::NotebookEditTool),
    ]
}

/// Adapter-facing definitions for the provider.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    registry()
        .iter()
        .map(|t| {
            let name = t.name();
            let description = tool_description(name);
            let parameters = t.input_schema();
            let mut bytes = Vec::new();
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(description.as_bytes());
            bytes.extend_from_slice(
                serde_json::to_string(&parameters)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            ToolDefinition {
                name: name.to_string(),
                description: description.to_string(),
                parameters,
                schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(Sha256::digest(
                    &bytes,
                ))),
            }
        })
        .collect()
}

/// Tool descriptions (kept beside the registry so definitions and docs
/// cannot drift). C6: full usage rules, not one-liners — the model is
/// told the contract each tool enforces (read-before-edit, uniqueness,
/// timeouts) so it does not have to discover them by failure.
pub fn tool_description(name: &str) -> &'static str {
    match name {
        "Read" => {
            "Reads a file from the local filesystem. Returns up to 2000 lines by default \
            with 1-based line numbers (cat -n format). Use offset/limit for long files. \
            Reading a file in full records it for the session's read-before-edit rule."
        }
        "Write" => {
            "Creates or overwrites a file with the given content. Overwriting an EXISTING \
            file requires reading it in full first this session (read-before-write). New files \
            need no prior read. Writes are atomic (temp file + rename)."
        }
        "Edit" => {
            "Replaces one exact string in a file. The file must have been read in full this \
            session first (read-before-edit). old_string must be UNIQUE in the file — include \
            surrounding context lines to disambiguate. The new_string replaces it verbatim."
        }
        "Glob" => {
            "Lists file paths matching a glob pattern (e.g. '**/*.rs', 'src/*.py'). \
            Respects .gitignore. Returns paths relative to the working directory, capped at 100 \
            matches."
        }
        "Grep" => {
            "Searches file contents with a regex (ripgrep-style). Searches the working \
            directory recursively, respecting .gitignore; use 'path' to scope and 'glob' to \
            filter file names (e.g. '*.py'). Results are capped — check the truncated flag."
        }
        "Bash" => {
            "Runs a shell command in the working directory, sandboxed (bubblewrap) when \
            available. Default timeout 120s; the command is killed at the timeout and partial \
            output is returned. Output is scanned for secrets before it reaches the model. \
            Commands touching deny-read paths (credentials) are refused."
        }
        "TaskStop" => {
            "Stops a background command started with Bash's run_in_background, by its \
            background id. The command's process group is killed."
        }
        "AskUserQuestion" => {
            "Asks the operator 1-4 multiple-choice questions when a decision is \
            genuinely theirs. Each question has 2-4 options; the operator may always answer \
            free-form. Use sparingly — most choices have a conventional default."
        }
        "ExitPlanMode" => {
            "Presents the completed plan and asks the operator to approve leaving \
            plan mode. On approval, execution proceeds with the plan as the prompt."
        }
        "TaskCreate" => {
            "Adds a task to the session task list (drives the Plan panel). Tasks are \
            visible to the operator and to subsequent turns."
        }
        "TaskUpdate" => "Updates a task's status (todo/in_progress/done), title or detail by id.",
        "TaskList" => "Lists the session's tasks with ids and statuses.",
        "WebFetch" => {
            "Fetches an https URL and returns it as markdown. Each domain requires an \
            egress grant (asked once per domain per session). http and private addresses are \
            refused."
        }
        "WebSearch" => {
            "Searches the web and returns results with titles, URLs and snippets \
            (requires a configured search API backend)."
        }
        "Agent" => {
            "Runs a subagent with its own context window and tool access; returns its \
            final report. Use for parallel or context-heavy exploration. The subagent shares \
            the session's permission scope."
        }
        "NotebookEdit" => {
            "Edits a Jupyter notebook (.ipynb) cell: replace, insert or delete by \
            cell id. The notebook must have been read this session first."
        }
        _ => "unknown tool",
    }
}

/// Wave 1 names (for permission classification).
pub fn is_wave1(name: &str) -> bool {
    matches!(
        name,
        "Read"
            | "Write"
            | "Edit"
            | "Glob"
            | "Grep"
            | "Bash"
            | "TaskStop"
            | "AskUserQuestion"
            | "ExitPlanMode"
            // B3: these have real implementations in registry() but
            // were missing here, so they fell through to the pure
            // built-in executor and answered "unknown tool".
            | "TaskCreate"
            | "TaskUpdate"
            | "TaskList"
            | "WebFetch"
            // Wave 2 completion: same registry membership rule.
            | "WebSearch"
            | "Agent"
            | "NotebookEdit"
    )
}

/// Read-only classification (backend-authoritative, roadmap rule).
pub fn is_read_only(name: &str) -> bool {
    // WebFetch is deliberately NOT here: its approval contract is "Yes,
    // per domain" (roadmap §Tools) — a new domain is an egress question,
    // so the pattern layer asks rather than silently allowing. The
    // tool's own read_only() flag still marks it parallel-safe.
    matches!(
        name,
        "Read" | "Glob" | "Grep" | "AskUserQuestion" | "TaskList" | "WebSearch"
    )
}

/// The default deny-read list (roadmap: credentials never reach a
/// provider). A Read/Glob/Grep touching any of these is denied.
pub fn deny_read_paths() -> &'static [&'static str] {
    &[
        "~/.ssh",
        "~/.aws",
        "~/.gnupg",
        "~/.netrc",
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/id_rsa*",
        "**/credentials.json",
        "**/secrets.*",
    ]
}

/// Does `path` fall under a deny-read entry? Expand `~`, match dir
/// prefixes and glob tails.
pub fn is_deny_read(path: &Path) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let s = path.to_string_lossy();
    let expanded = s.replace('~', &home);
    let p = Path::new(&expanded);
    // S2: match the CANONICAL path — a symlink to ~/.ssh/… must not
    // sidestep the list. Non-existent paths match as given (a Write
    // to a not-yet-created deny path is still denied).
    let canonical = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    for entry in deny_read_paths() {
        let e = entry.replace('~', &home);
        let ep = Path::new(&e);
        if canonical.starts_with(ep) || p.starts_with(ep) {
            return true;
        }
        // glob tails: **/<name>
        if let Some(tail) = e.strip_prefix("**/") {
            for comp in p.components() {
                let cs = comp.as_os_str().to_string_lossy();
                if tail.contains('*') {
                    if glob_match(tail, &cs) {
                        return true;
                    }
                } else if cs == tail {
                    return true;
                }
            }
        }
    }
    false
}

/// Minimal glob matcher for a single path component (`*` wildcard).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    // '*' matches any run (including none) within one component.
    fn rec(p: &[u8], t: &[u8]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p[0] == b'*' {
            // collapse consecutive stars
            let mut i = 1;
            while i < p.len() && p[i] == b'*' {
                i += 1;
            }
            for skip in 0..=t.len() {
                if rec(&p[i..], &t[skip..]) {
                    return true;
                }
            }
            false
        } else {
            !t.is_empty() && p[0] == t[0] && rec(&p[1..], &t[1..])
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// Resolve a tool argument path against the working directory,
/// expanding `~`.
pub fn resolve_path(cx: &ToolContext, p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix('~') {
        if let Ok(home) = std::env::var("HOME") {
            return Path::new(&home).join(rest.trim_start_matches('/'));
        }
    }
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cx.working_dir.join(path)
    }
}

#[cfg(test)]
mod extension_tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct Marker(u32);
    struct Other;

    fn cx() -> ToolContext {
        ToolContext::new("/h".into(), "s".into(), "/w".into())
    }

    /// A value is found by its type, replaced by a later one, and shared by
    /// every clone — what the session sets, a call's clone sees.
    #[test]
    fn a_value_is_found_by_type_and_shared_by_clones() {
        let cx = cx();
        assert!(cx.ext::<Marker>().is_none());
        cx.set_ext(Marker(1));
        let call = cx.clone();
        assert_eq!(call.ext::<Marker>().as_deref(), Some(&Marker(1)));
        assert!(call.ext::<Other>().is_none(), "another type is not found");
        cx.set_ext(Marker(2));
        assert_eq!(
            call.ext::<Marker>().as_deref(),
            Some(&Marker(2)),
            "replaced"
        );
        // A different context has its own.
        assert!(self::cx().ext::<Marker>().is_none());
    }
}

#[cfg(test)]
mod e4_tests {
    use super::*;

    #[test]
    fn verdict_ignores_nested_poison_but_catches_real_errors() {
        // Poison inside content: NOT an error. Built with json! so
        // the escaping is serde's own, not hand-rolled.
        let inner = serde_json::json!({
            "note": "a body that says \"ok\":false inside a string"
        })
        .to_string();
        let payload = serde_json::json!({
            "content": format!("1\t{inner}\n"),
            "ok": true
        })
        .to_string();
        assert!(!result_is_error(&payload), "nested text is not a verdict");
        // Real error: top-level ok:false.
        let real_error = r#"{"ok":false,"error":"denied"}"#;
        assert!(result_is_error(real_error));
        // Missing ok field: not an error (legacy plain payloads).
        assert!(!result_is_error("{\"content\":\"hello\"}"));
        // Not JSON at all: not an error.
        assert!(!result_is_error("plain text output"));
    }

    #[test]
    fn denial_flag_is_typed_not_textual() {
        // A refusal: the typed flag.
        let refusal = ToolResult::denied("denied by you").payload;
        assert!(result_is_denial(&refusal));
        assert!(result_is_error(&refusal), "a denial is also not-ok");
        assert_eq!(denial_reason(&refusal).as_deref(), Some("denied by you"));
        // A tool that ran and failed: NOT a denial, however much the
        // message says "denied" — the word alone was the old substring
        // heuristic (C4's bug).
        let failed = r#"{"ok":false,"error":"denied: no such file"}"#;
        assert!(!result_is_denial(failed));
        assert!(result_is_error(failed));
        assert!(denial_reason(failed).is_none());
        // A success payload is never a denial.
        assert!(!result_is_denial(r#"{"ok":true,"result":"x"}"#));
        // Legacy plain strings: no flag, not a denial.
        assert!(!result_is_denial("operator denied something"));
    }
}
