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

pub mod bash;
pub mod executor;
pub mod fs_tools;
pub mod permissions;
pub mod sandbox;
pub mod scan;
pub mod tasks;
pub mod webfetch;

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

/// What a tool execution needs: paths, session identity, spill dir.
/// Cloned per tool call; the read-before-edit state is shared (an
/// interior-mutex) so every tool call in a session sees the same map.
#[derive(Clone)]
pub struct ToolContext {
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
        }
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
}

/// Inline limit for tool results; longer payloads spill to a file the
/// model can Read later (roadmap's spanning rule).
pub const INLINE_LIMIT: usize = 30_000;

/// Wrap a result payload: inline when short, spilled when long.
pub fn finish(mut result: ToolResult, cx: &ToolContext, call_id: &str) -> ToolResult {
    if result.payload.len() > INLINE_LIMIT {
        if let Ok(dir) = cx.outputs_dir() {
            let path = dir.join(format!("{call_id}.txt"));
            if std::fs::write(&path, &result.payload).is_ok() {
                let preview = result.payload.chars().take(2_000).collect::<String>();
                result.payload = serde_json::json!({
                    "ok": result.payload.contains("\"ok\":true") || !result.is_error,
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

/// One-line descriptions (kept beside the registry so definitions and
/// docs cannot drift).
pub fn tool_description(name: &str) -> &'static str {
    match name {
        "Read" => "Reads a file from the local filesystem with line numbers",
        "Write" => "Creates or overwrites a file with the given content",
        "Edit" => "Replaces an exact string in a file (read before edit)",
        "Glob" => "Lists files matching a glob pattern",
        "Grep" => "Searches file contents (ripgrep-style regex)",
        "Bash" => "Runs a command in the persistent working directory",
        "TaskStop" => "Stops a background command",
        "AskUserQuestion" => "Asks the operator 1-4 multiple-choice questions",
        "ExitPlanMode" => "Presents the plan and asks to leave plan mode",
        "TaskCreate" => "Adds a task to the session task list (drives the Plan panel)",
        "TaskUpdate" => "Updates a task's status, title or detail",
        "TaskList" => "Lists the session's tasks",
        "WebFetch" => "Fetches an https URL as markdown; records an egress grant per domain",
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
    )
}

/// Read-only classification (backend-authoritative, roadmap rule).
pub fn is_read_only(name: &str) -> bool {
    matches!(
        name,
        "Read" | "Glob" | "Grep" | "AskUserQuestion" | "TaskList" | "WebFetch"
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
    for entry in deny_read_paths() {
        let e = entry.replace('~', &home);
        let ep = Path::new(&e);
        if p.starts_with(ep) {
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
