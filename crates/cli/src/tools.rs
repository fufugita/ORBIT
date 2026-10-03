//! Pure built-in tools (DR-19 tool-calling phase).
//!
//! Safety boundary: these tools are PURE DATA. No shell, no process spawning,
//! no filesystem writes, no network, no credentials, no plugin execution.
//! They cannot harm the host. Any unknown tool name is denied; malformed
//! arguments are rejected before any execution.

use orbit_adapter::types::ToolDefinition;
use sha2::{Digest, Sha256};

pub(crate) fn config_home_from_env() -> std::path::PathBuf {
    std::env::var("ORBIT_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(".orbit"))
}

/// A built-in tool's declarative identity (sent to the provider as the JSON
/// schema) plus a pure executor.
pub struct BuiltinTool {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters: serde_json::Value,
    pub execute: fn(&serde_json::Value) -> Result<serde_json::Value, String>,
}

impl BuiltinTool {
    fn to_definition(&self) -> ToolDefinition {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(self.description.as_bytes());
        bytes.extend_from_slice(
            serde_json::to_string(&self.parameters)
                .unwrap_or_default()
                .as_bytes(),
        );
        ToolDefinition {
            name: self.name.to_string(),
            description: self.description.to_string(),
            parameters: self.parameters.clone(),
            schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(Sha256::digest(&bytes))),
        }
    }
}

/// The three locked pure built-ins.
pub fn builtin_tools() -> Vec<BuiltinTool> {
    vec![calculator(), current_session_tool(), list_models_tool()]
}

/// Adapter-facing definitions for the provider: the Wave 1 tool set
/// (Read/Write/Edit/Glob/Grep/Bash/TaskStop) plus the locked pure
/// built-ins (calculator, session/model lookups). Phase 3.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    let mut defs: Vec<ToolDefinition> = orbit_tools::tool_definitions();
    defs.extend(builtin_tools().iter().map(|t| t.to_definition()));
    defs
}

/// The full session tool list: Wave 1 + built-ins + the Skill tool +
/// MCP server tools (mcp__<server>__<tool>). MCP servers from the
/// trusted scopes are spawned once, their tools declared up front so
/// the list never changes mid-conversation (phase 5).
pub fn session_tool_definitions(home: &std::path::Path) -> Vec<ToolDefinition> {
    // --bare skips discovering skills, mods, MCP servers and memory
    // files (phase 6: fast start for scripts).
    if std::env::var("ORBIT_BARE").map(|v| v == "1").unwrap_or(false) {
        return tool_definitions();
    }
    let mut defs = tool_definitions();

    // The Skill tool: load a skill's body on demand.
    defs.push(skill_tool_definition());

    // The Task tool: spawn a subagent (phase 5).
    defs.push(task_tool_definition());

    // MCP tools.
    let trusted = {
        let cwd = std::env::current_dir().unwrap_or_default();
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(&cwd)
    };
    let cfg = orbit_mcp::McpConfig::load(home, trusted);
    for (name, server) in &cfg.servers {
        // The process-lifetime pool: one server process per name,
        // reused across calls and definition builds (phase 5).
        if let Ok(tools) = orbit_mcp::POOL.list_tools(name, server) {
            for t in tools {
                let wire = orbit_mcp::wire_name(name, &t.name);
                let mut bytes = Vec::new();
                bytes.extend_from_slice(wire.as_bytes());
                bytes.extend_from_slice(t.description.as_bytes());
                bytes.extend_from_slice(
                    serde_json::to_string(&t.input_schema)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                defs.push(ToolDefinition {
                    name: wire.clone(),
                    description: format!("{} (mcp: {name})", t.description),
                    parameters: t.input_schema,
                    schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(
                        sha2::Sha256::digest(&bytes),
                    )),
                });
            }
        }
    }
    defs
}

/// The Skill tool definition (phase 5).
fn skill_tool_definition() -> ToolDefinition {
    let name = "Skill";
    let description =
        "Load a skill's full instructions by name (the index is in the system prompt)";
    let parameters = serde_json::json!({
        "type": "object",
        "properties": {
            "name": { "type": "string", "description": "The skill to load" }
        },
        "required": ["name"]
    });
    let mut bytes = Vec::new();
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(description.as_bytes());
    bytes.extend_from_slice(
        serde_json::to_string(&parameters)
            .unwrap_or_default()
            .as_bytes(),
    );
    ToolDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(
            &bytes,
        ))),
    }
}

/// The Task tool definition (phase 5): spawn a subagent. The agent
/// list is in the system prompt; the subagent runs a nested engine
/// turn with the agent's restricted tool set and returns its final
/// report.
fn task_tool_definition() -> ToolDefinition {
    let name = "Task";
    let description = "Run a subagent: Explore (read-only research), Plan (implementation plan), or general-purpose (delegated work). Returns the subagent's final report.";
    let parameters = serde_json::json!({
        "type": "object",
        "properties": {
            "agent": { "type": "string", "description": "The subagent to run (Explore, Plan, general-purpose)" },
            "prompt": { "type": "string", "description": "The task for the subagent" }
        },
        "required": ["agent", "prompt"]
    });
    let mut bytes = Vec::new();
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(description.as_bytes());
    bytes.extend_from_slice(
        serde_json::to_string(&parameters)
            .unwrap_or_default()
            .as_bytes(),
    );
    ToolDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(
            &bytes,
        ))),
    }
}

/// Execute the Task tool: run a subagent as a nested engine turn.
/// `turn_config` carries the provider/gate/model the session already
/// uses; the subagent's own tool set comes from its definition.
pub fn execute_task(
    home: &std::path::Path,
    agent_name: &str,
    prompt: &str,
    turn_config: &orbit_engine::TurnConfig,
    approval: &mut dyn crate::tool_runtime::ApprovalChannel,
) -> Result<serde_json::Value, String> {
    let trusted = {
        let cwd = std::env::current_dir().unwrap_or_default();
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(&cwd)
    };
    let agents = orbit_engine::skills::load_agents(home, trusted);
    let agent = agents
        .into_iter()
        .find(|a| a.name == agent_name)
        .ok_or_else(|| format!("unknown subagent: {agent_name}"))?;

    // The subagent's tool set: its allowlist intersected with the
    // session's tools (a subagent never gets tools the session lacks).
    let session_tools = session_tool_definitions(home);
    let sub_tools: Vec<ToolDefinition> = if agent.tools.is_empty() {
        session_tools
    } else {
        session_tools
            .into_iter()
            .filter(|t| agent.tools.contains(&t.name))
            .collect()
    };

    // A fresh transcript: the subagent does not see the parent's
    // conversation, only its prompt.
    let mut transcript: Vec<orbit_adapter::types::ChatMessage> = Vec::new();
    let cancel = orbit_provider_http::CancelToken::new();
    let options = orbit_engine::TurnOptions {
        tools: sub_tools,
        max_rounds: agent.max_turns,
        system_directive: Some(format!(
            "You are {name}, a subagent. {desc}\n\nComplete the task and reply with your final report. You do not see the parent conversation.",
            name = agent.name,
            desc = agent.description
        )),
        request_stem: format!("orbit-task-{}", agent.name),
        ..Default::default()
    };

    // The subagent's tool calls go through the same permission path as
    // the parent's — the approval channel is shared, so a subagent's
    // approval request appears in the main session (roadmap gate 5).
    let mut executor = crate::tool_runtime::SubagentExecutor::new(home.to_path_buf(), approval);
    let report = orbit_engine::run_turn(
        home,
        turn_config,
        &options,
        prompt,
        &mut transcript,
        &mut executor,
        &cancel,
        &mut |_| {},
    )?;

    // The final assistant text is the report.
    let report_text = transcript
        .iter()
        .rev()
        .find(|m| m.role == orbit_adapter::types::ChatRole::Assistant)
        .map(|m| m.content.clone())
        .unwrap_or_default();

    Ok(serde_json::json!({
        "ok": report.ok,
        "agent": agent.name,
        "rounds": report.rounds,
        "report": report_text,
    }))
}

/// Execute the Skill tool: return the named skill's body.
pub fn execute_skill(home: &std::path::Path, name: &str) -> Result<serde_json::Value, String> {
    let trusted = {
        let cwd = std::env::current_dir().unwrap_or_default();
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(&cwd)
    };
    let skills = orbit_engine::skills::load_skills(home, trusted);
    skills
        .into_iter()
        .find(|s| s.name == name)
        .map(|s| serde_json::json!({ "ok": true, "body": s.body }))
        .ok_or_else(|| format!("unknown skill: {name}"))
}

/// Execute a tool by name with parsed JSON arguments. Unknown tools are denied
/// (fail closed). Returns the JSON result or a structured error string.
pub fn execute(name: &str, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    for tool in builtin_tools() {
        if tool.name == name {
            return (tool.execute)(args);
        }
    }
    Err(format!("unknown tool: {name}"))
}

/// Display-safe summary of a tool call's arguments (name + argument keys only;
/// never raw argument values — they may be secrets).
pub fn safe_call_summary(name: &str, args: &serde_json::Value) -> String {
    // The card and transcript lines must name the target (review
    // blocker 2): the path for file tools, the command for Bash. The
    // value passes the secret scanner first — a real secret redacts,
    // an ordinary path or command shows.
    let target_key = match name {
        "Bash" => Some("command"),
        "Read" | "Write" | "Edit" | "Glob" | "Grep" => Some("file_path"),
        _ => None,
    };
    if let Some(key) = target_key {
        if let Some(v) = args.get(key).and_then(|v| v.as_str()) {
            let scanned = orbit_tools::scan::scan_result(v);
            return format!("{name}({})", scanned.text.trim());
        }
    }
    let keys: Vec<&str> = args
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    format!("{name}({})", keys.join(", "))
}

// ── Built-ins ────────────────────────────────────────────────────────────────

fn calculator() -> BuiltinTool {
    BuiltinTool {
        name: "calculator",
        description: "Evaluate a pure arithmetic expression over numbers and the operators + - * / ( ) ^ % with integer and floating point operands. Never executes shell or code.",
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "Arithmetic expression, e.g. '2 * (3 + 4)' or '10 / 4'"
                }
            },
            "required": ["expression"]
        }),
        execute: |args| {
            let expr = args
                .get("expression")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "calculator requires a string 'expression'".to_string())?;
            if expr.len() > 512 {
                return Err("expression too long".into());
            }
            if !expr.chars().all(|c| {
                c.is_ascii_digit()
                    || c.is_ascii_whitespace()
                    || "+-*/()^%.".contains(c)
            }) {
                return Err("expression contains disallowed characters".into());
            }
            let result = eval_arithmetic(expr).ok_or_else(|| "invalid expression".to_string())?;
            Ok(serde_json::json!({ "result": result }))
        },
    }
}

/// Tiny recursive-descent evaluator for + - * / ^ % over f64. Pure, no eval.
fn eval_arithmetic(expr: &str) -> Option<f64> {
    let mut chars = expr.chars().peekable();
    let mut pos = 0usize;
    let value = parse_expr(&mut chars, &mut pos)?;
    if chars.next().is_some() {
        return None; // trailing garbage
    }
    Some(value)
}

fn parse_expr(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    let mut left = parse_term(chars, pos)?;
    loop {
        match chars.peek().copied() {
            Some('+') => {
                *pos += 1;
                chars.next();
                left += parse_term(chars, pos)?;
            }
            Some('-') => {
                *pos += 1;
                chars.next();
                left -= parse_term(chars, pos)?;
            }
            _ => return Some(left),
        }
    }
}

fn parse_term(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    let mut left = parse_power(chars, pos)?;
    loop {
        match chars.peek().copied() {
            Some('*') => {
                *pos += 1;
                chars.next();
                left *= parse_power(chars, pos)?;
            }
            Some('/') => {
                *pos += 1;
                chars.next();
                let denom = parse_power(chars, pos)?;
                if denom == 0.0 {
                    return None; // division by zero
                }
                left /= denom;
            }
            Some('%') => {
                *pos += 1;
                chars.next();
                let denom = parse_power(chars, pos)?;
                if denom == 0.0 {
                    return None;
                }
                left %= denom;
            }
            _ => return Some(left),
        }
    }
}

fn parse_power(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    let base = parse_unary(chars, pos)?;
    if chars.peek() == Some(&'^') {
        *pos += 1;
        chars.next();
        let exp = parse_unary(chars, pos)?;
        return Some(base.powf(exp));
    }
    Some(base)
}

fn parse_unary(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    while chars
        .peek()
        .map(|c| c.is_ascii_whitespace())
        .unwrap_or(false)
    {
        *pos += 1;
        chars.next();
    }
    match chars.peek().copied() {
        Some('-') => {
            *pos += 1;
            chars.next();
            Some(-parse_unary(chars, pos)?)
        }
        Some('+') => {
            *pos += 1;
            chars.next();
            parse_unary(chars, pos)
        }
        Some('(') => {
            *pos += 1;
            chars.next();
            let inner = parse_expr(chars, pos)?;
            if chars.next() != Some(')') {
                return None;
            }
            *pos += 1;
            Some(inner)
        }
        _ => parse_number(chars, pos),
    }
}

fn parse_number(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    while chars
        .peek()
        .map(|c| c.is_ascii_whitespace())
        .unwrap_or(false)
    {
        *pos += 1;
        chars.next();
    }
    let mut s = String::new();
    let mut saw_dot = false;
    while let Some(c) = chars.peek().copied() {
        if c.is_ascii_digit() {
            s.push(c);
            *pos += 1;
            chars.next();
        } else if c == '.' && !saw_dot {
            saw_dot = true;
            s.push(c);
            *pos += 1;
            chars.next();
        } else {
            break;
        }
    }
    if s.is_empty() {
        return None;
    }
    s.parse::<f64>().ok()
}

fn current_session_tool() -> BuiltinTool {
    BuiltinTool {
        name: "current_session",
        description: "Read-only metadata about the current ORBIT session: session id, model, provider, turn count, and token usage. Contains no prompts, secrets, or conversation content.",
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        execute: |_args| {
            // Populated by the harness via a thread-local/closure set before
            // execution; a missing snapshot yields the empty default.
            let snap = SESSION_SNAPSHOT.with(|s| s.borrow().clone());
            Ok(serde_json::json!({
                "session_id": snap.session_id,
                "model": snap.model,
                "provider": snap.provider,
                "turns": snap.turns,
                "input_tokens": snap.input_tokens,
                "output_tokens": snap.output_tokens,
            }))
        },
    }
}

fn list_models_tool() -> BuiltinTool {
    BuiltinTool {
        name: "list_models",
        description: "List every model id declared across all configured providers (provider/model ids only).",
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        execute: |_args| {
            let home = config_home_from_env();
            let cfg = crate::config::ProvidersConfig::load(&home).unwrap_or_default();
            let models: Vec<serde_json::Value> = cfg
                .all_models()
                .into_iter()
                .map(|(p, m)| serde_json::json!({ "provider": p, "model": m }))
                .collect();
            Ok(serde_json::json!({ "models": models }))
        },
    }
}

/// Session snapshot exposed to `current_session` (never prompts/secrets).
#[derive(Clone, Default)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub model: String,
    pub provider: String,
    pub turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

thread_local! {
    pub static SESSION_SNAPSHOT: std::cell::RefCell<SessionSnapshot> =
        std::cell::RefCell::new(SessionSnapshot::default());
}

/// Validate + parse a tool call's accumulated arguments JSON.
pub fn parse_arguments(accumulated: &[u8]) -> Result<serde_json::Value, String> {
    if accumulated.is_empty() {
        return Err("tool call had no arguments".into());
    }
    serde_json::from_slice(accumulated).map_err(|e| format!("invalid arguments JSON: {e}"))
}

/// Validate a tool definition name against the built-in set (fail closed).
/// Read-only classification (backend-authoritative). Read-only tools
/// are parallel-safe AND allowed in plan mode — the model researches
/// while planning. Every current built-in is a pure-data calculator;
/// when write/shell tools land they classify false by default
/// (fail toward caution, like `tool_risk`).
pub fn is_read_only(name: &str) -> bool {
    orbit_tools::is_read_only(name)
        || matches!(name, "calculator" | "current_session" | "list_models")
}

pub fn is_known_tool(name: &str) -> bool {
    orbit_tools::is_wave1(name)
        || orbit_tools::registry()
            .iter()
            .any(|t| t.name() == name)
        || builtin_tools().iter().any(|t| t.name == name)
}

/// Structured risk classification for a tool (backend-authoritative — the
/// UI never classifies actions itself; docs/tui/DESIGN.md §6.15 facts rule).
/// All current built-ins are pure-data calculators: low risk. Shell/fs/net
/// tools, when they exist, will classify higher by construction.
/// The full classification vocabulary exists so future tools (shell, fs,
/// net) slot in without reshaping the type; v0.1's pure-data built-ins only
/// construct Low. `as_str` is exercised by tests and used by ledger/REPL
/// surfaces as they adopt the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Destructive,
}

impl RiskLevel {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Destructive => "destructive",
        }
    }

    /// 0..=3 for the ▰▰▱ badge.
    pub fn level(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Destructive => 3,
        }
    }
}

/// Risk classification for a known tool. Unknown tools never reach the UI
/// (deny-by-default before the approval channel), so this is total over the
/// known set.
pub fn tool_risk(name: &str) -> RiskLevel {
    // Wave 1 risk: Bash is per-command (the executor computes it);
    // writes are Medium at the classification level.
    if matches!(name, "Write" | "Edit") {
        return RiskLevel::Medium;
    }
    if orbit_tools::is_wave1(name) && !orbit_tools::is_read_only(name) {
        return RiskLevel::Medium;
    }
    // All v0.1 built-ins are pure-data (calculator, session snapshot, model
    // list). Anything not explicitly classified defaults to medium — fail
    // toward caution, never silently low.
    match name {
        "calculator" | "current_session" | "list_models" => RiskLevel::Low,
        // Wave 2 pure-data tools: the task list is session state, not
        // the filesystem.
        "TaskList" => RiskLevel::Low,
        _ => RiskLevel::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_classification_is_backend_authoritative() {
        // Known pure-data tools are low; anything unclassified fails toward
        // medium, never silently low.
        assert_eq!(tool_risk("calculator"), RiskLevel::Low);
        assert_eq!(tool_risk("current_session"), RiskLevel::Low);
        assert_eq!(tool_risk("list_models"), RiskLevel::Low);
        assert_eq!(tool_risk("some_future_tool"), RiskLevel::Medium);
        assert_eq!(RiskLevel::Low.as_str(), "low");
        assert_eq!(RiskLevel::Medium.as_str(), "medium");
        assert_eq!(RiskLevel::High.as_str(), "high");
        assert_eq!(RiskLevel::Destructive.as_str(), "destructive");
        assert_eq!(RiskLevel::Destructive.level(), 3);
    }

    #[test]
    fn calculator_evaluates_without_code_execution() {
        let out = execute("calculator", &serde_json::json!({"expression":"2*(3+4)"})).unwrap();
        assert_eq!(out["result"].as_f64(), Some(14.0));
    }

    #[test]
    fn calculator_rejects_code_characters_and_div_zero() {
        assert!(execute(
            "calculator",
            &serde_json::json!({"expression":"system(\"id\")"})
        )
        .is_err());
        assert!(execute("calculator", &serde_json::json!({"expression":"1/0"})).is_err());
    }

    #[test]
    fn unknown_tool_fails_closed() {
        assert!(execute("shell", &serde_json::json!({})).is_err());
        assert!(!is_known_tool("shell"));
    }

    #[test]
    fn safe_summary_never_contains_argument_values() {
        let secret = "super-secret-value";
        let summary = safe_call_summary("calculator", &serde_json::json!({"expression":secret}));
        assert!(summary.contains("expression"));
        assert!(!summary.contains(secret));
    }

    #[test]
    fn definitions_have_valid_schema_digests() {
        let defs = tool_definitions();
        // Wave 1 (Read/Write/Edit/Glob/Grep/Bash/TaskStop) + the three
        // locked pure built-ins + Wave 2 (TaskCreate/TaskUpdate/
        // TaskList/WebFetch).
        assert_eq!(defs.len(), 14);
        assert!(defs.iter().all(|d| d.schema_digest.as_str().len() == 64));
        // Every Wave 1 name is present exactly once.
        for name in ["Read", "Write", "Edit", "Glob", "Grep", "Bash", "TaskStop"] {
            assert_eq!(defs.iter().filter(|d| d.name == name).count(), 1, "{name}");
        }
    }

    #[test]
    fn malformed_arguments_are_rejected() {
        assert!(parse_arguments(b"not-json").is_err());
        assert!(parse_arguments(b"").is_err());
    }
}
