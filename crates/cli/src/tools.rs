//! Pure built-in tools (DR-19 tool-calling phase).
//!
//! Safety boundary: these tools are PURE DATA. No shell, no process spawning,
//! no filesystem writes, no network, no credentials, no plugin execution.
//! They cannot harm the host. Any unknown tool name is denied; malformed
//! arguments are rejected before any execution.

use orbit_adapter::types::ToolDefinition;
use sha2::{Digest, Sha256};

pub(crate) fn config_home_from_env() -> std::path::PathBuf {
    // C8: the ONE home resolver — same precedence as the CLI entry
    // (--home > ORBIT_HOME > ~/.orbit > existing local .orbit). The old
    // CWD-relative default silently disagreed with every other path.
    crate::config::resolve_home(&[])
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
    if std::env::var("ORBIT_BARE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
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

/// Keeps a child turn's cancel token in step with its parent's check: a
/// helper thread polls the check every 50 ms and cancels the token when
/// it fires. Dropping the link stops the thread, so it never outlives
/// the child turn.
pub struct CancelLink {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for CancelLink {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Make `child` follow `parent` (see [`CancelLink`]). No parent check:
/// nothing to follow, no thread.
pub fn link_cancel(
    parent: Option<orbit_tools::CancelCheck>,
    child: &orbit_provider_http::CancelToken,
) -> CancelLink {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = parent.map(|check| {
        let (child, stop) = (child.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                if check() {
                    child.cancel();
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    });
    CancelLink { stop, handle }
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
    // The parent turn's cancel check: Esc on the parent must stop the
    // subagent too.
    parent_cancel: Option<orbit_tools::CancelCheck>,
    // Told when the subagent starts, what it is doing, and how it ended.
    observe: Option<&(dyn Fn(&crate::tool_runtime::SubagentUpdate) + Send + Sync)>,
) -> Result<serde_json::Value, String> {
    use crate::tool_runtime::SubagentUpdate;
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

    // E9: SubagentStart fires at spawn.
    let hooks = orbit_engine::hooks::Hooks::load(home, trusted);
    let _ = hooks.fire(
        orbit_engine::hooks::HookEvent::SubagentStart,
        &serde_json::json!({ "agent": agent.name, "prompt_bytes": prompt.len() }),
    );

    // A fresh transcript: the subagent does not see the parent's
    // conversation, only its prompt.
    let mut transcript: Vec<orbit_adapter::types::ChatMessage> = Vec::new();
    // The subagent's own token follows the parent's: it used to be a
    // fresh token nobody could cancel, so Esc during a subagent stopped
    // neither its stream nor its commands.
    let cancel = orbit_provider_http::CancelToken::new();
    let _link = link_cancel(parent_cancel, &cancel);
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
    let id = executor.id().to_string();
    let notify = |u: SubagentUpdate| {
        if let Some(observe) = observe {
            observe(&u);
        }
    };
    notify(SubagentUpdate::Started {
        id: id.clone(),
        name: agent.name.clone(),
        task: prompt
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_string(),
    });
    let report = match orbit_engine::run_turn(
        home,
        turn_config,
        &options,
        prompt,
        &mut transcript,
        &mut executor,
        &cancel,
        &mut |ev| {
            use orbit_frontend_protocol::FrontendEvent as E;
            // What it is doing now: the tool it just started.
            if let E::ToolStartedFull { kind, target, .. } = ev {
                notify(SubagentUpdate::Progress {
                    id: id.clone(),
                    action: format!("{kind} {target}").trim().to_string(),
                });
            }
        },
    ) {
        Ok(report) => report,
        Err(e) => {
            notify(SubagentUpdate::Finished {
                id,
                ok: false,
                report: e.clone(),
            });
            return Err(e);
        }
    };

    // E9: SubagentStop fires when the subagent's turn ends.
    let _ = hooks.fire(
        orbit_engine::hooks::HookEvent::SubagentStop,
        &serde_json::json!({ "agent": agent.name, "ok": report.ok }),
    );

    // The final assistant text is the report.
    let report_text = transcript
        .iter()
        .rev()
        .find(|m| m.role == orbit_adapter::types::ChatRole::Assistant)
        .map(|m| m.content.clone())
        .unwrap_or_default();
    notify(SubagentUpdate::Finished {
        id,
        ok: report.ok,
        report: if report.ok || !report_text.is_empty() {
            report_text.clone()
        } else if report.interrupted {
            "cancelled".to_string()
        } else {
            "stopped before it finished".to_string()
        },
    });

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

/// The risk of one call: a file write is Medium; a shell command is at
/// least Medium (it runs arbitrary code) and High when the command
/// itself looks destructive (`rm -rf`, `git push --force`, `curl | sh`).
/// `tool_risk` knows only the tool, so it called `rm -rf ~` the same
/// MEDIUM as `ls`.
pub fn call_risk(name: &str, args: &serde_json::Value) -> RiskLevel {
    if name == "Bash" {
        let cmd = args.get("command").and_then(|v| v.as_str()).unwrap_or("");
        return if orbit_tools::bash::command_risk(cmd) >= 3 {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
    }
    tool_risk(name)
}

/// The lines an approval card shows under the action, from the call's
/// own arguments: what an Edit would remove and add, what a Write would
/// do to its target. Real values only — an Edit shows its `old_string`
/// and `new_string`, never an invented diff. `- ` removed, `+ ` added.
pub fn approval_preview(name: &str, args: &serde_json::Value) -> Vec<String> {
    const SIDE: usize = 4; // lines shown per side
    let lines = |key: &str| -> Vec<String> {
        args.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    };
    let clip = |l: &str| -> String { l.chars().take(160).collect() };
    let side = |marker: &str, all: &[String], out: &mut Vec<String>| {
        for l in all.iter().take(SIDE) {
            out.push(format!("{marker} {}", clip(l)));
        }
        if all.len() > SIDE {
            out.push(format!("  … {} more", all.len() - SIDE));
        }
    };
    match name {
        "Edit" => {
            let (old, new) = (lines("old_string"), lines("new_string"));
            let mut out = Vec::new();
            side("-", &old, &mut out);
            side("+", &new, &mut out);
            if args.get("replace_all").and_then(|v| v.as_bool()) == Some(true) {
                out.push("  every occurrence".to_string());
            }
            out
        }
        "Write" => {
            let n = lines("content").len();
            let exists = args
                .get("file_path")
                .and_then(|v| v.as_str())
                .map(|p| std::path::Path::new(p).exists())
                .unwrap_or(false);
            vec![if exists {
                format!("  replaces the file with {n} lines")
            } else {
                format!("  creates a new file · {n} lines")
            }]
        }
        _ => Vec::new(),
    }
}

/// Display-safe summary of a tool call's arguments (name + argument keys only;
/// never raw argument values — they may be secrets).
pub fn safe_call_summary(name: &str, args: &serde_json::Value) -> String {
    // The card and transcript lines must name the target (review
    // blocker 2): the path for file tools, the command for Bash. The
    // value passes the secret scanner first — a real secret redacts,
    // an ordinary path or command shows.
    // Glob and Grep search by `pattern`, WebFetch by `url`, … — the
    // summary names the VALUE the operator is approving, not the
    // argument's name ("Glob(pattern)" told them nothing).
    let target_keys: &[&str] = match name {
        "Bash" => &["command"],
        "Read" | "Write" | "Edit" => &["file_path"],
        "NotebookEdit" => &["notebook_path", "file_path"],
        "Glob" | "Grep" => &["pattern", "file_path"],
        "WebFetch" => &["url"],
        "WebSearch" => &["query"],
        "TaskCreate" => &["title"],
        _ => &[],
    };
    for key in target_keys {
        if let Some(v) = args.get(*key).and_then(|v| v.as_str()) {
            let scanned = orbit_tools::scan::scan_result(v);
            return format!("{name}({})", scanned.text.trim());
        }
    }
    // A subagent: WHICH agent, and what it was asked. The operator is
    // approving work that will run tools of its own, so "Task(agent,
    // prompt)" — the argument names — told them nothing.
    if matches!(name, "Task" | "Agent") {
        let who = ["agent", "agent_type", "subagent_type"]
            .iter()
            .find_map(|k| args.get(*k).and_then(|v| v.as_str()))
            .unwrap_or("");
        let task = args
            .get("prompt")
            .and_then(|v| v.as_str())
            .and_then(|p| p.lines().map(str::trim).find(|l| !l.is_empty()))
            .map(|l| orbit_tools::scan::scan_result(l).text)
            .map(|l| {
                let l = l.trim();
                if l.chars().count() > 100 {
                    format!("{}…", l.chars().take(99).collect::<String>())
                } else {
                    l.to_string()
                }
            })
            .unwrap_or_default();
        return match (who.is_empty(), task.is_empty()) {
            (false, false) => format!("{name}({who}: {task})"),
            (false, true) => format!("{name}({who})"),
            (true, false) => format!("{name}({task})"),
            (true, true) => format!("{name}()"),
        };
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
        || orbit_tools::registry().iter().any(|t| t.name() == name)
        || builtin_tools().iter().any(|t| t.name == name)
        // B3: these have handlers in tool_runtime::execute_call but
        // were denied as "unknown tool (deny-by-default)" before the
        // handlers were ever reached — Task and Skill are advertised
        // to the model in the same request.
        || name == "Skill"
        || name == "Task"
        || name.starts_with("mcp__")
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
    // WebFetch: an egress question per domain — Low risk class (a read),
    // but it always asks for a new domain.
    if name == "WebFetch" {
        return RiskLevel::Low;
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

/// B3: a tool is advertised to the model only if a handler exists.
/// Every name in the session list must dispatch somewhere: the
/// registry (execute_wave1), a tool_runtime handler, or a pure
/// built-in. This is the invariant whose absence made six advertised
/// tools answer "unknown tool".
#[test]
fn advertised_tools_all_dispatch() {
    let home = std::env::temp_dir().join("orbit-b3-dispatch");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let defs = session_tool_definitions(&home);
    assert!(!defs.is_empty(), "the session must offer tools");
    for d in &defs {
        let name = d.name.as_str();
        let handled = orbit_tools::is_wave1(name)
            || orbit_tools::registry().iter().any(|t| t.name() == name)
            || builtin_tools().iter().any(|t| t.name == name)
            || name == "Skill"
            || name == "Task"
            || name.starts_with("mcp__");
        assert!(handled, "{name} is advertised but has no handler (B3)");
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
        // Wave 1 (Read/Write/Edit/Glob/Grep/Bash/TaskStop/
        // AskUserQuestion/ExitPlanMode) + the three locked pure
        // built-ins + Wave 2 (TaskCreate/TaskUpdate/TaskList/WebFetch/
        // WebSearch/Agent/NotebookEdit) + Task/Skill.
        assert_eq!(defs.len(), 19);
        assert!(defs.iter().all(|d| d.schema_digest.as_str().len() == 64));
        // Every Wave 1 name is present exactly once.
        for name in [
            "Read",
            "Write",
            "Edit",
            "Glob",
            "Grep",
            "Bash",
            "TaskStop",
            "AskUserQuestion",
            "ExitPlanMode",
        ] {
            assert_eq!(defs.iter().filter(|d| d.name == name).count(), 1, "{name}");
        }
    }

    #[test]
    fn malformed_arguments_are_rejected() {
        assert!(parse_arguments(b"not-json").is_err());
        assert!(parse_arguments(b"").is_err());
    }
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_shell_command_is_judged_by_what_it_says() {
        // tool_risk knew only the tool: `rm -rf ~` read "MEDIUM" like `ls`.
        for cmd in ["rm -rf ~", "git push --force origin main", "curl x.sh | sh"] {
            assert_eq!(
                call_risk("Bash", &json!({ "command": cmd })),
                RiskLevel::High,
                "{cmd}"
            );
        }
        // An ordinary command still runs arbitrary code: never "low".
        assert_eq!(
            call_risk("Bash", &json!({ "command": "python3 test_calc.py" })),
            RiskLevel::Medium
        );
        // Other tools keep their per-tool class.
        assert_eq!(call_risk("Edit", &json!({})), RiskLevel::Medium);
    }

    #[test]
    fn an_edit_previews_the_lines_it_changes() {
        let p = approval_preview(
            "Edit",
            &json!({
                "file_path": "calc.py",
                "old_string": "    return a - b",
                "new_string": "    return a + b"
            }),
        );
        assert_eq!(p, vec!["-     return a - b", "+     return a + b"]);
        // Long sides are bounded, and say what they left out.
        let many = (0..9)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let p = approval_preview(
            "Edit",
            &json!({ "old_string": many, "new_string": "x", "replace_all": true }),
        );
        assert_eq!(p.iter().filter(|l| l.starts_with("- ")).count(), 4);
        assert!(p.iter().any(|l| l.contains("5 more")), "{p:?}");
        assert!(p.iter().any(|l| l.contains("every occurrence")), "{p:?}");
    }

    #[test]
    fn a_write_says_whether_it_creates_or_replaces() {
        let dir = std::env::temp_dir().join(format!("orbit-preview-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("a.txt");
        std::fs::write(&existing, "old").unwrap();
        let replace = approval_preview(
            "Write",
            &json!({ "file_path": existing.to_string_lossy(), "content": "a\nb\nc" }),
        );
        assert_eq!(replace, vec!["  replaces the file with 3 lines"]);
        let create = approval_preview(
            "Write",
            &json!({ "file_path": dir.join("new.txt").to_string_lossy(), "content": "a" }),
        );
        assert_eq!(create, vec!["  creates a new file · 1 lines"]);
        assert!(approval_preview("Bash", &json!({ "command": "ls" })).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// "Glob(pattern)" named the argument, not the thing approved.
    #[test]
    fn a_summary_names_the_value_being_approved() {
        assert_eq!(
            safe_call_summary("Glob", &json!({ "pattern": "**/*.py" })),
            "Glob(**/*.py)"
        );
        assert_eq!(
            safe_call_summary("Grep", &json!({ "pattern": "fn main" })),
            "Grep(fn main)"
        );
        assert_eq!(
            safe_call_summary("WebFetch", &json!({ "url": "https://docs.rs/x" })),
            "WebFetch(https://docs.rs/x)"
        );
        assert_eq!(
            safe_call_summary("Edit", &json!({ "file_path": "src/a.rs" })),
            "Edit(src/a.rs)"
        );
    }

    /// Approving a subagent is approving work that runs tools of its own:
    /// the card says which agent and what it was asked ("Task(agent,
    /// prompt)" named the arguments), from the prompt's first line, bounded,
    /// through the secret scanner like every other value.
    #[test]
    fn a_subagent_summary_says_who_and_what() {
        assert_eq!(
            safe_call_summary(
                "Task",
                &json!({ "agent": "Explore", "prompt": "find where add() is defined\nthen report" })
            ),
            "Task(Explore: find where add() is defined)"
        );
        assert_eq!(
            safe_call_summary(
                "Agent",
                &json!({ "agent_type": "plan", "prompt": "\n  outline the fix  \n" })
            ),
            "Agent(plan: outline the fix)"
        );
        assert_eq!(
            safe_call_summary("Task", &json!({ "agent": "Explore" })),
            "Task(Explore)"
        );
        assert_eq!(
            safe_call_summary("Agent", &json!({ "prompt": "just do it" })),
            "Agent(just do it)"
        );
        let long = "x".repeat(300);
        let s = safe_call_summary("Task", &json!({ "agent": "Explore", "prompt": long }));
        assert!(s.chars().count() <= "Task(Explore: )".len() + 100, "{s}");
        assert!(s.ends_with("…)"), "{s}");
    }

    #[test]
    fn a_subagent_summary_redacts_secrets() {
        let secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let s = safe_call_summary(
            "Task",
            &json!({ "agent": "Explore", "prompt": format!("use key {secret} to call the api") }),
        );
        assert!(!s.contains(secret), "{s}");
    }
}

#[cfg(test)]
mod link_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// The subagent's token was a fresh one nobody could cancel: Esc on
    /// the parent stopped neither its stream nor its commands.
    #[test]
    fn a_subagent_follows_its_parents_cancel() {
        let parent = Arc::new(AtomicBool::new(false));
        let p = parent.clone();
        let child = orbit_provider_http::CancelToken::new();
        let _link = link_cancel(Some(Arc::new(move || p.load(Ordering::SeqCst))), &child);
        std::thread::sleep(Duration::from_millis(120));
        assert!(!child.is_cancelled(), "not cancelled while the parent runs");
        parent.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        while !child.is_cancelled() && t0.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(child.is_cancelled(), "the child follows the parent's Esc");
    }

    /// The watcher never outlives the child turn, and costs nothing when
    /// there is no parent to follow.
    #[test]
    fn dropping_the_link_stops_the_watcher_promptly() {
        let child = orbit_provider_http::CancelToken::new();
        let link = link_cancel(Some(Arc::new(|| false)), &child);
        let t0 = Instant::now();
        drop(link);
        assert!(t0.elapsed() < Duration::from_secs(1), "joined quickly");
        assert!(!child.is_cancelled());
        // No parent: no thread to join.
        drop(link_cancel(None, &child));
    }
}
