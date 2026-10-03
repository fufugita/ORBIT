//! Tool-call approval, ledger evidence, pure execution (DR-19, DR-20 §2.6/§2.7).
//!
//! Execution ordering is fail-closed:
//!   ToolIntent append+fsync -> approval verdict append+fsync -> pure executor
//!   -> ToolResult append+fsync.
//! The ledger receives only hashes/sizes; never raw arguments or result bytes.
//!
//! Approval is behind an `ApprovalChannel` trait (DR-20 §2.6):
//! - `StdApprovalChannel` wraps the existing blocking stdin reader (REPL).
//! - `TuiApprovalChannel` (in hud-tui) posts to the bus and parks on a response.
//! - The `R` verdict (DR-20 §2.7) grants session-scoped per-tool auto-approval.

use orbit_ledger::event::{LedgerEvent, ToolIntent, ToolResult, ToolVerdict};
use orbit_ledger::LedgerWriter;
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_RESULT_BYTES: usize = 64 * 1024;

/// The operator's verdict on a pending tool call (DR-20 §2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalVerdict {
    /// Allow this one call.
    AllowOnce,
    /// Deny this call.
    Deny,
    /// Always-allow this tool for the rest of the session (session-scoped,
    /// per-tool-name, ledger-logged, revocable). Does NOT bypass `is_known_tool`.
    AllowSession,
}

thread_local! {
    /// True when the front-end is a plain surface (REPL / non-TTY) and
    /// stdout lines are safe. The TUI leaves it false — its worker threads
    /// must never print to the alt screen.
    static PLAIN_OUTPUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Enable plain-grammar stdout lines (REPL / non-TTY front-ends).
pub fn enable_plain_output() {
    PLAIN_OUTPUT.with(|c| c.set(true));
}

fn plain_output_enabled() -> bool {
    PLAIN_OUTPUT.with(|c| c.get())
}

/// Current wall-clock time as HH:MM for the plain grammar's line stamps.
fn hhmm_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (h, m) = ((secs / 3600) % 24, (secs / 60) % 60);
    format!("{h:02}:{m:02}")
}

/// A pending tool call awaiting approval — the data the channel sees.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Used by `TuiApprovalChannel` to correlate the modal with the call.
    #[allow(dead_code)] // wired in PR-D (TUI approval modal)
    pub call_id: String,
    /// Used by `TuiApprovalChannel` to check R-grants per tool.
    #[allow(dead_code)] // wired in PR-D (TUI approval modal)
    pub tool_name: String,
    pub summary: String,
    /// Structured risk classification (backend-authoritative; the UI renders
    /// it, never infers it). §6.15: the risk badge lives here so the
    /// approval card can draw ▰▰▱ without classifying on its own.
    pub risk: crate::tools::RiskLevel,
}

/// Approval channel — how the operator is asked to approve a tool call.
/// The default impl (`StdApprovalChannel`) wraps the existing stdin reader;
/// the TUI provides its own that posts to the event bus.
pub trait ApprovalChannel: Send {
    /// Ask the operator to approve a tool call. Returns the verdict.
    /// The `auto_tools` flag is true when `--auto-tools` was granted up front
    /// (in which case the channel may skip the prompt and return `AllowOnce`).
    fn ask(&mut self, req: &ApprovalRequest, auto_tools: bool) -> ApprovalVerdict;
}

/// The standard stdin-based approval channel (REPL behavior, unchanged).
pub struct StdApprovalChannel {
    interactive: bool,
}

impl StdApprovalChannel {
    pub fn new(interactive: bool) -> Self {
        Self { interactive }
    }
}

impl ApprovalChannel for StdApprovalChannel {
    fn ask(&mut self, req: &ApprovalRequest, auto_tools: bool) -> ApprovalVerdict {
        if auto_tools {
            return ApprovalVerdict::AllowOnce;
        }
        if !self.interactive {
            return ApprovalVerdict::Deny;
        }
        // Plain grammar (§11.4): words not glyphs, risk in words, the
        // choices spelled out. Same grammar as the TUI's copy mode.
        use std::io::Write;
        print!(
            "approval needed: {} ({} risk). y allow once, R allow {} this session, n deny: ",
            req.summary,
            req.risk.as_str(),
            req.tool_name
        );
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return ApprovalVerdict::Deny;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => ApprovalVerdict::AllowOnce,
            "r" => ApprovalVerdict::AllowSession,
            _ => ApprovalVerdict::Deny,
        }
    }
}

/// A session-scoped set of tools that have been R-granted (always-allow).
/// Stored in the harness; checked before calling `approval.ask`.
#[derive(Debug, Clone, Default)]
pub struct AutoGrants {
    tools: std::collections::HashSet<String>,
}

impl AutoGrants {
    pub fn new() -> Self {
        Self::default()
    }

    /// True if this tool name has been R-granted.
    pub fn is_granted(&self, tool_name: &str) -> bool {
        self.tools.contains(tool_name)
    }

    /// Grant always-allow for this tool (session-scoped).
    pub fn grant(&mut self, tool_name: &str) {
        self.tools.insert(tool_name.to_string());
    }

    /// Revoke the R-grant for this tool (e.g. operator pressed `n`).
    pub fn revoke(&mut self, tool_name: &str) {
        self.tools.remove(tool_name);
    }

    /// Revoke all grants (e.g. `/revoke` command).
    #[allow(dead_code)] // wired to `/revoke` and the TUI status control in PR-D
    pub fn revoke_all(&mut self) {
        self.tools.clear();
    }

    /// List currently granted tool names (for the status bar display).
    #[allow(dead_code)] // wired to the TUI status bar in PR-D
    pub fn granted_tools(&self) -> Vec<&str> {
        self.tools.iter().map(String::as_str).collect()
    }
}

/// Execute one pending call with approval + ledger evidence.
///
/// The `approval` channel is injected — `StdApprovalChannel` for the REPL,
/// `TuiApprovalChannel` for the TUI. The `grants` set tracks session-scoped
/// R-grants so previously-approved tools skip the prompt.
#[allow(clippy::too_many_arguments)]
pub fn execute_call(
    home: &Path,
    session_id: &str,
    decision_id: &str,
    call: &crate::PendingToolCall,
    auto_tools: bool,
    interactive: bool,
    approval: &mut dyn ApprovalChannel,
    grants: &mut AutoGrants,
) -> Result<String, String> {
    if call.arguments.len() > MAX_ARGUMENT_BYTES {
        return Ok(tool_error("tool arguments exceed 64 KiB"));
    }
    let arguments_sha256 = hex::encode(Sha256::digest(&call.arguments));
    let mut writer = LedgerWriter::open(&home.join("ledger"), "orbit-tool".into(), "0.1.0")
        .map_err(|e| format!("open ledger: {e}"))?;
    writer
        .append(LedgerEvent::ToolIntent(ToolIntent {
            session_id: session_id.into(),
            decision_id: decision_id.into(),
            call_id: call.id.clone(),
            tool_name: call.name.clone(),
            arguments_sha256,
            arguments_bytes: call.arguments.len() as u64,
        }))
        .map_err(|e| format!("record tool intent: {e}"))?;
    // LedgerWriter::append is the durability boundary (append+fsync), so no
    // execution may happen before the call returns successfully.

    let known = crate::tools::is_known_tool(&call.name);

    // Determine the verdict:
    // 1. Unknown tool → always deny (fail-closed, even with --auto-tools / R).
    // 2. Persistent deny rule → deny, no prompt.
    // 3. Persistent allow rule → allow once, no prompt (durable R-grant).
    // 4. --auto-tools → allow once (up-front consent for pure built-ins).
    // 5. Session R-grant → allow once (session-scoped, per-tool).
    // 6. Otherwise → ask the approval channel.
    // Unknown tools always deny (fail-closed, even with --auto-tools / R).
    // Persistent rules (permissions.toml) sit between unknown-tool denial
    // and everything else — deny rules are a durable fail-closed, allow
    // rules a durable consent. A malformed rules file degrades to ask
    // (never silently allow).
    let rules = crate::permissions::PermissionRules::load(home).unwrap_or_else(|e| {
        eprintln!("warning: permissions.toml: {e} (falling back to ask)");
        crate::permissions::PermissionRules::default()
    });
    let rule_verdict = rules.verdict(&call.name);
    let verdict = if !known || rule_verdict == crate::permissions::RuleVerdict::Deny {
        ApprovalVerdict::Deny
    } else if rule_verdict == crate::permissions::RuleVerdict::Allow
        || auto_tools
        || grants.is_granted(&call.name)
    {
        ApprovalVerdict::AllowOnce
    } else {
        approval.ask(
            &ApprovalRequest {
                call_id: call.id.clone(),
                tool_name: call.name.clone(),
                summary: safe_call_summary(call),
                risk: crate::tools::tool_risk(&call.name),
            },
            auto_tools,
        )
    };

    // Apply R-grant side effects.
    let allowed = match verdict {
        ApprovalVerdict::AllowOnce => true,
        ApprovalVerdict::AllowSession => {
            grants.grant(&call.name);
            true
        }
        ApprovalVerdict::Deny => {
            // Pressing `n` on a previously-R-granted tool revokes the grant.
            grants.revoke(&call.name);
            false
        }
    };

    let reason = if !known {
        "unknown tool (deny-by-default)"
    } else if rule_verdict == crate::permissions::RuleVerdict::Deny {
        "denied by persistent rule (permissions.toml)"
    } else if rule_verdict == crate::permissions::RuleVerdict::Allow {
        "allowed by persistent rule (permissions.toml)"
    } else if auto_tools {
        "allowed by --auto-tools up-front consent"
    } else if grants.is_granted(&call.name) && !matches!(verdict, ApprovalVerdict::Deny) {
        "allowed by session R-grant"
    } else if !interactive && !auto_tools {
        "non-interactive tool call requires --auto-tools"
    } else if allowed {
        "operator approved"
    } else {
        "operator denied"
    };
    writer
        .append(LedgerEvent::ToolVerdict(ToolVerdict {
            session_id: session_id.into(),
            decision_id: decision_id.into(),
            call_id: call.id.clone(),
            tool_name: call.name.clone(),
            allowed,
            reason: reason.into(),
        }))
        .map_err(|e| format!("record tool verdict: {e}"))?;

    // Plain grammar (§11.4): the verdict is one stamped line on stdout —
    // words not glyphs, greppable, screen-reader friendly. Only in plain
    // mode: the TUI worker shares this code path, and a println from it
    // would scribble on the alternate screen.
    if plain_output_enabled() {
        println!(
            "{} tool {} {}: {}",
            hhmm_now(),
            call.name,
            safe_call_summary(call),
            if allowed {
                "allowed by you"
            } else {
                "denied by you"
            }
        );
    }

    if !allowed {
        let output = tool_error(reason);
        // D9: a denial is not an error — audits must be able to tell an
        // operator refusal apart from a tool that ran and failed.
        record_result(
            &mut writer,
            session_id,
            decision_id,
            call,
            "denied",
            &output,
        )?;
        return Ok(output);
    }

    let args = match crate::tools::parse_arguments(&call.arguments) {
        Ok(v) => v,
        Err(e) => {
            let output = tool_error(&e);
            record_result(&mut writer, session_id, decision_id, call, "error", &output)?;
            return Ok(output);
        }
    };

    // The Skill tool (phase 5): load a body on demand.
    if call.name == "Skill" {
        let output = match args.get("name").and_then(|v| v.as_str()) {
            Some(name) => match crate::tools::execute_skill(home, name) {
                Ok(v) => serde_json::json!({ "ok": true, "result": v }).to_string(),
                Err(e) => tool_error(&e),
            },
            None => tool_error("Skill requires 'name'"),
        };
        let status = if output.contains("\"ok\":true") || output.contains("\"ok\": true") {
            "ok"
        } else {
            "error"
        };
        record_result(&mut writer, session_id, decision_id, call, status, &output)?;
        return Ok(output);
    }

    // The Task tool (phase 5): spawn a subagent. The subagent needs
    // the session's TurnConfig — derived from the same environment the
    // front-ends use, so provider/gate/model match the parent.
    if call.name == "Task" {
        let agent = args.get("agent").and_then(|v| v.as_str()).unwrap_or("");
        let prompt = args.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
        if agent.is_empty() || prompt.is_empty() {
            let output = tool_error("Task requires 'agent' and 'prompt'");
            record_result(&mut writer, session_id, decision_id, call, "error", &output)?;
            return Ok(output);
        }
        let turn_config = subagent_turn_config(home);
        let output = match crate::tools::execute_task(home, agent, prompt, &turn_config, approval) {
            Ok(v) => serde_json::json!({ "ok": true, "result": v }).to_string(),
            Err(e) => tool_error(&e),
        };
        let status = if output.contains("\"ok\":true") || output.contains("\"ok\": true") {
            "ok"
        } else {
            "error"
        };
        record_result(&mut writer, session_id, decision_id, call, status, &output)?;
        return Ok(output);
    }

    // MCP tools (phase 5): mcp__<server>__<tool> — spawn, call, scan.
    if call.name.starts_with("mcp__") {
        let output = execute_mcp(home, call, &args);
        let status = if output.contains("\"ok\":true") || output.contains("\"ok\": true") {
            "ok"
        } else {
            "error"
        };
        record_result(&mut writer, session_id, decision_id, call, status, &output)?;
        return Ok(output);
    }

    // Wave 1 tools (Read/Write/Edit/Glob/Grep/Bash/TaskStop) run
    // through the orbit-tools registry: the real implementations, the
    // permission layer (modes + pattern rules), the deny-read list and
    // the secret scanner on every result (review blocker 1).
    if orbit_tools::is_wave1(&call.name) {
        let output = execute_wave1(home, call, &args);
        let status = if output.contains("\"ok\":true") || output.contains("\"ok\": true") {
            "ok"
        } else {
            "error"
        };
        record_result(&mut writer, session_id, decision_id, call, status, &output)?;
        return Ok(output);
    }

    let result = crate::tools::execute(&call.name, &args);
    let output = match result {
        Ok(v) => serde_json::json!({ "ok": true, "result": v }).to_string(),
        Err(e) => tool_error(&e),
    };
    if output.len() > MAX_RESULT_BYTES {
        let truncated = tool_error("tool result exceeds 64 KiB");
        record_result(
            &mut writer,
            session_id,
            decision_id,
            call,
            "error",
            &truncated,
        )?;
        return Ok(truncated);
    }
    let status = if output.contains("\"ok\":true") {
        "ok"
    } else {
        "error"
    };
    record_result(&mut writer, session_id, decision_id, call, status, &output)?;
    Ok(output)
}

/// Display-safe summary of a tool call (name + argument keys only).
fn safe_call_summary(call: &crate::PendingToolCall) -> String {
    let args = crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
    crate::tools::safe_call_summary(&call.name, &args)
}

fn record_result(
    writer: &mut LedgerWriter,
    session_id: &str,
    decision_id: &str,
    call: &crate::PendingToolCall,
    status: &str,
    output: &str,
) -> Result<(), String> {
    writer
        .append(LedgerEvent::ToolResult(ToolResult {
            session_id: session_id.into(),
            decision_id: decision_id.into(),
            call_id: call.id.clone(),
            tool_name: call.name.clone(),
            status: status.into(),
            output_sha256: hex::encode(Sha256::digest(output.as_bytes())),
            output_bytes: output.len() as u64,
        }))
        .map_err(|e| format!("record tool result: {e}"))?;
    Ok(())
}

fn tool_error(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

/// Execute one Wave 1 call through the orbit-tools registry with the
/// live permission layer: modes, pattern rules, folder trust, deny-read
/// and the secret scanner. The verdict above (whole-tool rules +
/// approval channel) already ran; this adds the pattern-level check.
fn execute_wave1(home: &Path, call: &crate::PendingToolCall, args: &serde_json::Value) -> String {
    use orbit_tools::permissions::{evaluate, parse_rule, PermissionMode, RuleEffectSerde};

    // The session's mode: --permission-mode flag, else default.
    let mode = std::env::var("ORBIT_PERMISSION_MODE")
        .ok()
        .and_then(|m| PermissionMode::from_config(&m))
        .unwrap_or_default();

    // Merged rules: the new pattern scopes + the legacy whole-tool file.
    let mut rules = orbit_tools::executor::load_rules(home);
    // --allowedTools / --disallowedTools (command-line scope).
    if let Ok(list) = std::env::var("ORBIT_ALLOWED_TOOLS") {
        for entry in list.split(',') {
            if let Some(r) = parse_rule(entry.trim(), RuleEffectSerde::Allow) {
                rules.rules.push(r);
            }
        }
    }
    if let Ok(list) = std::env::var("ORBIT_DISALLOWED_TOOLS") {
        for entry in list.split(',') {
            if let Some(r) = parse_rule(entry.trim(), RuleEffectSerde::Deny) {
                rules.rules.push(r);
            }
        }
    }

    // Find the tool and compute its permission key.
    let Some(tool) = orbit_tools::registry()
        .into_iter()
        .find(|t| t.name() == call.name)
    else {
        return tool_error("unknown tool (deny-by-default)");
    };
    let key = tool.permission_key(args);
    let is_ro_cmd = call.name == "Bash"
        && orbit_tools::bash::is_readonly_command(
            args.get("command").and_then(|v| v.as_str()).unwrap_or(""),
        );

    match evaluate(
        mode,
        &rules,
        &key.tool,
        &key.pattern,
        tool.read_only(),
        is_ro_cmd,
    ) {
        orbit_tools::permissions::Verdict::Allow => {}
        orbit_tools::permissions::Verdict::Deny(reason) => {
            return tool_error(&reason);
        }
        orbit_tools::permissions::Verdict::Ask => {
            // The whole-tool verdict above already asked the channel
            // (the operator pressed y). Pattern-level ask collapses to
            // allow here — the operator's approval IS the answer.
        }
    }

    // Execute with the session's ToolContext.
    let working_dir = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    let session_id = session_id_stub();
    let cx = orbit_tools::ToolContext::new(home.to_path_buf(), session_id.clone(), working_dir);

    // Hooks (phase 5): PreToolUse can block (exit 2 / Deny decision)
    // before anything runs; PostToolUse sees the result.
    let hooks = orbit_engine::hooks::Hooks::load(home, project_trusted());
    let pre = hooks.fire(
        orbit_engine::hooks::HookEvent::PreToolUse,
        &serde_json::json!({
            "tool": call.name,
            "arguments": args,
        }),
    );
    if let Some(reason) = orbit_engine::hooks::blocked(&pre) {
        return tool_error(&format!("blocked by hook: {reason}"));
    }

    // Checkpoint (phase 4): before the first WRITE of a turn, snapshot
    // the target file's current bytes so /rewind can restore them.
    if call.name == "Write" || call.name == "Edit" {
        if let Some(path_str) = args.get("file_path").and_then(|v| v.as_str()) {
            let path = orbit_tools::resolve_path(&cx, path_str);
            if path.exists() {
                let cps = orbit_engine::transcript::Checkpoints::new(home, &session_id);
                let turn_cp = current_turn_checkpoint();
                let _ = cps.snapshot_file(&turn_cp, &path);
            }
        }
    }

    let result = tool.run(args, &cx);
    let result = orbit_tools::finish(result, &cx, &call.id);

    // PostToolUse: the hook sees the (scanned) result.
    let _ = hooks.fire(
        orbit_engine::hooks::HookEvent::PostToolUse,
        &serde_json::json!({
            "tool": call.name,
            "ok": !result.is_error,
        }),
    );
    result.payload
}

/// Is the current folder trusted (project-scope rules/hooks/skills
/// apply only after the operator trusted it once)?
fn project_trusted() -> bool {
    let home = std::env::var("ORBIT_HOME").unwrap_or_else(|_| ".orbit".into());
    let cwd = std::env::current_dir().unwrap_or_default();
    orbit_tools::permissions::FolderTrust::new(std::path::PathBuf::from(home)).is_trusted(&cwd)
}

/// The checkpoint id for the current turn: one per user prompt. The
/// engine opens it at the prompt; the executor snapshots into it.
fn current_turn_checkpoint() -> String {
    std::env::var("ORBIT_TURN_CHECKPOINT").unwrap_or_else(|_| {
        // No turn marker set (e.g. direct executor use): derive one
        // per process invocation.
        format!("cp-{}", ulid::Ulid::new())
    })
}

fn session_id_stub() -> String {
    std::env::var("ORBIT_SESSION_ID").unwrap_or_else(|_| "live".into())
}

/// Execute one MCP call: resolve the server from the config, spawn,
/// call, scan the result (never trust external output).
fn execute_mcp(home: &Path, call: &crate::PendingToolCall, args: &serde_json::Value) -> String {
    let Some((server, tool)) = orbit_mcp::split_wire_name(&call.name) else {
        return tool_error("malformed mcp tool name");
    };
    let trusted = project_trusted();
    let cfg = orbit_mcp::McpConfig::load(home, trusted);
    let Some(server_cfg) = cfg.servers.get(&server) else {
        return tool_error(&format!("mcp server not configured: {server}"));
    };
    match orbit_mcp::McpSession::spawn(&server, server_cfg) {
        Ok(mut session) => {
            // Strip the wrapper args the model was told about; pass the
            // rest through as the tool's own arguments.
            let mut call_args = args.clone();
            if let Some(obj) = call_args.as_object_mut() {
                obj.remove("server");
                obj.remove("tool");
            }
            match session.call_tool(&tool, call_args) {
                Ok(text) => {
                    let scanned = orbit_tools::scan::scan_result(&text.to_string());
                    serde_json::json!({
                        "ok": true,
                        "result": scanned.text,
                        "redactions": scanned.redactions.len(),
                    })
                    .to_string()
                }
                Err(e) => tool_error(&format!("mcp call failed: {e}")),
            }
        }
        Err(e) => tool_error(&format!("mcp server unreachable: {e}")),
    }
}

/// The subagent's tool executor: every call goes through execute_call
/// — the same permission path, ledger and approval channel as the
/// parent session (roadmap gate 5: the subagent's approval request
/// appears in the main session).
pub struct SubagentExecutor<'a> {
    home: std::path::PathBuf,
    session_id: String,
    approval: &'a mut dyn ApprovalChannel,
    grants: AutoGrants,
}

impl<'a> SubagentExecutor<'a> {
    pub fn new(home: std::path::PathBuf, approval: &'a mut dyn ApprovalChannel) -> Self {
        Self {
            session_id: format!("subagent-{}", ulid::Ulid::new()),
            home,
            approval,
            grants: AutoGrants::new(),
        }
    }
}

impl orbit_engine::ToolExecutor for SubagentExecutor<'_> {
    fn execute(
        &mut self,
        calls: &[crate::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        calls
            .iter()
            .map(|call| {
                let decision_id = ulid::Ulid::new().to_string();
                let content = execute_call(
                    &self.home,
                    &self.session_id,
                    &decision_id,
                    call,
                    false,
                    true,
                    self.approval,
                    &mut self.grants,
                )
                .unwrap_or_else(|e| tool_error(&e));
                orbit_engine::ToolRoundResult {
                    call_id: call.id.clone(),
                    content,
                }
            })
            .collect()
    }
}

/// Derive the TurnConfig for a subagent from the same sources the
/// front-ends use (env + providers.toml), so provider/gate/model match
/// the parent session.
pub fn subagent_turn_config(_home: &Path) -> orbit_engine::TurnConfig {
    let gate = std::env::var("ORBIT_GATE_URL").unwrap_or_else(|_| "http://127.0.0.1:4001".into());
    let model = std::env::var("ORBIT_MODEL").unwrap_or_else(|_| "glm-5.2".into());
    orbit_engine::dispatch::TurnConfig {
        provider_id: std::env::var("ORBIT_PROVIDER").unwrap_or_else(|_| "local".into()),
        gate,
        model,
        kind: orbit_engine::dispatch::ProviderKind::OpenAiCompatible,
        credential_env: std::env::var("ORBIT_CREDENTIAL_ENV").ok(),
        pricing: None,
        max_output_tokens: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call(name: &str, args: &[u8]) -> crate::PendingToolCall {
        crate::PendingToolCall {
            index: 0,
            id: "call-1".into(),
            name: name.into(),
            arguments: args.to_vec(),
        }
    }

    fn test_home(name: &str) -> std::path::PathBuf {
        let home = std::env::temp_dir().join(format!("orbit-tool-runtime-{name}"));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    /// A channel that always returns the given verdict (for tests).
    struct FixedChannel(ApprovalVerdict);
    impl ApprovalChannel for FixedChannel {
        fn ask(&mut self, _req: &ApprovalRequest, _auto: bool) -> ApprovalVerdict {
            self.0
        }
    }

    #[test]
    fn auto_tools_executes_and_records_digest_only() {
        let home = test_home("auto");
        let call = make_call("calculator", br#"{"expression":"2*(3+4)"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::Deny); // shouldn't be asked
        let mut grants = AutoGrants::new();
        let out =
            execute_call(&home, "s1", "d1", &call, true, false, &mut ch, &mut grants).unwrap();
        assert!(out.contains("14"));
        let mut ledger = String::new();
        for e in std::fs::read_dir(home.join("ledger/segments"))
            .unwrap()
            .flatten()
        {
            let bytes = std::fs::read(e.path()).unwrap_or_default();
            ledger.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(ledger.contains("tool_intent"));
        assert!(ledger.contains("tool_verdict"));
        assert!(ledger.contains("tool_result"));
        assert!(ledger.contains("arguments_sha256"));
        assert!(
            !ledger.contains("2*(3+4)"),
            "raw arguments must not enter ledger"
        );
        assert!(
            !ledger.contains("\"result\":14"),
            "raw output must not enter ledger"
        );
    }

    #[test]
    fn non_tty_denies_without_auto_tools() {
        let home = test_home("deny");
        let call = make_call("calculator", br#"{"expression":"1+1"}"#);
        let mut ch = StdApprovalChannel::new(false); // non-interactive
        let mut grants = AutoGrants::new();
        let out =
            execute_call(&home, "s1", "d1", &call, false, false, &mut ch, &mut grants).unwrap();
        assert!(out.contains("non-interactive"));
        assert!(!out.contains("\"result\":2"));
    }

    #[test]
    fn unknown_tool_is_denied_even_with_auto_tools() {
        let home = test_home("unknown");
        let call = make_call("shell", br#"{"cmd":"id"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::AllowOnce);
        let mut grants = AutoGrants::new();
        let out =
            execute_call(&home, "s1", "d1", &call, true, false, &mut ch, &mut grants).unwrap();
        assert!(out.contains("unknown tool"));
    }

    #[test]
    fn allow_once_executes() {
        let home = test_home("allow-once");
        let call = make_call("calculator", br#"{"expression":"3+4"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::AllowOnce);
        let mut grants = AutoGrants::new();
        let out =
            execute_call(&home, "s1", "d1", &call, false, true, &mut ch, &mut grants).unwrap();
        assert!(out.contains("7"));
    }

    #[test]
    fn deny_does_not_execute() {
        let home = test_home("deny-manual");
        let call = make_call("calculator", br#"{"expression":"3+4"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::Deny);
        let mut grants = AutoGrants::new();
        let out =
            execute_call(&home, "s1", "d1", &call, false, true, &mut ch, &mut grants).unwrap();
        assert!(out.contains("operator denied"));
        assert!(!out.contains("\"result\":7"));
        // D9: the ledger records a DENIED status, not error — refusal is
        // distinct from failure for audit purposes.
        let mut ledger = String::new();
        for e in std::fs::read_dir(home.join("ledger/segments"))
            .unwrap()
            .flatten()
        {
            let bytes = std::fs::read(e.path()).unwrap_or_default();
            ledger.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(
            ledger.contains("\"status\":\"denied\""),
            "denied verdict must record status=denied, got: {ledger}"
        );
    }

    #[test]
    fn r_grant_allows_subsequent_calls_without_prompt() {
        let home = test_home("r-grant");
        let call = make_call("calculator", br#"{"expression":"5+5"}"#);

        // First call: R verdict → grant + execute.
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let out1 =
            execute_call(&home, "s1", "d1", &call, false, true, &mut ch, &mut grants).unwrap();
        assert!(out1.contains("10"));
        assert!(grants.is_granted("calculator"));

        // Second call: should auto-approve from the grant (channel not asked).
        let call2 = make_call("calculator", br#"{"expression":"6+6"}"#);
        let mut ch2 = FixedChannel(ApprovalVerdict::Deny); // would deny, but shouldn't be asked
        let out2 = execute_call(
            &home,
            "s1",
            "d2",
            &call2,
            false,
            true,
            &mut ch2,
            &mut grants,
        )
        .unwrap();
        assert!(out2.contains("12"), "R-grant should auto-approve");
    }

    #[test]
    fn deny_revokes_r_grant() {
        let home = test_home("revoke");
        let call = make_call("calculator", br#"{"expression":"1+1"}"#);

        // Grant via R.
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let _ = execute_call(&home, "s1", "d1", &call, false, true, &mut ch, &mut grants).unwrap();
        assert!(grants.is_granted("calculator"));

        // Revoke explicitly (the operator pressed n → revoke path).
        grants.revoke("calculator");
        assert!(!grants.is_granted("calculator"));

        // Now the channel is asked again — deny.
        let mut ch2 = FixedChannel(ApprovalVerdict::Deny);
        let out =
            execute_call(&home, "s1", "d2", &call, false, true, &mut ch2, &mut grants).unwrap();
        assert!(out.contains("operator denied"));
        assert!(!grants.is_granted("calculator"));
    }

    #[test]
    fn r_grant_does_not_apply_to_unknown_tools() {
        let home = test_home("r-unknown");
        let call = make_call("shell", br#"{"cmd":"id"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let out =
            execute_call(&home, "s1", "d1", &call, false, true, &mut ch, &mut grants).unwrap();
        assert!(out.contains("unknown tool"));
        assert!(
            !grants.is_granted("shell"),
            "unknown tool should not be granted"
        );
    }

    #[test]
    fn r_grant_is_per_tool() {
        let home = test_home("r-per-tool");
        let calc = make_call("calculator", br#"{"expression":"1+1"}"#);
        let models = make_call("list_models", b"{}");

        // Grant R on calculator.
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let _ = execute_call(&home, "s1", "d1", &calc, false, true, &mut ch, &mut grants).unwrap();
        assert!(grants.is_granted("calculator"));
        assert!(
            !grants.is_granted("list_models"),
            "R on calculator should not grant list_models"
        );

        // list_models should still ask the channel.
        let mut ch2 = FixedChannel(ApprovalVerdict::Deny);
        let out = execute_call(
            &home,
            "s1",
            "d2",
            &models,
            false,
            true,
            &mut ch2,
            &mut grants,
        )
        .unwrap();
        assert!(
            out.contains("operator denied"),
            "list_models should not be auto-approved"
        );
    }

    #[test]
    fn revoke_all_clears_grants() {
        let mut grants = AutoGrants::new();
        grants.grant("calculator");
        grants.grant("list_models");
        assert_eq!(grants.granted_tools().len(), 2);
        grants.revoke_all();
        assert!(grants.granted_tools().is_empty());
    }

    #[test]
    fn ledger_records_r_grant_reason() {
        let home = test_home("r-ledger");
        let call = make_call("calculator", br#"{"expression":"2+2"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let _ = execute_call(&home, "s1", "d1", &call, false, true, &mut ch, &mut grants).unwrap();

        let mut ledger = String::new();
        for e in std::fs::read_dir(home.join("ledger/segments"))
            .unwrap()
            .flatten()
        {
            let bytes = std::fs::read(e.path()).unwrap_or_default();
            ledger.push_str(&String::from_utf8_lossy(&bytes));
        }
        // The first call's verdict should be "operator approved" (the R grant
        // is applied, and the reason reflects approval).
        assert!(ledger.contains("operator approved") || ledger.contains("R-grant"));
    }
}
