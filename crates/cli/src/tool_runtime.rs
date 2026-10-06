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

/// The session's permission scope (S5): the mode and the operator's
/// explicit allow/disallow lists, owned by the session and passed
/// explicitly — never process-wide environment variables, which are
/// not thread-safe (subagents run nested turns), can't change at
/// runtime, and leak into every Bash child.
#[derive(Debug, Clone, Default)]
pub struct PermissionScope {
    /// `--permission-mode` (default, acceptEdits, plan, dontAsk, bypass).
    pub mode: orbit_tools::permissions::PermissionMode,
    /// `--allowedTools`: an explicit scope — only what it names may run.
    pub allowlist: Option<Vec<String>>,
    /// `--disallowedTools`: deny rules on top of the scope.
    pub disallowlist: Vec<String>,
}

impl PermissionScope {
    /// Build from the CLI flags (`--permission-mode`, `--allowedTools`,
    /// `--disallowedTools`), comma-separated as on the command line.
    pub fn from_flags(mode: Option<&str>, allow: Option<&str>, deny: Option<&str>) -> Self {
        let mode = mode
            .and_then(orbit_tools::permissions::PermissionMode::from_config)
            .unwrap_or_default();
        let allowlist = allow.map(|l| {
            l.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect::<Vec<_>>()
        });
        let disallowlist = deny
            .map(|l| {
                l.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Self {
            mode,
            allowlist,
            disallowlist,
        }
    }
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
    // The SESSION's permission scope (S5): mode + operator lists,
    // owned by the caller and passed explicitly — env vars are gone.
    scope: &PermissionScope,
    // The SESSION's tool context (B2): cloned per call, but the clone
    // shares the read-before-edit map, so Read's record survives to
    // Edit. Callers build this once per session.
    tool_cx: &orbit_tools::ToolContext,
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

    // B4: layer 2's pattern verdict, computed once here so headless
    // runs don't blanket-deny calls the mode/rules allow. The channel
    // is only asked when BOTH layers say ask.
    let args_preview =
        crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
    let pattern_verdict = pattern_layer_verdict(home, scope, &call.name, &args_preview);

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
        // B4: the mode/pattern layer allows it outright (read-only in
        // default mode, edits in acceptEdits, an allow rule from
        // --allowedTools or settings.toml).
        || pattern_verdict == PatternOutcome::Allow
    {
        ApprovalVerdict::AllowOnce
    } else if matches!(pattern_verdict, PatternOutcome::Deny(_)) {
        // A pattern deny rule (or plan mode refusing a write) is final.
        ApprovalVerdict::Deny
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
    } else if let PatternOutcome::Deny(r) = &pattern_verdict {
        // B4: the mode/pattern layer denied (a deny rule, or plan mode
        // refusing a write) — its reason is the honest one.
        r
    } else if !interactive && !auto_tools {
        // B4: headless is not an error — the call needs one of the
        // headless allow paths (--auto-tools, a rule, --allowedTools)
        // and the denial says so.
        "non-interactive tool call requires --auto-tools or an allow rule (--allowedTools / settings.toml)"
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

    // Release the ledger's single-writer lock BEFORE execution: a
    // nested session (the Task tool spawning a subagent, phase 5) opens
    // its own writer for the subagent's calls, and holding this lock
    // across the dispatch deadlocked the subagent at boot (E0719). The
    // verdict is durably recorded above; the result reopens below.
    drop(writer);

    if !allowed {
        let output = tool_error(reason);
        // D9: a denial is not an error — audits must be able to tell an
        // operator refusal apart from a tool that ran and failed.
        record_result(home, session_id, decision_id, call, "denied", &output)?;
        return Ok(output);
    }

    let args = match crate::tools::parse_arguments(&call.arguments) {
        Ok(v) => v,
        Err(e) => {
            let output = tool_error(&e);
            record_result(home, session_id, decision_id, call, "error", &output)?;
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
        record_result(home, session_id, decision_id, call, status, &output)?;
        return Ok(output);
    }

    // The Task tool (phase 5) and its Agent alias: spawn a subagent.
    // The subagent needs the session's TurnConfig — derived from the
    // same environment the front-ends use, so provider/gate/model
    // match the parent. `Agent` is the current Claude Code name; both
    // shapes route to the one runner.
    if call.name == "Task" || call.name == "Agent" {
        let agent = args
            .get("agent")
            .or_else(|| args.get("agent_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("general");
        let prompt = args
            .get("prompt")
            .or_else(|| args.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if prompt.is_empty() {
            let output = tool_error("Task/Agent requires a 'prompt'");
            record_result(home, session_id, decision_id, call, "error", &output)?;
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
        record_result(home, session_id, decision_id, call, status, &output)?;
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
        record_result(home, session_id, decision_id, call, status, &output)?;
        return Ok(output);
    }

    // Wave 1 tools (Read/Write/Edit/Glob/Grep/Bash/TaskStop) run
    // through the orbit-tools registry: the real implementations, the
    // permission layer (modes + pattern rules), the deny-read list and
    // the secret scanner on every result (review blocker 1).
    if orbit_tools::is_wave1(&call.name) {
        let output = execute_wave1(home, scope, call, &args, tool_cx);
        let status = if output.contains("\"ok\":true") || output.contains("\"ok\": true") {
            "ok"
        } else {
            "error"
        };
        record_result(home, session_id, decision_id, call, status, &output)?;
        return Ok(output);
    }

    let result = crate::tools::execute(&call.name, &args);
    let output = match result {
        Ok(v) => serde_json::json!({ "ok": true, "result": v }).to_string(),
        Err(e) => tool_error(&e),
    };
    if output.len() > MAX_RESULT_BYTES {
        let truncated = tool_error("tool result exceeds 64 KiB");
        record_result(home, session_id, decision_id, call, "error", &truncated)?;
        return Ok(truncated);
    }
    let status = if output.contains("\"ok\":true") {
        "ok"
    } else {
        "error"
    };
    record_result(home, session_id, decision_id, call, status, &output)?;
    Ok(output)
}

/// Layer-2 outcome for the pre-check (B4): what would the mode/pattern
/// rules say about this call?
#[derive(PartialEq)]
enum PatternOutcome {
    Allow,
    Ask,
    Deny(String),
}

fn pattern_layer_verdict(
    home: &Path,
    scope: &PermissionScope,
    tool_name: &str,
    args: &serde_json::Value,
) -> PatternOutcome {
    use orbit_tools::permissions::{evaluate, parse_rule, RuleEffectSerde, Verdict};

    let mut rules = orbit_tools::executor::load_rules(home);
    // An explicit operator allowlist (--allowedTools / settings) is a
    // SCOPE statement: only what it names may run. The flag is tracked
    // separately so the pure-built-in bypass below cannot punch
    // through it (gate 6: a CI allowlist without calculator must deny
    // calculator with exit 2, not let the built-in run).
    if let Some(list) = &scope.allowlist {
        for entry in list {
            if let Some(r) = parse_rule(entry, RuleEffectSerde::Allow) {
                rules.rules.push(r);
            }
        }
    }
    for entry in &scope.disallowlist {
        if let Some(r) = parse_rule(entry, RuleEffectSerde::Deny) {
            rules.rules.push(r);
        }
    }
    let Some(tool) = orbit_tools::registry()
        .into_iter()
        .find(|t| t.name() == tool_name)
    else {
        // Not a registry tool. Pure built-ins (calculator, session
        // lookups) are safe by construction — UNLESS the operator
        // pinned an explicit allowlist, which names the whole scope
        // (a built-in outside it is outside the scope, full stop).
        if crate::tools::builtin_tools()
            .iter()
            .any(|t| t.name == tool_name)
        {
            if scope.allowlist.is_some() {
                return PatternOutcome::Ask;
            }
            return PatternOutcome::Allow;
        }
        return PatternOutcome::Ask;
    };
    let key = tool.permission_key(args);
    let is_ro_cmd = tool_name == "Bash"
        && orbit_tools::bash::is_readonly_command(
            args.get("command").and_then(|v| v.as_str()).unwrap_or(""),
        );
    match evaluate(
        scope.mode,
        &rules,
        &key.tool,
        &key.pattern,
        tool.read_only(),
        is_ro_cmd,
    ) {
        Verdict::Allow => PatternOutcome::Allow,
        Verdict::Ask => PatternOutcome::Ask,
        Verdict::Deny(reason) => PatternOutcome::Deny(reason),
    }
}

/// Display-safe summary of a tool call (name + argument keys only).
fn safe_call_summary(call: &crate::PendingToolCall) -> String {
    let args = crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
    crate::tools::safe_call_summary(&call.name, &args)
}

/// Open the ledger writer for one append (the single-writer lock is
/// held only for the append, then released — nested sessions open
/// their own between the parent's records).
fn reopen_writer(home: &Path) -> Result<LedgerWriter, String> {
    LedgerWriter::open(&home.join("ledger"), "orbit-tool".into(), "0.1.0")
        .map_err(|e| format!("open ledger: {e}"))
}

fn record_result(
    home: &Path,
    session_id: &str,
    decision_id: &str,
    call: &crate::PendingToolCall,
    status: &str,
    output: &str,
) -> Result<(), String> {
    let mut writer = reopen_writer(home)?;
    let head = writer
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
    // The proof chip's heartbeat (M19): every append is a visible
    // pulse. Emitted where the writer lives; the ledger crate itself
    // stays a pure library.
    if plain_output_enabled() {
        // (the TUI worker prints its own events; plain mode stays
        // quiet here — the head digest is already on the summary line)
        let _ = head;
    }
    Ok(())
}

/// Extract a readable message from a caught panic payload
/// (String or &str; anything else becomes "tool panicked").
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "tool panicked".to_string()
    }
}

/// S3: the standing refusal for an unrunnable sandbox.
fn sandbox_refusal() -> String {
    tool_error(
        "refused: the shell sandbox is unavailable on this machine \
(bubblewrap missing); set ORBIT_ALLOW_UNSANDBOXED_BASH=1 to run Bash unsandboxed",
    )
}

fn tool_error(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

/// Execute one Wave 1 call through the orbit-tools registry with the
/// live permission layer: modes, pattern rules, folder trust, deny-read
/// and the secret scanner. The verdict above (whole-tool rules +
/// approval channel) already ran; this adds the pattern-level check.
fn execute_wave1(
    home: &Path,
    scope: &PermissionScope,
    call: &crate::PendingToolCall,
    args: &serde_json::Value,
    tool_cx: &orbit_tools::ToolContext,
) -> String {
    use orbit_tools::permissions::{evaluate, parse_rule, RuleEffectSerde};

    // Merged rules: the new pattern scopes + the legacy whole-tool file.
    let mut rules = orbit_tools::executor::load_rules(home);
    // --allowedTools / --disallowedTools (command-line scope), from the
    // session's PermissionScope (S5) — not process env.
    // An explicit operator allowlist (--allowedTools / settings) is a
    // SCOPE statement: only what it names may run. The flag is tracked
    // separately so the pure-built-in bypass below cannot punch
    // through it (gate 6: a CI allowlist without calculator must deny
    // calculator with exit 2, not let the built-in run).
    if let Some(list) = &scope.allowlist {
        for entry in list {
            if let Some(r) = parse_rule(entry, RuleEffectSerde::Allow) {
                rules.rules.push(r);
            }
        }
    }
    for entry in &scope.disallowlist {
        if let Some(r) = parse_rule(entry, RuleEffectSerde::Deny) {
            rules.rules.push(r);
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

    // Hooks (phase 5): PreToolUse fires BEFORE every other gate —
    // hooks are the operator's policy layer and must see (and be able
    // to block) every call, whatever the machine's sandbox state.
    // PostToolUse sees the result.
    let hooks = orbit_engine::hooks::Hooks::load(home, project_trusted_home(home));
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

    // S3: when the shell sandbox cannot run on this machine, a Bash
    // command must not execute unsandboxed on an allow verdict. The
    // operator opts in explicitly (ORBIT_ALLOW_UNSANDBOXED_BASH=1) or
    // the call is refused with the reason. Read-only commands are
    // still safe to run bare.
    let sandbox_up = call.name != "Bash"
        || is_ro_cmd
        || matches!(
            orbit_tools::sandbox::ShellSandbox::probe(),
            orbit_tools::sandbox::SandboxStatus::Confined
        )
        || std::env::var("ORBIT_ALLOW_UNSANDBOXED_BASH")
            .map(|v| v == "1")
            .unwrap_or(false);

    match evaluate(
        scope.mode,
        &rules,
        &key.tool,
        &key.pattern,
        tool.read_only(),
        is_ro_cmd,
    ) {
        // S3 binds on every path that would RUN the command: a plain
        // allow, and the ask-collapse (the operator approved the call
        // — but not running it bare on a sandbox-less machine).
        orbit_tools::permissions::Verdict::Allow if !sandbox_up => return sandbox_refusal(),
        orbit_tools::permissions::Verdict::Allow => {}
        orbit_tools::permissions::Verdict::Deny(reason) => {
            return tool_error(&reason);
        }
        orbit_tools::permissions::Verdict::Ask if !sandbox_up => return sandbox_refusal(),
        orbit_tools::permissions::Verdict::Ask => {
            // The whole-tool verdict above already asked the channel
            // (the operator pressed y). Pattern-level ask collapses to
            // allow here — the operator's approval IS the answer.
        }
    }

    // Execute with the SESSION's ToolContext (B2): the clone shares
    // the read-before-edit map, so a Read in an earlier round
    // satisfies Edit's precondition. A fresh context per call is what
    // made Edit always refuse.
    let cx = tool_cx.clone();

    let hooks = orbit_engine::hooks::Hooks::load(home, project_trusted_home(home));
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
                let cps = orbit_engine::transcript::Checkpoints::new(home, &cx.session_id);
                let turn_cp = current_turn_checkpoint();
                let _ = cps.snapshot_file(&turn_cp, &path);
            }
        }
    }

    // B1: a tool bug must become a tool error, never a dead worker
    // (a panic here used to take the whole process or the TUI thread).
    let result =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tool.run(args, &cx))) {
            Ok(result) => result,
            Err(panic) => {
                let reason = panic_message(&panic);
                orbit_tools::ToolResult::err(&format!(
                    "internal tool error: {reason} (the panic was contained)"
                ))
            }
        };
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
/// apply only after the operator trusted it once)? Resolved against
/// the caller's REAL home path — the command
/// line's --home does not set the env var, so any helper that resolved
/// trust through the env silently skipped project scope (the MCP call
/// path reported "mcp server not configured" for a configured, trusted
/// project server).
/// The command
/// line's --home does not set the env var, so any helper that resolved
/// trust through the env silently skipped project scope (the MCP call
/// path reported "mcp server not configured" for a configured, trusted
/// project server).
fn project_trusted_home(home: &Path) -> bool {
    let cwd = std::env::current_dir().unwrap_or_default();
    orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(&cwd)
}

/// The checkpoint id for the current turn: one per user prompt. The
/// engine opens it at the prompt; the executor snapshots into it.
/// (S5: the old env-var marker was never set by anyone; the ULID is
/// per write-turn, which is the checkpoint granularity /rewind needs.)
fn current_turn_checkpoint() -> String {
    format!("cp-{}", ulid::Ulid::new())
}

/// Execute one MCP call: resolve the server from the config, spawn,
/// call, scan the result (never trust external output).
fn execute_mcp(home: &Path, call: &crate::PendingToolCall, args: &serde_json::Value) -> String {
    let Some((server, tool)) = orbit_mcp::split_wire_name(&call.name) else {
        return tool_error("malformed mcp tool name");
    };
    let trusted = project_trusted_home(home);
    let cfg = orbit_mcp::McpConfig::load(home, trusted);
    let Some(server_cfg) = cfg.servers.get(&server) else {
        return tool_error(&format!("mcp server not configured: {server}"));
    };
    // The process-lifetime pool: the server was spawned once (at
    // definition build) and is reused across every call (phase 5 —
    // no re-spawn, no re-handshake per tool call).
    let mut call_args = args.clone();
    if let Some(obj) = call_args.as_object_mut() {
        obj.remove("server");
        obj.remove("tool");
    }
    let params = serde_json::json!({
        "name": tool,
        "arguments": call_args,
    });
    match orbit_mcp::POOL.request(&server, server_cfg, "tools/call", params) {
        Ok(result) => {
            // MCP content blocks → text.
            let text = mcp_result_text(&result);
            let scanned = orbit_tools::scan::scan_result(&text);
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

/// Pull the text out of an MCP tools/call result (content blocks).
fn mcp_result_text(result: &serde_json::Value) -> String {
    result
        .get("content")
        .and_then(|c| c.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_else(|| result.to_string())
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
    /// The subagent inherits the parent session's permission scope
    /// (S5): same mode, same operator lists.
    pub scope: PermissionScope,
    /// The subagent's own tool context (B2): read-before-edit state
    /// shared across its calls, separate from the parent's.
    tool_cx: orbit_tools::ToolContext,
}

impl<'a> SubagentExecutor<'a> {
    pub fn new(home: std::path::PathBuf, approval: &'a mut dyn ApprovalChannel) -> Self {
        let session_id = format!("subagent-{}", ulid::Ulid::new());
        let working_dir =
            std::env::current_dir().unwrap_or_else(|_| std::path::Path::new(".").to_path_buf());
        let tool_cx = orbit_tools::ToolContext::new(home.clone(), session_id.clone(), working_dir);
        Self {
            session_id,
            home,
            approval,
            grants: AutoGrants::new(),
            scope: PermissionScope::default(),
            tool_cx,
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
                    &self.scope,
                    &self.tool_cx,
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

    /// A session context for tests: same shape the executors build.
    /// The working dir is the given path (file tools resolve relative
    /// paths against it).
    fn test_cx(work_dir: &std::path::Path) -> orbit_tools::ToolContext {
        orbit_tools::ToolContext::new(
            work_dir.to_path_buf(),
            "test-session".into(),
            work_dir.to_path_buf(),
        )
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
        let out = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            true,
            false,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&home.join("work")),
        )
        .unwrap();
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
    fn non_tty_denies_write_without_allow_path() {
        // B4: headless denies an ask-class tool with a visible reason;
        // read-only tools run (that is the fix, not a regression).
        let home = test_home("deny");
        let dir = home.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let call = make_call("Write", br#"{"file_path":"out.txt","content":"x"}"#);
        let mut ch = StdApprovalChannel::new(false); // non-interactive
        let mut grants = AutoGrants::new();
        let out = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            false,
            false,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&dir),
        )
        .unwrap();
        assert!(
            out.contains("non-interactive"),
            "headless ask must deny with the visible reason: {out}"
        );
        assert!(!dir.join("out.txt").exists());
    }

    #[test]
    fn unknown_tool_is_denied_even_with_auto_tools() {
        let home = test_home("unknown");
        let call = make_call("shell", br#"{"cmd":"id"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::AllowOnce);
        let mut grants = AutoGrants::new();
        let out = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            true,
            false,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&home.join("work")),
        )
        .unwrap();
        assert!(out.contains("unknown tool"));
    }

    #[test]
    fn allow_once_executes() {
        let home = test_home("allow-once");
        let call = make_call("calculator", br#"{"expression":"3+4"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::AllowOnce);
        let mut grants = AutoGrants::new();
        let out = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            false,
            true,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&home.join("work")),
        )
        .unwrap();
        assert!(out.contains("7"));
    }

    #[test]
    fn deny_does_not_execute() {
        let home = test_home("deny-manual");
        let dir = home.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let call = make_call("Write", br#"{"file_path":"out.txt","content":"x"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::Deny);
        let mut grants = AutoGrants::new();
        let out = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            false,
            true,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&dir),
        )
        .unwrap();
        assert!(out.contains("operator denied"));
        assert!(!dir.join("out.txt").exists());
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
        // B4: R-grants apply to ask-class tools; Write asks in default
        // mode, so the grant (not the channel) approves the second call.
        let home = test_home("r-grant");
        let dir = home.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let call = make_call("Write", br#"{"file_path":"a.txt","content":"1"}"#);

        // First call: R verdict → grant + execute.
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let out1 = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            false,
            true,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&dir),
        )
        .unwrap();
        assert!(out1.contains("\"ok\":true"), "first write ran: {out1}");
        assert!(grants.is_granted("Write"));

        // Second call: auto-approved from the grant (channel not asked).
        let call2 = make_call("Write", br#"{"file_path":"b.txt","content":"2"}"#);
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
            &PermissionScope::default(),
            &test_cx(&dir),
        )
        .unwrap();
        assert!(
            dir.join("b.txt").exists(),
            "R-grant should auto-approve the second call: {out2}"
        );
    }

    #[test]
    fn deny_revokes_r_grant() {
        let home = test_home("revoke");
        let dir = home.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let call = make_call("Write", br#"{"file_path":"c.txt","content":"x"}"#);

        // Grant via R.
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let _ = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            false,
            true,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&dir),
        )
        .unwrap();
        assert!(grants.is_granted("Write"));

        // Revoke explicitly (the operator pressed n → revoke path).
        grants.revoke("Write");
        assert!(!grants.is_granted("Write"));

        // Now the channel is asked again — deny.
        let mut ch2 = FixedChannel(ApprovalVerdict::Deny);
        let call2 = make_call("Write", br#"{"file_path":"d.txt","content":"y"}"#);
        let out = execute_call(
            &home,
            "s1",
            "d2",
            &call2,
            false,
            true,
            &mut ch2,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&dir),
        )
        .unwrap();
        assert!(out.contains("operator denied"));
        assert!(!dir.join("d.txt").exists());
        assert!(!grants.is_granted("Write"));
    }

    #[test]
    fn r_grant_does_not_apply_to_unknown_tools() {
        let home = test_home("r-unknown");
        let call = make_call("shell", br#"{"cmd":"id"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let out = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            false,
            true,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&home.join("work")),
        )
        .unwrap();
        assert!(out.contains("unknown tool"));
        assert!(
            !grants.is_granted("shell"),
            "unknown tool should not be granted"
        );
    }

    #[test]
    fn r_grant_is_per_tool() {
        // B4: grants are per-tool-name; an R on Write does not leak to
        // Edit. Edit asks the channel on its own.
        let home = test_home("r-per-tool");
        let dir = home.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let write = make_call("Write", br#"{"file_path":"e.txt","content":"x"}"#);

        // Grant R on Write.
        let mut ch = FixedChannel(ApprovalVerdict::AllowSession);
        let mut grants = AutoGrants::new();
        let _ = execute_call(
            &home,
            "s1",
            "d1",
            &write,
            false,
            true,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&dir),
        )
        .unwrap();
        assert!(grants.is_granted("Write"));
        assert!(
            !grants.is_granted("Edit"),
            "R on Write should not grant Edit"
        );

        // Edit should still ask the channel.
        let mut ch2 = FixedChannel(ApprovalVerdict::Deny);
        let edit = make_call(
            "Edit",
            br#"{"file_path":"e.txt","old_string":"x","new_string":"y"}"#,
        );
        let out = execute_call(
            &home,
            "s1",
            "d2",
            &edit,
            false,
            true,
            &mut ch2,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&dir),
        )
        .unwrap();
        assert!(out.contains("operator denied"), "the channel must be asked");
        assert!(!grants.is_granted("Edit"), "a Deny must not create a grant");
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
        let _ = execute_call(
            &home,
            "s1",
            "d1",
            &call,
            false,
            true,
            &mut ch,
            &mut grants,
            &PermissionScope::default(),
            &test_cx(&home.join("work")),
        )
        .unwrap();

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
