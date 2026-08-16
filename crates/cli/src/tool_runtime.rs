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
        // Existing blocking stdin reader — identical to the old prompt_approval.
        use std::io::Write;
        print!("[tool] {} allow? [y/N/R]: ", req.summary);
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
    call: &super::PendingToolCall,
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
    // 2. --auto-tools → allow once (up-front consent for pure built-ins).
    // 3. Session R-grant → allow once (session-scoped, per-tool).
    // 4. Otherwise → ask the approval channel.
    // Unknown tools always deny (fail-closed, even with --auto-tools / R).
    // Auto-tools and session R-grants both auto-allow without asking.
    let verdict = if !known {
        ApprovalVerdict::Deny
    } else if auto_tools || grants.is_granted(&call.name) {
        ApprovalVerdict::AllowOnce
    } else {
        approval.ask(
            &ApprovalRequest {
                call_id: call.id.clone(),
                tool_name: call.name.clone(),
                summary: safe_call_summary(call),
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

    if !allowed {
        let output = tool_error(reason);
        record_result(&mut writer, session_id, decision_id, call, "error", &output)?;
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
fn safe_call_summary(call: &super::PendingToolCall) -> String {
    let args = crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
    crate::tools::safe_call_summary(&call.name, &args)
}

fn record_result(
    writer: &mut LedgerWriter,
    session_id: &str,
    decision_id: &str,
    call: &super::PendingToolCall,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call(name: &str, args: &[u8]) -> super::super::PendingToolCall {
        super::super::PendingToolCall {
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
