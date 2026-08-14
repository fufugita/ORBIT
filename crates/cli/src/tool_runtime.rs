//! Tool-call approval, ledger evidence, pure execution (DR-19).
//!
//! Execution ordering is fail-closed:
//!   ToolIntent append+fsync -> approval verdict append+fsync -> pure executor
//!   -> ToolResult append+fsync.
//! The ledger receives only hashes/sizes; never raw arguments or result bytes.

use orbit_ledger::event::{LedgerEvent, ToolIntent, ToolResult, ToolVerdict};
use orbit_ledger::LedgerWriter;
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_RESULT_BYTES: usize = 64 * 1024;

/// Execute one pending call with approval + ledger evidence.
pub fn execute_call(
    home: &Path,
    session_id: &str,
    decision_id: &str,
    call: &super::PendingToolCall,
    auto_tools: bool,
    interactive: bool,
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
    let allowed = known && (auto_tools || (interactive && prompt_approval(call)?));
    let reason = if !known {
        "unknown tool (deny-by-default)"
    } else if auto_tools {
        "allowed by --auto-tools up-front consent"
    } else if !interactive {
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
    record_result(
        &mut writer,
        session_id,
        decision_id,
        call,
        status,
        &output,
    )?;
    Ok(output)
}

fn prompt_approval(call: &super::PendingToolCall) -> Result<bool, String> {
    use std::io::Write;
    let args = crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
    let summary = crate::tools::safe_call_summary(&call.name, &args);
    print!("[tool] {summary} allow? [y/N]: ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
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

    #[test]
    fn auto_tools_executes_and_records_digest_only() {
        let home = std::env::temp_dir().join("orbit-tool-runtime-auto");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let call = super::super::PendingToolCall {
            index: 0,
            id: "call-1".into(),
            name: "calculator".into(),
            arguments: br#"{"expression":"2*(3+4)"}"#.to_vec(),
        };
        let out = execute_call(&home, "s1", "d1", &call, true, false).unwrap();
        assert!(out.contains("14"));
        let mut ledger = String::new();
        for e in std::fs::read_dir(home.join("ledger/segments")).unwrap().flatten() {
            let bytes = std::fs::read(e.path()).unwrap_or_default();
            ledger.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(ledger.contains("tool_intent"));
        assert!(ledger.contains("tool_verdict"));
        assert!(ledger.contains("tool_result"));
        assert!(ledger.contains("arguments_sha256"));
        assert!(!ledger.contains("2*(3+4)"), "raw arguments must not enter ledger");
        assert!(!ledger.contains("\"result\":14"), "raw output must not enter ledger");
    }

    #[test]
    fn non_tty_denies_without_auto_tools() {
        let home = std::env::temp_dir().join("orbit-tool-runtime-deny");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let call = super::super::PendingToolCall {
            index: 0,
            id: "call-deny".into(),
            name: "calculator".into(),
            arguments: br#"{"expression":"1+1"}"#.to_vec(),
        };
        let out = execute_call(&home, "s1", "d1", &call, false, false).unwrap();
        assert!(out.contains("non-interactive"));
        assert!(!out.contains("\"result\":2"));
    }

    #[test]
    fn unknown_tool_is_denied_even_with_auto_tools() {
        let home = std::env::temp_dir().join("orbit-tool-runtime-unknown");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let call = super::super::PendingToolCall {
            index: 0,
            id: "call-unknown".into(),
            name: "shell".into(),
            arguments: br#"{"cmd":"id"}"#.to_vec(),
        };
        let out = execute_call(&home, "s1", "d1", &call, true, false).unwrap();
        assert!(out.contains("unknown tool"));
    }
}
