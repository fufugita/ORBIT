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

/// Adapter-facing definitions for the provider.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    builtin_tools().iter().map(|t| t.to_definition()).collect()
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
pub fn is_known_tool(name: &str) -> bool {
    builtin_tools().iter().any(|t| t.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(defs.len(), 3);
        assert!(defs.iter().all(|d| d.schema_digest.as_str().len() == 64));
    }

    #[test]
    fn malformed_arguments_are_rejected() {
        assert!(parse_arguments(b"not-json").is_err());
        assert!(parse_arguments(b"").is_err());
    }
}
