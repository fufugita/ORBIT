//! The Agent tool (Wave 2): run a subagent in its own context.
//!
//! The roadmap contract: "Returns only the subagent's final report;
//! its own calls are checked against your rules" (§Extensibility).
//! The engine lives above this crate, so the CLI installs a runner
//! hook at boot (the same pattern as the interrupt slot); without one
//! the tool answers honestly that subagents are unavailable.

use crate::{Tool, ToolContext, ToolResult};
use std::sync::{Arc, Mutex, OnceLock};

/// A subagent run: prompt in, final report out. The implementation is
/// the engine's turn loop with its own transcript and tool executor —
/// the CLI installs it (front-ends know the provider config).
pub type SubagentRunner = Arc<dyn Fn(&SubagentRequest) -> Result<String, String> + Send + Sync>;

/// What the model asked for.
#[derive(Debug, Clone)]
pub struct SubagentRequest {
    pub prompt: String,
    /// Optional role hint ("explore", "plan", "general"); the runner
    /// may shape the system prompt with it.
    pub agent_type: Option<String>,
}

fn runner() -> &'static Mutex<Option<SubagentRunner>> {
    static R: OnceLock<Mutex<Option<SubagentRunner>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(None))
}

/// Install (or clear) the subagent runner. Called by the CLI at boot,
/// after provider config is known.
pub fn set_subagent_runner(r: Option<SubagentRunner>) {
    if let Ok(mut g) = runner().lock() {
        *g = r;
    }
}

pub struct AgentTool;

impl Tool for AgentTool {
    fn name(&self) -> &'static str {
        "Agent"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "description": "The task for the subagent"},
                "agent_type": {
                    "type": "string",
                    "enum": ["explore", "plan", "general"],
                    "description": "The subagent's posture"
                }
            },
            "required": ["prompt"]
        })
    }
    fn read_only(&self) -> bool {
        false // the subagent's own calls decide their permissions
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        let t = input
            .get("agent_type")
            .and_then(|v| v.as_str())
            .unwrap_or("general");
        crate::PermissionKey {
            tool: "Agent".into(),
            pattern: t.to_string(),
        }
    }
    fn run(&self, args: &serde_json::Value, _cx: &ToolContext) -> ToolResult {
        let prompt = args
            .get("prompt")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if prompt.is_empty() {
            return ToolResult::err("Agent requires a prompt");
        }
        let req = SubagentRequest {
            prompt,
            agent_type: args
                .get("agent_type")
                .and_then(|v| v.as_str())
                .map(String::from),
        };
        let guard = runner().lock();
        match guard {
            Ok(g) => match g.as_ref() {
                Some(r) => match r(&req) {
                    Ok(report) => ToolResult::ok(serde_json::json!({
                        "report": report,
                    })),
                    Err(e) => ToolResult::err(&format!("subagent failed: {e}")),
                },
                None => ToolResult::err("subagents unavailable (no runner installed)"),
            },
            Err(_) => ToolResult::err("subagent runner lock poisoned"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runner slot is process-global; tests that swap it must not
    /// interleave (parallel cargo tests share one process).
    static RUNNER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn runs_the_installed_runner() {
        let _g = RUNNER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_subagent_runner(Some(Arc::new(|req: &SubagentRequest| {
            Ok(format!("did: {}", req.prompt))
        })));
        let cx = ToolContext::new(
            std::env::temp_dir().join("agent-test"),
            "s".into(),
            std::env::temp_dir(),
        );
        let r = AgentTool.run(&serde_json::json!({"prompt": "explore the crates"}), &cx);
        set_subagent_runner(None);
        assert!(!r.is_error);
        let v: serde_json::Value = serde_json::from_str(&r.payload).unwrap();
        assert_eq!(v["report"], "did: explore the crates");
    }

    #[test]
    fn honest_when_no_runner() {
        let _g = RUNNER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_subagent_runner(None);
        let cx = ToolContext::new(
            std::env::temp_dir().join("agent-test"),
            "s".into(),
            std::env::temp_dir(),
        );
        let r = AgentTool.run(&serde_json::json!({"prompt": "x"}), &cx);
        assert!(r.is_error);
        assert!(r.payload.contains("unavailable"));
    }
}
