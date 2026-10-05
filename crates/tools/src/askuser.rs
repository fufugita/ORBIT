//! AskUserQuestion and ExitPlanMode (Wave 1): the two interactive
//! round-trip tools.
//!
//! Both need an operator answer mid-turn, like an approval — but they
//! return structured answers, not allow/deny. The front-end supplies
//! an [`AskChannel`]; headless runs get an honest auto-answer so the
//! turn still completes (the transcript records that nobody was asked).

use crate::{Tool, ToolContext, ToolResult};
use std::sync::{Arc, Mutex, OnceLock};

/// One question as the model wrote it (validated: 1-4 questions,
/// 2-4 options each).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AskQuestion {
    pub question: String,
    pub header: String,
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_select: Option<bool>,
}

/// The operator's answer: the chosen option labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskAnswer {
    /// One entry per question, in order.
    pub choices: Vec<Vec<String>>,
}

/// Front-end-supplied question interaction. `None` (the default) is
/// the headless channel: it answers the first option of each question
/// and marks the result as auto-answered.
pub trait AskChannel: Send + Sync {
    fn ask(&self, questions: &[AskQuestion]) -> AskAnswer;
}

/// The headless auto-answer: first option per question.
pub struct AutoFirst;

impl AskChannel for AutoFirst {
    fn ask(&self, questions: &[AskQuestion]) -> AskAnswer {
        AskAnswer {
            choices: questions
                .iter()
                .map(|q| vec![q.options.first().cloned().unwrap_or_default()])
                .collect(),
        }
    }
}

fn channel() -> &'static Mutex<Option<Arc<dyn AskChannel>>> {
    static CH: OnceLock<Mutex<Option<Arc<dyn AskChannel>>>> = OnceLock::new();
    CH.get_or_init(|| Mutex::new(None))
}

/// Install the front-end's ask channel (the TUI at boot, a test, …).
/// Cleared when the front-end exits; the headless default is used
/// while unset.
pub fn set_ask_channel(ch: Option<Arc<dyn AskChannel>>) {
    if let Ok(mut g) = channel().lock() {
        *g = ch;
    }
}

fn ask(questions: &[AskQuestion]) -> AskAnswer {
    match channel().lock() {
        Ok(g) => match g.as_ref() {
            Some(ch) => ch.ask(questions),
            None => AutoFirst.ask(questions),
        },
        Err(_) => AutoFirst.ask(questions),
    }
}

// ── AskUserQuestion ────────────────────────────────────────────────

pub struct AskUserQuestionTool;

impl Tool for AskUserQuestionTool {
    fn name(&self) -> &'static str {
        "AskUserQuestion"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "items": {
                        "type": "object",
                        "properties": {
                            "question": {"type": "string"},
                            "header": {"type": "string", "description": "Short label (max 12 chars)"},
                            "options": {
                                "type": "array",
                                "minItems": 2,
                                "maxItems": 4,
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "label": {"type": "string"},
                                        "description": {"type": "string"}
                                    },
                                    "required": ["label"]
                                }
                            },
                            "multi_select": {"type": "boolean"}
                        },
                        "required": ["question", "header", "options"]
                    }
                }
            },
            "required": ["questions"]
        })
    }
    fn read_only(&self) -> bool {
        true // asks the operator; changes nothing
    }
    fn permission_key(&self, _input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "AskUserQuestion".into(),
            pattern: String::new(),
        }
    }
    fn run(&self, args: &serde_json::Value, _cx: &ToolContext) -> ToolResult {
        let Some(list) = args.get("questions").and_then(|v| v.as_array()) else {
            return ToolResult::err("AskUserQuestion requires a 'questions' array");
        };
        if list.is_empty() || list.len() > 4 {
            return ToolResult::err("1 to 4 questions");
        }
        let mut questions = Vec::new();
        for q in list {
            let question = q
                .get("question")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let header = q
                .get("header")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let options: Vec<String> = q
                .get("options")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|o| o.get("label").and_then(|l| l.as_str()))
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            if question.is_empty() || options.len() < 2 || options.len() > 4 {
                return ToolResult::err("each question needs text and 2-4 options");
            }
            questions.push(AskQuestion {
                question,
                header,
                options,
                multi_select: q.get("multi_select").and_then(|v| v.as_bool()),
            });
        }
        let interactive = channel().lock().map(|g| g.is_some()).unwrap_or(false);
        let answer = ask(&questions);
        ToolResult::ok(serde_json::json!({
            "answers": answer.choices,
            "auto_answered": !interactive,
        }))
    }
}

// ── ExitPlanMode ───────────────────────────────────────────────────

pub struct ExitPlanModeTool;

impl Tool for ExitPlanModeTool {
    fn name(&self) -> &'static str {
        "ExitPlanMode"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "plan": {"type": "string", "description": "The plan to present for approval"}
            },
            "required": ["plan"]
        })
    }
    fn read_only(&self) -> bool {
        false // it changes the session's mode posture
    }
    fn permission_key(&self, _input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "ExitPlanMode".into(),
            pattern: String::new(),
        }
    }
    fn run(&self, args: &serde_json::Value, _cx: &ToolContext) -> ToolResult {
        let plan = args
            .get("plan")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if plan.trim().is_empty() {
            return ToolResult::err("ExitPlanMode requires the plan text");
        }
        // The plan-approval interaction is the front-end's (the TUI's
        // PlanReady card). Without one (headless), the plan is
        // recorded and the mode stays — the operator approves plans
        // interactively; a script never silently exits plan mode.
        let interactive = channel().lock().map(|g| g.is_some()).unwrap_or(false);
        if !interactive {
            return ToolResult::ok(serde_json::json!({
                "approved": false,
                "note": "plan recorded; plan mode stays on (non-interactive run)",
            }));
        }
        // Interactive: present the plan as a single question.
        let questions = [AskQuestion {
            question: format!("Approve this plan and leave plan mode?\n\n{plan}"),
            header: "Plan".into(),
            options: vec!["approve".into(), "keep planning".into()],
            multi_select: Some(false),
        }];
        let answer = ask(&questions);
        let approved = answer
            .choices
            .first()
            .and_then(|c| c.first())
            .map(|c| c == "approve")
            .unwrap_or(false);
        ToolResult::ok(serde_json::json!({ "approved": approved }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_auto_answers_first_option() {
        let input = serde_json::json!({
            "questions": [{
                "question": "Which database?",
                "header": "DB",
                "options": [{"label": "postgres"}, {"label": "mysql"}]
            }]
        });
        let cx = ToolContext::new(
            std::env::temp_dir().join("askuser-test"),
            "s".into(),
            std::env::temp_dir(),
        );
        let r = AskUserQuestionTool.run(&input, &cx);
        assert!(!r.is_error);
        let v: serde_json::Value = serde_json::from_str(&r.payload).unwrap();
        assert_eq!(v["answers"][0][0], "postgres");
        assert_eq!(v["auto_answered"], true);
    }

    #[test]
    fn rejects_bad_shapes() {
        let cx = ToolContext::new(
            std::env::temp_dir().join("askuser-test"),
            "s".into(),
            std::env::temp_dir(),
        );
        let r = AskUserQuestionTool.run(&serde_json::json!({"questions": []}), &cx);
        assert!(r.is_error);
        let r = AskUserQuestionTool.run(
            &serde_json::json!({"questions": [{"question": "q", "header": "h", "options": [{"label": "only"}]}]}),
            &cx,
        );
        assert!(r.is_error);
    }

    #[test]
    fn exit_plan_mode_headless_records_but_stays() {
        let cx = ToolContext::new(
            std::env::temp_dir().join("askuser-test"),
            "s".into(),
            std::env::temp_dir(),
        );
        let r = ExitPlanModeTool.run(&serde_json::json!({"plan": "do the thing"}), &cx);
        let v: serde_json::Value = serde_json::from_str(&r.payload).unwrap();
        assert_eq!(v["approved"], false);
    }
}
