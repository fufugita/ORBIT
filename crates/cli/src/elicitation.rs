//! MCP elicitation: a server asks the operator for input while one of its
//! tools is running.
//!
//! The answer is decided in three steps:
//!
//! 1. `Elicitation` hooks (matcher: the server's name). Exit code 2 or a
//!    `block` decision declines. A hook that prints
//!    `{"hookSpecificOutput": {"action": "accept", "content": {…}}}` (or
//!    `decline` / `cancel`) answers for the operator, and no question is
//!    shown.
//! 2. Otherwise the front end asks, when it can ([`Asker`]). A front end
//!    with nobody to ask (a headless prompt) answers `cancel`.
//! 3. `ElicitationResult` hooks see the answer before the server does and
//!    can replace or decline it the same way.
//!
//! The terminal chat asks through its approval cards, one field at a time:
//! `y` / `n` for a yes-or-no field, `y` on the option wanted for a choice,
//! and for text the value typed as the card's note. A form of more than
//! [`MAX_FIELDS`] fields is declined rather than asked piecemeal.

use orbit_engine::hooks::{HookEvent, HookOutcome, Hooks};
use orbit_mcp::{Elicitation, ElicitationAnswer};
use std::path::Path;

/// More fields than this is not a question a row of cards can ask.
pub const MAX_FIELDS: usize = 12;
const MAX_MESSAGE_CHARS: usize = 2000;
const MAX_OPTIONS: usize = 12;

/// What one card came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardReply {
    /// `y`.
    Yes,
    /// `n`, with whatever note was typed.
    No(Option<String>),
}

/// How a front end shows one question card and waits for it.
pub trait Asker: Send + Sync {
    /// `title` names who is asking; `text` is the question; `details` are
    /// further lines shown under it.
    fn card(&self, title: &str, text: &str, details: &[String]) -> CardReply;
}

static ASKER: std::sync::Mutex<Option<std::sync::Arc<dyn Asker>>> = std::sync::Mutex::new(None);

/// Answer every MCP elicitation of this process from now on. Called before
/// the first MCP server starts, because a server is told at its handshake
/// whether questions are supported. Until a front end names who asks
/// ([`set_asker`]), only hooks can answer.
pub fn install(home: &Path) {
    // This runs before any MCP server starts, in every front end: the
    // moment to say which variables a server must not inherit. They are the
    // ones the configured providers read their credentials from.
    orbit_mcp::set_withheld_env(provider_credential_variables(home));
    let home = home.to_path_buf();
    orbit_mcp::set_elicitation_handler(Some(std::sync::Arc::new(move |request: &Elicitation| {
        let hooks = Hooks::load(&home, orbit_engine::hooks::project_trusted(&home));
        let asker = ASKER.lock().ok().and_then(|slot| slot.clone());
        answer(request, &hooks, asker.as_deref())
    })));
}

/// The environment variables the configured providers read their
/// credentials from (`env = "NAME"` in `providers.toml`).
fn provider_credential_variables(home: &Path) -> Vec<String> {
    let mut names: Vec<String> = crate::config::ProvidersConfig::load(home)
        .map(|providers| {
            providers
                .provider
                .iter()
                .filter_map(|provider| provider.env.clone())
                .filter(|name| !name.trim().is_empty())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.dedup();
    names
}

/// Who asks the operator, once a front end that can is running.
pub fn set_asker(asker: Option<std::sync::Arc<dyn Asker>>) {
    if let Ok(mut slot) = ASKER.lock() {
        *slot = asker;
    }
}

/// The three steps above, for one request.
pub fn answer(
    request: &Elicitation,
    hooks: &Hooks,
    asker: Option<&dyn Asker>,
) -> ElicitationAnswer {
    let fired = hooks.fire(
        HookEvent::Elicitation,
        &serde_json::json!({
            "mcp_server_name": request.server,
            "message": request.message,
            "mode": request.mode,
            "requested_schema": request.schema,
            "url": request.url,
        }),
    );
    let first = if orbit_engine::hooks::blocked(&fired).is_some() {
        ElicitationAnswer::Decline
    } else if let Some(decided) = hook_answer(&fired) {
        decided
    } else {
        match asker {
            Some(asker) => ask(request, asker),
            None => ElicitationAnswer::Cancel,
        }
    };
    let (action, content) = match &first {
        ElicitationAnswer::Accept(content) => ("accept", content.clone()),
        ElicitationAnswer::Decline => ("decline", serde_json::Value::Null),
        ElicitationAnswer::Cancel => ("cancel", serde_json::Value::Null),
    };
    let fired = hooks.fire(
        HookEvent::ElicitationResult,
        &serde_json::json!({
            "mcp_server_name": request.server,
            "action": action,
            "content": content,
        }),
    );
    if orbit_engine::hooks::blocked(&fired).is_some() {
        return ElicitationAnswer::Decline;
    }
    hook_answer(&fired).unwrap_or(first)
}

/// The answer a hook gave in `hookSpecificOutput`: the last one wins. Only a
/// hook that succeeded is heard.
fn hook_answer(outcomes: &[HookOutcome]) -> Option<ElicitationAnswer> {
    outcomes.iter().rev().find_map(|outcome| {
        if outcome.exit_code != 0 {
            return None;
        }
        let value: serde_json::Value = serde_json::from_str(outcome.stdout.trim()).ok()?;
        let specific = value.get("hookSpecificOutput")?;
        match specific.get("action")?.as_str()? {
            "accept" => Some(ElicitationAnswer::Accept(
                specific
                    .get("content")
                    .filter(|content| content.is_object())
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
            )),
            "decline" => Some(ElicitationAnswer::Decline),
            "cancel" => Some(ElicitationAnswer::Cancel),
            _ => None,
        }
    })
}

#[derive(Debug, Clone, PartialEq)]
enum Kind {
    Flag,
    Choice(Vec<String>),
    Number { whole: bool },
    Text,
}

#[derive(Debug, Clone, PartialEq)]
struct Field {
    name: String,
    label: String,
    kind: Kind,
    default: Option<serde_json::Value>,
    required: bool,
}

/// The fields of a form schema: a flat object of primitive properties, as
/// the protocol restricts it. Anything else in the schema is not a field.
fn fields(schema: &serde_json::Value) -> Vec<Field> {
    let required: Vec<&str> = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, spec)| {
            let options: Vec<String> = spec
                .get("enum")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|option| option.as_str().map(str::to_owned))
                .take(MAX_OPTIONS)
                .collect();
            let kind = match spec.get("type").and_then(serde_json::Value::as_str)? {
                "boolean" => Kind::Flag,
                "string" if !options.is_empty() => Kind::Choice(options),
                "string" => Kind::Text,
                "number" => Kind::Number { whole: false },
                "integer" => Kind::Number { whole: true },
                _ => return None,
            };
            let words = |key: &str| {
                spec.get(key)
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
            };
            let label = match (words("title"), words("description")) {
                (Some(title), Some(description)) => format!("{title}: {description}"),
                (Some(only), None) | (None, Some(only)) => only.to_owned(),
                (None, None) => name.clone(),
            };
            Some(Field {
                name: name.clone(),
                label: label.chars().take(300).collect(),
                kind,
                default: spec
                    .get("default")
                    .filter(|value| !value.is_null())
                    .cloned(),
                required: required.contains(&name.as_str()),
            })
        })
        .collect()
}

/// Ask the operator, a card at a time.
fn ask(request: &Elicitation, asker: &dyn Asker) -> ElicitationAnswer {
    let title = format!("mcp {}", request.server);
    // The server's words, bounded: a card is not a place for a document.
    let message: String = request.message.chars().take(MAX_MESSAGE_CHARS).collect();
    if request.mode == "url" {
        let Some(url) = request.url.as_deref() else {
            return ElicitationAnswer::Decline;
        };
        let reply = asker.card(
            &title,
            &format!("{} asks you to open a page: {}", request.server, message),
            &[
                url.chars().take(500).collect(),
                "y when you have finished there · n to decline".into(),
            ],
        );
        return match reply {
            CardReply::Yes => ElicitationAnswer::Accept(serde_json::json!({})),
            CardReply::No(_) => ElicitationAnswer::Decline,
        };
    }
    let fields = fields(&request.schema);
    if fields.len() > MAX_FIELDS {
        return ElicitationAnswer::Decline;
    }
    let mut details: Vec<String> = fields
        .iter()
        .map(|field| {
            format!(
                "{}{} ({})",
                field.name,
                if field.required { "" } else { ", optional" },
                match &field.kind {
                    Kind::Flag => "yes or no".to_owned(),
                    Kind::Choice(options) => options.join(" / "),
                    Kind::Number { .. } => "a number".to_owned(),
                    Kind::Text => "text".to_owned(),
                }
            )
        })
        .collect();
    details.push(if fields.is_empty() {
        "y to confirm · n to decline".into()
    } else {
        "y to answer · n to decline".into()
    });
    if let CardReply::No(_) = asker.card(
        &title,
        &format!("{} asks: {}", request.server, message),
        &details,
    ) {
        return ElicitationAnswer::Decline;
    }
    let mut content = serde_json::Map::new();
    for field in &fields {
        match ask_field(asker, &title, field) {
            Asked::Value(value) => {
                content.insert(field.name.clone(), value);
            }
            Asked::Skipped => {}
            Asked::GaveUp => return ElicitationAnswer::Cancel,
        }
    }
    ElicitationAnswer::Accept(serde_json::Value::Object(content))
}

enum Asked {
    Value(serde_json::Value),
    /// An optional field left unanswered.
    Skipped,
    /// A required field left unanswered: the whole form is dismissed.
    GaveUp,
}

fn ask_field(asker: &dyn Asker, title: &str, field: &Field) -> Asked {
    let unanswered = || {
        if field.required {
            Asked::GaveUp
        } else {
            Asked::Skipped
        }
    };
    match &field.kind {
        Kind::Flag => Asked::Value(serde_json::json!(matches!(
            asker.card(title, &field.label, &["y for yes · n for no".into()]),
            CardReply::Yes
        ))),
        Kind::Choice(options) => {
            for (index, option) in options.iter().enumerate() {
                let reply = asker.card(
                    title,
                    &format!("{}: \"{option}\"?", field.label),
                    &[format!(
                        "option {} of {} · y for this one · n for the next",
                        index + 1,
                        options.len()
                    )],
                );
                if reply == CardReply::Yes {
                    return Asked::Value(serde_json::json!(option));
                }
            }
            unanswered()
        }
        Kind::Text | Kind::Number { .. } => {
            let on_yes = match &field.default {
                Some(default) => format!("y uses {default}"),
                None if field.required => "y gives up the form".to_owned(),
                None => "y leaves it empty".to_owned(),
            };
            let reply = asker.card(
                title,
                &field.label,
                &[format!("press n and type the value · {on_yes}")],
            );
            let typed = match reply {
                CardReply::Yes => {
                    return field.default.clone().map_or_else(unanswered, Asked::Value);
                }
                CardReply::No(note) => note.map(|note| note.trim().to_owned()),
            };
            let Some(typed) = typed.filter(|text| !text.is_empty()) else {
                return unanswered();
            };
            match field.kind {
                Kind::Number { whole: true } => typed.parse::<i64>().map_or_else(
                    |_| unanswered(),
                    |number| Asked::Value(serde_json::json!(number)),
                ),
                Kind::Number { whole: false } => typed
                    .parse::<f64>()
                    .ok()
                    .filter(|number| number.is_finite())
                    .map_or_else(unanswered, |number| Asked::Value(serde_json::json!(number))),
                _ => Asked::Value(serde_json::json!(typed)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Replies in order, recording what each card said.
    struct Script {
        replies: Mutex<Vec<CardReply>>,
        seen: Mutex<Vec<String>>,
    }

    impl Script {
        fn new(replies: Vec<CardReply>) -> Self {
            Self {
                replies: Mutex::new(replies),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Asker for Script {
        fn card(&self, title: &str, text: &str, _details: &[String]) -> CardReply {
            self.seen.lock().unwrap().push(format!("{title} | {text}"));
            let mut replies = self.replies.lock().unwrap();
            if replies.is_empty() {
                CardReply::No(None)
            } else {
                replies.remove(0)
            }
        }
    }

    fn request(schema: serde_json::Value) -> Elicitation {
        Elicitation {
            server: "forge".into(),
            message: "Release details".into(),
            mode: "form".into(),
            schema,
            url: None,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
            cancelled: None,
        }
    }

    fn note(text: &str) -> CardReply {
        CardReply::No(Some(text.into()))
    }

    fn form() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "branch": {"type": "string", "title": "Branch"},
                "channel": {"type": "string", "enum": ["stable", "beta", "nightly"]},
                "draft": {"type": "boolean", "description": "Publish as a draft"},
                "retries": {"type": "integer", "default": 3},
                "weight": {"type": "number"},
                "nested": {"type": "object"}
            },
            "required": ["branch", "channel"]
        })
    }

    #[test]
    fn a_form_is_asked_a_field_at_a_time_and_typed_values_keep_their_types() {
        let script = Script::new(vec![
            CardReply::Yes,      // answer the form
            note("release/7"),   // branch
            CardReply::No(None), // channel: not stable
            CardReply::Yes,      // channel: beta
            CardReply::No(None), // draft: no
            CardReply::Yes,      // retries: the default
            note("0.5"),         // weight
        ]);
        let answered = answer(&request(form()), &Hooks::default(), Some(&script));
        assert_eq!(
            answered,
            ElicitationAnswer::Accept(serde_json::json!({
                "branch": "release/7", "channel": "beta", "draft": false,
                "retries": 3, "weight": 0.5
            }))
        );
        let seen = script.seen();
        assert_eq!(seen[0], "mcp forge | forge asks: Release details");
        assert_eq!(
            seen.len(),
            7,
            "the object-typed property is not a field: {seen:?}"
        );
    }

    #[test]
    fn declining_dismissing_and_leaving_optional_fields_empty() {
        let declined = answer(
            &request(form()),
            &Hooks::default(),
            Some(&Script::new(vec![CardReply::No(None)])),
        );
        assert_eq!(declined, ElicitationAnswer::Decline);
        // A required field with no answer dismisses the whole form.
        let dismissed = answer(
            &request(form()),
            &Hooks::default(),
            Some(&Script::new(vec![CardReply::Yes, CardReply::Yes])),
        );
        assert_eq!(dismissed, ElicitationAnswer::Cancel);
        let sparse = answer(
            &request(form()),
            &Hooks::default(),
            Some(&Script::new(vec![
                CardReply::Yes,
                note("main"),
                CardReply::Yes, // stable
                CardReply::Yes, // draft
                note("many"),   // retries: not a whole number, optional
                CardReply::Yes, // weight: left empty
            ])),
        );
        assert_eq!(
            sparse,
            ElicitationAnswer::Accept(serde_json::json!({
                "branch": "main", "channel": "stable", "draft": true
            }))
        );
        // Nobody to ask.
        assert_eq!(
            answer(&request(form()), &Hooks::default(), None),
            ElicitationAnswer::Cancel
        );
        // A confirmation with no fields, and a page to visit.
        let confirm = Script::new(vec![CardReply::Yes]);
        assert_eq!(
            answer(
                &request(serde_json::json!({})),
                &Hooks::default(),
                Some(&confirm)
            ),
            ElicitationAnswer::Accept(serde_json::json!({}))
        );
        let mut visit = request(serde_json::json!({}));
        visit.mode = "url".into();
        assert_eq!(
            answer(
                &visit,
                &Hooks::default(),
                Some(&Script::new(vec![CardReply::Yes]))
            ),
            ElicitationAnswer::Decline,
            "a url request without a url"
        );
        visit.url = Some("https://forge.example/authorize".into());
        assert_eq!(
            answer(
                &visit,
                &Hooks::default(),
                Some(&Script::new(vec![CardReply::Yes]))
            ),
            ElicitationAnswer::Accept(serde_json::json!({}))
        );
        // Too many fields to ask one by one.
        let wide: serde_json::Map<String, serde_json::Value> = (0..=MAX_FIELDS)
            .map(|n| (format!("f{n}"), serde_json::json!({"type": "boolean"})))
            .collect();
        let never = Script::new(vec![CardReply::Yes]);
        assert_eq!(
            answer(
                &request(serde_json::json!({"type": "object", "properties": wide})),
                &Hooks::default(),
                Some(&never)
            ),
            ElicitationAnswer::Decline
        );
        assert!(never.seen().is_empty());
    }

    fn hook(event: &str, matcher: &str, command: &str) -> orbit_engine::hooks::HookConfig {
        orbit_engine::hooks::HookConfig {
            event: event.into(),
            command: command.into(),
            timeout_secs: Some(10),
            matcher: Some(matcher.into()),
            condition: None,
            run_async: false,
            http: None,
            handler: None,
            origin: None,
        }
    }

    #[test]
    fn hooks_answer_for_the_operator_decline_and_rewrite_the_result() {
        let hooks = |list: Vec<orbit_engine::hooks::HookConfig>| Hooks {
            hooks: list,
            project_trusted: false,
            context_limit: None,
        };
        let never = Script::new(vec![CardReply::Yes]);
        // A hook answers: no card is shown.
        let answered = answer(
            &request(form()),
            &hooks(vec![hook(
                "Elicitation",
                "forge",
                r#"printf '%s' '{"hookSpecificOutput": {"action": "accept", "content": {"branch": "main"}}}'"#,
            )]),
            Some(&never),
        );
        assert_eq!(
            answered,
            ElicitationAnswer::Accept(serde_json::json!({"branch": "main"}))
        );
        // Exit code 2 declines; a hook for another server is not consulted.
        let declined = answer(
            &request(form()),
            &hooks(vec![
                hook(
                    "Elicitation",
                    "other",
                    r#"printf '{"hookSpecificOutput": {"action": "cancel"}}'"#,
                ),
                hook("Elicitation", "forge", "echo not from here >&2; exit 2"),
            ]),
            Some(&never),
        );
        assert_eq!(declined, ElicitationAnswer::Decline);
        assert!(never.seen().is_empty());
        // The result hook sees the operator's answer and may replace it or
        // stop it.
        let rewritten = answer(
            &request(serde_json::json!({})),
            &hooks(vec![hook(
                "ElicitationResult",
                "forge",
                r#"grep -q '"action":"accept"' && printf '{"hookSpecificOutput": {"action": "accept", "content": {"stamped": true}}}'"#,
            )]),
            Some(&Script::new(vec![CardReply::Yes])),
        );
        assert_eq!(
            rewritten,
            ElicitationAnswer::Accept(serde_json::json!({"stamped": true}))
        );
        let stopped = answer(
            &request(serde_json::json!({})),
            &hooks(vec![hook("ElicitationResult", "*", "exit 2")]),
            Some(&Script::new(vec![CardReply::Yes])),
        );
        assert_eq!(stopped, ElicitationAnswer::Decline);
    }
}
