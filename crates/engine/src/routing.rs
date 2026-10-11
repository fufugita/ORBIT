//! Difficulty routing — the phase router, in-harness (2026-10-10).
//!
//! The conversation's model is chosen per prompt from a small keyword
//! classifier: a `hard` signal sends the turn to the strong model, an
//! `easy` signal to the cheap one, and no signal keeps the session's
//! own. Hard always wins (a hard word inside a lazy-sounding request
//! is still hard work — the same lesson the litellm phase router
//! learned when easy keywords swallowed pentest turns).
//!
//! Deliberately deterministic and inspectable: no second model call,
//! no hidden state. `orbit route test "<prompt>"` shows exactly what
//! a prompt would route to and why, before anything is sent.

/// Which model serves a routed turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPhase {
    /// The hard/easy table says the strong model.
    Hard,
    /// The table says the cheap model.
    Easy,
    /// No signal — the session's own model.
    Main,
}

impl RoutingPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoutingPhase::Hard => "hard",
            RoutingPhase::Easy => "easy",
            RoutingPhase::Main => "main",
        }
    }
}

/// Routing as configured: target models (empty = routing off) plus
/// keyword lists. Defaults are merged in by the config layer; here a
/// list is what it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingTable {
    /// Model spec for hard turns ("" = routing off).
    pub hard: String,
    /// Model spec for easy turns ("" = routing off).
    pub easy: String,
    /// Hard-signal keywords (matched on word boundaries,
    /// case-insensitive; a phrase entry matches its words adjacently).
    pub hard_keywords: Vec<String>,
    /// Easy-signal keywords.
    pub easy_keywords: Vec<String>,
}

impl RoutingTable {
    /// Routing is armed when at least one target is set. A table with
    /// keywords but no models classifies nothing.
    pub fn enabled(&self) -> bool {
        !self.hard.is_empty() || !self.easy.is_empty()
    }
}

/// The shipped keyword defaults, used when `[routing]` declares models
/// but no (or partial) keyword lists. High-precision vocabulary only:
/// a word here moves real money, so words that merely sound
/// impressive ("specific", "detailed") stay out. Users extend with
/// `[routing.keywords]`.
pub fn default_hard_keywords() -> Vec<String> {
    [
        "refactor",
        "restructure",
        "rearchitect",
        "architect",
        "redesign",
        "design",
        "debug",
        "diagnose",
        "root cause",
        "trace",
        "investigate",
        "why does",
        "walk me through",
        "optimize",
        "optimise",
        "performance",
        "concurrency",
        "race condition",
        "deadlock",
        "memory leak",
        "throughput",
        "security review",
        "vulnerability",
        "exploit",
        "pentest",
        "threat model",
        "reverse engineer",
        "disassemble",
        "migration",
        "migrate",
        "from scratch",
        "ground up",
        "production ready",
        "comprehensive",
        "thorough",
        "exhaustive",
        "edge case",
        "corner case",
        "step by step",
        "trade-off",
        "tradeoffs",
        "state machine",
        "distributed",
        "consensus",
        "compiler",
        "protocol",
        "cryptographic",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn default_easy_keywords() -> Vec<String> {
    [
        "summarize",
        "summarise",
        "briefly",
        "quickly",
        "tl;dr",
        "tldr",
        "one line",
        "yes or no",
        "what is",
        "who is",
        "where is",
        "list the",
        "name the",
        "remind me",
        "typo",
        "rename",
        "lint",
        "format",
        "snippet",
        "example",
        "how do i",
        "how to",
        "copy",
        "paste",
        "simple question",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// One classification: the phase and every keyword that fired.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingDecision {
    pub phase: RoutingPhase,
    /// The matched keywords (lowercased as entered).
    pub matched: Vec<String>,
}

/// Classify one prompt. Word-boundary, case-insensitive substring
/// match; a multi-word entry matches its words adjacently (any single
/// whitespace between them). Hard wins over easy when both fire.
pub fn classify(table: &RoutingTable, prompt: &str) -> RoutingDecision {
    let hay = normalize(prompt);
    let hits = |list: &[String]| -> Vec<String> {
        list.iter()
            .filter(|kw| {
                let needle = normalize(kw);
                !needle.is_empty() && contains_phrase(&hay, &needle)
            })
            .cloned()
            .collect()
    };
    let hard = hits(&table.hard_keywords);
    if !hard.is_empty() {
        return RoutingDecision {
            phase: RoutingPhase::Hard,
            matched: hard,
        };
    }
    let easy = hits(&table.easy_keywords);
    if !easy.is_empty() {
        return RoutingDecision {
            phase: RoutingPhase::Easy,
            matched: easy,
        };
    }
    RoutingDecision {
        phase: RoutingPhase::Main,
        matched: Vec::new(),
    }
}

/// Lowercase + collapse whitespace runs to single spaces, so phrase
/// matching survives the paragraph breaks people actually type.
fn normalize(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Phrase containment on the normalized haystack: the needle must
/// appear starting and ending at a word boundary. `;` `:` `.` `,`
/// count as boundaries too (a keyword before punctuation matches).
fn contains_phrase(hay: &str, needle: &str) -> bool {
    let Some(at) = hay.find(needle) else {
        return false;
    };
    let before_ok = at == 0 || !is_word_char(hay.as_bytes()[at - 1]);
    let end = at + needle.len();
    let after_ok = end >= hay.len() || !is_word_char(hay.as_bytes()[end]);
    before_ok && after_ok
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Record one routing outcome under the session dir, the same pattern
/// as egress grants: a JSON file per decision, inspectable and
/// replayable without touching the ledger's hash chain. Best-effort —
/// a routing record is observability, never a gate.
pub fn record_decision(
    home: &std::path::Path,
    session_id: &str,
    from_model: &str,
    to_model: &str,
    phase: RoutingPhase,
    matched: &[String],
) {
    let dir = home.join("sessions").join(session_id).join("routing");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let body = serde_json::json!({
        "phase": phase.as_str(),
        "matched": matched,
        "from_model": from_model,
        "to_model": to_model,
        "at_ms": stamp,
    });
    let _ = std::fs::write(
        dir.join(format!("{stamp}-{}.json", phase.as_str())),
        body.to_string(),
    );
}

/// Strip opaque (thinking / redacted-thinking) blocks from the
/// transcript copy a turn will send, when the turn's model differs
/// from the one that produced them. Cross-model thinking replay is
/// rejected by providers (signatures are model-bound), and a routing
/// switch must not turn into an API 400. The session file keeps the
/// blocks; only the wire copy is cleaned. Returns how many were
/// dropped, for the status line.
pub fn strip_foreign_opaque_blocks(
    transcript: &mut [orbit_adapter::types::ChatMessage],
    keep_for: &str,
) -> usize {
    use orbit_adapter::types::{ChatRole, ContentBlock};
    let mut dropped = 0usize;
    for m in transcript.iter_mut() {
        if m.role != ChatRole::Assistant {
            continue;
        }
        // Opaque blocks carry no model identity of their own; the
        // guard is the message-level origin tag set when they were
        // produced. Absent tag = legacy message: drop it too when a
        // switch happened, because we cannot prove it belongs to
        // `keep_for`.
        if m.blocks.is_none() {
            continue;
        }
        let same = m
            .origin_model
            .as_deref()
            .map(|om| om == keep_for)
            .unwrap_or(false);
        if same {
            continue;
        }
        let blocks = m.blocks.take().unwrap_or_default();
        let kept: Vec<ContentBlock> = blocks
            .into_iter()
            .filter(|b| !matches!(b, ContentBlock::Opaque { .. }))
            .collect();
        dropped += 1;
        m.blocks = (!kept.is_empty()).then_some(kept);
    }
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> RoutingTable {
        RoutingTable {
            hard: "big".into(),
            easy: "small".into(),
            hard_keywords: default_hard_keywords(),
            easy_keywords: default_easy_keywords(),
        }
    }

    #[test]
    fn hard_wins_over_easy() {
        let d = classify(&table(), "quickly refactor the parser");
        assert_eq!(d.phase, RoutingPhase::Hard);
        assert!(d.matched.contains(&"refactor".to_string()));
    }

    #[test]
    fn easy_matches_without_hard() {
        let d = classify(&table(), "briefly, what is a mutex?");
        assert_eq!(d.phase, RoutingPhase::Easy);
        assert!(d.matched.len() >= 2);
    }

    #[test]
    fn no_signal_is_main() {
        let d = classify(&table(), "add a button to the settings page");
        assert_eq!(d.phase, RoutingPhase::Main);
        assert!(d.matched.is_empty());
    }

    #[test]
    fn word_boundaries_stop_prefix_hits() {
        // "trace" must not match "traceroute".
        let t = RoutingTable {
            hard: "m".into(),
            easy: String::new(),
            hard_keywords: vec!["trace".into()],
            easy_keywords: vec![],
        };
        assert_eq!(classify(&t, "run traceroute").phase, RoutingPhase::Main);
        assert_eq!(classify(&t, "trace this call").phase, RoutingPhase::Hard);
    }

    #[test]
    fn phrases_match_across_line_breaks() {
        let t = RoutingTable {
            hard: "m".into(),
            easy: String::new(),
            hard_keywords: vec!["root cause".into()],
            easy_keywords: vec![],
        };
        assert_eq!(
            classify(&t, "find the root\ncause of the flake").phase,
            RoutingPhase::Hard
        );
    }

    #[test]
    fn punctuation_ends_a_match() {
        let t = RoutingTable {
            hard: "m".into(),
            easy: String::new(),
            hard_keywords: vec!["debug".into()],
            easy_keywords: vec![],
        };
        assert_eq!(classify(&t, "Debug, then test").phase, RoutingPhase::Hard);
    }

    #[test]
    fn case_insensitive() {
        let d = classify(&table(), "REFACTOR the module");
        assert_eq!(d.phase, RoutingPhase::Hard);
    }

    #[test]
    fn disabled_table_classifies_nothing() {
        let t = RoutingTable::default();
        assert!(!t.enabled());
        // classify still answers Main (callers check enabled() first,
        // but the function must be total).
        assert_eq!(
            classify(&t, "refactor everything").phase,
            RoutingPhase::Main
        );
    }

    #[test]
    fn strip_removes_only_foreign_opaque() {
        use orbit_adapter::types::{ChatMessage, ChatRole, ContentBlock};
        let mut transcript = vec![
            ChatMessage {
                role: ChatRole::Assistant,
                content: "a".into(),
                tool_calls: None,
                tool_call_id: None,
                tool_result: None,
                blocks: Some(vec![ContentBlock::Opaque {
                    json: r#"{"type":"thinking"}"#.into(),
                }]),
                origin_model: Some("old-model".into()),
            },
            ChatMessage {
                role: ChatRole::Assistant,
                content: "b".into(),
                tool_calls: None,
                tool_call_id: None,
                tool_result: None,
                blocks: Some(vec![ContentBlock::Opaque {
                    json: r#"{"type":"thinking"}"#.into(),
                }]),
                origin_model: Some("new-model".into()),
            },
        ];
        let dropped = strip_foreign_opaque_blocks(&mut transcript, "new-model");
        assert_eq!(dropped, 1);
        assert!(transcript[0].blocks.is_none());
        assert!(transcript[1].blocks.is_some());
    }

    #[test]
    fn record_writes_a_file() {
        let dir = std::env::temp_dir().join(format!("orbit-route-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sessions/s1")).unwrap();
        record_decision(
            &dir,
            "s1",
            "main-m",
            "hard-m",
            RoutingPhase::Hard,
            &["refactor".to_string()],
        );
        let routing_dir = dir.join("sessions/s1/routing");
        let mut entries: Vec<_> = std::fs::read_dir(&routing_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        let body = std::fs::read_to_string(entries.remove(0).path()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["phase"], "hard");
        assert_eq!(v["to_model"], "hard-m");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
