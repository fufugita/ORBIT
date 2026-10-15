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
    !phrase_ranges(hay, needle).is_empty()
}

/// Maximum UTF-8 prompt and keyword sizes accepted by the phase classifier.
pub const MAX_ROUTING_PROMPT_BYTES: usize = 256 * 1024;
pub const MAX_ROUTING_KEYWORDS: usize = 128;
pub const MAX_ROUTING_KEYWORD_BYTES: usize = 96;

/// The type of work, independent of its difficulty.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum TaskPhase {
    General,
    Thinking,
    Planning,
    Coding,
    Design,
    Orchestration,
    Pentest,
}
impl TaskPhase {
    pub const ALL: [Self; 7] = [
        Self::General,
        Self::Thinking,
        Self::Planning,
        Self::Coding,
        Self::Design,
        Self::Orchestration,
        Self::Pentest,
    ];
    pub const PRECEDENCE: [Self; 6] = [
        Self::Pentest,
        Self::Design,
        Self::Planning,
        Self::Coding,
        Self::Orchestration,
        Self::Thinking,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Thinking => "thinking",
            Self::Planning => "planning",
            Self::Coding => "coding",
            Self::Design => "design",
            Self::Orchestration => "orchestration",
            Self::Pentest => "pentest",
        }
    }
}
impl std::str::FromStr for TaskPhase {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str() == value)
            .ok_or_else(|| "unknown task phase".into())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Difficulty {
    Normal,
    Easy,
    Hard,
}
impl Difficulty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Easy => "easy",
            Self::Hard => "hard",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KeywordHit {
    pub keyword: String,
    pub occurrences: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TaskDecision {
    pub phase: TaskPhase,
    pub difficulty: Difficulty,
    pub phase_hits: std::collections::BTreeMap<TaskPhase, Vec<KeywordHit>>,
    pub hard_hits: Vec<KeywordHit>,
    pub easy_hits: Vec<KeywordHit>,
    pub phase_override: bool,
}

pub fn default_phase_keywords() -> std::collections::BTreeMap<TaskPhase, Vec<String>> {
    use TaskPhase::*;
    [
        (
            Thinking,
            &[
                "analyze",
                "analyse",
                "explain",
                "reason",
                "compare",
                "understand",
            ] as &[&str],
        ),
        (
            Planning,
            &["plan", "planning", "roadmap", "milestone", "strategy"],
        ),
        (
            Coding,
            &[
                "code",
                "coding",
                "implement",
                "fix",
                "debug",
                "refactor",
                "function",
                "test",
            ],
        ),
        (
            Design,
            &[
                "design",
                "redesign",
                "layout",
                "theme",
                "interface",
                "typography",
            ],
        ),
        (
            Orchestration,
            &[
                "orchestrate",
                "orchestration",
                "delegate",
                "spawn agents",
                "coordinate",
            ],
        ),
        (
            Pentest,
            &[
                "pentest",
                "penetration test",
                "security review",
                "vulnerability",
                "exploit",
                "recon",
                "audit",
            ],
        ),
    ]
    .into_iter()
    .map(|(p, words)| (p, words.iter().map(|s| (*s).into()).collect()))
    .collect()
}

pub fn validate_keyword_list(words: &[String]) -> Result<(), String> {
    if words.len() > MAX_ROUTING_KEYWORDS {
        return Err("routing keyword category exceeds 128 entries".into());
    }
    for word in words {
        if word.len() > MAX_ROUTING_KEYWORD_BYTES
            || normalize(word).is_empty()
            || word.chars().any(|c| c.is_control() && !c.is_whitespace())
        {
            return Err("routing keyword must be nonempty, printable and at most 96 bytes".into());
        }
    }
    Ok(())
}

/// Match every valid occurrence. A substring within a larger Unicode word is not a hit.
fn phrase_ranges(hay: &str, needle: &str) -> Vec<std::ops::Range<usize>> {
    if needle.is_empty() {
        return Vec::new();
    }
    hay.match_indices(needle)
        .filter_map(|(at, _)| {
            let end = at + needle.len();
            let word = |c: char| {
                c.is_alphanumeric()
                    || c == '_'
                    || matches!(c,
                    '\u{0300}'..='\u{036f}' | '\u{1ab0}'..='\u{1aff}' |
                    '\u{1dc0}'..='\u{1dff}' | '\u{20d0}'..='\u{20ff}' |
                    '\u{fe20}'..='\u{fe2f}' | '\u{200c}' | '\u{200d}')
            };
            let before = hay[..at].chars().next_back().is_none_or(|c| !word(c));
            let after = hay[end..].chars().next().is_none_or(|c| !word(c));
            (before && after).then_some(at..end)
        })
        .collect()
}
fn keyword_hits(hay: &str, words: &[String]) -> Vec<KeywordHit> {
    let mut seen = std::collections::BTreeSet::new();
    words
        .iter()
        .filter_map(|word| {
            let keyword = normalize(word);
            if !seen.insert(keyword.clone()) {
                return None;
            }
            let occurrences = phrase_ranges(hay, &keyword).len();
            (occurrences > 0).then_some(KeywordHit {
                keyword,
                occurrences,
            })
        })
        .collect()
}

/// Classify phase mode without treating domain names as complexity evidence.
/// The returned matches contain keywords/counts only, never prompt content.
pub fn classify_task(
    phases: &std::collections::BTreeMap<TaskPhase, Vec<String>>,
    hard: &[String],
    easy: &[String],
    prompt: &str,
    phase_override: Option<TaskPhase>,
) -> Result<TaskDecision, String> {
    if prompt.len() > MAX_ROUTING_PROMPT_BYTES {
        return Err("routing prompt exceeds 256 KiB".into());
    }
    for words in phases.values().map(Vec::as_slice).chain([hard, easy]) {
        validate_keyword_list(words)?;
    }
    let hay = normalize(prompt);
    let phase_hits: std::collections::BTreeMap<_, _> = phases
        .iter()
        .filter_map(|(phase, words)| {
            let hits = keyword_hits(&hay, words);
            (!hits.is_empty()).then_some((*phase, hits))
        })
        .collect();
    let selected = phase_override.unwrap_or_else(|| {
        TaskPhase::PRECEDENCE
            .into_iter()
            .find(|p| phase_hits.contains_key(p))
            .unwrap_or(TaskPhase::General)
    });
    // Labels identify a domain; they do not make every task in that domain hard.
    // Keep action/complexity signals such as refactor, redesign and root cause.
    let labels = [
        "general",
        "thinking",
        "planning",
        "coding",
        "design",
        "orchestration",
        "pentest",
        "penetration test",
        "security review",
        "vulnerability",
        "exploit",
        "recon",
        "audit",
    ];
    let mut ranges: Vec<_> = labels
        .into_iter()
        .flat_map(|label| phrase_ranges(&hay, label))
        .collect();
    ranges.sort_by_key(|r| r.start);
    let mut stripped = String::with_capacity(hay.len());
    let mut cursor = 0;
    for range in ranges {
        if range.start < cursor {
            continue;
        }
        stripped.push_str(&hay[cursor..range.start]);
        stripped.push(' ');
        cursor = range.end;
    }
    stripped.push_str(&hay[cursor..]);
    let hard_hits = keyword_hits(&stripped, hard);
    let easy_hits = keyword_hits(&stripped, easy);
    let difficulty = if !hard_hits.is_empty() {
        Difficulty::Hard
    } else if !easy_hits.is_empty() {
        Difficulty::Easy
    } else {
        Difficulty::Normal
    };
    Ok(TaskDecision {
        phase: selected,
        difficulty,
        phase_hits,
        hard_hits,
        easy_hits,
        phase_override: phase_override.is_some(),
    })
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
    strip_opaque_blocks(transcript, None, keep_for)
}

/// Provider-aware dispatch guard. Legacy history without both provenance fields
/// cannot prove ownership, even if its raw model happens to match the target.
pub fn strip_foreign_opaque_blocks_for(
    transcript: &mut [orbit_adapter::types::ChatMessage],
    provider: &str,
    model: &str,
) -> usize {
    strip_opaque_blocks(transcript, Some(provider), model)
}

fn strip_opaque_blocks(
    transcript: &mut [orbit_adapter::types::ChatMessage],
    provider: Option<&str>,
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
            .unwrap_or(false)
            && provider.is_none_or(|provider| m.origin_provider.as_deref() == Some(provider));
        if same {
            continue;
        }
        let blocks = m.blocks.take().unwrap_or_default();
        let before = blocks.len();
        let kept: Vec<ContentBlock> = blocks
            .into_iter()
            .filter(|b| !matches!(b, ContentBlock::Opaque { .. }))
            .collect();
        dropped += usize::from(kept.len() != before);
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
                origin_provider: None,
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
                origin_provider: None,
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
