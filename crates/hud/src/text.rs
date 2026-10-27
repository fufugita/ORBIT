//! Shared display safety and private-reasoning filtering for frontends.

/// Tags that wrap chain-of-thought / private reasoning. Stripped at the bridge,
/// never reaching the reducer. The content between tags is discarded entirely.
const COT_TAGS: &[&str] = &[
    "antml:thinking",
    "reasoning",
    "analysis",
    "scratchpad",
    "internal",
    "thinking",
];
const MAX_COT_NESTING_DEPTH: usize = 64;

pub fn strip_cot(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let lower = text.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut stack = Vec::<&'static str>::new();

    while cursor < text.len() {
        if stack.is_empty() {
            let Some((position, _, tag, token_len)) = next_cot_token(&lower, cursor, false) else {
                output.push_str(&text[cursor..]);
                break;
            };
            output.push_str(&text[cursor..position]);
            stack.push(tag);
            cursor = position + token_len;
            continue;
        }

        let Some((position, is_open, tag, token_len)) = next_cot_token(&lower, cursor, true) else {
            // An unclosed or malformed block stays private through EOF.
            return output;
        };
        cursor = position + token_len;
        if is_open {
            if stack.len() == MAX_COT_NESTING_DEPTH {
                // Do not retain attacker-controlled nesting or expose its tail.
                return output;
            }
            stack.push(tag);
        } else if stack.last() == Some(&tag) {
            stack.pop();
        }
    }

    output
}

/// Find the earliest recognized CoT token in an ASCII-folded string.
/// Byte offsets remain valid because ASCII case folding preserves UTF-8 length.
fn next_cot_token(
    lower: &str,
    from: usize,
    include_closers: bool,
) -> Option<(usize, bool, &'static str, usize)> {
    let bytes = lower.as_bytes();
    for position in from..bytes.len() {
        if bytes[position] != b'<' {
            continue;
        }

        for &tag in COT_TAGS {
            if let Some(token_len) = cot_token_len_at(bytes, position, false, tag) {
                return Some((position, true, tag, token_len));
            }
            if include_closers && let Some(token_len) = cot_token_len_at(bytes, position, true, tag)
            {
                return Some((position, false, tag, token_len));
            }
        }
    }
    None
}

fn cot_token_len_at(bytes: &[u8], position: usize, closing: bool, tag: &str) -> Option<usize> {
    let prefix: &[u8] = if closing { b"</" } else { b"<" };
    let token_len = prefix.len().checked_add(tag.len())?.checked_add(1)?;
    let end = position.checked_add(token_len)?;
    let token = bytes.get(position..end)?;
    let tag_start = prefix.len();
    let tag_end = tag_start + tag.len();

    (token.starts_with(prefix)
        && token[tag_start..tag_end] == *tag.as_bytes()
        && token[tag_end] == b'>')
        .then_some(token_len)
}

/// Retain a trailing prefix that could become any recognized CoT token.
fn partial_cot_token_suffix(hay: &str, include_closers: bool) -> String {
    let max_token_len = COT_TAGS
        .iter()
        .map(|tag| tag.len() + if include_closers { 3 } else { 2 })
        .max()
        .unwrap_or(0);
    for length in (1..=hay.len().min(max_token_len)).rev() {
        let start = hay.len() - length;
        if !hay.is_char_boundary(start) {
            continue;
        }
        let tail = &hay[start..];
        let tail_lower = tail.to_ascii_lowercase();
        if COT_TAGS.iter().any(|tag| {
            format!("<{tag}>").starts_with(&tail_lower)
                || (include_closers && format!("</{tag}>").starts_with(&tail_lower))
        }) {
            return tail.to_owned();
        }
    }
    String::new()
}

/// Apply display_safe (H-3) to a text chunk. If the gate rejects, return a
/// safe placeholder — never crash, never leak.
pub fn safe_text(text: &str) -> String {
    match crate::display_safe(text) {
        Ok(clean) => clean,
        Err(_) => "[redacted]".to_string(),
    }
}

/// Stateful CoT stripper for streaming deltas. Recognized nested tags are
/// balanced as a stack; malformed, unclosed or over-deep blocks fail closed.
#[derive(Default)]
pub struct CotStripper {
    inside: Vec<&'static str>,
    pending: String,
    failed_closed: bool,
}

impl CotStripper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, delta: &str) -> String {
        if self.failed_closed {
            return String::new();
        }

        let mut hay = std::mem::take(&mut self.pending);
        hay.push_str(delta);
        let lower = hay.to_ascii_lowercase();
        let mut cursor = 0usize;
        let mut output = String::new();

        loop {
            if self.inside.is_empty() {
                if let Some((position, _, tag, token_len)) = next_cot_token(&lower, cursor, false) {
                    output.push_str(&hay[cursor..position]);
                    self.inside.push(tag);
                    cursor = position + token_len;
                    continue;
                }

                let pending = partial_cot_token_suffix(&hay[cursor..], false);
                let emit_end = hay.len() - pending.len();
                output.push_str(&hay[cursor..emit_end]);
                self.pending = pending;
                return output;
            }

            let Some((position, is_open, tag, token_len)) = next_cot_token(&lower, cursor, true)
            else {
                self.pending = partial_cot_token_suffix(&hay[cursor..], true);
                return output;
            };
            cursor = position + token_len;
            if is_open {
                if self.inside.len() == MAX_COT_NESTING_DEPTH {
                    self.failed_closed = true;
                    self.inside.clear();
                    self.pending.clear();
                    return output;
                }
                self.inside.push(tag);
            } else if self.inside.last() == Some(&tag) {
                self.inside.pop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{COT_TAGS, CotStripper, safe_text, strip_cot};

    #[test]
    fn safe_text_redacts_secret_values_without_discarding_the_line() {
        let secret = "sk-abc123def456ghi789jkl012mno";
        let output = safe_text(&format!("request used {secret}; request completed"));
        assert!(!output.contains(secret));
        assert_eq!(
            output,
            "request used [redacted:api token]; request completed"
        );
        assert!(output.starts_with("request used "));
        assert!(output.ends_with("; request completed"));

        let output = safe_text(&format!("token = {secret}; request completed"));
        assert!(!output.contains(secret));
        assert_eq!(output, "token = [redacted:secret]");
        assert!(output.starts_with("token = "));
    }

    #[test]
    fn safe_text_rejects_content_markers_and_preserves_unicode_lines() {
        for marker in ["prompt:", "USER_MESSAGE", "Chain_Of_Thought"] {
            assert_eq!(safe_text(&format!("before {marker} after")), "[redacted]");
        }
        assert_eq!(
            safe_text("naïve café 東京 🦀\nnext\tline\r\0"),
            "naïve café 東京 🦀\nnextline"
        );
        assert_eq!(
            safe_text("api_key=secret https://example.com"),
            "api_key=secret https://example.com"
        );
    }

    #[test]
    fn strip_cot_removes_every_supported_tag_case_without_corrupting_unicode() {
        for tag in COT_TAGS {
            assert_eq!(
                strip_cot(&format!("café 🦀 <{tag}>hidden 東京</{tag}> visible")),
                "café 🦀  visible"
            );
            let upper = tag.to_ascii_uppercase();
            assert_eq!(
                strip_cot(&format!("before<{upper}>hidden</{tag}>after")),
                "beforeafter"
            );
        }
        assert_eq!(
            strip_cot("ordinary naïve 東京 🦀 text"),
            "ordinary naïve 東京 🦀 text"
        );
    }

    #[test]
    fn many_reasoning_tag_pairs_stay_hidden_in_batch_and_streaming_modes() {
        let pair = "<analysis>SYNTHETIC_PRIVATE</analysis>";
        let input = format!("visible{}after", pair.repeat(2_048));

        let batch = strip_cot(&input);
        assert_eq!(batch, "visibleafter");
        assert!(!batch.contains("SYNTHETIC_PRIVATE"));

        let mut stripper = CotStripper::new();
        let streamed = stripper.push(&input);
        assert_eq!(streamed, "visibleafter");
        assert!(!streamed.contains("SYNTHETIC_PRIVATE"));
        assert_eq!(stripper.push(" still visible"), " still visible");
    }

    #[test]
    fn strip_cot_discards_an_unclosed_block_and_keeps_ordinary_markup() {
        assert_eq!(
            strip_cot("visible<internal>hidden <other> never closed"),
            "visible"
        );
        assert_eq!(
            strip_cot("math: 1 < 2; <code>visible</code>"),
            "math: 1 < 2; <code>visible</code>"
        );
        assert_eq!(
            strip_cot("a<analysis>x</analysis>b<analysis>y</analysis>c"),
            "abc"
        );
        assert_eq!(
            strip_cot(
                "visible<analysis>outer <analysis>inner</analysis> private outer tail</analysis>after"
            ),
            "visibleafter"
        );
    }

    #[test]
    fn streaming_split_open_and_close_keep_unicode_visible_bytes() {
        let mut stripper = CotStripper::new();
        assert_eq!(stripper.push("café 🦀 <thin"), "café 🦀 ");
        assert_eq!(stripper.push("king>private 東京"), "");
        assert_eq!(stripper.push("</thin"), "");
        assert_eq!(stripper.push("king> 東京"), " 東京");
        assert_eq!(stripper.push(" café"), " café");
    }

    #[test]
    fn streaming_unclosed_reasoning_stays_hidden_across_deltas() {
        let mut stripper = CotStripper::default();
        assert_eq!(stripper.push("visible <analysis>"), "visible ");
        assert_eq!(stripper.push("private\0 東京"), "");
        assert_eq!(stripper.push("still private"), "");
        assert_eq!(stripper.push("</ana"), "");
        assert_eq!(stripper.push("lysis>after"), "after");
    }

    #[test]
    fn streaming_complete_close_prefix_is_held_until_its_final_byte() {
        let mut stripper = CotStripper::new();
        assert_eq!(stripper.push("before<reasoning>hidden"), "before");
        assert_eq!(stripper.push("</reasoning"), "");
        assert_eq!(stripper.push(">after"), "after");
    }

    #[test]
    fn streaming_disproved_open_prefix_is_released_without_losing_text() {
        let mut stripper = CotStripper::new();
        assert_eq!(stripper.push("value <"), "value ");
        assert_eq!(stripper.push("plain>東京"), "<plain>東京");
        assert_eq!(stripper.push(" 1 < 2"), " 1 < 2");
        assert_eq!(stripper.push(""), "");
    }

    #[test]
    fn independent_streams_do_not_share_private_reasoning_state() {
        let mut hidden = CotStripper::new();
        let mut visible = CotStripper::default();
        assert_eq!(hidden.push("<scratchpad>private"), "");
        assert_eq!(visible.push("ordinary café"), "ordinary café");
        assert_eq!(hidden.push("still private"), "");
        assert_eq!(visible.push(" 東京"), " 東京");
        assert_eq!(hidden.push("</scratchpad>done"), "done");
    }

    #[test]
    fn streaming_mixed_tags_follow_input_order_instead_of_tag_priority() {
        for (first, second) in [
            ("thinking", "analysis"),
            ("analysis", "thinking"),
            ("internal", "antml:thinking"),
            ("antml:thinking", "internal"),
        ] {
            let input =
                format!("a<{first}>hidden first</{first}>b<{second}>hidden second</{second}>c");
            let mut stripper = CotStripper::new();
            assert_eq!(stripper.push(&input), "abc", "{first} then {second}");
        }
        let mut stripper = CotStripper::new();
        assert_eq!(
            stripper.push("a<thinking>x</thinking>b<internal>y</internal>c<analysis>z</analysis>d"),
            "abcd"
        );
    }

    #[test]
    fn streaming_nested_different_tags_hide_the_entire_earliest_outer_block() {
        for (outer, inner) in [
            ("thinking", "analysis"),
            ("analysis", "thinking"),
            ("scratchpad", "antml:thinking"),
            ("antml:thinking", "scratchpad"),
        ] {
            let input =
                format!("before<{outer}>outer <{inner}>inner</{inner}> outer tail</{outer}>after");
            let mut stripper = CotStripper::new();
            assert_eq!(
                stripper.push(&input),
                "beforeafter",
                "{outer} contains {inner}"
            );
            assert_eq!(strip_cot(&input), "beforeafter");
        }
    }

    #[test]
    fn same_tag_nesting_hides_outer_tail_in_batch_and_streaming_modes() {
        let input =
            "visible<analysis>outer <analysis>inner</analysis> private outer tail</analysis>after";
        assert_eq!(strip_cot(input), "visibleafter");

        // Exercise every UTF-8-safe two-delta boundary, including boundaries
        // inside both the nested opener and its matching close.
        for split in input
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(input.len()))
        {
            let mut stripper = CotStripper::new();
            let output = stripper.push(&input[..split]) + &stripper.push(&input[split..]);
            assert_eq!(output, "visibleafter", "split at byte {split}");
        }

        // One-character deltas force every token, including the nested pair,
        // to cross streaming boundaries while preserving the outer depth.
        let mut stripper = CotStripper::new();
        let mut output = String::new();
        for character in input.chars() {
            output.push_str(&stripper.push(&character.to_string()));
        }
        assert_eq!(output, "visibleafter");
    }

    #[test]
    fn crossed_mixed_tags_keep_private_tail_hidden_at_every_stream_boundary() {
        let input = "visible café<analysis>outer <thinking>inner</analysis>LEAK</thinking>outer tail</analysis>after résumé";
        let expected = "visible caféafter résumé";

        assert_eq!(strip_cot(input), expected);
        assert!(!strip_cot(input).contains("LEAK"));

        // Every UTF-8-safe split exercises partial open/close tokens and confirms
        // mismatched </analysis> cannot pop the nested <thinking> frame.
        for split in input
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(input.len()))
        {
            let mut stripper = CotStripper::new();
            let output = stripper.push(&input[..split]) + &stripper.push(&input[split..]);
            assert_eq!(output, expected, "split at byte {split}");
            assert!(!output.contains("LEAK"), "split at byte {split}");
        }

        let mut stripper = CotStripper::new();
        let mut output = String::new();
        for character in input.chars() {
            output.push_str(&stripper.push(&character.to_string()));
        }
        assert_eq!(output, expected);
        assert!(!output.contains("LEAK"));
    }

    #[test]
    fn cot_nesting_depth_overflow_fails_closed_in_batch_and_streaming_modes() {
        let openers = "<analysis>".repeat(super::MAX_COT_NESTING_DEPTH + 1);
        let closers = "</analysis>".repeat(super::MAX_COT_NESTING_DEPTH + 1);
        let batch = format!("safe prefix{openers}SYNTHETIC_PRIVATE_BODY{closers}safe suffix");
        assert_eq!(strip_cot(&batch), "safe prefix");
        assert!(!strip_cot(&batch).contains("SYNTHETIC_PRIVATE_BODY"));

        let mut stripper = CotStripper::new();
        let streamed_openers = format!("safe prefix{openers}SYNTHETIC_PRIVATE_BODY");
        assert_eq!(stripper.push(&streamed_openers), "safe prefix");
        assert!(stripper.failed_closed);
        assert_eq!(stripper.push(&format!("{closers}safe suffix")), "");
    }

    #[test]
    fn streaming_split_open_and_close_then_a_different_tag_keep_only_visible_text() {
        let mut stripper = CotStripper::new();
        assert_eq!(stripper.push("before<thin"), "before");
        assert_eq!(stripper.push("king>hidden</thi"), "");
        assert_eq!(
            stripper.push("nking>middle<analysis>also hidden</analysis>after"),
            "middleafter"
        );
        let mut reverse = CotStripper::new();
        assert_eq!(reverse.push("before<ana"), "before");
        assert_eq!(reverse.push("lysis>hidden</anal"), "");
        assert_eq!(
            reverse.push("ysis>middle<thinking>also hidden</thinking>after"),
            "middleafter"
        );
    }

    #[test]
    fn unicode_case_expansion_never_shifts_open_or_close_offsets() {
        for tag in COT_TAGS {
            let input = format!("İ café 🦀 <{tag}>İ hidden 東京</{tag}> İ visible");
            assert_eq!(strip_cot(&input), "İ café 🦀  İ visible");
            let mut stripper = CotStripper::new();
            assert_eq!(stripper.push(&input), "İ café 🦀  İ visible");
            let mut streamed = CotStripper::new();
            assert_eq!(
                streamed.push(&format!("İ before<{tag}>İ hidden")),
                "İ before"
            );
            assert_eq!(
                streamed.push(&format!("İ private</{tag}>İ after")),
                "İ after"
            );
        }
    }

    #[test]
    fn every_supported_tag_is_hidden_at_every_utf8_delta_boundary() {
        for tag in COT_TAGS {
            for spelling in [tag.to_string(), tag.to_ascii_uppercase()] {
                let input = format!("İ café 🦀 <{spelling}>hidden 東京 İ</{spelling}> visible é");
                for split in input
                    .char_indices()
                    .map(|(index, _)| index)
                    .chain(std::iter::once(input.len()))
                {
                    let mut stripper = CotStripper::new();
                    let output = stripper.push(&input[..split]) + &stripper.push(&input[split..]);
                    assert_eq!(output, "İ café 🦀  visible é", "{spelling} at byte {split}");
                }
                let mut one_character_at_a_time = CotStripper::new();
                let mut output = String::new();
                for character in input.chars() {
                    output.push_str(&one_character_at_a_time.push(&character.to_string()));
                }
                assert_eq!(
                    output, "İ café 🦀  visible é",
                    "{spelling} in single-character deltas"
                );
            }
        }
    }

    #[test]
    fn wholly_partial_and_long_openers_stay_pending_until_completed_or_disproved() {
        for tag in COT_TAGS {
            let opener = format!("<{tag}>");
            for end in 1..opener.len() {
                let mut stripper = CotStripper::new();
                assert_eq!(
                    stripper.push(&opener[..end]),
                    "",
                    "{tag} prefix length {end}"
                );
                assert_eq!(
                    stripper.push(&format!("{}hidden</{tag}>after", &opener[end..])),
                    "after"
                );
            }
        }
        let mut long = CotStripper::new();
        assert_eq!(long.push("<antml:thinkin"), "");
        assert_eq!(long.push("g>hidden</antml:thinking>visible"), "visible");
        let mut disproved = CotStripper::new();
        assert_eq!(disproved.push("<scratchpa"), "");
        assert_eq!(disproved.push("per>İ visible"), "<scratchpaper>İ visible");
    }

    #[test]
    fn every_unclosed_supported_tag_fails_closed_across_utf8_boundaries() {
        for tag in COT_TAGS {
            let input = format!("İ visible<{tag}>hidden 東京 İ");
            assert_eq!(strip_cot(&input), "İ visible");
            for split in input
                .char_indices()
                .map(|(index, _)| index)
                .chain(std::iter::once(input.len()))
            {
                let mut stripper = CotStripper::new();
                let output = stripper.push(&input[..split]) + &stripper.push(&input[split..]);
                assert_eq!(output, "İ visible", "{tag} at byte {split}");
                let other = if *tag == "analysis" {
                    "thinking"
                } else {
                    "analysis"
                };
                assert_eq!(
                    stripper.push(&format!(" still hidden <{other}>nested</{other}>")),
                    ""
                );
                assert_eq!(stripper.push(" still not closed"), "");
            }
        }
    }
}
