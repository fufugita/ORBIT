//! Grapheme-aware text shaping (DR-21 L14/L15).
//!
//! All layout passes through here — no `chars()` for column math, no byte
//! slicing. `unicode-segmentation` provides grapheme cluster boundaries;
//! `unicode-width` provides display widths; emoji presentation is forced to
//! 2 cells (the EAW-Wide convention, DR-21 §5.1).

use unicode_segmentation::UnicodeSegmentation;
pub use unicode_width::UnicodeWidthStr;

/// Display width of `s` in terminal cells, using EAW (East Asian Width)
/// for CJK/Ambiguous and treating emoji sequences as 2 cells.
pub fn display_width(s: &str) -> usize {
    s.graphemes(true).map(grapheme_width).sum()
}

/// Display width of a single grapheme cluster as a string.
pub fn grapheme_width(g: &str) -> usize {
    // Fast path: empty cluster contributes nothing.
    let Some(first) = g.chars().next() else {
        return 0;
    };
    if is_emoji(first) {
        return 2;
    }
    UnicodeWidthStr::width(g)
}

/// True for codepoints with **emoji presentation** (2 cells in terminals).
///
/// This is deliberately NOT a whole-block sweep. The original implementation
/// treated all of Misc Symbols (2600–26FF) and Dingbats (2700–27BF) as
/// 2-cell, which mis-measured text-presentation glyphs — ✓ (U+2713),
/// ✕ (U+2715), ✦ (U+2726) — that render as narrow symbols in terminal
/// fonts. Only the `Emoji_Presentation=Yes` codepoints are 2-cell; the
/// rest of those blocks measure via their East Asian Width (1 in
/// non-CJK context).
///
/// VS-16 (U+FE0F) forces emoji presentation for an otherwise-text glyph.
pub fn is_emoji(c: char) -> bool {
    let cp = c as u32;
    // High SMP blocks: all emoji-presentation by construction.
    (0x1F000..=0x1FFFF).contains(&cp) // Emoticons, Symbols, Pictographs, Transport, Supp-A/B, Extended-A
        || (0x1F1E6..=0x1F1FF).contains(&cp) // Regional Indicators (flags)
        // Low blocks: Emoji_Presentation=Yes subsets only (Unicode 15.1).
        // Misc Symbols (2600–26FF):
        || matches!(cp,
            0x2614..=0x2615 | 0x261D | 0x2620 | 0x2622..=0x2623 | 0x2626
            | 0x262A | 0x262E..=0x262F | 0x2638..=0x263A | 0x2640 | 0x2642
            | 0x2648..=0x2653 | 0x265F..=0x2660 | 0x2663 | 0x2665..=0x2666
            | 0x2668 | 0x267B | 0x267E..=0x267F | 0x2692..=0x2697 | 0x2699
            | 0x269B..=0x269C | 0x26A0..=0x26A1 | 0x26A7 | 0x26AA..=0x26AB
            | 0x26B0..=0x26B1 | 0x26BD..=0x26BE | 0x26C4..=0x26C5 | 0x26C8
            | 0x26CE..=0x26CF | 0x26D1 | 0x26D3..=0x26D4 | 0x26E9
            | 0x26F0..=0x26F5 | 0x26F7..=0x26FA | 0x26FD)
        // Dingbats (2700–27BF):
        || matches!(cp,
            0x2705 | 0x2708..=0x270D | 0x2714 | 0x2716 | 0x271D | 0x2721
            | 0x2728 | 0x2733..=0x2734 | 0x2744 | 0x2747 | 0x274C | 0x274E
            | 0x2753..=0x2755 | 0x2757 | 0x2763..=0x2764 | 0x2795..=0x2797
            | 0x27A1 | 0x27B0 | 0x27BF)
        || cp == 0xFE0F // Variation Selector-16 (forces emoji presentation)
}

/// Wrap `s` to `max_width` cells, breaking on grapheme boundaries.
/// Never breaks inside a grapheme cluster (emoji ZWJ, skin tone, etc.),
/// and never splits a single grapheme wider than the target.
pub fn prev_grapheme_boundary(s: &str, byte_index: usize) -> usize {
    let idx = byte_index.min(s.len());
    s.grapheme_indices(true)
        .map(|(index, _)| index)
        .chain(std::iter::once(s.len()))
        .take_while(|&index| index <= idx)
        .last()
        .unwrap_or(0)
}

/// Return the next grapheme boundary at or after a byte index.
pub fn next_grapheme_boundary(s: &str, byte_index: usize) -> usize {
    s.grapheme_indices(true)
        .map(|(index, grapheme)| index + grapheme.len())
        .find(|&end| end > byte_index)
        .unwrap_or(s.len())
}

/// Split at the nearest prior grapheme boundary.
pub fn split_at_boundary(s: &str, byte_index: usize) -> (&str, &str) {
    let index = prev_grapheme_boundary(s, byte_index.min(s.len()));
    s.split_at(index)
}

/// Wrap `s` to `max_width` cells, breaking on grapheme boundaries.
pub fn wrap_graphemes(s: &str, max_width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut current_width = 0usize;
    for g in s.graphemes(true) {
        let w = grapheme_width(g);
        if current_width + w > max_width && !current.is_empty() {
            out.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push_str(g);
        current_width += w;
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Word-wrap variant: greedy on spaces per PROMPT.md §7.4.
///
/// A line never starts with the spaces at a break, and spaces at the end of a
/// broken line are dropped. A word longer than the line is hard-broken at the
/// width on grapheme boundaries.
pub fn wrap_words(s: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    let mut line_width = 0usize;

    for word in s.split_whitespace() {
        let w = display_width(word);
        // A word longer than the line is hard-broken at the width.
        if w > max_width {
            if !line.is_empty() {
                out.push(std::mem::take(&mut line));
                line_width = 0;
            }
            let mut pieces = wrap_graphemes(word, max_width);
            if let Some(tail) = pieces.pop() {
                line_width = display_width(&tail);
                line = tail;
            }
            out.extend(pieces);
            continue;
        }
        if line.is_empty() {
            line.push_str(word);
            line_width = w;
            continue;
        }
        // The single separating space counts toward the line width.
        if line_width + 1 + w > max_width {
            out.push(std::mem::take(&mut line));
            line_width = w;
        } else {
            line.push(' ');
            line_width += 1;
        }
        line.push_str(word);
        line_width += w;
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

/// Wrap plain text greedily by spaces and indent continuation lines.
/// Styled spans are not represented by this string-only helper, so callers
/// must preserve style at the span layer while wrapping each span sequence.
pub fn wrap(s: &str, width: usize, indent: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let prefix = " ".repeat(indent.min(width.saturating_sub(1)));
    let content_width = width.saturating_sub(prefix.len()).max(1);
    let mut lines = wrap_words(s, content_width);
    if lines.is_empty() {
        return lines;
    }
    for line in lines.iter_mut().skip(1) {
        *line = format!("{prefix}{line}");
    }
    lines
}

/// Truncate `s` to at most `max_width` cells, appending `…` (U+2026, 1 cell)
/// if truncated. Never truncates mid-grapheme. The total rendered width
/// (including the ellipsis) is ≤ `max_width`.
pub fn truncate_graphemes(s: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    // Fits entirely — no ellipsis.
    if display_width(s) <= max_width {
        return s.to_string();
    }
    // Reserve one cell for the ellipsis; fill the rest with graphemes.
    let budget = max_width.saturating_sub(1);
    let mut out = String::new();
    let mut width = 0usize;
    for g in s.graphemes(true) {
        let w = grapheme_width(g);
        if width + w > budget {
            break;
        }
        out.push_str(g);
        width += w;
    }
    out.push('…');
    out
}

/// End-truncate at a grapheme boundary, appending an ellipsis if needed.
pub fn truncate_end(s: &str, max_width: usize) -> String {
    truncate_graphemes(s, max_width)
}

/// Middle truncation per PROMPT.md §7.4: with `w` columns available, keep the
/// last `ceil((w − 1) / 2)` clusters and the first `w − 1 − that` clusters,
/// joined by `…`. Widths are measured in cells; a wide cluster that does not
/// fit its side is dropped rather than split.
pub fn truncate_middle(s: &str, max_width: usize) -> String {
    if display_width(s) <= max_width {
        return s.to_string();
    }
    if max_width == 0 {
        return String::new();
    }
    if max_width == 1 {
        return "…".to_string();
    }
    let tail_budget = (max_width - 1).div_ceil(2);
    let head_budget = max_width - 1 - tail_budget;
    let clusters: Vec<&str> = s.graphemes(true).collect();
    let mut head = String::new();
    let mut head_width = 0;
    for cluster in clusters.iter().take(head_budget) {
        let width = grapheme_width(cluster);
        if head_width + width > head_budget {
            break;
        }
        head.push_str(cluster);
        head_width += width;
    }
    let mut tail = String::new();
    let mut tail_width = 0;
    for cluster in clusters.iter().rev().take(tail_budget) {
        let width = grapheme_width(cluster);
        if tail_width + width > tail_budget {
            break;
        }
        tail.insert_str(0, cluster);
        tail_width += width;
    }
    format!("{head}…{tail}")
}

/// Truncate `s` to at most `max_width` cells, KEEPING the tail and
/// prefixing `…` if truncated — `crates/…/restore.rs`. The end of a path
/// or command is its most specific part (§6.5). Never truncates
/// mid-grapheme; total width (including the ellipsis) ≤ `max_width`.
pub fn truncate_graphemes_tail(s: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if display_width(s) <= max_width {
        return s.to_string();
    }
    // Reserve one cell for the leading ellipsis; fill from the end.
    let budget = max_width.saturating_sub(1);
    let graphemes: Vec<&str> = s.graphemes(true).collect();
    let mut out: Vec<&str> = Vec::new();
    let mut width = 0usize;
    for g in graphemes.iter().rev() {
        let w = grapheme_width(g);
        if width + w > budget {
            break;
        }
        out.push(g);
        width += w;
    }
    out.reverse();
    let mut result = String::from("…");
    result.extend(out);
    result
}

#[cfg(test)]
mod tests {
    // Regression (2026-09-26): text-presentation glyphs in Misc Symbols /
    // Dingbats are ONE cell. The old whole-block is_emoji() sweep measured
    // them as 2 and misaligned every row containing them — these exact
    // codepoints are the ORBIT chrome vocabulary (glyphs.rs §4.3).
    #[test]
    fn text_presentation_dingbats_are_one_cell() {
        for g in ["✦", "✧", "✓", "✕", "✎", "✏", "✒"] {
            assert_eq!(grapheme_width(g), 1, "{g:?} is text presentation");
        }
    }

    #[test]
    fn text_presentation_misc_symbols_are_one_cell() {
        for g in ["◌", "◉", "○", "◎", "◐", "◑", "◓", "◒", "◔", "⊖", "⊘"] {
            assert_eq!(grapheme_width(g), 1, "{g:?} is narrow");
        }
    }

    #[test]
    fn emoji_presentation_still_two_cells() {
        // The Emoji_Presentation=Yes subset keeps its 2-cell measurement.
        for g in ["☔", "⛔", "✅", "❌", "❗", "➡"] {
            assert_eq!(grapheme_width(g), 2, "{g:?} is emoji presentation");
        }
    }

    use super::*;

    #[test]
    fn grapheme_boundary_helpers_preserve_clusters() {
        let text = "á界";
        assert_eq!(prev_grapheme_boundary(text, 2), 0);
        assert_eq!(next_grapheme_boundary(text, 1), 3);
        assert_eq!(split_at_boundary(text, 2), ("", text));
        assert_eq!(split_at_boundary(text, 3), ("á", "界"));
    }

    #[test]
    fn truncation_helpers_obey_width() {
        assert_eq!(truncate_end("abcdef", 4), "abc…");
        // Head and tail each get (w-1) cells split as ceil/floor: 3+1+3.
        assert_eq!(truncate_middle("abcdefghij", 7), "abc…hij");
        assert!(display_width(&truncate_middle("日本語の題名", 5)) <= 5);
    }

    #[test]
    fn wrap_drops_spaces_and_indents_continuations() {
        assert_eq!(
            wrap("alpha beta gamma", 8, 2),
            vec!["alpha", "  beta", "  gamma"]
        );
        assert_eq!(wrap("  alpha   beta  ", 8, 0), vec!["alpha", "beta"]);
    }

    #[test]
    fn ascii_width_one() {
        assert_eq!(display_width("a"), 1);
        assert_eq!(display_width("abc def"), 7);
    }

    #[test]
    fn cjk_width_two() {
        assert_eq!(display_width("中"), 2);
        assert_eq!(display_width("日本語"), 6);
    }

    #[test]
    fn emoji_width_two() {
        assert_eq!(display_width("👋"), 2);
        assert_eq!(display_width("✨"), 2);
    }

    #[test]
    fn zwj_family_width_two() {
        assert_eq!(display_width("👨‍👩‍👧"), 2);
    }

    #[test]
    fn regional_pair_width_two() {
        assert_eq!(display_width("🇺🇸"), 2);
    }

    #[test]
    fn combining_mark_width_one() {
        assert_eq!(display_width("a\u{0301}"), 1);
    }

    #[test]
    fn wrap_no_break_in_zwj() {
        let wrapped = wrap_graphemes("a👨‍👩‍👧b", 1);
        assert_eq!(wrapped, vec!["a", "👨‍👩‍👧", "b"]);
    }

    #[test]
    fn truncate_appends_ellipsis() {
        assert_eq!(truncate_graphemes("hello world", 5), "hell…");
        assert_eq!(truncate_graphemes("hi", 5), "hi");
        assert_eq!(truncate_graphemes("", 5), "");
    }

    #[test]
    fn prop_wrap_width_invariant() {
        for s in all_test_strings() {
            for w in 1..=20 {
                for line in wrap_graphemes(&s, w) {
                    let lw = display_width(&line);
                    let single_grapheme = line.graphemes(true).count() == 1;
                    assert!(
                        lw <= w || single_grapheme,
                        "line '{line}' (width {lw}) exceeds {w} and is not a single grapheme"
                    );
                    assert!(!line.is_empty(), "wrap produced an empty line");
                }
            }
        }
    }

    #[test]
    fn prop_wrap_roundtrip() {
        for s in all_test_strings() {
            let wrapped = wrap_graphemes(&s, 10);
            let joined: String = wrapped.concat();
            assert_eq!(joined, s, "wrap must be lossless");
        }
    }

    #[test]
    fn emoji_surrogate_pair_never_split() {
        // The classic family ZWJ cluster must never be split across lines.
        let wrapped = wrap_graphemes("x👨‍👩‍👧x", 2);
        // Round-trips losslessly…
        assert_eq!(wrapped.concat(), "x👨‍👩‍👧x");
        // …and the full cluster appears unbroken in exactly one line.
        assert!(wrapped.iter().any(|l| l.contains("👨‍👩‍👧")));
        // No line is a partial prefix of the cluster (e.g. just "👨").
        for line in &wrapped {
            for member in ["👨", "👩", "👧"] {
                assert!(
                    !line.contains(member) || line.contains("👨‍👩‍👧"),
                    "line {line:?} splits the family cluster"
                );
            }
        }
    }

    fn all_test_strings() -> Vec<String> {
        vec![
            String::new(),
            "a".into(),
            "abc def ghi".into(),
            "Hello 👋 World ✨".into(),
            "Family 👨‍👩‍👧 trip 🏳️‍🌈 to 🇯🇵".into(),
            "Math: ∑∞ 𝛼² + 𝛽² = 𝛾²".into(),
            "a\u{0301} e\u{0301} i\u{0301}".into(),
            "مرحبا עברית".into(),
            "Tabs:\tcol1\tcol2".into(),
            "Newline:\nline2".into(),
            "x".repeat(200),
        ]
    }
}
