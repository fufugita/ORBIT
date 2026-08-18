//! Grapheme-aware text shaping (DR-21 L14/L15).
//!
//! All layout passes through here — no `chars()` for column math, no byte
//! slicing. `unicode-segmentation` provides grapheme cluster boundaries;
//! `unicode-width` provides display widths; emoji presentation is forced to
//! 2 cells (the EAW-Wide convention, DR-21 §5.1).

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

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

/// True for the Unicode 15.1 emoji + extended pictographic ranges.
/// VS-16 (U+FE0F) forces emoji presentation for an otherwise-text glyph.
pub fn is_emoji(c: char) -> bool {
    let cp = c as u32;
    (0x1F000..=0x1FFFF).contains(&cp) // Emoticons, Symbols, Pictographs, Transport
        || (0x2600..=0x26FF).contains(&cp) // Misc Symbols (☀-⛿)
        || (0x2700..=0x27BF).contains(&cp) // Dingbats
        || (0x1F1E6..=0x1F1FF).contains(&cp) // Regional Indicators
        || (0x1F900..=0x1F9FF).contains(&cp) // Supplemental Symbols and Pictographs
        || (0x1FA70..=0x1FAFF).contains(&cp) // Symbols and Pictographs Extended-A
        || cp == 0xFE0F // Variation Selector-16 (forces emoji presentation)
}

/// Wrap `s` to `max_width` cells, breaking on grapheme boundaries.
/// Never breaks inside a grapheme cluster (emoji ZWJ, skin tone, etc.),
/// and never splits a single grapheme wider than the target.
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

/// Word-wrap variant: prefer breaking on whitespace, fall back to grapheme
/// boundary when no whitespace fits.
pub fn wrap_words(s: &str, max_width: usize) -> Vec<String> {
    // Split into words (whitespace-separated runs + single whitespace chars).
    let mut out = Vec::new();
    let mut line = String::new();
    let mut line_width = 0usize;

    let mut words: Vec<&str> = Vec::new();
    for w in s.split_inclusive(char::is_whitespace) {
        words.push(w);
    }

    for word in words {
        let w = display_width(word);
        if line_width + w > max_width && !line.is_empty() && !word.trim().is_empty() {
            // Flush the current line only when the next word is non-space.
            out.push(std::mem::take(&mut line));
            line_width = 0;
        }
        // A single overlong token: hard-split on grapheme boundaries.
        if w > max_width {
            if !line.is_empty() {
                out.push(std::mem::take(&mut line));
                line_width = 0;
            }
            // Word itself with no internal spaces: wrap_graphemes handles it,
            // but preserve the trailing whitespace separately.
            for piece in wrap_graphemes(word.trim_end(), max_width) {
                out.push(piece);
            }
            let tail: String = word.chars().skip_while(|c| !c.is_whitespace()).collect();
            if !tail.is_empty() {
                line.push_str(&tail);
                line_width += display_width(&tail);
            }
            continue;
        }
        line.push_str(word);
        line_width += w;
        // If the line is now exactly full and the word ended in whitespace,
        // flush eagerly.
        if line_width >= max_width && word.ends_with(char::is_whitespace) {
            out.push(std::mem::take(&mut line));
            line_width = 0;
        }
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

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
