//! The prototype's glyph and colour vocabulary (the `core` module).
//!
//! Colour means state or content; each panel has an identity colour.
//! Glyphs are the motion table's vocabulary.

/// The colour tokens (true-colour values; the tier mapper downshifts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    App,
    Panel,
    Raise,
    Inset,
    Rule,
    Ink,
    Muted,
    Magenta,
    Cyan,
    Green,
    Red,
    Amber,
    Violet,
    Blue,
    // §6.1's palette, exactly.
    /// `bg` — the canvas.
    Bg,
    /// `surface` — user-turn band, composer band, approval fill.
    Surface,
    /// `surface2` — chips, palette fill, unfocused cursor row.
    Surface2,
    /// `wash` — the focused cursor row.
    Wash,
    /// `rule_hi` — focused header rule, overlay frames.
    RuleHi,
    /// `ink2` — secondary text.
    Ink2,
    /// `faint` — placeholders, disabled items, session id.
    Faint,
    /// `magenta_hi` — the one-frame startup flash.
    MagentaHi,
    /// `magenta_dim` — the expanded mark's ring.
    MagentaDim,
}

impl Token {
    /// The true-colour value. Under 256/16 colours the tier mapper
    /// downshifts once; under NO_COLOR only glyphs remain.
    pub fn rgb(self) -> (u8, u8, u8) {
        match self {
            Self::App => (0x08, 0x07, 0x0C),
            Self::Panel => (0x10, 0x0E, 0x16),
            Self::Raise => (0x18, 0x15, 0x1F),
            Self::Inset => (0x0B, 0x0A, 0x10),
            Self::Rule => (0x2A, 0x25, 0x34),
            Self::Ink => (0xEE, 0xEA, 0xF5),
            Self::Muted => (0x8C, 0x85, 0x99),
            Self::Magenta => (0xE3, 0x56, 0xD0),
            Self::Cyan => (0x5C, 0xC6, 0xDD),
            Self::Green => (0x62, 0xCC, 0x8E),
            Self::Red => (0xF0, 0x6A, 0x5E),
            Self::Amber => (0xE9, 0xB2, 0x52),
            Self::Violet => (0xB3, 0x9D, 0xFF),
            Self::Blue => (0x7A, 0xA2, 0xF7),
            Self::Bg => (0x10, 0x0E, 0x16),
            Self::Surface => (0x17, 0x14, 0x1F),
            Self::Surface2 => (0x21, 0x1C, 0x2B),
            Self::Wash => (0x2B, 0x16, 0x31),
            Self::RuleHi => (0x46, 0x3F, 0x55),
            Self::Ink2 => (0xBD, 0xB6, 0xCA),
            Self::Faint => (0x65, 0x5F, 0x73),
            Self::MagentaHi => (0xF5, 0x8C, 0xE4),
            Self::MagentaDim => (0x8E, 0x3C, 0x7F),
        }
    }
}

/// The colour tier detected from the environment. Ordered: `TrueColor`
/// is the richest tier, `None` the poorest — comparisons read as
/// "richer than" (`tier <= T16` = colour effects must switch off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Tier {
    TrueColor,
    T256,
    T16,
    #[default]
    None,
}

impl Tier {
    /// Detect from the environment the way the prototype does:
    /// NO_COLOR wins, then COLORTERM, then TERM.
    pub fn detect(no_color: bool, colorterm: Option<&str>, term: Option<&str>) -> Self {
        if no_color {
            return Self::None;
        }
        if let Some(ct) = colorterm {
            if ct.contains("truecolor") || ct.contains("24bit") {
                return Self::TrueColor;
            }
        }
        match term {
            Some(t) if t.contains("256color") => Self::T256,
            Some(_) => Self::T16,
            None => Self::T16,
        }
    }
}

/// The motion-table glyphs.
pub mod glyphs {
    pub const STAR_STILL: &str = "✦";
    pub const NEEDS_YOU: &str = "◆";
    pub const DONE: &str = "✓";
    pub const FAILED: &str = "✕";
    pub const DENIED: &str = "⊘";
    pub const QUEUED: &str = "◌";
    /// Agent arcs, 10 fps in the agent's colour.
    pub const AGENT_ARCS: [&str; 4] = ["◜", "◝", "◞", "◟"];
    /// Meters and bars.
    pub const BAR_FULL: &str = "▰";
    pub const BAR_EMPTY: &str = "▱";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_detection() {
        assert_eq!(Tier::detect(true, Some("truecolor"), None), Tier::None);
        assert_eq!(
            Tier::detect(false, Some("truecolor"), Some("xterm")),
            Tier::TrueColor
        );
        assert_eq!(
            Tier::detect(false, None, Some("xterm-256color")),
            Tier::T256
        );
        assert_eq!(Tier::detect(false, None, Some("xterm")), Tier::T16);
    }

    #[test]
    fn tokens_have_distinct_colours() {
        let all = [
            Token::App,
            Token::Panel,
            Token::Raise,
            Token::Inset,
            Token::Rule,
            Token::Ink,
            Token::Muted,
            Token::Magenta,
            Token::Cyan,
            Token::Green,
            Token::Red,
            Token::Amber,
            Token::Violet,
            Token::Blue,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.rgb(), b.rgb(), "{a:?} and {b:?} must differ");
            }
        }
    }
}
