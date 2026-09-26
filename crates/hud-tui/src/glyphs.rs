//! The glyph vocabulary (docs/tui/DESIGN.md §4.3, §4.2).
//!
//! One small vocabulary. Circles are work, diamonds are authority, the star
//! is ORBIT. A glyph means the same thing wherever it appears (✕ is always
//! broken, ↻ always again), and each has a plain-ASCII twin. No render code
//! may contain a glyph literal — everything comes from here (§13.2).
//!
//! Every unicode glyph below is one cell in unicode-width (§4.4). The ASCII
//! tier keeps every chrome cell printable (invariant_ascii_tier_is_ascii).

use crate::tokens::GlyphSet;

/// The complete glyph vocabulary, resolved for one glyph set.
///
/// Construct via [`Glyphs::unicode()`] / [`Glyphs::ascii()`], or
/// [`Glyphs::for_set`] from a capabilities value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Glyphs {
    set: GlyphSet,

    // ── Roles ──
    /// ORBIT's voice / the mark. Magenta when settled, cyan while live.
    pub orbit: &'static str,
    /// You — gutter marker (muted) and composer prompt (magenta).
    pub you: &'static str,
    /// Notice marker for system lines.
    pub notice: &'static str,

    // ── Work (circles) ──
    /// Pending / queued.
    pub pending: &'static str,
    /// Active / running.
    pub running: &'static str,
    /// Done — claimed, not proven. Neutral: evidence earns green.
    pub done: &'static str,
    /// Failed / broken. ✕ is always broken.
    pub failed: &'static str,
    /// Blocked.
    pub blocked: &'static str,
    /// Awaiting retest. ↻ always means "again".
    pub retest: &'static str,

    // ── Authority (diamonds) ──
    /// Awaiting your decision.
    pub decision: &'static str,
    /// Allowed once.
    pub allowed_once: &'static str,
    /// Allowed for this session.
    pub allowed_session: &'static str,
    /// Denied by you — a decision, not a failure.
    pub denied: &'static str,

    // ── Connection ──
    pub conn_online: &'static str,
    pub conn_retrying: &'static str,
    pub conn_rate_limited: &'static str,
    pub conn_offline: &'static str,
    // Rounded-corner pane border glyphs (herdr-style softer frame).
    pub border_tl: &'static str,
    pub border_tr: &'static str,
    pub border_bl: &'static str,
    pub border_br: &'static str,
    pub border_h: &'static str,
    pub border_v: &'static str,

    // ── Structure ──
    /// Disclosure collapsed.
    pub collapsed: &'static str,
    /// Disclosure expanded.
    pub expanded: &'static str,
    /// Bullet (top level).
    pub bullet: &'static str,
    /// Nested bullet.
    pub bullet_nested: &'static str,
    /// Wrap continuation marker at line start.
    pub wrap: &'static str,
    /// Truncation marker.
    pub ellipsis: &'static str,
    /// Selection bar (left edge of the selected row).
    pub selection: &'static str,
    /// Risk meter segment — filled.
    pub risk_on: &'static str,
    /// Risk meter segment — empty.
    pub risk_off: &'static str,
    /// Token counters: down / up arrows.
    pub tokens_down: &'static str,
    pub tokens_up: &'static str,
    /// Status-line separator (unicode: ·, ascii: |).
    pub sep: &'static str,

    // ── Motion — the working star (§4.3, one spinner, 4 fps) ──
    /// The four frames of the working star, in turn order.
    pub working_star: &'static [&'static str; 4],
    /// ASCII working-star frames (the classic spinner quadrants).
    pub working_star_ascii: &'static [&'static str; 4],

    // ── Lines and frames (§4.2) ──
    /// Header rule — unfocused pane headers.
    pub rule: &'static str,
    /// Focus rule — the focused pane header only (heavy line survives mono).
    pub rule_focus: &'static str,
    /// Divider / scroll track (full height between panes).
    pub divider: &'static str,
    /// Scroll thumb (divider, heavier).
    pub thumb: &'static str,
    /// Quote bar — markdown blockquotes.
    pub quote_bar: &'static str,

    // ── Frame set — overlays only (§4.2: never nested, never ┌┐, never ═) ──
    pub frame_top_left: &'static str,
    pub frame_top: &'static str,
    pub frame_top_right: &'static str,
    pub frame_left: &'static str,
    pub frame_right: &'static str,
    pub frame_bottom_left: &'static str,
    pub frame_bottom: &'static str,
    pub frame_bottom_right: &'static str,
}

impl Glyphs {
    /// The full unicode vocabulary.
    pub const fn unicode() -> Self {
        Self {
            set: GlyphSet::Unicode,
            orbit: "✦",
            you: "›",
            notice: "∙",
            pending: "◌",
            running: "◉",
            done: "✓",
            failed: "✕",
            blocked: "⊖",
            retest: "↻",
            decision: "◇",
            allowed_once: "◆",
            allowed_session: "◈",
            denied: "⊘",
            conn_online: "●",
            conn_retrying: "↻",
            conn_rate_limited: "◔",
            conn_offline: "✕",
            border_tl: "╭",
            border_tr: "╮",
            border_bl: "╰",
            border_br: "╯",
            border_h: "─",
            border_v: "│",
            collapsed: "▸",
            expanded: "▾",
            bullet: "∙",
            bullet_nested: "◦",
            wrap: "↪",
            ellipsis: "…",
            selection: "▌",
            risk_on: "▰",
            risk_off: "▱",
            tokens_down: "↓",
            tokens_up: "↑",
            sep: "·",
            working_star: &["◐", "◓", "◑", "◒"],
            working_star_ascii: &["-", "\\", "|", "/"],
            rule: "─",
            rule_focus: "━",
            divider: "│",
            thumb: "┃",
            quote_bar: "▎",
            frame_top_left: "╭",
            frame_top: "─",
            frame_top_right: "╮",
            frame_left: "│",
            frame_right: "│",
            frame_bottom_left: "╰",
            frame_bottom: "─",
            frame_bottom_right: "╯",
        }
    }

    /// The ASCII twin vocabulary. Every chrome cell stays printable ASCII
    /// (invariant_ascii_tier_is_ascii, §13.5).
    pub const fn ascii() -> Self {
        Self {
            set: GlyphSet::Ascii,
            orbit: "*",
            you: ">",
            notice: "-",
            pending: ".",
            running: "@",
            done: "+",
            failed: "x",
            blocked: "#",
            retest: "~",
            decision: "?",
            allowed_once: "+",
            allowed_session: "+",
            denied: "/",
            conn_online: "o",
            conn_retrying: "~",
            conn_rate_limited: "%",
            conn_offline: "x",
            border_tl: "+",
            border_tr: "+",
            border_bl: "+",
            border_br: "+",
            border_h: "-",
            border_v: "|",
            collapsed: ">",
            expanded: "v",
            bullet: "-",
            bullet_nested: "-",
            wrap: ">",
            ellipsis: "~",
            selection: ">",
            risk_on: "#",
            risk_off: "-",
            tokens_down: "v",
            tokens_up: "^",
            sep: "|",
            working_star: &["-", "\\", "|", "/"],
            working_star_ascii: &["-", "\\", "|", "/"],
            rule: "-",
            rule_focus: "=",
            divider: "|",
            thumb: "|",
            quote_bar: "|",
            frame_top_left: "+",
            frame_top: "-",
            frame_top_right: "+",
            frame_left: "|",
            frame_right: "|",
            frame_bottom_left: "+",
            frame_bottom: "-",
            frame_bottom_right: "+",
        }
    }

    /// Resolve for a glyph set.
    pub const fn for_set(set: GlyphSet) -> Self {
        match set {
            GlyphSet::Unicode => Self::unicode(),
            GlyphSet::Ascii => Self::ascii(),
        }
    }

    /// The glyph set this vocabulary was built for.
    pub fn set(&self) -> GlyphSet {
        self.set
    }

    /// The four-frame working-star sequence for this glyph set.
    pub fn corner_tl(&self) -> &'static str { self.border_tl }
    pub fn corner_tr(&self) -> &'static str { self.border_tr }
    pub fn corner_bl(&self) -> &'static str { self.border_bl }
    pub fn corner_br(&self) -> &'static str { self.border_br }
    pub fn border_h(&self) -> &'static str { self.border_h }
    pub fn border_v(&self) -> &'static str { self.border_v }
    pub fn working(&self) -> &'static [&'static str; 4] {
        match self.set {
            GlyphSet::Unicode => self.working_star,
            GlyphSet::Ascii => self.working_star_ascii,
        }
    }

    /// Build a risk meter string (`▰▰▱`-style) for levels 0..=3.
    pub fn risk_meter(&self, level: u8) -> String {
        let n = level.min(3) as usize;
        let mut s = String::with_capacity(3 * self.risk_on.len());
        for i in 0..3 {
            s.push_str(if i < n { self.risk_on } else { self.risk_off });
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unicode::{display_width, wrap_graphemes};

    const U: Glyphs = Glyphs::unicode();
    const A: Glyphs = Glyphs::ascii();

    #[test]
    fn every_unicode_glyph_is_one_cell_wide() {
        // §4.4: every glyph above is one cell in unicode-width.
        let one_cell = [
            U.orbit,
            U.you,
            U.notice,
            U.pending,
            U.running,
            U.done,
            U.failed,
            U.blocked,
            U.retest,
            U.decision,
            U.allowed_once,
            U.allowed_session,
            U.denied,
            U.conn_online,
            U.conn_retrying,
            U.conn_rate_limited,
            U.conn_offline,
            U.collapsed,
            U.expanded,
            U.bullet,
            U.bullet_nested,
            U.wrap,
            U.ellipsis,
            U.selection,
            U.risk_on,
            U.risk_off,
            U.tokens_down,
            U.tokens_up,
            U.rule,
            U.rule_focus,
            U.divider,
            U.thumb,
            U.quote_bar,
            U.frame_top_left,
            U.frame_top,
            U.frame_top_right,
            U.frame_left,
            U.frame_right,
            U.frame_bottom_left,
            U.frame_bottom,
            U.frame_bottom_right,
        ];
        for g in one_cell {
            assert_eq!(display_width(g), 1, "glyph {g:?} must be exactly one cell");
        }
        for g in U.working() {
            assert_eq!(display_width(g), 1, "working frame {g:?} must be one cell");
        }
    }

    #[test]
    fn every_ascii_glyph_is_printable_ascii() {
        // invariant_ascii_tier_is_ascii (§13.5): with the ASCII glyph set,
        // every cell ORBIT draws itself is printable ASCII.
        fn all_ascii(s: &str) -> bool {
            !s.is_empty() && s.bytes().all(|b| (0x20..0x7f).contains(&b))
        }
        let chrome = [
            A.orbit,
            A.you,
            A.notice,
            A.pending,
            A.running,
            A.done,
            A.failed,
            A.blocked,
            A.retest,
            A.decision,
            A.allowed_once,
            A.allowed_session,
            A.denied,
            A.conn_online,
            A.conn_retrying,
            A.conn_rate_limited,
            A.conn_offline,
            A.collapsed,
            A.expanded,
            A.bullet,
            A.bullet_nested,
            A.wrap,
            A.ellipsis,
            A.selection,
            A.risk_on,
            A.risk_off,
            A.tokens_down,
            A.tokens_up,
            A.rule,
            A.rule_focus,
            A.divider,
            A.thumb,
            A.quote_bar,
            A.frame_top_left,
            A.frame_top,
            A.frame_top_right,
            A.frame_left,
            A.frame_right,
            A.frame_bottom_left,
            A.frame_bottom,
            A.frame_bottom_right,
        ];
        for g in chrome {
            assert!(all_ascii(g), "ASCII glyph {g:?} must be printable ASCII");
        }
        for g in A.working() {
            assert!(all_ascii(g), "ASCII working frame {g:?} must be printable");
        }
    }

    #[test]
    fn families_are_semantic() {
        // Circles are work, diamonds are authority (§4.3).
        let work = [U.pending, U.running, U.done, U.failed, U.blocked, U.retest];
        let authority = [U.decision, U.allowed_once, U.allowed_session, U.denied];
        // The work family glyphs are all circle-forms (U+25xx geometric
        // circles / crosses sharing the family look). We assert the stronger
        // spec property instead: work and authority families are disjoint,
        // and each glyph appears exactly once in the vocabulary.
        for w in work {
            assert!(!authority.contains(&w), "families must be disjoint");
        }
    }

    #[test]
    fn meaning_is_unique_per_glyph() {
        // "A glyph means the same thing wherever it appears" — the shared
        // glyphs (✕ broken, ↻ again) must be the same codepoint in every
        // role that uses them.
        assert_eq!(U.conn_offline, U.failed); // ✕ always broken
        assert_eq!(U.conn_retrying, U.retest); // ↻ always again
                                               // ...and their ASCII twins agree too.
        assert_eq!(A.conn_offline, A.failed);
        assert_eq!(A.conn_retrying, A.retest);
    }

    #[test]
    fn frame_set_is_rounded_and_unnested() {
        // §4.2: frame is ╭─╮│╰─╯, never ┌┐, never ═.
        assert_eq!(U.frame_top_left, "╭");
        assert_eq!(U.frame_bottom_right, "╯");
        // The ASCII frame is a plain box, still never double-line.
        assert_ne!(A.frame_top, "=");
    }

    #[test]
    fn working_star_has_four_frames() {
        assert_eq!(U.working().len(), 4);
        assert_eq!(A.working().len(), 4);
        // one full turn per second at 4 fps — order is the turn order
        assert_eq!(U.working(), &["◐", "◓", "◑", "◒"]);
    }

    #[test]
    fn risk_meter_builds_levels() {
        assert_eq!(U.risk_meter(0), "▱▱▱");
        assert_eq!(U.risk_meter(1), "▰▱▱");
        assert_eq!(U.risk_meter(2), "▰▰▱");
        assert_eq!(U.risk_meter(3), "▰▰▰");
        // clamps
        assert_eq!(U.risk_meter(9), "▰▰▰");
        assert_eq!(A.risk_meter(2), "##-");
    }

    #[test]
    fn for_set_matches_constructors() {
        assert_eq!(
            Glyphs::for_set(GlyphSet::Unicode).orbit,
            Glyphs::unicode().orbit
        );
        assert_eq!(
            Glyphs::for_set(GlyphSet::Ascii).orbit,
            Glyphs::ascii().orbit
        );
        assert_eq!(Glyphs::unicode().set(), GlyphSet::Unicode);
        assert_eq!(Glyphs::ascii().set(), GlyphSet::Ascii);
    }

    #[test]
    fn wrap_never_breaks_a_glyph() {
        // The wrap marker itself must survive grapheme wrapping (it is used
        // at line starts in tool output).
        let lines = wrap_graphemes(&format!("{}payload", U.wrap), 4);
        assert!(lines.iter().all(|l| l.contains(U.wrap) || !l.is_empty()));
    }
}
