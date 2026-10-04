//! The prototype's widgets (`comps`): every component renders from
//! scenario state + tick as a pure function — no widget owns time.
//!
//! Each returns styled [`Line`]s sized for the panel it's drawn in;
//! the panels compose these. Under reduced motion every animation
//! collapses to its end state (the caller passes the end tick).

use super::anim::{pulse, Anim, Curve};
use super::core::{glyphs, Token};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Map a token to a ratatui colour (true-colour tier).
pub fn colour(t: Token) -> Color {
    let (r, g, b) = t.rgb();
    Color::Rgb(r, g, b)
}

/// M05 — the thinking line: "waiting for {model}" with the star.
/// Replaced by the first token in the same row.
pub fn thinking_line(model: &str, star: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{star} "), Style::default().fg(colour(Token::Cyan))),
        Span::styled(
            format!("waiting for {model}"),
            Style::default().fg(colour(Token::Muted)),
        ),
    ])
}

/// M06 — fresh ink: a chunk lands near white and fades to ink in
/// 450 ms, ease-out. Returns the style for a delta that arrived at
/// `arrived_ms`.
pub fn fresh_ink_style(now_ms: u64, arrived_ms: u64, reduced: bool) -> Style {
    if reduced {
        return Style::default().fg(colour(Token::Ink));
    }
    let a = Anim::new(arrived_ms, 450, Curve::EaseOut);
    let p = a.progress(now_ms); // 0 → 1
                                // lerp white(0xEE) → ink(0xEE)… actually bright → ink: near-white
                                // (0xFF-ish) to ink (0xEE,0xEA,0xF5) is subtle; the design means
                                // bright white → normal ink, i.e. bold-white → ink. Use the ink
                                // channel lerp from white.
    let (ir, ig, ib) = Token::Ink.rgb();
    let (r, g, b) = (lerp(0xFF, ir, p), lerp(0xFF, ig, p), lerp(0xFF, ib, p));
    Style::default().fg(Color::Rgb(r, g, b))
}

/// The caret `▍`: follows the ink, breathes at 0.9 Hz after 400 ms
/// without data.
pub fn caret(now_ms: u64, last_data_ms: u64, reduced: bool) -> Span<'static> {
    if reduced || now_ms.saturating_sub(last_data_ms) < 400 {
        return Span::styled("▍", Style::default().fg(colour(Token::Cyan)));
    }
    let bright = pulse(now_ms, 0.9) > 0.5;
    Span::styled(
        "▍",
        Style::default().fg(colour(if bright { Token::Ink } else { Token::Muted })),
    )
}

/// M07 — a tool line enters: target types in at 240 cps; the kind
/// chip flashes for 250 ms. `typed` returns the visible prefix.
pub fn tool_line(
    kind: &str,
    target: &str,
    started_ms: u64,
    now_ms: u64,
    reduced: bool,
) -> Line<'static> {
    let visible_target = if reduced {
        target.to_string()
    } else {
        typed_prefix(target, started_ms, now_ms)
    };
    let chip_flash = !reduced && now_ms.saturating_sub(started_ms) < 250;
    let chip_style = if chip_flash {
        Style::default()
            .fg(colour(Token::Ink))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(colour(Token::Cyan))
    };
    Line::from(vec![
        Span::styled(format!("{kind} "), chip_style),
        Span::styled(visible_target, Style::default().fg(colour(Token::Ink))),
    ])
}

/// 240 characters per second since `started_ms`.
pub fn typed_prefix(s: &str, started_ms: u64, now_ms: u64) -> String {
    let elapsed = now_ms.saturating_sub(started_ms);
    let n = ((elapsed as f64 / 1000.0) * 240.0) as usize;
    if n == 0 {
        return String::new();
    }
    s.chars().take(n).collect()
}

/// M08 — the comet: a tool is running. One pass per 1.3 s over the
/// track row; bright head, 10-cell tail. Returns the comet's column
/// (None while between passes is wrong — the pass is continuous; the
/// comet wraps).
pub fn comet_column(now_ms: u64, track_width: u16, reduced: bool) -> Option<u16> {
    if reduced || track_width == 0 {
        return None;
    }
    let period = 1300.0;
    let phase = (now_ms as f64 % period) / period;
    Some((phase * track_width as f64) as u16)
}

/// Draw the comet row: `track_width` cells, head bright cyan, tail
/// fading behind.
pub fn comet_row(now_ms: u64, track_width: u16, reduced: bool) -> Line<'static> {
    let Some(head) = comet_column(now_ms, track_width, reduced) else {
        return Line::from(Span::styled(
            "─".repeat(track_width as usize),
            Style::default().fg(colour(Token::Rule)),
        ));
    };
    let mut spans = Vec::new();
    let mut col: u16 = 0;
    while col < track_width {
        let dist = head.abs_diff(col);
        let (ch, st) = if dist == 0 {
            (
                "●",
                Style::default()
                    .fg(colour(Token::Cyan))
                    .add_modifier(Modifier::BOLD),
            )
        } else if dist <= 10 {
            // tail fades: 10 cells behind the head
            let fade = 1.0 - dist as f64 / 10.0;
            let (r, g, b) = Token::Cyan.rgb();
            let dim = Style::default().fg(Color::Rgb(
                (r as f64 * fade) as u8,
                (g as f64 * fade) as u8,
                (b as f64 * fade) as u8,
            ));
            ("·", dim)
        } else {
            ("─", Style::default().fg(colour(Token::Rule)))
        };
        spans.push(Span::styled(ch.to_string(), st));
        col += 1;
    }
    Line::from(spans)
}

/// M10 — settle: `✓` white → green in 250 ms; the stripe settles
/// cyan → green/red in 300 ms.
pub fn settle_glyph(now_ms: u64, finished_ms: u64, ok: bool, reduced: bool) -> Span<'static> {
    let g = if ok { glyphs::DONE } else { glyphs::FAILED };
    if reduced {
        let t = if ok { Token::Green } else { Token::Red };
        return Span::styled(g, Style::default().fg(colour(t)));
    }
    let a = Anim::new(finished_ms, 250, Curve::EaseOut);
    let p = a.progress(now_ms);
    let (wr, wg, wb) = (0xFFu8, 0xFFu8, 0xFFu8);
    let (er, eg, eb) = if ok {
        Token::Green.rgb()
    } else {
        Token::Red.rgb()
    };
    Span::styled(
        g,
        Style::default().fg(Color::Rgb(
            lerp(wr, er, p),
            lerp(wg, eg, p),
            lerp(wb, eb, p),
        )),
    )
}

/// M13 — the approval card rises from the composer in 200 ms; border
/// and badge breathe at 1 Hz for 3 s, then hold. The rise is the
/// caller's layout concern (a rect lerp); this returns the badge.
pub fn approval_badge(now_ms: u64, requested_ms: u64, reduced: bool) -> Span<'static> {
    let age = now_ms.saturating_sub(requested_ms);
    let breathing = !reduced && age < 3000;
    let bright = !breathing || pulse(now_ms, 1.0) > 0.5;
    let t = if bright { Token::Magenta } else { Token::Muted };
    Span::styled(
        format!("{} needs you", glyphs::NEEDS_YOU),
        Style::default().fg(colour(t)).add_modifier(Modifier::BOLD),
    )
}

/// M18 — the context meter: eases in 300 ms; compaction drains it
/// over 1.2 s while amber.
pub fn context_meter(
    used: u64,
    window: u64,
    now_ms: u64,
    shown_ms: u64,
    compacting: bool,
    reduced: bool,
    width: u16,
) -> Line<'static> {
    let a = Anim::new(shown_ms, 300, Curve::EaseOut);
    let p = if reduced { 1.0 } else { a.progress(now_ms) };
    let frac = if window == 0 {
        0.0
    } else {
        (used as f64 / window as f64).min(1.0) * p
    };
    let full = (frac * width as f64).round() as u16;
    let token = if compacting {
        Token::Amber
    } else {
        Token::Blue
    };
    Line::from(vec![
        Span::styled(
            glyphs::BAR_FULL.repeat(full as usize),
            Style::default().fg(colour(token)),
        ),
        Span::styled(
            glyphs::BAR_EMPTY.repeat((width - full) as usize),
            Style::default().fg(colour(Token::Rule)),
        ),
        Span::styled(
            format!(" {used}"),
            Style::default().fg(colour(Token::Muted)),
        ),
    ])
}

/// M15 — agent arcs `◜◝◞◟` at 10 fps in the agent's colour.
pub fn agent_arc(now_ms: u64, agent_running: bool, reduced: bool) -> Span<'static> {
    if !agent_running || reduced {
        return Span::styled("●", Style::default().fg(colour(Token::Cyan)));
    }
    let frame = ((now_ms / 100) % 4) as usize;
    Span::styled(
        glyphs::AGENT_ARCS[frame],
        Style::default().fg(colour(Token::Cyan)),
    )
}

/// M24 — a toast: slides in 160 ms, stays 4 s with a draining line,
/// slides out 160 ms.
pub fn toast(text: &str, now_ms: u64, shown_ms: u64, width: u16) -> Line<'static> {
    let age = now_ms.saturating_sub(shown_ms);
    // drain: full → empty over 4 s
    let drain = (1.0 - (age as f64 / 4000.0).min(1.0)) * width as f64;
    let full = drain.round() as u16;
    Line::from(vec![
        Span::styled(text.to_string(), Style::default().fg(colour(Token::Ink))),
        Span::styled(" ", Style::default()),
        Span::styled(
            glyphs::BAR_FULL.repeat(full as usize),
            Style::default().fg(colour(Token::Muted)),
        ),
    ])
}

fn lerp(a: u8, b: u8, t: f64) -> u8 {
    (a as f64 + (b as f64 - a as f64) * t).round() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_prefix_is_240_cps() {
        // 240 cps = 4 chars per ~16.7 ms; at 250 ms ≈ 60 chars
        let s: String = "x".repeat(200);
        assert_eq!(typed_prefix(&s, 0, 0).len(), 0);
        assert_eq!(typed_prefix(&s, 0, 250).len(), 60);
        assert_eq!(typed_prefix(&s, 0, 60_000).len(), 200, "clamped");
    }

    #[test]
    fn fresh_ink_fades_white_to_ink() {
        let start = fresh_ink_style(0, 0, false);
        let end = fresh_ink_style(1000, 0, false);
        assert_ne!(start, end);
        // reduced: steady ink
        assert_eq!(fresh_ink_style(0, 0, true), fresh_ink_style(1000, 0, true));
    }

    #[test]
    fn comet_wraps_the_track() {
        // the head advances with time and wraps at the period
        let a = comet_column(0, 40, false).unwrap();
        let b = comet_column(650, 40, false).unwrap();
        let c = comet_column(1300, 40, false).unwrap();
        assert_eq!(a, 0);
        assert!(b > 15, "mid-pass: {b}");
        assert_eq!(c, 0, "wraps every 1300 ms");
        assert_eq!(comet_column(0, 40, true), None, "reduced: still track");
    }

    #[test]
    fn meter_eases_in_and_compaction_is_amber() {
        let l0 = context_meter(500, 1000, 0, 0, false, false, 10);
        let l1 = context_meter(500, 1000, 1000, 0, false, false, 10);
        let text0 = line_text(&l0);
        let text1 = line_text(&l1);
        assert!(text1.matches(glyphs::BAR_FULL).count() > text0.matches(glyphs::BAR_FULL).count());
        // full at rest
        let full = context_meter(500, 1000, 10_000, 0, false, false, 10);
        assert_eq!(line_text(&full).matches(glyphs::BAR_FULL).count(), 5);
        // compacting → amber token (colour differs from blue)
        let c = context_meter(500, 1000, 10_000, 0, true, false, 10);
        assert_ne!(full, c);
    }

    #[test]
    fn agent_arc_cycles_at_10fps() {
        assert_eq!(agent_arc(0, true, false).content, "◜");
        assert_eq!(agent_arc(100, true, false).content, "◝");
        assert_eq!(agent_arc(300, true, false).content, "◟");
        assert_eq!(agent_arc(400, true, false).content, "◜", "wraps at 400 ms");
        // still when not running or reduced
        assert_eq!(agent_arc(0, false, false).content, "●");
        assert_eq!(agent_arc(0, true, true).content, "●");
    }

    fn line_text(l: &Line) -> String {
        l.spans.iter().map(|s| s.content.as_ref()).collect()
    }
}
