//! Panel chrome: the frame (thin `╭─╮` or heavy `┏━┓` when focused), the
//! tinted header band with its number chip, state badges, pills and key
//! hints — ported from the prototype's `panelFrame`.

use super::canvas::{clip_text, mix, segs_width, text_width, tint, Cv, Rgb, Seg};
use super::pal::*;
use ratatui::layout::Rect;
use ratatui::style::Modifier;

/// The four status-star frames (`◐ ◓ ◑ ◒`), 4 fps while working.
pub fn star_frame(now_ms: u64, reduced: bool) -> &'static str {
    if reduced {
        return "✦";
    }
    ["◐", "◓", "◑", "◒"][((now_ms / 250) % 4) as usize]
}

/// A state a badge can show (the prototype's STATE table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeState {
    Working,
    Running,
    Needs,
    Done,
    Idle,
    Failed,
}

/// The badge's segments for `state` (glyph + word, optional extra).
pub fn badge(state: BadgeState, extra: Option<&str>, now_ms: u64, reduced: bool) -> Vec<Seg> {
    let (g, col, word): (String, Rgb, &str) = match state {
        BadgeState::Working => (star_frame(now_ms, reduced).into(), CYAN, "working"),
        BadgeState::Running => (star_frame(now_ms, reduced).into(), CYAN, "running"),
        BadgeState::Needs => ("◆".into(), MAGENTA, "needs you"),
        BadgeState::Done => ("✓".into(), GREEN, "done"),
        BadgeState::Idle => ("○".into(), MUTED, "idle"),
        BadgeState::Failed => ("✕".into(), RED, "failed"),
    };
    let strong = matches!(state, BadgeState::Needs | BadgeState::Failed);
    let mut parts = vec![
        Seg::bold(format!("{g} "), col),
        Seg {
            text: word.into(),
            fg: col,
            bold: strong,
        },
    ];
    if let Some(e) = extra {
        parts.push(Seg::new(
            format!(" · {e}"),
            if state == BadgeState::Needs {
                col
            } else {
                MUTED
            },
        ));
    }
    parts
}

/// A tinted pill: ` parts ` on `tint(col, base, amt)`. Returns next x.
pub fn pill(cv: &mut Cv, x: i32, y: i32, parts: &[Seg], col: Rgb, base: Rgb, amt: f32) -> i32 {
    let bg = tint(col, base, amt);
    let x = cv.text(x, y, " ", col, Some(bg));
    let x = cv.spans(x, y, parts, Some(bg));
    cv.text(x, y, " ", col, Some(bg))
}

pub fn pill_width(parts: &[Seg]) -> i32 {
    segs_width(parts) + 2
}

/// A keycap (` k `), hot = the accent one.
pub fn keycap(cv: &mut Cv, x: i32, y: i32, k: &str, hot: bool) -> i32 {
    let (fg, bg) = if hot {
        (ON_ACCENT, MAGENTA)
    } else {
        (INK, RULE_HI)
    };
    cv.put(x, y, &format!(" {k} "), fg, Some(bg), Modifier::BOLD)
}

/// Key hints: `key label   key label …`. Returns next x.
pub fn keyhints(cv: &mut Cv, x: i32, y: i32, pairs: &[(&str, &str)], bg: Option<Rgb>) -> i32 {
    let mut x = x;
    for (i, (k, l)) in pairs.iter().enumerate() {
        if i > 0 {
            x += 3;
        }
        x = cv.put(x, y, k, INK2, bg, Modifier::BOLD);
        x = cv.text(x + 1, y, l, FAINT, bg);
    }
    x
}

pub fn hints_width(pairs: &[(&str, &str)]) -> i32 {
    pairs
        .iter()
        .enumerate()
        .map(|(i, (k, l))| (if i > 0 { 3 } else { 0 }) + text_width(k) + 1 + text_width(l))
        .sum()
}

/// The leading hints that fit in `w` cells.
pub fn fit_hints<'a>(pairs: &[(&'a str, &'a str)], w: i32) -> Vec<(&'a str, &'a str)> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    for p in pairs {
        let mut t = out.clone();
        t.push(*p);
        if hints_width(&t) > w {
            break;
        }
        out.push(*p);
    }
    out
}

/// The focus sweep (M20): how much of the border is heavy, and the old
/// focus's border fading back to thin.
#[derive(Debug, Clone, Copy)]
pub struct FocusFx {
    /// 0..=1 heavy coverage, growing from the number chip both ways.
    pub sweep: f32,
    /// The fade (0..=1) of a border that just lost focus.
    pub fade: Option<f32>,
}

impl FocusFx {
    /// Settled: fully focused or not at all.
    pub fn settled(focused: bool) -> Self {
        FocusFx {
            sweep: if focused { 1.0 } else { 0.0 },
            fade: None,
        }
    }
}

/// What a panel frame needs.
pub struct FrameSpec<'a> {
    pub num: usize,
    pub title: &'a str,
    pub ident: Rgb,
    pub focused: bool,
    pub focus_fx: FocusFx,
    pub badge: Option<Vec<Seg>>,
    /// 0..=1: how hard the header band calls for attention.
    pub attention: f32,
    pub footer: Vec<(&'a str, &'a str)>,
    pub footer_parts: Vec<Seg>,
}

/// Draw a panel frame into `r`; returns the content rect (inside the
/// border, below the header band), or `None` when too small.
pub fn panel_frame(cv: &mut Cv, r: Rect, spec: &FrameSpec) -> Option<Rect> {
    let (x, y, w, h) = (r.x as i32, r.y as i32, r.width as i32, r.height as i32);
    if w < 4 || h < 3 {
        return None;
    }
    cv.fill(x, y, w, h, PANEL);
    // The border runs around the perimeter; the heavy part grows from
    // the number chip (index 3) both ways as `sweep` rises.
    let mut per: Vec<(i32, i32, &str)> = Vec::new();
    for i in 0..w {
        per.push((
            x + i,
            y,
            if i == 0 {
                "tl"
            } else if i == w - 1 {
                "tr"
            } else {
                "h"
            },
        ));
    }
    for j in 1..h - 1 {
        per.push((x + w - 1, y + j, "v"));
    }
    for i in (0..w).rev() {
        per.push((
            x + i,
            y + h - 1,
            if i == 0 {
                "bl"
            } else if i == w - 1 {
                "br"
            } else {
                "h"
            },
        ));
    }
    for j in (1..h - 1).rev() {
        per.push((x, y + j, "v"));
    }
    let n = per.len() as i32;
    let reach = spec.focus_fx.sweep * n as f32 / 2.0;
    for (i, (px, py, kind)) in per.iter().enumerate() {
        let i = i as i32;
        let d = (i - 3).abs().min(n - (i - 3).abs());
        let heavy = spec.focus_fx.sweep > 0.0 && d as f32 <= reach;
        let col = if heavy {
            spec.ident
        } else if let Some(f) = spec.focus_fx.fade {
            mix(spec.ident, RULE, f)
        } else {
            RULE
        };
        let g = match (*kind, heavy) {
            ("tl", true) => "┏",
            ("tr", true) => "┓",
            ("bl", true) => "┗",
            ("br", true) => "┛",
            ("h", true) => "━",
            ("v", true) => "┃",
            ("tl", false) => "╭",
            ("tr", false) => "╮",
            ("bl", false) => "╰",
            ("br", false) => "╯",
            ("h", false) => "─",
            _ => "│",
        };
        cv.text(*px, *py, g, col, Some(PANEL));
    }
    // Header band.
    let band = tint(
        spec.ident,
        PANEL,
        0.09 + 0.11 * if spec.focused { 1.0 } else { 0.0 },
    );
    cv.fill(x + 1, y + 1, w - 2, 1, band);
    let num = format!(" {} ", spec.num);
    let xx = if spec.focused {
        cv.put(
            x + 2,
            y + 1,
            &num,
            ON_ACCENT,
            Some(spec.ident),
            Modifier::BOLD,
        )
    } else {
        cv.put(
            x + 2,
            y + 1,
            &num,
            spec.ident,
            Some(tint(spec.ident, PANEL, 0.3)),
            Modifier::BOLD,
        )
    };
    // The badge gives up its trailing parts before it covers the title.
    let mut badge = spec.badge.clone();
    let max_b = w - 7 - (xx - x) - text_width(spec.title).min(10);
    while let Some(b) = &badge {
        if b.len() > 1 && pill_width(b) > max_b {
            let mut t = b.clone();
            t.pop();
            badge = Some(t);
        } else {
            break;
        }
    }
    if let Some(b) = &badge {
        if pill_width(b) > max_b {
            badge = None;
        }
    }
    let bw = badge.as_ref().map(|b| pill_width(b)).unwrap_or(0);
    let room = w - 6 - (xx - x) - bw;
    cv.put(
        xx + 1,
        y + 1,
        &clip_text(spec.title, room.max(1)),
        if spec.focused { INK } else { INK2 },
        Some(band),
        Modifier::BOLD,
    );
    if let Some(b) = &badge {
        let lead = b.first().map(|s| s.fg).unwrap_or(MUTED);
        pill(
            cv,
            x + w - 2 - bw,
            y + 1,
            b,
            lead,
            PANEL,
            0.16 + 0.22 * spec.attention,
        );
    }
    // Footer: key hints (or free parts) over the bottom border.
    if !spec.footer.is_empty() {
        let fh = fit_hints(&spec.footer, w - 6);
        if !fh.is_empty() {
            cv.fill(x + 2, y + h - 1, hints_width(&fh) + 2, 1, PANEL);
            keyhints(cv, x + 3, y + h - 1, &fh, Some(PANEL));
        }
    }
    if !spec.footer_parts.is_empty() {
        let mut parts = spec.footer_parts.clone();
        while parts.len() > 1 && segs_width(&parts) > w - 6 {
            parts.pop();
        }
        if segs_width(&parts) <= w - 6 {
            cv.fill(x + 2, y + h - 1, segs_width(&parts) + 2, 1, PANEL);
            cv.spans(x + 3, y + h - 1, &parts, Some(PANEL));
        }
    }
    let _ = mix; // palette helpers re-exported for siblings
    Some(Rect {
        x: (x + 2) as u16,
        y: (y + 2) as u16,
        width: (w - 4) as u16,
        height: (h - 3) as u16,
    })
}

/// An empty-state block: glyph + title + wrapped body.
pub fn empty_state(cv: &mut Cv, inner: Rect, glyph: &str, col: Rgb, title: &str, body: &str) {
    let (x, y, w) = (inner.x as i32, inner.y as i32, inner.width as i32);
    cv.bold(x + 1, y + 1, glyph, col, None);
    cv.bold(x + 3, y + 1, title, INK2, None);
    for (i, (a, b)) in super::canvas::wrap_ranges(body, w - 4)
        .into_iter()
        .enumerate()
    {
        let line: String = body.chars().skip(a).take(b - a).collect();
        cv.text(x + 3, y + 3 + i as i32, &line, MUTED, None);
    }
}
