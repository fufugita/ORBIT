//! The top bar (row 0) and the status line (last row).

use super::canvas::{mix, segs_width, tint, Cv, Rgb, Seg};
use super::frame::{keyhints, pill, pill_width};
use super::motion::{ease_in_out, flash, prog, secs, shimmer, star_at};
use super::pal::*;
use crate::proto::scenario::{Activity, Scenario};
use ratatui::style::Modifier;

/// The layout tabs the top bar offers.
pub const PRESET_TABS: [&str; 4] = ["columns", "build", "agents", "review"];

/// The preset whose tab sits at column `x` in the top bar (tabs start at
/// column 12, each ` name ` plus one air column).
pub fn preset_at(x: i32) -> Option<crate::proto::layout::Preset> {
    use crate::proto::layout::Preset;
    let presets = [
        Preset::Columns,
        Preset::Build,
        Preset::Agents,
        Preset::Review,
    ];
    let mut cx = 12;
    for (name, p) in PRESET_TABS.iter().zip(presets) {
        let w = name.chars().count() as i32 + 2;
        if x >= cx && x < cx + w {
            return Some(p);
        }
        cx += w + 1;
    }
    None
}

/// The working directory as `~/…` when under home.
pub fn cwd_label() -> String {
    let Ok(cwd) = std::env::current_dir() else {
        return String::new();
    };
    let s = cwd.display().to_string();
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() && s.starts_with(&h) => format!("~{}", &s[h.len()..]),
        _ => s,
    }
}

/// The current git branch, read from `.git/HEAD` (cached).
pub fn branch_label() -> Option<String> {
    static BRANCH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    BRANCH
        .get_or_init(|| {
            let mut dir = std::env::current_dir().ok()?;
            loop {
                let head = dir.join(".git/HEAD");
                if let Ok(s) = std::fs::read_to_string(&head) {
                    let s = s.trim();
                    return Some(
                        s.strip_prefix("ref: refs/heads/")
                            .map(str::to_string)
                            .unwrap_or_else(|| s.chars().take(7).collect()),
                    );
                }
                if !dir.pop() {
                    return None;
                }
            }
        })
        .clone()
}

/// What the top bar shows.
pub struct TopBar<'a> {
    pub scenario: &'a Scenario,
    /// Index into [`PRESET_TABS`] (or `None` for "yours").
    pub preset: Option<usize>,
    pub approval_pending: bool,
    pub now_ms: u64,
    pub reduced: bool,
    /// Colour effects off (16 colours or less): the shimmer and the
    /// ledger flash switch off.
    pub mono: bool,
    /// When the layout last saved as "yours" (the ✓ saved note).
    pub saved_ms: Option<u64>,
    /// The focused panel is zoomed (`z`).
    pub zoom: bool,
    /// One-at-a-time mode: `(number, title, badge glyph)` per panel.
    pub switcher: Option<Vec<(usize, String, bool)>>,
    pub focus_idx: usize,
    pub cwd: String,
    pub branch: Option<String>,
}

pub fn top_bar(cv: &mut Cv, w: i32, tb: &TopBar) {
    // Gradient strip: deep violet fading into the bar colour.
    let strip = (w as f32 * 0.42).max(20.0);
    for x in 0..w {
        let t = (x as f32 / strip).min(1.0).powf(0.8);
        cv.fill(x, 0, 1, 1, mix(GRAD0, TOPBAR, t));
    }
    let bg_at = |x: i32| -> Rgb {
        let t = (x as f32 / strip).min(1.0).powf(0.8);
        mix(GRAD0, TOPBAR, t)
    };
    cv.bold(2, 0, "✦", MAGENTA_HI, Some(bg_at(2)));
    for (i, ch) in "ORBIT".chars().enumerate() {
        cv.bold(
            4 + i as i32,
            0,
            &ch.to_string(),
            brand_at(i as f32 / 4.0),
            Some(bg_at(4 + i as i32)),
        );
    }
    let mut x = 12;
    if let Some(panels) = &tb.switcher {
        for (num, title, attn) in panels {
            let on = *num - 1 == tb.focus_idx;
            if on {
                x = cv.put(
                    x,
                    0,
                    &format!(" {num} {title} "),
                    ON_ACCENT,
                    Some(MAGENTA),
                    Modifier::BOLD,
                );
                if *attn {
                    x = cv.put(x, 0, "◆ ", ON_ACCENT, Some(MAGENTA), Modifier::BOLD);
                }
            } else {
                x = cv.put(
                    x,
                    0,
                    &format!(" {num} "),
                    FAINT,
                    Some(bg_at(x)),
                    Modifier::BOLD,
                );
                x = cv.text(x, 0, &format!("{title} "), MUTED, Some(bg_at(x)));
                if *attn {
                    x = cv.put(x, 0, "◆ ", MAGENTA, Some(bg_at(x)), Modifier::BOLD);
                }
            }
            x += 1;
        }
    } else {
        for (i, name) in PRESET_TABS.iter().enumerate() {
            let label = format!(" {name} ");
            if tb.preset == Some(i) {
                let pb = tint(MAGENTA, TOPBAR, 1.0);
                x = cv.put(x, 0, &label, ON_ACCENT, Some(pb), Modifier::BOLD);
                if tb.approval_pending {
                    x = cv.put(x, 0, "◆ ", ON_ACCENT, Some(pb), Modifier::BOLD);
                }
            } else {
                x = cv.text(x, 0, &label, MUTED, Some(bg_at(x)));
            }
            x += 1;
        }
        if tb.preset.is_none() {
            x = cv.put(x, 0, " yours ", INK2, Some(bg_at(x)), Modifier::BOLD) + 1;
        }
        if tb.zoom {
            x = cv.put(x + 1, 0, " ZOOM ", ON_ACCENT, Some(AMBER), Modifier::BOLD);
        }
        // M30: `✓ saved` for 1.2 s, then it fades.
        if let Some(t) = tb.saved_ms {
            let age = secs(tb.now_ms.saturating_sub(t));
            if age < 1.8 {
                let a = if tb.reduced {
                    1.0
                } else {
                    1.0 - ((age - 1.2) / 0.6).clamp(0.0, 1.0)
                };
                cv.bold(
                    x + 1,
                    0,
                    "✓ saved",
                    mix(bg_at(x + 1), GREEN, a),
                    Some(bg_at(x + 1)),
                );
            }
        }
    }

    // Right: facts as pills; the least important drop first.
    let s = tb.scenario;
    let mut chips: Vec<(Vec<Seg>, Option<Rgb>, u8)> = Vec::new();
    if !tb.cwd.is_empty() {
        chips.push((vec![Seg::new(tb.cwd.clone(), INK2)], Some(INK2), 1));
    }
    if let Some(b) = &tb.branch {
        chips.push((
            vec![Seg::new("⎇ ", GREEN), Seg::bold(b.clone(), GREEN)],
            Some(GREEN),
            3,
        ));
    }
    if !s.model_id.is_empty() {
        chips.push((vec![Seg::bold(s.model_id.clone(), VIOLET)], Some(VIOLET), 2));
    }
    if s.window_tokens > 0 {
        // M18: the meter eases to the new fraction in 300 ms.
        let ctx = if tb.reduced {
            s.ctx_to
        } else {
            s.ctx_eased(tb.now_ms)
        };
        let k = (ctx * 10.0).round() as usize;
        let mut meter = vec![Seg::new("ctx ", FAINT)];
        for i in 0..10 {
            let col = if i < k {
                let u = i as f32 / 9.0;
                if u < 0.5 {
                    CYAN
                } else if u < 0.8 {
                    AMBER
                } else {
                    RED
                }
            } else {
                RULE_HI
            };
            meter.push(Seg::new(if i < k { "▰" } else { "▱" }, col));
        }
        meter.push(Seg::new(
            format!(" {}%", (ctx * 100.0).round() as u32),
            if ctx > 0.85 { AMBER } else { INK2 },
        ));
        chips.push((meter, None, 9));
    }
    if let Some(n) = s.ledger_count {
        chips.push((
            // M19: the dot flashes for 350 ms per record.
            vec![
                Seg::bold(
                    "● ",
                    mix(
                        GREEN,
                        WHITE,
                        flash(
                            secs(tb.now_ms),
                            s.ledger_ms.map(secs),
                            0.35,
                            tb.reduced || tb.mono,
                        ),
                    ),
                ),
                Seg::new(group_thousands(n), INK2),
            ],
            None,
            4,
        ));
    }
    if s.priced {
        chips.push((
            vec![Seg::bold(
                format!("${:.3}", s.cost_microcents as f64 / 1_000_000.0),
                AMBER,
            )],
            Some(AMBER),
            10,
        ));
    }
    let cw =
        |c: &(Vec<Seg>, Option<Rgb>, u8)| segs_width(&c.0) + if c.1.is_some() { 2 } else { 0 } + 1;
    while chips.len() > 1 && chips.iter().map(cw).sum::<i32>() - 1 > w - 2 - x {
        let lo = chips
            .iter()
            .enumerate()
            .min_by_key(|(_, c)| c.2)
            .map(|(i, _)| i)
            .unwrap();
        chips.remove(lo);
    }
    let total: i32 = chips.iter().map(cw).sum::<i32>() - 1;
    let mut rx = w - 1 - total;
    for (parts, col, _) in &chips {
        match col {
            Some(c) => rx = pill(cv, rx, 0, parts, *c, TOPBAR, 0.22) + 1,
            None => rx = cv.spans(rx, 0, parts, Some(TOPBAR)) + 1,
        }
    }
    let _ = pill_width;
}

fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// The permission-mode pill: label + (fg, bg).
pub fn mode_pill_spec(mode: Option<&str>) -> (&'static str, Rgb, Rgb) {
    match mode.unwrap_or("default") {
        "acceptEdits" | "accept_edits" | "accept-edits" => ("ACCEPT EDITS", ON_ACCENT, VIOLET),
        "plan" => ("PLAN", ON_ACCENT, CYAN),
        "bypass" | "bypassPermissions" | "dontAsk" => ("BYPASS", WHITE, RED),
        _ => ("DEFAULT", INK, MODE_DEFAULT_BG),
    }
}

/// The status line (last row).
#[allow(clippy::too_many_arguments)]
pub fn status_line(
    cv: &mut Cv,
    w: i32,
    y: i32,
    s: &Scenario,
    now_ms: u64,
    reduced: bool,
    mono: bool,
    focus_is_conversation: bool,
    focus_is_diff: bool,
    arranging: bool,
) {
    cv.fill(0, y, w, 1, APP);
    if arranging {
        let mut x = cv.put(1, y, " NAVIGATE ", ON_ACCENT, Some(CYAN), Modifier::BOLD) + 2;
        let all: [(&str, &str); 10] = [
            ("h j k l", "move"),
            ("H J K L", "swap"),
            ("v", "split right"),
            ("s", "split down"),
            ("x", "close"),
            ("p", "panel"),
            ("< >", "size"),
            ("b", "sidebar"),
            ("[ ]", "layout"),
            ("i", "back"),
        ];
        let mut fit = Vec::new();
        for h in all {
            let t = super::frame::hints_width(&[fit.clone(), vec![h]].concat()) + x;
            if t > w - 1 {
                break;
            }
            fit.push(h);
        }
        keyhints(cv, x, y, &fit, Some(APP));
        x = 0;
        let _ = x;
        return;
    }
    // M14: the new colour wipes across the pill in 240 ms; the label
    // swaps at the midpoint.
    let (n_label, n_fg, n_bg) = mode_pill_spec(s.permission_mode.as_deref());
    let (o_label, o_fg, o_bg) =
        mode_pill_spec(s.mode_prev.as_deref().or(s.permission_mode.as_deref()));
    let p = ease_in_out(prog(
        secs(now_ms),
        s.mode_changed_ms.map(secs),
        0.24,
        reduced,
    ));
    let label = if p < 0.5 { o_label } else { n_label };
    let text = format!(" {label} ");
    let len = text.chars().count();
    let edge = (p * len as f32).round() as usize;
    let mut x = 1;
    for (i, ch) in text.chars().enumerate() {
        let (fg, bg) = if i < edge { (n_fg, n_bg) } else { (o_fg, o_bg) };
        x = cv.put(x, y, &ch.to_string(), fg, Some(bg), Modifier::BOLD);
    }
    x += 1;
    let now = secs(now_ms);
    let waiting_model = matches!(s.activity(), Activity::WaitingModel(_));
    // 2 fps while waiting for the model, 4 fps while streaming or running.
    let star = star_at(now, if waiting_model { 2.0 } else { 4.0 }, reduced);
    let sh = |t: &str, c: Rgb| shimmer(t, now, c, reduced || mono);
    let secs = |from: u64| now_ms.saturating_sub(from) / 1000;
    let el = |t: u64| {
        let n = secs(t);
        if n >= 1 {
            vec![Seg::new(format!(" · {n}s"), MUTED)]
        } else {
            vec![]
        }
    };
    let head = |g: &str, col: Rgb| vec![Seg::bold(g.to_string(), col), Seg::bold(" ORBIT  ", INK2)];
    // M27: rate-limit backoff — a still amber star and a draining bar.
    let backoff = s.backoff_until_ms.filter(|u| *u > now_ms);
    let (seg_col, parts): (Option<Rgb>, Vec<Seg>) = if let Some(until) = backoff {
        let left = until - now_ms;
        let n = 8usize;
        let k =
            ((n as f32 * left as f32 / s.backoff_total_ms.max(1) as f32).round() as usize).min(n);
        (
            Some(AMBER),
            [
                head("✦", AMBER),
                vec![
                    Seg::bold(
                        format!("rate limited · retrying in {}s ", left.div_ceil(1000)),
                        AMBER,
                    ),
                    Seg::new("▰".repeat(k), AMBER),
                    Seg::new("▱".repeat(n - k), RULE_HI),
                ],
            ]
            .concat(),
        )
    } else {
        match s.activity() {
            Activity::Approval(t) => (
                Some(MAGENTA),
                [
                    head("✦", MAGENTA),
                    vec![Seg::bold(format!("◆ approval needed · {t}"), MAGENTA)],
                ]
                .concat(),
            ),
            Activity::RunningMany(n) => (
                Some(CYAN),
                [
                    head(star, CYAN),
                    sh(&format!("running {n} tools"), CYAN),
                    el(s.turn_started_ms),
                ]
                .concat(),
            ),
            Activity::Running(t) => (
                Some(CYAN),
                [
                    head(star, CYAN),
                    sh(&format!("running {t}"), CYAN),
                    el(s.turn_started_ms),
                ]
                .concat(),
            ),
            Activity::Streaming => (
                Some(CYAN),
                [
                    head(star, CYAN),
                    sh("streaming", CYAN),
                    el(s.turn_started_ms),
                ]
                .concat(),
            ),
            Activity::WaitingModel(m) => (
                Some(CYAN),
                [
                    head(star, CYAN),
                    sh(&format!("waiting for {m}"), CYAN),
                    el(s.turn_started_ms),
                ]
                .concat(),
            ),
            Activity::Compacting => (
                Some(AMBER),
                [head(star, AMBER), sh("compacting context", AMBER)].concat(),
            ),
            Activity::Done => (
                Some(GREEN),
                [head("✦", MAGENTA), vec![Seg::bold("✓ done", GREEN)]].concat(),
            ),
            Activity::Failed => (
                Some(RED),
                [head("✦", MAGENTA), vec![Seg::bold("✕ failed", RED)]].concat(),
            ),
            Activity::Ready => (
                None,
                [head("✦", MAGENTA), vec![Seg::new("ready", MUTED)]].concat(),
            ),
        }
    };
    let bg = seg_col.map(|c| tint(c, APP, 0.16)).unwrap_or(APP);
    x = cv.text(x, y, " ", INK, Some(bg));
    x = cv.spans(x, y, &parts, Some(bg));
    cv.text(x, y, " ", INK, Some(bg));

    let hints: Vec<(&str, &str)> = if s.approval_pending.is_some() {
        vec![("y", "allow"), ("n", "deny"), ("?", "keys")]
    } else if focus_is_diff {
        vec![
            ("j/k", "file"),
            ("z", "zoom"),
            ("esc", "arrange"),
            ("i", "back to ORBIT"),
        ]
    } else if !focus_is_conversation {
        vec![("z", "zoom"), ("esc", "arrange"), ("i", "back to ORBIT")]
    } else if s.turn_live {
        vec![
            ("esc", "arrange panels"),
            ("⌃c", "interrupt"),
            ("?", "keys"),
        ]
    } else {
        vec![("esc", "arrange panels"), (":", "commands"), ("?", "keys")]
    };
    let hw = super::frame::hints_width(&hints);
    let used = x + 2 + segs_width(&parts);
    if used + hw + 2 < w {
        keyhints(cv, w - 1 - hw, y, &hints, Some(APP));
    }
}
