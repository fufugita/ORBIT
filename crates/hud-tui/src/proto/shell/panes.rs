//! The non-conversation panels: Changes, Terminal, Plan, Activity,
//! Context, Review and Agent. Each draws only what the engine has
//! actually sent; an empty panel shows the prototype's empty state.

use super::canvas::{clip_path, clip_text, mix, text_width, tint, wrap_ranges, Cv, Rgb, Seg};
use super::convo::kind_of;
use super::diffrows;
use super::frame::{badge, empty_state, panel_frame, BadgeState, FrameSpec};
use super::motion::{ease_out, flash, prog, pulse, secs};
use super::pal::*;
use crate::proto::layout::View;
use crate::proto::panels::FileChangeRow;
use crate::proto::scenario::{LineKind, Scenario, ToolState};
use ratatui::layout::Rect;
use ratatui::style::Modifier;

/// What every side panel needs.
pub struct PaneIn<'a> {
    pub s: &'a Scenario,
    pub now_ms: u64,
    pub reduced: bool,
    /// Colour effects off (16 colours or less): flashes switch off.
    pub mono: bool,
    pub focused: bool,
    pub focus_fx: super::frame::FocusFx,
    pub num: usize,
    /// Rows scrolled up from the newest (this panel only).
    pub scroll: usize,
    /// For an Agent panel, which agent it follows (empty = any).
    pub agent: &'a str,
}

fn ident(view: View) -> super::canvas::Rgb {
    match view {
        View::Conversation => MAGENTA,
        View::Changes | View::Review => VIOLET,
        View::Terminal => AMBER,
        View::Plan => CYAN,
        View::Activity => GREEN,
        View::Context => BLUE,
        View::Agent => MAGENTA,
    }
}

/// Draw one non-conversation panel.
pub fn draw(cv: &mut Cv, r: Rect, view: View, inp: &PaneIn) {
    match view {
        View::Changes => changes(cv, r, inp),
        View::Terminal => terminal(cv, r, inp),
        View::Plan => plan(cv, r, inp),
        View::Activity => activity(cv, r, inp),
        View::Context => context(cv, r, inp),
        View::Review => review(cv, r, inp),
        View::Agent => agent(cv, r, inp),
        View::Conversation => {}
    }
}

fn frame<'a>(
    cv: &mut Cv,
    r: Rect,
    view: View,
    inp: &PaneIn,
    badge: Vec<Seg>,
    footer: Vec<(&'a str, &'a str)>,
    footer_parts: Vec<Seg>,
) -> Option<Rect> {
    panel_frame(
        cv,
        r,
        &FrameSpec {
            num: inp.num,
            title: view.title(),
            ident: ident(view),
            focused: inp.focused,
            focus_fx: inp.focus_fx,
            badge: Some(badge),
            attention: 0.0,
            footer,
            footer_parts,
        },
    )
}

fn changes(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let files = &inp.s.file_changes;
    let add: u32 = files.iter().map(|f| f.added).sum();
    let del: u32 = files.iter().map(|f| f.removed).sum();
    let b = if files.is_empty() {
        vec![Seg::new("none", FAINT)]
    } else {
        vec![
            Seg::new(
                format!(
                    "{} file{}  ",
                    files.len(),
                    if files.len() > 1 { "s" } else { "" }
                ),
                MUTED,
            ),
            Seg::bold(format!("+{add}"), GREEN),
            Seg::bold(format!(" −{del}"), RED),
        ]
    };
    let Some(inner) = frame(
        cv,
        r,
        View::Changes,
        inp,
        b,
        vec![("j/k", "file"), ("⏎", "full diff")],
        vec![],
    ) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width - 2,
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        if files.is_empty() {
            empty_state(
                cv,
                inner,
                "◌",
                VIOLET,
                "No changes yet",
                "Files ORBIT edits appear here. A checkpoint is taken before every prompt, so each change can be rewound.",
            );
            return;
        }
        let (x, w) = (inner.x as i32, inner.width as i32);
        // The window follows the selection, so `j` past the last visible
        // row scrolls instead of selecting something off screen.
        let selected = inp.s.selected_file().unwrap_or(0);
        let rows = (inner.height as usize).max(1);
        let first = (selected + 1).saturating_sub(rows);
        for (i, f) in files.iter().enumerate().skip(first).take(rows) {
            let yy = inner.y as i32 + (i - first) as i32;
            cv.hit(r.x as i32 + 1, yy, r.width as i32 - 2, 1, super::hits::Click::File(i));
            let sel = i == selected;
            // M11: the changed row flashes for 600 ms and its counters
            // count up in 300 ms.
            let changed = inp.s.file_changed_ms.get(i).copied().filter(|t| *t > 0).map(secs);
            let fl = flash(secs(inp.now_ms), changed, 0.6, inp.reduced || inp.mono);
            let roll = ease_out(prog(secs(inp.now_ms), changed, 0.3, inp.reduced));
            let base = if sel { tint(VIOLET, PANEL, 0.12) } else { PANEL };
            let bg = mix(base, tint(VIOLET, PANEL, 0.35), fl);
            cv.fill(r.x as i32 + 1, yy, r.width as i32 - 2, 1, bg);
            if sel {
                cv.text(r.x as i32 + 1, yy, "▌", VIOLET, Some(bg));
            }
            cv.put(x, yy, " M ", ON_ACCENT, Some(AMBER), Modifier::BOLD);
            let added = (f.added as f32 * roll).round() as u32;
            let removed = (f.removed as f32 * roll).round() as u32;
            let mut cnt = vec![Seg::bold(format!("+{added}"), GREEN)];
            if f.removed > 0 {
                cnt.push(Seg::bold(format!(" −{removed}"), RED));
            }
            let cw = super::canvas::segs_width(&cnt);
            cv.put(
                x + 4,
                yy,
                &clip_path(&f.path, w - 14),
                if sel { INK } else { INK2 },
                Some(bg),
                if sel { Modifier::BOLD } else { Modifier::empty() },
            );
            cv.spans(x + w - cw, yy, &cnt, Some(bg));
        }
    });
}

/// The most recent shell command card, if any.
fn last_shell(s: &Scenario) -> Option<&crate::proto::scenario::TranscriptLine> {
    s.transcript
        .iter()
        .rev()
        .find(|l| l.kind == LineKind::Tool && kind_of(&l.tool_name) == "BASH")
}

/// The card of the command a tape belongs to (matched by call id): it
/// holds the command line, how it ended and how long it took. A tape whose
/// card cannot be found (a bare `┃` status line carried no id) is the
/// newest command's, so the newest tape falls back to the newest card.
fn tape_card(s: &Scenario, i: usize) -> Option<&crate::proto::scenario::TranscriptLine> {
    let id = &s.tapes[i].call_id;
    s.transcript
        .iter()
        .rev()
        .find(|l| l.kind == LineKind::Tool && !id.is_empty() && &l.call_id == id)
        .or_else(|| (i + 1 == s.tapes.len()).then(|| last_shell(s)).flatten())
}

/// The glyph and colour a command's state shows (the card's own, §9.8).
fn tape_tone(state: ToolState) -> (&'static str, Rgb) {
    match state {
        ToolState::Running => ("◐", AMBER),
        ToolState::Done => ("✓", GREEN),
        ToolState::Failed => ("✕", RED),
        ToolState::AwaitingYou => ("◆", MAGENTA),
        ToolState::Cancelled | ToolState::Denied | ToolState::Blocked => ("⊘", MUTED),
        ToolState::Queued => ("◌", MUTED),
    }
}

/// What a tab says of its command: the command itself, whitespace
/// squeezed, cut to fit. (Its first two words alone told `python3 -c "…"`
/// from `python3 -c "…"` not at all.)
fn tape_label(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The Terminal's tab strip: one tab per command, numbered, so every one
/// fits and none is mistaken for another (commands often share a long
/// prefix). Only the SELECTED tab spells out its command, in whatever room
/// the others leave; the full line is under the strip. As many tabs as fit
/// are shown with the selected one always in view (`‹ ›` mark what is cut).
/// Every tab is a click target.
fn terminal_tabs(cv: &mut Cv, x: i32, y: i32, w: i32, s: &Scenario, sel: usize) {
    let n = s.tapes.len();
    let states: Vec<ToolState> = (0..n)
        .map(|i| tape_card(s, i).map(|c| c.tool_state).unwrap_or_default())
        .collect();
    // " ✓12 " — a space, the glyph, the number, a space — and a gap.
    let digits = |i: usize| (i + 1).to_string().len() as i32;
    let compact = |i: usize| 3 + digits(i) + 1;
    let room = (w - 2).max(1);
    let (mut lo, mut hi) = (sel, sel);
    let mut used = compact(sel);
    loop {
        if lo > 0 && used + compact(lo - 1) <= room {
            lo -= 1;
            used += compact(lo);
        } else if hi + 1 < n && used + compact(hi + 1) <= room {
            hi += 1;
            used += compact(hi);
        } else {
            break;
        }
    }
    // What is left after every compact tab is the selected tab's label.
    let label = tape_card(s, sel)
        .map(|c| tape_label(&c.text))
        .unwrap_or_default();
    let spare = (room - used - 1).max(0);
    let label = if spare >= 4 {
        clip_text(&label, spare)
    } else {
        String::new()
    };
    let mut cx = x;
    if lo > 0 {
        cx = cv.text(cx, y, "‹", FAINT, None);
    }
    for (i, state) in states.iter().enumerate().take(hi + 1).skip(lo) {
        let (g, col) = tape_tone(*state);
        let from = cx;
        if i == sel {
            let text = if label.is_empty() {
                format!(" {g}{} ", i + 1)
            } else {
                format!(" {g}{} {label} ", i + 1)
            };
            cx = cv.put(cx, y, &text, ON_ACCENT, Some(col), Modifier::BOLD);
        } else {
            cx = cv.text(cx, y, " ", MUTED, None);
            cx = cv.bold(cx, y, g, col, None);
            cx = cv.text(cx, y, &format!("{} ", i + 1), MUTED, None);
        }
        cv.hit(from, y, cx - from, 1, super::hits::Click::Tape(i));
        cx += 1;
    }
    if hi + 1 < n {
        cv.text(x + w - 1, y, "›", FAINT, None);
    }
}

fn terminal(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let s = inp.s;
    let sel = s.selected_tape();
    let card = sel.and_then(|i| tape_card(s, i));
    let b = match card {
        None => vec![Seg::new("none", FAINT)],
        Some(l) => match l.tool_state {
            ToolState::Running => badge(BadgeState::Running, None, inp.now_ms, inp.reduced),
            ToolState::Done => badge(
                BadgeState::Done,
                Some(l.meta.trim_start_matches("done · ")),
                inp.now_ms,
                inp.reduced,
            ),
            ToolState::Failed => badge(BadgeState::Failed, None, inp.now_ms, inp.reduced),
            _ => badge(BadgeState::Idle, None, inp.now_ms, inp.reduced),
        },
    };
    let footer = if s.tapes.len() > 1 {
        vec![("j/k", "scroll"), ("[ ]", "command")]
    } else {
        vec![("j/k", "scroll")]
    };
    let Some(inner) = frame(cv, r, View::Terminal, inp, b, footer, vec![]) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width - 2,
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        let (Some(sel), true) = (sel, !s.tapes.is_empty()) else {
            empty_state(
                cv,
                inner,
                "◌",
                AMBER,
                "No commands yet",
                "Commands ORBIT runs stream here, inside the sandbox. Start a line with ! in the composer to run your own.",
            );
            return;
        };
        let tape = &s.tapes[sel];
        let (x, y, w, h) = (inner.x as i32, inner.y as i32, inner.width as i32, inner.height as i32);
        // The command tabs.
        terminal_tabs(cv, x, y, w, s, sel);
        // Output inset: the full command line, then the tape.
        let top = y + 2;
        let bottom = y + h - 1;
        cv.fill(r.x as i32 + 1, top - 1, r.width as i32 - 2, (bottom - top + 1).max(0), INSET);
        let command = card.map(|c| c.text.as_str()).unwrap_or("");
        cv.bold(x, top, "$ ", AMBER, Some(INSET));
        cv.bold(x + 2, top, &clip_text(command, w - 2), INK, Some(INSET));
        // How it ended takes the last row, so the person need not scroll
        // to learn whether it worked.
        let ended = card.filter(|c| {
            !matches!(
                c.tool_state,
                ToolState::Running | ToolState::Queued | ToolState::AwaitingYou
            )
        });
        let reserve = if ended.is_some() { 1 } else { 0 };
        let avail = (bottom - top - 1 - reserve).max(0) as usize;
        let note = (tape.dropped > 0).then(|| format!("… {} earlier lines not kept", tape.dropped));
        let rows: Vec<(&str, Rgb)> = note
            .iter()
            .map(|n| (n.as_str(), FAINT))
            .chain(tape.lines.iter().map(|l| (l.as_str(), INK2)))
            .collect();
        let start = rows.len().saturating_sub(avail + inp.scroll.min(rows.len()));
        for (i, (line, col)) in rows.iter().skip(start).take(avail).enumerate() {
            cv.text(x, top + 1 + i as i32, &clip_text(line, w), *col, Some(INSET));
        }
        if let Some(c) = ended {
            let (g, col) = tape_tone(c.tool_state);
            let what = if c.meta.is_empty() {
                match c.tool_state {
                    ToolState::Denied => "denied".to_string(),
                    ToolState::Cancelled => "cancelled".to_string(),
                    _ => String::new(),
                }
            } else {
                c.meta.clone()
            };
            cv.bold(x, bottom, g, col, Some(INSET));
            cv.text(x + 2, bottom, &clip_text(&what, w - 2), col, Some(INSET));
        }
    });
}

fn plan(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let tasks = &inp.s.tasks;
    let done = tasks.iter().filter(|t| t.status == "done").count();
    let b = if tasks.is_empty() {
        vec![Seg::new("none", FAINT)]
    } else {
        vec![Seg::bold(format!("{done}/{} done", tasks.len()), CYAN)]
    };
    let Some(inner) = frame(cv, r, View::Plan, inp, b, vec![], vec![]) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width - 2,
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        if tasks.is_empty() {
            empty_state(
                cv,
                inner,
                "◌",
                CYAN,
                "Nothing planned yet",
                "When a task has steps, the plan collects here.",
            );
            return;
        }
        let (x, y, w) = (inner.x as i32, inner.y as i32, inner.width as i32);
        // Progress bar + percent.
        let target = done as f32 / tasks.len() as f32;
        // M17: the bar eases in over 300 ms after a step finishes.
        let last = inp
            .s
            .task_changed_ms
            .iter()
            .copied()
            .max()
            .filter(|t| *t > 0);
        let from = ((done as f32 - 1.0).max(0.0)) / tasks.len() as f32;
        let pct = from
            + (target - from) * ease_out(prog(secs(inp.now_ms), last.map(secs), 0.3, inp.reduced));
        let bw = (w - 6).max(4);
        let k = (pct * bw as f32).round() as i32;
        cv.text(x, y + 1, &"━".repeat(k as usize), CYAN, None);
        cv.text(x + k, y + 1, &"─".repeat((bw - k) as usize), RULE_HI, None);
        cv.text(
            x + w - 4,
            y + 1,
            &format!("{:>3}%", (pct * 100.0).round() as u32),
            MUTED,
            None,
        );
        for (i, t) in tasks.iter().enumerate() {
            let yy = y + 3 + i as i32 * 2;
            let active = t.status == "active" || t.status == "running";
            // M17: a finished step flashes 450 ms; the active one
            // breathes at 0.5 Hz.
            let changed = inp
                .s
                .task_changed_ms
                .get(i)
                .copied()
                .filter(|c| *c > 0)
                .map(secs);
            let fl = flash(secs(inp.now_ms), changed, 0.45, inp.reduced || inp.mono);
            let (g, gc) = if t.status == "done" {
                ("✓", mix(GREEN, WHITE, fl))
            } else if active {
                (
                    "◉",
                    mix(
                        tint(CYAN, PANEL, 0.5),
                        CYAN,
                        0.55 + 0.45 * pulse(secs(inp.now_ms), 0.5, inp.reduced),
                    ),
                )
            } else {
                ("○", FAINT)
            };
            cv.bold(x, yy, g, gc, None);
            cv.put(
                x + 2,
                yy,
                &clip_text(&t.title, w - 3),
                if active {
                    INK
                } else if t.status == "done" {
                    INK2
                } else {
                    MUTED
                },
                None,
                if active {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                },
            );
        }
    });
}

/// The glyph and colour of an Activity row, from what it is and what it
/// says. Green is reserved for outcomes the ledger backs (design law 4);
/// magenta marks an authority decision (law 2).
fn activity_tone(kind: &str, fact: &str) -> (&'static str, Rgb) {
    match kind {
        "intent" => ("→", FAINT),
        "verdict" if fact.starts_with("allowed") => ("◆", MAGENTA),
        "verdict" => ("⊘", MUTED),
        "result" => match fact {
            "ok" => ("✓", GREEN),
            "denied" => ("⊘", MUTED),
            _ => ("✕", RED),
        },
        "egress" | "request" => ("↗", CYAN),
        "compaction" | "retry" => ("◌", AMBER),
        _ => ("∙", MUTED),
    }
}

/// What an Activity row says: the HEADLINE (the outcome a reader scans
/// for) and the secondary detail that follows the target.
///
///   verdict  `allowed — operator approved` → `allowed`, `operator approved`
///   result   `ok` / `denied` / `error`    → itself, no detail
///   intent   `requested` is noise         → `intent`, no detail
///   others   (egress, compaction, retry)  → their kind, the fact as detail
fn activity_parts(a: &crate::proto::scenario::ActivityRow) -> (String, String) {
    match a.kind.as_str() {
        "verdict" => match a.fact.split_once(" — ") {
            Some((head, why)) => (head.to_string(), why.to_string()),
            None => (a.fact.clone(), String::new()),
        },
        "result" => (a.fact.clone(), String::new()),
        "intent" => ("intent".to_string(), String::new()),
        _ => (a.kind.clone(), a.fact.clone()),
    }
}

fn activity(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let s = inp.s;
    let rows = &s.activity;
    let proof = rows.iter().filter(|a| a.digest.is_some()).count();
    let b = if rows.is_empty() {
        vec![Seg::new("none", FAINT)]
    } else {
        vec![
            Seg::bold(format!("{} events", rows.len()), GREEN),
            Seg::new(format!(" · {proof} on the ledger"), MUTED),
        ]
    };
    let Some(inner) = frame(
        cv,
        r,
        View::Activity,
        inp,
        b,
        vec![("j/k", "scroll")],
        vec![],
    ) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width - 2,
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        if rows.is_empty() {
            empty_state(
                cv,
                inner,
                "◌",
                GREEN,
                "No activity yet",
                "Every request, decision and result is listed here as it is recorded. Ledger records carry their hash.",
            );
            return;
        }
        let (x, y, w, h) = (
            inner.x as i32,
            inner.y as i32,
            inner.width as i32,
            inner.height as i32,
        );
        // A wide panel (zoomed, or a big terminal) gives every record one
        // line; a side column gives it two, because time, kind, outcome,
        // target and hash do not fit on one:
        //   14:02:11 ◆ allowed                       #a1b2c3
        //            Bash(cargo test -p orbit-export) · operator approved
        // The HEADLINE is the outcome (`allowed`, `ok`, `denied`), so the
        // thing worth reading is on the first line and cannot be clipped
        // off by a long command.
        let wide = w >= 84;
        let per = if wide { 1usize } else { 2 };
        let visible = (h as usize / per).max(1);
        let start = rows
            .len()
            .saturating_sub(visible + inp.scroll.min(rows.len()));
        for (i, a) in rows.iter().skip(start).take(visible).enumerate() {
            let y0 = y + (i * per) as i32;
            let (g, gcol) = activity_tone(&a.kind, &a.fact);
            let (head, detail) = activity_parts(a);
            cv.text(x, y0, &a.time, FAINT, None);
            cv.bold(x + 9, y0, g, gcol, None);
            let hash = a
                .digest
                .as_deref()
                .map(|d| format!("#{}", d.chars().take(6).collect::<String>()));
            let hash_w = hash.as_ref().map_or(0, |h| text_width(h) + 1);
            if let Some(h) = &hash {
                cv.text(x + w - text_width(h), y0, h, FAINT, None);
            }
            let body = if detail.is_empty() {
                a.target.clone()
            } else {
                format!("{} · {}", a.target, detail)
            };
            if wide {
                // Glyph and colour already say what kind of record it is;
                // the headline column carries the outcome.
                let bx = x + 11 + 10;
                cv.bold(x + 11, y0, &clip_text(&head, 9), gcol, None);
                cv.text(bx, y0, &clip_text(&body, x + w - bx - hash_w - 1), INK, None);
            } else {
                cv.bold(
                    x + 11,
                    y0,
                    &clip_text(&head, w - 11 - hash_w - 1),
                    gcol,
                    None,
                );
                cv.text(x + 9, y0 + 1, &clip_text(&body, w - 9), INK, None);
            }
        }
    });
}

/// Tokens as a person reads them: `842`, `3.2k`, `54k`, `1.2M`.
pub fn tokens_short(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1_000..=9_999 => format!("{:.1}k", n as f64 / 1_000.0),
        10_000..=99_999 => {
            let k = n as f64 / 1_000.0;
            if (k - k.round()).abs() < 0.05 {
                format!("{}k", k.round() as u64)
            } else {
                format!("{k:.1}k")
            }
        }
        100_000..=999_999 => format!("{}k", (n + 500) / 1_000),
        _ => format!("{:.1}M", n as f64 / 1_000_000.0),
    }
}

/// The Context panel: what the window is made of, where compaction starts,
/// and what compactions did. The parts are the engine's estimates (a
/// provider reports one total, never the parts) and say so; the total in
/// the header is the provider's.
fn context(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let s = inp.s;
    let ctx = if s.window_tokens > 0 {
        (s.used_tokens as f32 / s.window_tokens as f32).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let b = vec![Seg::bold(
        format!("{}%", (ctx * 100.0).round() as u32),
        if ctx > 0.85 { AMBER } else { BLUE },
    )];
    let Some(inner) = frame(cv, r, View::Context, inp, b, vec![], vec![]) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width - 2,
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        let (x, y, w, h) = (
            inner.x as i32,
            inner.y as i32,
            inner.width as i32,
            inner.height as i32,
        );
        if s.window_tokens == 0 {
            empty_state(
                cv,
                inner,
                "◌",
                BLUE,
                "No usage yet",
                "The context meter fills as the conversation grows.",
            );
            return;
        }
        let window = s.window_tokens;
        let bw = (w - 1).max(4);
        // Cells for `n` tokens, over the window.
        let cells = |n: u64| ((n as f64 / window as f64) * bw as f64).round() as i32;
        // The provider's own total, plain.
        cv.text(
            x,
            y,
            &clip_text(
                &format!("{} of {} tokens", tokens_short(s.used_tokens), tokens_short(window)),
                w,
            ),
            INK2,
            None,
        );
        let mut yy = y + 1;
        let Some(bd) = s.ctx_breakdown else {
            // No breakdown (a producer that does not measure it): the
            // total alone, as the provider reported it.
            let k = (ctx * bw as f32).round() as i32;
            cv.text(
                x,
                yy,
                &"▰".repeat(k as usize),
                mix(CYAN, if ctx > 0.85 { AMBER } else { CYAN }, ctx),
                None,
            );
            cv.text(x + k, yy, &"▱".repeat((bw - k) as usize), RULE_HI, None);
            cv.text(
                x,
                yy + 2,
                &format!("{} of {} tokens", s.used_tokens, window),
                INK2,
                None,
            );
            cv.text(
                x,
                yy + 4,
                &format!("in {}  out {}", s.input_tokens, s.output_tokens),
                MUTED,
                None,
            );
            return;
        };
        let parts: [(&str, u64, Rgb); 4] = [
            ("system", bd.system, BLUE),
            ("tools", bd.tools, CYAN),
            ("memory", bd.memory, VIOLET),
            ("messages", bd.messages, MAGENTA),
        ];
        let measured: u64 = parts.iter().map(|p| p.1).sum();
        // The estimates can undershoot the provider's own count (different
        // tokenizer): say so rather than hide the gap, once it is visible.
        let other = s.used_tokens.saturating_sub(measured);
        let other = if other * 20 >= window { other } else { 0 };
        let total = measured + other;
        // The stacked bar: every part at least a cell wide when it is not
        // empty, the rest free.
        let mut x_cur = x;
        let mut left = bw;
        let mut stack: Vec<(u64, Rgb)> = parts.iter().map(|(_, n, c)| (*n, *c)).collect();
        if other > 0 {
            stack.push((other, FAINT));
        }
        for (n, col) in stack {
            if n == 0 || left == 0 {
                continue;
            }
            let c = cells(n).clamp(1, left);
            cv.text(x_cur, yy, &"█".repeat(c as usize), col, None);
            x_cur += c;
            left -= c;
        }
        cv.text(x_cur, yy, &"░".repeat(left as usize), RULE_HI, None);
        // Where compaction starts: the conversation reaching `compact_at`
        // on top of everything that is always sent.
        let fixed = bd.system + bd.tools + bd.memory;
        let marker_at = fixed + bd.compact_at;
        if bd.compact_at > 0 {
            let mx = x + cells(marker_at.min(window)).clamp(0, bw - 1);
            cv.bold(mx, yy + 1, "▲", AMBER, None);
        }
        yy += 3;
        // The legend: the parts, then what is left.
        let mut rows: Vec<(&str, u64, Rgb)> = parts.to_vec();
        if other > 0 {
            rows.push(("other", other, FAINT));
        }
        for (name, n, col) in &rows {
            let pct = (*n as f64 / window as f64 * 100.0).round() as u32;
            let num = format!("~{}", tokens_short(*n));
            cv.text(x, yy, "■", *col, None);
            cv.text(x + 2, yy, name, INK2, None);
            cv.text(x + w - 5 - text_width(&num), yy, &num, INK, None);
            cv.text(x + w - 4, yy, &format!("{pct:>3}%"), MUTED, None);
            yy += 1;
        }
        let free = window.saturating_sub(total);
        let num = format!("~{}", tokens_short(free));
        cv.text(x, yy, "□", RULE_HI, None);
        cv.text(x + 2, yy, "free", INK2, None);
        cv.text(x + w - 5 - text_width(&num), yy, &num, INK, None);
        cv.text(
            x + w - 4,
            yy,
            &format!(
                "{:>3}%",
                (free as f64 / window as f64 * 100.0).round() as u32
            ),
            MUTED,
            None,
        );
        yy += 2;
        if bd.compact_at > 0 {
            // The number first: it is what a narrow panel must not cut.
            cv.text(
                x,
                yy,
                &clip_text(&format!("▲ compacts at ~{}", tokens_short(bd.compact_at)), w),
                MUTED,
                None,
            );
            yy += 1;
            let why = format!(
                "when the conversation alone reaches this: 90% of the window, less {} kept for the answer",
                tokens_short(bd.reserve)
            );
            let chars: Vec<char> = why.chars().collect();
            for (a, b) in wrap_ranges(&why, w - 2).into_iter().take(3) {
                let line: String = chars[a..b].iter().collect();
                cv.text(x + 2, yy, &line, FAINT, None);
                yy += 1;
            }
            yy += 1;
        }
        cv.text(
            x,
            yy,
            &clip_text(
                &format!("provider: {} in · {} out", s.input_tokens, s.output_tokens),
                w,
            ),
            FAINT,
            None,
        );
        yy += 1;
        cv.text(x, yy, &clip_text("the parts are estimates", w), FAINT, None);
        yy += 2;
        // What compaction did, newest last.
        if !s.compactions.is_empty() && yy + 2 < y + h {
            cv.text(x, yy, "COMPACTED", FAINT, None);
            yy += 1;
            let room = (y + h - yy).max(0) as usize;
            let skip = s.compactions.len().saturating_sub(room);
            for c in s.compactions.iter().skip(skip) {
                cv.text(x, yy, &c.time, FAINT, None);
                cv.text(
                    x + 9,
                    yy,
                    &clip_text(
                        &format!("~{} → ~{}", tokens_short(c.before), tokens_short(c.after)),
                        w - 9,
                    ),
                    INK2,
                    None,
                );
                yy += 1;
            }
        }
    });
}

fn review(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let files = &inp.s.file_changes;
    let add: u32 = files.iter().map(|f| f.added).sum();
    let del: u32 = files.iter().map(|f| f.removed).sum();
    let b = if files.is_empty() {
        vec![Seg::new("none", MUTED)]
    } else {
        vec![
            Seg::new(format!("{} files  ", files.len()), MUTED),
            Seg::bold(format!("+{add}"), GREEN),
            Seg::bold(format!(" −{del}"), RED),
        ]
    };
    let Some(inner) = frame(
        cv,
        r,
        View::Review,
        inp,
        b,
        vec![("j/k", "file"), ("n/p", "hunk"), ("⏎", "full diff")],
        vec![],
    ) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width - 2,
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        if files.is_empty() {
            empty_state(
                cv,
                inner,
                "◌",
                VIOLET,
                "Nothing to review",
                "Changed files, checkpoints and proof appear here once ORBIT edits something.",
            );
            return;
        }
        let (x, y, w, h) = (
            inner.x as i32,
            inner.y as i32,
            inner.width as i32,
            inner.height as i32,
        );
        // Files on the left, the selected file on the right.
        let lw = (w * 2 / 5).clamp(24, 40).min(w - 10);
        cv.text(x, y, "FILES", FAINT, None);
        let selected = inp.s.selected_file().unwrap_or(0);
        let rows = ((h - 1).max(1)) as usize;
        let first = (selected + 1).saturating_sub(rows);
        for (i, f) in files.iter().enumerate().skip(first).take(rows) {
            let yy = y + 1 + (i - first) as i32;
            cv.hit(x, yy, lw, 1, super::hits::Click::File(i));
            let sel = i == selected;
            let bg = if sel {
                Some(tint(VIOLET, PANEL, 0.12))
            } else {
                None
            };
            if sel {
                cv.fill(x, yy, lw, 1, tint(VIOLET, PANEL, 0.12));
                cv.text(x, yy, "▌", VIOLET, bg);
            }
            let cnt = if f.removed > 0 {
                format!("+{} −{}", f.added, f.removed)
            } else {
                format!("+{}", f.added)
            };
            cv.put(
                x + 2,
                yy,
                &clip_path(&f.path, lw - 4 - text_width(&cnt)),
                if sel { INK } else { INK2 },
                bg,
                if sel {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                },
            );
            cv.text(x + lw - 1 - text_width(&cnt), yy, &cnt, GREEN, bg);
        }
        for yy in y..y + h {
            cv.text(x + lw, yy, "│", RULE, None);
        }
        let rx = x + lw + 2;
        let rw = w - lw - 2;
        if let Some(i) = inp.s.selected_file() {
            review_diff(cv, rx, y, rw, h, &files[i], inp.s.selected_hunk());
        }
    });
}

/// The Review panel's right pane: the selected file's real hunks, from the
/// current one down. Says plainly when the engine had nothing to diff
/// against — it never shows a placeholder as if it were a diff.
fn review_diff(cv: &mut Cv, x: i32, y: i32, w: i32, h: i32, f: &FileChangeRow, hunk: usize) {
    match &f.hunks {
        None => {
            cv.bold(x, y, &clip_path(&f.path, w), BLUE, None);
            cv.text(x, y + 2, "◌ no diff captured", MUTED, None);
            cv.text(
                x,
                y + 3,
                &clip_text(
                    "this change arrived without a \"before\" to diff against",
                    w,
                ),
                FAINT,
                None,
            );
        }
        Some(hs) if hs.is_empty() => {
            cv.bold(x, y, &clip_path(&f.path, w), BLUE, None);
            cv.text(x, y + 2, "◌ no visible changes", MUTED, None);
            cv.text(
                x,
                y + 3,
                &clip_text("the edit touched only lines the bounds cut", w),
                FAINT,
                None,
            );
        }
        Some(hs) => {
            let counter = format!("hunk {}/{}", hunk + 1, hs.len());
            let cw = text_width(&counter);
            cv.bold(x, y, &clip_path(&f.path, w - cw - 2), BLUE, None);
            cv.text(x + w - cw, y, &counter, FAINT, None);
            let (rows, starts) = diffrows::rows(hs);
            let top = starts[hunk.min(starts.len() - 1)];
            let room = (h - 2).max(1) as usize;
            let left = rows.len() - top;
            // When the hunk (and the ones after it) do not fit, give the
            // last row to "N more" instead of cutting a line mid-thought.
            let shown = if left > room { room - 1 } else { left };
            diffrows::draw(cv, x, y + 2, w, &rows[top..top + shown], PANEL);
            if left > shown {
                cv.text(
                    x,
                    y + 2 + shown as i32,
                    &clip_text(&format!("… {} more · ⏎ full diff", left - shown), w),
                    FAINT,
                    None,
                );
            }
        }
    }
}

fn agent(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let s = inp.s;
    let mine: Vec<_> = s
        .agents
        .values()
        // "Explore" (the agent's own name) shows in the panel named "explore".
        .filter(|a| inp.agent.is_empty() || a.name.eq_ignore_ascii_case(inp.agent))
        .collect();
    let b = if mine.iter().any(|a| !a.done) {
        badge(BadgeState::Working, None, inp.now_ms, inp.reduced)
    } else if mine.is_empty() {
        vec![Seg::new("none", FAINT)]
    } else {
        badge(BadgeState::Done, None, inp.now_ms, inp.reduced)
    };
    let title = if inp.agent.is_empty() {
        "Agent".to_string()
    } else {
        format!("Agent · {}", inp.agent)
    };
    let Some(inner) = panel_frame(
        cv,
        r,
        &FrameSpec {
            num: inp.num,
            title: &title,
            ident: if inp.agent == "review" { GREEN } else { BLUE },
            focused: inp.focused,
            focus_fx: inp.focus_fx,
            badge: Some(b),
            attention: 0.0,
            footer: vec![],
            footer_parts: vec![],
        },
    ) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width - 2,
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        if mine.is_empty() {
            empty_state(
                cv,
                inner,
                "◌",
                BLUE,
                "No agent yet",
                "A subagent ORBIT starts shows its task and what it is doing here.",
            );
            return;
        }
        let (x, y, w, h) = (
            inner.x as i32,
            inner.y as i32,
            inner.width as i32,
            inner.height as i32,
        );
        // One block per agent: who and how long, what it was asked, then
        // what it is doing — or, once it has finished, what it reported.
        //
        //   ◜ Explore                                    12s
        //     find where add() is defined
        //     ▸ Read calc.py
        let mut yy = y;
        for a in &mine {
            if yy >= y + h {
                break;
            }
            // M15: arcs turn at 10 fps.
            let arc = if inp.reduced {
                "●"
            } else {
                ["◜", "◝", "◞", "◟"][((secs(inp.now_ms) * 10.0) as usize) & 3]
            };
            let (glyph, gcol) = match (a.done, a.ok) {
                (false, _) => (arc, CYAN),
                (true, true) => ("✓", GREEN),
                (true, false) => ("✕", RED),
            };
            let (dur, _) = crate::proto::runtime::format_duration(
                a.done_ms.unwrap_or(inp.now_ms).saturating_sub(a.started_ms),
            );
            let (status, scol) = match (a.done, a.ok) {
                (false, _) => (dur, MUTED),
                (true, true) => (format!("done · {dur}"), GREEN),
                (true, false) => (format!("failed · {dur}"), RED),
            };
            let sw = text_width(&status);
            cv.bold(x, yy, glyph, gcol, None);
            cv.bold(x + 2, yy, &clip_text(&a.name, w - 5 - sw), INK, None);
            cv.text(x + w - sw, yy, &status, scol, None);
            yy += 1;
            if !a.task.is_empty() {
                cv.text(x + 2, yy, &clip_text(&a.task, w - 3), MUTED, None);
                yy += 1;
            }
            if !a.done {
                let (line, col) = if a.action.is_empty() {
                    ("starting…".to_string(), FAINT)
                } else {
                    (format!("▸ {}", a.action), INK2)
                };
                cv.text(x + 2, yy, &clip_text(&line, w - 3), col, None);
                yy += 1;
            } else {
                // Its report, wrapped, at most four lines.
                let report = a.report.trim();
                let (text, col) = if report.is_empty() {
                    ("(no report)", FAINT)
                } else if a.ok {
                    (report, INK2)
                } else {
                    (report, RED)
                };
                let chars: Vec<char> = text.chars().collect();
                let lines = wrap_ranges(text, w - 3);
                for (n, (s, e)) in lines.iter().take(4).enumerate() {
                    if yy >= y + h {
                        break;
                    }
                    let mut line: String = chars[*s..*e].iter().collect();
                    if n == 3 && lines.len() > 4 {
                        line = clip_text(&format!("{line}…"), w - 3);
                    }
                    cv.text(x + 2, yy, &line, col, None);
                    yy += 1;
                }
            }
            yy += 1; // a gap between agents
        }
    });
}

#[cfg(test)]
mod activity_row_tests {
    use super::*;
    use crate::proto::scenario::ActivityRow;

    fn row(kind: &str, fact: &str) -> ActivityRow {
        ActivityRow {
            time: "14:02:11".into(),
            kind: kind.into(),
            target: "Edit(calc.py)".into(),
            fact: fact.into(),
            digest: Some("a1b2c3d4".into()),
        }
    }

    /// The outcome is the headline; the reason follows the target. A
    /// long command can clip the reason, never the verdict.
    #[test]
    fn a_verdict_leads_with_allowed_or_denied() {
        assert_eq!(
            activity_parts(&row("verdict", "allowed — operator approved")),
            ("allowed".to_string(), "operator approved".to_string())
        );
        assert_eq!(
            activity_parts(&row("verdict", "denied — plan mode is read-only")),
            ("denied".to_string(), "plan mode is read-only".to_string())
        );
        assert_eq!(
            activity_parts(&row("verdict", "denied")),
            ("denied".to_string(), String::new())
        );
    }

    #[test]
    fn results_intents_and_runtime_events_read_plainly() {
        assert_eq!(activity_parts(&row("result", "ok")).0, "ok");
        assert_eq!(activity_parts(&row("result", "denied")).0, "denied");
        assert_eq!(
            activity_parts(&row("intent", "requested")),
            ("intent".to_string(), String::new()),
            "\"requested\" says nothing the kind does not"
        );
        assert_eq!(
            activity_parts(&row("egress", "gpt · 5 in / 3 out")),
            ("egress".to_string(), "gpt · 5 in / 3 out".to_string())
        );
    }
}
