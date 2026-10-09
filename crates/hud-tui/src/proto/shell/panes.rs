//! The non-conversation panels: Changes, Terminal, Plan, Activity,
//! Context, Review and Agent. Each draws only what the engine has
//! actually sent; an empty panel shows the prototype's empty state.

use super::canvas::{clip_text, mix, text_width, tint, Cv, Seg};
use super::convo::kind_of;
use super::frame::{badge, empty_state, panel_frame, BadgeState, FrameSpec};
use super::motion::{ease_out, flash, prog, pulse, secs};
use super::pal::*;
use crate::proto::layout::View;
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
        vec![("j/k", "file"), ("⏎", "full diff"), ("u", "revert file")],
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
        for (i, f) in files.iter().enumerate() {
            let yy = inner.y as i32 + i as i32;
            let sel = i == 0;
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
                &clip_text(&f.path, w - 14),
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

fn terminal(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let s = inp.s;
    let sh = last_shell(s);
    let b = match sh {
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
    let Some(inner) = frame(cv, r, View::Terminal, inp, b, vec![("⌃c", "stop")], vec![]) else {
        return;
    };
    let clip = Rect {
        x: r.x + 1,
        y: inner.y,
        width: r.width - 2,
        height: inner.height,
    };
    cv.clipped(clip, |cv| {
        let Some(l) = sh else {
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
        let (x, y, w, h) = (inner.x as i32, inner.y as i32, inner.width as i32, inner.height as i32);
        // The command tab.
        let (g, bg) = match l.tool_state {
            ToolState::Running => ("◐", AMBER),
            ToolState::Done => ("✓", GREEN),
            ToolState::Failed => ("✕", RED),
            _ => ("◌", MUTED),
        };
        let cmd: String = l.text.split(' ').take(2).collect::<Vec<_>>().join(" ");
        cv.put(x, y, &format!(" {g} {} ", clip_text(&cmd, 18)), ON_ACCENT, Some(bg), Modifier::BOLD);
        // Output inset.
        let top = y + 2;
        let bottom = y + h - 1;
        cv.fill(r.x as i32 + 1, top - 1, r.width as i32 - 2, (bottom - top + 1).max(0), INSET);
        cv.bold(x, top, "$ ", AMBER, Some(INSET));
        cv.bold(x + 2, top, &clip_text(&l.text, w - 2), INK, Some(INSET));
        let lines = &s.tool_output;
        let avail = (bottom - top - 1).max(0) as usize;
        let start = lines.len().saturating_sub(avail + inp.scroll.min(lines.len()));
        for (i, line) in lines.iter().skip(start).take(avail).enumerate() {
            cv.text(x, top + 1 + i as i32, &clip_text(line, w), INK2, Some(INSET));
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
    let Some(inner) = frame(cv, r, View::Plan, inp, b, vec![("j/k", "step")], vec![]) else {
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

fn activity(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let s = inp.s;
    let rows: Vec<&crate::proto::scenario::TranscriptLine> = s
        .transcript
        .iter()
        .filter(|l| l.kind == LineKind::Tool)
        .collect();
    let b = vec![Seg::bold(format!("{} events", rows.len()), GREEN)];
    let Some(inner) = frame(cv, r, View::Activity, inp, b, vec![], vec![]) else {
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
                "Every tool call and decision is listed here as it happens.",
            );
            return;
        }
        let (x, y, w, h) = (
            inner.x as i32,
            inner.y as i32,
            inner.width as i32,
            inner.height as i32,
        );
        let start = rows
            .len()
            .saturating_sub(h as usize + inp.scroll.min(rows.len()));
        for (i, l) in rows.iter().skip(start).take(h as usize).enumerate() {
            let yy = y + i as i32;
            let (g, gc) = l.tool_state.glyph_parts();
            let gcol = match gc {
                crate::proto::core::Token::Cyan => CYAN,
                crate::proto::core::Token::Red => RED,
                crate::proto::core::Token::Amber => AMBER,
                crate::proto::core::Token::Magenta => MAGENTA,
                _ => GREEN,
            };
            cv.text(x, yy, g, gcol, None);
            let k = kind_of(&l.tool_name);
            let x2 = cv.bold(x + 2, yy, &k, INK, None);
            cv.text(
                x2 + 1,
                yy,
                &clip_text(&l.text, w - 4 - text_width(&k)),
                MUTED,
                None,
            );
        }
    });
}

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
        let (x, y, w) = (inner.x as i32, inner.y as i32, inner.width as i32);
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
        let bw = (w - 2).max(4);
        let k = (ctx * bw as f32).round() as i32;
        cv.text(
            x,
            y + 1,
            &"▰".repeat(k as usize),
            mix(CYAN, if ctx > 0.85 { AMBER } else { CYAN }, ctx),
            None,
        );
        cv.text(x + k, y + 1, &"▱".repeat((bw - k) as usize), RULE_HI, None);
        cv.text(
            x,
            y + 3,
            &format!("{} of {} tokens", s.used_tokens, s.window_tokens),
            INK2,
            None,
        );
        cv.text(
            x,
            y + 5,
            &format!("in {}  out {}", s.input_tokens, s.output_tokens),
            MUTED,
            None,
        );
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
        vec![("j/k", "file"), ("n/p", "hunk"), ("u", "revert hunk")],
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
        for (i, f) in files.iter().enumerate() {
            let yy = y + 1 + i as i32;
            if yy >= y + h {
                break;
            }
            let sel = i == 0;
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
                &clip_text(&f.path, lw - 4 - text_width(&cnt)),
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
        if let Some(f) = files.first() {
            cv.bold(rx, y, &clip_text(&f.path, rw), BLUE, None);
            cv.text(
                rx,
                y + 2,
                &clip_text(
                    "The diff appears here once the engine sends hunks for this change.",
                    rw,
                ),
                MUTED,
                None,
            );
        }
    });
}

fn agent(cv: &mut Cv, r: Rect, inp: &PaneIn) {
    let s = inp.s;
    let mine: Vec<_> = s
        .agents
        .values()
        .filter(|a| inp.agent.is_empty() || a.name == inp.agent)
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
        let (x, y, w) = (inner.x as i32, inner.y as i32, inner.width as i32);
        for (i, a) in mine.iter().enumerate() {
            let yy = y + i as i32 * 3;
            // M15: arcs turn at 10 fps.
            let arc = if inp.reduced {
                "●"
            } else {
                ["◜", "◝", "◞", "◟"][((secs(inp.now_ms) * 10.0) as usize) & 3]
            };
            cv.bold(
                x,
                yy,
                if a.done { "✓" } else { arc },
                if a.done { GREEN } else { CYAN },
                None,
            );
            cv.bold(x + 2, yy, &clip_text(&a.name, w - 3), INK, None);
            cv.text(x + 2, yy + 1, &clip_text(&a.action, w - 3), MUTED, None);
        }
    });
}
