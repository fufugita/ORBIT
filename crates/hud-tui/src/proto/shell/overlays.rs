//! Overlays in the prototype's style: the command palette (rows drop in
//! at 12 ms each, the selection bar glides), help, the quit card, the
//! "show what?" picker, toasts that slide in with a draining line, and
//! the big panel numbers shown while arranging.

use super::canvas::{clip_text, mix, segs_width, text_width, tint, Cv, Rgb, Seg};
use super::frame::{hints_width, keyhints};
use super::motion::{ease_in_out, ease_out, prog, secs};
use super::pal::*;
use crate::proto::chrome::{subsequence, COMMANDS};
use crate::proto::layout::View;
use ratatui::layout::Rect;
use ratatui::style::Modifier;

/// What to draw on top, with its own clock.
pub enum Overlay<'a> {
    Palette {
        query: &'a str,
        sel: usize,
        sel_prev: usize,
        opened_ms: u64,
        sel_ms: u64,
    },
    Help {
        opened_ms: u64,
    },
    Quit {
        turn_live: bool,
    },
    /// The full diff of a changed file (M11): the bounded hunks carried
    /// by the FileChanged event, or the honest "no diff captured" note.
    Diff {
        path: &'a str,
        added: u32,
        removed: u32,
        hunks: &'a Option<Vec<orbit_frontend_protocol::DiffHunk>>,
        opened_ms: u64,
    },
}

/// A framed, shadowed box in the prototype's `┏━┓` magenta style with
/// a title chip. `reveal` rows are visible (the drop-in).
fn frame_box(cv: &mut Cv, x: i32, y: i32, w: i32, h: i32, reveal: i32, title: &str) {
    cv.veil(x + 1, y + 1, w, reveal, (0, 0, 0), 0.45);
    cv.fill(x, y, w, reveal, RAISE);
    cv.clipped(
        Rect {
            x: x.max(0) as u16,
            y: y.max(0) as u16,
            width: w as u16,
            height: reveal.max(0) as u16,
        },
        |cv| {
            cv.text(
                x,
                y,
                &format!("┏{}┓", "━".repeat((w - 2) as usize)),
                MAGENTA,
                Some(RAISE),
            );
            for j in 1..h - 1 {
                cv.text(x, y + j, "┃", MAGENTA, Some(RAISE));
                cv.text(x + w - 1, y + j, "┃", MAGENTA, Some(RAISE));
            }
            cv.text(
                x,
                y + h - 1,
                &format!("┗{}┛", "━".repeat((w - 2) as usize)),
                MAGENTA,
                Some(RAISE),
            );
            cv.put(
                x + 3,
                y,
                &format!(" {title} "),
                ON_ACCENT,
                Some(MAGENTA),
                Modifier::BOLD,
            );
        },
    );
}

/// The palette's matching commands for `query`.
pub fn palette_items(query: &str) -> Vec<(&'static str, &'static str)> {
    let q = query.trim_start_matches('/');
    COMMANDS
        .iter()
        .filter(|(c, _)| subsequence(q, c.trim_start_matches('/')))
        .copied()
        .collect()
}

pub fn draw(cv: &mut Cv, w: i32, h: i32, ov: &Overlay, now_ms: u64, reduced: bool) {
    match ov {
        Overlay::Palette {
            query,
            sel,
            sel_prev,
            opened_ms,
            sel_ms,
        } => palette(
            cv, w, query, *sel, *sel_prev, *opened_ms, *sel_ms, now_ms, reduced,
        ),
        Overlay::Help { opened_ms } => help(cv, w, h, *opened_ms, now_ms, reduced),
        Overlay::Quit { turn_live } => quit(cv, w, h, *turn_live),
        Overlay::Diff {
            path,
            added,
            removed,
            hunks,
            opened_ms,
        } => diff(
            cv, w, h, path, *added, *removed, hunks, *opened_ms, now_ms, reduced,
        ),
    }
}

/// The diff overlay (M11): `@@` headers, `-`/`+` lines in red/green,
/// context in muted ink — bounded by what the event carried. When no
/// "before" existed (an uncheckpointed write, or a fixture without
/// hunks) it says so plainly instead of inventing a diff.
#[allow(clippy::too_many_arguments)]
fn diff(
    cv: &mut Cv,
    w: i32,
    h: i32,
    path: &str,
    added: u32,
    removed: u32,
    hunks: &Option<Vec<orbit_frontend_protocol::DiffHunk>>,
    opened_ms: u64,
    now_ms: u64,
    reduced: bool,
) {
    // The box is 8 rows of chrome (border, blank, header, rule, blank,
    // … content …, blank, footer, border) around its content, and keeps
    // a row of screen on each side.
    let rows_avail = h.saturating_sub(10) as usize;
    // The overlay's rows: hunk headers + lines.
    let body: Vec<(char, String)> = match hunks {
        Some(hs) => super::diffrows::rows(hs).0,
        None => Vec::new(),
    };
    // A diff taller than the screen gives its last row to "N more"
    // rather than cutting a line off silently.
    let cut = body.len() > rows_avail && rows_avail > 0;
    let shown = if cut { rows_avail - 1 } else { body.len() };
    // A note (no diff to show) takes two rows.
    let content = if matches!(hunks, Some(hs) if !hs.is_empty()) {
        shown + cut as usize
    } else {
        2
    };
    let box_h = (content as i32 + 8).min(h.saturating_sub(2));
    let box_w = (w.saturating_sub(8)).clamp(30, 100);
    let x = (w - box_w) / 2;
    let y = (h - box_h) / 2;
    let reveal = (ease_out(prog(secs(now_ms), Some(secs(opened_ms)), 0.22, reduced)) * box_h as f32)
        .round() as i32;

    frame_box(cv, x, y, box_w, box_h, reveal, "diff");
    if reveal < box_h {
        return;
    }
    cv.clipped(
        Rect {
            x: x as u16,
            y: y as u16,
            width: box_w as u16,
            height: box_h as u16,
        },
        |cv| {
            // Header: path + counts.
            let p = clip_text(path, box_w - 16);
            cv.bold(x + 2, y + 2, &p, INK, Some(RAISE));
            let mut cnt = vec![Seg::bold(format!("+{added}"), GREEN)];
            if removed > 0 {
                cnt.push(Seg::bold(format!(" −{removed}"), RED));
            }
            let cw = segs_width(&cnt);
            cv.spans(x + box_w - 2 - cw, y + 2, &cnt, Some(RAISE));
            // Rule under the header.
            cv.text(
                x + 2,
                y + 3,
                &"─".repeat((box_w - 4) as usize),
                RULE,
                Some(RAISE),
            );

            match hunks {
                None => {
                    cv.text(x + 3, y + 5, "◌ no diff captured", MUTED, Some(RAISE));
                    cv.text(
                        x + 3,
                        y + 6,
                        &clip_text(
                            "this change arrived without a \"before\" to diff against",
                            box_w - 6,
                        ),
                        FAINT,
                        Some(RAISE),
                    );
                }
                Some(hs) if hs.is_empty() => {
                    cv.text(x + 3, y + 5, "◌ no visible changes", MUTED, Some(RAISE));
                    cv.text(
                        x + 3,
                        y + 6,
                        &clip_text("the edit touched only lines the bounds cut", box_w - 6),
                        FAINT,
                        Some(RAISE),
                    );
                }
                Some(_) => {
                    super::diffrows::draw(cv, x + 2, y + 5, box_w - 4, &body[..shown], RAISE);
                    if cut {
                        cv.text(
                            x + 2,
                            y + 5 + shown as i32,
                            &clip_text(&format!("… {} more lines", body.len() - shown), box_w - 4),
                            FAINT,
                            Some(RAISE),
                        );
                    }
                }
            }
            // Footer hint.
            let hint = "esc close";
            cv.text(
                x + box_w - 2 - text_width(hint),
                y + box_h - 2,
                hint,
                FAINT,
                Some(RAISE),
            );
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn palette(
    cv: &mut Cv,
    sw: i32,
    query: &str,
    sel: usize,
    sel_prev: usize,
    opened_ms: u64,
    sel_ms: u64,
    now_ms: u64,
    reduced: bool,
) {
    let w = 70.min(sw - 8);
    let (x, y) = ((sw - w) / 2, 4);
    let items = palette_items(query);
    let shown = items.len().min(9) as i32;
    let h = shown.max(1) + 5;
    // Rows drop in at 12 ms each.
    let reveal = if reduced {
        h
    } else {
        h.min((now_ms.saturating_sub(opened_ms) / 12) as i32 + 2)
    };
    frame_box(cv, x, y, w, h, reveal, "COMMANDS");
    cv.clipped(
        Rect {
            x: x.max(0) as u16,
            y: y.max(0) as u16,
            width: w as u16,
            height: reveal.max(0) as u16,
        },
        |cv| {
            cv.hit(x, y, w, h, super::hits::Click::Inert);
            cv.fill(x + 2, y + 1, w - 4, 1, INSET);
            cv.bold(x + 3, y + 1, "›", MAGENTA, Some(INSET));
            let e = cv.text(x + 5, y + 1, query, INK, Some(INSET));
            cv.text(e, y + 1, "▏", INK, Some(INSET));
            if query.is_empty() {
                cv.text(e + 1, y + 1, "type to filter", FAINT, Some(INSET));
            }
            // The selection bar glides between rows.
            let p = ease_out(prog(secs(now_ms), Some(secs(sel_ms)), 0.08, reduced));
            let sel_y =
                y + 3 + (sel_prev as f32 + (sel as f32 - sel_prev as f32) * p).round() as i32;
            if items.is_empty() {
                cv.text(x + 4, y + 3, "no matching command", MUTED, Some(RAISE));
            }
            for (i, (cmd, desc)) in items.iter().take(9).enumerate() {
                let ry = y + 3 + i as i32;
                cv.hit(x + 1, ry, w - 2, 1, super::hits::Click::Palette(i));
                let on = i == sel;
                let q: Vec<char> = query
                    .trim_start_matches('/')
                    .to_lowercase()
                    .chars()
                    .collect();
                let mut qi = 0;
                let mut xx = x + 4;
                for ch in cmd.chars() {
                    let hit = qi < q.len() && ch.to_ascii_lowercase() == q[qi];
                    if hit {
                        qi += 1;
                    }
                    let col = if hit {
                        MAGENTA_HI
                    } else if on {
                        INK
                    } else {
                        INK2
                    };
                    xx = cv.put(
                        xx,
                        ry,
                        &ch.to_string(),
                        col,
                        Some(RAISE),
                        if hit || on {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        },
                    );
                }
                cv.text(x + 22, ry, &clip_text(desc, w - 26), MUTED, Some(RAISE));
            }
            if sel_y >= y + 3 && sel_y < y + 3 + shown {
                cv.wash(x + 1, sel_y, w - 2, 1, tint(MAGENTA, RAISE, 0.16));
                cv.text(x + 2, sel_y, "▌", MAGENTA, Some(tint(MAGENTA, RAISE, 0.16)));
            }
            keyhints(
                cv,
                x + 3,
                y + h - 1,
                &[("↑↓", "move"), ("⏎", "run"), ("esc", "close")],
                Some(RAISE),
            );
        },
    );
}

fn help(cv: &mut Cv, sw: i32, sh: i32, opened_ms: u64, now_ms: u64, reduced: bool) {
    let left: [(&str, Vec<(&str, &str)>); 3] = [
        (
            "TYPING",
            vec![
                ("⏎", "send, or queue while busy"),
                ("⇧⏎  alt+⏎", "new line"),
                ("↑  ↓", "history"),
                ("pgup  pgdn", "scroll the transcript"),
                ("/", "commands"),
                ("!", "run your own command"),
                ("⇧tab", "cycle mode"),
                ("esc", "arrange panels"),
            ],
        ),
        (
            "APPROVALS",
            vec![
                ("y", "allow once"),
                ("R", "allow this tool for the session"),
                ("n  esc", "deny"),
            ],
        ),
        (
            "ANYWHERE",
            vec![
                ("tab  1-9", "move between panels"),
                ("?", "this help"),
                ("⌃c", "quit card"),
            ],
        ),
    ];
    let right: [(&str, Vec<(&str, &str)>); 1] = [(
        "ARRANGE  · esc",
        vec![
            ("h j k l", "move focus"),
            ("H J K L", "swap with the next panel"),
            ("v", "split right, then pick"),
            ("s", "split down, then pick"),
            ("p", "change what this shows"),
            ("x", "close this panel"),
            ("< >  - +", "resize"),
            ("=", "even out every split"),
            ("b", "show or hide the sidebar"),
            ("[ ]", "columns · build · agents · review"),
            ("i  ⏎", "back to typing"),
        ],
    )];
    let rows = |col: &[(&str, Vec<(&str, &str)>)]| -> i32 {
        col.iter()
            .enumerate()
            .map(|(i, (_, k))| (if i > 0 { 1 } else { 0 }) + 2 + k.len() as i32)
            .sum()
    };
    let w = 88.min(sw - 6);
    let h = rows(&left).max(rows(&right)) + 4;
    let (x, y) = ((sw - w) / 2, ((sh - h) / 2).max(1));
    let a = ease_out(prog(secs(now_ms), Some(secs(opened_ms)), 0.14, reduced));
    let hh = ((h as f32) * (0.6 + 0.4 * a)).round() as i32;
    frame_box(cv, x, y, w, h, hh.max(3), "KEYS");
    cv.clipped(
        Rect {
            x: x.max(0) as u16,
            y: y.max(0) as u16,
            width: w as u16,
            height: hh.max(3) as u16,
        },
        |cv| {
            let col_w = (w - 6) / 2;
            let mut draw_col = |col: &[(&str, Vec<(&str, &str)>)], ci: i32| {
                let cx = x + 3 + ci * (col_w + 1);
                let mut cy = y + 2;
                for (i, (title, keys)) in col.iter().enumerate() {
                    if i > 0 {
                        cy += 1;
                    }
                    cv.bold(
                        cx,
                        cy,
                        title,
                        if ci == 1 { CYAN } else { FAINT },
                        Some(RAISE),
                    );
                    cy += 2;
                    for (k, l) in keys {
                        cv.bold(cx, cy, k, INK, Some(RAISE));
                        cv.text(cx + 11, cy, &clip_text(l, col_w - 12), INK2, Some(RAISE));
                        cy += 1;
                    }
                }
            };
            draw_col(&left, 0);
            draw_col(&right, 1);
        },
    );
}

fn quit(cv: &mut Cv, sw: i32, sh: i32, turn_live: bool) {
    let w = 46.min(sw - 4);
    let h = if turn_live { 8 } else { 7 };
    let (x, y) = ((sw - w) / 2, (sh - h) / 2);
    frame_box(cv, x, y, w, h, h, "QUIT ORBIT?");
    let line = if turn_live {
        "A turn is running. Quitting stops it."
    } else {
        "Your session is saved. Resume it any time."
    };
    cv.text(x + 3, y + 2, &clip_text(line, w - 6), INK2, Some(RAISE));
    if turn_live {
        cv.text(
            x + 3,
            y + 3,
            "Running tools are killed with it.",
            MUTED,
            Some(RAISE),
        );
    }
    cv.hit(x, y, w, h, super::hits::Click::Inert);
    let ky = y + h - 2;
    let mut kx = x + 3;
    for (k, l, hot) in [("y", "quit", true), ("n", "stay", false)] {
        let from = kx;
        kx = super::frame::keycap(cv, kx, ky, k, hot);
        kx = cv.text(kx + 1, ky, l, INK2, Some(RAISE));
        if let Some((code, mods)) = super::hits::parse_key(k) {
            cv.hit(from, ky, kx - from, 1, super::hits::Click::Key(code, mods));
        }
        kx += 3;
    }
}

/// The "show what?" picker: rows drop in at 12 ms each.
pub fn picker(cv: &mut Cv, sw: i32, sh: i32, opened_ms: u64, now_ms: u64, reduced: bool) {
    let views = super::PICKER_VIEWS;
    let (bw, bh) = (36, views.len() as i32 + 5);
    let (x, y) = ((sw - bw) / 2, (sh - bh) / 2);
    let reveal = if reduced {
        bh
    } else {
        bh.min((now_ms.saturating_sub(opened_ms) / 12) as i32 + 2)
    };
    frame_box(cv, x, y, bw, bh, reveal, "SHOW WHAT?");
    cv.clipped(
        Rect {
            x: x.max(0) as u16,
            y: y.max(0) as u16,
            width: bw as u16,
            height: reveal.max(0) as u16,
        },
        |cv| {
            cv.hit(x, y, bw, bh, super::hits::Click::Inert);
            for (i, v) in views.iter().enumerate() {
                let yy = y + 2 + i as i32;
                // A row picks its view, like the digit that names it.
                if let Some(d) = char::from_digit(i as u32 + 1, 10) {
                    cv.hit(
                        x + 2,
                        yy,
                        bw - 4,
                        1,
                        super::hits::Click::Key(
                            crossterm::event::KeyCode::Char(d),
                            crossterm::event::KeyModifiers::NONE,
                        ),
                    );
                }
                let col = ident(*v);
                cv.put(
                    x + 3,
                    yy,
                    &format!(" {} ", i + 1),
                    ON_ACCENT,
                    Some(col),
                    Modifier::BOLD,
                );
                cv.text(x + 8, yy, v.title(), INK2, Some(RAISE));
            }
            keyhints(
                cv,
                x + 3,
                y + bh - 1,
                &[("1-8", "pick"), ("esc", "cancel")],
                Some(RAISE),
            );
        },
    );
}

fn ident(v: View) -> Rgb {
    match v {
        View::Conversation | View::Agent => MAGENTA,
        View::Changes | View::Review => VIOLET,
        View::Terminal => AMBER,
        View::Plan => CYAN,
        View::Activity => GREEN,
        View::Context => BLUE,
    }
}

/// A toast: slides in over 160 ms, stays, drains a line, slides out.
#[allow(clippy::too_many_arguments)]
pub fn toast(
    cv: &mut Cv,
    sw: i32,
    sh: i32,
    text: &str,
    ok: bool,
    shown_ms: u64,
    ttl_ms: u64,
    now_ms: u64,
    reduced: bool,
) {
    let age = secs(now_ms.saturating_sub(shown_ms));
    let ttl = secs(ttl_ms);
    if age > ttl + 0.2 {
        return;
    }
    let w = text_width(text) + 6;
    let in_p = ease_out(prog(secs(now_ms), Some(secs(shown_ms)), 0.16, reduced));
    let out_p = if age > ttl {
        ease_in_out(prog(
            secs(now_ms),
            Some(secs(shown_ms) + ttl),
            0.16,
            reduced,
        ))
    } else {
        0.0
    };
    let x = (sw as f32 - 2.0 - w as f32 + (w + 2) as f32 * (1.0 - in_p) + (w + 2) as f32 * out_p)
        .round() as i32;
    let y = sh - 4;
    let col = if ok { GREEN } else { VIOLET };
    let bg = tint(col, RAISE, 0.14);
    cv.veil(x + 1, y + 1, w, 2, (0, 0, 0), 0.4);
    cv.fill(x, y, w, 2, bg);
    cv.text(x, y, "▌", col, Some(bg));
    cv.text(x, y + 1, "▌", col, Some(bg));
    cv.bold(x + 2, y, if ok { "✓" } else { "✦" }, col, Some(bg));
    cv.text(x + 4, y, text, INK, Some(bg));
    // The drain line shows how long the toast stays.
    let left = if reduced {
        1.0
    } else {
        (1.0 - age / ttl).clamp(0.0, 1.0)
    };
    let n = ((w - 2) as f32 * left).round() as i32;
    for i in 0..w - 2 {
        cv.text(
            x + 1 + i,
            y + 1,
            "▁",
            if i < n { mix(bg, col, 0.7) } else { bg },
            Some(bg),
        );
    }
}

const BIGNUM: [[&str; 3]; 9] = [
    ["▄█ ", " █ ", "▄█▄"],
    ["▀▀▄", "▄▀ ", "█▄▄"],
    ["▀▀▄", " ▀▄", "▄▄▀"],
    ["█ █", "▀▀█", "  █"],
    ["█▀▀", "▀▀▄", "▄▄▀"],
    ["▄▀▀", "█▀▄", "▀▄▀"],
    ["▀▀█", " ▄▀", " █ "],
    ["▄▀▄", "▄▀▄", "▀▄▀"],
    ["▄▀▄", "▀▄█", "▄▄▀"],
];

/// The big panel number and name shown over a dimmed panel (arranging).
pub fn nav_badge(cv: &mut Cv, r: Rect, num: usize, col: Rgb, a: f32, label: &str) {
    let (rx, ry, rw, rh) = (r.x as i32, r.y as i32, r.width as i32, r.height as i32);
    let (bw, bh) = (9, 5);
    if rw < bw + 2 || rh < bh + 2 {
        if rw >= 5 && rh >= 3 {
            cv.put(
                rx + (rw - 3) / 2,
                ry + rh / 2,
                &format!(" {num} "),
                ON_ACCENT,
                Some(col),
                Modifier::BOLD,
            );
        }
        return;
    }
    let bx = rx + (rw - bw) / 2;
    let by = ry + (rh - bh) / 2;
    if rh >= bh + 6 && rw >= 8 {
        let lb = format!(" {} ", clip_text(label, rw - 6));
        let lbg = tint(col, APP, 0.28 * a);
        cv.put(
            rx + (rw - text_width(&lb)) / 2,
            by + bh + 1,
            &lb,
            mix(lbg, WHITE, a),
            Some(lbg),
            Modifier::BOLD,
        );
    }
    let bg = tint(col, APP, 0.28 * a);
    let edge = mix(bg, col, a);
    cv.fill(bx, by, bw, bh, bg);
    cv.text(
        bx,
        by,
        &format!("╭{}╮", "─".repeat((bw - 2) as usize)),
        edge,
        Some(bg),
    );
    for j in 1..bh - 1 {
        cv.text(bx, by + j, "│", edge, Some(bg));
        cv.text(bx + bw - 1, by + j, "│", edge, Some(bg));
    }
    cv.text(
        bx,
        by + bh - 1,
        &format!("╰{}╯", "─".repeat((bw - 2) as usize)),
        edge,
        Some(bg),
    );
    let g = BIGNUM[(num.clamp(1, 9)) - 1];
    for (j, row) in g.iter().enumerate() {
        cv.put(
            bx + 3,
            by + 1 + j as i32,
            row,
            mix(bg, WHITE, a),
            Some(bg),
            Modifier::BOLD,
        );
    }
    let _ = hints_width;
}
