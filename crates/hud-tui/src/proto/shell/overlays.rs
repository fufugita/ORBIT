//! Overlays in the prototype's style: the command palette (rows drop in
//! at 12 ms each, the selection bar glides), help, the quit card, the
//! "show what?" picker, toasts that slide in with a draining line, and
//! the big panel numbers shown while arranging.

use super::canvas::{Cv, Rgb, Seg, clip_text, mix, segs_width, text_width, tint};
use super::frame::{hints_width, keyhints};
use super::motion::{ease_in_out, ease_out, prog, secs};
use super::pal::Palette;
use crate::proto::chrome::{COMMANDS, subsequence};
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
    /// The model/session picker: one selection bar over plain rows.
    Picker {
        title: &'static str,
        rows: &'a [super::super::scenario::PickerRow],
        sel: usize,
        opened_ms: u64,
    },
}

/// A framed, shadowed box in the prototype's `┏━┓` magenta style with
/// a title chip. `reveal` rows are visible (the drop-in).
fn frame_box(cv: &mut Cv, x: i32, y: i32, w: i32, h: i32, reveal: i32, title: &str) {
    let colors = cv.palette;
    cv.veil(x + 1, y + 1, w, reveal, (0, 0, 0), 0.45);
    cv.fill(x, y, w, reveal, colors.raise);
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
                colors.magenta,
                Some(colors.raise),
            );
            for j in 1..h - 1 {
                cv.text(x, y + j, "┃", colors.magenta, Some(colors.raise));
                cv.text(x + w - 1, y + j, "┃", colors.magenta, Some(colors.raise));
            }
            cv.text(
                x,
                y + h - 1,
                &format!("┗{}┛", "━".repeat((w - 2) as usize)),
                colors.magenta,
                Some(colors.raise),
            );
            cv.put(
                x + 3,
                y,
                &format!(" {title} "),
                colors.on_accent,
                Some(colors.magenta),
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
            cv, w, h, query, *sel, *sel_prev, *opened_ms, *sel_ms, now_ms, reduced,
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
        Overlay::Picker {
            title,
            rows,
            sel,
            opened_ms,
        } => choice_picker(cv, w, h, title, rows, *sel, *opened_ms, now_ms, reduced),
    }
}

/// The model/session picker: the palette's frame and selection bar,
/// over plain rows (no typing, no matching).
#[allow(clippy::too_many_arguments)]
fn choice_picker(
    cv: &mut Cv,
    sw: i32,
    sh: i32,
    title: &str,
    rows: &[super::super::scenario::PickerRow],
    sel: usize,
    opened_ms: u64,
    now_ms: u64,
    reduced: bool,
) {
    // A frame needs two borders, one spacer and at least one row. Clamp
    // before converting dimensions to unsigned buffer coordinates.
    let sw = sw.clamp(0, i32::from(u16::MAX));
    let sh = sh.clamp(0, i32::from(u16::MAX));
    if sw < 8 || sh < 4 {
        return;
    }
    let colors = cv.palette;
    let session_rows = title == "SESSIONS";
    let row_height = if session_rows { 2 } else { 1 };
    let w = 76.min((sw - 8).max(8)).min(sw);
    let footer_rows = if session_rows { 1 } else { 0 };
    let minimum_content_height = if rows.is_empty() { 1 } else { row_height };
    let minimum_frame_height = minimum_content_height + 3;
    if session_rows && sh < minimum_frame_height + footer_rows {
        return;
    }
    let y = if session_rows {
        4.min((sh - minimum_frame_height - footer_rows).max(0))
    } else {
        4.min(sh - 4)
    };
    let x = (sw - w) / 2;
    let available_rows = sh - y - 3 - footer_rows;
    let rows_that_fit = available_rows / row_height;
    if !rows.is_empty() && rows_that_fit == 0 {
        return;
    }
    let capacity = rows_that_fit.clamp(1, 12) as usize;
    let selected = sel.min(rows.len().saturating_sub(1));
    let first = selected.saturating_sub(capacity - 1);
    let shown = rows.len().min(capacity) as i32;
    let content_height = if rows.is_empty() {
        1
    } else {
        shown * row_height
    };
    let h = content_height + 3;
    let reveal = if reduced {
        h
    } else {
        (now_ms.saturating_sub(opened_ms) / 12).min(h as u64) as i32 + 2
    };
    let reveal = reveal.min(h);
    frame_box(cv, x, y, w, h, reveal, title);
    cv.clipped(
        Rect {
            x: x.max(0) as u16,
            y: y.max(0) as u16,
            width: w as u16,
            height: reveal.max(0) as u16,
        },
        |cv| {
            cv.hit(x, y, w, h, super::hits::Click::Inert);
            if rows.is_empty() {
                cv.text(x + 4, y + 2, "no entries", colors.muted, Some(colors.raise));
            }
            for (i, row) in rows.iter().enumerate().skip(first).take(capacity) {
                let ry = y + 2 + (i - first) as i32 * row_height;
                cv.hit(x + 1, ry, w - 2, row_height, super::hits::Click::Picker(i));
                let on = i == selected;
                if on {
                    cv.fill(x + 1, ry, w - 2, row_height, colors.magenta);
                }
                let fg = if on { colors.on_accent } else { colors.ink };
                if on {
                    cv.text(x + 1, ry, "▌", colors.on_accent, Some(colors.magenta));
                    if row_height == 2 {
                        cv.text(x + 1, ry + 1, "▌", colors.on_accent, Some(colors.magenta));
                    }
                }
                let content_width = w - 6;
                let bg = Some(if on { colors.magenta } else { colors.raise });
                if session_rows {
                    let label = clip_text(&crate::bridge::safe_text(&row.label), content_width);
                    cv.text(x + 3, ry, &label, fg, bg);
                    let detail = clip_text(&crate::bridge::safe_text(&row.detail), content_width);
                    cv.text(
                        x + 3,
                        ry + 1,
                        &detail,
                        if on { colors.on_accent } else { colors.muted },
                        bg,
                    );
                } else {
                    let detail_width = if content_width >= 30 {
                        content_width / 3
                    } else {
                        0
                    };
                    let label_width = content_width - detail_width;
                    let label = clip_text(&crate::bridge::safe_text(&row.label), label_width);
                    cv.text(x + 3, ry, &label, fg, bg);
                    let detail = clip_text(&crate::bridge::safe_text(&row.detail), detail_width);
                    cv.text(
                        x + 3 + label_width,
                        ry,
                        &detail,
                        if on { colors.on_accent } else { colors.muted },
                        bg,
                    );
                }
            }
        },
    );
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
    let colors = cv.palette;
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
            cv.bold(x + 2, y + 2, &p, colors.ink, Some(colors.raise));
            let mut cnt = vec![Seg::bold(format!("+{added}"), colors.green)];
            if removed > 0 {
                cnt.push(Seg::bold(format!(" −{removed}"), colors.red));
            }
            let cw = segs_width(&cnt);
            cv.spans(x + box_w - 2 - cw, y + 2, &cnt, Some(colors.raise));
            // Rule under the header.
            cv.text(
                x + 2,
                y + 3,
                &"─".repeat((box_w - 4) as usize),
                colors.rule,
                Some(colors.raise),
            );

            match hunks {
                None => {
                    cv.text(
                        x + 3,
                        y + 5,
                        "◌ no diff captured",
                        colors.muted,
                        Some(colors.raise),
                    );
                    cv.text(
                        x + 3,
                        y + 6,
                        &clip_text(
                            "this change arrived without a \"before\" to diff against",
                            box_w - 6,
                        ),
                        colors.faint,
                        Some(colors.raise),
                    );
                }
                Some(hs) if hs.is_empty() => {
                    cv.text(
                        x + 3,
                        y + 5,
                        "◌ no visible changes",
                        colors.muted,
                        Some(colors.raise),
                    );
                    cv.text(
                        x + 3,
                        y + 6,
                        &clip_text("the edit touched only lines the bounds cut", box_w - 6),
                        colors.faint,
                        Some(colors.raise),
                    );
                }
                Some(_) => {
                    super::diffrows::draw(
                        cv,
                        x + 2,
                        y + 5,
                        box_w - 4,
                        &body[..shown],
                        colors.raise,
                    );
                    if cut {
                        cv.text(
                            x + 2,
                            y + 5 + shown as i32,
                            &clip_text(&format!("… {} more lines", body.len() - shown), box_w - 4),
                            colors.faint,
                            Some(colors.raise),
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
                colors.faint,
                Some(colors.raise),
            );
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn palette(
    cv: &mut Cv,
    sw: i32,
    sh: i32,
    query: &str,
    sel: usize,
    sel_prev: usize,
    opened_ms: u64,
    sel_ms: u64,
    now_ms: u64,
    reduced: bool,
) {
    let colors = cv.palette;
    let w = 70.min(sw - 8);
    let y = 4.min((sh - 6).max(0));
    let x = (sw - w) / 2;
    let items = palette_items(query);
    let capacity = (sh - y - 5).clamp(1, 9) as usize;
    let selected = sel.min(items.len().saturating_sub(1));
    let first = selected.saturating_sub(capacity - 1);
    let shown = items.len().min(capacity) as i32;
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
            cv.fill(x + 2, y + 1, w - 4, 1, colors.inset);
            cv.bold(x + 3, y + 1, "›", colors.magenta, Some(colors.inset));
            let e = cv.text(x + 5, y + 1, query, colors.ink, Some(colors.inset));
            cv.text(e, y + 1, "▏", colors.ink, Some(colors.inset));
            if query.is_empty() {
                cv.text(
                    e + 1,
                    y + 1,
                    "type to filter",
                    colors.faint,
                    Some(colors.inset),
                );
            }
            // The selection bar glides between rows.
            let p = ease_out(prog(secs(now_ms), Some(secs(sel_ms)), 0.08, reduced));
            let previous = sel_prev.clamp(first, first + shown.max(1) as usize - 1) - first;
            let current = selected - first;
            let sel_y =
                y + 3 + (previous as f32 + (current as f32 - previous as f32) * p).round() as i32;
            if items.is_empty() {
                cv.text(
                    x + 4,
                    y + 3,
                    "no matching command",
                    colors.muted,
                    Some(colors.raise),
                );
            }
            for (i, (cmd, desc)) in items.iter().enumerate().skip(first).take(capacity) {
                let ry = y + 3 + (i - first) as i32;
                cv.hit(x + 1, ry, w - 2, 1, super::hits::Click::Palette(i));
                let on = i == selected;
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
                        colors.magenta_hi
                    } else if on {
                        colors.ink
                    } else {
                        colors.ink2
                    };
                    xx = cv.put(
                        xx,
                        ry,
                        &ch.to_string(),
                        col,
                        Some(colors.raise),
                        if hit || on {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        },
                    );
                }
                cv.text(
                    x + 22,
                    ry,
                    &clip_text(desc, w - 26),
                    colors.muted,
                    Some(colors.raise),
                );
            }
            if sel_y >= y + 3 && sel_y < y + 3 + shown {
                cv.wash(
                    x + 1,
                    sel_y,
                    w - 2,
                    1,
                    colors
                        .selection_override
                        .unwrap_or_else(|| tint(colors.magenta, colors.raise, 0.16)),
                );
                cv.text(
                    x + 2,
                    sel_y,
                    "▌",
                    colors.magenta,
                    Some(
                        colors
                            .selection_override
                            .unwrap_or_else(|| tint(colors.magenta, colors.raise, 0.16)),
                    ),
                );
            }
            keyhints(
                cv,
                x + 3,
                y + h - 1,
                &[("↑↓", "move"), ("⏎", "run"), ("esc", "close")],
                Some(colors.raise),
            );
        },
    );
}

fn help(cv: &mut Cv, sw: i32, sh: i32, opened_ms: u64, now_ms: u64, reduced: bool) {
    let colors = cv.palette;
    let left: [(&str, Vec<(&str, &str)>); 3] = [
        (
            "TYPING",
            vec![
                ("⏎", "send, or queue while busy"),
                ("⇧⏎  alt+⏎", "new line"),
                ("↑  ↓", "history"),
                ("pgup  pgdn", "scroll the transcript"),
                ("/", "commands"),
                ("/effort", "show or set request effort"),
                ("!", "run your own command"),
                ("⇧tab", "cycle mode"),
                ("esc", "arrange panels"),
            ],
        ),
        (
            "APPROVALS",
            vec![
                ("y", "allow once"),
                // The columns clip a description at 29 cells, and the
                // scope is the part of these lines that must not be cut.
                ("s", "this kind of call, session"),
                ("a", "same, saved in this folder"),
                ("n", "deny, with a word on why"),
                ("esc", "deny"),
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
    let right: [(&str, Vec<(&str, &str)>); 2] = [
        (
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
        ),
        (
            "DRAFT PICKERS",
            vec![
                ("@", "workspace files"),
                ("⌃r", "search history; older match"),
                ("tab", "accept a file suggestion"),
                ("⏎", "accept a file or search draft"),
                ("esc", "close files; restore search"),
            ],
        ),
    ];
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
                        if ci == 1 { colors.cyan } else { colors.faint },
                        Some(colors.raise),
                    );
                    cy += 2;
                    for (k, l) in keys {
                        cv.bold(cx, cy, k, colors.ink, Some(colors.raise));
                        cv.text(
                            cx + 11,
                            cy,
                            &clip_text(l, col_w - 12),
                            colors.ink2,
                            Some(colors.raise),
                        );
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
    let colors = cv.palette;
    let w = 46.min(sw - 4);
    let h = if turn_live { 8 } else { 7 };
    let (x, y) = ((sw - w) / 2, (sh - h) / 2);
    frame_box(cv, x, y, w, h, h, "QUIT ORBIT?");
    let line = if turn_live {
        "A turn is running. Quitting stops it."
    } else {
        "Your session is saved. Resume it any time."
    };
    cv.text(
        x + 3,
        y + 2,
        &clip_text(line, w - 6),
        colors.ink2,
        Some(colors.raise),
    );
    if turn_live {
        cv.text(
            x + 3,
            y + 3,
            "Running tools are killed with it.",
            colors.muted,
            Some(colors.raise),
        );
    }
    cv.hit(x, y, w, h, super::hits::Click::Inert);
    let ky = y + h - 2;
    let mut kx = x + 3;
    for (k, l, hot) in [("y", "quit", true), ("n", "stay", false)] {
        let from = kx;
        kx = super::frame::keycap(cv, kx, ky, k, hot);
        kx = cv.text(kx + 1, ky, l, colors.ink2, Some(colors.raise));
        if let Some((code, mods)) = super::hits::parse_key(k) {
            cv.hit(from, ky, kx - from, 1, super::hits::Click::Key(code, mods));
        }
        kx += 3;
    }
}

/// The "show what?" picker: rows drop in at 12 ms each.
pub fn picker(cv: &mut Cv, sw: i32, sh: i32, opened_ms: u64, now_ms: u64, reduced: bool) {
    let colors = cv.palette;
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
                let col = ident_themed(colors, *v);
                cv.put(
                    x + 3,
                    yy,
                    &format!(" {} ", i + 1),
                    colors.on_accent,
                    Some(col),
                    Modifier::BOLD,
                );
                cv.text(x + 8, yy, v.title(), colors.ink2, Some(colors.raise));
            }
            keyhints(
                cv,
                x + 3,
                y + bh - 1,
                &[("1-8", "pick"), ("esc", "cancel")],
                Some(colors.raise),
            );
        },
    );
}

fn ident_themed(colors: Palette, v: View) -> Rgb {
    match v {
        View::Conversation | View::Agent => colors.magenta,
        View::Custom => colors.cyan,

        View::Changes | View::Review => colors.violet,
        View::Terminal => colors.amber,
        View::Plan => colors.cyan,
        View::Activity => colors.green,
        View::Context => colors.blue,
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
    let sw = sw.clamp(0, i32::from(u16::MAX));
    let sh = sh.clamp(0, i32::from(u16::MAX));
    if sw < 8 || sh < 6 {
        return;
    }
    let colors = cv.palette;
    let age = secs(now_ms.saturating_sub(shown_ms));
    let ttl = secs(ttl_ms);
    if age > ttl + 0.2 {
        return;
    }
    let max_box_width = sw - 2;
    let text = clip_text(text, max_box_width - 6);
    let w = text_width(&text) + 6;
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
    let y = sh - 6;
    let col = if ok { colors.green } else { colors.violet };
    let bg = tint(col, colors.raise, 0.14);
    cv.veil(x + 1, y + 1, w, 2, (0, 0, 0), 0.4);
    cv.fill(x, y, w, 2, bg);
    cv.text(x, y, "▌", col, Some(bg));
    cv.text(x, y + 1, "▌", col, Some(bg));
    cv.bold(x + 2, y, if ok { "✓" } else { "✦" }, col, Some(bg));
    cv.text(x + 4, y, &text, colors.ink, Some(bg));
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
    let colors = cv.palette;
    let (rx, ry, rw, rh) = (r.x as i32, r.y as i32, r.width as i32, r.height as i32);
    let (bw, bh) = (9, 5);
    if rw < bw + 2 || rh < bh + 2 {
        if rw >= 5 && rh >= 3 {
            cv.put(
                rx + (rw - 3) / 2,
                ry + rh / 2,
                &format!(" {num} "),
                colors.on_accent,
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
        let lbg = tint(col, colors.app, 0.28 * a);
        cv.put(
            rx + (rw - text_width(&lb)) / 2,
            by + bh + 1,
            &lb,
            mix(lbg, colors.white, a),
            Some(lbg),
            Modifier::BOLD,
        );
    }
    let bg = tint(col, colors.app, 0.28 * a);
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
            mix(bg, colors.white, a),
            Some(bg),
            Modifier::BOLD,
        );
    }
    let _ = hints_width;
}

#[cfg(test)]
mod choice_picker_tests {
    use super::super::hits::{Click, Hit};
    use super::*;
    use crate::proto::scenario::PickerRow;
    use ratatui::buffer::Buffer;

    fn rows(count: usize) -> Vec<PickerRow> {
        (0..count)
            .map(|i| PickerRow {
                label: format!("model-{i}"),
                value: format!("value-{i}"),
                detail: "configured".into(),
            })
            .collect()
    }

    fn render(width: u16, height: u16, rows: &[PickerRow], sel: usize) -> (Buffer, Vec<Hit>) {
        render_title(width, height, rows, sel, "MODELS")
    }

    fn render_title(
        width: u16,
        height: u16,
        rows: &[PickerRow],
        sel: usize,
        title: &'static str,
    ) -> (Buffer, Vec<Hit>) {
        let mut buffer = Buffer::empty(Rect::new(0, 0, width, height));
        let hits = {
            let mut cv = Cv::new(&mut buffer);
            draw(
                &mut cv,
                i32::from(width),
                i32::from(height),
                &Overlay::Picker {
                    title,
                    rows,
                    sel,
                    opened_ms: 0,
                },
                u64::MAX,
                false,
            );
            cv.take_hits()
        };
        (buffer, hits)
    }

    fn line(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect()
    }

    #[test]
    fn selected_picker_row_stays_visible_and_clickable_after_long_list_navigation_and_resize() {
        let rows = rows(40);
        for (width, height) in [(100, 24), (80, 10), (24, 4)] {
            let (buffer, hits) = render(width, height, &rows, 27);
            let selected = hits
                .iter()
                .find(|hit| hit.click == Click::Picker(27))
                .unwrap();
            assert!(line(&buffer, selected.rect.y).contains("model-27"));
            assert_eq!(
                super::super::hits::at(&hits, selected.rect.x, selected.rect.y),
                Some(Click::Picker(27))
            );
            assert!(
                hits.iter()
                    .filter(|hit| matches!(hit.click, Click::Picker(_)))
                    .count()
                    <= 12
            );
            assert!(!hits.iter().any(|hit| hit.click == Click::Picker(0)));
            assert!(
                hits.iter()
                    .all(|hit| hit.rect.right() <= width && hit.rect.bottom() <= height)
            );
        }
    }

    #[test]
    fn sessions_picker_keeps_full_identity_and_both_lines_share_one_hit() {
        let id = "session-01JAB12CD34EF56GH78JK90MNP";
        let rows = vec![PickerRow {
            label: format!("{id}  (this session)"),
            value: id.into(),
            detail: "12 turns · mock/model-with-a-long-name".into(),
        }];
        let (buffer, hits) = render_title(80, 24, &rows, 0, "SESSIONS");
        let row = hits
            .iter()
            .find(|hit| hit.click == Click::Picker(0))
            .unwrap();
        assert_eq!(row.rect.height, 2);
        assert!(line(&buffer, row.rect.y).contains(id));
        assert!(line(&buffer, row.rect.y).contains("(this session)"));
        assert!(line(&buffer, row.rect.y + 1).contains("12 turns · mock/model-with-a-long-name"));
        for y in [row.rect.y, row.rect.y + 1] {
            assert_eq!(
                super::super::hits::at(&hits, row.rect.x, y),
                Some(Click::Picker(0))
            );
        }
    }

    #[test]
    fn sessions_picker_height_boundaries_and_scrolled_selection_stay_bounded() {
        let rows: Vec<_> = (0..40)
            .map(|i| PickerRow {
                label: format!("session-{i:02}"),
                value: format!("session-{i:02}"),
                detail: format!("{i} turns · mock/model · updated today"),
            })
            .collect();
        let (_, no_capacity_hits) = render_title(80, 5, &rows[..1], 0, "SESSIONS");
        assert!(
            no_capacity_hits.is_empty(),
            "zero capacity draws no partial picker"
        );

        let (minimum_buffer, minimum_hits) = render_title(80, 6, &rows[..1], 0, "SESSIONS");
        let minimum_picker_hits: Vec<_> = minimum_hits
            .iter()
            .filter(|hit| matches!(hit.click, Click::Picker(_)))
            .collect();
        assert_eq!(minimum_picker_hits.len(), 1);
        assert_eq!(minimum_picker_hits[0].rect.height, 2);
        assert!(minimum_hits.iter().all(|hit| hit.rect.bottom() <= 5));
        assert!(line(&minimum_buffer, 2).contains("session-00"));

        let (buffer, hits) = render_title(80, 24, &rows, 27, "SESSIONS");
        let picker_hits: Vec<_> = hits
            .iter()
            .filter(|hit| matches!(hit.click, Click::Picker(_)))
            .collect();
        assert_eq!(
            picker_hits.len(),
            8,
            "capacity uses two terminal rows plus footer reserve"
        );
        let selected = picker_hits
            .iter()
            .find(|hit| hit.click == Click::Picker(27))
            .expect("selected row remains visible while scrolled");
        assert_eq!(selected.rect.height, 2);
        assert!(line(&buffer, selected.rect.y).contains("session-27"));
        assert!(line(&buffer, selected.rect.y + 1).contains("27 turns · mock/model"));
        assert!(picker_hits.iter().all(|hit| hit.rect.bottom() <= 23));
        let frame = hits
            .iter()
            .find(|hit| hit.click == Click::Inert && hit.rect.width == 72)
            .expect("picker frame hit target exists");
        assert!(
            frame.rect.bottom() <= 23,
            "leave terminal row 23 for status/footer"
        );
        assert!(frame.rect.bottom() <= buffer.area.height);
    }

    #[test]
    fn picker_zero_tiny_empty_and_out_of_range_geometry_remains_bounded() {
        for width in 0..=12 {
            for height in 0..=8 {
                for rows in [Vec::new(), rows(20)] {
                    let (_, hits) = render(width, height, &rows, usize::MAX);
                    assert!(
                        hits.iter()
                            .all(|hit| hit.rect.right() <= width && hit.rect.bottom() <= height)
                    );
                    if width < 8 || height < 4 {
                        assert!(
                            hits.is_empty(),
                            "no usable picker frame at {width}x{height}"
                        );
                    }
                }
            }
        }
        let mut buffer = Buffer::empty(Rect::new(0, 0, 20, 8));
        let mut cv = Cv::new(&mut buffer);
        choice_picker(
            &mut cv,
            i32::MIN,
            i32::MIN,
            "MODELS",
            &rows(1),
            0,
            0,
            0,
            true,
        );
        assert!(cv.take_hits().is_empty());
    }

    #[test]
    fn picker_wide_labels_respect_detail_cells_and_untrusted_text_cannot_escape() {
        let rows = vec![
            PickerRow {
                label: "界".repeat(60),
                value: "wide".into(),
                detail: "DETAIL".into(),
            },
            PickerRow {
                label: "unsafe\u{1b}]52;c;YQ==\u{7}".into(),
                value: "untouched".into(),
                detail: "safe".into(),
            },
        ];
        let (buffer, hits) = render(80, 12, &rows, 0);
        let wide = hits
            .iter()
            .find(|hit| hit.click == Click::Picker(0))
            .unwrap();
        let detail_cells: Vec<_> = (wide.rect.x..wide.rect.right())
            .filter(|&x| buffer[(x, wide.rect.y)].symbol() == "D")
            .collect();
        assert_eq!(
            detail_cells.len(),
            1,
            "detail survives a label with double-width glyphs"
        );
        assert!(
            (detail_cells[0] + 6..wide.rect.right())
                .all(|x| buffer[(x, wide.rect.y)].symbol() != "界"),
            "wide label cannot spill through the detail column"
        );
        assert_eq!(buffer[(wide.rect.right(), wide.rect.y)].symbol(), "┃");
        assert!((0..buffer.area.height).all(|y| !line(&buffer, y).chars().any(|c| c.is_control())));
    }

    fn render_toast(width: u16, height: u16, text: &str) -> Buffer {
        let mut buffer = Buffer::empty(Rect::new(0, 0, width, height));
        let mut cv = Cv::new(&mut buffer);
        toast(
            &mut cv,
            i32::from(width),
            i32::from(height),
            text,
            false,
            0,
            3000,
            1000,
            true,
        );
        buffer
    }

    #[test]
    fn toast_clips_whole_graphemes_to_exact_and_one_cell_short_widths() {
        let text = "e\u{301}界";
        let exact_width = (text_width(text) + 8) as u16;
        let exact = render_toast(exact_width, 8, text);
        let exact_row = line(&exact, 2);
        assert!(exact_row.contains(text), "{exact_row:?}");
        assert!(text_width(&exact_row) <= i32::from(exact_width));

        let short_width = exact_width - 1;
        let short = render_toast(short_width, 8, text);
        let short_row = line(&short, 2);
        assert!(short_row.contains("e\u{301}…"), "{short_row:?}");
        assert!(!short_row.contains('界'), "{short_row:?}");
        assert!(text_width(&short_row) <= i32::from(short_width));
    }

    #[test]
    fn toast_keeps_its_actionable_prefix_inside_a_48_column_terminal() {
        let text = "wait for the active work to finish; draft retained";
        let buffer = render_toast(48, 16, text);
        let row = line(&buffer, 10);
        assert!(row.contains("wait for the active work"), "{row:?}");
        assert!(text_width(&row) <= 48);
        for y in 0..buffer.area.height {
            assert!(text_width(&line(&buffer, y)) <= 48);
        }
    }

    #[test]
    fn toast_omits_its_decoration_when_a_terminal_is_too_narrow() {
        for width in 0..8 {
            let buffer = render_toast(width, 8, "notice");
            for y in 0..buffer.area.height {
                assert!(line(&buffer, y).chars().all(|ch| ch == ' '));
            }
        }
        for height in 0..6 {
            let buffer = render_toast(48, height, "notice");
            for y in 0..buffer.area.height {
                assert!(line(&buffer, y).chars().all(|ch| ch == ' '));
            }
        }
    }
}
