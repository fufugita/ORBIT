//! The Conversation panel: user and ORBIT turns, tool cards, the turn
//! report, the approval card and the composer — ported from the
//! prototype's `userRows` / `orbitRows` / `cardRows` / `approvalCard` /
//! `composer`.

use super::canvas::{clip_text, mix, segs_width, text_width, tint, wrap_ranges, Cv, Rgb, Seg};
use super::frame::{badge_themed, fit_hints, keycap, keyhints, panel_frame, BadgeState, FrameSpec};
use super::mark::{draw_hero, Hero};
use super::motion::{ease_out, flash, prog, pulse, secs, shimmer, star_at};
use super::pal::Palette;
use crate::proto::scenario::{LineKind, Scenario, ToolState, TranscriptLine};
use crate::proto::welcome::BrandTier;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use unicode_width::UnicodeWidthChar;

type RowFn = Box<dyn Fn(&mut Cv, i32, i32)>;
type Row = Option<RowFn>;

/// Everything the panel reads.
pub struct ConvIn<'a> {
    pub s: &'a Scenario,
    pub now_ms: u64,
    pub reduced: bool,
    /// Colour effects off (16 colours or less): shimmer and the
    /// fresh-ink fade switch off.
    pub mono: bool,
    pub composer: &'a str,
    /// The highlighted row of the `/` command list.
    pub completion_sel: usize,
    pub file_completion: Option<&'a crate::proto::composer::FileCompletion>,
    pub history_search: Option<&'a crate::proto::composer::HistorySearch>,
    pub focused: bool,
    pub focus_fx: super::frame::FocusFx,
    pub scroll_offset: usize,
    pub num: usize,
    pub brand: BrandTier,
}

/// The tool-card kind chip for a tool name.
pub fn kind_of(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    let k = match n.as_str() {
        "read" | "read_file" | "view" => "READ",
        "grep" | "search" | "search_code" => "GREP",
        "glob" | "ls" | "list" | "list_dir" | "find" => "GLOB",
        "edit" | "edit_file" | "multiedit" | "patch" | "apply_patch" => "EDIT",
        "write" | "write_file" | "create" | "create_file" => "WRITE",
        "bash" | "shell" | "run" | "exec" | "run_command" | "terminal" => "BASH",
        "task" | "agent" | "subagent" | "spawn_agent" => "AGENT",
        "todo" | "todowrite" | "tasks" | "task_create" | "task_update" | "taskcreate"
        | "taskupdate" | "tasklist" => "TASKS",
        "taskstop" => "STOP",
        "fetch" | "web_fetch" | "webfetch" => "FETCH",
        "websearch" | "web_search" => "WEB",
        "notebookedit" => "EDIT",
        "ask" | "ask_user" | "askuserquestion" => "ASK",
        "exitplanmode" => "PLAN",
        // A tool from an MCP server: `mcp__<server>__<tool>`.
        _ if n.starts_with("mcp__") => "MCP",
        _ => return n.chars().take(5).collect::<String>().to_ascii_uppercase(),
    };
    k.to_string()
}

fn kind_colour_themed(colors: Palette, kind: &str) -> Rgb {
    match kind {
        "READ" | "GREP" | "GLOB" | "FETCH" | "WEB" => colors.blue,
        "EDIT" | "WRITE" => colors.violet,
        "BASH" | "STOP" => colors.amber,
        "TASKS" => colors.cyan,
        "AGENT" | "ASK" | "PLAN" => colors.magenta,
        _ => colors.ink2,
    }
}

/// Split model text into (plain chars, code mask): inline `code` spans
/// and ``` fenced lines are masked; the markers are dropped.
pub fn rich_plain(text: &str) -> (Vec<char>, Vec<bool>) {
    let mut plain = Vec::new();
    let mut mask = Vec::new();
    let mut fence = false;
    let lines: Vec<&str> = text.split('\n').collect();
    for (li, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("```") {
            fence = !fence;
            continue;
        }
        if fence {
            for ch in line.chars() {
                plain.push(ch);
                mask.push(true);
            }
        } else {
            let mut code = false;
            for ch in line.chars() {
                if ch == '`' {
                    code = !code;
                } else {
                    plain.push(ch);
                    mask.push(code);
                }
            }
        }
        if li + 1 < lines.len() {
            plain.push('\n');
            mask.push(false);
        }
    }
    (plain, mask)
}

fn user_rows_themed(colors: Palette, l: &TranscriptLine, w: i32) -> Vec<Row> {
    let time = l.time.clone().unwrap_or_default();
    let bg = tint(colors.magenta, colors.panel, 0.07);
    let (plain, mask) = rich_plain(&l.text);
    let text: String = plain.iter().collect();
    let lines = wrap_ranges(&text, w - 5 - if time.is_empty() { 0 } else { 7 });
    lines
        .into_iter()
        .enumerate()
        .map(|(i, (a, b))| {
            let plain = plain.clone();
            let mask = mask.clone();
            let time = time.clone();
            Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
                cv.fill(x, y, w, 1, bg);
                cv.text(x, y, "▎", colors.magenta, Some(bg));
                if i == 0 {
                    cv.bold(x + 2, y, "›", colors.magenta, Some(bg));
                    if !time.is_empty() {
                        cv.text(
                            x + w - 1 - time.chars().count() as i32,
                            y,
                            &time,
                            colors.faint,
                            Some(bg),
                        );
                    }
                }
                let mut in_at = false;
                for k in a..b.min(plain.len()) {
                    if plain[k] == '@' && (k == 0 || plain[k - 1] == ' ') {
                        in_at = true;
                    } else if plain[k] == ' ' {
                        in_at = false;
                    }
                    let cbg = if mask[k] { colors.raise2 } else { bg };
                    let (fg, m) = if in_at {
                        (colors.blue, Modifier::BOLD)
                    } else {
                        (colors.ink, Modifier::empty())
                    };
                    cv.put(
                        x + 4 + (k - a) as i32,
                        y,
                        &plain[k].to_string(),
                        fg,
                        Some(cbg),
                        m,
                    );
                }
                // The words, for a selection: not the `▎ ›` or the time.
                let words: String = plain[a.min(plain.len())..b.min(plain.len())]
                    .iter()
                    .collect();
                cv.hit(x + 4, y, text_width(&words), 1, super::hits::Click::Text);
            }) as RowFn)
        })
        .collect()
}

/// One displayed row of a reply: the chars it holds, and how a
/// continuation row of a list item or a quote sits.
#[derive(Debug, PartialEq, Eq)]
struct ReplyRow {
    a: usize,
    b: usize,
    /// Columns a continuation row is indented: under the item's text, not
    /// under its marker. 0 on the first row of a line.
    hang: usize,
    /// A continuation row of a quote repeats its `│` gutter.
    gutter: bool,
}

/// How far a wrapped line's later rows hang, and whether they carry the
/// quote gutter: a bullet or number hangs under its text, a quote under
/// the text after `│ `. Code is never a list.
fn hang_of(line: &[char], sty: &[super::md::Sty]) -> (usize, bool) {
    let indent = line.iter().take_while(|c| **c == ' ').count();
    let rest = &line[indent..];
    let Some(first) = sty.get(indent) else {
        return (0, false);
    };
    if first.code {
        return (0, false);
    }
    if first.quote && rest.first() == Some(&'│') {
        return (indent + 2, true);
    }
    if rest.first() == Some(&'•') && rest.get(1) == Some(&' ') {
        return (indent + 2, false);
    }
    let digits = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    if (1..=3).contains(&digits)
        && rest.get(digits) == Some(&'.')
        && rest.get(digits + 1) == Some(&' ')
    {
        return (indent + digits + 2, false);
    }
    (0, false)
}

/// Word-wrap one line (no newline in it) into char ranges: `first`
/// columns on the first row, `rest` on the others. A word longer than a
/// row is split; spaces at a break are dropped.
fn wrap_line(chars: &[char], first: usize, rest: usize) -> Vec<(usize, usize)> {
    let n = chars.len();
    if n == 0 {
        return vec![(0, 0)];
    }
    let mut out = Vec::new();
    let (mut i, mut w) = (0usize, first.max(1));
    while i < n {
        let mut end = (i + w).min(n);
        if end < n && chars[end] != ' ' {
            if let Some(sp) = chars[i..end].iter().rposition(|&c| c == ' ') {
                if sp > 0 {
                    end = i + sp;
                }
            }
        }
        out.push((i, end));
        i = end;
        while i < n && chars[i] == ' ' {
            i += 1;
        }
        w = rest.max(1);
    }
    out
}

/// The rows of a displayed reply at `width` columns. A line that ends in
/// a newline makes one row per wrapped piece; the empty line after the
/// final newline makes none, as before.
fn reply_rows(plain: &[char], sty: &[super::md::Sty], width: usize) -> Vec<ReplyRow> {
    let mut rows = Vec::new();
    let mut start = 0usize;
    loop {
        let end = plain[start..]
            .iter()
            .position(|&c| c == '\n')
            .map_or(plain.len(), |p| start + p);
        if start == plain.len() && start > 0 {
            break; // nothing after the last newline
        }
        let line = &plain[start..end];
        let (hang, gutter) = hang_of(line, &sty[start..end]);
        let hang = hang.min(width.saturating_sub(1));
        for (k, (ra, rb)) in wrap_line(line, width, width - hang).into_iter().enumerate() {
            rows.push(ReplyRow {
                a: start + ra,
                b: start + rb,
                hang: if k == 0 { 0 } else { hang },
                gutter: k > 0 && gutter,
            });
        }
        if end >= plain.len() {
            break;
        }
        start = end + 1;
    }
    rows
}

fn orbit_rows_themed(
    colors: Palette,
    l: &TranscriptLine,
    w: i32,
    live: bool,
    now_ms: u64,
    reduced: bool,
    mono: bool,
) -> Vec<Row> {
    let time = l.time.clone().unwrap_or_default();
    // The reply as the reader sees it: markdown markers gone, what they
    // meant kept as per-character style. Streaming arrival offsets count
    // raw chars; map them onto the displayed ones so the fresh-ink fade
    // keeps its place when markers drop.
    let width = (w - 5 - if time.is_empty() { 0 } else { 7 }).max(1) as usize;
    let md = super::md::rich_styled_fit(&l.text, width);
    let labels = md.labels.clone();
    let arrivals: Vec<(usize, u64)> = l
        .arrivals
        .iter()
        .map(|&(raw, ms)| (md.raw_to_plain[raw.min(md.raw_to_plain.len() - 1)], ms))
        .collect();
    let last_data = arrivals.last().map(|a| a.1);
    let (plain, sty) = (md.plain, md.sty);
    let lines = reply_rows(&plain, &sty, width);
    let n = lines.len();
    lines
        .into_iter()
        .enumerate()
        .map(|(i, row)| {
            let (a, b, hang, gutter) = (row.a, row.b, row.hang as i32, row.gutter);
            // A line of a fenced block is a band across the panel, with
            // the block's language tag right-aligned on its first row.
            let band = sty.get(a).is_some_and(|st| st.block);
            let tag = labels
                .iter()
                .find(|(at, _)| *at == a && (i > 0 || time.is_empty()))
                .map(|(_, t)| t.clone());
            let plain = plain.clone();
            let sty = sty.clone();
            let time = time.clone();
            let arrivals = arrivals.clone();
            Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
                if i == 0 {
                    cv.bold(
                        x + 2,
                        y,
                        "✦",
                        if live { colors.cyan } else { colors.magenta },
                        None,
                    );
                    if !time.is_empty() {
                        cv.text(
                            x + w - 1 - time.chars().count() as i32,
                            y,
                            &time,
                            colors.faint,
                            None,
                        );
                    }
                }
                if gutter {
                    cv.text(x + 4 + hang - 2, y, "│", colors.muted, None);
                }
                if band {
                    cv.fill(x + 3, y, w - 5, 1, colors.raise2);
                    if let Some(tag) = &tag {
                        let at = x + w - 3 - text_width(tag);
                        // Only where the code leaves room for it.
                        if at > x + 4 + (b - a) as i32 + 1 {
                            cv.text(at, y, tag, colors.muted, Some(colors.raise2));
                        }
                    }
                }
                for k in a..b.min(plain.len()) {
                    let st = sty[k];
                    let bg = if st.code { Some(colors.raise2) } else { None };
                    // What the markdown meant, as colour and weight. Magenta
                    // stays reserved for ORBIT and authority; emphasis is
                    // brightness, links are blue, furniture is muted.
                    let (target, mods) = if st.code {
                        let line_start = plain[..k]
                            .iter()
                            .rposition(|c| *c == '\n')
                            .map_or(0, |i| i + 1);
                        let prefix: String = plain[line_start..=k].iter().collect();
                        let c = plain[k];
                        let color = if prefix.trim_start().starts_with("//")
                            || prefix.trim_start().starts_with('#')
                        {
                            colors.syn_comment
                        } else if prefix.matches('"').count() % 2 == 1 || c == '"' {
                            colors.syn_str
                        } else if c.is_ascii_digit() {
                            colors.syn_num
                        } else if c.is_alphabetic() {
                            colors.syn_kw
                        } else {
                            colors.ink
                        };
                        (color, Modifier::empty())
                    } else if st.dim || st.quote {
                        (colors.muted, Modifier::empty())
                    } else if st.link {
                        (colors.blue, Modifier::UNDERLINED)
                    } else if st.heading > 0 {
                        (
                            if st.heading <= 2 {
                                colors.white
                            } else {
                                colors.ink
                            },
                            Modifier::BOLD,
                        )
                    } else if st.bold {
                        (mix(colors.ink, colors.white, 0.6), Modifier::BOLD)
                    } else if st.italic {
                        (colors.ink2, Modifier::ITALIC)
                    } else {
                        (colors.ink, Modifier::empty())
                    };
                    // M06 fresh ink: a chunk lands near white and fades
                    // to its colour in 450 ms, ease-out.
                    let t0 = arrivals.iter().rev().find(|a| a.0 <= k).map(|a| secs(a.1));
                    let fade = ease_out(prog(secs(now_ms), t0, 0.45, reduced || mono));
                    let fg = mix(mix(colors.white, colors.cyan, 0.35), target, fade);
                    cv.put(
                        x + 4 + hang + (k - a) as i32,
                        y,
                        &plain[k].to_string(),
                        fg,
                        bg,
                        mods,
                    );
                }
                // The words, for a selection: not the `✦` or the time.
                let words: String = plain[a.min(plain.len())..b.min(plain.len())]
                    .iter()
                    .collect();
                cv.hit(
                    x + 4 + hang,
                    y,
                    text_width(&words),
                    1,
                    super::hits::Click::Text,
                );
                if live && i + 1 == n {
                    // The caret breathes at 0.9 Hz after 400 ms without data.
                    let idle = last_data
                        .map(|t| now_ms.saturating_sub(t) > 400)
                        .unwrap_or(true);
                    let col = if idle && !reduced {
                        mix(colors.muted, colors.cyan, pulse(secs(now_ms), 0.9, false))
                    } else {
                        colors.cyan
                    };
                    let end = (b.saturating_sub(a)) as i32;
                    cv.text(x + 4 + hang + end, y, "▍", col, None);
                }
            }) as RowFn)
        })
        .collect()
}

fn think_rows_themed(
    colors: Palette,
    model: String,
    since_ms: u64,
    now_ms: u64,
    reduced: bool,
    mono: bool,
) -> Vec<Row> {
    vec![Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
        let now = secs(now_ms);
        cv.bold(x + 2, y, star_at(now, 2.0, reduced), colors.cyan, None);
        let label = format!("waiting for {model}");
        cv.spans(
            x + 4,
            y,
            &shimmer(&label, now, colors.cyan, reduced || mono),
            None,
        );
        let el = now_ms.saturating_sub(since_ms) / 1000;
        if el >= 1 {
            cv.text(
                x + 4 + label.chars().count() as i32,
                y,
                &format!(" · {el}s"),
                colors.muted,
                None,
            );
        }
    }) as RowFn)]
}

fn note_rows_themed(colors: Palette, l: &TranscriptLine, w: i32) -> Vec<Row> {
    if l.wrap {
        return wrapped_note_text(&l.text, w - 8)
            .into_iter()
            .enumerate()
            .map(|(index, text)| {
                Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
                    if index == 0 {
                        cv.text(x + 2, y, "∙", colors.faint, None);
                    }
                    cv.text(x + 4, y, &text, colors.faint, None);
                }) as RowFn)
            })
            .collect();
    }
    let text = l.text.clone();
    vec![Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
        cv.text(x + 2, y, "∙", colors.faint, None);
        cv.text(x + 4, y, &clip_text(&text, w - 8), colors.faint, None);
    }) as RowFn)]
}

/// Wrap just control reports by terminal cells; keep legal long values intact
/// across rows and recompute ranges when their panel is resized.
fn wrapped_note_text(text: &str, width: i32) -> Vec<String> {
    let width = width.max(2) as usize;
    let mut rows = Vec::new();
    for paragraph in text.split('\n') {
        let chars: Vec<char> = paragraph.chars().collect();
        if chars.is_empty() {
            rows.push(String::new());
            continue;
        }
        let mut start = 0;
        while start < chars.len() {
            let mut end = start;
            let mut cells = 0;
            let mut word_break = None;
            while end < chars.len() {
                let size = chars[end].width().unwrap_or(0);
                if cells + size > width {
                    break;
                }
                cells += size;
                end += 1;
                if chars[end - 1] == ' ' {
                    word_break = Some(end);
                }
            }
            if end < chars.len() {
                if let Some(boundary) = word_break {
                    end = boundary;
                }
            }
            rows.push(chars[start..end].iter().collect());
            start = end;
        }
    }
    rows
}

fn queued_rows_themed(colors: Palette, l: &TranscriptLine, w: i32) -> Vec<Row> {
    let text = l.text.clone();
    vec![Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
        cv.text(x + 2, y, "◌", colors.muted, None);
        cv.text(x + 4, y, &clip_text(&text, w - 8), colors.muted, None);
    }) as RowFn)]
}

fn report_rows_themed(
    colors: Palette,
    text: String,
    ended_ms: Option<u64>,
    now_ms: u64,
    reduced: bool,
) -> Vec<Row> {
    vec![Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
        // M25: the report types in at 60 characters per second.
        let n = match ended_ms {
            Some(t) if !reduced => (now_ms.saturating_sub(t) as f32 / 1000.0 * 60.0) as usize,
            _ => usize::MAX,
        };
        let shown: String = text.chars().take(n).collect();
        let bg = tint(colors.green, colors.panel, 0.12);
        cv.fill(x + 2, y, text_width(&text) + 2, 1, bg);
        cv.bold(x + 3, y, &shown, colors.green, Some(bg));
    }) as RowFn)]
}

fn card_rows_themed(
    colors: Palette,
    l: &TranscriptLine,
    w: i32,
    now_ms: u64,
    reduced: bool,
    mono: bool,
) -> Vec<Row> {
    let kind = kind_of(&l.tool_name);
    let st = l.tool_state;
    let now = secs(now_ms);
    let started = l.started_ms.map(secs);
    let finished = l.finished_ms.map(secs);
    // M10 settle: the stripe turns cyan → green (or red) in 300 ms.
    let settle = prog(now, finished, 0.3, reduced || mono);
    let stripe = match st {
        ToolState::Done => mix(colors.cyan, colors.green, settle),
        ToolState::Failed => mix(colors.cyan, colors.red, settle),
        ToolState::AwaitingYou => colors.magenta,
        ToolState::Denied | ToolState::Queued | ToolState::Cancelled => colors.rule_hi,
        ToolState::Blocked => colors.amber,
        ToolState::Running => colors.cyan,
    };
    let kcol = kind_colour_themed(colors, &kind);
    let target = l.text.clone();
    let meta = l
        .meta
        .strip_prefix("done · ")
        .map(str::to_string)
        .unwrap_or_else(|| l.meta.clone());
    let is_bash = kind == "BASH";
    let k2 = kind.clone();
    // M16: the AGENT card's live sub-status, cloned before row1 moves
    // `meta` — the running card shows what its subagent is doing.
    let sub_status = if kind == "AGENT" && st == ToolState::Running && !meta.is_empty() {
        Some(meta.clone())
    } else {
        None
    };
    let row1: RowFn = Box::new(move |cv: &mut Cv, x: i32, y: i32| {
        cv.fill(x, y, w, 1, colors.raise);
        cv.text(x, y, "▌", stripe, Some(colors.raise));
        // M07: the kind chip flashes for 250 ms as the call starts.
        let chip_flash = flash(now, started, 0.25, reduced || mono);
        let mut xx = if is_bash {
            cv.put(
                x + 1,
                y,
                &format!(" {:<5}", k2),
                colors.on_accent,
                Some(mix(colors.amber, colors.white, chip_flash * 0.6)),
                Modifier::BOLD,
            )
        } else {
            cv.put(
                x + 1,
                y,
                &format!(" {:<5}", k2),
                kcol,
                Some(mix(tint(kcol, colors.raise, 0.3), kcol, chip_flash * 0.5)),
                Modifier::BOLD,
            )
        };
        xx += 1;
        let mut right: Vec<Seg> = Vec::new();
        if !meta.is_empty() && !matches!(st, ToolState::Denied | ToolState::Running) {
            right.push(Seg::new(meta.clone(), colors.muted));
        }
        let sep = if right.is_empty() { "" } else { "  " };
        match st {
            ToolState::Running => right.extend([
                Seg::bold(format!("{} ", star_at(now, 4.0, reduced)), colors.cyan),
                Seg::new("running", colors.cyan),
            ]),
            ToolState::AwaitingYou => right.extend([
                Seg::new(sep, colors.muted),
                Seg::bold("◆ ", colors.magenta),
                Seg::bold("needs you", colors.magenta),
            ]),
            ToolState::Done => right.extend([
                Seg::new(sep, colors.muted),
                Seg::bold(
                    "✓",
                    mix(
                        colors.white,
                        colors.green,
                        prog(now, finished, 0.25, reduced || mono),
                    ),
                ),
            ]),
            ToolState::Failed => right.extend([
                Seg::new(sep, colors.muted),
                Seg::bold("✕ ", colors.red),
                Seg::new("failed", colors.red),
            ]),
            ToolState::Denied => right.extend([
                Seg::bold("⊘ ", colors.muted),
                Seg::new("denied by you", colors.muted),
            ]),
            ToolState::Blocked => right.extend([
                Seg::new(sep, colors.muted),
                Seg::bold("⊖ ", colors.amber),
                Seg::new("blocked", colors.amber),
            ]),
            ToolState::Cancelled => right.extend([
                Seg::new(sep, colors.muted),
                Seg::bold("⊘ ", colors.muted),
                Seg::new("cancelled", colors.muted),
            ]),
            ToolState::Queued => right.extend([
                Seg::new("◌ ", colors.muted),
                Seg::new("queued", colors.muted),
            ]),
        }
        let rw = segs_width(&right);
        if is_bash {
            xx = cv.bold(xx, y, "$ ", colors.amber, Some(colors.raise));
        }
        let tmax = x + w - 2 - rw - xx;
        let tcol = if matches!(k2.as_str(), "READ" | "EDIT" | "WRITE" | "GLOB") {
            colors.blue
        } else {
            colors.ink
        };
        let mods = if is_bash || k2 == "AGENT" {
            Modifier::BOLD
        } else {
            Modifier::empty()
        };
        // M07: the target types in at 240 characters per second.
        let typed: String = match started {
            Some(t0) if !reduced => target
                .chars()
                .take(((now - t0).max(0.0) * 240.0) as usize)
                .collect(),
            _ => target.clone(),
        };
        cv.put(
            xx,
            y,
            &clip_text(&typed, tmax),
            tcol,
            Some(colors.raise),
            mods,
        );
        cv.spans(x + w - 1 - rw, y, &right, Some(colors.raise));
    });
    let mut rows: Vec<Row> = vec![Some(row1)];
    // M16: a running AGENT card carries a sub-status line — what its
    // subagent is doing right now (the meta the progress events keep
    // fresh). The card stops being a black box while it runs.
    if let Some(sub) = sub_status {
        rows.push(Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
            cv.fill(x, y, w, 1, colors.raise);
            cv.text(x, y, "▌", stripe, Some(colors.raise));
            cv.text(x + 2, y, "┆", colors.muted, Some(colors.raise));
            cv.text(
                x + 4,
                y,
                &clip_text(&sub, w - 6),
                colors.muted,
                Some(colors.raise),
            );
        }) as RowFn));
    }
    if st == ToolState::Running {
        let comet_col = if kind == "AGENT" {
            colors.magenta
        } else {
            colors.cyan
        };
        rows.push(Some(Box::new(move |cv: &mut Cv, x: i32, y: i32| {
            cv.fill(x, y, w, 1, colors.raise);
            cv.text(x, y, "▌", stripe, Some(colors.raise));
            let track = (w - 3).max(1);
            cv.text(
                x + 2,
                y,
                &"─".repeat(track as usize),
                colors.rule_hi,
                Some(colors.raise),
            );
            if !reduced {
                // M08: bright head and a 10-cell tail, one pass per 1.3 s.
                let period = 1300.0;
                let tail = 10.0_f32;
                let pos = (now_ms as f32 % period) / period * (track as f32 + tail);
                for i in 0..track {
                    let d = pos - i as f32;
                    if (0.0..tail).contains(&d) {
                        let a = 1.0 - d / tail;
                        cv.text(
                            x + 2 + i,
                            y,
                            "━",
                            mix(colors.rule_hi, comet_col, a),
                            Some(colors.raise),
                        );
                    }
                }
            }
        }) as RowFn));
    }
    rows
}

/// All transcript rows (None = blank), in order.
fn transcript_rows_themed(colors: Palette, compact: bool, inp: &ConvIn, w: i32) -> Vec<Row> {
    let s = inp.s;
    let mut rows: Vec<Row> = Vec::new();
    let mut prev: Option<&str> = None;
    let last_model = s.transcript.iter().rposition(|l| l.kind == LineKind::Model);
    for (i, l) in s.transcript.iter().enumerate() {
        let (kind, r): (&str, Vec<Row>) = match l.kind {
            LineKind::User => ("user", user_rows_themed(colors, l, w)),
            LineKind::Model => {
                let live = s.turn_live && s.visible_output && Some(i) == last_model;
                (
                    "orbit",
                    orbit_rows_themed(colors, l, w, live, inp.now_ms, inp.reduced, inp.mono),
                )
            }
            LineKind::Tool => (
                "card",
                card_rows_themed(colors, l, w, inp.now_ms, inp.reduced, inp.mono),
            ),
            LineKind::System => ("note", note_rows_themed(colors, l, w)),
            LineKind::Queued => ("note", queued_rows_themed(colors, l, w)),
        };
        if r.is_empty() {
            continue;
        }
        let both_cards = prev == Some("card") && kind == "card";
        if !rows.is_empty() && !both_cards && !compact {
            rows.push(None);
        }
        rows.extend(r);
        prev = Some(kind);
    }
    // Honest waiting (design law 5): the row says the MODEL is awaited
    // only when it is. While an approval is open, a tool runs or a
    // subagent works, the row is absent — the card, the tool line and
    // the status bar already say what is happening.
    if matches!(
        s.activity(),
        super::super::scenario::Activity::WaitingModel(_)
    ) {
        if !rows.is_empty() {
            rows.push(None);
        }
        rows.extend(think_rows_themed(
            colors,
            s.model.clone(),
            s.turn_started_ms,
            inp.now_ms,
            inp.reduced,
            inp.mono,
        ));
    } else if let Some(r) = &s.turn_report {
        if !s.turn_live {
            let noun = if r.tools == 1 { "tool" } else { "tools" };
            let mut t = format!("✓ done · {}s · {} {noun}", r.duration_ms / 1000, r.tools);
            if r.priced {
                t.push_str(&format!(
                    " · +${:.3}",
                    r.cost_microcents as f64 / 1_000_000.0
                ));
            }
            rows.push(None);
            rows.extend(report_rows_themed(
                colors,
                t,
                s.turn_ended_ms,
                inp.now_ms,
                inp.reduced,
            ));
        }
    }
    rows
}

/// The approval card's facts, keys and risk — from real data only.
struct Approval {
    tool: String,
    action: String,
    risk: u8,
    dir: String,
    mode: String,
    /// Real facts the backend supplied (the sandbox state): `(label, value)`.
    facts: Vec<(String, String)>,
    /// The lines an edit would change: `- ` removed, `+ ` added.
    preview: Vec<String>,
    /// The decision keys are disabled while the person types (§9.14):
    /// the border row says so INSTEAD of showing them.
    armed: bool,
    /// `1 of N` when approvals are queued.
    queue_note: Option<String>,
    shown_ms: u64,
    /// The rule `s` and `a` would remember for this call, when there is one.
    grant: Option<crate::msg::ApprovalGrant>,
    /// The note being typed with a denial: `n` opened the field.
    note: Option<String>,
}

fn approval_of(s: &Scenario, now_ms: u64) -> Option<Approval> {
    let tool = s.approval_queue.first()?.clone();
    let action = s
        .approval_summary
        .clone()
        .unwrap_or_else(|| format!("{tool}()"));
    let last_typing = s.last_key_ms;
    let armed = now_ms.saturating_sub(last_typing) < 1000 && last_typing > 0;
    let queue_note =
        (s.approval_queue.len() > 1).then(|| format!("1 of {}", s.approval_queue.len()));
    Some(Approval {
        tool,
        action,
        risk: s.approval_risk,
        dir: s.approval_dir.clone(),
        mode: s
            .permission_mode
            .clone()
            .unwrap_or_else(|| "default".into()),
        facts: s.approval_facts.clone(),
        preview: s.approval_preview.clone(),
        armed,
        queue_note,
        shown_ms: s.approval_shown_ms,
        grant: s.offered_grant().cloned(),
        note: s.approval_note.clone(),
    })
}

fn approval_height(ap: &Approval) -> i32 {
    // border, header, gap, action, [preview], gap, [facts], gap, keys+border
    // directory (when known), mode, the backend's facts, and what the
    // grant keys would remember: `s` (and `a`), or `R`.
    let grant_rows = match &ap.grant {
        Some(g) => 1 + usize::from(g.can_save),
        None => 1,
    };
    let facts = usize::from(!ap.dir.is_empty()) + 1 + ap.facts.len() + grant_rows;
    (7 + facts + ap.preview.len()) as i32
}

fn draw_approval(
    cv: &mut Cv,
    x: i32,
    y: i32,
    w: i32,
    ap: &Approval,
    now_ms: u64,
    reduced: bool,
) -> i32 {
    let colors = cv.palette;
    let h = approval_height(ap);
    // M13: the border and badge breathe at 1 Hz for 3 s, then hold.
    let age = secs(now_ms.saturating_sub(ap.shown_ms));
    let breath = if age < 3.0 {
        pulse(age, 1.0, reduced)
    } else {
        1.0
    };
    let edge = mix(colors.magenta_dim, colors.magenta, 0.35 + 0.65 * breath);
    let halo = tint(colors.magenta, colors.panel, 0.04 + 0.08 * breath);
    cv.fill(x - 1, y - 1, w + 2, h + 1, halo);
    cv.fill(x, y, w, h, colors.raise);
    cv.text(
        x,
        y,
        &format!("┏{}┓", "━".repeat((w - 2) as usize)),
        edge,
        Some(colors.raise),
    );
    for yy in y + 1..y + h - 1 {
        cv.text(x, yy, "┃", edge, Some(colors.raise));
        cv.text(x + w - 1, yy, "┃", edge, Some(colors.raise));
    }
    cv.text(
        x,
        y + h - 1,
        &format!("┗{}┛", "━".repeat((w - 2) as usize)),
        edge,
        Some(colors.raise),
    );
    // Header band: what it is, what is asked, how risky. In a narrow card
    // the risk badge gives up words before the title is overdrawn.
    cv.fill(x + 1, y + 1, w - 2, 1, colors.magenta);
    let (risk_word, filled, rcol, rfg) = match ap.risk {
        0 => ("LOW", 1, colors.green, colors.on_accent),
        1 => ("LOW", 1, colors.green, colors.on_accent),
        2 => ("MEDIUM", 2, colors.amber, colors.on_accent),
        _ => ("HIGH", 3, colors.red, colors.white),
    };
    let bars = format!("{}{}", "▰".repeat(filled), "▱".repeat(3 - filled));
    let badges = [
        format!(" {bars} {risk_word} RISK "),
        format!(" {bars} {risk_word} "),
        format!(" {risk_word} "),
        format!(" {bars} "),
    ];
    let inner = w - 4;
    let title_w = text_width(&format!("Allow {}?", ap.tool));
    let left_w = text_width("◆ NEEDS YOU");
    let (gap, rt) = [3, 1]
        .into_iter()
        .find_map(|gap| {
            badges
                .iter()
                .find(|b| left_w + gap + title_w + 1 + text_width(b) <= inner)
                .map(|b| (gap, b.clone()))
        })
        .unwrap_or((1, badges[3].clone()));
    let mut tx = cv.put(
        x + 2,
        y + 1,
        "◆ NEEDS YOU",
        colors.on_accent,
        Some(colors.magenta),
        Modifier::BOLD,
    );
    // The title ends before the badge starts, with its `?` kept.
    let title_room = (inner - left_w - gap - 1 - text_width(&rt)).max(7);
    let tool = clip_text(&ap.tool, (title_room - 7).max(1));
    tx = cv.put(
        tx + gap,
        y + 1,
        "Allow ",
        colors.on_accent,
        Some(colors.magenta),
        Modifier::empty(),
    );
    tx = cv.put(
        tx,
        y + 1,
        &tool,
        colors.on_accent,
        Some(colors.magenta),
        Modifier::BOLD,
    );
    cv.put(
        tx,
        y + 1,
        "?",
        colors.on_accent,
        Some(colors.magenta),
        Modifier::empty(),
    );
    cv.put(
        x + w - 2 - text_width(&rt),
        y + 1,
        &rt,
        rfg,
        Some(rcol),
        Modifier::BOLD,
    );
    // Action inset (and, for an edit, the lines it changes).
    let mut yy = y + 3;
    cv.fill(x + 2, yy, w - 4, 1 + ap.preview.len() as i32, colors.inset);
    let is_cmd = matches!(ap.tool.to_ascii_lowercase().as_str(), "bash" | "shell");
    if is_cmd {
        let cmd = ap
            .action
            .strip_prefix(&format!("{}(", ap.tool))
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or(&ap.action);
        let x2 = cv.bold(x + 3, yy, "$ ", colors.amber, Some(colors.inset));
        cv.bold(
            x2,
            yy,
            &clip_text(cmd, w - 8),
            colors.ink,
            Some(colors.inset),
        );
    } else {
        cv.bold(
            x + 3,
            yy,
            &clip_text(&ap.action, w - 6),
            colors.blue,
            Some(colors.inset),
        );
    }
    yy += 1;
    for line in &ap.preview {
        // `- ` removed (red), `+ ` added (green), anything else context.
        let (marker, colour) = match line.chars().next() {
            Some('-') => ("-", colors.red),
            Some('+') => ("+", colors.green),
            _ => (" ", colors.muted),
        };
        let body = line.get(1..).unwrap_or("").trim_start_matches(' ');
        cv.bold(x + 3, yy, marker, colour, Some(colors.inset));
        cv.text(
            x + 5,
            yy,
            &clip_text(body, w - 9),
            colour,
            Some(colors.inset),
        );
        yy += 1;
    }
    yy += 1;
    // Facts: only values the backend measured.
    if !ap.dir.is_empty() {
        cv.text(x + 3, yy, "directory", colors.muted, Some(colors.raise));
        cv.text(
            x + 14,
            yy,
            &clip_text(&ap.dir, w - 17),
            colors.ink2,
            Some(colors.raise),
        );
        yy += 1;
    }
    cv.text(x + 3, yy, "mode", colors.muted, Some(colors.raise));
    cv.text(x + 14, yy, &ap.mode, colors.ink2, Some(colors.raise));
    yy += 1;
    for (label, value) in &ap.facts {
        cv.text(
            x + 3,
            yy,
            &clip_text(label, 10),
            colors.muted,
            Some(colors.raise),
        );
        // No sandbox is the one fact that must not read like the others.
        let unconfined = value.starts_with("NONE");
        if unconfined {
            cv.bold(
                x + 14,
                yy,
                &clip_text(value, w - 17),
                colors.amber,
                Some(colors.raise),
            );
        } else {
            cv.text(
                x + 14,
                yy,
                &clip_text(value, w - 17),
                colors.ink2,
                Some(colors.raise),
            );
        }
        yy += 1;
    }
    // What the grant keys really grant (design law 6: a grant displays its
    // actual scope — never implied to be this one call). With a rule on
    // offer, `s` and `a` name it; `R` stays on the key row, labelled with
    // the whole tool. With none, `R` is the only grant and says so here.
    let room = w - 17;
    if let Some(g) = &ap.grant {
        cv.text(x + 3, yy, "s grants", colors.muted, Some(colors.raise));
        let shown = [format!("{}, this session", g.rule), g.rule.clone()]
            .into_iter()
            .find(|v| text_width(v) <= room)
            .unwrap_or_else(|| clip_text(&g.rule, room));
        cv.text(x + 14, yy, &shown, colors.ink2, Some(colors.raise));
        yy += 1;
        if g.can_save {
            cv.text(x + 3, yy, "a grants", colors.muted, Some(colors.raise));
            let shown = [
                "same, saved in .orbit/settings.local.toml".to_string(),
                "same, saved in this folder".to_string(),
                "same, saved".to_string(),
            ]
            .into_iter()
            .find(|v| text_width(v) <= room)
            .unwrap_or_else(|| clip_text("same, saved", room));
            cv.text(x + 14, yy, &shown, colors.ink2, Some(colors.raise));
            yy += 1;
        }
    } else {
        // No rule is on offer for this call, so no grant can be remembered
        // from the card. Scope honesty without a whole-tool escape hatch:
        // the row says exactly that instead of advertising one.
        cv.text(x + 3, yy, "no rule", colors.muted, Some(colors.raise));
        let shown = [
            format!("this {} call is not covered by a remembered rule", ap.tool),
            "this call has no rule to remember".to_string(),
            "no rule to remember".to_string(),
        ]
        .into_iter()
        .find(|v| text_width(v) <= room)
        .unwrap_or_else(|| clip_text("no rule to remember", room));
        cv.text(x + 14, yy, &shown, colors.ink2, Some(colors.raise));
        yy += 1;
    }
    yy += 1;
    // The note field: `n` opened it. The denial waits for ⏎ (send the note)
    // or esc (deny without one); nothing else answers the card meanwhile.
    if let Some(note) = &ap.note {
        let key = |code: crossterm::event::KeyCode| {
            super::hits::Click::Key(code, crossterm::event::KeyModifiers::NONE)
        };
        let n_end = keycap(cv, x + 3, yy, "n", false);
        let from = x + 3;
        cv.hit(
            from,
            yy,
            n_end - from,
            1,
            key(crossterm::event::KeyCode::Esc),
        );
        // The hints on the right: ⏎ send · esc skip (or just the keys).
        let hints: [&[(&str, &str, crossterm::event::KeyCode)]; 2] = [
            &[
                ("⏎", "send", crossterm::event::KeyCode::Enter),
                ("esc", "skip", crossterm::event::KeyCode::Esc),
            ],
            &[
                ("⏎", "", crossterm::event::KeyCode::Enter),
                ("esc", "", crossterm::event::KeyCode::Esc),
            ],
        ];
        let width_of = |hs: &[(&str, &str, crossterm::event::KeyCode)]| {
            hs.iter()
                .map(|(k, l, _)| text_width(k) + if l.is_empty() { 0 } else { 1 + text_width(l) })
                .sum::<i32>()
                + 2 * (hs.len() as i32 - 1)
        };
        let label = "because: ";
        let hs = hints
            .iter()
            .find(|hs| width_of(hs) + 3 + 1 + text_width(label) + 6 <= w - 6)
            .copied()
            .unwrap_or(hints[1]);
        let mut hx = x + w - 3 - width_of(hs);
        for (k, l, code) in hs {
            let from = hx;
            hx = cv.bold(hx, yy, k, colors.ink2, Some(colors.raise));
            if !l.is_empty() {
                hx = cv.text(hx + 1, yy, l, colors.faint, Some(colors.raise));
            }
            cv.hit(from, yy, hx - from, 1, key(*code));
            hx += 2;
        }
        let tx = cv.text(n_end + 1, yy, label, colors.muted, Some(colors.raise));
        let room = (x + w - 3 - width_of(hs) - 2 - tx - 1).max(1) as usize;
        let chars: Vec<char> = note.chars().collect();
        let shown: String = chars[chars.len().saturating_sub(room)..].iter().collect();
        let end = cv.bold(tx, yy, &shown, colors.ink, Some(colors.raise));
        cv.text(end, yy, "▏", colors.magenta, Some(colors.raise));
        return h;
    }
    // Keys — drawn on the bottom border row. While the person is typing
    // they are disabled (§9.14) and the border says so in their place;
    // drawing both put the note over the key labels.
    if ap.armed {
        cv.text(
            x + 3,
            yy,
            " paused while you type ",
            colors.muted,
            Some(colors.raise),
        );
        return h;
    }
    // Groups on the border row: the grants on the left, the refusal
    // anchored at the right (`n  esc deny`). Laying the refusal out
    // explicitly matters: it used to hide behind the right-aligned
    // `esc deny` only because a longer `R` label happened to push it
    // exactly there.
    //
    // With a rule on offer the grants are `y` once, `s` this session and
    // `a` always (when it can be saved). Without a rule `y` is the only
    // grant — the whole-tool session grant is gone, so the card never
    // offers a broader key than the rule it can remember (design law 6:
    // scope honesty). When the card is too narrow for every group at
    // full length the words shrink (`once`, `session`, `deny`), and below
    // that only the keys stay; groups never overlap.
    let cap = |label: &str| {
        3 + if label.is_empty() {
            0
        } else {
            1 + text_width(label)
        }
    };
    let avail = w - 6; // from x + 3 to x + w - 3
    let has_a = ap.grant.as_ref().is_some_and(|g| g.can_save);
    // `(y, s, a, n)` labels, longest wording first.
    let wordings: Vec<[String; 4]> = if ap.grant.is_some() {
        [
            ("allow once", "this session", "always", "esc deny"),
            ("allow once", "session", "always", "esc deny"),
            ("once", "session", "always", "deny"),
            ("", "", "", ""),
        ]
        .into_iter()
        .map(|(y, s, a, n)| [y.into(), s.into(), a.into(), n.into()])
        .collect()
    } else {
        [
            ("allow once", "", "", "esc deny"),
            ("once", "", "", "deny"),
            ("", "", "", ""),
        ]
        .into_iter()
        .map(|(y, s, a, n)| [y.into(), s.into(), a.into(), n.into()])
        .collect()
    };
    let left = |wd: &[String; 4]| -> Vec<(&'static str, String)> {
        let mut g = vec![("y", wd[0].clone())];
        if ap.grant.is_some() {
            g.push(("s", wd[1].clone()));
            if has_a {
                g.push(("a", wd[2].clone()));
            }
        }
        g
    };
    let fits = |wd: &[String; 4]| {
        let groups = left(wd);
        groups.iter().map(|(_, l)| cap(l)).sum::<i32>() + 3 * groups.len() as i32 + cap(&wd[3])
            <= avail
    };
    let chosen = wordings
        .iter()
        .find(|wd| fits(wd))
        .cloned()
        .unwrap_or_default();
    let n_label = chosen[3].as_str();
    let deny_w = cap(n_label);
    let deny_x = x + w - 3 - deny_w;
    // Each is clickable as the key it shows: the click goes through the
    // same handler, so the arming delay and the mode rules apply to it.
    let key = |c: char| {
        super::hits::Click::Key(
            crossterm::event::KeyCode::Char(c),
            crossterm::event::KeyModifiers::NONE,
        )
    };
    let mut kx = x + 3;
    for (k, lab) in left(&chosen) {
        let from = kx;
        kx = keycap(cv, kx, yy, k, k == "y");
        if !lab.is_empty() {
            kx = cv.text(kx + 1, yy, &lab, colors.ink2, Some(colors.raise));
        }
        cv.hit(from, yy, kx - from, 1, key(k.chars().next().unwrap_or('y')));
        kx += 3;
    }
    let after_n = keycap(cv, deny_x, yy, "n", false);
    let mut deny_end = after_n;
    if n_label == "esc deny" {
        cv.bold(after_n + 1, yy, "esc", colors.ink2, Some(colors.raise));
        deny_end = cv.text(
            after_n + 1 + text_width("esc"),
            yy,
            " deny",
            colors.faint,
            Some(colors.raise),
        );
    } else if !n_label.is_empty() {
        deny_end = cv.text(after_n + 1, yy, n_label, colors.faint, Some(colors.raise));
    }
    cv.hit(deny_x, yy, deny_end - deny_x, 1, key('n'));
    // `1 of N`, between the grants and the refusal when there is room.
    if let Some(n) = &ap.queue_note {
        let t = format!(" {n} ");
        let nx = deny_x - 2 - text_width(&t);
        if nx > kx {
            cv.text(nx, yy, &t, colors.muted, Some(colors.raise));
        }
    }
    h
}

/// The composer: input row + key hints.
fn draw_composer(cv: &mut Cv, x: i32, y: i32, w: i32, inp: &ConvIn) {
    let colors = cv.palette;
    let s = inp.s;
    let bg = tint(colors.magenta, colors.raise2, 0.05);
    cv.fill(x, y, w, 1, bg);
    let f = inp.focused;
    cv.text(
        x,
        y,
        "▎",
        if f { colors.magenta } else { colors.rule_hi },
        Some(bg),
    );
    cv.bold(
        x + 2,
        y,
        "›",
        if f { colors.magenta } else { colors.faint },
        Some(bg),
    );
    if !inp.composer.is_empty() {
        let n = (w - 7).max(1) as usize;
        let chars: Vec<char> = inp.composer.chars().collect();
        let vis: String = chars[chars.len().saturating_sub(n)..]
            .iter()
            .map(|&ch| if ch == '\n' { '⏎' } else { ch })
            .collect();
        let e = cv.text(x + 4, y, &vis, colors.ink, Some(bg));
        cv.text(e, y, "▏", colors.ink, Some(bg));
    } else {
        cv.text(
            x + 4,
            y,
            "▏",
            if f { colors.ink } else { colors.faint },
            Some(bg),
        );
        let ph = if s.turn_live {
            "Add to the queue, or wait for ORBIT"
        } else {
            "Ask ORBIT, or type / for commands"
        };
        cv.text(x + 5, y, &clip_text(ph, w - 6), colors.faint, Some(bg));
    }
    let hints: Vec<(&str, &str)> = if inp.history_search.is_some() {
        vec![("⌃r", "older"), ("⏎", "accept draft"), ("esc", "restore")]
    } else if inp.file_completion.is_some_and(|picker| picker.is_open()) {
        vec![
            ("↑↓", "choose"),
            ("⇥", "complete"),
            ("⏎", "accept draft"),
            ("esc", "close"),
        ]
    } else if s.turn_live {
        vec![
            ("⏎", "queue"),
            ("esc", "stop"),
            ("⇧⏎", "newline"),
            ("@", "file"),
            ("⌃r", "history"),
            ("/", "commands"),
        ]
    } else {
        vec![
            ("⏎", "send"),
            ("esc", "arrange"),
            ("⇧tab", "mode"),
            ("⇧⏎", "newline"),
            ("@", "file"),
            ("⌃r", "history"),
            ("/", "commands"),
        ]
    };
    if f {
        let fh = fit_hints(&hints, w - 2);
        keyhints(cv, x + 1, y + 1, &fh, None);
    }
}

/// Draw the whole Conversation panel into `r`.
pub fn draw(cv: &mut Cv, r: Rect, inp: &ConvIn) {
    let colors = cv.palette;
    let s = inp.s;
    let ap = approval_of(s, inp.now_ms);
    let b = if ap.is_some() {
        badge_themed(colors, BadgeState::Needs, None, inp.now_ms, inp.reduced)
    } else if s.turn_live {
        badge_themed(colors, BadgeState::Working, None, inp.now_ms, inp.reduced)
    } else if s.turn_report.is_some() {
        badge_themed(colors, BadgeState::Done, None, inp.now_ms, inp.reduced)
    } else if s.transcript.is_empty() {
        vec![
            Seg::bold("✦ ", colors.magenta),
            Seg::new("ready", colors.magenta),
        ]
    } else {
        badge_themed(colors, BadgeState::Idle, None, inp.now_ms, inp.reduced)
    };
    let title = if s.transcript.is_empty() {
        "New session"
    } else {
        "Conversation"
    }
    .to_string();
    let spec = FrameSpec {
        num: inp.num,
        title: &title,
        ident: colors.magenta,
        focused: inp.focused,
        focus_fx: inp.focus_fx,
        badge: Some(b),
        attention: if ap.is_some() && !inp.focused {
            1.0
        } else {
            0.0
        },
        footer: vec![],
        footer_parts: vec![],
    };
    let Some(inner) = panel_frame(cv, r, &spec) else {
        return;
    };
    let (x, y, w, h) = (
        inner.x as i32,
        inner.y as i32,
        inner.width as i32,
        inner.height as i32,
    );
    if w < 8 || h < 4 {
        return;
    }
    cv.clipped(
        Rect {
            x: r.x + 1,
            y: inner.y,
            width: r.width - 2,
            height: inner.height,
        },
        |cv| {
            // Bottom block: approval card or the composer.
            let bottom_h = match &ap {
                Some(a) => approval_height(a) + 1,
                None => 3 + i32::from(inp.history_search.is_some()),
            };
            let view_h = (h - bottom_h).max(0);
            // The welcome hero (M01 startup, M26 welcome orbit): shown on an
            // empty session and while the first prompt waits.
            let hero_on =
                inp.brand != BrandTier::Off && (s.transcript.is_empty() || s.first_prompt_waiting);
            let animate = inp.brand == BrandTier::Anim && !inp.reduced;
            let mut used = 0;
            if hero_on {
                used = draw_hero(
                    cv,
                    x,
                    y,
                    w,
                    view_h,
                    &Hero {
                        since_start: if animate { secs(inp.now_ms) } else { 99.0 },
                        waiting_for: s.first_prompt_waiting.then(|| {
                            if animate {
                                secs(inp.now_ms.saturating_sub(s.turn_started_ms))
                            } else {
                                0.0
                            }
                        }),
                        reduced: !animate,
                        checks: &s.welcome_chips,
                    },
                );
            }
            if !s.transcript.is_empty() {
                let view_h = view_h - used;
                let rows = transcript_rows_themed(colors, cv.compact, inp, w);
                let total = rows.len() as i32;
                let start = (total - view_h - inp.scroll_offset as i32).max(0);
                let shown = (total - start).min(view_h);
                let top = y + used + view_h - shown.min(view_h);
                for (i, row) in rows
                    .iter()
                    .skip(start as usize)
                    .take(shown as usize)
                    .enumerate()
                {
                    if let Some(f) = row {
                        f(cv, x, top + i as i32);
                    }
                }
            }
            match &ap {
                Some(a) => {
                    draw_approval(
                        cv,
                        x,
                        y + h - approval_height(a),
                        w,
                        a,
                        inp.now_ms,
                        inp.reduced,
                    );
                }
                None => {
                    draw_composer(cv, x, y + h - 2, w, inp);
                    if inp.focused {
                        if let Some(search) = inp.history_search {
                            let text = format!(
                                "History search: {}{}",
                                if search.matched.is_none() {
                                    "(no match) "
                                } else {
                                    ""
                                },
                                search.query
                            );
                            cv.fill(x, y + h - 3, w, 1, colors.raise);
                            cv.text(
                                x + 2,
                                y + h - 3,
                                &clip_text(&text, w - 4),
                                colors.blue,
                                Some(colors.raise),
                            );
                        } else if let Some(picker) =
                            inp.file_completion.filter(|picker| picker.is_open())
                        {
                            draw_files(cv, x, y + h - 3, w, picker);
                        } else {
                            // The `/` command list floats above the composer.
                            let list = crate::proto::chrome::slash_list(inp.composer);
                            if !list.is_empty() {
                                draw_completion(cv, x, y + h - 3, w, &list, inp.completion_sel);
                            }
                        }
                    }
                }
            }
        },
    );
}

/// File rows follow the highlighted candidate just like slash completion.
fn draw_files(
    cv: &mut Cv,
    x: i32,
    bottom: i32,
    w: i32,
    picker: &crate::proto::composer::FileCompletion,
) {
    let colors = cv.palette;
    let rows = picker
        .candidates
        .len()
        .min(crate::proto::chrome::COMPLETION_ROWS);
    let selected = picker
        .selected
        .min(picker.candidates.len().saturating_sub(1));
    let start = selected.saturating_add(1).saturating_sub(rows);
    let top = bottom - rows as i32;
    cv.fill(x, top - 1, w, rows as i32 + 1, colors.raise);
    cv.text(x + 2, top - 1, "Files", colors.faint, Some(colors.raise));
    let more = if picker.truncated || start + rows < picker.candidates.len() {
        "  ↓ more"
    } else {
        ""
    };
    let keys = format!("↑↓ choose   ⇥/⏎ accept draft{more}");
    let kw = text_width(&keys);
    if w > kw + 10 {
        cv.text(
            x + w - kw - 2,
            top - 1,
            &keys,
            colors.faint,
            Some(colors.raise),
        );
    }
    for (i, candidate) in picker.candidates.iter().skip(start).take(rows).enumerate() {
        let row = top + i as i32;
        let on = start + i == selected;
        let bg = if on {
            tint(colors.blue, colors.raise, 0.14)
        } else {
            colors.raise
        };
        cv.fill(x, row, w, 1, bg);
        cv.hit(x, row, w, 1, super::hits::Click::Completion(start + i));
        if on {
            cv.text(x, row, "▌", colors.blue, Some(bg));
        }
        let path = format!(
            "{}{}",
            candidate.path,
            if candidate.directory { "/" } else { "" }
        );
        cv.bold(
            x + 2,
            row,
            &clip_text(&path, w - 4),
            if on { colors.white } else { colors.ink },
            Some(bg),
        );
    }
}

/// The inline `/` command list (§9.13): the commands that match what is
/// typed, the highlighted one marked, with the keys that act on it. It
/// sits on the row above the composer and grows upward.
fn draw_completion(
    cv: &mut Cv,
    x: i32,
    bottom: i32,
    w: i32,
    list: &[(&'static str, &'static str)],
    sel: usize,
) {
    let colors = cv.palette;
    let sel = sel.min(list.len().saturating_sub(1));
    // A window of the matches that follows the selection.
    let rows = list.len().min(crate::proto::chrome::COMPLETION_ROWS);
    let start = if sel >= rows { sel + 1 - rows } else { 0 };
    let shown = &list[start..start + rows];
    let n = rows as i32;
    let top = bottom - n; // first command row; the header is one above
    cv.fill(x, top - 1, w, n + 1, colors.raise);
    cv.text(x + 2, top - 1, "Commands", colors.faint, Some(colors.raise));
    let more = if start + rows < list.len() {
        "  ↓ more"
    } else {
        ""
    };
    let keys = &format!("↑↓ choose   ⇥ complete   ⏎ run{more}");
    let kw = text_width(keys);
    if w > kw + 14 {
        cv.text(
            x + w - kw - 2,
            top - 1,
            keys,
            colors.faint,
            Some(colors.raise),
        );
    }
    for (i, (cmd, desc)) in shown.iter().enumerate() {
        let yy = top + i as i32;
        // The window scrolls: the row's index is in the whole list.
        cv.hit(x, yy, w, 1, super::hits::Click::Slash(start + i));
        let on = start + i == sel;
        let bg = if on {
            tint(colors.magenta, colors.raise, 0.14)
        } else {
            colors.raise
        };
        cv.fill(x, yy, w, 1, bg);
        if on {
            cv.text(x, yy, "▌", colors.magenta, Some(bg));
        }
        let cx = cv.bold(
            x + 2,
            yy,
            cmd,
            if on { colors.white } else { colors.ink },
            Some(bg),
        );
        let dx = (x + 2 + 10).max(cx + 2);
        cv.text(
            dx,
            yy,
            &clip_text(desc, x + w - dx - 1),
            colors.muted,
            Some(bg),
        );
    }
}

#[cfg(test)]
fn note_rows(l: &TranscriptLine, w: i32) -> Vec<Row> {
    note_rows_themed(Palette::default(), l, w)
}

#[cfg(test)]
mod effort_note_tests {
    use super::*;

    #[test]
    fn effort_reports_keep_long_values_and_rewrap_unicode_by_cells() {
        let text = format!("Supported: {}", "x".repeat(64));
        let narrow = wrapped_note_text(&text, 52);
        assert_eq!(narrow.concat(), text);
        assert!(narrow.iter().all(|line| text_width(line) <= 52));
        assert!(wrapped_note_text(&text, 80).len() < narrow.len());
        let wide = format!("Configured effort: {}", "界".repeat(16));
        let rows = wrapped_note_text(&wide, 26);
        assert_eq!(rows.concat(), wide);
        assert!(rows.iter().all(|line| text_width(line) <= 26));
        let reason = wrapped_note_text(
            "OpenAI-compatible reasoning_effort requires a named level",
            49,
        );
        assert!(reason.iter().any(|line| line.contains("named level")));
        assert_eq!(
            reason.concat(),
            "OpenAI-compatible reasoning_effort requires a named level"
        );
        let report = TranscriptLine {
            text,
            wrap: true,
            ..Default::default()
        };
        assert_eq!(note_rows(&report, 60).len(), 3);
        assert_eq!(
            note_rows(
                &TranscriptLine {
                    wrap: false,
                    ..report
                },
                60
            )
            .len(),
            1
        );
    }
}
#[cfg(test)]
mod kind_tests {
    use super::kind_of;

    /// The chip is read at a glance: the REAL tool names (CamelCase), not
    /// just snake_case aliases, map to a short readable label — `TaskCreate`
    /// used to read `TASKC`.
    #[test]
    fn real_tool_names_get_readable_chips() {
        for (tool, chip) in [
            ("Read", "READ"),
            ("Glob", "GLOB"),
            ("Grep", "GREP"),
            ("Edit", "EDIT"),
            ("Write", "WRITE"),
            ("Bash", "BASH"),
            ("TaskCreate", "TASKS"),
            ("TaskUpdate", "TASKS"),
            ("TaskList", "TASKS"),
            ("TaskStop", "STOP"),
            ("WebFetch", "FETCH"),
            ("WebSearch", "WEB"),
            ("NotebookEdit", "EDIT"),
            ("AskUserQuestion", "ASK"),
            ("ExitPlanMode", "PLAN"),
            ("Agent", "AGENT"),
            ("mcp__github__create_issue", "MCP"),
        ] {
            assert_eq!(kind_of(tool), chip, "{tool}");
        }
        // Anything unknown still shows its name, clipped.
        assert_eq!(kind_of("Skill"), "SKILL");
    }
}
#[cfg(test)]
mod reply_row_tests {
    use super::*;
    use crate::proto::shell::md::rich_styled;

    fn rows(markdown: &str, width: usize) -> (Vec<char>, Vec<ReplyRow>) {
        let md = rich_styled(markdown);
        let rows = reply_rows(&md.plain, &md.sty, width);
        (md.plain, rows)
    }

    fn pieces(plain: &[char], rows: &[ReplyRow]) -> Vec<String> {
        rows.iter()
            .map(|r| plain[r.a..r.b].iter().collect())
            .collect()
    }

    /// A bullet or a number that wraps continues under its text.
    #[test]
    fn a_wrapped_list_item_hangs_under_its_text() {
        let (plain, r) = rows("- aaa bbb ccc ddd", 10);
        assert_eq!(pieces(&plain, &r), ["• aaa bbb", "ccc ddd"]);
        assert_eq!((r[0].hang, r[1].hang), (0, 2));
        assert!(!r[1].gutter);

        // `1. ` hangs 3, `10. ` hangs 4, a nested item keeps its indent.
        let (_, r) = rows("1. aaa bbb ccc ddd eee", 10);
        assert_eq!(r[1].hang, 3);
        let (_, r) = rows("10. aaa bbb ccc ddd eee", 10);
        assert_eq!(r[1].hang, 4);
        let (_, r) = rows("  - aaa bbb ccc ddd eee", 12);
        assert_eq!(r[1].hang, 4);
    }

    /// A quote that wraps repeats its gutter on every row.
    #[test]
    fn a_wrapped_quote_repeats_its_gutter() {
        let (plain, r) = rows("> aaa bbb ccc ddd", 10);
        assert_eq!(pieces(&plain, &r), ["│ aaa bbb", "ccc ddd"]);
        assert_eq!((r[1].hang, r[1].gutter), (2, true));
        assert!(!r[0].gutter);
    }

    /// Code and prose that merely look like a list do not hang.
    #[test]
    fn code_and_plain_prose_do_not_hang() {
        let (_, r) = rows("```\n• aaa bbb ccc ddd eee\n```", 10);
        assert!(r.iter().all(|row| row.hang == 0), "{r:?}");
        let (_, r) = rows("aaa bbb ccc ddd eee fff", 10);
        assert!(r.iter().all(|row| row.hang == 0), "{r:?}");
        // `2024. A year` has four digits: not a numbered item.
        let (_, r) = rows("2024. aaa bbb ccc ddd eee", 10);
        assert!(r.iter().all(|row| row.hang == 0), "{r:?}");
    }

    /// Blank lines stay rows; the empty line after the last newline and
    /// an empty reply behave as before.
    #[test]
    fn blank_lines_and_the_end_of_the_text() {
        let (plain, r) = rows("a\n\nb", 10);
        assert_eq!(pieces(&plain, &r), ["a", "", "b"]);
        let (plain, r) = rows("abc\n", 10);
        assert_eq!(pieces(&plain, &r), ["abc"]);
        let (_, r) = rows("", 10);
        assert_eq!(r.len(), 1);
    }

    /// A word longer than the row is split, and a hang wider than the
    /// row cannot starve it of columns.
    #[test]
    fn long_words_split_and_a_huge_hang_is_capped() {
        let (plain, r) = rows("abcdefghijkl", 5);
        assert_eq!(pieces(&plain, &r), ["abcde", "fghij", "kl"]);
        let (_, r) = rows("- aaa bbb", 2);
        assert!(r.iter().all(|row| row.hang < 2), "{r:?}");
    }
}
