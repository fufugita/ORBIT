//! Bounded, side-effect-free setup choice rendering and keyboard decoding.
use crate::onboarding::SetupChoice;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub(crate) const MAX_CHOICES: usize = 4096;
pub(crate) const MAX_MENU_TEXT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_TYPED_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Enter,
    Back,
    Cancel,
    Erase,
    Text(u8),
    Ignore,
}

pub(crate) fn key(bytes: &[u8]) -> Option<Key> {
    Some(match bytes {
        [3 | 4 | 26 | 28] => Key::Cancel,
        [b'\r' | b'\n'] => Key::Enter,
        [8 | 127] => Key::Erase,
        [27] | [27, b'[', b'D'] | [27, b'O', b'D'] => Key::Back,
        [27, b'[', b'A'] | [27, b'O', b'A'] => Key::Up,
        [27, b'[', b'B'] | [27, b'O', b'B'] => Key::Down,
        [27, b'[', b'H'] | [27, b'O', b'H'] | [27, b'[', b'1', b'~'] => Key::Home,
        [27, b'[', b'F'] | [27, b'O', b'F'] | [27, b'[', b'4', b'~'] => Key::End,
        [27, b'[', b'5', b'~'] => Key::PageUp,
        [27, b'[', b'6', b'~'] => Key::PageDown,
        [byte] if *byte >= 32 => Key::Text(*byte),
        [byte] if *byte < 32 => Key::Ignore,
        _ if bytes.len() >= 16 => Key::Ignore,
        _ if bytes.starts_with(&[27, b'['])
            && bytes.len() > 2
            && bytes.last().is_some_and(|b| (0x40..=0x7e).contains(b)) =>
        {
            Key::Ignore
        }
        _ => return None,
    })
}

fn is_default_ignorable(character: char) -> bool {
    matches!(
        character as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF0..=0xFFF8
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

/// Controls are separated; default-ignorable code points stay visible in labels.
/// keep ANSI color/move sequences while stripping other control
/// characters, so detail lines can carry palette swatches safely.
pub(crate) fn safe_with_ansi(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\x1b' && chars.peek() == Some(&'[') {
            result.push('\x1b');
            for escape in chars.by_ref() {
                result.push(escape);
                if escape.is_ascii_alphabetic() {
                    break;
                }
            }
        } else if character.is_control() {
            result.push(' ');
        } else {
            result.push(character);
        }
    }
    result
}

pub(crate) fn safe(value: &str) -> String {
    use std::fmt::Write as _;

    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            safe.push(' ');
        } else if is_default_ignorable(character) {
            write!(safe, "⟦U+{:04X}⟧", character as u32)
                .expect("writing a Unicode escape into a String cannot fail");
        } else {
            safe.push(character);
        }
    }
    safe
}

pub(crate) fn clip_ansi(value: &str, columns: usize) -> String {
    let clean = safe_with_ansi(value);
    let mut result = String::new();
    let mut used = 0;
    for cluster in clean.graphemes(true) {
        let width = UnicodeWidthStr::width(cluster);
        if used + width > columns {
            break;
        }
        used += width;
        result.push_str(cluster);
    }
    result
}

pub(crate) fn clip(value: &str, columns: usize) -> String {
    let clean = safe(value);
    let mut result = String::new();
    let mut used = 0;
    for cluster in clean.graphemes(true) {
        let width = UnicodeWidthStr::width(cluster);
        if used + width > columns {
            break;
        }
        result.push_str(cluster);
        used += width;
    }
    result
}

pub(crate) struct Menu {
    pub(crate) selected: usize,
    pub(crate) armed: bool,
    count: usize,
}
impl Menu {
    pub(crate) fn new(count: usize, current: Option<usize>) -> Self {
        Self {
            selected: current.unwrap_or(0).min(count.saturating_sub(1)),
            armed: current.is_some(),
            count,
        }
    }
    pub(crate) fn navigate(&mut self, key: Key, page: usize) {
        if self.count == 0 {
            return;
        }
        self.selected = match key {
            Key::Up => self.selected.saturating_sub(1),
            Key::Down => (self.selected + 1).min(self.count - 1),
            Key::Home => 0,
            Key::End => self.count - 1,
            Key::PageUp => self.selected.saturating_sub(page.max(1)),
            Key::PageDown => self
                .selected
                .saturating_add(page.max(1))
                .min(self.count - 1),
            _ => return,
        };
        self.armed = true;
    }
}

pub(crate) struct Frame {
    pub(crate) lines: Vec<String>,
    pub(crate) selected_line: usize,
    pub(crate) page: usize,
}
pub(crate) fn frame(
    title: &str,
    choices: &[SetupChoice<'_>],
    menu: &Menu,
    typed: &[u8],
    columns: usize,
    rows: usize,
    allow_back: bool,
) -> Frame {
    let columns = columns.clamp(1, 240);
    let page = rows.clamp(8, 120).saturating_sub(7).max(1);
    let start = menu
        .selected
        .saturating_sub(page - 1)
        .min(choices.len().saturating_sub(page));
    let end = (start + page).min(choices.len());
    let mut lines = vec![
        "ORBIT  /  SETUP".to_owned(),
        title.to_owned(),
        String::new(),
    ];
    let selected_line = 3 + menu.selected.saturating_sub(start);
    for (index, choice) in choices.iter().enumerate().take(end).skip(start) {
        lines.push(format!(
            "{} {}. {}",
            if index == menu.selected { ">" } else { " " },
            index + 1,
            choice.label
        ));
    }
    let selected = choices.get(menu.selected);
    lines.push(selected.and_then(|c| c.detail).unwrap_or("").to_owned());
    lines.push(format!(
        "{} of {}  |  {}",
        menu.selected + 1,
        choices.len(),
        selected.map(|c| c.label).unwrap_or("")
    ));
    lines.push(format!("{title}: {}", String::from_utf8_lossy(typed)));
    lines.push(
        if allow_back {
            "Arrows select  Enter choose  Left/Esc back  Ctrl-C cancel"
        } else {
            "Arrows select  Enter choose  Esc/Ctrl-C cancel"
        }
        .to_owned(),
    );
    // The detail line may carry ANSI swatches; other lines stay plain.
    let detail = selected
        .and_then(|c| c.detail)
        .map(|detail| clip_ansi(detail, columns.saturating_sub(1)));
    let mut rendered: Vec<String> = lines
        .into_iter()
        .map(|s| clip(&s, columns.saturating_sub(1)))
        .collect();
    if let Some(detail) = detail {
        // The detail sits after the choice lines: header(3) + page choices.
        let index = 3 + (end - start);
        rendered[index] = detail;
    }
    Frame {
        lines: rendered,
        selected_line,
        page,
    }
}

// ---------------------------------------------------------------------------
// The rich screen: the same choices, drawn in ORBIT's own colours.
//
// `frame` above stays the plain form (and the one a very small terminal
// gets). Everything here is still bounded and side-effect free: text goes
// through `clip`, so nothing a label carries can move the cursor or hide,
// and no line is wider than the terminal less one column.

#[cfg(feature = "tui")]
use orbit_hud_tui::proto::shell::pal;

/// How many colours the terminal takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Depth {
    /// 24-bit colour.
    True,
    /// The 256-colour cube.
    Indexed,
    /// The 16 named colours.
    Basic,
}

/// The colour depth the environment promises: `COLORTERM` for 24-bit,
/// a `256color` terminal name for the cube, otherwise the named colours.
pub(crate) fn depth(colorterm: Option<&str>, term: Option<&str>) -> Depth {
    if colorterm.is_some_and(|value| value.contains("truecolor") || value.contains("24bit")) {
        Depth::True
    } else if term.is_some_and(|term| term.contains("256color")) {
        Depth::Indexed
    } else {
        Depth::Basic
    }
}

pub(crate) fn depth_from_env() -> Depth {
    depth(
        std::env::var("COLORTERM").ok().as_deref(),
        std::env::var("TERM").ok().as_deref(),
    )
}

/// What a piece of the screen is, which decides its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "tui")]
enum Tone {
    /// The mark's ring and the accents.
    Brand,
    /// The star, the cursor of the list, the step being done.
    Star,
    /// Text that is read first.
    Ink,
    /// Text that is read second.
    Soft,
    Muted,
    Faint,
    /// Box lines.
    Rule,
    Warn,
}

#[cfg(feature = "tui")]
const RESET: &str = "\x1b[0m";

/// The escape sequence that selects `tone` as the text colour.
#[cfg(feature = "tui")]
fn tone(depth: Depth, tone: Tone) -> String {
    let (rgb, basic) = match tone {
        Tone::Brand => (pal::MAGENTA, 35),
        Tone::Star => (pal::CYAN, 96),
        Tone::Ink => (pal::INK, 97),
        Tone::Soft => (pal::INK2, 37),
        Tone::Muted => (pal::MUTED, 90),
        Tone::Faint => (pal::FAINT, 90),
        Tone::Rule => (pal::RULE_HI, 90),
        Tone::Warn => (pal::AMBER, 33),
    };
    match depth {
        Depth::True => format!("\x1b[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2),
        Depth::Indexed => format!("\x1b[38;5;{}m", cube(rgb)),
        Depth::Basic => format!("\x1b[{basic}m"),
    }
}

/// The background of the row the list's cursor is on. The named colours
/// have no quiet background, so there the row is shown in reverse.
#[cfg(feature = "tui")]
fn selected_background(depth: Depth) -> String {
    let rgb = pal::RAISE2;
    match depth {
        Depth::True => format!("\x1b[48;2;{};{};{}m", rgb.0, rgb.1, rgb.2),
        Depth::Indexed => format!("\x1b[48;5;{}m", cube(rgb)),
        Depth::Basic => "\x1b[7m".to_owned(),
    }
}

/// The nearest entry of the 256-colour cube (or its grey ramp).
#[cfg(feature = "tui")]
fn cube(rgb: (u8, u8, u8)) -> u8 {
    let (r, g, b) = (u16::from(rgb.0), u16::from(rgb.1), u16::from(rgb.2));
    let spread = r.max(g).max(b) - r.min(g).min(b);
    if spread < 12 {
        // Greys: 232..=255 step 10 from 8.
        let level = (r + g + b) / 3;
        return 232 + ((level.saturating_sub(8)) / 10).min(23) as u8;
    }
    let step = |value: u16| ((value * 5 + 127) / 255) as u8;
    16 + 36 * step(r) + 6 * step(g) + step(b)
}

/// One line being put together: styled text and how many cells it takes.
#[cfg(feature = "tui")]
struct Line {
    text: String,
    cells: usize,
    limit: usize,
}

#[cfg(feature = "tui")]
impl Line {
    fn new(limit: usize, margin: usize) -> Self {
        let margin = margin.min(limit);
        Self {
            text: " ".repeat(margin),
            cells: margin,
            limit,
        }
    }
    /// Add `text` in `style`, cut to what is left of the line. `text` is
    /// made safe here: a label cannot carry a control or hidden character.
    fn put(&mut self, style: &str, text: &str) -> &mut Self {
        let piece = clip(text, self.limit - self.cells);
        if !piece.is_empty() {
            self.cells += UnicodeWidthStr::width(piece.as_str());
            self.text.push_str(style);
            self.text.push_str(&piece);
            self.text.push_str(RESET);
        }
        self
    }
    /// Spaces (in `style`, which may be a background) up to `column`.
    fn pad_to(&mut self, style: &str, column: usize) -> &mut Self {
        let column = column.min(self.limit);
        if column > self.cells {
            self.text.push_str(style);
            self.text.push_str(&" ".repeat(column - self.cells));
            self.text.push_str(RESET);
            self.cells = column;
        }
        self
    }
    fn done(self) -> String {
        self.text
    }
}

/// The mark, as the terminal chat's welcome draws it: the ring in the
/// brand colour, the star in its own, the letters in ink.
#[cfg(feature = "tui")]
fn mark_rows(depth: Depth, limit: usize, margin: usize) -> Vec<String> {
    const RING: &str = "⣠⠖⠋⠙⠒⠤⠴";
    orbit_hud_tui::proto::mark::MARK_ROWS
        .iter()
        .map(|row| {
            let mut line = Line::new(limit, margin);
            for ch in row.chars() {
                let style = if ch == '✦' {
                    tone(depth, Tone::Star)
                } else if RING.contains(ch) {
                    tone(depth, Tone::Brand)
                } else {
                    format!("\x1b[1m{}", tone(depth, Tone::Ink))
                };
                line.put(&style, ch.encode_utf8(&mut [0; 4]));
            }
            line.done()
        })
        .collect()
}

/// What opens a first setup in the scroll-back: the mark and its tagline.
#[cfg(feature = "tui")]
pub(crate) fn banner(depth: Depth, columns: usize) -> String {
    let limit = columns.clamp(1, 240).saturating_sub(1);
    let margin = if limit >= 64 { 2 } else { 0 };
    let mut lines = vec![String::new()];
    if limit >= 40 {
        lines.extend(mark_rows(depth, limit, margin));
    } else {
        let mut line = Line::new(limit, margin);
        line.put(&tone(depth, Tone::Star), "✦ ")
            .put(&format!("\x1b[1m{}", tone(depth, Tone::Ink)), "ORBIT");
        lines.push(line.done());
    }
    let mut tagline = Line::new(limit, margin);
    tagline.put(
        &tone(depth, Tone::Muted),
        orbit_hud_tui::proto::mark::TAGLINE,
    );
    lines.push(tagline.done());
    lines.join("\n")
}

/// A paragraph of the scroll-back in the quiet text colour.
#[cfg(feature = "tui")]
pub(crate) fn note(depth: Depth, columns: usize, text: &str) -> String {
    let limit = columns.clamp(1, 240).saturating_sub(1);
    let margin = if limit >= 64 { 2 } else { 0 };
    text.lines()
        .map(|row| {
            let mut line = Line::new(limit, margin);
            line.put(&tone(depth, Tone::Soft), row);
            line.done()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Words of the setup in the scroll-back, under the margin and in the
/// quiet colour, with nothing cut (an address to copy stays whole) and
/// control characters made harmless.
#[cfg(feature = "tui")]
pub(crate) fn plain_note(depth: Depth, columns: usize, text: &str) -> String {
    let margin = if columns.clamp(1, 240) > 64 { "  " } else { "" };
    let colour = tone(depth, Tone::Soft);
    text.split('\n')
        .map(|row| {
            if row.is_empty() {
                String::new()
            } else {
                format!("{margin}{colour}{}{RESET}", safe_with_ansi(row))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A question asked in the scroll-back (a name, a key): marked like the
/// choice screen's input line. Line breaks before it are kept.
#[cfg(feature = "tui")]
pub(crate) fn question(depth: Depth, columns: usize, prompt: &str) -> String {
    let margin = if columns.clamp(1, 240) > 64 { "  " } else { "" };
    let text = prompt.trim_start_matches('\n');
    format!(
        "{}{margin}{}› {RESET}\x1b[1m{}{}{RESET}",
        &prompt[..prompt.len() - text.len()],
        tone(depth, Tone::Star),
        tone(depth, Tone::Ink),
        safe_with_ansi(text)
    )
}

/// A step of the setup in the scroll-back: where it is among the steps,
/// its name, and one line on what it asks.
#[cfg(feature = "tui")]
pub(crate) fn stage_header(
    depth: Depth,
    columns: usize,
    number: usize,
    total: usize,
    title: &str,
    detail: &str,
) -> String {
    let limit = columns.clamp(1, 240).saturating_sub(1);
    let margin = if limit >= 64 { 2 } else { 0 };
    let total = total.clamp(1, 12);
    let number = number.clamp(1, total);
    let mut head = Line::new(limit, margin);
    for step in 1..=total {
        let (style, dot) = if step < number {
            (tone(depth, Tone::Brand), "●")
        } else if step == number {
            (tone(depth, Tone::Star), "●")
        } else {
            (tone(depth, Tone::Faint), "○")
        };
        head.put(&style, dot);
    }
    head.put(&tone(depth, Tone::Muted), &format!("  {number}/{total}  "))
        .put(&format!("\x1b[1m{}", tone(depth, Tone::Ink)), title);
    let mut body = Line::new(limit, margin);
    body.put(&tone(depth, Tone::Soft), detail);
    format!("\n{}\n{}", head.done(), body.done())
}

/// The rich choice screen.
/// A question as the panel's title. The plain prompt carries reminders in
/// brackets — the answers' names, the default, which key does what — that
/// the panel shows in other ways. What they hold of state (a page, a count)
/// stays, after the name: `Models · page 1/4 · 0 selected`.
#[cfg(feature = "tui")]
fn panel_title(prompt: &str) -> String {
    let Some(open) = prompt.find(" (") else {
        return prompt
            .split(" [")
            .next()
            .unwrap_or(prompt)
            .trim()
            .to_owned();
    };
    let mut title = prompt[..open].trim().to_owned();
    let inside = prompt[open + 2..].split(')').next().unwrap_or("");
    for part in inside.split([';', ',']) {
        let part = part.trim();
        let keys = ["Enter", "Finish", "name or number", "Esc", "Arrows"];
        let reminder = keys.iter().any(|key| part.starts_with(key))
            || !part.chars().any(|c| c.is_ascii_digit());
        if !part.is_empty() && !reminder {
            title.push_str(" · ");
            title.push_str(part);
        }
    }
    title
}

pub(crate) struct Screen {
    /// One styled line per terminal row, top to bottom.
    pub(crate) lines: Vec<String>,
    /// How many choices are shown at once: what Page Up and Down move by.
    pub(crate) page: usize,
}

/// The smallest terminal the rich screen is drawn in. A smaller one gets
/// the plain [`frame`].
pub(crate) const SCREEN_MIN: (usize, usize) = (40, 12);

/// Draw the choices as a panel under ORBIT's mark: the row the cursor is
/// on stands out, what a choice means is said under the list, and what was
/// typed and the keys that work are at the foot.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "tui")]
pub(crate) fn screen(
    title: &str,
    choices: &[SetupChoice<'_>],
    menu: &Menu,
    typed: &[u8],
    error: &str,
    columns: usize,
    rows: usize,
    allow_back: bool,
    depth: Depth,
) -> Screen {
    let limit = columns.clamp(1, 240).saturating_sub(1);
    let rows = rows.clamp(1, 120);
    let margin = if limit >= 64 { 2 } else { 0 };
    // The panel: its border, one space inside, the text.
    let width = (limit - margin.min(limit)).min(78);
    let inner = width.saturating_sub(4);
    let left = margin;
    let right = margin + width;

    // The mark when there is room for it and a real list under it.
    let with_mark = rows >= 24 && width >= 40;
    let header = if with_mark { 6 } else { 2 };
    // Header, the box's two lines, the detail, the notice, the input, the
    // keys; and the terminal's last row is left alone.
    let page = rows.saturating_sub(header + 2 + 4 + 1).max(1);
    let start = menu
        .selected
        .saturating_sub(page - 1)
        .min(choices.len().saturating_sub(page));
    let end = (start + page).min(choices.len());

    let rule = tone(depth, Tone::Rule);
    let bold_ink = format!("\x1b[1m{}", tone(depth, Tone::Ink));
    let mut lines = Vec::new();

    if with_mark {
        lines.push(String::new());
        lines.extend(mark_rows(depth, limit, margin));
        let mut tagline = Line::new(limit, margin);
        tagline.put(
            &tone(depth, Tone::Muted),
            orbit_hud_tui::proto::mark::TAGLINE,
        );
        lines.push(tagline.done());
        lines.push(String::new());
    } else {
        let mut brand = Line::new(limit, margin);
        brand
            .put(&tone(depth, Tone::Star), "✦ ")
            .put(&bold_ink, "ORBIT")
            .put(&tone(depth, Tone::Muted), "  setup");
        lines.push(brand.done());
        lines.push(String::new());
    }

    // ╭─ Title ─────────────╮
    let mut top = Line::new(limit, left);
    top.put(&rule, "╭─ ");
    let room = (right.saturating_sub(top.cells)).saturating_sub(3);
    // The foot of the screen says how to answer; the question's own
    // reminder of it would say so twice.
    let name = clip(&panel_title(title), room);
    top.put(&bold_ink, &name).put(&rule, " ");
    let fill = right.saturating_sub(top.cells + 1);
    top.put(&rule, &"─".repeat(fill)).put(&rule, "╮");
    lines.push(top.done());

    let digits = choices.len().to_string().len();
    let highlight = selected_background(depth);
    for (index, choice) in choices.iter().enumerate().take(end).skip(start) {
        let chosen = index == menu.selected;
        let back = if chosen { highlight.as_str() } else { "" };
        let mut row = Line::new(limit, left);
        row.put(&rule, "│");
        row.put(back, " ");
        row.put(
            &format!("{back}\x1b[1m{}", tone(depth, Tone::Star)),
            if chosen { "❯ " } else { "  " },
        );
        row.put(
            &format!(
                "{back}{}",
                tone(depth, if chosen { Tone::Soft } else { Tone::Faint })
            ),
            &format!("{:>digits$}  ", index + 1),
        );
        // "name — what it is": the name is read first.
        let (name, rest) = match choice.label.split_once(" — ") {
            Some((name, rest)) => (name, Some(rest)),
            None => (choice.label, None),
        };
        let text_end = left + 2 + inner;
        let name_style = if chosen {
            format!("{back}{bold_ink}")
        } else {
            format!("{back}{}", tone(depth, Tone::Soft))
        };
        // Leave the border's column free whatever the label holds.
        let room = text_end.saturating_sub(row.cells);
        row.put(&name_style, &clip(name, room));
        if let Some(rest) = rest {
            let room = text_end.saturating_sub(row.cells);
            row.put(
                &format!("{back}{}", tone(depth, Tone::Muted)),
                &clip(&format!("  {rest}"), room),
            );
        }
        row.pad_to(back, right.saturating_sub(1));
        row.put(&rule, "│");
        lines.push(row.done());
    }

    // ╰──────── ▲ 3 of 10 ▼ ─╯
    let position = format!(
        "{}{} of {}{}",
        if start > 0 { "▲ " } else { "" },
        (menu.selected + 1).min(choices.len()),
        choices.len(),
        if end < choices.len() { " ▼" } else { "" }
    );
    let mut bottom = Line::new(limit, left);
    bottom.put(&rule, "╰");
    let counter = UnicodeWidthStr::width(position.as_str()) + 4;
    let fill = right.saturating_sub(bottom.cells + 1 + counter);
    bottom.put(&rule, &"─".repeat(fill));
    if right.saturating_sub(bottom.cells + 1) >= counter {
        bottom
            .put(&rule, " ")
            .put(&tone(depth, Tone::Muted), &position)
            .put(&rule, " ─");
    }
    let fill = right.saturating_sub(bottom.cells + 1);
    bottom.put(&rule, &"─".repeat(fill)).put(&rule, "╯");
    lines.push(bottom.done());

    // What the choice under the cursor means. It may carry colour of its
    // own (a theme's swatches), which is kept.
    let detail = choices
        .get(menu.selected)
        .and_then(|choice| choice.detail)
        .unwrap_or("");
    let room = limit.saturating_sub(left + 2);
    lines.push(if detail.contains('\x1b') {
        format!(
            "{}{}{RESET}",
            " ".repeat((left + 2).min(limit)),
            clip_ansi(detail, room)
        )
    } else {
        let mut line = Line::new(limit, left + 2);
        line.put(&tone(depth, Tone::Soft), detail);
        line.done()
    });

    lines.push(if error.is_empty() {
        String::new()
    } else {
        let mut notice = Line::new(limit, left + 2);
        notice
            .put(&tone(depth, Tone::Warn), "! ")
            .put(&tone(depth, Tone::Warn), error);
        notice.done()
    });

    let mut input = Line::new(limit, left + 2);
    input.put(&tone(depth, Tone::Star), "› ");
    if typed.is_empty() {
        input.put(
            &tone(depth, Tone::Faint),
            "type a number or a name to choose it directly",
        );
    } else {
        input
            .put(&bold_ink, &String::from_utf8_lossy(typed))
            .put(&tone(depth, Tone::Brand), "▏");
    }
    lines.push(input.done());

    let mut keys = Line::new(limit, left + 2);
    let hints: &[(&str, &str)] = if allow_back {
        &[
            ("↑↓", "move"),
            ("⏎", "choose"),
            ("←/esc", "back"),
            ("ctrl-c", "cancel"),
        ]
    } else {
        &[("↑↓", "move"), ("⏎", "choose"), ("esc", "cancel")]
    };
    for (index, (key, what)) in hints.iter().enumerate() {
        if index > 0 {
            keys.put("", "   ");
        }
        keys.put(&tone(depth, Tone::Soft), key)
            .put(&tone(depth, Tone::Faint), &format!(" {what}"));
    }
    lines.push(keys.done());

    Screen { lines, page }
}

#[cfg(not(feature = "tui"))]
pub(crate) use plain::{banner, note, plain_note, question, screen, stage_header};

/// Builds without the graphical frontend retain the bounded setup workflow.
#[cfg(not(feature = "tui"))]
mod plain {
    use super::*;

    pub(crate) fn banner(depth: Depth, columns: usize) -> String {
        note(depth, columns, "ORBIT / SETUP")
    }

    pub(crate) fn note(_depth: Depth, columns: usize, text: &str) -> String {
        text.lines()
            .map(|row| clip(row, columns.clamp(1, 240).saturating_sub(1)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub(crate) fn plain_note(_depth: Depth, _columns: usize, text: &str) -> String {
        text.split('\n').map(safe).collect::<Vec<_>>().join("\n")
    }

    pub(crate) fn question(depth: Depth, columns: usize, prompt: &str) -> String {
        plain_note(depth, columns, prompt)
    }

    pub(crate) fn stage_header(
        depth: Depth,
        columns: usize,
        number: usize,
        total: usize,
        title: &str,
        detail: &str,
    ) -> String {
        let total = total.clamp(1, 12);
        note(
            depth,
            columns,
            &format!("{}/{} {}\n{}", number.clamp(1, total), total, title, detail),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn screen(
        title: &str,
        choices: &[SetupChoice<'_>],
        menu: &Menu,
        typed: &[u8],
        error: &str,
        columns: usize,
        rows: usize,
        allow_back: bool,
        _depth: Depth,
    ) -> Screen {
        let mut frame = frame(title, choices, menu, typed, columns, rows, allow_back);
        if !error.is_empty() {
            frame.lines[2] = clip(error, columns.clamp(1, 240).saturating_sub(1));
        }
        Screen {
            lines: frame.lines,
            page: frame.page,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a styled line shows, without its colours.
    #[cfg(feature = "tui")]
    fn shown(line: &str) -> String {
        let mut out = String::new();
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn providers() -> Vec<SetupChoice<'static>> {
        vec![
            SetupChoice {
                id: "openrouter-browser",
                label: "openrouter — sign in with your browser",
                detail: Some("OpenRouter — one key, many providers' models"),
            },
            SetupChoice {
                id: "anthropic",
                label: "anthropic",
                detail: Some("Anthropic — Claude models over the native Messages API"),
            },
            SetupChoice {
                id: "custom",
                label: "custom",
                detail: None,
            },
        ]
    }

    /// The rich screen at an ordinary size: the mark, a panel named for
    /// the question, the cursor's row marked, its meaning under the list.
    #[cfg(feature = "tui")]
    #[test]
    fn the_rich_screen_is_a_panel_under_the_mark() {
        let choices = providers();
        let mut menu = Menu::new(choices.len(), None);
        menu.navigate(Key::Down, 5);
        let drawn = screen(
            "Provider",
            &choices,
            &menu,
            &[],
            "",
            100,
            30,
            false,
            Depth::True,
        );
        let text: Vec<String> = drawn.lines.iter().map(|line| shown(line)).collect();
        assert_eq!(
            text,
            [
                "",
                "     ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
                "  ⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
                "  ⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
                "  the harness that orbits around you",
                "",
                "  ╭─ Provider ─────────────────────────────────────────────────────────────────╮",
                "  │   1  openrouter  sign in with your browser                                 │",
                "  │ ❯ 2  anthropic                                                             │",
                "  │   3  custom                                                                │",
                "  ╰────────────────────────────────────────────────────────────────── 2 of 3 ──╯",
                "    Anthropic — Claude models over the native Messages API",
                "",
                "    › type a number or a name to choose it directly",
                "    ↑↓ move   ⏎ choose   esc cancel",
            ]
        );
        // The box is 78 wide and its corners sit over its sides.
        for line in &text[6..11] {
            assert_eq!(UnicodeWidthStr::width(line.as_str()), 80, "{line}");
        }
        // The cursor's row, and only it, has the highlight behind it.
        let highlight = selected_background(Depth::True);
        let lit: Vec<usize> = drawn
            .lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains(&highlight))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(lit, [8]);
        assert!(drawn.lines[1].contains(&tone(Depth::True, Tone::Star)));

        // What was typed, a notice, and the way back.
        let typed = screen(
            "Provider",
            &choices,
            &menu,
            b"anth",
            "Choose an offered number.",
            100,
            30,
            true,
            Depth::Basic,
        );
        let text: Vec<String> = typed.lines.iter().map(|line| shown(line)).collect();
        assert_eq!(text[12], "    ! Choose an offered number.");
        assert_eq!(text[13], "    › anth▏");
        assert_eq!(
            text[14],
            "    ↑↓ move   ⏎ choose   ←/esc back   ctrl-c cancel"
        );
        assert!(
            !typed.lines.join("").contains("38;2;"),
            "named colours only"
        );
    }

    /// At any size the rich screen is asked for, with any labels, no line
    /// is wider than the terminal less a column, nothing hidden or
    /// controlling gets through, the screen fits the rows, and the cursor's
    /// row is on it.
    #[cfg(feature = "tui")]
    #[test]
    fn the_rich_screen_fits_and_stays_safe() {
        let ids: Vec<String> = (0..40)
            .map(|n| match n % 4 {
                0 => format!(
                    "provider/raw/{n} — a very long note about this choice {}",
                    "x".repeat(90)
                ),
                1 => format!("中文模型/{n}\u{202e}\u{200b}evil"),
                2 => format!("e\u{301}mo👨‍👩‍👧‍👦/{n}\x1b[2J\x07"),
                _ => format!("m{n}"),
            })
            .collect();
        let choices: Vec<_> = ids
            .iter()
            .map(|id| SetupChoice {
                id: "internal-id",
                label: id,
                detail: Some("detail \x1b[31mwith colour\x1b[0m and a tail that is long enough to be cut somewhere"),
            })
            .collect();
        for selected in [0, 1, 2, 17, 39] {
            let mut menu = Menu::new(choices.len(), Some(selected));
            menu.armed = true;
            for (columns, rows) in [
                (40, 12),
                (41, 13),
                (63, 23),
                (64, 24),
                (80, 24),
                (120, 40),
                (240, 120),
                (500, 500),
            ] {
                for depth in [Depth::True, Depth::Indexed, Depth::Basic] {
                    let drawn = screen(
                        "Models (name or number)",
                        &choices,
                        &menu,
                        b"typed \xff text",
                        "an error",
                        columns,
                        rows,
                        true,
                        depth,
                    );
                    assert!(
                        drawn.lines.len() < rows.min(120),
                        "{columns}x{rows}: {} lines",
                        drawn.lines.len()
                    );
                    assert!(drawn.page >= 1);
                    let text: Vec<String> = drawn.lines.iter().map(|line| shown(line)).collect();
                    for line in &text {
                        assert!(
                            UnicodeWidthStr::width(line.as_str()) < columns.min(240),
                            "{columns}x{rows}: {line:?}"
                        );
                        assert!(!line.chars().any(char::is_control), "{line:?}");
                        assert!(!line.contains('\u{202e}') && !line.contains('\u{200b}'));
                        assert!(!line.contains("internal-id"));
                    }
                    assert_eq!(
                        text.iter().filter(|line| line.contains('❯')).count(),
                        1,
                        "{columns}x{rows} at {selected}: the cursor's row is shown"
                    );
                    // The box's sides line up on every row of the list.
                    let sides: Vec<usize> = text
                        .iter()
                        .filter(|line| line.trim_start().starts_with('│'))
                        .map(|line| UnicodeWidthStr::width(line.as_str()))
                        .collect();
                    assert!(sides.windows(2).all(|pair| pair[0] == pair[1]), "{sides:?}");
                }
            }
        }
        let hidden = screen(
            "Models",
            &choices[1..2],
            &Menu::new(1, Some(0)),
            &[],
            "",
            80,
            24,
            true,
            Depth::True,
        );
        assert!(shown(&hidden.lines.join("\n")).contains("⟦U+202E⟧⟦U+200B⟧evil"));
    }

    /// The scroll-back pieces: the banner, a step's header, a note.
    #[cfg(feature = "tui")]
    #[test]
    fn the_scroll_back_pieces_are_drawn_in_the_same_hand() {
        let wide: Vec<String> = banner(Depth::Indexed, 100).lines().map(shown).collect();
        assert_eq!(wide.len(), 5);
        assert_eq!(wide[1], "     ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀");
        assert_eq!(wide[4], "  the harness that orbits around you");
        let narrow: Vec<String> = banner(Depth::Basic, 30).lines().map(shown).collect();
        assert_eq!(narrow, ["", "✦ ORBIT", "the harness that orbits aroun"]);

        let header = stage_header(Depth::True, 100, 2, 6, "Sign in\x1b[2J", "Paste a key.");
        assert_eq!(
            shown(&header),
            "\n  ●●○○○○  2/6  Sign in [2J\n  Paste a key."
        );
        assert!(header.contains(&tone(Depth::True, Tone::Star)));
        assert_eq!(shown(&note(Depth::True, 100, "one\ntwo")), "  one\n  two");
        // A long address is not cut, an empty line stays empty.
        let address = format!("Open https://example.test/{}", "a".repeat(300));
        assert_eq!(
            shown(&plain_note(Depth::True, 100, &format!("\n{address}\x07"))),
            format!("\n  {address} ")
        );
        assert_eq!(
            shown(&question(Depth::Basic, 100, "\nAPI key (hidden): ")),
            "\n  › API key (hidden): "
        );
        assert_eq!(depth(Some("truecolor"), Some("xterm")), Depth::True);
        assert_eq!(depth(None, Some("xterm-256color")), Depth::Indexed);
        assert_eq!(depth(None, Some("vt100")), Depth::Basic);
        assert_eq!(cube((255, 255, 255)), 255);
        assert_eq!(cube(pal::MAGENTA), 16 + 36 * 4 + 6 * 2 + 4);
    }
    #[test]
    fn unicode_clip_never_splits_a_cluster_or_exceeds_cells() {
        for text in [
            "alpha",
            "中中文",
            "e\u{301}next",
            "👨‍👩‍👧‍👦 tail",
            "\x1b[31mred\u{202e}text",
        ] {
            for width in 0..20 {
                let clipped = clip(text, width);
                assert!(UnicodeWidthStr::width(clipped.as_str()) <= width);
                assert!(!clipped.chars().any(char::is_control));
                assert!(!clipped.contains('\u{202e}'));
            }
        }
        assert_eq!(clip("e\u{301}x", 1), "e\u{301}");
        assert_eq!(clip("中x", 1), "");
    }
    #[test]
    fn frame_displays_invisible_code_points_without_collapsing_identifiers() {
        let hidden = "vendor\u{202e}/model\u{200b}-fast";
        let choices = [SetupChoice {
            id: hidden,
            label: hidden,
            detail: None,
        }];
        let rendered = frame(
            "Models",
            &choices,
            &Menu::new(1, Some(0)),
            &[],
            80,
            24,
            true,
        );
        let text = rendered.lines.join("\n");
        assert!(text.contains("vendor⟦U+202E⟧/model⟦U+200B⟧-fast"));
        assert!(!text.contains('\u{200b}'));
        assert_ne!(safe("model\u{200b}x"), safe("modelx"));
    }
    #[test]
    fn scroll_and_resize_keep_exact_last_identity_visible() {
        let ids: Vec<_> = (0..32).map(|n| format!("provider/raw/{n}")).collect();
        let choices: Vec<_> = ids
            .iter()
            .map(|id| SetupChoice {
                id,
                label: id,
                detail: None,
            })
            .collect();
        let mut menu = Menu::new(choices.len(), None);
        menu.navigate(Key::End, 5);
        for (columns, rows) in [(160, 32), (40, 10), (1, 1), (160, 32)] {
            let rendered = frame("Models", &choices, &menu, &[], columns, rows, true);
            assert_eq!(menu.selected, 31);
            assert!(rendered.selected_line < rendered.lines.len());
            assert!(
                rendered
                    .lines
                    .iter()
                    .all(|line| UnicodeWidthStr::width(line.as_str()) <= columns.saturating_sub(1))
            );
        }
        menu.navigate(Key::Home, 5);
        assert_eq!(menu.selected, 0);
    }
    #[test]
    fn frame_shows_human_label_instead_of_internal_choice_id() {
        let choices = [SetupChoice {
            id: "provider:add",
            label: "Add or replace a provider",
            detail: Some("Use a supported sign-in or API key"),
        }];
        let menu = Menu::new(choices.len(), Some(0));
        let rendered = frame("Configuration", &choices, &menu, &[], 80, 24, true);
        let text = rendered.lines.join("\n");
        assert!(text.contains("1 of 1  |  Add or replace a provider"));
        assert!(!text.contains("provider:add"));
    }
    #[test]
    fn known_escape_sequences_are_bounded_and_do_not_become_text() {
        assert_eq!(key(b"\x1b[A"), Some(Key::Up));
        assert_eq!(key(b"\x1b[D"), Some(Key::Back));
        assert_eq!(key(b"\x1b[6~"), Some(Key::PageDown));
        assert_eq!(key(b"\x1b[200~"), Some(Key::Ignore));
        assert_eq!(key(b"\x1b["), None);
        assert_eq!(key(&[27; 16]), Some(Key::Ignore));
    }

    #[cfg(feature = "tui")]
    #[test]
    fn panel_titles_keep_state_and_drop_reminders() {
        for (prompt, title) in [
            ("Models (name or number)", "Models"),
            ("Model source (manual/discover) [manual]", "Model source"),
            (
                "Discovered models (page 1/4, 0 selected; Enter toggles, Finish continues)",
                "Discovered models · page 1/4 · 0 selected",
            ),
            ("Provider", "Provider"),
            ("Main model ID", "Main model ID"),
            ("Adapter kind [openai-compatible]", "Adapter kind"),
        ] {
            assert_eq!(panel_title(prompt), title, "{prompt}");
        }
    }

    #[cfg(not(feature = "tui"))]
    #[test]
    fn setup_without_graphical_frontend_keeps_choices_notices_and_copyable_text() {
        let choices = providers();
        let rendered = screen(
            "Provider\x1b[2J",
            &choices,
            &Menu::new(choices.len(), Some(1)),
            b"anth",
            "Choose an offered provider.",
            80,
            24,
            true,
            Depth::True,
        );
        let text = rendered.lines.join("\n");
        assert!(text.contains("> 2. anthropic"));
        assert!(text.contains("Choose an offered provider."));
        assert!(!text.contains('\x1b'));
        assert!(rendered.page > 0);
        assert!(
            rendered
                .lines
                .iter()
                .all(|line| UnicodeWidthStr::width(line.as_str()) < 80)
        );
        let address = format!("https://example.test/{}", "x".repeat(300));
        assert_eq!(plain_note(Depth::True, 80, &address), address);
    }
}
