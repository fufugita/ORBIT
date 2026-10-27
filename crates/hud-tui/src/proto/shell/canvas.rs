//! A cell canvas over a ratatui buffer: `put`, `fill`, `spans` with a
//! clip rectangle, the same drawing vocabulary the prototype paints
//! with. Colours are true-colour [`Rgb`] triples so tints can be mixed;
//! `None` as a background keeps whatever is already in the cell.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use std::borrow::Cow;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// A true-colour value.
pub type Rgb = (u8, u8, u8);

/// Furniture only: user text remains readable and no terminal escapes are introduced.
pub fn ascii_glyph(ch: char) -> char {
    match ch {
        '─' | '━' | '╌' | '┄' | '▰' | '▱' => '-',
        '│' | '┃' | '▏' | '▎' | '▍' | '▌' | '▐' => '|',
        '╭' | '╮' | '╰' | '╯' | '┏' | '┓' | '┗' | '┛' | '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬'
        | '┴' | '┼' => '+',
        '✓' => '+',
        '✕' | '×' | '⊘' | '⊖' => 'x',
        '✦' | '◆' | '◇' | '●' | '◉' | '○' | '◌' | '◐' | '◓' | '◑' | '◒' | '◜' | '◝' | '◞' | '◟'
        | '∙' | '·' => '*',
        '›' | '→' | '▶' | '▸' => '>',
        '‹' | '←' | '◀' | '▾' => '<',
        '…' => '.',
        _ => ch,
    }
}

/// Linear mix: `t = 0` → `a`, `t = 1` → `b`.
pub fn mix(a: Rgb, b: Rgb, t: f32) -> Rgb {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    (f(a.0, b.0), f(a.1, b.1), f(a.2, b.2))
}

/// `col` laid over `base` at strength `amt` (the prototype's `tint`).
pub fn tint(col: Rgb, base: Rgb, amt: f32) -> Rgb {
    mix(base, col, amt)
}

pub fn c(rgb: Rgb) -> Color {
    Color::Rgb(rgb.0, rgb.1, rgb.2)
}

/// One styled run of text.
#[derive(Debug, Clone)]
pub struct Seg {
    pub text: String,
    pub fg: Rgb,
    pub bold: bool,
}

impl Seg {
    pub fn new(text: impl Into<String>, fg: Rgb) -> Self {
        Seg {
            text: text.into(),
            fg,
            bold: false,
        }
    }
    pub fn bold(text: impl Into<String>, fg: Rgb) -> Self {
        Seg {
            text: text.into(),
            fg,
            bold: true,
        }
    }
    pub fn width(&self) -> i32 {
        text_width(&self.text)
    }
}

pub fn segs_width(parts: &[Seg]) -> i32 {
    let mut text = String::new();
    for part in parts {
        text.push_str(&part.text);
    }
    text_width(&text)
}

/// Display width of a string in cells.
pub fn text_width(s: &str) -> i32 {
    s.graphemes(true).fold(0i32, |width, grapheme| {
        let display = printable_grapheme(grapheme);
        let grapheme_width =
            i32::try_from(UnicodeWidthStr::width(display.as_ref())).unwrap_or(i32::MAX);
        width.saturating_add(grapheme_width)
    })
}

/// Convert a raw grapheme into a printable terminal symbol without changing
/// the text retained in drafts, transcripts, or provider requests.
fn printable_grapheme(grapheme: &str) -> Cow<'_, str> {
    if grapheme.contains('\n') {
        Cow::Borrowed("⏎")
    } else if grapheme == "\t" {
        Cow::Borrowed("⇥")
    } else if grapheme.chars().any(char::is_control) {
        Cow::Owned(
            grapheme
                .chars()
                .map(|ch| {
                    let code = u32::from(ch);
                    match code {
                        0x00..=0x1f => char::from_u32(0x2400 + code).unwrap_or('�'),
                        0x7f => '␡',
                        _ => '�',
                    }
                })
                .collect(),
        )
    } else if UnicodeWidthStr::width(grapheme) == 0 {
        let mut visible = String::from("◌");
        visible.push_str(grapheme);
        Cow::Owned(visible)
    } else {
        Cow::Borrowed(grapheme)
    }
}

pub(in crate::proto) fn printable_text(text: &str) -> String {
    text.graphemes(true)
        .map(|grapheme| printable_grapheme(grapheme).into_owned())
        .collect()
}

/// End-clip to `n` cells with a trailing `…`.
pub fn clip_text(s: &str, n: i32) -> String {
    if n <= 0 {
        return String::new();
    }
    if text_width(s) <= n {
        return printable_text(s);
    }
    let mut out = String::new();
    let mut used = 0i32;
    for grapheme in s.graphemes(true) {
        let display = printable_grapheme(grapheme);
        let width = text_width(display.as_ref());
        if used.saturating_add(width) > n - 1 {
            break;
        }
        out.push_str(display.as_ref());
        used += width;
    }
    out.push('…');
    out
}

/// Clip a path to `n` cells from the LEFT, with a leading `…`: the end
/// of a path (the file name) is the part that identifies it, so it is
/// what must survive.
pub fn clip_path(s: &str, n: i32) -> String {
    if n <= 0 {
        return String::new();
    }
    if text_width(s) <= n {
        return printable_text(s);
    }
    let mut tail: Vec<String> = Vec::new();
    let mut used = 0i32;
    for grapheme in s.graphemes(true).rev() {
        let display = printable_grapheme(grapheme).into_owned();
        let width = text_width(&display);
        if used.saturating_add(width) > n - 1 {
            break;
        }
        tail.push(display);
        used += width;
    }
    tail.reverse();
    format!("…{}", tail.concat())
}

/// The canvas: a buffer plus a clip rectangle, and the clickable regions
/// drawn so far (shared by every clipped view of the same canvas).
pub struct Cv<'a> {
    pub buf: &'a mut Buffer,
    pub clip: Rect,
    pub palette: super::pal::Palette,
    pub compact: bool,
    pub ascii: bool,
    hits: std::rc::Rc<std::cell::RefCell<Vec<super::hits::Hit>>>,
}

impl<'a> Cv<'a> {
    pub fn new(buf: &'a mut Buffer) -> Self {
        let clip = buf.area;
        Cv {
            buf,
            clip,
            palette: super::pal::Palette::default(),
            compact: false,
            ascii: false,
            hits: Default::default(),
        }
    }

    pub fn with_profile(
        buf: &'a mut Buffer,
        profile: &orbit_frontend_protocol::customization::Profile,
    ) -> Self {
        let mut cv = Self::new(buf);
        cv.palette = super::pal::Palette::from_profile(profile);
        cv.compact = profile.density == orbit_frontend_protocol::customization::Density::Compact;
        cv.ascii = profile.glyphs == orbit_frontend_protocol::customization::Glyphs::Ascii;
        cv
    }

    /// Run `f` with the clip narrowed to `r` (intersected).
    pub fn clipped<R>(&mut self, r: Rect, f: impl FnOnce(&mut Cv<'_>) -> R) -> R {
        let inter = self.clip.intersection(r);
        let mut inner = Cv {
            buf: &mut *self.buf,
            clip: inter,
            palette: self.palette,
            compact: self.compact,
            ascii: self.ascii,
            hits: std::rc::Rc::clone(&self.hits),
        };
        f(&mut inner)
    }

    /// Mark the cells `(x, y, w, h)` clickable: a click there does `click`.
    /// Only the part inside the clip counts — a control scrolled or clipped
    /// out of sight must not be clickable where it cannot be seen.
    pub fn hit(&mut self, x: i32, y: i32, w: i32, h: i32, click: super::hits::Click) {
        if w <= 0 || h <= 0 {
            return;
        }
        let (x0, y0) = (x.max(0), y.max(0));
        let (x1, y1) = ((x + w).max(0), (y + h).max(0));
        let want = Rect {
            x: x0.min(u16::MAX as i32) as u16,
            y: y0.min(u16::MAX as i32) as u16,
            width: (x1 - x0).clamp(0, u16::MAX as i32) as u16,
            height: (y1 - y0).clamp(0, u16::MAX as i32) as u16,
        };
        let rect = self.clip.intersection(want);
        if rect.width == 0 || rect.height == 0 {
            return;
        }
        self.hits
            .borrow_mut()
            .push(super::hits::Hit { rect, click });
    }

    /// How many regions exist now, to drop the ones drawn after this
    /// point with `truncate_hits`.
    pub fn hit_mark(&self) -> usize {
        self.hits.borrow().len()
    }

    /// Forget the regions drawn since `mark`.
    pub fn truncate_hits(&mut self, mark: usize) {
        self.hits.borrow_mut().truncate(mark);
    }

    /// The regions drawn so far, in drawing order (later = on top).
    pub fn take_hits(&mut self) -> Vec<super::hits::Hit> {
        std::mem::take(&mut *self.hits.borrow_mut())
    }

    fn inside(&self, x: i32, y: i32) -> bool {
        x >= self.clip.x as i32
            && y >= self.clip.y as i32
            && x < self.clip.right() as i32
            && y < self.clip.bottom() as i32
    }

    fn inside_buffer(&self, x: i32, y: i32) -> bool {
        x >= self.buf.area.x as i32
            && y >= self.buf.area.y as i32
            && x < self.buf.area.right() as i32
            && y < self.buf.area.bottom() as i32
    }

    /// Find the cell footprint of the glyph that owns this buffer cell.
    fn glyph_footprint_at(&self, x: i32, y: i32) -> Option<(i32, i32)> {
        if !self.inside_buffer(x, y) {
            return None;
        }

        let symbol = self.buf[(x as u16, y as u16)].symbol();
        let current_width = text_width(symbol);
        if current_width > 0 {
            return Some((x, current_width));
        }
        if x > self.buf.area.x as i32 {
            let previous_x = x - 1;
            let previous = self.buf[(previous_x as u16, y as u16)].symbol();
            let previous_width = text_width(previous);
            if previous_width > 1 && previous_x.saturating_add(previous_width) > x {
                return Some((previous_x, previous_width));
            }
        }
        Some((x, 1))
    }

    fn footprint_inside_clip(&self, x: i32, y: i32, width: i32) -> bool {
        width > 0 && self.inside(x, y) && self.inside(x.saturating_add(width - 1), y)
    }

    /// Clear a glyph footprint already confirmed to fit wholly inside the clip.
    fn clear_glyph_footprint(&mut self, x: i32, y: i32, width: i32) {
        for cell_x in x..x.saturating_add(width) {
            let cell = &mut self.buf[(cell_x as u16, y as u16)];
            cell.set_symbol(" ");
            // Preserve the cell background: put with bg=None promises that an
            // overwrite does not erase a panel's existing tint.
            cell.set_fg(Color::Reset);
            cell.modifier = Modifier::empty();
        }
    }

    /// Paint one string at (x, y); returns the next x. `bg = None`
    /// keeps the cell's existing background.
    pub fn put(
        &mut self,
        x: i32,
        y: i32,
        s: &str,
        fg: Rgb,
        bg: Option<Rgb>,
        mods: Modifier,
    ) -> i32 {
        let mut cx = x;
        let mut glyphs = Vec::new();
        for grapheme in s.graphemes(true) {
            let display = printable_grapheme(grapheme);
            let symbol = if self.ascii {
                display.chars().map(ascii_glyph).collect::<String>()
            } else {
                display.into_owned()
            };
            let w = text_width(&symbol);
            if w == 0 {
                continue;
            }
            let end = cx.saturating_add(w);
            glyphs.push((cx, end, symbol));
            cx = end;
        }

        if y < self.clip.y as i32 || y >= self.clip.bottom() as i32 {
            return cx;
        }

        // Validate each grapheme and its old footprint before changing either.
        // A grapheme that cannot fit in the clip leaves neighboring text intact.
        let clip_left = self.clip.x as i32;
        let clip_right = self.clip.right() as i32;
        for (start, end, symbol) in &glyphs {
            if *end <= clip_left || *start >= clip_right {
                continue;
            }
            if *start < clip_left || *end > clip_right {
                continue;
            }
            let mut footprints = Vec::new();
            let mut safe_to_replace = true;
            for cell_x in *start..*end {
                let Some(footprint) = self.glyph_footprint_at(cell_x, y) else {
                    safe_to_replace = false;
                    break;
                };
                if !self.footprint_inside_clip(footprint.0, y, footprint.1) {
                    safe_to_replace = false;
                    break;
                }
                if !footprints.contains(&footprint) {
                    footprints.push(footprint);
                }
            }
            if !safe_to_replace {
                continue;
            }
            for (old_start, width) in footprints {
                self.clear_glyph_footprint(old_start, y, width);
            }
            let mut style = Style::default().fg(c(fg)).add_modifier(mods);
            if let Some(bg) = bg {
                style = style.bg(c(bg));
            }
            for cell_x in *start..*end {
                let cell = &mut self.buf[(cell_x as u16, y as u16)];
                cell.set_symbol(if cell_x == *start {
                    symbol.as_str()
                } else {
                    ""
                });
                cell.set_style(style);
            }
        }
        cx
    }

    pub fn text(&mut self, x: i32, y: i32, s: &str, fg: Rgb, bg: Option<Rgb>) -> i32 {
        self.put(x, y, s, fg, bg, Modifier::empty())
    }

    pub fn bold(&mut self, x: i32, y: i32, s: &str, fg: Rgb, bg: Option<Rgb>) -> i32 {
        self.put(x, y, s, fg, bg, Modifier::BOLD)
    }

    /// Paint a run of segments; returns the next x.
    pub fn spans(&mut self, x: i32, y: i32, parts: &[Seg], bg: Option<Rgb>) -> i32 {
        // A style boundary can fall between scalars that form one grapheme.
        // Join text before segmentation and use the leading scalar's style for
        // the cell, since a terminal cannot style parts of one cell separately.
        let mut text = String::new();
        let mut styles = Vec::new();
        for part in parts {
            let start = text.len();
            text.push_str(&part.text);
            let end = text.len();
            if start < end {
                styles.push((start, end, part.fg, part.bold));
            }
        }

        let mut cx = x;
        let mut style_index = 0usize;
        for (start, grapheme) in text.grapheme_indices(true) {
            while style_index + 1 < styles.len() && start >= styles[style_index].1 {
                style_index += 1;
            }
            let Some((range_start, range_end, fg, bold)) = styles.get(style_index) else {
                continue;
            };
            if start < *range_start || start >= *range_end {
                continue;
            }
            let m = if *bold {
                Modifier::BOLD
            } else {
                Modifier::empty()
            };
            cx = self.put(cx, y, grapheme, *fg, bg, m);
        }
        cx
    }

    /// Fill a rectangle with a background (clearing glyphs).
    pub fn fill(&mut self, x: i32, y: i32, w: i32, h: i32, bg: Rgb) {
        if w <= 0 || h <= 0 {
            return;
        }
        let x0 = x.max(self.clip.x as i32);
        let y0 = y.max(self.clip.y as i32);
        let x1 = x.saturating_add(w).min(self.clip.right() as i32);
        let y1 = y.saturating_add(h).min(self.clip.bottom() as i32);
        let mut fill_cells = Vec::new();
        let mut footprints = Vec::new();
        for yy in y0..y1 {
            for xx in x0..x1 {
                let Some(footprint) = self.glyph_footprint_at(xx, yy) else {
                    continue;
                };
                if !self.footprint_inside_clip(footprint.0, yy, footprint.1) {
                    continue;
                }
                fill_cells.push((xx, yy));
                let footprint = (footprint.0, yy, footprint.1);
                if !footprints.contains(&footprint) {
                    footprints.push(footprint);
                }
            }
        }
        for (start, yy, width) in footprints {
            self.clear_glyph_footprint(start, yy, width);
        }
        for (xx, yy) in fill_cells {
            let cell = &mut self.buf[(xx as u16, yy as u16)];
            cell.set_symbol(" ");
            cell.set_style(Style::default().bg(c(bg)));
        }
    }

    /// Dim a rectangle toward `toward` (the prototype's `veil`): the
    /// foreground by `amt`, the background by 70% of it.
    pub fn veil(&mut self, x: i32, y: i32, w: i32, h: i32, toward: Rgb, amt: f32) {
        let unpack = |c: Color| match c {
            Color::Rgb(r, g, b) => Some((r, g, b)),
            _ => None,
        };
        for yy in y..y + h {
            for xx in x..x + w {
                if self.inside(xx, yy) {
                    let cell = &mut self.buf[(xx as u16, yy as u16)];
                    if let Some(fg) = unpack(cell.fg) {
                        cell.set_fg(c(mix(fg, toward, amt)));
                    }
                    if let Some(bg) = unpack(cell.bg) {
                        cell.set_bg(c(mix(bg, toward, amt * 0.7)));
                    }
                }
            }
        }
    }

    /// Re-colour the background of a rectangle without touching glyphs.
    pub fn wash(&mut self, x: i32, y: i32, w: i32, h: i32, bg: Rgb) {
        for yy in y..y + h {
            for xx in x..x + w {
                if self.inside(xx, yy) {
                    self.buf[(xx as u16, yy as u16)].set_bg(c(bg));
                }
            }
        }
    }
}

/// Word-wrap `text` to `w` cells, returning `(start, end)` char
/// ranges. Long words split at grapheme boundaries; a grapheme wider than
/// the line occupies a line by itself.
pub fn wrap_ranges(text: &str, w: i32) -> Vec<(usize, usize)> {
    struct Cluster<'a> {
        text: &'a str,
        char_start: usize,
        char_end: usize,
        width: usize,
    }

    let mut clusters = Vec::new();
    let mut char_offset = 0usize;
    for grapheme in text.graphemes(true) {
        let char_end = char_offset + grapheme.chars().count();
        clusters.push(Cluster {
            text: grapheme,
            char_start: char_offset,
            char_end,
            width: text_width(grapheme).max(0) as usize,
        });
        char_offset = char_end;
    }
    let width = usize::try_from(w.max(1)).unwrap_or(1);
    let mut out = Vec::new();
    let mut i = 0;
    if clusters.is_empty() {
        return vec![(0, 0)];
    }
    while i < clusters.len() {
        if clusters[i].text.contains('\n') {
            out.push((clusters[i].char_start, clusters[i].char_start));
            i += 1;
            continue;
        }

        let mut end = i;
        let mut used = 0usize;
        let mut last_space = None;
        while end < clusters.len() && !clusters[end].text.contains('\n') {
            let cluster_width = clusters[end].width;
            if used.saturating_add(cluster_width) > width {
                if end == i {
                    // A single grapheme may be wider than the requested line.
                    // Keep it intact rather than split the cluster or loop.
                    end += 1;
                }
                break;
            }
            used += cluster_width;
            if clusters[end].text == " " {
                last_space = Some(end);
            }
            end += 1;
        }

        if end < clusters.len() && clusters[end].text.contains('\n') {
            out.push((clusters[i].char_start, clusters[end].char_start));
            i = end + 1;
            continue;
        }
        if end < clusters.len()
            && clusters[end].text != " "
            && let Some(space) = last_space
            && space > i
        {
            end = space;
        }
        if end == i {
            end += 1;
        }
        let char_end = if end < clusters.len() {
            clusters[end].char_start
        } else {
            clusters.last().map_or(0, |cluster| cluster.char_end)
        };
        out.push((clusters[i].char_start, char_end));
        i = end;
        while i < clusters.len() && clusters[i].text == " " {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_on_spaces() {
        let r = wrap_ranges("the restored namespace starts a brand-new chain", 20);
        let t: Vec<String> = r
            .iter()
            .map(|&(a, b)| "the restored namespace starts a brand-new chain"[a..b].to_string())
            .collect();
        assert_eq!(t, ["the restored", "namespace starts a", "brand-new chain"]);
    }

    #[test]
    fn clip_adds_ellipsis() {
        assert_eq!(clip_text("abcdefgh", 5), "abcd…");
        assert_eq!(clip_text("abc", 5), "abc");
    }

    #[test]
    fn widths_measure_graphemes_in_terminal_cells() {
        assert_eq!(Seg::new("e\u{301}", (0, 0, 0)).width(), 1);
        assert_eq!(text_width("界"), 2);
        assert_eq!(text_width("🇧🇷"), 2);
        assert_eq!(text_width("❤️"), 2);
        assert_eq!(text_width("👩🏽‍💻"), 2);
    }

    #[test]
    fn standalone_zero_width_grapheme_has_display_only_dotted_circle() {
        for raw in ["\u{301}", "\u{fe0f}", "\u{200d}"] {
            let display = format!("◌{raw}");
            assert_eq!(UnicodeWidthStr::width(raw), 0, "{raw:?}");
            assert_eq!(text_width(raw), 1, "{raw:?}");
            assert_eq!(clip_text(raw, 1), display, "{raw:?}");
            assert_eq!(clip_path(raw, 1), display, "{raw:?}");
            assert_eq!(wrap_ranges(raw, 1), [(0, raw.chars().count())], "{raw:?}");

            let mut buf = Buffer::empty(Rect::new(0, 0, 1, 1));
            let next = Cv::new(&mut buf).text(0, 0, raw, (255, 255, 255), None);
            assert_eq!(next, 1, "{raw:?}");
            assert_eq!(buf[(0, 0)].symbol(), display, "{raw:?}");
            assert_eq!(raw.chars().count(), 1, "source text is unchanged");
        }
    }

    #[test]
    fn controls_share_visible_widths_across_measure_clip_wrap_and_paint() {
        let controls = "\t\r\n\u{1b}\u{7f}\u{85}\r";
        let visible = "⇥⏎␛␡�␍";
        assert_eq!(text_width(controls), 6);
        assert_eq!(clip_text(controls, 6), visible);
        assert_eq!(clip_path(controls, 6), visible);

        let source = "a\tb\r\nc\rd";
        let ranges = wrap_ranges(source, 3);
        assert_eq!(ranges, [(0, 3), (5, 8)]);
        let rows = ranges
            .iter()
            .map(|&(start, end)| {
                source
                    .chars()
                    .skip(start)
                    .take(end - start)
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        assert_eq!(rows, ["a\tb", "c\rd"]);
        assert!(rows.iter().all(|row| text_width(row) <= 3));

        let mut buffer = Buffer::empty(Rect::new(0, 0, 6, 1));
        let next = Cv::new(&mut buffer).text(0, 0, controls, (255, 255, 255), None);
        assert_eq!(next, 6);
        assert_eq!(
            (0..6).map(|x| buffer[(x, 0)].symbol()).collect::<Vec<_>>(),
            ["⇥", "⏎", "␛", "␡", "�", "␍"]
        );
        assert!(
            buffer
                .content
                .iter()
                .all(|cell| cell.symbol().chars().all(|ch| !ch.is_control()))
        );
        assert_eq!(controls, "\t\r\n\u{1b}\u{7f}\u{85}\r");
    }

    #[test]
    fn clipping_keeps_complete_graphemes_at_cell_boundaries() {
        let combining = "e\u{301}";
        let joined = "👩🏽‍💻";
        assert_eq!(
            clip_text(&format!("{combining}{joined}x"), 3),
            format!("{combining}…")
        );
        assert_eq!(
            clip_text(&format!("{combining}{joined}"), 4),
            format!("{combining}{joined}")
        );
        assert_eq!(
            clip_path(&format!("root/{joined}"), 3),
            format!("…{joined}")
        );
        assert_eq!(clip_path(&format!("root/{joined}"), 2), "…");
        assert_eq!(
            text_width(&clip_text(&format!("{combining}{joined}x"), 3)),
            2
        );
    }

    #[test]
    fn clip_text_and_path_cover_unicode_exact_and_one_cell_short_boundaries() {
        for (grapheme, width) in [("e\u{301}", 1), ("界", 2), ("🇧🇷", 2), ("☀️", 2), ("👩🏽‍💻", 2)]
        {
            assert_eq!(text_width(grapheme), width, "{grapheme:?}");
            assert_eq!(clip_text(grapheme, width), grapheme, "{grapheme:?}");
            assert_eq!(clip_path(grapheme, width), grapheme, "{grapheme:?}");
            let short = width - 1;
            let short_result = if short == 0 { "" } else { "…" };
            assert_eq!(clip_text(grapheme, short), short_result, "{grapheme:?}");
            assert_eq!(clip_path(grapheme, short), short_result, "{grapheme:?}");
        }
    }

    #[test]
    fn put_writes_complete_graphemes_and_advances_by_cells() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 10, 1));
        let text = "e\u{301}界🇧🇷❤️👩🏽‍💻";
        let next = Cv::new(&mut buf).text(0, 0, text, (255, 255, 255), None);
        assert_eq!(next, 9);
        assert_eq!(buf[(0, 0)].symbol(), "e\u{301}");
        assert_eq!(buf[(1, 0)].symbol(), "界");
        assert_eq!(buf[(2, 0)].symbol(), "");
        assert_eq!(buf[(3, 0)].symbol(), "🇧🇷");
        assert_eq!(buf[(4, 0)].symbol(), "");
        assert_eq!(buf[(5, 0)].symbol(), "❤️");
        assert_eq!(buf[(6, 0)].symbol(), "");
        assert_eq!(buf[(7, 0)].symbol(), "👩🏽‍💻");
        assert_eq!(buf[(8, 0)].symbol(), "");
    }

    #[test]
    fn replacing_two_narrow_cells_with_wide_grapheme_clears_both_old_cells() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        {
            let mut cv = Cv::new(&mut buf);
            cv.text(0, 0, "ab", (255, 255, 255), None);
            assert_eq!(cv.text(0, 0, "界", (1, 2, 3), None), 2);
        }
        assert_eq!(buf[(0, 0)].symbol(), "界");
        assert_eq!(buf[(1, 0)].symbol(), "");
        assert_eq!(buf[(2, 0)].symbol(), " ");
    }

    #[test]
    fn spans_keep_graphemes_whole_across_style_boundaries() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 2, 1));
        let parts = [
            Seg::new("❤", (255, 0, 0)),
            Seg::new("\u{fe0f}", (0, 0, 255)),
        ];
        assert_eq!(segs_width(&parts), 2);
        assert_eq!(Cv::new(&mut buf).spans(0, 0, &parts, None), 2);
        assert_eq!(buf[(0, 0)].symbol(), "❤️");
        assert_eq!(buf[(1, 0)].symbol(), "");
        assert_eq!(buf[(0, 0)].fg, c((255, 0, 0)));
    }

    #[test]
    fn wide_grapheme_at_one_cell_clip_is_skipped_whole() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 2, 1));
        let mut cv = Cv::new(&mut buf);
        let next = cv.clipped(Rect::new(0, 0, 1, 1), |inner| {
            inner.text(0, 0, "界", (255, 255, 255), None)
        });
        assert_eq!(next, 2);
        assert_eq!(buf[(0, 0)].symbol(), " ");
        assert_eq!(buf[(1, 0)].symbol(), " ");
    }

    #[test]
    fn put_skips_only_the_grapheme_that_straddles_the_clip() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 2, 1));
        let mut cv = Cv::new(&mut buf);
        let next = cv.clipped(Rect::new(0, 0, 2, 1), |inner| {
            inner.text(0, 0, "a界", (255, 255, 255), None)
        });
        assert_eq!(next, 3);
        assert_eq!(buf[(0, 0)].symbol(), "a");
        assert_eq!(buf[(1, 0)].symbol(), " ");
    }

    #[test]
    fn put_continues_after_skipping_a_conflicting_old_glyph() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 4, 1));
        {
            let mut cv = Cv::new(&mut buf);
            cv.text(1, 0, "界", (255, 255, 255), None);
            cv.clipped(Rect::new(2, 0, 2, 1), |inner| {
                inner.text(2, 0, "xy", (255, 255, 255), None);
            });
        }
        assert_eq!(buf[(1, 0)].symbol(), "界");
        assert_eq!(buf[(2, 0)].symbol(), "");
        assert_eq!(buf[(3, 0)].symbol(), "y");
    }

    #[test]
    fn overwriting_a_wide_continuation_preserves_glyph_outside_clip() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        {
            let mut cv = Cv::new(&mut buf);
            cv.text(0, 0, "界", (255, 255, 255), None);
            cv.clipped(Rect::new(1, 0, 1, 1), |inner| {
                inner.text(1, 0, "x", (255, 255, 255), None);
            });
        }
        assert_eq!(buf[(0, 0)].symbol(), "界");
        assert_eq!(buf[(1, 0)].symbol(), "");
        assert_eq!(buf[(2, 0)].symbol(), " ");
    }

    #[test]
    fn continuation_overwrite_clears_full_wide_glyph_when_clip_contains_it() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        {
            let mut cv = Cv::new(&mut buf);
            cv.text(0, 0, "界", (255, 255, 255), None);
            cv.clipped(Rect::new(0, 0, 3, 1), |inner| {
                inner.text(1, 0, "x", (255, 255, 255), None);
            });
        }
        assert_eq!(buf[(0, 0)].symbol(), " ");
        assert_eq!(buf[(1, 0)].symbol(), "x");
        assert_eq!(buf[(2, 0)].symbol(), " ");
    }

    #[test]
    fn one_half_fill_skips_wide_glyph_straddling_clip() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        {
            let mut cv = Cv::new(&mut buf);
            cv.text(0, 0, "界", (255, 255, 255), None);
            cv.clipped(Rect::new(1, 0, 1, 1), |inner| {
                inner.fill(1, 0, 1, 1, (9, 8, 7))
            });
        }
        assert_eq!(buf[(0, 0)].symbol(), "界");
        assert_eq!(buf[(1, 0)].symbol(), "");
        assert_eq!(buf[(1, 0)].bg, Color::Reset);
    }

    #[test]
    fn fill_continues_on_narrow_cells_next_to_a_straddling_glyph() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 4, 1));
        {
            let mut cv = Cv::new(&mut buf);
            cv.text(0, 0, "界", (255, 255, 255), None);
            cv.clipped(Rect::new(1, 0, 3, 1), |inner| {
                inner.fill(1, 0, 3, 1, (9, 8, 7))
            });
        }
        assert_eq!(buf[(0, 0)].symbol(), "界");
        assert_eq!(buf[(1, 0)].symbol(), "");
        assert_eq!(buf[(1, 0)].bg, Color::Reset);
        for x in 2..4 {
            assert_eq!(buf[(x, 0)].symbol(), " ");
            assert_eq!(buf[(x, 0)].bg, c((9, 8, 7)));
        }
    }

    #[test]
    fn one_half_fill_clears_in_clip_glyph_but_colors_only_requested_cell() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        {
            let mut cv = Cv::new(&mut buf);
            cv.text(0, 0, "界", (255, 255, 255), None);
            cv.fill(1, 0, 1, 1, (9, 8, 7));
        }
        assert_eq!(buf[(0, 0)].symbol(), " ");
        assert_eq!(buf[(1, 0)].symbol(), " ");
        assert_eq!(buf[(1, 0)].bg, c((9, 8, 7)));
        assert_eq!(buf[(0, 0)].bg, Color::Reset);
    }

    #[test]
    fn fill_covers_both_cells_of_a_wide_grapheme() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 2, 1));
        {
            let mut cv = Cv::new(&mut buf);
            cv.text(0, 0, "界", (255, 255, 255), None);
            cv.fill(0, 0, 2, 1, (9, 8, 7));
        }
        for x in 0..2 {
            assert_eq!(buf[(x, 0)].symbol(), " ");
            assert_eq!(buf[(x, 0)].bg, c((9, 8, 7)));
        }
    }

    #[test]
    fn clip_path_keeps_the_file_name() {
        assert_eq!(clip_path("src/calc.py", 20), "src/calc.py");
        let long = "/tmp/orbit-shot-ohez8kxv/fixture/deep/dir/calc.py";
        let clipped = clip_path(long, 16);
        assert_eq!(text_width(&clipped), 16);
        assert!(
            clipped.starts_with('…') && clipped.ends_with("calc.py"),
            "{clipped}"
        );
        // clip_text keeps the START, which is the part that loses the name.
        assert!(!clip_text(long, 16).ends_with("calc.py"));
        assert_eq!(clip_path("abc", 0), "");
    }

    #[test]
    fn wrap_uses_cell_width_and_returns_grapheme_safe_char_ranges() {
        let text = "e\u{301}🇧🇷👩🏽‍💻界";
        let ranges = wrap_ranges(text, 2);
        let chars: Vec<char> = text.chars().collect();
        let lines: Vec<String> = ranges
            .iter()
            .map(|&(start, end)| chars[start..end].iter().collect())
            .collect();
        assert_eq!(lines, ["e\u{301}", "🇧🇷", "👩🏽‍💻", "界"]);

        let mut boundaries = vec![0];
        let mut char_offset = 0;
        for grapheme in text.graphemes(true) {
            char_offset += grapheme.chars().count();
            boundaries.push(char_offset);
        }
        for (start, end) in ranges {
            assert!(boundaries.contains(&start));
            assert!(boundaries.contains(&end));
        }
        assert_eq!(wrap_ranges("界界", 2), [(0, 1), (1, 2)]);
    }

    #[test]
    fn wrap_keeps_vs16_cluster_whole_and_ranges_cover_source() {
        let text = "x☀️y";
        let ranges = wrap_ranges(text, 2);
        let chars: Vec<char> = text.chars().collect();
        let lines: Vec<String> = ranges
            .iter()
            .map(|&(start, end)| chars[start..end].iter().collect())
            .collect();
        assert_eq!(lines, ["x", "☀️", "y"]);
        assert_eq!(lines.concat(), text);
        assert!(lines.iter().all(|line| text_width(line) <= 2));
        assert_eq!(ranges.first().map(|range| range.0), Some(0));
        assert_eq!(
            ranges.last().map(|range| range.1),
            Some(text.chars().count())
        );
    }

    #[test]
    fn wrap_preserves_newlines_and_splits_long_words_by_grapheme() {
        assert_eq!(wrap_ranges("abcdef", 3), [(0, 3), (3, 6)]);
        assert_eq!(wrap_ranges("\n界\nx", 1), [(0, 0), (1, 2), (3, 4)]);
        let joined = "👩🏽‍💻";
        assert_eq!(wrap_ranges(joined, 1), [(0, joined.chars().count())]);
    }

    #[test]
    fn mix_endpoints() {
        assert_eq!(mix((0, 0, 0), (200, 100, 50), 0.0), (0, 0, 0));
        assert_eq!(mix((0, 0, 0), (200, 100, 50), 1.0), (200, 100, 50));
    }
}
