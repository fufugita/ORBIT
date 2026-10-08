//! A cell canvas over a ratatui buffer: `put`, `fill`, `spans` with a
//! clip rectangle, the same drawing vocabulary the prototype paints
//! with. Colours are true-colour [`Rgb`] triples so tints can be mixed;
//! `None` as a background keeps whatever is already in the cell.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use unicode_width::UnicodeWidthChar;

/// A true-colour value.
pub type Rgb = (u8, u8, u8);

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
        self.text
            .chars()
            .map(|ch| ch.width().unwrap_or(0) as i32)
            .sum()
    }
}

pub fn segs_width(parts: &[Seg]) -> i32 {
    parts.iter().map(Seg::width).sum()
}

/// Display width of a string in cells.
pub fn text_width(s: &str) -> i32 {
    s.chars().map(|ch| ch.width().unwrap_or(0) as i32).sum()
}

/// End-clip to `n` cells with a trailing `…`.
pub fn clip_text(s: &str, n: i32) -> String {
    if n <= 0 {
        return String::new();
    }
    if text_width(s) <= n {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let w = ch.width().unwrap_or(0) as i32;
        if used + w > n - 1 {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

/// The canvas: a buffer plus a clip rectangle.
pub struct Cv<'a> {
    pub buf: &'a mut Buffer,
    pub clip: Rect,
}

impl<'a> Cv<'a> {
    pub fn new(buf: &'a mut Buffer) -> Self {
        let clip = buf.area;
        Cv { buf, clip }
    }

    /// Run `f` with the clip narrowed to `r` (intersected).
    pub fn clipped<R>(&mut self, r: Rect, f: impl FnOnce(&mut Cv<'_>) -> R) -> R {
        let inter = self.clip.intersection(r);
        let mut inner = Cv {
            buf: &mut *self.buf,
            clip: inter,
        };
        f(&mut inner)
    }

    fn inside(&self, x: i32, y: i32) -> bool {
        x >= self.clip.x as i32
            && y >= self.clip.y as i32
            && x < self.clip.right() as i32
            && y < self.clip.bottom() as i32
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
        for ch in s.chars() {
            let w = ch.width().unwrap_or(0) as i32;
            if w == 0 {
                continue;
            }
            if self.inside(cx, y) && self.inside(cx + w - 1, y) {
                let cell = &mut self.buf[(cx as u16, y as u16)];
                let mut buf = [0u8; 4];
                cell.set_symbol(ch.encode_utf8(&mut buf));
                let mut style = Style::default().fg(c(fg)).add_modifier(mods);
                if let Some(b) = bg {
                    style = style.bg(c(b));
                }
                cell.set_style(style);
                // A wide glyph owns the next cell too.
                if w == 2 {
                    let next = &mut self.buf[((cx + 1) as u16, y as u16)];
                    next.set_symbol("");
                }
            }
            cx += w;
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
        let mut cx = x;
        for p in parts {
            let m = if p.bold {
                Modifier::BOLD
            } else {
                Modifier::empty()
            };
            cx = self.put(cx, y, &p.text, p.fg, bg, m);
        }
        cx
    }

    /// Fill a rectangle with a background (clearing glyphs).
    pub fn fill(&mut self, x: i32, y: i32, w: i32, h: i32, bg: Rgb) {
        for yy in y..y + h {
            for xx in x..x + w {
                if self.inside(xx, yy) {
                    let cell = &mut self.buf[(xx as u16, yy as u16)];
                    cell.set_symbol(" ");
                    cell.set_style(Style::default().bg(c(bg)));
                }
            }
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
/// ranges. Words longer than the line are split.
pub fn wrap_ranges(text: &str, w: i32) -> Vec<(usize, usize)> {
    let chars: Vec<char> = text.chars().collect();
    let w = w.max(1) as usize;
    let mut out = Vec::new();
    let mut i = 0;
    let n = chars.len();
    if n == 0 {
        return vec![(0, 0)];
    }
    while i < n {
        if chars[i] == '\n' {
            out.push((i, i));
            i += 1;
            continue;
        }
        let mut end = (i + w).min(n);
        if let Some(nl) = chars[i..end].iter().position(|&ch| ch == '\n') {
            end = i + nl;
            out.push((i, end));
            i = end + 1;
            continue;
        }
        if end < n && chars[end] != ' ' {
            if let Some(sp) = chars[i..end].iter().rposition(|&ch| ch == ' ') {
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
    fn mix_endpoints() {
        assert_eq!(mix((0, 0, 0), (200, 100, 50), 0.0), (0, 0, 0));
        assert_eq!(mix((0, 0, 0), (200, 100, 50), 1.0), (200, 100, 50));
    }
}
