//! Colour tiers: the screen is composed in true colour and mapped once
//! per frame to what the terminal can show — 256 colours, 16 colours,
//! or none (glyphs, bold and reverse video only).

use crate::proto::core::Tier;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};

fn rgb_of(c: Color) -> Option<(u8, u8, u8)> {
    match c {
        Color::Rgb(r, g, b) => Some((r, g, b)),
        _ => None,
    }
}

fn dist(a: (u8, u8, u8), b: (u8, u8, u8)) -> i32 {
    let d = |x: u8, y: u8| (x as i32 - y as i32).pow(2);
    // Weighted: the eye is most sensitive to green.
    2 * d(a.0, b.0) + 4 * d(a.1, b.1) + 3 * d(a.2, b.2)
}

fn lum(c: (u8, u8, u8)) -> f32 {
    (0.2126 * c.0 as f32 + 0.7152 * c.1 as f32 + 0.0722 * c.2 as f32) / 255.0
}

fn sat(c: (u8, u8, u8)) -> f32 {
    let mx = c.0.max(c.1).max(c.2) as f32;
    let mn = c.0.min(c.1).min(c.2) as f32;
    if mx == 0.0 {
        0.0
    } else {
        (mx - mn) / mx
    }
}

/// The nearest xterm-256 index (6×6×6 cube or the grey ramp).
pub fn to_256(c: (u8, u8, u8)) -> u8 {
    let lv = |v: u8| -> u8 {
        if v < 48 {
            0
        } else if v < 115 {
            1
        } else {
            ((v as u16 - 35) / 40) as u8
        }
    };
    let steps = [0u8, 95, 135, 175, 215, 255];
    let (r, g, b) = (lv(c.0), lv(c.1), lv(c.2));
    let cube = (steps[r as usize], steps[g as usize], steps[b as usize]);
    let cube_idx = 16 + 36 * r + 6 * g + b;
    let avg = ((c.0 as u16 + c.1 as u16 + c.2 as u16) / 3) as u8;
    let gi = if avg < 8 {
        0
    } else {
        ((avg as u16 - 8) / 10).min(23) as u8
    };
    let gv = 8 + 10 * gi;
    let grey = (gv, gv, gv);
    if dist(c, grey) < dist(c, cube) {
        232 + gi
    } else {
        cube_idx
    }
}

const ANSI16: [((u8, u8, u8), Color); 16] = [
    ((0, 0, 0), Color::Black),
    ((205, 49, 49), Color::Red),
    ((13, 188, 121), Color::Green),
    ((229, 229, 16), Color::Yellow),
    ((36, 114, 200), Color::Blue),
    ((188, 63, 188), Color::Magenta),
    ((17, 168, 205), Color::Cyan),
    ((229, 229, 229), Color::Gray),
    ((102, 102, 102), Color::DarkGray),
    ((241, 76, 76), Color::LightRed),
    ((35, 209, 139), Color::LightGreen),
    ((245, 245, 67), Color::LightYellow),
    ((59, 142, 234), Color::LightBlue),
    ((214, 112, 214), Color::LightMagenta),
    ((41, 184, 219), Color::LightCyan),
    ((255, 255, 255), Color::White),
];

/// The nearest of the 16 ANSI colours.
pub fn to_16(c: (u8, u8, u8)) -> Color {
    ANSI16
        .iter()
        .min_by_key(|(rgb, _)| dist(c, *rgb))
        .map(|(_, col)| *col)
        .unwrap_or(Color::Reset)
}

/// Map every cell of `buf` to `tier`. True colour is left as it is.
pub fn apply(buf: &mut Buffer, tier: Tier) {
    if tier == Tier::TrueColor {
        return;
    }
    let area = buf.area;
    for y in area.y..area.bottom() {
        for x in area.x..area.right() {
            let cell = &mut buf[(x, y)];
            let fg = rgb_of(cell.fg);
            let bg = rgb_of(cell.bg);
            match tier {
                Tier::T256 => {
                    if let Some(c) = fg {
                        cell.set_fg(Color::Indexed(to_256(c)));
                    }
                    if let Some(c) = bg {
                        cell.set_bg(Color::Indexed(to_256(c)));
                    }
                }
                Tier::T16 => {
                    if let Some(c) = fg {
                        cell.set_fg(to_16(c));
                    }
                    if let Some(c) = bg {
                        // Dark surfaces stay the terminal's own background;
                        // accent pills keep their colour.
                        if lum(c) < 0.16 && sat(c) < 0.55 {
                            cell.set_bg(Color::Reset);
                        } else {
                            cell.set_bg(to_16(c));
                        }
                    }
                }
                Tier::None => {
                    // Glyphs and emphasis only: a pill (a bright or
                    // saturated background) becomes reverse video.
                    let pill = bg.map(|c| lum(c) > 0.2 || sat(c) > 0.5).unwrap_or(false);
                    cell.set_fg(Color::Reset);
                    cell.set_bg(Color::Reset);
                    if pill {
                        cell.modifier.insert(Modifier::REVERSED);
                    }
                }
                Tier::TrueColor => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;
    use ratatui::style::Style;

    #[test]
    fn nearest_256_is_in_range_and_keeps_greys_grey() {
        assert_eq!(to_256((0, 0, 0)), 16);
        assert!(to_256((0x80, 0x80, 0x80)) >= 232);
        assert_eq!(to_256((255, 0, 0)), 196);
    }

    #[test]
    fn sixteen_colour_picks_a_near_hue() {
        assert_eq!(to_16((0xE3, 0x56, 0xD0)), Color::LightMagenta);
        assert_eq!(to_16((0x5C, 0xC6, 0xDD)), Color::LightCyan);
    }

    #[test]
    fn mono_drops_colour_and_reverses_pills() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 2, 1));
        buf[(0, 0)].set_style(
            Style::default()
                .fg(Color::Rgb(0xEE, 0xEA, 0xF5))
                .bg(Color::Rgb(0x10, 0x0E, 0x16)),
        );
        buf[(1, 0)].set_style(
            Style::default()
                .fg(Color::Rgb(0x17, 0x09, 0x1A))
                .bg(Color::Rgb(0xE3, 0x56, 0xD0)),
        );
        apply(&mut buf, Tier::None);
        assert_eq!(buf[(0, 0)].fg, Color::Reset);
        assert!(!buf[(0, 0)].modifier.contains(Modifier::REVERSED));
        assert!(buf[(1, 0)].modifier.contains(Modifier::REVERSED));
    }
}
