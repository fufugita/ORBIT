//! The welcome screen (§9.22): the expanded mark, the tagline, the
//! starters — centred in the conversation column, replaced by the
//! transcript at the first output.
//!
//! Brand tiers: anim/static show the mark; text shows ORBIT in bold
//! on the middle row; off drops the block entirely.

use super::comps;
use super::core::Token;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

/// The expanded mark, exactly (§9.22): 3 rows. The star is cyan
/// while the first prompt waits (M9's rest state is magenta).
pub const MARK_ROWS: [&str; 3] = [
    "   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
    "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
    "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
];

pub const TAGLINE: &str = "the harness that orbits around you";

/// Which brand tier governs the welcome block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrandTier {
    /// M1 plays at launch; the mark shows after.
    Anim,
    /// The mark, still.
    #[default]
    Static,
    /// ORBIT in bold on the middle row.
    Text,
    /// No block at all.
    Off,
}

/// The welcome block's render input.
pub struct Welcome {
    pub tier: BrandTier,
    /// The first prompt is waiting (M9: the star is cyan, items
    /// 4–9 drop).
    pub first_prompt_waiting: bool,
}

impl Welcome {
    /// The block's rows (mark + tagline + starters), already styled.
    pub fn lines(&self) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        match self.tier {
            BrandTier::Off => return out,
            BrandTier::Text => {
                // Only the middle row: ORBIT bold. The mark's other
                // two rows are blank.
                out.push(Line::from(""));
                out.push(Line::from(Span::styled(
                    "ORBIT",
                    Style::default()
                        .fg(comps::colour(Token::Ink))
                        .add_modifier(ratatui::style::Modifier::BOLD),
                )));
                out.push(Line::from(""));
            }
            BrandTier::Anim | BrandTier::Static => {
                for row in MARK_ROWS.iter() {
                    out.push(mark_line(row, self.first_prompt_waiting));
                }
            }
        }
        out.push(Line::from(""));
        out.push(Line::from(Span::styled(
            TAGLINE,
            Style::default().fg(comps::colour(Token::Muted)),
        )));
        // Items 4–9 drop while the first prompt waits.
        if !self.first_prompt_waiting {
            out.push(Line::from(""));
            out.push(Line::from(""));
            out.push(Line::from(""));
            out.push(Line::from(Span::styled(
                "Describe a task below, or start with",
                Style::default().fg(comps::colour(Token::Muted)),
            )));
            out.push(Line::from(""));
            for (cmd, desc) in [
                ("/models", "list models from configured providers"),
                ("/sessions", "browse and resume earlier work"),
                ("?", "keys and commands"),
            ] {
                out.push(Line::from(vec![
                    Span::styled(
                        format!("  {cmd}"),
                        Style::default()
                            .fg(comps::colour(Token::Ink))
                            .add_modifier(ratatui::style::Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(desc.to_string(), Style::default().fg(comps::colour(Token::Muted))),
                ]));
            }
        }
        out
    }

    /// The block's widest line.
    pub fn width(&self) -> u16 {
        let _ = &self.tier;
        if self.first_prompt_waiting {
            // The mark (33) vs the tagline (34).
            34
        } else {
            44
        }
    }
}

/// One mark row: letters ink, ring magenta_dim, star magenta (cyan
/// while the first prompt waits).
fn mark_line(row: &str, star_cyan: bool) -> Line<'static> {
    // The mark's glyph classes: the ring chars (braille + ⠤ dotted
    // strokes) are magenta_dim; the star ✦ is its own colour; the
    // half-block letters (▄ ▀ █) are ink.
    let ring: &str = "⣠⠖⠋⠙⠒⠤";
    let mut spans = Vec::new();
    let mut cur = String::new();
    let mut cur_is_ring = None;
    for ch in row.chars() {
        let is_ring = ring.contains(ch);
        let is_star = ch == '✦';
        let class = if is_star {
            2
        } else if is_ring {
            1
        } else {
            0
        };
        if cur_is_ring != Some(class) && !cur.is_empty() {
            spans.push(span_for(&cur, cur_is_ring, star_cyan));
            cur.clear();
        }
        cur_is_ring = Some(class);
        cur.push(ch);
    }
    if !cur.is_empty() {
        spans.push(span_for(&cur, cur_is_ring, star_cyan));
    }
    Line::from(spans)
}

fn span_for(text: &str, class: Option<u8>, star_cyan: bool) -> Span<'static> {
    let colour = match class {
        Some(1) => comps::colour(Token::Magenta),
        Some(2) => {
            if star_cyan {
                comps::colour(Token::Cyan)
            } else {
                comps::colour(Token::Magenta)
            }
        }
        _ => comps::colour(Token::Ink),
    };
    Span::styled(text.to_string(), Style::default().fg(colour))
}

/// The welcome block's area inside the conversation column, per the
/// fit rule: centred horizontally, top at 2 + free/3.
pub fn area(body: Rect, block_h: u16, block_w: u16) -> Rect {
    let free = body.height.saturating_sub(block_h);
    Rect {
        x: body.x + body.width.saturating_sub(block_w) / 2,
        y: body.y + 2 + free / 3,
        width: block_w.min(body.width),
        height: block_h.min(body.height),
    }
}
