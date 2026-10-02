//! Per-pane text selection (herdr-style functional isolation).
//!
//! The host terminal's native selection grabs rectangular regions across
//! pane borders — it doesn't know the panes exist. ORBIT captures the
//! mouse (SGR mode) and owns selection itself: each selection is bound to
//! one pane, clamped to that pane's inner rect, and rendered only inside
//! it. Copy goes through OSC 52 so it works over SSH.
//!
//! Lifecycle (herdr's):
//!   MouseDown in pane → anchor recorded (nothing visible yet)
//!   MouseDrag         → selection active, cells highlighted
//!   MouseUp           → selection finalized; copied to the clipboard
//!   Next click / key  → selection cleared

use crate::state::Focus;

/// Selection phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Mouse down, not yet moved — might be a plain click.
    Anchored,
    /// Dragging — cells highlighted.
    Dragging,
    /// Released after a drag. Visible until the next click/key.
    Done,
}

/// A text selection bound to ONE pane.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Which pane this selection lives in — the isolation boundary.
    pub pane: Focus,
    /// Anchor (row, col) in pane-content coordinates.
    anchor: (u16, u16),
    /// Current/final (row, col).
    cursor: (u16, u16),
    phase: Phase,
}

impl Selection {
    /// Start a selection at a pane-local position.
    pub fn anchor(pane: Focus, row: u16, col: u16) -> Self {
        Self {
            pane,
            anchor: (row, col),
            cursor: (row, col),
            phase: Phase::Anchored,
        }
    }

    /// Extend the selection to a new pane-local position.
    pub fn extend(&mut self, row: u16, col: u16) {
        self.cursor = (row, col);
        self.phase = Phase::Dragging;
    }

    /// Finalize on mouse-up.
    pub fn finish(&mut self) {
        if self.phase == Phase::Dragging {
            self.phase = Phase::Done;
        } else {
            // A click without a drag: no selection.
            self.phase = Phase::Anchored;
        }
    }

    /// True when the selection should render.
    pub fn is_visible(&self) -> bool {
        matches!(self.phase, Phase::Dragging | Phase::Done)
    }

    /// Ordered (start, end) corners.
    fn ordered(&self) -> ((u16, u16), (u16, u16)) {
        let a = self.anchor;
        let c = self.cursor;
        if (a.0, a.1) <= (c.0, c.1) {
            (a, c)
        } else {
            (c, a)
        }
    }

    /// True if a pane-local cell is inside the selection.
    pub fn contains(&self, row: u16, col: u16) -> bool {
        if !self.is_visible() {
            return false;
        }
        let ((sr, sc), (er, ec)) = self.ordered();
        if row < sr || row > er {
            return false;
        }
        if sr == er {
            col >= sc && col <= ec
        } else if row == sr {
            col >= sc
        } else if row == er {
            col <= ec
        } else {
            true
        }
    }

    /// Extract the selected text from the pane's lines.
    pub fn extract<'a>(&self, lines: &'a [String]) -> Vec<&'a str> {
        if !self.is_visible() {
            return Vec::new();
        }
        let ((sr, sc), (er, ec)) = self.ordered();
        let mut out = Vec::new();
        for row in sr..=er {
            let Some(line) = lines.get(row as usize) else {
                break;
            };
            // Char-indexed, never byte-indexed: rendered lines carry
            // multi-byte glyphs (the logo, box-drawing, CJK), and a byte
            // slice at a char boundary-less offset panics. Map the char
            // range to a byte range via char_indices.
            let char_indices: Vec<(usize, char)> = line.char_indices().collect();
            let nchars = char_indices.len();
            let start = if row == sr { sc as usize } else { 0 };
            let end = if row == er {
                (ec as usize + 1).min(nchars)
            } else {
                nchars
            };
            if start < nchars && start < end {
                let byte_start = char_indices[start].0;
                let byte_end = if end < nchars {
                    char_indices[end].0
                } else {
                    line.len()
                };
                out.push(&line[byte_start..byte_end]);
            }
        }
        out
    }
}

/// The OSC 52 clipboard sequence: `ESC ] 52 ; c ; <base64> BEL`.
///
/// BEL termination (not ST) — some terminals only honor BEL.
pub fn osc52_sequence(text: &str) -> String {
    // Base64 without a dependency: the text is short (a selection), so a
    // tiny encoder suffices.
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    format!("\x1b]52;c;{out}\x07")
}

/// Hit-test a screen (row, col) against the three pane rects. Returns the
/// pane + the pane-local (row, col), or None if the point is on a border
/// or gap (borders belong to no pane — clicks there are ignored).
pub fn hit_test(
    row: u16,
    col: u16,
    left: Option<ratatui::layout::Rect>,
    center: ratatui::layout::Rect,
    right: Option<ratatui::layout::Rect>,
) -> Option<(Focus, u16, u16)> {
    let in_inner = |r: ratatui::layout::Rect| -> Option<(u16, u16)> {
        // Inner rect: skip the 1-cell border on each side.
        let (x, y, w, h) = (
            r.x + 1,
            r.y + 1,
            r.width.saturating_sub(2),
            r.height.saturating_sub(2),
        );
        if w == 0 || h == 0 {
            return None;
        }
        if col >= x && col < x + w && row >= y && row < y + h {
            Some((row - y, col - x))
        } else {
            None
        }
    };
    if let Some((pr, pc)) = left.and_then(in_inner) {
        return Some((Focus::Left, pr, pc));
    }
    if let Some((pr, pc)) = in_inner(center) {
        return Some((Focus::Center, pr, pc));
    }
    if let Some((pr, pc)) = right.and_then(in_inner) {
        return Some((Focus::Right, pr, pc));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_is_bound_to_one_pane() {
        let mut sel = Selection::anchor(Focus::Left, 0, 0);
        sel.extend(2, 5);
        sel.finish();
        assert!(sel.is_visible());
        // The selection only answers for its own pane.
        assert!(sel.contains(1, 3));
        // Extract from 3 lines: rows 0..=2.
        let lines = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let got = sel.extract(&lines);
        assert_eq!(got, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn click_without_drag_is_not_a_selection() {
        let mut sel = Selection::anchor(Focus::Center, 3, 4);
        sel.finish();
        assert!(!sel.is_visible(), "a plain click selects nothing");
    }

    #[test]
    fn partial_row_extraction() {
        let mut sel = Selection::anchor(Focus::Center, 0, 2);
        sel.extend(1, 3);
        sel.finish();
        let lines = vec!["abcdef".to_string(), "ghijkl".to_string()];
        let got = sel.extract(&lines);
        // The end cursor is inclusive: (1,3) covers cols 0..=3.
        assert_eq!(got, vec!["cdef", "ghij"]);
    }

    #[test]
    fn hit_test_lands_in_exactly_one_pane() {
        use ratatui::layout::Rect;
        let left = Rect::new(0, 0, 24, 30);
        let center = Rect::new(25, 0, 60, 30);
        let right = Rect::new(86, 0, 40, 30);
        // Inside the left pane's content.
        assert_eq!(
            hit_test(5, 5, Some(left), center, Some(right)),
            Some((Focus::Left, 4, 4))
        );
        // Inside the center.
        assert_eq!(
            hit_test(5, 50, Some(left), center, Some(right)),
            Some((Focus::Center, 4, 24))
        );
        // On the left pane's border (col 0) — no pane.
        assert_eq!(hit_test(5, 0, Some(left), center, Some(right)), None);
        // In the gap between panes — no pane.
        assert_eq!(hit_test(5, 24, Some(left), center, Some(right)), None);
    }

    #[test]
    fn osc52_is_well_formed() {
        let seq = osc52_sequence("hi");
        assert!(seq.starts_with("\x1b]52;c;"));
        assert!(seq.ends_with("\x07"));
        assert!(seq.contains("aGk="), "base64 of 'hi' is aGk=");
    }
}
