//! What a click does. The regions are recorded by the same code that
//! draws them — `Cv::hit` beside the `cv.text` — so a clickable thing can
//! never sit somewhere other than where it is drawn, and a frame that
//! does not draw a control has no region for it.
//!
//! The rule that keeps this small and safe: clicking a KEY HINT is
//! pressing that key. `⏎ send`, `y allow once`, `z zoom` register the key
//! they name, and the runtime feeds it through the same handler a real key
//! press goes through — so the approval card's arming delay, the arrange
//! mode's rules and every other guard apply to a click exactly as they do
//! to the key. Only things a key cannot express (a list row, a tab) have
//! a click of their own.

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::layout::Rect;

/// What clicking a region does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Click {
    /// Press this key (the region is a key hint).
    Key(KeyCode, KeyModifiers),
    /// Select row `index` of the changed-files list (Changes and Review).
    File(usize),
    /// Pick row `index` of the `/` command list.
    Slash(usize),
    /// Run row `index` of the command palette.
    Palette(usize),
    /// Show tape `index` in the Terminal panel (a command's tab).
    Tape(usize),
    /// Focus panel `index` (the switcher tab of a narrow screen).
    Panel(usize),
    /// Apply layout preset `index` (the top bar's tabs).
    Preset(usize),
    /// Outside the open overlay: close it. Registered under the overlay,
    /// so what is drawn behind a modal cannot be clicked through it.
    Dismiss,
    /// A part of an overlay that answers to nothing (its frame, its
    /// text): the click stays inside the box and neither acts nor closes.
    Inert,
}

/// A clickable region of the last frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub rect: Rect,
    pub click: Click,
}

/// The region at `(col, row)`: the LAST one drawn there, since what is
/// drawn later is on top.
pub fn at(hits: &[Hit], col: u16, row: u16) -> Option<Click> {
    hits.iter()
        .rev()
        .find(|h| {
            col >= h.rect.x && col < h.rect.right() && row >= h.rect.y && row < h.rect.bottom()
        })
        .map(|h| h.click)
}

/// The key a hint's key text names, when it names exactly one. Composite
/// hints (`j/k`, `h j k l`, `< >`, `⌃c`) are not clickable: there is no
/// single key to press, and guessing one would make the click do
/// something the label does not say.
pub fn parse_key(token: &str) -> Option<(KeyCode, KeyModifiers)> {
    let none = KeyModifiers::NONE;
    Some(match token {
        "⏎" => (KeyCode::Enter, none),
        "esc" => (KeyCode::Esc, none),
        "⇥" | "tab" => (KeyCode::Tab, none),
        "⇧tab" => (KeyCode::BackTab, none),
        "⇧⏎" => (KeyCode::Enter, KeyModifiers::ALT),
        t => {
            let mut chars = t.chars();
            let c = chars.next()?;
            if chars.next().is_some() || c.is_whitespace() {
                return None;
            }
            (KeyCode::Char(c), none)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_and_single_keys_parse() {
        assert_eq!(parse_key("⏎"), Some((KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(parse_key("esc"), Some((KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(
            parse_key("⇧tab"),
            Some((KeyCode::BackTab, KeyModifiers::NONE))
        );
        assert_eq!(
            parse_key("y"),
            Some((KeyCode::Char('y'), KeyModifiers::NONE))
        );
        assert_eq!(
            parse_key("R"),
            Some((KeyCode::Char('R'), KeyModifiers::NONE))
        );
        assert_eq!(
            parse_key("@"),
            Some((KeyCode::Char('@'), KeyModifiers::NONE))
        );
        assert_eq!(
            parse_key("["),
            Some((KeyCode::Char('['), KeyModifiers::NONE))
        );
        assert_eq!(
            parse_key(":"),
            Some((KeyCode::Char(':'), KeyModifiers::NONE))
        );
        assert_eq!(
            parse_key("?"),
            Some((KeyCode::Char('?'), KeyModifiers::NONE))
        );
    }

    /// A hint that names several keys, or a chord, has no ONE key to press:
    /// it stays a label.
    #[test]
    fn composite_hints_are_not_clickable() {
        for t in [
            "j/k", "n/p", "h j k l", "H J K L", "< >", "[ ]", "⌃c", "", " ",
        ] {
            assert_eq!(parse_key(t), None, "{t:?}");
        }
    }

    #[test]
    fn the_region_drawn_last_wins() {
        let under = Hit {
            rect: Rect::new(0, 0, 10, 10),
            click: Click::Dismiss,
        };
        let over = Hit {
            rect: Rect::new(2, 2, 3, 1),
            click: Click::File(1),
        };
        let hits = [under, over];
        assert_eq!(at(&hits, 3, 2), Some(Click::File(1)));
        assert_eq!(at(&hits, 3, 3), Some(Click::Dismiss));
        assert_eq!(at(&hits, 12, 3), None);
        assert_eq!(
            at(&hits, 5, 2),
            Some(Click::Dismiss),
            "right edge is exclusive"
        );
    }
}
