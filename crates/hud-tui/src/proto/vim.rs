//! Vim-style editing for the composer (opt-in: `ORBIT_VIM=1`).
//!
//! A small modal layer over the draft: INSERT behaves like the ordinary
//! composer, NORMAL takes motions and edits. It covers the single-line
//! core of Claude Code's vim mode — `h l 0 ^ $ w b e`, `i a I A`, `x`, `D`,
//! `C`, `dd`, `cc`, `d`/`c` with a motion, `p P`, and one level of `u` — and
//! leaves everything else to the composer. The cursor is a grapheme index,
//! as everywhere else in the composer.

use crossterm::event::{KeyCode, KeyModifiers};
use unicode_segmentation::UnicodeSegmentation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VimMode {
    #[default]
    Insert,
    Normal,
}

/// What the layer did with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VimOutcome {
    /// Not a vim key here: the composer handles it as usual.
    Pass,
    /// Handled; the draft or cursor may have changed.
    Consumed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VimState {
    pub mode: VimMode,
    /// A `d` or `c` waiting for its motion.
    pending: Option<char>,
    /// The last deleted or changed text, for `p` / `P`.
    register: String,
    /// The draft and cursor before the last change, for `u`.
    undo: Option<(String, usize)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Space,
    Word,
    Punct,
}

fn class(grapheme: &str) -> Class {
    match grapheme.chars().next() {
        Some(c) if c.is_whitespace() => Class::Space,
        Some(c) if c.is_alphanumeric() || c == '_' => Class::Word,
        _ => Class::Punct,
    }
}

/// The start of the next word after `at`.
fn next_word(cells: &[String], at: usize) -> usize {
    let mut i = at;
    if i < cells.len() {
        let start = class(&cells[i]);
        while i < cells.len() && class(&cells[i]) == start && start != Class::Space {
            i += 1;
        }
    }
    while i < cells.len() && class(&cells[i]) == Class::Space {
        i += 1;
    }
    i
}

/// The start of the word at or before `at`.
fn previous_word(cells: &[String], at: usize) -> usize {
    let mut i = at;
    while i > 0 && class(&cells[i - 1]) == Class::Space {
        i -= 1;
    }
    if i > 0 {
        let kind = class(&cells[i - 1]);
        while i > 0 && class(&cells[i - 1]) == kind {
            i -= 1;
        }
    }
    i
}

/// The last cell of the word at or after `at`.
fn word_end(cells: &[String], at: usize) -> usize {
    let mut i = (at + 1).min(cells.len());
    while i < cells.len() && class(&cells[i]) == Class::Space {
        i += 1;
    }
    if i < cells.len() {
        let kind = class(&cells[i]);
        while i + 1 < cells.len() && class(&cells[i + 1]) == kind {
            i += 1;
        }
    }
    i.min(cells.len().saturating_sub(1))
}

impl VimState {
    /// Handle one key. `draft` and `cursor` are the composer's own.
    pub fn key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        draft: &mut String,
        cursor: &mut usize,
    ) -> VimOutcome {
        if modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
            return VimOutcome::Pass;
        }
        if self.mode == VimMode::Insert {
            if code != KeyCode::Esc {
                return VimOutcome::Pass;
            }
            self.mode = VimMode::Normal;
            // As in vim, leaving INSERT steps back onto the last typed cell.
            *cursor = cursor.saturating_sub(1);
            return VimOutcome::Consumed;
        }
        let KeyCode::Char(key) = code else {
            // Esc drops a pending operator, otherwise it belongs to the
            // screen (arrange controls). Enter, arrows and the rest pass.
            return match (code, self.pending.take()) {
                (KeyCode::Esc, Some(_)) => VimOutcome::Consumed,
                _ => VimOutcome::Pass,
            };
        };
        let cells: Vec<String> = draft.graphemes(true).map(str::to_owned).collect();
        let len = cells.len();
        let at = (*cursor).min(len);
        let last = len.saturating_sub(1);

        if let Some(operator) = self.pending.take() {
            // The range an operator covers: the whole line when doubled,
            // otherwise from the cursor to where the motion lands.
            let range = match key {
                _ if key == operator => Some((0, len)),
                'w' => Some((at, next_word(&cells, at))),
                'e' => Some((at, (word_end(&cells, at) + 1).min(len))),
                'b' => Some((previous_word(&cells, at), at)),
                '$' => Some((at, len)),
                '0' | '^' => Some((0, at)),
                'h' => Some((at.saturating_sub(1), at)),
                'l' => Some((at, (at + 1).min(len))),
                _ => None,
            };
            if let Some((from, to)) = range.filter(|(from, to)| from < to) {
                self.cut(draft, cursor, &cells, from, to);
                if operator == 'c' {
                    self.mode = VimMode::Insert;
                } else {
                    *cursor = (*cursor).min(draft.graphemes(true).count().saturating_sub(1));
                }
            } else if operator == 'c' && range.is_some() {
                self.mode = VimMode::Insert;
            }
            return VimOutcome::Consumed;
        }

        match key {
            'h' => *cursor = at.saturating_sub(1),
            'l' => *cursor = (at + 1).min(last),
            '0' => *cursor = 0,
            '^' => {
                *cursor = cells
                    .iter()
                    .position(|cell| class(cell) != Class::Space)
                    .unwrap_or(0);
            }
            '$' => *cursor = last,
            'w' => *cursor = next_word(&cells, at).min(last),
            'b' => *cursor = previous_word(&cells, at),
            'e' => *cursor = word_end(&cells, at),
            'i' => self.mode = VimMode::Insert,
            'a' => {
                *cursor = (at + 1).min(len);
                self.mode = VimMode::Insert;
            }
            'I' => {
                *cursor = 0;
                self.mode = VimMode::Insert;
            }
            'A' => {
                *cursor = len;
                self.mode = VimMode::Insert;
            }
            'x' if at < len => {
                self.cut(draft, cursor, &cells, at, at + 1);
                *cursor = (*cursor).min(draft.graphemes(true).count().saturating_sub(1));
            }
            'D' | 'C' if at < len => {
                self.cut(draft, cursor, &cells, at, len);
                if key == 'C' {
                    self.mode = VimMode::Insert;
                } else {
                    *cursor = cursor.saturating_sub(1);
                }
            }
            'C' => self.mode = VimMode::Insert,
            'd' | 'c' => self.pending = Some(key),
            'p' | 'P' if !self.register.is_empty() => {
                self.undo = Some((draft.clone(), at));
                let insert_at = if key == 'p' { (at + 1).min(len) } else { at };
                let mut next: String = cells[..insert_at].concat();
                next.push_str(&self.register);
                next.push_str(&cells[insert_at..].concat());
                *draft = next;
                *cursor = insert_at + self.register.graphemes(true).count() - 1;
            }
            'u' => {
                if let Some((before, before_cursor)) = self.undo.take() {
                    self.undo = Some((draft.clone(), at));
                    *draft = before;
                    *cursor = before_cursor;
                }
            }
            // NORMAL never types: anything else is swallowed.
            _ => {}
        }
        VimOutcome::Consumed
    }

    /// Remove `from..to`, remember it for `p` and the old draft for `u`.
    fn cut(
        &mut self,
        draft: &mut String,
        cursor: &mut usize,
        cells: &[String],
        from: usize,
        to: usize,
    ) {
        self.undo = Some((draft.clone(), *cursor));
        self.register = cells[from..to].concat();
        let mut next: String = cells[..from].concat();
        next.push_str(&cells[to..].concat());
        *draft = next;
        *cursor = from;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Type keys in NORMAL mode from the given cursor; returns draft and cursor.
    fn normal(draft: &str, cursor: usize, keys: &str) -> (String, usize, VimState) {
        let mut state = VimState {
            mode: VimMode::Normal,
            ..VimState::default()
        };
        let (mut draft, mut cursor) = (draft.to_string(), cursor);
        for key in keys.chars() {
            state.key(
                KeyCode::Char(key),
                KeyModifiers::NONE,
                &mut draft,
                &mut cursor,
            );
        }
        (draft, cursor, state)
    }

    #[test]
    fn insert_mode_passes_everything_but_escape() {
        let mut state = VimState::default();
        let (mut draft, mut cursor) = ("hello".to_string(), 5);
        assert_eq!(
            state.key(
                KeyCode::Char('x'),
                KeyModifiers::NONE,
                &mut draft,
                &mut cursor
            ),
            VimOutcome::Pass
        );
        assert_eq!(
            state.key(KeyCode::Esc, KeyModifiers::NONE, &mut draft, &mut cursor),
            VimOutcome::Consumed
        );
        assert_eq!((state.mode, cursor), (VimMode::Normal, 4));
        // In NORMAL, Esc, Enter and Ctrl keys belong to the screen.
        for (code, modifiers) in [
            (KeyCode::Esc, KeyModifiers::NONE),
            (KeyCode::Enter, KeyModifiers::NONE),
            (KeyCode::Char('r'), KeyModifiers::CONTROL),
        ] {
            assert_eq!(
                state.key(code, modifiers, &mut draft, &mut cursor),
                VimOutcome::Pass
            );
        }
        assert_eq!(draft, "hello");
    }

    #[test]
    fn motions_move_by_cell_word_and_line() {
        let text = "fix the  parser, now";
        assert_eq!(normal(text, 0, "w").1, 4);
        assert_eq!(normal(text, 0, "ww").1, 9);
        assert_eq!(normal(text, 9, "w").1, 15, "punctuation is its own word");
        assert_eq!(normal(text, 9, "b").1, 4);
        assert_eq!(normal(text, 0, "e").1, 2);
        assert_eq!(normal(text, 2, "e").1, 6);
        assert_eq!(normal(text, 5, "0").1, 0);
        assert_eq!(normal(text, 5, "$").1, 19);
        assert_eq!(normal("  indented", 7, "^").1, 2);
        assert_eq!(normal(text, 0, "h").1, 0);
        assert_eq!(normal(text, 19, "l").1, 19, "l stops on the last cell");
        // Wide and combined characters count as one cell each.
        assert_eq!(normal("한글 e\u{301}x", 0, "w").1, 3);
    }

    #[test]
    fn edits_delete_change_paste_and_undo() {
        assert_eq!(normal("hello", 1, "x").0, "hllo");
        assert_eq!(normal("fix the parser", 4, "dw").0, "fix parser");
        assert_eq!(normal("fix the parser", 4, "D").0, "fix ");
        assert_eq!(normal("fix the parser", 4, "dd").0, "");
        assert_eq!(normal("fix the parser", 8, "db").0, "fix parser");
        assert_eq!(normal("fix the parser", 4, "d$").0, "fix ");
        assert_eq!(normal("fix the parser", 4, "de").0, "fix  parser");

        let (draft, cursor, state) = normal("fix the parser", 4, "cw");
        assert_eq!(
            (draft.as_str(), cursor, state.mode),
            ("fix parser", 4, VimMode::Insert)
        );
        let (draft, _, state) = normal("fix the parser", 4, "cc");
        assert_eq!((draft.as_str(), state.mode), ("", VimMode::Insert));
        assert_eq!(normal("abc", 1, "A").1, 3);
        assert_eq!(normal("abc", 1, "a").1, 2);
        assert_eq!(normal("abc", 1, "I").1, 0);

        // x then p swaps two characters; u restores the line.
        assert_eq!(normal("ab", 0, "xp").0, "ba");
        assert_eq!(normal("fix the parser", 4, "dwu").0, "fix the parser");
        assert_eq!(normal("fix the parser", 4, "dwP").0, "fix the parser");
        // An unknown motion cancels the operator and changes nothing.
        assert_eq!(normal("abc", 0, "dz").0, "abc");
        // Letters in NORMAL never reach the draft.
        assert_eq!(normal("abc", 0, "qzQ").0, "abc");
        // An empty draft survives every key.
        assert_eq!(normal("", 0, "xDdwpu$hlweb").0, "");
    }
}
