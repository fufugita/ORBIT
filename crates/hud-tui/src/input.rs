//! crossterm key-event parsing (DR-20 §6 keymap).
//!
//! Chord-free, `g`/`z` leader map — no readline/emacs collisions, no `Ctrl+Z`.
//! The parser is a two-state machine: a pending leader (`g` or `z`) is
//! consumed by the next key; any other key resets it.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A parsed key action — the semantic intent, independent of the raw key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Quit,
    FocusNext,
    FocusPrev,
    FocusLeft,
    FocusCenter,
    FocusRight,
    TabSessions,
    TabVerbose,
    NewSession,
    ToggleToolDetail,
    ToggleCost,
    CommandPalette,
    /// Key was recognized but not actionable in the current context.
    Unknown,
}

/// Two-state leader-key parser.
#[derive(Debug, Clone, Default)]
pub struct KeyParser {
    /// `Some('g')` or `Some('z')` when waiting for the second key of a chord.
    pending_leader: Option<char>,
}

impl KeyParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a crossterm key event into a `KeyAction`. Returns `None` if the
    /// event is a leader key (the parser is now waiting for the next key).
    pub fn parse(&mut self, event: &KeyEvent) -> Option<KeyAction> {
        // Ctrl+C → handled specially in the event loop (double-press to quit).
        // We return Unknown here; the event loop intercepts Ctrl+C before
        // calling the parser.
        if event.modifiers.contains(KeyModifiers::CONTROL) {
            return match event.code {
                KeyCode::Char('c') => {
                    self.pending_leader = None;
                    Some(KeyAction::Quit) // will be intercepted by handle_key
                }
                _ => {
                    self.pending_leader = None;
                    Some(KeyAction::Unknown)
                }
            };
        }

        // No modifiers from here on.
        match event.code {
            KeyCode::Char(c) => {
                // If we have a pending leader, consume it.
                if let Some(leader) = self.pending_leader.take() {
                    return Some(self.parse_leader(leader, c));
                }
                // Single keys.
                match c {
                    'q' => Some(KeyAction::Quit),
                    '1' => Some(KeyAction::FocusLeft),
                    '2' => Some(KeyAction::FocusCenter),
                    '3' => Some(KeyAction::FocusRight),
                    '/' => Some(KeyAction::CommandPalette),
                    'g' | 'z' => {
                        self.pending_leader = Some(c);
                        None // waiting for next key
                    }
                    _ => Some(KeyAction::Unknown),
                }
            }
            KeyCode::Tab => {
                self.pending_leader = None;
                Some(KeyAction::FocusNext)
            }
            KeyCode::BackTab => {
                self.pending_leader = None;
                Some(KeyAction::FocusPrev)
            }
            _ => {
                self.pending_leader = None;
                Some(KeyAction::Unknown)
            }
        }
    }

    fn parse_leader(&mut self, leader: char, second: char) -> KeyAction {
        match (leader, second) {
            ('g', 's') => KeyAction::TabSessions,
            ('g', 'v') => KeyAction::TabVerbose,
            ('g', 'n') => KeyAction::NewSession,
            ('z', 't') => KeyAction::ToggleToolDetail,
            ('z', 'c') => KeyAction::ToggleCost,
            ('z', 'y') => KeyAction::CommandPalette, // reuse for copy mode trigger
            _ => KeyAction::Unknown,
        }
    }

    /// Reset any pending leader (e.g. on focus change or timeout).
    #[allow(dead_code)] // wired in PR-D (focus change resets leader)
    pub fn reset(&mut self) {
        self.pending_leader = None;
    }

    /// True if waiting for the second key of a chord.
    #[allow(dead_code)] // used in tests; wired in PR-D
    pub fn has_pending_leader(&self) -> bool {
        self.pending_leader.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn parse_single_keys() {
        let mut p = KeyParser::new();
        assert_eq!(p.parse(&key('q')), Some(KeyAction::Quit));
        assert_eq!(p.parse(&key('1')), Some(KeyAction::FocusLeft));
        assert_eq!(p.parse(&key('2')), Some(KeyAction::FocusCenter));
        assert_eq!(p.parse(&key('3')), Some(KeyAction::FocusRight));
        assert_eq!(p.parse(&key('/')), Some(KeyAction::CommandPalette));
    }

    #[test]
    fn parse_tab() {
        let mut p = KeyParser::new();
        assert_eq!(
            p.parse(&KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Some(KeyAction::FocusNext)
        );
        assert_eq!(
            p.parse(&KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE)),
            Some(KeyAction::FocusPrev)
        );
    }

    #[test]
    fn parse_leader_keys() {
        let mut p = KeyParser::new();
        // g then s → TabSessions
        assert_eq!(p.parse(&key('g')), None);
        assert!(p.has_pending_leader());
        assert_eq!(p.parse(&key('s')), Some(KeyAction::TabSessions));
        assert!(!p.has_pending_leader());

        // g then v → TabVerbose
        assert_eq!(p.parse(&key('g')), None);
        assert_eq!(p.parse(&key('v')), Some(KeyAction::TabVerbose));

        // g then n → NewSession
        assert_eq!(p.parse(&key('g')), None);
        assert_eq!(p.parse(&key('n')), Some(KeyAction::NewSession));

        // z then t → ToggleToolDetail
        assert_eq!(p.parse(&key('z')), None);
        assert_eq!(p.parse(&key('t')), Some(KeyAction::ToggleToolDetail));

        // z then c → ToggleCost
        assert_eq!(p.parse(&key('z')), None);
        assert_eq!(p.parse(&key('c')), Some(KeyAction::ToggleCost));
    }

    #[test]
    fn parse_ctrl_c() {
        let mut p = KeyParser::new();
        assert_eq!(p.parse(&ctrl('c')), Some(KeyAction::Quit));
    }

    #[test]
    fn parse_unknown_key() {
        let mut p = KeyParser::new();
        assert_eq!(p.parse(&key('x')), Some(KeyAction::Unknown));
    }

    #[test]
    fn leader_then_unknown_resets() {
        let mut p = KeyParser::new();
        assert_eq!(p.parse(&key('g')), None);
        assert!(p.has_pending_leader());
        // Unknown second key → Unknown, leader cleared.
        assert_eq!(p.parse(&key('x')), Some(KeyAction::Unknown));
        assert!(!p.has_pending_leader());
        // Next key is parsed fresh (not as a leader second).
        assert_eq!(p.parse(&key('q')), Some(KeyAction::Quit));
    }

    #[test]
    fn leader_reset_on_tab() {
        let mut p = KeyParser::new();
        assert_eq!(p.parse(&key('g')), None);
        assert!(p.has_pending_leader());
        // Tab resets the leader.
        assert_eq!(
            p.parse(&KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Some(KeyAction::FocusNext)
        );
        assert!(!p.has_pending_leader());
    }

    #[test]
    fn explicit_reset() {
        let mut p = KeyParser::new();
        assert_eq!(p.parse(&key('z')), None);
        assert!(p.has_pending_leader());
        p.reset();
        assert!(!p.has_pending_leader());
    }
}
