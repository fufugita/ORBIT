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
    /// Click-to-focus: set focus directly (from the mouse hit-test).
    FocusSet(crate::state::Focus),
    TabSessions,
    TabVerbose,
    NewSession,
    ToggleToolDetail,
    ToggleCost,
    CommandPalette,
    /// Open the command palette (§6.13).
    OpenPalette,
    /// Toggle the help overlay (§6.16).
    HelpToggle,
    /// Enter INSERT mode (from NORMAL).
    EnterInsert,
    /// Toggle zoom on the focused pane (herdr-style fullscreen).
    ZoomToggle,
    /// Scroll the focused pane up by n lines.
    ScrollUp(u16),
    /// Scroll the focused pane down by n lines.
    ScrollDown(u16),
    /// D3: re-submit the last prompt (`r` in NORMAL mode).
    RerunLast,
    /// Key was recognized but not actionable in the current context.
    Unknown,
}

/// Two-state leader-key parser.
#[derive(Debug, Clone)]
pub struct KeyParser {
    /// `Some('g')` or `Some('z')` when waiting for the second key of a chord.
    pending_leader: Option<char>,
    /// D14: when the pending leader was set. A leader older than
    /// LEADER_TIMEOUT is stale — the next key must NOT be consumed as a
    /// chord second (an operator who pressed `g`, got distracted, and
    /// later typed `s` meant a literal `s`, not `g s`).
    leader_set_at: Option<std::time::Instant>,
}

/// D14: a pending leader expires after 1 s (herdr/tmux feel — chords are
/// fast; anything slower is typing, not a chord).
pub const LEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

impl Default for KeyParser {
    fn default() -> Self {
        Self {
            pending_leader: None,
            leader_set_at: None,
        }
    }
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
                // D14: expire a stale leader BEFORE consuming — a chord
                // second pressed after LEADER_TIMEOUT is a fresh key.
                if let Some(at) = self.leader_set_at {
                    if at.elapsed() > LEADER_TIMEOUT {
                        self.pending_leader = None;
                        self.leader_set_at = None;
                    }
                }
                // If we have a pending leader, consume it.
                if let Some(leader) = self.pending_leader.take() {
                    self.leader_set_at = None;
                    return Some(self.parse_leader(leader, c));
                }
                // Single keys.
                match c {
                    'q' => Some(KeyAction::Quit),
                    '?' => Some(KeyAction::HelpToggle),
                    '1' => Some(KeyAction::FocusLeft),
                    '2' => Some(KeyAction::FocusCenter),
                    '3' => Some(KeyAction::FocusRight),
                    '/' => Some(KeyAction::CommandPalette),
                    'i' => Some(KeyAction::EnterInsert),
                    'r' => Some(KeyAction::RerunLast),
                    'Z' => Some(KeyAction::ZoomToggle),
                    'g' | 'z' => {
                        self.pending_leader = Some(c);
                        self.leader_set_at = Some(std::time::Instant::now());
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
            // Per-pane scroll (herdr-style functional isolation): the
            // scroll keys act on whichever pane is focused.
            KeyCode::Up => {
                self.pending_leader = None;
                Some(KeyAction::ScrollUp(1))
            }
            KeyCode::Down => {
                self.pending_leader = None;
                Some(KeyAction::ScrollDown(1))
            }
            KeyCode::PageUp => {
                self.pending_leader = None;
                Some(KeyAction::ScrollUp(10))
            }
            KeyCode::PageDown => {
                self.pending_leader = None;
                Some(KeyAction::ScrollDown(10))
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
    pub fn reset(&mut self) {
        self.pending_leader = None;
        self.leader_set_at = None;
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

    // ── D14: leader expiry ─────────────────────────────────────────────

    #[test]
    fn stale_leader_expires_and_key_is_fresh() {
        let mut p = KeyParser::new();
        assert!(p.parse(&key('g')).is_none()); // leader set
        // Age the leader past the timeout.
        p.leader_set_at = Some(std::time::Instant::now() - LEADER_TIMEOUT - std::time::Duration::from_millis(50));
        // `s` now must be a FRESH key (Unknown), not the g+s chord.
        assert_eq!(p.parse(&key('s')), Some(KeyAction::Unknown));
        assert!(!p.has_pending_leader());
    }

    #[test]
    fn fresh_leader_still_forms_chord() {
        let mut p = KeyParser::new();
        assert!(p.parse(&key('g')).is_none());
        assert_eq!(p.parse(&key('s')), Some(KeyAction::TabSessions));
    }

    #[test]
    fn reset_clears_leader_and_timestamp() {
        let mut p = KeyParser::new();
        assert!(p.parse(&key('z')).is_none());
        p.reset();
        assert!(!p.has_pending_leader());
        assert!(p.leader_set_at.is_none());
        // After reset, `t` is a fresh key — not z+t.
        assert_eq!(p.parse(&key('t')), Some(KeyAction::Unknown));
    }
}
