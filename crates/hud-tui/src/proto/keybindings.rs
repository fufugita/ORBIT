//! Operator key bindings, read once at start from
//! `$ORBIT_HOME/keybindings.toml`.
//!
//! ```toml
//! [keys]
//! "ctrl+k" = "ctrl+w"   # send another key instead
//! "f5"     = "/compact" # run a slash command
//! "alt+m"  = "/model"
//! "f1"     = "none"     # swallow the key
//! ```
//!
//! A binding rewrites the key before the rest of the screen sees it, so it
//! applies everywhere a real key press does. Ctrl+C and Ctrl+D always open
//! the quit card: they can be neither rebound nor used as a target's source.

use std::collections::HashMap;
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// The largest bindings file ORBIT reads.
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_BINDINGS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Chord {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    /// Deliver this key (the original one when nothing is bound).
    Key(KeyEvent),
    /// Run this slash command.
    Command(String),
    /// Swallow the key.
    Ignore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Key(Chord),
    Command(String),
    Ignore,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keybindings {
    map: HashMap<Chord, Action>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    keys: std::collections::BTreeMap<String, String>,
}

impl Keybindings {
    /// Reads `keybindings.toml` under `home`. A missing file is no bindings;
    /// a malformed one is an error naming the entry, and no bindings apply.
    pub fn load(home: &Path) -> Result<Self, String> {
        let path = home.join("keybindings.toml");
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(format!("keybindings.toml: {error}")),
        };
        if !meta.is_file() {
            return Err("keybindings.toml: not a regular file".into());
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err("keybindings.toml: larger than 64 KiB".into());
        }
        let text =
            std::fs::read_to_string(&path).map_err(|error| format!("keybindings.toml: {error}"))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let file: File =
            toml::from_str(text).map_err(|error| format!("keybindings.toml: {error}"))?;
        if file.keys.len() > MAX_BINDINGS {
            return Err(format!(
                "keybindings.toml: more than {MAX_BINDINGS} bindings"
            ));
        }
        let mut map = HashMap::new();
        for (from, to) in &file.keys {
            let chord = parse_chord(from)
                .ok_or_else(|| format!("keybindings.toml: unknown key \"{from}\""))?;
            if is_quit(chord) {
                return Err(format!("keybindings.toml: \"{from}\" cannot be rebound"));
            }
            let to = to.trim();
            let action = if to.eq_ignore_ascii_case("none") {
                Action::Ignore
            } else if let Some(command) = to.strip_prefix('/') {
                if command.is_empty() || to.chars().any(char::is_control) {
                    return Err(format!("keybindings.toml: bad command for \"{from}\""));
                }
                Action::Command(to.to_string())
            } else {
                Action::Key(parse_chord(to).ok_or_else(|| {
                    format!("keybindings.toml: unknown target \"{to}\" for \"{from}\"")
                })?)
            };
            if map.insert(chord, action).is_some() {
                return Err(format!("keybindings.toml: \"{from}\" is bound twice"));
            }
        }
        Ok(Self { map })
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// What a real key press becomes. Bindings do not chain: the target of
    /// one binding is never looked up again.
    pub fn resolve(&self, key: KeyEvent) -> Bound {
        if self.map.is_empty() || key.kind == KeyEventKind::Release {
            return Bound::Key(key);
        }
        match self.map.get(&normalize(key.code, key.modifiers)) {
            None => Bound::Key(key),
            Some(Action::Ignore) => Bound::Ignore,
            Some(Action::Command(command)) => Bound::Command(command.clone()),
            Some(Action::Key(chord)) => Bound::Key(KeyEvent::new(chord.code, chord.modifiers)),
        }
    }
}

fn is_quit(chord: Chord) -> bool {
    chord.modifiers == KeyModifiers::CONTROL
        && matches!(chord.code, KeyCode::Char('c') | KeyCode::Char('d'))
}

/// One spelling per chord: letters are lower-case with SHIFT kept as a
/// modifier only when another modifier is held; a plain shifted character is
/// just that character, as terminals report it.
fn normalize(code: KeyCode, modifiers: KeyModifiers) -> Chord {
    let mut modifiers =
        modifiers & (KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT);
    let code = match code {
        KeyCode::BackTab => {
            modifiers |= KeyModifiers::SHIFT;
            KeyCode::Tab
        }
        KeyCode::Char(c) => {
            let held = modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
            if held && c.is_ascii_uppercase() {
                modifiers |= KeyModifiers::SHIFT;
                KeyCode::Char(c.to_ascii_lowercase())
            } else {
                if !held {
                    modifiers -= KeyModifiers::SHIFT;
                }
                KeyCode::Char(c)
            }
        }
        other => other,
    };
    Chord { code, modifiers }
}

/// `ctrl+shift+k`, `alt+enter`, `f5`, `pageup`, `?`.
pub fn parse_chord(text: &str) -> Option<Chord> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut modifiers = KeyModifiers::NONE;
    let mut rest = text;
    while let Some((head, tail)) = rest.split_once('+') {
        if tail.is_empty() {
            break;
        }
        let modifier = match head.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => KeyModifiers::CONTROL,
            "alt" | "meta" | "option" => KeyModifiers::ALT,
            "shift" => KeyModifiers::SHIFT,
            _ => return None,
        };
        modifiers |= modifier;
        rest = tail;
    }
    let lower = rest.to_ascii_lowercase();
    let code = match lower.as_str() {
        "enter" | "return" => KeyCode::Enter,
        "esc" | "escape" => KeyCode::Esc,
        "tab" => KeyCode::Tab,
        "space" => KeyCode::Char(' '),
        "backspace" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        "insert" => KeyCode::Insert,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" | "pgup" => KeyCode::PageUp,
        "pagedown" | "pgdn" => KeyCode::PageDown,
        "plus" => KeyCode::Char('+'),
        _ => {
            if let Some(number) = lower.strip_prefix('f')
                && let Ok(n) = number.parse::<u8>()
                && (1..=12).contains(&n)
            {
                KeyCode::F(n)
            } else {
                let mut chars = rest.chars();
                let c = chars.next()?;
                if chars.next().is_some() || c.is_control() {
                    return None;
                }
                // "Ctrl+K" in the file means the same chord as "ctrl+k".
                if modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
                    KeyCode::Char(c.to_ascii_lowercase())
                } else {
                    KeyCode::Char(c)
                }
            }
        }
    };
    Some(normalize(code, modifiers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn chords_parse_with_modifiers_and_names() {
        assert_eq!(
            parse_chord("ctrl+k"),
            Some(Chord {
                code: KeyCode::Char('k'),
                modifiers: KeyModifiers::CONTROL
            })
        );
        assert_eq!(
            parse_chord("Ctrl+Shift+K"),
            Some(Chord {
                code: KeyCode::Char('k'),
                modifiers: KeyModifiers::CONTROL | KeyModifiers::SHIFT
            })
        );
        assert_eq!(parse_chord("f5").map(|c| c.code), Some(KeyCode::F(5)));
        assert_eq!(
            parse_chord("alt+enter").map(|c| c.code),
            Some(KeyCode::Enter)
        );
        assert_eq!(
            parse_chord("ctrl+plus").map(|c| c.code),
            Some(KeyCode::Char('+'))
        );
        assert_eq!(parse_chord("?").map(|c| c.code), Some(KeyCode::Char('?')));
        assert_eq!(parse_chord("hyper+k"), None);
        assert_eq!(parse_chord("f13"), None);
        assert_eq!(parse_chord("ab"), None);
        assert_eq!(parse_chord(""), None);
    }

    #[test]
    fn a_binding_rewrites_runs_or_swallows_the_key() {
        let keys = Keybindings::parse(
            "[keys]\n\"ctrl+k\" = \"ctrl+w\"\n\"f5\" = \"/compact\"\n\"f1\" = \"none\"\n",
        )
        .unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(
            keys.resolve(key(KeyCode::Char('k'), KeyModifiers::CONTROL)),
            Bound::Key(key(KeyCode::Char('w'), KeyModifiers::CONTROL))
        );
        assert_eq!(
            keys.resolve(key(KeyCode::F(5), KeyModifiers::NONE)),
            Bound::Command("/compact".into())
        );
        assert_eq!(
            keys.resolve(key(KeyCode::F(1), KeyModifiers::NONE)),
            Bound::Ignore
        );
        // Unbound keys, and the target of a binding, pass through untouched.
        let plain = key(KeyCode::Char('w'), KeyModifiers::CONTROL);
        assert_eq!(keys.resolve(plain), Bound::Key(plain));
    }

    #[test]
    fn terminal_spellings_of_one_chord_match() {
        let keys =
            Keybindings::parse("[keys]\n\"shift+tab\" = \"f2\"\n\"alt+m\" = \"/model\"\n").unwrap();
        assert_eq!(
            keys.resolve(key(KeyCode::BackTab, KeyModifiers::SHIFT)),
            Bound::Key(key(KeyCode::F(2), KeyModifiers::NONE))
        );
        assert_eq!(
            keys.resolve(key(KeyCode::BackTab, KeyModifiers::NONE)),
            Bound::Key(key(KeyCode::F(2), KeyModifiers::NONE))
        );
        assert_eq!(
            keys.resolve(key(KeyCode::Char('m'), KeyModifiers::ALT)),
            Bound::Command("/model".into())
        );
        // A plain shifted character is the character itself.
        let keys = Keybindings::parse("[keys]\n\"?\" = \"f1\"\n").unwrap();
        assert_eq!(
            keys.resolve(key(KeyCode::Char('?'), KeyModifiers::SHIFT)),
            Bound::Key(key(KeyCode::F(1), KeyModifiers::NONE))
        );
    }

    #[test]
    fn quit_keys_and_bad_entries_are_refused() {
        for text in [
            "[keys]\n\"ctrl+c\" = \"f1\"\n",
            "[keys]\n\"ctrl+d\" = \"none\"\n",
            "[keys]\n\"nope+k\" = \"f1\"\n",
            "[keys]\n\"f1\" = \"wat\"\n",
            "[keys]\n\"f1\" = \"/\"\n",
            "[keys]\n\"ctrl+k\" = \"f1\"\n\"Ctrl+K\" = \"f2\"\n",
            "[other]\nx = 1\n",
        ] {
            assert!(Keybindings::parse(text).is_err(), "{text}");
        }
        assert!(Keybindings::parse("").unwrap().is_empty());
    }

    #[test]
    fn a_missing_file_is_no_bindings() {
        let home = std::env::temp_dir().join(format!(
            "orbit-keys-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&home).unwrap();
        assert!(Keybindings::load(&home).unwrap().is_empty());
        std::fs::write(
            home.join("keybindings.toml"),
            "[keys]\n\"f5\" = \"/compact\"\n",
        )
        .unwrap();
        assert_eq!(Keybindings::load(&home).unwrap().len(), 1);
    }
}
