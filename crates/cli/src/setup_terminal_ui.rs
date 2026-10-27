//! Bounded, side-effect-free setup choice rendering and keyboard decoding.
use crate::onboarding::SetupChoice;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub(crate) const MAX_CHOICES: usize = 4096;
pub(crate) const MAX_MENU_TEXT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_TYPED_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Enter,
    Back,
    Cancel,
    Erase,
    Text(u8),
    Ignore,
}

pub(crate) fn key(bytes: &[u8]) -> Option<Key> {
    Some(match bytes {
        [3 | 4 | 26 | 28] => Key::Cancel,
        [b'\r' | b'\n'] => Key::Enter,
        [8 | 127] => Key::Erase,
        [27] | [27, b'[', b'D'] | [27, b'O', b'D'] => Key::Back,
        [27, b'[', b'A'] | [27, b'O', b'A'] => Key::Up,
        [27, b'[', b'B'] | [27, b'O', b'B'] => Key::Down,
        [27, b'[', b'H'] | [27, b'O', b'H'] | [27, b'[', b'1', b'~'] => Key::Home,
        [27, b'[', b'F'] | [27, b'O', b'F'] | [27, b'[', b'4', b'~'] => Key::End,
        [27, b'[', b'5', b'~'] => Key::PageUp,
        [27, b'[', b'6', b'~'] => Key::PageDown,
        [byte] if *byte >= 32 => Key::Text(*byte),
        [byte] if *byte < 32 => Key::Ignore,
        _ if bytes.len() >= 16 => Key::Ignore,
        _ if bytes.starts_with(&[27, b'['])
            && bytes.len() > 2
            && bytes.last().is_some_and(|b| (0x40..=0x7e).contains(b)) =>
        {
            Key::Ignore
        }
        _ => return None,
    })
}

fn is_default_ignorable(character: char) -> bool {
    matches!(
        character as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF0..=0xFFF8
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

/// Controls are separated; default-ignorable code points stay visible in labels.
pub(crate) fn safe(value: &str) -> String {
    use std::fmt::Write as _;

    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            safe.push(' ');
        } else if is_default_ignorable(character) {
            write!(safe, "⟦U+{:04X}⟧", character as u32)
                .expect("writing a Unicode escape into a String cannot fail");
        } else {
            safe.push(character);
        }
    }
    safe
}

pub(crate) fn clip(value: &str, columns: usize) -> String {
    let clean = safe(value);
    let mut result = String::new();
    let mut used = 0;
    for cluster in clean.graphemes(true) {
        let width = UnicodeWidthStr::width(cluster);
        if used + width > columns {
            break;
        }
        result.push_str(cluster);
        used += width;
    }
    result
}

pub(crate) struct Menu {
    pub(crate) selected: usize,
    pub(crate) armed: bool,
    count: usize,
}
impl Menu {
    pub(crate) fn new(count: usize, current: Option<usize>) -> Self {
        Self {
            selected: current.unwrap_or(0).min(count.saturating_sub(1)),
            armed: current.is_some(),
            count,
        }
    }
    pub(crate) fn navigate(&mut self, key: Key, page: usize) {
        if self.count == 0 {
            return;
        }
        self.selected = match key {
            Key::Up => self.selected.saturating_sub(1),
            Key::Down => (self.selected + 1).min(self.count - 1),
            Key::Home => 0,
            Key::End => self.count - 1,
            Key::PageUp => self.selected.saturating_sub(page.max(1)),
            Key::PageDown => self
                .selected
                .saturating_add(page.max(1))
                .min(self.count - 1),
            _ => return,
        };
        self.armed = true;
    }
}

pub(crate) struct Frame {
    pub(crate) lines: Vec<String>,
    pub(crate) selected_line: usize,
    pub(crate) page: usize,
}
pub(crate) fn frame(
    title: &str,
    choices: &[SetupChoice<'_>],
    menu: &Menu,
    typed: &[u8],
    columns: usize,
    rows: usize,
    allow_back: bool,
) -> Frame {
    let columns = columns.clamp(1, 240);
    let page = rows.clamp(8, 120).saturating_sub(7).max(1);
    let start = menu
        .selected
        .saturating_sub(page - 1)
        .min(choices.len().saturating_sub(page));
    let end = (start + page).min(choices.len());
    let mut lines = vec![
        "ORBIT  /  SETUP".to_owned(),
        title.to_owned(),
        String::new(),
    ];
    let selected_line = 3 + menu.selected.saturating_sub(start);
    for (index, choice) in choices.iter().enumerate().take(end).skip(start) {
        lines.push(format!(
            "{} {}. {}",
            if index == menu.selected { ">" } else { " " },
            index + 1,
            choice.label
        ));
    }
    let selected = choices.get(menu.selected);
    lines.push(selected.and_then(|c| c.detail).unwrap_or("").to_owned());
    lines.push(format!(
        "{} of {}  |  {}",
        menu.selected + 1,
        choices.len(),
        selected.map(|c| c.label).unwrap_or("")
    ));
    lines.push(format!("{title}: {}", String::from_utf8_lossy(typed)));
    lines.push(
        if allow_back {
            "Arrows select  Enter choose  Left/Esc back  Ctrl-C cancel"
        } else {
            "Arrows select  Enter choose  Esc/Ctrl-C cancel"
        }
        .to_owned(),
    );
    Frame {
        lines: lines
            .into_iter()
            .map(|s| clip(&s, columns.saturating_sub(1)))
            .collect(),
        selected_line,
        page,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_clip_never_splits_a_cluster_or_exceeds_cells() {
        for text in [
            "alpha",
            "中中文",
            "e\u{301}next",
            "👨‍👩‍👧‍👦 tail",
            "\x1b[31mred\u{202e}text",
        ] {
            for width in 0..20 {
                let clipped = clip(text, width);
                assert!(UnicodeWidthStr::width(clipped.as_str()) <= width);
                assert!(!clipped.chars().any(char::is_control));
                assert!(!clipped.contains('\u{202e}'));
            }
        }
        assert_eq!(clip("e\u{301}x", 1), "e\u{301}");
        assert_eq!(clip("中x", 1), "");
    }
    #[test]
    fn frame_displays_invisible_code_points_without_collapsing_identifiers() {
        let hidden = "vendor\u{202e}/model\u{200b}-fast";
        let choices = [SetupChoice {
            id: hidden,
            label: hidden,
            detail: None,
        }];
        let rendered = frame(
            "Models",
            &choices,
            &Menu::new(1, Some(0)),
            &[],
            80,
            24,
            true,
        );
        let text = rendered.lines.join("\n");
        assert!(text.contains("vendor⟦U+202E⟧/model⟦U+200B⟧-fast"));
        assert!(!text.contains('\u{200b}'));
        assert_ne!(safe("model\u{200b}x"), safe("modelx"));
    }
    #[test]
    fn scroll_and_resize_keep_exact_last_identity_visible() {
        let ids: Vec<_> = (0..32).map(|n| format!("provider/raw/{n}")).collect();
        let choices: Vec<_> = ids
            .iter()
            .map(|id| SetupChoice {
                id,
                label: id,
                detail: None,
            })
            .collect();
        let mut menu = Menu::new(choices.len(), None);
        menu.navigate(Key::End, 5);
        for (columns, rows) in [(160, 32), (40, 10), (1, 1), (160, 32)] {
            let rendered = frame("Models", &choices, &menu, &[], columns, rows, true);
            assert_eq!(menu.selected, 31);
            assert!(rendered.selected_line < rendered.lines.len());
            assert!(
                rendered
                    .lines
                    .iter()
                    .all(|line| UnicodeWidthStr::width(line.as_str()) <= columns.saturating_sub(1))
            );
        }
        menu.navigate(Key::Home, 5);
        assert_eq!(menu.selected, 0);
    }
    #[test]
    fn frame_shows_human_label_instead_of_internal_choice_id() {
        let choices = [SetupChoice {
            id: "provider:add",
            label: "Add or replace a provider",
            detail: Some("Use a supported sign-in or API key"),
        }];
        let menu = Menu::new(choices.len(), Some(0));
        let rendered = frame("Configuration", &choices, &menu, &[], 80, 24, true);
        let text = rendered.lines.join("\n");
        assert!(text.contains("1 of 1  |  Add or replace a provider"));
        assert!(!text.contains("provider:add"));
    }
    #[test]
    fn known_escape_sequences_are_bounded_and_do_not_become_text() {
        assert_eq!(key(b"\x1b[A"), Some(Key::Up));
        assert_eq!(key(b"\x1b[D"), Some(Key::Back));
        assert_eq!(key(b"\x1b[6~"), Some(Key::PageDown));
        assert_eq!(key(b"\x1b[200~"), Some(Key::Ignore));
        assert_eq!(key(b"\x1b["), None);
        assert_eq!(key(&[27; 16]), Some(Key::Ignore));
    }
}
