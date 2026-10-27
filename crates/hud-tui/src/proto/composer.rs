//! Draft-only file completion and reverse history search.

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use unicode_segmentation::UnicodeSegmentation;

pub const FILE_RESULTS_MAX: usize = 64;
const FILE_SCAN_MAX: usize = 4096;

/// Number of user-perceived text units in a draft. The composer cursor is
/// stored in these units rather than UTF-8 bytes or Unicode scalar values.
pub fn grapheme_count(text: &str) -> usize {
    UnicodeSegmentation::graphemes(text, true).count()
}

/// Clamp a composer cursor to a valid grapheme boundary in `text`.
pub fn clamp_cursor(text: &str, cursor: usize) -> usize {
    cursor.min(grapheme_count(text))
}

/// UTF-8 byte offset for a grapheme-boundary cursor.
pub fn cursor_byte_index(text: &str, cursor: usize) -> usize {
    UnicodeSegmentation::grapheme_indices(text, true)
        .nth(clamp_cursor(text, cursor))
        .map_or(text.len(), |(byte, _)| byte)
}

/// Grapheme-boundary cursor at or after a UTF-8 byte offset. If an inserted
/// combining mark or joiner merged with an adjacent cluster, the caret lands
/// after the whole resulting cluster.
fn cursor_for_byte_offset(text: &str, offset: usize) -> usize {
    let offset = offset.min(text.len());
    for (index, (byte, cluster)) in UnicodeSegmentation::grapheme_indices(text, true).enumerate() {
        if offset <= byte {
            return index;
        }
        if offset < byte + cluster.len() {
            return index + 1;
        }
    }
    grapheme_count(text)
}

/// Insert literal text at a grapheme boundary and leave the cursor after the
/// complete resulting grapheme, even when Unicode joins the inserted text to
/// a neighbor.
pub fn insert_at_cursor(text: &mut String, cursor: &mut usize, inserted: &str) {
    if inserted.is_empty() {
        *cursor = clamp_cursor(text, *cursor);
        return;
    }
    *cursor = clamp_cursor(text, *cursor);
    let byte = cursor_byte_index(text, *cursor);
    text.insert_str(byte, inserted);
    *cursor = cursor_for_byte_offset(text, byte + inserted.len());
}

/// Remove the grapheme before the insertion point.
pub fn delete_before_cursor(text: &mut String, cursor: &mut usize) -> bool {
    *cursor = clamp_cursor(text, *cursor);
    if *cursor == 0 {
        return false;
    }
    let start = cursor_byte_index(text, *cursor - 1);
    let end = cursor_byte_index(text, *cursor);
    text.replace_range(start..end, "");
    *cursor = cursor_for_byte_offset(text, start);
    true
}

/// Remove the grapheme at the insertion point.
pub fn delete_at_cursor(text: &mut String, cursor: &mut usize) -> bool {
    *cursor = clamp_cursor(text, *cursor);
    let start = cursor_byte_index(text, *cursor);
    let end = cursor_byte_index(text, *cursor + 1);
    if start == end {
        return false;
    }
    text.replace_range(start..end, "");
    *cursor = cursor_for_byte_offset(text, start);
    true
}

/// Ctrl+W: delete the previous space-delimited word (and its separator),
/// preserving any text after the cursor. This retains the existing shortcut's
/// ASCII-space behavior while making edits safe at a middle-of-draft cursor.
pub fn delete_previous_word(text: &mut String, cursor: &mut usize) -> bool {
    *cursor = clamp_cursor(text, *cursor);
    if *cursor == 0 {
        return false;
    }
    let clusters: Vec<&str> = UnicodeSegmentation::graphemes(text.as_str(), true).collect();
    let end = *cursor;
    let mut word_end = end;
    while word_end > 0 && clusters[word_end - 1] == " " {
        word_end -= 1;
    }
    let mut start = word_end;
    while start > 0 && clusters[start - 1] != " " {
        start -= 1;
    }
    start = start.saturating_sub(1);
    if start == end {
        return false;
    }
    let byte_start = cursor_byte_index(text, start);
    let byte_end = cursor_byte_index(text, end);
    text.replace_range(byte_start..byte_end, "");
    *cursor = cursor_for_byte_offset(text, byte_start);
    true
}

pub fn move_left(text: &str, cursor: &mut usize) {
    *cursor = clamp_cursor(text, *cursor).saturating_sub(1);
}

pub fn move_right(text: &str, cursor: &mut usize) {
    *cursor = (clamp_cursor(text, *cursor) + 1).min(grapheme_count(text));
}

pub fn move_home(text: &str, cursor: &mut usize) {
    let byte = cursor_byte_index(text, *cursor);
    let line_start = text[..byte].rfind('\n').map_or(0, |newline| newline + 1);
    *cursor = grapheme_count(&text[..line_start]);
}

pub fn move_end(text: &str, cursor: &mut usize) {
    let byte = cursor_byte_index(text, *cursor);
    let line_end = UnicodeSegmentation::grapheme_indices(&text[byte..], true)
        .find(|(_, cluster)| cluster.contains('\n'))
        .map_or(text.len(), |(offset, _)| byte + offset);
    *cursor = grapheme_count(&text[..line_end]);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCandidate {
    pub path: String,
    pub directory: bool,
}

/// A trailing mention at the insertion point. Offsets are UTF-8 byte boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mention {
    start: usize,
    end: usize,
    prefix: String,
}

fn trailing_mention(draft: &str, cursor: usize) -> Option<Mention> {
    let cursor = cursor.min(draft.len());
    let before_cursor = &draft[..cursor];
    let mut skip_until = 0;
    for (start, ch) in before_cursor.char_indices() {
        if start < skip_until || ch != '@' {
            continue;
        }
        let mut boundary = start;
        while let Some((idx, prev)) = before_cursor[..boundary].char_indices().next_back() {
            if matches!(prev, '(' | '[' | '{' | '<' | '\'' | '"' | '`') {
                boundary = idx;
            } else {
                break;
            }
        }
        if before_cursor[..boundary]
            .chars()
            .next_back()
            .is_some_and(|prev| !prev.is_whitespace())
        {
            continue;
        }
        let tail = &before_cursor[start + 1..];
        let prefix = if tail.starts_with(['"', '\'']) {
            let quote = tail.chars().next()?;
            let mut chars = tail[quote.len_utf8()..].char_indices().peekable();
            let mut prefix = String::new();
            let mut finished = false;
            while let Some((offset, c)) = chars.next() {
                if c == quote {
                    skip_until = start + 1 + quote.len_utf8() + offset + c.len_utf8();
                    finished = true;
                    break;
                }
                if c.is_control() {
                    return None;
                }
                if c == '\\' && chars.peek().is_some_and(|(_, c)| *c == quote || *c == '\\') {
                    prefix.push(chars.next()?.1);
                } else {
                    prefix.push(c);
                }
            }
            if finished {
                continue;
            }
            prefix
        } else {
            if tail
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '"' | '\'' | '`'))
            {
                continue;
            }
            tail.to_string()
        };
        let path = Path::new(&prefix);
        if path.is_absolute()
            || path.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            continue;
        }
        return Some(Mention {
            start,
            end: cursor,
            prefix,
        });
    }
    None
}

fn sensitive(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "target"
            | "node_modules"
            | ".git"
            | "credentials"
            | "secrets"
            | "id_rsa"
            | "id_ed25519"
            | "id_ecdsa"
    ) || name.starts_with(".env")
        || [".pem", ".key", ".p12", ".pfx", ".keystore"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn mention_text(path: &str, directory: bool) -> String {
    let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
    if directory {
        format!("@\"{escaped}/")
    } else {
        format!("@\"{escaped}\" ")
    }
}

pub struct FileCompletion {
    root: PathBuf,
    last_draft: Option<String>,
    last_cursor: Option<usize>,
    mention: Option<Mention>,
    pub candidates: Vec<FileCandidate>,
    pub selected: usize,
    pub truncated: bool,
}

impl Default for FileCompletion {
    fn default() -> Self {
        Self::new(std::env::current_dir().unwrap_or_default())
    }
}

impl FileCompletion {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            last_draft: None,
            last_cursor: None,
            mention: None,
            candidates: Vec::new(),
            selected: 0,
            truncated: false,
        }
    }

    /// Refresh only when the draft or insertion point changes, never on animation frames.
    pub fn sync(&mut self, draft: &str) {
        self.sync_at_cursor(draft, grapheme_count(draft));
    }

    /// Refresh suggestions for the text immediately before the insertion
    /// point. Moving the caret away from an `@` mention closes its picker.
    pub fn sync_at_cursor(&mut self, draft: &str, cursor: usize) {
        let cursor = clamp_cursor(draft, cursor);
        if self.last_draft.as_deref() == Some(draft) && self.last_cursor == Some(cursor) {
            return;
        }
        self.last_draft = Some(draft.to_string());
        self.last_cursor = Some(cursor);
        self.mention = trailing_mention(draft, cursor_byte_index(draft, cursor));
        self.candidates.clear();
        self.selected = 0;
        self.truncated = false;
        let Some(mention) = &self.mention else {
            return;
        };
        let (dir, prefix) = mention
            .prefix
            .rsplit_once('/')
            .unwrap_or(("", &mention.prefix));
        let Ok(root) = self.root.canonicalize() else {
            return;
        };
        let Ok(directory) = root.join(dir).canonicalize() else {
            return;
        };
        if !directory.starts_with(&root) || !directory.is_dir() {
            return;
        }
        // Walking from the workspace retains parent .gitignore rules, including
        // rules that hide the directory itself. Do not follow symlinks.
        let relative_dir = directory.strip_prefix(&root).unwrap_or(Path::new(""));
        if relative_dir
            .components()
            .any(|c| sensitive(&c.as_os_str().to_string_lossy()))
        {
            return;
        }
        let mut builder = ignore::WalkBuilder::new(&root);
        let wanted = directory.clone();
        builder
            .hidden(true)
            .require_git(false)
            .follow_links(false)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .ignore(true)
            .parents(true)
            .max_depth(Some(relative_dir.components().count() + 1))
            .filter_entry(move |entry| {
                let path = entry.path();
                (path == wanted
                    || wanted.starts_with(path)
                    || path.parent() == Some(wanted.as_path()))
                    && !sensitive(&entry.file_name().to_string_lossy())
                    && !entry.file_type().is_some_and(|t| t.is_symlink())
            });
        let began = Instant::now();
        for (scanned, entry) in builder.build().enumerate() {
            if scanned >= FILE_SCAN_MAX || began.elapsed() > Duration::from_millis(40) {
                self.truncated = true;
                break;
            }
            let Ok(entry) = entry else {
                continue;
            };
            if entry.path().parent() != Some(directory.as_path()) {
                continue;
            }
            let Some(name) = entry.file_name().to_str() else {
                continue;
            };
            if !name.starts_with(prefix) || name.chars().any(char::is_control) {
                continue;
            }
            let Some(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_file() && !kind.is_dir() {
                continue;
            }
            let Ok(path) = entry.path().strip_prefix(&root) else {
                continue;
            };
            let Some(path) = path.to_str() else {
                continue;
            };
            self.candidates.push(FileCandidate {
                path: path.to_string(),
                directory: kind.is_dir(),
            });
        }
        self.candidates.sort_by(|a, b| {
            b.directory
                .cmp(&a.directory)
                .then_with(|| a.path.cmp(&b.path))
        });
        self.truncated |= self.candidates.len() > FILE_RESULTS_MAX;
        self.candidates.truncate(FILE_RESULTS_MAX);
    }

    pub fn is_open(&self) -> bool {
        !self.candidates.is_empty()
    }

    pub fn dismiss(&mut self) {
        self.candidates.clear();
    }

    pub fn accept(&mut self, draft: &mut String) {
        let mut cursor = grapheme_count(draft);
        self.accept_at_cursor(draft, &mut cursor);
    }

    /// Replace the active mention at the insertion point, preserving any
    /// suffix after the caret and returning the caret after the inserted path.
    pub fn accept_at_cursor(&mut self, draft: &mut String, cursor: &mut usize) {
        let Some(candidate) = self.candidates.get(self.selected).cloned() else {
            return;
        };
        let Some(mention) = &self.mention else {
            return;
        };
        let start = mention.start;
        let end = mention.end;
        let replacement = mention_text(&candidate.path, candidate.directory);
        draft.replace_range(start..end, &replacement);
        *cursor = cursor_for_byte_offset(draft, start + replacement.len());
        self.sync_at_cursor(draft, *cursor);
    }
}

pub struct HistorySearch {
    pub query: String,
    pub matched: Option<usize>,
    original: String,
    original_cursor: usize,
}

impl HistorySearch {
    pub fn new(draft: &str, history: &[String]) -> Self {
        Self::new_with_cursor(draft, grapheme_count(draft), history)
    }

    pub fn new_with_cursor(draft: &str, cursor: usize, history: &[String]) -> Self {
        let mut search = Self {
            query: String::new(),
            matched: None,
            original: draft.to_string(),
            original_cursor: clamp_cursor(draft, cursor),
        };
        search.find(history, 0);
        search
    }

    fn find(&mut self, history: &[String], start: usize) {
        self.matched = (start..history.len())
            .chain(0..start.min(history.len()))
            .find(|&i| history[i].contains(&self.query));
    }

    pub fn older(&mut self, history: &[String]) {
        self.find(history, self.matched.map_or(0, |i| i + 1));
    }

    pub fn update(&mut self, history: &[String]) {
        self.find(history, 0);
    }

    pub fn preview(&self, history: &[String], draft: &mut String) -> usize {
        draft.clone_from(
            self.matched
                .and_then(|i| history.get(i))
                .unwrap_or(&self.original),
        );
        self.matched
            .map_or(self.original_cursor, |_| grapheme_count(draft))
    }

    pub fn restore(self, draft: &mut String) -> usize {
        *draft = self.original;
        self.original_cursor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "orbit-composer-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }
        fn file(&self, path: &str) {
            let path = self.0.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "sample").unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn only_trailing_mentions_open_completion() {
        for draft in [
            "mail@host",
            "https://host/@path",
            "https://host/(@path",
            "mail(@host",
            "@@path",
            "@../",
            "@/etc",
            "@file then text",
            "@\"closed\"",
        ] {
            assert!(trailing_mention(draft, draft.len()).is_none(), "{draft}");
        }
        assert_eq!(trailing_mention("<@file", 6).unwrap().prefix, "file");
        let quoted_path = "日本語 (@\"docs/a b";
        assert_eq!(
            trailing_mention(quoted_path, quoted_path.len()).unwrap(),
            Mention {
                start: 11,
                end: quoted_path.len(),
                prefix: "docs/a b".into()
            }
        );
        let escaped_path = "@\"a\\\"b\\\\c";
        assert_eq!(
            trailing_mention(escaped_path, escaped_path.len())
                .unwrap()
                .prefix,
            "a\"b\\c"
        );
        let nested_mention = "@\"old @file\" @next";
        assert_eq!(
            trailing_mention(nested_mention, nested_mention.len())
                .unwrap()
                .prefix,
            "next"
        );
        let open_quoted_path = "@\"a @b";
        assert_eq!(
            trailing_mention(open_quoted_path, open_quoted_path.len())
                .unwrap()
                .prefix,
            "a @b"
        );
    }

    #[test]
    fn suggestions_hide_ignored_sensitive_and_symlink_paths() {
        let f = Fixture::new();
        for path in [
            "visible.rs",
            "target/x",
            "node_modules/x",
            ".env",
            "private.key",
            "secrets/x",
            "ignored/x",
            "also-ignored.rs",
        ] {
            f.file(path);
        }
        std::fs::write(f.0.join(".gitignore"), "ignored/\nalso-ignored.rs\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("visible.rs", f.0.join("link.rs")).unwrap();
        let mut picker = FileCompletion::new(f.0.clone());
        picker.sync("@");
        assert_eq!(
            picker.candidates,
            vec![FileCandidate {
                path: "visible.rs".into(),
                directory: false
            }]
        );
        picker.sync("@ignored/");
        assert!(!picker.is_open());
        picker.sync("@secrets/");
        assert!(!picker.is_open());
    }

    #[test]
    fn accepting_directories_continues_and_files_quote_exact_unicode_paths() {
        let f = Fixture::new();
        f.file("日本語 docs/a b\"c.rs");
        let mut picker = FileCompletion::new(f.0.clone());
        let mut draft = "Read @日".to_string();
        picker.sync(&draft);
        picker.accept(&mut draft);
        assert_eq!(draft, "Read @\"日本語 docs/");
        assert!(picker.is_open());
        picker.accept(&mut draft);
        assert_eq!(draft, "Read @\"日本語 docs/a b\\\"c.rs\" ");
        assert!(!picker.is_open());
    }

    #[test]
    fn completion_tracks_the_caret_and_preserves_text_after_it() {
        let f = Fixture::new();
        f.file("日本語.txt");
        let mut picker = FileCompletion::new(f.0.clone());
        let mut draft = "@日suffix".to_string();
        let mut cursor = 2;
        picker.sync_at_cursor(&draft, cursor);
        assert_eq!(picker.candidates.len(), 1);
        picker.accept_at_cursor(&mut draft, &mut cursor);
        assert_eq!(draft, "@\"日本語.txt\" suffix");
        assert_eq!(cursor, grapheme_count("@\"日本語.txt\" "));
        assert!(!picker.is_open());

        let draft = "@日".to_string();
        picker.sync_at_cursor(&draft, 0);
        assert!(!picker.is_open());
    }

    #[test]
    fn results_are_bounded_and_escape_only_dismisses_the_current_draft() {
        let f = Fixture::new();
        for n in 0..FILE_RESULTS_MAX + 5 {
            f.file(&format!("file{n:03}.rs"));
        }
        let mut picker = FileCompletion::new(f.0.clone());
        picker.sync("@file");
        assert_eq!(picker.candidates.len(), FILE_RESULTS_MAX);
        assert!(picker.truncated);
        picker.dismiss();
        picker.sync("@file");
        assert!(!picker.is_open());
        picker.sync("@file0");
        assert!(picker.is_open());
    }

    #[test]
    fn reverse_search_updates_cycles_and_restores_a_multiline_draft() {
        let history = vec!["new build".into(), "other".into(), "old build\nnext".into()];
        let mut draft = "unfinished\n日本語".to_string();
        let mut search = HistorySearch::new(&draft, &history);
        search.query = "build".into();
        search.update(&history);
        search.preview(&history, &mut draft);
        assert_eq!(draft, "new build");
        search.older(&history);
        search.preview(&history, &mut draft);
        assert_eq!(draft, "old build\nnext");
        search.older(&history);
        assert_eq!(search.matched, Some(0));
        search.query = "missing".into();
        search.update(&history);
        assert_eq!(search.matched, None);
        search.restore(&mut draft);
        assert_eq!(draft, "unfinished\n日本語");
    }
}

#[cfg(test)]
mod cursor_tests {
    use super::*;

    #[test]
    fn cursor_edits_complete_graphemes_without_touching_suffixes() {
        let mut text = "a🇧🇷b".to_string();
        let mut cursor = 1;
        insert_at_cursor(&mut text, &mut cursor, "猫");
        assert_eq!(text, "a猫🇧🇷b");
        assert_eq!(cursor, 2);
        assert!(delete_at_cursor(&mut text, &mut cursor));
        assert_eq!(text, "a猫b");
        assert_eq!(cursor, 2);
        assert!(delete_before_cursor(&mut text, &mut cursor));
        assert_eq!(text, "ab");
        assert_eq!(cursor, 1);
    }

    #[test]
    fn inserting_combining_marks_and_joined_emoji_keeps_valid_boundaries() {
        let mut text = "eX".to_string();
        let mut cursor = 1;
        insert_at_cursor(&mut text, &mut cursor, "\u{301}");
        assert_eq!(text, "e\u{301}X");
        assert_eq!(cursor, 1);

        insert_at_cursor(&mut text, &mut cursor, "👩🏽‍💻");
        assert_eq!(text, "e\u{301}👩🏽‍💻X");
        assert_eq!(cursor, 2);
        assert!(delete_before_cursor(&mut text, &mut cursor));
        assert_eq!(text, "e\u{301}X");
        assert_eq!(cursor, 1);
    }

    #[test]
    fn word_delete_preserves_suffix_and_history_search_restores_cursor() {
        let mut text = "one two three".to_string();
        let mut cursor = 7;
        assert!(delete_previous_word(&mut text, &mut cursor));
        assert_eq!(text, "one three");
        assert_eq!(cursor, 3);

        let history = vec!["older prompt".to_string()];
        let mut search = HistorySearch::new_with_cursor(&text, 2, &history);
        let mut draft = text.clone();
        search.query = "missing".into();
        search.update(&history);
        assert_eq!(search.preview(&history, &mut draft), 2);
        assert_eq!(draft, text);
        search.query = "older".into();
        search.update(&history);
        assert_eq!(
            search.preview(&history, &mut draft),
            grapheme_count("older prompt")
        );
        assert_eq!(draft, "older prompt");
        assert_eq!(search.restore(&mut draft), 2);
        assert_eq!(draft, text);
    }

    #[test]
    fn home_and_end_stop_at_multiline_grapheme_boundaries() {
        let text = "first\n🇧🇷second\nlast";
        let mut cursor = grapheme_count("first\n🇧🇷sec");
        move_home(text, &mut cursor);
        assert_eq!(cursor, grapheme_count("first\n"));
        move_end(text, &mut cursor);
        assert_eq!(cursor, grapheme_count("first\n🇧🇷second"));
    }

    #[test]
    fn home_and_end_keep_crlf_as_one_grapheme() {
        let text = "first\r\nsecond";
        let mut cursor = 0;

        move_end(text, &mut cursor);
        assert_eq!(cursor, grapheme_count("first"));
        assert_eq!(cursor_byte_index(text, cursor), text.find('\r').unwrap());

        move_home(text, &mut cursor);
        assert_eq!(cursor, 0);
        move_end(text, &mut cursor);
        assert_eq!(cursor, grapheme_count("first"));

        move_right(text, &mut cursor);
        assert_eq!(cursor, grapheme_count("first\r\n"));
        move_end(text, &mut cursor);
        assert_eq!(cursor, grapheme_count(text));
        move_home(text, &mut cursor);
        assert_eq!(cursor, grapheme_count("first\r\n"));
    }
}
