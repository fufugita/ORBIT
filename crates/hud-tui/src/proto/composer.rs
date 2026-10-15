//! Draft-only file completion and reverse history search.

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub const FILE_RESULTS_MAX: usize = 64;
const FILE_SCAN_MAX: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCandidate {
    pub path: String,
    pub directory: bool,
}

/// A trailing mention at the insertion point. Offsets are UTF-8 byte boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mention {
    start: usize,
    prefix: String,
}

fn trailing_mention(draft: &str) -> Option<Mention> {
    let mut skip_until = 0;
    for (start, ch) in draft.char_indices() {
        if start < skip_until || ch != '@' {
            continue;
        }
        let mut boundary = start;
        while let Some((idx, prev)) = draft[..boundary].char_indices().next_back() {
            if matches!(prev, '(' | '[' | '{' | '<' | '\'' | '"' | '`') {
                boundary = idx;
            } else {
                break;
            }
        }
        if draft[..boundary]
            .chars()
            .next_back()
            .is_some_and(|prev| !prev.is_whitespace())
        {
            continue;
        }
        let tail = &draft[start + 1..];
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
        return Some(Mention { start, prefix });
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
            mention: None,
            candidates: Vec::new(),
            selected: 0,
            truncated: false,
        }
    }

    /// Refresh only when the draft changes, never on animation frames.
    pub fn sync(&mut self, draft: &str) {
        if self.last_draft.as_deref() == Some(draft) {
            return;
        }
        self.last_draft = Some(draft.to_string());
        self.mention = trailing_mention(draft);
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
        let Some(candidate) = self.candidates.get(self.selected).cloned() else {
            return;
        };
        let Some(mention) = &self.mention else {
            return;
        };
        draft.truncate(mention.start);
        draft.push_str(&mention_text(&candidate.path, candidate.directory));
        self.sync(draft);
    }
}

pub struct HistorySearch {
    pub query: String,
    pub matched: Option<usize>,
    original: String,
}

impl HistorySearch {
    pub fn new(draft: &str, history: &[String]) -> Self {
        let mut search = Self {
            query: String::new(),
            matched: None,
            original: draft.to_string(),
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

    pub fn preview(&self, history: &[String], draft: &mut String) {
        draft.clone_from(
            self.matched
                .and_then(|i| history.get(i))
                .unwrap_or(&self.original),
        );
    }

    pub fn restore(self, draft: &mut String) {
        *draft = self.original;
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
            assert!(trailing_mention(draft).is_none(), "{draft}");
        }
        assert_eq!(trailing_mention("<@file").unwrap().prefix, "file");
        assert_eq!(
            trailing_mention("日本語 (@\"docs/a b").unwrap(),
            Mention {
                start: 11,
                prefix: "docs/a b".into()
            }
        );
        assert_eq!(
            trailing_mention("@\"a\\\"b\\\\c").unwrap().prefix,
            "a\"b\\c"
        );
        assert_eq!(
            trailing_mention("@\"old @file\" @next").unwrap().prefix,
            "next"
        );
        assert_eq!(trailing_mention("@\"a @b").unwrap().prefix, "a @b");
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
