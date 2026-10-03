//! Read, Write, Edit, Glob, Grep — the file tools.
//!
//! Read caps at 2000 lines / 256 KiB. Edit requires a prior full Read
//! (hash match) so the model cannot blind-edit. All results pass the
//! secret scanner at the boundary.

use crate::{glob_match, is_deny_read, resolve_path, Tool, ToolContext, ToolResult};
use serde_json::json;
use std::path::Path;

const MAX_READ_LINES: usize = 2000;
const MAX_READ_BYTES: u64 = 256 * 1024;

// ============================== Read ==============================

pub struct ReadTool;

impl Tool for ReadTool {
    fn name(&self) -> &'static str {
        "Read"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string", "description": "Path to read" },
                "offset": { "type": "integer", "description": "Line to start at (1-based)" },
                "limit": { "type": "integer", "description": "Lines to read (default 2000)" }
            },
            "required": ["file_path"]
        })
    }
    fn read_only(&self) -> bool {
        true
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "Read".into(),
            pattern: input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }
    }
    fn run(&self, input: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let Some(file_path) = input.get("file_path").and_then(|v| v.as_str()) else {
            return ToolResult::err("file_path is required");
        };
        let path = resolve_path(cx, file_path);
        if is_deny_read(&path) {
            return ToolResult::err(
                "denied: that path is on the deny-read list (credentials never reach the provider)",
            );
        }
        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => return ToolResult::err(&format!("cannot read {file_path}: {e}")),
        };
        if metadata.is_dir() {
            return ToolResult::err(&format!(
                "{file_path} is a directory; use Glob to list files"
            ));
        }
        if metadata.len() > MAX_READ_BYTES {
            return ToolResult::err(&format!(
                "{file_path} is {} bytes; Read caps at {} bytes — use Grep to explore it in slices",
                metadata.len(),
                MAX_READ_BYTES
            ));
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => return ToolResult::err(&format!("cannot read {file_path}: {e}")),
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let offset = input
            .get("offset")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .max(1) as usize;
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(MAX_READ_LINES as u64) as usize;
        let mut numbered = String::new();
        let mut total = 0usize;
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            total = n;
            if n < offset {
                continue;
            }
            if n >= offset + limit {
                continue;
            }
            numbered.push_str(&format!("{n}\t{line}\n"));
        }
        // Record the content hash for read-before-edit. A partial read
        // (offset/limit) does NOT satisfy the read-before-edit rule —
        // only a full read does.
        if offset == 1 && total < limit {
            use sha2::Digest;
            let hash = hex::encode(sha2::Sha256::digest(&bytes));
            cx.record_read(path.clone(), hash);
        }
        let partial = total >= offset + limit;
        let scanned = crate::scan::scan_result(&numbered);
        let content = if scanned.redactions.is_empty() {
            numbered
        } else {
            scanned.text
        };
        let mut payload = json!({ "ok": true, "content": content });
        if partial {
            payload["partial"] = json!(true);
            payload["note"] = json!(format!(
                "showing lines {offset}..{} of {total}; use offset/limit for the rest",
                offset + limit - 1
            ));
        }
        if !scanned.redactions.is_empty() {
            payload["redacted"] = json!(scanned.redactions);
        }
        ToolResult::ok(payload)
    }
}

// ============================== Write ==============================

pub struct WriteTool;

impl Tool for WriteTool {
    fn name(&self) -> &'static str {
        "Write"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string", "description": "Path to write" },
                "content": { "type": "string", "description": "Full file content" }
            },
            "required": ["file_path", "content"]
        })
    }
    fn read_only(&self) -> bool {
        false
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "Write".into(),
            pattern: input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }
    }
    fn run(&self, input: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let Some(file_path) = input.get("file_path").and_then(|v| v.as_str()) else {
            return ToolResult::err("file_path is required");
        };
        let Some(content) = input.get("content").and_then(|v| v.as_str()) else {
            return ToolResult::err("content is required");
        };
        let path = resolve_path(cx, file_path);
        if is_deny_read(&path) {
            return ToolResult::err("denied: that path is on the deny list");
        }
        // An existing file must have been read in full this session
        // (read-before-write, the Write half of read-before-edit).
        if path.exists() && !cx.was_read(&path) {
            return ToolResult::err(
                "refused: the file exists but was not read in full this session — Read it first",
            );
        }
        // Atomic write: temp file in the same dir, then rename.
        let parent = path
            .parent()
            .ok_or_else(|| ToolResult::err("invalid path"))
            .unwrap()
            .to_path_buf();
        if let Err(e) = std::fs::create_dir_all(&parent) {
            return ToolResult::err(&format!("cannot create {}: {e}", parent.display()));
        }
        let tmp = parent.join(format!(".orbit-write-{}", ulid::Ulid::new()));
        if let Err(e) = std::fs::write(&tmp, content) {
            return ToolResult::err(&format!("cannot write {file_path}: {e}"));
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return ToolResult::err(&format!("cannot write {file_path}: {e}"));
        }
        // The write satisfies read-before-edit for the new content.
        use sha2::Digest;
        let hash = hex::encode(sha2::Sha256::digest(content.as_bytes()));
        cx.record_read(path.clone(), hash);
        ToolResult::ok(json!({
            "ok": true,
            "written": file_path,
            "bytes": content.len(),
        }))
    }
}

// ============================== Edit ==============================

pub struct EditTool;

impl Tool for EditTool {
    fn name(&self) -> &'static str {
        "Edit"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string", "description": "Path to edit" },
                "old_string": { "type": "string", "description": "Exact text to replace" },
                "new_string": { "type": "string", "description": "Replacement" },
                "replace_all": { "type": "boolean", "description": "Replace every occurrence (default false)" }
            },
            "required": ["file_path", "old_string", "new_string"]
        })
    }
    fn read_only(&self) -> bool {
        false
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "Edit".into(),
            pattern: input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }
    }
    fn run(&self, input: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let Some(file_path) = input.get("file_path").and_then(|v| v.as_str()) else {
            return ToolResult::err("file_path is required");
        };
        let Some(old_string) = input.get("old_string").and_then(|v| v.as_str()) else {
            return ToolResult::err("old_string is required");
        };
        let Some(new_string) = input.get("new_string").and_then(|v| v.as_str()) else {
            return ToolResult::err("new_string is required");
        };
        let replace_all = input
            .get("replace_all")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let path = resolve_path(cx, file_path);
        if is_deny_read(&path) {
            return ToolResult::err("denied: that path is on the deny list");
        }
        if !cx.was_read(&path) {
            return ToolResult::err(
                "refused: read the file in full before editing it (read-before-edit)",
            );
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => return ToolResult::err(&format!("cannot read {file_path}: {e}")),
        };
        // Refuse binary files (a NUL byte in the first 8 KiB is the
        // standard heuristic).
        if bytes[..bytes.len().min(8192)].contains(&0) {
            return ToolResult::err("refused: binary file");
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let count = text.matches(old_string).count();
        if count == 0 {
            return ToolResult::err("old_string not found in the file");
        }
        if count > 1 && !replace_all {
            return ToolResult::err(&format!(
                "old_string appears {count} times; add replace_all or make it unique"
            ));
        }
        let new_text = if replace_all {
            text.replace(old_string, new_string)
        } else {
            text.replacen(old_string, new_string, 1)
        };
        // Atomic write.
        let parent = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let tmp = parent.join(format!(".orbit-edit-{}", ulid::Ulid::new()));
        if let Err(e) = std::fs::write(&tmp, &new_text) {
            return ToolResult::err(&format!("cannot write {file_path}: {e}"));
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return ToolResult::err(&format!("cannot write {file_path}: {e}"));
        }
        // The edit changes the content — update the recorded hash.
        use sha2::Digest;
        let hash = hex::encode(sha2::Sha256::digest(new_text.as_bytes()));
        cx.record_read(path.clone(), hash);
        // A display diff (unified-ish, first hunk only for brevity).
        let diff = simple_diff(&text, &new_text);
        ToolResult::ok(json!({
            "ok": true,
            "edited": file_path,
            "replacements": if replace_all { count } else { 1 },
            "diff": diff,
        }))
    }
}

/// A minimal line diff for display (first differing region).
fn simple_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = String::new();
    let mut shown = 0;
    let mut i = 0;
    let mut j = 0;
    while i < old_lines.len() && j < new_lines.len() {
        if old_lines[i] == new_lines[j] {
            i += 1;
            j += 1;
            continue;
        }
        // find resync point (up to 20 lines of context)
        let mut oi = i;
        let mut nj = j;
        while oi < old_lines.len() && nj < new_lines.len() && old_lines[oi] != new_lines[nj] {
            oi += 1;
            nj += 1;
        }
        for l in &old_lines[i..oi] {
            out.push_str(&format!("- {l}\n"));
            shown += 1;
        }
        for l in &new_lines[j..nj] {
            out.push_str(&format!("+ {l}\n"));
            shown += 1;
        }
        if shown > 40 {
            out.push_str("…\n");
            break;
        }
        i = oi;
        j = nj;
    }
    while i < old_lines.len() && shown < 40 {
        out.push_str(&format!("- {}\n", old_lines[i]));
        i += 1;
        shown += 1;
    }
    while j < new_lines.len() && shown < 40 {
        out.push_str(&format!("+ {}\n", new_lines[j]));
        j += 1;
        shown += 1;
    }
    out
}

// ============================== Glob ==============================

pub struct GlobTool;

impl Tool for GlobTool {
    fn name(&self) -> &'static str {
        "Glob"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "Glob pattern (e.g. **/*.rs)" },
                "path": { "type": "string", "description": "Base directory (default working dir)" }
            },
            "required": ["pattern"]
        })
    }
    fn read_only(&self) -> bool {
        true
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "Glob".into(),
            pattern: input
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }
    }
    fn run(&self, input: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let Some(pattern) = input.get("pattern").and_then(|v| v.as_str()) else {
            return ToolResult::err("pattern is required");
        };
        let base = input
            .get("path")
            .and_then(|v| v.as_str())
            .map(|p| resolve_path(cx, p))
            .unwrap_or_else(|| cx.working_dir.clone());
        if is_deny_read(&base) {
            return ToolResult::err("denied: that path is on the deny-read list");
        }
        let mut matches = Vec::new();
        let cap = 100usize;
        walk(&base, &mut |p| {
            if matches.len() >= cap {
                return false;
            }
            if is_deny_read(p) {
                return false;
            }
            let rel = p.strip_prefix(&base).unwrap_or(p);
            if glob_path_match(pattern, &rel.to_string_lossy()) {
                matches.push(rel.to_string_lossy().into_owned());
            }
            true
        });
        let truncated = matches.len() >= cap;
        ToolResult::ok(json!({
            "ok": true,
            "matches": matches,
            "truncated": truncated,
        }))
    }
}

/// Match a glob pattern against a relative path. `**` spans
/// directories; `*` stays within one component.
pub fn glob_path_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    fn rec(p: &[&str], s: &[&str]) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }
        if p[0] == "**" {
            // ** matches zero or more segments
            for skip in 0..=s.len() {
                if rec(&p[1..], &s[skip..]) {
                    return true;
                }
            }
            return false;
        }
        if s.is_empty() {
            return false;
        }
        if glob_match(p[0], s[0]) {
            rec(&p[1..], &s[1..])
        } else {
            false
        }
    }
    rec(&pat, &segs)
}

/// Walk a directory tree (bounded depth, .gitignore-aware for the
/// common entries).
fn walk(dir: &Path, f: &mut dyn FnMut(&Path) -> bool) {
    const MAX_DEPTH: usize = 12;
    fn rec(dir: &Path, depth: usize, f: &mut dyn FnMut(&Path) -> bool) {
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".git" || name == "target" || name == "node_modules" {
                continue;
            }
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                rec(&p, depth + 1, f);
            } else if !f(&p) {
                return;
            }
        }
    }
    rec(dir, 0, f);
}

// ============================== Grep ==============================

pub struct GrepTool;

impl Tool for GrepTool {
    fn name(&self) -> &'static str {
        "Grep"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "Regex to search for" },
                "path": { "type": "string", "description": "File or directory to search" },
                "glob": { "type": "string", "description": "Limit to files matching this glob" },
                "head_limit": { "type": "integer", "description": "Max matches (default 100)" }
            },
            "required": ["pattern"]
        })
    }
    fn read_only(&self) -> bool {
        true
    }
    fn permission_key(&self, input: &serde_json::Value) -> crate::PermissionKey {
        crate::PermissionKey {
            tool: "Grep".into(),
            pattern: input
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }
    }
    fn run(&self, input: &serde_json::Value, cx: &ToolContext) -> ToolResult {
        let Some(pattern) = input.get("pattern").and_then(|v| v.as_str()) else {
            return ToolResult::err("pattern is required");
        };
        let base = input
            .get("path")
            .and_then(|v| v.as_str())
            .map(|p| resolve_path(cx, p))
            .unwrap_or_else(|| cx.working_dir.clone());
        if is_deny_read(&base) {
            return ToolResult::err("denied: that path is on the deny-read list");
        }
        let glob_filter = input.get("glob").and_then(|v| v.as_str());
        let head_limit = input
            .get("head_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        let re = match simple_regex::compile(pattern) {
            Ok(re) => re,
            Err(e) => return ToolResult::err(&format!("bad pattern: {e}")),
        };
        let mut matches: Vec<serde_json::Value> = Vec::new();
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        if base.is_file() {
            files.push(base.clone());
        } else {
            walk(&base, &mut |p| {
                if let Some(g) = glob_filter {
                    if !glob_path_match(g, &p.to_string_lossy()) {
                        return true;
                    }
                }
                files.push(p.to_path_buf());
                files.len() < 500
            });
        }
        for file in files {
            if matches.len() >= head_limit {
                break;
            }
            if is_deny_read(&file) {
                continue;
            }
            let Ok(bytes) = std::fs::read(&file) else {
                continue;
            };
            if bytes[..bytes.len().min(8192)].contains(&0) {
                continue; // binary
            }
            let text = String::from_utf8_lossy(&bytes);
            for (i, line) in text.lines().enumerate() {
                if matches.len() >= head_limit {
                    break;
                }
                if re.is_match(line) {
                    matches.push(json!({
                        "file": file.to_string_lossy(),
                        "line": i + 1,
                        "text": line,
                    }));
                }
            }
        }
        let truncated = matches.len() >= head_limit;
        ToolResult::ok(json!({
            "ok": true,
            "matches": matches,
            "truncated": truncated,
        }))
    }
}

/// A tiny regex engine (literal + alternation + classes + anchors +
/// quantifiers) — enough for Grep's common patterns without pulling a
/// regex dependency into the tool crate. Falls back to substring
/// matching for anything it cannot compile.
pub mod simple_regex {
    pub struct Regex {
        /// None = substring fallback for the raw pattern.
        parts: Option<Vec<Alt>>,
    }

    struct Alt {
        branches: Vec<Vec<Piece>>,
    }

    #[derive(Clone)]
    enum Piece {
        Literal(char),
        Class(String),
        Any,
        Star(Box<Piece>),
        Plus(Box<Piece>),
        Optional(Box<Piece>),
    }

    pub fn compile(pattern: &str) -> Result<Regex, String> {
        // Parse alternation of sequences.
        let mut branches: Vec<Vec<Piece>> = Vec::new();
        let mut current: Vec<Piece> = Vec::new();
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '|' => {
                    branches.push(std::mem::take(&mut current));
                }
                '[' => {
                    let mut class = String::new();
                    for c2 in chars.by_ref() {
                        if c2 == ']' {
                            break;
                        }
                        class.push(c2);
                    }
                    current.push(Piece::Class(class));
                }
                '.' => current.push(Piece::Any),
                '*' => {
                    let prev = current.pop().ok_or("nothing to repeat")?;
                    current.push(Piece::Star(Box::new(prev)));
                }
                '+' => {
                    let prev = current.pop().ok_or("nothing to repeat")?;
                    current.push(Piece::Plus(Box::new(prev)));
                }
                '?' => {
                    let prev = current.pop().ok_or("nothing to repeat")?;
                    current.push(Piece::Optional(Box::new(prev)));
                }
                '\\' => {
                    if let Some(c2) = chars.next() {
                        current.push(Piece::Literal(c2));
                    }
                }
                _ => current.push(Piece::Literal(c)),
            }
        }
        branches.push(current);
        Ok(Regex {
            parts: Some(
                branches
                    .into_iter()
                    .map(|b| Alt { branches: vec![b] })
                    .collect(),
            ),
        })
    }

    impl Regex {
        pub fn is_match(&self, line: &str) -> bool {
            let Some(alts) = &self.parts else {
                return true;
            };
            for alt in alts {
                for branch in &alt.branches {
                    if match_seq(branch, line) {
                        return true;
                    }
                }
            }
            false
        }
    }

    fn match_seq(seq: &[Piece], line: &str) -> bool {
        // Try every starting offset (unanchored search).
        for start in 0..=line.len() {
            if rec(seq, &line[start..]) {
                return true;
            }
        }
        false
    }

    fn rec(seq: &[Piece], rest: &str) -> bool {
        if seq.is_empty() {
            return true;
        }
        let mut chars = rest.chars();
        match &seq[0] {
            Piece::Literal(c) => chars.next() == Some(*c) && rec(&seq[1..], &rest[c.len_utf8()..]),
            Piece::Class(class) => {
                // support ranges a-z, 0-9, and negation ^, and \d \w \s
                match chars.next() {
                    Some(ch) => class_match(class, ch) && rec(&seq[1..], &rest[ch.len_utf8()..]),
                    None => false,
                }
            }
            Piece::Any => match chars.next() {
                Some(_) => rec(&seq[1..], &rest[1..]),
                None => false,
            },
            Piece::Star(inner) => {
                // zero or more
                if rec(&seq[1..], rest) {
                    return true;
                }
                let mut consumed = String::new();
                let mut it = rest.chars();
                loop {
                    let save = it.clone();
                    match it.next() {
                        Some(ch) => {
                            consumed.push(ch);
                            if piece_matches_one(inner, ch) {
                                if rec(&seq[1..], &rest[consumed.len()..]) {
                                    return true;
                                }
                            } else {
                                let _ = save;
                                return false;
                            }
                        }
                        None => return false,
                    }
                }
            }
            Piece::Plus(inner) => {
                let mut consumed = String::new();
                let mut it = rest.chars();
                loop {
                    match it.next() {
                        Some(ch) => {
                            consumed.push(ch);
                            if !piece_matches_one(inner, ch) {
                                return false;
                            }
                            if rec(&seq[1..], &rest[consumed.len()..]) {
                                return true;
                            }
                        }
                        None => return false,
                    }
                }
            }
            Piece::Optional(inner) => {
                if rec(&seq[1..], rest) {
                    return true;
                }
                let mut it = rest.chars();
                if let Some(ch) = it.next() {
                    if piece_matches_one(inner, ch) {
                        return rec(&seq[1..], &rest[ch.len_utf8()..]);
                    }
                }
                false
            }
        }
    }

    fn piece_matches_one(p: &Piece, ch: char) -> bool {
        match p {
            Piece::Literal(c) => *c == ch,
            Piece::Class(class) => class_match(class, ch),
            Piece::Any => true,
            _ => false,
        }
    }

    fn class_match(class: &str, ch: char) -> bool {
        let (neg, body) = match class.strip_prefix('^') {
            Some(b) => (true, b),
            None => (false, class),
        };
        let mut hit = false;
        let mut cs = body.chars().peekable();
        while let Some(c) = cs.next() {
            if c == '\\' {
                if let Some(d) = cs.next() {
                    let m = match d {
                        'd' => ch.is_ascii_digit(),
                        'w' => ch.is_alphanumeric() || ch == '_',
                        's' => ch.is_whitespace(),
                        _ => ch == d,
                    };
                    if m {
                        hit = true;
                    }
                }
            } else if cs.peek() == Some(&'-') {
                cs.next();
                if let Some(hi) = cs.next() {
                    if c <= ch && ch <= hi {
                        hit = true;
                    }
                }
            } else if c == ch {
                hit = true;
            }
        }
        hit != neg
    }
}
