//! Read, Write, Edit, Glob, Grep — the file tools.
//!
//! Read caps at 2000 lines / 256 KiB. Edit requires a prior full Read
//! (hash match) so the model cannot blind-edit. All results pass the
//! secret scanner at the boundary.

use crate::{Tool, ToolContext, ToolResult, glob_match, is_deny_read, resolve_path};
use serde_json::json;
use std::path::Path;

const MAX_READ_LINES: usize = 2000;
const MAX_READ_BYTES: u64 = 256 * 1024;
/// Room for file lines in one Read result. It sits under the inline
/// limit with space for the wrapper and the note, so a long file comes
/// back as a window of whole lines and not as a spilled result.
const READ_INLINE_BUDGET: usize = crate::INLINE_LIMIT - 1_000;

/// An image a Read returns as data instead of text: the extension the
/// Anthropic and OpenAI vision APIs both accept.
const IMAGE_EXTS: [&str; 4] = ["png", "jpg", "jpeg", "webp"];
/// The inline cap for an image the Read tool returns: 5 MB of bytes
/// before base64 (the providers' own request limits sit above this;
/// the cap keeps one image from eating the context budget).
const MAX_IMAGE_BYTES: u64 = 5 * 1024 * 1024;
/// PDF Read caps: file size, and pages delivered per read.
const MAX_PDF_BYTES: u64 = 20 * 1024 * 1024;
const MAX_PDF_PAGES: usize = 8;

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
            return ToolResult::denied(
                "that path is on the deny-read list (credentials never reach the provider)",
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
        // An image Read returns data, not lossy text: the payload
        // carries `image_base64` + `image_media_type`, and the engine
        // attaches the block to the wire where the provider speaks
        // blocks (Anthropic tool_result). The text path is untouched.
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if IMAGE_EXTS.contains(&ext.as_str()) {
            return read_image(&path, file_path, &metadata, &ext);
        }
        if ext == "pdf" {
            return read_pdf(&path, file_path, &metadata);
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
        // A window too long for one inline result is cut at a line
        // boundary, so the model gets real lines and the place to go on
        // from instead of a short preview of a spilled result.
        let mut cut_at: Option<usize> = None;
        let mut inline_cost = 0usize;
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            total = n;
            if n < offset {
                continue;
            }
            if n >= offset + limit || cut_at.is_some() {
                continue;
            }
            let row = format!("{n}\t{line}\n");
            let cost = serde_json::to_string(&row).map_or(row.len(), |quoted| quoted.len() - 2);
            if inline_cost + cost > READ_INLINE_BUDGET && !numbered.is_empty() {
                cut_at = Some(n);
                continue;
            }
            inline_cost += cost;
            numbered.push_str(&row);
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
        if let Some(next) = cut_at {
            payload["partial"] = json!(true);
            payload["note"] = json!(format!(
                "showing lines {offset}..{} of {total}: the rest did not fit in one result; go on with offset {next}",
                next - 1
            ));
        } else if partial {
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

/// An image Read: the bytes as base64 data, not lossy text. The
/// payload carries `image_base64` + `image_media_type` (the engine
/// attaches the `ContentBlock::Image` where the provider speaks
/// blocks); `content` says what it was, so a non-vision provider or a
/// plain transcript still reads honestly. The deny-read check already
/// ran (the caller's path); the size cap is the image's own.
fn read_image(path: &Path, file_path: &str, metadata: &std::fs::Metadata, ext: &str) -> ToolResult {
    if metadata.len() > MAX_IMAGE_BYTES {
        return ToolResult::err(&format!(
            "{file_path} is {} bytes; Read caps images at {} bytes",
            metadata.len(),
            MAX_IMAGE_BYTES
        ));
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return ToolResult::err(&format!("cannot read {file_path}: {e}")),
    };
    let media_type = match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "image/png",
    };
    let data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
    ToolResult::ok(json!({
        "ok": true,
        "content": format!("[image: {file_path}, {} bytes, {media_type}]", bytes.len()),
        "image_base64": data,
        "image_media_type": media_type,
    }))
}

/// A PDF Read: the first pages' extracted text. The honest,
/// dependency-light path — pure-Rust extraction, no rasterizer, no system
/// pdfium. Text PDFs become readable content; scanned image-only PDFs
/// come back with empty page text and say so rather than pretending.
/// The deny-read check already ran; the caps are the PDF's own.
fn read_pdf(path: &Path, file_path: &str, metadata: &std::fs::Metadata) -> ToolResult {
    if metadata.len() > MAX_PDF_BYTES {
        return ToolResult::err(&format!(
            "{file_path} is {} bytes; Read caps PDFs at {} bytes",
            metadata.len(),
            MAX_PDF_BYTES
        ));
    }
    let document = match pdf_oxide::document::PdfDocument::open(path) {
        Ok(document) => document,
        Err(error) => {
            return ToolResult::err(&format!("{file_path} is not a readable PDF: {error}"));
        }
    };
    let page_count = document.page_count().unwrap_or(0);
    let shown = page_count.min(MAX_PDF_PAGES);
    let mut pages = Vec::with_capacity(shown);
    let mut total_chars = 0usize;
    for page in 0..shown {
        let text = document.extract_text(page).unwrap_or_default();
        total_chars += text.len();
        pages.push(text);
    }
    if total_chars == 0 {
        return ToolResult::err(&format!(
            "{file_path} has {page_count} page(s) but no extractable text (likely scanned images); text extraction cannot read it"
        ));
    }
    let mut content = String::new();
    for (index, text) in pages.iter().enumerate() {
        content.push_str(&format!("--- page {} ---\n{text}\n", index + 1));
    }
    let mut payload = json!({
        "ok": true,
        "content": content,
        "pages_total": page_count,
    });
    if page_count > MAX_PDF_PAGES {
        payload["partial"] = json!(true);
        payload["note"] = json!(format!("showing pages 1..{MAX_PDF_PAGES} of {page_count}"));
    }
    ToolResult::ok(payload)
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
            return ToolResult::denied("that path is on the deny list");
        }
        if crate::is_operator_config(&path, &cx.home) {
            return ToolResult::denied(OPERATOR_CONFIG_REFUSAL);
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

/// Why Write and Edit leave ORBIT's own configuration alone.
const OPERATOR_CONFIG_REFUSAL: &str = "that file is the operator's own ORBIT configuration (settings, permissions, MCP servers, providers): it decides what runs outside the sandbox or without asking, so only the operator edits it";

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
            return ToolResult::denied("that path is on the deny list");
        }
        if crate::is_operator_config(&path, &cx.home) {
            return ToolResult::denied(OPERATOR_CONFIG_REFUSAL);
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

/// A line diff for display: the lines that left (`- `) and the lines that
/// arrived (`+ `), in file order, at most [`DIFF_LINES`] of them. Lines the
/// two texts share are left out, wherever they sit.
fn simple_diff(old: &str, new: &str) -> String {
    const DIFF_LINES: usize = 40;
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let head = old_lines
        .iter()
        .zip(&new_lines)
        .take_while(|(a, b)| a == b)
        .count();
    let tail = old_lines[head..]
        .iter()
        .rev()
        .zip(new_lines[head..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let old_mid = &old_lines[head..old_lines.len() - tail];
    let new_mid = &new_lines[head..new_lines.len() - tail];
    let mut out = String::new();
    for (shown, (sign, line)) in diff_middle(old_mid, new_mid).into_iter().enumerate() {
        if shown == DIFF_LINES {
            out.push_str("…\n");
            break;
        }
        out.push(sign);
        out.push(' ');
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The changed lines between two runs of lines that share no first and no
/// last line, by longest common subsequence. Two runs too large for the
/// table are reported as all removed, then all added.
fn diff_middle<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<(char, &'a str)> {
    const TABLE_CELLS: usize = 4_000_000;
    let (n, m) = (old.len(), new.len());
    if n.saturating_mul(m) > TABLE_CELLS {
        return old
            .iter()
            .map(|line| ('-', *line))
            .chain(new.iter().map(|line| ('+', *line)))
            .collect();
    }
    // lcs[i][j]: the longest common subsequence of old[i..] and new[j..].
    let width = m + 1;
    let mut lcs = vec![0u32; (n + 1) * width];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i * width + j] = if old[i] == new[j] {
                lcs[(i + 1) * width + j + 1] + 1
            } else {
                lcs[(i + 1) * width + j].max(lcs[i * width + j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if old[i] == new[j] {
            i += 1;
            j += 1;
        } else if lcs[(i + 1) * width + j] >= lcs[i * width + j + 1] {
            out.push(('-', old[i]));
            i += 1;
        } else {
            out.push(('+', new[j]));
            j += 1;
        }
    }
    out.extend(old[i..].iter().map(|line| ('-', *line)));
    out.extend(new[j..].iter().map(|line| ('+', *line)));
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
            .unwrap_or_else(|| cx.cwd());
        if is_deny_read(&base) {
            return ToolResult::denied("that path is on the deny-read list");
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

/// Build a gitignore-aware walker (ripgrep's `ignore` crate): hidden
/// files stay out, .gitignore/.ignore are respected, and `target`/
/// `node_modules`/`.git` are always excluded even without a gitignore.
fn walk_builder(dir: &Path) -> ignore::WalkBuilder {
    let mut b = ignore::WalkBuilder::new(dir);
    b.hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .parents(true)
        .max_depth(Some(12))
        .filter_entry(move |e| {
            let name = e.file_name().to_string_lossy();
            name != "target" && name != "node_modules" && name != ".git"
        });
    b
}

/// Walk a directory tree, gitignore-aware (B1: the walker).
fn walk(dir: &Path, f: &mut dyn FnMut(&Path) -> bool) {
    for entry in walk_builder(dir).build().flatten() {
        let Some(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_file() && !f(entry.path()) {
            return;
        }
    }
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
            .unwrap_or_else(|| cx.cwd());
        if is_deny_read(&base) {
            return ToolResult::denied("that path is on the deny-read list");
        }
        let glob_filter = input.get("glob").and_then(|v| v.as_str());
        let head_limit = input
            .get("head_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        // The real regex engine (B1): UTF-8-correct, never panics on
        // multi-byte text the way the hand-written offset loop did.
        let re = match regex::Regex::new(pattern) {
            Ok(re) => re,
            Err(e) => return ToolResult::err(&format!("bad pattern: {e}")),
        };
        let mut matches: Vec<serde_json::Value> = Vec::new();
        let mut file_count = 0usize;
        const FILE_LIMIT: usize = 2000;
        if base.is_file() {
            file_count = 1;
            if !is_deny_read(&base) {
                grep_file(&base, &re, head_limit, &mut matches);
            }
        } else {
            // One honest pass over the whole tree (B1: the old cap
            // returned early from whichever directory came first and
            // still reported truncated:false).
            walk(&base, &mut |p| {
                if matches.len() >= head_limit || file_count >= FILE_LIMIT {
                    return false;
                }
                if let Some(g) = glob_filter
                    && !glob_path_match(g, &p.to_string_lossy())
                {
                    return true;
                }
                file_count += 1;
                if !is_deny_read(p) {
                    grep_file(p, &re, head_limit, &mut matches);
                }
                true
            });
        }
        let truncated = matches.len() >= head_limit || file_count >= FILE_LIMIT;
        ToolResult::ok(json!({
            "ok": true,
            "matches": matches,
            "truncated": truncated,
            "files_searched": file_count,
        }))
    }
}

/// Search one file for `re`, appending up to the remaining limit.
/// Non-UTF-8 and binary files are skipped; multi-byte text is safe
/// (the regex crate is UTF-8-native).
fn grep_file(path: &Path, re: &regex::Regex, limit: usize, out: &mut Vec<serde_json::Value>) {
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return; // binary
    }
    let text = String::from_utf8_lossy(&bytes);
    for (i, line) in text.lines().enumerate() {
        if out.len() >= limit {
            return;
        }
        if re.is_match(line) {
            out.push(json!({
                "file": path.to_string_lossy(),
                "line": i + 1,
                "text": line,
            }));
        }
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
                if let Some(ch) = it.next()
                    && piece_matches_one(inner, ch)
                {
                    return rec(&seq[1..], &rest[ch.len_utf8()..]);
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
                if let Some(hi) = cs.next()
                    && c <= ch
                    && ch <= hi
                {
                    hit = true;
                }
            } else if c == ch {
                hit = true;
            }
        }
        hit != neg
    }
}

#[cfg(test)]
mod image_read_tests {
    use super::*;
    use serde_json::json;

    fn cx_in(dir: &std::path::Path) -> ToolContext {
        ToolContext::new(dir.to_path_buf(), "image-test".into(), dir.to_path_buf())
    }

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("orbit-imgread-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A minimal valid PNG (1×1 transparent): the 8-byte signature
    /// plus an IHDR/IDAT/IEND the media type check never parses — the
    /// Read tool keys on the extension, not the bytes.
    fn tiny_png() -> Vec<u8> {
        let mut b = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        b.extend_from_slice(b"fake-but-bounded-png-bytes-for-the-test");
        b
    }

    /// An image Read returns base64 data, not lossy text: the payload
    /// carries `image_base64` + `image_media_type`, and `content` says
    /// what it was so a plain transcript reads honestly.
    #[test]
    fn an_image_read_returns_base64_data() {
        let d = temp_home("b64");
        std::fs::write(d.join("shot.png"), tiny_png()).unwrap();
        let cx = cx_in(&d);
        let r = ReadTool
            .run(&json!({ "file_path": "shot.png" }), &cx)
            .payload;
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert!(v["ok"].as_bool().unwrap());
        assert_eq!(v["image_media_type"], "image/png");
        let data = v["image_base64"].as_str().unwrap();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data).unwrap();
        assert_eq!(decoded, tiny_png());
        assert!(
            v["content"].as_str().unwrap().contains("[image: shot.png"),
            "the honest content line: {}",
            v["content"]
        );
    }

    /// The extension decides: jpg/jpeg/webp map to their media types;
    /// a text file with image-ish bytes stays the text path.
    #[test]
    fn media_types_follow_the_extension() {
        let d = temp_home("ext");
        std::fs::write(d.join("a.jpg"), tiny_png()).unwrap();
        std::fs::write(d.join("b.webp"), tiny_png()).unwrap();
        std::fs::write(d.join("c.txt"), "just text").unwrap();
        let cx = cx_in(&d);
        for (name, mt) in [("a.jpg", "image/jpeg"), ("b.webp", "image/webp")] {
            let r = ReadTool.run(&json!({ "file_path": name }), &cx).payload;
            let v: serde_json::Value = serde_json::from_str(&r).unwrap();
            assert_eq!(v["image_media_type"], mt, "{name}");
        }
        let r = ReadTool.run(&json!({ "file_path": "c.txt" }), &cx).payload;
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert!(
            v.get("image_base64").is_none(),
            "a text file never carries image data"
        );
        assert!(v["content"].as_str().unwrap().contains("just text"));
    }

    /// The deny-read list holds for images exactly as for text.
    #[test]
    fn a_deny_read_image_is_refused() {
        let d = temp_home("deny");
        let ssh = d.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("key.png"), tiny_png()).unwrap();
        let cx = cx_in(&d);
        let r = ReadTool
            .run(&json!({ "file_path": "~/.ssh/key.png" }), &cx)
            .payload;
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert!(!v["ok"].as_bool().unwrap(), "the deny-read path refused");
        assert!(v["denied"].as_bool().unwrap(), "a typed refusal");
    }

    /// The image cap: a file above 5 MB is refused with the cap named,
    /// never read into memory.
    #[test]
    fn an_oversized_image_is_refused_without_reading() {
        let d = temp_home("cap");
        // A sparse file: 6 MB of zeros without writing 6 MB.
        let f = std::fs::File::create(d.join("big.png")).unwrap();
        f.set_len(MAX_IMAGE_BYTES + 1).unwrap();
        drop(f);
        let cx = cx_in(&d);
        let r = ReadTool
            .run(&json!({ "file_path": "big.png" }), &cx)
            .payload;
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert!(!v["ok"].as_bool().unwrap());
        assert!(
            v["error"].as_str().unwrap().contains("caps images"),
            "the refusal names the cap: {}",
            v["error"]
        );
    }
}

#[cfg(test)]
mod pdf_read_tests {
    use super::*;
    use serde_json::json;

    fn cx_in(dir: &std::path::Path) -> ToolContext {
        ToolContext::new(dir.to_path_buf(), "pdf-test".into(), dir.to_path_buf())
    }

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("orbit-pdfread-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A two-page text PDF, built with pdf_oxide's own writer so the
    /// fixture is a real document, not a fake signature.
    fn two_page_pdf(dir: &std::path::Path, name: &str) {
        use pdf_oxide::writer::PdfWriter;
        let mut writer = PdfWriter::new();
        writer.add_page(612.0, 792.0).add_text(
            "orbit pdf page one",
            72.0,
            700.0,
            "Helvetica",
            12.0,
        );
        writer.add_page(612.0, 792.0).add_text(
            "orbit pdf page two",
            72.0,
            700.0,
            "Helvetica",
            12.0,
        );
        writer.save(dir.join(name)).expect("save");
    }

    #[test]
    fn a_pdf_read_returns_extracted_page_text() {
        let d = temp_home("text");
        two_page_pdf(&d, "doc.pdf");
        let cx = cx_in(&d);
        let r = ReadTool
            .run(&json!({ "file_path": "doc.pdf" }), &cx)
            .payload;
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert!(v["ok"].as_bool().unwrap(), "{r}");
        assert_eq!(v["pages_total"], 2);
        let content = v["content"].as_str().unwrap();
        assert!(content.contains("--- page 1 ---"), "{content}");
        assert!(content.contains("page one"), "{content}");
        assert!(content.contains("page two"), "{content}");
        assert!(v.get("partial").is_none(), "two pages fit the cap");
    }

    #[test]
    fn a_non_pdf_with_pdf_extension_is_an_honest_error() {
        let d = temp_home("fake");
        std::fs::write(d.join("fake.pdf"), b"not a pdf at all").unwrap();
        let cx = cx_in(&d);
        let r = ReadTool
            .run(&json!({ "file_path": "fake.pdf" }), &cx)
            .payload;
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert!(v.get("ok") != Some(&json!(true)), "{r}");
        let error = v["error"].as_str().unwrap_or(&r);
        assert!(error.contains("not a readable PDF"), "{error}");
    }
}

#[cfg(test)]
mod long_read_tests {
    use super::*;
    use serde_json::json;

    /// A file under the line cap but too long for one inline result used
    /// to come back as a 2,000-character preview of a spilled result. It
    /// now comes back as a window of whole lines with the line to go on
    /// from, and the windows together are the whole file.
    #[test]
    fn a_long_file_is_read_in_windows_of_whole_lines() {
        let d = std::env::temp_dir().join(format!("orbit-longread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let body: String = (1..=1600)
            .map(|n| {
                format!(
                    "line {n:04} \"quoted\" and a tab\tthen filler {}\n",
                    "x".repeat(40)
                )
            })
            .collect();
        std::fs::write(d.join("long.txt"), &body).unwrap();
        let cx = ToolContext::new(d.clone(), "long-read-test".into(), d.clone());

        let mut offset = 1usize;
        let mut seen = String::new();
        let mut windows = 0;
        loop {
            let raw = ReadTool.run(&json!({ "file_path": "long.txt", "offset": offset }), &cx);
            let finished = crate::finish(raw, &cx, "call");
            assert!(finished.spilled_to.is_none(), "a window fits inline");
            assert!(finished.payload.len() <= crate::INLINE_LIMIT);
            let v: serde_json::Value = serde_json::from_str(&finished.payload).unwrap();
            let content = v["content"].as_str().unwrap();
            assert!(content.ends_with('\n'), "whole lines only");
            for row in content.lines() {
                let (_, line) = row.split_once('\t').unwrap();
                seen.push_str(line);
                seen.push('\n');
            }
            windows += 1;
            let Some(note) = v["note"].as_str() else {
                break;
            };
            assert_eq!(v["partial"], true);
            let next: usize = note.rsplit(' ').next().unwrap().parse().expect(note);
            assert!(next > offset, "{note}");
            assert!(
                note.contains(&format!("showing lines {offset}..{} of 1600", next - 1)),
                "{note}"
            );
            offset = next;
        }
        assert!(windows > 1, "the file does not fit one result");
        assert_eq!(seen, body);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A short file is unchanged: whole, no note.
    #[test]
    fn a_short_file_is_still_one_result_with_no_note() {
        let d = std::env::temp_dir().join(format!("orbit-shortread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("s.txt"), "a\nb\n").unwrap();
        let cx = ToolContext::new(d.clone(), "short-read-test".into(), d.clone());
        let v: serde_json::Value =
            serde_json::from_str(&ReadTool.run(&json!({ "file_path": "s.txt" }), &cx).payload)
                .unwrap();
        assert_eq!(v["content"], "1\ta\n2\tb\n");
        assert!(v.get("note").is_none() && v.get("partial").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod diff_tests {
    use super::simple_diff;

    #[test]
    fn a_change_of_line_count_does_not_drag_the_rest_of_the_file_in() {
        let old = "import sys\n\ndef count(text):\n    # BUG\n    return len(text.split(\" \"))\n\n\ndef main():\n    return 0\n";
        let new = "import sys\n\ndef count(text):\n    return len(text.split())\n\n\ndef main():\n    return 0\n";
        assert_eq!(
            simple_diff(old, new),
            "-     # BUG\n-     return len(text.split(\" \"))\n+     return len(text.split())\n"
        );
    }

    #[test]
    fn separate_changes_are_each_reported_and_shared_lines_between_them_are_not() {
        let old = "a\nb\nc\nd\ne\n";
        let new = "a\nB\nc\nd\nE\nf\n";
        assert_eq!(simple_diff(old, new), "- b\n+ B\n- e\n+ E\n+ f\n");
        assert_eq!(simple_diff("same\n", "same\n"), "");
        assert_eq!(simple_diff("", "x\n"), "+ x\n");
        assert_eq!(simple_diff("x\n", ""), "- x\n");
    }

    #[test]
    fn a_long_diff_is_cut_with_a_mark() {
        let old: String = (0..100).map(|n| format!("old {n}\n")).collect();
        let new: String = (0..100).map(|n| format!("new {n}\n")).collect();
        let diff = simple_diff(&old, &new);
        assert_eq!(diff.lines().count(), 41);
        assert!(diff.ends_with("…\n"), "{diff}");
    }
}

/// The files that decide what runs without a sandbox or without asking
/// (hooks, permission rules, the sandbox's own switch, MCP servers, provider
/// endpoints) are the operator's. The model's file tools never write them, in
/// any permission mode: a model that could would switch its own sandbox off.
#[cfg(test)]
mod operator_config_tests {
    use super::*;

    const FILES: [&str; 6] = [
        "settings.toml",
        "settings.local.toml",
        "permissions.toml",
        "permission-overrides.toml",
        "mcp.json",
        "providers.toml",
    ];

    /// A context whose ORBIT home and working directory are different directories.
    fn fixture(tag: &str) -> (ToolContext, std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("orbit-opcfg-{tag}-{}", ulid::Ulid::new()));
        let (home, work) = (root.join("home"), root.join("work"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        let (home, work) = (home.canonicalize().unwrap(), work.canonicalize().unwrap());
        (
            ToolContext::new(home.clone(), "opcfg".into(), work.clone()),
            home,
            work,
        )
    }

    fn denied(result: &ToolResult) -> bool {
        serde_json::from_str::<serde_json::Value>(&result.payload)
            .map(|v| v["denied"] == true)
            .unwrap_or(false)
    }

    fn write(cx: &ToolContext, path: &std::path::Path, content: &str) -> ToolResult {
        WriteTool.run(
            &json!({ "file_path": path.to_string_lossy(), "content": content }),
            cx,
        )
    }

    #[test]
    fn the_models_file_tools_never_write_the_operators_configuration() {
        let (cx, home, _work) = fixture("write");
        for name in FILES {
            let target = home.join(name);
            let result = write(&cx, &target, "[sandbox]\nenabled = false\n");
            assert!(denied(&result), "{name}: {}", result.payload);
            assert!(!target.exists(), "{name} must not have been created");
        }
        // An existing file stays what it was, however it is approached.
        let settings = home.join("settings.toml");
        let original = "[sandbox]\nnetwork = false\n";
        std::fs::write(&settings, original).unwrap();
        let path = settings.to_string_lossy().into_owned();
        ReadTool.run(&json!({ "file_path": path }), &cx);
        let edit = EditTool.run(
            &json!({ "file_path": path, "old_string": "false", "new_string": "true" }),
            &cx,
        );
        assert!(denied(&edit), "{}", edit.payload);
        let rewrite = write(&cx, &settings, "[sandbox]\nenabled = false\n");
        assert!(denied(&rewrite), "{}", rewrite.payload);
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), original);
    }

    #[test]
    fn another_spelling_of_the_same_file_is_the_same_file() {
        let (cx, home, work) = fixture("spelling");
        std::fs::create_dir_all(home.join("sub")).unwrap();
        let settings = home.join("settings.toml");
        std::fs::write(&settings, "original\n").unwrap();
        // `..` through a directory that exists.
        let dotted = home.join("sub").join("..").join("settings.toml");
        let result = write(&cx, &dotted, "x");
        assert!(denied(&result), "{}", result.payload);
        // A link in the working directory that points at it.
        let link = work.join("innocent.txt");
        std::os::unix::fs::symlink(&settings, &link).unwrap();
        let result = write(&cx, &link, "x");
        assert!(denied(&result), "{}", result.payload);
        // A link to a directory that holds a file the tools could create.
        let dir_link = work.join("home-link");
        std::os::unix::fs::symlink(&home, &dir_link).unwrap();
        let result = write(&cx, &dir_link.join("providers.toml"), "x");
        assert!(denied(&result), "{}", result.payload);
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "original\n");
        assert!(!home.join("providers.toml").exists());
    }

    #[test]
    fn a_project_file_of_the_same_name_and_the_rest_of_the_home_are_not_affected() {
        let (cx, home, work) = fixture("unaffected");
        // A project's own settings.toml is just a file of the project.
        let project_settings = work.join("settings.toml");
        let result = write(&cx, &project_settings, "a = 1\n");
        assert!(!denied(&result), "{}", result.payload);
        assert!(project_settings.exists());
        // So is anything else, even where the tools may not usually go.
        let notes = home.join("notes.txt");
        let result = write(&cx, &notes, "hello\n");
        assert!(!denied(&result), "{}", result.payload);
        assert!(notes.exists());
    }
}
