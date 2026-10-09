//! Markdown for the conversation panel: the model's reply, flattened to
//! displayed characters with a style per character.
//!
//! A terminal cannot show a heading as a heading, so the markers that
//! make one go away (`## `, `**`, `*`, a link's brackets, `> `, the
//! bullet dash) and what they meant survives as style: bold, italic,
//! heading level, link, quote, code. Nothing is invented: the text the
//! reader sees is the text the model wrote, minus the markup.
//!
//! The parser is deliberately small and conservative. A marker with no
//! partner on its line stays literal (`a * b`, `snake_case_name`, one
//! stray `**`), and fenced code is never parsed.
//!
//! A pipe table (a header row, a `|---|` row, then rows) is laid out as a
//! grid: columns sized to their content and shrunk to fit the panel,
//! cells clipped with `…`, the header bold, the `|---|` row a rule. Text
//! that merely contains `|` is left alone.

use super::canvas::text_width;

/// What one displayed character is, beyond its glyph.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Sty {
    /// Inline `code` or a fenced line.
    pub code: bool,
    pub bold: bool,
    pub italic: bool,
    /// `#` count of the heading the character is in; 0 = not a heading.
    pub heading: u8,
    /// Part of a `> ` block quote line.
    pub quote: bool,
    /// The text of a `[text](url)` link.
    pub link: bool,
    /// Muted furniture: a link's URL, a quote's gutter.
    pub dim: bool,
    /// A line of a fenced code block (inline `code` is not a block): its
    /// row is a band across the panel, and so is its newline.
    pub block: bool,
}

/// A reply flattened for display.
#[derive(Clone, Default, Debug)]
pub struct Styled {
    pub plain: Vec<char>,
    pub sty: Vec<Sty>,
    /// For each char of the RAW text (plus one past the end): the index
    /// in `plain` of the first displayed char at or after it. Streaming
    /// arrival offsets count raw chars; this maps them onto what is on
    /// screen, so the fresh-ink fade keeps its place when markers drop.
    pub raw_to_plain: Vec<usize>,
    /// The language tag of each fenced block that has one: the index in
    /// `plain` of the block's first line, and the tag (` ```rust `).
    pub labels: Vec<(usize, String)>,
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric()
}

/// A single-char emphasis closer (`*` or `_`) somewhere after
/// `content_start` (which holds at least one content char): not after a
/// space, not part of a doubled marker, and for `_` not inside a word.
fn italic_closer(line: &[char], content_start: usize, c: char) -> bool {
    (content_start + 1..line.len()).any(|p| {
        line[p] == c
            && line[p - 1] != ' '
            && line[p - 1] != c
            && line.get(p + 1) != Some(&c)
            && (c == '*' || !line.get(p + 1).is_some_and(|n| is_word(*n)))
    })
}

/// A doubled emphasis closer (`**` or `__`) after `content_start`.
fn bold_closer(line: &[char], content_start: usize, c: char) -> bool {
    (content_start + 1..line.len().saturating_sub(1))
        .any(|p| line[p] == c && line[p + 1] == c && line[p - 1] != ' ')
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Align {
    Left,
    Right,
    Center,
}

/// A pipe table found in the lines, laid out and ready to emit.
struct Table {
    /// Raw lines the table covers (header, rule, body rows).
    lines: usize,
    /// Displayed rows, one per raw line: the header, the rule, the body.
    shown: Vec<Vec<(char, Sty)>>,
}

/// A `|` that is not escaped.
fn has_pipe(line: &str) -> bool {
    let mut prev = ' ';
    for c in line.chars() {
        if c == '|' && prev != '\\' {
            return true;
        }
        prev = c;
    }
    false
}

/// The cells of a pipe row: outer pipes dropped, `\|` a literal pipe.
fn split_cells(line: &str) -> Vec<String> {
    let t = line.trim();
    let t = t.strip_prefix('|').unwrap_or(t);
    let t = if t.ends_with('|') && !t.ends_with("\\|") {
        &t[..t.len() - 1]
    } else {
        t
    };
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut chars = t.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'|') {
            cur.push('|');
            chars.next();
        } else if c == '|' {
            cells.push(cur.trim().to_string());
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    cells.push(cur.trim().to_string());
    cells
}

/// The alignments of a `|---|:---:|` row, or None if it is not one.
fn rule_aligns(line: &str) -> Option<Vec<Align>> {
    if !has_pipe(line) {
        return None;
    }
    split_cells(line)
        .iter()
        .map(|c| {
            let body = c.trim_matches(':');
            (!body.is_empty() && body.chars().all(|ch| ch == '-')).then(|| {
                match (c.starts_with(':'), c.ends_with(':')) {
                    (true, true) => Align::Center,
                    (false, true) => Align::Right,
                    _ => Align::Left,
                }
            })
        })
        .collect()
}

/// Clip a styled cell to `w` cells, ending in `…` when it had to be cut.
fn clip_cell(cell: &Styled, w: usize) -> Vec<(char, Sty)> {
    let chars: Vec<(char, Sty)> = cell
        .plain
        .iter()
        .copied()
        .zip(cell.sty.iter().copied())
        .collect();
    let width = |cs: &[(char, Sty)]| {
        cs.iter()
            .map(|(c, _)| text_width(&c.to_string()) as usize)
            .sum::<usize>()
    };
    if width(&chars) <= w {
        return chars;
    }
    let mut out: Vec<(char, Sty)> = Vec::new();
    for (c, st) in &chars {
        if width(&out) + text_width(&c.to_string()) as usize > w.saturating_sub(1) {
            break;
        }
        out.push((*c, *st));
    }
    let st = out.last().map_or_else(Sty::default, |(_, st)| *st);
    out.push(('…', st));
    out
}

/// A table starting at line `at`: a header row with a pipe in it, a rule
/// row with as many cells, then the rows that follow while they have a
/// pipe. None when it is not one, or cannot fit `max_width` at all.
fn table_at(lines: &[&str], at: usize, max_width: usize) -> Option<Table> {
    let header = lines.get(at).filter(|l| has_pipe(l))?;
    let aligns = rule_aligns(lines.get(at + 1)?)?;
    let head = split_cells(header);
    if head.len() != aligns.len() {
        return None;
    }
    let n = head.len();
    let mut count = 2;
    while lines.get(at + count).is_some_and(|l| has_pipe(l)) {
        count += 1;
    }
    // Cells, inline markup parsed. The rule row sits between the header
    // and the body but has no cells of its own.
    let mut rows: Vec<Vec<Styled>> = Vec::new();
    for (k, line) in lines[at..at + count].iter().enumerate() {
        if k == 1 {
            continue;
        }
        let mut cells = split_cells(line);
        cells.resize(n, String::new());
        rows.push(cells.iter().map(|c| rich_styled(c)).collect());
    }
    let cell_w = |c: &Styled| {
        c.plain
            .iter()
            .map(|ch| text_width(&ch.to_string()) as usize)
            .sum::<usize>()
    };
    let mut widths: Vec<usize> = (0..n)
        .map(|c| rows.iter().map(|r| cell_w(&r[c])).max().unwrap_or(0).max(1))
        .collect();
    let seps = 3 * (n - 1);
    // Shrink the widest column until the grid fits; give up if even
    // three cells per column do not.
    if n * 3 + seps > max_width {
        return None;
    }
    while widths.iter().sum::<usize>() + seps > max_width {
        let (widest, _) = widths.iter().enumerate().max_by_key(|(_, w)| **w)?;
        widths[widest] -= 1;
    }
    let dim = Sty {
        dim: true,
        ..Sty::default()
    };
    let mut shown: Vec<Vec<(char, Sty)>> = Vec::new();
    for (k, row) in rows.iter().enumerate() {
        let mut out: Vec<(char, Sty)> = Vec::new();
        for (c, w) in widths.iter().enumerate() {
            if c > 0 {
                out.extend([(' ', dim), ('│', dim), (' ', dim)]);
            }
            let mut cell = clip_cell(&row[c], *w);
            if k == 0 {
                for (_, st) in cell.iter_mut() {
                    st.bold = true;
                }
            }
            let used: usize = cell
                .iter()
                .map(|(ch, _)| text_width(&ch.to_string()) as usize)
                .sum();
            let pad = w.saturating_sub(used);
            let (left, right) = match aligns[c] {
                Align::Left => (0, pad),
                Align::Right => (pad, 0),
                Align::Center => (pad / 2, pad - pad / 2),
            };
            out.extend(std::iter::repeat_n((' ', Sty::default()), left));
            out.extend(cell);
            // No trailing padding on the last column.
            if c + 1 < n {
                out.extend(std::iter::repeat_n((' ', Sty::default()), right));
            }
        }
        shown.push(out);
        if k == 0 {
            // The `|---|` row becomes a rule under the header, even while
            // the body has not arrived yet.
            let mut rule = Vec::new();
            for (c, w) in widths.iter().enumerate() {
                if c > 0 {
                    rule.extend([('─', dim), ('┼', dim), ('─', dim)]);
                }
                rule.extend(std::iter::repeat_n(('─', dim), *w));
            }
            shown.push(rule);
        }
    }
    Some(Table {
        lines: count,
        shown,
    })
}

/// Append a laid-out table. `ri` is the raw index of its first line;
/// returns the raw index after its last line. Every raw char of a line
/// maps onto that line's displayed row, proportionally, so streaming
/// arrival offsets stay monotonic.
fn emit_table(
    out: &mut Styled,
    table: &Table,
    raw: &[&str],
    mut ri: usize,
    more_after: bool,
) -> usize {
    for (k, line) in raw.iter().enumerate() {
        let shown = &table.shown[k];
        let len = line.chars().count();
        let start = out.plain.len();
        for r in 0..=len {
            let at = start + (r * shown.len()) / len.max(1);
            if ri + r < out.raw_to_plain.len() {
                out.raw_to_plain[ri + r] = at;
            }
        }
        for (c, st) in shown {
            out.plain.push(*c);
            out.sty.push(*st);
        }
        let last = k + 1 == raw.len();
        if !last || more_after {
            out.raw_to_plain[ri + len] = out.plain.len();
            out.plain.push('\n');
            out.sty.push(Sty::default());
        }
        ri += len + 1;
    }
    ri
}

/// Parse a reply with no width limit. `text` is the raw model text,
/// newlines included.
pub fn rich_styled(text: &str) -> Styled {
    rich_styled_fit(text, usize::MAX)
}

/// Parse a reply for a panel `max_width` cells wide: only a table cares
/// (it shrinks its columns to fit); everything else wraps later.
pub fn rich_styled_fit(text: &str, max_width: usize) -> Styled {
    let raw_len = text.chars().count();
    let all_lines: Vec<&str> = text.split('\n').collect();
    let nlines = all_lines.len();
    let mut out = Styled {
        raw_to_plain: vec![0; raw_len + 1],
        ..Default::default()
    };
    let mut fence = false;
    // The tag of the block just opened, until its first line is emitted.
    let mut pending_label: Option<String> = None;
    let mut ri = 0usize; // raw index of the start of the current line
    let mut skip_to = 0usize; // lines already laid out as part of a table
    for (li, line_str) in all_lines.iter().enumerate() {
        if li < skip_to {
            continue;
        }
        if !fence {
            if let Some(table) = table_at(&all_lines, li, max_width) {
                ri = emit_table(
                    &mut out,
                    &table,
                    &all_lines[li..li + table.lines],
                    ri,
                    li + table.lines < nlines,
                );
                skip_to = li + table.lines;
                continue;
            }
        }
        let line: Vec<char> = line_str.chars().collect();
        let has_newline = li + 1 < nlines;
        // Emit one displayed char; `$r` is its raw index, or None for a
        // char with no raw origin (the bullet that replaces a dash).
        macro_rules! emit {
            ($r:expr, $c:expr, $s:expr) => {{
                if let Some(r) = $r {
                    out.raw_to_plain[ri + r] = out.plain.len();
                }
                out.plain.push($c);
                out.sty.push($s);
            }};
        }
        // Mark raw index `$r` consumed without displaying it.
        macro_rules! drop_raw {
            ($r:expr) => {{
                out.raw_to_plain[ri + $r] = out.plain.len();
            }};
        }

        let indent = line.iter().position(|c| *c != ' ').unwrap_or(line.len());
        let is_fence = line[indent..].starts_with(&['`', '`', '`']);
        if is_fence {
            fence = !fence;
            // ` ```rust `: the first word after the backticks is the tag.
            pending_label = fence
                .then(|| {
                    line[indent..]
                        .iter()
                        .skip_while(|c| **c == '`')
                        .collect::<String>()
                        .split_whitespace()
                        .next()
                        .map(str::to_string)
                })
                .flatten();
            for r in 0..line.len() {
                drop_raw!(r);
            }
        } else if fence {
            if let Some(tag) = pending_label.take() {
                out.labels.push((out.plain.len(), tag));
            }
            let code = Sty {
                code: true,
                block: true,
                ..Default::default()
            };
            for (r, c) in line.iter().enumerate() {
                emit!(Some(r), *c, code);
            }
        } else {
            let mut base = Sty::default();
            for r in 0..indent {
                emit!(Some(r), ' ', base);
            }
            let mut j = indent;
            // Line-level markers.
            let rest = &line[indent..];
            let hashes = rest.iter().take_while(|c| **c == '#').count();
            if (1..=6).contains(&hashes) && rest.get(hashes) == Some(&' ') {
                for r in 0..=hashes {
                    drop_raw!(indent + r);
                }
                j = indent + hashes + 1;
                base.heading = hashes as u8;
            } else if rest.starts_with(&['>', ' ']) {
                drop_raw!(indent);
                drop_raw!(indent + 1);
                base.quote = true;
                let gutter = Sty { dim: true, ..base };
                emit!(None::<usize>, '│', gutter);
                emit!(None::<usize>, ' ', gutter);
                j = indent + 2;
            } else if matches!(rest.first(), Some('-' | '*' | '+')) && rest.get(1) == Some(&' ') {
                drop_raw!(indent);
                emit!(None::<usize>, '•', base);
                j = indent + 1; // the space after the bullet stays
            }
            // Inline.
            let mut code = false;
            let mut bold: Option<char> = None;
            let mut italic: Option<char> = None;
            while j < line.len() {
                let c = line[j];
                let sty = Sty {
                    code,
                    bold: bold.is_some() || base.heading > 0,
                    italic: italic.is_some(),
                    ..base
                };
                if c == '`' {
                    drop_raw!(j);
                    code = !code;
                    j += 1;
                    continue;
                }
                if code {
                    emit!(Some(j), c, sty);
                    j += 1;
                    continue;
                }
                // **bold** and __bold__
                if (c == '*' || c == '_') && line.get(j + 1) == Some(&c) {
                    let opening = bold.is_none()
                        && (c == '*' || j == 0 || !is_word(line[j - 1]))
                        && line.get(j + 2).is_some_and(|n| *n != ' ')
                        && bold_closer(&line, j + 2, c);
                    let closing = bold == Some(c) && j > 0 && line[j - 1] != ' ';
                    if opening || closing {
                        drop_raw!(j);
                        drop_raw!(j + 1);
                        bold = if opening { Some(c) } else { None };
                        j += 2;
                        continue;
                    }
                }
                // *italic* and _italic_
                if (c == '*' || c == '_')
                    && line.get(j + 1) != Some(&c)
                    && (j == 0 || line[j - 1] != c)
                {
                    let opening = italic.is_none()
                        && (c == '*' || j == 0 || !is_word(line[j - 1]))
                        && line.get(j + 1).is_some_and(|n| *n != ' ')
                        && italic_closer(&line, j + 1, c);
                    let closing = italic == Some(c)
                        && j > 0
                        && line[j - 1] != ' '
                        && (c == '*' || !line.get(j + 1).is_some_and(|n| is_word(*n)));
                    if opening || closing {
                        drop_raw!(j);
                        italic = if opening { Some(c) } else { None };
                        j += 1;
                        continue;
                    }
                }
                // [text](url)
                if c == '[' {
                    if let Some(close) = line[j + 1..].iter().position(|x| *x == ']') {
                        let close = j + 1 + close;
                        if line.get(close + 1) == Some(&'(') {
                            if let Some(end) = line[close + 2..].iter().position(|x| *x == ')') {
                                let end = close + 2 + end;
                                drop_raw!(j);
                                let link = Sty { link: true, ..sty };
                                for (r, ch) in line.iter().enumerate().take(close).skip(j + 1) {
                                    emit!(Some(r), *ch, link);
                                }
                                drop_raw!(close);
                                drop_raw!(close + 1);
                                let dim = Sty { dim: true, ..sty };
                                emit!(None::<usize>, ' ', dim);
                                emit!(None::<usize>, '(', dim);
                                for (r, ch) in line.iter().enumerate().take(end).skip(close + 2) {
                                    emit!(Some(r), *ch, dim);
                                }
                                emit!(None::<usize>, ')', dim);
                                drop_raw!(end);
                                j = end + 1;
                                continue;
                            }
                        }
                    }
                }
                emit!(Some(j), c, sty);
                j += 1;
            }
        }
        if has_newline {
            out.raw_to_plain[ri + line.len()] = out.plain.len();
            // A fence line leaves no row of its own. The newline of a code
            // line stays part of the block, so a blank line inside it is
            // still a row of the band.
            if !is_fence {
                out.plain.push('\n');
                out.sty.push(Sty {
                    block: fence,
                    ..Default::default()
                });
            }
        }
        ri += line.len() + 1;
    }
    let end = out.plain.len();
    *out.raw_to_plain.last_mut().expect("one past the end") = end;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &Styled) -> String {
        s.plain.iter().collect()
    }

    /// The characters of `s` that carry `f`, in order.
    fn with(s: &Styled, f: impl Fn(&Sty) -> bool) -> String {
        s.plain
            .iter()
            .zip(&s.sty)
            .filter(|(_, st)| f(st))
            .map(|(c, _)| *c)
            .collect()
    }

    #[test]
    fn headings_lose_their_hashes_and_keep_their_level() {
        let s = rich_styled("## Summary\n\nbody");
        assert_eq!(text(&s), "Summary\n\nbody");
        assert_eq!(with(&s, |st| st.heading == 2), "Summary");
        // `#` with no space is not a heading.
        assert_eq!(text(&rich_styled("#hashtag")), "#hashtag");
    }

    #[test]
    fn bold_and_italic_become_styles() {
        let s = rich_styled("Here is **what changed** and *why*, not _this_one.");
        // `_this_one`: an underscore inside a word is not emphasis.
        assert_eq!(text(&s), "Here is what changed and why, not _this_one.");
        assert_eq!(with(&s, |st| st.bold), "what changed");
        assert_eq!(with(&s, |st| st.italic), "why");
        // A closing marker at the very end of a line closes.
        let s = rich_styled("**done**");
        assert_eq!(text(&s), "done");
        assert_eq!(with(&s, |st| st.bold), "done");
        let s = rich_styled("_fine_ and __strong__");
        assert_eq!(text(&s), "fine and strong");
        assert_eq!(with(&s, |st| st.italic), "fine");
        assert_eq!(with(&s, |st| st.bold), "strong");
    }

    #[test]
    fn a_marker_with_no_partner_stays_literal() {
        assert_eq!(text(&rich_styled("2 * 3 * 4")), "2 * 3 * 4");
        assert_eq!(text(&rich_styled("a stray ** here")), "a stray ** here");
        assert_eq!(text(&rich_styled("x ** y")), "x ** y");
        assert_eq!(text(&rich_styled("**never closed")), "**never closed");
        assert_eq!(
            text(&rich_styled("call super_long_snake_case_name now")),
            "call super_long_snake_case_name now"
        );
    }

    #[test]
    fn code_is_never_parsed() {
        let s = rich_styled("use `**not bold** and *not italic*` ok");
        assert_eq!(text(&s), "use **not bold** and *not italic* ok");
        assert!(with(&s, |st| st.bold || st.italic).is_empty());
        assert_eq!(with(&s, |st| st.code), "**not bold** and *not italic*");
    }

    #[test]
    fn fenced_code_is_kept_whole_and_unparsed() {
        let s = rich_styled("before\n```rust\nlet a = *b;\n# not a heading\n```\nafter");
        assert_eq!(text(&s), "before\nlet a = *b;\n# not a heading\nafter");
        assert_eq!(with(&s, |st| st.code), "let a = *b;# not a heading");
        assert_eq!(with(&s, |st| st.heading > 0), "");
    }

    #[test]
    fn a_fenced_block_remembers_its_language_and_marks_its_lines() {
        let s = rich_styled("a\n```rust\nlet x;\n\nlet y;\n```\nb");
        assert_eq!(text(&s), "a\nlet x;\n\nlet y;\nb");
        // The tag points at the block's first line; the lines, blank one
        // included, are the block; the prose around it is not.
        assert_eq!(s.labels, vec![(2, "rust".to_string())]);
        assert_eq!(with(&s, |st| st.block), "let x;\n\nlet y;\n");
        assert_eq!(with(&s, |st| !st.block), "a\nb");
        // No tag, no label. Inline code is not a block.
        assert!(rich_styled("```\nx\n```").labels.is_empty());
        let s = rich_styled("use `x` here");
        assert!(with(&s, |st| st.block).is_empty());
        // A tag with trailing words keeps only the first; an unclosed
        // fence (a reply still streaming) keeps its label.
        let s = rich_styled("```python title=x\nprint(1)");
        assert_eq!(s.labels, vec![(0, "python".to_string())]);
        // An empty block has no first line, so no label.
        assert!(rich_styled("```rust\n```").labels.is_empty());
    }

    #[test]
    fn a_pipe_table_becomes_a_grid() {
        let s = rich_styled("| file | change |\n|------|--------|\n| calc.py | +1 -1 |");
        assert_eq!(
            text(&s),
            "file    │ change\n────────┼───────\ncalc.py │ +1 -1"
        );
        // The header is bold; the furniture is muted; the cells are not.
        assert_eq!(with(&s, |st| st.bold), "filechange");
        assert_eq!(with(&s, |st| st.dim), " │ ────────┼─────── │ ");
        // Text around a table is untouched, and the table ends with it.
        let s = rich_styled("before\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\nafter | not a table");
        assert_eq!(
            text(&s),
            "before\n\na │ b\n──┼──\n1 │ 2\n\nafter | not a table"
        );
    }

    #[test]
    fn columns_follow_the_alignment_row() {
        let s = rich_styled("| name | n |\n|:----:|--:|\n| x | 12345 |");
        assert_eq!(text(&s), "name │     n\n─────┼──────\n x   │ 12345");
    }

    #[test]
    fn cells_keep_their_inline_markup() {
        let s = rich_styled("| a | b |\n|---|---|\n| `x` | **y** |");
        assert_eq!(text(&s).lines().nth(2), Some("x │ y"));
        assert_eq!(with(&s, |st| st.code), "x");
        assert_eq!(with(&s, |st| st.bold), "aby");
    }

    #[test]
    fn a_table_with_no_body_yet_is_still_a_table() {
        // While a reply streams, the rule row arrives before the rows.
        let s = rich_styled("| a | b |\n|---|---|");
        assert_eq!(text(&s), "a │ b\n──┼──");
    }

    #[test]
    fn pipes_without_a_rule_row_stay_literal() {
        for t in [
            "a | b",
            "| a | b |",
            "| a | b |\n| c | d |",
            "| a | b |\n|---|\n| c | d |", // rule row with another cell count
            "x\n|---|---|",                // a rule row alone
        ] {
            assert_eq!(text(&rich_styled(t)), t, "{t:?}");
        }
    }

    #[test]
    fn a_table_shrinks_to_the_panel_and_clips_with_an_ellipsis() {
        let t = "| a very long cell here | short |\n|---|---|\n| x | y |";
        let s = rich_styled_fit(t, 14);
        let shown = text(&s);
        for row in shown.lines() {
            assert!(row.chars().count() <= 14, "{row:?} is wider than 14");
        }
        assert!(shown.lines().next().unwrap().contains('…'), "{shown}");
        assert!(shown.contains("short"), "the narrow column keeps its text");
        // So narrow that three cells per column do not fit: literal.
        assert_eq!(text(&rich_styled_fit(t, 8)), t);
    }

    /// A table streams in line by line, and every prefix must parse, map
    /// its raw offsets monotonically and cover the end.
    #[test]
    fn every_prefix_of_a_table_parses_and_maps() {
        let reply = "intro\n| a | bb |\n|:-|-:|\n| 1 | 22 |\n| 3 | 4 |\nafter";
        let chars: Vec<char> = reply.chars().collect();
        for n in 0..=chars.len() {
            let prefix: String = chars[..n].iter().collect();
            for width in [usize::MAX, 12] {
                let s = rich_styled_fit(&prefix, width);
                assert_eq!(s.plain.len(), s.sty.len(), "{prefix:?}");
                assert_eq!(s.raw_to_plain.len(), n + 1, "{prefix:?}");
                assert!(
                    s.raw_to_plain.windows(2).all(|w| w[0] <= w[1]),
                    "monotonic for {prefix:?}: {:?}",
                    s.raw_to_plain
                );
                assert!(s.raw_to_plain.iter().all(|i| *i <= s.plain.len()));
                assert_eq!(*s.raw_to_plain.last().unwrap(), s.plain.len());
            }
        }
    }

    #[test]
    fn links_show_their_text_and_keep_the_url_dim() {
        let s = rich_styled("See [the docs](https://example.com/d) now");
        assert_eq!(text(&s), "See the docs (https://example.com/d) now");
        assert_eq!(with(&s, |st| st.link), "the docs");
        assert_eq!(with(&s, |st| st.dim), " (https://example.com/d)");
        // An unclosed link is literal.
        assert_eq!(text(&rich_styled("[not a link]")), "[not a link]");
        assert_eq!(text(&rich_styled("[a](b")), "[a](b");
    }

    #[test]
    fn quotes_and_bullets_get_real_glyphs() {
        let s = rich_styled("> a quote\n- one\n  - two\n* three\n1. four");
        assert_eq!(text(&s), "│ a quote\n• one\n  • two\n• three\n1. four");
        assert_eq!(with(&s, |st| st.quote), "│ a quote");
        // A bullet needs the space: `-x` is not a list, `*x*` is italic.
        assert_eq!(text(&rich_styled("-x")), "-x");
        assert_eq!(text(&rich_styled("*x* y")), "x y");
    }

    #[test]
    fn heading_text_can_hold_inline_styles() {
        let s = rich_styled("# The `add()` fix");
        assert_eq!(text(&s), "The add() fix");
        assert_eq!(with(&s, |st| st.heading == 1 && st.code), "add()");
    }

    /// Streaming arrival offsets count RAW chars. They must land on the
    /// right displayed char even though markers disappear, and the map
    /// must be monotonic and cover the end.
    #[test]
    fn raw_offsets_map_onto_displayed_chars() {
        let raw = "## Hi\n**ab** c";
        let s = rich_styled(raw);
        assert_eq!(text(&s), "Hi\nab c");
        let m = &s.raw_to_plain;
        assert_eq!(m.len(), raw.chars().count() + 1);
        assert!(m.windows(2).all(|w| w[0] <= w[1]), "monotonic: {m:?}");
        assert_eq!(*m.last().unwrap(), s.plain.len());
        // raw 'H' (3) is displayed 0; raw 'a' (8) and 'b' (9) are 3, 4.
        assert_eq!(m[3], 0);
        assert_eq!(s.plain[m[8]], 'a');
        assert_eq!(s.plain[m[9]], 'b');
    }

    #[test]
    fn plain_text_is_unchanged() {
        let t = "just words, with punctuation: (parens) and 1. 2. 3.\nsecond line";
        let s = rich_styled(t);
        assert_eq!(text(&s), t);
        assert!(s.sty.iter().all(|st| *st == Sty::default()));
    }

    /// A reply streams in, so the parser sees every prefix of it: none
    /// may panic, and the mapping stays total.
    #[test]
    fn every_prefix_of_a_reply_parses() {
        let reply = "## T\n**b** *i* `c` [l](u)\n> q\n- x\n```\nf\n```\nend";
        let chars: Vec<char> = reply.chars().collect();
        for n in 0..=chars.len() {
            let prefix: String = chars[..n].iter().collect();
            let s = rich_styled(&prefix);
            assert_eq!(s.plain.len(), s.sty.len());
            assert_eq!(s.raw_to_plain.len(), n + 1);
            assert!(s.raw_to_plain.iter().all(|i| *i <= s.plain.len()));
        }
    }
}
