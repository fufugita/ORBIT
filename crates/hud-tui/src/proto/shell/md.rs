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

/// Parse a reply. `text` is the raw model text, newlines included.
pub fn rich_styled(text: &str) -> Styled {
    let raw_len = text.chars().count();
    let nlines = text.split('\n').count();
    let mut out = Styled {
        raw_to_plain: vec![0; raw_len + 1],
        ..Default::default()
    };
    let mut fence = false;
    let mut ri = 0usize; // raw index of the start of the current line
    for (li, line_str) in text.split('\n').enumerate() {
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
            for r in 0..line.len() {
                drop_raw!(r);
            }
        } else if fence {
            let code = Sty {
                code: true,
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
            // A fence line leaves no row of its own.
            if !is_fence {
                out.plain.push('\n');
                out.sty.push(Sty::default());
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
