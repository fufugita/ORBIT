//! The rows of a diff, shared by the full-diff overlay and the Review
//! panel: `@@` headers in violet, `+` and `-` lines in green and red on a
//! faint bar, context in muted ink. Built only from the bounded hunks a
//! `FileChanged` event carried — nothing here invents a line.

use super::canvas::{clip_text, tint, Cv, Rgb};
use super::pal::*;
use orbit_frontend_protocol::DiffHunk;

/// One displayable row: its marker (`@` hunk header, `+`, `-`, ` `
/// context, `…` elided lines) and its text.
pub type Row = (char, String);

/// Flatten hunks into rows. Also returns the row index of each hunk's
/// header, so a caller can scroll to hunk N.
pub fn rows(hunks: &[DiffHunk]) -> (Vec<Row>, Vec<usize>) {
    let mut out: Vec<Row> = Vec::new();
    let mut starts = Vec::with_capacity(hunks.len());
    for hk in hunks {
        starts.push(out.len());
        out.push((
            '@',
            format!(
                "@@ -{},{} +{},{} @@",
                hk.old_start, hk.old_lines, hk.new_start, hk.new_lines
            ),
        ));
        for (marker, text) in &hk.lines {
            out.push((*marker, text.clone()));
        }
    }
    (out, starts)
}

/// Draw `rows` from `(x, y)`, one per line, in `w` columns over `base`.
/// A `+`/`-` line keeps its glyph as well as its tinted bar: colour is
/// never the only signal (it must still read under NO_COLOR).
pub fn draw(cv: &mut Cv, x: i32, y: i32, w: i32, rows: &[Row], base: Rgb) {
    for (i, (marker, text)) in rows.iter().enumerate() {
        let yy = y + i as i32;
        match marker {
            '@' => {
                cv.bold(x, yy, &clip_text(text, w), VIOLET, Some(base));
            }
            '+' | '-' => {
                let (glyph, fg) = if *marker == '+' {
                    ("+ ", GREEN)
                } else {
                    ("- ", RED)
                };
                let bg = tint(fg, base, 0.10);
                cv.fill(x, yy, w, 1, bg);
                cv.text(
                    x,
                    yy,
                    &format!("{glyph}{}", clip_text(text, w - 2)),
                    fg,
                    Some(bg),
                );
            }
            '…' => {
                cv.text(
                    x,
                    yy,
                    &format!("  {}", clip_text(text, w - 2)),
                    FAINT,
                    Some(base),
                );
            }
            _ => {
                cv.text(
                    x,
                    yy,
                    &format!("  {}", clip_text(text, w - 2)),
                    INK2,
                    Some(base),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hunk(old_start: u32, lines: &[(char, &str)]) -> DiffHunk {
        DiffHunk {
            old_start,
            old_lines: lines.iter().filter(|(m, _)| *m != '+').count() as u32,
            new_start: old_start,
            new_lines: lines.iter().filter(|(m, _)| *m != '-').count() as u32,
            lines: lines.iter().map(|(m, t)| (*m, t.to_string())).collect(),
        }
    }

    /// Rows come out header-first per hunk, and `starts` points at each
    /// header so "hunk 2" can be scrolled to.
    #[test]
    fn rows_flatten_hunks_and_remember_where_each_starts() {
        let hunks = [
            hunk(
                3,
                &[
                    (' ', "def add(a, b):"),
                    ('-', "    return a - b"),
                    ('+', "    return a + b"),
                ],
            ),
            hunk(20, &[('-', "x"), ('+', "y")]),
        ];
        let (rows, starts) = rows(&hunks);
        assert_eq!(starts, vec![0, 4]);
        assert_eq!(rows[0], ('@', "@@ -3,2 +3,2 @@".to_string()));
        assert_eq!(rows[2], ('-', "    return a - b".to_string()));
        assert_eq!(rows[4], ('@', "@@ -20,1 +20,1 @@".to_string()));
        assert_eq!(rows.len(), 7);
    }

    #[test]
    fn no_hunks_is_no_rows() {
        let (rows, starts) = rows(&[]);
        assert!(rows.is_empty() && starts.is_empty());
    }
}
