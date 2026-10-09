//! Bounded unified diffs (M11): the Changes panel shows what a write
//! actually did, computed from the checkpoint's "before" bytes and the
//! file's "after" bytes.
//!
//! A plain line-based LCS diff — the inputs are one file's old vs new
//! text, sizes a code editor produces, so the O(n·m) table is fine and
//! the result is the standard minimal diff. Hunks are bounded (context
//! 2, at most `MAX_HUNKS` hunks, at most `MAX_LINES` lines each): a
//! panel line budget, not a fidelity claim — `added`/`removed` in the
//! event stay the true totals.

pub const CONTEXT: usize = 2;
pub const MAX_HUNKS: usize = 4;
pub const MAX_LINES: usize = 6;

use orbit_frontend_protocol::DiffHunk;

/// One op in the edit script.
#[derive(Debug, Clone, PartialEq)]
enum Op {
    Same(String),
    Del(String),
    Ins(String),
}

/// Diff two files by line. `\n`-separated; a missing trailing newline
/// is preserved on the line that has it.
fn ops(old: &str, new: &str) -> Vec<Op> {
    let a: Vec<&str> = split_lines(old);
    let b: Vec<&str> = split_lines(new);
    let n = a.len();
    let m = b.len();
    // LCS table.
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    // Walk the table.
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push(Op::Same(a[i].to_string()));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push(Op::Del(a[i].to_string()));
            i += 1;
        } else {
            out.push(Op::Ins(b[j].to_string()));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|l| Op::Del(l.to_string())));
    out.extend(b[j..].iter().map(|l| Op::Ins(l.to_string())));
    out
}

fn split_lines(s: &str) -> Vec<&str> {
    let mut v: Vec<&str> = s.split('\n').collect();
    // A trailing newline produces an empty last element — drop it; a
    // file not ending in newline keeps its last partial line.
    if s.ends_with('\n') {
        v.pop();
    }
    v
}

/// True totals of the diff: inserted lines, deleted lines. Unbounded —
/// the event's `added`/`removed` stay honest even when the hunks are
/// cut to a panel's line budget.
pub fn counts(old: &str, new: &str) -> (u32, u32) {
    let script = ops(old, new);
    let ins = script
        .iter()
        .filter(|op| matches!(op, Op::Ins(_)))
        .count() as u32;
    let del = script
        .iter()
        .filter(|op| matches!(op, Op::Del(_)))
        .count() as u32;
    (ins, del)
}

/// Unified hunks with the bounds above. Returns `None` when there is
/// nothing to show (identical files, or every change cut by the
/// bounds — the panel then reports counts alone).
pub fn hunks(old: &str, new: &str) -> Option<Vec<DiffHunk>> {
    let script = ops(old, new);
    if script.iter().all(|op| matches!(op, Op::Same(_))) {
        return None;
    }

    // Indexes of changed runs, separated by runs of ≥ 2*CONTEXT same
    // lines (the standard hunk-splitting rule).
    let is_chg = |op: &Op| !matches!(op, Op::Same(_));
    let mut groups: Vec<(usize, usize)> = Vec::new(); // [start, end) in script
    let mut i = 0;
    while i < script.len() {
        if !is_chg(&script[i]) {
            i += 1;
            continue;
        }
        let start = i.saturating_sub(CONTEXT);
        let mut end = i;
        while end < script.len() {
            if is_chg(&script[end]) {
                end += 1;
                continue;
            }
            // A same-run shorter than 2*CONTEXT+1 joins the hunks.
            let run = script[end..]
                .iter()
                .take_while(|op| !is_chg(op))
                .count();
            if run <= 2 * CONTEXT {
                end += run;
            } else {
                break;
            }
        }
        let end = (end + CONTEXT).min(script.len());
        groups.push((start, end));
        i = end;
    }
    if groups.is_empty() {
        return None;
    }

    // Line numbers: walk once, remembering each script index's old/new line.
    let mut old_no = vec![0u32; script.len()];
    let mut new_no = vec![0u32; script.len()];
    let (mut o, mut nw) = (1u32, 1u32);
    for (idx, op) in script.iter().enumerate() {
        old_no[idx] = o;
        new_no[idx] = nw;
        match op {
            Op::Same(_) => {
                o += 1;
                nw += 1;
            }
            Op::Del(_) => o += 1,
            Op::Ins(_) => nw += 1,
        }
    }
    let total_old = o; // one past the last
    let total_new = nw;

    let mut out = Vec::new();
    for &(s, e) in groups.iter().take(MAX_HUNKS) {
        let mut lines = Vec::new();
        let (mut os, mut ns) = (0u32, 0u32);
        for op in &script[s..e] {
            match op {
                Op::Same(l) => {
                    if os == 0 {
                        os = old_no[s];
                        ns = new_no[s];
                    }
                    lines.push((' ', l.to_string()));
                }
                Op::Del(l) => {
                    if os == 0 {
                        os = old_no[s];
                        ns = new_no[s];
                    }
                    lines.push(('-', l.to_string()));
                }
                Op::Ins(l) => {
                    if os == 0 {
                        os = old_no[s];
                        ns = new_no[s];
                    }
                    lines.push(('+', l.to_string()));
                }
            }
        }
        // Bound the lines inside the hunk: keep the head, mark the cut.
        if lines.len() > MAX_LINES {
            let head: Vec<(char, String)> = lines[..MAX_LINES - 1].to_vec();
            let mut bounded = head;
            bounded.push(('…', format!("{} more lines", lines.len() - MAX_LINES + 1)));
            lines = bounded;
        }
        let old_count = lines.iter().filter(|(m, _)| *m != '+').count() as u32;
        let new_count = lines.iter().filter(|(m, _)| *m != '-').count() as u32;
        out.push(DiffHunk {
            old_start: os.max(1),
            old_lines: old_count,
            new_start: ns.max(1),
            new_lines: new_count,
            lines,
        });
    }
    let _ = (total_old, total_new);
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_is_none() {
        assert!(hunks("a\nb\n", "a\nb\n").is_none());
    }

    #[test]
    fn a_line_changed() {
        let h = hunks("one\ntwo\nthree\n", "one\nTWO\nthree\n").unwrap();
        assert_eq!(h.len(), 1);
        // Context 2 reaches the file head: the hunk starts at old line 1.
        assert_eq!(h[0].old_start, 1);
        assert_eq!(h[0].lines.len(), 4); // one, -two, +TWO, three
        let marks: Vec<char> = h[0].lines.iter().map(|(m, _)| *m).collect();
        assert_eq!(marks, vec![' ', '-', '+', ' ']);
    }

    #[test]
    fn counts_carry_in_hunk_header() {
        let h = hunks("a\nb\nc\n", "a\nx\ny\nc\n").unwrap();
        assert_eq!(h[0].old_lines, 3);
        assert_eq!(h[0].new_lines, 4);
    }

    #[test]
    fn far_apart_changes_make_two_hunks() {
        let old: String = (0..30).map(|i| format!("l{i}\n")).collect();
        let new: String = (0..30)
            .map(|i| if i == 1 || i == 28 { format!("X{i}\n") } else { format!("l{i}\n") })
            .collect();
        let h = hunks(&old, &new).unwrap();
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn hunks_are_bounded() {
        let old: String = (0..40).map(|i| format!("l{i}\n")).collect();
        let new: String = (0..40).map(|i| format!("n{i}\n")).collect();
        let h = hunks(&old, &new).unwrap();
        // One huge run → one hunk, MAX_HUNKS bound respected and the
        // line list is cut with a … marker.
        assert_eq!(h.len(), 1);
        assert!(h[0].lines.len() <= MAX_LINES);
        assert_eq!(h[0].lines.last().unwrap().0, '…');
    }

    #[test]
    fn max_hunks_respected() {
        let old: String = (0..60).map(|i| format!("l{i}\n")).collect();
        let new: String = (0..60)
            .map(|i| if i % 10 == 0 { format!("X{i}\n") } else { format!("l{i}\n") })
            .collect();
        let h = hunks(&old, &new).unwrap();
        assert_eq!(h.len(), MAX_HUNKS);
    }

    #[test]
    fn file_ended_without_newline() {
        let h = hunks("a\nb", "a\nb\nc").unwrap();
        assert_eq!(h.len(), 1);
        // Context 2 pulls both old lines in: a, b, then the insert.
        let marks: Vec<char> = h[0].lines.iter().map(|(m, _)| *m).collect();
        assert_eq!(marks, vec![' ', ' ', '+']);
    }
}
