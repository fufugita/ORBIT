//! The sidebar (`b`): SESSIONS, AGENTS, SHELLS and PLAN, drawn from
//! what the engine has sent. A section with no data says so instead of
//! inventing rows.

use super::canvas::{Cv, Rgb, Seg, clip_text, text_width, tint};
use super::convo::kind_of;
use super::frame::{pill, pill_width, star_frame};
use super::hits::Click;
use super::motion::{flash, secs};
use super::sessions_list::{self, OPEN_TAG};
use crate::proto::scenario::{LineKind, Scenario, ToolState};
use ratatui::layout::Rect;
use ratatui::style::Modifier;

/// The sidebar's width in columns.
pub const WIDTH: u16 = 30;

fn section(cv: &mut Cv, x: i32, y: i32, w: i32, label: &str, col: Rgb, count: Option<String>) {
    let colors = cv.palette;
    cv.bold(x + 1, y, "▍", col, Some(colors.sidebar));
    cv.bold(x + 3, y, label, colors.ink2, Some(colors.sidebar));
    if let Some(n) = count {
        let parts = vec![Seg::bold(n.clone(), col)];
        pill(
            cv,
            x + w - 3 - text_width(&n),
            y,
            &parts,
            col,
            colors.sidebar,
            0.18,
        );
    }
}

pub fn draw(cv: &mut Cv, r: Rect, s: &Scenario, now_ms: u64, reduced: bool, mono: bool) {
    let colors = cv.palette;
    let (x, y, w, h) = (r.x as i32, r.y as i32, r.width as i32, r.height as i32);
    cv.fill(x, y, w, h, colors.sidebar);
    cv.clipped(r, |cv| {
        let mut yy = y + 1;
        let approval = s.approval_pending.is_some();

        // SESSIONS — the open session, then the other saved ones.
        section(
            cv,
            x,
            yy,
            w,
            "SESSIONS",
            colors.magenta,
            Some(s.saved_sessions.count_with_open(&s.session_id).to_string()),
        );
        yy += 2;
        let bg = tint(colors.magenta, colors.sidebar, 0.1);
        cv.fill(x, yy, w, 1, bg);
        // The open session's row answers a click as the others do: it says
        // which session this is, instead of leaving the click unanswered.
        if let Some(i) = s.saved_sessions.current_index(&s.session_id) {
            cv.hit(x, yy, w, 1, Click::Session(i));
        }
        cv.text(x, yy, "▌", colors.magenta, Some(bg));
        // The glyph is what the session is doing; the word on the right is
        // always there, so the open one can be told from the rest at a glance.
        // (Their ages would say "now" too, for anything saved a moment ago.)
        let (g, gc, right, rc) = if approval {
            ("◆".to_string(), colors.magenta, "needs you", colors.magenta)
        } else if s.turn_live {
            (
                star_frame(now_ms, reduced).to_string(),
                colors.cyan,
                OPEN_TAG,
                colors.magenta,
            )
        } else if s.turn_report.is_some() {
            ("✓".to_string(), colors.green, OPEN_TAG, colors.magenta)
        } else {
            ("●".to_string(), colors.magenta, OPEN_TAG, colors.magenta)
        };
        cv.bold(x + 2, yy, &g, gc, Some(bg));
        let title = s.session_label();
        cv.put(
            x + 4,
            yy,
            &clip_text(&title, w - 6 - text_width(right)),
            colors.ink,
            Some(bg),
            Modifier::BOLD,
        );
        cv.put(
            x + w - 1 - text_width(right),
            yy,
            right,
            rc,
            Some(bg),
            if rc == colors.magenta {
                Modifier::BOLD
            } else {
                Modifier::empty()
            },
        );
        yy += 1;
        // The other saved sessions of this folder: a click resumes one.
        yy += sessions_list::draw_sidebar_rows(
            cv,
            (x, yy, w),
            &s.saved_sessions,
            &s.session_id,
            sessions_list::sidebar_room(h),
        );
        yy += 1;

        // AGENTS — ORBIT itself, then any subagents.
        let n_agents = 1 + s.agents.len();
        section(
            cv,
            x,
            yy,
            w,
            "AGENTS",
            colors.blue,
            Some(n_agents.to_string()),
        );
        yy += 2;
        let (o_lab, o_col, o_sub): (Vec<Seg>, Rgb, String) = if approval {
            (
                vec![
                    Seg::bold("◆ ", colors.magenta),
                    Seg::bold("needs you", colors.magenta),
                ],
                colors.magenta,
                format!(
                    "approval needed · {}",
                    s.approval_pending.clone().unwrap_or_default()
                ),
            )
        } else if s.turn_live {
            (
                vec![
                    Seg::bold(format!("{} ", star_frame(now_ms, reduced)), colors.cyan),
                    Seg::new("working", colors.cyan),
                ],
                colors.cyan,
                "working".to_string(),
            )
        } else {
            (
                vec![Seg::new("○ ", colors.faint), Seg::new("idle", colors.faint)],
                colors.faint,
                "idle".to_string(),
            )
        };
        cv.bold(x + 2, yy, "●", colors.magenta, Some(colors.sidebar));
        cv.put(
            x + 4,
            yy,
            "orbit",
            if s.turn_live { colors.ink } else { colors.ink2 },
            Some(colors.sidebar),
            Modifier::BOLD,
        );
        pill(
            cv,
            x + w - 1 - pill_width(&o_lab),
            yy,
            &o_lab,
            o_col,
            colors.sidebar,
            0.16,
        );
        cv.text(
            x + 4,
            yy + 1,
            &clip_text(&o_sub, w - 5),
            colors.muted,
            Some(colors.sidebar),
        );
        yy += 2;
        for a in s.agents.values() {
            // M15: arcs at 10 fps; M16: the pill flashes green for 600 ms
            // when the agent finishes.
            let arc = if reduced {
                "●"
            } else {
                ["◜", "◝", "◞", "◟"][((secs(now_ms) * 10.0) as usize) & 3]
            };
            let lab = if a.done {
                vec![
                    Seg::bold("✓ ", colors.green),
                    Seg::new("done", colors.green),
                ]
            } else {
                vec![
                    Seg::bold(format!("{arc} "), colors.cyan),
                    Seg::new("working", colors.cyan),
                ]
            };
            let done_flash = flash(secs(now_ms), a.done_ms.map(secs), 0.6, reduced || mono);
            let col = if a.done { colors.green } else { colors.cyan };
            cv.bold(x + 2, yy, "●", colors.cyan, Some(colors.sidebar));
            cv.put(
                x + 4,
                yy,
                &clip_text(&a.name, w - 6 - pill_width(&lab)),
                colors.ink,
                Some(colors.sidebar),
                Modifier::BOLD,
            );
            pill(
                cv,
                x + w - 1 - pill_width(&lab),
                yy,
                &lab,
                col,
                colors.sidebar,
                0.16 + done_flash * 0.45,
            );
            cv.text(
                x + 4,
                yy + 1,
                &clip_text(&a.action, w - 5),
                colors.muted,
                Some(colors.sidebar),
            );
            yy += 2;
        }
        yy += 1;

        // SHELLS — the commands ORBIT ran.
        let shells: Vec<_> = s
            .transcript
            .iter()
            .filter(|l| l.kind == LineKind::Tool && kind_of(&l.tool_name) == "BASH")
            .collect();
        section(
            cv,
            x,
            yy,
            w,
            "SHELLS",
            colors.amber,
            (!shells.is_empty()).then(|| shells.len().to_string()),
        );
        yy += 2;
        if shells.is_empty() {
            cv.bold(x + 2, yy, "○", colors.faint, Some(colors.sidebar));
            cv.text(x + 4, yy, "none yet", colors.muted, Some(colors.sidebar));
            yy += 1;
        }
        for l in shells.iter().rev().take(3).rev() {
            let (g, gc, right, rc) = match l.tool_state {
                ToolState::Running => (
                    star_frame(now_ms, reduced),
                    colors.cyan,
                    String::new(),
                    colors.muted,
                ),
                ToolState::Done => (
                    "✓",
                    colors.green,
                    l.meta.trim_start_matches("done · ").to_string(),
                    colors.green,
                ),
                ToolState::Failed => ("✕", colors.red, "failed".to_string(), colors.red),
                ToolState::Unavailable => (
                    "?",
                    colors.muted,
                    "result unavailable".to_string(),
                    colors.muted,
                ),
                _ => ("○", colors.faint, String::new(), colors.faint),
            };
            cv.bold(x + 2, yy, g, gc, Some(colors.sidebar));
            cv.text(
                x + 4,
                yy,
                &clip_text(&l.text, w - 6 - text_width(&right)),
                colors.ink2,
                Some(colors.sidebar),
            );
            if !right.is_empty() {
                cv.text(
                    x + w - 1 - text_width(&right),
                    yy,
                    &right,
                    rc,
                    Some(colors.sidebar),
                );
            }
            yy += 1;
        }
        yy += 1;

        // PLAN.
        cv.bold(x + 1, yy, "▍", colors.cyan, Some(colors.sidebar));
        cv.bold(x + 3, yy, "PLAN", colors.ink2, Some(colors.sidebar));
        let done = s.tasks.iter().filter(|t| t.status == "done").count();
        let n = s.tasks.len();
        if n > 0 {
            let k = ((done as f32 / n as f32) * 6.0).round() as usize;
            let label = format!("{done}/{n}");
            let mut bx = x + w - 1 - 6 - 1 - text_width(&label);
            for i in 0..6 {
                bx = cv.text(
                    bx,
                    yy,
                    if i < k { "▰" } else { "▱" },
                    if i < k { colors.cyan } else { colors.rule_hi },
                    Some(colors.sidebar),
                );
            }
            cv.text(bx + 1, yy, &label, colors.ink2, Some(colors.sidebar));
        }
        yy += 2;
        if s.tasks.is_empty() {
            cv.text(x + 2, yy, "◌", colors.faint, Some(colors.sidebar));
            cv.text(x + 4, yy, "no plan yet", colors.muted, Some(colors.sidebar));
        }
        for t in &s.tasks {
            if yy >= y + h {
                break;
            }
            let active = t.status == "active" || t.status == "running";
            let bg = if active {
                tint(colors.cyan, colors.sidebar, 0.1)
            } else {
                colors.sidebar
            };
            if active {
                cv.fill(x, yy, w, 1, bg);
            }
            if t.status == "done" {
                cv.bold(x + 2, yy, "✓", colors.green, Some(bg));
                cv.text(
                    x + 4,
                    yy,
                    &clip_text(&t.title, w - 5),
                    colors.ink2,
                    Some(bg),
                );
            } else if active {
                cv.bold(x + 2, yy, "◉", colors.cyan, Some(bg));
                cv.put(
                    x + 4,
                    yy,
                    &clip_text(&t.title, w - 5),
                    colors.ink,
                    Some(bg),
                    Modifier::BOLD,
                );
            } else {
                cv.text(x + 2, yy, "◌", colors.faint, Some(bg));
                cv.text(
                    x + 4,
                    yy,
                    &clip_text(&t.title, w - 5),
                    colors.muted,
                    Some(bg),
                );
            }
            yy += 1;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::scenario::TranscriptLine;
    use ratatui::buffer::Buffer;

    /// The sidebar's rows as text, one string a row.
    fn rows(s: &Scenario) -> Vec<String> {
        let (w, h) = (WIDTH, 30);
        let mut buf = Buffer::empty(Rect::new(0, 0, w, h));
        let mut cv = Cv::new(&mut buf);
        draw(&mut cv, Rect::new(0, 0, w, h), s, 0, false, false);
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect())
            .collect()
    }

    /// The open session's own row: the first under the SESSIONS heading.
    fn open_row(s: &Scenario) -> String {
        rows(s)[3].clone()
    }

    fn prompted(text: &str) -> Scenario {
        let mut s = Scenario {
            session_id: "session-open".into(),
            ..Default::default()
        };
        s.transcript.push(TranscriptLine {
            kind: LineKind::User,
            text: text.into(),
            ..Default::default()
        });
        s
    }

    /// The open row had a hollow dot and "now", the same as any session
    /// saved a moment ago. It is filled and says "open" instead.
    #[test]
    fn the_open_session_has_a_filled_dot_and_says_open() {
        let row = open_row(&prompted("Fix the login redirect"));
        assert!(row.starts_with('▌'), "{row:?}");
        assert!(row.contains('●') && !row.contains('○'), "{row:?}");
        assert!(row.contains("Fix the login red"), "{row:?}");
        assert!(row.trim_end().ends_with(OPEN_TAG), "{row:?}");
        assert!(!row.contains("now"), "{row:?}");
        let new = open_row(&Scenario::default());
        assert!(
            new.contains("New session") && new.trim_end().ends_with(OPEN_TAG),
            "{new:?}"
        );
    }

    /// The word stays while the session works, so the open one can still be
    /// found; only the dot gives way to what it is doing.
    #[test]
    fn the_word_stays_while_the_session_works() {
        let mut s = prompted("Fix the login redirect");
        s.turn_live = true;
        let row = open_row(&s);
        assert!(!row.contains('●') && !row.contains('○'), "{row:?}");
        assert!(row.trim_end().ends_with(OPEN_TAG), "{row:?}");
    }

    /// A question to the operator outranks the label: it is what the row
    /// has to say, and the row is still the open one by its bar.
    #[test]
    fn a_waiting_approval_replaces_the_word() {
        let mut s = prompted("Fix the login redirect");
        s.approval_pending = Some("Bash(ls)".into());
        let row = open_row(&s);
        assert!(row.starts_with('▌') && row.contains("needs you"), "{row:?}");
        assert!(!row.contains(OPEN_TAG), "{row:?}");
    }

    /// The open row is a click target like the rest, so that a click on it is
    /// answered; with the session not in the list yet there is nothing to ask.
    #[test]
    fn the_open_row_is_a_click_target_once_the_list_has_it() {
        let saved = |id: &str| crate::msg::SavedSession {
            id: id.into(),
            title: id.into(),
            model: "m".into(),
            turns: 1,
            age: "1m ago".into(),
            current: false,
        };
        let draw_hits = |s: &Scenario| {
            let mut buf = Buffer::empty(Rect::new(0, 0, WIDTH, 30));
            let mut cv = Cv::new(&mut buf);
            draw(&mut cv, Rect::new(0, 0, WIDTH, 30), s, 0, false, false);
            cv.take_hits()
        };
        let mut s = prompted("Fix the login redirect");
        assert!(
            !draw_hits(&s)
                .iter()
                .any(|hit| matches!(hit.click, Click::Session(_))),
            "an unlisted session has no row to answer for"
        );
        s.saved_sessions
            .receive(vec![saved("session-other"), saved("session-open")]);
        let open = s.saved_sessions.current_index("session-open").unwrap();
        let hits = draw_hits(&s);
        let on_open_row = hits
            .iter()
            .find(|hit| hit.click == Click::Session(open))
            .expect("the open row is a target");
        assert_eq!(
            (
                on_open_row.rect.y,
                on_open_row.rect.width,
                on_open_row.rect.height
            ),
            (3, WIDTH, 1),
            "the whole row, on the line the open session is drawn"
        );
    }

    /// A rename shows at once, in place of the first prompt, and a name that
    /// belongs to another session shows nowhere.
    #[test]
    fn the_open_row_wears_the_sessions_name() {
        let mut s = prompted("Fix the login redirect");
        s.session_name = Some(("session-open".into(), "login work".into()));
        assert!(open_row(&s).contains("login work"), "{:?}", open_row(&s));
        s.session_name = Some(("session-else".into(), "not mine".into()));
        let row = open_row(&s);
        assert!(
            !row.contains("not mine") && row.contains("Fix the login"),
            "{row:?}"
        );
    }
}
