//! The sidebar (`b`): SESSIONS, AGENTS, SHELLS and PLAN, drawn from
//! what the engine has sent. A section with no data says so instead of
//! inventing rows.

use super::canvas::{clip_text, text_width, tint, Cv, Rgb, Seg};
use super::convo::kind_of;
use super::frame::{pill, pill_width, star_frame};
use super::motion::{flash, secs};
use super::pal::*;
use crate::proto::scenario::{LineKind, Scenario, ToolState};
use ratatui::layout::Rect;
use ratatui::style::Modifier;

/// The sidebar's width in columns.
pub const WIDTH: u16 = 30;

fn section(cv: &mut Cv, x: i32, y: i32, w: i32, label: &str, col: Rgb, count: Option<String>) {
    cv.bold(x + 1, y, "▍", col, Some(SIDEBAR));
    cv.bold(x + 3, y, label, INK2, Some(SIDEBAR));
    if let Some(n) = count {
        let parts = vec![Seg::bold(n.clone(), col)];
        pill(
            cv,
            x + w - 3 - text_width(&n),
            y,
            &parts,
            col,
            SIDEBAR,
            0.18,
        );
    }
}

pub fn draw(cv: &mut Cv, r: Rect, s: &Scenario, now_ms: u64, reduced: bool, mono: bool) {
    let (x, y, w, h) = (r.x as i32, r.y as i32, r.width as i32, r.height as i32);
    cv.fill(x, y, w, h, SIDEBAR);
    cv.clipped(r, |cv| {
        let mut yy = y + 1;
        let approval = s.approval_pending.is_some();

        // SESSIONS — the open session.
        section(cv, x, yy, w, "SESSIONS", MAGENTA, Some("1".into()));
        yy += 2;
        let bg = tint(MAGENTA, SIDEBAR, 0.1);
        cv.fill(x, yy, w, 1, bg);
        cv.text(x, yy, "▌", MAGENTA, Some(bg));
        let (g, gc, right, rc) = if approval {
            ("◆".to_string(), MAGENTA, "needs you", MAGENTA)
        } else if s.turn_live {
            (star_frame(now_ms, reduced).to_string(), CYAN, "now", MUTED)
        } else if s.turn_report.is_some() {
            ("✓".to_string(), GREEN, "now", MUTED)
        } else {
            ("○".to_string(), MUTED, "now", MUTED)
        };
        cv.bold(x + 2, yy, &g, gc, Some(bg));
        let title = if s.transcript.is_empty() {
            "New session".to_string()
        } else {
            s.session_title()
        };
        cv.put(
            x + 4,
            yy,
            &clip_text(&title, w - 6 - text_width(right)),
            INK,
            Some(bg),
            Modifier::BOLD,
        );
        cv.put(
            x + w - 1 - text_width(right),
            yy,
            right,
            rc,
            Some(bg),
            if rc == MAGENTA {
                Modifier::BOLD
            } else {
                Modifier::empty()
            },
        );
        yy += 2;

        // AGENTS — ORBIT itself, then any subagents.
        let n_agents = 1 + s.agents.len();
        section(cv, x, yy, w, "AGENTS", BLUE, Some(n_agents.to_string()));
        yy += 2;
        let (o_lab, o_col, o_sub): (Vec<Seg>, Rgb, String) = if approval {
            (
                vec![Seg::bold("◆ ", MAGENTA), Seg::bold("needs you", MAGENTA)],
                MAGENTA,
                format!(
                    "approval needed · {}",
                    s.approval_pending.clone().unwrap_or_default()
                ),
            )
        } else if s.turn_live {
            (
                vec![
                    Seg::bold(format!("{} ", star_frame(now_ms, reduced)), CYAN),
                    Seg::new("working", CYAN),
                ],
                CYAN,
                "working".to_string(),
            )
        } else {
            (
                vec![Seg::new("○ ", FAINT), Seg::new("idle", FAINT)],
                FAINT,
                "idle".to_string(),
            )
        };
        cv.bold(x + 2, yy, "●", MAGENTA, Some(SIDEBAR));
        cv.put(
            x + 4,
            yy,
            "orbit",
            if s.turn_live { INK } else { INK2 },
            Some(SIDEBAR),
            Modifier::BOLD,
        );
        pill(
            cv,
            x + w - 1 - pill_width(&o_lab),
            yy,
            &o_lab,
            o_col,
            SIDEBAR,
            0.16,
        );
        cv.text(
            x + 4,
            yy + 1,
            &clip_text(&o_sub, w - 5),
            MUTED,
            Some(SIDEBAR),
        );
        yy += 2;
        for (_, a) in s.agents.iter() {
            // M15: arcs at 10 fps; M16: the pill flashes green for 600 ms
            // when the agent finishes.
            let arc = if reduced {
                "●"
            } else {
                ["◜", "◝", "◞", "◟"][((secs(now_ms) * 10.0) as usize) & 3]
            };
            let lab = if a.done {
                vec![Seg::bold("✓ ", GREEN), Seg::new("done", GREEN)]
            } else {
                vec![
                    Seg::bold(format!("{arc} "), CYAN),
                    Seg::new("working", CYAN),
                ]
            };
            let done_flash = flash(secs(now_ms), a.done_ms.map(secs), 0.6, reduced || mono);
            let col = if a.done { GREEN } else { CYAN };
            cv.bold(x + 2, yy, "●", CYAN, Some(SIDEBAR));
            cv.put(
                x + 4,
                yy,
                &clip_text(&a.name, w - 6 - pill_width(&lab)),
                INK,
                Some(SIDEBAR),
                Modifier::BOLD,
            );
            pill(
                cv,
                x + w - 1 - pill_width(&lab),
                yy,
                &lab,
                col,
                SIDEBAR,
                0.16 + done_flash * 0.45,
            );
            cv.text(
                x + 4,
                yy + 1,
                &clip_text(&a.action, w - 5),
                MUTED,
                Some(SIDEBAR),
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
            AMBER,
            (!shells.is_empty()).then(|| shells.len().to_string()),
        );
        yy += 2;
        if shells.is_empty() {
            cv.bold(x + 2, yy, "○", FAINT, Some(SIDEBAR));
            cv.text(x + 4, yy, "none yet", MUTED, Some(SIDEBAR));
            yy += 1;
        }
        for l in shells.iter().rev().take(3).rev() {
            let (g, gc, right, rc) = match l.tool_state {
                ToolState::Running => (star_frame(now_ms, reduced), CYAN, String::new(), MUTED),
                ToolState::Done => (
                    "✓",
                    GREEN,
                    l.meta.trim_start_matches("done · ").to_string(),
                    GREEN,
                ),
                ToolState::Failed => ("✕", RED, "failed".to_string(), RED),
                _ => ("○", FAINT, String::new(), FAINT),
            };
            cv.bold(x + 2, yy, g, gc, Some(SIDEBAR));
            cv.text(
                x + 4,
                yy,
                &clip_text(&l.text, w - 6 - text_width(&right)),
                INK2,
                Some(SIDEBAR),
            );
            if !right.is_empty() {
                cv.text(
                    x + w - 1 - text_width(&right),
                    yy,
                    &right,
                    rc,
                    Some(SIDEBAR),
                );
            }
            yy += 1;
        }
        yy += 1;

        // PLAN.
        cv.bold(x + 1, yy, "▍", CYAN, Some(SIDEBAR));
        cv.bold(x + 3, yy, "PLAN", INK2, Some(SIDEBAR));
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
                    if i < k { CYAN } else { RULE_HI },
                    Some(SIDEBAR),
                );
            }
            cv.text(bx + 1, yy, &label, INK2, Some(SIDEBAR));
        }
        yy += 2;
        if s.tasks.is_empty() {
            cv.text(x + 2, yy, "◌", FAINT, Some(SIDEBAR));
            cv.text(x + 4, yy, "no plan yet", MUTED, Some(SIDEBAR));
        }
        for t in &s.tasks {
            if yy >= y + h {
                break;
            }
            let active = t.status == "active" || t.status == "running";
            let bg = if active {
                tint(CYAN, SIDEBAR, 0.1)
            } else {
                SIDEBAR
            };
            if active {
                cv.fill(x, yy, w, 1, bg);
            }
            if t.status == "done" {
                cv.bold(x + 2, yy, "✓", GREEN, Some(bg));
                cv.text(x + 4, yy, &clip_text(&t.title, w - 5), INK2, Some(bg));
            } else if active {
                cv.bold(x + 2, yy, "◉", CYAN, Some(bg));
                cv.put(
                    x + 4,
                    yy,
                    &clip_text(&t.title, w - 5),
                    INK,
                    Some(bg),
                    Modifier::BOLD,
                );
            } else {
                cv.text(x + 2, yy, "◌", FAINT, Some(bg));
                cv.text(x + 4, yy, &clip_text(&t.title, w - 5), MUTED, Some(bg));
            }
            yy += 1;
        }
    });
}
