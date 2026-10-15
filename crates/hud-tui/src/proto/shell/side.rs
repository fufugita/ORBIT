//! The sidebar (`b`): SESSIONS, AGENTS, SHELLS and PLAN, drawn from
//! what the engine has sent. A section with no data says so instead of
//! inventing rows.

use super::canvas::{Cv, Rgb, Seg, clip_text, text_width, tint};
use super::convo::kind_of;
use super::frame::{pill, pill_width, star_frame};
use super::motion::{flash, secs};
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

        // SESSIONS — the open session.
        section(cv, x, yy, w, "SESSIONS", colors.magenta, Some("1".into()));
        yy += 2;
        let bg = tint(colors.magenta, colors.sidebar, 0.1);
        cv.fill(x, yy, w, 1, bg);
        cv.text(x, yy, "▌", colors.magenta, Some(bg));
        let (g, gc, right, rc) = if approval {
            ("◆".to_string(), colors.magenta, "needs you", colors.magenta)
        } else if s.turn_live {
            (
                star_frame(now_ms, reduced).to_string(),
                colors.cyan,
                "now",
                colors.muted,
            )
        } else if s.turn_report.is_some() {
            ("✓".to_string(), colors.green, "now", colors.muted)
        } else {
            ("○".to_string(), colors.muted, "now", colors.muted)
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
        yy += 2;

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
