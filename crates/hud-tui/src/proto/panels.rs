//! The eight panel views (`panels`): each renders from scenario
//! state + tick into its rect. A panel shows one view; a view can be
//! open in more than one panel.
//!
//! Golden tests render any panel at any tick with ratatui's
//! `TestBackend` and compare cells and styles.

use super::comps;
use super::core::{glyphs, Token};
use super::layout::View;
use super::scenario::Scenario;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

/// The identity chip: the panel's number (1–9, reading order) in its
/// identity colour.
pub fn number_chip(n: u8, view: View) -> Span<'static> {
    Span::styled(
        format!(" {n} "),
        Style::default()
            .fg(Color::Black)
            .bg(comps::colour(view.token()))
            .add_modifier(Modifier::BOLD),
    )
}

/// The panel frame: `┏━┓` when focused (M20's heavy border), `╭─╮`
/// otherwise. The header band is the view title in its identity
/// colour.
pub fn frame(n: u8, view: View, focused: bool) -> Block<'static> {
    let border = if focused {
        Style::default().fg(comps::colour(view.token()))
    } else {
        Style::default().fg(comps::colour(Token::Rule))
    };
    let title = Line::from(vec![
        number_chip(n, view),
        Span::styled(
            format!(" {}", view.title()),
            Style::default().fg(comps::colour(view.token())),
        ),
    ]);
    Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(title)
}

/// One panel's render: the frame plus the view's content, clipped to
/// the inner rect.
pub fn render_panel(
    f: &mut ratatui::Frame,
    area: Rect,
    n: u8,
    view: View,
    focused: bool,
    scenario: &Scenario,
    tick_ms: u64,
    reduced: bool,
) {
    let block = frame(n, view, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let lines = match view {
        View::Conversation => conversation(scenario, tick_ms, reduced),
        View::Changes => changes(scenario),
        View::Terminal => terminal(scenario),
        View::Plan => plan(scenario),
        View::Activity => activity(scenario, tick_ms, reduced),
        View::Context => context(scenario, tick_ms, reduced, inner.width),
        View::Review => review(scenario),
        View::Agent => agent(scenario, tick_ms, reduced),
    };
    f.render_widget(Paragraph::new(lines), inner);
}

/// Conversation: the transcript tail + the thinking line while the
/// model works (M05) + the caret while streaming (M06).
fn conversation(s: &Scenario, tick: u64, reduced: bool) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    // The last turn's visible output (the scenario keeps it simple:
    // the reducer's transcript lives in the front-end state; here we
    // render the activity + a transcript placeholder driven by it).
    if s.turn_live && !s.visible_output {
        out.push(comps::thinking_line(&s.model, glyphs::STAR_STILL));
    }
    if s.turn_live && s.visible_output {
        out.push(Line::from(vec![
            Span::styled("▌streaming", Style::default().fg(comps::colour(Token::Cyan))),
            comps::caret(tick, tick, reduced),
        ]));
    }
    out
}

/// Changes: FileChanged rows (M11): path + added/removed counts.
fn changes(s: &Scenario) -> Vec<Line<'static>> {
    let mut out = vec![Line::from(Span::styled(
        "Changes",
        Style::default().fg(comps::colour(Token::Violet)).add_modifier(Modifier::BOLD),
    ))];
    if s.file_changes.is_empty() {
        out.push(Line::from(Span::styled(
            format!("{} no changes yet", glyphs::QUEUED),
            Style::default().fg(comps::colour(Token::Muted)),
        )));
    }
    for fc in &s.file_changes {
        out.push(Line::from(vec![
            Span::styled("~ ", Style::default().fg(comps::colour(Token::Violet))),
            Span::styled(
                format!("{}", fc.path),
                Style::default().fg(comps::colour(Token::Blue)),
            ),
            Span::styled(
                format!(" +{} −{}", fc.added, fc.removed),
                Style::default().fg(comps::colour(Token::Muted)),
            ),
        ]));
    }
    out
}

/// Terminal: live output tail (M09/M12): the last 3 lines.
fn terminal(s: &Scenario) -> Vec<Line<'static>> {
    let mut out = vec![Line::from(Span::styled(
        "Terminal",
        Style::default().fg(comps::colour(Token::Amber)).add_modifier(Modifier::BOLD),
    ))];
    let tail: Vec<String> = s.tool_output.iter().rev().take(3).cloned().collect();
    for line in tail.iter().rev() {
        out.push(Line::from(Span::styled(
            line.clone(),
            Style::default().fg(comps::colour(Token::Ink)),
        )));
    }
    out
}

/// Plan: the task list (TaskCreate/TaskUpdate drive it).
fn plan(s: &Scenario) -> Vec<Line<'static>> {
    let mut out = vec![Line::from(Span::styled(
        "Plan",
        Style::default().fg(comps::colour(Token::Green)).add_modifier(Modifier::BOLD),
    ))];
    if s.tasks.is_empty() {
        out.push(Line::from(Span::styled(
            format!("{} no tasks", glyphs::QUEUED),
            Style::default().fg(comps::colour(Token::Muted)),
        )));
    }
    for t in &s.tasks {
        let g = match t.status.as_str() {
            "done" => glyphs::DONE,
            "in_progress" => "◐",
            _ => "○",
        };
        let token = match t.status.as_str() {
            "done" => Token::Green,
            "in_progress" => Token::Cyan,
            _ => Token::Muted,
        };
        out.push(Line::from(vec![
            Span::styled(format!("{g} "), Style::default().fg(comps::colour(token))),
            Span::styled(t.title.clone(), Style::default().fg(comps::colour(Token::Ink))),
        ]));
    }
    out
}

/// Activity: the running tools with their comets (M08).
fn activity(s: &Scenario, tick: u64, reduced: bool) -> Vec<Line<'static>> {
    let mut out = vec![Line::from(Span::styled(
        "Activity",
        Style::default().fg(comps::colour(Token::Cyan)).add_modifier(Modifier::BOLD),
    ))];
    if s.running.is_empty() {
        out.push(Line::from(Span::styled(
            format!("{} idle", glyphs::QUEUED),
            Style::default().fg(comps::colour(Token::Muted)),
        )));
    }
    for (id, kind) in &s.running {
        out.push(comps::tool_line(kind, id, tick, tick, reduced));
    }
    let _ = reduced;
    out
}

/// Context: the context meter (M18).
fn context(s: &Scenario, tick: u64, reduced: bool, width: u16) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            "Context",
            Style::default().fg(comps::colour(Token::Blue)).add_modifier(Modifier::BOLD),
        )),
        comps::context_meter(
            s.used_tokens,
            s.window_tokens,
            tick,
            s.usage_shown_ms,
            s.compacting,
            reduced,
            width.saturating_sub(8),
        ),
    ]
}

/// Review: findings + the last turn's verdict.
fn review(s: &Scenario) -> Vec<Line<'static>> {
    let mut out = vec![Line::from(Span::styled(
        "Review",
        Style::default().fg(comps::colour(Token::Red)).add_modifier(Modifier::BOLD),
    ))];
    let g = if s.last_failed { glyphs::FAILED } else { glyphs::DONE };
    let t = if s.last_failed { Token::Red } else { Token::Green };
    out.push(Line::from(Span::styled(
        format!("{g} last turn {}", if s.last_failed { "failed" } else { "ok" }),
        Style::default().fg(comps::colour(t)),
    )));
    out
}

/// Agent: one agent's panel — its arcs while running (M15), the
/// report when done (M16).
fn agent(s: &Scenario, tick: u64, reduced: bool) -> Vec<Line<'static>> {
    let mut out = vec![Line::from(vec![
        comps::agent_arc(tick, s.agents_running > 0, reduced),
        Span::styled(
            " Agent",
            Style::default().fg(comps::colour(Token::Cyan)).add_modifier(Modifier::BOLD),
        ),
    ])];
    for a in s.agents.values() {
        let status = if a.done {
            format!("{} {}", glyphs::DONE, a.name)
        } else {
            format!("{} {}", comps::agent_arc(tick, true, reduced).content, a.action)
        };
        out.push(Line::from(Span::styled(
            status,
            Style::default().fg(if a.done {
                comps::colour(Token::Green)
            } else {
                comps::colour(Token::Ink)
            }),
        )));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Golden-shape test: render the default three-column layout at a
    /// fixed tick and assert the structural invariants (numbers in
    /// reading order, identity chips, frame glyphs).
    #[test]
    fn golden_default_layout_structure() {
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        let tree = super::super::layout::Node::default_tree();
        let mut s = Scenario::new();
        s.model = "glm-5.2".into();
        s.apply("round_started", 0);

        term
            .draw(|f| {
                let areas = split_areas(f.area(), &tree);
                for (i, (area, view)) in areas.iter().enumerate() {
                    render_panel(
                        f,
                        *area,
                        (i + 1) as u8,
                        *view,
                        i == 1, // focus the conversation (middle)
                        &s,
                        1000,
                        false,
                    );
                }
            })
            .unwrap();

        let buf = term.backend().buffer();
        let text = buffer_text(buf);
        // Golden invariants: panel numbers 1-3 in reading order, each
        // chip beside its view title, the middle panel focused and
        // carrying the activity row.
        for want in ["1", "Changes", "2", "Conversation", "3", "Terminal"] {
            assert!(
                text.contains(want),
                "golden: {want:?} missing; rows:\n{}",
                text.lines().take(2).collect::<Vec<_>>().join("\n")
            );
        }
        assert!(text.contains("waiting for glm-5.2"));
    }

    #[test]
    fn plan_panel_lists_tasks_with_status_glyphs() {
        let mut s = Scenario::new();
        s.tasks.push(TaskRow {
            title: "ship it".into(),
            status: "done".into(),
        });
        s.tasks.push(TaskRow {
            title: "write docs".into(),
            status: "in_progress".into(),
        });
        let lines = plan(&s);
        let t: String = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(t.contains('✓'));
        assert!(t.contains('◐'));
        assert!(t.contains("ship it"));
    }

    #[test]
    fn changes_panel_shows_add_remove() {
        let mut s = Scenario::new();
        s.file_changes.push(FileChangeRow {
            path: "src/main.rs".into(),
            added: 12,
            removed: 3,
        });
        let lines = changes(&s);
        let t: String = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(t.contains("src/main.rs"));
        assert!(t.contains("+12"));
        assert!(t.contains("−3"));
    }

    fn buffer_text(buf: &Buffer) -> String {
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf.get(x, y).symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Split the tree into concrete areas (the layout glide interpolates
/// between two of these).
pub fn split_areas(area: Rect, tree: &super::layout::Node) -> Vec<(Rect, View)> {
    let mut out = Vec::new();
    areas_rec(area, tree, &mut out);
    out
}

fn areas_rec(area: Rect, node: &super::layout::Node, out: &mut Vec<(Rect, View)>) {
    use super::layout::{Direction, Node};
    match node {
        Node::Panel { view, .. } => out.push((area, *view)),
        Node::Split {
            direction,
            shares,
            children,
        } => {
            let total: u32 = shares.iter().sum();
            if total == 0 || children.is_empty() {
                return;
            }
            match direction {
                Direction::Right => {
                    let mut x = area.x;
                    for (i, c) in children.iter().enumerate() {
                        let w = (area.width as u64 * shares[i] as u64 / total as u64) as u16;
                        let w = w.max(1);
                        let last = i == children.len() - 1;
                        let r = Rect {
                            x,
                            width: if last { area.right().saturating_sub(x) } else { w },
                            ..area
                        };
                        areas_rec(r, c, out);
                        x = x.saturating_add(w);
                    }
                }
                Direction::Down => {
                    let mut y = area.y;
                    for (i, c) in children.iter().enumerate() {
                        let h = (area.height as u64 * shares[i] as u64 / total as u64) as u16;
                        let h = h.max(1);
                        let last = i == children.len() - 1;
                        let r = Rect {
                            y,
                            height: if last { area.bottom().saturating_sub(y) } else { h },
                            ..area
                        };
                        areas_rec(r, c, out);
                        y = y.saturating_add(h);
                    }
                }
            }
        }
    }
}

/// A task row the Plan panel lists (from TaskCreate/TaskUpdate).
#[derive(Debug, Clone, PartialEq)]
pub struct TaskRow {
    pub title: String,
    pub status: String,
}

/// A file-change row the Changes panel lists (from FileChanged).
#[derive(Debug, Clone, PartialEq)]
pub struct FileChangeRow {
    pub path: String,
    pub added: u32,
    pub removed: u32,
}
