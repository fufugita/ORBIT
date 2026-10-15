//! Checked frontend presentation and explicit actions for portable profiles.
use crate::proto::{
    layout::{Node, View},
    shell::{
        canvas::{Cv, clip_text, wrap_ranges},
        frame::{FocusFx, FrameSpec, panel_frame},
        hits::Click,
    },
};
use orbit_frontend_protocol::customization::{
    CustomizationError, MAX_PANE_LINES, MAX_PANE_OUTPUT_BYTES, PaneAction, PaneContext, PaneOutput,
    PaneState, Profile, ProfileHost, ResolvedProfile, Surface,
};
use ratatui::layout::Rect;
use std::{collections::BTreeMap, sync::Arc};

pub struct CustomizationSession {
    pub host: Arc<dyn ProfileHost>,
    pub resolved: ResolvedProfile,
    pub outputs: BTreeMap<String, PaneOutput>,
    pub context: PaneContext,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionEffect {
    Refreshed,
    FocusConversation,
    InsertDraft(String),
    OwnerCancel,
}

impl CustomizationSession {
    pub fn invalidate_session(&mut self, context: PaneContext) {
        self.context = context;
        for pane in self.outputs.values_mut() {
            pane.state = PaneState::Stale;
            pane.text = "Session changed; refresh this pane".into();
        }
    }
    pub fn open(host: Arc<dyn ProfileHost>) -> Result<Self, CustomizationError> {
        let resolved = host.load()?;
        resolved.profile.validate()?;
        Ok(Self {
            host,
            resolved,
            outputs: BTreeMap::new(),
            context: PaneContext::default(),
        })
    }
    pub fn accept(&mut self, resolved: ResolvedProfile) -> Result<(), CustomizationError> {
        resolved.profile.validate()?;
        if resolved.revision.len() > 256 {
            return Err(CustomizationError::Invalid(
                "profile revision exceeds bounds".into(),
            ));
        }
        self.resolved = resolved;
        self.outputs
            .retain(|id, _| self.resolved.profile.panes.iter().any(|p| p.id == *id));
        Ok(())
    }
    pub fn refresh(&mut self, id: &str) -> Result<(), CustomizationError> {
        let def = self
            .resolved
            .profile
            .panes
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| CustomizationError::Invalid("unknown pane".into()))?;
        if !def.surfaces.contains(&Surface::Terminal) {
            self.outputs.insert(
                id.into(),
                PaneOutput {
                    id: id.into(),
                    title: def.title.clone(),
                    state: PaneState::Error,
                    text: "This pane does not support the terminal surface".into(),
                    truncated: false,
                    actions: Vec::new(),
                },
            );
            return Err(CustomizationError::Invalid(
                "pane does not support terminal".into(),
            ));
        }
        let result = self
            .host
            .read_pane(id, &self.context)
            .and_then(|mut output| {
                if output.id != id
                    || output.text.len() > MAX_PANE_OUTPUT_BYTES
                    || output.text.lines().count() > MAX_PANE_LINES
                    || output.actions.iter().any(|a| !def.actions.contains(a))
                {
                    return Err(CustomizationError::Invalid(
                        "pane output does not match declared bounds/actions".into(),
                    ));
                }
                output.title = def.title.clone();
                output.text = safe_pane_text(&output.text)?;
                if output.text.is_empty() && output.state == PaneState::Ready {
                    output.state = PaneState::Empty;
                }
                Ok(output)
            });
        match result {
            Ok(output) => {
                self.outputs.insert(id.into(), output);
                Ok(())
            }
            Err(error) => {
                self.outputs.insert(
                    id.into(),
                    PaneOutput {
                        id: id.into(),
                        title: def.title.clone(),
                        state: PaneState::Error,
                        text: crate::bridge::terminal_safe(&crate::bridge::safe_text(
                            &error.to_string(),
                        )),
                        truncated: false,
                        actions: vec![PaneAction::Refresh],
                    },
                );
                Err(error)
            }
        }
    }
    pub fn refresh_all(&mut self) {
        let ids: Vec<_> = self
            .resolved
            .profile
            .panes
            .iter()
            .map(|p| p.id.clone())
            .collect();
        for id in ids {
            let _ = self.refresh(&id);
        }
    }
    pub fn action(&mut self, id: &str, index: usize) -> Result<ActionEffect, CustomizationError> {
        let def = self
            .resolved
            .profile
            .panes
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| CustomizationError::Invalid("unknown pane".into()))?;
        let action = self
            .outputs
            .get(id)
            .and_then(|output| output.actions.get(index))
            .cloned()
            .ok_or_else(|| {
                CustomizationError::Invalid("pane action unavailable until refresh".into())
            })?;
        if !def.actions.contains(&action) {
            return Err(CustomizationError::Invalid(
                "pane action is undeclared".into(),
            ));
        }
        if !def.surfaces.contains(&Surface::Terminal) {
            return Err(CustomizationError::Invalid(
                "pane does not support terminal".into(),
            ));
        }
        match action {
            PaneAction::Refresh => {
                self.refresh(id)?;
                Ok(ActionEffect::Refreshed)
            }
            PaneAction::FocusConversation => Ok(ActionEffect::FocusConversation),
            PaneAction::InsertPrompt { text } => Ok(ActionEffect::InsertDraft(
                crate::bridge::terminal_safe(&crate::bridge::safe_text(&text)),
            )),
            PaneAction::OwnerCancel if self.context.controller => Ok(ActionEffect::OwnerCancel),
            PaneAction::OwnerCancel => Err(CustomizationError::Invalid(
                "owner cancellation requires controller authority".into(),
            )),
        }
    }
    pub fn persist_tree(&mut self, tree: &Node) -> Result<(), CustomizationError> {
        let mut profile = self.resolved.profile.clone();
        profile.layout.tree = serde_json::from_value(
            serde_json::to_value(tree)
                .map_err(|_| CustomizationError::Invalid("layout cannot be encoded".into()))?,
        )
        .map_err(|_| CustomizationError::Invalid("layout contains an unsupported view".into()))?;
        profile.layout.preset = "custom".into();
        profile.validate()?;
        let next = self.host.replace(profile, &self.resolved.revision)?;
        self.accept(next)
    }
}

pub fn profile_tree(profile: &Profile) -> Result<Node, CustomizationError> {
    profile.validate()?;
    serde_json::from_value(
        serde_json::to_value(&profile.layout.tree)
            .map_err(|_| CustomizationError::Invalid("layout cannot be encoded".into()))?,
    )
    .map_err(|_| CustomizationError::Invalid("layout cannot be displayed".into()))
}

pub fn pane_title<'a>(
    tree: &Node,
    index: usize,
    outputs: &'a BTreeMap<String, PaneOutput>,
) -> Option<&'a str> {
    let id = tree.custom_id_at(index)?;
    outputs.get(&id).map(|p| p.title.as_str())
}

fn safe_pane_text(text: &str) -> Result<String, CustomizationError> {
    if text.len() > MAX_PANE_OUTPUT_BYTES || text.lines().count() > MAX_PANE_LINES {
        return Err(CustomizationError::Invalid(
            "pane output exceeds display bounds".into(),
        ));
    }
    // Keep refusals on the original input, even when a forbidden marker is
    // hidden inside an escape sequence. Parse escapes before display_safe
    // removes ESC, then gate the visible result as well.
    let text = if !crate::bridge::safe_text_probe(text) {
        crate::bridge::safe_text(text)
    } else {
        crate::bridge::safe_text(&crate::bridge::terminal_safe_multiline(text))
    };
    if text.len() > MAX_PANE_OUTPUT_BYTES || text.lines().count() > MAX_PANE_LINES {
        return Err(CustomizationError::Invalid(
            "pane output exceeds display bounds".into(),
        ));
    }
    Ok(text)
}

/// The custom view shares the same production frame, hit map and clipping engine.
pub fn draw_pane(
    cv: &mut Cv,
    r: Rect,
    id: &str,
    output: Option<&PaneOutput>,
    num: usize,
    focused: bool,
    scroll: usize,
) {
    let palette = cv.palette;
    let title = output.map(|o| o.title.as_str()).unwrap_or(id);
    let Some(inner) = panel_frame(
        cv,
        r,
        &FrameSpec {
            num,
            title,
            ident: palette.cyan,
            focused,
            focus_fx: FocusFx::settled(focused),
            badge: None,
            attention: 0.0,
            footer: Vec::new(),
            footer_parts: Vec::new(),
        },
    ) else {
        return;
    };
    let (x, y, w, h) = (
        inner.x as i32,
        inner.y as i32,
        inner.width as i32,
        inner.height as i32,
    );
    let Some(output) = output else {
        cv.text(x, y, "loading · refresh with r", palette.muted, None);
        return;
    };
    let (state, mut text) = match safe_pane_text(&output.text) {
        Ok(text) => (output.state.clone(), text),
        Err(error) => (
            PaneState::Error,
            crate::bridge::safe_text(&error.to_string()),
        ),
    };
    let state = match state {
        PaneState::Ready => "",
        PaneState::Empty => "empty",
        PaneState::Missing => "missing",
        PaneState::Loading => "loading",
        PaneState::Stale => "stale · refresh",
        PaneState::Error => "error",
    };
    if !state.is_empty() {
        text = format!("{state}\n{text}");
    }
    if output.truncated {
        text.push_str("\n[truncated]");
    }
    let width = (w - 2).max(1);
    let ranges = wrap_ranges(&text, width);
    let chars: Vec<char> = text.chars().collect();
    let content_height = h.saturating_sub(if output.actions.is_empty() { 0 } else { 2 });
    for (row, (a, b)) in ranges
        .into_iter()
        .skip(scroll)
        .take(content_height.max(0) as usize)
        .enumerate()
    {
        let line: String = chars[a..b].iter().collect();
        cv.text(x + 1, y + row as i32, &line, palette.ink, None);
    }
    if !output.actions.is_empty() && h >= 2 {
        let mut at = x + 1;
        for (i, action) in output.actions.iter().take(8).enumerate() {
            let label = match action {
                PaneAction::Refresh => "refresh",
                PaneAction::FocusConversation => "conversation",
                PaneAction::InsertPrompt { .. } => "insert draft",
                PaneAction::OwnerCancel => "cancel turn",
            };
            let label = clip_text(&format!("{} {label}  ", i + 1), (x + w - at).max(0));
            if label.is_empty() {
                break;
            }
            let end = cv.text(at, y + h - 1, &label, palette.cyan, None);
            cv.hit(
                at,
                y + h - 1,
                end - at,
                1,
                Click::CustomAction {
                    panel: num - 1,
                    action: i,
                },
            );
            at = end;
        }
    }
}

pub fn focus_conversation(app: &mut crate::proto::app::App) {
    if let Some(index) = app
        .tree
        .leaves()
        .iter()
        .position(|(_, view)| *view == View::Conversation)
    {
        app.focus = index;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_frontend_protocol::customization::{
        CustomizationCapabilities, LayoutNode, PaneDef, PaneSource, Surface,
    };
    struct Host(String);
    impl Host {
        fn new(text: impl Into<String>) -> Self {
            Self(text.into())
        }
    }
    impl ProfileHost for Host {
        fn load(&self) -> Result<ResolvedProfile, CustomizationError> {
            let mut p = Profile::default();
            p.panes.push(PaneDef {
                id: "notes".into(),
                title: "Local notes".into(),
                surfaces: vec![Surface::Terminal],
                source: PaneSource::Text {
                    text: "fixture proof".into(),
                },
                actions: vec![PaneAction::Refresh],
            });
            p.layout.tree = LayoutNode::Split {
                direction: orbit_frontend_protocol::customization::Direction::Right,
                shares: vec![1, 1],
                children: vec![
                    LayoutNode::panel(orbit_frontend_protocol::customization::View::Conversation),
                    LayoutNode::Custom {
                        pane_id: "notes".into(),
                    },
                ],
            };
            Ok(ResolvedProfile {
                profile: p,
                sources: Default::default(),
                revision: "1".into(),
                capabilities: CustomizationCapabilities::default(),
            })
        }
        fn replace(&self, _: Profile, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            self.load()
        }
        fn reset(&self, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            self.load()
        }
        fn read_pane(&self, id: &str, _: &PaneContext) -> Result<PaneOutput, CustomizationError> {
            Ok(PaneOutput {
                id: id.into(),
                title: "untrusted host title".into(),
                state: PaneState::Ready,
                text: self.0.clone(),
                truncated: false,
                actions: vec![PaneAction::Refresh],
            })
        }
    }
    #[test]
    fn custom_pane_tracer_renders_named_host_data_alongside_conversation() {
        let mut session = CustomizationSession::open(Arc::new(Host::new("fixture proof"))).unwrap();
        session.refresh_all();
        let tree = profile_tree(&session.resolved.profile).unwrap();
        assert!(tree.leaves().iter().any(|(_, v)| *v == View::Conversation));
        let mut buffer = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 12));
        let mut cv = Cv::new(&mut buffer);
        draw_pane(
            &mut cv,
            Rect::new(0, 0, 60, 12),
            "notes",
            session.outputs.get("notes"),
            2,
            true,
            0,
        );
        let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Local notes"));
        assert!(text.contains("fixture proof"));
    }

    fn buffer_row(buffer: &ratatui::buffer::Buffer, row: u16) -> String {
        (1..buffer.area.width - 1)
            .map(|col| buffer[(col, row)].symbol())
            .collect::<String>()
            .trim()
            .to_string()
    }

    #[test]
    fn refresh_keeps_blank_and_trailing_lines_and_renders_separate_rows() {
        let mut session =
            CustomizationSession::open(Arc::new(Host::new("alpha\n\nomega\n"))).unwrap();
        session.refresh("notes").unwrap();
        let output = session.outputs.get("notes").unwrap();
        assert_eq!(output.text, "alpha\n\nomega\n");
        assert_eq!(output.state, PaneState::Ready);
        assert_eq!(output.title, "Local notes");

        let area = Rect::new(0, 0, 40, 10);
        let mut buffer = ratatui::buffer::Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        draw_pane(&mut cv, area, "notes", Some(output), 2, true, 0);
        let hits = cv.take_hits();
        assert_eq!(buffer_row(&buffer, 2), "alpha");
        assert_eq!(buffer_row(&buffer, 3), "");
        assert_eq!(buffer_row(&buffer, 4), "omega");
        assert_eq!(buffer_row(&buffer, 5), "");
        let action = hits
            .iter()
            .find(|hit| matches!(hit.click, Click::CustomAction { .. }))
            .unwrap();
        assert_eq!(
            action.click,
            Click::CustomAction {
                panel: 1,
                action: 0
            }
        );
        assert_eq!(buffer_row(&buffer, action.rect.y), "1 refresh");

        let mut buffer = ratatui::buffer::Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        draw_pane(&mut cv, area, "notes", Some(output), 2, true, 2);
        assert_eq!(buffer_row(&buffer, 2), "omega");
        assert_eq!(buffer_row(&buffer, action.rect.y), "1 refresh");
        assert_eq!(session.action("notes", 0).unwrap(), ActionEffect::Refreshed);
        assert_eq!(session.outputs["notes"].text, "alpha\n\nomega\n");
    }

    #[test]
    fn refresh_sanitizes_raw_multiline_escapes_controls_and_secrets() {
        let mut session = CustomizationSession::open(Arc::new(Host::new(concat!(
            "first\n\u{1b}]0;hidden\nOSC title\u{7}\u{1b}[31\nmred\u{1b}[0m\n",
            "token=ghp_0123456789abcdef0123456789abcdef0123 done\r\u{7}\u{85}\n",
            "last\tcell\n"
        ))))
        .unwrap();
        session.refresh("notes").unwrap();
        let text = &session.outputs["notes"].text;
        assert!(text.starts_with("first\nred\ntoken="), "{text}");
        assert!(text.ends_with(" done\nlast    cell\n"), "{text}");
        assert!(!text.contains("ghp_0123"), "{text}");
        assert!(!text.contains("hidden"), "{text}");
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
    }

    #[test]
    fn refresh_preserves_raw_and_visible_content_gate_refusals() {
        for text in [
            "first\nprompt: hidden\nlast",
            "first\nuser_message\nlast",
            "first\nchain_of_thought\nlast",
            "first\n\u{1b}]0;prompt: hidden\u{7}last",
            "first\npro\u{1b}[31mmpt: hidden\nlast",
        ] {
            let mut session = CustomizationSession::open(Arc::new(Host::new(text))).unwrap();
            session.refresh("notes").unwrap();
            assert_eq!(session.outputs["notes"].text, "[redacted]", "{text:?}");
        }
    }

    #[test]
    fn refresh_rejects_in_bound_text_that_expands_beyond_display_bounds() {
        let raw = "\t".repeat(MAX_PANE_OUTPUT_BYTES);
        assert_eq!(raw.len(), MAX_PANE_OUTPUT_BYTES);
        assert!(raw.lines().count() <= MAX_PANE_LINES);
        let mut session = CustomizationSession::open(Arc::new(Host::new(raw))).unwrap();
        assert!(matches!(
            session.refresh("notes"),
            Err(CustomizationError::Invalid(_))
        ));
        let output = &session.outputs["notes"];
        assert_eq!(output.state, PaneState::Error);
        assert!(output.text.contains("exceeds display bounds"));
        assert!(output.text.len() <= MAX_PANE_OUTPUT_BYTES);
        assert_eq!(output.actions, vec![PaneAction::Refresh]);
    }

    #[test]
    fn refresh_accepts_tab_expansion_at_exact_display_limit() {
        let raw = "\t".repeat(MAX_PANE_OUTPUT_BYTES / 4);
        let mut session = CustomizationSession::open(Arc::new(Host::new(raw))).unwrap();
        session.refresh("notes").unwrap();
        let output = &session.outputs["notes"];
        assert_eq!(output.state, PaneState::Ready);
        assert_eq!(output.text.len(), MAX_PANE_OUTPUT_BYTES);
        assert!(output.text.chars().all(|c| c == ' '));
    }

    #[test]
    fn direct_pane_render_sanitizes_multiline_input_without_refresh() {
        let output = PaneOutput {
            id: "notes".into(),
            title: "Local notes".into(),
            state: PaneState::Ready,
            text: "\u{1b}[31malpha\u{1b}[0m\n\u{1b}]0;hidden\ntext\u{7}omega\n".into(),
            truncated: false,
            actions: Vec::new(),
        };
        let area = Rect::new(0, 0, 40, 9);
        let mut buffer = ratatui::buffer::Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        draw_pane(&mut cv, area, "notes", Some(&output), 2, true, 0);
        assert_eq!(buffer_row(&buffer, 2), "alpha");
        assert_eq!(buffer_row(&buffer, 3), "omega");
        assert_eq!(buffer_row(&buffer, 4), "");
        let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
        assert!(!text.contains("hidden"));
        assert!(!text.contains("[31m"));
    }

    #[test]
    fn direct_pane_render_keeps_secret_redaction_and_content_refusals() {
        for (text, expected) in [
            ("alpha\nchain_of_thought hidden\nlast", "[redacted]"),
            (
                "token=ghp_0123456789abcdef0123456789abcdef0123\nlast",
                "[redacted:github token]",
            ),
        ] {
            let output = PaneOutput {
                id: "notes".into(),
                title: "Local notes".into(),
                state: PaneState::Ready,
                text: text.into(),
                truncated: false,
                actions: Vec::new(),
            };
            let area = Rect::new(0, 0, 60, 9);
            let mut buffer = ratatui::buffer::Buffer::empty(area);
            draw_pane(
                &mut Cv::new(&mut buffer),
                area,
                "notes",
                Some(&output),
                2,
                true,
                0,
            );
            let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains("ghp_0123"), "{text}");
            assert!(!text.contains("chain_of_thought"), "{text}");
        }
    }

    #[test]
    fn direct_pane_render_rejects_raw_and_expanded_over_bound_text() {
        for text in [
            "x".repeat(MAX_PANE_OUTPUT_BYTES + 1),
            "\t".repeat(MAX_PANE_OUTPUT_BYTES),
            "row\n".repeat(MAX_PANE_LINES + 1),
        ] {
            let output = PaneOutput {
                id: "notes".into(),
                title: "Local notes".into(),
                state: PaneState::Ready,
                text,
                truncated: false,
                actions: vec![PaneAction::Refresh],
            };
            let area = Rect::new(0, 0, 80, 9);
            let mut buffer = ratatui::buffer::Buffer::empty(area);
            let mut cv = Cv::new(&mut buffer);
            draw_pane(&mut cv, area, "notes", Some(&output), 2, true, 0);
            let hits = cv.take_hits();
            assert_eq!(buffer_row(&buffer, 2), "error");
            assert_eq!(
                buffer_row(&buffer, 3),
                "invalid customization: pane output exceeds display bounds"
            );
            assert!(hits.iter().any(|hit| hit.click
                == Click::CustomAction {
                    panel: 1,
                    action: 0
                }));
            let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
            assert!(!text.contains("row"), "{text}");
            assert!(!text.contains("xxx"), "{text}");
        }
    }
}
