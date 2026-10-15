//! Bounded browser presentation over the same checked profile host as the terminal.
use orbit_frontend_protocol::customization::{
    CustomizationError, PaneAction, PaneContext, PaneOutput, PaneState, ProfileCommand,
    ProfileHost, ResolvedProfile, Surface, MAX_PANE_LINES, MAX_PANE_OUTPUT_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserAction {
    Customize {
        command: ProfileCommand,
        expected_revision: Option<String>,
    },
    PaneRefresh {
        pane_id: String,
        revision: String,
    },
    PaneAction {
        pane_id: String,
        action_index: usize,
        revision: String,
    },
}
pub fn parse(value: Value) -> Result<BrowserAction, String> {
    let action: BrowserAction = serde_json::from_value(value.clone())
        .map_err(|e| format!("invalid customization action: {e}"))?;
    let normalized = serde_json::to_value(&action).map_err(|e| e.to_string())?;
    fn keys(input: &Value, normalized: &Value) -> Result<(), String> {
        match (input, normalized) {
            (Value::Object(a), Value::Object(b)) => {
                for (key, value) in a {
                    keys(value, b.get(key).ok_or("unexpected customization field")?)?;
                }
            }
            (Value::Array(a), Value::Array(b)) => {
                if a.len() != b.len() {
                    return Err("invalid customization array".into());
                }
                for (a, b) in a.iter().zip(b) {
                    keys(a, b)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    keys(&value, &normalized)?;
    Ok(action)
}

pub struct BrowserSession {
    host: Arc<dyn ProfileHost>,
    resolved: ResolvedProfile,
    outputs: BTreeMap<String, PaneOutput>,
    session_id: String,
}
impl BrowserSession {
    pub fn open(host: Arc<dyn ProfileHost>, session_id: String) -> Result<Self, String> {
        let resolved = host.load().map_err(|e| e.to_string())?;
        resolved.profile.validate().map_err(|e| e.to_string())?;
        Ok(Self {
            host,
            resolved,
            outputs: BTreeMap::new(),
            session_id,
        })
    }
    pub fn session_changed(&mut self, id: &str) {
        if self.session_id != id {
            self.session_id = id.into();
            for output in self.outputs.values_mut() {
                output.state = PaneState::Stale;
                output.text = "Session changed; refresh this pane".into();
            }
        }
    }
    pub fn refresh_all(&mut self, context: &PaneContext) {
        let ids: Vec<_> = self
            .resolved
            .profile
            .panes
            .iter()
            .filter(|p| p.surfaces.contains(&Surface::Browser))
            .map(|p| p.id.clone())
            .collect();
        for id in ids {
            let _ = self.refresh(&id, context);
        }
    }
    fn check_revision(&self, revision: &str) -> Result<(), String> {
        if revision.len() > 256
            || self.resolved.revision != revision
            || self.host.load().map_err(|e| e.to_string())?.revision != revision
        {
            return Err("Customization changed; reload before using this action".into());
        }
        Ok(())
    }
    fn refresh(&mut self, id: &str, context: &PaneContext) -> Result<(), String> {
        let def = self
            .resolved
            .profile
            .panes
            .iter()
            .find(|p| p.id == id)
            .ok_or("unknown custom pane")?;
        if !def.surfaces.contains(&Surface::Browser) {
            return Err("pane does not support browser".into());
        }
        let result = self.host.read_pane(id, context).and_then(|mut output| {
            if output.id != id
                || output.text.len() > MAX_PANE_OUTPUT_BYTES
                || output.text.lines().count() > MAX_PANE_LINES
                || output
                    .actions
                    .iter()
                    .any(|action| !def.actions.contains(action))
            {
                return Err(CustomizationError::Invalid(
                    "pane output violates its declared bounds/actions".into(),
                ));
            }
            output.title = def.title.clone();
            output.text = super::display_error(&output.text);
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
                        text: super::display_error(&error.to_string()),
                        truncated: false,
                        actions: Vec::new(),
                    },
                );
                Ok(())
            }
        }
    }
    pub fn execute(
        &mut self,
        action: BrowserAction,
        context: &PaneContext,
    ) -> Result<(Value, Option<PaneAction>), String> {
        let mut effect = None;
        let mut message = String::new();
        let mut applied_command = Value::Null;
        match action {
            BrowserAction::Customize {
                command,
                expected_revision,
            } => {
                applied_command = serde_json::to_value(&command).map_err(|e| e.to_string())?;
                let readonly = matches!(
                    command,
                    ProfileCommand::Show
                        | ProfileCommand::Reload
                        | ProfileCommand::Capabilities
                        | ProfileCommand::Validate { .. }
                );
                let reply = if readonly {
                    self.host.command(command)
                } else {
                    let revision = expected_revision
                        .as_deref()
                        .ok_or("expected customization revision is required")?;
                    self.check_revision(revision)?;
                    self.host.command_checked(command, revision)
                }
                .map_err(|e| e.to_string())?;
                message = reply.message;
                if let Some(resolved) = reply.profile {
                    resolved.profile.validate().map_err(|e| e.to_string())?;
                    if resolved.revision.len() > 256 {
                        return Err("invalid profile revision".into());
                    }
                    self.resolved = resolved;
                    self.outputs.clear();
                    self.refresh_all(context);
                }
            }
            BrowserAction::PaneRefresh { pane_id, revision } => {
                self.check_revision(&revision)?;
                self.refresh(&pane_id, context)?;
            }
            BrowserAction::PaneAction {
                pane_id,
                action_index,
                revision,
            } => {
                self.check_revision(&revision)?;
                let def = self
                    .resolved
                    .profile
                    .panes
                    .iter()
                    .find(|p| p.id == pane_id)
                    .ok_or("unknown custom pane")?;
                let action = self
                    .outputs
                    .get(&pane_id)
                    .and_then(|p| p.actions.get(action_index))
                    .ok_or("refresh this pane before using its actions")?
                    .clone();
                if !def.surfaces.contains(&Surface::Browser) || !def.actions.contains(&action) {
                    return Err("undeclared pane action".into());
                }
                match action {
                    PaneAction::Refresh => self.refresh(&pane_id, context)?,
                    PaneAction::OwnerCancel if !context.controller => {
                        return Err("owner cancellation requires controller authority".into())
                    }
                    action => effect = Some(action),
                }
            }
        }
        let mut reply = self.reply(&message);
        reply["applied_command"] = orbit_cli::display_safe_json(applied_command);
        Ok((reply, effect))
    }
    pub fn reply(&self, message: &str) -> Value {
        let palette =
            orbit_hud_tui::proto::shell::pal::Palette::from_profile(&self.resolved.profile);
        let hex = |c: (u8, u8, u8)| format!("#{:02x}{:02x}{:02x}", c.0, c.1, c.2);
        orbit_cli::display_safe_json(json!({"type":"customization", "resolved":self.resolved,
            "session_id":self.session_id,"message":super::display_error(message),"panes":self.outputs.values().collect::<Vec<_>>(),
            "palette":{"bg":hex(palette.app),"bg-raised":hex(palette.panel),"bg-inset":hex(palette.inset),
                "line":hex(palette.rule),"text":hex(palette.ink),"dim":hex(palette.muted),"faint":hex(palette.faint),
                "accent":hex(palette.magenta),"accent-dim":hex(palette.magenta_dim),"ok":hex(palette.green),
                "warn":hex(palette.amber),"error":hex(palette.red),"denied":hex(palette.violet)}}))
    }
}
