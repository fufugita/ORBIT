//! Customization command grammar and the session-only recovery host.
use crate::customization::{Error, LocalProfileHost};
use crate::tool_runtime::PermissionScope;
use orbit_frontend_protocol::customization::{
    MAX_PROFILE_BYTES, PaneContext, PaneOutput, Profile, ProfileCommand, ProfileCommandResult,
    ProfileHost, ResolvedProfile,
};
use std::path::Path;
use std::sync::Arc;

pub fn parse(words: &[String]) -> Result<ProfileCommand, String> {
    if words.iter().map(String::len).sum::<usize>() > MAX_PROFILE_BYTES + 1024 || words.len() > 5 {
        return Err("customization command exceeds its bounds".into());
    }
    if words
        .iter()
        .filter(|word| word.as_str() == "--json")
        .count()
        > 1
    {
        return Err("--json cannot be repeated".into());
    }
    let words: Vec<&str> = words
        .iter()
        .map(String::as_str)
        .filter(|word| *word != "--json")
        .collect();
    let operation = words.first().copied().unwrap_or("show");
    let tail = words.get(1..).unwrap_or_default();
    let path = || -> Result<String, String> {
        match tail {
            [path] if !path.is_empty() && !path.starts_with('-') => Ok((*path).into()),
            _ => Err(format!("usage: customize {operation} PATH")),
        }
    };
    Ok(match (operation, tail) {
        ("show", []) => ProfileCommand::Show,
        ("capabilities", []) => ProfileCommand::Capabilities,
        ("reload", []) => ProfileCommand::Reload,
        ("validate", _) => ProfileCommand::Validate { path: path()? },
        ("import", _) => ProfileCommand::Import { path: path()? },
        ("export", _) => ProfileCommand::Export { path: path()? },
        ("set", [key, value]) if !key.starts_with('-') => ProfileCommand::Set { key: (*key).into(), value: (*value).into() },
        ("reset", []) => ProfileCommand::Reset { key: None },
        ("reset", [key]) if !key.starts_with('-') => ProfileCommand::Reset { key: Some((*key).into()) },
        ("theme", [name]) if !name.starts_with('-') => ProfileCommand::Theme { name: (*name).into() },
        _ => return Err("usage: customize show|capabilities|validate PATH|import PATH|export PATH|set KEY VALUE|reset [KEY]|theme NAME|reload".into()),
    })
}

pub fn command(
    home: &Path,
    workspace: &Path,
    words: &[String],
) -> Result<serde_json::Value, String> {
    let host = LocalProfileHost {
        home: home.into(),
        workspace: workspace.into(),
        scope: PermissionScope::default(),
    };
    command_for(&host, words)
}

pub fn command_for(host: &dyn ProfileHost, words: &[String]) -> Result<serde_json::Value, String> {
    let operation = parse(words)?;
    let result = host.command(operation).map_err(|error| error.to_string())?;
    let mut value = serde_json::to_value(result).map_err(|error| error.to_string())?;
    value["schema"] = serde_json::json!("orbit.cli/v1");
    value["command"] = serde_json::json!("customize");
    value["status"] = serde_json::json!("ok");
    Ok(crate::display_safe_json(value))
}

pub fn host(
    home: &Path,
    workspace: &Path,
    scope: PermissionScope,
    safe_defaults: bool,
) -> Arc<dyn ProfileHost> {
    let local = LocalProfileHost {
        home: home.into(),
        workspace: workspace.into(),
        scope,
    };
    if safe_defaults {
        Arc::new(SessionDefaultsHost)
    } else {
        Arc::new(local)
    }
}

/// Explicit recovery is read-only: malformed stored files remain available for repair.
struct SessionDefaultsHost;
impl ProfileHost for SessionDefaultsHost {
    fn load(&self) -> Result<ResolvedProfile, Error> {
        Ok(crate::customization::safe_session_defaults())
    }
    fn replace(&self, _: Profile, _: &str) -> Result<ResolvedProfile, Error> {
        Err(recovery_error())
    }
    fn reset(&self, _: &str) -> Result<ResolvedProfile, Error> {
        Err(recovery_error())
    }
    fn read_pane(&self, _: &str, _: &PaneContext) -> Result<PaneOutput, Error> {
        Err(recovery_error())
    }
    fn command(&self, command: ProfileCommand) -> Result<ProfileCommandResult, Error> {
        match command {
            ProfileCommand::Show | ProfileCommand::Reload | ProfileCommand::Capabilities => Ok(ProfileCommandResult {
                message: "Session-only defaults are active; stored customization is unchanged. Repair it with orbit customize outside this session.".into(),
                profile: Some(self.load()?),
            }),
            _ => Err(recovery_error()),
        }
    }
}
fn recovery_error() -> Error {
    Error::Invalid("Session-only defaults cannot write customization; repair the stored file explicitly outside this session".into())
}
