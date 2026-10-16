use crate::CompatError;
use crate::inspect::SourceTree;
use crate::model::*;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const MCP_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
const MAX_JSON_BYTES: usize = 256 * 1024;
const MAX_METADATA_NODES: usize = 8192;

pub(crate) fn normalize(
    tree: &SourceTree,
    options: &InspectOptions,
) -> Result<Inspection, CompatError> {
    let root = tree
        .contains("plugin.json")
        .then(|| parse_json(tree.text("plugin.json")?))
        .transpose()?;
    let portable = root
        .as_ref()
        .is_some_and(|value| value.get("$schema").and_then(Value::as_str) == Some(PLUGIN_SCHEMA));
    let codex = root
        .as_ref()
        .and_then(|value| value.pointer("/extensions/com.openai"))
        .is_some_and(Value::is_object)
        || tree.contains(".codex-plugin/plugin.json");
    let claude_manifest = tree.contains(".claude-plugin/plugin.json")
        || root
            .as_ref()
            .is_some_and(|value| value.get("$schema").is_none());
    let hermes = tree.contains("plugin.yaml") || tree.contains("plugin.yml");
    let claude_layout = root.is_none()
        && !codex
        && !hermes
        && (["skills", "commands", "agents"]
            .iter()
            .any(|path| tree.directories.contains(*path))
            || tree.contains("hooks/hooks.json")
            || tree.contains(".mcp.json"));
    let claude = claude_manifest || claude_layout;
    let mut detected = Vec::new();
    if codex {
        detected.push(PluginFormat::Codex);
    } else if portable {
        detected.push(PluginFormat::Portable);
    }
    if claude {
        detected.push(PluginFormat::Claude);
    }
    if hermes {
        detected.push(PluginFormat::Hermes);
    }
    let format = match options.format {
        Some(format) => format,
        None if detected.len() == 1 => detected[0],
        None if detected.is_empty() => return Err(failure("plugin_manifest_missing")),
        None => return Err(failure("plugin_format_ambiguous")),
    };
    if format == PluginFormat::Codex {
        return normalize_codex(tree, options, root);
    }
    if format == PluginFormat::Hermes {
        return normalize_hermes(tree);
    }
    if format == PluginFormat::Claude {
        let (path, raw) = if tree.contains(".claude-plugin/plugin.json") {
            (
                Some(".claude-plugin/plugin.json"),
                parse_json(tree.text(".claude-plugin/plugin.json")?)?,
            )
        } else if let Some(raw) = root.filter(|value| value.get("$schema").is_none()) {
            (Some("plugin.json"), raw)
        } else if claude_layout {
            let name = tree
                .directory_name
                .as_ref()
                .ok_or_else(|| failure("plugin_id_invalid"))?;
            validate_legacy_id(name)?;
            (None, serde_json::json!({"name":name}))
        } else {
            return Err(failure("plugin_manifest_missing"));
        };
        return normalize_claude(tree, options, path, raw);
    }
    if format != PluginFormat::Portable {
        return Err(failure("plugin_format_unavailable"));
    }
    if !portable {
        return Err(failure(if root.is_some() {
            "manifest_schema_invalid"
        } else {
            "plugin_manifest_missing"
        }));
    }
    normalize_portable(tree, options, root.expect("portable manifest checked"))
}

fn normalize_portable(
    tree: &SourceTree,
    options: &InspectOptions,
    raw: Value,
) -> Result<Inspection, CompatError> {
    normalize_portable_components(tree, options, raw, true)
}

fn normalize_portable_components(
    tree: &SourceTree,
    options: &InspectOptions,
    raw: Value,
    include_mcp: bool,
) -> Result<Inspection, CompatError> {
    let object = raw
        .as_object()
        .ok_or_else(|| failure("manifest_field_invalid"))?;
    check_keys(
        object,
        &[
            "$schema",
            "name",
            "version",
            "description",
            "author",
            "homepage",
            "repository",
            "license",
            "keywords",
            "extensions",
        ],
        "manifest_field_unmapped",
    )?;
    let name = required_string(object, "name", "manifest_field_invalid")?;
    validate_plugin_id(&name)?;
    for key in [
        "version",
        "description",
        "homepage",
        "repository",
        "license",
    ] {
        optional_string(object, key, "manifest_field_invalid")?;
    }
    if let Some(author) = object.get("author") {
        let author = author
            .as_object()
            .ok_or_else(|| failure("manifest_field_invalid"))?;
        check_keys(author, &["name", "email", "url"], "manifest_field_unmapped")?;
        for key in ["name", "email", "url"] {
            optional_string(author, key, "manifest_field_invalid")?;
        }
    }
    optional_list(object, "keywords", "manifest_field_invalid")?;
    let mut inspection = Inspection {
        schema_version: 1,
        source: PluginSource {
            format: PluginFormat::Portable,
            manifest_path: Some("plugin.json".to_owned()),
            inferred_name: None,
            source_digest: tree.source_digest.clone(),
            files: tree.files.clone(),
        },
        manifest: PluginManifest {
            id: name.clone(),
            name: name.clone(),
            version: optional_string(object, "version", "manifest_field_invalid")?,
            description: optional_string(object, "description", "manifest_field_invalid")?
                .unwrap_or_default(),
            license: optional_string(object, "license", "manifest_field_invalid")?,
            source_metadata: raw.clone(),
        },
        components: Vec::new(),
        requirements: Vec::new(),
        diagnostics: Vec::new(),
        migration: MigrationPlan::default(),
    };
    inspection.diagnostics.push(diagnostic("inspection_only", DiagnosticSeverity::Info, None, None,
        "Inspection validates declarations and source bytes; plugin behavior and dependencies have not been executed",
        None));
    if tree.scm_excluded {
        inspection.diagnostics.push(diagnostic("source_scm_excluded", DiagnosticSeverity::Info, None, None,
            "Git control metadata was excluded from the package inventory; all other source entries were inspected", None));
    }
    if let Some(extensions) = object.get("extensions") {
        let extensions = extensions
            .as_object()
            .ok_or_else(|| failure("manifest_field_invalid"))?;
        for (namespace, value) in extensions {
            if !value.is_object() || !valid_namespace(namespace) {
                return Err(failure("manifest_field_invalid"));
            }
            inspection.diagnostics.push(diagnostic(
                "extension_mapping_required",
                DiagnosticSeverity::Error,
                None,
                Some("plugin.json"),
                "A host extension requires an explicit compatibility mapping",
                Some("Select the matching source format or generate a concrete host adapter"),
            ));
            inspection.requirements.push(Requirement { component_id: None, kind: "host_extension".into(), name: namespace.clone(), satisfied: false,
                action: "Select the extension's host format or provide its explicit adapter before activation".into() });
        }
    }
    for path in tree.bytes.keys() {
        let parts: Vec<_> = path.split('/').collect();
        if parts.len() == 3 && parts[0] == "skills" && parts[2] == "SKILL.md" {
            normalize_skill(tree, options, &mut inspection, path, parts[1])?;
        }
    }
    if include_mcp && tree.contains("mcp.json") {
        normalize_mcp(tree, &mut inspection)?;
    }
    inspection.components.sort_by(|a, b| a.id.cmp(&b.id));
    if inspection
        .components
        .windows(2)
        .any(|pair| pair[0].id.eq_ignore_ascii_case(&pair[1].id))
    {
        return Err(failure("component_id_collision"));
    }
    inspection.migration.requirements = inspection.requirements.clone();
    inspection.migration.diagnostics = inspection
        .diagnostics
        .iter()
        .filter(|d| d.severity == DiagnosticSeverity::Error)
        .cloned()
        .collect();
    Ok(inspection)
}

// Selection and component precedence follow the official packaging reference:
// https://developers.openai.com/plugins/build/plugins
// https://developers.openai.com/plugins/deploy/submission
fn normalize_codex(
    tree: &SourceTree,
    options: &InspectOptions,
    root: Option<Value>,
) -> Result<Inspection, CompatError> {
    let portable = root
        .as_ref()
        .is_some_and(|value| value.get("$schema").and_then(Value::as_str) == Some(PLUGIN_SCHEMA));
    let inline = if portable {
        root.as_ref()
            .and_then(|value| value.pointer("/extensions/com.openai"))
    } else {
        None
    };
    if inline.is_some_and(|value| !value.is_object()) {
        return Err(failure("manifest_field_invalid"));
    }
    let (overlay, overlay_path, inline_selected) = if let Some(inline) = inline {
        (inline.clone(), "plugin.json", true)
    } else if tree.contains(".codex-plugin/plugin.json") {
        (
            parse_json(tree.text(".codex-plugin/plugin.json")?)?,
            ".codex-plugin/plugin.json",
            false,
        )
    } else if portable {
        (Value::Object(Map::new()), "plugin.json", false)
    } else {
        return Err(failure("plugin_manifest_missing"));
    };
    let object = overlay
        .as_object()
        .ok_or_else(|| failure("manifest_field_invalid"))?;
    let mut inspection = if portable {
        let mut base = root.as_ref().expect("portable root checked").clone();
        if let Some(extensions) = base.get_mut("extensions").and_then(Value::as_object_mut) {
            extensions.remove("com.openai");
        }
        normalize_portable_components(tree, options, base, false)?
    } else {
        codex_legacy_header(tree, &overlay)?
    };
    inspection.source.format = PluginFormat::Codex;
    inspection.manifest.source_metadata = serde_json::json!({"root_manifest":root,"openai_overlay":overlay,"overlay_source":overlay_path});
    inspection.diagnostics.push(diagnostic(
        "openai_overlay_selected",
        DiagnosticSeverity::Info,
        None,
        Some(overlay_path),
        if inline_selected {
            "The inline OpenAI extension replaces the complete compatibility overlay"
        } else {
            "OpenAI settings use the selected compatibility overlay without merging another overlay"
        },
        None,
    ));
    let metadata_keys = [
        "$schema",
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
    ];
    let settings_keys = [
        "id",
        "interface",
        "apps",
        "hooks",
        "skills",
        "mcpServers",
        "extensions",
    ];
    for key in object.keys() {
        let known = settings_keys.contains(&key.as_str())
            || (!inline_selected && metadata_keys.contains(&key.as_str()))
            || (inline_selected
                && ["onboardingSkill", "review", "publication"].contains(&key.as_str()));
        if !known {
            codex_unmapped(&mut inspection, key, overlay_path);
        }
    }
    optional_string(object, "id", "manifest_field_invalid")?;
    let mut supplemental = Map::new();
    if let Some(extensions) = object.get("extensions") {
        let extensions = extensions
            .as_object()
            .ok_or_else(|| failure("manifest_field_invalid"))?;
        for (namespace, value) in extensions {
            if !valid_namespace(namespace) || !value.is_object() {
                return Err(failure("manifest_field_invalid"));
            }
            if namespace == "com.openai" && !inline_selected {
                for (key, value) in value.as_object().expect("extension object checked") {
                    if ["onboardingSkill", "review", "publication"].contains(&key.as_str()) {
                        supplemental.insert(key.clone(), value.clone());
                    } else {
                        codex_unmapped(&mut inspection, key, overlay_path);
                    }
                }
            } else {
                codex_unmapped(&mut inspection, namespace, overlay_path);
            }
        }
    }
    if let Some(interface) = object.get("interface") {
        codex_interface(tree, &mut inspection, interface, overlay_path)?;
    }
    if portable {
        if object.contains_key("skills") || object.contains_key("mcpServers") {
            inspection.diagnostics.push(diagnostic("portable_component_precedence", DiagnosticSeverity::Info, None, Some(overlay_path),
                "Portable skills and MCP components remain canonical; compatibility component declarations were retained without applying them", None));
        }
        if tree.contains("mcp.json") {
            normalize_codex_portable_mcp(tree, &mut inspection)?;
        }
    } else {
        if let Some(value) = object.get("skills") {
            let mut paths = std::collections::BTreeSet::new();
            for path in declared_paths(value)? {
                collect_skill_directory(tree, &package_path(&path, true)?, true, &mut paths)?;
            }
            for path in paths {
                let parent = path
                    .rsplit_once('/')
                    .map(|(parent, _)| parent)
                    .unwrap_or("");
                normalize_skill(
                    tree,
                    options,
                    &mut inspection,
                    &path,
                    parent.rsplit('/').next().unwrap_or(""),
                )?;
            }
        }
        if let Some(value) = object.get("mcpServers") {
            let mut servers = BTreeMap::new();
            collect_legacy_mcp(tree, &mut inspection, &mut servers, value, overlay_path)?;
            for (name, entry) in servers {
                normalize_codex_legacy_mcp(&mut inspection, &name, entry)?;
            }
        }
    }
    let hook_start = inspection.components.len();
    if let Some(hooks) = object.get("hooks") {
        codex_hooks(tree, &mut inspection, hooks, overlay_path)?;
    } else if tree.contains("hooks/hooks.json") {
        claude_hook_file(tree, &mut inspection, "hooks/hooks.json")?;
    }
    for component in &mut inspection.components[hook_start..] {
        if let ComponentKind::Hook(hook) = &mut component.kind {
            hook.source_contract = "codex".into();
            inspection.requirements.push(Requirement { component_id: Some(component.id.clone()), kind: "hook_trust".into(), name: hook.event.clone(), satisfied: false,
                action: "Review and trust the current source hook definition before execution; installation alone is not hook approval".into() });
        }
    }
    if let Some(apps) = object.get("apps") {
        let path = package_path(
            apps.as_str()
                .ok_or_else(|| failure("manifest_field_invalid"))?,
            false,
        )?;
        let config = parse_json(tree.text(&path)?)?;
        if !config.is_object() && !config.is_array() {
            return Err(failure("manifest_field_invalid"));
        }
        host_adapter_required(&mut inspection, "registered_mcp_mapping", &path);
        inspection.requirements.push(Requirement { component_id: None, kind: "registered_mcp_mapping".into(), name: path, satisfied: false,
            action: "Map each registered app identity to an explicitly configured MCP server and verify the generated adapter".into() });
    }
    let onboarding = if inline_selected {
        object.get("onboardingSkill")
    } else {
        supplemental.get("onboardingSkill")
    };
    if let Some(path) = onboarding {
        let path = package_path(
            path.as_str()
                .ok_or_else(|| failure("component_field_invalid"))?,
            false,
        )?;
        require_path(tree, &path)?;
        let component = inspection.components.iter_mut().find(|component| matches!(&component.kind, ComponentKind::Skill(skill) if skill.entry == path))
            .ok_or_else(|| failure("onboarding_skill_missing"))?;
        component
            .metadata
            .as_object_mut()
            .ok_or_else(|| failure("component_field_invalid"))?
            .insert("onboarding".into(), Value::Bool(true));
        component.compatibility = Compatibility::RequiresMigration;
        inspection.requirements.push(Requirement { component_id: Some(component.id.clone()), kind: "onboarding_skill".into(), name: path, satisfied: false,
            action: "Connect the packaged onboarding skill to the real setup conversation path and verify its invocation".into() });
    }
    for key in ["review", "publication"] {
        let value = if inline_selected {
            object.get(key)
        } else {
            supplemental.get(key)
        };
        if value.is_some_and(|value| !value.is_object()) {
            return Err(failure("manifest_field_invalid"));
        }
    }
    finish_legacy_inspection(inspection)
}

fn codex_legacy_header(tree: &SourceTree, raw: &Value) -> Result<Inspection, CompatError> {
    let object = raw
        .as_object()
        .ok_or_else(|| failure("manifest_field_invalid"))?;
    let name = required_string(object, "name", "manifest_field_invalid")?;
    validate_legacy_id(&name)?;
    for key in [
        "version",
        "description",
        "homepage",
        "repository",
        "license",
    ] {
        optional_string(object, key, "manifest_field_invalid")?;
    }
    optional_list(object, "keywords", "manifest_field_invalid")?;
    if let Some(author) = object.get("author") {
        let author = author
            .as_object()
            .ok_or_else(|| failure("manifest_field_invalid"))?;
        check_keys(author, &["name", "email", "url"], "manifest_field_invalid")?;
        required_string(author, "name", "manifest_field_invalid")?;
        for key in ["email", "url"] {
            optional_string(author, key, "manifest_field_invalid")?;
        }
    }
    let mut inspection = Inspection {
        schema_version: 1,
        source: PluginSource {
            format: PluginFormat::Codex,
            manifest_path: Some(".codex-plugin/plugin.json".into()),
            inferred_name: None,
            source_digest: tree.source_digest.clone(),
            files: tree.files.clone(),
        },
        manifest: PluginManifest {
            id: name.clone(),
            name,
            version: optional_string(object, "version", "manifest_field_invalid")?,
            description: optional_string(object, "description", "manifest_field_invalid")?
                .unwrap_or_default(),
            license: optional_string(object, "license", "manifest_field_invalid")?,
            source_metadata: raw.clone(),
        },
        components: Vec::new(),
        requirements: Vec::new(),
        diagnostics: Vec::new(),
        migration: MigrationPlan::default(),
    };
    inspection.diagnostics.push(diagnostic("inspection_only", DiagnosticSeverity::Info, None, None,
        "Inspection validates declarations and source bytes; plugin behavior and dependencies have not been executed", None));
    if tree.scm_excluded {
        inspection.diagnostics.push(diagnostic("source_scm_excluded", DiagnosticSeverity::Info, None, None,
        "Git control metadata was excluded from the package inventory; all other source entries were inspected", None));
    }
    for key in ["version", "description", "author", "interface"] {
        if !object.contains_key(key) {
            inspection.diagnostics.push(diagnostic("codex_listing_metadata_missing", DiagnosticSeverity::Warning, None, Some(".codex-plugin/plugin.json"),
            "Legacy listing metadata is incomplete; preserved executable declarations still require runtime verification", Some("Complete the source format's listing metadata before distribution")));
        }
    }
    Ok(inspection)
}

fn codex_unmapped(inspection: &mut Inspection, name: &str, path: &str) {
    inspection.diagnostics.push(diagnostic(
        "openai_overlay_field_unmapped",
        DiagnosticSeverity::Error,
        None,
        Some(path),
        "An OpenAI-specific field requires an explicit compatibility mapping",
        Some("Preserve the source declaration and provide its concrete host adapter"),
    ));
    inspection.requirements.push(Requirement {
        component_id: None,
        kind: "openai_overlay_mapping".into(),
        name: name.into(),
        satisfied: false,
        action: "Map this source field explicitly before activation".into(),
    });
}

fn codex_interface(
    tree: &SourceTree,
    inspection: &mut Inspection,
    value: &Value,
    path: &str,
) -> Result<(), CompatError> {
    let object = value
        .as_object()
        .ok_or_else(|| failure("manifest_field_invalid"))?;
    let strings = [
        "displayName",
        "shortDescription",
        "longDescription",
        "developerName",
        "category",
        "websiteURL",
        "supportURL",
        "privacyPolicyURL",
        "termsOfServiceURL",
        "brandColor",
        "brandColorDark",
    ];
    let assets = ["composerIcon", "composerIconDark", "logo", "logoDark"];
    for key in strings {
        optional_string(object, key, "manifest_field_invalid")?;
    }
    for key in ["capabilities", "defaultPrompt"] {
        optional_list(object, key, "manifest_field_invalid")?;
    }
    for key in assets {
        if let Some(asset) = optional_string(object, key, "manifest_field_invalid")? {
            let asset = package_path(&asset, false)?;
            if !tree.contains(&asset) {
                return Err(CompatError::new(
                    "source_component_missing",
                    "A declared presentation asset is missing from the package inventory",
                ));
            }
        }
    }
    if let Some(assets) = optional_list(object, "screenshots", "manifest_field_invalid")? {
        for asset in assets {
            let asset = package_path(&asset, false)?;
            if !tree.contains(&asset) {
                return Err(CompatError::new(
                    "source_component_missing",
                    "A declared presentation asset is missing from the package inventory",
                ));
            }
        }
    }
    for key in object.keys() {
        if !strings.contains(&key.as_str())
            && !assets.contains(&key.as_str())
            && !["capabilities", "defaultPrompt", "screenshots"].contains(&key.as_str())
        {
            codex_unmapped(inspection, key, path);
        }
    }
    Ok(())
}

fn codex_hooks(
    tree: &SourceTree,
    inspection: &mut Inspection,
    value: &Value,
    path: &str,
) -> Result<(), CompatError> {
    match value {
        Value::String(file) => claude_hook_file(tree, inspection, &package_path(file, false)?),
        Value::Array(values) => {
            for value in values {
                codex_hooks(tree, inspection, value, path)?;
            }
            Ok(())
        }
        Value::Object(object) if object.contains_key("hooks") => {
            check_keys(object, &["hooks", "description"], "hook_field_invalid")?;
            let events = object
                .get("hooks")
                .and_then(Value::as_object)
                .ok_or_else(|| failure("hook_field_invalid"))?;
            claude_hook_events(inspection, events, path)
        }
        Value::Object(events) => claude_hook_events(inspection, events, path),
        _ => Err(failure("hook_field_invalid")),
    }
}

fn normalize_codex_legacy_mcp(
    inspection: &mut Inspection,
    name: &str,
    mut entry: LegacyMcpEntry,
) -> Result<(), CompatError> {
    let raw = entry.value.clone();
    let object = entry
        .value
        .as_object_mut()
        .ok_or_else(|| failure("mcp_field_invalid"))?;
    // The Codex compatibility format documents url-only entries as HTTP MCP.
    if !object.contains_key("type") && object.contains_key("url") && !object.contains_key("command")
    {
        object.insert("type".into(), Value::String("http".into()));
    }
    normalize_legacy_mcp_server(inspection, name, entry)?;
    if let Some(component) = inspection.components.last_mut() {
        component.metadata["source_definition"] = raw;
    }
    Ok(())
}

fn normalize_codex_portable_mcp(
    tree: &SourceTree,
    inspection: &mut Inspection,
) -> Result<(), CompatError> {
    let raw = parse_json(tree.text("mcp.json")?)?;
    let object = raw
        .as_object()
        .ok_or_else(|| failure("mcp_field_invalid"))?;
    check_keys(object, &["$schema", "mcpServers"], "mcp_field_invalid")?;
    if object.get("$schema").and_then(Value::as_str) != Some(MCP_SCHEMA) {
        return Err(failure("manifest_schema_invalid"));
    }
    let servers = object
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| failure("mcp_field_invalid"))?;
    let mut seen = BTreeSet::new();
    for (name, value) in servers {
        if !valid_component_name(name) {
            return Err(failure("component_id_invalid"));
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(failure("component_id_collision"));
        }
        let mut normalized = value
            .as_object()
            .ok_or_else(|| failure("mcp_field_invalid"))?
            .clone();
        let extensions = normalized.remove("extensions");
        let mut auth = None;
        let mut unknown = Vec::new();
        if let Some(extensions) = extensions {
            for (namespace, value) in extensions
                .as_object()
                .ok_or_else(|| failure("mcp_field_invalid"))?
            {
                if !valid_namespace(namespace) {
                    return Err(failure("mcp_field_invalid"));
                }
                let fields = value
                    .as_object()
                    .ok_or_else(|| failure("mcp_field_invalid"))?;
                if namespace == "com.openai" {
                    for key in fields.keys() {
                        if key != "auth" {
                            unknown.push(key.clone());
                        }
                    }
                    if let Some(value) = fields.get("auth") {
                        validate_codex_auth(value)?;
                        auth = Some(value.clone());
                    }
                } else {
                    unknown.push(namespace.clone());
                }
            }
        }
        let transport = normalized
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("mcp_field_invalid"))?;
        let allowed = match transport {
            "stdio" => &["type", "command", "args", "env", "cwd"][..],
            "streamable-http" | "sse" => &["type", "url", "headers"][..],
            _ => return Err(failure("mcp_field_invalid")),
        };
        check_keys(&normalized, allowed, "mcp_field_invalid")?;
        if transport == "streamable-http" {
            normalized.insert("type".into(), Value::String("http".into()));
        }
        let start = inspection.components.len();
        normalize_legacy_mcp_server(
            inspection,
            name,
            LegacyMcpEntry {
                value: Value::Object(normalized),
                path: "mcp.json".into(),
                shadowed: Vec::new(),
                from_default: false,
            },
        )?;
        let component = &mut inspection.components[start];
        component.metadata = value.clone();
        if let ComponentKind::Mcp(server) = &mut component.kind
            && let Some(auth) = auth
        {
            let setup_required = auth.get("type").and_then(Value::as_str) != Some("none");
            server.auth = Some(auth);
            if setup_required {
                component.compatibility = Compatibility::RequiresMigration;
                inspection.requirements.push(Requirement { component_id: Some(component.id.clone()), kind: "mcp_auth_setup".into(), name: name.clone(), satisfied: false,
                    action: "Generate and verify the declared OpenAI MCP authentication flow with private connection credentials".into() });
            }
        }
        for field in unknown {
            codex_unmapped(inspection, &field, "mcp.json");
            inspection.components[start].compatibility = Compatibility::RequiresMigration;
        }
    }
    Ok(())
}

fn validate_codex_auth(value: &Value) -> Result<(), CompatError> {
    let object = value
        .as_object()
        .ok_or_else(|| failure("mcp_auth_invalid"))?;
    let kind = required_string(object, "type", "mcp_auth_invalid")?;
    let allowed = match kind.as_str() {
        "none" => &["type"][..],
        "oauth" | "mixed" => &[
            "type",
            "client",
            "authorizationUrl",
            "tokenUrl",
            "registrationUrl",
            "authorizationServerBase",
            "resource",
            "baseScopes",
            "defaultScopes",
            "oidcEnabled",
            "oidcConfigurationUrl",
            "oidcUserinfoEndpoint",
            "oidcScopesSupported",
        ][..],
        "api_key" => &["type", "headerScheme", "headerName"][..],
        _ => return Err(failure("mcp_auth_invalid")),
    };
    check_keys(object, allowed, "mcp_auth_invalid")?;
    if let Some(client) = object.get("client") {
        let client = client
            .as_object()
            .ok_or_else(|| failure("mcp_auth_invalid"))?;
        check_keys(
            client,
            &["mode", "clientId", "tokenEndpointAuthMethod"],
            "mcp_auth_invalid",
        )?;
        let mode = required_string(client, "mode", "mcp_auth_invalid")?;
        match mode.as_str() {
            "provided" => {
                if required_string(client, "clientId", "mcp_auth_invalid")?.is_empty() {
                    return Err(failure("mcp_auth_invalid"));
                }
            }
            "dcr" | "cimd" => {
                if client.contains_key("clientId") || client.contains_key("tokenEndpointAuthMethod")
                {
                    return Err(failure("mcp_auth_invalid"));
                }
            }
            _ => return Err(failure("mcp_auth_invalid")),
        }
        if let Some(method) =
            optional_string(client, "tokenEndpointAuthMethod", "mcp_auth_invalid")?
            && ![
                "none",
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
            ]
            .contains(&method.as_str())
        {
            return Err(failure("mcp_auth_invalid"));
        }
    }
    for field in [
        "authorizationUrl",
        "tokenUrl",
        "registrationUrl",
        "authorizationServerBase",
        "oidcConfigurationUrl",
        "oidcUserinfoEndpoint",
    ] {
        if let Some(endpoint) = optional_string(object, field, "mcp_auth_invalid")? {
            let endpoint = url::Url::parse(&endpoint).map_err(|_| failure("mcp_auth_invalid"))?;
            if !["http", "https"].contains(&endpoint.scheme())
                || endpoint.host_str().is_none()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.fragment().is_some()
            {
                return Err(failure("mcp_auth_invalid"));
            }
        }
    }
    for field in ["baseScopes", "defaultScopes", "oidcScopesSupported"] {
        if let Some(scopes) = optional_list(object, field, "mcp_auth_invalid")?
            && scopes.iter().any(|scope| scope.trim().is_empty())
        {
            return Err(failure("mcp_auth_invalid"));
        }
    }
    optional_bool(object, "oidcEnabled", false).map_err(|_| failure("mcp_auth_invalid"))?;
    optional_string(object, "resource", "mcp_auth_invalid")?;
    if kind == "api_key" {
        let scheme = required_string(object, "headerScheme", "mcp_auth_invalid")?;
        if !["bearer", "basic", "custom_header"].contains(&scheme.as_str()) {
            return Err(failure("mcp_auth_invalid"));
        }
        let header = optional_string(object, "headerName", "mcp_auth_invalid")?;
        if scheme == "custom_header" {
            let header = header.ok_or_else(|| failure("mcp_auth_invalid"))?;
            if !valid_header_name(&header) || header.eq_ignore_ascii_case("Host") {
                return Err(failure("mcp_auth_invalid"));
            }
        } else if header.is_some() {
            return Err(failure("mcp_auth_invalid"));
        }
    }
    Ok(())
}

// Native discovery and dependency precedence follow Hermes's directory loader:
// https://hermes-agent.nousresearch.com/docs/developer-guide/plugins
// Declarations describe registrations; only an activated register(ctx) supplies
// actual handlers. Inspection never imports the entry point to discover them.
fn normalize_hermes(tree: &SourceTree) -> Result<Inspection, CompatError> {
    let manifest_path = ["plugin.yaml", "plugin.yml"]
        .into_iter()
        .find(|path| tree.contains(path))
        .ok_or_else(|| failure("plugin_manifest_missing"))?;
    let raw = crate::frontmatter::parse_yaml_metadata(tree.text(manifest_path)?)?;
    let object = raw.as_object().expect("YAML metadata mapping checked");
    let inferred_name = if object.contains_key("name") {
        None
    } else {
        Some(
            tree.directory_name
                .clone()
                .ok_or_else(|| failure("plugin_id_invalid"))?,
        )
    };
    let name = if let Some(name) = &inferred_name {
        name.clone()
    } else {
        required_string(object, "name", "manifest_field_invalid")?
    };
    validate_legacy_id(&name)?;
    for field in [
        "description",
        "license",
        "homepage",
        "label",
        "requires_hermes",
    ] {
        optional_string(object, field, "manifest_field_invalid")?;
    }
    if let Some(author) = object.get("author")
        && !author.is_string()
        && !author.is_object()
    {
        return Err(failure("manifest_field_invalid"));
    }
    for field in ["tags", "capabilities", "emits", "listens"] {
        optional_list(object, field, "manifest_field_invalid")?;
    }
    let api_version = hermes_api_version(object.get("api_version"))?;
    let manifest_version = hermes_api_version(object.get("manifest_version"))?;
    let (dependencies, python, dependency_source, project) =
        hermes_python_declaration(tree, object, manifest_path)?;
    let mut inspection = Inspection {
        schema_version: 1,
        source: PluginSource {
            format: PluginFormat::Hermes,
            manifest_path: Some(manifest_path.into()),
            inferred_name,
            source_digest: tree.source_digest.clone(),
            files: tree.files.clone(),
        },
        manifest: PluginManifest {
            id: name.clone(),
            name: name.clone(),
            version: hermes_version_label(object.get("version"))?,
            description: optional_string(object, "description", "manifest_field_invalid")?
                .unwrap_or_default(),
            license: optional_string(object, "license", "manifest_field_invalid")?,
            source_metadata: raw.clone(),
        },
        components: Vec::new(),
        requirements: Vec::new(),
        diagnostics: Vec::new(),
        migration: MigrationPlan::default(),
    };
    inspection.diagnostics.push(diagnostic("inspection_only", DiagnosticSeverity::Info, None, None,
        "Inspection preserves native declarations without importing Python or executing registration, dependency checks or installation", None));
    if tree.scm_excluded {
        inspection.diagnostics.push(diagnostic("source_scm_excluded", DiagnosticSeverity::Info, None, None,
            "Git control metadata was excluded from the package inventory; all other source entries were inspected", None));
    }
    if inspection.source.inferred_name.is_some() {
        inspection.diagnostics.push(diagnostic("manifest_inferred", DiagnosticSeverity::Info, None, Some(manifest_path),
            "The native manifest omits its name; identity uses the validated original package directory", None));
    }
    if manifest_version
        .as_deref()
        .is_some_and(|version| !["1", "2"].contains(&version))
    {
        hermes_unmapped(
            &mut inspection,
            "manifest_version",
            "Verify this native manifest generation against the concrete runtime adapter before activation",
        );
    }
    let runtime_id = format!("{name}:python_runtime:register");
    let has_runtime = tree.contains("__init__.py");
    let python_constraint = python.clone();
    if has_runtime {
        push_legacy_component(
            &mut inspection,
            PluginComponent {
                id: runtime_id.clone(),
                source_path: Some("__init__.py".into()),
                compatibility: Compatibility::RequiresMigration,
                kind: ComponentKind::PythonRuntime(PythonRuntimeSpec {
                    entry: "__init__.py".into(),
                    dependencies: dependencies.clone(),
                    python,
                    api_version,
                }),
                metadata: serde_json::json!({"source_manifest":raw,"registration":{"entry":"__init__.py","function":"register","discovered":false},"dependency_source":dependency_source,"pyproject":project}),
            },
        )?;
        inspection.diagnostics.push(diagnostic("hermes_runtime_required", DiagnosticSeverity::Error, Some(&runtime_id), Some("__init__.py"),
            "Native registration has not run; tools, commands, hooks, skills, middleware and provider objects remain undiscovered",
            Some("Activate only through the verified persistent Python bridge, retain real callbacks and verify each requested host contract")));
        inspection.requirements.push(Requirement { component_id: Some(runtime_id.clone()), kind: "python_runtime".into(), name: "register(ctx)".into(), satisfied: false,
            action: "Load this immutable entry point in the isolated persistent runtime after explicit enablement, then bind its actual registrations to ORBIT".into() });
    }
    for dependency in dependencies {
        inspection.requirements.push(Requirement { component_id: has_runtime.then(|| runtime_id.clone()), kind: "python_dependency".into(), name: dependency, satisfied: false,
            action: "Validate the declared requirement and resolve a locked per-plugin environment before activation; inspection does not import or install packages".into() });
    }
    if let Some(constraint) = python_constraint {
        inspection.requirements.push(Requirement { component_id: has_runtime.then(|| runtime_id.clone()), kind: "python_constraint".into(), name: constraint, satisfied: false,
            action: "Resolve and verify an isolated interpreter satisfying the authored Python constraint; this field is not an interpreter executable path".into() });
    }
    if dependency_source == "pyproject.toml" {
        inspection.requirements.push(Requirement { component_id: has_runtime.then(|| runtime_id.clone()), kind: "python_project".into(), name: "pyproject.toml".into(), satisfied: false,
            action: "Validate project metadata and any build backend while preparing the isolated locked environment; do not run a build during inspection".into() });
        if object.contains_key("python_dependencies") || object.contains_key("pip_dependencies") {
            inspection.diagnostics.push(diagnostic("hermes_dependency_precedence", DiagnosticSeverity::Info, None, Some("pyproject.toml"),
                "The authored Python project replaces legacy manifest dependency lists; all original declarations remain preserved", None));
        }
    } else if tree.contains("pyproject.toml") {
        inspection.diagnostics.push(diagnostic("hermes_dependency_precedence", DiagnosticSeverity::Info, None, Some("pyproject.toml"),
            "A legacy dependency-manager project does not replace the source manifest's Python requirements", None));
    }
    for field in ["provides_tools", "provides_hooks", "hooks"] {
        if field == "hooks" && object.contains_key("provides_hooks") {
            inspection.diagnostics.push(diagnostic("hermes_hook_declaration_precedence", DiagnosticSeverity::Info, None, Some(manifest_path),
                "The provides_hooks declaration replaces its legacy hooks alias; both source fields remain preserved", None));
            continue;
        }
        if let Some(names) = optional_list(object, field, "manifest_field_invalid")? {
            let mut seen = BTreeSet::new();
            for declared in names {
                if !valid_component_name(&declared) {
                    return Err(failure("component_id_invalid"));
                }
                if !seen.insert(declared.to_ascii_lowercase()) {
                    return Err(failure("component_id_collision"));
                }
                inspection.requirements.push(Requirement { component_id: has_runtime.then(|| runtime_id.clone()),
                    kind: (if field == "provides_tools" { "runtime_tool" } else { "runtime_hook" }).into(), name: declared, satisfied: false,
                    action: "Discover and verify this declaration through the actual native registration; no callable or tool schema is fabricated from manifest names".into() });
            }
        }
    }
    hermes_environment(&mut inspection, object, "requires_env", true)?;
    hermes_environment(&mut inspection, object, "optional_env", false)?;
    if let Some(external) = object.get("external_dependencies") {
        for entry in external
            .as_array()
            .ok_or_else(|| failure("manifest_field_invalid"))?
        {
            let entry = entry
                .as_object()
                .ok_or_else(|| failure("manifest_field_invalid"))?;
            let dependency = required_string(entry, "name", "manifest_field_invalid")?;
            if dependency.trim().is_empty() || dependency.contains(['\0', '\r', '\n']) {
                return Err(failure("manifest_field_invalid"));
            }
            for field in ["install", "check"] {
                optional_string(entry, field, "manifest_field_invalid")?;
            }
            for field in entry.keys().filter(|field| {
                !["name", "install", "check", "description", "url"].contains(&field.as_str())
            }) {
                hermes_unmapped(
                    &mut inspection,
                    &format!("external_dependencies.{field}"),
                    "Map the additional external-dependency declaration before running its setup or check workflow",
                );
            }
            inspection.requirements.push(Requirement { component_id: has_runtime.then(|| runtime_id.clone()), kind: "external_dependency".into(), name: dependency, satisfied: false,
                action: "Verify the external dependency in the selected runtime; preserved install/check strings are instructions, never commands executed by inspection".into() });
        }
    }
    if let Some(plugins) = object.get("requires_plugins") {
        for dependency in plugins
            .as_array()
            .ok_or_else(|| failure("manifest_field_invalid"))?
        {
            let id = if let Some(id) = dependency.as_str() {
                id.to_owned()
            } else {
                let dependency = dependency
                    .as_object()
                    .ok_or_else(|| failure("manifest_field_invalid"))?;
                optional_string(dependency, "version_range", "manifest_field_invalid")?;
                for field in dependency
                    .keys()
                    .filter(|field| !["id", "version_range"].contains(&field.as_str()))
                {
                    hermes_unmapped(
                        &mut inspection,
                        &format!("requires_plugins.{field}"),
                        "Map the additional plugin-dependency declaration before changing activation or load order",
                    );
                }
                required_string(dependency, "id", "manifest_field_invalid")?
            };
            if !valid_hermes_dependency_reference(&id) {
                return Err(failure("manifest_field_invalid"));
            }
            inspection.requirements.push(Requirement { component_id: has_runtime.then(|| runtime_id.clone()), kind: "plugin_dependency".into(), name: id, satisfied: false,
                action: "Resolve the declared plugin identity and advisory version/load-order constraint before native registration; inspection does not load sibling plugins".into() });
        }
    }
    if let Some(capabilities) = optional_list(object, "capabilities", "manifest_field_invalid")? {
        for capability in capabilities {
            if capability.trim().is_empty() {
                return Err(failure("manifest_field_invalid"));
            }
            inspection.requirements.push(Requirement { component_id: has_runtime.then(|| runtime_id.clone()), kind: "capability_consent".into(), name: capability, satisfied: false,
                action: "Map and approve this concrete host capability without bypassing ORBIT permissions; a manifest declaration grants no authority".into() });
        }
    }
    if let Some(kind) = optional_string(object, "kind", "manifest_field_invalid")?
        && kind != "standalone"
    {
        hermes_unmapped(
            &mut inspection,
            "kind",
            "Provide the declared native backend, exclusive provider or platform lifecycle before activation",
        );
    }
    if object.contains_key("requires_hermes") {
        hermes_unmapped(
            &mut inspection,
            "requires_hermes",
            "Verify the declared Hermes compatibility constraint against the actual adapter capabilities instead of comparing it with the ORBIT version",
        );
    }
    if let Some(runtime) = optional_string(object, "python_runtime", "manifest_field_invalid")? {
        if runtime != "external" {
            return Err(failure("manifest_field_invalid"));
        }
        hermes_unmapped(
            &mut inspection,
            "python_runtime",
            "Provide and verify the plugin-owned external interpreter or sidecar; dependency declarations do not authorize installation into the host environment",
        );
    }
    if let Some(schema) = object.get("config_schema") {
        if !schema.is_object() {
            return Err(failure("manifest_field_invalid"));
        }
        hermes_unmapped(
            &mut inspection,
            "config_schema",
            "Bind and validate this settings schema against private profile-scoped plugin configuration before exposing get_config/set_config",
        );
    }
    let descriptive = [
        "name",
        "version",
        "description",
        "author",
        "license",
        "homepage",
        "label",
        "tags",
        "metadata",
        "notes",
        "documentation",
        "repository",
        "readme",
    ];
    let handled = [
        "manifest_version",
        "api_version",
        "python_dependencies",
        "pip_dependencies",
        "python_runtime",
        "requires_hermes",
        "requires_plugins",
        "requires_env",
        "optional_env",
        "external_dependencies",
        "capabilities",
        "kind",
        "provides_tools",
        "provides_hooks",
        "hooks",
        "config_schema",
    ];
    for field in object.keys() {
        if descriptive.contains(&field.as_str()) || handled.contains(&field.as_str()) {
            continue;
        }
        hermes_unmapped(
            &mut inspection,
            field,
            "Map this preserved native host declaration explicitly, including any runtime, command, memory, UI, middleware, event, locale or provider behavior, before activation",
        );
    }
    for path in [
        "desktop/plugin.js",
        "dashboard/plugin.js",
        "dashboard/plugin_api.py",
    ] {
        if tree.contains(path) {
            host_adapter_required(&mut inspection, path, path);
        }
    }
    if !has_runtime
        && !tree.contains("desktop/plugin.js")
        && !object.contains_key("provides_locales")
    {
        return Err(CompatError::new(
            "source_component_missing",
            "A native plugin requires its Python entry point or an explicitly declared supported host asset",
        ));
    }
    finish_legacy_inspection(inspection)
}

fn hermes_unmapped(inspection: &mut Inspection, field: &str, action: &str) {
    inspection.diagnostics.push(diagnostic(
        "hermes_field_unmapped",
        DiagnosticSeverity::Error,
        None,
        inspection.source.manifest_path.as_deref(),
        "A native source declaration requires an explicit host compatibility mapping",
        Some(action),
    ));
    inspection.requirements.push(Requirement {
        component_id: None,
        kind: "hermes_host_mapping".into(),
        name: field.into(),
        satisfied: false,
        action: action.into(),
    });
}

fn hermes_environment(
    inspection: &mut Inspection,
    object: &Map<String, Value>,
    field: &str,
    required: bool,
) -> Result<(), CompatError> {
    if let Some(values) = object.get(field) {
        for value in values
            .as_array()
            .ok_or_else(|| failure("manifest_field_invalid"))?
        {
            let name = if let Some(name) = value.as_str() {
                name.to_owned()
            } else {
                let value = value
                    .as_object()
                    .ok_or_else(|| failure("manifest_field_invalid"))?;
                for key in ["description", "url"] {
                    optional_string(value, key, "manifest_field_invalid")?;
                }
                optional_bool(value, "secret", true)
                    .map_err(|_| failure("manifest_field_invalid"))?;
                for key in value
                    .keys()
                    .filter(|key| !["name", "description", "url", "secret"].contains(&key.as_str()))
                {
                    hermes_unmapped(
                        inspection,
                        &format!("{field}.{key}"),
                        "Map the additional environment declaration before collecting or exposing any runtime configuration",
                    );
                }
                required_string(value, "name", "manifest_field_invalid")?
            };
            if !valid_env_name(&name) {
                return Err(failure("manifest_field_invalid"));
            }
            if required {
                inspection.requirements.push(Requirement { component_id: None, kind: "credential_env".into(), name, satisfied: false,
                    action: "Provide this declared variable only at authorized runtime launch; inspection does not read its ambient value".into() });
            } else {
                inspection.diagnostics.push(diagnostic("hermes_optional_environment", DiagnosticSeverity::Info, None, inspection.source.manifest_path.as_deref(),
                    "An optional environment declaration was preserved without reading ambient values or making it a required credential", None));
            }
        }
    }
    Ok(())
}

fn hermes_version_label(value: Option<&Value>) -> Result<Option<String>, CompatError> {
    match value {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => Ok(Some(value.to_string())),
        _ => Err(failure("manifest_field_invalid")),
    }
}

fn hermes_api_version(value: Option<&Value>) -> Result<Option<String>, CompatError> {
    let Some(value) = value else { return Ok(None) };
    let number = if let Some(value) = value.as_str() {
        let value = value.trim();
        let decimal = value.strip_prefix('+').unwrap_or(value);
        if decimal.is_empty() || !decimal.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(failure("manifest_field_invalid"));
        }
        let decimal = decimal.trim_start_matches('0');
        if decimal.is_empty() || decimal.len() > 20 {
            return Err(failure("manifest_field_invalid"));
        }
        decimal
            .parse::<u64>()
            .map_err(|_| failure("manifest_field_invalid"))?
    } else {
        value
            .as_u64()
            .ok_or_else(|| failure("manifest_field_invalid"))?
    };
    if number == 0 {
        return Err(failure("manifest_field_invalid"));
    }
    Ok(Some(number.to_string()))
}

fn valid_hermes_dependency_reference(reference: &str) -> bool {
    // A source registry key can be namespace-qualified. Keep it distinct from
    // an installed ORBIT identity and never interpret it as a filesystem path.
    !reference.trim().is_empty()
        && reference.len() <= 256
        && !reference.chars().any(char::is_control)
        && !reference.contains('\\')
        && reference
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

type HermesPythonDeclaration = (Vec<String>, Option<String>, &'static str, Option<Value>);

fn hermes_python_declaration(
    tree: &SourceTree,
    object: &Map<String, Value>,
    manifest_path: &'static str,
) -> Result<HermesPythonDeclaration, CompatError> {
    let project = if tree.contains("pyproject.toml") {
        let text = tree.text("pyproject.toml")?;
        if text.len() > MAX_JSON_BYTES {
            return Err(failure("manifest_size_limit"));
        }
        // Hermes's dependency manager gives its legacy generated project files
        // no precedence over the source manifest's declared requirements.
        if text.contains("GENERATED by pm") {
            None
        } else {
            Some(parse_hermes_project(text)?)
        }
    } else {
        None
    };
    let (mut dependencies, python, source) = if let Some(project) = &project {
        let project = project
            .get("project")
            .map(|project| {
                project
                    .as_object()
                    .ok_or_else(|| failure("manifest_field_invalid"))
            })
            .transpose()?;
        let dependencies = project
            .map(|project| optional_list(project, "dependencies", "manifest_field_invalid"))
            .transpose()?
            .flatten()
            .unwrap_or_default();
        let python = project
            .map(|project| optional_string(project, "requires-python", "manifest_field_invalid"))
            .transpose()?
            .flatten();
        (dependencies, python, "pyproject.toml")
    } else {
        let mut dependencies = Vec::new();
        for field in ["pip_dependencies", "python_dependencies"] {
            dependencies.extend(
                optional_list(object, field, "manifest_field_invalid")?.unwrap_or_default(),
            );
        }
        (dependencies, None, manifest_path)
    };
    if dependencies
        .iter()
        .any(|value| value.trim().is_empty() || value.contains(['\0', '\r', '\n']))
        || python
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.contains(['\0', '\r', '\n']))
    {
        return Err(failure("manifest_field_invalid"));
    }
    let mut seen = BTreeSet::new();
    dependencies.retain(|value| seen.insert(value.clone()));
    Ok((dependencies, python, source, project))
}

fn parse_hermes_project(text: &str) -> Result<Value, CompatError> {
    let parsed: toml::Value = toml::from_str(text.strip_prefix('\u{feff}').unwrap_or(text))
        .map_err(|_| failure("manifest_toml_invalid"))?;
    let mut pending = vec![(&parsed, 0usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_METADATA_NODES || depth > 32 {
            return Err(failure("manifest_structure_limit"));
        }
        match value {
            toml::Value::Table(values) => {
                for (key, value) in values {
                    if key.len() > 64 * 1024 {
                        return Err(failure("manifest_structure_limit"));
                    }
                    pending.push((value, depth + 1));
                }
            }
            toml::Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)))
            }
            toml::Value::String(value) if value.len() > 64 * 1024 => {
                return Err(failure("manifest_structure_limit"));
            }
            _ => {}
        }
    }
    serde_json::to_value(parsed).map_err(|_| failure("manifest_toml_invalid"))
}

fn normalize_claude(
    tree: &SourceTree,
    options: &InspectOptions,
    manifest_path: Option<&str>,
    raw: Value,
) -> Result<Inspection, CompatError> {
    let object = raw
        .as_object()
        .ok_or_else(|| failure("manifest_field_invalid"))?;
    let name = required_string(object, "name", "manifest_field_invalid")?;
    validate_legacy_id(&name)?;
    for key in [
        "$schema",
        "displayName",
        "version",
        "description",
        "homepage",
        "repository",
        "license",
        "icon",
        "documentationUrl",
        "supportUrl",
        "privacyPolicyUrl",
        "termsOfServiceUrl",
    ] {
        optional_string(object, key, "manifest_field_invalid")?;
    }
    optional_list(object, "keywords", "manifest_field_invalid")?;
    if let Some(author) = object.get("author") {
        let author = author
            .as_object()
            .ok_or_else(|| failure("manifest_field_invalid"))?;
        required_string(author, "name", "manifest_field_invalid")?;
        for key in ["email", "url"] {
            optional_string(author, key, "manifest_field_invalid")?;
        }
    }
    if object
        .get("metadata")
        .is_some_and(|value| !value.is_object())
    {
        return Err(failure("manifest_field_invalid"));
    }
    if object
        .get("defaultEnabled")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(failure("manifest_field_invalid"));
    }
    let mut inspection = Inspection {
        schema_version: 1,
        source: PluginSource {
            format: PluginFormat::Claude,
            manifest_path: manifest_path.map(str::to_owned),
            inferred_name: manifest_path.is_none().then(|| name.clone()),
            source_digest: tree.source_digest.clone(),
            files: tree.files.clone(),
        },
        manifest: PluginManifest {
            id: name.clone(),
            name,
            version: optional_string(object, "version", "manifest_field_invalid")?,
            description: optional_string(object, "description", "manifest_field_invalid")?
                .unwrap_or_default(),
            license: optional_string(object, "license", "manifest_field_invalid")?,
            source_metadata: if manifest_path.is_some() {
                raw.clone()
            } else {
                Value::Null
            },
        },
        components: Vec::new(),
        requirements: Vec::new(),
        diagnostics: Vec::new(),
        migration: MigrationPlan::default(),
    };
    if manifest_path.is_none() {
        inspection.diagnostics.push(diagnostic("manifest_inferred", DiagnosticSeverity::Info, None, None,
        "No manifest is present; identity was inferred from the validated source directory name", None));
    }
    let manifest_path = manifest_path.unwrap_or("");
    inspection.diagnostics.push(diagnostic("inspection_only", DiagnosticSeverity::Info, None, None,
        "Inspection validates declarations and source bytes; plugin behavior and dependencies have not been executed", None));
    if tree.scm_excluded {
        inspection.diagnostics.push(diagnostic("source_scm_excluded", DiagnosticSeverity::Info, None, None,
        "Git control metadata was excluded from the package inventory; all other source entries were inspected", None));
    }
    let known = [
        "$schema",
        "name",
        "displayName",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
        "metadata",
        "icon",
        "documentationUrl",
        "supportUrl",
        "privacyPolicyUrl",
        "termsOfServiceUrl",
        "defaultEnabled",
        "dependencies",
        "settings",
        "userConfig",
        "channels",
        "skills",
        "commands",
        "agents",
        "hooks",
        "mcpServers",
        "lspServers",
        "outputStyles",
        "workflows",
        "experimental",
        "themes",
        "monitors",
        "types",
    ];
    for key in object.keys().filter(|key| !known.contains(&key.as_str())) {
        inspection.diagnostics.push(diagnostic(
            "manifest_field_unmapped",
            DiagnosticSeverity::Error,
            None,
            Some(manifest_path),
            "Manifest metadata includes a field without an authority mapping",
            Some("Provide a source-specific mapping before activation"),
        ));
        inspection.requirements.push(Requirement {
            component_id: None,
            kind: "manifest_mapping".into(),
            name: key.clone(),
            satisfied: false,
            action: "Map this preserved source field explicitly before activation".into(),
        });
    }
    if let Some(dependencies) = object.get("dependencies") {
        for dependency in dependencies
            .as_array()
            .ok_or_else(|| failure("manifest_field_invalid"))?
        {
            let name = if let Some(name) = dependency.as_str() {
                name.to_owned()
            } else {
                let dependency = dependency
                    .as_object()
                    .ok_or_else(|| failure("manifest_field_invalid"))?;
                check_keys(
                    dependency,
                    &["name", "marketplace", "version"],
                    "manifest_field_unmapped",
                )?;
                for key in ["marketplace", "version"] {
                    optional_string(dependency, key, "manifest_field_invalid")?;
                }
                required_string(dependency, "name", "manifest_field_invalid")?
            };
            inspection.requirements.push(Requirement { component_id: None, kind: "plugin_dependency".into(), name, satisfied: false,
                action: "Install and enable the exact declared dependency; inspection does not resolve marketplaces".into() });
        }
    }
    let mut skill_paths = std::collections::BTreeSet::new();
    collect_skill_directory(tree, "skills", false, &mut skill_paths)?;
    if let Some(value) = object.get("skills") {
        for path in declared_paths(value)? {
            let path = package_path(&path, true)?;
            collect_skill_directory(tree, &path, true, &mut skill_paths)?;
        }
    }
    for path in skill_paths {
        let parent = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
        let directory_name = parent.rsplit('/').next().unwrap_or("");
        normalize_skill(tree, options, &mut inspection, &path, directory_name)?;
    }
    normalize_claude_commands(
        tree,
        options,
        &mut inspection,
        object.get("commands"),
        manifest_path,
    )?;
    let agents = match object.get("agents") {
        None => flat_markdown(tree, "agents", false, true)?,
        Some(value) => {
            let mut files = Vec::new();
            for path in declared_paths(value)? {
                files.extend(flat_markdown(
                    tree,
                    &package_path(&path, false)?,
                    true,
                    false,
                )?);
            }
            files
        }
    };
    for path in agents {
        normalize_claude_agent(tree, options, &mut inspection, &path)?;
    }
    if tree.contains("hooks/hooks.json") {
        claude_hook_file(tree, &mut inspection, "hooks/hooks.json")?;
    }
    if let Some(value) = object.get("hooks") {
        claude_hook_declaration(tree, &mut inspection, value, manifest_path)?;
    }
    let mut servers = BTreeMap::new();
    if tree.contains(".mcp.json") {
        collect_legacy_mcp_file(tree, &mut inspection, &mut servers, ".mcp.json", true)?;
    }
    if let Some(value) = object.get("mcpServers") {
        collect_legacy_mcp(tree, &mut inspection, &mut servers, value, manifest_path)?;
    }
    for (name, entry) in servers {
        normalize_legacy_mcp_server(&mut inspection, &name, entry)?;
    }
    for (field, default) in [
        ("outputStyles", "output-styles"),
        ("workflows", "workflows"),
        ("themes", "themes"),
    ] {
        match object.get(field) {
            Some(value) => {
                for path in declared_paths(value)? {
                    let path = package_path(&path, false)?;
                    require_path(tree, &path)?;
                    host_adapter_required(&mut inspection, field, &path);
                }
            }
            None if tree.directories.contains(default) => {
                host_adapter_required(&mut inspection, field, default)
            }
            None => {}
        }
    }
    for field in [
        "lspServers",
        "settings",
        "userConfig",
        "channels",
        "monitors",
        "experimental",
        "types",
    ] {
        if let Some(value) = object.get(field) {
            if field == "types" {
                let path = package_path(
                    value
                        .as_str()
                        .ok_or_else(|| failure("manifest_field_invalid"))?,
                    false,
                )?;
                require_path(tree, &path)?;
            }
            if let Value::String(path) = value
                && (field == "lspServers" || field == "monitors")
            {
                require_path(tree, &package_path(path, false)?)?;
            }
            host_adapter_required(&mut inspection, field, manifest_path);
        }
    }
    for path in [".lsp.json", "settings.json", "monitors/monitors.json"] {
        if tree.contains(path) {
            host_adapter_required(&mut inspection, path, path);
        }
    }
    finish_legacy_inspection(inspection)
}

pub(crate) fn validate_legacy_id(name: &str) -> Result<(), CompatError> {
    if !valid_component_name(name)
        || ["orbit", "native", "builtin", "builtins", "mcp"]
            .contains(&name.to_ascii_lowercase().as_str())
    {
        return Err(failure("plugin_id_invalid"));
    }
    Ok(())
}

fn package_path(path: &str, allow_root: bool) -> Result<String, CompatError> {
    if allow_root && (path == "." || path == "./") {
        return Ok(String::new());
    }
    let path = path
        .strip_prefix("./")
        .ok_or_else(|| failure("component_path_invalid"))?
        .trim_end_matches('/');
    if path.is_empty()
        || path.contains(['\\', '\0'])
        || path.bytes().any(|b| b.is_ascii_control())
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part == ".git")
    {
        return Err(failure("component_path_invalid"));
    }
    Ok(path.to_owned())
}

fn declared_paths(value: &Value) -> Result<Vec<String>, CompatError> {
    match value {
        Value::String(path) => Ok(vec![path.clone()]),
        Value::Array(paths) => paths
            .iter()
            .map(|path| {
                path.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| failure("manifest_field_invalid"))
            })
            .collect(),
        _ => Err(failure("manifest_field_invalid")),
    }
}

fn require_path(tree: &SourceTree, path: &str) -> Result<(), CompatError> {
    if tree.contains(path) || tree.directories.contains(path) {
        Ok(())
    } else {
        Err(CompatError::new(
            "source_component_missing",
            "A declared component path is missing from the package inventory",
        ))
    }
}

fn collect_skill_directory(
    tree: &SourceTree,
    directory: &str,
    required: bool,
    output: &mut std::collections::BTreeSet<String>,
) -> Result<(), CompatError> {
    if required && !tree.directories.contains(directory) {
        return Err(CompatError::new(
            "source_component_missing",
            "A declared skill directory is missing from the package inventory",
        ));
    }
    let prefix = if directory.is_empty() {
        String::new()
    } else {
        format!("{directory}/")
    };
    for path in tree.bytes.keys() {
        let Some(relative) = path.strip_prefix(&prefix) else {
            continue;
        };
        let parts: Vec<_> = relative.split('/').collect();
        if relative == "SKILL.md" || (parts.len() == 2 && parts[1] == "SKILL.md") {
            output.insert(path.clone());
        }
    }
    Ok(())
}

fn flat_markdown(
    tree: &SourceTree,
    path: &str,
    required: bool,
    allow_directory: bool,
) -> Result<Vec<String>, CompatError> {
    if tree.contains(path) {
        if !path.ends_with(".md") {
            return Err(failure("component_path_invalid"));
        }
        return Ok(vec![path.to_owned()]);
    }
    if !allow_directory && tree.directories.contains(path) {
        return Err(failure("component_path_invalid"));
    }
    if required {
        require_path(tree, path)?;
    }
    let prefix = format!("{path}/");
    Ok(tree
        .bytes
        .keys()
        .filter(|entry| {
            entry
                .strip_prefix(&prefix)
                .is_some_and(|relative| !relative.contains('/') && relative.ends_with(".md"))
        })
        .cloned()
        .collect())
}

fn claude_tools(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<String>>, CompatError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Value::String(value) = value else {
        let tools = optional_list(object, key, "component_field_invalid")?;
        if tools.as_ref().is_some_and(|tools| {
            tools
                .iter()
                .any(|tool| tool.is_empty() || tool.bytes().any(|b| b.is_ascii_control()))
        }) {
            return Err(failure("component_field_invalid"));
        }
        return Ok(tools);
    };
    let mut tools = Vec::new();
    let mut token = String::new();
    let mut depth = 0usize;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            token.push(character);
            escaped = true;
            continue;
        }
        match character {
            '(' => {
                depth += 1;
                token.push(character);
            }
            ')' => {
                if depth == 0 {
                    return Err(failure("component_field_invalid"));
                }
                depth -= 1;
                token.push(character);
            }
            ',' | ' ' | '\t' | '\n' if depth == 0 => {
                if !token.is_empty() {
                    tools.push(std::mem::take(&mut token));
                }
            }
            c if c.is_control() => return Err(failure("component_field_invalid")),
            c => token.push(c),
        }
    }
    if depth != 0 || escaped {
        return Err(failure("component_field_invalid"));
    }
    if !token.is_empty() {
        tools.push(token);
    }
    Ok(Some(tools))
}

fn mapped_tools(
    object: &Map<String, Value>,
    key: &str,
    options: &InspectOptions,
) -> Result<Option<Vec<String>>, CompatError> {
    let mut tools = claude_tools(object, key)?;
    if let Some(tools) = &mut tools {
        for tool in tools {
            if let Some(mapped) = options.tool_map.get(tool) {
                if mapped.is_empty() || mapped.bytes().any(|b| b.is_ascii_control()) {
                    return Err(failure("component_field_invalid"));
                }
                *tool = mapped.clone();
            }
        }
    }
    Ok(tools)
}

fn mapped_model(
    object: &Map<String, Value>,
    options: &InspectOptions,
    inspection: &mut Inspection,
    id: &str,
) -> Result<Option<String>, CompatError> {
    let Some(model) = optional_string(object, "model", "component_field_invalid")? else {
        return Ok(None);
    };
    if model.is_empty() || model.bytes().any(|b| b.is_ascii_control()) {
        return Err(failure("component_field_invalid"));
    }
    if let Some(mapped) = options.model_map.get(&model) {
        if mapped.is_empty() || mapped.bytes().any(|b| b.is_ascii_control()) {
            return Err(failure("component_field_invalid"));
        }
        return Ok(Some(mapped.clone()));
    }
    if model == "inherit" {
        return Ok(None);
    }
    inspection.requirements.push(Requirement { component_id: Some(id.to_owned()), kind: "model_mapping".into(), name: model.clone(), satisfied: false,
        action: "Provide --model-map SOURCE=TARGET or validate this exact model identity during activation".into() });
    Ok(Some(model))
}

fn checked_effort(object: &Map<String, Value>) -> Result<Option<Value>, CompatError> {
    match object.get("effort") {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(Value::Bool(*value))),
        Some(Value::String(value))
            if !value.is_empty()
                && value.len() <= 64
                && !value.bytes().any(|b| b.is_ascii_control()) =>
        {
            Ok(Some(Value::String(value.clone())))
        }
        _ => Err(failure("component_field_invalid")),
    }
}

fn unknown_component_fields(
    inspection: &mut Inspection,
    object: &Map<String, Value>,
    known: &[&str],
    id: &str,
    path: &str,
) -> Compatibility {
    let mut compatibility = Compatibility::Adapted;
    for key in object.keys().filter(|key| !known.contains(&key.as_str())) {
        compatibility = Compatibility::RequiresMigration;
        inspection.diagnostics.push(diagnostic(
            "component_field_unmapped",
            DiagnosticSeverity::Error,
            Some(id),
            Some(path),
            "Component metadata includes a field without an authority mapping",
            Some("Provide a concrete mapping before enabling this component"),
        ));
        inspection.requirements.push(Requirement {
            component_id: Some(id.into()),
            kind: "component_mapping".into(),
            name: key.clone(),
            satisfied: false,
            action: "Map this preserved source field explicitly before activation".into(),
        });
    }
    compatibility
}

fn normalize_claude_agent(
    tree: &SourceTree,
    options: &InspectOptions,
    inspection: &mut Inspection,
    path: &str,
) -> Result<(), CompatError> {
    let document = crate::parse_frontmatter(tree.text(path)?)?;
    let object = document
        .frontmatter
        .as_object()
        .ok_or_else(|| failure("component_field_invalid"))?;
    let name = required_string(object, "name", "component_field_invalid")?;
    if !valid_component_name(&name) {
        return Err(failure("component_id_invalid"));
    }
    let id = format!("{}:agent:{name}", inspection.manifest.id);
    let description = required_string(object, "description", "component_field_invalid")?;
    optional_string(object, "color", "component_field_invalid")?;
    let compatibility = unknown_component_fields(
        inspection,
        object,
        &[
            "name",
            "description",
            "tools",
            "model",
            "effort",
            "maxTurns",
            "color",
        ],
        &id,
        path,
    );
    let model = mapped_model(object, options, inspection, &id)?;
    let max_turns = object
        .get("maxTurns")
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| failure("component_field_invalid"))
        })
        .transpose()?;
    let spec = AgentSpec {
        name: format!("{}:{name}", inspection.manifest.id),
        description,
        instructions: document.body,
        tools: mapped_tools(object, "tools", options)?,
        model,
        effort: checked_effort(object)?,
        max_turns,
    };
    push_legacy_component(
        inspection,
        PluginComponent {
            id,
            source_path: Some(path.into()),
            compatibility,
            kind: ComponentKind::Agent(spec),
            metadata: document.frontmatter,
        },
    )
}

fn markdown_document(text: &str) -> Result<crate::FrontmatterDocument, CompatError> {
    match crate::parse_frontmatter(text) {
        Err(error) if error.code == "frontmatter_missing" => Ok(crate::FrontmatterDocument {
            frontmatter: Value::Object(Map::new()),
            body: text.trim().to_owned(),
        }),
        result => result,
    }
}

fn normalize_claude_commands(
    tree: &SourceTree,
    options: &InspectOptions,
    inspection: &mut Inspection,
    declaration: Option<&Value>,
    manifest_path: &str,
) -> Result<(), CompatError> {
    match declaration {
        Some(Value::Object(commands)) => {
            for (name, value) in commands {
                let object = value
                    .as_object()
                    .ok_or_else(|| failure("component_field_invalid"))?;
                if object.contains_key("source") == object.contains_key("content") {
                    return Err(failure("component_field_invalid"));
                }
                let (document, path) = if let Some(path) =
                    optional_string(object, "source", "component_field_invalid")?
                {
                    let path = package_path(&path, false)?;
                    if !path.ends_with(".md") {
                        return Err(failure("component_path_invalid"));
                    }
                    let document = markdown_document(tree.text(&path)?)?;
                    (document, Some(path))
                } else {
                    (
                        markdown_document(&required_string(
                            object,
                            "content",
                            "component_field_invalid",
                        )?)?,
                        None,
                    )
                };
                add_claude_command(
                    options,
                    inspection,
                    name,
                    document,
                    path.as_deref().unwrap_or(manifest_path),
                    path.clone(),
                    Some(object),
                )?;
            }
        }
        value => {
            let paths = match value {
                None => flat_markdown(tree, "commands", false, true)?,
                Some(value) => {
                    let mut paths = Vec::new();
                    for path in declared_paths(value)? {
                        paths.extend(flat_markdown(
                            tree,
                            &package_path(&path, false)?,
                            true,
                            true,
                        )?);
                    }
                    paths
                }
            };
            for path in paths {
                let name = path
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .strip_suffix(".md")
                    .unwrap_or("");
                add_claude_command(
                    options,
                    inspection,
                    name,
                    markdown_document(tree.text(&path)?)?,
                    &path,
                    Some(path.clone()),
                    None,
                )?;
            }
        }
    }
    Ok(())
}

fn add_claude_command(
    options: &InspectOptions,
    inspection: &mut Inspection,
    name: &str,
    document: crate::FrontmatterDocument,
    diagnostic_path: &str,
    path: Option<String>,
    overlay: Option<&Map<String, Value>>,
) -> Result<(), CompatError> {
    if !valid_component_name(name) {
        return Err(failure("component_id_invalid"));
    }
    let id = format!("{}:command:{name}", inspection.manifest.id);
    let mut object = document
        .frontmatter
        .as_object()
        .ok_or_else(|| failure("component_field_invalid"))?
        .clone();
    let mut metadata = document.frontmatter.clone();
    if let Some(overlay) = overlay {
        check_keys(
            overlay,
            &[
                "source",
                "content",
                "description",
                "argumentHint",
                "model",
                "allowedTools",
            ],
            "component_field_invalid",
        )?;
        for (source, target) in [
            ("description", "description"),
            ("argumentHint", "argument-hint"),
            ("model", "model"),
            ("allowedTools", "allowed-tools"),
        ] {
            if let Some(value) = overlay.get(source) {
                object.insert(target.into(), value.clone());
            }
        }
        metadata = serde_json::json!({"frontmatter":metadata,"manifest_entry":overlay});
    }
    let compatibility = unknown_component_fields(
        inspection,
        &object,
        &[
            "name",
            "description",
            "argument-hint",
            "allowed-tools",
            "model",
            "effort",
        ],
        &id,
        diagnostic_path,
    );
    let description =
        optional_string(&object, "description", "component_field_invalid")?.unwrap_or_default();
    let spec = CommandSpec {
        name: format!("{}:{name}", inspection.manifest.id),
        description,
        prompt: Some(document.body),
        native_callback: None,
        argument_hint: optional_string(&object, "argument-hint", "component_field_invalid")?,
        allowed_tools: mapped_tools(&object, "allowed-tools", options)?,
        model: mapped_model(&object, options, inspection, &id)?,
        effort: checked_effort(&object)?,
    };
    push_legacy_component(
        inspection,
        PluginComponent {
            id,
            source_path: path,
            compatibility,
            kind: ComponentKind::Command(spec),
            metadata,
        },
    )
}

fn host_adapter_required(inspection: &mut Inspection, capability: &str, path: &str) {
    inspection.diagnostics.push(diagnostic(
        "host_adapter_required",
        DiagnosticSeverity::Error,
        None,
        Some(path),
        "A declared host capability requires a concrete adapter before activation",
        Some("Generate and verify a source-specific host adapter"),
    ));
    inspection.requirements.push(Requirement { component_id: None, kind: "host_adapter".into(), name: capability.into(), satisfied: false,
        action: "Provide a runnable adapter and its conformance check; source assets and declarations remain preserved".into() });
}

fn push_legacy_component(
    inspection: &mut Inspection,
    component: PluginComponent,
) -> Result<(), CompatError> {
    if inspection.components.len() >= 4096 {
        return Err(failure("manifest_structure_limit"));
    }
    inspection.components.push(component);
    Ok(())
}

fn finish_legacy_inspection(mut inspection: Inspection) -> Result<Inspection, CompatError> {
    inspection.components.sort_by(|a, b| a.id.cmp(&b.id));
    let mut identities = std::collections::BTreeSet::new();
    if inspection
        .components
        .iter()
        .any(|component| !identities.insert(component.id.to_ascii_lowercase()))
    {
        return Err(failure("component_id_collision"));
    }
    if inspection.requirements.len() > 8192 || inspection.diagnostics.len() > 8192 {
        return Err(failure("manifest_structure_limit"));
    }
    inspection.migration.requirements = inspection.requirements.clone();
    inspection.migration.diagnostics = inspection
        .diagnostics
        .iter()
        .filter(|d| d.severity == DiagnosticSeverity::Error)
        .cloned()
        .collect();
    Ok(inspection)
}

fn claude_hook_file(
    tree: &SourceTree,
    inspection: &mut Inspection,
    path: &str,
) -> Result<(), CompatError> {
    let raw = parse_json(tree.text(path)?)?;
    let object = raw
        .as_object()
        .ok_or_else(|| failure("hook_field_invalid"))?;
    check_keys(object, &["hooks", "description"], "hook_field_invalid")?;
    optional_string(object, "description", "hook_field_invalid")?;
    let events = object
        .get("hooks")
        .and_then(Value::as_object)
        .ok_or_else(|| failure("hook_field_invalid"))?;
    claude_hook_events(inspection, events, path)
}

fn claude_hook_declaration(
    tree: &SourceTree,
    inspection: &mut Inspection,
    value: &Value,
    path: &str,
) -> Result<(), CompatError> {
    match value {
        Value::String(file) => claude_hook_file(tree, inspection, &package_path(file, false)?),
        Value::Array(values) => {
            for value in values {
                claude_hook_declaration(tree, inspection, value, path)?;
            }
            Ok(())
        }
        Value::Object(events) => claude_hook_events(inspection, events, path),
        _ => Err(failure("hook_field_invalid")),
    }
}

fn claude_hook_events(
    inspection: &mut Inspection,
    events: &Map<String, Value>,
    path: &str,
) -> Result<(), CompatError> {
    for (event, groups) in events {
        if !valid_component_name(event) {
            return Err(failure("hook_field_invalid"));
        }
        let groups = groups
            .as_array()
            .ok_or_else(|| failure("hook_field_invalid"))?;
        for group in groups {
            let group = group
                .as_object()
                .ok_or_else(|| failure("hook_field_invalid"))?;
            let matcher = optional_string(group, "matcher", "hook_field_invalid")?;
            let hooks = group
                .get("hooks")
                .and_then(Value::as_array)
                .ok_or_else(|| failure("hook_field_invalid"))?;
            let mut group_metadata = group.clone();
            group_metadata.remove("hooks");
            for hook in hooks {
                let hook = hook
                    .as_object()
                    .ok_or_else(|| failure("hook_field_invalid"))?;
                if hook.get("type").and_then(Value::as_str) != Some("command") {
                    host_adapter_required(inspection, &format!("hook:{event}"), path);
                    continue;
                }
                let command = required_string(hook, "command", "hook_field_invalid")?;
                if command.is_empty() || command.contains('\0') {
                    return Err(failure("hook_field_invalid"));
                }
                let ordinal = inspection
                    .components
                    .iter()
                    .filter(|component| matches!(component.kind, ComponentKind::Hook(_)))
                    .count();
                let id = format!("{}:hook:{event}:{ordinal}", inspection.manifest.id);
                let timeout_secs = hook
                    .get("timeout")
                    .map(|value| {
                        value
                            .as_u64()
                            .filter(|value| *value > 0)
                            .ok_or_else(|| failure("hook_field_invalid"))
                    })
                    .transpose()?;
                optional_string(hook, "statusMessage", "hook_field_invalid")?;
                for key in ["async", "once", "asyncRewake"] {
                    if hook.get(key).is_some_and(|value| !value.is_boolean()) {
                        return Err(failure("hook_field_invalid"));
                    }
                }
                unknown_component_fields(
                    inspection,
                    hook,
                    &[
                        "type",
                        "command",
                        "timeout",
                        "statusMessage",
                        "async",
                        "once",
                        "asyncRewake",
                    ],
                    &id,
                    path,
                );
                unknown_component_fields(inspection, group, &["matcher", "hooks"], &id, path);
                if ![
                    "SessionStart",
                    "SessionEnd",
                    "UserPromptSubmit",
                    "PreToolUse",
                    "PermissionRequest",
                    "PostToolUse",
                    "PostToolUseFailure",
                    "Notification",
                    "SubagentStart",
                    "SubagentStop",
                    "Stop",
                    "StopFailure",
                    "PreCompact",
                    "PostCompact",
                    "ConfigChange",
                    "WorktreeCreate",
                    "WorktreeRemove",
                    "Setup",
                    "TaskCompleted",
                    "TeammateIdle",
                    "Elicitation",
                    "ElicitationResult",
                    "InstructionsLoaded",
                ]
                .contains(&event.as_str())
                {
                    inspection.diagnostics.push(diagnostic(
                        "hook_event_mapping_required",
                        DiagnosticSeverity::Error,
                        Some(&id),
                        Some(path),
                        "Hook event requires an explicit lifecycle mapping",
                        Some("Provide this source event's real lifecycle adapter"),
                    ));
                }
                inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "hook_protocol".into(), name: event.clone(), satisfied: false,
                    action: "Validate the source hook input, decision output and matching semantics through the runtime adapter before activation".into() });
                push_legacy_component(
                    inspection,
                    PluginComponent {
                        id,
                        source_path: Some(path.into()),
                        compatibility: Compatibility::RequiresMigration,
                        kind: ComponentKind::Hook(HookSpec {
                            event: event.clone(),
                            matcher: matcher.clone(),
                            command: Some(command),
                            native_callback: None,
                            timeout_secs,
                            source_contract: "claude".into(),
                        }),
                        metadata: serde_json::json!({"handler":hook,"group":group_metadata}),
                    },
                )?;
            }
        }
    }
    Ok(())
}

struct LegacyMcpEntry {
    value: Value,
    path: String,
    shadowed: Vec<Value>,
    from_default: bool,
}

fn collect_legacy_mcp_file(
    tree: &SourceTree,
    inspection: &mut Inspection,
    servers: &mut BTreeMap<String, LegacyMcpEntry>,
    path: &str,
    from_default: bool,
) -> Result<(), CompatError> {
    if path.ends_with(".mcpb") || path.ends_with(".dxt") {
        require_path(tree, path)?;
        host_adapter_required(inspection, "mcp_bundle", path);
        return Ok(());
    }
    if !path.ends_with(".json") {
        return Err(failure("component_path_invalid"));
    }
    let raw = parse_json(tree.text(path)?)?;
    let object = raw
        .as_object()
        .ok_or_else(|| failure("mcp_field_invalid"))?;
    check_keys(
        object,
        &["mcpServers", "$schema", "description"],
        "mcp_field_invalid",
    )?;
    let map = object
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| failure("mcp_field_invalid"))?;
    collect_legacy_mcp_map(inspection, servers, map, path, from_default)
}

fn collect_legacy_mcp(
    tree: &SourceTree,
    inspection: &mut Inspection,
    servers: &mut BTreeMap<String, LegacyMcpEntry>,
    value: &Value,
    path: &str,
) -> Result<(), CompatError> {
    match value {
        Value::String(file)
            if file.starts_with("https://")
                && (file.ends_with(".mcpb") || file.ends_with(".dxt")) =>
        {
            host_adapter_required(inspection, "remote_mcp_bundle", path);
            Ok(())
        }
        Value::String(file) => collect_legacy_mcp_file(
            tree,
            inspection,
            servers,
            &package_path(file, false)?,
            false,
        ),
        Value::Array(values) => {
            for value in values {
                collect_legacy_mcp(tree, inspection, servers, value, path)?;
            }
            Ok(())
        }
        Value::Object(map) => collect_legacy_mcp_map(inspection, servers, map, path, false),
        _ => Err(failure("mcp_field_invalid")),
    }
}

fn collect_legacy_mcp_map(
    inspection: &mut Inspection,
    servers: &mut BTreeMap<String, LegacyMcpEntry>,
    map: &Map<String, Value>,
    path: &str,
    from_default: bool,
) -> Result<(), CompatError> {
    for (name, value) in map {
        if !valid_component_name(name) || !value.is_object() {
            return Err(failure("mcp_field_invalid"));
        }
        if servers
            .keys()
            .any(|existing| existing != name && existing.eq_ignore_ascii_case(name))
        {
            return Err(failure("component_id_collision"));
        }
        if let Some(existing) = servers.get_mut(name) {
            if !existing.from_default || from_default {
                return Err(failure("component_id_collision"));
            }
            // Claude explicitly defines ordered replacement at this boundary.
            // Preserve shadowed declarations rather than silently losing them.
            existing
                .shadowed
                .push(serde_json::json!({"source_path":existing.path,"definition":existing.value}));
            existing.value = value.clone();
            existing.path = path.into();
            existing.from_default = false;
            inspection.diagnostics.push(diagnostic("mcp_source_override", DiagnosticSeverity::Info, None, Some(path),
                "A later Claude MCP declaration replaced an earlier same-name server; both source definitions are preserved", None));
        } else {
            servers.insert(
                name.clone(),
                LegacyMcpEntry {
                    value: value.clone(),
                    path: path.into(),
                    shadowed: Vec::new(),
                    from_default,
                },
            );
        }
    }
    Ok(())
}

fn normalize_legacy_mcp_server(
    inspection: &mut Inspection,
    name: &str,
    entry: LegacyMcpEntry,
) -> Result<(), CompatError> {
    let object = entry
        .value
        .as_object()
        .ok_or_else(|| failure("mcp_field_invalid"))?;
    let id = format!("{}:mcp:{name}", inspection.manifest.id);
    let mut compatibility = unknown_component_fields(
        inspection,
        object,
        &[
            "type",
            "command",
            "args",
            "env",
            "cwd",
            "url",
            "headers",
            "auth",
            "oauth",
            "description",
        ],
        &id,
        &entry.path,
    );
    let transport = match object.get("type").and_then(Value::as_str) {
        None if object.contains_key("command") => McpTransport::Stdio,
        Some("stdio") => McpTransport::Stdio,
        Some("http") => McpTransport::StreamableHttp,
        Some("sse") => McpTransport::LegacySse,
        _ => return Err(failure("mcp_field_invalid")),
    };
    let mut spec = McpSpec {
        server_id: name.into(),
        transport,
        command: None,
        args: Vec::new(),
        env: BTreeMap::new(),
        cwd: None,
        url: None,
        headers: BTreeMap::new(),
        auth: None,
    };
    if transport == McpTransport::Stdio {
        if object.contains_key("url") || object.contains_key("headers") {
            return Err(failure("mcp_field_invalid"));
        }
        let command = required_string(object, "command", "mcp_field_invalid")?;
        if command.is_empty() || command.contains(['\0', '\r', '\n']) {
            return Err(failure("mcp_field_invalid"));
        }
        spec.command = Some(command.clone());
        spec.args = optional_list(object, "args", "mcp_field_invalid")?.unwrap_or_default();
        if spec.args.iter().any(|value| value.contains('\0')) {
            return Err(failure("mcp_field_invalid"));
        }
        spec.env = optional_string_map(object, "env")?;
        if spec.env.iter().any(|(key, value)| {
            !valid_env_name(key)
                || [
                    "PLUGIN_ROOT",
                    "PLUGIN_DATA",
                    "CLAUDE_PLUGIN_ROOT",
                    "CLAUDE_PLUGIN_DATA",
                    "CLAUDE_PROJECT_DIR",
                ]
                .contains(&key.as_str())
                || value.contains('\0')
        }) {
            return Err(failure("mcp_field_invalid"));
        }
        spec.cwd = optional_string(object, "cwd", "mcp_field_invalid")?;
        if let Some(cwd) = &spec.cwd {
            validate_cwd(
                &cwd.replace("${CLAUDE_PLUGIN_ROOT}", "${PLUGIN_ROOT}")
                    .replace("${CLAUDE_PLUGIN_DATA}", "${PLUGIN_DATA}"),
            )?;
        }
        inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "executable".into(), name: command, satisfied: false,
            action: "Verify the declared executable and plugin-root expansion during activation; inspection does not search PATH".into() });
    } else {
        if ["command", "args", "env", "cwd"]
            .iter()
            .any(|key| object.contains_key(*key))
        {
            return Err(failure("mcp_field_invalid"));
        }
        let endpoint = required_string(object, "url", "mcp_field_invalid")?;
        let parsed = url::Url::parse(&endpoint).map_err(|_| failure("mcp_url_invalid"))?;
        if !["http", "https"].contains(&parsed.scheme())
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(failure("mcp_url_invalid"));
        }
        spec.url = Some(endpoint);
        spec.headers = optional_string_map(object, "headers")?;
        if spec
            .headers
            .iter()
            .any(|(name, value)| !valid_header_name(name) || value.contains(['\0', '\r', '\n']))
        {
            return Err(failure("mcp_field_invalid"));
        }
        inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "remote_mcp".into(), name: name.into(), satisfied: false,
            action: "Validate transport, endpoint and authentication through the MCP adapter before activation".into() });
    }
    if object.contains_key("auth") && object.contains_key("oauth") {
        return Err(failure("mcp_field_invalid"));
    }
    if let Some(auth) = object.get("auth").or_else(|| object.get("oauth")) {
        if !auth.is_object() {
            return Err(failure("mcp_field_invalid"));
        }
        spec.auth = Some(auth.clone());
        compatibility = Compatibility::RequiresMigration;
        inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "mcp_auth_setup".into(), name: name.into(), satisfied: false,
            action: "Generate and verify the declared authentication setup flow; no credentials are imported by inspection".into() });
    }
    for value in spec.env.values().chain(spec.headers.values()) {
        for variable in environment_references(value) {
            if [
                "CLAUDE_PLUGIN_ROOT",
                "CLAUDE_PLUGIN_DATA",
                "CLAUDE_PROJECT_DIR",
            ]
            .contains(&variable.as_str())
            {
                continue;
            }
            inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "credential_env".into(), name: variable, satisfied: false,
            action: "Provide this variable at authorized launch time; inspection does not read environment values".into() });
        }
    }
    push_legacy_component(
        inspection,
        PluginComponent {
            id,
            source_path: Some(entry.path),
            compatibility,
            kind: ComponentKind::Mcp(spec),
            metadata: serde_json::json!({"source_definition":entry.value,"overridden":entry.shadowed}),
        },
    )
}

fn normalize_skill(
    tree: &SourceTree,
    options: &InspectOptions,
    inspection: &mut Inspection,
    path: &str,
    directory_name: &str,
) -> Result<(), CompatError> {
    let document = crate::parse_frontmatter(tree.text(path)?)?;
    let object = document
        .frontmatter
        .as_object()
        .ok_or_else(|| failure("component_field_invalid"))?;
    let claude = inspection.source.format == PluginFormat::Claude;
    let source_name = if claude {
        optional_string(object, "name", "component_field_invalid")?
            .unwrap_or_else(|| directory_name.to_owned())
    } else {
        required_string(object, "name", "component_field_invalid")?
    };
    if !valid_component_name(&source_name)
        || (!claude && !directory_name.is_empty() && source_name != directory_name)
    {
        return Err(failure("component_id_invalid"));
    }
    let id = format!("{}:skill:{source_name}", inspection.manifest.id);
    let mut compatibility = Compatibility::Adapted;
    for key in object.keys() {
        if ![
            "name",
            "description",
            "version",
            "license",
            "compatibility",
            "metadata",
            "allowed-tools",
            "model",
            "effort",
            "disable-model-invocation",
            "user-invocable",
            "context",
            "agent",
            "argument-hint",
        ]
        .contains(&key.as_str())
        {
            compatibility = Compatibility::RequiresMigration;
            inspection.diagnostics.push(diagnostic(
                "component_field_unmapped",
                DiagnosticSeverity::Error,
                Some(&id),
                Some(path),
                "Component metadata includes a field without an authority mapping",
                Some("Provide a concrete mapping before enabling this component"),
            ));
        }
    }
    let description = required_string(object, "description", "component_field_invalid")?;
    if optional_string(object, "version", "component_field_invalid")?.is_some_and(|value| {
        value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control)
    }) {
        return Err(failure("component_field_invalid"));
    }
    let mut allowed_tools = if matches!(
        inspection.source.format,
        PluginFormat::Claude | PluginFormat::Codex
    ) {
        claude_tools(object, "allowed-tools")?
    } else {
        optional_tools(object, "allowed-tools")?
    };
    if let Some(tools) = allowed_tools.as_mut() {
        if tools
            .iter()
            .any(|tool| tool.is_empty() || tool.bytes().any(|b| b.is_ascii_control()))
        {
            return Err(failure("component_field_invalid"));
        }
        for tool in tools {
            if let Some(mapped) = options.tool_map.get(tool) {
                *tool = mapped.clone();
            }
        }
    }
    let model = if inspection.source.format == PluginFormat::Claude {
        mapped_model(object, options, inspection, &id)?
    } else {
        let declared_model = optional_string(object, "model", "component_field_invalid")?;
        let model = declared_model
            .as_ref()
            .map(|value| options.model_map.get(value).unwrap_or(value).clone());
        if let Some(model) = declared_model.filter(|value| !options.model_map.contains_key(value)) {
            inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "model_mapping".into(), name: model, satisfied: false,
                action: "Provide --model-map SOURCE=TARGET or validate the exact configured model identity during activation".into() });
        }
        model
    };
    let effort = object.get("effort").cloned();
    if effort
        .as_ref()
        .is_some_and(|value| !matches!(value, Value::Bool(_) | Value::String(_)))
    {
        return Err(failure("component_field_invalid"));
    }
    if effort
        .as_ref()
        .and_then(Value::as_str)
        .is_some_and(|value| {
            value.is_empty() || value.len() > 64 || value.bytes().any(|b| b.is_ascii_control())
        })
    {
        return Err(failure("component_field_invalid"));
    }
    let context = optional_string(object, "context", "component_field_invalid")?;
    if context.as_deref().is_some_and(|value| value != "fork") {
        return Err(failure("component_field_invalid"));
    }
    let agent = optional_string(object, "agent", "component_field_invalid")?;
    if object
        .get("metadata")
        .is_some_and(|value| !value.is_object())
    {
        return Err(failure("component_field_invalid"));
    }
    for field in ["license", "compatibility", "argument-hint"] {
        optional_string(object, field, "component_field_invalid")?;
    }
    let spec = SkillSpec {
        name: format!("{}:{source_name}", inspection.manifest.id),
        description,
        body: document.body,
        entry: path.to_owned(),
        allowed_tools,
        model,
        effort,
        disable_model_invocation: optional_bool(object, "disable-model-invocation", false)?,
        user_invocable: optional_bool(object, "user-invocable", true)?,
        context,
        agent,
    };
    inspection.components.push(PluginComponent {
        id,
        source_path: Some(path.to_owned()),
        compatibility,
        kind: ComponentKind::Skill(spec),
        metadata: document.frontmatter,
    });
    Ok(())
}

fn normalize_mcp(tree: &SourceTree, inspection: &mut Inspection) -> Result<(), CompatError> {
    let raw = parse_json(tree.text("mcp.json")?)?;
    let object = raw
        .as_object()
        .ok_or_else(|| failure("mcp_field_invalid"))?;
    check_keys(object, &["$schema", "mcpServers"], "mcp_field_invalid")?;
    if object.get("$schema").and_then(Value::as_str) != Some(MCP_SCHEMA) {
        return Err(failure("manifest_schema_invalid"));
    }
    let servers = object
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| failure("mcp_field_invalid"))?;
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in servers {
        if !valid_component_name(name) || !seen.insert(name.to_ascii_lowercase()) {
            return Err(failure("component_id_invalid"));
        }
        let object = value
            .as_object()
            .ok_or_else(|| failure("mcp_field_invalid"))?;
        let transport = match object.get("type").and_then(Value::as_str) {
            Some("stdio") => McpTransport::Stdio,
            Some("streamable-http") => McpTransport::StreamableHttp,
            Some("sse") => McpTransport::LegacySse,
            _ => return Err(failure("mcp_field_invalid")),
        };
        let allowed = if transport == McpTransport::Stdio {
            &["type", "command", "args", "env", "cwd"][..]
        } else {
            &["type", "url", "headers"][..]
        };
        check_keys(object, allowed, "mcp_field_invalid")?;
        let id = format!("{}:mcp:{name}", inspection.manifest.id);
        let mut spec = McpSpec {
            server_id: name.clone(),
            transport,
            command: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            url: None,
            headers: BTreeMap::new(),
            auth: None,
        };
        if transport == McpTransport::Stdio {
            let command = required_string(object, "command", "mcp_field_invalid")?;
            if command.is_empty() || command.bytes().any(|b| b.is_ascii_control()) {
                return Err(failure("mcp_field_invalid"));
            }
            if command
                .split('/')
                .any(|part| part == ".." || part == ".git")
            {
                return Err(failure("component_path_invalid"));
            }
            spec.command = Some(command.clone());
            spec.args = optional_list(object, "args", "mcp_field_invalid")?.unwrap_or_default();
            if spec.args.iter().any(|value| value.contains('\0')) {
                return Err(failure("mcp_field_invalid"));
            }
            spec.env = optional_string_map(object, "env")?;
            if spec.env.iter().any(|(key, value)| {
                key == "PLUGIN_ROOT"
                    || key == "PLUGIN_DATA"
                    || !valid_env_name(key)
                    || value.contains('\0')
            }) {
                return Err(failure("mcp_field_invalid"));
            }
            spec.cwd = optional_string(object, "cwd", "mcp_field_invalid")?;
            if let Some(cwd) = &spec.cwd {
                validate_cwd(cwd)?;
            }
            inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "executable".into(), name: command, satisfied: false,
                action: "Verify this declared executable with plugin doctor before activation; inspection does not search PATH".into() });
        } else {
            let endpoint = required_string(object, "url", "mcp_field_invalid")?;
            let parsed = url::Url::parse(&endpoint).map_err(|_| failure("mcp_url_invalid"))?;
            if !["http", "https"].contains(&parsed.scheme())
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
            {
                return Err(failure("mcp_url_invalid"));
            }
            spec.url = Some(endpoint);
            spec.headers = optional_string_map(object, "headers")?;
            if spec
                .headers
                .iter()
                .any(|(name, value)| !valid_header_name(name) || value.contains(['\r', '\n', '\0']))
            {
                return Err(failure("mcp_field_invalid"));
            }
            inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "remote_mcp".into(), name: name.clone(), satisfied: false,
                action: "Validate transport, endpoint and authentication through the MCP adapter before activation".into() });
        }
        for value in spec.env.values().chain(spec.headers.values()) {
            for variable in environment_references(value) {
                inspection.requirements.push(Requirement { component_id: Some(id.clone()), kind: "credential_env".into(), name: variable, satisfied: false,
                    action: "Provide this variable at authorized launch time; inspection does not read environment values".into() });
            }
        }
        inspection.components.push(PluginComponent {
            id,
            source_path: Some("mcp.json".into()),
            compatibility: Compatibility::Adapted,
            kind: ComponentKind::Mcp(spec),
            metadata: value.clone(),
        });
    }
    Ok(())
}

fn check_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    code: &'static str,
) -> Result<(), CompatError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(failure(code));
    }
    Ok(())
}

fn required_string(
    object: &Map<String, Value>,
    key: &str,
    code: &'static str,
) -> Result<String, CompatError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| failure(code))
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
    code: &'static str,
) -> Result<Option<String>, CompatError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| failure(code))
        })
        .transpose()
}

fn optional_list(
    object: &Map<String, Value>,
    key: &str,
    code: &'static str,
) -> Result<Option<Vec<String>>, CompatError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| failure(code))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| failure(code))
                })
                .collect()
        })
        .transpose()
}

fn optional_tools(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<String>>, CompatError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(
            value
                .split([',', ' ', '\t', '\n'])
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
        )),
        Some(Value::Array(_)) => optional_list(object, key, "component_field_invalid"),
        _ => Err(failure("component_field_invalid")),
    }
}

fn optional_bool(
    object: &Map<String, Value>,
    key: &str,
    default: bool,
) -> Result<bool, CompatError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| failure("component_field_invalid"))
        })
        .unwrap_or(Ok(default))
}

fn optional_string_map(
    object: &Map<String, Value>,
    key: &str,
) -> Result<BTreeMap<String, String>, CompatError> {
    match object.get(key) {
        None => Ok(BTreeMap::new()),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| {
                Ok((
                    key.clone(),
                    value
                        .as_str()
                        .ok_or_else(|| failure("mcp_field_invalid"))?
                        .to_owned(),
                ))
            })
            .collect(),
        _ => Err(failure("mcp_field_invalid")),
    }
}

fn validate_plugin_id(name: &str) -> Result<(), CompatError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        || name.contains("..")
        || name.contains("--")
        || ["orbit", "native", "builtin", "builtins", "mcp"].contains(&name)
    {
        return Err(failure("plugin_id_invalid"));
    }
    Ok(())
}

fn valid_component_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        && !name.contains("..")
}

fn valid_namespace(name: &str) -> bool {
    name.contains('.')
        && name.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && (name.as_bytes()[0].is_ascii_alphabetic() || name.starts_with('_'))
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn validate_cwd(path: &str) -> Result<(), CompatError> {
    let relative = if path == "${PLUGIN_ROOT}" || path == "${PLUGIN_DATA}" {
        ""
    } else {
        path.strip_prefix("./")
            .or_else(|| path.strip_prefix("${PLUGIN_ROOT}/"))
            .or_else(|| path.strip_prefix("${PLUGIN_DATA}/"))
            .ok_or_else(|| failure("component_path_invalid"))?
    };
    if path.contains(['\\', '\0', '\r', '\n'])
        || relative.starts_with('/')
        || relative
            .split('/')
            .any(|part| part == ".." || part == ".git")
    {
        return Err(failure("component_path_invalid"));
    }
    Ok(())
}

fn environment_references(value: &str) -> Vec<String> {
    let mut variables = Vec::new();
    let mut rest = value;
    while let Some((_, after)) = rest.split_once("${") {
        let Some((name, after)) = after.split_once('}') else {
            break;
        };
        if valid_env_name(name) && !["PLUGIN_ROOT", "PLUGIN_DATA"].contains(&name) {
            variables.push(name.to_owned());
        }
        rest = after;
    }
    variables.sort();
    variables.dedup();
    variables
}

fn diagnostic(
    code: &str,
    severity: DiagnosticSeverity,
    component: Option<&str>,
    path: Option<&str>,
    message: &str,
    action: Option<&str>,
) -> Diagnostic {
    Diagnostic {
        code: code.to_owned(),
        severity,
        component_id: component.map(str::to_owned),
        source_path: path.map(str::to_owned),
        message: message.to_owned(),
        action: action.map(str::to_owned),
    }
}

pub(crate) fn parse_json(text: &str) -> Result<Value, CompatError> {
    if text.len() > MAX_JSON_BYTES {
        return Err(failure("manifest_size_limit"));
    }
    let mut deserializer =
        serde_json::Deserializer::from_str(text.strip_prefix('\u{feff}').unwrap_or(text));
    let value = StrictJson::deserialize(&mut deserializer)
        .map_err(|_| failure("manifest_json_invalid"))?
        .0;
    deserializer
        .end()
        .map_err(|_| failure("manifest_json_invalid"))?;
    let mut pending = vec![(&value, 0usize)];
    let mut nodes = 0;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_METADATA_NODES || depth > 32 {
            return Err(failure("manifest_structure_limit"));
        }
        match value {
            Value::Object(values) => {
                for (key, value) in values {
                    if key.len() > 64 * 1024 {
                        return Err(failure("manifest_structure_limit"));
                    }
                    pending.push((value, depth + 1));
                }
            }
            Value::Array(values) => pending.extend(values.iter().map(|value| (value, depth + 1))),
            Value::String(value) if value.len() > 64 * 1024 => {
                return Err(failure("manifest_structure_limit"));
            }
            _ => {}
        }
    }
    Ok(value)
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = StrictJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON metadata without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::from(value)))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::from(value)))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<StrictJson, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| StrictJson(Value::Number(value)))
                    .ok_or_else(|| E::custom("invalid metadata number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::String(value)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StrictJson, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(StrictJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictJson, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate metadata key"));
                    }
                    let StrictJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(StrictJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

fn failure(code: &'static str) -> CompatError {
    let message = match code {
        "plugin_manifest_missing" => "The selected plugin format has no matching root manifest",
        "plugin_format_ambiguous" => {
            "Competing plugin roots require an explicit --format selection"
        }
        "plugin_format_unavailable" => {
            "The selected source format has no registered inspection adapter"
        }
        "plugin_id_invalid" => {
            "Plugin identity violates its source grammar or uses a reserved namespace"
        }
        "component_id_invalid" => {
            "Component identity is invalid or does not match its declared directory"
        }
        "component_id_collision" => "Component identities collide after case folding",
        "component_field_invalid" => "Component authority metadata has an invalid type or value",
        "component_path_invalid" => {
            "Component path escapes its allowed root or uses reserved metadata"
        }
        "mcp_field_invalid" => "MCP metadata has invalid, unknown or mixed transport fields",
        "mcp_auth_invalid" => "MCP authentication metadata has invalid or unsupported fields",
        "onboarding_skill_missing" => {
            "The declared onboarding skill is not included in the package"
        }
        "hook_field_invalid" => "Hook metadata has invalid fields or executable forms",
        "mcp_url_invalid" => {
            "MCP endpoint must be an HTTP URL without user information or a fragment"
        }
        "manifest_schema_invalid" => {
            "Manifest schema does not match the selected supported version"
        }
        "manifest_json_invalid" => "Manifest JSON is malformed or contains a duplicate key",
        "manifest_toml_invalid" => {
            "Python project metadata is malformed or contains a duplicate key"
        }
        "manifest_size_limit" => "Manifest exceeds the byte limit",
        "manifest_structure_limit" => "Manifest exceeds the nesting, node or scalar limit",
        "manifest_field_unmapped" => {
            "Manifest includes a field requiring an explicit compatibility mapping"
        }
        _ => "Manifest field has an invalid type or value",
    };
    CompatError::new(code, message)
}
