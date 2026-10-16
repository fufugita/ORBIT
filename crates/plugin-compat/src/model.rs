use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginFormat {
    Portable,
    Claude,
    Codex,
    Hermes,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectOptions {
    pub format: Option<PluginFormat>,
    pub model_map: BTreeMap<String, String>,
    pub tool_map: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSource {
    pub format: PluginFormat,
    pub manifest_path: Option<String>,
    #[serde(default)]
    pub inferred_name: Option<String>,
    pub source_digest: String,
    pub files: Vec<SourceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub description: String,
    pub license: Option<String>,
    pub source_metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub schema_version: u32,
    pub source: PluginSource,
    pub manifest: PluginManifest,
    pub components: Vec<PluginComponent>,
    pub requirements: Vec<Requirement>,
    pub diagnostics: Vec<Diagnostic>,
    pub migration: MigrationPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginComponent {
    pub id: String,
    pub source_path: Option<String>,
    pub compatibility: Compatibility,
    pub kind: ComponentKind,
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "spec", rename_all = "snake_case")]
pub enum ComponentKind {
    Skill(SkillSpec),
    Agent(AgentSpec),
    Command(CommandSpec),
    Hook(HookSpec),
    Mcp(McpSpec),
    PythonRuntime(PythonRuntimeSpec),
    MemoryProvider(MemoryProviderSpec),
    PortAsset(PortAssetSpec),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compatibility {
    Exact,
    Adapted,
    RequiresMigration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub component_id: Option<String>,
    pub kind: String,
    pub name: String,
    pub satisfied: bool,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub component_id: Option<String>,
    pub source_path: Option<String>,
    pub message: String,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPlan {
    pub files: Vec<MigrationFile>,
    pub requirements: Vec<Requirement>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationFile {
    pub relative_path: String,
    pub bytes: Vec<u8>,
    pub executable: bool,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSpec {
    pub name: String,
    pub description: String,
    pub body: String,
    pub entry: String,
    pub allowed_tools: Option<Vec<String>>,
    pub model: Option<String>,
    pub effort: Option<Value>,
    pub disable_model_invocation: bool,
    pub user_invocable: bool,
    pub context: Option<String>,
    pub agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub name: String,
    pub description: String,
    pub instructions: String,
    pub tools: Option<Vec<String>>,
    pub model: Option<String>,
    pub effort: Option<Value>,
    pub max_turns: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub name: String,
    pub description: String,
    pub prompt: Option<String>,
    pub native_callback: Option<String>,
    pub argument_hint: Option<String>,
    pub allowed_tools: Option<Vec<String>>,
    pub model: Option<String>,
    pub effort: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookSpec {
    pub event: String,
    pub matcher: Option<String>,
    pub command: Option<String>,
    pub native_callback: Option<String>,
    pub timeout_secs: Option<u64>,
    pub source_contract: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpSpec {
    pub server_id: String,
    pub transport: McpTransport,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub url: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub auth: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    Stdio,
    StreamableHttp,
    LegacySse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonRuntimeSpec {
    pub entry: String,
    pub dependencies: Vec<String>,
    pub python: Option<String>,
    pub api_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryProviderSpec {
    pub runtime_component: String,
    pub provider_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortAssetSpec {
    pub source_capability: String,
    pub generated_entry: String,
    pub conformance_entry: String,
    pub remaining_contract: Value,
}
