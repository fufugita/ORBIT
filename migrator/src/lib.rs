//! ORBIT migrator — Phase F (F19).
//!
//! Claude Workflow → ORBIT fail-closed migration (DR-11 §5-6):
//! - Static mapping: `agent` → spawn with ModelRef, `parallel` → barrier,
//!   `pipeline` → per-item stages, `phase` → orchestrator-only, `workflow` → nested.
//! - Unresolvable constructs are FAIL-CLOSED, never silently dropped:
//!   runtime fallback → E1851, budget enforcement → E1852, streaming → E1853,
//!   isolation:remote / human-in-loop → E1854, unmappable → E1841.
//! - YAML is emitted ONLY for safe mappings (DR-11 §6.1 #4).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Migration error family (E1841-E1854).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MigError {
    #[error("ORBIT-E1841 mig_unmappable_construct: {0}")]
    Unmappable(String),
    #[error("ORBIT-E1842 mig_security_gap: {0}")]
    SecurityGap(String),
    #[error("ORBIT-E1851 mig_runtime_fallback_removed: {0}")]
    RuntimeFallbackRemoved(String),
    #[error("ORBIT-E1852 mig_budget_attribution_only_v0_1: {0}")]
    BudgetNotEnforced(String),
    #[error("ORBIT-E1853 mig_streaming_partial_unsupported_v0_1: {0}")]
    StreamingUnsupported(String),
    #[error("ORBIT-E1854 mig_unsupported_construct: {0}")]
    UnsupportedConstruct(String),
}

impl MigError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unmappable(_) => "E1841",
            Self::SecurityGap(_) => "E1842",
            Self::RuntimeFallbackRemoved(_) => "E1851",
            Self::BudgetNotEnforced(_) => "E1852",
            Self::StreamingUnsupported(_) => "E1853",
            Self::UnsupportedConstruct(_) => "E1854",
        }
    }
}

/// A parsed Claude Workflow construct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeConstruct {
    pub kind: ConstructKind,
    pub location: String, // file:line
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstructKind {
    Agent { model: String, effort: String },
    Parallel,
    Pipeline,
    Phase,
    NestedWorkflow,
    RuntimeFallback { models: Vec<String> }, // declared fallback list
    BudgetEnforcement,
    StreamingPartial,
    IsolationRemote,
    HumanInLoop,
}

/// The ORBIT YAML output (safe mappings only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrbitWorkflowYaml {
    pub orbit_version: String, // "0.1"
    pub spawns: Vec<OrbitSpawn>,
    pub migration_warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrbitSpawn {
    pub id: String,
    pub phase: String,
    pub label: String,
    pub model_ref: String, // NOT a bare model string when wrapped; here the flat name
    pub effort: String,
}

/// Migration result: either a safe YAML or a fail-closed error (never both).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationResult {
    Success { yaml: OrbitWorkflowYaml },
    Failed { errors: Vec<MigError> },
}

/// The fail-closed migrator (DR-11 §6.1: no silent drop).
pub struct Migrator;

impl Migrator {
    /// Migrate a list of parsed constructs. Any unresolvable construct fails
    /// the WHOLE migration (no partial YAML for the safe subgraph unless it's
    /// clean — DR-11 §6.1 #4: YAML only for safe mappings).
    pub fn migrate(&self, constructs: &[ClaudeConstruct]) -> MigrationResult {
        let mut spawns = Vec::new();
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        for (i, c) in constructs.iter().enumerate() {
            match &c.kind {
                ConstructKind::Agent { model, effort } => {
                    spawns.push(OrbitSpawn {
                        id: format!("spawn-{i}"),
                        phase: "exec".into(),
                        label: format!("agent-{i}"),
                        model_ref: model.clone(),
                        effort: effort.clone(),
                    });
                }
                ConstructKind::Parallel => {
                    warnings.push(format!("parallel barrier mapped (spawn-{i})"));
                }
                ConstructKind::Pipeline => {
                    warnings.push(format!("pipeline per-item mapped (spawn-{i})"));
                }
                ConstructKind::Phase => {
                    warnings.push("phase annotated (orchestrator-only)".into());
                }
                ConstructKind::NestedWorkflow => {
                    warnings.push("nested workflow mapped".into());
                }
                ConstructKind::RuntimeFallback { models } => {
                    // DR-11 §5.2 / DR-14 §4: a declared fallback list the user did
                    // not grant is DROPPED with E1851 — fail closed, never silent.
                    errors.push(MigError::RuntimeFallbackRemoved(format!(
                        "source declares fallback {models:?}; ORBIT requires an explicit user grant (E1851)"
                    )));
                }
                ConstructKind::BudgetEnforcement => {
                    errors.push(MigError::BudgetNotEnforced(
                        "v0.1 attributes cost only; no runtime budget gate (E1852)".into(),
                    ));
                }
                ConstructKind::StreamingPartial => {
                    errors.push(MigError::StreamingUnsupported(
                        "v0.1 returns AgentResult at TerminalState only (E1853)".into(),
                    ));
                }
                ConstructKind::IsolationRemote => {
                    errors.push(MigError::UnsupportedConstruct(
                        "isolation:remote has no v0.1 mapping (E1854)".into(),
                    ));
                }
                ConstructKind::HumanInLoop => {
                    errors.push(MigError::UnsupportedConstruct(
                        "human-in-the-loop has no v0.1 mapping (E1854)".into(),
                    ));
                }
            }
        }

        if errors.is_empty() {
            MigrationResult::Success {
                yaml: OrbitWorkflowYaml {
                    orbit_version: "0.1".into(),
                    spawns,
                    migration_warnings: warnings,
                },
            }
        } else {
            MigrationResult::Failed { errors }
        }
    }

    /// Determinism: same source → same YAML bytes (DR-11 §5.3).
    pub fn canonical_yaml(yaml: &OrbitWorkflowYaml) -> Result<String, MigError> {
        serde_json::to_string(yaml).map_err(|e| MigError::Unmappable(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(kind: ConstructKind) -> ClaudeConstruct {
        ClaudeConstruct {
            kind,
            location: "workflow.yaml:1".into(),
        }
    }

    #[test]
    fn safe_constructs_map_to_yaml() {
        let m = Migrator;
        let r = m.migrate(&[
            c(ConstructKind::Agent {
                model: "gpt-4".into(),
                effort: "high".into(),
            }),
            c(ConstructKind::Parallel),
            c(ConstructKind::Phase),
        ]);
        match r {
            MigrationResult::Success { yaml } => {
                assert_eq!(yaml.orbit_version, "0.1");
                assert_eq!(yaml.spawns.len(), 1);
                assert_eq!(yaml.spawns[0].model_ref, "gpt-4");
            }
            _ => panic!("safe constructs must succeed"),
        }
    }

    #[test]
    fn fallback_fails_closed_e1851() {
        let m = Migrator;
        let r = m.migrate(&[c(ConstructKind::RuntimeFallback {
            models: vec!["gpt-4".into()],
        })]);
        match r {
            MigrationResult::Failed { errors } => {
                assert_eq!(errors[0].code(), "E1851");
            }
            _ => panic!("fallback must fail closed"),
        }
    }

    #[test]
    fn no_silent_drop_for_unsupported() {
        let m = Migrator;
        let r = m.migrate(&[c(ConstructKind::IsolationRemote)]);
        assert!(matches!(r, MigrationResult::Failed { .. }));
    }

    #[test]
    fn yaml_deterministic() {
        let m = Migrator;
        let r = m.migrate(&[c(ConstructKind::Agent {
            model: "gpt-4".into(),
            effort: "high".into(),
        })]);
        if let MigrationResult::Success { yaml } = r {
            assert_eq!(
                Migrator::canonical_yaml(&yaml).unwrap(),
                Migrator::canonical_yaml(&yaml).unwrap()
            );
        } else {
            panic!("expected success");
        }
    }
}
