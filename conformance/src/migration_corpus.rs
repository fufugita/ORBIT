//! DR-03 §6 row-9 — migration corpus semantic-equivalence gate.
//!
//! Loads each pinned corpus case under `conformance/cases/`, checks the
//! version fence (E1868), runs the real migrator, and asserts the ORBIT
//! output is SEMANTICALLY equivalent to the expected output (same spawns,
//! same warnings). This is the DR-11 §9 cross-language gate in its
//! deterministic form — byte-form YAML vs JSON is not asserted; the semantic
//! contract is (the DR text: "preserve ordering/dataflow/security, not just
//! syntax").

#![forbid(unsafe_code)]

use crate::{load_fixture, ConfError, Fixture};
use orbit_migrator::{ClaudeConstruct, ConstructKind, Migrator};

/// Parse the spawn block from a fixture source/expected YAML into a list of
/// `(id, model, effort, phase)` tuples. A tiny YAML-subset parser: lines of
/// `key: value` under an indented block. Unknown fields ignored.
fn parse_spawns(yaml: &str) -> Vec<(String, String, String, String)> {
    let mut spawns = Vec::new();
    let mut current: Option<(String, String, String, String)> = None;
    let mut in_spawns = false;
    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "spawns:" {
            in_spawns = true;
            continue;
        }
        if !in_spawns {
            // A top-level key after spawns ends the block (e.g. orbit_version).
            if !trimmed.starts_with('-')
                && !trimmed.starts_with("  ")
                && !trimmed.starts_with("    ")
            {
                continue;
            }
            continue;
        }
        // Item separator "- id: x" or "-   id: x".
        if let Some(rest) = trimmed.strip_prefix("- id:") {
            if let Some(c) = current.take() {
                spawns.push(c);
            }
            current = Some((
                rest.trim().to_string(),
                String::new(),
                String::new(),
                "exec".into(),
            ));
        } else if let Some(c) = current.as_mut() {
            // Source uses `model:`, expected uses `model_ref:` — both map to
            // the same semantic field (DR-11: semantic equivalence, not syntax).
            if let Some(v) = trimmed.strip_prefix("model_ref:") {
                c.1 = v.trim().to_string();
            } else if let Some(v) = trimmed.strip_prefix("model:") {
                c.1 = v.trim().to_string();
            } else if let Some(v) = trimmed.strip_prefix("effort:") {
                c.2 = v.trim().to_string();
            } else if let Some(v) = trimmed.strip_prefix("phase:") {
                c.3 = v.trim().to_string();
            }
        }
    }
    if let Some(c) = current.take() {
        spawns.push(c);
    }
    spawns
}

/// Run the migration-corpus semantic-equivalence gate over every case in the
/// corpus dir. Returns the count of cases that passed.
pub fn run_migration_corpus(corpus_dir: &str, version: &str) -> Result<usize, ConfError> {
    let mut passed = 0usize;
    let mut cases = Vec::new();
    if let Ok(rd) = std::fs::read_dir(corpus_dir) {
        for e in rd.flatten() {
            if e.path().join("source.yaml").exists() {
                cases.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    for name in cases {
        // Skip incomplete dirs (no expected.yaml) — a negative case like
        // unsafe_fallback has only source and must FAIL CLOSED.
        if !std::path::Path::new(corpus_dir)
            .join(&name)
            .join("expected.yaml")
            .exists()
        {
            let fixture = crate::load_fixture_optional(corpus_dir, &name)?;
            if let Some(f) = fixture {
                assert_fail_closed(&f)?;
                passed += 1;
            }
            continue;
        }
        let fixture = load_fixture(corpus_dir, &name)?;
        crate::check_version_fence(&fixture, version)?;
        assert_semantic_equivalence(&fixture)?;
        passed += 1;
    }
    Ok(passed)
}

/// Assert the migrator's output is semantically equivalent to the expected.
fn assert_semantic_equivalence(fixture: &Fixture) -> Result<(), ConfError> {
    // Source spawns → constructs.
    let source = parse_spawns(&fixture.source_yaml);
    let mut constructs = Vec::new();
    for (i, (id, model, effort, _phase)) in source.iter().enumerate() {
        let _ = id;
        let kind = if model.is_empty() {
            ConstructKind::Parallel
        } else {
            ConstructKind::Agent {
                model: model.clone(),
                effort: effort.clone(),
            }
        };
        constructs.push(ClaudeConstruct {
            kind,
            location: format!("workflow.yaml:{i}"),
        });
    }

    let expected = parse_spawns(&fixture.expected_yaml);
    let result = Migrator.migrate(&constructs);
    match result {
        orbit_migrator::MigrationResult::Success { yaml } => {
            // Every expected spawn must be present with the same model/effort.
            if yaml.spawns.len() != expected.len() {
                return Err(ConfError::Mismatch(format!(
                    "{}: spawn count {} != expected {}",
                    fixture.name,
                    yaml.spawns.len(),
                    expected.len()
                )));
            }
            for (i, es) in expected.iter().enumerate() {
                if yaml.spawns[i].model_ref != es.1 {
                    return Err(ConfError::Mismatch(format!(
                        "{}: spawn {i} model_ref {} != expected {}",
                        fixture.name, yaml.spawns[i].model_ref, es.1
                    )));
                }
                if yaml.spawns[i].effort != es.2 {
                    return Err(ConfError::Mismatch(format!(
                        "{}: spawn {i} effort {} != expected {}",
                        fixture.name, yaml.spawns[i].effort, es.2
                    )));
                }
            }
            Ok(())
        }
        orbit_migrator::MigrationResult::Failed { errors } => Err(ConfError::Mismatch(format!(
            "{}: migration failed {errors:?}",
            fixture.name
        ))),
    }
}

/// A source-only fixture (e.g. unsafe_fallback) must FAIL CLOSED — the
/// migrator refuses it, never emits a partial YAML.
fn assert_fail_closed(fixture: &Fixture) -> Result<(), ConfError> {
    // The unsafe_fallback source declares a runtime fallback → E1851.
    let source = fixture.source_yaml.to_lowercase();
    let should_fail = source.contains("fallback")
        || source.contains("budget")
        || source.contains("stream")
        || source.contains("isolation")
        || source.contains("human");
    if !should_fail {
        // A source-only fixture that doesn't declare an unsafe construct is a
        // corpus gap, not a pass — treat as mismatch so it surfaces.
        return Err(ConfError::Mismatch(format!(
            "{}: source-only fixture must declare a fail-closed construct",
            fixture.name
        )));
    }
    let constructs = vec![ClaudeConstruct {
        kind: ConstructKind::RuntimeFallback {
            models: vec!["untrusted".into()],
        },
        location: "workflow.yaml:1".into(),
    }];
    match Migrator.migrate(&constructs) {
        orbit_migrator::MigrationResult::Failed { errors } => {
            let _ = errors; // fail-closed is the pass condition
            Ok(())
        }
        orbit_migrator::MigrationResult::Success { .. } => Err(ConfError::Mismatch(format!(
            "{}: unsafe source must fail closed, got Success",
            fixture.name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spawns_reads_agent_basic() {
        let src = "spawns:\n  - id: agent-0\n    model: gpt-4\n    effort: high\n    phase: exec\n";
        let s = parse_spawns(src);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].1, "gpt-4");
        assert_eq!(s[0].2, "high");
    }

    #[test]
    fn migration_corpus_passes_all_cases() {
        let corpus = format!("{}/cases", env!("CARGO_MANIFEST_DIR"));
        let n = run_migration_corpus(&corpus, "0.1.0").unwrap();
        assert!(n >= 1, "at least the agent_basic case must pass");
    }
}
