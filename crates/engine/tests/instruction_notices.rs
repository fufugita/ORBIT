//! An instruction file the cap cuts, or whose link leads somewhere it may not, is named to the
//! operator once, and the prompt itself says where it was cut. One test: the notice is
//! process-wide and told once.

#![deny(unsafe_code)]

use orbit_engine::context::build_system_prompt_for;
use orbit_engine::hooks::take_hook_problems;
use std::path::Path;

fn prompt(home: &Path, project: &Path, claude: &Path) -> String {
    build_system_prompt_for(home, project, "m", &[], "", Some(claude)).text
}

#[test]
fn a_cut_instruction_file_is_named_once_and_marked_in_the_prompt() {
    let root =
        std::env::temp_dir().join(format!("orbit-instruction-notices-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (home, project, claude) = (root.join("home"), root.join("project"), root.join("claude"));
    for dir in [&home, &project, &claude] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let long: String = (1..=300).map(|n| format!("rule {n}\n")).collect();
    let claude_file = claude.join("CLAUDE.md");
    std::fs::write(&claude_file, &long).unwrap();
    std::fs::write(project.join("AGENTS.md"), "short, and it imports @big.md\n").unwrap();
    std::fs::write(project.join("big.md"), &long).unwrap();
    std::fs::create_dir_all(project.join(".claude/rules")).unwrap();
    std::fs::write(project.join(".claude/rules/long.md"), &long).unwrap();
    std::fs::write(
        project.join(".claude/rules/scoped.md"),
        format!("---\npaths:\n  - \"src/**/*.rs\"\n---\n{long}"),
    )
    .unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/a.rs"), "x").unwrap();
    std::fs::write(home.join("ORBIT.md"), format!("{}\n", "y".repeat(40_000))).unwrap();

    let _ = take_hook_problems();
    let text = prompt(&home, &project, &claude_file);
    assert!(text.contains("(truncated at 200 lines)") && text.contains("(truncated at 25 KB)"));
    assert!(text.contains("rule 200") && !text.contains("rule 201"));
    let problems = take_hook_problems();
    let about = |needle: &str| problems.iter().filter(|p| p.contains(needle)).count();
    assert_eq!(about(&claude_file.display().to_string()), 1, "{problems:?}");
    assert_eq!(
        about(&home.join("ORBIT.md").display().to_string()),
        1,
        "{problems:?}"
    );
    assert_eq!(
        about("AGENTS.md"),
        0,
        "a file that fits is not mentioned: {problems:?}"
    );
    let told = problems.iter().find(|p| p.contains("CLAUDE.md")).unwrap();
    assert!(told.contains("300") && told.contains("200"), "{told}");
    // What a file imports and the rules are held to the same cap, and named the same way.
    assert_eq!(about("big.md"), 1, "an import: {problems:?}");
    assert_eq!(about("long.md"), 1, "a rule: {problems:?}");
    // A path-scoped rule is cut when it is delivered, with the first read of a matching file.
    let delivered = orbit_engine::context::scoped_rules_for(&project, &project.join("src/a.rs"));
    assert_eq!(delivered.len(), 1);
    assert!(delivered[0].1.contains("(truncated at 200 lines)"));
    let later = take_hook_problems();
    assert!(later.iter().any(|p| p.contains("scoped.md")), "{later:?}");

    // The prompt is built again (a model switch, a resume): the operator is not told again.
    let _ = prompt(&home, &project, &claude_file);
    assert!(take_hook_problems().is_empty(), "told once per file");
    let _ = orbit_engine::context::scoped_rules_for(&project, &project.join("src/a.rs"));
    assert!(take_hook_problems().is_empty(), "and the rule once as well");

    // A file whose link leads to a key, or out of the project, is not read, and the operator is
    // told which file and why, once. A cloned repository can ship any link.
    #[cfg(unix)]
    {
        let hostile = root.join("hostile");
        std::fs::create_dir_all(hostile.join(".claude/rules")).unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/id_rsa_made_up"), "MADE-UP KEY\n").unwrap();
        std::fs::write(root.join("outside/notes.md"), "OUTSIDE NOTES\n").unwrap();
        std::os::unix::fs::symlink("../outside/id_rsa_made_up", hostile.join("AGENTS.md")).unwrap();
        std::os::unix::fs::symlink("../outside/notes.md", hostile.join("CLAUDE.md")).unwrap();
        std::os::unix::fs::symlink(
            "../../../outside/notes.md",
            hostile.join(".claude/rules/shared.md"),
        )
        .unwrap();
        let text = prompt(&home, &hostile, &claude_file);
        assert!(
            !text.contains("MADE-UP KEY") && !text.contains("OUTSIDE NOTES"),
            "none of it reaches the prompt"
        );
        let refusals = take_hook_problems();
        let told = |name: &str, why: &str| {
            refusals
                .iter()
                .filter(|p| p.contains(&format!("hostile/{name} is not read")) && p.contains(why))
                .count()
        };
        assert_eq!(told("AGENTS.md", "deny-read"), 1, "{refusals:?}");
        assert_eq!(told("CLAUDE.md", "outside the project"), 1, "{refusals:?}");
        assert_eq!(
            told(".claude/rules/shared.md", "outside the project"),
            1,
            "{refusals:?}"
        );
        let _ = prompt(&home, &hostile, &claude_file);
        assert!(take_hook_problems().is_empty(), "told once per file");

        // A path-scoped rule that leads out of the project is refused when its text would be
        // delivered, and the operator is told even in a process that never built the prompt (a
        // resumed session keeps the prompt it had).
        let scoped = root.join("hostile-scoped");
        std::fs::create_dir_all(scoped.join(".claude/rules")).unwrap();
        std::fs::create_dir_all(scoped.join("src")).unwrap();
        std::fs::write(scoped.join("src/a.rs"), "x").unwrap();
        std::fs::write(
            root.join("outside/scoped-rule.md"),
            "---\npaths: [\"src/**\"]\n---\nOUTSIDE SCOPED RULE\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../../../outside/scoped-rule.md",
            scoped.join(".claude/rules/scoped.md"),
        )
        .unwrap();
        let delivered = orbit_engine::context::scoped_rules_for(&scoped, &scoped.join("src/a.rs"));
        assert!(delivered.is_empty(), "{delivered:?}");
        let told = take_hook_problems();
        assert!(
            told.iter().any(
                |p| p.contains("hostile-scoped/.claude/rules/scoped.md is not read")
                    && p.contains("outside the project")
            ),
            "{told:?}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
