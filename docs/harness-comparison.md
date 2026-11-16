# CLI harness comparison

This comparison used REA 6.8.0 to inspect installed executable artifacts and
capture their actual help and version output on 15 November 2026:

| Harness | Observed version |
| --- | --- |
| Claude Code | 2.1.325 |
| Codex CLI | 0.162.1 |
| OpenCode | 1.19.3 |

The captures ran with empty private homes and working directories, a minimal
environment, and network access denied. All help/version commands exited
successfully and terminal output was retained completely. REA verified cleanup.
Codex's filesystem snapshots were partial because generated symlinks were not
followed; that limitation does not establish complete filesystem behavior.

Competitor capabilities below are advertised by those captured executables.
Authenticated model workflows were not exercised. ORBIT comparisons come from
its implementation, rather than assuming a feature is absent from a help page.
File-permission semantics were additionally checked against the linked official
Claude Code documentation; the help captures alone do not establish them.

## QOL improvements in this release

- Shell completion emits a directly sourceable script by default; `--json`
  retains structured output. Zsh registers its handler after `compinit`.
- Human help exposes supported permission modes, tool rules, worktrees,
  fallback models, channels and settings controls.
- `orbit migrate --from claude` performs a read-only readiness assessment with
  permission portability, configuration validation and actionable next steps.
- Offline doctor can inspect a read-only credential store and reports partial
  cache counts when traversal reaches a bound.
- Subtree permission patterns retain their directory boundary: `/src/**`
  does not match a sibling such as `/src-backup/file`.
- Permission import withholds incompatible file-tool rules and refuses to
  apply a batch that contains an untranslated ask or deny rule.
- Task/Agent aliases share permission rules. Configured confirmations and
  pinned tool scopes apply before a subagent can launch.

## Useful remaining additions

| Priority | Improvement | Benefit | Existing ORBIT foundation |
| --- | --- | --- | --- |
| 1 | Compatible filesystem permission selectors | Claude's [file rules](https://code.claude.com/docs/en/permissions#read-and-edit) distinguish path anchors and check requested and resolved paths. | ORBIT matches native tool argument patterns; filesystem confinement is separate. Read/Edit rules remain excluded from automatic migration. Compatibility needs explicit path and tool-group semantics. |
| 2 | Initial prompt when opening an interactive session | Claude and Codex accept a prompt on startup. ORBIT currently accepts the prompt after interactive startup or through headless `-p`. | Interactive turn handling; add a clearly defined initial-prompt argument without changing unknown-command errors. |
| 3 | Offline session listing and naming | Find and organize work before starting a model session, as competitor session commands allow. | Session listing, `/sessions`, `/rename` and display-name storage. Start with shell listing and names; preserve accounting records. |
| 4 | Background launch and attachment by ID or name | Claude exposes direct background launch, listing, logs and stop controls. | Existing `serve`/`attach` ownership protocol; add managed discovery and launch ergonomics. |
| 5 | Rich mode that preserves shell scrollback | Codex offers `--no-alt-screen`; OpenCode advertises a minimal interface and replay controls. | Plain `--no-tui` is a partial substitute; the rich interface uses an alternate screen. |
| 6 | Optional strict configuration diagnostics | Detect misspelled provider and routing keys before defaults hide mistakes. Codex advertises `--strict-config`. | Extend offline doctor with exact unknown-key paths while preserving forward compatibility. |

Argument-aware completion of flags and nested commands would also improve
daily use. Current completion intentionally covers command verbs.

ORBIT already implements `/find` conversation search, `/recap`, 33 hook events,
worktrees, custom commands, background tools, MCP/OAuth/channels/skills and
structured headless output. These are not missing features. See the
[compatibility inventory](claude-code-parity.md) and
[migration guide](migration.md) for their supported scope and limits.

REA authenticated the executable bytes and captured CLI behavior. Native
decompilation was unavailable because a supported native analysis engine was
not configured. This comparison makes no claim about recovered competitor
functions, internal architecture, or complete behavioral equivalence.
