# ORBIT: competitive gap analysis

## Current implementation status — 15 Oct 2026

The current candidate adds a shared, deterministic phase router. Phase and
difficulty are separate decisions, exact provider/model identities are checked
before dispatch, and previews use the same selection path as live turns.
Explicit model selections pin a session; `/route auto` clears the pin. Saved
sessions and agents retain that choice. Provider/model changes discard foreign
signed thinking from the outgoing copy while preserving saved history.

Offline `setup`, idempotent `init`, and `doctor` expose installation and local
readiness. Managed Linux bundles contain both command-line and browser
executables, verified before an atomic activation. Setup stores credential
environment-variable names and preserves existing signing identity and ledger.
See [setup](setup.md) for supported installation and configuration paths.

Terminal and browser use a versioned appearance profile with three themes,
semantic color overrides, density, glyphs, reduced motion, layouts and named
panes. Browser fonts are configurable; terminal fonts belong to the terminal
application. Portable profiles contain inert text, permitted local Markdown,
or bounded context snapshots. Pane actions can refresh, focus, prepare a draft
or request an authorized cancellation. They cannot execute arbitrary extension
code. See [customization](customization.md) for the schema and limits.

`pentest init` provides an explicit local scaffold with empty scope, evidence,
findings, reports, workflow skills, a triage agent and a portable pane profile.
It preserves existing work and leaves folder trust, profile import and external
actions explicit. See [pentest workspaces](pentest.md).

MCP policy now exposes exact server/tool Allow, Deny and Ask decisions. Local
owners and attach clients share one session with exclusive control, durable
leases, reconnect recovery and cancellation. The browser consumes that owner.
Opt-in LSP diagnostics and browser tools through configured stdio MCP servers
use inherited scope, bounded results and cancellation. Signed content packages
have checked installation, local catalog/status and durable install records.

Live-provider acceptance for this candidate remains a separate step; follow the
[provider trial](provider-acceptance.md). Remaining gaps include remote HTTP MCP,
argument-aware MCP grants, live agent steering/background scheduling, native
IDE integration, a hosted marketplace and arbitrary JavaScript extension APIs.
Reference comparisons use bounded help, schema, documentation and package-source
evidence; they do not establish exhaustive runtime parity.

## Earlier checkpoints

The comparison below records the earlier checkpoint. The latest pass adds
workspace file completion, URL/email-safe mentions, quoted paths, Ctrl-R
history search, exact multiline history persistence with legacy-file support,
and image attachments from file mentions. Suggestions and search results
edit the draft; they do not send a turn. Read permissions, deny-read defaults,
scanning, cancellation, and image size limits still apply.

Agents now have stable IDs, display names, persisted conversations, explicit
configured model choices and bounded message queues. `Task`/`Agent` resumes
the saved profile and model; `ListAgents` provides paged discovery, and
`AgentSendMessage` queues input for the next explicit resume. Runs remain
synchronous. The panel shows the actual model, and child runs inherit
parent permissions, directories and cancellation with a three-level
nesting limit. Saved state does not restore grants or credentials.

The native Unix MCP path now isolates each server, applies absolute
deadlines and cancellation to lock/pipe/protocol waits, bounds frames
and paged discovery, and supports exact tool exposure filters. Dispatch
checks those filters and inherited caller scope, preserves server error
flags and structured results, scans success/error content, and bounds
the encoded response. Failed calls are not automatically replayed.

Provider-specific effort controls now use declared model choices and
defaults. Startup flags and chat commands select or reset the setting;
saved chats and named agents retain selection provenance. Dispatch validates
the actual model and uses each adapter's effort/thinking field. Missing
capability metadata remains unknown, and explicit choices require a declared
match. Existing provider defaults remain unchanged when no choice is set.

Remaining agent work includes live steering and background scheduling.
Remaining MCP work includes argument-aware
rules and narrow grants, remote HTTP transport and broader server attachment.
At that checkpoint, other follow-up areas were LSP diagnostics, browser
integration and distribution. The lifecycle pass used REA to generate and inspect the
reference's declared app-server schemas; this establishes interface
contracts, not exercised reference lifecycle behavior.
The seven-reference survey has bounded help and package-source coverage;
it does not establish exhaustive feature parity or native decompilation.

Oct 10–11, 2026 · @fugi · built from the code on `night-2026-10-10-router-and-subagents` (off `main` at `5a172eb`)

## Method

Acting as senior engineer and senior UI/UX designer. Every ORBIT claim
below was verified in the code the same day (file and line at the time
of writing); competitor facts come from their published docs and
repos, listed at the end. Two web search results arrived garbled or
carrying injected markup and were discarded whole; affected queries
were re-run.

The question was not "which harness has the longest feature list" but
"what would a developer who uses Claude Code / Codex / Cline / opencode
daily find missing on day one, and what of it is worth building?"

## The one-line verdict

ORBIT's differentiators are intact and unmatched: the hash-chained
ledger, the four-gate gateway, typed pattern grants, folder trust,
replay and encrypted export. Nobody else has proof. What the field has
that ORBIT lacks clusters into three groups: **day-one ergonomics**
(@-mentions, input history, discoverable commands), **throughput**
(parallel tool calls, subagent fan-out — the latter ORBIT already has),
and **integrations** (LSP, browser use). The first two are cheap; the
third is deliberate scope.

## The table

| Capability | Claude Code | Codex CLI | Cline | opencode | pi | ORBIT (before tonight) | Verdict |
|---|---|---|---|---|---|---|---|
| Difficulty routing (easy→cheap, hard→smart) | effort levels, manual | manual picker | — | — | — | static `[roles]` per task type | **Built tonight** |
| Parallel read-only tool calls | 8 concurrent | yes | yes | yes | yes | waves of 8 (Read/Glob/Grep/TaskList), writes sequential | **Built 11 Oct** |
| Subagents | Agent tool + custom agents | — | — | build/plan | — | Task/Agent, roles, shared approvals, Subagent* panels | Parity |
| @-file mentions | yes + completion | yes | @-mentions | yes | yes | expands through the Read tool (deny-read + scanner apply); completion popup still open | Mostly built 11 Oct |
| Composer input history | ↑/↓ | ↑/↓ | n/a | ↑/↓ | ↑/↓ | ↑/↓ persisted per session | **Built 11 Oct** |
| Slash commands | full list, searchable | full list | — | full list | — | 12 exist, 7 listed | **Fixed tonight** |
| Image/PDF read → vision | yes | yes | yes | yes | yes | Read of an image returns base64 data; the block rides the tool_result where the provider speaks blocks | **Built 11 Oct** |
| LSP diagnostics in context | partial (IDE surface) | — | yes | **yes** | — | none | Later |
| Browser-use tool | — | — | **headless browser** | — | — | WebFetch only | Later |
| Session share URL | — | — | — | yes | — | encrypted export + verify (provable, offline) | Different axis — ours is stronger for audit, theirs for collaboration |
| Thinking display / effort control | toggle + levels | levels | — | — | — | model-declared effort choices, startup/chat controls, saved selections | Built; dynamic capability discovery remains open |
| Plugin marketplace | plugins | — | **MCP marketplace** | — | — | signed mods (`orbit mod install`) | Later |
| Checkpoints / rewind | `/rewind` | — | checkpoints | — | session branch | checkpoints + `/rewind` + `/undo` | Parity |
| Permission rules w/ patterns | yes | sandbox-first | yes | yes | ask-always | 5 scopes, deny-read defaults, folder trust | **Ahead** |
| Tamper-evident record | JSONL only | JSONL | JSONL | JSONL | JSONL | hash-chained ledger + replay + export | **Ahead** |

Sources for the field: [Claude Code docs](https://code.claude.com/docs),
[opencode docs](https://opencode.ai/docs) (client/server TUI, LSP
context injection, extensions, share links, Zen relay), [Cline](https://cline.bot)
(Plan/Act, checkpoints, headless browser, MCP marketplace),
[pi / pi-mono](https://github.com/badlogic/pi-mono) (minimal composable
agent, session branching, MCP), Codex CLI (apply_patch, review mode,
custom prompts — its changelog was not reachable this session; facts
from prior verified reading).

## Findings that were bugs in our own code

1. **The `/` list lied by omission.** `/compact`, `/rewind`, `/undo`,
   `/mode`, `/permissions` were implemented (worker commands existed,
   handlers existed) but absent from the completion list and palette.
   A user could not discover them. — **Fixed tonight**: 12 commands
   listed, all five dispatch, `/rewind` and `/undo` refuse during a
   live turn.
2. **Subagents looked dead but weren't.** The registry's `AgentTool`
   ("subagents are unavailable" without a runner) was an unreachable
   fallback: `tool_runtime::execute_call` intercepts `Task`/`Agent`
   first and runs a real engine subagent with role routing, shared
   approvals, cancel linkage and observer events. — **Deleted (11
   Oct)**: `agent.rs` is gone, `agent_permission_key` preserves the
   `Agent(<agent-type>)` rule semantics, regression test added.
3. **Roles existed but nothing read the prompt.** `[roles]` routes
   tasks (subagent, explore, compaction) — never difficulty. —
   **Fixed tonight**: see `docs/roadmap/orbit-roadmap.md` (11 Oct).

## Priorities chosen (and why)

| Priority | Item | Rationale |
|---|---|---|
| 1 | Difficulty routing | the litellm phase router's idea, but in-harness: deterministic, inspectable (`route test`), recorded per decision — provable, which a gateway plugin cannot be. User-requested. |
| 2 | Slash discoverability | 30-minute honesty fix; the UI promised commands it hid. |
| 3 | Parallel read-only calls | **Built 11 Oct** — waves of 8, contiguous runs, ledger flock retry; see the roadmap. |
| 4 | Activity panel from ledger records | ORBIT's differentiator deserves a real proof surface (NEXT-STEPS P2 agrees). |
| 5 | @-mentions + input history | day-one ergonomics; both small, both expected. |
| 6 | Image reads → Image blocks | the adapter type exists; Read needs to produce it. |

At that earlier checkpoint, deferred work included LSP diagnostics (valuable, but a context-
quality project, not a correctness one), browser-use (Cline's niche;
ORBIT is not a browser harness), thinking-effort control,
marketplace (signed mods already install; distribution is a later
problem).
