# ORBIT: competitive gap analysis

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
| Thinking display / effort control | toggle + levels | levels | — | — | — | adaptive only, hardcoded | Later |
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

Deliberately **not now**: LSP diagnostics (valuable, but a context-
quality project, not a correctness one), browser-use (Cline's niche;
ORBIT is not a browser harness), thinking-effort control (adaptive
thinking is wired; effort levels are provider-specific and shallow),
marketplace (signed mods already install; distribution is a later
problem).
