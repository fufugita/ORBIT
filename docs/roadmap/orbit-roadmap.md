# ORBIT: the path to a real harness

Oct 2, 2026 · @fugi

## Verdict

ORBIT today is a well-guarded chat client, not an agent: the model can call a calculator and two status lookups, so it cannot read a file, change code or run a command. Closing the gap to Claude Code is six phases of work on top of a core that is worth keeping.

What to keep, because Claude Code has nothing like it:

- The four-gate gateway (trust, capability, egress, fsync) and the hash-chained ledger with replay planning and encrypted export.
- Streaming dispatch with cancellation, tool-call accumulation, per-turn token and cost accounting.
- The approval flow (allow once, allow for the session, deny), persistent allow and deny rules, plan mode, resumable sessions, `/compact`, mods and the WASI plugin runtime.

What blocks real use, most blocking first:

1. **No tools that act.** No read, search, edit, write or shell tool exists, so permissions, plan mode and the sandbox guard nothing.
2. **One provider kind.** Only OpenAI-compatible endpoints work; the Anthropic and Ollama adapters in `provider-http` are never wired in.
3. **No context.** No system prompt, no working directory, no project instructions file, no automatic compaction, and a hard stop after 8 tool rounds.
4. **Four copies of the agent loop** (REPL, TUI worker, web bridge, Go bridge), so every feature must be built four times.
5. **Honesty and privacy defects** that contradict ORBIT's own promises: the approval card shows invented sandbox facts, and `@file` can send any file, including secrets, to the provider.

Built from `main` at `78b0135` (2 Oct 2026). All 731 workspace tests pass once the Tauri crate is excluded (it needs GTK system libraries), and a prompt runs end to end through the gateway against the mock provider.

## The bar: Claude Code, capability by capability

Of the 23 capabilities that make Claude Code a harness, ORBIT has none working end to end, and it leads on a 24th: proof. Nine are missing, five exist as libraries nothing calls, and nine are partial.

| Capability | Claude Code | ORBIT on main | Status |
| --- | --- | --- | --- |
| Agent loop | One loop behind the CLI, IDE, desktop, web and SDK; parallel tool calls; interrupt at any time | Four copies (REPL, TUI, web, Go); calls run one at a time; stops after 8 rounds; replies capped at 2,048 tokens | Partial |
| Read, Write, Edit | Line-numbered reads with paging, images, PDFs, notebooks; exact-match edits; read before edit | None; `@file` pastes a file into the prompt | Missing |
| Search | Glob and Grep (ripgrep, respects .gitignore, capped results), or `find` and `grep` through Bash | None | Missing |
| Shell | Bash with a persistent working directory, 2 min default and 10 min maximum timeout, background tasks up to 2 h, long output saved to a file | Only the user's `!cmd`, which runs unsandboxed and freezes the UI | Missing |
| Web | WebFetch with an extraction prompt and per-domain rules; WebSearch | None | Missing |
| Task list | TaskCreate, TaskUpdate, TaskList | Workspace rail fed only a phase index; the TTE primitive in `orbit-core` is unused | Library, not wired |
| Subagents | Agent tool; built-in Explore and Plan; custom agents with their own tools and model | The SDE primitive and the `SubagentCall` ledger event exist; nothing spawns a subagent | Library, not wired |
| Permission modes | default, acceptEdits, plan, auto, dontAsk, bypassPermissions; Shift+Tab cycles them | Ask per call (y, R, n), `--auto-tools`, and a plan mode that denies every tool, reads included | Partial |
| Permission rules | allow, ask and deny with patterns such as `Bash(npm run *)`, `Edit(/src/**)`, `WebFetch(domain:...)`, merged across five settings scopes | `permissions.toml` allows or denies whole tools only | Partial |
| Sandbox | Shell commands in bubblewrap (Linux) or Seatbelt (macOS): writes limited to the working directory, network through an allowlist proxy | `orbit-sandbox` (Landlock v4, seccomp, three profiles) is never used; the approval card shows invented sandbox facts | Library, not wired |
| Project memory | CLAUDE.md or AGENTS.md at managed, user, project and local scope; `.claude/rules/`; auto memory (first 200 lines or 25 KB) | `orbit-memory` (global, project, path-local; the same 200-line, 25 KB bound) is never used; mods inject text | Library, not wired |
| System prompt | Working directory, git state, platform, date; a reminder when a file it read changes on disk | No system prompt at all | Missing |
| Context window | Auto-compaction before the window fills; `/compact`, `/context`; automatic prompt caching | Manual `/compact`; `orbit-context` (token ceiling, reversible compaction) unused; no caching | Partial |
| Providers | Anthropic API, Bedrock, Vertex, Foundry and gateways; 1M-token windows on current models | OpenAI-compatible only; the Anthropic adapter sends one text message with no tools or history, and is not wired in | Partial |
| Sessions | JSONL transcripts; resume, continue, fork | JSON session files with resume; no fork | Partial |
| Checkpoints | Files snapshotted before every prompt; `/rewind` restores code, conversation or both | `/undo` drops the last exchange; files are never snapshotted | Missing |
| Hooks | 33 events, including PreToolUse (can block), PostToolUse, UserPromptSubmit, Stop, PreCompact, SessionStart | None | Missing |
| MCP | stdio and HTTP servers; tools, resources and prompts; tool search for large tool sets | None | Missing |
| Skills and commands | SKILL.md skills loaded when relevant; `.claude/commands/*.md`; bundled skills | Mods: `instructions.md` always injected, `commands/*.md` as slash commands | Partial |
| Plugins | Bundles of skills, hooks, MCP servers and agents, from marketplaces | `orbit-plugin` WASI runtime (wasmtime 47, signed install) is not exposed to the agent | Library, not wired |
| Headless and SDK | `claude -p`; `--output-format json` or `stream-json`; `--json-schema`; `--allowedTools`; Agent SDK for TypeScript and Python | `orbit ask` prints one JSON reply without tools; the SDKs carry IR types only | Partial |
| Git and worktrees | Git state in context, commit and PR conventions, `--worktree` for parallel sessions | None | Missing |
| Front-ends | Terminal, IDE, desktop, web, mobile, Slack and CI on one engine | REPL, ratatui TUI, Go TUI, web and Tauri, each with its own loop | Partial |
| Proof and audit | JSONL transcripts, no tamper evidence | Hash-chained ledger, replay plans, encrypted export, signed trust root | ORBIT is ahead |

Claude Code facts are from its docs: [tools](https://code.claude.com/docs/en/tools-reference), [permission modes](https://code.claude.com/docs/en/permission-modes), [sandboxing](https://code.claude.com/docs/en/sandboxing), [memory](https://code.claude.com/docs/en/memory), [hooks](https://code.claude.com/docs/en/hooks), [checkpointing](https://code.claude.com/docs/en/checkpointing), [headless](https://code.claude.com/docs/en/headless) and [model configuration](https://code.claude.com/docs/en/model-config). ORBIT facts are from the code on `main`.

## Fix first: defects that break ORBIT's own promises

Fix these nine before adding features: two show users invented facts, two leak or mangle data, and the rest will break the moment real tools land. Each is small and local.

| # | Defect | Where | Fix |
| --- | --- | --- | --- |
| 1 | Every approval card shows the same invented facts: `runs in ~/src/orbit`, `sandbox landlock · rw /tmp only`, `egress none`, `ledger decision is recorded` | `crates/hud-tui/src/render.rs:2581` | Draw facts only from the request. Until the sandbox is wired in, the card shows no facts |
| 2 | The welcome screen shows invented readiness: `✓ ledger · 7 records`, `✓ local · glm-5.2`, whatever the real model is | `render.rs:1223` | Compute each check (trust root, ledger count, provider) at startup, or drop the row |
| 3 | `@path` pastes any readable file into the prompt, unscanned: `@.env` or `@~/.ssh/id_rsa` goes straight to the provider | `crates/hud-tui/src/lib.rs:1070` | Expand mentions through the Read tool, so permission rules, deny-by-default credential paths and the secret scanner (row 4) all apply |
| 4 | The display gate rejects a whole chunk when it contains `authorization`, `api_key` or any `://`, yet passes a real key that lacks those words. In a coding agent it would blank ordinary code and every URL | `crates/hud/src/lib.rs:55` | Replace keyword rejection with value detection (private key blocks, known key formats, high-entropy tokens). Redact the value, keep the line, and run the same scanner on everything sent to a provider |
| 5 | `!cmd` runs `sh -c` on the input thread: the TUI freezes until it exits, and the output never reaches the model | `lib.rs:1017` | Run it on the worker like any command, stream its output, and add command and output to the conversation, as Claude Code's shell mode does |
| 6 | Every reply is capped at 2,048 output tokens at temperature 0.7, so a file write or long answer is cut off | `crates/cli/src/lib.rs:492` | Take max output tokens per model from `providers.toml` (default 32,000) and report a `length` stop instead of treating it as done |
| 7 | Ledger decision ids repeat every turn (`tool-round-0-0`), so a tool record cannot be tied to its turn | `tui_worker.rs` and the three other loops | A ULID per call, plus the turn id, in every `ToolIntent` and `ToolResult` |
| 8 | Plan mode denies every tool call, reads included, so the model cannot research while planning | `tui_worker.rs:910` | Plan mode allows read-only tools and blocks the rest, as Claude Code does |
| 9 | No CI, and `cargo test --workspace` fails on any machine without GTK because of the Tauri crate | `Cargo.toml` workspace members | A CI workflow (fmt, clippy, test, deny) with the Tauri crate behind a feature or excluded |

The welcome screen also prints the tagline twice and sits at the bottom of its panel; the TUI section below replaces it.

## One agent engine for every front-end

Build one `orbit-engine` crate that owns the agent loop, and make every front-end a client of it. Today each front-end runs its own copy of the loop, so the TUI has plan mode and persistent rules while the web app and the Go TUI do not.

&#91;embedded content: target architecture · 6 front-ends, 1 protocol, 1 engine\]

The engine is also where the unused libraries finally get wired in: `orbit-context`, `orbit-memory`, `orbit-session`, `orbit-sandbox` and the six primitives in `orbit-core`.

- **Protocol.** Grow `crates/frontend-protocol`, designed as every front-end's shared vocabulary but used today only by the desktop shell, into the engine API. `EngineCommand` goes in: prompt, cancel, approval decision, set mode, slash command, rewind. `EngineEvent` comes out: text delta, tool queued, started, progress and finished, approval requested, usage, compaction, turn ended, error. Version it, and make every client state the version it speaks.
- **Engine.** `Engine::start(config)` returns a handle for commands and a stream of events. One tokio task per session runs turns, so a slow front-end never blocks the loop and a long tool call never freezes a front-end.
- **Process model.** The TUI, the plain REPL and headless `-p` link the engine in-process. Web, desktop and the Go TUI connect to `orbit serve` over a Unix socket (WebSocket for the browser) and speak the same protocol as JSON lines.
- **Migration.** Move `tui_worker.rs` into the engine first, since it is the most complete loop. Point the TUI at it, then delete the loops at `main.rs:926`, `web/turn.rs:313` and `go_bridge.rs:417` one by one, switching each client to the protocol.
- **Rule.** A capability lands in the engine or nowhere. Front-ends render events and send commands; they never call a provider, a tool or the ledger directly.

## The agent loop

Replace the fixed 8-round loop with one that runs until the model stops calling tools, runs independent reads at the same time, and stops the moment you press Esc.

&#91;embedded content: one turn · 7 steps, 1 decision, 1 loop\]

- **Rounds.** No fixed cap in interactive use. A configurable guard (default 100 rounds) stops a runaway turn and says why; headless runs and subagents take `--max-turns`.
- **Stop reasons.** `end_turn` ends the turn. `tool_use` runs the calls. `max_tokens` inside a tool call's arguments retries the round once with a higher output limit; inside text it ends the turn with a visible "cut off" note.
- **Parallel calls.** Read-only tools (Read, Glob, Grep, WebFetch, WebSearch) run concurrently, up to 8 at a time. Anything that writes or executes runs one at a time, in the order the model asked. Results return in the model's order.
- **Per-round limit.** Raise the cap from 16 calls to 64, and answer extra calls with an error result instead of ending the turn.
- **Interrupt.** Esc cancels the stream and kills each running tool's process group. Partial text is kept and marked interrupted. Calls that never ran get a `cancelled by user` result, so the transcript stays valid for the next turn.
- **Messages mid-turn.** A message sent while ORBIT works joins the running turn as soon as the current tool calls finish, as in Claude Code. Commands and `!` commands still wait for the turn to end.
- **Retries.** On 429 and 529 the engine backs off exponentially with jitter, honours `retry-after`, and tries up to 8 times over about two minutes, showing the countdown. Authentication errors and 400s never retry. The gateway's two-attempt rule per dispatch stays; record the engine's backoff as a new spec decision.
- **Context.** Before each round the engine estimates the prompt size and compacts first when it is near the window (§Context). A `prompt too long` error compacts and retries once.
- **Ledger.** Each round is already a recorded gateway dispatch. Each tool call adds intent, decision and result records keyed by a per-call ULID and the turn id.

## Tools: the core set and their contracts

Ship sixteen tools in two waves, using Claude Code's names and argument shapes so prompts, skills and agent definitions written for it work unchanged. Every tool implements one trait, and every result passes the secret scanner before it enters the transcript.

```rust
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    fn input_schema(&self) -> serde_json::Value;          // JSON Schema sent to the model
    fn read_only(&self, input: &Value) -> bool;           // parallel-safe, allowed in plan mode
    fn permission_key(&self, input: &Value) -> PermissionKey; // Bash("cargo test"), Edit("/src/a.rs")
    async fn run(&self, input: Value, cx: &ToolContext) -> ToolOutput;
}

pub struct ToolOutput {
    pub for_model: Vec<ContentBlock>, // text or image blocks, already scanned
    pub display: ToolDisplay,         // Diff, Terminal, FileList, Matches: what the panels draw
    pub is_error: bool,
}
```

**Wave 1** (the minimum for real coding work):

| Tool | What it does | Limits and rules | Asks in default mode |
| --- | --- | --- | --- |
| Read | Returns a file with line numbers; images as image blocks | First 2,000 lines or 25,000 tokens, then a `PARTIAL` notice explaining `offset` and `limit`; records the file's hash for read-before-edit | No, inside working directories |
| Write | Creates or overwrites a file | An existing file must have been read in full this session; atomic write (temp file, then rename); checkpoint first | Yes, unless acceptEdits |
| Edit | Replaces `old_string` with `new_string` | Exact match, unique unless `replace_all`; read before edit; keeps line endings and encoding; refuses binary files; returns a diff for display | Yes, unless acceptEdits |
| Glob | Lists files matching a pattern | Respects `.gitignore`; newest first; 100 results, then a truncated flag | No |
| Grep | Searches file contents with ripgrep syntax | Modes `files_with_matches`, `content`, `count`; respects `.gitignore`; `head_limit` and `offset` for paging | No |
| Bash | Runs a command in a persistent working directory | 2 min default and 10 min maximum timeout, then moved to the background; output over 30,000 characters is saved to a file and the model gets the path plus a 2,000-character preview; kills the process group on cancel; runs in the sandbox when it is on | Yes, except a read-only allowlist (`ls`, `cat`, `rg`, `git status`, `git diff`, `git log`) |
| TaskStop | Stops a background command | Background commands live up to 30 min by default, 2 h at most; their output is a file Read can open | No |
| AskUserQuestion | Asks 1 to 4 multiple-choice questions | 2 to 4 options each, optional multi-select; drawn as a card in the conversation panel | No |
| ExitPlanMode | Presents the plan and asks to leave plan mode | Wraps ORBIT's existing plan approval | Always asks |

**Wave 2** (after permissions and context are solid):

| Tool | What it does | Limits and rules | Asks in default mode |
| --- | --- | --- | --- |
| WebFetch | Fetches a URL, converts it to Markdown, answers a prompt about it with a small model | HTTPS only; refuses `localhost`; 15 min cache; returns cross-host redirects instead of following them; each new domain is an egress grant recorded in the ledger | Yes, per domain |
| WebSearch | Searches the web | The provider's server-side search on Anthropic, otherwise a configured search API; off until configured | Yes |
| TaskCreate, TaskUpdate, TaskList | The session's task list | Persisted with the session; drives the Plan panel; stored as TTE primitives | No |
| Agent | Runs a subagent in its own context (§Extensibility) | Returns only the subagent's final report; its own calls are checked against your rules | No (its calls may ask) |
| NotebookEdit | Edits Jupyter cells | Read before edit, like Edit | Yes, unless acceptEdits |

Two rules span every tool. Results over the inline limit spill to `$ORBIT_HOME/sessions/<id>/outputs/<call-id>.txt`, which Read can open later. And `@path` mentions in prompts become a Read call, so they get the same rules, scanner and record. Source for Claude Code's behaviour: [tools reference](https://code.claude.com/docs/en/tools-reference).

## Permissions, approvals and the sandbox

Reads run freely, edits and commands ask, and a sandbox makes saying yes safe. Every decision is a ledger record, which is the part Claude Code does not have.

**Modes.** Shift+Tab cycles the first three. Keep vim-style Insert and Normal on their own key; today they share Shift+Tab with plan mode.

| Mode | Runs without asking | For |
| --- | --- | --- |
| default | Read-only tools and the read-only shell allowlist | Everyday work, unfamiliar code |
| acceptEdits | Also Write, Edit and common file commands (`mkdir`, `mv`, `cp`) inside working directories | Iterating on code you are watching |
| plan | Read-only tools only; edits wait for ExitPlanMode approval | Exploring before changing anything |
| dontAsk | Only calls an allow rule covers; anything else is denied, never asked | CI and scripts |
| bypass | Everything | Containers and VMs only; refuse to start as root |

A model-based `auto` mode can come later, once the rules and ledger can explain each automatic approval.

**Rules.** Patterns name a tool and what it may touch: `Bash(cargo test *)`, `Read(~/.ssh/**)`, `Edit(/src/**)`, `WebFetch(domain:docs.rs)`, `mcp__github__create_issue`, `Agent(Explore)`.

- Evaluate deny, then ask, then allow; the first match wins, and the mode applies only when no rule matches. A deny anywhere beats an allow anywhere.
- Scopes, highest first: managed (`/etc/orbit/settings.toml`), command line (`--allowedTools`, `--disallowedTools`, `--permission-mode`), local (`.orbit/settings.local.toml`, gitignored), project (`.orbit/settings.toml`, committed), user (`$ORBIT_HOME/settings.toml`). Lists merge across scopes.
- Project allow rules, hooks and MCP servers apply only after you trust the folder once, so cloning a repository cannot grant itself permissions.
- Ship a default deny-read list that Claude Code lacks: `~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**`, `**/.env*`, `~/.netrc`, `$ORBIT_HOME/trust/**`. That is how ORBIT keeps its promise that credentials never reach a provider.
- The existing `permissions.toml` becomes the `[permissions]` table of the user scope; migrate its whole-tool rules as they are.

**The approval card.** The options become: `y` allow once; `a` always allow this pattern (for example `Bash(cargo test *)`, saved to the local scope); `s` allow it for this session only; `n` deny, with an optional note telling ORBIT what to do instead; `Esc` deny. Today's `R` grants the whole tool for the session, which is too broad once Bash exists. The facts on the card come only from the request: working directory, the sandbox profile actually applied, the network policy actually applied, and a risk level computed from the command (for example `rm -rf`, `git push --force`, `curl ... | sh` are high).

**Sandbox.** `orbit-sandbox` today defines plugin and local-model profiles and probes the kernel, but applies nothing to a child process and has no shell profile. Build the shell sandbox as follows:

1. **Linux:** run each Bash command under bubblewrap, the approach Claude Code takes: writes allowed in the working directories and a per-session temp directory, reads everywhere except the deny-read list, no network namespace access except a Unix socket to ORBIT's egress broker.
2. **Network:** the egress broker becomes an HTTP and HTTPS proxy with a domain allowlist. A new domain asks once and the grant is recorded in the ledger, so the existing egress gate covers tools as well as providers.
3. **macOS:** a Seatbelt profile with the same boundary.
4. **Probe safely:** `probe_no_new_privs` calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` on the calling process, which permanently stops ORBIT's own children from using setuid programs such as `sudo`. Run every probe in a short-lived child process.
5. **Fallback:** when the sandbox cannot start, the status line says so, and every command asks, whatever the mode.

Sources: [permissions](https://code.claude.com/docs/en/permissions), [permission modes](https://code.claude.com/docs/en/permission-modes), [sandboxing](https://code.claude.com/docs/en/sandboxing).

## Context: system prompt, project memory, compaction

Build the system prompt once per session, load project instructions from `ORBIT.md`, and keep the transcript append-only. Append-only is not a style choice: current Claude models reject edited history, and it is what keeps the prompt cache warm.

**The system prompt, frozen at session start**, in this order (stable parts first, so they cache):

1. ORBIT's base instructions: identity, how to use each tool, safety, git and commit conventions. Identical across sessions.
2. The full tool set for the session, declared up front.
3. An environment snapshot: working directories, platform, shell, date, model, git repository yes or no, branch, the first 50 lines of `git status --short`, the last 5 commits.
4. Memory files, lowest scope first: managed `/etc/orbit/ORBIT.md`, user `$ORBIT_HOME/ORBIT.md`, project `ORBIT.md` or `.orbit/ORBIT.md`, local `ORBIT.local.md`. Read `AGENTS.md` and `CLAUDE.md` too when present, so existing repositories work on day one. Support `@path` imports, 5 levels deep. Add auto memory from `orbit-memory`, capped at 200 lines or 25 KB as its spec already says.
5. Enabled mods' instructions, and the skills index (names and one-line descriptions only).

**Append-only transcript.** Never edit, delete or reorder an earlier message. A mode switch, a mod toggled mid-session or a file changed on disk arrives as an appended note: a mid-conversation `role: "system"` message on models that support it, otherwise a text block after the tool results.

- On Claude Opus 5.5, Sonnet 5.5 and Fable 5.1, accounts created on or after 31 August 2026 get a 400 when replayed thinking follows edited history.
- Today ORBIT re-inserts the mods directive at the front of every request, which breaks this and defeats caching. Move it into the frozen system prompt.

**Reminders** are appended when something the model relies on changes: a file it read changed on disk (path and a short diff), the task list changed, plan mode switched, a hook produced output, a background command finished, or the working directory was reset.

**Token budget.** Track usage every round from the provider's usage report, and on Anthropic from `/v1/messages/count_tokens` before sending. Show a context meter in the status line. `/context` shows the split between system, tools, memory, messages and free space.

**Compaction.**

- **When:** automatically, when the next request would pass 90% of the model's window minus the output reserve; or on `/compact [focus]`.
- **On Anthropic:** use server-side compaction (beta `compact-2026-01-12`), which keeps replayed thinking valid.
- **On other providers:** simple compaction. Replace the whole history with one summary (the task, decisions, files touched, open questions, the task list) plus the latest user message.
- **Reversible:** the originals stay in the session file and in `orbit-context` tombstones (its CTX-I3 rule), so `/rewind` can restore them. PreCompact and PostCompact hooks fire around it.

Sources: [memory](https://code.claude.com/docs/en/memory), [model configuration](https://code.claude.com/docs/en/model-config); the API rules are from Anthropic's Claude API reference as of 25 September 2026.

## Providers: a real Anthropic adapter and content blocks

Make messages a list of content blocks, then finish the Anthropic adapter, so tools, images and thinking survive every round trip. Today `ChatMessage` holds one `String`, and `provider-http/anthropic.rs` sends a single user message with no system prompt, tools, history, thinking or caching.

**Message model.** Replace `content: String` with blocks: `Text`, `Image`, `ToolUse { id, name, input }`, `ToolResult { tool_use_id, content, is_error }`, and opaque `Thinking`, `RedactedThinking` and `Compaction` blocks. Opaque blocks are stored and sent back unchanged, never displayed: that satisfies ORBIT's rule that chain-of-thought never reaches the screen and the API's rule that thinking is replayed intact. Each adapter maps blocks to its own wire format; the OpenAI-compatible one drops thinking.

**The Anthropic adapter** (`POST /v1/messages`, streamed):

- Top-level `system` (the frozen prompt), `messages` as blocks, `tools` with `input_schema`, `strict: true` and `eager_input_streaming: true`. Validate each streamed tool input against its schema before running it.
- `tool_choice: auto` only. Forced tool choice returns a 400 on Claude Opus 5.5, Sonnet 5.5 and Fable 5.1.
- `thinking: {type: "adaptive"}`; it cannot be disabled on Opus 5.5. Leave `display` at its default, `omitted`.
- Set `output_config.effort` explicitly. Opus 5.5 defaults to `medium`; use `high` for coding turns and `low` for subagents and summaries.
- `max_tokens` 64,000 on streamed requests; the models allow up to 128,000.
- Caching: one explicit `cache_control` breakpoint at the end of the system prompt plus top-level automatic caching for the growing tail, 5-minute TTL. Agent rounds are well under 5 minutes apart, so every round refreshes it. Check `cache_read_input_tokens` in tests.
- Stop reasons: `end_turn`, `tool_use`, `max_tokens`, `pause_turn` (resend to continue a server tool), and `refusal`, where `stop_details` gives the category. Opt into server-side fallback (`fallbacks: "default"`, beta `server-side-fallback-2026-07-01`) and tell the user when a fallback model answered.
- Read `max_input_tokens` and `max_tokens` from `/v1/models/{id}` to set the window and compaction thresholds per model.

**Configuration.** Add `kind = "anthropic" | "openai-compatible" | "ollama"` to `providers.toml`, wire the existing Ollama adapter, and add Bedrock and Vertex later. Bedrock ids take an `anthropic.` prefix; Vertex uses the bare ids with Google Cloud credentials.

**Defaults when an Anthropic key is configured:**

| Role | Model | Price per million tokens, in / out |
| --- | --- | --- |
| Main agent | `claude-opus-5-5` | $4 / $20, cache reads $0.20 |
| Faster main agent, or a coding subagent | `claude-sonnet-5-5` | $2 / $10, cache reads $0.20 |
| Explore subagent, WebFetch extraction, summaries | `claude-haiku-4-5` | $1 / $5 |

**Routing cheaper, ORBIT's promise, done safely.** Caches and thinking blocks belong to one model, so switching the main model mid-conversation costs an uncached turn and drops replayed thinking. Route by task instead: a subagent or a headless job picks its model, and the main conversation keeps one. Each subagent's definition names its model; the reactor's phase router stays orchestrator-only, as DR-04 §8 requires.

Facts from Anthropic's Claude API reference as of 25 September 2026.

## Sessions: transcripts, resume, checkpoints and rewind

Store every session as an append-only JSONL file, snapshot files before ORBIT changes them, and let `/rewind` undo code, conversation or both. Today a session is one JSON file rewritten after every turn, and `/undo` only drops the last exchange.

- **Transcript.** One line per event (user message, assistant blocks, tool call, tool result, appended note, compaction, checkpoint) in `$ORBIT_HOME/projects/<project>/<session-id>.jsonl`, written with fsync. The JSONL is the content record and stays on the machine; the ledger stays the proof record, digests only.
- **Resume, continue, fork.** `orbit --continue` reopens the latest session in this directory, `--resume <id>` reopens a named one (a picker when the id is left out), and `--fork-session` or `/branch` copies the history into a new session id.
- **Checkpoints.** Before each prompt that starts a turn, open a checkpoint. The first time a tool writes a file in that turn, store the file's previous bytes by content hash under `sessions/<id>/snapshots/`. Keep the last 100 checkpoints and delete snapshots after 30 days, as Claude Code does.
- **Rewind.** `/rewind`, or Esc twice on an empty composer, lists the prompts of the session. For the chosen one: restore code and conversation, restore conversation only, restore code only, or summarize from there. Changes made by shell commands are not tracked; the rewind screen says so.
- **Proof.** Each checkpoint and each rewind is a ledger record with the digest of its snapshot set, so `orbit replay` can start from any checkpoint. That turns "replay it differently" into something a user can actually do.
- **Git.** Put commit and pull request conventions in the base instructions, with a configurable attribution trailer. `orbit --worktree <name>` creates `.orbit/worktrees/<name>` on a new branch, so parallel sessions never touch each other's files. `/add-dir` adds a working directory.

Sources: [checkpointing](https://code.claude.com/docs/en/checkpointing), [how Claude Code works](https://code.claude.com/docs/en/how-claude-code-works), [worktrees](https://code.claude.com/docs/en/worktrees).

## Extensibility: MCP, hooks, skills, subagents

Add the four extension points Claude Code users expect, and put each one behind ORBIT's existing gates: permission rules, the egress broker, the secret scanner and the ledger. Signed installs from `orbit-plugin` become ORBIT's edge here.

**MCP client** (a new `orbit-mcp` crate):

- stdio and Streamable HTTP transports. Servers come from `.orbit/mcp.json` (project scope, needs folder trust) and the user scope.
- Tools appear as `mcp__<server>__<tool>`, resources through two read tools, and server prompts as slash commands.
- Declare every server's tools at session start, so the tool list never changes mid-conversation. Past roughly 50 tools, send short descriptions and load the full schemas through a ToolSearch tool.
- stdio servers run inside the sandbox; HTTP servers are egress destinations, so the first connection asks and is recorded. Every result passes the secret scanner.

**Hooks**, configured in the settings scopes:

- Version 1 events: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`, `Stop`, `SubagentStart`, `SubagentStop`, `PreCompact`, `PostCompact`, `Notification`, `SessionEnd`.
- A hook gets JSON on stdin. Exit code 2 blocks the action and feeds stderr to the model; JSON on stdout can allow, deny, ask or rewrite the tool input. Default timeout 60 s.
- Deny and ask rules still apply when a hook says allow. Project hooks run only in trusted folders. Each run is a ledger record: hook name, command digest, exit code.

**Skills and commands.**

- Skills follow the open Agent Skills format: `.orbit/skills/<name>/SKILL.md` with `name` and `description` frontmatter. Only the description sits in context; the body loads when the model calls the Skill tool or you type `/<name>`.
- Commands are `.orbit/commands/<name>.md` prompts with `$ARGUMENTS`, as mods' `commands/*.md` already work.
- Mods become ORBIT's plugins: a bundle of instructions, commands, skills, hooks and MCP servers, installed with `orbit-plugin`'s signed-manifest flow (issuer key, content digest, operator approval, ledger record).

**Subagents** through the Agent tool:

- Definitions in `.orbit/agents/<name>.md`: `name`, `description`, `tools`, `model`, `maxTurns`, and an optional worktree for isolation.
- Built-ins: Explore (read-only tools, Haiku, a thoroughness level of quick, medium or very thorough), Plan (read-only, returns a plan) and general-purpose.
- Each runs as a child task in the engine with its own context. It inherits your permission rules, surfaces its approval requests in the main session, and returns only its final report.
- Record each one with the `SubagentCall` ledger event and the SDE primitive, both of which already exist and are unused.

Sources: [MCP](https://code.claude.com/docs/en/mcp), [hooks](https://code.claude.com/docs/en/hooks), [skills](https://code.claude.com/docs/en/skills), [subagents](https://code.claude.com/docs/en/sub-agents).

## Headless mode, SDK and CI

Give the engine a non-interactive front-end, `orbit -p`, that streams the same protocol as JSON lines; the SDKs and a CI action then become thin wrappers around it. Today `orbit ask` prints one JSON reply and cannot use tools.

- **Command.** `orbit -p "<prompt>"` runs one turn with tools and exits. It accepts `--continue`, `--resume <id>`, `--max-turns`, `--model`, `--allowedTools`, `--disallowedTools` and `--permission-mode`.
- **Never hang.** With no terminal to answer a prompt, `-p` defaults to `dontAsk`: anything no allow rule covers is denied and reported.
- **Output.** `--output-format text`, `json` or `stream-json`. `stream-json` is exactly the engine's `EngineEvent` stream, one object per line. `json` returns the final text, session id, turns, token usage, cost, files changed and the ledger head digest, so a CI log can prove what the agent did.
- **Structured output.** `--json-schema <file>` uses `output_config.format` on Anthropic and validate-and-retry elsewhere.
- **Fast start.** `--bare` skips discovering hooks, skills, mods, MCP servers and memory files; recommend it for scripts.
- **Exit codes.** 0 done, 1 turn failed, 2 stopped by a permission denial, 3 hit `--max-turns`, 130 interrupted.
- **SDKs.** The TypeScript and Python SDKs, which today carry IR types only, gain `query(prompt, options)`. It spawns `orbit -p --output-format stream-json` and yields typed events generated from the protocol schema, so the SDKs cannot drift from the engine.
- **CI.** A GitHub Action runs `orbit -p` on pull request events with an explicit allowlist, posts the result, and uploads the encrypted ledger export as a build artifact. An auditable CI agent run is something Claude Code's action does not offer.

Source: [headless mode](https://code.claude.com/docs/en/headless).

## What ORBIT adds over Claude Code

Parity makes ORBIT usable; these six make it worth choosing. Each one is built from crates that already exist, so it costs wiring, not invention.

| Advantage | Built from | What the user gets |
| --- | --- | --- |
| Proof of every action | `orbit-ledger`: tool intent, decision and result, approvals, egress grants, hook runs, subagent calls, checkpoints | `orbit verify-ledger` shows the record of a session was not altered; the Activity panel shows it live |
| Replay from any checkpoint | Replay planning in the CLI, plus checkpoints and recorded tool outputs | Re-run a session with another model, other rules or a changed prompt, and compare; regression-test agent behaviour on your own work |
| Claims checked, not trusted | The RTA (retest attestation) and EPB (evidence publish) primitives in `orbit-core` | When the agent says tests pass, ORBIT re-runs the recorded command itself; only an attested pass turns green |
| Spoken rules become real rules | The authority extractor in `orbit-core` (UserAuthorityIntent) | "Run the tests but never push" becomes `Bash(cargo test *)` allowed and `Bash(git push *)` denied, recorded as an AuthorityGrant |
| Credentials stay home | Deny-read defaults, the secret scanner, the egress broker | Keys and `.env` files never reach a provider, and every outbound host is on a list you approved |
| Spend under control | Per-turn cost accounting, model routing by subagent | A live cost meter, `--max-cost` per session or job, cheaper models for exploration |

The last three rows are what the README already promises; today none of them is enforced in the chat path.

## The TUI: isolated panels

Keep herdr's model of closed, isolated panels, and fill them with what a real harness produces: diffs, live terminal output, subagents and proof. Today's TUI looks bland because its boxes are empty and one accent colour does every job; the fix is content and state colour, not decoration.

&#91;image: Build layout while ORBIT works: sidebar, Conversation, Changes and Terminal panels\]

*Layout 1, build, while ORBIT works (164 × 48). Conversation has focus; Changes shows the diff of the current checkpoint; Terminal streams the test run inside the sandbox; the sidebar carries sessions, agents, shells, the plan and proof.*

**The panel contract.** These rules make a panel isolated:

- A panel is a closed box with its own border, numbered title tab, scroll position, selection, copy mode and search. A mouse selection never crosses a border, and copying never includes border characters.
- Keys go only to the focused panel. Exactly one panel has focus: magenta border and a filled title tab.
- State lives in the badge on the top border: `◐ working`, `◆ needs you`, `✓ done` (bold until you look), `○ idle`, `✕ failed`. A panel that needs you while unfocused gets a magenta badge, never a magenta border, so focus stays unambiguous.
- Panels never cover each other. The approval card lives inside the Conversation panel; only the palette and help overlay the screen.
- Each panel redraws on its own dirty flag. The `◐` glyphs in badges, rows and cards are static; only the status-line star turns, as the motion spec already says.
- Zoom (`⌃⌥z`) fills the panel area with one panel and shows `ZOOM` in the top bar; the others keep running.

**Panels and what feeds them.** Every value comes from an engine event; nothing is fixture data at runtime.

| Panel | Shows | Fed by |
| --- | --- | --- |
| Conversation | Transcript, tool cards, composer, approval cards | Text, tool and approval events |
| Agent · name | One subagent's task, model, tool calls and final report | SubagentStart, its tool events, SubagentStop |
| Changes | Files changed per checkpoint, diffs, revert hunk or file | Checkpoint store, Edit and Write results |
| Terminal | One tab per shell: foreground and background Bash, your `!` commands | Bash output streams |
| Plan | Tasks, reactor phases, retest attestations | Task events, RTA records |
| Activity | Approvals, grants, egress hosts, hook runs, compactions | The ledger as it is appended |
| Context | Window use, memory files loaded, compaction history | Usage reports, the context builder |

The sidebar is not a panel; it is the dashboard, as in herdr. It lists sessions with their rolled-up state, agents, shells, the plan, and proof: ledger verified, grants, egress hosts.

**Layouts** are tabs in the top bar: `1 build` (Conversation, Changes over Terminal), `2 review` (Changes zoomed), `3 agents` (Conversation beside agent panels). You can split, close and swap panels, and each layout is saved per project.

**Keys.** Typing goes to the composer. `Esc` enters navigate mode: `h j k l` move focus, `1`–`9` jump to a panel, `z` zoom, `x` close, `s` and `v` split, `[` and `]` switch layouts, `i` or `⏎` returns to the composer. Direct chords use the `ctrl+alt` family (`⌃⌥h j k l`, `⌃⌥1`–`9`, `⌃⌥z`), which herdr's own docs identify as free in nearly every terminal. ORBIT never binds `ctrl+b`, so it runs cleanly inside herdr or tmux. The mouse works too: click to focus, drag a border to resize, scroll the panel under the pointer.

**The visual system.**

- Colour means state or content, nothing else. State: cyan working, magenta needs you (and focus, the ORBIT mark, your prompt), green done, red failed, grey idle. Content: diff tints, syntax colour, blue file paths, and one colour per kind of tool action: look (blue), change (violet), run (amber), agent (magenta).
- A tool card is a stripe in its state colour, a kind label, the target and a right-aligned fact. An edit shows its diff inline; a command shows its live tail.
- Depth instead of lines: panels sit on a darker app background, cards and the composer are one step lighter, so panels need no inner rules.
- The top bar carries layouts on the left and facts on the right: repository, branch, model and effort, a context meter, cost. The status line carries the mode pill (`DEFAULT`, `ACCEPT EDITS`, `PLAN`, `BYPASS`), the live activity and key hints.

&#91;image: Needs-you state: approval card inside the Conversation panel\]

*Needs you. The card lives inside the panel, and every fact on it comes from the request or the engine: working directory, sandbox profile, network host (first use), and a computed risk. The tab, the sidebar row and the status line all turn magenta; no panel is covered.*

&#91;image: Agents layout: Conversation beside two subagent panels\]

*Layout 3, agents. Each subagent runs in its own isolated panel, herdr-style: explore is still working, review has finished and its report is unseen.*

&#91;image: Changes panel zoomed with file tree, checkpoints and diff\]

*Layout 2, review, with Changes zoomed: files, checkpoints you can rewind to, and the proof for these edits.*

&#91;image: Narrow terminal: one panel at a time with the panel switcher in the top bar\]

*Narrow (100 × 32). Below 110 columns the sidebar folds away and the top bar becomes the panel switcher, with each panel's state on its tab.*

&#91;image: Welcome: new session with real readiness checks and empty panels\]

*A new session. Readiness rows are computed at startup, and each empty panel says what will appear in it; nothing is invented.*

&#91;image: Component sheet: panel states, state glyphs, tool cards, markers, chrome\]

*The component sheet: panel states, the state vocabulary, every kind of tool card, the markers, mode pills, top bar, diff and sidebar rows.*

**What changes on `main`.** Keep the boxed panes from commit `8cb6599`. Add numbered tabs and state badges, the sidebar dashboard, the Changes, Terminal and Agent panels, the top bar, the mode pill, striped tool cards, diff and terminal colour, zoom and navigate mode. Remove the invented readiness and approval facts, the doubled tagline and the always-empty Sessions and Workspace rails. The glyph, honesty and motion rules of `docs/tui/PROMPT.md` stay; its layout sections (§8) are replaced by this one.

## Roadmap: six phases, each closed by a gate

Build in six phases, in this order. Each phase ends at a gate: a scripted session, run end to end through the real binary, that fails on `main` today and must pass before the next phase starts. ORBIT becomes usable for real coding work at gate 3 and reaches Claude Code parity at gate 5; phase 6 is where it pulls ahead.

&#91;embedded content: roadmap · 6 phases, 6 gates, the TUI built alongside\]

**Why this order.** Each phase stands on the one before it. Tools need content blocks and a single loop (phase 2). Checkpoints need tools that write (phase 3). Hooks, MCP tools and subagents need permissions and a sandbox to run under (phase 3) and the context builder to load them (phase 4). The SDKs wrap a protocol that has stopped changing (phase 6). The TUI is built alongside, not at the end: each panel lands in the phase whose events feed it, so no panel ever shows placeholder data.

**How a gate runs.**

- A gate is a test in the repository. It drives `orbit -p --output-format stream-json` against the mock provider, extended from its fixed behaviours to play back a scripted conversation with tool calls, so it runs on every push without an API key. That is why a minimal `orbit -p` ships in phase 2 rather than phase 6. The TUI and web parts reuse the PTY and browser harness scripts already in `scripts/`.
- Before a gate is called passed, the same scenario runs once against a real model through the Anthropic adapter, and someone watches it in the TUI.
- Gates only accumulate: every later phase keeps every earlier gate green. A bug found later gets its test at the earliest gate it belongs to.

| Phase | What ships | Gate: the scenario that must pass |
| --- | --- | --- |
| 1. Fix first | The nine defects in §Fix first. Until Read exists, `@path` applies the deny-read list and the secret scanner itself. CI runs fmt, clippy, test and deny, with the Tauri crate out of the default build. | **Honest and green.** CI passes on a fresh runner without GTK. Golden frames of the welcome screen and an approval card show only facts computed from the test's own environment. A prompt with `@.env` is refused with a reason, and a reply holding a fake API key shows it redacted while keeping the line. `!sleep 5` leaves the composer responsive. |
| 2. One engine | `orbit-engine` and protocol v1. The TUI worker's loop moves into it; the REPL, web and Go bridge loops are deleted. Content blocks, the Anthropic adapter with caching and adaptive thinking, Ollama wired in. The new loop: no fixed round cap, stop reasons, retries, Esc. `orbit -p` with `stream-json`. | **One loop everywhere.** One scripted session, run through the TUI, the REPL and the web front-end, produces the same event stream, and the old loop functions no longer exist. On Anthropic, the second round of a turn reports cache reads and replayed thinking is accepted. Esc during a slow tool kills its process group, and the next prompt works. |
| 3. Tools and safety | Wave 1 tools. Permission modes, rules and scopes, folder trust, deny-read defaults. The secret scanner on every tool result and every request. The approval card with real facts. The shell sandbox (bubblewrap on Linux, Seatbelt on macOS) and the egress proxy. | **Fix a failing test.** In a fixture crate with one failing test, "make the tests pass" leads ORBIT to search, read, edit and run `cargo test` in the sandbox until the tests pass. The same session, scripted to also read `~/.ssh/id_rsa`, fetch from an unlisted host and run `rm -rf ~`, meets a denial, an egress question and a high-risk approval card; in `dontAsk` all three are denied. `orbit verify-ledger` passes and lists intent, decision and result for every call. |
| 4. Context and sessions | The frozen system prompt. ORBIT.md, AGENTS.md and CLAUDE.md. Reminders, the context meter and `/context`. Auto-compaction. JSONL transcripts with resume, continue and fork. Checkpoints and `/rewind`. Worktrees. | **Survive a long session.** A scripted session that crosses 90% of the window compacts by itself and finishes its task, on Anthropic and on an OpenAI-compatible provider. `/rewind` to an earlier prompt restores every file to its recorded digest and the conversation to that point. After `kill -9` mid-turn, `orbit --continue` loses nothing written before the kill. A snapshot test shows the memory files and the environment in the system prompt. |
| 5. Extensions | `orbit-mcp` (stdio and HTTP). Hooks, 13 events. Skills and commands. Subagents with Explore, Plan and general-purpose. Wave 2 tools. Mods as signed plugins. | **One session, every extension.** One session uses an Explore subagent, a tool from a stdio MCP server, a SKILL.md copied unchanged from a Claude Code project, and a PreToolUse hook that blocks `git push`. The subagent's approval request appears in the main session, and each extension shows in the TUI and in the ledger. |
| 6. Automation and proof | `json` output, `--json-schema`, `--bare` and exit codes. `query()` in the TypeScript and Python SDKs. The GitHub Action. Replay from a checkpoint. Attested test passes (RTA). Spoken rules (the authority extractor). `--max-cost`. | **Audited CI run.** The Action runs `orbit -p` on a pull request under an allowlist, posts its result and uploads the encrypted ledger export, and `orbit verify-ledger` accepts that export on another machine. A replay from a checkpoint with another model runs to completion. A model's claim that tests pass turns green only after ORBIT's own re-run. |

## What to freeze or cut while this happens

Today one codebase carries five front-ends, two SDKs and nine libraries that only tests call. Freeze what no gate needs and cut what the new design replaces, so every change lands once.

**Freeze.** These keep building and passing their tests, but get no new features until the phase named.

| Part | Today | Decision |
| --- | --- | --- |
| Go TUI (`frontends/go-tui`, 1,468 lines of Go) | Its own loop through `go_bridge.rs` | Freeze now. Its bridge loop is deleted in phase 2 and it leaves the release packages. After gate 6, port it to `orbit serve` only if a second terminal UI is still wanted. |
| Desktop shell (Tauri) | Already speaks `frontend-protocol`; needs GTK, so it breaks `cargo test --workspace` | Freeze now, outside the default build (phase 1). After gate 6 it connects through `orbit serve`. |
| Web front-end (`crates/web`) | Its own loop at `web/turn.rs:313` | Keep, as a protocol client from phase 2: it is one of gate 2's three front-ends. No new browser features before gate 6. |
| SDKs (TypeScript, Python) | IR types only | Freeze until phase 6, when `query()` arrives. |
| The nine libraries only tests call: `orbit-core`, `orbit-context`, `orbit-memory`, `orbit-session`, `orbit-sandbox`, `orbit-plugin`, `orbit-ledger-events`, `orbit-api`, `orbit-ir` | Tested, never called | Change each only in the phase that wires it: the sandbox in 3; context, memory and session in 4; the plugin runtime in 5; each of `orbit-core`'s primitives, with its ledger events, in the phase that first uses it (TTE and SDE in 5, RTA, EPB and the authority extractor in 6). `orbit-api` and `orbit-ir` wait for the SDK decision below. |
| Releases | `v0.1.0-rc.1` is tagged | No new tag until gate 3. The next release is the first one that can change code. |

**The SDK decision.** DR-11 names `orbit-ir` (deterministic CBOR) as the one contract between the Rust core and the SDKs, while §Headless generates the SDKs' events from the engine protocol's JSON. Settle it at the start of phase 6, before writing `query()`, and record the answer as a decision record.

**Cut.** Each goes when its replacement lands.

| Remove | Replaced by | Phase |
| --- | --- | --- |
| `crates/capability`, a three-line stub nothing depends on | The capability gate in `gateway/src/dispatch.rs`, which is the one that runs | 1 |
| The display gate's keyword rejection (`hud/src/lib.rs:55`) | Value-based secret detection | 1 |
| The 2,048-token reply cap | Per-model output limits from `providers.toml` | 1 |
| The REPL, web and Go bridge copies of the loop, with their 8-round and 16-call caps | `orbit-engine` and its loop guard | 2 |
| The Sessions and Workspace rails and the doubled tagline | The sidebar and panels (§The TUI) | 2 |
| `orbit ask` | `orbit -p`; `ask` stays an alias for one release | 2 |
| The `R` approval key and `--auto-tools` | Pattern grants (`a`, `s`) and `--permission-mode`; `--auto-tools` maps to `bypass`, with a warning, for one release | 3 |
| `permissions.toml` | The `[permissions]` table of the user settings scope, migrated on first start | 3 |
| `@path` pasting a file into the prompt | A Read call | 3 |
| The mods directive re-inserted at the front of every request | The frozen system prompt | 4 |
| Session files rewritten whole after every turn | JSONL transcripts; old sessions convert on first open | 4 |
| `/undo` as it works today | `/rewind`; `/undo` stays as a shortcut that rewinds the conversation one prompt | 4 |

**Set the record straight.** ORBIT's three status records disagree. The README says all three v0.1 release gates are met; `spec/spec-manifest.yaml` says implementation has not started; and the workspace `Cargo.toml` still forbids product semantics before the spec freeze, which passed on 12 August 2026. In phase 1, make all three match this roadmap, with the README naming the last gate ORBIT has passed. Record the engine and its protocol, the tool contract, the permission model and the sandbox as new decision records rather than edits to the frozen DR-01 to DR-14.

**Not now.** These wait until after gate 6: a model-based `auto` mode, Bedrock and Vertex, IDE integrations, a plugin marketplace, and the desktop and Go front-end ports.

## Where this stands (9 Oct 2026)

Written against the `night-2026-10-09` branch; the plan above is unchanged. Hashes are from `git log`.

**Fix first: nine of nine done.** All nine landed in `bb4db4e` (2 Oct) and still hold in the code. The approval card has since gone from honest to useful: it carries the Edit diff, the sandbox state and what `R` grants (`9c9cd2d`), and `!cmd` runs through the Bash tool path (`12399c8`). `ci.yml` exists and the Tauri crate is outside the default build; that CI is green on a fresh runner is still confirmed only by a push.

**Gates 1 to 6: the scripted tests pass** (`tests/tests/gates.rs`, `tests/tests/scenarios.rs`). The rule under "How a gate runs" also asks for one run against a real model through the Anthropic adapter. That run has not been made, so by this document's own rule no gate is passed yet.

| Phase | Landed |
| --- | --- |
| 1. Fix first | `bb4db4e` |
| 2. One engine | `a18dff4`, `fb3312e`; gate test `97cc638` |
| 3. Tools and safety | `047575a` |
| 4. Context and sessions | `0112fec` |
| 5. Extensions | `5b18e7e` |
| 6. Automation and proof | `4bbdf20` |

The first review found the phases built but not wired into the live path; `fddad2d` and `853384a` (3 Oct) wired them. After that came the repair guide's B, S, E, C and Q series (`c8b46e7` to `9292c7f`), the terminal watchdog (`604564c`), the shell tool's pipe drain and `kill(2)` fix (`0d43971`, `3b57e2c`), and the panels that read engine events: Terminal (`45cf3e0`, `fa63fe6`), Plan (`60acf86`), Activity (`727e029`), Agents (`afcdad3`) and Context (`9743955`). The approval card then got pattern grants: a Bash rule matches the whole command and never through an operator (`a78cc1b`), a folder's own settings grant nothing until it is trusted (`a232b81`), `s` and `a` remember a rule and `n` takes a note (`ca6b7c3`), and the card shows the keys (`f0b6be9`). The earlier three-pane HUD and `--old-tui` were then deleted on their own branch, `night-2026-10-09-delete-v1-hud` (`f814bfb`, `9d284ba`); the default screen never expanded `@path`, which only the old composer did, so that went with it.

**Open.** A real-model run of each gate. Removing `R` (kept for one release as the whole-tool grant, off the card when a rule is on offer), and teaching the web and Go front-ends `s`, `a` and a denial note: they still send allow, session or deny. Markdown tables and fence labels, and narrow-screen polish. "Not now" above is unchanged.
