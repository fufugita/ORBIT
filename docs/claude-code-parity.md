# Claude Code parity audit

Compatibility inventory for ORBIT 0.2.1, reviewed 16 November 2026.

This answers one question: if you move your daily work from Claude Code to
ORBIT today, what stops working? It is narrower and more granular than
[gap-analysis.md](gap-analysis.md), which compares capabilities across several
harnesses and dates from 15 Oct.

## Method and limits

- The Claude Code side comes from its published documentation as fetched on
  11 Nov 2026: the docs index, and the tools, commands, hooks, interactive-mode
  and CLI reference pages. Selected command contracts were rechecked against
  an installed Claude Code 2.1.326 artifact with REA and an isolated `--help`
  terminal capture. Static interface descriptors establish the declared
  contract, not availability for every account or a successful remote run.
- The ORBIT side comes from reading and searching this repository. "Present"
  means the code path exists, not that it behaves like Claude Code's. A few
  paths have since been run in the terminal chat under a scripted
  pseudo-terminal against a scripted provider (a prompt and reply, the
  fallback model, a command file's `model:` and `` !`command` ``, `/find
  next`, `/memory edit`, `/config edit`, the channel permission relay).
  This inventory does not certify live-provider or remote-MCP interoperability;
  validate those with the providers and integrations you intend to use.
- Native Council and Reactor have passed an isolated terminal journey against
  a local fabricated provider, including four actual Council requests, saved
  accounting, live pane updates and art changes. This is functional local
  acceptance, not evidence that a particular upstream provider or roster works.
- Statuses: **Present**, **Partial** (exists but narrower), **Missing** (no code
  found), **Unverified** (a search hit I did not confirm), **Out of scope**
  (tied to Anthropic's cloud, apps or account system).

## What will hurt first

Ranked for projects with many local MCP servers, hooks
from other tools, plugins and skills, subagents.

1. **Hooks cover all 33 of Claude Code's events and all five handler types**
   (command, HTTP, prompt, agent, MCP tool), with matchers, `if`, `async`,
   blocking `Stop` / `SubagentStop` / `PreCompact`, Claude Code's payload
   field names, its JSON output and (opt-in) its `settings.json` entries
   (see [integrations](integrations.md#run-hooks)). `TeammateIdle` stands for
   a background agent finishing its turn: ORBIT has no agent teams. The
   prompt and agent handlers have run against a scripted provider, not a real
   model.
2. **Tool search is new and untried.** Past 40 MCP tools ORBIT now declares
   `McpToolSearch` and `McpToolCall` instead of every schema (see
   [integrations](integrations.md#search-large-mcp-tool-sets)). It has unit
   tests only; it has not run against real servers or a real model.
3. **Background subagents are bare.** `Task` can run in the background with
   `AgentOutput` and `AgentStop`, they show in the Agent panels, and
   `/tasks stop <agent>` stops one. `/tasks agents` lists them and
   `/tasks show <agent>` prints one agent's own conversation. There is no
   key to background a running one, and they cannot ask for approval.
4. **Commands and skills are simpler.** `/skill-name` and command files
   (`.orbit/commands`, `.claude/commands`) run as prompts, and a command
   file's `` !`command` `` lines run when its `allowed-tools` covers them.
   Its `allowed-tools` also cover the turn it starts, a plugin's skill runs
   as `/plugin:skill`, and the `/` list and the palette offer these names.
   A command file's `model:` front matter picks the model for the turn it
   starts.
5. **Chat commands are mostly there.** `/init`, `/memory`, `/config`,
   `/context`, `/export`, `/copy`, `/rename`, `/add-dir`, `/btw`, `/review`
   `/security-review`, `/cd`, `/plugin` and `/doctor` exist. `/memory add`
   and `/memory remove` edit an instruction file line by line,
   `/config set` changes three single-value settings, and `/memory edit`
   and `/config edit` open the file in your editor.
   `/fork` branches in place: the chat continues in a copy and the
   original is kept.
6. **MCP covers tools, resources, prompts, OAuth sign-in and elicitation,**
   reads `.mcp.json`, and `orbit mcp add | list | get | remove` edits the
   server list. A server's question is answered by hooks or through approval
   cards, one field at a time, not a form. Channels work for stdio servers
   named with `--channels`; one named with `--channel-permissions` as well
   can answer approval prompts. Sign-in has only been run against a
   local test server. A set of 29 real servers (27 stdio, 2 HTTP) was
   started together: 27 came up in about 6 s on the first prompt, 801 tools,
   each server's tool count equal to a direct handshake; the other two needed
   an application that was not running and a sign-in. Three servers that did
   not start before now do: one prints a dotenv banner on standard output, one
   answers a notification with an error that has no `id`, one sends a 3.5 MB
   tool list.
7. **Scheduling and `Monitor` need an open session.** `CronCreate`,
   `CronList`, `CronDelete`, `ScheduleWakeup` and `Monitor` deliver only while
   a terminal session is open and idle in that directory. A `Monitor` or
   channel event also reaches a running turn with its next tool round.
   `/goal` is judged by a second model after each round.
8. **Editor ergonomics.** Vim editing (`ORBIT_VIM=1`, single line),
   `keybindings.toml`, an external editor (`Ctrl+G`), a prompt stash
   (`Ctrl+S`), `/btw`, an opt-in bell or notification and a custom
   status-line command exist. Transcript search uses `/find`, with the
   wrapping and highlighting limits described below.
9. **Auto mode is simpler.** `/mode auto` puts uncovered calls to a classifier
   that now sees your last three messages (trimmed) as well as the call, so it
   can tell what you asked for; it still never sees tool results. Its requests
   bill to the session's housekeeping subtotal. The classifier itself is still
   a straight prompt-and-parse with no escalation, and its verdict is not
   verified by a second pass.

## Instructions and memory

| Feature | ORBIT | Notes |
|---|---|---|
| `CLAUDE.md` and `AGENTS.md` are read | Present | `engine/src/context.rs`, alongside `ORBIT.md` (system, user, project, local) |
| User-level `~/.claude/CLAUDE.md` | Present | Read with `claude_compat` (or link it as `~/.orbit/ORBIT.md`), after the managed file and before ORBIT's own user file. User-level `~/.claude/rules/*.md` and the parent folders' `CLAUDE.md` files are not read |
| Instruction file caps | Present | 200 lines or 25 KB per file, a cut marked in the text and named once per run; `/memory` and `orbit doctor` (`instructions`) show it. A file reached by two names is read once; a pipe or folder is skipped |
| Links in instruction files | Present | ORBIT's own rule, not compared with Claude Code: a project's instruction and rule files must resolve inside the project, and no instruction file may lead to the deny-read list (the rule `@path` imports already had); a refused file is not read, is named once per run, is listed by `/memory` and is counted apart by `orbit doctor`. Your own files may be links to anything else |
| Hook context size | Present | 8 KiB in all for the hooks of one event by default; `hook_context_max_bytes` (0 to 256 KiB) in your own settings sets it; a cut is marked in the context and named once per run |
| `@path` imports inside instruction files | Present | Inside the project or the importing file's folder only; five levels |
| Path-scoped rules (`.claude/rules`) | Present | Delivered with the first Read, Edit or Write of a matching file |
| Auto memory | Present | `context.rs` loads and caps a memory index; write path not checked |
| `/memory`, `/init` | Partial | `/memory` lists the files; `/memory add [--user\|--local] <text>` and `/memory remove` change one line; `/memory edit [--user\|--local]` opens the file in `$VISUAL`/`$EDITOR`; all three also in the plain chat. `/init` is a built-in prompt |

## Sessions

| Feature | ORBIT | Notes |
|---|---|---|
| `--continue`, `--resume`, `/resume` picker | Present | Also `/sessions`; sessions are bound to their workspace. The picker lists every saved session except unnamed ones without a turn (the one in use stays). A row this folder cannot resume says so (`other folder`, `not bound to a folder`), and choosing it prints the reason. It has no search or filter. The sidebar and the Sessions pane (`s` in "Show what?") also list this folder's newest sessions, and a click on a row resumes it |
| Fork a session | Present | `--fork-session` at launch; `/fork` in the chat continues in a copy and keeps the original |
| Name or rename a session | Partial | `/rename`; the name shows in `/sessions`, the sidebar and the Sessions pane |
| Export or copy the transcript | Partial | `/copy` (last reply) and `/export [file]` (Markdown of what the pane shows); `orbit export --to` is an encrypted bundle, a different feature |
| Checkpoints and rewind | Present | `/rewind`, `/undo` |
| `/clear`, `/compact`, automatic compaction | Present | Also `orbit compact` for saved sessions. `/compact` keeps the last two exchanges whole. Within one long turn ORBIT drops old tool results instead of summarizing them |
| Worktrees (`--worktree`) | Present | `.orbit/worktrees/<name>`; no per-subagent isolation found |
| `/cd`, `/add-dir`, extra working directories | Present | `/add-dir` for the session; `--add-dir` at launch; `/cd <path>` moves where tools run, inside the session's directories. The session's own files stay in the workspace it started in |
| Session recap on return | Partial | `/recap` on request; nothing automatic |
| Serve and attach to a running session | Present | `orbit serve` / `orbit attach`; local only |

## Interactive terminal

| Feature | ORBIT | Notes |
|---|---|---|
| `@` file mentions with completion | Present | Goes through the Read tool, so deny-read applies |
| Images in prompts | Partial | Through file mentions; clipboard image paste not confirmed |
| Prompt history, `Ctrl+R` search | Present | Persisted per session; Claude Code searches across projects |
| `!` shell mode | Present | `hud-tui/src/proto/runtime.rs`. The command and its output stay in the conversation, and the next prompt tells the model what was run and what it printed |
| `Esc` stops a turn and the session goes on | Present | The stopped request is closed as abandoned and the same session takes the next prompt; its cost is a lower bound from then on. Scripted use keeps refusing such a session (`docs/setup.md`) |
| Queue messages during a turn | Partial | A pending prompt is held; no "send now", no take-back |
| Background Bash | Partial | `run_in_background` and `TaskStop`; `TaskOutput` reads the log; no `Ctrl+B` for a running command |
| Task checklist | Present | `TaskCreate/List/Update`, Plan panel |
| Diff review | Present | `/diff` focuses a recorded Changes/Review pane, or adds a side pane when space permits; a second invocation returns to the conversation. It is not a scan of untracked or pre-existing worktree changes |
| Themes | Present | Three themes plus colour overrides; no plugin-shipped themes |
| Status line | Present | Built-in chips can be shown, hidden and width-bounded; `status_line = "<command>"` adds the operator's own line (Claude Code's `statusLine` with the compatibility switch). `/statusline` inspects it; `set`, `off` and `reset` change the native setting. An explicit `--settings` value has priority. Plain text, no colour |
| Vim mode, keybindings file | Partial | `ORBIT_VIM=1`: single-line motions and edits, no counts or visual mode. `keybindings.toml` remaps keys to keys or slash commands; no per-context bindings or chords |
| External editor, prompt stash, input undo | Partial | `Ctrl+G`, `Ctrl+S`; no input undo outside vim mode |
| `/btw` side questions | Partial | Between turns only; tokens billed to the session's housekeeping subtotal in a managed session, uncounted otherwise |
| Prompt suggestions | Unverified | |
| Transcript viewer and search | Partial | Copy mode (`y` while arranging); `/find <text>` lists matches, `/find next` and `/find prev` move the conversation to them and show what was searched in reverse video (not a match that wrapping broke across two rows) |
| Completion bell or notification | Partial | `ORBIT_BELL=1` rings after turns of ten seconds or more; `ORBIT_BELL=notify` adds an OSC 9 notification |
| Voice, spell check, emoji shortcodes | Missing | |
| Reduced motion, ASCII glyphs | Present | Screen reader mode not checked |

## Commands

Present in both: `/clear`, `/compact`, `/effort`, `/help`, `/model`,
`/permissions`, `/resume`, `/rewind`, `/theme`, `/usage`.

Present as read-only lists: `/hooks`, `/skills`, `/agents`, `/mcp` (which also
has `login` and `logout`). Present in
a simpler form: `/goal`, `/loop`.

Also present: `/copy`, `/export`, and custom command files.

ORBIT only: `/mode`, `/models`, `/sessions`, `/undo`, `/customize`, `/route`,
`/mods`, `/mod`, `/council`, `/reactor`.

Also present: `/init`, `/memory`, `/config`, `/context`, `/rename`, `/add-dir`,
`/btw`, `/find`, `/tasks`, `/status`, `/sandbox`, `/plan`, `/vim`,
`/keybindings`, `/output-style`, `/recap`, `/review`, `/security-review`,
`/diff`, `/stats`, `/feedback`, `/statusline`.

`/stats` is a session-scoped alias of `/usage`; it does not report an upstream
subscription quota or global activity history. `/feedback` displays the issue
URL and local version/platform information, and attaches or sends nothing.
`/statusline set COMMAND`, `/statusline off` and `/statusline reset` use the
normal configuration controls. ConfigChange hooks still apply outside bare
mode; a configured model hook uses managed housekeeping accounting.

Missing from ORBIT's chat:
`/background`, `/stop`, `/schedule`, `/pr-comments`.

These names are not interchangeable with existing primitives. Claude Code
2.1.326 declares `/background` as moving the current session into the
background, and `/schedule` as managing remote agents. ORBIT's background
subagents and local schedules are narrower capabilities. ORBIT's attached
session already has `/stop`, which stops its owner; the main terminal chat
does not expose that command. `/stats` is an alias of `/usage` in the checked
Claude artifact. `/pr-comments` was not observed there, so its absence from
ORBIT is a requested workflow gap rather than confirmed parity with that
version.

## Tools

| Claude Code tool | ORBIT | Notes |
|---|---|---|
| Read, Write, Edit, Glob, Grep, Bash | Present | Read handles images and PDFs |
| NotebookEdit, WebFetch, WebSearch | Present | |
| Agent, ListAgents | Present | Plus ORBIT's `AgentSendMessage` |
| AskUserQuestion, Skill, ExitPlanMode | Present | No `EnterPlanMode` |
| TaskCreate, TaskList, TaskUpdate, TaskStop | Present | No `TaskGet`, `TaskOutput` |
| LSP | Present | `LspDiagnostics`, and with an `operation`: definition, references, hover, document symbols, workspace symbols. One server process per request, so a large project may still be indexing when the deadline passes |
| ToolSearch | Partial | `McpToolSearch` + `McpToolCall` past 40 MCP tools; the declared list stays fixed, so tools are called through the wrapper |
| CronCreate/List/Delete, ScheduleWakeup | Partial | Persistent, but fire only while a session is open in that directory |
| Monitor | Present | Watches a background Bash task; output reaches a running turn with its next tool round, else arrives as a prompt when a terminal session is idle |
| EnterWorktree, ExitWorktree | Present | Offered inside a git repository. The worktree is `.orbit/worktrees/<name>` on `orbit/<name>`; the session's files stay in the workspace it started in. `--worktree` at launch still exists |
| ListMcpResourcesTool, ReadMcpResourceTool | Present | `ListMcpResources`, `ReadMcpResource` |
| SendMessage | Missing | `AgentSendMessage` queues a child agent message for its next explicit resume. It does not provide Claude's running-agent, teammate, peer-session or control-message delivery contract |
| Workflow | Missing | The checked reference declares a script/DSL execution surface with agent, parallel, pipeline and phase operations, resumable run IDs and background execution. Skill prompts and task checklists are not substitutes |
| PushNotification | Missing | ORBIT can issue an opt-in local terminal notification after a turn. It does not have a model-callable notification tool or a configured remote push transport |
| Artifact, RemoteTrigger, PowerShell | Out of scope | |

## Permissions and safety

| Feature | ORBIT | Notes |
|---|---|---|
| Modes: default, acceptEdits, plan, dontAsk, bypass | Present | `/mode`, `--permission-mode` |
| Deny and ask rules hold in bypass mode | Present | A deny rule denies and a rule that asks still asks in `bypass`; only what no rule speaks about runs unasked (changed 12 Nov, it used to skip settings rules) |
| Auto mode | Partial | `/mode auto`: the classifier sees the call and the operator's recent messages (never tool results); high-risk calls always ask; its requests bill to the session's housekeeping subtotal |
| Allow, ask and deny rules with patterns | Present | Five scopes, typed grants, deny-read defaults |
| Import Claude permission rules | Partial | Preview and guarded apply are available. Read/Edit operation groups, settings-relative path anchors, resolved symlink checks and WebFetch domain/sandbox semantics require manual migration; an unsupported restrictive rule blocks the entire apply |
| Rules that match tool arguments | Unverified | MCP grants are per tool, not per argument |
| Folder trust | Present | ORBIT only |
| Sandboxed Bash | Unverified | `crates/sandbox` exists; boundary not reviewed |
| Run Bash without the sandbox | Present | `[sandbox] enabled = false` in your own settings (never a project's; the model has no parameter for it). `inherit_env = ["SSH_AUTH_SOCK"]` copies named variables into such commands. Needed for `docker` (the sandbox's user namespace drops your `docker` group), `ssh` with your agent and `ps` on the host. `/sandbox`, `/status`, the welcome line and the approval card say it is off; a command file's `` !`cmd` `` still needs the sandbox |
| The model cannot rewrite ORBIT's own settings | Present | Write and Edit refuse `settings.toml`, `settings.local.toml`, `permissions.toml`, `permission-overrides.toml`, `mcp.json` and `providers.toml` in ORBIT's home, in every mode, links and `..` included. Until 24 Nov a model in bypass mode could write hooks, rules or the sandbox's own settings there |
| Managed (organisation) settings | Partial | `/etc/orbit/ORBIT.md`; no policy delivery |

## Hooks

| Feature | ORBIT | Notes |
|---|---|---|
| Events | Present | All 33. `Setup` fires for `--init`, `--init-only` and `--maintenance`; `TeammateIdle` when a background agent finishes a turn |
| Command handlers, exit code 2 blocks | Present | 60 s default timeout |
| Matchers | Partial | Name lists with `*` wildcards as before, and regular expressions searched anywhere in the name as Claude Code does (`^…$` pins one): a matcher with any of `^ $ ( ) [ ] { } + ? \` is also read as one, so `WebSearch\|WebFetch\|mcp__.*(exa\|tavily)` and `^(startup\|resume)$` run unchanged. The dialect is Rust's `regex`: no look-around or back-references. A pattern that does not compile is reported (hook trouble when the hooks load, `orbit doctor`, `/hooks`) and only its plain names match, as in Claude Code, which only logs it. A pattern without those characters stays a name list, so `Web*` is a prefix here, where Claude Code reads it as a regular expression |
| `if` conditions | Present | `Tool(pattern)` on the tool and its main argument |
| JSON output: decisions, rewritten input, added context | Partial | ORBIT's schema and Claude Code's `hookSpecificOutput` / `decision`; `ask` opens the approval card. SessionStart and UserPromptSubmit feed model context; PreToolUse, PostToolUse and PostToolUseFailure append bounded context to the tool result; SubagentStart adds context to the child input. Tool events carry the original `tool_use_id`; failure events include `is_interrupt`. Cancelled calls suppress failure hooks. Other event outcomes need individual review. A deny with no reason takes `systemMessage` as its reason (hookify's block message); `systemMessage` on a hook that does not deny is not shown |
| `SessionStart` in interactive sessions | Partial | Fires at launch and after committed clear, interactive resume and fork; context is replaced for the new owner and model costs are saved before publication. Async Prompt/Agent lifecycle handlers are refused; async command/HTTP attachment hooks remain available. `SessionEnd` runs on actual exit, not clear/resume cleanup |
| HTTP handlers | Present | Through `curl`; blocks only via the response body |
| Prompt, agent and MCP-tool handlers | Partial | Model checks use the `explore` role (or the hook's `model`) and durable housekeeping accounting; the agent may only Read, Grep and Glob inside the working directories. A child session without its own managed hook accounting reports an error instead of sending an untracked model request |
| Blocking `SubagentStop`, `PreCompact`, `TeammateIdle` | Present | A blocked subagent continues, at most three times a turn unless `stop_hook_max_continuations` raises it; blocked compaction is skipped while the request still fits |
| Stop-hook continuation limit | Partial | A blocking `Stop` hook sends the model back to work at most 3 times a turn by default, so a hook that never lets go cannot hold a turn. `stop_hook_max_continuations` (0 to 1000, your own settings only) changes it, and ORBIT says when the limit or the round limit overruled a hook |
| Hook environment | Partial | `CLAUDE_PROJECT_DIR`, and the session id as `CLAUDE_SESSION_ID`, `CLAUDE_CODE_SESSION_ID` and `ORBIT_SESSION_ID`; a valid id replaces one inherited from the shell. No `CLAUDE_ENV_FILE`. A plugin's hooks also get `CLAUDE_PLUGIN_ROOT` and `CLAUDE_PLUGIN_DATA` |
| Async hooks | Present | Started and not awaited; when a session ends ORBIT waits up to 5 s for those still running and says how many were left |

At cold launch, the TUI currently infers `startup` versus `resume` from the saved
turn count, so a saved zero-turn session can report `startup`. Interactive clear,
resume and fork use explicit sources. Attachment hooks should accept the relevant
start sources and use the current payload's session ID rather than retain a
previous conversation's ID.

## MCP

| Feature | ORBIT | Notes |
|---|---|---|
| stdio, Streamable HTTP, legacy SSE | Present | |
| Per-tool allow, ask, deny | Present | |
| Project servers behind folder trust | Present | |
| `mcp add/list/remove` commands, `/mcp` | Present | `orbit mcp add | list | get | remove` (and `/mcp add …` in chat for values without spaces); a trusted project's `.mcp.json` is read |
| Credentials in `orbit mcp list` and `get` | Present | URL query values and user information, the word after a credential flag, `NAME=value` arguments of a credential name and credential header values show as `<hidden>`; a command-line word is cut at 100 characters; the file keeps what it was given |
| Servers that print a banner or answer a notification | Present | A standard-output line that is not JSON and does not begin with `{` is skipped, and a reply with no `id` is ignored, as the official clients do; a cut-off `{…` frame, JSON that is not an object and `"id": null` stay errors. The last skipped line is quoted when a server ends or never answers |
| Large replies | Present | A server's stdio frame, HTTP body, SSE stream and `tools/list` (summed over pages) may be 16 MiB; ORBIT's own requests stay within 1 MiB; the model sees at most 64 KiB of a result |
| Many servers on the first prompt | Present | The enabled servers are started together, eight at a time, and listed in configuration order; one that fails costs only itself |
| OAuth sign-in | Partial | `/mcp login <server>`: authorization code + PKCE with discovery and dynamic registration; no client secrets or device flow; not yet run against a real provider |
| Resources | Present | List and read; no subscriptions |
| Prompts | Partial | `/mcp prompts`, `/mcp prompt <server> <name>`; text content only |
| Elicitation | Partial | Answered by `Elicitation` hooks, or in the terminal chat through approval cards (`y`/`n`, a typed value as the card's note); headless and attached sessions answer `cancel` unless a hook answers. Over HTTP transports the answer must arrive within the server's request timeout |
| Channels | Partial | `--channels name[,name]` for configured stdio MCP servers: `notifications/claude/channel` enters the session as a `<channel>` tag. The server's `instructions` join the system prompt in the terminal chat. Permission relay (`claude/channel/permission`) for a channel also named with `--channel-permissions`, which Claude Code does not ask for: it answers the approval prompts of the terminal chat and the plain chat. Stdio servers only; a plugin cannot be named as a channel |
| Tool search for large tool sets | Partial | Keyword search over names and descriptions; `ORBIT_TOOL_SEARCH` sets the threshold |

## Subagents, skills, plugins

| Feature | ORBIT | Notes |
|---|---|---|
| Custom agents from Markdown files | Present | `.orbit/agents/*.md`, saved reports, explicit resume |
| Nested subagents | Present | Three levels |
| Background and parallel subagents | Partial | `Task` with `run_in_background`, `AgentOutput`; `AgentStop`; `/tasks stop <agent>`; four at most, no approvals |
| Agent view, agent teams, session messaging | Partial | Background agents show in the Agent panels and `/tasks`; `/tasks agents` and `/tasks show <agent>` give the operator each agent's conversation; no teams; `AgentSendMessage` queues for the next resume |
| Dynamic workflows | Missing | |
| Skills (`SKILL.md`) | Present | `.orbit/skills`, via the `Skill` tool |
| Skills and commands as `/name` | Partial | User, project and plugin skills (`/plugin:skill`), `.orbit/commands`, `.claude/commands`, in the terminal and the plain chat, with completion. In a command file `` !`command` `` runs sandboxed when `allowed-tools` covers it, and `allowed-tools` cover the turn it starts; `model:` picks the model for that turn and `argument-hint:` is shown in the `/` list. `disable-model-invocation` is not read: the model cannot start a command file here, only skills |
| Plugins | Partial | `orbit plugin import` reads Claude, Codex and Hermes formats; `--lenient` reads a plugin the way Claude Code does (leaving out its `.in_use` session markers), and `orbit plugin import --from-claude` brings in everything Claude Code has enabled. A plugin's command hooks run only when you name it in `plugin_hooks`. Withheld: its MCP servers, auth, prompt, agent and HTTP hooks, `asyncRewake`, LSP servers, output styles, themes and `userConfig` |
| Plugin hooks | Partial | Command hooks of an imported plugin run from the stored copy when named in `plugin_hooks` (optionally pinned to a digest); `matcher`, `timeout`, `if` and `async` are kept. Opt in, where Claude Code runs every enabled plugin's hooks; not run, and named: `asyncRewake`, a non-bash `shell`, `once` outside `SessionStart`, `SessionEnd` and `Setup`, an event ORBIT lacks |
| Marketplaces | Present | `orbit plugin marketplace add | list | update | remove` and `orbit plugin install NAME@MARKETPLACE` (also `/plugin …`). A marketplace is fetched only when added or updated; installing goes through the ordinary importer, so a plugin's hooks stay off until named in `plugin_hooks`, and its credentials and MCP servers stay withheld |
| Mods (panes, commands, tool rules in code) | Partial | Declarative panes and signed content; no executable API by design |

## Models and output

| Feature | ORBIT | Notes |
|---|---|---|
| Switch model, effort levels | Present | Any configured provider |
| Routing by task phase and difficulty | Present | ORBIT only |
| Prompt caching | Present | Anthropic adapter: breakpoints on the system prompt and on the two newest user-side messages, so earlier turns are read from cache |
| Fallback model | Present | `--fallback-model` for `-p`, as in Claude Code: when the model is unreachable and nothing was produced, the prompt runs again on the fallback as a new session (a resumed conversation continues as a fork). In the terminal chat the same failure continues the conversation in a fork on the fallback model, once per chat; the plain chat hands over to a new plain chat on the fork |
| Output styles | Partial | `--output-style` / `output_style`; `/output-style <name>` in the terminal chat |
| Advisor tool, fast mode | Missing | |

## Headless and SDK

| Feature | ORBIT | Notes |
|---|---|---|
| `-p` with text, JSON and stream-JSON output | Present | |
| Piped input | Present | `git diff \| orbit -p "review this"` puts the piped text before the prompt; `echo "question" \| orbit -p` uses it as the prompt. Both `-p` and `--print` accept up to 1 MiB of raw input from a pipe or redirected file. Model routing limits the assembled prompt to 256 KiB. A pipe that the program which started the run still holds, and never writes to, is given a quarter of a second and then ignored |
| `--max-turns`, `--json-schema`, `--permission-mode`, `--allowedTools`, `--disallowedTools` | Present | Plus `--max-cost` |
| `--append-system-prompt`, `--mcp-config` | Present | Also `--append-system-prompt-file`, `--output-style` |
| `--settings` | Present | One more settings file for the run: TOML (hooks, permission rules, `output_style`, `status_line`) or a Claude Code `settings.json` (its hooks and `statusLine`) |
| Python and TypeScript SDKs | Unverified | `sdk/python`, `sdk/typescript` exist; API not compared |

## Monitoring and cost

| Feature | ORBIT | Notes |
|---|---|---|
| `/usage`, per-session cost | Present | Cost qualification is stricter than Claude Code's |
| Cache and reasoning token counts | Partial | Reactor pane, this run only |
| OpenTelemetry export | Partial | `ORBIT_ENABLE_TELEMETRY=1` with the standard `OTEL_EXPORTER_OTLP_*` variables: token, cost and session counters and per-turn and per-tool events as OTLP `http/json`, `http/protobuf` or `grpc`. The per-signal protocol variables are read. With `OTEL_TRACES_EXPORTER=otlp`, one trace per turn: a turn span and a span per tool call. No prompt or tool content, no span per model request, and a gRPC collector's status is not read |
| Tamper-evident ledger, replay, encrypted export | Present | ORBIT only |

## Platforms

| Feature | ORBIT | Notes |
|---|---|---|
| Browser interface | Present | `orbit web` |
| Desktop app | Unverified | `crates/desktop` (Tauri) exists |
| VS Code and JetBrains extensions | Missing | |
| Chrome integration, computer use | Missing | A browser MCP server is the substitute |
| Cloud sessions, scheduled cloud tasks, mobile, Slack, GitHub Actions, Code Review | Out of scope | |
| `/code-review`, `/security-review` in a local session | Partial | Built-in prompts; no dedicated reviewer agents |

## Suggested order

1. Turn on `claude_compat` and run your real Claude Code hooks, skills and
   commands once each; then add the hook events and payload fields they miss.
2. Try tool search against your real MCP servers and tune the threshold.
3. Run `/mcp login` against each real server you use, and `/mode auto` on real
   work, before relying on either.
4. A stop control and a panel for background subagents.
5. Plugin skills and `.claude/commands` as `/name`, plus `/context`.
6. Cron-style scheduling that survives a restart.
7. External editor, prompt stash, multi-line vim.

Each of these should be confirmed against a live session before it is
scheduled: this audit shows what the code contains, not how it behaves.
