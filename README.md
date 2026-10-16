<p align="center">
  <img src="docs/tui/img/logo.gif" alt="ORBIT" width="440">
</p>

<p align="center">
  <strong>A configurable workspace for coding and pentest work.</strong><br>
  Your terminal or browser. Your models, tools, and layout.
</p>

<p align="center">
  <a href="#install">Install</a> · <a href="#get-started">Get started</a> ·
  <a href="#connect-mcp-tools">MCP</a> · <a href="#plugins-skills-and-agents">Plugins</a> ·
  <a href="#documentation">Documentation</a>
</p>

ORBIT brings conversation, file changes, command output, and delegated work into
one open-source workspace. Connect a provider or local model, choose the tools it
can use, and work in the terminal, browser, or a headless command.

<p align="center">
  <img src="docs/tui/media/orbit-demo.gif" alt="ORBIT reading a project, proposing an edit, requesting approval, running tests, and opening the review layout" width="960">
</p>

<p align="center"><sub>Real terminal capture with a scripted provider and a disposable project.</sub></p>

## Install

ORBIT currently targets Linux. Both `orbit` and `orbit-web` are installed together.

### Homebrew on Linux

```sh
brew tap fufugita/orbit https://github.com/fufugita/ORBIT.git
brew install --HEAD fufugita/orbit/orbit
```

This builds the current main branch, using Homebrew's Rust build dependency.

### From source

Install Rust through [rustup](https://rustup.rs/), then use the pinned Rust 1.99 toolchain:

```sh
git clone https://github.com/fufugita/ORBIT.git
cd ORBIT
bash install.sh --method source --source . --version 0.2.0 --dir "$HOME/.local/bin"
```

Add the installation directory to `PATH`. The managed installer switches both
executables together and preserves your configuration. See [installation details](docs/setup.md)
for bundle installation, upgrades, prerequisites, and uninstall instructions.

### npm preview

The native Linux packages are available, but publication of the
`@fufugita/orbit` launcher is still pending. The following command becomes usable
once that launcher is published:

```sh
npm install --global --include=optional @fufugita/orbit@next
```

The npm distribution requires Node.js **22.15+ (22.x), or 23.11+**, Linux
**x64 or arm64**, and **glibc 2.35+**. It includes both executables and needs no
Rust compiler or lifecycle download script. See [package distribution](docs/setup.md#package-distribution)
for availability and local archive installation.

## Get started

Open a terminal in the project you want to work on:

```sh
cd your-project
orbit setup
orbit doctor
orbit
```

Plain `orbit setup` opens the provider wizard when both input and output are
terminals. It walks you through:

1. **Provider and endpoint:** choose a preset, or choose `custom` and enter a name,
   adapter kind, and your provider's base URL.
2. **Authentication:** enter a hidden API key, name an environment variable, or
   use browser sign-in for the supported OpenRouter endpoint. Custom/local
   providers can also use explicit no-auth.
3. **Models:** choose `discover` to fetch the catalog, filter it and select model
   numbers, or enter exact raw IDs manually, including any slashes in the ID.
4. **Default and save:** optionally select the main model, review the complete
   summary, and type `yes` to save.

A privately saved key needs no shell export. With an ENV reference, set that exact
variable before making requests. Replacing an existing provider or main default
requires a separate confirmation. Canceling, declining, or reaching EOF before
commit leaves existing configuration and credentials intact.

`orbit doctor` checks local readiness without contacting providers or starting
integration servers. Setup reports credential presence and leaves completion
connectivity untested; your first prompt makes a completion request. Conversation and tool
context are sent to the provider you select.

To add another provider, use the same wizard:

```sh
orbit provider add
orbit provider list
orbit models
```

Model discovery contacts only the provider you selected. Catalog access does not
establish that a completion will succeed. If discovery fails or is incomplete,
you can use manual IDs; missing context and output limits remain unknown.

Refresh advertised limits for the models you already configured:

```sh
orbit provider refresh work
```

Refresh preserves manually overridden limits, model IDs and routing choices.
It does not add every model in the catalog. `provider list`, `models`
and `doctor` stay offline. See [discovery and refresh](docs/setup.md#discover-models-and-refresh-limits)
for catalog controls and custom provider schemas.

For an existing provider, choose how to sign in:

```sh
orbit provider login work
orbit provider login work --method key
```

The browser flow is currently supported for OpenRouter's official API endpoint.
Use `--no-browser` to open its URL yourself, or `--headless` for its hidden code
flow when a local browser callback is unavailable. Other endpoints can use an
API key or ENV reference. See [provider sign-in](docs/setup.md#sign-in-and-remove-a-saved-key)
for the complete flow and local logout.

### Where configuration lives

The default home is `~/.orbit`; `--home DIR` and `ORBIT_HOME` select another home.
See [home selection](docs/setup.md#initialize-once) for the retained workspace-home behavior.
Providers and model defaults live in `providers.toml`. For example, an ENV-backed
configuration has this shape:

```toml
[[provider]]
name = "work"
kind = "openai-compatible"
url = "https://provider.example/v1"
env = "WORK_API_KEY"

[[provider.models]]
id = "family/model"

[roles]
main = "work/family/model"
```

Replace the example URL and model with your provider's actual values. The public
configuration contains credential **references**, never key values. Hidden-key
setup generates its own reference and stores the key privately, bound to that
provider and endpoint. A nonempty ENV value for the same reference takes precedence.

For automation, use explicit manual flags:

```sh
orbit setup --provider work --kind openai-compatible \
  --gate https://provider.example/v1 --model family/model \
  --credential-env WORK_API_KEY
```

`setup --json`, redirected plain setup, `setup --no-provider`, and
`setup --dry-run` keep their offline, prompt-free behavior. `setup --guided`
is the older offline ENV-name prompt flow and requires terminal input and output;
interactive flags cannot be combined with JSON. `setup repair --dry-run` inspects
missing identity artifacts without replacing the identity.

## Choose how to work

| Use case | Start with |
|---|---|
| Understand or change a project | Run `orbit` in its directory; ask it to inspect files, propose edits, and run checks. |
| Use the browser interface | Run `orbit web` from the project directory. |
| Run one task from a script | `orbit -p "Summarize this project" --output-format text` |
| Reopen work | `orbit --resume SESSION_ID`, or use `--continue` for the latest session in the directory. |
| Keep a session owned by another terminal | Use `orbit serve` and `orbit attach`; see [owned sessions](docs/integrations.md#keep-a-session-running-with-serve-and-attach). |
| Prepare an engagement workspace | Use `orbit pentest init`; see the example below. |

Headless output also supports JSON and streaming JSON. A call requiring an
unanswered approval is denied. Browser sessions use the saved provider
configuration, permissions, and conversations; see the [browser guide](docs/browser-harness.md)
for session ownership and access controls.

In the terminal, use `@` to complete workspace files and `Ctrl-R` to search prompt
history. With an empty composer while idle, `Esc` opens arrange controls, `?`
shows help, and `:` opens the command palette. During a live turn, `Esc` cancels it.
Approval cards show proposed edits and commands before you decide.

<p align="center">
  <img src="docs/images/terminal-customization.png" alt="ORBIT terminal conversation beside custom Engagement and Notes panes in the Midnight theme" width="960">
</p>

<p align="center"><sub>Real terminal capture with workspace notes and an unsent draft; no provider request.</sub></p>

## Connect MCP tools

Put server configuration in `~/.orbit/mcp.json`, or in the home selected by
`ORBIT_HOME`/`--home`. ORBIT supports **Unix stdio**, **Streamable HTTP**, and
**legacy SSE** MCP servers. For example:

```json
{
  "servers": {
    "browser": {
      "transport": "stdio",
      "command": "/path/to/installed/browser-mcp-server",
      "args": [],
      "tools": ["browser_navigate", "browser_snapshot"]
    },
    "docs": {
      "transport": "streamable-http",
      "url": "https://mcp.example/mcp"
    }
  }
}
```

Replace the executable, URL, and tool names with your server's values. Stdio
servers must already be installed; remote servers use their configured URL and
optional literal headers. Remote MCP authentication does not provide an automatic
OAuth/login flow. An omitted `tools` exposes discovered tools; `[]` exposes none.

In ordinary terminal chat, inspect or change policy with:

```text
/permissions
/permissions ask mcp__browser__*
/permissions allow mcp__browser__browser_snapshot
```

An exact Allow does not remove a surviving server-wide Ask or Deny. Review the
effective result. Enabled servers may initialize during tool discovery, before a
tool-call approval; permission rules govern subsequent calls. A workspace's
`.orbit/mcp.json` is used only after an explicit `orbit folder trust` decision.
See [MCP configuration and permissions](docs/integrations.md#configure-mcp-servers)
for transport details, credentials, server selection, and policy limits.

## Plugins, skills, and agents

Inspect a local package before importing it, then list what is installed:

```sh
orbit plugin inspect ./review-kit
orbit plugin import ./review-kit --scope user
orbit plugin list
orbit plugin status PLUGIN_ID
```

Use the ID returned by import/list in place of `PLUGIN_ID`. Imports create managed
local snapshots and are enabled by default; add `--no-enable` to keep one inactive.
Use `plugin enable`, `disable`, `upgrade`, or `remove` to manage that index.
Importing does not run package code. Enabled index state and runtime readiness
are reported separately; removal retains stored versions and user data.

Supported installed **skills and agents** enter the shared catalog when their
requirements are met. Ask ORBIT to use the exact `PLUGIN:SKILL` or `PLUGIN:AGENT`
identity from the package inspection. Skills use the `Skill` tool; agent delegation
uses `Task`. Agents inherit the parent's tool scope and permissions. Named agents
have saved reports and explicit resume; a task call runs synchronously.

Inspection recognizes `portable`, `claude`, `codex`, and `hermes` formats, with
explicit model/tool mapping options. Recognition is not full runtime portability:
components marked as requiring migration, with relevant errors, or with unmet
requirements are withheld. Project plugins require folder trust, and `--bare`
skips skills and agents. Foreign runtime hooks, authentication, dependencies, and
registration behavior may still need manual migration. Use `orbit plugin --help`
for exact formats, mappings, scopes, and revision options.

## Route models by task

With two declared models, choose easy and hard targets and preview a decision:

```sh
orbit route setup --easy work/small --hard work/strong
orbit route test "Implement a comprehensive parser"
orbit route status
```

The names must exist in your configuration. Routing uses deterministic phase and
difficulty rules; individual phase targets are configurable. An explicit model
choice pins the session, while `/route auto` restores automatic routing. Roles
provide separate model choices for delegated work and other supported tasks.

Use `--effort high` or `/effort high` only when the selected model declares that
choice; `/effort default` restores its configured default. See [provider configuration](docs/setup.md#declare-providers-and-routing)
for exact identities, roles, and routing commands.

## Make the workspace yours

```sh
orbit customize theme midnight
orbit customize set colors.accent '#8A91FF'
orbit customize set layout.preset review
orbit customize set browser.font_family 'Fira Code, monospace'
orbit customize set browser.font_size_px 15
```

Choose `orbit`, `midnight`, or `paper`. Arrange Conversation, Changes, Terminal,
Plan, Context, Activity, Review, and Agent panels using presets or your own splits.
Add named panes for notes, workspace Markdown, routing, usage, agents, scope,
evidence, or findings. Validate, import, and export portable appearance profiles.

Browser fonts use installed system families. Your terminal application controls
its font family and size. Custom panes display declared content and actions;
they do not execute JavaScript or shell commands. See [customization](docs/customization.md).

<p align="center">
  <img src="docs/images/browser-customization.png" alt="ORBIT browser interface in the Paper theme with Engagement and Notes panes and appearance controls" width="960">
</p>

<p align="center"><sub>Real browser capture of the same local workspace, with Paper and custom font settings; no provider request.</sub></p>

## Pentest workspaces

```sh
orbit pentest init ./engagement --profile standard
orbit pentest status ./engagement --json
cd engagement
orbit customize validate pentest-profile.json
orbit customize import pentest-profile.json
orbit
```

The scaffold creates scope, notes, evidence/findings directories, report templates,
workflow skills, a triage agent, and an engagement layout. It preserves existing
work and starts no scans or external tools. Fill in the scope and adapt the
provided templates to your engagement. See [pentest workspaces](docs/pentest.md)
for readiness checks and evidence handling.

## Documentation

[Setup and installation](docs/setup.md) · [Customization](docs/customization.md) ·
[Integrations](docs/integrations.md) · [Browser harness](docs/browser-harness.md) ·
[Pentest workspaces](docs/pentest.md) · [First provider trial](docs/provider-acceptance.md)

## Development

Built with **Rust 1.99** and **edition 2024**, with locked dependencies and a shared
engine/frontend protocol.

```sh
cargo fmt --all --check
CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --locked -- -D warnings
CARGO_BUILD_JOBS=1 scripts/in-jail.sh cargo test --workspace --locked -- --test-threads=1
```

Process-control tests use the provided Linux PID jail. Use `orbit --help` for the
command surface.

## License

[Apache-2.0](LICENSE).
