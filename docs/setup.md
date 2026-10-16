# Install and set up ORBIT

ORBIT's command-line and browser executables ship together. The managed installer
checks the archive checksum and both executable hashes before switching the
installation to the new bundle. It leaves your ORBIT home alone.

## Install a published bundle

Use Bash to run the installer. Release mode requires Python 3.11 or newer, curl,
and `sha256sum` or `shasum`; Rust is only required for a source build.

```sh
bash install.sh --method release --version 0.2.0 --dir "$HOME/.local/bin"
```

Choose a version with a published archive and checksum for your platform. An
unavailable asset or failed checksum stops the installation; there is no automatic
source-build fallback. A checksum verifies downloaded bytes against the published
checksum, rather than an independent signing identity. Current installation
validation covers native Linux builds. Other platform assets require separate
validation.

`orbit version` reports compiled build facts. Release evidence remains
`unavailable` until it is bound to the installed executable; historical checkout
files do not establish a signature, audit, or reproducibility claim for a bundle.

The destination must be owned by you and safe to update. If it already contains
unmanaged executables, choose a fresh `--dir`. Managed versions live beneath that
directory's `.orbit/versions`; the stable launchers use one `.orbit/current`
pointer, so an upgrade switches `orbit` and `orbit-web` together.

For a source build, provide the checkout and its version explicitly:

```sh
bash install.sh --method source --source . --version 0.2.0 --dir "$HOME/.local/bin"
```

Source mode requires the pinned Rust 1.99 toolchain and `Cargo.lock`. It builds
both executables with locked dependencies. Add the chosen destination to `PATH`,
then check `orbit --version` and `orbit --help` from outside the checkout.

## Initialize once

```sh
orbit setup
orbit doctor
```

Plain `orbit setup` opens a provider wizard when both input and output are
terminals. Choose a preset or custom provider name, adapter and base URL, then
choose a hidden API key, a credential ENV reference, supported browser sign-in,
or explicit no-auth for a custom/local provider. Choose manual model IDs or online discovery, optionally
choose the main default, review the summary and type `yes` to save.
`orbit provider add` opens the same wizard for another provider. Manual model
entry with API-key/ENV/no-auth authentication sends no provider requests. Browser
sign-in and online model discovery contact their selected provider.

Hidden keys are stored in owned private files under the selected home's
`auth/providers` directory. Public provider configuration contains a generated
credential reference, not the key. The saved binding includes provider name,
adapter kind, canonical endpoint and credential reference. A nonempty ENV value
for that exact reference takes precedence; invalid nonempty values are refused.
Changing the endpoint or reference requires a matching credential. Set an ENV
reference in your shell before making requests, or use a privately saved key
without a shell export.

Identity setup creates the trust root, signed manifest, identity and ledger once.
Repeating setup or `orbit init` preserves the existing identity and history.
Partial or inconsistent identity files produce a diagnosis rather than a new
signing key. Use `orbit setup repair --dry-run` to inspect missing artifacts.
Canceling before confirmation preserves existing configuration and credentials.

For prompt-free automation, use explicit provider flags below, `setup --json`,
`setup --no-provider`, or `setup --dry-run`. Redirected plain setup also stays
offline. `orbit setup --guided` retains the older offline ENV-name prompt flow
and requires terminal input and output. Interactive flags cannot use JSON.

The configuration directory is selected by `--home`, then nonempty `ORBIT_HOME`.
Otherwise ORBIT uses an existing `~/.orbit`, then an existing workspace `.orbit`,
and finally `~/.orbit` as the creation default. Set `--home` explicitly when
comparing disposable workspaces, so their existing `.orbit` directory cannot
select a different home. Do not copy a signing key into an example or portable
profile.

## Declare providers and routing

A provider needs a unique name, an absolute HTTP(S) endpoint, its adapter kind,
and exact model IDs. Edit `providers.toml` directly or use setup. Credentials are
ENV references or exact-bound privately saved keys; key values do not belong in
`providers.toml`. Embedded credentials in URL userinfo are refused.

```sh
orbit setup --provider first --kind openai-compatible \
  --gate https://provider.example/v1 --model small,strong \
  --credential-env PROVIDER_API_KEY
orbit provider list
orbit route setup --easy first/small --hard first/strong
orbit route test "Implement a comprehensive parser"
orbit route status
```

Replace the example endpoint and IDs with declared provider values before use.
`provider/model` selects a declared provider and preserves the remaining raw ID,
including slashes. An ambiguous bare model ID is refused. Invalid route changes
leave the existing configuration intact. Roles and unrelated configuration survive
routing updates.

Routing classifies a task phase and its difficulty independently. Use
`orbit route set coding hard first/strong` for an individual target, and
`orbit route reset coding` to remove that phase's overrides. Existing legacy
`route easy`, `route hard`, `route off`, and keyword commands remain available.

An explicit model flag, environment selection, or `/model` pins a session.
`/route auto` clears that pin in a live session. A stopped saved session can be
changed with `orbit route auto --session SESSION_ID`. Queries and settings do not
send provider requests.

## Sign in and remove a saved key

For a provider already in `providers.toml`, run:

```sh
orbit provider login work
```

Choose an API key, ENV reference, or supported browser sign-in. The command
requires terminal input and output and shows a summary before saving. It keeps
your models, limits, routing and main default. API-key and ENV choices also work
with custom provider names and endpoints:

```sh
orbit provider login work --method key
orbit provider login work --method env
```

Browser sign-in is available for the official OpenRouter API endpoint,
`https://openrouter.ai/api/v1`, regardless of your chosen provider name. Selecting
a custom endpoint with that name does not enable OpenRouter login. The provider
asks for consent in your browser, returns a code to ORBIT's temporary local
callback, and exchanges it for an API key using S256 PKCE. Review and confirm the
local save afterward. The key stays private; ORBIT does not import another
application's account files.

Use these browser options when needed:

```sh
orbit provider login work --method browser --no-browser
orbit provider login work --headless --no-browser
```

`--no-browser` prints the authorization URL for you to open manually. It retains
the local callback unless you also select `--headless`. Headless mode uses the
provider's code flow: open the URL, then paste the returned authorization code
into ORBIT's hidden prompt. The code is tied to that login attempt. Authorization
and exchange have a ten-minute deadline; canceling closes the listener and leaves the
previous local configuration and credential intact. A code exchange is attempted
once; an uncertain or refused exchange requires a new login.

To remove the private key for the provider's current exact binding:

```sh
orbit provider logout work
orbit provider logout work --yes --json
```

Interactive logout asks for confirmation; `--yes` explicitly permits removal
without that prompt. Logout preserves providers, models, defaults and ENV values.
An active ENV override can therefore still authenticate requests afterward, and
the result reports that source. This removes ORBIT's local key copy; use the
provider's own account controls to revoke an issued API key. Older unselected
credential bindings are not automatically pruned.

## Discover models and refresh limits

In the setup wizard, choose `discover` at **Model source**. ORBIT fetches the
selected provider's catalog with the credential shown in the wizard. Choose
comma-separated model numbers, use `next` or `prev` to browse, and use
`filter TEXT` to find an ID or label. `filter` clears the filter. Enter `manual`
to supply raw IDs yourself, or `cancel` to leave without saving. A selection
supports up to 128 distinct models.

A complete catalog and successful completions are separate checks. If the
catalog is partial, ORBIT asks before using its partial results. An unavailable
catalog offers manual entry. Context and output limits are used only when the
provider advertises valid values; names do not imply a context size. Missing
information stays unknown. Ollama's advertised architectural context is not a
measurement of the context configured in a running local model.

Discovery supports OpenAI-compatible lists, OpenRouter catalogs, Anthropic
catalogs/details and Ollama tags. A custom OpenAI-compatible endpoint
asks whether its catalog uses the generic or OpenRouter schema. Raw model IDs,
including slashes, are preserved exactly. The catalog/detail operation has a
shared 45-second budget and bounded pagination, response sizes and concurrency.

Refresh metadata for the models already declared under one provider:

```sh
orbit provider refresh work
orbit provider refresh work --schema openrouter
orbit provider refresh work --json
```

The optional `--schema` accepts `generic`, `openrouter`, `anthropic` or `ollama`.
Declared adapter kind selects the default; custom OpenAI-compatible endpoints
use the generic schema unless their exact binding has recorded OpenRouter
provenance. Use an explicit schema when your custom gateway needs another
supported catalog format. Refresh makes network requests; `provider list`,
`models` and `doctor` do not.

Refresh preserves model membership, manual limit overrides, effort controls,
pricing, sampling and unrelated providers and roles. Provider observations are
recorded separately under the selected home's private `metadata/providers`
directory. If metadata history is missing or invalid, existing explicit limits
are preserved. An optional metadata-save warning can follow a successful
provider save; review that warning before relying on later refreshes. A provider
change during fetching is refused rather than overwriting the newer settings.

Hidden-key setup normally creates a fresh credential reference. The advanced
`key-env` choice lets you name that reference yourself and still store a key
privately. A nonempty value in that exact ENV takes precedence over the saved
key during discovery and later requests. Use ordinary `key` when you do not
need a deliberate ENV override.

## Read readiness accurately

Doctor checks local identity, ledger, configuration, integration metadata,
executable availability, and the installed browser bundle. It never starts a
configured MCP/LSP process or contacts a provider. `configured` and `not_tested`
are deliberately different from a successful connection test. Required invalid
checks make readiness fail; optional unavailable integrations remain visible.
Credential checks distinguish an active ENV override, exact saved binding,
explicit no-auth, missing credentials and invalid storage. They do not create
credential files or establish that a provider accepts the key.

See [customization](customization.md), [pentest workspaces](pentest.md), and the
[first real-provider trial](provider-acceptance.md) for the next steps.

## Package distribution

Homebrew uses the existing repository as an explicit tap. This is a Linux-only
source formula; `--HEAD` selects main until a stable source release is declared.
It installs Rust as a build dependency and installs both `orbit` and `orbit-web`.

```sh
brew tap fufugita/orbit https://github.com/fufugita/ORBIT.git
brew install --HEAD fufugita/orbit/orbit
brew upgrade --fetch-HEAD fufugita/orbit/orbit
brew uninstall fufugita/orbit/orbit
```

For npm, the launcher package is `@fufugita/orbit`. Exact-version optional
packages supply both native executables on Linux x64 or arm64 with glibc 2.35+.
Node.js must provide `process.execve` (22.15+ or 23.11+). Other platforms,
including musl Linux, receive an explicit unsupported-platform message. Enable
optional dependencies; `--omit=optional` omits the native executable package.
No lifecycle script downloads code or modifies your configuration.

After publication, install the candidate with:

```sh
npm install --global --include=optional @fufugita/orbit@next
npm uninstall --global @fufugita/orbit
```

Registry installation requires an actually published version. A local archive
can be tested without publishing or changing the system prefix:

```sh
node packaging/npm/stage.mjs --archive path/to/orbit-0.2.0-x86_64-unknown-linux-gnu.tar.gz --output dist/npm
mkdir -p dist/npm-packs
npm pack ./dist/npm/orbit-linux-x64-gnu --pack-destination dist/npm-packs
npm pack ./dist/npm/orbit --pack-destination dist/npm-packs
npm install --global --prefix /tmp/orbit-npm-trial --ignore-scripts --offline --no-audit --no-fund dist/npm-packs/*.tgz
/tmp/orbit-npm-trial/bin/orbit --version
```

Supply each archive's adjacent `.sha256` file. Staging checks the archive,
manifest, both executable hashes and ELF architecture before writing packages.
The archive is unsigned; these checks establish integrity, not publisher identity.
Local staging permits one architecture; public publication must include both.

The `distribution` GitHub workflow builds both native architectures inside
Ubuntu 22.04 containers, stages npm packages, and uploads the archives and npm
packs. Pushes build artifacts only. To publish, configure access to the npm
scope with trusted publishing or the `npm` environment's `NPM_TOKEN` secret,
then dispatch the workflow on main with `publish` enabled. Native packages are
published before the launcher. The default tag is `next`; choose `latest` only
after provider acceptance. For the first publication, npm may require an account
bootstrap before trusted publishing can be configured.

Normal uninstall removes package-manager files and preserves ORBIT's home,
identity, sessions and configuration. Run `orbit setup` and `orbit doctor` after
installation. Provider settings retain credential references; private key records
remain separate and are preserved during upgrades and normal uninstall.
