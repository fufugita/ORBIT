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
choose a hidden API key, a credential ENV reference, or explicit no-auth for a
custom/local provider. Enter exact raw model IDs, optionally choose the main
default, review the summary and type `yes` to save. `orbit provider add` opens the
same wizard for another provider. Manual model entry sends no provider requests.
Online catalog selection, refresh and browser login are not wired into this flow
yet.

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
