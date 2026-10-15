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

Source mode requires the pinned Rust 1.94 toolchain and `Cargo.lock`. It builds
both executables with locked dependencies. Add the chosen destination to `PATH`,
then check `orbit --version` and `orbit --help` from outside the checkout.

## Initialize once

```sh
orbit setup
orbit doctor
```

Setup is offline by default. It creates the trust root, signed manifest, identity,
and ledger once. Repeating setup or `orbit init` preserves the existing identity
and history. Partial or inconsistent identity files produce a diagnosis rather
than a new signing key. Use `orbit setup repair --dry-run` to inspect missing
artifacts before deciding how to recover them.

Use `orbit setup --guided` for manual terminal prompts. Enter provider metadata,
model IDs, and a credential environment-variable name; enter the credential value
in your shell separately. Manual setup does not discover models or start servers.
An explicitly selected provider-discovery workflow can contact the endpoint.

The configuration directory is selected by `--home`, then nonempty `ORBIT_HOME`.
Otherwise ORBIT uses an existing `~/.orbit`, then an existing workspace `.orbit`,
and finally `~/.orbit` as the creation default. Set `--home` explicitly when
comparing disposable workspaces, so their existing `.orbit` directory cannot
select a different home. Do not copy a signing key into an example or portable
profile.

## Declare providers and routing

A provider needs a unique name, an absolute HTTP(S) endpoint, its adapter kind,
and exact model IDs. Credential configuration references an environment-variable
name. Embedded credentials in URLs are refused.

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

See [customization](customization.md), [pentest workspaces](pentest.md), and the
[first real-provider trial](provider-acceptance.md) for the next steps.
