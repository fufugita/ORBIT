# ORBIT Desktop

Tauri desktop shell for ORBIT. The TUI and desktop share the typed domain
protocol in `orbit-frontend-protocol`; frontend rendering and input remain
platform-specific.

## Run

From the repository root:

```sh
RUSTUP_TOOLCHAIN=1.94.0 cargo tauri dev --manifest-path crates/desktop/src-tauri/Cargo.toml
```

If the Tauri CLI is not installed:

```sh
cargo install tauri-cli --version '^2'
```

Linux prerequisites (Mint 22 / Ubuntu 24.04):

```sh
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev librsvg2-dev libayatana-appindicator3-dev \
  librsvg2-dev patchelf
```

## Current boundary

The first milestone is the visual shell and protocol wiring. The webview
renders the conversation, composer, navigation, and status footer. Tauri
commands accept `FrontendAction` and publish `FrontendEvent`. The actual
harness/worker bridge and full workspace, approvals, inspector, and replay
surfaces are subsequent implementation stages; until then, the UI is a shell,
not a connected agent.

## Design reference

`../../docs/desktop/DESIGN.md` is normative; its rendered frames are canonical.
