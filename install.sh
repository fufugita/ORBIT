#!/usr/bin/env bash
# ORBIT installer: release binary when one exists, cargo build otherwise.
#
#   curl -fsSL https://raw.githubusercontent.com/fufugita/ORBIT/main/install.sh | sh
#
# Installs to ~/.local/bin (override: ORBIT_INSTALL_DIR=/usr/local/bin).
# Verifies the release asset's sha256 when the release ships one.
set -euo pipefail

REPO="fufugita/ORBIT"
INSTALL_DIR="${ORBIT_INSTALL_DIR:-$HOME/.local/bin}"
BIN="orbit"

say() { printf 'install: %s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

command -v cargo >/dev/null 2>&1 || die "neither a release nor cargo found — install Rust from https://rustup.rs and retry"

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS:$ARCH" in
  Linux:x86_64) TARGET="x86_64-unknown-linux-musl" ;;
  Linux:aarch64) TARGET="aarch64-unknown-linux-musl" ;;
  Darwin:x86_64) TARGET="x86_64-apple-darwin" ;;
  Darwin:arm64|Darwin:aarch64) TARGET="aarch64-apple-darwin" ;;
  *) die "unsupported platform: $OS $ARCH" ;;
esac

mkdir -p "$INSTALL_DIR"

# Try the latest release first. No releases yet (or no asset for this
# platform) falls through to the cargo path — the script works today.
ASSET_URL=""
SHA_URL=""
if command -v curl >/dev/null 2>&1; then
  say "looking for a release for $TARGET…"
  if RELEASE_JSON="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null)"; then
    if command -v python3 >/dev/null 2>&1; then
      ASSET_URL="$(printf '%s' "$RELEASE_JSON" | python3 -c "
import json,sys
try:
    rel = json.load(sys.stdin)
    for a in rel.get('assets', []):
        if a['name'].endswith('$TARGET'):
            print(a['browser_download_url']); break
except Exception: pass
" 2>/dev/null || true)"
      SHA_URL="$(printf '%s' "$RELEASE_JSON" | python3 -c "
import json,sys
try:
    rel = json.load(sys.stdin)
    for a in rel.get('assets', []):
        if a['name'] == 'orbit-$TARGET.sha256':
            print(a['browser_download_url']); break
except Exception: pass
" 2>/dev/null || true)"
    fi
  fi
fi

if [ -n "$ASSET_URL" ]; then
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  say "downloading $ASSET_URL"
  curl -fsSL "$ASSET_URL" -o "$TMP/$BIN"
  if [ -n "$SHA_URL" ]; then
    say "verifying checksum"
    curl -fsSL "$SHA_URL" -o "$TMP/$BIN.sha256"
    ( cd "$TMP" && sha256sum -c "$BIN.sha256" >/dev/null 2>&1 ) \
      || die "checksum mismatch — the download is corrupt; retry"
  fi
  chmod 755 "$TMP/$BIN"
  mv "$TMP/$BIN" "$INSTALL_DIR/$BIN"
  say "installed $INSTALL_DIR/$BIN"
  "$INSTALL_DIR/$BIN" --version || true
  exit 0
fi

# No release asset: build from source. The workspace holds several
# binaries, so the package is passed as the positional crate.
say "no release binary for $TARGET — building from source"
cargo install --git "https://github.com/$REPO" orbit-cli --bin "$BIN" --locked \
  --root "$INSTALL_DIR" 2>/dev/null \
  || cargo install --git "https://github.com/$REPO" orbit-cli --bin "$BIN" --root "$INSTALL_DIR"
say "installed $INSTALL_DIR/$BIN"
say "next: $BIN init"
