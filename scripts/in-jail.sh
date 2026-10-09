#!/bin/sh
# Run a command inside a throwaway PID + user + mount namespace.
#
# Nothing in there can see or signal a process outside it — the desktop
# session's manager included — and --kill-child tears the whole
# namespace down if the parent shell dies. Use it for anything that
# kills process groups on purpose: the PTY suite, the tools tests, a
# manual run of the TUI that uses Esc on a long Bash command.
#
#   scripts/in-jail.sh cargo test --workspace
#   scripts/in-jail.sh env ORBIT_PTY_ALLOW_KILL_TESTS=1 \
#       python3 scripts/pty_tui_test.py
#
# The network is NOT isolated (a mock provider on 127.0.0.1 still works).
# Needs unprivileged user namespaces (the default on Ubuntu / Mint).
exec unshare --user --map-current-user --pid --fork --mount-proc --kill-child "$@"
