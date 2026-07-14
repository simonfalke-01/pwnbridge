#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-shell-e2e-$$"
mkdir -p "$TMP/challenge"
cleanup() {
    if [ -d "$TMP/challenge" ]; then
        (cd "$TMP/challenge" && "$ROOT/bin/pwnbridge" clean --remote --yes >/dev/null 2>&1) || true
    fi
    MUTAGEN_DATA_DIRECTORY="$XDG_STATE_HOME/pwnbridge/mutagen/v0.18" mutagen daemon stop >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

export XDG_CONFIG_HOME="$TMP/config"
export XDG_STATE_HOME="$TMP/state"
export XDG_DATA_HOME="$TMP/data"
export XDG_CACHE_HOME="$TMP/cache"
export PATH="$ROOT/test/e2e/bin:$PATH"
export PWNBRIDGE_AGENT_PATH="$ROOT/bin/pwnbridge-agent-linux-amd64"
export PWNBRIDGE_E2E_ROOT="$ROOT"

# The shell lifecycle case only needs a real Linux amd64 executable in the
# workspace; reuse the agent produced by `make build` instead of depending on a
# challenge binary outside this repository.
cp "$ROOT/bin/pwnbridge-agent-linux-amd64" "$TMP/challenge/ret2win"
chmod +x "$TMP/challenge/ret2win"
cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima

# Nearby concise commands reuse one bounded warm OpenSSH master.
"$ROOT/bin/pb" true >/dev/null
CONTROL=$(find "$XDG_CACHE_HOME/pwnbridge/ssh" -type s -name c -print)
test -n "$CONTROL"
test "$(printf '%s\n' "$CONTROL" | wc -l | tr -d ' ')" -eq 1
CONTROL_INODE=$(ls -di "$CONTROL" | awk '{print $1}')
"$ROOT/bin/pb" true >/dev/null
test "$(ls -di "$CONTROL" | awk '{print $1}')" = "$CONTROL_INODE"
ssh -S "$CONTROL" -O check lima-pwn >/dev/null

expect "$ROOT/test/e2e/lima-shell.exp"
"$ROOT/bin/pwnbridge" clean --remote --yes
test ! -e "$CONTROL"
