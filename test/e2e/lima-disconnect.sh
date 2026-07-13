#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-disconnect-e2e-$$"
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

printf preserved > "$TMP/challenge/reconnect-sentinel.txt"
cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima
expect "$ROOT/test/e2e/lima-disconnect.exp"

# A fresh control master adopts the preserved synchronization history and data.
"$ROOT/bin/pwnbridge" run -- test -f reconnect-sentinel.txt
"$ROOT/bin/pwnbridge" run -- sh -c 'printf reconnected > reconnect-artifact.txt'
test "$(cat reconnect-artifact.txt)" = reconnected
"$ROOT/bin/pwnbridge" clean --remote --yes
