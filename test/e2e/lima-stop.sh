#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-stop-e2e-$$"
RUNNER=""
mkdir -p "$TMP/challenge"
cleanup() {
    if [ -n "$RUNNER" ]; then kill "$RUNNER" >/dev/null 2>&1 || true; fi
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

cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima
"$ROOT/bin/pwnbridge" run -- sh -c 'while :; do sleep 1; done' >"$TMP/runner.log" 2>&1 &
RUNNER=$!

ready=false
for _ in $(jot 100); do
    if find "$XDG_STATE_HOME/pwnbridge/sessions" -name '*.json' -type f -print -quit 2>/dev/null | grep -q .; then
        ready=true
        break
    fi
    sleep 0.1
done
if [ "$ready" != true ]; then
    cat "$TMP/runner.log" >&2
    echo "active session record did not appear" >&2
    exit 1
fi

"$ROOT/bin/pwnbridge" stop
set +e
wait "$RUNNER"
status=$?
set -e
RUNNER=""
test "$status" -eq 130
test -z "$(find "$XDG_STATE_HOME/pwnbridge/sessions" -name '*.json' -type f -print -quit 2>/dev/null)"
"$ROOT/bin/pwnbridge" sync status --json | python3 -c 'import json,sys; assert json.load(sys.stdin)["data"]["paused"] is True'
"$ROOT/bin/pwnbridge" clean --remote --yes
