#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-pwndbg-e2e-$$"
mkdir -p "$TMP/challenge" "$TMP/provider-logs"
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
export PWNBRIDGE_E2E_PROVIDER_LOG="$TMP/provider-logs"

cp "$ROOT/../ret2win" "$TMP/challenge/ret2win"
chmod +x "$TMP/challenge/ret2win"
cat > "$TMP/challenge/solve-pwndbg.py" <<'PY'
from pwn import *

context.gdb_binary = "pwndbg"
io = gdb.debug("./ret2win", gdbscript="continue\nquit")
io.sendline(b"AAAA")
assert b"x86_64" in io.recvall(timeout=30)
PY

cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima
"$ROOT/bin/pwnbridge" host bootstrap lima --profile pwn --with-pwndbg >/dev/null
sed -i.bak "s/provider = 'auto'/provider = 'custom:e2e'/" "$XDG_CONFIG_HOME/pwnbridge/config.toml"
"$ROOT/bin/pwnbridge" run -- python solve-pwndbg.py
grep -a -q 'pwndbg: loaded' "$TMP"/provider-logs/pane-*.log
if grep -a -q 'GEF for linux ready' "$TMP"/provider-logs/pane-*.log; then
    echo "isolated Pwndbg unexpectedly loaded the user GDB plugin" >&2
    exit 1
fi
"$ROOT/bin/pwnbridge" clean --remote --yes
