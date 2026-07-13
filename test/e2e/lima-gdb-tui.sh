#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-gdb-tui-e2e-$$"
mkdir -p "$TMP/challenge" "$TMP/provider-logs"
cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ "$status" -ne 0 ]; then
        for log in "$TMP"/provider-logs/pane-*.log; do
            test -f "$log" || continue
            echo "--- $log (failure tail)" >&2
            tail -c 12000 "$log" >&2 || true
        done
    fi
    if [ -d "$TMP/challenge" ]; then
        (cd "$TMP/challenge" && "$ROOT/bin/pwnbridge" clean --remote --yes >/dev/null 2>&1) || true
    fi
    MUTAGEN_DATA_DIRECTORY="$XDG_STATE_HOME/pwnbridge/mutagen/v0.18" mutagen daemon stop >/dev/null 2>&1 || true
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup EXIT INT TERM

export XDG_CONFIG_HOME="$TMP/config"
export XDG_STATE_HOME="$TMP/state"
export XDG_DATA_HOME="$TMP/data"
export XDG_CACHE_HOME="$TMP/cache"
export PATH="$ROOT/test/e2e/bin:$PATH"
export PWNBRIDGE_AGENT_PATH="$ROOT/bin/pwnbridge-agent-linux-amd64"
export PWNBRIDGE_E2E_PROVIDER_LOG="$TMP/provider-logs"
export PWNBRIDGE_E2E_PTY_PROVIDER=1

cp "$ROOT/../ret2win" "$TMP/challenge/ret2win"
chmod +x "$TMP/challenge/ret2win"
cat > "$TMP/challenge/solve-tui.py" <<'PY'
from pwn import *

io = gdb.debug("./ret2win", gdbscript="""
set pagination off
tui enable
layout regs
echo PWNBRIDGE-RESIZE-READY\n
""")
io.sendline(b"AAAA")
assert b"x86_64" in io.recvall(timeout=15)
PY

cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima
sed -i.bak "s/provider = 'auto'/provider = 'custom:e2e'/" "$XDG_CONFIG_HOME/pwnbridge/config.toml"
"$ROOT/bin/pwnbridge" run -- python solve-tui.py

python3 - "$TMP/provider-logs" <<'PY'
import glob
import os
import sys

paths = glob.glob(os.path.join(sys.argv[1], "pane-*.log"))
assert len(paths) == 1, paths
data = open(paths[0], "rb").read()
assert b"45 120" in data, data[-4000:]
assert b"\x1b[120G" in data, data[-4000:]
assert b"\x1b[" in data and b"register" in data.lower(), data[-4000:]
PY
"$ROOT/bin/pwnbridge" clean --remote --yes
