#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-gdb-e2e-$$"
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
PROVIDER=${PWNBRIDGE_E2E_PROVIDER:-custom:e2e}

cp "$ROOT/../ret2win" "$TMP/challenge/ret2win"
chmod +x "$TMP/challenge/ret2win"
cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima
sed -i.bak "s/provider = 'auto'/provider = '$PROVIDER'/" "$XDG_CONFIG_HOME/pwnbridge/config.toml"

cat > solve-gdb.py <<'PY'
from pwn import *

context.log_level = "debug"
io = gdb.debug("./ret2win", gdbscript="continue\nquit")
io.sendline(b"AAAA")
output = io.recvall(timeout=10)
assert b"x86_64" in output
PY

"$ROOT/bin/pwnbridge" run -- python solve-gdb.py

cat > solve-attach.py <<'PY'
from pwn import *

context.log_level = "debug"
io = process("./ret2win")
gdb.attach(io, gdbscript="continue\nquit")
io.sendline(b"AAAA")
output = io.recvall(timeout=10)
assert b"x86_64" in output
PY

"$ROOT/bin/pwnbridge" run -- python solve-attach.py

cat > solve-api.py <<'PY'
from pwn import *

io = process("./ret2win")
_, bridge_gdb = gdb.attach(io, api=True)
bridge_gdb.continue_nowait()
io.sendline(b"AAAA")
output = io.recvall(timeout=10)
assert b"x86_64" in output
bridge_gdb.quit()
PY

"$ROOT/bin/pwnbridge" run -- python solve-api.py

cat > solve-one.py <<'PY'
from pwn import *

io = gdb.debug("./ret2win", gdbscript="continue\nquit")
io.sendline(b"AAAA")
assert b"x86_64" in io.recvall(timeout=10)
PY

cat > solve-concurrent.py <<'PY'
import subprocess
import sys

children = [subprocess.Popen([sys.executable, "solve-one.py"]) for _ in range(2)]
assert all(child.wait(timeout=30) == 0 for child in children)
PY

"$ROOT/bin/pwnbridge" run -- python solve-concurrent.py
if [ "$PROVIDER" = custom:e2e ]; then
    test "$(find "$TMP/provider-logs" -name 'pane-*.log' | wc -l | tr -d ' ')" -ge 5
fi
"$ROOT/bin/pwnbridge" clean --remote --yes
