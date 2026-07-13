#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-container-gdb-e2e-$$"
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
cat > "$TMP/challenge/.pwnbridge.toml" <<'TOML'
schema = 1
target = "linux/amd64"

[runtime]
kind = "container"

[runtime.container]
engine = "podman"
image = "localhost/pwnbridge-pwn:e2e"
workdir = "/work"
network = "bridge"
TOML

cat > "$TMP/challenge/solve-container.py" <<'PY'
from pwn import *
import importlib.metadata

assert importlib.metadata.version("pwntools") == "4.15.0"

io = gdb.debug("./ret2win", gdbscript="continue\nquit")
io.sendline(b"AAAA")
assert b"x86_64" in io.recvall(timeout=10)

io = process("./ret2win")
gdb.attach(io, gdbscript="continue\nquit")
io.sendline(b"AAAA")
assert b"x86_64" in io.recvall(timeout=10)

io = process("./ret2win")
_, bridge_gdb = gdb.attach(io, api=True)
bridge_gdb.continue_nowait()
io.sendline(b"AAAA")
assert b"x86_64" in io.recvall(timeout=10)
bridge_gdb.quit()

with open("container-gdb-artifact.txt", "w", encoding="utf-8") as output:
    output.write("same-container-gdb-ok")
PY

cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima
sed -i.bak "s/provider = 'auto'/provider = 'custom:e2e'/" "$XDG_CONFIG_HOME/pwnbridge/config.toml"
"$ROOT/bin/pwnbridge" run -- python solve-container.py
test "$(cat container-gdb-artifact.txt)" = same-container-gdb-ok
test -n "$(find "$TMP/provider-logs" -name 'pane-*.log' -print -quit)"
"$ROOT/bin/pwnbridge" clean --remote --yes
