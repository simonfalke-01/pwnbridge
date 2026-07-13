#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-pwntools-dev-e2e-$$"
# Current dev HEAD verified on 2026-07-13. Pinning makes this acceptance test
# reproducible even as the upstream dev branch moves.
DEV_COMMIT=6571ec7de50d3c8fc235fad2a27bcdb07ca87acf
DEV_ENV_REL=".cache/pwnbridge/test-pwntools-dev-$DEV_COMMIT"
mkdir -p "$TMP/challenge" "$TMP/provider-logs"
cleanup() {
    if [ -d "$TMP/challenge" ]; then
        (cd "$TMP/challenge" && "$ROOT/bin/pwnbridge" clean --remote --yes >/dev/null 2>&1) || true
    fi
    # DEV_ENV_REL is a fixed test-owned relative path expanded locally.
    # shellcheck disable=SC2029
    ssh lima-pwn "rm -rf -- \"\$HOME/$DEV_ENV_REL\"" >/dev/null 2>&1 || true
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

REMOTE_HOME=$(ssh lima-pwn 'printf %s "$HOME"')
# Both interpolated values are fixed acceptance-test constants.
# shellcheck disable=SC2029
ssh lima-pwn "set -eu; dir=\"\$HOME/$DEV_ENV_REL\"; if [ ! -f \"\$dir/.pwnbridge-commit\" ] || [ \"\$(cat \"\$dir/.pwnbridge-commit\")\" != '$DEV_COMMIT' ]; then rm -rf \"\$dir\"; python3 -m venv --system-site-packages \"\$dir\"; \"\$dir/bin/pip\" install --no-deps 'git+https://github.com/Gallopsled/pwntools.git@$DEV_COMMIT'; printf '%s' '$DEV_COMMIT' > \"\$dir/.pwnbridge-commit\"; fi"

cp "$ROOT/../ret2win" "$TMP/challenge/ret2win"
chmod +x "$TMP/challenge/ret2win"
cat > "$TMP/challenge/solve-dev.py" <<'PY'
from pwn import *
import pwnlib

assert pwnlib.__version__.startswith("5.0.0dev")

io = gdb.debug("./ret2win", gdbscript="continue\nquit")
io.sendline(b"AAAA")
assert b"x86_64" in io.recvall(timeout=10)

io = process("./ret2win")
_, bridge_gdb = gdb.attach(io, api=True)
bridge_gdb.continue_nowait()
io.sendline(b"AAAA")
assert b"x86_64" in io.recvall(timeout=10)
bridge_gdb.quit()
PY

cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima
sed -i.bak "s/provider = 'auto'/provider = 'custom:e2e'/" "$XDG_CONFIG_HOME/pwnbridge/config.toml"
"$ROOT/bin/pwnbridge" run -- "$REMOTE_HOME/$DEV_ENV_REL/bin/python" solve-dev.py
test "$(find "$TMP/provider-logs" -name 'pane-*.log' | wc -l | tr -d ' ')" -ge 2
"$ROOT/bin/pwnbridge" clean --remote --yes
