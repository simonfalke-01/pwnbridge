#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-mosh-e2e-$$"
mkdir -p "$TMP/challenge"
QMP_SOCKET="$HOME/.lima/pwn/qmp.sock"
QMP_FORWARD=0
cleanup() {
    if [ -d "$TMP/challenge" ]; then
        (cd "$TMP/challenge" && "$ROOT/bin/pwnbridge" clean --remote --yes >/dev/null 2>&1) || true
    fi
    MUTAGEN_DATA_DIRECTORY="$XDG_STATE_HOME/pwnbridge/mutagen/v0.18" mutagen daemon stop >/dev/null 2>&1 || true
    if [ "$QMP_FORWARD" = 1 ]; then
        printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"human-monitor-command","arguments":{"command-line":"hostfwd_remove net0 udp:127.0.0.1:60000"}}' |
            socat - UNIX-CONNECT:"$QMP_SOCKET" >/dev/null 2>&1 || true
    fi
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

# QEMU user networking exposes Lima SSH on loopback. Add one private UDP
# forward for the test and remove it during cleanup. Other Lima networks can
# route Mosh directly and need no special handling.
SSH_HOST=$(ssh -G -F "$PWNBRIDGE_E2E_SSH_CONFIG" lima-pwn 2>/dev/null | awk '$1 == "hostname" { print $2; exit }')
if [ "$SSH_HOST" = 127.0.0.1 ] && [ -S "$QMP_SOCKET" ] && command -v socat >/dev/null 2>&1; then
    printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"human-monitor-command","arguments":{"command-line":"hostfwd_add net0 udp:127.0.0.1:60000-:60000"}}' |
        socat - UNIX-CONNECT:"$QMP_SOCKET" >/dev/null
    QMP_FORWARD=1
fi

printf '#!/bin/sh\nprintf "mosh-e2e\\n"\n' > "$TMP/challenge/ret2win"
chmod +x "$TMP/challenge/ret2win"
cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn --shell-transport mosh --mosh-port 60000
"$ROOT/bin/pwnbridge" host use lima
expect "$ROOT/test/e2e/lima-mosh.exp"
"$ROOT/bin/pwnbridge" clean --remote --yes
