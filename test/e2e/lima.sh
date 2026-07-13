#!/bin/sh
set -eu

: "${PWNBRIDGE_E2E_SSH_CONFIG:?set PWNBRIDGE_E2E_SSH_CONFIG to a Lima SSH config}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP="/tmp/pwnbridge-e2e-$$"
mkdir -p "$TMP"
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

mkdir -p "$TMP/challenge"
cp "$ROOT/../ret2win" "$TMP/challenge/ret2win"
cp "$ROOT/../flag.txt" "$TMP/challenge/flag.txt"
chmod +x "$TMP/challenge/ret2win"

cd "$TMP/challenge"
"$ROOT/bin/pwnbridge" host add lima lima-pwn
"$ROOT/bin/pwnbridge" host use lima
"$ROOT/bin/pwnbridge" doctor --json || true
"$ROOT/bin/pwnbridge" run -- file ./ret2win
"$ROOT/bin/pwnbridge" run -- sh -c 'printf "AAAA\n" | ./ret2win | grep -q x86_64'
"$ROOT/bin/pwnbridge" run -- sh -c 'printf remote-artifact > generated.txt'
test "$(cat generated.txt)" = remote-artifact

REMOTE=$("$ROOT/bin/pwnbridge" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["workspace"]["remote_path"])')
REMOTE_REL=$(printf '%s' "$REMOTE" | sed 's|^~/||')

printf '#!/bin/sh\nexit 0\n' > executable-artifact
chmod +x executable-artifact
ln -s flag.txt portable-link
printf unicode-ok > "unicode-猫.txt"
# Expansion intentionally occurs in the remote shell.
# shellcheck disable=SC2016
"$ROOT/bin/pwnbridge" run -- sh -c 'test -x executable-artifact && test "$(readlink portable-link)" = flag.txt && test "$(cat unicode-猫.txt)" = unicode-ok'

printf delete-me > remote-delete.txt
"$ROOT/bin/pwnbridge" run -- true
# REMOTE_REL comes from Pwnbridge's generated workspace path.
# shellcheck disable=SC2029
ssh lima-pwn "rm -f -- \"\$HOME/$REMOTE_REL/remote-delete.txt\""
"$ROOT/bin/pwnbridge" run -- true
test ! -e remote-delete.txt

# A real endpoint permission error must block execution without resetting sync
# history; restoring the owned root must make the same session recoverable.
# shellcheck disable=SC2029
ssh lima-pwn "chmod 0500 \"\$HOME/$REMOTE_REL\""
printf permission-recovery > permission-block.txt
if "$ROOT/bin/pwnbridge" run -- true; then
    echo "expected endpoint permission error to block execution" >&2
    exit 1
fi
# shellcheck disable=SC2029
ssh lima-pwn "chmod 0700 \"\$HOME/$REMOTE_REL\""
"$ROOT/bin/pwnbridge" run -- test -f permission-block.txt

printf base > conflict.txt
"$ROOT/bin/pwnbridge" run -- true
printf local-wins > conflict.txt
# shellcheck disable=SC2029
ssh lima-pwn "printf remote-loses > \"\$HOME/$REMOTE_REL/conflict.txt\""
if "$ROOT/bin/pwnbridge" run -- true; then
    echo "expected synchronization conflict to block execution" >&2
    exit 1
fi
"$ROOT/bin/pwnbridge" sync conflicts
"$ROOT/bin/pwnbridge" sync resolve --prefer local -- conflict.txt
# Expansion intentionally occurs in the remote shell.
# shellcheck disable=SC2016
"$ROOT/bin/pwnbridge" run -- sh -c 'test "$(cat conflict.txt)" = local-wins'

printf base > "space name.txt"
"$ROOT/bin/pwnbridge" run -- true
printf local-space-wins > "space name.txt"
# shellcheck disable=SC2029
ssh lima-pwn "printf remote-space-loses > \"\$HOME/$REMOTE_REL/space name.txt\""
if "$ROOT/bin/pwnbridge" run -- true; then
    echo "expected spaced-path conflict to block execution" >&2
    exit 1
fi
"$ROOT/bin/pwnbridge" sync resolve --prefer local -- "space name.txt"
test "$(cat "space name.txt")" = local-space-wins

# shellcheck disable=SC2029
ssh lima-pwn "rm -rf -- \"\$HOME/$REMOTE_REL\""
if "$ROOT/bin/pwnbridge" run -- true; then
    echo "expected remote root deletion to block execution" >&2
    exit 1
fi
test -x ret2win
"$ROOT/bin/pwnbridge" clean
"$ROOT/bin/pwnbridge" run -- test -x ./ret2win
"$ROOT/bin/pwnbridge" sync status --json
"$ROOT/bin/pwnbridge" stop
"$ROOT/bin/pwnbridge" clean --remote --yes
