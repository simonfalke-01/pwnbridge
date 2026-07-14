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
HOST_ADD_JSON=$("$ROOT/bin/pwnbridge" host add lima lima-pwn --check --json)
printf '%s' "$HOST_ADD_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["persisted"] is True and d["default"] is True and d["replaced"] is False; assert d["check"]["ok"] is True and d["check"]["complete"] is True'
if "$ROOT/bin/pwnbridge" host add lima lima-pwn; then
    echo "expected duplicate host registration to require --replace" >&2
    exit 1
fi
"$ROOT/bin/pwnbridge" host add retire-me lima-pwn
REMOVE_PREVIEW=$("$ROOT/bin/pwnbridge" host remove retire-me --dry-run --json)
printf '%s' "$REMOVE_PREVIEW" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["dry_run"] is True and d["safe"] is True and d["allowed"] is True and d["removed"] is False'
REMOVE_RESULT=$("$ROOT/bin/pwnbridge" host remove retire-me --yes --json)
printf '%s' "$REMOVE_RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["dry_run"] is False and d["safe"] is True and d["allowed"] is True and d["removed"] is True'
"$ROOT/bin/pwnbridge" host use lima
DOCTOR_JSON=$("$ROOT/bin/pwnbridge" doctor --json || true)
printf '%s' "$DOCTOR_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["complete"] is True; names={c["name"] for c in d["checks"]}; assert "remote-platform" in names and "ssh-reverse-forwarding" in names and "diagnostic-agent" not in names'
"$ROOT/bin/pwnbridge" support --local-only --json
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
CONFLICT_DIFF=$("$ROOT/bin/pwnbridge" sync diff -- conflict.txt)
printf '%s\n' "$CONFLICT_DIFF" | grep -F -- 'conflict "conflict.txt" (local -> remote)'
printf '%s\n' "$CONFLICT_DIFF" | grep -F -- '-local-wins'
printf '%s\n' "$CONFLICT_DIFF" | grep -F -- '+remote-loses'
"$ROOT/bin/pwnbridge" sync resolve --prefer local -- conflict.txt
RECOVERY_JSON=$("$ROOT/bin/pwnbridge" sync recovery list --json)
RECOVERY_ID=$(printf '%s' "$RECOVERY_JSON" | python3 -c 'import json,sys; entries=json.load(sys.stdin)["data"]["entries"]; entry=next(e for e in entries if e["original_path"] == "conflict.txt" and e["loser"] == "remote"); assert len(entry["sha256"]) == 64; print(entry["id"])')
"$ROOT/bin/pwnbridge" sync recovery verify "$RECOVERY_ID"
VERIFY_JSON=$("$ROOT/bin/pwnbridge" sync recovery verify "$RECOVERY_ID" --json)
printf '%s' "$VERIFY_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["complete"] is True and d["checked"] == d["total"] == 1 and d["entries"][0]["status"] == "verified"'
"$ROOT/bin/pwnbridge" sync recovery restore "$RECOVERY_ID" --to conflict.remote-recovered
test "$(cat conflict.remote-recovered)" = remote-loses
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
PRUNE_PREVIEW=$("$ROOT/bin/pwnbridge" sync recovery prune --keep-last 1 --dry-run --json)
printf '%s' "$PRUNE_PREVIEW" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["complete"] is True and d["dry_run"] is True and d["kept"] == d["selected"] == 1 and d["pruned"] == 0'
PRUNE_RESULT=$("$ROOT/bin/pwnbridge" sync recovery prune --keep-last 1 --yes --json)
printf '%s' "$PRUNE_RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["complete"] is True and d["kept"] == d["selected"] == d["pruned"] == 1 and d["pending_cleanup"] == 0'
if "$ROOT/bin/pwnbridge" sync recovery verify "$RECOVERY_ID"; then
    echo "expected pruned recovery ID to be unavailable" >&2
    exit 1
fi

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
