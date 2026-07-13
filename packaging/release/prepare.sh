#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
DEST="$ROOT/packaging/release/generated"
mkdir -p "$DEST"
go run "$ROOT/cmd/pwnbridge" completion bash > "$DEST/pwnbridge.bash"
go run "$ROOT/cmd/pwnbridge" completion zsh > "$DEST/_pwnbridge"
go run "$ROOT/cmd/pwnbridge" completion fish > "$DEST/pwnbridge.fish"
