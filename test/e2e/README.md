# End-to-end tests

These scripts exercise a real Ubuntu amd64 Lima VM through the production
OpenSSH/Mutagen/agent paths. They intentionally keep test config/state in
private `/tmp` directories and remove their remote workspace on exit.

Requirements:

```console
export PWNBRIDGE_E2E_SSH_CONFIG="$HOME/.lima/pwn/ssh.config"
ssh -F "$PWNBRIDGE_E2E_SSH_CONFIG" lima-pwn uname -m
make build
```

The SSH config must define `lima-pwn`. The VM bootstrap profile and Podman image
requirements are documented in `docs/development.md`.

Run `make e2e-lima` for the deterministic custom-provider suite or invoke a
script directly. Set `PWNBRIDGE_E2E_PROVIDER=zellij`/`tmux` while actually
inside that multiplexer to test native host panes.

The shell suite covers prompt barriers, raw PTY behavior, signals, job control,
readline, alternate-screen bytes, and resize propagation. The disconnect suite
terminates a live SSH master, checks terminal restoration, reconnects, and
proves that both workspace data and post-reconnect artifact sync survive.
The GDB TUI test gives the custom test pane a real PTY, resizes it from 30x90
to 45x120, and asserts the remote GDB TUI observes the new dimensions.
