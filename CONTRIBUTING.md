# Contributing

Pwnbridge accepts focused changes that preserve its core guarantees: no stale
execution, no silent conflict winner, no implicit deletion, structured command
argv, system OpenSSH compatibility, and no remote-controlled Mac command.

Before submitting a change:

```console
make verify
make test-race
make fuzz-smoke
make security
shellcheck -x packaging/release/*.sh test/e2e/*.sh test/e2e/bin/ssh test/e2e/bin/scp
actionlint .github/workflows/*.yml
```

Changes to synchronization ordering, SSH forwarding, PTY handling, the broker,
terminal providers, or runtimes should include both a fake-executable/unit test
and the relevant real amd64 Lima scenario. Provider commands must remain argv
arrays. Fixed remote housekeeping scripts must single-quote every variable
path.

Do not commit host addresses, SSH configuration, challenge flags, bearer
tokens, generated release output, IDE state, or test VM credentials. Keep
machine preference in global config and project intent in `.pwnbridge.toml`.

See [development.md](docs/development.md), [architecture.md](docs/architecture.md),
and [security.md](docs/security.md) before changing protocol or lifecycle code.
