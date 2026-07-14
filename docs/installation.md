# Installation

## Supported topology

The supported complete topology is macOS ARM64/AMD64 as client and
Linux amd64 as execution host. The client is a native Darwin
binary; the remote agent is a static Linux amd64 binary deployed over SSH.
The supported macOS base supplies POSIX `diff`, which Pwnbridge uses only for
read-only unified conflict previews.

## Release archive

A Darwin release archive contains:

```text
pwnbridge
pwnbridge-agent-linux-amd64
README.md
PLAN.md
LICENSE
docs/
completions/
```

Keep the client and agent adjacent, place both somewhere on PATH, or set
`PWNBRIDGE_AGENT_PATH` to the agent's absolute path. Verify the release archive
with `checksums.txt` and the published attestation/SBOM before installation.

```console
tar -xzf pwnbridge_VERSION_Darwin_arm64.tar.gz
install -m 0755 pwnbridge ~/.local/bin/pwnbridge
ln -sf pwnbridge ~/.local/bin/pb
install -m 0755 pwnbridge-agent-linux-amd64 \
  ~/.local/bin/pwnbridge-agent-linux-amd64
```

Pwnbridge uploads the agent automatically on first use and whenever its content
hash changes. Nothing is manually installed into `/usr/local/bin` on Ubuntu.

## Homebrew

Install from the published tap with:

```console
brew install simonfalke-01/pwnbridge/pwnbridge
```

The formula installs the release Darwin client, the `pb` one-shot alias, its
matching static Linux agent in formula `libexec`, and shell completions. It
depends on the external Mutagen and Mosh formulas and never vendors either.

## Source build

Requirements are Go 1.25 or 1.26 and a C-free cross-build path:

```console
git clone https://github.com/simonfalke-01/pwnbridge.git
cd pwnbridge
make verify
make build
```

Outputs:

```text
bin/pwnbridge                         native Darwin client
bin/pwnbridge-agent-linux-amd64       static remote agent
```

The build is equivalent to:

```console
go build -trimpath -o bin/pwnbridge ./cmd/pwnbridge
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o bin/pwnbridge-agent-linux-amd64 \
  ./cmd/pwnbridge-agent
```

During source-tree development, export the agent path if the binary is not
adjacent to the invoked client:

```console
export PWNBRIDGE_AGENT_PATH="$PWD/bin/pwnbridge-agent-linux-amd64"
```

## Mutagen

Install Mutagen exactly 0.18.1. Mosh is optional unless you select it explicitly:

```console
brew install mutagen-io/mutagen/mutagen mosh
test "$(mutagen version)" = 0.18.1
```

Pwnbridge version-gates the executable and uses a private
`MUTAGEN_DATA_DIRECTORY`. It does not embed, link, or redistribute Mutagen.

## OpenSSH

macOS provides `ssh` and `scp`. Create an ordinary alias before registering a
host:

```sshconfig
Host pwnbox
    HostName 203.0.113.10
    User pwner
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 15
```

Confirm it without Pwnbridge:

```console
ssh pwnbox 'uname -s; uname -m'
```

Do not add options that disable host verification or forward your agent merely
for Pwnbridge. Pwnbridge supplies its own no-agent/no-X11 channel options.

## Shell completions

Release archives include generated completions. They can also be generated
from the installed executable:

```console
pwnbridge completion zsh  > ~/.zfunc/_pwnbridge
pwnbridge completion bash > ~/.local/share/bash-completion/completions/pwnbridge
pwnbridge completion fish > ~/.config/fish/completions/pwnbridge.fish
```

For Zsh, ensure the chosen directory is in `fpath` before `compinit`.

## Remote bootstrap

Registration is machine-local:

```console
pwnbridge host add x86 pwnbox --check
pwnbridge host bootstrap x86 --dry-run
pwnbridge host bootstrap x86
pwnbridge host doctor x86
```

The host name is a small local identifier (ASCII letters, digits, `.`, `_`, and
`-`); the destination remains your normal OpenSSH alias. Checked registration
uses bounded read-only inventory and temporary forwarding probes and saves only
when the built-in `pwn` plan can prepare the host. It validates platform,
capacity, ptrace policy, and scope-required forwarding; it does not require
installable bootstrap tools to exist yet. The first host becomes the default.
Existing names require `--replace`, and a failed checked replacement preserves
the old record. Add without `--check` when a strictly offline local registration
is intentional.

Doctor verifies the
remote platform, toolchain, disk/inodes, ptrace, pinned pwntools environment,
reverse forwarding, configured container engine, and explicit Mosh
prerequisites when selected. Mosh and forwarding diagnostics do not prevent the
default predictive inline shell, plain SSH, one-shot runs, or
`terminal.scope = "remote"` operation.
Doctor uses bounded read-only inventory plus a temporary forwarding probe; it
does not deploy the agent or install anything. Its partial report identifies a
timed-out/unavailable collector separately from a completed missing-capability
check. `host bootstrap` is the explicit remote mutation step; checked add and
doctor never deploy, copy, install, invoke sudo, or write remotely.

The default TTY command is an inline wizard. It inventories the host, lets you
choose `pwn`, `minimal`, a saved recipe, or custom components, then reviews the
exact install/repair/skip plan before ordinary terminal sudo authentication.
It never clears the terminal or enters the alternate screen. For automation:

```console
pwnbridge host bootstrap x86 --interactive=never --profile pwn --yes
```

The `pwn` recipe installs `mosh-server` and standard build/debug packages,
creates `~/.local/share/pwnbridge/envs/pwn-v1`, and enforces pwntools 4.15.0.
Optional Pwndbg is pinned and checksum verified:

```console
pwnbridge host bootstrap x86 --with-pwndbg
```

Bootstrap supports apt, dnf/yum, pacman, zypper, apk, XBPS, Portage, and Nix
adapters on Linux amd64. It is additive and safe to rerun after interruption.
Use `pwnbridge config bootstrap` to manage named portable recipes.

Mosh requires inbound UDP. Its default configured range is 60000–61000; allow
that range in both the host firewall and cloud security group, or narrow
`hosts.NAME.mosh_port` to a permitted port/range. SSH remains required because
Mosh uses it for authentication and Pwnbridge uses it for its control plane.

## Verify installation

```console
pwnbridge --version
pwnbridge version --json
pwnbridge doctor
pwnbridge terminal providers
pwnbridge host default x86
cd /path/to/challenge
pwnbridge host use x86
pwnbridge run -- uname -m
```

`host default` sets the machine-wide fallback; `host use` creates an override
for this verification project, and `host use --default` would remove it. In
`host list`, `*` marks the machine default and `>` marks the current project's
effective host. The final command must print `x86_64` even on an Apple Silicon
Mac.
