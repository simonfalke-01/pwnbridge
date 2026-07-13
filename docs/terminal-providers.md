# Terminal providers

Pwnbridge treats pane creation as a local presentation concern. Pwntools, GDB,
gdbserver, and the inferior execute remotely; a host provider opens a local pane
containing a trusted helper and a second SSH PTY.

List detection and capabilities at any time:

```console
pwnbridge terminal providers
pwnbridge terminal providers --json
pwnbridge terminal test --provider zellij --placement right --size 50%
```

## Automatic selection

For `scope = "host"`, automatic order is:

1. the current Zellij session;
2. the current tmux client/pane;
3. the current supported terminal application;
4. macOS Terminal.app;
5. an actionable error.

Pwnbridge never forwards local `$ZELLIJ*`, `$TMUX`, or `$TMUX_PANE` values to
Ubuntu. This avoids triggering pwntools' remote multiplexer detection and lets
the Mac provider remain authoritative.

Make a provider explicit in global configuration:

```toml
[terminal]
provider = "zellij"
scope = "host"
placement = "right"
size = "50%"
focus = true
close_on_success = true
hold_on_failure = true
```

`close_on_success` closes a provider handle after clean GDB exit.
`hold_on_failure` keeps an interactive pane available for diagnostics when the
helper fails. Natural close, parent cancellation, and Pwnbridge shutdown are
idempotent.

## Zellij

Zellij is first-class and supports `right`, `down`, `tab`, and `floating`.
Pwnbridge invokes the CLI with an argv array, captures stable pane IDs where the
version provides them, and has rename/list recovery for ID output differences.

```toml
[terminal]
provider = "zellij"
placement = "right"
size = "50%"

[terminal.zellij]
near_current_pane = true
direction = "right"
floating = false
```

Set `placement = "tab"` for a new tab or `floating = true` for a floating pane.
`terminal test` can validate all four modes without a remote host.

The implementation is tested against Zellij 0.44.3. Provider detection checks
both the session environment and the executable; having `zellij` installed
outside a Zellij session is not enough for host-pane mode.

## tmux

tmux supports right/down splits and new windows (`placement = "tab"`). It uses
the current `$TMUX_PANE` as origin where available and stores the stable
`%pane_id` returned by `split-window -P`/`new-window -P`.

```toml
[terminal]
provider = "tmux"
placement = "right"

[terminal.tmux]
direction = "horizontal" # horizontal/right or vertical/down
size = "50%"
```

The implementation is tested against tmux 3.6a, including concurrent pwntools
debugger panes and deterministic close.

## WezTerm

When running inside WezTerm, Pwnbridge uses `wezterm cli split-pane` for right
or down and `wezterm cli spawn` for a tab. Returned pane IDs are retained for
focus/close operations. Detection requires the WezTerm environment and CLI.

```toml
[terminal]
provider = "wezterm"
placement = "right"
```

## Kitty

Kitty uses its remote-control CLI for `launch`, focus, and close. Detection
requires a Kitty session and executable. Right/down/tab placement maps to Kitty
location/type arguments.

```toml
[terminal]
provider = "kitty"
placement = "down"
```

## iTerm2 and Terminal.app

iTerm2 and Terminal.app are zero-configuration window fallbacks. Pwnbridge
creates a private mode-0700 temporary directory and a generated `.command` file
containing only the locally constructed helper argv, launches it through the
application, and removes its temporary state afterward.

These AppleScript/application launchers cannot offer the same stable pane
handle semantics as Zellij/tmux. Window-close behavior after helper exit follows
the terminal profile. They support `placement = "window"`.

```toml
[terminal]
provider = "terminal-app" # or iterm2
placement = "window"
```

## Custom providers

Set `provider = "custom:NAME"`. Pwnbridge resolves an executable named
`pwnbridge-terminal-NAME` on the Mac. It exchanges newline-independent JSON on
stdin/stdout using provider protocol 1.

An open request resembles:

```json
{
  "protocol": 1,
  "operation": "open",
  "value": {
    "session_id": "opaque",
    "request_id": "opaque",
    "cwd": "/local/challenge",
    "title": "pwntools GDB",
    "placement": "right",
    "size": "50%",
    "focus": true,
    "command": ["/trusted/pwnbridge", "__pane", "..."]
  }
}
```

The provider returns a JSON handle:

```json
{"provider":"custom:NAME","id":"stable-provider-id","aux":"optional"}
```

Subsequent `inspect`, `focus`, and `close` requests put that handle in `value`.
`inspect` returns `{"Exists":true,"Running":true}`; focus/close may return an
empty object.

Security rule: a custom provider receives only Pwnbridge's trusted local pane
helper. It never receives GDB argv from the remote manifest. Providers should
execute the `command` array directly and must not concatenate it into a shell
string.

## Explicit remote multiplexer scope

Remote scope is a fallback for headless use or servers that prohibit reverse
forwarding:

```toml
[terminal]
scope = "remote"
provider = "remote-tmux" # or remote-zellij / auto
placement = "right"
```

Pwnbridge starts the managed shell inside a named remote multiplexer and lets
the injected terminal wrapper split that same remote session. This produces a
nested multiplexer when the Mac is already in Zellij/tmux and is intentionally
not the default.

Remote scope:

- supports right/down placement only;
- requires tmux or Zellij installed on Ubuntu;
- does not use the Mac broker/provider path;
- is incompatible with container runtime;
- still preserves argv as individual multiplexer arguments.

## Pwntools configuration

Normally omit `context.terminal`; pwntools discovers the injected executable.
For templates that require an explicit setting:

```python
context.terminal = ["pwntools-terminal"]
```

Do not set it to local `zellij`, `tmux`, `open`, or an SSH command. Those bypass
Pwnbridge's runtime authority and lifecycle broker. See
[pwntools.md](pwntools.md).
