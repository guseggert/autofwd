# autofwd

Automatic port forwarding for SSH sessions. Detects listening ports on a remote server and forwards them to your local machine — like VS Code/Cursor, but for the terminal.

## Features

- **Automatic detection** — monitors `/proc/net/tcp` on the remote host and forwards new ports as they appear
- **TUI interface** — view and manage forwarded ports in real-time
- **Toggle forwards** — enable/disable individual port forwards without disconnecting
- **Smart port mapping** — automatically finds free local ports when there's a collision
- **SSH ControlMaster** — uses a single SSH connection for all operations

## Installation

### From releases

Download the latest binary for your platform from [Releases](https://github.com/anomalyco/autofwd/releases).

### From source

```bash
cargo install --path .
```

## Usage

```bash
autofwd user@hostname
```

This opens an SSH connection and starts monitoring for listening ports. When a service starts listening (e.g., a dev server on port 3000), it's automatically forwarded to the same port locally.

### Options

```
autofwd [OPTIONS] <TARGET> [-- <SSH_ARGS>...]

Arguments:
  <TARGET>       SSH target, e.g. user@host or host
  [SSH_ARGS]...  Extra args to pass to ssh (after --), e.g. -i key -p 2222

Options:
      --interval <INTERVAL>          Poll interval for scanning [default: 1s]
      --allow <ALLOW>                Only forward ports in this allowlist, e.g. "3000,5173,8000-9000"
      --collision-tries <N>          If local port is taken, try next N ports [default: 50]
  -h, --help                         Print help
```

### Examples

Forward all detected ports:
```bash
autofwd myserver
```

Only forward specific ports:
```bash
autofwd myserver --allow "3000,8080,5173"
```

With custom SSH options:
```bash
autofwd myserver -- -i ~/.ssh/mykey -p 2222
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑`/`k`/`Ctrl+P` | Move selection up |
| `↓`/`j`/`Ctrl+N` | Move selection down |
| `Space` | Toggle port forwarding |
| `e` | Toggle events log |
| `?` | Show help |
| `q`/`Esc` | Quit (with confirmation) |

## Requirements

- Remote host must be Linux (reads `/proc/net/tcp`)
- SSH access to the remote host

## How it works

1. Establishes an SSH ControlMaster connection to the remote host
2. Runs a monitoring script that periodically reads `/proc/net/tcp` and `/proc/net/tcp6`
3. Parses the output to detect listening ports owned by your user
4. Uses SSH's `-O forward` to dynamically add port forwards through the ControlMaster
5. Displays everything in a terminal UI

## License

MIT
