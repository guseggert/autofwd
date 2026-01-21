# autofwd

Automatic port forwarding for SSH sessions. Detects listening ports on a remote server and forwards them to your local machine — like VS Code/Cursor, but for the terminal.

## Features

- **Automatic detection** — monitors listening ports on the remote host and forwards them as they appear
- **Process names** — shows which process owns each port (e.g., `node`, `python`, `nginx`)
- **TUI interface** — view and manage forwarded ports in real-time
- **Toggle forwards** — enable/disable individual port forwards without disconnecting
- **Smart port mapping** — automatically finds free local ports when there's a collision
- **SSH ControlMaster** — uses a single SSH connection for all operations
- **Zero dependencies on remote** — works on any Linux server, no installation required

## Installation

### From releases

Download the latest binary for your platform from [Releases](https://github.com/anomalyco/autofwd/releases).

### From source

```bash
# Install mise (or use cargo directly)
brew install mise

# Build with embedded agent binaries (requires Docker for cross-compilation)
mise run build

# Or for development (uses shell fallback, no cross-compilation needed)
mise run build-dev
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
      --interval <INTERVAL>          Poll interval for scanning [default: 200ms]
      --allow <ALLOW>                Only forward ports in this allowlist, e.g. "3000,5173,8000-9000"
      --collision-tries <N>          If local port is taken, try next N ports [default: 50]

By default, system ports (SSH, DNS, databases, etc.) and high ports (32768-65535) are excluded.
Use --allow to override and forward specific ports.
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

- **Remote**: Linux (x86_64, aarch64, or armv7)
- **Local**: SSH client with ControlMaster support
- **Network**: SSH access to the remote host

## How it works

autofwd uses a lightweight agent binary that runs on the remote server to monitor listening ports.

### Architecture

```
┌─────────────────┐         SSH          ┌─────────────────┐
│   Local (TUI)   │◄────────────────────►│  Remote Server  │
│                 │                       │                 │
│  - Display UI   │   ControlMaster      │  - Agent binary │
│  - Manage fwds  │◄────────────────────►│  - Port monitor │
│                 │   Port forwards      │  - Process info │
└─────────────────┘                       └─────────────────┘
```

### Startup sequence

1. **Connect** — Establishes an SSH ControlMaster connection
2. **Deploy agent** — Uploads a small (~250KB) static binary to `/tmp/autofwd-agent-<hash>`
3. **Monitor** — Agent runs `netstat` to detect listening ports and their owning processes
4. **Forward** — Uses SSH's `-O forward` to dynamically add/remove port forwards
5. **Display** — Shows everything in a terminal UI with real-time updates

### Agent vs Shell fallback

The TUI header shows the current monitoring mode:

- **`[agent]`** (green) — Using the deployed agent binary. Full functionality including process names.
- **`[shell]`** (yellow) — Fallback mode using a shell script. Port forwarding works, but process names are unavailable.

The shell fallback is used when:
- The remote architecture isn't supported (only x86_64, aarch64, armv7 Linux are bundled)
- Agent deployment fails for any reason
- Running a development build without compiled agents

### Supported platforms

| Remote OS | Architectures |
|-----------|---------------|
| Linux | x86_64, aarch64 (arm64), armv7 |

The local machine can be any platform that supports Rust (macOS, Linux, Windows).

## License

MIT
