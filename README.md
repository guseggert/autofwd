# autofwd

Automatic SSH port forwarding. Detects listening ports on a remote server and auto-forwards them to your local machine. Inspired by VS Code's port forwarding.

![autofwd demo](docs/demo.gif)

## Installation

### From releases

Download the latest binary for your platform from [Releases](https://github.com/guseggert/autofwd/releases).

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

## Requirements

- **Remote**: Linux (x86_64, aarch64, or armv7)
- **Local**: SSH client with ControlMaster support

## How it works

autofwd uses a lightweight agent binary that runs on the remote server to monitor listening ports.

The client includes support for any remote architecture. It detects the architecture and installs the right agent binary at runtime.

If the remote client can't be used for some reason, autofwd falls back to running a remote shell script.

## License

MIT
