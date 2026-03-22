# terminal-relay

Access your AI coding assistants from any device. Secure, end-to-end encrypted terminal mirroring with structured agent events for Claude Code, Aider, GitHub Copilot, Gemini, and any terminal-based AI tool.

## How it works

Run `terminal-relay start claude` on your dev machine. Claude Code launches in a PTY and you get a QR code. Scan it from your phone to get a live, encrypted session — both a terminal mirror and a structured view with native UI for tool calls, thinking indicators, and prompts.

```
Your Machine                         Cloud                          Your Phone
┌──────────────────┐           ┌──────────────┐           ┌──────────────────┐
│ Claude Code      │           │ Relay Server │           │ Structured View  │
│ (real TUI)       │◄── PTY ──│ (zero-       │── E2E ───│ (native cards)   │
│                  │           │  knowledge)  │ encrypted │                  │
│ Desktop: Enter   │           │              │           │ Terminal View    │
│ to take over     │           │              │           │ (raw PTY mirror) │
└──────────────────┘           └──────────────┘           └──────────────────┘
```

**Desktop** gets the real Claude Code TUI via takeover mode. **Phone** gets structured events (thinking, tool calls, text) as native UI cards, plus a terminal view toggle. Both can send input simultaneously. The relay is a dumb pipe — it forwards opaque encrypted bytes and never sees your data.

## Install

```bash
# macOS / Linux (recommended)
curl -fsSL https://raw.githubusercontent.com/yipjunkai/terminal-relay/main/install.sh | sh

# From source
cargo install --git https://github.com/yipjunkai/terminal-relay -p cli

# Docker (relay server only)
docker pull ghcr.io/yipjunkai/terminal-relay:latest
```

## Quick start

```bash
# Start a session (auto-detects your AI tool)
terminal-relay start

# Or specify a tool with extra args
terminal-relay start claude
terminal-relay start aider --model sonnet
```

Scan the QR code from your phone to connect. On the host:

- **Enter** — take over the terminal (you type directly into Claude Code)
- **Double-tap Esc** — return to the dashboard
- **q** — quit the session

### Manual attach (from another terminal)

```bash
terminal-relay attach --pairing-uri "termrelay://pair?..."
```

## What your phone sees

For tools that support structured output (currently Claude Code), the phone shows two views:

**Structured view** (default for Claude Code):

- Thinking blocks (purple cards with reasoning)
- Tool call cards (tool name, arguments)
- Tool results (output, truncated to 32KB)
- Text responses
- Turn markers and busy indicator
- Prompt bar with mic/send button (Telegram-style)

**Terminal view** (toggle via AppBar button):

- Raw PTY output mirror — exactly what the desktop sees
- Bottom sheet with terminal actions (Ctrl+C, arrows, paste, etc.)

Both views update in real-time as Claude Code works. The structured events come from tailing Claude Code's `.jsonl` session log (`~/.claude/projects/`), not from parsing terminal output.

## Commands

```bash
terminal-relay start                  # Auto-detect and start AI tool
terminal-relay start claude           # Start Claude Code
terminal-relay start aider --model x  # Start with extra args
terminal-relay attach --pairing-uri   # Attach from another terminal
terminal-relay doctor                 # Diagnose environment
terminal-relay auth                   # Authenticate (hosted relay)
terminal-relay completions zsh        # Generate shell completions
terminal-relay --version              # Show version
```

## Supported AI tools

Auto-detected in order of priority:

| Tool                               | Structured events | Notes                                          |
| ---------------------------------- | :---------------: | ---------------------------------------------- |
| **Claude Code** (Anthropic)        |        Yes        | JSONL session log tailing for native mobile UI |
| **OpenCode** (open source)         |     PTY only      |                                                |
| **GitHub Copilot CLI** (Microsoft) |     PTY only      |                                                |
| **Gemini CLI** (Google)            |     PTY only      |                                                |
| **Aider** (open source)            |     PTY only      |                                                |
| Any command on PATH                |     PTY only      | `terminal-relay start my-tool`                 |

Tools without structured support work via PTY mirroring — the phone shows a terminal emulator.

## Architecture

### Dual-channel design

For Claude Code, the host sends two parallel streams through the same encrypted channel:

```
Claude Code (PTY)
├── Raw PTY bytes ──→ SecureMessage::PtyOutput ──→ Phone terminal view
│
└── ~/.claude/projects/<hash>/<session>.jsonl
    └── JSONL watcher (notify/kqueue) ──→ SecureMessage::AgentEvent ──→ Phone structured view
```

The JSONL watcher tails Claude Code's session log file using filesystem notifications. It parses assistant messages, tool calls, tool results, thinking blocks, and turn completion (`stop_reason: "end_turn"`). These are emitted as `AgentEvent` variants through the same E2E encrypted channel.

Phone input flows back via `AgentCommand::Prompt` which gets injected into the PTY as keystrokes (`text + \r`). Tool approvals send `y\r`, denials send `n\r`.

### Takeover mode

Press Enter on the host dashboard to take over the PTY directly:

1. TUI dashboard suspends, terminal switches to raw mode
2. PTY output displays on your screen (Ctrl+L redraw on entry)
3. Your keyboard input goes directly to the PTY
4. Terminal resizes are forwarded to the PTY
5. PTY output simultaneously flows to the phone via relay
6. Double-tap Esc returns to the dashboard

Both desktop and phone can send input at any time. There's no locking — the PTY processes input from both sources.

### Protocol layers

All WebSocket messages are MessagePack-encoded across three layers:

**Relay-level** (`RelayMessage`): Register, Registered, Route, PeerStatus, Ping/Pong, Error

**E2E-level** (`PeerFrame` inside Route payload): Handshake, HandshakeConfirm, Secure (AES-GCM sealed), KeepAlive

**Application-level** (`SecureMessage` inside Secure):

- Terminal: `PtyInput`, `PtyOutput`, `Resize`
- Agent: `AgentEvent`, `AgentCommand`
- Session: `Heartbeat`, `VersionNotice`, `Notification`, `SessionEnded`, `ReadOnly`
- Voice: `VoiceCommand`

### Crates

| Crate      | Description                                                                              |
| ---------- | ---------------------------------------------------------------------------------------- |
| `cli`      | User-facing binary (`terminal-relay`), PTY management, JSONL watcher, TUI, takeover mode |
| `relay`    | Zero-knowledge relay server                                                              |
| `protocol` | Shared protocol types, crypto (X25519 + AES-256-GCM), pairing primitives                 |

A Flutter mobile app (iOS + Android) is available separately as the primary mobile client.

## Security

Terminal Relay is designed so that **no one except you and your connected device can read your terminal data** — not us, not the relay operator, not anyone on the network.

### Threat model

The relay server is assumed to be **honest-but-curious**: it faithfully forwards messages but may attempt to read them. All terminal data is encrypted end-to-end before it reaches the relay, so a compromised or malicious relay learns nothing beyond metadata (session ID, peer role, message timing and size).

### End-to-end encryption

Every session establishes a unique encrypted channel between the host (your dev machine) and the client (your phone/tablet/other terminal):

1. **Key exchange**: Each side generates an ephemeral X25519 key pair. Public keys are exchanged via the relay inside `Handshake` messages.
2. **Key derivation**: Both sides compute a shared secret via Diffie-Hellman, then derive two 256-bit symmetric keys (one per direction) using HKDF-SHA256 with the session ID as salt and `terminal-relay/v1/channel-keys` as the info string.
3. **Encryption**: All terminal I/O and agent events are sealed with AES-256-GCM before transmission. Each frame carries a monotonically increasing nonce.
4. **Key confirmation**: After key derivation, both sides exchange an HMAC-SHA256 over the handshake transcript, proving each peer holds the private key corresponding to their advertised public key.

### Replay and reorder protection

Every encrypted frame includes a strictly monotonic 64-bit nonce. The receiver rejects any frame with a nonce less than or equal to the last accepted nonce.

### Identity verification

The pairing URI (displayed as a QR code) includes a SHA-256 fingerprint of the host's public key. The client verifies this fingerprint on connection, detecting any man-in-the-middle substitution by the relay.

### Zero-knowledge relay

The relay server sees only session ID, peer role, message size, and timing. It **never** sees plaintext terminal content, keystrokes, agent events, public keys, or encryption keys. The relay cannot decrypt, modify, or forge messages — any tampering is detected by AES-GCM authentication.

### Structured events and security

The new `AgentEvent` and `AgentCommand` message types go through the same `SecureChannel::seal()`/`open()` pipeline as all other messages. The JSONL watcher reads files from `~/.claude/projects/` — a trusted local directory written by Claude Code. Tool results are truncated to 32KB before transmission to prevent large payloads. No new attack surface is introduced.

### Cryptographic primitives

| Purpose              | Algorithm                        | Notes                                            |
| -------------------- | -------------------------------- | ------------------------------------------------ |
| Key exchange         | X25519                           | Ephemeral per-session key pairs                  |
| Key derivation       | HKDF-SHA256                      | Session ID as salt, domain-separated info string |
| Authenticated cipher | AES-256-GCM                      | Per-frame encryption with monotonic nonce        |
| Key confirmation     | HMAC-SHA256                      | MAC over handshake transcript                    |
| Fingerprint          | SHA-256 (truncated)              | First 8 bytes of public key hash                 |
| At-rest encryption   | AES-256-GCM                      | Random nonce per file, machine-local key         |
| Nonce construction   | 4 zero bytes + 8-byte BE counter | 96-bit nonce from 64-bit counter                 |

### What Terminal Relay does NOT protect against

- **Compromised endpoints**: If your machine or phone is compromised, the attacker has access to the decrypted session.
- **Traffic analysis**: The relay can see message timing and sizes, revealing activity patterns.
- **Denial of service**: A malicious relay can drop or delay messages (but cannot read or forge content).

## Self-hosting

Run your own relay server — no account, API key, or control API needed:

```bash
# From source
cargo run -p relay -- --bind 0.0.0.0:8080

# With Docker
docker run -p 8080:8080 ghcr.io/yipjunkai/terminal-relay:latest
```

Point the CLI at your relay:

```bash
TERMINAL_RELAY_URL=ws://your-server:8080/ws terminal-relay start
```

> **Note:** `terminal-relay auth` is for the hosted service only. Self-hosted relays run unauthenticated by default.

## Development

```bash
# Run the relay server locally
cargo run -p relay -- --bind 0.0.0.0:8080

# Run the CLI against local relay
TERMINAL_RELAY_URL=ws://127.0.0.1:8080/ws cargo run -p cli -- start

# Run with hosted service features (auth, device flow)
TERMINAL_RELAY_URL=ws://127.0.0.1:8080/ws cargo run -p cli --features hosted -- start

# Run tests
cargo test
```

### Feature flags

| Build command                          | Includes auth? | Use case                   |
| -------------------------------------- | -------------- | -------------------------- |
| `cargo build -p cli`                   | No             | Self-hosted / contributors |
| `cargo build -p cli --features hosted` | Yes            | Hosted service users       |

## License

Terminal Relay is licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

at your option.
