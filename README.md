# terminal-relay

Access your AI coding assistants from any device. Secure, end-to-end encrypted terminal mirroring for Claude Code, Aider, GitHub Copilot, Gemini, and any terminal-based AI tool.

## How it works

You run `terminal-relay start` on your dev machine. It spawns your AI tool in a PTY, connects to our hosted relay, and gives you a QR code. Scan it from your phone, tablet, or another machine to get a live, encrypted terminal session.

```text
Your Device                          Cloud                           Remote Device
┌─────────────┐                 ┌──────────────┐                 ┌──────────────┐
│  AI Tool     │                │ Relay Server │                 │ Web/Mobile   │
│  (Claude,    │◄──► PTY ◄──►  │ (zero-       │ ◄────────────► │ Client       │
│   Aider...)  │     CLI        │  knowledge)  │   E2E encrypted│              │
└─────────────┘                 └──────────────┘                 └──────────────┘
```

The relay is a dumb pipe — it forwards opaque encrypted bytes and never sees your data.

## Quick start

```bash
# Install
cargo install terminal-relay

# Start a session (connects to hosted relay automatically)
terminal-relay start

# Or specify a tool
terminal-relay start --tool claude
```

Scan the QR code from your remote device to attach.

### Manual attach (from another terminal)

```bash
terminal-relay attach --pairing-uri "termrelay://pair?..."
```

## Commands

```bash
terminal-relay start              # Start a session with auto-detected AI tool
terminal-relay start --tool aider # Start with a specific tool
terminal-relay attach             # Attach to a session via pairing URI
terminal-relay detect-tools       # List available AI tools on PATH
terminal-relay sessions           # List active/persisted sessions
```

## Supported AI tools

- **Claude Code** (Anthropic)
- **GitHub Copilot CLI** (Microsoft)
- **Gemini CLI** (Google)
- **Aider** (open source)
- Any terminal-based AI tool (via `--tool-arg`)

## What this repo includes

- `terminal-relay-cli`: the user-facing binary (`terminal-relay`)
- `terminal-relay-server`: the hosted relay service (users never run this)
- `terminal-relay-core`: shared protocol, crypto, and pairing primitives

## Security

- **End-to-end encryption**: AES-256-GCM with X25519 key exchange and HKDF-SHA256 key derivation
- **Zero-knowledge relay**: server only sees metadata (session ID, role, heartbeat) — never plaintext
- **Fingerprint verification**: pairing URI includes a fingerprint for identity verification
- **Replay protection**: strict monotonic nonce enforcement on every frame
- **No unsafe code**: `forbid(unsafe_code)` across the entire workspace

## Architecture

### Environments

| Environment | Relay URL                               | Use case                   |
| ----------- | --------------------------------------- | -------------------------- |
| Production  | `wss://relay.terminal-relay.dev/ws`     | End users                  |
| Development | `wss://dev-relay.terminal-relay.dev/ws` | Beta testers               |
| Local       | `ws://localhost:8080/ws`                | Contributors / self-hosted |

The relay URL is determined by build profile. Users never configure it.

### Protocol

All WebSocket messages are bincode-encoded.

**Relay-level** (`RelayMessage`): Register, Registered, Route, PeerStatus, Ping/Pong, Error

**E2E-level** (`PeerFrame` inside Route payload): Handshake (X25519 public key exchange), Secure (AES-GCM sealed), KeepAlive

**Application-level** (`SecureMessage` inside Secure): PtyInput, PtyOutput, Resize, Heartbeat, VersionNotice, Notification

### Cryptography

- DH: X25519
- KDF: HKDF-SHA256 with session ID as salt
- AEAD: AES-256-GCM
- Nonce: monotonically increasing u64 expanded into 96-bit nonce
- Replay check: strict monotonic inbound nonce enforcement

## Development

```bash
# Run the relay server locally
cargo run -p terminal-relay-server -- --bind 0.0.0.0:8080

# Run the CLI against local relay
cargo run -p terminal-relay-cli -- start --relay-url ws://127.0.0.1:8080/ws --tool auto

# Attach from another terminal
cargo run -p terminal-relay-cli -- attach --pairing-uri "termrelay://pair?..."
```

## Current status

Working foundation with PTY relay, reconnect, QR pairing, E2E encryption, and session persistence. See [TODO.md](TODO.md) for the roadmap.

## License

Terminal Relay is licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in **Terminal Relay** by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
