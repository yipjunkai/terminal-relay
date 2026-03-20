# terminal-relay

Access your AI coding assistants from any device. Secure, end-to-end encrypted terminal mirroring for Claude Code, Aider, GitHub Copilot, Gemini, and any terminal-based AI tool.

## How it works

You run `terminal-relay start` on your dev machine. It spawns your AI tool in a PTY, connects to our hosted relay, and gives you a QR code. Scan it from your phone, tablet, or another machine to get a live, encrypted terminal session.

```text
Your Device                          Cloud                           Remote Device
┌─────────────┐                 ┌──────────────┐                 ┌──────────────┐
│  AI Tool     │                │ Relay Server │                 │ iOS/Android  │
│  (Claude,    │◄──► PTY ◄──►  │ (zero-       │ ◄────────────► │ App or CLI   │
│   Aider...)  │     CLI        │  knowledge)  │   E2E encrypted│              │
└─────────────┘                 └──────────────┘                 └──────────────┘
```

The relay is a dumb pipe — it forwards opaque encrypted bytes and never sees your data.

## Install

```bash
# macOS (Homebrew)
brew install yipjunkai/terminal-relay/terminal-relay

# macOS / Linux (script)
curl -fsSL https://raw.githubusercontent.com/yipjunkai/terminal-relay/main/install.sh | sh

# From source
cargo install --git https://github.com/yipjunkai/terminal-relay --package cli
```

## Quick start

```bash
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
terminal-relay start                      # Start with auto-detected AI tool
terminal-relay start --tool opencode      # Start with a specific known tool
terminal-relay start --tool my-custom-ai  # Start with any command on PATH
terminal-relay attach --pairing-uri "..." # Attach to a session
terminal-relay detect-tools               # List available AI tools on PATH
terminal-relay sessions                   # List active/persisted sessions
terminal-relay --version                  # Show version
```

## Supported AI tools

Auto-detected in order of priority:

- **Claude Code** (Anthropic)
- **OpenCode** (open source)
- **GitHub Copilot CLI** (Microsoft)
- **Gemini CLI** (Google)
- **Aider** (open source)
- Any terminal-based AI tool (via `--tool <command>`)

## What this repo includes

- `cli`: the user-facing binary (`terminal-relay`)
- `relay`: the zero-knowledge relay server
- `protocol`: shared protocol, crypto, and pairing primitives

A Flutter mobile app (iOS + Android) is available separately as the primary mobile client, with speech-to-code support for hands-free interaction with your AI tools.

## Security

Terminal Relay is designed so that **no one except you and your connected device can read your terminal data** — not us, not the relay operator, not anyone on the network.

### Threat model

The relay server is assumed to be **honest-but-curious**: it faithfully forwards messages but may attempt to read them. All terminal data is encrypted end-to-end before it reaches the relay, so a compromised or malicious relay learns nothing beyond metadata (session ID, peer role, message timing and size).

### End-to-end encryption

Every session establishes a unique encrypted channel between the host (your dev machine) and the client (your phone/tablet/other terminal):

1. **Key exchange**: Each side generates an ephemeral X25519 key pair. Public keys are exchanged via the relay inside `Handshake` messages.
2. **Key derivation**: Both sides compute a shared secret via Diffie-Hellman, then derive two 256-bit symmetric keys (one per direction) using HKDF-SHA256 with the session ID as salt and `terminal-relay/v1/channel-keys` as the info string.
3. **Encryption**: All terminal I/O is sealed with AES-256-GCM before transmission. Each frame carries a monotonically increasing nonce.
4. **Key confirmation**: After key derivation, both sides exchange an HMAC-SHA256 over the handshake transcript (`local_public || remote_public || session_id`), proving each peer holds the private key corresponding to their advertised public key. The channel is not trusted until confirmation succeeds.

### Replay and reorder protection

Every encrypted frame includes a strictly monotonic 64-bit nonce. The receiver rejects any frame with a nonce less than or equal to the last accepted nonce. This prevents:

- **Replay attacks**: re-sending a previously captured frame.
- **Reorder attacks**: delivering frames out of sequence.

Skipped nonces are tolerated (for dropped packets), but going backward is always rejected.

### Handshake freshness

Each `Handshake` message includes a `timestamp_ms` field. The receiver rejects handshakes older than 5 minutes, preventing stale or pre-recorded handshake replay.

### Identity verification

The pairing URI (displayed as a QR code or copied manually) includes a SHA-256 fingerprint of the host's public key. The client verifies this fingerprint on connection, detecting any man-in-the-middle substitution of public keys by the relay.

### Zero-knowledge relay

The relay server sees only:

- Session ID and peer role (Host or Client)
- Message size and timing
- Connection metadata (IP, WebSocket headers)

It **never** sees plaintext terminal content, keystrokes, public keys (they're inside opaque `Route` payloads), or encryption keys. The relay cannot decrypt, modify, or forge messages between peers — any tampering is detected by AES-GCM authentication.

### At-rest encryption

Session state files (stored in `~/.terminal-relay/sessions/`) contain key material and are encrypted with AES-256-GCM using a machine-local state key (`~/.terminal-relay/state.key`). File permissions are restricted to owner-only (`0600` for files, `0700` for directories) on Unix systems.

### Memory safety

- All secret key material (`KeyPair`, `SessionKeys`, `SecureChannel`) is automatically zeroed from memory on drop via the `zeroize` crate, preventing secrets from lingering in freed memory.
- `KeyPair` intentionally does not implement `Clone`, preventing accidental duplication of secret material.
- `forbid(unsafe_code)` is enforced across the entire workspace — no raw pointer manipulation, no `transmute`, no undefined behavior.

### Cryptographic primitives

| Purpose              | Algorithm                                | Notes                                                  |
| -------------------- | ---------------------------------------- | ------------------------------------------------------ |
| Key exchange         | X25519                                   | Ephemeral per-session key pairs                        |
| Key derivation       | HKDF-SHA256                              | Session ID as salt, domain-separated info string       |
| Authenticated cipher | AES-256-GCM                              | Per-frame encryption with monotonic nonce              |
| Key confirmation     | HMAC-SHA256                              | MAC over handshake transcript with derived session key |
| Fingerprint          | SHA-256 (truncated)                      | First 8 bytes (16 hex chars) of public key hash        |
| At-rest encryption   | AES-256-GCM                              | Random nonce per file, machine-local key               |
| Nonce construction   | 4 zero bytes + 8-byte big-endian counter | 96-bit nonce from 64-bit counter                       |

### Server-side hardening

The relay server enforces several defensive measures even though it never sees plaintext:

- **Input validation**: `session_id` must be valid UUID v4, `pairing_code` must match the `XXXXXX-XXXXXX-XXXXXX` format, and all `RegisterRequest` string fields are length-bounded to prevent abuse.
- **Route isolation**: the relay validates that every `Route` message's `session_id` matches the sender's registered session, preventing cross-session message injection.
- **Pairing rate limiting**: failed pairing-code attempts are tracked per session. After 5 failures the session is locked out, mitigating brute-force pairing code guessing.

### What Terminal Relay does NOT protect against

- **Compromised endpoints**: If your dev machine or remote device is compromised, the attacker has access to the decrypted terminal session (same as if they were sitting at your keyboard).
- **Traffic analysis**: The relay and network observers can see message timing and sizes, which may reveal activity patterns (e.g. "the user is typing" vs "the AI is generating output").
- **Denial of service**: A malicious relay can drop or delay messages, disrupting the session (but cannot read or forge content).

## Architecture

### Environments

| Environment | Relay URL                               | Use case                   |
| ----------- | --------------------------------------- | -------------------------- |
| Production  | `wss://relay.terminal-relay.dev/ws`     | End users                  |
| Development | `wss://dev-relay.terminal-relay.dev/ws` | Beta testers               |
| Local       | `ws://localhost:8080/ws`                | Contributors / self-hosted |

The relay URL defaults to production. Override with `TERMINAL_RELAY_URL` env var for development or self-hosted use.

### Protocol

All WebSocket messages are MessagePack-encoded across three layers:

**Relay-level** (`RelayMessage`): Register, Registered, Route, PeerStatus, Ping/Pong, Error

**E2E-level** (`PeerFrame` inside Route payload): Handshake, HandshakeConfirm, Secure (AES-GCM sealed), KeepAlive

**Application-level** (`SecureMessage` inside Secure): PtyInput, PtyOutput, Resize, Heartbeat, VersionNotice, Notification

## Self-hosting

Run your own relay server:

```bash
# From source
cargo run -p relay -- --bind 0.0.0.0:8080

# With Docker
docker run -p 8080:8080 ghcr.io/yipjunkai/terminal-relay:latest

# With session limits
cargo run -p relay -- --bind 0.0.0.0:8080 \
  --max-sessions 100 \
  --max-sessions-per-ip 10
```

Point the CLI at your relay:

```bash
TERMINAL_RELAY_URL=ws://your-server:8080/ws terminal-relay start
```

### Relay server flags

| Flag                    | Env var                     | Default         | Description             |
| ----------------------- | --------------------------- | --------------- | ----------------------- |
| `--bind`                | —                           | `0.0.0.0:8080`  | Listen address          |
| `--max-sessions`        | `RELAY_MAX_SESSIONS`        | `0` (unlimited) | Global session cap      |
| `--max-sessions-per-ip` | `RELAY_MAX_SESSIONS_PER_IP` | `0` (unlimited) | Per-IP session cap      |
| `--session-ttl-secs`    | —                           | `86400` (24h)   | Inactive session expiry |
| `--min-version`         | —                           | `0.1.0`         | Minimum client version  |

## Development

```bash
# Run the relay server locally
cargo run -p relay -- --bind 0.0.0.0:8080

# Run the CLI against local relay
TERMINAL_RELAY_URL=ws://127.0.0.1:8080/ws cargo run -p cli -- start

# Attach from another terminal
cargo run -p cli -- attach --pairing-uri "termrelay://pair?..."

# Run tests
cargo test
```

## License

Terminal Relay is licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in **Terminal Relay** by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
