# TODO

## Hosted relay service

- [ ] Deploy the relay server to a cloud provider (Fly.io, Railway, or similar). Set up `wss://relay.terminal-relay.dev/ws` for production.
- [x] Hardcode the production relay URL into the CLI binary so users never configure it. Support environment-based URL selection (production, development, local) via env var (`TERMINAL_RELAY_URL`).
- [ ] Set up a development relay at `wss://dev-relay.terminal-relay.dev/ws` for beta testing.
- [ ] Add TLS termination (via reverse proxy or native rustls) for the production relay.
- [ ] Add authn/authz and tenant isolation for the hosted relay (API keys, account system, or anonymous with rate limits).
- [ ] Add a maximum session count and per-IP session limits on the relay to prevent abuse.
- [ ] Enrich the `/healthz` endpoint to return structured JSON with session count, uptime, and server version.
- [ ] Add multi-region relay support with geo-routing so clients connect to the nearest relay for lower latency.

## Clients

- [ ] Build a web client (xterm.js + WebSocket + WebCrypto) with encrypted attach, bidirectional input, terminal resize, and responsive layout for mobile browsers.
- [ ] Add PWA support (manifest, service worker, home screen install) for quick access from mobile home screens.
- [ ] Build native iOS app (Swift) with speech-to-code: on-device speech recognition that converts voice commands into coding actions (refactor, commit, debug) sent as encrypted `PtyInput` to the host session.
- [ ] Build native Android app (Kotlin) with the same speech-to-code functionality, using on-device ML Kit speech recognition.
- [ ] Add a `VoiceCommand` variant to `SecureMessage` for structured voice-to-action messages (distinct from raw `PtyInput`) so the host can interpret intent rather than raw text.
- [ ] Add push notifications via APNS (iOS) and FCM (Android) for session events (peer connected, session ended, tool output idle).
- [ ] Generate shareable web URLs (e.g. `https://terminal-relay.dev/s/<token>`) that open the web client with pairing info embedded, so the remote side doesn't need the CLI installed.

## User experience

- [ ] Add a first-run setup flow: detect installed AI tools, confirm default tool, display a quick-start summary.
- [ ] Add human-readable session names (e.g. `claude-backend-a3f`) instead of raw UUIDs in CLI output and QR codes.
- [ ] Add a user config file (`~/.terminal-relay/config.toml`) for default tool, default args, and preferences.
- [ ] Add shell completions generation (`terminal-relay completions bash/zsh/fish`).
- [ ] Add auto-update check on startup: warn the user if a newer CLI version is available (with `--no-update-check` to suppress).
- [ ] Add a connection quality indicator on the attach side (latency, connection state) rendered in a status bar.
- [ ] Add read-only attach mode (`--read-only`) for demos and presentations where the remote side can only watch.
- [ ] Add session idle timeout: automatically stop sessions after configurable inactivity (default 1 hour).
- [ ] Add colored/formatted CLI output for session status, pairing info, and error messages instead of raw `println!`.

## Security

- [ ] Encrypt session state files at rest and restrict file permissions (`chmod 0600` on session JSON, `0700` on `~/.terminal-relay/`). Secret keys are currently stored in plaintext.
- [ ] Derive `ZeroizeOnDrop` on `KeyPair`, `SessionKeys`, and `SecureChannel` so secret material is cleared from memory on drop. Remove `Clone` from `KeyPair`.
- [ ] Add a key confirmation step after the DH handshake (e.g. MAC over transcript) to prove each peer holds the private key. Validate `timestamp_ms` to reject stale/replayed handshakes.
- [ ] Rate-limit failed pairing-code attempts per session on the relay. Lock out after N failures and log with source IP.
- [ ] Validate `Route.session_id` matches the sender's registered session before forwarding, preventing cross-session message injection.
- [ ] Validate `session_id` (UUID v4 format) and `pairing_code` format on the server. Enforce max lengths on all `RegisterRequest` string fields.

## Reliability

- [ ] Add graceful shutdown to the relay server (`tokio::signal` + `with_graceful_shutdown`). Send WebSocket close frames and cancel the cleanup loop.
- [ ] Add a maximum retry count or total timeout to reconnect loops. Use `tokio::select!` with `ctrl_c()` inside the loop so users can interrupt.
- [ ] Wrap `connect_async` and initial registration exchange in `tokio::time::timeout()` to prevent hangs on unresponsive servers.
- [ ] Notify connected peers before removing expired sessions in the cleanup loop.
- [ ] Handle SIGTERM (not just SIGINT) on the host for clean shutdown in containers.
- [ ] Send a `SessionEnded { exit_code }` message to the attached client when the PTY child exits.
- [ ] Add a circular scrollback buffer on the host (e.g. last 100KB) so clients reconnecting mid-session get caught up with recent output.

## Performance

- [ ] Add wire compression (WebSocket per-message deflate or application-level zstd/lz4 before `seal()`) to reduce bandwidth.
- [ ] Replace `mpsc::unbounded_channel` in `RelayConnection` with a bounded channel to add backpressure.
- [ ] Increase the PTY read buffer from 4096 to 16384+ bytes to reduce per-frame overhead.
- [ ] Cache the last-sent terminal size on the attach side and only send `Resize` when it actually changes.

## CLI features

- [ ] Add session management subcommands: `session kill <id>`, `session delete <id>`, `session clean` (purge stale).
- [ ] Add an SSH-style escape sequence (e.g. `~.` to detach, `~~` to send literal `~`) for clean detach and Ctrl-C forwarding.
- [ ] Add `--version` flag to the CLI (`#[command(version)]`).
- [ ] Show a status indicator on the attach side when the secure channel is not yet established, instead of silently dropping input.
- [ ] Strengthen session persistence and recovery by restoring active host sessions after CLI restart.
- [ ] Add clipboard support: allow copy/paste between the remote client and the host PTY via an encrypted `SecureMessage` variant.
- [ ] Add a daemon/background mode (`terminal-relay start --daemon`) that detaches from the terminal and runs the session in the background.

## Code quality

- [x] Add unit tests for `crypto.rs` (seal/open roundtrip, replay rejection, nonce exhaustion, key derivation symmetry, fingerprint determinism), `pairing.rs` (URI roundtrip, malformed input, code format), and `protocol.rs` (encode/decode all variants, garbage rejection). 51 tests total.
- [ ] Add unit tests for `relay.rs` (registration, cleanup, version validation) and `state.rs` (save/load roundtrip).
- [ ] Add integration tests for relay registration, encrypted handshake, reconnect/resume, and replay protection.
- [ ] Extract duplicated functions (`now_millis`, `send_handshake`, `send_peer_frame`) from `host.rs` and `attach.rs` into a shared module.
- [ ] Remove or wire up `#[allow(dead_code)]` items in `state.rs` (`load()`, `ensure_path_exists()`).
- [ ] Use RFC 3339 timestamps in `SessionRecord.created_at` instead of the non-standard `"unix:..."` format.

## Protocol

- [ ] Implement version range negotiation (client sends min/max, server selects) instead of strict equality on `PROTOCOL_VERSION`.
- [ ] Add forward-compatible extensibility to the wire format so new `SecureMessage` variants don't break old clients.
- [ ] Actually send `VersionNotice` when peers connect with older versions.
- [ ] Add a `Clipboard`, `SessionEnded`, and `ReadOnly` variant to `SecureMessage` to support new features without breaking the protocol.

## Packaging & distribution

- [ ] Add a `LICENSE` file to the repository.
- [ ] Add crate metadata (`description`, `repository`, `homepage`, `keywords`, `authors`) to all `Cargo.toml` files.
- [ ] Publish prebuilt binaries for macOS (Intel + Apple Silicon), Linux (x64 + ARM64), and Windows (x64). Set up CI release pipeline.
- [ ] Add `cargo install terminal-relay` support (publish `terminal-relay-cli` to crates.io).
- [ ] Add Homebrew formula and tap (`brew install terminal-relay`).
- [ ] Add install script (`curl -fsSL https://terminal-relay.dev/install.sh | sh`) for quick onboarding.
- [ ] Add optional Windows PTY support and CI coverage for macOS/Linux/Windows matrices.
- [ ] Add documentation to `docs/`: protocol spec, architecture overview, deployment guide.
- [ ] Add structured observability (metrics, traces, logs) for relay latency, dropped frames, reconnect attempts, and PTY health.
- [ ] Add opt-in anonymous usage telemetry (session count, tool usage, OS) to inform development priorities.
