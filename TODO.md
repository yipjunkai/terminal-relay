# TODO

Items are roughly ordered by priority within each phase.

## Phase 1: Security hardening (complete)

- [x] Derive `ZeroizeOnDrop` on `KeyPair`, `SessionKeys`, and `SecureChannel` so secret material is cleared from memory on drop. Remove `Clone` from `KeyPair`.
- [x] Encrypt session state files at rest and restrict file permissions (`chmod 0600` on session JSON, `0700` on `~/.terminal-relay/`). AES-256-GCM with machine-local state key, legacy plaintext fallback for migration.
- [x] Add `HandshakeConfirm` peer frame with HMAC-SHA256 key confirmation after DH handshake. Validate `timestamp_ms` to reject stale handshakes (5-minute window). Channel not trusted until confirmation succeeds.
- [x] Validate `Route.session_id` matches the sender's registered session before forwarding, preventing cross-session message injection.
- [x] Validate `session_id` (UUID v4 format) and `pairing_code` format on the server. Enforce max lengths on all `RegisterRequest` string fields.
- [x] Rate-limit failed pairing-code attempts per session on the relay. Lock out after 5 failures with per-session counter and warning logs.

## Phase 2: Relay reliability (complete)

- [x] Add server versioning: `server_version` (from `CARGO_PKG_VERSION`) in `RegisterResponse` and structured JSON `/healthz` endpoint with version + session count.
- [x] Add graceful shutdown to the relay server (`with_graceful_shutdown`, SIGINT + SIGTERM). Cancel cleanup loop on exit.
- [x] Handle SIGTERM (not just SIGINT) on host and attach for clean shutdown in containers.
- [x] Wrap `connect_async` and initial registration exchange in `tokio::time::timeout(15s)` to prevent hangs on unresponsive servers.
- [x] Add bounded reconnect loops (max 10 attempts, exponential backoff) with shutdown signal interrupt via `tokio::select!`.
- [x] Notify connected peers with error message before removing expired sessions in the cleanup loop.

## Phase 3: Protocol extensions (complete)

- [x] Add `SessionEnded { exit_code }`, `Clipboard`, `ReadOnly`, and `VoiceCommand` variants to `SecureMessage`. Added `VoiceAction` struct for structured speech-to-code payloads.
- [x] Add forward-compatible extensibility: `decode_secure_message` returns `Unknown(Vec<u8>)` instead of erroring on unrecognized variants. All handlers silently ignore `Unknown`.
- [x] Implement version range negotiation: client sends `protocol_version` (max) and `protocol_version_min`, server selects highest mutually supported version and returns `negotiated_protocol_version`. Bumped to protocol v2, supporting v1-v2.
- [x] Send `SessionEnded { exit_code }` to the attached client when the PTY child exits. Attach side displays the exit code.
- [x] Switch wire format from bincode to MessagePack (`rmp-serde`) for cross-platform client compatibility (Swift, Kotlin, JS).
- [x] Add `opencode` to tool detection list.
- [x] Add `--command` flag for running arbitrary commands (e.g. `--command opencode`).
- [x] Fix PTY to inherit current working directory instead of defaulting to `$HOME`.
- [x] Compact QR code rendering using Unicode half-block characters.
- [x] Attach client cleanly exits on `SessionEnded` or host going offline, with "Press enter to exit" prompt.
- [x] Clear attach screen on handshake confirm and send immediate resize so host PTY renders at correct dimensions.

## Phase 4: Relay deployment (pre-native-app)

- [ ] Deploy the relay server to a cloud provider (Fly.io, Railway, or similar). Set up `wss://relay.terminal-relay.dev/ws` for production.
- [ ] Add TLS termination (via reverse proxy or native rustls) for the production relay.
- [ ] Set up a development relay at `wss://dev-relay.terminal-relay.dev/ws` for beta testing.

## Phase 5: Native mobile apps

- [ ] Build native iOS app (Swift) with terminal rendering, QR/URI pairing, E2E encryption (CryptoKit X25519 + AES-GCM), and bidirectional input.
- [ ] Add speech-to-code on iOS: on-device Speech framework recognition that converts voice commands into coding actions (refactor, commit, debug) sent as encrypted `VoiceCommand` messages to the host session.
- [ ] Build native Android app (Kotlin) with the same terminal + encryption + pairing functionality.
- [ ] Add speech-to-code on Android using on-device ML Kit speech recognition.
- [ ] Add push notifications via APNS (iOS) and FCM (Android) for session events (peer connected, session ended, tool output idle).
- [ ] Generate shareable web URLs (e.g. `https://terminal-relay.dev/s/<token>`) that open the app or fall back to a web client with pairing info embedded.
- [ ] Add `protocol_version` to the peer-to-peer `Handshake` struct so peers can compare versions and send `VersionNotice` to prompt updates on older clients.

## Phase 6: Web client (deferred)

Lower priority since native apps are the primary mobile strategy. Web client serves as fallback and desktop attach option.

- [ ] Build a web client (xterm.js + WebSocket + WebCrypto) with encrypted attach, bidirectional input, terminal resize, and responsive layout.
- [ ] Add PWA support (manifest, service worker, home screen install) for quick access.

## Hosted relay service (ongoing)

- [x] Hardcode the production relay URL into the CLI binary so users never configure it. Support environment-based URL selection (production, development, local) via env var (`TERMINAL_RELAY_URL`).
- [ ] Add authn/authz and tenant isolation for the hosted relay (API keys, account system, or anonymous with rate limits).
- [ ] Add a maximum session count and per-IP session limits on the relay to prevent abuse.
- [x] Enrich the `/healthz` endpoint to return structured JSON with session count and server version. _(Done in Phase 2.)_
- [ ] Add multi-region relay support with geo-routing so clients connect to the nearest relay for lower latency.

## User experience

- [ ] Add colored/formatted CLI output for session status, pairing info, and error messages instead of raw `println!`.
- [ ] Add human-readable session names (e.g. `claude-backend-a3f`) instead of raw UUIDs in CLI output and QR codes.
- [ ] Add a first-run setup flow: detect installed AI tools, confirm default tool, display a quick-start summary.
- [ ] Add a user config file (`~/.terminal-relay/config.toml`) for default tool, default args, and preferences.
- [ ] Add shell completions generation (`terminal-relay completions bash/zsh/fish`).
- [ ] Add auto-update check on startup: warn the user if a newer CLI version is available (with `--no-update-check` to suppress).
- [ ] Add a connection quality indicator on the attach side (latency, connection state) rendered in a status bar.
- [ ] Add read-only attach mode (`--read-only`) for demos and presentations where the remote side can only watch.
- [ ] Add session idle timeout: automatically stop sessions after configurable inactivity (default 1 hour).

## CLI features

- [x] Add `--version` flag to the CLI (`#[command(version)]`).
- [ ] Add `session` subcommand group: `session stop <id>` / `session stop --all` to kill sessions, `session status` for live info (running process, connected peers, uptime), `session cleanup` to remove stale session files.
- [ ] Add an SSH-style escape sequence (e.g. `~.` to detach, `~~` to send literal `~`) for clean detach and Ctrl-C forwarding.
- [ ] Show a status indicator on the attach side when the secure channel is not yet established, instead of silently dropping input.
- [ ] Strengthen session persistence and recovery by restoring active host sessions after CLI restart.
- [ ] Add clipboard support: allow copy/paste between the remote client and the host PTY via an encrypted `SecureMessage` variant.
- [ ] Add a daemon/background mode (`terminal-relay start --daemon`) that detaches from the terminal and runs the session in the background.

## Performance

- [ ] Add wire compression (WebSocket per-message deflate or application-level zstd/lz4 before `seal()`) to reduce bandwidth.
- [ ] Replace `mpsc::unbounded_channel` in `RelayConnection` with a bounded channel to add backpressure.
- [ ] Increase the PTY read buffer from 4096 to 16384+ bytes to reduce per-frame overhead.
- [ ] Cache the last-sent terminal size on the attach side and only send `Resize` when it actually changes.
- [ ] Add a circular scrollback buffer on the host (e.g. last 100KB) so clients reconnecting mid-session get caught up with recent output.

## Code quality

- [x] Add unit tests for `crypto.rs` (seal/open roundtrip, replay rejection, nonce exhaustion, key derivation symmetry, fingerprint determinism), `pairing.rs` (URI roundtrip, malformed input, code format), and `protocol.rs` (encode/decode all variants, garbage rejection). 51 tests.
- [x] Add unit tests for `state.rs` (save/load roundtrip, encryption verification, legacy plaintext migration, file permissions, key persistence, corruption handling). 7 tests.
- [ ] Add unit tests for `relay.rs` (registration, cleanup, version validation).
- [ ] Add integration tests for relay registration, encrypted handshake, reconnect/resume, and replay protection.
- [x] Extract duplicated functions (`ChannelState`, `now_millis`, `send_handshake`, `send_peer_frame`, `shutdown_signal`) from `host.rs` and `attach.rs` into `common.rs`.
- [x] Remove `ensure_path_exists()` from `state.rs` (replaced by `ensure_dir` in rewrite). `load()` is used in tests and retained with `#[allow(dead_code)]` until session resume is implemented.
- [x] Use RFC 3339 timestamps in `SessionRecord.created_at` instead of the non-standard `"unix:..."` format. No new deps — manual UTC formatting.

## Packaging & distribution

- [ ] Add crate metadata (`description`, `repository`, `homepage`, `keywords`, `authors`) to all `Cargo.toml` files.
- [ ] Publish prebuilt binaries for macOS (Intel + Apple Silicon), Linux (x64 + ARM64), and Windows (x64). Set up CI release pipeline.
- [ ] Add `cargo install terminal-relay` support (publish `terminal-relay-cli` to crates.io).
- [ ] Add Homebrew formula and tap (`brew install terminal-relay`).
- [ ] Add install script (`curl -fsSL https://terminal-relay.dev/install.sh | sh`) for quick onboarding.
- [ ] Add optional Windows PTY support and CI coverage for macOS/Linux/Windows matrices.
- [ ] Add documentation to `docs/`: protocol spec, architecture overview, deployment guide.
- [ ] Add structured observability (metrics, traces, logs) for relay latency, dropped frames, reconnect attempts, and PTY health.
- [ ] Add opt-in anonymous usage telemetry (session count, tool usage, OS) to inform development priorities.
