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
- [x] Switch MessagePack encoding to `rmp_serde::to_vec_named` (named map keys) for cross-platform decoding compatibility. Decoding (`from_slice`) accepts both named and positional formats.
- [x] Add `opencode` to tool detection list.
- [x] Add `--command` flag for running arbitrary commands (e.g. `--command opencode`).
- [x] Fix PTY to inherit current working directory instead of defaulting to `$HOME`.
- [x] Compact QR code rendering using Unicode half-block characters.
- [x] Attach client cleanly exits on `SessionEnded` or host going offline, with "Press enter to exit" prompt.
- [x] Clear attach screen on handshake confirm and send immediate resize so host PTY renders at correct dimensions.

## Phase 4: Relay deployment (in progress)

- [x] Deploy the relay server to Fly.io. Added `Dockerfile` (multi-stage Rust build with dependency caching), `fly.toml` (auto-TLS, health checks, auto-suspend), and `.dockerignore`.
- [x] TLS termination via Fly.io's built-in proxy (`force_https: true`). No reverse proxy or native rustls needed.
- [x] Add `.env` file support to the CLI via `dotenvy` for dev/staging relay URL configuration.
- [x] Add `rustls` with `ring` crypto backend to fix TLS provider initialization for WebSocket connections.
- [ ] Set up custom domain: CNAME `relay.terminal-relay.dev` to Fly app for production relay URL.
- [ ] Set up a development relay at `wss://dev-relay.terminal-relay.dev/ws` for beta testing.

## Phase 5: Mobile app (in progress)

Pivoted from separate native iOS/Android apps to a single Flutter app (`terminal_relay_app`) targeting both platforms. Native platform channels will be used for speech recognition and push notifications. Production-quality release build on Android with E2E encrypted terminal mirroring, auto-reconnect, explicit state machine, terminal toolbar, deep links, and app lifecycle handling. 58 tests passing.

### Core functionality (complete)

- [x] Build Flutter app with terminal rendering (`xterm.dart`), QR code scanning (`mobile_scanner`), and manual URI paste pairing.
- [x] Implement full E2E encryption in Dart: X25519 key exchange, HKDF-SHA256 key derivation, AES-256-GCM encrypt/decrypt, HMAC-SHA256 handshake confirmation. Wire-compatible with Rust implementation.
- [x] Implement MessagePack protocol codec in Dart for all message types (RelayMessage, PeerFrame, SecureMessage). Forward-compatible with `Unknown` fallback.
- [x] Implement WebSocket relay client with registration, heartbeat pings, and message buffering to prevent race conditions during handshake.
- [x] Implement `termrelay://` deep link URI parsing for QR code pairing.
- [x] Mobile client sends encrypted `SessionEnded` on graceful disconnect.
- [x] Connection status bar with state indicator (connecting, handshaking, E2E encrypted, error).
- [x] Reconnect button in status bar when connection is lost.

### Relay client (complete)

- [x] Replace custom message buffering with callback-based architecture. Registration handled internally.
- [x] Add automatic reconnect with exponential backoff (1s to 30s, max 10 attempts).
- [x] Add WebSocket ping/pong keepalive via `IOWebSocketChannel` with `pingInterval = 15s`.
- [x] Add connection timeout handling (15s on WebSocket connect and registration).
- [x] Handle app lifecycle: pause heartbeats when backgrounded, reconnect immediately when foregrounded.
- [x] Add proper close/dispose lifecycle with intentional-close and disposed flags.

### Session state machine (complete)

- [x] Rewrite `RelaySession` as explicit state machine with 8 states: `disconnected -> connecting -> waitingForPeer -> handshaking -> awaitingConfirm -> connected`, plus `reconnecting` and `error`.
- [x] Fix handshake race condition with frame queue. All frames during async key derivation are queued and processed sequentially.
- [x] Add handshake timeout (15s across `waitingForPeer`, `handshaking`, and `awaitingConfirm`).

### Deep links (complete)

- [x] Register `termrelay://` scheme handler on Android (intent filter in AndroidManifest.xml + MainActivity.kt MethodChannel).
- [x] Register `termrelay://` scheme handler on iOS (CFBundleURLTypes in Info.plist).
- [x] Route handler in main.dart: checks initial link on cold start, listens for links on warm start, navigates directly to terminal screen.

### UI (complete)

- [x] Terminal toolbar with Ctrl keys (C, D, Z, L, A, E, R, W), Tab, Esc, arrow keys, Paste, and common symbols. Toggleable, haptic feedback, horizontally scrollable rows.
- [x] Home screen with session history, reconnect options.
- [x] Camera permission error handling with specific messages and retry button.
- [x] Error states show message and reconnect action.

### Session & protocol improvements

- [x] Handle the dual-handshake pattern correctly. Both sides send Handshake simultaneously; first handshake wins, duplicates ignored. Fixed in host.rs, attach.rs, and session.dart.
- [x] Add scrollback buffer (128KB) on the host that replays recent PTY output to reconnecting clients after handshake confirm. Preserves forward secrecy (full handshake with fresh keys on every reconnect).
- [ ] Add `protocol_version` to the peer-to-peer `Handshake` struct so peers can compare versions and send `VersionNotice` to prompt updates on older clients.
- [ ] Generate shareable web URLs (e.g. `https://terminal-relay.dev/s/<token>`) that open the app or fall back to a web client with pairing info embedded.
- [ ] Add host liveness check for the home screen: add a relay HTTP endpoint (e.g. `GET /session/:id/status`) that returns whether the host is currently connected, so the app can show live/offline status on saved sessions without opening a WebSocket.
- [ ] Add E2E heartbeat-based liveness detection during active sessions: host sends periodic `SecureMessage::Heartbeat` (e.g. every 30s), mobile client tracks last received message time and shows "host may be unresponsive" if no data arrives within a timeout (e.g. 90s). Proves the host application layer is healthy, not just the WebSocket.

### Crypto hardening

- [x] Verify constant-time MAC comparison actually works in Dart. Consolidated into `constantTimeMacEqual()` helper in crypto.dart, used by both `verifyHandshakeMac()` and `_onPeerConfirm()`.
- [x] Handle key material cleanup: `SecureChannel.dispose()` zeros TX/RX keys, `RelaySession.disconnect()`/`dispose()` zeros ephemeral key pair via `zeroOut()` helper.

### Configuration

- [x] Relay URL is already dynamic — received from the pairing URI at runtime, not hardcoded in Dart source. No `.env` needed.

### UI / UX improvements

- [ ] Add a reconnect overlay when connection drops (error message with reconnect/close buttons instead of just a small icon).
- [ ] Support landscape orientation for more terminal columns.
- [ ] Validate pairing URI before navigating (check that the relay URL is reachable).
- [ ] Support scanning from photo gallery (screenshot of QR code).
- [ ] Add global error boundary that catches unhandled exceptions and shows a recovery screen.
- [ ] Surface crypto errors clearly: "Fingerprint mismatch" should explain what it means and what to do.
- [ ] Add a settings screen: default relay URL, terminal font size, theme (dark/light/custom), haptic feedback toggle. Persist with `shared_preferences`.
- [ ] Show session metadata: host fingerprint, connection duration, data transferred.
- [ ] Polish terminal rendering: font selection, theme customization.

### Features

- [ ] Add speech-to-code: on-device speech recognition (platform channels to iOS Speech framework / Android ML Kit) that sends `VoiceCommand` messages to the host.
- [ ] Add push notifications via APNS (iOS) and FCM (Android) for session events (peer connected, session ended, tool output idle).

### Testing

- [ ] Update widget test: app launches to home screen.
- [ ] Add widget tests for terminal screen and status bar states.
- [ ] Add integration test: mock WebSocket server that replays a captured Rust handshake sequence, verify the Dart client completes handshake and decrypts output.

### Build / Release

- [x] Replace `debugPrint` with `log()` wrapper (core/log.dart) guarded by `kDebugMode`. All 35 calls stripped in release builds.
- [ ] Set up app signing for Android (keystore) for Play Store distribution.
- [ ] Set up app signing for iOS (provisioning profiles, certificates).
- [ ] App store preparation: icons, splash screen, screenshots, store listings.
- [ ] Set up CI (GitHub Actions) for building and testing on push.

## Phase 6: Web client (deferred)

Lower priority since native apps are the primary mobile strategy. Web client serves as fallback and desktop attach option.

- [ ] Build a web client (xterm.js + WebSocket + WebCrypto) with encrypted attach, bidirectional input, terminal resize, and responsive layout.
- [ ] Add PWA support (manifest, service worker, home screen install) for quick access.

## Hosted relay service (ongoing)

- [x] Hardcode the production relay URL into the CLI binary so users never configure it. Support environment-based URL selection (production, development, local) via env var (`TERMINAL_RELAY_URL`).
- [x] Add a maximum session count and per-IP session limits on the relay to prevent abuse. Configurable via `--max-sessions` / `RELAY_MAX_SESSIONS` and `--max-sessions-per-ip` / `RELAY_MAX_SESSIONS_PER_IP`. Defaults to unlimited (0). IP tracking cleaned up on session expiry.
- [x] Enrich the `/healthz` endpoint to return structured JSON with session count and server version. _(Done in Phase 2.)_
- [ ] Add multi-region relay support with geo-routing so clients connect to the nearest relay for lower latency.

### Control API gateway (in progress)

Authentication and billing belong in the control API (`control/`), not in the open-source relay. The relay stays a simple dumb pipe; the control API handles auth, metering, and billing.

#### Completed

- [x] Add user registration endpoint (`POST /auth/register` with email). Returns JWT + first API key.
- [x] Add `ApiKey` Prisma model with multi-key support: SHA-256 hashed keys, `tr_` prefix, named keys, expiry, revocation, `lastUsedAt` tracking. Replaced single `User.apiKey` field.
- [x] Add API key management endpoints: `POST /api/keys` (create), `GET /api/keys` (list), `DELETE /api/keys/:id` (revoke). Keys tied to `User` model via Prisma. JWT-protected.
- [x] Fix Dockerfile to use pnpm (was incorrectly using npm/package-lock.json).
- [x] Remove dead `@nestjs/platform-express` dependency.
- [x] Implement signed API key generation in the control API: encode `{ user_id, key_id, tier, created_at }` + HMAC-SHA256 into the `tr_` prefixed key. Store the key hash in Prisma for revocation tracking. Constant-time signature verification.
- [x] Add HMAC key verification to the Rust relay on WebSocket upgrade. Shared secret via `HMAC_SECRET` env var. Dual-secret support for rotation via `HMAC_SECRET_PREVIOUS`. Returns 401/403 before upgrade if key is missing/invalid. Gracefully degrades to open relay when `HMAC_SECRET` is not set.
- [x] Add revocation list sync: relay fetches `GET /internal/revoked-keys` from control API every 60s, caches `key_id` set in memory. Control API endpoint authenticated with `X-Internal-Secret` header.
- [x] Add relay session lifecycle callbacks: `POST /internal/session-started` and `POST /internal/session-ended { session_id, user_id, bytes_up, bytes_down, duration_ms }` to the control API for usage metering. Relay tracks bytes up/down per connection and reports on disconnect.
- [x] Add WebSocket proxy endpoint as interim solution (to be removed once signed key flow is validated end-to-end).
- [x] Add `TERMINAL_RELAY_CONTROL_URL` env var support to CLI auth command for local development and testing.
- [x] Update Flutter mobile app to parse `api_key` from pairing URI `&key=` param and append `?api_key=` to WebSocket URL on connect. 58 Flutter tests passing.
- [x] Create initial Prisma migration (`20260319_initial`) for all tables (users, api_keys, sessions, usage) with indexes and foreign keys.

#### Signed API key architecture

API keys are **self-validating signed tokens** so the relay can verify them locally with zero network calls.

**Key format:** `tr_<base64url(payload_json + "." + HMAC-SHA256(payload_json, HMAC_SECRET))>` where payload = `{ uid, kid, tier, iat }`. The relay shares the same `HMAC_SECRET` with the control API and can verify + decode any key in microseconds with no database or HTTP calls.

**Connection flow:**
1. CLI/mobile connects directly to the relay: `wss://relay.../ws?api_key=tr_...`.
2. Relay decodes the key, verifies the HMAC signature, extracts `user_id` and `tier`.
3. Relay checks the in-memory revocation set (synced periodically from the control API).
4. All traffic is Client ⟷ Relay directly. Control API is never in the data path.

**Revocation:** Relay periodically fetches `GET /internal/revoked-keys` from the control API (every 60s) and caches the set in memory. Revocation propagation delay is acceptable — the user revoking the key is the same user who had access.

**Usage reporting:** Relay reports session stats to the control API on disconnect via `POST /internal/session-ended`. Periodic heartbeats allow the control API to reconcile stale sessions from relay crashes.

**Advantages over proxy/ticket:** zero per-frame overhead, zero per-connection HTTP round-trips, control API downtime doesn't block new or existing sessions, scales to multi-region relays with a single control API.

**Security notes:** The HMAC secret must be kept secure on both the control API and relay — compromise of the secret allows forging arbitrary API keys. Key contents (uid, tier) are not encrypted, only signed — they are visible to anyone who base64-decodes the key, but cannot be tampered with. This is acceptable since API keys are already bearer tokens.

#### Remaining

- [x] Add a helpful error message when connecting to the hosted relay without an API key. CLI blocks with clear instructions before attempting connection. Also catches 401/403 from the relay and suggests re-authenticating.
- [ ] Add periodic relay heartbeat (`POST /internal/heartbeat { active_sessions }`) so control API can detect and reconcile stale sessions from relay crashes.
- [ ] Remove the WebSocket proxy from the control API once signed key flow is validated end-to-end.
- [x] Add `terminal-relay auth` CLI command: consolidates registration (`--email`) and login (`--api-key`) into a single entry point. Stores signed API key in `~/.terminal-relay/config.toml`. Also added `terminal-relay logout` and `terminal-relay status`.
- [x] Update pairing URI to include `api_key` so mobile app connects through the same authenticated path. Added `api_key` field to `PairingUri` struct, serialized as `&key=` param.
- [x] Update `relay_client.rs` to append `?api_key=` to WebSocket URL when a key is available. Host reads key from CLI arg → env var → config file. Attach reads key from pairing URI.
- [x] Add tests for signed key generation/verification (control API: 14 tests) and HMAC verification/revocation (relay auth.rs: 20 tests). Covers roundtrip, tampered payload/signature, wrong secret, revocation, dual-secret rotation, malformed input, constant-time comparison, and cross-platform compatibility.
#### Key lifecycle and secret rotation (planned)

Two-layer rotation strategy inspired by Infisical's active/inactive/revoked model. User-level key rotation and infra-level HMAC secret rotation work together — regular key rotation at the user level ensures all active keys are re-signed before an old HMAC secret is dropped.

**User API key lifecycle (active → inactive → revoked):**

API keys have a `status` field tracking their lifecycle. The control API marks keys as inactive based on age policy (e.g., 90 days). Clients detect inactive status and rotate automatically. This gives users a graceful deprecation window instead of hard cutoffs.

- [ ] Add `status` field to `ApiKey` model (`active`, `inactive`, `revoked`). Inactive keys still pass validation but signal the client to rotate.
- [ ] Relay signals key status on WebSocket upgrade (e.g., custom close code or initial message) when the key's `created_at` exceeds the inactive threshold. CLI detects this and requests a fresh key from `POST /api/keys/rotate` in the background.
- [ ] Add `POST /api/keys/rotate` endpoint: creates a new key for the user, marks the old key as inactive, returns the new raw key. CLI stores it automatically in `~/.terminal-relay/config.toml`.
- [ ] Add a scheduled job in the control API to transition keys: mark keys older than N days as inactive, revoke keys that have been inactive for M days.
- [ ] Handle QR code / pairing URI gracefully: keys in the inactive window still work for mobile connections. The mobile app does not need to rotate — the session is short-lived.

**HMAC signing secret rotation (infra level):**

The HMAC secret used to sign API keys needs periodic rotation. The relay supports dual verification during a transition window. Because user-level key rotation re-signs keys with the current secret on a regular cadence, all active keys naturally migrate to the new secret before the old one is dropped.

- [x] Support multiple HMAC secrets on the relay (`HMAC_SECRET` + `HMAC_SECRET_PREVIOUS`). On verification, try current first, fall back to previous. Tested with dual-secret acceptance and rejection.
- [ ] Rotation procedure: generate new secret → deploy to relays as `HMAC_SECRET` (old secret moves to `HMAC_SECRET_PREVIOUS`) → new keys are signed with the new secret → after grace period (e.g., 30 days, long enough for user-level key rotation to re-sign all active keys), drop `HMAC_SECRET_PREVIOUS`.
- [ ] Add `signing_secret_version` to the signed key payload so the relay knows which secret to verify with, avoiding trial-and-error.
- [ ] Automate secrets rotation via Infisical, Doppler, or similar secrets management platform. The platform would handle: (1) scheduled HMAC_SECRET rotation (generate new secret, push to both relay and control API as HMAC_SECRET, move old to HMAC_SECRET_PREVIOUS), (2) JWT_SECRET rotation on the control API, (3) INTERNAL_SECRET rotation between relay and control API, (4) audit logging of all secret access and rotation events. Evaluate Infisical (open-source, self-hostable), Doppler (managed, good Fly.io integration), and HashiCorp Vault (enterprise). This is a long-term operational concern — manual rotation is fine until there are paying users.

#### Remaining

- [x] Add per-user session rate limiting based on API key tier. Relay tracks active sessions per `user_id` in memory (similar to IP tracking). Limits enforced on WebSocket upgrade before connection: free tier = 3 concurrent sessions (default), pro = 20. Configurable via `--tier-limit-free` / `--tier-limit-pro` CLI args or `RELAY_TIER_LIMIT_FREE` / `RELAY_TIER_LIMIT_PRO` env vars. Session counts cleaned up on disconnect and session expiry. Returns HTTP 429 with clear message when limit is hit.
- [ ] Add anonymous access mode: no API key required but subject to aggressive per-IP limits (e.g. 2 sessions, 1 hour TTL). Encourages sign-up without blocking first-time users.
- [ ] Add billing integration: enforce plan limits (session count, concurrent sessions, bandwidth) and return clear errors when exceeded.

## User experience

- [ ] Replace `terminal-relay auth --email` / `--api-key` with a device authorization flow (like `gh auth login`). The CLI runs `terminal-relay auth`, displays a URL + short code, user authenticates in browser, CLI polls for completion, receives API key automatically. Current `--email`/`--api-key` flags remain as fallbacks. Full breakdown:
  - [ ] Add device code endpoints in control API: `POST /auth/device/code` (returns `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`) and `POST /auth/device/poll` (client polls with `device_code`, returns `pending`/`authorized`/`expired`).
  - [ ] Build web frontend at `terminal-relay.dev/activate` where users enter the short code. Page validates the code against the control API, then presents sign-up or login (email, OAuth via GitHub/Google — Clerk integration point).
  - [ ] On successful browser auth, the control API marks the device code as authorized and generates a signed API key for the user. The polling CLI receives the key and stores it.
  - [ ] Update `terminal-relay auth` to default to the device flow when run with no flags: print the URL + code, open the browser automatically (`open` / `xdg-open`), poll with a spinner, save the key on success.
  - [ ] Add account management web dashboard at `terminal-relay.dev/dashboard`: view/revoke API keys, see usage, manage billing. This is where Clerk would handle user sessions and the API key CRUD endpoints are already built.
- [x] Add a user config file (`~/.terminal-relay/config.toml`) for API key and preferences. File permissions 0600, directory 0700.
- [ ] Add colored/formatted CLI output for session status, pairing info, and error messages instead of raw `println!`.
- [ ] Add human-readable session names (e.g. `claude-backend-a3f`) instead of raw UUIDs in CLI output and QR codes.
- [ ] Add a first-run setup flow: detect installed AI tools, confirm default tool, display a quick-start summary.
- [ ] Add default tool and args to `~/.terminal-relay/config.toml`.
- [ ] Add shell completions generation (`terminal-relay completions bash/zsh/fish`).
- [ ] Add auto-update check on startup: warn the user if a newer CLI version is available (with `--no-update-check` to suppress).
- [ ] Add a connection quality indicator on the attach side (latency, connection state) rendered in a status bar.
- [ ] Add read-only attach mode (`--read-only`) for demos and presentations where the remote side can only watch.
- [ ] Add session idle timeout: automatically stop sessions after configurable inactivity (default 1 hour).

## CLI features

- [x] Add `--version` flag to the CLI (`#[command(version)]`).
- [ ] Add `session` subcommand group: `session stop <id>` / `session stop --all` to kill sessions, `session status` for live info (running process, connected peers, uptime), `session cleanup` to remove stale session files.
- [x] Ctrl-C on attach side detaches cleanly without stopping the host. Terminal state fully reset on detach (alternate screen, mouse tracking, cursor, colors, screen clear).
- [ ] Add SSH-style escape sequences (`~.` to detach, `~~` to send literal `~`) as an alternative to Ctrl-C.
- [ ] Show a status indicator on the attach side when the secure channel is not yet established, instead of silently dropping input.
- [ ] Strengthen session persistence and recovery by restoring active host sessions after CLI restart.
- [ ] Add clipboard support: allow copy/paste between the remote client and the host PTY via an encrypted `SecureMessage` variant.
- [ ] Add a daemon/background mode (`terminal-relay start --daemon`) that detaches from the terminal and runs the session in the background.

## Performance

- [ ] Add wire compression (WebSocket per-message deflate or application-level zstd/lz4 before `seal()`) to reduce bandwidth.
- [ ] Replace `mpsc::unbounded_channel` in `RelayConnection` with a bounded channel to add backpressure.
- [ ] Increase the PTY read buffer from 4096 to 16384+ bytes to reduce per-frame overhead.
- [ ] Cache the last-sent terminal size on the attach side and only send `Resize` when it actually changes.
- [x] Add a circular scrollback buffer on the host (128KB) so clients reconnecting mid-session get caught up with recent output. Replayed after handshake confirm, before the handshake-window backlog.

## Code quality

- [x] Add unit tests for `crypto.rs` (seal/open roundtrip, replay rejection, nonce exhaustion, key derivation symmetry, fingerprint determinism), `pairing.rs` (URI roundtrip, malformed input, code format), and `protocol.rs` (encode/decode all variants, garbage rejection). 51 tests.
- [x] Add unit tests for `state.rs` (save/load roundtrip, encryption verification, legacy plaintext migration, file permissions, key persistence, corruption handling). 7 tests.
- [ ] Add unit tests for `relay.rs` (registration, cleanup, version validation).
- [ ] Add integration tests for relay registration, encrypted handshake, reconnect/resume, and replay protection.
- [x] Extract duplicated functions (`ChannelState`, `now_millis`, `send_handshake`, `send_peer_frame`, `shutdown_signal`) from `host.rs` and `attach.rs` into `common.rs`.
- [x] Remove `ensure_path_exists()` from `state.rs` (replaced by `ensure_dir` in rewrite). `load()` is used in tests and retained with `#[allow(dead_code)]` until session resume is implemented.
- [x] Use RFC 3339 timestamps in `SessionRecord.created_at` instead of the non-standard `"unix:..."` format. No new deps — manual UTC formatting.

## Packaging & distribution

- [x] Add crate metadata (`description`, `repository`, `homepage`, `keywords`, `authors`) to all `Cargo.toml` files.
- [x] Publish prebuilt binaries for macOS (Intel + Apple Silicon), Linux (x64 + ARM64). CI release pipeline via `.github/workflows/release.yml` — builds on tag push, uploads to GitHub Releases.
- [ ] Add `cargo install terminal-relay` support (publish `terminal-relay-cli` to crates.io).
- [x] Add Homebrew formula (`Formula/terminal-relay.rb`). Use as tap: `brew install yipjunkai/terminal-relay/terminal-relay`. SHA256 hashes need filling after first release.
- [x] Add install script (`install.sh`): `curl -fsSL https://raw.githubusercontent.com/yipjunkai/terminal-relay/main/install.sh | sh`.
- [ ] Add optional Windows PTY support and CI coverage for macOS/Linux/Windows matrices.
- [ ] Add documentation to `docs/`: protocol spec, architecture overview, deployment guide.
- [ ] Add structured observability (metrics, traces, logs) for relay latency, dropped frames, reconnect attempts, and PTY health.
- [ ] Add opt-in anonymous usage telemetry (session count, tool usage, OS) to inform development priorities.
