# TODO

## Onboarding & auth (ship-blocking)

The path from "installed the CLI" to "session running on my phone" must be frictionless.

- [x] **Device authorization flow** — `terminal-relay auth` opens browser, user enters code + email + invite code, CLI polls and saves the key. Flags (`--email`, `--api-key`, `--invite-code`) remain as fallbacks.
  - [x] Control API: `POST /auth/device/code`, `POST /auth/device/poll`, `POST /auth/device/activate` endpoints.
  - [x] Inline activation page served at `GET /activate` (no separate frontend build).
  - [x] CLI: default to device flow when no flags given. Print URL + code, auto-open browser, poll with spinner.
  - [x] Invite code gating on registration (`INVITE_CODES` env var, constant-time comparison).
  - [x] Rate limiting on auth endpoints (`@nestjs/throttler`).
  - [x] CORS lockdown (configurable `CORS_ORIGINS` env var).
  - [x] Constant-time internal secret comparison.
  - [ ] Web dashboard at `terminal-relay.dev/dashboard`: manage API keys, view usage, billing.
  - [ ] Replace inline activation page with Clerk/OAuth integration for production.
- [x] `terminal-relay auth` CLI command (email/api-key flags), `logout`, `status`. Config stored in `~/.terminal-relay/config.toml`.
- [x] Helpful error message when connecting without API key or with expired/revoked key.
- [x] **First-run setup flow** — Interactive TUI tool picker on first `terminal-relay start`. Detects installed AI tools, user selects default with arrow keys, saved to config. Auto-selects if only one tool found.
- [x] Add default tool to `~/.terminal-relay/config.toml`.
- [x] `terminal-relay doctor` command — colored diagnostic output: version, build type, config, auth status, relay connectivity, detected tools with paths.

## CLI UX (high impact, quick wins)

- [x] **TUI host dashboard** — `terminal-relay start` renders a fixed ratatui-based terminal UI with session info panel, QR code panel, scrolling event log, and status bar. Live updates for connection status, traffic stats, and uptime. Replaces raw `println!` output.
- [x] **Hosted/self-hosted feature flag** — `hosted` Cargo feature compiles out all hosted-service code (auth, device flow, control API calls). Default build is clean self-hosted binary; CI/Homebrew/install.sh build with `--features hosted`.
- [x] **Keyless client connections** — Clients join authenticated sessions via pairing code alone; host's API key never leaves the host machine. QR codes are significantly smaller.
- [x] **Colored/formatted output** — `doctor` command with colored diagnostics. `status` and `detect-tools` merged into `doctor`. `sessions` command removed (redundant with TUI).
- [ ] **Human-readable session names** — e.g. `claude-backend-a3f` instead of raw UUIDs in CLI output and QR codes. Easier to reference in conversation.
- [ ] **Session management commands** — `session stop <id>` / `session stop --all`, `session status` (live info: running process, connected peers, uptime), `session cleanup` (remove stale files).
- [ ] Shell completions generation (`terminal-relay completions bash/zsh/fish`).
- [ ] Auto-update check on startup: warn if newer CLI version available (`--no-update-check` to suppress).
- [x] `terminal-relay doctor` command replaces `--diagnostics` (inspired by `flutter doctor`).

## Multi-session support (competitive necessity)

Termly supports multiple concurrent sessions. DISPATCH.md envisions managing multiple AI agents across worktrees from a single phone. This is referenced in 4 notes files and is the biggest feature gap vs. the direct competitor.

### Phase 1: tmux integration (CLI only, ~1-2 days)

Relay server and mobile app need zero changes. Scoped entirely to `cli` crate.

- [ ] Auto-detect tmux on PATH.
- [ ] Spawn AI tool inside a tmux session (`tmux new-session -d -s relay-{session_id} {command}`).
- [ ] `--tmux` / `--no-tmux` flag on `start` command. Fall back to direct PTY if tmux unavailable.
- [ ] "Release back to computer" — user can `tmux attach -t relay-{session_id}` locally while the relay session continues.

### Phase 2: Protocol-level multi-session

- [ ] Add session/tab ID to `SecureMessage` variants (`PtyInput`, `PtyOutput`, `Resize`).
- [ ] Manage `HashMap<SessionId, PtyPair>` instead of single PTY on the host.
- [ ] New `SecureMessage` variants: `SpawnTerminal`, `CloseTerminal`, `ListTerminals`.
- [ ] Mobile app: multiple terminal tabs, session dashboard with live previews, session groups by project.
- [ ] Broadcast mode: type once, send to multiple sessions (e.g. "stop all agents", "git status" across projects).

## Web client (free tier acquisition channel)

The business model (README.md) puts the web client in the **Free tier** and the mobile app in **Pro**. The web client is the free acquisition funnel — users try it at zero cost, then upgrade for mobile + push notifications + speech-to-code. This should not be "deferred."

- [ ] Build web client: xterm.js + WebSocket + WebCrypto. Encrypted attach, bidirectional input, terminal resize, responsive layout.
- [ ] PWA support (manifest, service worker, home screen install) for quick access without app store.
- [ ] Shareable web URLs (e.g. `https://terminal-relay.dev/s/<token>`) that open the web client with pairing info embedded. Falls back to app store links on mobile.

## Mobile app (Pro tier — premium hook)

The mobile app is the paid differentiator. Speech-to-code, push notifications, and native UX justify the Pro tier. 58 tests passing, E2E encryption working, deployed on Android.

### Immediate UX improvements

- [ ] **Smart input bar** — Compose input field above the keyboard with send button, draft saving, history recall. Typing directly into a terminal on mobile is painful — this is the single biggest UX improvement possible.
- [ ] Reconnect overlay when connection drops (error message + reconnect/close buttons, not just a small icon).
- [ ] Landscape orientation support for more terminal columns.
- [ ] Terminal themes and customization (Dracula, Solarized, Nord, Catppuccin, custom fonts).
- [ ] Settings screen: relay URL, font size, theme, haptic feedback toggle. Persist with `shared_preferences`.
- [ ] Validate pairing URI before navigating (check relay URL is reachable).
- [ ] Scan QR from photo gallery (screenshot of QR code).
- [ ] Surface crypto errors clearly: "Fingerprint mismatch" should explain what it means and what to do.
- [ ] Show session metadata: host fingerprint, connection duration, data transferred.

### Push notifications & idle detection

Push notifications are a **Pro tier feature** and a competitive gap vs. Termly. Tied directly to monetization.

- [ ] Host-side idle/busy detection: track `lastOutputTime` on every PTY write. Status = `idle` if no output for 15+ seconds. Report in heartbeat messages.
- [ ] Push notification infrastructure: APNS (iOS) + FCM (Android) for session events (peer connected, session ended, agent idle/waiting for input).
- [ ] Smart notification batching: don't spam. Periodic summaries ("Claude modified 4 files, tests passing") with configurable frequency.
- [ ] Watch expressions: user-defined regex triggers on terminal output ("notify me when `BUILD SUCCESSFUL` appears").

### Speech-to-code (premium differentiator)

Speech-to-code is something the web client and CLI cannot replicate. This justifies the Pro tier (README.md). Needs a detailed plan, not a single line item.

- [ ] Platform channels to iOS `SFSpeechRecognizer` / Android ML Kit for on-device recognition.
- [ ] Send `VoiceCommand` messages to the host (protocol already has the variant).
- [ ] Continuous listening mode with "Hey Terminal" wake word detection (on-device).
- [ ] Voice command chaining: "Run tests, and if they pass, commit with message 'fix auth bug'" — parsed into conditional sequential commands.
- [ ] Context-aware dictation: use current terminal context (language, framework) to improve recognition accuracy.

### Gesture & interaction improvements

- [ ] Gesture-based terminal control: swipe-left for Ctrl-C, swipe-up for scroll-back, pinch-to-zoom for font size.
- [ ] Radial/pie menu on long-press for most-used actions (interrupt, clear, paste, resize).
- [ ] Prompt templates / quick commands: user-defined snippets ("fix the failing tests", "explain this error"). Tap to send.
- [ ] Haptic + audio feedback for agent state changes (distinct vibration patterns for thinking, waiting, finished, disconnected).

### Advanced features (post-launch)

- [ ] Session recording & playback (asciinema-style, built-in). Review what an agent did overnight.
- [ ] Offline command queue: queue commands while disconnected, auto-send on reconnect.
- [ ] iOS home screen widget + Android widget showing session status and quick-action button.
- [ ] iOS Shortcuts / Siri integration: "Hey Siri, what's my agent doing?"
- [ ] Picture-in-picture / floating window (Android PiP, iOS Live Activities).
- [ ] Error detection + suggested actions: detect stack traces / test failures, surface "Retry" or "Ask agent to fix" cards.
- [ ] Agent output summarization via on-device LLM (Apple Intelligence / Gemini Nano) for quick catch-up.

### Build & release

- [ ] Set up app signing for Android (keystore) for Play Store distribution.
- [ ] Set up app signing for iOS (provisioning profiles, certificates).
- [ ] App store preparation: icons, splash screen, screenshots, store listings.
- [ ] CI (GitHub Actions) for building and testing on push.

### Testing

- [ ] Widget tests for terminal screen and status bar states.
- [ ] Integration test: mock WebSocket server that replays a captured Rust handshake, verify Dart client completes handshake and decrypts output.

## Structured agent interface (exploratory — long-term differentiator)

This is the fork that turns Terminal Relay from "remote terminal" into "remote agent interface." Raw PTY bytes work for terminal mirroring but are insufficient for rich mobile UX (native tool approvals, thinking indicators, code diffs). Identified independently in BOWLINE.md and GOOSE.md competitive analyses.

### Dual-channel architecture

Terminal clients use `PtyOutput` (existing). Rich mobile clients use `AgentEvent` / `AgentCommand` (new). Both go through the same encrypted relay. The existing `SecureMessage::Unknown` fallback provides forward compatibility.

- [ ] Define `AgentEvent` and `AgentCommand` variants in `SecureMessage` enum: `TurnStarted`, `ContentDelta`, `ToolUse`, `ToolApprovalRequired`, `ToolResult`, `TurnCompleted`.
- [ ] Define `AgentCommand` variants: `Prompt`, `ApproveToolUse`, `DenyToolUse`.
- [ ] Prototype Claude Code structured output parsing (`--output-format stream-json`) on the host side.
- [ ] Design dual-channel host mode: PTY stream for terminal clients + parsed event stream for rich clients.
- [ ] Investigate ACP (Agent Client Protocol) as a structured communication alternative to PTY for compatible agents (Goose, potentially Claude Code, Codex).
- [ ] Mobile: approval queue as native UI (approve/reject buttons instead of typing y/n in terminal).
- [ ] Mobile: structured diff viewer with syntax highlighting for agent-produced diffs.
- [ ] Mobile: task timeline / activity feed ("Modified 3 files", "Ran tests (2 failed)", "Waiting for approval").
- [ ] Evaluate aligning structured message format with MCP/ACP conventions for interoperability.

## Session sharing & collaboration

Expands the current single-viewer model into a collaboration platform. Feeds the Team tier (README.md).

- [ ] **Read-only attach mode** — `--read-only` flag for demos and presentations. Expand into per-link permission control: generate one-time share links with read-only or read-write access.
- [ ] Session handoff: generate a link to hand a session to a teammate. They scan QR and get access with specified permissions.
- [ ] **Session recipes** (inspired by Goose): YAML files defining tool, relay URL, args, display name. Shareable as `termrelay://` deep links or QR codes. "Scan this to connect to a Claude Code session for our monorepo."

## Tool registry & detection

- [ ] Enrich `ai_tools.rs` with metadata: display name, description, website, install instructions (shown when tool not found: "Claude Code not found. Install from [https://docs.claude.com](https://docs.claude.com)").
- [ ] Version detection and minimum version enforcement (semver check after `which::which()`). Clear error: "Claude Code 0.9.9 found, requires >=1.0.0."
- [ ] TUI tool differentiation: detect tools that use alternate screen buffers (OpenCode, Kilo Code) and skip backlog replay on reconnect — they redraw everything.
- [ ] Expand tool list to match Termly's 22+ (Cursor CLI, Amazon Q, Grok CLI, Kilo Code, etc.). This is more marketing than code.

## Hosted relay service

### Deployed & operational

- [x] Production relay on Fly.io with auto-TLS, health checks, auto-suspend.
- [x] Control API on Fly.io with Postgres, auto-migration on deploy.
- [x] Signed API key auth, per-user rate limiting (free: 3, pro: 20), revocation sync.
- [x] Session lifecycle reporting (bytes, duration) to control API.

### Remaining

- [ ] Add periodic relay heartbeat (`POST /internal/heartbeat { active_sessions }`) so control API can reconcile stale sessions from relay crashes.
- [ ] Set up custom domain: CNAME `relay.terminal-relay.dev` to Fly app.
- [ ] Billing integration: enforce plan limits (session count, concurrent sessions, bandwidth) and return clear errors when exceeded.
- [ ] Multi-region relay support with geo-routing for lower latency. Premature until there's meaningful traffic.

### Key lifecycle & secret rotation (post-launch)

Manual rotation is fine until there are paying users. This section is reference for when it becomes necessary.

- [x] **Keyless client connections** — Clients can now join authenticated sessions without an API key. The relay verifies the session was created by an authenticated host, and the pairing code serves as the client's authorization. The host's API key never leaves the host machine, eliminating the QR code key leakage concern.
- [ ] **Default API key expiration** — Keys are created with no expiry. Add a default TTL (e.g. 90 days) at creation. CLI should warn when approaching expiry and support `terminal-relay auth rotate`.
- [ ] Add `status` field to `ApiKey` model (`active`, `inactive`, `revoked`). Inactive keys still validate but signal the client to rotate.
- [ ] `POST /api/keys/rotate` endpoint + CLI auto-rotation. Scheduled job to transition keys by age.
- [ ] HMAC secret rotation procedure: new secret → deploy → grace period → drop old.
- [x] Dual HMAC secret support on relay (`HMAC_SECRET` + `HMAC_SECRET_PREVIOUS`).
- [ ] Automate rotation via Infisical, Doppler, or HashiCorp Vault. Long-term operational concern.

## CLI features

- [x] `--version` flag.
- [x] Ctrl-C on attach side detaches cleanly with full terminal state reset.
- [ ] SSH-style escape sequences (`~.` to detach, `~~` to send literal `~`).
- [ ] Status indicator on attach side when secure channel not yet established.
- [ ] Session persistence and recovery: restore active host sessions after CLI restart.
- [ ] Clipboard support: copy/paste between remote client and host PTY via encrypted `SecureMessage`.
- [ ] Daemon/background mode (`terminal-relay start --daemon`).
- [ ] E2E heartbeat-based liveness detection: host sends periodic `Heartbeat`, mobile shows "host may be unresponsive" after timeout.

## Performance

- [ ] Backlog drain throttling: send catchup messages in batches with delays to prevent overwhelming mobile clients (Termly does 100 messages / 10ms delay).
- [ ] Wire compression (WebSocket per-message deflate or application-level zstd/lz4 before `seal()`).
- [ ] Replace `mpsc::unbounded_channel` in `RelayConnection` with bounded channel for backpressure.
- [ ] Increase PTY read buffer from 4096 to 16384+ bytes.
- [ ] Cache last-sent terminal size on attach side, only send `Resize` when changed.
- [x] Circular scrollback buffer (128KB) with replay on reconnect.

## Packaging & distribution

- [ ] **npm wrapper package** — Like esbuild/turbo, publish an npm package that downloads the correct prebuilt binary. `npm install -g terminal-relay` reaches orders of magnitude more developers than current channels.
- [ ] Self-hosting documentation: relay server setup, custom domain, TLS, auth config, enterprise customization points, mobile app white-labeling.
- [ ] Protocol spec, architecture overview in `docs/`.
- [x] Prebuilt binaries (macOS Intel + Apple Silicon, Linux x64 + ARM64) via GitHub Actions.
- [x] Homebrew formula (`brew install yipjunkai/terminal-relay/terminal-relay`).
- [x] Install script (`curl -fsSL ... | sh`).
- [ ] `cargo install terminal-relay` (publish to crates.io). Lower priority than npm.
- [ ] Windows PTY support and CI coverage.
- [ ] Structured observability (OpenTelemetry tracing for relay, metrics for latency/errors/capacity).
- [ ] Opt-in anonymous usage telemetry (session count, tool usage, OS).

## Code quality

- [x] Unit tests: crypto.rs (51 tests), state.rs (7 tests), auth.rs (20 tests), api-key.service (14 tests).
- [x] Common module extraction (`common.rs`).
- [ ] Unit tests for `relay.rs` (registration, cleanup, version validation, rate limiting).
- [ ] Integration tests: relay registration, encrypted handshake, reconnect/resume, replay protection.
- [ ] `protocol_version` in peer-to-peer `Handshake` struct for version comparison and `VersionNotice`.

## Competitive positioning

Terminal Relay's advantages vs. Termly (the direct competitor) that should be emphasized in docs and marketing:

| Area                | Terminal Relay                   | Termly                        |
| ------------------- | -------------------------------- | ----------------------------- |
| Key exchange        | X25519 (~128-bit)                | DH-2048 (~112-bit)            |
| Replay protection   | Monotonic nonce                  | None (random IVs)             |
| Key confirmation    | Automatic HMAC-SHA256            | Manual fingerprint comparison |
| Key derivation      | Separate tx/rx keys              | Single bidirectional key      |
| Relay server        | Open source, self-hostable       | Closed source                 |
| Wire format         | MessagePack (compact)            | JSON (verbose)                |
| Language            | Rust (single binary, low memory) | Node.js (requires runtime)    |
| Protocol versioning | Range negotiation                | Server minimum only           |
| Test suite          | 161 tests                        | None                          |

- [ ] Benchmark and document security advantages in a comparison page.
- [ ] Security whitepaper: protocol spec with crypto rationale.

---

## Completed phases (collapsed)

### Phase 1: Security hardening (complete)

- [x] `ZeroizeOnDrop` on key material, removed `Clone` from `KeyPair`.
- [x] Encrypted session state files (AES-256-GCM, machine-local key, 0600 permissions).
- [x] `HandshakeConfirm` with HMAC-SHA256 key confirmation + timestamp validation (5-min window).
- [x] Route session_id validation to prevent cross-session injection.
- [x] Input validation on session_id (UUID v4), pairing_code format, and field lengths.
- [x] Rate-limit failed pairing attempts (5 failures → lockout).

### Phase 2: Relay reliability (complete)

- [x] Server versioning in `RegisterResponse` and `/healthz` endpoint.
- [x] Graceful shutdown (SIGINT + SIGTERM), cleanup loop cancellation.
- [x] Connection timeout (15s) on `connect_async` and registration.
- [x] Bounded reconnect (10 attempts, exponential backoff, shutdown interrupt).
- [x] Peer notification before session expiry.

### Phase 3: Protocol extensions (complete)

- [x] New `SecureMessage` variants: `SessionEnded`, `Clipboard`, `ReadOnly`, `VoiceCommand`.
- [x] Forward-compatible extensibility (`Unknown` fallback).
- [x] Protocol version range negotiation (v1-v2).
- [x] MessagePack wire format with named keys.
- [x] `--command` flag, CWD inheritance, compact QR codes.
- [x] Clean attach exit on `SessionEnded` / host offline.

### Phase 4: Relay deployment (complete)

- [x] Fly.io deployment with Dockerfile, auto-TLS, health checks.
- [x] `.env` support via `dotenvy`.
- [x] `rustls` with `ring` crypto backend.
- [ ] Custom domain (CNAME `relay.terminal-relay.dev`). Low priority.
- [ ] Development relay for beta testing. Low priority.

### Phase 5: Mobile app core (complete)

- [x] Flutter app: terminal rendering, QR scanning, manual URI paste, E2E encryption.
- [x] Full Dart crypto: X25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA256 handshake.
- [x] MessagePack protocol codec, WebSocket client, deep links (Android + iOS).
- [x] Explicit state machine (8 states), handshake race fix, timeouts.
- [x] Terminal toolbar, home screen, error handling, reconnect.
- [x] API key support in pairing URI and WebSocket connection.

### Control API gateway (complete)

- [x] User registration, API key management (create/list/revoke).
- [x] Signed API key architecture (HMAC-SHA256, zero-latency relay verification).
- [x] Revocation sync, session lifecycle callbacks, byte tracking.
- [x] Per-user rate limiting by tier (free: 3, pro: 20).
- [x] Deployed to Fly.io with Postgres, auto-migration.
- [x] 34 auth tests (20 Rust + 14 TypeScript).
