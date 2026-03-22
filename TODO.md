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

Both Termly and Happy Coder support multiple concurrent sessions. DISPATCH.md envisions managing multiple AI agents across worktrees from a single phone. This is referenced in 4+ competitor analyses and remains the single biggest feature gap vs. every direct competitor.

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

> **Competitor insight (Happy Coder):** Happy gets a web app (app.happy.engineering) for free from Expo/React Native — one codebase targets iOS, Android, and Web. Flutter has web support but it's less mature for terminal-heavy apps. If building the web client from scratch, xterm.js + WebCrypto is the simplest path. If considering a framework pivot for the mobile app, React Native/Expo gives web for free.

- [ ] Build web client: xterm.js + WebSocket + WebCrypto. Encrypted attach, bidirectional input, terminal resize, responsive layout.
- [ ] PWA support (manifest, service worker, home screen install) for quick access without app store.
- [ ] Shareable web URLs (e.g. `https://terminal-relay.dev/s/<token>`) that open the web client with pairing info embedded. Falls back to app store links on mobile.

## Mobile app (Pro tier — premium hook)

The mobile app is the paid differentiator. Speech-to-code, push notifications, and native UX justify the Pro tier. 58 tests passing, E2E encryption working, deployed on Android.

### Immediate UX improvements

- [x] **Smart input bar** — Unified prompt bar with Telegram-style mic/send toggle button. Structured view for Claude Code with native UI cards (thinking, tool calls, text blocks, turn markers). Busy indicator disables input during agent turns. STT fills the prompt bar for editing before send.
- [ ] Draft saving, history recall in prompt bar.
- [ ] Reconnect overlay when connection drops (error message + reconnect/close buttons, not just a small icon).
- [ ] Landscape orientation support for more terminal columns.
- [ ] Terminal themes and customization (Dracula, Solarized, Nord, Catppuccin, custom fonts).
- [ ] Settings screen: relay URL, font size, theme, haptic feedback toggle. Persist with `shared_preferences`.
- [ ] Validate pairing URI before navigating (check relay URL is reachable).
- [ ] Scan QR from photo gallery (screenshot of QR code).
- [ ] Surface crypto errors clearly: "Fingerprint mismatch" should explain what it means and what to do.
- [ ] Show session metadata: host fingerprint, connection duration, data transferred.

### Push notifications & idle detection

Push notifications are a **Pro tier feature** and a competitive gap vs. both Termly and Happy Coder. Tied directly to monetization.

> **Competitor insight:** Termly tracks `lastOutputTime` on every PTY write. If no output for 15+ seconds, status = `idle`. Reported in heartbeat pongs. Server triggers push. Happy Coder ships full encrypted push notifications via APNs/FCM — this is table stakes for the category now.

- [ ] Host-side idle/busy detection: track `lastOutputTime` on every PTY write. Status = `idle` if no output for 15+ seconds. Report in heartbeat messages.
- [ ] Push notification infrastructure: APNS (iOS) + FCM (Android) for session events (peer connected, session ended, agent idle/waiting for input).
- [ ] Smart notification batching: don't spam. Periodic summaries ("Claude modified 4 files, tests passing") with configurable frequency.
- [ ] Watch expressions: user-defined regex triggers on terminal output ("notify me when `BUILD SUCCESSFUL` appears").

### Speech-to-code (premium differentiator)

Speech-to-code is something the web client and CLI cannot replicate. This justifies the Pro tier (README.md). Needs a detailed plan, not a single line item.

> **Competitor insight (Happy Coder):** Happy doesn't just transcribe speech — they run a separate Claude Sonnet instance (via ElevenLabs STT/TTS) as a **voice agent** that refines stream-of-consciousness speech into concrete, well-structured prompts. The voice agent has its own conversation context and acts as an intermediary between the user and Claude Code. This is a significantly higher bar than raw transcription.

- [x] On-device speech recognition via `speech_to_text` package (iOS SFSpeechRecognizer / Android SpeechRecognizer).
- [x] Send `VoiceCommand` messages to the host. Host writes transcript to PTY.
- [x] Unified mic/send button in prompt bar (structured view). Mic FAB retained for terminal view. Transcript fills prompt bar for editing before send.
- [ ] **Voice agent intermediary** — Instead of injecting raw transcription, pipe speech through an on-device or cloud LLM that refines it into a structured prompt before sending. "Uh, can you like, look at the auth thing and maybe fix the tests" → "Fix the failing authentication tests in `src/auth/`." Could run on-device (Apple Intelligence / Gemini Nano) or as a lightweight cloud call. Happy Coder validates this is what users expect.
- [ ] Continuous listening mode with "Hey Terminal" wake word detection (on-device).
- [ ] Voice command chaining: "Run tests, and if they pass, commit with message 'fix auth bug'" — parsed into conditional sequential commands.
- [ ] Context-aware dictation: use current terminal context (language, framework) to improve recognition accuracy.

### Gesture & interaction improvements

- [ ] Gesture-based terminal control: swipe-left for Ctrl-C, swipe-up for scroll-back, pinch-to-zoom for font size.
- [x] Bottom sheet terminal actions: Interrupt, EOF, Suspend, Clear, arrow navigation, Tab, Esc, Paste, Search. Grouped by category with icons. Replaces the old inline toolbar.
- [ ] Prompt templates / quick commands: user-defined snippets ("fix the failing tests", "explain this error"). Tap to send.
- [ ] Haptic + audio feedback for agent state changes (distinct vibration patterns for thinking, waiting, finished, disconnected).

### Advanced features (post-launch)

- [ ] Session recording & playback (asciinema-style, built-in). Review what an agent did overnight.
- [ ] **Server-side encrypted session history** — Happy Coder's killer feature for async workflows: start a task, go to lunch, review results from your phone hours later. Their model: per-session AES-256 DEK encrypts content, DEK is encrypted with user's content public key. Only the 32-byte DEK needs re-encryption for sharing/multi-device. Design question: grow the relay server with a persistence layer, or add a separate history service that subscribes to encrypted session events?
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

## Structured agent interface

Terminal clients use `PtyOutput` (existing). Rich mobile clients use `AgentEvent` / `AgentCommand` (new). Both go through the same encrypted relay. The `SecureMessage::Unknown` fallback provides forward compatibility. Claude Code support is live via JSONL session log tailing; other agents fall back to PTY-only.

> **Competitor insight (Happy Coder):** Happy uses Claude Code's `--input-format stream-json --output-format stream-json` for a fully bidirectional JSON protocol over stdin/stdout — no PTY at all in remote mode. They also support `--permission-prompt-tool stdio` for intercepting tool approvals as structured JSON control requests/responses, enabling native Allow/Deny cards on mobile. Their "local mode" uses a `SessionScanner` that tails the JSONL log (identical to our approach) for read-only mobile viewing, then kills+respawns Claude with `--resume` + `stream-json` flags when mobile sends a message. See `HAPPY.md` for full analysis.

### Dual-channel architecture (complete for Claude Code)

- [x] Define `AgentEvent` variants in `SecureMessage` enum: `SessionInit`, `TurnStarted`, `TextDelta`, `ThinkingDelta`, `TextBlock`, `ToolUseStart`, `ToolResult`, `TurnCompleted`, `SessionResult`.
- [x] Define `AgentCommand` variants: `Prompt`, `ApproveToolUse`, `DenyToolUse`.
- [x] JSONL session log watcher (`jsonl_watcher.rs`): tails `~/.claude/projects/<hash>/<sessionId>.jsonl` via `notify` (kqueue), parses events, emits `AgentEvent` alongside PTY output. Turn completion detected via `stop_reason: "end_turn"`.
- [x] Dual-channel host mode: PTY stream for terminal clients + parsed event stream for rich clients, both through the same encrypted relay simultaneously.
- [x] Dart protocol: full MessagePack encode/decode for all `AgentEvent` and `AgentCommand` variants with forward-compatible unit variant handling.
- [x] PTY injection: `AgentCommand::Prompt` → `pty.send_input(text + \r)`, `ApproveToolUse` → `y\r`, `DenyToolUse` → `n\r`.
- [x] Takeover mode: Enter to attach desktop to PTY, double-tap Esc to return to dashboard. Resize forwarding, Ctrl+L redraw. Both desktop and phone can write simultaneously.
- [x] Tool result truncation (32KB cap) to prevent huge payloads over the relay.
- [x] 13 protocol roundtrip tests for new variants, 7 JSONL parser tests.

### Remaining

- [ ] Investigate ACP (Agent Client Protocol) as a structured communication alternative to PTY for compatible agents (Goose, potentially Claude Code, Codex).
- [ ] Mobile: structured diff viewer with syntax highlighting for agent-produced diffs.
- [ ] Mobile: task timeline / activity feed ("Modified 3 files", "Ran tests (2 failed)", "Waiting for approval").
- [ ] Evaluate aligning structured message format with MCP/ACP conventions for interoperability.
- [ ] Extend JSONL watcher to other tools that write session logs (or add tool-specific parsers).
- [ ] Multi-turn follow-up prompts from phone (currently each prompt is independent PTY injection; no conversation threading on the structured side).
- [ ] **Native tool-approval interception** — Happy Coder intercepts Claude's `control_request` messages (via `--permission-prompt-tool stdio`) and shows native Allow/Deny cards with tool name, description, and input preview. Currently we inject `y\r` / `n\r` into the PTY via `AgentCommand`. Investigate spawning Claude with `--permission-prompt-tool stdio` in a sidecar JSON channel so the mobile app can render proper approval cards instead of relying on PTY text prompts. This is the biggest remaining UX gap vs Happy Coder.
- [ ] **Subagent tracking** — Happy Coder's protocol includes a `subagent` field in the event envelope for Claude Code's parallel subagent feature. Reserve a `subagent_id: Option<String>` field in `AgentEvent` so the mobile app can display parallel agent workstreams independently. Not urgent but worth reserving in the protocol before it ships widely.
- [ ] **Happy-style mode switching** — Evaluate the kill+respawn approach: local mode (PTY, `stdio: inherit`) for desktop use, remote mode (`--input-format stream-json --resume`) for mobile control. Switching kills the Claude process and respawns in the other mode. `--resume` preserves conversation context. Pro: true bidirectional structured protocol for mobile. Con: process restart latency, only works for Claude Code, adds complexity vs our JSONL watcher which gives both simultaneously.

## Session sharing & collaboration

Expands the current single-viewer model into a collaboration platform. Feeds the Team tier (README.md).

- [ ] **Read-only attach mode** — `--read-only` flag for demos and presentations. Expand into per-link permission control: generate one-time share links with read-only or read-write access.
- [ ] Session handoff: generate a link to hand a session to a teammate. They scan QR and get access with specified permissions.
- [ ] **Session recipes** (inspired by Goose): YAML files defining tool, relay URL, args, display name. Shareable as `termrelay://` deep links or QR codes. "Scan this to connect to a Claude Code session for our monorepo."

## Multi-device & key management (longer-term)

> **Competitor insight (Happy Coder):** Happy uses a master secret → content key pair → per-session DEK hierarchy. The master secret lives on the phone, the content public key goes to all CLI machines. Any device with the master secret can decrypt any session. To share a session, re-encrypt the 32-byte DEK with a friend's public key — the actual content never needs re-encryption. Terminal Relay currently requires a new QR code pairing per session, with no way to access the same session from multiple devices.

- [ ] **Multi-device key hierarchy** — Design a key model that allows accessing sessions from phone and tablet without per-session QR codes. Consider a hybrid: ephemeral X25519 keys for real-time PTY streams (preserves forward secrecy), plus an optional persistent identity key for session history and multi-device access (convenience). This is a fundamental crypto architecture decision — don't rush it.
- [ ] **Hash-based session identity** (inspired by Sisyphus) — If you create a session with the same tool, args, relay URL, and working directory, it could deterministically reconnect to the existing session instead of creating a new one. Identity = hash of configuration, not a random token. Makes session resume more robust.
- [ ] **Session import/export** — Share session recordings, configs, or state between team members. Export a session (tool config + encrypted output recording), import for review or continuation. (Sisyphus's `import_work_directory` model.)

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

> **Competitor insight:** Both Happy Coder (`npm install -g happy-coder`) and Termly (`npm install -g @termly-dev/cli`) distribute via npm. For the "AI coding tools" audience, npm is the default package manager. Happy Coder also gets a web app for free from Expo/React Native.

- [ ] **Homebrew tap** — Create `yipjunkai/homebrew-terminal-relay` repo with formula pointing to GitHub Release binaries. Auto-update version and SHA256 sums on release via CI.
- [ ] **npm wrapper package** — Like esbuild/turbo, publish an npm package that downloads the correct prebuilt binary. `npm install -g terminal-relay` reaches orders of magnitude more developers than current channels. Both direct competitors validate this channel.
- [ ] Self-hosting documentation: relay server setup, custom domain, TLS, auth config, enterprise customization points, mobile app white-labeling. (Goose has thorough `CUSTOM_DISTROS.md` for reference.)
- [ ] **TypeScript/JSON protocol spec** — If Terminal Relay's protocol needs to be consumed by non-Rust clients (web app, third-party integrations), publish the protocol types as a TypeScript package or JSON schema. Happy Coder does this with `@slopus/happy-wire` (Zod schemas). Lower priority than web client but enables ecosystem.
- [ ] Protocol spec, architecture overview in `docs/`.
- [x] Prebuilt binaries (macOS Intel + Apple Silicon, Linux x64 + ARM64) via GitHub Actions.
- [x] Homebrew formula (`brew install yipjunkai/terminal-relay/terminal-relay`).
- [x] Install script (`curl -fsSL ... | sh`).
- [ ] `cargo install terminal-relay` (publish to crates.io). Lower priority than npm.
- [ ] Windows PTY support and CI coverage. (Termly has explicit Windows optimizations: PTY output deduplication within ~150ms, escape sequence normalization for mobile.)
- [ ] Structured observability (OpenTelemetry tracing for relay, metrics for latency/errors/capacity). Goose uses PostHog + OpenTelemetry + Langfuse.
- [ ] Opt-in anonymous usage telemetry (session count, tool usage, OS).

## Code quality

- [x] Unit tests: crypto.rs (51 tests), state.rs (7 tests), auth.rs (20 tests), api-key.service (14 tests).
- [x] Common module extraction (`common.rs`).
- [ ] Unit tests for `relay.rs` (registration, cleanup, version validation, rate limiting).
- [ ] Integration tests: relay registration, encrypted handshake, reconnect/resume, replay protection.
- [ ] `protocol_version` in peer-to-peer `Handshake` struct for version comparison and `VersionNotice`.

## Competitive positioning

Terminal Relay's advantages vs. the field — emphasized in docs and marketing:

### vs. Termly (direct PTY competitor, 141 stars)

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
| Test suite          | 161+ tests                       | None                          |
| Structured events   | Yes (AgentEvent/AgentCommand)    | No                            |
| Voice input         | Yes (on-device STT)              | No                            |
| Desktop takeover    | Yes (Enter/double-Esc)           | No                            |

Terminal Relay now significantly outclasses Termly on features. Remaining Termly advantages: multi-session, push notifications, npm distribution, Windows support.

### vs. Happy Coder (primary competitor, 15.8k stars)

| Area                 | Terminal Relay                            | Happy Coder                    |
| -------------------- | ----------------------------------------- | ------------------------------ |
| Agent agnosticism    | Any CLI tool via PTY                      | Claude Code, Codex, Gemini only (per-agent parsers) |
| Forward secrecy      | Yes (ephemeral X25519)                    | No (master secret decrypts all) |
| Replay protection    | Monotonic nonce + sliding window          | Not documented                 |
| Server storage       | Zero (in-memory relay)                    | Encrypted blobs in Postgres    |
| Crypto test suite    | 51+ crypto tests, cross-platform vectors  | Minimal                        |
| Performance          | Rust single binary                        | Node.js                        |
| Structured events    | Yes (JSONL watcher + native mobile UI)    | Yes (stdin/stdout JSON)        |
| Desktop takeover     | Yes (TUI + PTY attach)                    | Yes (any key reclaims)         |
| Voice input          | Yes (on-device STT)                       | Yes (ElevenLabs + Claude Sonnet intermediary) |
| Multi-session        | No (single CLI session)                   | Yes                            |
| Push notifications   | Protocol types only                       | Shipped (APNs/FCM)            |
| Session history      | Mobile-only (local)                       | Server-side (encrypted blobs)  |
| npm distribution     | No                                        | Yes                            |
| Web app              | No                                        | Yes (Expo web)                 |
| Multi-device keys    | Per-session pairing                       | Master secret hierarchy        |
| Permission prompts   | PTY injection (`y\r`/`n\r`)               | Native Allow/Deny cards        |

Terminal Relay has closed the structured events, desktop takeover, and voice input gaps. Remaining Happy Coder advantages: multi-session, push notifications, server-side history, npm, web app, native permission UI, intelligent voice agent, multi-device keys.

- [ ] Benchmark and document security advantages in a comparison page.
- [ ] Security whitepaper: protocol spec with crypto rationale.
- [ ] Prepare competitive positioning messaging against Happy Coder's "everything is free and open source" angle. Counter: sustainable business model, stronger crypto, agent-agnostic, lighter server.
- [ ] Monitor Happy Coder's traction and feature development closely — this is the primary competitor with 15.8k stars and 44 contributors.

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

- [x] New `SecureMessage` variants: `SessionEnded`, `Clipboard`, `ReadOnly`, `VoiceCommand`, `AgentEvent`, `AgentCommand`.
- [x] Forward-compatible extensibility (`Unknown` fallback). Dart handles unit variants (strings) gracefully.
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
