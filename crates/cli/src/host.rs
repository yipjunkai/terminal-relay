use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Args;
use crossterm::terminal;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::tui::{self, LogLevel, PeerStatus, SessionInfo, Tui, TuiAction, TuiState};

use protocol::{
    crypto::{fingerprint, generate_key_pair},
    pairing::{PairingUri, build_pairing_uri, new_pairing_code, new_session_id},
    protocol::{
        PROTOCOL_VERSION, PROTOCOL_VERSION_MIN, PeerFrame, PeerRole,
        RegisterRequest, RelayMessage, RelayRoute, SecureMessage, decode_peer_frame,
    },
};

use crate::common::{
    ChannelState, now_millis, process_inbound_handshake, reconnect_with_backoff,
    send_handshake, send_peer_frame, shutdown_signal, verify_handshake_confirm,
};

/// Identity and key material for the local side of a session (immutable after creation).
struct SessionIdentity {
    session_id: String,
    tool_name: String,
    local_secret: [u8; 32],
    local_public: [u8; 32],
}

/// Shared mutable state for a host session, threaded through the event loop,
/// handle_route, and takeover mode to avoid passing many individual parameters.
struct HostContext {
    chan: ChannelState,
    output_backlog: BoundedByteBuffer,
    scrollback: BoundedByteBuffer,
    relay_tx: mpsc::Sender<RelayMessage>,
    identity: SessionIdentity,
    tui_state: TuiState,
}

impl HostContext {
    /// Seal a message and send it to the peer. No-op if the channel is not confirmed.
    fn send_secure(&mut self, msg: &SecureMessage) -> anyhow::Result<()> {
        let Some(channel) = self.chan.confirmed_channel() else {
            return Ok(());
        };
        let sealed = channel.seal(msg)?;
        send_peer_frame(&self.relay_tx, &self.identity.session_id, PeerFrame::Secure(sealed))
    }
}

use crate::{
    ai_tools::{resolve_tool, tool_supports_structured},
    pty::PtySession,
    relay_client::RelayConnection,
    state::{SessionRecord, SessionStore},
};

#[derive(Debug, Clone, Args)]
pub struct HostArgs {
    #[arg(long, default_value = crate::constants::DEFAULT_RELAY_URL, env = crate::constants::RELAY_URL_ENV, hide = true)]
    pub relay_url: String,
    /// API key for authenticating with the relay. Reads from config if not specified.
    #[cfg(feature = "hosted")]
    #[arg(long, env = crate::constants::API_KEY_ENV, hide = true)]
    pub api_key: Option<String>,
    /// AI tool to run, with optional arguments.
    /// Accepts known names (claude, opencode, copilot, gemini, aider) or any
    /// command on PATH. Extra arguments can follow the tool name.
    ///
    /// Examples:
    ///   farwatch start claude
    ///   farwatch start aider --model sonnet
    ///   farwatch start my-custom-tool --flag
    ///
    /// Auto-detects if not specified.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub tool: Vec<String>,
}

pub async fn run_host_sessions(args: HostArgs, store: SessionStore) -> anyhow::Result<()> {
    // Split positional args: first element is the tool name, rest are tool args.
    let (tool_name, tool_args) = if args.tool.is_empty() {
        (None, Vec::new())
    } else {
        (
            Some(args.tool[0].as_str()),
            args.tool[1..].to_vec(),
        )
    };

    let tool = resolve_tool(tool_name, &tool_args)?;
    let (rows, cols) = initial_size();

    // Resolve API key: CLI arg > env var > config file (hosted builds only).
    #[cfg(feature = "hosted")]
    let api_key = {
        let key = args
            .api_key
            .or_else(|| crate::config::Config::load().ok().and_then(|c| c.api_key));
        // Warn if connecting to the production relay without an API key.
        if key.is_none() && args.relay_url == crate::constants::DEFAULT_RELAY_URL {
            eprintln!("Warning: No API key found. The hosted relay requires authentication.");
            eprintln!("Run `farwatch auth` to authenticate.\n");
            return Err(anyhow::anyhow!("authentication required"));
        }
        key
    };
    #[cfg(not(feature = "hosted"))]
    let api_key: Option<String> = None;

    run_single_host_session(HostSessionParams {
        tool_name: tool.name,
        command: tool.command,
        args: tool.args,
        relay_url: args.relay_url,
        api_key,
        rows,
        cols,
        store,
    })
    .await
}

struct HostSessionParams {
    tool_name: String,
    command: String,
    args: Vec<String>,
    relay_url: String,
    api_key: Option<String>,
    rows: u16,
    cols: u16,
    store: SessionStore,
}

async fn run_single_host_session(params: HostSessionParams) -> anyhow::Result<()> {
    let HostSessionParams {
        tool_name,
        command,
        args,
        relay_url,
        api_key,
        rows,
        cols,
        store,
    } = params;

    let session_id = new_session_id();
    let pairing_code = new_pairing_code();
    let local_key = generate_key_pair();
    let local_fingerprint = fingerprint(&local_key.public);

    let (mut relay, registered) = connect_host(
        &relay_url,
        &session_id,
        &pairing_code,
        None,
        api_key.as_deref(),
    )
    .await?;
    let relay_tx = relay.sender();
    let mut resume_token = registered.resume_token.clone();

    // Build pairing URI without the API key — clients can now join authenticated
    // sessions without their own key (the relay checks the host's auth instead).
    let pairing_uri = build_pairing_uri(&PairingUri {
        relay_url: relay_url.clone(),
        session_id: session_id.clone(),
        pairing_code: pairing_code.clone(),
        expected_fingerprint: Some(local_fingerprint.clone()),
        api_key: None,
    })?;

    let record = SessionRecord {
        session_id: session_id.clone(),
        relay_url: relay_url.clone(),
        pairing_code: pairing_code.clone(),
        resume_token: resume_token.clone(),
        tool: tool_name.clone(),
        command: command.clone(),
        command_args: args.clone(),
        created_at: rfc3339_now(),
        public_key: local_key.public,
        secret_key: local_key.secret,
    };
    store.save(&record)?;

    // ── Set up TUI ──────────────────────────────────────────────────
    let qr_lines = tui::qr_to_lines(&pairing_uri).unwrap_or_default();

    let tui_state = TuiState::new(
        SessionInfo {
            tool_name: tool_name.clone(),
            session_id: session_id.clone(),
            relay_url: relay_url.clone(),
            fingerprint: local_fingerprint.clone(),
        },
        qr_lines,
    );

    let mut tui_handle = Tui::new()?;
    let mut tui_state = tui_state;
    tui_state.push_log(LogLevel::Info, "Connected to relay");
    tui_state.push_log(LogLevel::Info, "Session registered");
    tui_handle.draw(&tui_state)?;

    let identity = SessionIdentity {
        session_id,
        tool_name,
        local_secret: local_key.secret,
        local_public: local_key.public,
    };

    // ── Always spawn PTY ──────────────────────────────────────────
    let (pty, streams) = PtySession::spawn(&command, &args, rows, cols)?;
    let mut output_rx = streams.output_rx;
    let mut exit_rx = streams.exit_rx;

    // For tools with structured support (Claude Code), start a JSONL watcher
    // that tails the session log and emits AgentEvent alongside PTY output.
    let mut event_rx: Option<mpsc::Receiver<protocol::protocol::AgentEvent>> = None;
    let mut watcher_log_rx: Option<mpsc::Receiver<String>> = None;
    if tool_supports_structured(&identity.tool_name) {
        tui_state.push_log(LogLevel::Info, "Starting JSONL session watcher");
        match crate::jsonl_watcher::start_watching() {
            Ok(watcher) => {
                event_rx = Some(watcher.event_rx);
                watcher_log_rx = Some(watcher.log_rx);
            }
            Err(err) => {
                tui_state.push_log(LogLevel::Warning, format!("JSONL watcher failed: {err}"));
            }
        }
    }

    let mut ctx = HostContext {
        chan: ChannelState::new(),
        output_backlog: BoundedByteBuffer::new(crate::constants::OUTPUT_BACKLOG_CAP),
        scrollback: BoundedByteBuffer::new(SCROLLBACK_CAPACITY),
        relay_tx,
        identity,
        tui_state,
    };
    let mut peer_online = registered.peer_online;

    if peer_online {
        send_handshake(
            &ctx.identity.session_id,
            &ctx.relay_tx,
            &ctx.identity.local_public,
            &local_fingerprint,
            Some(ctx.identity.tool_name.clone()),
        )?;
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    let mut heartbeat = tokio::time::interval(Duration::from_secs(crate::constants::HEARTBEAT_INTERVAL_SECS));
    let mut redraw = tokio::time::interval(Duration::from_millis(crate::constants::REDRAW_INTERVAL_MS));

    loop {
        tokio::select! {
                // ── PTY output ──
                output = output_rx.recv() => {
                    let Some(bytes) = output else { continue; };
                    let len = bytes.len() as u64;
                    ctx.scrollback.push(bytes.clone());
                    if ctx.chan.is_confirmed() {
                        if let Err(err) = ctx.send_secure(&SecureMessage::PtyOutput(bytes)) {
                            warn!(error = %err, "failed sending PTY output");
                        }
                        ctx.tui_state.bytes_sent += len;
                    } else {
                        ctx.output_backlog.push(bytes);
                    }
                }
                // ── JSONL watcher: agent events (for structured-capable tools) ──
                agent_event = async { event_rx.as_mut().unwrap().recv().await }, if event_rx.is_some() => {
                    let Some(evt) = agent_event else { continue; };
                    if let Err(err) = ctx.send_secure(&SecureMessage::AgentEvent(evt)) {
                        warn!(error = %err, "failed sending agent event");
                    }
                }
                // ── JSONL watcher: log messages → TUI ──
                log_msg = async { watcher_log_rx.as_mut().unwrap().recv().await }, if watcher_log_rx.is_some() => {
                    if let Some(msg) = log_msg {
                        ctx.tui_state.push_log(LogLevel::Info, msg);
                    }
                }
                // ── Relay inbound messages ──
                inbound = relay.recv() => {
                    match inbound {
                        Some(RelayMessage::Route(route)) => {
                            if route.session_id != ctx.identity.session_id {
                                continue;
                            }
                            let payload_len = route.payload.len() as u64;
                            handle_route(route, &pty, &mut ctx)?;
                            ctx.tui_state.bytes_received += payload_len;
                        }
                        Some(RelayMessage::PeerStatus(status)) => {
                            if status.role == PeerRole::Client {
                                peer_online = status.online;
                                if peer_online {
                                    ctx.tui_state.push_log(LogLevel::Info, "Client connected");
                                    send_handshake(
                                        &ctx.identity.session_id,
                                        &ctx.relay_tx,
                                        &ctx.identity.local_public,
                                        &local_fingerprint,
                                        Some(ctx.identity.tool_name.clone()),
                                    )?;
                                    ctx.tui_state.status = PeerStatus::Handshaking;
                                } else {
                                    ctx.tui_state.push_log(LogLevel::Warning, "Client disconnected");
                                    info!(session_id = %ctx.identity.session_id, "client disconnected, awaiting reconnect");
                                    ctx.chan.reset();
                                    ctx.tui_state.status = PeerStatus::WaitingForPeer;
                                }
                            }
                        }
                        Some(RelayMessage::Error(err)) => {
                            ctx.tui_state.push_log(LogLevel::Error, format!("Relay error: {}", err.message));
                            warn!(session_id = %ctx.identity.session_id, message = %err.message, "relay reported error");
                        }
                        Some(RelayMessage::Pong(_)) | Some(RelayMessage::Ping(_)) | Some(RelayMessage::Registered(_)) | Some(RelayMessage::Register(_)) => {}
                        None => {
                            ctx.tui_state.status = PeerStatus::Disconnected;
                            ctx.tui_state.push_log(LogLevel::Warning, "Relay disconnected, reconnecting...");
                            warn!(session_id = %ctx.identity.session_id, "relay disconnected, attempting recovery");
                            let (new_relay, new_registered) = reconnect_host(&relay_url, &ctx.identity.session_id, &pairing_code, &resume_token, api_key.as_deref()).await?;
                            relay = new_relay;
                            ctx.relay_tx = relay.sender();
                            resume_token = new_registered.resume_token.clone();
                            ctx.chan.reset();
                            peer_online = new_registered.peer_online;
                            ctx.tui_state.status = PeerStatus::WaitingForPeer;
                            ctx.tui_state.push_log(LogLevel::Info, "Reconnected to relay");
                            if peer_online {
                                send_handshake(
                                    &ctx.identity.session_id,
                                    &ctx.relay_tx,
                                    &ctx.identity.local_public,
                                    &local_fingerprint,
                                    Some(ctx.identity.tool_name.clone()),
                                )?;
                            }
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    let _ = ctx.relay_tx.try_send(RelayMessage::Ping(now_millis()));
                }
                _ = redraw.tick() => {
                    match tui_handle.poll_action(Duration::ZERO)? {
                        TuiAction::Quit => {
                            ctx.tui_state.push_log(LogLevel::Info, "Shutting down...");
                            tui_handle.draw(&ctx.tui_state)?;
                            break;
                        }
                        TuiAction::Takeover => {
                            ctx.tui_state.push_log(LogLevel::Info, "Takeover mode — double-tap Esc to return");
                            tui_handle.draw(&ctx.tui_state)?;

                            // Suspend TUI and enter takeover loop.
                            tui_handle.suspend()?;
                            run_takeover(&pty, &mut output_rx, &mut event_rx, &mut watcher_log_rx, &mut relay, &mut ctx).await?;
                            tui_handle.resume()?;
                            ctx.tui_state.push_log(LogLevel::Info, "Returned to dashboard");
                        }
                        TuiAction::None => {}
                    }
                    tui_handle.draw(&ctx.tui_state)?;
                }
                exit_code = &mut exit_rx => {
                    let code = exit_code.unwrap_or(1);
                    ctx.tui_state.push_log(LogLevel::Info, format!("Process exited (code {code})"));
                    info!(session_id = %ctx.identity.session_id, code = code, "PTY process exited");
                    let _ = ctx.send_secure(&SecureMessage::SessionEnded { exit_code: code });
                    tui_handle.draw(&ctx.tui_state)?;
                    sleep(Duration::from_secs(1)).await;
                    break;
                }
                _ = &mut shutdown => {
                    ctx.tui_state.push_log(LogLevel::Info, "Received shutdown signal");
                    info!(session_id = %ctx.identity.session_id, "received shutdown signal, stopping host session");
                    tui_handle.draw(&ctx.tui_state)?;
                    break;
                }
            }
        }
    // Terminal restored automatically by Tui::Drop.
    Ok(())
}



fn handle_route(
    route: RelayRoute,
    pty: &PtySession,
    ctx: &mut HostContext,
) -> anyhow::Result<()> {
    let frame = decode_peer_frame(&route.payload)?;
    match frame {
        PeerFrame::Handshake(handshake) => {
            let result = process_inbound_handshake(
                PeerRole::Host,
                &ctx.identity.session_id,
                ctx.identity.local_secret,
                &ctx.identity.local_public,
                &handshake,
                &ctx.chan,
                None, // Host does not verify fingerprint
                &ctx.relay_tx,
            )?;

            let Some(hs) = result else {
                return Ok(()); // Duplicate or stale — ignored
            };

            ctx.tui_state.push_log(LogLevel::Info, format!("Peer fingerprint: {}", handshake.fingerprint));
            info!(
                session_id = %ctx.identity.session_id,
                peer_fingerprint = %handshake.fingerprint,
                "peer handshake received"
            );

            ctx.chan.start_handshake(hs.channel, hs.expected_peer_mac);
        }
        PeerFrame::HandshakeConfirm(confirm) => {
            if !verify_handshake_confirm(&confirm, &ctx.chan) {
                warn!(session_id = %ctx.identity.session_id, "handshake confirmation MAC mismatch — tearing down channel");
                ctx.chan.reset();
                return Ok(());
            }

            ctx.tui_state.status = PeerStatus::Secure;
            ctx.tui_state.push_log(LogLevel::Success, "E2E encryption established");
            info!(session_id = %ctx.identity.session_id, "handshake confirmed, channel trusted");
            ctx.chan.confirm();

            // Replay scrollback first so reconnecting clients catch up on
            // output that was produced while they were disconnected.
            let replay = ctx.scrollback.drain();
            if !replay.is_empty() {
                let total_bytes: usize = replay.iter().map(Vec::len).sum();
                ctx.tui_state.push_log(
                    LogLevel::Info,
                    format!("Sending scrollback ({:.1} KB)", total_bytes as f64 / 1024.0),
                );
                info!(
                    session_id = %ctx.identity.session_id,
                    chunks = replay.len(),
                    bytes = total_bytes,
                    "replaying scrollback"
                );
                for bytes in replay {
                    ctx.send_secure(&SecureMessage::PtyOutput(bytes))?;
                }
            }

            // Then drain the handshake-window backlog (output produced
            // between handshake start and confirm).
            for bytes in ctx.output_backlog.drain() {
                ctx.send_secure(&SecureMessage::PtyOutput(bytes))?;
            }

            ctx.send_secure(&SecureMessage::Notification(protocol::protocol::PushNotification {
                title: format!("Connected to {}", ctx.identity.tool_name),
                body: "Session encryption established".to_string(),
            }))?;
        }
        PeerFrame::Secure(sealed) => {
            let Some(channel) = ctx.chan.confirmed_channel() else {
                return Ok(());
            };
            let message = channel.open(&sealed)?;
            match message {
                SecureMessage::PtyInput(bytes) => {
                    pty.send_input(bytes)?;
                }
                SecureMessage::Resize { cols, rows } => {
                    pty.resize(cols, rows)?;
                }
                SecureMessage::VoiceCommand(action) => {
                    pty.send_input(action.transcript.into_bytes())?;
                }
                SecureMessage::AgentCommand(cmd) => {
                    match cmd {
                        protocol::protocol::AgentCommand::Prompt { text } => {
                            // Inject the prompt into the PTY as keystrokes.
                            // Use \r (carriage return) not \n — PTY Enter is \r.
                            pty.send_input(format!("{text}\r").into_bytes())?;
                        }
                        protocol::protocol::AgentCommand::ApproveToolUse { .. } => {
                            // Inject 'y' + Enter into the PTY to approve.
                            pty.send_input(b"y\r".to_vec())?;
                        }
                        protocol::protocol::AgentCommand::DenyToolUse { .. } => {
                            // Inject 'n' + Enter into the PTY to deny.
                            pty.send_input(b"n\r".to_vec())?;
                        }
                    }
                }
                SecureMessage::Heartbeat
                | SecureMessage::VersionNotice { .. }
                | SecureMessage::Notification(_)
                | SecureMessage::PtyOutput(_)
                | SecureMessage::SessionEnded { .. }
                | SecureMessage::Clipboard { .. }
                | SecureMessage::ReadOnly { .. }
                | SecureMessage::AgentEvent(_)
                | SecureMessage::Unknown(_) => {}
            }
        }
        PeerFrame::KeepAlive => {}
    }
    Ok(())
}

/// Takeover mode: the desktop user directly interacts with the PTY.
///
/// The TUI is suspended. PTY output goes to stdout (so the user sees Claude
/// Code's real TUI). Keyboard input goes to the PTY. The relay still receives
/// PTY output so the phone stays in sync. Double-tap Esc exits back to the dashboard.
async fn run_takeover(
    pty: &PtySession,
    output_rx: &mut mpsc::Receiver<Vec<u8>>,
    event_rx: &mut Option<mpsc::Receiver<protocol::protocol::AgentEvent>>,
    watcher_log_rx: &mut Option<mpsc::Receiver<String>>,
    relay: &mut RelayConnection,
    ctx: &mut HostContext,
) -> anyhow::Result<()> {
    use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
    use tokio::io::{AsyncWriteExt, stdout};

    // Enter raw mode for direct keyboard passthrough.
    enable_raw_mode()?;

    let mut out = stdout();

    // Force the TUI app to redraw by resizing the PTY to the current
    // terminal size (shrink then restore to guarantee SIGWINCH) and
    // sending Ctrl+L (universal "redraw screen" in TUI apps).
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        let _ = pty.resize(cols.saturating_sub(1).max(1), rows);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = pty.resize(cols, rows);
    }
    let _ = pty.send_input(vec![0x0c]); // Ctrl+L



    // Spawn a blocking task to read stdin keypresses and resize events.
    enum TakeoverInput {
        Key(Vec<u8>),
        Resize(u16, u16),
    }
    let (key_tx, mut key_rx) = mpsc::channel::<TakeoverInput>(64);
    let stdin_task = tokio::task::spawn_blocking(move || {
        use crossterm::event::{self, Event, KeyCode, KeyModifiers};
        use std::time::Instant;

        let mut last_esc: Option<Instant> = None;
        let double_tap_ms = crate::constants::DOUBLE_TAP_ESC_MS;

        loop {
            if event::poll(Duration::from_millis(50)).unwrap_or(false) {
                match event::read() {
                Ok(Event::Resize(cols, rows)) => {
                    if key_tx.blocking_send(TakeoverInput::Resize(cols, rows)).is_err() {
                        break;
                    }
                }
                Ok(Event::Key(key)) => {
                    // Double-tap Esc = exit takeover.
                    if key.code == KeyCode::Esc {
                        if let Some(prev) = last_esc {
                            if prev.elapsed().as_millis() < double_tap_ms {
                                break;
                            }
                        }
                        last_esc = Some(Instant::now());
                        // Still send the first Esc to the PTY.
                        if key_tx.blocking_send(TakeoverInput::Key(vec![0x1b])).is_err() {
                            break;
                        }
                        continue;
                    }
                    last_esc = None;

                    // Convert key event to bytes for the PTY.
                    let bytes = match key.code {
                        KeyCode::Char(c) => {
                            if key.modifiers.contains(KeyModifiers::CONTROL) {
                                // Ctrl+letter → ASCII control code.
                                let ctrl = (c as u8).wrapping_sub(b'a').wrapping_add(1);
                                vec![ctrl]
                            } else {
                                let mut buf = [0u8; 4];
                                let s = c.encode_utf8(&mut buf);
                                s.as_bytes().to_vec()
                            }
                        }
                        KeyCode::Enter => vec![b'\r'],
                        KeyCode::Backspace => vec![0x7f],
                        KeyCode::Tab => vec![b'\t'],
                        KeyCode::Up => b"\x1b[A".to_vec(),
                        KeyCode::Down => b"\x1b[B".to_vec(),
                        KeyCode::Right => b"\x1b[C".to_vec(),
                        KeyCode::Left => b"\x1b[D".to_vec(),
                        KeyCode::Home => b"\x1b[H".to_vec(),
                        KeyCode::End => b"\x1b[F".to_vec(),
                        KeyCode::Delete => b"\x1b[3~".to_vec(),
                        _ => continue,
                    };

                    if key_tx.blocking_send(TakeoverInput::Key(bytes)).is_err() {
                        break;
                    }
                }
                _ => {}
                }
            }
        }
    });

    // Main takeover loop: PTY I/O + relay + watcher + heartbeat.
    let mut heartbeat = tokio::time::interval(Duration::from_secs(crate::constants::HEARTBEAT_INTERVAL_SECS));
    loop {
        tokio::select! {
            // ── PTY output → host stdout + scrollback + relay ──
            output = output_rx.recv() => {
                let Some(bytes) = output else { break; };
                let len = bytes.len() as u64;
                ctx.scrollback.push(bytes.clone());
                out.write_all(&bytes).await?;
                out.flush().await?;
                if ctx.chan.is_confirmed() {
                    let _ = ctx.send_secure(&SecureMessage::PtyOutput(bytes));
                    ctx.tui_state.bytes_sent += len;
                }
            }
            // ── Keyboard + resize → PTY ──
            input = key_rx.recv() => {
                match input {
                    Some(TakeoverInput::Key(bytes)) => {
                        pty.send_input(bytes)?;
                    }
                    Some(TakeoverInput::Resize(cols, rows)) => {
                        let _ = pty.resize(cols, rows);
                    }
                    None => break, // Double-tap Esc
                }
            }
            // ── JSONL watcher: agent events → relay ──
            agent_event = async { event_rx.as_mut().unwrap().recv().await }, if event_rx.is_some() => {
                let Some(evt) = agent_event else { continue; };
                let _ = ctx.send_secure(&SecureMessage::AgentEvent(evt));
            }
            // ── JSONL watcher: log (ignored during takeover, no TUI) ──
            _log = async { watcher_log_rx.as_mut().unwrap().recv().await }, if watcher_log_rx.is_some() => {}
            // ── Relay inbound (phone messages) ──
            inbound = relay.recv() => {
                if let Some(RelayMessage::Route(route)) = inbound {
                    if route.session_id == ctx.identity.session_id {
                        let _ = handle_route(route, pty, ctx);
                    }
                }
            }
            // ── Heartbeat ──
            _ = heartbeat.tick() => {
                let _ = ctx.relay_tx.try_send(RelayMessage::Ping(now_millis()));
            }
        }
    }

    // Clean up: abort stdin task, restore terminal, notify phone.
    stdin_task.abort();
    disable_raw_mode()?;



    Ok(())
}

async fn connect_host(
    relay_url: &str,
    session_id: &str,
    pairing_code: &str,
    resume_token: Option<String>,
    api_key: Option<&str>,
) -> anyhow::Result<(RelayConnection, protocol::protocol::RegisterResponse)> {
    RelayConnection::connect(
        relay_url,
        RegisterRequest {
            protocol_version: PROTOCOL_VERSION,
            protocol_version_min: Some(PROTOCOL_VERSION_MIN),
            client_version: crate::constants::CLIENT_VERSION.to_string(),
            session_id: session_id.to_string(),
            pairing_code: pairing_code.to_string(),
            role: PeerRole::Host,
            resume_token,
        },
        api_key,
    )
    .await
}

async fn reconnect_host(
    relay_url: &str,
    session_id: &str,
    pairing_code: &str,
    resume_token: &str,
    api_key: Option<&str>,
) -> anyhow::Result<(RelayConnection, protocol::protocol::RegisterResponse)> {
    reconnect_with_backoff("host", || {
        connect_host(
            relay_url,
            session_id,
            pairing_code,
            Some(resume_token.to_string()),
            api_key,
        )
    })
    .await
}

/// Maximum scrollback size in bytes (128KB).
const SCROLLBACK_CAPACITY: usize = 128 * 1024;

// ---------------------------------------------------------------------------
// Bounded byte buffer: a VecDeque<Vec<u8>> with a byte-capacity limit.
// Used for both scrollback (reconnect replay) and the handshake-window
// output backlog. Oldest chunks are evicted when the cap is exceeded.
// ---------------------------------------------------------------------------

struct BoundedByteBuffer {
    chunks: VecDeque<Vec<u8>>,
    total_bytes: usize,
    capacity: usize,
}

impl BoundedByteBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            total_bytes: 0,
            capacity,
        }
    }

    /// Append a chunk, evicting oldest chunks if over capacity.
    fn push(&mut self, bytes: Vec<u8>) {
        self.total_bytes += bytes.len();
        self.chunks.push_back(bytes);
        while self.total_bytes > self.capacity {
            if let Some(front) = self.chunks.pop_front() {
                self.total_bytes -= front.len();
            } else {
                break;
            }
        }
    }

    /// Drain all buffered chunks, leaving the buffer empty.
    fn drain(&mut self) -> Vec<Vec<u8>> {
        self.total_bytes = 0;
        self.chunks.drain(..).collect()
    }
}

fn initial_size() -> (u16, u16) {
    let (default_cols, default_rows) = crate::constants::DEFAULT_TERMINAL_SIZE;
    terminal::size()
        .map(|(c, r)| (r, c))
        .unwrap_or((default_rows, default_cols))
}

/// Returns the current time as an RFC 3339 UTC timestamp (e.g. "2026-03-17T16:30:00Z").
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs();
    unix_secs_to_rfc3339(secs)
}

/// Format unix seconds as an RFC 3339 UTC timestamp.
///
/// Uses Howard Hinnant's civil calendar algorithm (public domain) to avoid
/// pulling in a datetime crate.
fn unix_secs_to_rfc3339(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch() {
        assert_eq!(unix_secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamp_2024() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(unix_secs_to_rfc3339(1704067200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamp_2000() {
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(unix_secs_to_rfc3339(946684800), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn end_of_day() {
        // 1970-01-01T23:59:59Z = 86399
        assert_eq!(unix_secs_to_rfc3339(86399), "1970-01-01T23:59:59Z");
    }

    #[test]
    fn leap_year_feb_29() {
        // 2024-02-29T12:00:00Z = 1709208000
        assert_eq!(unix_secs_to_rfc3339(1709208000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn year_2038() {
        // 2038-01-19T03:14:07Z = 2147483647 (max i32, the Y2K38 problem)
        assert_eq!(unix_secs_to_rfc3339(2147483647), "2038-01-19T03:14:07Z");
    }

    // ── BoundedByteBuffer ────────────────────────────────────────────

    #[test]
    fn buffer_new_is_empty() {
        let mut buf = BoundedByteBuffer::new(1024);
        assert_eq!(buf.total_bytes, 0);
        assert!(buf.drain().is_empty());
    }

    #[test]
    fn buffer_push_within_capacity() {
        let mut buf = BoundedByteBuffer::new(1024);
        buf.push(vec![1, 2, 3]);
        buf.push(vec![4, 5]);
        buf.push(vec![6]);
        assert_eq!(buf.total_bytes, 6);
        let chunks = buf.drain();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], vec![1, 2, 3]);
        assert_eq!(chunks[1], vec![4, 5]);
        assert_eq!(chunks[2], vec![6]);
    }

    #[test]
    fn buffer_push_evicts_oldest() {
        let mut buf = BoundedByteBuffer::new(10);
        buf.push(vec![0; 6]); // 6 bytes
        buf.push(vec![1; 6]); // total 12, over cap → evict first
        assert_eq!(buf.total_bytes, 6);
        let chunks = buf.drain();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], vec![1; 6]);
    }

    #[test]
    fn buffer_exact_capacity_no_eviction() {
        let mut buf = BoundedByteBuffer::new(10);
        buf.push(vec![0; 5]);
        buf.push(vec![1; 5]);
        assert_eq!(buf.total_bytes, 10);
        assert_eq!(buf.drain().len(), 2);
    }

    #[test]
    fn buffer_drain_resets() {
        let mut buf = BoundedByteBuffer::new(1024);
        buf.push(vec![1, 2, 3]);
        buf.drain();
        assert_eq!(buf.total_bytes, 0);
        assert!(buf.drain().is_empty());
    }

    #[test]
    fn buffer_push_after_drain() {
        let mut buf = BoundedByteBuffer::new(1024);
        buf.push(vec![1]);
        buf.drain();
        buf.push(vec![2, 3]);
        assert_eq!(buf.total_bytes, 2);
        let chunks = buf.drain();
        assert_eq!(chunks, vec![vec![2, 3]]);
    }

    #[test]
    fn buffer_zero_capacity_evicts_everything() {
        let mut buf = BoundedByteBuffer::new(0);
        buf.push(vec![1, 2, 3]);
        assert_eq!(buf.total_bytes, 0);
        assert!(buf.drain().is_empty());
    }

    #[test]
    fn buffer_multiple_evictions() {
        let mut buf = BoundedByteBuffer::new(10);
        buf.push(vec![0; 3]); // 3
        buf.push(vec![1; 3]); // 6
        buf.push(vec![2; 3]); // 9
        buf.push(vec![3; 5]); // 14 → evict [0;3],[1;3] → 8
        assert_eq!(buf.total_bytes, 8);
        let chunks = buf.drain();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], vec![2; 3]);
        assert_eq!(chunks[1], vec![3; 5]);
    }
}
