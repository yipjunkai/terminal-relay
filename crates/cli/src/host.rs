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
    crypto::{
        HANDSHAKE_MAX_AGE_MS, SecureChannel, compute_handshake_mac, derive_session_keys,
        fingerprint, generate_key_pair,
    },
    pairing::{PairingUri, build_pairing_uri, new_pairing_code, new_session_id},
    protocol::{
        HandshakeConfirm, PROTOCOL_VERSION, PROTOCOL_VERSION_MIN, PeerFrame, PeerRole,
        RegisterRequest, RelayMessage, RelayRoute, SecureMessage, decode_peer_frame,
    },
};

use crate::common::{ChannelState, now_millis, send_handshake, send_peer_frame, shutdown_signal};

/// Identity and key material for the local side of a session (immutable after creation).
struct SessionIdentity {
    session_id: String,
    tool_name: String,
    local_secret: [u8; 32],
    local_public: [u8; 32],
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
    ///   terminal-relay start claude
    ///   terminal-relay start aider --model sonnet
    ///   terminal-relay start my-custom-tool --flag
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
            eprintln!("Run `terminal-relay auth` to authenticate.\n");
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
    let mut relay_tx = relay.sender();
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

    let mut chan = ChannelState::new();
    let mut output_backlog: VecDeque<Vec<u8>> = VecDeque::new();
    let mut scrollback = ScrollbackBuffer::new();
    let mut peer_online = registered.peer_online;

    if peer_online {
        send_handshake(
            &identity.session_id,
            &relay_tx,
            &identity.local_public,
            &local_fingerprint,
            Some(identity.tool_name.clone()),
        )?;
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
    let mut redraw = tokio::time::interval(Duration::from_millis(250));

    let result: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                // ── PTY output ──
                output = output_rx.recv() => {
                    let Some(bytes) = output else { continue; };
                    let len = bytes.len() as u64;
                    scrollback.push(bytes.clone());
                    if chan.confirmed {
                        if let Some(channel) = chan.channel.as_mut() {
                            let sealed = channel.seal(&SecureMessage::PtyOutput(bytes))?;
                            let frame = PeerFrame::Secure(sealed);
                            if let Err(err) = send_peer_frame(&relay_tx, &identity.session_id, frame) {
                                warn!(error = %err, "failed sending PTY output");
                            }
                            tui_state.bytes_sent += len;
                        }
                    } else {
                        queue_backlog(&mut output_backlog, bytes);
                    }
                }
                // ── JSONL watcher: agent events (for structured-capable tools) ──
                agent_event = async { event_rx.as_mut().unwrap().recv().await }, if event_rx.is_some() => {
                    let Some(evt) = agent_event else { continue; };
                    if chan.confirmed {
                        if let Some(channel) = chan.channel.as_mut() {
                            let sealed = channel.seal(&SecureMessage::AgentEvent(evt))?;
                            let frame = PeerFrame::Secure(sealed);
                            if let Err(err) = send_peer_frame(&relay_tx, &identity.session_id, frame) {
                                warn!(error = %err, "failed sending agent event");
                            }
                        }
                    }
                }
                // ── JSONL watcher: log messages → TUI ──
                log_msg = async { watcher_log_rx.as_mut().unwrap().recv().await }, if watcher_log_rx.is_some() => {
                    if let Some(msg) = log_msg {
                        tui_state.push_log(LogLevel::Info, msg);
                    }
                }
                // ── Relay inbound messages ──
                inbound = relay.recv() => {
                    match inbound {
                        Some(RelayMessage::Route(route)) => {
                            if route.session_id != identity.session_id {
                                continue;
                            }
                            let payload_len = route.payload.len() as u64;
                            handle_route(
                                route,
                                &identity,
                                &pty,
                                &mut chan,
                                &mut output_backlog,
                                &mut scrollback,
                                &relay_tx,
                                &mut tui_state,
                            )?;
                            tui_state.bytes_received += payload_len;
                        }
                        Some(RelayMessage::PeerStatus(status)) => {
                            if status.role == PeerRole::Client {
                                peer_online = status.online;
                                if peer_online {
                                    tui_state.status = PeerStatus::PeerConnected;
                                    tui_state.push_log(LogLevel::Info, "Client connected");
                                    send_handshake(
                                        &identity.session_id,
                                        &relay_tx,
                                        &identity.local_public,
                                        &local_fingerprint,
                                        Some(identity.tool_name.clone()),
                                    )?;
                                    tui_state.status = PeerStatus::Handshaking;
                                } else {
                                    tui_state.status = PeerStatus::Disconnected;
                                    tui_state.push_log(LogLevel::Warning, "Client disconnected");
                                    info!(session_id = %identity.session_id, "client disconnected, awaiting reconnect");
                                    chan.reset();
                                    tui_state.status = PeerStatus::WaitingForPeer;
                                }
                            }
                        }
                        Some(RelayMessage::Error(err)) => {
                            tui_state.push_log(LogLevel::Error, format!("Relay error: {}", err.message));
                            warn!(session_id = %identity.session_id, message = %err.message, "relay reported error");
                        }
                        Some(RelayMessage::Pong(_)) | Some(RelayMessage::Ping(_)) | Some(RelayMessage::Registered(_)) | Some(RelayMessage::Register(_)) => {}
                        None => {
                            tui_state.status = PeerStatus::Disconnected;
                            tui_state.push_log(LogLevel::Warning, "Relay disconnected, reconnecting...");
                            warn!(session_id = %identity.session_id, "relay disconnected, attempting recovery");
                            let (new_relay, new_registered) = reconnect_host(&relay_url, &identity.session_id, &pairing_code, &resume_token, api_key.as_deref()).await?;
                            relay = new_relay;
                            relay_tx = relay.sender();
                            resume_token = new_registered.resume_token.clone();
                            chan.reset();
                            peer_online = new_registered.peer_online;
                            tui_state.status = PeerStatus::WaitingForPeer;
                            tui_state.push_log(LogLevel::Info, "Reconnected to relay");
                            if peer_online {
                                send_handshake(
                                    &identity.session_id,
                                    &relay_tx,
                                    &identity.local_public,
                                    &local_fingerprint,
                                    Some(identity.tool_name.clone()),
                                )?;
                            }
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    let _ = relay_tx.send(RelayMessage::Ping(now_millis()));
                }
                _ = redraw.tick() => {
                    match tui_handle.poll_action(Duration::ZERO)? {
                        TuiAction::Quit => {
                            tui_state.push_log(LogLevel::Info, "Shutting down...");
                            tui_handle.draw(&tui_state)?;
                            break;
                        }
                        TuiAction::Takeover => {
                            tui_state.push_log(LogLevel::Info, "Takeover mode — double-tap Esc to return");
                            tui_handle.draw(&tui_state)?;

                            // Suspend TUI and enter takeover loop.
                            tui_handle.suspend()?;
                            run_takeover(&pty, &mut output_rx, &mut event_rx, &mut watcher_log_rx, &mut relay, &relay_tx, &mut chan, &mut output_backlog, &mut scrollback, &identity, &mut tui_state).await?;
                            tui_handle.resume()?;
                            tui_state.push_log(LogLevel::Info, "Returned to dashboard");
                        }
                        TuiAction::None => {}
                    }
                    tui_handle.draw(&tui_state)?;
                }
                exit_code = &mut exit_rx => {
                    let code = exit_code.unwrap_or(1);
                    tui_state.push_log(LogLevel::Info, format!("Process exited (code {code})"));
                    info!(session_id = %identity.session_id, code = code, "PTY process exited");
                    if chan.confirmed
                        && let Some(channel) = chan.channel.as_mut()
                    {
                        let msg = SecureMessage::SessionEnded { exit_code: code };
                        if let Ok(sealed) = channel.seal(&msg) {
                            let _ = send_peer_frame(&relay_tx, &identity.session_id, PeerFrame::Secure(sealed));
                        }
                    }
                    tui_handle.draw(&tui_state)?;
                    sleep(Duration::from_secs(1)).await;
                    break;
                }
                _ = &mut shutdown => {
                    tui_state.push_log(LogLevel::Info, "Received shutdown signal");
                    info!(session_id = %identity.session_id, "received shutdown signal, stopping host session");
                    tui_handle.draw(&tui_state)?;
                    break;
                }
            }
        }
        Ok(())
    }
    .await;

    // Ensure terminal is restored even on error.
    tui_handle.restore()?;
    result
}

fn handle_route(
    route: RelayRoute,
    id: &SessionIdentity,
    pty: &PtySession,
    chan: &mut ChannelState,
    output_backlog: &mut VecDeque<Vec<u8>>,
    scrollback: &mut ScrollbackBuffer,
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
    tui_state: &mut TuiState,
) -> anyhow::Result<()> {
    let frame = decode_peer_frame(&route.payload)?;
    match frame {
        PeerFrame::Handshake(handshake) => {
            // Ignore duplicate handshakes if we already have a channel
            // (in-progress or confirmed). This handles the dual-handshake
            // race where both sides send Handshake simultaneously — the
            // first one processed wins, and the second is safely dropped.
            if chan.channel.is_some() {
                info!(
                    session_id = %id.session_id,
                    confirmed = chan.confirmed,
                    "ignoring duplicate handshake, channel already established"
                );
                return Ok(());
            }

            // Validate handshake timestamp to reject stale/replayed messages.
            let now = now_millis();
            let age = now.saturating_sub(handshake.timestamp_ms);
            if age > HANDSHAKE_MAX_AGE_MS {
                warn!(
                    session_id = %id.session_id,
                    age_ms = age,
                    "rejecting stale handshake"
                );
                return Ok(());
            }

            tui_state.push_log(LogLevel::Info, format!("Peer fingerprint: {}", handshake.fingerprint));
            info!(
                session_id = %id.session_id,
                peer_fingerprint = %handshake.fingerprint,
                "peer handshake received"
            );

            let keys = derive_session_keys(
                PeerRole::Host,
                &id.session_id,
                id.local_secret,
                handshake.public_key,
            )?;

            // Compute our outbound confirmation MAC and the expected peer MAC.
            let our_mac = compute_handshake_mac(
                &keys.tx,
                &id.local_public,
                &handshake.public_key,
                &id.session_id,
            );
            let peer_mac = compute_handshake_mac(
                &keys.rx,
                &handshake.public_key,
                &id.local_public,
                &id.session_id,
            );

            chan.channel = Some(SecureChannel::new(keys));
            chan.confirmed = false;
            chan.expected_peer_mac = Some(peer_mac);

            send_peer_frame(
                relay_tx,
                &id.session_id,
                PeerFrame::HandshakeConfirm(HandshakeConfirm { mac: our_mac }),
            )?;
        }
        PeerFrame::HandshakeConfirm(confirm) => {
            let Some(expected) = &chan.expected_peer_mac else {
                warn!(session_id = %id.session_id, "received HandshakeConfirm without pending handshake");
                return Ok(());
            };

            if confirm.mac != *expected {
                warn!(session_id = %id.session_id, "handshake confirmation MAC mismatch — tearing down channel");
                chan.reset();
                return Ok(());
            }

            tui_state.status = PeerStatus::Secure;
            tui_state.push_log(LogLevel::Success, "E2E encryption established");
            info!(session_id = %id.session_id, "handshake confirmed, channel trusted");
            chan.confirmed = true;
            chan.expected_peer_mac = None;

            // Replay scrollback first so reconnecting clients catch up on
            // output that was produced while they were disconnected.
            let replay = scrollback.drain();
            if !replay.is_empty() {
                let total_bytes: usize = replay.iter().map(Vec::len).sum();
                tui_state.push_log(
                    LogLevel::Info,
                    format!("Sending scrollback ({:.1} KB)", total_bytes as f64 / 1024.0),
                );
                info!(
                    session_id = %id.session_id,
                    chunks = replay.len(),
                    bytes = total_bytes,
                    "replaying scrollback"
                );
                for bytes in replay {
                    if let Some(ch) = chan.channel.as_mut() {
                        let sealed = ch.seal(&SecureMessage::PtyOutput(bytes))?;
                        send_peer_frame(relay_tx, &id.session_id, PeerFrame::Secure(sealed))?;
                    }
                }
            }

            // Then drain the handshake-window backlog (output produced
            // between handshake start and confirm).
            while let Some(bytes) = output_backlog.pop_front() {
                if let Some(ch) = chan.channel.as_mut() {
                    let sealed = ch.seal(&SecureMessage::PtyOutput(bytes))?;
                    send_peer_frame(relay_tx, &id.session_id, PeerFrame::Secure(sealed))?;
                }
            }

            let notice = SecureMessage::Notification(protocol::protocol::PushNotification {
                title: format!("Connected to {}", id.tool_name),
                body: "Session encryption established".to_string(),
            });
            if let Some(ch) = chan.channel.as_mut() {
                let sealed = ch.seal(&notice)?;
                send_peer_frame(relay_tx, &id.session_id, PeerFrame::Secure(sealed))?;
            }

        }
        PeerFrame::Secure(sealed) => {
            if !chan.confirmed {
                return Ok(());
            }
            let Some(channel) = chan.channel.as_mut() else {
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
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
    chan: &mut ChannelState,
    output_backlog: &mut VecDeque<Vec<u8>>,
    scrollback: &mut ScrollbackBuffer,
    identity: &SessionIdentity,
    tui_state: &mut TuiState,
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
        std::thread::sleep(Duration::from_millis(50));
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
        const DOUBLE_TAP_MS: u128 = 300;

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
                            if prev.elapsed().as_millis() < DOUBLE_TAP_MS {
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
    let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            // ── PTY output → host stdout + scrollback + relay ──
            output = output_rx.recv() => {
                let Some(bytes) = output else { break; };
                let len = bytes.len() as u64;
                scrollback.push(bytes.clone());
                out.write_all(&bytes).await?;
                out.flush().await?;
                if chan.confirmed {
                    if let Some(channel) = chan.channel.as_mut() {
                        if let Ok(sealed) = channel.seal(&SecureMessage::PtyOutput(bytes)) {
                            let _ = send_peer_frame(relay_tx, &identity.session_id, PeerFrame::Secure(sealed));
                        }
                        tui_state.bytes_sent += len;
                    }
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
                if chan.confirmed {
                    if let Some(channel) = chan.channel.as_mut() {
                        if let Ok(sealed) = channel.seal(&SecureMessage::AgentEvent(evt)) {
                            let _ = send_peer_frame(relay_tx, &identity.session_id, PeerFrame::Secure(sealed));
                        }
                    }
                }
            }
            // ── JSONL watcher: log (ignored during takeover, no TUI) ──
            _log = async { watcher_log_rx.as_mut().unwrap().recv().await }, if watcher_log_rx.is_some() => {}
            // ── Relay inbound (phone messages) ──
            inbound = relay.recv() => {
                if let Some(RelayMessage::Route(route)) = inbound {
                    if route.session_id == identity.session_id {
                        let _ = handle_route(
                            route,
                            identity,
                            pty,
                            chan,
                            output_backlog,
                            scrollback,
                            relay_tx,
                            tui_state,
                        );
                    }
                }
            }
            // ── Heartbeat ──
            _ = heartbeat.tick() => {
                let _ = relay_tx.send(RelayMessage::Ping(now_millis()));
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

/// Maximum number of reconnect attempts before giving up.
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

async fn reconnect_host(
    relay_url: &str,
    session_id: &str,
    pairing_code: &str,
    resume_token: &str,
    api_key: Option<&str>,
) -> anyhow::Result<(RelayConnection, protocol::protocol::RegisterResponse)> {
    let mut delay = Duration::from_secs(1);
    for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
        tokio::select! {
            result = connect_host(
                relay_url,
                session_id,
                pairing_code,
                Some(resume_token.to_string()),
                api_key,
            ) => {
                match result {
                    Ok(connection) => return Ok(connection),
                    Err(err) => {
                        warn!(
                            error = %err,
                            attempt = attempt,
                            max = MAX_RECONNECT_ATTEMPTS,
                            "host reconnect attempt failed"
                        );
                    }
                }
            }
            _ = shutdown_signal() => {
                return Err(anyhow::anyhow!("reconnect interrupted by shutdown signal"));
            }
        }
        if attempt < MAX_RECONNECT_ATTEMPTS {
            sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(30));
        }
    }
    Err(anyhow::anyhow!(
        "failed to reconnect after {MAX_RECONNECT_ATTEMPTS} attempts"
    ))
}

fn queue_backlog(queue: &mut VecDeque<Vec<u8>>, bytes: Vec<u8>) {
    queue.push_back(bytes);
    let mut total_bytes: usize = queue.iter().map(Vec::len).sum();
    while total_bytes > 1_048_576 {
        if let Some(front) = queue.pop_front() {
            total_bytes = total_bytes.saturating_sub(front.len());
        } else {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Scrollback buffer: captures recent PTY output so reconnecting clients
// can catch up without a full session replay.
// ---------------------------------------------------------------------------

/// Maximum scrollback size in bytes (128KB).
const SCROLLBACK_CAPACITY: usize = 128 * 1024;

struct ScrollbackBuffer {
    chunks: VecDeque<Vec<u8>>,
    total_bytes: usize,
}

impl ScrollbackBuffer {
    fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            total_bytes: 0,
        }
    }

    /// Append a chunk of PTY output, evicting oldest chunks if over capacity.
    fn push(&mut self, bytes: Vec<u8>) {
        self.total_bytes += bytes.len();
        self.chunks.push_back(bytes);
        while self.total_bytes > SCROLLBACK_CAPACITY {
            if let Some(front) = self.chunks.pop_front() {
                self.total_bytes -= front.len();
            } else {
                break;
            }
        }
    }

    /// Drain all buffered chunks for replay, leaving the buffer empty.
    fn drain(&mut self) -> Vec<Vec<u8>> {
        self.total_bytes = 0;
        self.chunks.drain(..).collect()
    }


}

fn initial_size() -> (u16, u16) {
    terminal::size()
        .map(|(c, r)| (r, c))
        .unwrap_or((40, 120))
}

/// Returns the current time as an RFC 3339 UTC timestamp (e.g. "2026-03-17T16:30:00Z").
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();

    // Manual RFC 3339 formatting to avoid pulling in a datetime crate.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch to y/m/d using a civil calendar algorithm.
    // Based on Howard Hinnant's algorithm (public domain).
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
