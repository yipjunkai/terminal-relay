use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use clap::Args;
use crossterm::terminal;
use qrcode::QrCode;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, warn};

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
    ai_tools::resolve_tool,
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
    /// AI tool to run. Auto-detects if not specified. Accepts known tool names
    /// (claude, opencode, copilot, gemini, aider) or any command on PATH.
    #[arg(long)]
    pub tool: Option<String>,
    /// Extra arguments to pass to the AI tool.
    #[arg(long = "tool-arg")]
    pub tool_args: Vec<String>,
    #[arg(long)]
    pub rows: Option<u16>,
    #[arg(long)]
    pub cols: Option<u16>,
    #[arg(long)]
    pub no_qr: bool,
}

pub async fn run_host_sessions(args: HostArgs, store: SessionStore) -> anyhow::Result<()> {
    let tool = resolve_tool(args.tool.as_deref(), &args.tool_args)?;
    let (rows, cols) = initial_size(args.rows, args.cols);

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
        no_qr: args.no_qr,
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
    no_qr: bool,
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
        no_qr,
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

    let pairing_uri = build_pairing_uri(&PairingUri {
        relay_url: relay_url.clone(),
        session_id: session_id.clone(),
        pairing_code: pairing_code.clone(),
        expected_fingerprint: Some(local_fingerprint.clone()),
        api_key: api_key.clone(),
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

    println!("\nSession {session_id} started for tool '{tool_name}'");
    println!("Pairing code: {pairing_code}");
    println!("Fingerprint: {local_fingerprint}");
    println!("Pairing URI: {pairing_uri}");
    if !no_qr {
        print_qr(&pairing_uri)?;
    }

    let identity = SessionIdentity {
        session_id,
        tool_name,
        local_secret: local_key.secret,
        local_public: local_key.public,
    };

    let (mut pty, streams) = PtySession::spawn(&command, &args, rows, cols)?;
    let mut output_rx = streams.output_rx;
    let mut exit_rx = streams.exit_rx;
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
    loop {
        tokio::select! {
            output = output_rx.recv() => {
                let Some(bytes) = output else { continue; };
                // Always capture output for reconnecting clients.
                scrollback.push(bytes.clone());
                if chan.confirmed {
                    if let Some(channel) = chan.channel.as_mut() {
                        let sealed = channel.seal(&SecureMessage::PtyOutput(bytes))?;
                        let frame = PeerFrame::Secure(sealed);
                        if let Err(err) = send_peer_frame(&relay_tx, &identity.session_id, frame) {
                            warn!(error = %err, "failed sending PTY output");
                        }
                    }
                } else {
                    queue_backlog(&mut output_backlog, bytes);
                }
            }
            inbound = relay.recv() => {
                match inbound {
                    Some(RelayMessage::Route(route)) => {
                        if route.session_id != identity.session_id {
                            continue;
                        }
                        handle_route(
                            route,
                            &identity,
                            &mut chan,
                            &mut pty,
                            &mut output_backlog,
                            &mut scrollback,
                            &relay_tx,
                        )?;
                    }
                    Some(RelayMessage::PeerStatus(status)) => {
                        if status.role == PeerRole::Client {
                            peer_online = status.online;
                            if peer_online {
                                send_handshake(
                                    &identity.session_id,
                                    &relay_tx,
                                    &identity.local_public,
                                    &local_fingerprint,
                                    Some(identity.tool_name.clone()),
                                )?;
                            } else {
                                info!(session_id = %identity.session_id, "client disconnected, awaiting reconnect");
                                chan.reset();
                            }
                        }
                    }
                    Some(RelayMessage::Error(err)) => {
                        warn!(session_id = %identity.session_id, message = %err.message, "relay reported error");
                    }
                    Some(RelayMessage::Pong(_)) | Some(RelayMessage::Ping(_)) | Some(RelayMessage::Registered(_)) | Some(RelayMessage::Register(_)) => {}
                    None => {
                        warn!(session_id = %identity.session_id, "relay disconnected, attempting recovery");
                        let (new_relay, new_registered) = reconnect_host(&relay_url, &identity.session_id, &pairing_code, &resume_token, api_key.as_deref()).await?;
                        relay = new_relay;
                        relay_tx = relay.sender();
                        resume_token = new_registered.resume_token.clone();
                        chan.reset();
                        peer_online = new_registered.peer_online;
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
            exit_code = &mut exit_rx => {
                let code = exit_code.unwrap_or(1);
                info!(session_id = %identity.session_id, code = code, "PTY process exited");
                // Notify the attached client that the session has ended.
                if chan.confirmed
                    && let Some(channel) = chan.channel.as_mut()
                {
                    let msg = SecureMessage::SessionEnded { exit_code: code };
                    if let Ok(sealed) = channel.seal(&msg) {
                        let _ = send_peer_frame(&relay_tx, &identity.session_id, PeerFrame::Secure(sealed));
                    }
                }
                break;
            }
            _ = &mut shutdown => {
                info!(session_id = %identity.session_id, "received shutdown signal, stopping host session");
                break;
            }
        }
    }

    Ok(())
}

fn handle_route(
    route: RelayRoute,
    id: &SessionIdentity,
    chan: &mut ChannelState,
    pty: &mut PtySession,
    output_backlog: &mut VecDeque<Vec<u8>>,
    scrollback: &mut ScrollbackBuffer,
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
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

            info!(session_id = %id.session_id, "handshake confirmed, channel trusted");
            chan.confirmed = true;
            chan.expected_peer_mac = None;

            // Replay scrollback first so reconnecting clients catch up on
            // output that was produced while they were disconnected.
            let replay = scrollback.drain();
            if !replay.is_empty() {
                info!(
                    session_id = %id.session_id,
                    chunks = replay.len(),
                    bytes = replay.iter().map(Vec::len).sum::<usize>(),
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
                    // Convert voice command to PTY input.
                    // For now, send the raw transcript. Future: interpret intent.
                    pty.send_input(action.transcript.into_bytes())?;
                }
                SecureMessage::Heartbeat
                | SecureMessage::VersionNotice { .. }
                | SecureMessage::Notification(_)
                | SecureMessage::PtyOutput(_)
                | SecureMessage::SessionEnded { .. }
                | SecureMessage::Clipboard { .. }
                | SecureMessage::ReadOnly { .. }
                | SecureMessage::Unknown(_) => {}
            }
        }
        PeerFrame::KeepAlive => {}
    }
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

fn initial_size(rows: Option<u16>, cols: Option<u16>) -> (u16, u16) {
    if let (Some(r), Some(c)) = (rows, cols) {
        return (r, c);
    }
    terminal::size()
        .map(|(c, r)| (rows.unwrap_or(r), cols.unwrap_or(c)))
        .unwrap_or((40, 120))
}

fn print_qr(data: &str) -> anyhow::Result<()> {
    let code = QrCode::new(data.as_bytes()).context("failed generating QR code")?;
    let width = code.width();
    let modules: Vec<bool> = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();

    // Use Unicode half-block rendering: each character encodes two vertical rows.
    // ▀ = top dark, bottom light    █ = both dark
    // ▄ = top light, bottom dark    (space) = both light
    // This halves the QR code height compared to one-char-per-module rendering.
    let get = |row: i32, col: i32| -> bool {
        if row < 0 || col < 0 || row >= width as i32 || col >= width as i32 {
            false
        } else {
            modules[row as usize * width + col as usize]
        }
    };

    let margin = 1i32;
    let mut output = String::new();
    output.push('\n');
    let mut row = -margin;
    while row < width as i32 + margin {
        for col in -margin..width as i32 + margin {
            let top = get(row, col);
            let bottom = get(row + 1, col);
            output.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        output.push('\n');
        row += 2;
    }
    println!("{output}");
    Ok(())
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
