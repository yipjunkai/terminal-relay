use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use clap::Args;
use crossterm::terminal;
use qrcode::QrCode;
use tokio::sync::mpsc;
use tokio::{task::JoinHandle, time::sleep};
use tracing::{info, warn};

use terminal_relay_core::{
    crypto::{
        HANDSHAKE_MAX_AGE_MS, SecureChannel, compute_handshake_mac, derive_session_keys,
        fingerprint, generate_key_pair,
    },
    pairing::{PairingUri, build_pairing_uri, new_pairing_code, new_session_id},
    protocol::{
        Handshake, HandshakeConfirm, PROTOCOL_VERSION, PROTOCOL_VERSION_MIN, PeerFrame, PeerRole,
        RegisterRequest, RelayMessage, RelayRoute, SecureMessage, decode_peer_frame,
        encode_peer_frame,
    },
};

/// Identity and key material for the local side of a session (immutable after creation).
struct SessionIdentity {
    session_id: String,
    tool_name: String,
    local_secret: [u8; 32],
    local_public: [u8; 32],
}

/// Mutable state for the encrypted channel during a session.
struct ChannelState {
    channel: Option<SecureChannel>,
    confirmed: bool,
    expected_peer_mac: Option<[u8; 32]>,
}

impl ChannelState {
    fn new() -> Self {
        Self {
            channel: None,
            confirmed: false,
            expected_peer_mac: None,
        }
    }

    fn reset(&mut self) {
        self.channel = None;
        self.confirmed = false;
        self.expected_peer_mac = None;
    }
}

use crate::{
    ai_tools::{ToolSelector, resolve_tool},
    pty::PtySession,
    relay_client::RelayConnection,
    state::{SessionRecord, SessionStore},
};

#[derive(Debug, Clone, Args)]
pub struct HostArgs {
    #[arg(long, default_value = crate::constants::DEFAULT_RELAY_URL, env = crate::constants::RELAY_URL_ENV, hide = true)]
    pub relay_url: String,
    #[arg(long = "tool", value_enum, value_delimiter = ',')]
    pub tools: Vec<ToolSelector>,
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
    let selectors = if args.tools.is_empty() {
        vec![ToolSelector::Auto]
    } else {
        args.tools.clone()
    };

    let mut tasks: Vec<JoinHandle<anyhow::Result<()>>> = Vec::new();
    for selector in selectors {
        let tool = resolve_tool(selector, &args.tool_args)?;
        let relay_url = args.relay_url.clone();
        let no_qr = args.no_qr;
        let (rows, cols) = initial_size(args.rows, args.cols);
        let session_store = store.clone();

        tasks.push(tokio::spawn(async move {
            run_single_host_session(HostSessionParams {
                tool_name: tool.name,
                command: tool.command,
                args: tool.args,
                relay_url,
                rows,
                cols,
                no_qr,
                store: session_store,
            })
            .await
        }));
    }

    for task in tasks {
        task.await??;
    }
    Ok(())
}

struct HostSessionParams {
    tool_name: String,
    command: String,
    args: Vec<String>,
    relay_url: String,
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
        rows,
        cols,
        no_qr,
        store,
    } = params;

    let session_id = new_session_id();
    let pairing_code = new_pairing_code();
    let local_key = generate_key_pair();
    let local_fingerprint = fingerprint(&local_key.public);

    let (mut relay, registered) =
        connect_host(&relay_url, &session_id, &pairing_code, None).await?;
    let mut relay_tx = relay.sender();
    let mut resume_token = registered.resume_token.clone();

    let pairing_uri = build_pairing_uri(&PairingUri {
        relay_url: relay_url.clone(),
        session_id: session_id.clone(),
        pairing_code: pairing_code.clone(),
        expected_fingerprint: Some(local_fingerprint.clone()),
    })?;

    let record = SessionRecord {
        session_id: session_id.clone(),
        relay_url: relay_url.clone(),
        pairing_code: pairing_code.clone(),
        resume_token: resume_token.clone(),
        tool: tool_name.clone(),
        command: command.clone(),
        command_args: args.clone(),
        created_at: chrono_ish_now(),
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
                if chan.confirmed {
                    if let Some(channel) = chan.channel.as_mut() {
                        let sealed = channel.seal(&SecureMessage::PtyOutput(bytes.clone()))?;
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
                        let (new_relay, new_registered) = reconnect_host(&relay_url, &identity.session_id, &pairing_code, &resume_token).await?;
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
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
) -> anyhow::Result<()> {
    let frame = decode_peer_frame(&route.payload)?;
    match frame {
        PeerFrame::Handshake(handshake) => {
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

            // Drain backlog now that channel is confirmed.
            while let Some(bytes) = output_backlog.pop_front() {
                if let Some(ch) = chan.channel.as_mut() {
                    let sealed = ch.seal(&SecureMessage::PtyOutput(bytes))?;
                    send_peer_frame(relay_tx, &id.session_id, PeerFrame::Secure(sealed))?;
                }
            }

            let notice =
                SecureMessage::Notification(terminal_relay_core::protocol::PushNotification {
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

fn send_handshake(
    session_id: &str,
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
    public_key: &[u8; 32],
    fingerprint: &str,
    tool_name: Option<String>,
) -> anyhow::Result<()> {
    let frame = PeerFrame::Handshake(Handshake {
        public_key: *public_key,
        fingerprint: fingerprint.to_string(),
        tool_name,
        timestamp_ms: now_millis(),
    });
    send_peer_frame(relay_tx, session_id, frame)
}

fn send_peer_frame(
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
    session_id: &str,
    frame: PeerFrame,
) -> anyhow::Result<()> {
    let payload = encode_peer_frame(&frame)?;
    relay_tx
        .send(RelayMessage::Route(RelayRoute {
            session_id: session_id.to_string(),
            payload,
        }))
        .map_err(|_| anyhow::anyhow!("relay send channel closed"))
}

async fn connect_host(
    relay_url: &str,
    session_id: &str,
    pairing_code: &str,
    resume_token: Option<String>,
) -> anyhow::Result<(
    RelayConnection,
    terminal_relay_core::protocol::RegisterResponse,
)> {
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
) -> anyhow::Result<(
    RelayConnection,
    terminal_relay_core::protocol::RegisterResponse,
)> {
    let mut delay = Duration::from_secs(1);
    for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
        tokio::select! {
            result = connect_host(
                relay_url,
                session_id,
                pairing_code,
                Some(resume_token.to_string()),
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
    let rendered = code
        .render::<char>()
        .quiet_zone(true)
        .dark_color('#')
        .light_color(' ')
        .module_dimensions(2, 1)
        .build();
    println!("\n{rendered}\n");
    Ok(())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

fn chrono_ish_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    format!("unix:{now}")
}

/// Wait for SIGINT (ctrl-c) or SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
}
