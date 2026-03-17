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
    crypto::{SecureChannel, derive_session_keys, fingerprint, generate_key_pair},
    pairing::{PairingUri, build_pairing_uri, new_pairing_code, new_session_id},
    protocol::{
        Handshake, PROTOCOL_VERSION, PeerFrame, PeerRole, RegisterRequest, RelayMessage,
        RelayRoute, SecureMessage, decode_peer_frame, encode_peer_frame,
    },
};

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
            run_single_host_session(
                tool.name,
                tool.command,
                tool.args,
                relay_url,
                rows,
                cols,
                no_qr,
                session_store,
            )
            .await
        }));
    }

    for task in tasks {
        task.await??;
    }
    Ok(())
}

async fn run_single_host_session(
    tool_name: String,
    command: String,
    args: Vec<String>,
    relay_url: String,
    rows: u16,
    cols: u16,
    no_qr: bool,
    store: SessionStore,
) -> anyhow::Result<()> {
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

    let (mut pty, streams) = PtySession::spawn(&command, &args, rows, cols)?;
    let mut output_rx = streams.output_rx;
    let mut exit_rx = streams.exit_rx;
    let mut secure_channel: Option<SecureChannel> = None;
    let mut output_backlog: VecDeque<Vec<u8>> = VecDeque::new();
    let mut peer_online = registered.peer_online;

    if peer_online {
        send_handshake(
            &session_id,
            &relay_tx,
            &local_key.public,
            &local_fingerprint,
            Some(tool_name.clone()),
        )?;
    }

    let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            output = output_rx.recv() => {
                let Some(bytes) = output else { continue; };
                if let Some(channel) = secure_channel.as_mut() {
                    let sealed = channel.seal(&SecureMessage::PtyOutput(bytes.clone()))?;
                    let frame = PeerFrame::Secure(sealed);
                    if let Err(err) = send_peer_frame(&relay_tx, &session_id, frame) {
                        warn!(error = %err, "failed sending PTY output");
                    }
                } else {
                    queue_backlog(&mut output_backlog, bytes);
                }
            }
            inbound = relay.recv() => {
                match inbound {
                    Some(RelayMessage::Route(route)) => {
                        if route.session_id != session_id {
                            continue;
                        }
                        handle_route(
                            route,
                            &session_id,
                            &tool_name,
                            local_key.secret,
                            &mut secure_channel,
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
                                    &session_id,
                                    &relay_tx,
                                    &local_key.public,
                                    &local_fingerprint,
                                    Some(tool_name.clone()),
                                )?;
                            } else {
                                secure_channel = None;
                            }
                        }
                    }
                    Some(RelayMessage::Error(err)) => {
                        warn!(session_id = %session_id, message = %err.message, "relay reported error");
                    }
                    Some(RelayMessage::Pong(_)) | Some(RelayMessage::Ping(_)) | Some(RelayMessage::Registered(_)) | Some(RelayMessage::Register(_)) => {}
                    None => {
                        warn!(session_id = %session_id, "relay disconnected, attempting recovery");
                        let (new_relay, new_registered) = reconnect_host(&relay_url, &session_id, &pairing_code, &resume_token).await?;
                        relay = new_relay;
                        relay_tx = relay.sender();
                        resume_token = new_registered.resume_token.clone();
                        secure_channel = None;
                        peer_online = new_registered.peer_online;
                        if peer_online {
                            send_handshake(
                                &session_id,
                                &relay_tx,
                                &local_key.public,
                                &local_fingerprint,
                                Some(tool_name.clone()),
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
                info!(session_id = %session_id, code = code, "PTY process exited");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                info!(session_id = %session_id, "received ctrl-c, stopping host session");
                break;
            }
        }
    }

    Ok(())
}

fn handle_route(
    route: RelayRoute,
    session_id: &str,
    tool_name: &str,
    local_secret: [u8; 32],
    secure_channel: &mut Option<SecureChannel>,
    pty: &mut PtySession,
    output_backlog: &mut VecDeque<Vec<u8>>,
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
) -> anyhow::Result<()> {
    let frame = decode_peer_frame(&route.payload)?;
    match frame {
        PeerFrame::Handshake(handshake) => {
            info!(
                session_id = %session_id,
                peer_fingerprint = %handshake.fingerprint,
                "peer handshake received"
            );

            let keys = derive_session_keys(
                PeerRole::Host,
                session_id,
                local_secret,
                handshake.public_key,
            )?;
            *secure_channel = Some(SecureChannel::new(keys));

            while let Some(bytes) = output_backlog.pop_front() {
                if let Some(channel) = secure_channel.as_mut() {
                    let sealed = channel.seal(&SecureMessage::PtyOutput(bytes))?;
                    send_peer_frame(relay_tx, session_id, PeerFrame::Secure(sealed))?;
                }
            }

            let notice =
                SecureMessage::Notification(terminal_relay_core::protocol::PushNotification {
                    title: format!("Connected to {tool_name}"),
                    body: "Session encryption established".to_string(),
                });
            if let Some(channel) = secure_channel.as_mut() {
                let sealed = channel.seal(&notice)?;
                send_peer_frame(relay_tx, session_id, PeerFrame::Secure(sealed))?;
            }
        }
        PeerFrame::Secure(sealed) => {
            let Some(channel) = secure_channel.as_mut() else {
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
                SecureMessage::Heartbeat
                | SecureMessage::VersionNotice { .. }
                | SecureMessage::Notification(_)
                | SecureMessage::PtyOutput(_) => {}
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
            client_version: crate::constants::CLIENT_VERSION.to_string(),
            session_id: session_id.to_string(),
            pairing_code: pairing_code.to_string(),
            role: PeerRole::Host,
            resume_token,
        },
    )
    .await
}

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
    loop {
        match connect_host(
            relay_url,
            session_id,
            pairing_code,
            Some(resume_token.to_string()),
        )
        .await
        {
            Ok(connection) => return Ok(connection),
            Err(err) => {
                warn!(error = %err, "host reconnect attempt failed");
                sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
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
