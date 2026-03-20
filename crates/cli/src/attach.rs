use std::time::Duration;

use anyhow::Context;
use clap::Args;
use crossterm::terminal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, warn};

use protocol::{
    crypto::{
        HANDSHAKE_MAX_AGE_MS, SecureChannel, compute_handshake_mac, derive_session_keys,
        fingerprint, generate_key_pair,
    },
    pairing::{PairingUri, parse_pairing_uri},
    protocol::{
        HandshakeConfirm, PROTOCOL_VERSION, PROTOCOL_VERSION_MIN, PeerFrame, PeerRole,
        RegisterRequest, RelayMessage, RelayRoute, SecureMessage, decode_peer_frame,
    },
};

use crate::common::{ChannelState, now_millis, send_handshake, send_peer_frame, shutdown_signal};
use crate::relay_client::RelayConnection;

#[derive(Debug, Clone, Args)]
pub struct AttachArgs {
    #[arg(long)]
    pub pairing_uri: Option<String>,
    #[arg(long, env = crate::constants::RELAY_URL_ENV, hide = true)]
    pub relay_url: Option<String>,
    #[arg(long)]
    pub session_id: Option<String>,
    #[arg(long)]
    pub pairing_code: Option<String>,
    #[arg(long)]
    pub expected_fingerprint: Option<String>,
}

pub async fn run_attach(args: AttachArgs) -> anyhow::Result<()> {
    let pairing = resolve_pairing(&args)?;
    let _raw_mode = RawModeGuard::new()?;

    let local_key = generate_key_pair();
    let local_fingerprint = fingerprint(&local_key.public);
    let (mut relay, registered) = connect_client(&pairing, None).await?;
    let mut relay_tx = relay.sender();
    let mut resume_token = registered.resume_token.clone();
    let mut chan = ChannelState::new();

    eprintln!("Connected to session {}", pairing.session_id);
    eprintln!("Local fingerprint: {}", local_fingerprint);

    if registered.peer_online {
        send_handshake(
            &pairing.session_id,
            &relay_tx,
            &local_key.public,
            &local_fingerprint,
            Some("remote-terminal".to_string()),
        )?;
    }

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(256);
    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if stdin_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let (resize_tx, mut resize_rx) = mpsc::channel::<()>(32);
    #[cfg(unix)]
    {
        let mut resize_signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .context("failed to subscribe to SIGWINCH")?;
        tokio::spawn(async move {
            while resize_signal.recv().await.is_some() {
                if resize_tx.send(()).await.is_err() {
                    break;
                }
            }
        });
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    let mut heartbeat = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            local_input = stdin_rx.recv() => {
                let Some(bytes) = local_input else { continue; };
                // Ctrl-C (0x03) detaches the attach client without stopping the host.
                if bytes == [0x03] {
                    let mut stdout = tokio::io::stdout();
                    stdout.write_all(b"\r\n[detached]\r\n").await?;
                    stdout.flush().await?;
                    break;
                }
                if chan.confirmed
                    && let Some(channel) = chan.channel.as_mut()
                {
                    let sealed = channel.seal(&SecureMessage::PtyInput(bytes))?;
                    send_peer_frame(&relay_tx, &pairing.session_id, PeerFrame::Secure(sealed))?;
                }
            }
            inbound = relay.recv() => {
                match inbound {
                    Some(RelayMessage::Route(route)) => {
                        if route.session_id != pairing.session_id {
                            continue;
                        }
                        let action = handle_route(
                            route,
                            &pairing,
                            local_key.secret,
                            &local_key.public,
                            &mut chan,
                            &relay_tx,
                            &mut stdout,
                        ).await?;
                        if matches!(action, RouteAction::Disconnect) {
                            break;
                        }
                    }
                    Some(RelayMessage::PeerStatus(status)) => {
                        if status.role == PeerRole::Host {
                            if status.online {
                                send_handshake(
                                    &pairing.session_id,
                                    &relay_tx,
                                    &local_key.public,
                                    &local_fingerprint,
                                    Some("remote-terminal".to_string()),
                                )?;
                                send_resize(&relay_tx, &pairing.session_id, &mut chan)?;
                            } else {
                                stdout
                                    .write_all(b"\r\n[disconnected] host went offline\r\n")
                                    .await?;
                                stdout.flush().await?;
                                break;
                            }
                        }
                    }
                    Some(RelayMessage::Error(err)) => {
                        warn!(message = %err.message, "relay error");
                    }
                    Some(RelayMessage::Pong(_)) | Some(RelayMessage::Ping(_)) | Some(RelayMessage::Registered(_)) | Some(RelayMessage::Register(_)) => {}
                    None => {
                        warn!("relay disconnected, attempting to reconnect client");
                        let (new_relay, new_registered) = reconnect_client(&pairing, &resume_token).await?;
                        relay = new_relay;
                        relay_tx = relay.sender();
                        resume_token = new_registered.resume_token.clone();
                        chan.reset();
                        if new_registered.peer_online {
                            send_handshake(
                                &pairing.session_id,
                                &relay_tx,
                                &local_key.public,
                                &local_fingerprint,
                                Some("remote-terminal".to_string()),
                            )?;
                        }
                    }
                }
            }
            _ = heartbeat.tick() => {
                let _ = relay_tx.send(RelayMessage::Ping(now_millis()));
                send_resize(&relay_tx, &pairing.session_id, &mut chan)?;
            }
            resize_event = resize_rx.recv() => {
                if resize_event.is_none() {
                    continue;
                }
                send_resize(&relay_tx, &pairing.session_id, &mut chan)?;
            }
            _ = &mut shutdown => {
                break;
            }
        }
    }

    // Reset terminal state before dropping raw mode:
    // - Exit alternate screen buffer (in case the tool used it)
    // - Disable mouse tracking
    // - Reset all attributes
    {
        let mut stdout = tokio::io::stdout();
        stdout
            .write_all(b"\x1b[?1049l\x1b[?1000l\x1b[?1006l\x1b[?25h\x1b[0m\x1b[2J\x1b[H")
            .await?;
        stdout.flush().await?;
    }

    // Drop raw mode so the terminal behaves normally for the prompt.
    drop(_raw_mode);

    // Full terminal reset after raw mode is off — this catches anything the
    // escape sequences above missed (e.g. buffered TUI output that arrived late).
    print!("\x1b[!p\x1b[?1049l\x1b[2J\x1b[H\x1b[0m");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    eprintln!("Press enter to exit...");
    let mut buf = [0u8; 1];
    let _ = tokio::io::stdin().read(&mut buf).await;

    Ok(())
}

/// Return value from handle_route indicating whether the session should continue.
enum RouteAction {
    Continue,
    Disconnect,
}

async fn handle_route(
    route: RelayRoute,
    pairing: &PairingUri,
    local_secret: [u8; 32],
    local_public: &[u8; 32],
    chan: &mut ChannelState,
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
    stdout: &mut tokio::io::Stdout,
) -> anyhow::Result<RouteAction> {
    let frame = decode_peer_frame(&route.payload)?;
    match frame {
        PeerFrame::Handshake(handshake) => {
            // Ignore duplicate handshakes if we already have a channel
            // (in-progress or confirmed). This handles the dual-handshake
            // race where both sides send Handshake simultaneously — the
            // first one processed wins, and the second is safely dropped.
            if chan.channel.is_some() {
                info!(
                    confirmed = chan.confirmed,
                    "ignoring duplicate handshake, channel already established"
                );
                return Ok(RouteAction::Continue);
            }

            // Validate handshake timestamp to reject stale/replayed messages.
            let now = now_millis();
            let age = now.saturating_sub(handshake.timestamp_ms);
            if age > HANDSHAKE_MAX_AGE_MS {
                warn!(age_ms = age, "rejecting stale handshake");
                return Ok(RouteAction::Continue);
            }

            if let Some(expected) = &pairing.expected_fingerprint
                && &handshake.fingerprint != expected
            {
                return Err(anyhow::anyhow!(
                    "fingerprint mismatch: expected {}, received {}",
                    expected,
                    handshake.fingerprint
                ));
            }

            let keys = derive_session_keys(
                PeerRole::Client,
                &pairing.session_id,
                local_secret,
                handshake.public_key,
            )?;

            // Compute our outbound confirmation MAC and the expected peer MAC.
            let our_mac = compute_handshake_mac(
                &keys.tx,
                local_public,
                &handshake.public_key,
                &pairing.session_id,
            );
            let peer_mac = compute_handshake_mac(
                &keys.rx,
                &handshake.public_key,
                local_public,
                &pairing.session_id,
            );

            chan.channel = Some(SecureChannel::new(keys));
            chan.confirmed = false;
            chan.expected_peer_mac = Some(peer_mac);

            send_peer_frame(
                relay_tx,
                &pairing.session_id,
                PeerFrame::HandshakeConfirm(HandshakeConfirm { mac: our_mac }),
            )?;
            info!(peer_fingerprint = %handshake.fingerprint, "handshake received, awaiting confirmation");
        }
        PeerFrame::HandshakeConfirm(confirm) => {
            let Some(expected) = &chan.expected_peer_mac else {
                warn!("received HandshakeConfirm without pending handshake");
                return Ok(RouteAction::Continue);
            };

            if confirm.mac != *expected {
                warn!("handshake confirmation MAC mismatch — tearing down channel");
                chan.reset();
                return Ok(RouteAction::Continue);
            }

            info!("handshake confirmed, channel trusted");
            chan.confirmed = true;
            chan.expected_peer_mac = None;

            // Clear the screen so connection info doesn't bleed into the terminal output.
            stdout.write_all(b"\x1b[2J\x1b[H").await?;
            stdout.flush().await?;

            // Send our terminal size so the host PTY renders at the correct dimensions.
            let (cols, rows) = terminal::size().unwrap_or((120, 40));
            if let Some(ch) = chan.channel.as_mut() {
                let sealed = ch.seal(&SecureMessage::Resize { cols, rows })?;
                send_peer_frame(relay_tx, &pairing.session_id, PeerFrame::Secure(sealed))?;
            }
        }
        PeerFrame::Secure(sealed) => {
            if !chan.confirmed {
                return Ok(RouteAction::Continue);
            }
            let Some(channel) = chan.channel.as_mut() else {
                return Ok(RouteAction::Continue);
            };
            match channel.open(&sealed)? {
                SecureMessage::PtyOutput(bytes) => {
                    stdout.write_all(&bytes).await?;
                    stdout.flush().await?;
                }
                SecureMessage::Notification(notice) => {
                    stdout
                        .write_all(
                            format!("\r\n[notification] {}: {}\r\n", notice.title, notice.body)
                                .as_bytes(),
                        )
                        .await?;
                    stdout.flush().await?;
                }
                SecureMessage::VersionNotice { minimum_version } => {
                    stdout
                        .write_all(
                            format!(
                                "\r\n[version] minimum required CLI version: {minimum_version}\r\n"
                            )
                            .as_bytes(),
                        )
                        .await?;
                    stdout.flush().await?;
                }
                SecureMessage::SessionEnded { exit_code } => {
                    stdout
                        .write_all(
                            format!("\r\n[session ended] exit code: {exit_code}\r\n").as_bytes(),
                        )
                        .await?;
                    stdout.flush().await?;
                    return Ok(RouteAction::Disconnect);
                }
                SecureMessage::Heartbeat
                | SecureMessage::Resize { .. }
                | SecureMessage::PtyInput(_)
                | SecureMessage::Clipboard { .. }
                | SecureMessage::ReadOnly { .. }
                | SecureMessage::VoiceCommand(_)
                | SecureMessage::Unknown(_) => {}
            }
        }
        PeerFrame::KeepAlive => {}
    }
    Ok(RouteAction::Continue)
}

fn send_resize(
    relay_tx: &mpsc::UnboundedSender<RelayMessage>,
    session_id: &str,
    chan: &mut ChannelState,
) -> anyhow::Result<()> {
    if !chan.confirmed {
        return Ok(());
    }
    let Some(channel) = chan.channel.as_mut() else {
        return Ok(());
    };
    let (cols, rows) = terminal::size().unwrap_or((120, 40));
    let sealed = channel.seal(&SecureMessage::Resize { cols, rows })?;
    send_peer_frame(relay_tx, session_id, PeerFrame::Secure(sealed))
}

fn resolve_pairing(args: &AttachArgs) -> anyhow::Result<PairingUri> {
    if let Some(uri) = &args.pairing_uri {
        return Ok(parse_pairing_uri(uri)?);
    }
    Ok(PairingUri {
        relay_url: args
            .relay_url
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--relay-url is required without --pairing-uri"))?,
        session_id: args
            .session_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--session-id is required without --pairing-uri"))?,
        pairing_code: args
            .pairing_code
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--pairing-code is required without --pairing-uri"))?,
        expected_fingerprint: args.expected_fingerprint.clone(),
        api_key: None, // When attaching manually, the API key comes from the pairing URI
    })
}

async fn connect_client(
    pairing: &PairingUri,
    resume_token: Option<String>,
) -> anyhow::Result<(RelayConnection, protocol::protocol::RegisterResponse)> {
    RelayConnection::connect(
        &pairing.relay_url,
        RegisterRequest {
            protocol_version: PROTOCOL_VERSION,
            protocol_version_min: Some(PROTOCOL_VERSION_MIN),
            client_version: crate::constants::CLIENT_VERSION.to_string(),
            session_id: pairing.session_id.clone(),
            pairing_code: pairing.pairing_code.clone(),
            role: PeerRole::Client,
            resume_token,
        },
        pairing.api_key.as_deref(),
    )
    .await
}

/// Maximum number of reconnect attempts before giving up.
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

async fn reconnect_client(
    pairing: &PairingUri,
    resume_token: &str,
) -> anyhow::Result<(RelayConnection, protocol::protocol::RegisterResponse)> {
    let mut delay = Duration::from_secs(1);
    for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
        tokio::select! {
            result = connect_client(pairing, Some(resume_token.to_string())) => {
                match result {
                    Ok(connection) => return Ok(connection),
                    Err(err) => {
                        warn!(
                            error = %err,
                            attempt = attempt,
                            max = MAX_RECONNECT_ATTEMPTS,
                            "client reconnect attempt failed"
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

struct RawModeGuard;

impl RawModeGuard {
    fn new() -> anyhow::Result<Self> {
        terminal::enable_raw_mode().context("failed enabling terminal raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}
