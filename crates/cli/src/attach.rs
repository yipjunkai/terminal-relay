use std::time::Duration;

use anyhow::Context;
use clap::Args;
use crossterm::terminal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use protocol::{
    crypto::{fingerprint, generate_key_pair},
    pairing::{PairingUri, parse_pairing_uri},
    protocol::{
        PROTOCOL_VERSION, PROTOCOL_VERSION_MIN, PeerFrame, PeerRole, RegisterRequest, RelayMessage,
        RelayRoute, SecureMessage, decode_peer_frame,
    },
};

use crate::common::{
    ChannelState, now_millis, process_inbound_handshake, reconnect_with_backoff, send_handshake,
    send_peer_frame, shutdown_signal, verify_handshake_confirm,
};
use crate::relay_client::RelayConnection;

/// Channel capacity for input events (keyboard, mouse, resize).
const STDIN_CHANNEL_CAPACITY: usize = 256;

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

    // Enable mouse capture so mouse events from the user's terminal are forwarded
    // to the remote host. This allows TUI apps (OpenCode, etc.) to receive clicks,
    // drags, scrolls, etc.
    crossterm::execute!(std::io::stdout(), crossterm::event::EnableMouseCapture)?;

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

    // Input events from crossterm (keyboard, mouse, resize) — replaces raw stdin reader.
    enum InputEvent {
        Key(Vec<u8>),
        Resize(u16, u16),
        Detach,
    }
    let (input_tx, mut input_rx) = mpsc::channel::<InputEvent>(STDIN_CHANNEL_CAPACITY);
    let input_task = tokio::task::spawn_blocking(move || {
        use crossterm::event::{self, Event, KeyCode, KeyModifiers};

        loop {
            if event::poll(Duration::from_millis(50)).unwrap_or(false) {
                match event::read() {
                    Ok(Event::Key(key)) => {
                        // Ctrl-C detaches the attach client without stopping the host.
                        if key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                        {
                            let _ = input_tx.blocking_send(InputEvent::Detach);
                            break;
                        }

                        if let Some(bytes) = crate::input::key_to_bytes(&key)
                            && input_tx.blocking_send(InputEvent::Key(bytes)).is_err()
                        {
                            break;
                        }
                    }
                    Ok(Event::Mouse(mouse)) => {
                        if let Some(bytes) = crate::input::mouse_to_bytes(&mouse)
                            && input_tx.blocking_send(InputEvent::Key(bytes)).is_err()
                        {
                            break;
                        }
                    }
                    Ok(Event::Resize(cols, rows)) => {
                        if input_tx
                            .blocking_send(InputEvent::Resize(cols, rows))
                            .is_err()
                        {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let mut stdout = tokio::io::stdout();

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    let mut heartbeat = tokio::time::interval(Duration::from_secs(
        crate::constants::HEARTBEAT_INTERVAL_SECS,
    ));

    loop {
        tokio::select! {
            local_input = input_rx.recv() => {
                match local_input {
                    Some(InputEvent::Key(bytes)) => {
                        if let Some(channel) = chan.confirmed_channel() {
                            let sealed = channel.seal(&SecureMessage::PtyInput(bytes))?;
                            send_peer_frame(&relay_tx, &pairing.session_id, PeerFrame::Secure(sealed))?;
                        }
                    }
                    Some(InputEvent::Resize(cols, rows)) => {
                        if let Some(channel) = chan.confirmed_channel() {
                            let sealed = channel.seal(&SecureMessage::Resize { cols, rows })?;
                            send_peer_frame(&relay_tx, &pairing.session_id, PeerFrame::Secure(sealed))?;
                        }
                    }
                    Some(InputEvent::Detach) | None => {
                        let mut stdout = tokio::io::stdout();
                        stdout.write_all(b"\r\n[detached]\r\n").await?;
                        stdout.flush().await?;
                        break;
                    }
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
                let _ = relay_tx.try_send(RelayMessage::Ping(now_millis()));
                send_resize(&relay_tx, &pairing.session_id, &mut chan)?;
            }
            _ = &mut shutdown => {
                break;
            }
        }
    }

    // Clean up: disable mouse capture, reset terminal state.
    input_task.abort();
    crossterm::execute!(std::io::stdout(), crossterm::event::DisableMouseCapture)?;

    // Reset terminal state before dropping raw mode:
    // - Exit alternate screen buffer (in case the tool used it)
    // - Disable mouse tracking (belt-and-suspenders with DECSET sequences)
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
    relay_tx: &mpsc::Sender<RelayMessage>,
    stdout: &mut tokio::io::Stdout,
) -> anyhow::Result<RouteAction> {
    let frame = decode_peer_frame(&route.payload)?;
    match frame {
        PeerFrame::Handshake(handshake) => {
            let result = process_inbound_handshake(
                PeerRole::Client,
                &pairing.session_id,
                local_secret,
                local_public,
                &handshake,
                chan,
                pairing.expected_fingerprint.as_deref(),
                relay_tx,
            )?;

            let Some(hs) = result else {
                return Ok(RouteAction::Continue); // Duplicate or stale — ignored
            };

            chan.start_handshake(hs.channel, hs.expected_peer_mac);

            info!(peer_fingerprint = %handshake.fingerprint, "handshake received, awaiting confirmation");
        }
        PeerFrame::HandshakeConfirm(confirm) => {
            if !verify_handshake_confirm(&confirm, chan) {
                warn!("handshake confirmation MAC mismatch — tearing down channel");
                chan.reset();
                return Ok(RouteAction::Continue);
            }

            info!("handshake confirmed, channel trusted");
            chan.confirm();

            // Clear the screen so connection info doesn't bleed into the terminal output.
            stdout.write_all(b"\x1b[2J\x1b[H").await?;
            stdout.flush().await?;

            // Send our terminal size so the host PTY renders at the correct dimensions.
            let (cols, rows) = terminal::size().unwrap_or(crate::constants::DEFAULT_TERMINAL_SIZE);
            if let Some(ch) = chan.confirmed_channel() {
                let sealed = ch.seal(&SecureMessage::Resize { cols, rows })?;
                send_peer_frame(relay_tx, &pairing.session_id, PeerFrame::Secure(sealed))?;
            }
        }
        PeerFrame::Secure(sealed) => {
            let Some(channel) = chan.confirmed_channel() else {
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
                | SecureMessage::AgentEvent(_)
                | SecureMessage::AgentCommand(_)
                | SecureMessage::Unknown(_) => {}
            }
        }
        PeerFrame::KeepAlive => {}
    }
    Ok(RouteAction::Continue)
}

fn send_resize(
    relay_tx: &mpsc::Sender<RelayMessage>,
    session_id: &str,
    chan: &mut ChannelState,
) -> anyhow::Result<()> {
    let Some(channel) = chan.confirmed_channel() else {
        return Ok(());
    };
    let (cols, rows) = terminal::size().unwrap_or(crate::constants::DEFAULT_TERMINAL_SIZE);
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

async fn reconnect_client(
    pairing: &PairingUri,
    resume_token: &str,
) -> anyhow::Result<(RelayConnection, protocol::protocol::RegisterResponse)> {
    reconnect_with_backoff("client", || {
        connect_client(pairing, Some(resume_token.to_string()))
    })
    .await
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with_uri(uri: &str) -> AttachArgs {
        AttachArgs {
            pairing_uri: Some(uri.to_string()),
            relay_url: None,
            session_id: None,
            pairing_code: None,
            expected_fingerprint: None,
        }
    }

    fn args_manual(
        relay: Option<&str>,
        session: Option<&str>,
        code: Option<&str>,
        fingerprint: Option<&str>,
    ) -> AttachArgs {
        AttachArgs {
            pairing_uri: None,
            relay_url: relay.map(String::from),
            session_id: session.map(String::from),
            pairing_code: code.map(String::from),
            expected_fingerprint: fingerprint.map(String::from),
        }
    }

    #[test]
    fn resolve_pairing_from_uri() {
        let uri =
            "farwatch://pair?relay=wss://example.com/ws&session=abc-123&code=AAAAAA-BBBBBB-CCCCCC";
        let result = resolve_pairing(&args_with_uri(uri)).unwrap();
        assert_eq!(result.relay_url, "wss://example.com/ws");
        assert_eq!(result.session_id, "abc-123");
        assert_eq!(result.pairing_code, "AAAAAA-BBBBBB-CCCCCC");
    }

    #[test]
    fn resolve_pairing_from_individual_args() {
        let args = args_manual(
            Some("wss://relay.example.com/ws"),
            Some("sess-1"),
            Some("XYZXYZ-XYZXYZ-XYZXYZ"),
            None,
        );
        let result = resolve_pairing(&args).unwrap();
        assert_eq!(result.relay_url, "wss://relay.example.com/ws");
        assert_eq!(result.session_id, "sess-1");
        assert_eq!(result.pairing_code, "XYZXYZ-XYZXYZ-XYZXYZ");
        assert!(result.expected_fingerprint.is_none());
    }

    #[test]
    fn resolve_pairing_with_fingerprint() {
        let args = args_manual(
            Some("wss://r.example.com/ws"),
            Some("s1"),
            Some("AAAAAA-BBBBBB-CCCCCC"),
            Some("abc123"),
        );
        let result = resolve_pairing(&args).unwrap();
        assert_eq!(result.expected_fingerprint, Some("abc123".to_string()));
    }

    #[test]
    fn resolve_pairing_missing_relay_url() {
        let args = args_manual(None, Some("sess"), Some("CODE12-CODE34-CODE56"), None);
        let err = resolve_pairing(&args).unwrap_err();
        assert!(err.to_string().contains("--relay-url"));
    }

    #[test]
    fn resolve_pairing_missing_session_id() {
        let args = args_manual(
            Some("wss://r.com/ws"),
            None,
            Some("CODE12-CODE34-CODE56"),
            None,
        );
        let err = resolve_pairing(&args).unwrap_err();
        assert!(err.to_string().contains("--session-id"));
    }

    #[test]
    fn resolve_pairing_missing_pairing_code() {
        let args = args_manual(Some("wss://r.com/ws"), Some("sess"), None, None);
        let err = resolve_pairing(&args).unwrap_err();
        assert!(err.to_string().contains("--pairing-code"));
    }

    #[test]
    fn resolve_pairing_invalid_uri() {
        let result = resolve_pairing(&args_with_uri("not-a-valid-uri"));
        assert!(result.is_err());
    }
}
