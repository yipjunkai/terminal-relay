use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use protocol::{
    crypto::SecureChannel,
    protocol::{Handshake, PeerFrame, RelayMessage, RelayRoute, encode_peer_frame},
};

/// Mutable state for the encrypted channel during a session.
pub struct ChannelState {
    pub channel: Option<SecureChannel>,
    pub confirmed: bool,
    pub expected_peer_mac: Option<[u8; 32]>,
}

impl ChannelState {
    pub fn new() -> Self {
        Self {
            channel: None,
            confirmed: false,
            expected_peer_mac: None,
        }
    }

    pub fn reset(&mut self) {
        self.channel = None;
        self.confirmed = false;
        self.expected_peer_mac = None;
    }
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

pub fn send_handshake(
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

pub fn send_peer_frame(
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

/// Wait for SIGINT (ctrl-c) or SIGTERM.
pub async fn shutdown_signal() {
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
