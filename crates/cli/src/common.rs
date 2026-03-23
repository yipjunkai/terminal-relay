use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::warn;

use protocol::{
    crypto::{
        HANDSHAKE_MAX_AGE_MS, SecureChannel, compute_handshake_mac, derive_session_keys,
    },
    protocol::{
        Handshake, HandshakeConfirm, PeerFrame, PeerRole, RelayMessage, RelayRoute,
        encode_peer_frame,
    },
};

use crate::relay_client::RelayConnection;

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
    relay_tx: &mpsc::Sender<RelayMessage>,
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
    relay_tx: &mpsc::Sender<RelayMessage>,
    session_id: &str,
    frame: PeerFrame,
) -> anyhow::Result<()> {
    let payload = encode_peer_frame(&frame)?;
    relay_tx
        .try_send(RelayMessage::Route(RelayRoute {
            session_id: session_id.to_string(),
            payload,
        }))
        .map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                anyhow::anyhow!("relay send channel full (backpressure)")
            }
            mpsc::error::TrySendError::Closed(_) => {
                anyhow::anyhow!("relay send channel closed")
            }
        })
}

// ── Reconnect with exponential backoff ──────────────────────────────────

/// Maximum number of reconnect attempts before giving up.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// Generic reconnect loop with exponential backoff, interruptible by shutdown signal.
///
/// `connect_fn` is called on each attempt and should return a future that resolves
/// to the connection result. The label is used in log messages (e.g. "host", "client").
pub async fn reconnect_with_backoff<F, Fut>(
    label: &str,
    mut connect_fn: F,
) -> anyhow::Result<(RelayConnection, protocol::protocol::RegisterResponse)>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<(RelayConnection, protocol::protocol::RegisterResponse)>>,
{
    let mut delay = Duration::from_secs(1);
    for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
        tokio::select! {
            result = connect_fn() => {
                match result {
                    Ok(connection) => return Ok(connection),
                    Err(err) => {
                        warn!(
                            error = %err,
                            attempt = attempt,
                            max = MAX_RECONNECT_ATTEMPTS,
                            "{label} reconnect attempt failed"
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

// ── Shared handshake processing ─────────────────────────────────────────

/// Result of processing an inbound `PeerFrame::Handshake`.
pub struct HandshakeResult {
    /// The MAC we sent to the peer in our `HandshakeConfirm` (kept for diagnostics).
    #[allow(dead_code)]
    pub our_mac: [u8; 32],
    /// The MAC we expect from the peer's `HandshakeConfirm`.
    pub expected_peer_mac: [u8; 32],
    /// The secure channel ready for use (not yet confirmed).
    pub channel: SecureChannel,
}

/// Process an inbound `PeerFrame::Handshake`: validate timestamp, derive keys,
/// compute MACs, create the channel, and send `HandshakeConfirm`.
///
/// Returns `None` if the handshake should be ignored (duplicate or stale).
/// Returns `Err` on fingerprint mismatch (attach only) or crypto failure.
pub fn process_inbound_handshake(
    role: PeerRole,
    session_id: &str,
    local_secret: [u8; 32],
    local_public: &[u8; 32],
    handshake: &Handshake,
    chan: &ChannelState,
    expected_fingerprint: Option<&str>,
    relay_tx: &mpsc::Sender<RelayMessage>,
) -> anyhow::Result<Option<HandshakeResult>> {
    // Ignore duplicate handshakes if we already have a channel.
    if chan.channel.is_some() {
        return Ok(None);
    }

    // Validate handshake timestamp to reject stale/replayed messages.
    let now = now_millis();
    let age = now.saturating_sub(handshake.timestamp_ms);
    if age > HANDSHAKE_MAX_AGE_MS {
        warn!(age_ms = age, "rejecting stale handshake");
        return Ok(None);
    }

    // Fingerprint verification (attach only).
    if let Some(expected) = expected_fingerprint {
        if handshake.fingerprint != expected {
            return Err(anyhow::anyhow!(
                "fingerprint mismatch: expected {expected}, received {}",
                handshake.fingerprint
            ));
        }
    }

    let keys = derive_session_keys(
        role,
        session_id,
        local_secret,
        handshake.public_key,
    )?;

    let our_mac = compute_handshake_mac(
        &keys.tx,
        local_public,
        &handshake.public_key,
        session_id,
    );
    let peer_mac = compute_handshake_mac(
        &keys.rx,
        &handshake.public_key,
        local_public,
        session_id,
    );

    let channel = SecureChannel::new(keys);

    send_peer_frame(
        relay_tx,
        session_id,
        PeerFrame::HandshakeConfirm(HandshakeConfirm { mac: our_mac }),
    )?;

    Ok(Some(HandshakeResult {
        our_mac,
        expected_peer_mac: peer_mac,
        channel,
    }))
}

/// Verify an inbound `HandshakeConfirm` MAC against the expected value.
/// Returns `true` if valid, `false` if mismatch (caller should reset channel).
pub fn verify_handshake_confirm(
    confirm: &HandshakeConfirm,
    chan: &ChannelState,
) -> bool {
    match &chan.expected_peer_mac {
        Some(expected) => confirm.mac == *expected,
        None => {
            warn!("received HandshakeConfirm without pending handshake");
            false
        }
    }
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
