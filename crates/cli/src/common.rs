use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::warn;

use protocol::{
    crypto::{HANDSHAKE_MAX_AGE_MS, SecureChannel, compute_handshake_mac, derive_session_keys},
    protocol::{
        Handshake, HandshakeConfirm, PeerFrame, PeerRole, RelayMessage, RelayRoute,
        encode_peer_frame,
    },
};

use crate::relay_client::RelayConnection;

/// State machine for the encrypted channel during a session.
///
/// Transitions: `Disconnected` → `Handshaking` → `Confirmed` → `Disconnected` (on reset).
/// The enum makes impossible states unrepresentable (e.g. confirmed without a channel).
pub enum ChannelState {
    /// No channel established.
    Disconnected,
    /// Handshake sent, waiting for peer confirmation.
    Handshaking {
        channel: SecureChannel,
        expected_peer_mac: [u8; 32],
    },
    /// Handshake confirmed, channel is trusted and ready for use.
    Confirmed { channel: SecureChannel },
}

impl ChannelState {
    pub fn new() -> Self {
        Self::Disconnected
    }

    pub fn reset(&mut self) {
        *self = Self::Disconnected;
    }

    /// Returns `true` if the channel is confirmed and ready for sealed messages.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// Returns `true` if any channel exists (handshaking or confirmed).
    pub fn has_channel(&self) -> bool {
        !matches!(self, Self::Disconnected)
    }

    /// Get a mutable reference to the confirmed channel for sealing/opening messages.
    /// Returns `None` if not yet confirmed.
    pub fn confirmed_channel(&mut self) -> Option<&mut SecureChannel> {
        match self {
            Self::Confirmed { channel } => Some(channel),
            _ => None,
        }
    }

    /// Transition from Handshaking to Confirmed. Returns false if not in Handshaking state.
    pub fn confirm(&mut self) -> bool {
        let old = std::mem::replace(self, Self::Disconnected);
        match old {
            Self::Handshaking { channel, .. } => {
                *self = Self::Confirmed { channel };
                true
            }
            other => {
                *self = other;
                false
            }
        }
    }

    /// Get the expected peer MAC (only available during Handshaking).
    pub fn expected_peer_mac(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Handshaking {
                expected_peer_mac, ..
            } => Some(expected_peer_mac),
            _ => None,
        }
    }

    /// Transition from Disconnected to Handshaking with the given channel and expected MAC.
    pub fn start_handshake(&mut self, channel: SecureChannel, expected_peer_mac: [u8; 32]) {
        *self = Self::Handshaking {
            channel,
            expected_peer_mac,
        };
    }
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_millis() as u64
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
#[allow(clippy::too_many_arguments)]
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
    if chan.has_channel() {
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
    if let Some(expected) = expected_fingerprint
        && handshake.fingerprint != expected
    {
        return Err(anyhow::anyhow!(
            "fingerprint mismatch: expected {expected}, received {}",
            handshake.fingerprint
        ));
    }

    let keys = derive_session_keys(role, session_id, local_secret, handshake.public_key)?;

    let our_mac = compute_handshake_mac(&keys.tx, local_public, &handshake.public_key, session_id);
    let peer_mac = compute_handshake_mac(&keys.rx, &handshake.public_key, local_public, session_id);

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
pub fn verify_handshake_confirm(confirm: &HandshakeConfirm, chan: &ChannelState) -> bool {
    match chan.expected_peer_mac() {
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
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(_) => {
                // SIGTERM registration failed; fall back to SIGINT only.
                tokio::signal::ctrl_c().await.ok();
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::crypto::SessionKeys;

    fn dummy_channel() -> SecureChannel {
        SecureChannel::new(SessionKeys {
            tx: [1u8; 32],
            rx: [2u8; 32],
        })
    }

    #[test]
    fn channel_state_starts_disconnected() {
        let chan = ChannelState::new();
        assert!(!chan.is_confirmed());
        assert!(!chan.has_channel());
        assert!(chan.expected_peer_mac().is_none());
    }

    #[test]
    fn channel_state_handshaking_transition() {
        let mut chan = ChannelState::new();
        let mac = [0xABu8; 32];
        chan.start_handshake(dummy_channel(), mac);
        assert!(chan.has_channel());
        assert!(!chan.is_confirmed());
        assert_eq!(chan.expected_peer_mac(), Some(&mac));
    }

    #[test]
    fn channel_state_confirmed_channel_none_when_handshaking() {
        let mut chan = ChannelState::new();
        chan.start_handshake(dummy_channel(), [0u8; 32]);
        assert!(chan.confirmed_channel().is_none());
    }

    #[test]
    fn channel_state_confirm_transition() {
        let mut chan = ChannelState::new();
        chan.start_handshake(dummy_channel(), [0u8; 32]);
        assert!(chan.confirm());
        assert!(chan.is_confirmed());
        assert!(chan.has_channel());
        assert!(chan.confirmed_channel().is_some());
        assert!(chan.expected_peer_mac().is_none());
    }

    #[test]
    fn channel_state_confirm_from_disconnected_returns_false() {
        let mut chan = ChannelState::new();
        assert!(!chan.confirm());
        assert!(!chan.has_channel());
    }

    #[test]
    fn channel_state_confirm_from_confirmed_returns_false() {
        let mut chan = ChannelState::new();
        chan.start_handshake(dummy_channel(), [0u8; 32]);
        chan.confirm();
        // Second confirm should return false, stay Confirmed
        assert!(!chan.confirm());
        assert!(chan.is_confirmed());
    }

    #[test]
    fn channel_state_reset_from_confirmed() {
        let mut chan = ChannelState::new();
        chan.start_handshake(dummy_channel(), [0u8; 32]);
        chan.confirm();
        chan.reset();
        assert!(!chan.is_confirmed());
        assert!(!chan.has_channel());
    }

    #[test]
    fn channel_state_reset_from_handshaking() {
        let mut chan = ChannelState::new();
        chan.start_handshake(dummy_channel(), [0u8; 32]);
        chan.reset();
        assert!(!chan.has_channel());
        assert!(chan.expected_peer_mac().is_none());
    }

    #[test]
    fn confirmed_channel_returns_none_when_disconnected() {
        let mut chan = ChannelState::new();
        assert!(chan.confirmed_channel().is_none());
    }

    #[test]
    fn verify_handshake_confirm_matching_mac() {
        let mut chan = ChannelState::new();
        let mac = [0x42u8; 32];
        chan.start_handshake(dummy_channel(), mac);
        let confirm = HandshakeConfirm { mac };
        assert!(verify_handshake_confirm(&confirm, &chan));
    }

    #[test]
    fn verify_handshake_confirm_mismatched_mac() {
        let mut chan = ChannelState::new();
        chan.start_handshake(dummy_channel(), [0x42u8; 32]);
        let confirm = HandshakeConfirm { mac: [0x00u8; 32] };
        assert!(!verify_handshake_confirm(&confirm, &chan));
    }

    #[test]
    fn verify_handshake_confirm_no_pending_handshake() {
        let chan = ChannelState::new();
        let confirm = HandshakeConfirm { mac: [0u8; 32] };
        assert!(!verify_handshake_confirm(&confirm, &chan));
    }

    #[test]
    fn verify_handshake_confirm_after_confirmed() {
        let mut chan = ChannelState::new();
        chan.start_handshake(dummy_channel(), [0x42u8; 32]);
        chan.confirm();
        // After confirm, expected_peer_mac is gone
        let confirm = HandshakeConfirm { mac: [0x42u8; 32] };
        assert!(!verify_handshake_confirm(&confirm, &chan));
    }

    #[test]
    fn send_peer_frame_closed_channel_returns_err() {
        let (tx, rx) = mpsc::channel::<RelayMessage>(1);
        drop(rx); // close the receiver
        let result = send_peer_frame(&tx, "session-id", PeerFrame::KeepAlive);
        assert!(result.is_err());
    }
}
