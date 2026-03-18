use bincode::config::{standard, Configuration};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum PeerRole {
    Host,
    Client,
}

impl PeerRole {
    pub fn opposite(self) -> Self {
        match self {
            Self::Host => Self::Client,
            Self::Client => Self::Host,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub protocol_version: u16,
    pub client_version: String,
    pub session_id: String,
    pub pairing_code: String,
    pub role: PeerRole,
    pub resume_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub resume_token: String,
    pub peer_online: bool,
    pub session_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRoute {
    pub session_id: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub session_id: String,
    pub role: PeerRole,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayError {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayMessage {
    Register(RegisterRequest),
    Registered(RegisterResponse),
    Route(RelayRoute),
    PeerStatus(PeerStatus),
    Ping(u64),
    Pong(u64),
    Error(RelayError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub public_key: [u8; 32],
    pub fingerprint: String,
    pub tool_name: Option<String>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedFrame {
    pub nonce: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeConfirm {
    /// HMAC-SHA256 over the handshake transcript, proving the sender holds the DH private key.
    pub mac: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerFrame {
    Handshake(Handshake),
    HandshakeConfirm(HandshakeConfirm),
    Secure(SealedFrame),
    KeepAlive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotification {
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecureMessage {
    PtyInput(Vec<u8>),
    PtyOutput(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Heartbeat,
    VersionNotice { minimum_version: String },
    Notification(PushNotification),
}

pub fn wire_config() -> Configuration {
    standard()
}

pub fn encode_relay(message: &RelayMessage) -> CoreResult<Vec<u8>> {
    bincode::serde::encode_to_vec(message, wire_config())
        .map_err(|err| CoreError::Serialization(err.to_string()))
}

pub fn decode_relay(bytes: &[u8]) -> CoreResult<RelayMessage> {
    bincode::serde::decode_from_slice(bytes, wire_config())
        .map(|(message, _)| message)
        .map_err(|err| CoreError::Deserialization(err.to_string()))
}

pub fn encode_peer_frame(frame: &PeerFrame) -> CoreResult<Vec<u8>> {
    bincode::serde::encode_to_vec(frame, wire_config())
        .map_err(|err| CoreError::Serialization(err.to_string()))
}

pub fn decode_peer_frame(bytes: &[u8]) -> CoreResult<PeerFrame> {
    bincode::serde::decode_from_slice(bytes, wire_config())
        .map(|(frame, _)| frame)
        .map_err(|err| CoreError::Deserialization(err.to_string()))
}

pub fn encode_secure_message(message: &SecureMessage) -> CoreResult<Vec<u8>> {
    bincode::serde::encode_to_vec(message, wire_config())
        .map_err(|err| CoreError::Serialization(err.to_string()))
}

pub fn decode_secure_message(bytes: &[u8]) -> CoreResult<SecureMessage> {
    bincode::serde::decode_from_slice(bytes, wire_config())
        .map(|(message, _)| message)
        .map_err(|err| CoreError::Deserialization(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── PeerRole ──

    #[test]
    fn peer_role_opposite() {
        assert_eq!(PeerRole::Host.opposite(), PeerRole::Client);
        assert_eq!(PeerRole::Client.opposite(), PeerRole::Host);
    }

    // ── RelayMessage encode/decode roundtrip ──

    fn relay_roundtrip(msg: &RelayMessage) {
        let bytes = encode_relay(msg).unwrap();
        let decoded = decode_relay(&bytes).unwrap();
        // Compare debug representations as a simple equality check
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn relay_register_roundtrip() {
        relay_roundtrip(&RelayMessage::Register(RegisterRequest {
            protocol_version: PROTOCOL_VERSION,
            client_version: "0.1.0".to_string(),
            session_id: "sess-123".to_string(),
            pairing_code: "ABC-DEF".to_string(),
            role: PeerRole::Host,
            resume_token: None,
        }));
    }

    #[test]
    fn relay_register_with_resume_token() {
        relay_roundtrip(&RelayMessage::Register(RegisterRequest {
            protocol_version: PROTOCOL_VERSION,
            client_version: "0.1.0".to_string(),
            session_id: "sess-123".to_string(),
            pairing_code: "ABC-DEF".to_string(),
            role: PeerRole::Client,
            resume_token: Some("token-xyz".to_string()),
        }));
    }

    #[test]
    fn relay_registered_roundtrip() {
        relay_roundtrip(&RelayMessage::Registered(RegisterResponse {
            resume_token: "tok".to_string(),
            peer_online: true,
            session_ttl_secs: 3600,
        }));
    }

    #[test]
    fn relay_route_roundtrip() {
        relay_roundtrip(&RelayMessage::Route(RelayRoute {
            session_id: "sess".to_string(),
            payload: vec![1, 2, 3, 4],
        }));
    }

    #[test]
    fn relay_peer_status_roundtrip() {
        relay_roundtrip(&RelayMessage::PeerStatus(PeerStatus {
            session_id: "sess".to_string(),
            role: PeerRole::Host,
            online: false,
        }));
    }

    #[test]
    fn relay_ping_pong_roundtrip() {
        relay_roundtrip(&RelayMessage::Ping(42));
        relay_roundtrip(&RelayMessage::Pong(42));
    }

    #[test]
    fn relay_error_roundtrip() {
        relay_roundtrip(&RelayMessage::Error(RelayError {
            message: "something went wrong".to_string(),
        }));
    }

    // ── PeerFrame encode/decode roundtrip ──

    fn peer_frame_roundtrip(frame: &PeerFrame) {
        let bytes = encode_peer_frame(frame).unwrap();
        let decoded = decode_peer_frame(&bytes).unwrap();
        assert_eq!(format!("{frame:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn peer_frame_handshake_roundtrip() {
        peer_frame_roundtrip(&PeerFrame::Handshake(Handshake {
            public_key: [7u8; 32],
            fingerprint: "abc123".to_string(),
            tool_name: Some("claude".to_string()),
            timestamp_ms: 1700000000000,
        }));
    }

    #[test]
    fn peer_frame_handshake_no_tool_roundtrip() {
        peer_frame_roundtrip(&PeerFrame::Handshake(Handshake {
            public_key: [0u8; 32],
            fingerprint: "".to_string(),
            tool_name: None,
            timestamp_ms: 0,
        }));
    }

    #[test]
    fn peer_frame_handshake_confirm_roundtrip() {
        peer_frame_roundtrip(&PeerFrame::HandshakeConfirm(HandshakeConfirm {
            mac: [0xAB; 32],
        }));
    }

    #[test]
    fn peer_frame_secure_roundtrip() {
        peer_frame_roundtrip(&PeerFrame::Secure(SealedFrame {
            nonce: 99,
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        }));
    }

    #[test]
    fn peer_frame_keepalive_roundtrip() {
        peer_frame_roundtrip(&PeerFrame::KeepAlive);
    }

    // ── SecureMessage encode/decode roundtrip ──

    fn secure_msg_roundtrip(msg: &SecureMessage) {
        let bytes = encode_secure_message(msg).unwrap();
        let decoded = decode_secure_message(&bytes).unwrap();
        assert_eq!(format!("{msg:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn secure_pty_input_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::PtyInput(b"ls -la\n".to_vec()));
    }

    #[test]
    fn secure_pty_output_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::PtyOutput(b"total 42\n".to_vec()));
    }

    #[test]
    fn secure_resize_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::Resize { cols: 80, rows: 24 });
    }

    #[test]
    fn secure_heartbeat_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::Heartbeat);
    }

    #[test]
    fn secure_version_notice_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::VersionNotice {
            minimum_version: "1.0.0".to_string(),
        });
    }

    #[test]
    fn secure_notification_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::Notification(PushNotification {
            title: "Session ended".to_string(),
            body: "Your session has been closed.".to_string(),
        }));
    }

    #[test]
    fn secure_empty_payloads() {
        secure_msg_roundtrip(&SecureMessage::PtyInput(vec![]));
        secure_msg_roundtrip(&SecureMessage::PtyOutput(vec![]));
    }

    #[test]
    fn secure_large_payload() {
        let big = vec![0xABu8; 1_000_000];
        secure_msg_roundtrip(&SecureMessage::PtyOutput(big));
    }

    // ── Error cases ──

    #[test]
    fn decode_relay_rejects_garbage() {
        assert!(decode_relay(&[0xff, 0xff, 0xff]).is_err());
        assert!(decode_relay(&[]).is_err());
    }

    #[test]
    fn decode_peer_frame_rejects_garbage() {
        assert!(decode_peer_frame(&[0xff, 0xff, 0xff]).is_err());
        assert!(decode_peer_frame(&[]).is_err());
    }

    #[test]
    fn decode_secure_message_rejects_garbage() {
        assert!(decode_secure_message(&[0xff, 0xff, 0xff]).is_err());
        assert!(decode_secure_message(&[]).is_err());
    }
}
