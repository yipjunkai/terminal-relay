use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Current protocol version. Bump when adding breaking wire format changes.
pub const PROTOCOL_VERSION: u16 = 2;

/// Minimum protocol version this build supports.
pub const PROTOCOL_VERSION_MIN: u16 = 1;

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
    /// Minimum protocol version the client supports (for range negotiation).
    /// If absent, assumed equal to `protocol_version` (strict match, legacy behavior).
    pub protocol_version_min: Option<u16>,
    pub client_version: String,
    pub session_id: String,
    pub pairing_code: String,
    pub role: PeerRole,
    pub resume_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub server_version: String,
    /// The protocol version selected by the server (highest mutually supported).
    pub negotiated_protocol_version: u16,
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

/// Action requested by a voice command from a mobile client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceAction {
    /// The raw transcribed text from speech recognition.
    pub transcript: String,
    /// A structured intent (e.g. "refactor", "commit", "debug"), if recognized.
    pub intent: Option<String>,
    /// Confidence score from the speech recognizer (0.0 to 1.0).
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecureMessage {
    // ── Core variants ──
    PtyInput(Vec<u8>),
    PtyOutput(Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
    },
    Heartbeat,
    VersionNotice {
        minimum_version: String,
    },
    Notification(PushNotification),

    // ── Extended variants ──
    /// Sent by the host when the PTY child process exits.
    SessionEnded {
        exit_code: i32,
    },
    /// Clipboard content shared between peers.
    Clipboard {
        content: String,
    },
    /// Sent by the host to indicate this session is read-only (no input accepted).
    ReadOnly {
        enabled: bool,
    },
    /// Voice command from a mobile client, transcribed on-device.
    VoiceCommand(VoiceAction),
    /// Unknown message from a newer protocol version. Receivers should silently ignore this.
    /// This must remain the LAST variant.
    Unknown(Vec<u8>),
}

pub fn encode_relay(message: &RelayMessage) -> CoreResult<Vec<u8>> {
    rmp_serde::to_vec_named(message).map_err(|err| CoreError::Serialization(err.to_string()))
}

pub fn decode_relay(bytes: &[u8]) -> CoreResult<RelayMessage> {
    rmp_serde::from_slice(bytes).map_err(|err| CoreError::Deserialization(err.to_string()))
}

pub fn encode_peer_frame(frame: &PeerFrame) -> CoreResult<Vec<u8>> {
    rmp_serde::to_vec_named(frame).map_err(|err| CoreError::Serialization(err.to_string()))
}

pub fn decode_peer_frame(bytes: &[u8]) -> CoreResult<PeerFrame> {
    rmp_serde::from_slice(bytes).map_err(|err| CoreError::Deserialization(err.to_string()))
}

pub fn encode_secure_message(message: &SecureMessage) -> CoreResult<Vec<u8>> {
    rmp_serde::to_vec_named(message).map_err(|err| CoreError::Serialization(err.to_string()))
}

/// Decode a `SecureMessage`, falling back to `SecureMessage::Unknown` for unrecognized variants.
/// This provides forward compatibility: older clients receiving messages with new variant
/// discriminants will get `Unknown` instead of a deserialization error.
pub fn decode_secure_message(bytes: &[u8]) -> CoreResult<SecureMessage> {
    match rmp_serde::from_slice(bytes) {
        Ok(message) => Ok(message),
        Err(_) => Ok(SecureMessage::Unknown(bytes.to_vec())),
    }
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
            protocol_version_min: Some(PROTOCOL_VERSION_MIN),
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
            protocol_version_min: None,
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
            server_version: "0.1.0".to_string(),
            negotiated_protocol_version: PROTOCOL_VERSION,
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
    fn secure_session_ended_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::SessionEnded { exit_code: 0 });
        secure_msg_roundtrip(&SecureMessage::SessionEnded { exit_code: -1 });
    }

    #[test]
    fn secure_clipboard_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::Clipboard {
            content: "copied text".to_string(),
        });
    }

    #[test]
    fn secure_read_only_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::ReadOnly { enabled: true });
        secure_msg_roundtrip(&SecureMessage::ReadOnly { enabled: false });
    }

    #[test]
    fn secure_voice_command_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::VoiceCommand(VoiceAction {
            transcript: "commit changes".to_string(),
            intent: Some("commit".to_string()),
            confidence: 0.92,
        }));
        secure_msg_roundtrip(&SecureMessage::VoiceCommand(VoiceAction {
            transcript: "um maybe refactor".to_string(),
            intent: None,
            confidence: 0.3,
        }));
    }

    #[test]
    fn secure_unknown_roundtrip() {
        secure_msg_roundtrip(&SecureMessage::Unknown(vec![1, 2, 3]));
    }

    #[test]
    fn decode_secure_message_returns_unknown_for_garbage() {
        // Forward compatibility: garbage input should return Unknown, not an error.
        let result = decode_secure_message(&[0xff, 0xff, 0xff]);
        assert!(matches!(result, Ok(SecureMessage::Unknown(_))));
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
    fn decode_secure_message_empty_returns_unknown() {
        // Empty input is also treated as Unknown for forward compatibility.
        let result = decode_secure_message(&[]);
        assert!(matches!(result, Ok(SecureMessage::Unknown(_))));
    }
}
