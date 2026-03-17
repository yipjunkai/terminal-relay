use bincode::config::{Configuration, standard};
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
pub enum PeerFrame {
    Handshake(Handshake),
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
