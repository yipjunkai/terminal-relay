pub mod crypto;
pub mod error;
pub mod pairing;
mod wire;

pub use error::{Error, Result};

// Re-export all public wire types and functions at the crate root.
pub use wire::{
    // Constants
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_MIN,
    // Relay types
    PeerRole,
    PeerStatus,
    RegisterRequest,
    RegisterResponse,
    RelayError,
    RelayMessage,
    RelayRoute,
    // Peer-to-peer frame types
    Handshake,
    HandshakeConfirm,
    PeerFrame,
    SealedFrame,
    // Secure message types
    AgentCommand,
    AgentEvent,
    PushNotification,
    SecureMessage,
    TodoItem,
    VoiceAction,
    // Encode/decode functions
    decode_peer_frame,
    decode_relay,
    decode_secure_message,
    encode_peer_frame,
    encode_relay,
    encode_secure_message,
};
