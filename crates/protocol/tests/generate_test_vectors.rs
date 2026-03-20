use protocol::{
    crypto::{compute_handshake_mac, derive_session_keys, fingerprint, verify_handshake_mac},
    pairing::{build_pairing_uri, parse_pairing_uri, PairingUri},
    protocol::*,
};
/// Generates deterministic test vectors for cross-platform compatibility testing.
/// Run with: cargo test -p protocol --test generate_test_vectors -- --nocapture
///
/// The output JSON can be saved and used by Dart, Swift, Kotlin tests to verify
/// wire-compatible encoding/decoding and identical crypto outputs.
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Fixed test keys (deterministic, NOT for production use)
// ---------------------------------------------------------------------------

const HOST_SECRET: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const CLIENT_SECRET: [u8; 32] = [
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
];

const SESSION_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

fn host_public() -> [u8; 32] {
    let secret = StaticSecret::from(HOST_SECRET);
    PublicKey::from(&secret).to_bytes()
}

fn client_public() -> [u8; 32] {
    let secret = StaticSecret::from(CLIENT_SECRET);
    PublicKey::from(&secret).to_bytes()
}

// ---------------------------------------------------------------------------
// Protocol encoding test vectors
// ---------------------------------------------------------------------------

fn protocol_vectors() -> Value {
    let mut vectors = Vec::new();

    // RelayMessage::Register
    let register = RelayMessage::Register(RegisterRequest {
        protocol_version: 2,
        protocol_version_min: Some(1),
        client_version: "0.1.0".to_string(),
        session_id: SESSION_ID.to_string(),
        pairing_code: "ABCDEF-GHIJKL-MNOPQR".to_string(),
        role: PeerRole::Client,
        resume_token: None,
    });
    vectors.push(json!({
        "name": "RelayMessage::Register",
        "bytes": hex::encode(encode_relay(&register).unwrap()),
    }));

    // RelayMessage::Registered
    let registered = RelayMessage::Registered(RegisterResponse {
        server_version: "0.1.0".to_string(),
        negotiated_protocol_version: 2,
        resume_token: "resume-tok-123".to_string(),
        peer_online: true,
        session_ttl_secs: 86400,
    });
    vectors.push(json!({
        "name": "RelayMessage::Registered",
        "bytes": hex::encode(encode_relay(&registered).unwrap()),
    }));

    // RelayMessage::Route
    let route = RelayMessage::Route(RelayRoute {
        session_id: SESSION_ID.to_string(),
        payload: vec![0xde, 0xad, 0xbe, 0xef],
    });
    vectors.push(json!({
        "name": "RelayMessage::Route",
        "bytes": hex::encode(encode_relay(&route).unwrap()),
    }));

    // RelayMessage::PeerStatus
    let status = RelayMessage::PeerStatus(PeerStatus {
        session_id: SESSION_ID.to_string(),
        role: PeerRole::Host,
        online: true,
    });
    vectors.push(json!({
        "name": "RelayMessage::PeerStatus",
        "bytes": hex::encode(encode_relay(&status).unwrap()),
    }));

    // RelayMessage::Ping / Pong
    let ping = RelayMessage::Ping(1700000000000);
    vectors.push(json!({
        "name": "RelayMessage::Ping",
        "bytes": hex::encode(encode_relay(&ping).unwrap()),
    }));

    let pong = RelayMessage::Pong(1700000000000);
    vectors.push(json!({
        "name": "RelayMessage::Pong",
        "bytes": hex::encode(encode_relay(&pong).unwrap()),
    }));

    // RelayMessage::Error
    let err = RelayMessage::Error(RelayError {
        message: "session not found".to_string(),
    });
    vectors.push(json!({
        "name": "RelayMessage::Error",
        "bytes": hex::encode(encode_relay(&err).unwrap()),
    }));

    // PeerFrame::Handshake
    let handshake = PeerFrame::Handshake(Handshake {
        public_key: host_public(),
        fingerprint: fingerprint(&host_public()),
        tool_name: Some("claude".to_string()),
        timestamp_ms: 1700000000000,
    });
    vectors.push(json!({
        "name": "PeerFrame::Handshake",
        "bytes": hex::encode(encode_peer_frame(&handshake).unwrap()),
    }));

    // PeerFrame::HandshakeConfirm
    let confirm = PeerFrame::HandshakeConfirm(HandshakeConfirm { mac: [0xAB; 32] });
    vectors.push(json!({
        "name": "PeerFrame::HandshakeConfirm",
        "bytes": hex::encode(encode_peer_frame(&confirm).unwrap()),
    }));

    // PeerFrame::Secure
    let secure = PeerFrame::Secure(SealedFrame {
        nonce: 42,
        ciphertext: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    });
    vectors.push(json!({
        "name": "PeerFrame::Secure",
        "bytes": hex::encode(encode_peer_frame(&secure).unwrap()),
    }));

    // PeerFrame::KeepAlive
    let keepalive = PeerFrame::KeepAlive;
    vectors.push(json!({
        "name": "PeerFrame::KeepAlive",
        "bytes": hex::encode(encode_peer_frame(&keepalive).unwrap()),
    }));

    // SecureMessage variants
    let pty_output = SecureMessage::PtyOutput(b"hello world".to_vec());
    vectors.push(json!({
        "name": "SecureMessage::PtyOutput",
        "bytes": hex::encode(encode_secure_message(&pty_output).unwrap()),
    }));

    let pty_input = SecureMessage::PtyInput(b"ls -la\n".to_vec());
    vectors.push(json!({
        "name": "SecureMessage::PtyInput",
        "bytes": hex::encode(encode_secure_message(&pty_input).unwrap()),
    }));

    let resize = SecureMessage::Resize {
        cols: 120,
        rows: 40,
    };
    vectors.push(json!({
        "name": "SecureMessage::Resize",
        "bytes": hex::encode(encode_secure_message(&resize).unwrap()),
    }));

    let heartbeat = SecureMessage::Heartbeat;
    vectors.push(json!({
        "name": "SecureMessage::Heartbeat",
        "bytes": hex::encode(encode_secure_message(&heartbeat).unwrap()),
    }));

    let session_ended = SecureMessage::SessionEnded { exit_code: 0 };
    vectors.push(json!({
        "name": "SecureMessage::SessionEnded",
        "bytes": hex::encode(encode_secure_message(&session_ended).unwrap()),
    }));

    let clipboard = SecureMessage::Clipboard {
        content: "copied text".to_string(),
    };
    vectors.push(json!({
        "name": "SecureMessage::Clipboard",
        "bytes": hex::encode(encode_secure_message(&clipboard).unwrap()),
    }));

    let voice = SecureMessage::VoiceCommand(VoiceAction {
        transcript: "commit changes".to_string(),
        intent: Some("commit".to_string()),
        confidence: 0.95,
    });
    vectors.push(json!({
        "name": "SecureMessage::VoiceCommand",
        "bytes": hex::encode(encode_secure_message(&voice).unwrap()),
    }));

    json!(vectors)
}

// ---------------------------------------------------------------------------
// Crypto test vectors
// ---------------------------------------------------------------------------

fn crypto_vectors() -> Value {
    let hp = host_public();
    let cp = client_public();

    let host_keys = derive_session_keys(PeerRole::Host, SESSION_ID, HOST_SECRET, cp).unwrap();

    let client_keys = derive_session_keys(PeerRole::Client, SESSION_ID, CLIENT_SECRET, hp).unwrap();

    // Verify symmetry
    assert_eq!(host_keys.tx, client_keys.rx);
    assert_eq!(host_keys.rx, client_keys.tx);

    // Host MAC
    let host_mac = compute_handshake_mac(&host_keys.tx, &hp, &cp, SESSION_ID);
    // Verify host MAC
    verify_handshake_mac(&client_keys.rx, &hp, &cp, SESSION_ID, &host_mac).unwrap();

    // Client MAC
    let client_mac = compute_handshake_mac(&client_keys.tx, &cp, &hp, SESSION_ID);
    // Verify client MAC
    verify_handshake_mac(&host_keys.rx, &cp, &hp, SESSION_ID, &client_mac).unwrap();

    // Encrypt a message with host keys (nonce=0)
    let plaintext =
        encode_secure_message(&SecureMessage::PtyOutput(b"test data".to_vec())).unwrap();
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&host_keys.tx).unwrap();
    use aes_gcm::aead::{Aead, KeyInit};
    let nonce_bytes = {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&0u64.to_be_bytes());
        n
    };
    let ciphertext = cipher
        .encrypt(&nonce_bytes.into(), plaintext.as_slice())
        .unwrap();

    json!({
        "session_id": SESSION_ID,
        "host_secret": hex::encode(HOST_SECRET),
        "host_public": hex::encode(hp),
        "client_secret": hex::encode(CLIENT_SECRET),
        "client_public": hex::encode(cp),
        "host_fingerprint": fingerprint(&hp),
        "client_fingerprint": fingerprint(&cp),
        "host_tx_key": hex::encode(host_keys.tx),
        "host_rx_key": hex::encode(host_keys.rx),
        "client_tx_key": hex::encode(client_keys.tx),
        "client_rx_key": hex::encode(client_keys.rx),
        "host_handshake_mac": hex::encode(host_mac),
        "client_handshake_mac": hex::encode(client_mac),
        "seal_test": {
            "plaintext": hex::encode(&plaintext),
            "nonce": 0,
            "nonce_bytes": hex::encode(nonce_bytes),
            "ciphertext": hex::encode(&ciphertext),
        }
    })
}

// ---------------------------------------------------------------------------
// Pairing test vectors
// ---------------------------------------------------------------------------

fn pairing_vectors() -> Value {
    let pairing = PairingUri {
        relay_url: "wss://relay.terminal-relay.dev/ws".to_string(),
        session_id: SESSION_ID.to_string(),
        pairing_code: "ABCDEF-GHIJKL-MNOPQR".to_string(),
        expected_fingerprint: Some(fingerprint(&host_public())),
        api_key: None,
    };
    let uri = build_pairing_uri(&pairing).unwrap();
    let parsed = parse_pairing_uri(&uri).unwrap();

    let pairing_no_fp = PairingUri {
        relay_url: "ws://localhost:8080/ws".to_string(),
        session_id: SESSION_ID.to_string(),
        pairing_code: "XYZXYZ-XYZXYZ-XYZXYZ".to_string(),
        expected_fingerprint: None,
        api_key: None,
    };
    let uri_no_fp = build_pairing_uri(&pairing_no_fp).unwrap();

    json!({
        "with_fingerprint": {
            "uri": uri,
            "relay_url": parsed.relay_url,
            "session_id": parsed.session_id,
            "pairing_code": parsed.pairing_code,
            "expected_fingerprint": parsed.expected_fingerprint,
        },
        "without_fingerprint": {
            "uri": uri_no_fp,
            "relay_url": pairing_no_fp.relay_url,
            "session_id": pairing_no_fp.session_id,
            "pairing_code": pairing_no_fp.pairing_code,
        }
    })
}

// ---------------------------------------------------------------------------
// Main test that prints everything
// ---------------------------------------------------------------------------

#[test]
fn generate_test_vectors() {
    let output = json!({
        "version": "1.0",
        "description": "Test vectors generated by protocol crate for cross-platform compatibility testing",
        "protocol": protocol_vectors(),
        "crypto": crypto_vectors(),
        "pairing": pairing_vectors(),
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
