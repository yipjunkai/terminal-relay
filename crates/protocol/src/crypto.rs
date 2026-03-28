use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::{RngCore, thread_rng};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{Error, Result},
    wire::{PeerRole, SealedFrame, SecureMessage, decode_secure_message, encode_secure_message},
};

/// X25519 key pair. Not `Clone` — secret material should not be casually duplicated.
/// Secret bytes are zeroed on drop.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

/// Derived per-session TX/RX symmetric keys. Zeroed on drop.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub tx: [u8; 32],
    pub rx: [u8; 32],
}

/// Encrypts/decrypts frames using derived session keys. Key material is zeroed on drop.
pub struct SecureChannel {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_nonce: u64,
    last_rx_nonce: Option<u64>,
}

impl Drop for SecureChannel {
    fn drop(&mut self) {
        self.tx_key.zeroize();
        self.rx_key.zeroize();
    }
}

impl SecureChannel {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            tx_key: keys.tx,
            rx_key: keys.rx,
            tx_nonce: 0,
            last_rx_nonce: None,
        }
    }

    pub fn seal(&mut self, message: &SecureMessage) -> Result<SealedFrame> {
        let plaintext = encode_secure_message(message)?;
        let nonce = self.tx_nonce;
        self.tx_nonce = self
            .tx_nonce
            .checked_add(1)
            .ok_or(Error::InvalidMessage("nonce exhausted"))?;
        let ciphertext = encrypt(&self.tx_key, nonce, &plaintext)?;
        Ok(SealedFrame { nonce, ciphertext })
    }

    pub fn open(&mut self, frame: &SealedFrame) -> Result<SecureMessage> {
        if let Some(last_seen) = self.last_rx_nonce
            && frame.nonce <= last_seen
        {
            return Err(Error::ReplayDetected);
        }
        let plaintext = decrypt(&self.rx_key, frame.nonce, &frame.ciphertext)?;
        self.last_rx_nonce = Some(frame.nonce);
        decode_secure_message(&plaintext)
    }
}

pub fn generate_key_pair() -> KeyPair {
    let mut secret = [0_u8; 32];
    thread_rng().fill_bytes(&mut secret);
    let secret_key = StaticSecret::from(secret);
    let public = PublicKey::from(&secret_key).to_bytes();
    KeyPair { secret, public }
}

pub fn derive_session_keys(
    role: PeerRole,
    session_id: &str,
    local_secret: [u8; 32],
    remote_public: [u8; 32],
) -> Result<SessionKeys> {
    let local = StaticSecret::from(local_secret);
    let remote = PublicKey::from(remote_public);
    let shared = local.diffie_hellman(&remote);

    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes());
    let mut okm = [0_u8; 64];
    hk.expand(b"farwatch/v1/channel-keys", &mut okm)
        .map_err(|_| Error::CryptoFailure)?;

    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    first.copy_from_slice(&okm[..32]);
    second.copy_from_slice(&okm[32..]);

    let keys = match role {
        PeerRole::Host => SessionKeys {
            tx: first,
            rx: second,
        },
        PeerRole::Client => SessionKeys {
            tx: second,
            rx: first,
        },
    };

    okm.zeroize();
    Ok(keys)
}

pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[..8])
}

/// Maximum allowed age for a handshake timestamp (5 minutes).
pub const HANDSHAKE_MAX_AGE_MS: u64 = 5 * 60 * 1000;

/// Compute an HMAC-SHA256 over the handshake transcript using the derived TX key.
///
/// The transcript is: `local_public || remote_public || session_id`.
/// Each side computes this with their own public key first, so the MACs differ
/// and each side verifies the other's MAC using the *RX* key.
pub fn compute_handshake_mac(
    tx_key: &[u8; 32],
    local_public: &[u8; 32],
    remote_public: &[u8; 32],
    session_id: &str,
) -> [u8; 32] {
    use hmac::{Hmac, Mac};

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(tx_key).expect("HMAC accepts any key size");
    mac.update(local_public);
    mac.update(remote_public);
    mac.update(session_id.as_bytes());
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Verify a received handshake MAC using the RX key.
///
/// The remote peer computed the MAC with *their* TX key (which is *our* RX key)
/// over `remote_public || local_public || session_id`.
pub fn verify_handshake_mac(
    rx_key: &[u8; 32],
    remote_public: &[u8; 32],
    local_public: &[u8; 32],
    session_id: &str,
    received_mac: &[u8; 32],
) -> Result<()> {
    use hmac::{Hmac, Mac};

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(rx_key).expect("HMAC accepts any key size");
    mac.update(remote_public);
    mac.update(local_public);
    mac.update(session_id.as_bytes());
    mac.verify_slice(received_mac)
        .map_err(|_| Error::CryptoFailure)
}

fn encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::CryptoFailure)?;
    let nonce = nonce_from_counter(counter);
    cipher
        .encrypt(&nonce.into(), plaintext)
        .map_err(|_| Error::CryptoFailure)
}

fn decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::CryptoFailure)?;
    let nonce = nonce_from_counter(counter);
    cipher
        .decrypt(&nonce.into(), ciphertext)
        .map_err(|_| Error::CryptoFailure)
}

fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::SecureMessage;

    /// Helper: create a Host/Client SecureChannel pair from a fresh key exchange.
    fn make_channel_pair() -> (SecureChannel, SecureChannel) {
        let host_kp = generate_key_pair();
        let client_kp = generate_key_pair();
        let session_id = "test-session-id";

        let host_keys =
            derive_session_keys(PeerRole::Host, session_id, host_kp.secret, client_kp.public)
                .unwrap();

        let client_keys = derive_session_keys(
            PeerRole::Client,
            session_id,
            client_kp.secret,
            host_kp.public,
        )
        .unwrap();

        (
            SecureChannel::new(host_keys),
            SecureChannel::new(client_keys),
        )
    }

    #[test]
    fn seal_open_roundtrip() {
        let (mut host, mut client) = make_channel_pair();

        let msg = SecureMessage::PtyOutput(b"hello world".to_vec());
        let sealed = host.seal(&msg).unwrap();
        let opened = client.open(&sealed).unwrap();

        match opened {
            SecureMessage::PtyOutput(data) => assert_eq!(data, b"hello world"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn seal_open_bidirectional() {
        let (mut host, mut client) = make_channel_pair();

        // Host -> Client
        let sealed = host
            .seal(&SecureMessage::PtyOutput(b"from host".to_vec()))
            .unwrap();
        let opened = client.open(&sealed).unwrap();
        match opened {
            SecureMessage::PtyOutput(data) => assert_eq!(data, b"from host"),
            other => panic!("unexpected: {other:?}"),
        }

        // Client -> Host
        let sealed = client
            .seal(&SecureMessage::PtyInput(b"from client".to_vec()))
            .unwrap();
        let opened = host.open(&sealed).unwrap();
        match opened {
            SecureMessage::PtyInput(data) => assert_eq!(data, b"from client"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn seal_open_all_message_types() {
        let (mut host, mut client) = make_channel_pair();

        let messages: Vec<SecureMessage> = vec![
            SecureMessage::PtyInput(b"input".to_vec()),
            SecureMessage::PtyOutput(b"output".to_vec()),
            SecureMessage::Resize {
                cols: 120,
                rows: 40,
            },
            SecureMessage::Heartbeat,
            SecureMessage::VersionNotice {
                minimum_version: "0.2.0".to_string(),
            },
            SecureMessage::Notification(crate::wire::PushNotification {
                title: "Test".to_string(),
                body: "Hello".to_string(),
            }),
            SecureMessage::SessionEnded { exit_code: 0 },
            SecureMessage::Clipboard {
                content: "hello".to_string(),
            },
            SecureMessage::ReadOnly { enabled: true },
            SecureMessage::VoiceCommand(crate::wire::VoiceAction {
                transcript: "refactor this function".to_string(),
                intent: Some("refactor".to_string()),
                confidence: 0.95,
            }),
            SecureMessage::Unknown(vec![0xff, 0xfe]),
        ];

        for msg in &messages {
            let sealed = host.seal(msg).unwrap();
            let _ = client.open(&sealed).unwrap();
        }
    }

    #[test]
    fn replay_rejected() {
        let (mut host, mut client) = make_channel_pair();

        let msg = SecureMessage::Heartbeat;
        let sealed = host.seal(&msg).unwrap();

        // First open succeeds
        client.open(&sealed).unwrap();

        // Replaying the same frame fails
        let err = client.open(&sealed).unwrap_err();
        assert!(matches!(err, Error::ReplayDetected));
    }

    #[test]
    fn out_of_order_rejected() {
        let (mut host, mut client) = make_channel_pair();

        let frame0 = host.seal(&SecureMessage::Heartbeat).unwrap();
        let frame1 = host.seal(&SecureMessage::Heartbeat).unwrap();
        let frame2 = host.seal(&SecureMessage::Heartbeat).unwrap();

        // Accept frame2 first (skip ahead)
        client.open(&frame2).unwrap();

        // frame0 and frame1 should be rejected (nonce <= last_seen)
        assert!(matches!(
            client.open(&frame0),
            Err(Error::ReplayDetected)
        ));
        assert!(matches!(
            client.open(&frame1),
            Err(Error::ReplayDetected)
        ));
    }

    #[test]
    fn skipped_nonces_accepted() {
        let (mut host, mut client) = make_channel_pair();

        let frame0 = host.seal(&SecureMessage::Heartbeat).unwrap();
        let _frame1 = host.seal(&SecureMessage::Heartbeat).unwrap(); // skip this one
        let frame2 = host.seal(&SecureMessage::Heartbeat).unwrap();

        client.open(&frame0).unwrap();
        // Skipping frame1, frame2 should still work (nonce 2 > 0)
        client.open(&frame2).unwrap();
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let (mut host, _client) = make_channel_pair();
        let (_, mut wrong_client) = make_channel_pair();

        let sealed = host.seal(&SecureMessage::Heartbeat).unwrap();
        assert!(wrong_client.open(&sealed).is_err());
    }

    #[test]
    fn nonce_increments() {
        let (mut host, mut client) = make_channel_pair();

        for expected_nonce in 0..10u64 {
            let sealed = host.seal(&SecureMessage::Heartbeat).unwrap();
            assert_eq!(sealed.nonce, expected_nonce);
            client.open(&sealed).unwrap();
        }
    }

    #[test]
    fn key_derivation_host_client_symmetric() {
        let host_kp = generate_key_pair();
        let client_kp = generate_key_pair();
        let session_id = "symmetric-test";

        let host_keys =
            derive_session_keys(PeerRole::Host, session_id, host_kp.secret, client_kp.public)
                .unwrap();

        let client_keys = derive_session_keys(
            PeerRole::Client,
            session_id,
            client_kp.secret,
            host_kp.public,
        )
        .unwrap();

        // Host's TX should be Client's RX and vice versa
        assert_eq!(host_keys.tx, client_keys.rx);
        assert_eq!(host_keys.rx, client_keys.tx);
    }

    #[test]
    fn different_sessions_produce_different_keys() {
        let host_kp = generate_key_pair();
        let client_kp = generate_key_pair();

        let keys_a = derive_session_keys(
            PeerRole::Host,
            "session-a",
            host_kp.secret,
            client_kp.public,
        )
        .unwrap();

        let keys_b = derive_session_keys(
            PeerRole::Host,
            "session-b",
            host_kp.secret,
            client_kp.public,
        )
        .unwrap();

        assert_ne!(keys_a.tx, keys_b.tx);
        assert_ne!(keys_a.rx, keys_b.rx);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let kp = generate_key_pair();
        let fp1 = fingerprint(&kp.public);
        let fp2 = fingerprint(&kp.public);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_is_hex_16_chars() {
        let kp = generate_key_pair();
        let fp = fingerprint(&kp.public);
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_keys_different_fingerprints() {
        let kp1 = generate_key_pair();
        let kp2 = generate_key_pair();
        assert_ne!(fingerprint(&kp1.public), fingerprint(&kp2.public));
    }

    #[test]
    fn nonce_from_counter_layout() {
        // First 4 bytes should be zero, last 8 should be big-endian counter
        let nonce = nonce_from_counter(0x0102030405060708);
        assert_eq!(&nonce[..4], &[0, 0, 0, 0]);
        assert_eq!(&nonce[4..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"test data";
        let ciphertext = encrypt(&key, 0, plaintext).unwrap();
        let decrypted = decrypt(&key, 0, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let mut ciphertext = encrypt(&key, 0, b"test").unwrap();
        // Flip a byte
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xff;
        }
        assert!(decrypt(&key, 0, &ciphertext).is_err());
    }

    // ── Handshake MAC tests ──

    #[test]
    fn handshake_mac_verify_roundtrip() {
        let host_kp = generate_key_pair();
        let client_kp = generate_key_pair();
        let session_id = "mac-test";

        let host_keys =
            derive_session_keys(PeerRole::Host, session_id, host_kp.secret, client_kp.public)
                .unwrap();
        let client_keys = derive_session_keys(
            PeerRole::Client,
            session_id,
            client_kp.secret,
            host_kp.public,
        )
        .unwrap();

        // Host computes MAC with its TX key over (host_pub || client_pub || session_id)
        let host_mac = compute_handshake_mac(
            &host_keys.tx,
            &host_kp.public,
            &client_kp.public,
            session_id,
        );

        // Client verifies using its RX key (== host's TX key)
        // with (host_pub || client_pub || session_id) — note the order matches host's compute
        verify_handshake_mac(
            &client_keys.rx,
            &host_kp.public,
            &client_kp.public,
            session_id,
            &host_mac,
        )
        .expect("client should verify host MAC");

        // Client computes MAC with its TX key over (client_pub || host_pub || session_id)
        let client_mac = compute_handshake_mac(
            &client_keys.tx,
            &client_kp.public,
            &host_kp.public,
            session_id,
        );

        // Host verifies using its RX key (== client's TX key)
        verify_handshake_mac(
            &host_keys.rx,
            &client_kp.public,
            &host_kp.public,
            session_id,
            &client_mac,
        )
        .expect("host should verify client MAC");
    }

    #[test]
    fn handshake_mac_rejects_wrong_mac() {
        let host_kp = generate_key_pair();
        let client_kp = generate_key_pair();
        let session_id = "mac-reject-test";

        let host_keys =
            derive_session_keys(PeerRole::Host, session_id, host_kp.secret, client_kp.public)
                .unwrap();
        let client_keys = derive_session_keys(
            PeerRole::Client,
            session_id,
            client_kp.secret,
            host_kp.public,
        )
        .unwrap();

        let host_mac = compute_handshake_mac(
            &host_keys.tx,
            &host_kp.public,
            &client_kp.public,
            session_id,
        );

        // Tamper with the MAC
        let mut bad_mac = host_mac;
        bad_mac[0] ^= 0xff;

        assert!(
            verify_handshake_mac(
                &client_keys.rx,
                &host_kp.public,
                &client_kp.public,
                session_id,
                &bad_mac,
            )
            .is_err()
        );
    }

    #[test]
    fn handshake_mac_host_and_client_differ() {
        let host_kp = generate_key_pair();
        let client_kp = generate_key_pair();
        let session_id = "mac-differ-test";

        let host_keys =
            derive_session_keys(PeerRole::Host, session_id, host_kp.secret, client_kp.public)
                .unwrap();
        let client_keys = derive_session_keys(
            PeerRole::Client,
            session_id,
            client_kp.secret,
            host_kp.public,
        )
        .unwrap();

        let host_mac = compute_handshake_mac(
            &host_keys.tx,
            &host_kp.public,
            &client_kp.public,
            session_id,
        );
        let client_mac = compute_handshake_mac(
            &client_keys.tx,
            &client_kp.public,
            &host_kp.public,
            session_id,
        );

        // The two MACs must differ (different keys, different transcript order)
        assert_ne!(host_mac, client_mac);
    }
}
