use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::{RngCore, thread_rng};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    error::{CoreError, CoreResult},
    protocol::{
        PeerRole, SealedFrame, SecureMessage, decode_secure_message, encode_secure_message,
    },
};

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub tx: [u8; 32],
    pub rx: [u8; 32],
}

pub struct SecureChannel {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_nonce: u64,
    last_rx_nonce: Option<u64>,
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

    pub fn seal(&mut self, message: &SecureMessage) -> CoreResult<SealedFrame> {
        let plaintext = encode_secure_message(message)?;
        let nonce = self.tx_nonce;
        self.tx_nonce = self
            .tx_nonce
            .checked_add(1)
            .ok_or(CoreError::InvalidMessage("nonce exhausted"))?;
        let ciphertext = encrypt(&self.tx_key, nonce, &plaintext)?;
        Ok(SealedFrame { nonce, ciphertext })
    }

    pub fn open(&mut self, frame: &SealedFrame) -> CoreResult<SecureMessage> {
        if let Some(last_seen) = self.last_rx_nonce {
            if frame.nonce <= last_seen {
                return Err(CoreError::ReplayDetected);
            }
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
) -> CoreResult<SessionKeys> {
    let local = StaticSecret::from(local_secret);
    let remote = PublicKey::from(remote_public);
    let shared = local.diffie_hellman(&remote);

    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes());
    let mut okm = [0_u8; 64];
    hk.expand(b"terminal-relay/v1/channel-keys", &mut okm)
        .map_err(|_| CoreError::CryptoFailure)?;

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

fn encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> CoreResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::CryptoFailure)?;
    let nonce = nonce_from_counter(counter);
    cipher
        .encrypt(&nonce.into(), plaintext)
        .map_err(|_| CoreError::CryptoFailure)
}

fn decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> CoreResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::CryptoFailure)?;
    let nonce = nonce_from_counter(counter);
    cipher
        .decrypt(&nonce.into(), ciphertext)
        .map_err(|_| CoreError::CryptoFailure)
}

fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}
