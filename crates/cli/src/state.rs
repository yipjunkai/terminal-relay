use std::{
    fs,
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use anyhow::Context;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub relay_url: String,
    pub pairing_code: String,
    pub resume_token: String,
    pub tool: String,
    pub command: String,
    pub command_args: Vec<String>,
    pub created_at: String,
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    root: PathBuf,
    /// AES-256-GCM key for encrypting session state files at rest.
    state_key: [u8; 32],
}

/// File header written before the ciphertext so we can detect encrypted vs legacy files.
const ENCRYPTED_MAGIC: &[u8; 4] = b"TRSE"; // Terminal Relay Session Encrypted

impl SessionStore {
    pub fn new(root: PathBuf) -> anyhow::Result<Self> {
        ensure_dir(&root)?;
        set_dir_permissions(&root)?;

        let sessions = root.join("sessions");
        ensure_dir(&sessions)?;
        set_dir_permissions(&sessions)?;

        let state_key = load_or_create_state_key(&root)?;
        Ok(Self { root, state_key })
    }

    pub fn save(&self, record: &SessionRecord) -> anyhow::Result<()> {
        let plaintext =
            serde_json::to_vec_pretty(record).context("failed serializing session record")?;
        let ciphertext = seal_state(&self.state_key, &plaintext)?;

        let path = self.record_path(&record.session_id);
        fs::write(&path, &ciphertext)
            .with_context(|| format!("failed writing session state {}", path.display()))?;
        set_file_permissions(&path)?;
        Ok(())
    }

    #[allow(dead_code)] // Used in tests; will be used by session resume
    pub fn load(&self, session_id: &str) -> anyhow::Result<SessionRecord> {
        let path = self.record_path(session_id);
        let bytes = fs::read(&path)
            .with_context(|| format!("failed reading session state {}", path.display()))?;
        let plaintext = open_state_or_legacy(&self.state_key, &bytes)?;
        serde_json::from_slice(&plaintext).context("failed parsing session state")
    }

    pub fn list(&self) -> anyhow::Result<Vec<SessionRecord>> {
        let mut records = Vec::new();
        for entry in
            fs::read_dir(self.sessions_dir()).context("failed reading sessions directory")?
        {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let plaintext = match open_state_or_legacy(&self.state_key, &bytes) {
                Ok(p) => p,
                Err(err) => {
                    tracing::warn!(
                        path = %entry.path().display(),
                        error = %err,
                        "skipping unreadable session file"
                    );
                    continue;
                }
            };
            let record: SessionRecord = serde_json::from_slice(&plaintext)?;
            records.push(record);
        }
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(records)
    }

    fn sessions_dir(&self) -> PathBuf {
        self.root.join("sessions")
    }

    fn record_path(&self, session_id: &str) -> PathBuf {
        self.sessions_dir().join(format!("{session_id}.json"))
    }
}

impl Drop for SessionStore {
    fn drop(&mut self) {
        self.state_key.zeroize();
    }
}

// ── State encryption ──

/// Encrypt plaintext for at-rest storage: `MAGIC || nonce (12) || ciphertext`.
fn seal_state(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("bad state key"))?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&nonce.into(), plaintext)
        .map_err(|_| anyhow::anyhow!("state encryption failed"))?;

    let mut out = Vec::with_capacity(4 + 12 + ciphertext.len());
    out.extend_from_slice(ENCRYPTED_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt an at-rest file, or fall back to treating it as legacy plaintext JSON.
fn open_state_or_legacy(key: &[u8; 32], bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    if bytes.len() >= 4 && &bytes[..4] == ENCRYPTED_MAGIC {
        if bytes.len() < 4 + 12 {
            anyhow::bail!("encrypted state file too short");
        }
        let nonce: [u8; 12] = bytes[4..16].try_into().unwrap();
        let ciphertext = &bytes[16..];
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("bad state key"))?;
        let plaintext = cipher
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|_| anyhow::anyhow!("state decryption failed (wrong key or corrupted)"))?;
        Ok(plaintext)
    } else {
        // Legacy unencrypted JSON — return as-is.
        Ok(bytes.to_vec())
    }
}

// ── State key management ──

/// Load the state encryption key from `<root>/state.key`, or generate and persist one.
fn load_or_create_state_key(root: &Path) -> anyhow::Result<[u8; 32]> {
    let key_path = root.join("state.key");
    if key_path.exists() {
        let bytes = fs::read(&key_path).context("failed reading state key")?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "state key file has invalid length {} (expected 32)",
                bytes.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    } else {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        fs::write(&key_path, key).context("failed writing state key")?;
        set_file_permissions(&key_path)?;
        Ok(key)
    }
}

// ── File permissions (Unix) ──

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed setting permissions on {}", path.display()))
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed setting permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("failed creating directory {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_store() -> (tempfile::TempDir, SessionStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf()).unwrap();
        (dir, store)
    }

    fn sample_record(id: &str) -> SessionRecord {
        SessionRecord {
            session_id: id.to_string(),
            relay_url: "ws://localhost:8080/ws".to_string(),
            pairing_code: "ABC123-DEF456-GHI789".to_string(),
            resume_token: "token".to_string(),
            tool: "claude".to_string(),
            command: "claude".to_string(),
            command_args: vec![],
            created_at: "unix:1700000000".to_string(),
            public_key: [1u8; 32],
            secret_key: [2u8; 32],
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let (_dir, store) = temp_store();
        let record = sample_record("sess-1");
        store.save(&record).unwrap();
        let loaded = store.load("sess-1").unwrap();
        assert_eq!(loaded.session_id, "sess-1");
        assert_eq!(loaded.secret_key, [2u8; 32]);
        assert_eq!(loaded.public_key, [1u8; 32]);
    }

    #[test]
    fn saved_file_is_encrypted() {
        let (dir, store) = temp_store();
        let record = sample_record("sess-enc");
        store.save(&record).unwrap();

        let path = dir.path().join("sessions/sess-enc.json");
        let raw = fs::read(&path).unwrap();
        // Should start with our magic header, not '{' (JSON)
        assert_eq!(&raw[..4], ENCRYPTED_MAGIC);
        // Should not contain plaintext secret key or session id
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("sess-enc"));
    }

    #[test]
    fn legacy_plaintext_still_loads() {
        let (dir, store) = temp_store();
        let record = sample_record("sess-legacy");
        // Write as plaintext JSON directly (simulating pre-encryption state)
        let json = serde_json::to_vec_pretty(&record).unwrap();
        let path = dir.path().join("sessions/sess-legacy.json");
        fs::write(&path, &json).unwrap();

        let loaded = store.load("sess-legacy").unwrap();
        assert_eq!(loaded.session_id, "sess-legacy");
    }

    #[test]
    fn list_returns_saved_records() {
        let (_dir, store) = temp_store();
        store.save(&sample_record("a")).unwrap();
        store.save(&sample_record("b")).unwrap();
        let records = store.list().unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn state_key_persists_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let store1 = SessionStore::new(dir.path().to_path_buf()).unwrap();
        store1.save(&sample_record("persist-test")).unwrap();
        drop(store1);

        // New store instance should use the same key and decrypt successfully
        let store2 = SessionStore::new(dir.path().to_path_buf()).unwrap();
        let loaded = store2.load("persist-test").unwrap();
        assert_eq!(loaded.session_id, "persist-test");
    }

    #[cfg(unix)]
    #[test]
    fn file_permissions_are_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, store) = temp_store();
        store.save(&sample_record("perm-test")).unwrap();

        let key_path = dir.path().join("state.key");
        let key_mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600, "state.key should be 0600");

        let session_path = dir.path().join("sessions/perm-test.json");
        let session_mode = fs::metadata(&session_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(session_mode, 0o600, "session file should be 0600");

        let root_mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o700, "root dir should be 0700");
    }

    #[test]
    fn corrupted_file_returns_error() {
        let (dir, store) = temp_store();
        let path = dir.path().join("sessions/corrupt.json");
        // Write data with magic header but garbage content
        let mut garbage = ENCRYPTED_MAGIC.to_vec();
        garbage.extend_from_slice(&[0u8; 20]);
        fs::write(&path, &garbage).unwrap();

        assert!(store.load("corrupt").is_err());
    }
}
