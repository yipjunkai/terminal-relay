use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Typed errors for session state operations.
#[derive(Debug)]
pub enum StateError {
    /// Filesystem I/O failure (read, write, mkdir, permissions).
    Io { context: String, source: io::Error },
    /// State encryption key is invalid (wrong length or corrupt).
    InvalidKey,
    /// State key file has wrong length.
    InvalidKeyLength { actual: usize },
    /// AES-GCM encryption failed.
    EncryptionFailed,
    /// AES-GCM decryption failed (wrong key or corrupted file).
    DecryptionFailed,
    /// Encrypted file is too short to contain nonce + ciphertext.
    FileTooShort,
    /// JSON serialization failed.
    Serialize(serde_json::Error),
    /// JSON deserialization failed.
    Deserialize(serde_json::Error),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::InvalidKey => write!(f, "invalid state encryption key"),
            Self::InvalidKeyLength { actual } => {
                write!(
                    f,
                    "state key file has invalid length {actual} (expected 32)"
                )
            }
            Self::EncryptionFailed => write!(f, "state encryption failed"),
            Self::DecryptionFailed => {
                write!(f, "state decryption failed (wrong key or corrupted file)")
            }
            Self::FileTooShort => write!(f, "encrypted state file too short"),
            Self::Serialize(e) => write!(f, "failed serializing session record: {e}"),
            Self::Deserialize(e) => write!(f, "failed parsing session state: {e}"),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialize(e) | Self::Deserialize(e) => Some(e),
            _ => None,
        }
    }
}

/// Helper to wrap io::Error with context.
fn io_err(context: impl Into<String>, source: io::Error) -> StateError {
    StateError::Io {
        context: context.into(),
        source,
    }
}

type StateResult<T> = Result<T, StateError>;

#[derive(Serialize, Deserialize)]
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
    pub(crate) secret_key: [u8; 32],
}

impl SessionRecord {
    /// Access the secret key. Prefer passing by reference to avoid copies.
    #[allow(dead_code)] // Used in tests; will be used by session resume
    pub(crate) fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }
}

impl std::fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRecord")
            .field("session_id", &self.session_id)
            .field("relay_url", &self.relay_url)
            .field("pairing_code", &self.pairing_code)
            .field("resume_token", &"[REDACTED]")
            .field("tool", &self.tool)
            .field("command", &self.command)
            .field("command_args", &self.command_args)
            .field("created_at", &self.created_at)
            .field("public_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SessionRecord {
    fn drop(&mut self) {
        self.secret_key.zeroize();
        self.public_key.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    root: PathBuf,
    /// AES-256-GCM key for encrypting session state files at rest.
    state_key: [u8; 32],
}

/// File header written before the ciphertext so we can detect encrypted vs legacy files.
const ENCRYPTED_MAGIC: &[u8; 4] = b"FWSE"; // Farwatch Session Encrypted

impl SessionStore {
    pub fn new(root: PathBuf) -> StateResult<Self> {
        ensure_dir(&root)?;
        set_dir_permissions(&root)?;

        let sessions = root.join("sessions");
        ensure_dir(&sessions)?;
        set_dir_permissions(&sessions)?;

        let state_key = load_or_create_state_key(&root)?;
        Ok(Self { root, state_key })
    }

    pub fn save(&self, record: &SessionRecord) -> StateResult<()> {
        let plaintext = serde_json::to_vec_pretty(record).map_err(StateError::Serialize)?;
        let ciphertext = seal_state(&self.state_key, &plaintext)?;

        let path = self.record_path(&record.session_id);
        fs::write(&path, &ciphertext).map_err(|e| {
            io_err(
                format!("failed writing session state {}", path.display()),
                e,
            )
        })?;
        set_file_permissions(&path)?;
        Ok(())
    }

    #[allow(dead_code)] // Used in tests; will be used by session resume
    pub fn load(&self, session_id: &str) -> StateResult<SessionRecord> {
        let path = self.record_path(session_id);
        let bytes = fs::read(&path).map_err(|e| {
            io_err(
                format!("failed reading session state {}", path.display()),
                e,
            )
        })?;
        let plaintext = open_state_or_legacy(&self.state_key, &bytes)?;
        serde_json::from_slice(&plaintext).map_err(StateError::Deserialize)
    }

    #[allow(dead_code)] // Used in tests; will be used by session management
    pub fn list(&self) -> StateResult<Vec<SessionRecord>> {
        let dir = self.sessions_dir();
        let mut records = Vec::new();
        for entry in
            fs::read_dir(&dir).map_err(|e| io_err("failed reading sessions directory", e))?
        {
            let entry = entry.map_err(|e| io_err("failed reading directory entry", e))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    match self.load(stem) {
                        Ok(record) => records.push(record),
                        Err(e) => {
                            tracing::warn!("skipping session file {}: {e}", path.display());
                        }
                    }
                }
            }
        }
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
fn seal_state(key: &[u8; 32], plaintext: &[u8]) -> StateResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| StateError::InvalidKey)?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&nonce.into(), plaintext)
        .map_err(|_| StateError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(4 + 12 + ciphertext.len());
    out.extend_from_slice(ENCRYPTED_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt an at-rest file, or fall back to treating it as legacy plaintext JSON.
fn open_state_or_legacy(key: &[u8; 32], bytes: &[u8]) -> StateResult<Vec<u8>> {
    if bytes.len() >= 4 && &bytes[..4] == ENCRYPTED_MAGIC {
        if bytes.len() < 4 + 12 {
            return Err(StateError::FileTooShort);
        }
        let nonce: [u8; 12] = bytes[4..16].try_into().unwrap();
        let ciphertext = &bytes[16..];
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| StateError::InvalidKey)?;
        let plaintext = cipher
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|_| StateError::DecryptionFailed)?;
        Ok(plaintext)
    } else {
        // Legacy unencrypted JSON — return as-is.
        Ok(bytes.to_vec())
    }
}

// ── State key management ──

/// Load the state encryption key from `<root>/state.key`, or generate and persist one.
fn load_or_create_state_key(root: &Path) -> StateResult<[u8; 32]> {
    let key_path = root.join("state.key");
    if key_path.exists() {
        let bytes = fs::read(&key_path).map_err(|e| io_err("failed reading state key", e))?;
        if bytes.len() != 32 {
            return Err(StateError::InvalidKeyLength {
                actual: bytes.len(),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    } else {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        fs::write(&key_path, key).map_err(|e| io_err("failed writing state key", e))?;
        set_file_permissions(&key_path)?;
        Ok(key)
    }
}

// ── File permissions (Unix) ──

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> StateResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
        io_err(
            format!("failed setting permissions on {}", path.display()),
            e,
        )
    })
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> StateResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        io_err(
            format!("failed setting permissions on {}", path.display()),
            e,
        )
    })
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> StateResult<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> StateResult<()> {
    Ok(())
}

fn ensure_dir(path: &Path) -> StateResult<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .map_err(|e| io_err(format!("failed creating directory {}", path.display()), e))?;
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
        assert_eq!(*loaded.secret_key(), [2u8; 32]);
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
        let mut ids: Vec<String> = records.iter().map(|r| r.session_id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
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

    #[test]
    fn encrypted_file_too_short_returns_error() {
        let (dir, store) = temp_store();
        let path = dir.path().join("sessions/short.json");
        // Magic header but no nonce (less than 16 bytes total)
        let mut data = ENCRYPTED_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 4]); // only 8 bytes total, need 16
        fs::write(&path, &data).unwrap();

        let err = store.load("short").unwrap_err();
        assert!(matches!(err, StateError::FileTooShort));
    }

    #[test]
    fn load_nonexistent_session_returns_io_error() {
        let (_dir, store) = temp_store();
        let err = store.load("nonexistent").unwrap_err();
        assert!(matches!(err, StateError::Io { .. }));
    }

    #[test]
    fn session_record_debug_redacts_secrets() {
        let record = sample_record("redact-test");
        let debug_output = format!("{:?}", record);
        assert!(debug_output.contains("[REDACTED]"));
        // Ensure actual key bytes don't appear as decimal arrays
        assert!(!debug_output.contains("[2, 2, 2"));
        assert!(!debug_output.contains("[1, 1, 1"));
    }

    #[test]
    fn state_error_display_contains_context() {
        let io_err = StateError::Io {
            context: "reading key".into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };
        assert!(io_err.to_string().contains("reading key"));

        let key_err = StateError::InvalidKeyLength { actual: 16 };
        assert!(key_err.to_string().contains("16"));

        let decrypt_err = StateError::DecryptionFailed;
        assert!(
            decrypt_err.to_string().contains("wrong key")
                || decrypt_err.to_string().contains("corrupted")
        );
    }

    #[test]
    fn invalid_key_length_error() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-create directory structure
        fs::create_dir_all(dir.path().join("sessions")).unwrap();
        // Write a state.key with wrong length
        fs::write(dir.path().join("state.key"), &[0u8; 16]).unwrap();

        let err = SessionStore::new(dir.path().to_path_buf()).unwrap_err();
        assert!(matches!(err, StateError::InvalidKeyLength { actual: 16 }));
    }
}
