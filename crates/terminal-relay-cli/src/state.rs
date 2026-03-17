use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

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
}

impl SessionStore {
    pub fn new(root: PathBuf) -> anyhow::Result<Self> {
        if !root.exists() {
            fs::create_dir_all(&root)
                .with_context(|| format!("failed creating state directory {}", root.display()))?;
        }
        let sessions = root.join("sessions");
        if !sessions.exists() {
            fs::create_dir_all(&sessions).with_context(|| {
                format!("failed creating sessions directory {}", sessions.display())
            })?;
        }
        Ok(Self { root })
    }

    pub fn save(&self, record: &SessionRecord) -> anyhow::Result<()> {
        let bytes =
            serde_json::to_vec_pretty(record).context("failed serializing session record")?;
        let path = self.record_path(&record.session_id);
        fs::write(&path, bytes)
            .with_context(|| format!("failed writing session state {}", path.display()))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn load(&self, session_id: &str) -> anyhow::Result<SessionRecord> {
        let path = self.record_path(session_id);
        let bytes = fs::read(&path)
            .with_context(|| format!("failed reading session state {}", path.display()))?;
        serde_json::from_slice(&bytes).context("failed parsing session state")
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
            let record: SessionRecord = serde_json::from_slice(&bytes)?;
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

#[allow(dead_code)]
pub fn ensure_path_exists(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("failed creating directory {}", path.display()))?;
    }
    Ok(())
}
