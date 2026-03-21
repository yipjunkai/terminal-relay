use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::constants::STATE_DIR_NAME;

const CONFIG_FILE: &str = "config.toml";

/// User configuration persisted in `~/.terminal-relay/config.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Default AI tool to use when `--tool` is not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_tool: Option<String>,
    /// API key for authenticating with the hosted relay.
    #[cfg(feature = "hosted")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Control API base URL (for register/login).
    #[cfg(feature = "hosted")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_api_url: Option<String>,
}

impl Config {
    /// Load config from `~/.terminal-relay/config.toml`, or return defaults if missing.
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed reading config from {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed parsing config from {}", path.display()))?;
        Ok(config)
    }

    /// Save config to `~/.terminal-relay/config.toml`.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating config dir {}", parent.display()))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).ok();
            }
        }
        let content = toml::to_string_pretty(self).context("failed serializing config")?;
        fs::write(&path, content)
            .with_context(|| format!("failed writing config to {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();
        }

        Ok(())
    }
}

fn config_path() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("failed resolving home directory")?;
    Ok(home.join(STATE_DIR_NAME).join(CONFIG_FILE))
}
