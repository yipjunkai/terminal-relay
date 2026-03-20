use anyhow::Context;
use serde::Deserialize;

use crate::config::Config;
use crate::constants::{CONTROL_API_URL_ENV, DEFAULT_CONTROL_API_URL};

/// Response from POST /auth/register.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterResponse {
    #[allow(dead_code)]
    access_token: String,
    api_key: String,
    user: UserInfo,
}

/// Response from POST /auth/login.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    #[allow(dead_code)]
    access_token: String,
    user: UserInfo,
}

#[derive(Deserialize)]
struct UserInfo {
    #[allow(dead_code)]
    id: String,
    email: String,
    #[allow(dead_code)]
    name: Option<String>,
}

/// Resolve the control API URL: env var → config file → default.
fn resolve_control_api_url(config: &Config) -> String {
    if let Ok(url) = std::env::var(CONTROL_API_URL_ENV) {
        return url;
    }
    config
        .control_api_url
        .clone()
        .unwrap_or_else(|| DEFAULT_CONTROL_API_URL.to_string())
}

/// Authenticate with the control API.
///
/// Current implementation: email-based registration or API key login.
/// Planned: device authorization flow (open browser, enter code, poll for completion).
pub async fn auth(email: Option<&str>, api_key: Option<&str>) -> anyhow::Result<()> {
    match (email, api_key) {
        (_, Some(key)) => login_with_key(key).await,
        (Some(email), None) => register_with_email(email).await,
        (None, None) => {
            // TODO: Replace with device authorization flow.
            // For now, prompt the user to provide email or API key.
            println!("Authenticate with Terminal Relay:\n");
            println!("  New user:      terminal-relay auth --email you@example.com");
            println!("  Existing key:  terminal-relay auth --api-key tr_...");
            println!("\nIn a future version, this will open your browser for login.");
            Ok(())
        }
    }
}

/// Log out by removing the stored API key.
pub fn logout() -> anyhow::Result<()> {
    let mut config = Config::load()?;
    if config.api_key.is_none() {
        println!("Not logged in.");
        return Ok(());
    }
    config.api_key = None;
    config.save()?;
    println!("Logged out. API key removed from ~/.terminal-relay/config.toml");
    Ok(())
}

async fn register_with_email(email: &str) -> anyhow::Result<()> {
    let config = Config::load()?;
    let base_url = resolve_control_api_url(&config);

    let client = reqwest::Client::new();
    let body = serde_json::json!({ "email": email });

    let resp = client
        .post(format!("{base_url}/auth/register"))
        .json(&body)
        .send()
        .await
        .context("failed to reach control API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("registration failed ({status}): {text}");
    }

    let data: RegisterResponse = resp.json().await.context("failed to parse response")?;

    let mut config = Config::load()?;
    config.api_key = Some(data.api_key.clone());
    config.save()?;

    println!("Authenticated as {}", data.user.email);
    println!("API key saved to ~/.terminal-relay/config.toml");
    println!("\nYour API key (save this — it won't be shown again):");
    println!("  {}", data.api_key);

    Ok(())
}

async fn login_with_key(api_key: &str) -> anyhow::Result<()> {
    let config = Config::load()?;
    let base_url = resolve_control_api_url(&config);

    let client = reqwest::Client::new();
    let body = serde_json::json!({ "apiKey": api_key });

    let resp = client
        .post(format!("{base_url}/auth/login"))
        .json(&body)
        .send()
        .await
        .context("failed to reach control API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("login failed ({status}): {text}");
    }

    let data: LoginResponse = resp.json().await.context("failed to parse response")?;

    let mut config = Config::load()?;
    config.api_key = Some(api_key.to_string());
    config.save()?;

    println!("Authenticated as {}", data.user.email);
    println!("API key saved to ~/.terminal-relay/config.toml");

    Ok(())
}
