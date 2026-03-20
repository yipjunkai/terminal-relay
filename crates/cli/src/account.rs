use std::io::{self, Write};

use anyhow::Context;
use serde::Deserialize;
use tokio::time::{Duration, sleep};

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

/// Response from POST /auth/device/code.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

/// Response from POST /auth/device/poll.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevicePollResponse {
    status: String,
    api_key: Option<String>,
    email: Option<String>,
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
/// Default (no flags): device authorization flow — opens browser, user enters code.
/// Fallbacks: --email + --invite-code for direct registration, --api-key for login.
pub async fn auth(
    email: Option<&str>,
    api_key: Option<&str>,
    invite_code: Option<&str>,
) -> anyhow::Result<()> {
    match (email, api_key) {
        (_, Some(key)) => login_with_key(key).await,
        (Some(email), None) => {
            let code = invite_code.ok_or_else(|| {
                anyhow::anyhow!(
                    "An invite code is required for registration.\n\
                     Usage: terminal-relay auth --email you@example.com --invite-code CODE"
                )
            })?;
            register_with_email(email, code).await
        }
        (None, None) => device_auth_flow().await,
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

// ── Device Authorization Flow ────────────────────────────────────────

async fn device_auth_flow() -> anyhow::Result<()> {
    let config = Config::load()?;
    let base_url = resolve_control_api_url(&config);
    let client = reqwest::Client::new();

    // Step 1: Request a device code.
    let resp = client
        .post(format!("{base_url}/auth/device/code"))
        .send()
        .await
        .context("failed to reach control API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("failed to request device code ({status}): {text}");
    }

    let device: DeviceCodeResponse = resp
        .json()
        .await
        .context("failed to parse device code response")?;

    // Step 2: Display instructions and open browser.
    println!();
    println!("  Open this URL in your browser:");
    println!();
    println!("    {}", device.verification_uri);
    println!();
    println!("  Then enter this code:");
    println!();
    println!("    {}", device.user_code);
    println!();

    // Try to open the browser (non-fatal if it fails).
    if let Err(e) = open::that(&device.verification_uri) {
        tracing::debug!("could not open browser: {e}");
    }

    // Step 3: Poll until activated or expired.
    let poll_interval = Duration::from_secs(device.interval.max(2));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(device.expires_in);
    let spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut tick = 0usize;

    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("device code expired — run `terminal-relay auth` to try again");
        }

        // Show spinner
        print!(
            "\r  {} Waiting for activation...",
            spinner[tick % spinner.len()]
        );
        io::stdout().flush().ok();
        tick += 1;

        sleep(poll_interval).await;

        let resp = client
            .post(format!("{base_url}/auth/device/poll"))
            .json(&serde_json::json!({ "deviceCode": device.device_code }))
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("poll request failed: {e}");
                continue; // Retry on transient errors.
            }
        };

        if !resp.status().is_success() {
            // Device code may have expired on the server side.
            let status = resp.status();
            if status.as_u16() == 400 {
                print!("\r");
                anyhow::bail!(
                    "device code expired or not found — run `terminal-relay auth` to try again"
                );
            }
            tracing::debug!("poll returned {status}");
            continue;
        }

        let poll: DevicePollResponse = match resp.json().await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("failed to parse poll response: {e}");
                continue;
            }
        };

        if poll.status == "complete" {
            // Clear the spinner line.
            print!("\r                                      \r");

            let api_key = poll
                .api_key
                .context("server returned complete but no API key")?;
            let email = poll.email.unwrap_or_else(|| "unknown".to_string());

            let mut config = Config::load()?;
            config.api_key = Some(api_key.clone());
            config.save()?;

            println!("  Authenticated as {email}");
            println!("  API key saved to ~/.terminal-relay/config.toml");
            println!();
            println!("  Your API key (save this — it won't be shown again):");
            println!("    {api_key}");
            println!();
            println!("  Get started:");
            println!("    terminal-relay start");
            return Ok(());
        }

        // status == "pending" — keep polling.
    }
}

// ── Direct registration / login (fallback) ───────────────────────────

async fn register_with_email(email: &str, invite_code: &str) -> anyhow::Result<()> {
    let config = Config::load()?;
    let base_url = resolve_control_api_url(&config);

    let client = reqwest::Client::new();
    let body = serde_json::json!({ "email": email, "inviteCode": invite_code });

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
