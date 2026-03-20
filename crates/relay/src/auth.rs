use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// Decoded payload from a signed API key.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ApiKeyPayload {
    /// User ID (UUID).
    pub uid: String,
    /// Key ID (UUID) — used for revocation checks.
    pub kid: String,
    /// Pricing tier (e.g. "free", "pro").
    pub tier: String,
    /// Issued-at timestamp (unix seconds).
    #[allow(dead_code)]
    pub iat: u64,
}

/// Handles API key verification and revocation list management.
pub struct AuthState {
    /// Current HMAC secret for verifying signed API keys.
    hmac_secret: Vec<u8>,
    /// Previous HMAC secret (for rotation). Optional.
    hmac_secret_previous: Option<Vec<u8>>,
    /// Set of revoked key IDs, synced periodically from the control API.
    revoked_keys: RwLock<HashSet<String>>,
    /// Control API base URL for fetching revocation lists and reporting.
    control_api_url: Option<String>,
    /// Shared secret for authenticating with the control API.
    internal_secret: Option<String>,
    /// HTTP client for control API requests.
    http: reqwest::Client,
}

impl AuthState {
    pub fn new(
        hmac_secret: String,
        hmac_secret_previous: Option<String>,
        control_api_url: Option<String>,
        internal_secret: Option<String>,
    ) -> Self {
        Self {
            hmac_secret: hmac_secret.into_bytes(),
            hmac_secret_previous: hmac_secret_previous.map(|s| s.into_bytes()),
            revoked_keys: RwLock::new(HashSet::new()),
            control_api_url,
            internal_secret,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    /// Verify a signed API key and return the decoded payload.
    /// Returns None if the key is invalid, has a bad signature, or is revoked.
    pub async fn verify_api_key(&self, raw_key: &str) -> Option<ApiKeyPayload> {
        if !raw_key.starts_with("tr_") {
            return None;
        }

        let decoded = URL_SAFE_NO_PAD.decode(&raw_key[3..]).ok()?;
        let decoded_str = std::str::from_utf8(&decoded).ok()?;

        let dot_index = decoded_str.rfind('.')?;
        let payload_json = &decoded_str[..dot_index];
        let provided_sig = &decoded_str[dot_index + 1..];

        // Try current secret, then previous (for rotation)
        let valid = self.verify_hmac(&self.hmac_secret, payload_json, provided_sig)
            || self
                .hmac_secret_previous
                .as_ref()
                .is_some_and(|prev| self.verify_hmac(prev, payload_json, provided_sig));

        if !valid {
            return None;
        }

        let payload: ApiKeyPayload = serde_json::from_str(payload_json).ok()?;

        // Check revocation list
        let revoked = self.revoked_keys.read().await;
        if revoked.contains(&payload.kid) {
            debug!(key_id = %payload.kid, "API key is revoked");
            return None;
        }

        Some(payload)
    }

    /// Verify HMAC-SHA256 signature (constant-time comparison via hmac crate).
    fn verify_hmac(&self, secret: &[u8], payload_json: &str, provided_sig: &str) -> bool {
        let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
            return false;
        };
        mac.update(payload_json.as_bytes());

        let expected_sig = hex::encode(mac.finalize().into_bytes());
        constant_time_eq(expected_sig.as_bytes(), provided_sig.as_bytes())
    }

    /// Periodically sync the revocation list from the control API.
    pub async fn revocation_sync_loop(self: Arc<Self>) {
        let Some(ref base_url) = self.control_api_url else {
            info!("no CONTROL_API_URL configured, skipping revocation sync");
            return;
        };
        let Some(ref secret) = self.internal_secret else {
            warn!("no INTERNAL_SECRET configured, skipping revocation sync");
            return;
        };

        let url = format!("{}/internal/revoked-keys", base_url);
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            match self
                .http
                .get(&url)
                .header("x-internal-secret", secret)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<RevokedKeysResponse>().await {
                        Ok(body) => {
                            let count = body.revoked_key_ids.len();
                            let mut set = self.revoked_keys.write().await;
                            *set = body.revoked_key_ids.into_iter().collect();
                            debug!(count, "revocation list synced");
                        }
                        Err(err) => {
                            warn!(error = %err, "failed to parse revocation response");
                        }
                    }
                }
                Ok(resp) => {
                    warn!(status = %resp.status(), "revocation sync got non-success status");
                }
                Err(err) => {
                    warn!(error = %err, "revocation sync request failed");
                }
            }
        }
    }

    /// Report a session start to the control API.
    pub async fn report_session_started(
        &self,
        session_id: &str,
        user_id: &str,
        tool_name: Option<&str>,
    ) {
        let Some(ref base_url) = self.control_api_url else {
            return;
        };
        let Some(ref secret) = self.internal_secret else {
            return;
        };

        let url = format!("{}/internal/session-started", base_url);
        let body = serde_json::json!({
            "sessionId": session_id,
            "userId": user_id,
            "toolName": tool_name,
        });

        if let Err(err) = self
            .http
            .post(&url)
            .header("x-internal-secret", secret)
            .json(&body)
            .send()
            .await
        {
            warn!(error = %err, "failed to report session start");
        }
    }

    /// Report a session end to the control API.
    pub async fn report_session_ended(
        &self,
        session_id: &str,
        user_id: &str,
        bytes_up: u64,
        bytes_down: u64,
        duration_ms: u64,
    ) {
        let Some(ref base_url) = self.control_api_url else {
            return;
        };
        let Some(ref secret) = self.internal_secret else {
            return;
        };

        let url = format!("{}/internal/session-ended", base_url);
        let body = serde_json::json!({
            "sessionId": session_id,
            "userId": user_id,
            "bytesUp": bytes_up,
            "bytesDown": bytes_down,
            "durationMs": duration_ms,
        });

        if let Err(err) = self
            .http
            .post(&url)
            .header("x-internal-secret", secret)
            .json(&body)
            .send()
            .await
        {
            warn!(error = %err, "failed to report session end");
        }
    }

    /// Whether auth is enabled (HMAC secret is configured).
    pub fn is_enabled(&self) -> bool {
        !self.hmac_secret.is_empty()
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokedKeysResponse {
    revoked_key_ids: Vec<String>,
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
