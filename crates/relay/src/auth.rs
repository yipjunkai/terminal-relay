use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::RwLock;
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

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
    hmac_secret: Zeroizing<Vec<u8>>,
    /// Previous HMAC secret (for rotation). Optional.
    hmac_secret_previous: Option<Zeroizing<Vec<u8>>>,
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
            hmac_secret: Zeroizing::new(hmac_secret.into_bytes()),
            hmac_secret_previous: hmac_secret_previous.map(|s| Zeroizing::new(s.into_bytes())),
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
        expected_sig.as_bytes().ct_eq(provided_sig.as_bytes()).into()
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



#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-hmac-secret-for-unit-tests";
    const TEST_SECRET_PREV: &str = "old-hmac-secret-from-previous-rotation";

    /// Helper: build a signed API key the same way the control API does.
    fn build_signed_key(secret: &str, uid: &str, kid: &str, tier: &str, iat: u64) -> String {
        let payload_json =
            format!(r#"{{"uid":"{uid}","kid":"{kid}","tier":"{tier}","iat":{iat}}}"#);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload_json.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let combined = format!("{payload_json}.{signature}");
        format!("tr_{}", URL_SAFE_NO_PAD.encode(combined.as_bytes()))
    }

    fn auth_state(secret: &str, previous: Option<&str>) -> AuthState {
        AuthState::new(
            secret.to_string(),
            previous.map(|s| s.to_string()),
            None,
            None,
        )
    }

    #[tokio::test]
    async fn valid_key_roundtrip() {
        let state = auth_state(TEST_SECRET, None);
        let key = build_signed_key(TEST_SECRET, "user-123", "key-456", "pro", 1700000000);

        let payload = state.verify_api_key(&key).await.expect("should verify");
        assert_eq!(payload.uid, "user-123");
        assert_eq!(payload.kid, "key-456");
        assert_eq!(payload.tier, "pro");
        assert_eq!(payload.iat, 1700000000);
    }

    #[tokio::test]
    async fn rejects_missing_prefix() {
        let state = auth_state(TEST_SECRET, None);
        assert!(state.verify_api_key("notakey").await.is_none());
    }

    #[tokio::test]
    async fn rejects_empty_key() {
        let state = auth_state(TEST_SECRET, None);
        assert!(state.verify_api_key("").await.is_none());
        assert!(state.verify_api_key("tr_").await.is_none());
    }

    #[tokio::test]
    async fn rejects_invalid_base64() {
        let state = auth_state(TEST_SECRET, None);
        assert!(
            state
                .verify_api_key("tr_not-valid-base64!!!")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_wrong_secret() {
        let state = auth_state(TEST_SECRET, None);
        let key = build_signed_key("wrong-secret", "user-123", "key-456", "free", 1700000000);
        assert!(state.verify_api_key(&key).await.is_none());
    }

    #[tokio::test]
    async fn rejects_tampered_payload() {
        let state = auth_state(TEST_SECRET, None);
        let key = build_signed_key(TEST_SECRET, "user-123", "key-456", "free", 1700000000);

        // Decode, tamper with tier, re-encode (signature is now invalid)
        let decoded = URL_SAFE_NO_PAD.decode(&key[3..]).unwrap();
        let decoded_str = std::str::from_utf8(&decoded).unwrap();
        let tampered = decoded_str.replace(r#""free""#, r#""enterprise""#);
        let tampered_key = format!("tr_{}", URL_SAFE_NO_PAD.encode(tampered.as_bytes()));

        assert!(state.verify_api_key(&tampered_key).await.is_none());
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let state = auth_state(TEST_SECRET, None);
        let key = build_signed_key(TEST_SECRET, "user-123", "key-456", "free", 1700000000);

        // Decode, flip a character in the signature
        let decoded = URL_SAFE_NO_PAD.decode(&key[3..]).unwrap();
        let mut decoded_str = std::str::from_utf8(&decoded).unwrap().to_string();
        let last_char = decoded_str.pop().unwrap();
        let replacement = if last_char == 'a' { 'b' } else { 'a' };
        decoded_str.push(replacement);
        let tampered_key = format!("tr_{}", URL_SAFE_NO_PAD.encode(decoded_str.as_bytes()));

        assert!(state.verify_api_key(&tampered_key).await.is_none());
    }

    #[tokio::test]
    async fn rejects_malformed_json_payload() {
        let state = auth_state(TEST_SECRET, None);
        // Valid HMAC over garbage JSON
        let payload_json = "not-valid-json";
        let mut mac = HmacSha256::new_from_slice(TEST_SECRET.as_bytes()).unwrap();
        mac.update(payload_json.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let combined = format!("{payload_json}.{signature}");
        let key = format!("tr_{}", URL_SAFE_NO_PAD.encode(combined.as_bytes()));

        assert!(state.verify_api_key(&key).await.is_none());
    }

    #[tokio::test]
    async fn rejects_no_dot_separator() {
        let state = auth_state(TEST_SECRET, None);
        let no_dot = URL_SAFE_NO_PAD.encode(b"nodotinthisstring");
        let key = format!("tr_{no_dot}");
        assert!(state.verify_api_key(&key).await.is_none());
    }

    #[tokio::test]
    async fn revoked_key_is_rejected() {
        let state = auth_state(TEST_SECRET, None);
        let key = build_signed_key(
            TEST_SECRET,
            "user-123",
            "revoked-key-id",
            "free",
            1700000000,
        );

        // Add to revocation list
        {
            let mut revoked = state.revoked_keys.write().await;
            revoked.insert("revoked-key-id".to_string());
        }

        assert!(state.verify_api_key(&key).await.is_none());
    }

    #[tokio::test]
    async fn non_revoked_key_with_populated_list() {
        let state = auth_state(TEST_SECRET, None);
        let key = build_signed_key(TEST_SECRET, "user-123", "good-key-id", "free", 1700000000);

        // Add a different key to revocation list
        {
            let mut revoked = state.revoked_keys.write().await;
            revoked.insert("other-key-id".to_string());
        }

        let payload = state.verify_api_key(&key).await.expect("should verify");
        assert_eq!(payload.kid, "good-key-id");
    }

    #[tokio::test]
    async fn dual_secret_accepts_current() {
        let state = auth_state(TEST_SECRET, Some(TEST_SECRET_PREV));
        let key = build_signed_key(TEST_SECRET, "user-1", "key-1", "pro", 1700000000);

        let payload = state
            .verify_api_key(&key)
            .await
            .expect("should verify with current");
        assert_eq!(payload.uid, "user-1");
    }

    #[tokio::test]
    async fn dual_secret_accepts_previous() {
        let state = auth_state(TEST_SECRET, Some(TEST_SECRET_PREV));
        let key = build_signed_key(TEST_SECRET_PREV, "user-2", "key-2", "free", 1700000000);

        let payload = state
            .verify_api_key(&key)
            .await
            .expect("should verify with previous");
        assert_eq!(payload.uid, "user-2");
    }

    #[tokio::test]
    async fn dual_secret_rejects_unknown() {
        let state = auth_state(TEST_SECRET, Some(TEST_SECRET_PREV));
        let key = build_signed_key(
            "completely-different",
            "user-3",
            "key-3",
            "free",
            1700000000,
        );
        assert!(state.verify_api_key(&key).await.is_none());
    }

    #[tokio::test]
    async fn is_enabled_with_secret() {
        let state = auth_state(TEST_SECRET, None);
        assert!(state.is_enabled());
    }

    #[tokio::test]
    async fn is_disabled_without_secret() {
        let state = auth_state("", None);
        assert!(!state.is_enabled());
    }

}
