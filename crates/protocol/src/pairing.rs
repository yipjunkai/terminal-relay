use rand::{Rng, distributions::Alphanumeric, thread_rng};
use url::Url;
use uuid::Uuid;

use crate::{error::CoreError, error::CoreResult};

#[derive(Debug, Clone)]
pub struct PairingUri {
    pub relay_url: String,
    pub session_id: String,
    pub pairing_code: String,
    pub expected_fingerprint: Option<String>,
    pub api_key: Option<String>,
}

pub fn new_session_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn new_pairing_code() -> String {
    let mut rng = thread_rng();
    let raw: String = (&mut rng)
        .sample_iter(Alphanumeric)
        .map(char::from)
        .take(18)
        .collect();

    let upper = raw.to_ascii_uppercase();
    let chunks = upper
        .as_bytes()
        .chunks(6)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>();
    chunks.join("-")
}

pub fn build_pairing_uri(pairing: &PairingUri) -> CoreResult<String> {
    let mut url = Url::parse("termrelay://pair").map_err(|_| CoreError::InvalidPairingUri)?;
    url.query_pairs_mut()
        .append_pair("relay", &pairing.relay_url)
        .append_pair("session", &pairing.session_id)
        .append_pair("code", &pairing.pairing_code);

    if let Some(fingerprint) = &pairing.expected_fingerprint {
        url.query_pairs_mut()
            .append_pair("fingerprint", fingerprint);
    }

    if let Some(api_key) = &pairing.api_key {
        url.query_pairs_mut().append_pair("key", api_key);
    }

    Ok(url.to_string())
}

pub fn parse_pairing_uri(input: &str) -> CoreResult<PairingUri> {
    let url = Url::parse(input).map_err(|_| CoreError::InvalidPairingUri)?;
    if url.scheme() != "termrelay" || url.host_str() != Some("pair") {
        return Err(CoreError::InvalidPairingUri);
    }

    let mut relay_url = None;
    let mut session_id = None;
    let mut pairing_code = None;
    let mut expected_fingerprint = None;
    let mut api_key = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "relay" => relay_url = Some(value.to_string()),
            "session" => session_id = Some(value.to_string()),
            "code" => pairing_code = Some(value.to_string()),
            "fingerprint" => expected_fingerprint = Some(value.to_string()),
            "key" => api_key = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(PairingUri {
        relay_url: relay_url.ok_or(CoreError::InvalidPairingUri)?,
        session_id: session_id.ok_or(CoreError::InvalidPairingUri)?,
        pairing_code: pairing_code.ok_or(CoreError::InvalidPairingUri)?,
        expected_fingerprint,
        api_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_uri_roundtrip_without_fingerprint() {
        let original = PairingUri {
            relay_url: "wss://relay.terminal-relay.dev/ws".to_string(),
            session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            pairing_code: "ABC123-DEF456-GHI789".to_string(),
            expected_fingerprint: None,
            api_key: None,
        };

        let uri_str = build_pairing_uri(&original).unwrap();
        let parsed = parse_pairing_uri(&uri_str).unwrap();

        assert_eq!(parsed.relay_url, original.relay_url);
        assert_eq!(parsed.session_id, original.session_id);
        assert_eq!(parsed.pairing_code, original.pairing_code);
        assert_eq!(parsed.expected_fingerprint, None);
    }

    #[test]
    fn pairing_uri_roundtrip_with_fingerprint() {
        let original = PairingUri {
            relay_url: "ws://localhost:8080/ws".to_string(),
            session_id: "test-session".to_string(),
            pairing_code: "AAAAAA-BBBBBB-CCCCCC".to_string(),
            expected_fingerprint: Some("abcdef0123456789".to_string()),
            api_key: None,
        };

        let uri_str = build_pairing_uri(&original).unwrap();
        let parsed = parse_pairing_uri(&uri_str).unwrap();

        assert_eq!(parsed.relay_url, original.relay_url);
        assert_eq!(parsed.session_id, original.session_id);
        assert_eq!(parsed.pairing_code, original.pairing_code);
        assert_eq!(
            parsed.expected_fingerprint,
            Some("abcdef0123456789".to_string())
        );
    }

    #[test]
    fn parse_rejects_wrong_scheme() {
        let err = parse_pairing_uri("https://pair?relay=x&session=y&code=z");
        assert!(err.is_err());
    }

    #[test]
    fn parse_rejects_wrong_host() {
        let err = parse_pairing_uri("termrelay://wrong?relay=x&session=y&code=z");
        assert!(err.is_err());
    }

    #[test]
    fn parse_rejects_missing_relay() {
        let err = parse_pairing_uri("termrelay://pair?session=y&code=z");
        assert!(err.is_err());
    }

    #[test]
    fn parse_rejects_missing_session() {
        let err = parse_pairing_uri("termrelay://pair?relay=x&code=z");
        assert!(err.is_err());
    }

    #[test]
    fn parse_rejects_missing_code() {
        let err = parse_pairing_uri("termrelay://pair?relay=x&session=y");
        assert!(err.is_err());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_pairing_uri("").is_err());
        assert!(parse_pairing_uri("not a uri").is_err());
        assert!(parse_pairing_uri("termrelay://").is_err());
    }

    #[test]
    fn parse_ignores_unknown_params() {
        let uri = "termrelay://pair?relay=ws://localhost&session=s1&code=c1&unknown=ignored";
        let parsed = parse_pairing_uri(uri).unwrap();
        assert_eq!(parsed.relay_url, "ws://localhost");
        assert_eq!(parsed.session_id, "s1");
        assert_eq!(parsed.pairing_code, "c1");
    }

    #[test]
    fn new_session_id_is_valid_uuid() {
        let id = new_session_id();
        // UUID v4 format: 8-4-4-4-12 hex digits
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn new_pairing_code_format() {
        let code = new_pairing_code();
        // Format: XXXXXX-XXXXXX-XXXXXX (18 alphanumeric chars in 3 groups of 6)
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(
            parts.len(),
            3,
            "expected 3 dash-separated groups, got: {code}"
        );
        for part in &parts {
            assert_eq!(part.len(), 6, "each group should be 6 chars, got: {part}");
            assert!(
                part.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "group should be uppercase alphanumeric, got: {part}"
            );
        }
    }

    #[test]
    fn pairing_codes_are_unique() {
        let codes: Vec<String> = (0..100).map(|_| new_pairing_code()).collect();
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(
            codes.len(),
            unique.len(),
            "expected all unique pairing codes"
        );
    }
}
