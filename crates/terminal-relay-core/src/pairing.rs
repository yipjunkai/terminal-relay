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

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "relay" => relay_url = Some(value.to_string()),
            "session" => session_id = Some(value.to_string()),
            "code" => pairing_code = Some(value.to_string()),
            "fingerprint" => expected_fingerprint = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(PairingUri {
        relay_url: relay_url.ok_or(CoreError::InvalidPairingUri)?,
        session_id: session_id.ok_or(CoreError::InvalidPairingUri)?,
        pairing_code: pairing_code.ok_or(CoreError::InvalidPairingUri)?,
        expected_fingerprint,
    })
}
