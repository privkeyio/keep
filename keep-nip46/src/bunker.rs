// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use keep_core::relay::{normalize_relay_url, validate_relay_url, MAX_RELAYS};
use nostr_sdk::prelude::*;

pub fn generate_bunker_url(
    pubkey: &PublicKey,
    relay_urls: &[String],
    secret: Option<&str>,
) -> String {
    let mut url = format!("bunker://{}", pubkey.to_hex());

    for (i, relay_url) in relay_urls.iter().enumerate() {
        let relay = urlencoding::encode(relay_url);
        let sep = if i == 0 { '?' } else { '&' };
        url.push_str(&format!("{sep}relay={relay}"));
    }

    if let Some(s) = secret {
        let sep = if relay_urls.is_empty() { '?' } else { '&' };
        let secret = urlencoding::encode(s);
        url.push_str(&format!("{sep}secret={secret}"));
    }

    url
}

#[derive(Debug, Clone)]
pub struct NostrConnectRequest {
    pub client_pubkey: PublicKey,
    pub relays: Vec<String>,
    pub secret: String,
    pub name: Option<String>,
    pub url: Option<String>,
    pub image: Option<String>,
    pub perms: Option<String>,
}

const MAX_NOSTRCONNECT_RELAYS: usize = 10;
const MAX_DISPLAY_NAME_LEN: usize = 50;
const MIN_SECRET_LEN: usize = 16;

fn validate_metadata_url(value: &str) -> Result<String, String> {
    let parsed = ::url::Url::parse(value).map_err(|e| format!("invalid URL: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(parsed.to_string()),
        _ => Err("only https:// URLs are allowed".into()),
    }
}

fn sanitize_display_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .filter(|c| !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'))
        .take(MAX_DISPLAY_NAME_LEN)
        .collect()
}

pub fn parse_nostrconnect_uri(uri: &str) -> std::result::Result<NostrConnectRequest, String> {
    if !uri.starts_with("nostrconnect://") {
        return Err("must start with nostrconnect://".into());
    }

    let parsed = ::url::Url::parse(uri).map_err(|e| format!("invalid URL: {e}"))?;

    let pubkey_hex = parsed.host_str().ok_or("missing client pubkey")?;
    if pubkey_hex.len() != 64 || !pubkey_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid client pubkey".into());
    }
    let client_pubkey =
        PublicKey::from_hex(pubkey_hex).map_err(|e| format!("invalid client pubkey: {e}"))?;

    let mut relays = Vec::new();
    let mut secret = None;
    let mut name = None;
    let mut url_param = None;
    let mut image = None;
    let mut perms = None;

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "relay" => {
                if relays.len() < MAX_NOSTRCONNECT_RELAYS && validate_relay_url(&value).is_ok() {
                    relays.push(normalize_relay_url(&value));
                }
            }
            "secret" => secret = Some(value.to_string()),
            "name" => name = Some(sanitize_display_name(&value)),
            "url" => url_param = validate_metadata_url(&value).ok(),
            "image" => image = validate_metadata_url(&value).ok(),
            "perms" => perms = Some(value.to_string()),
            _ => {}
        }
    }

    if relays.is_empty() {
        return Err("at least one relay required".into());
    }

    let secret = secret.ok_or("secret is required")?;
    let secret_len = secret.chars().count();
    if secret_len < MIN_SECRET_LEN || secret_len > 64 {
        return Err(format!("secret must be {MIN_SECRET_LEN}-64 characters"));
    }

    Ok(NostrConnectRequest {
        client_pubkey,
        relays,
        secret,
        name,
        url: url_param,
        image,
        perms,
    })
}

pub fn parse_bunker_url(
    bunker_url: &str,
) -> std::result::Result<(PublicKey, Vec<String>, Option<String>), String> {
    if !bunker_url.starts_with("bunker://") {
        return Err("Invalid bunker URL: must start with bunker://".into());
    }

    let url = ::url::Url::parse(bunker_url).map_err(|e| format!("Invalid URL: {e}"))?;

    let pubkey_hex = url.host_str().ok_or("Missing pubkey in URL")?;
    let pubkey = PublicKey::from_hex(pubkey_hex).map_err(|e| format!("Invalid pubkey: {e}"))?;

    let mut relays = Vec::new();
    let mut secret = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "relay" => {
                if relays.len() < MAX_RELAYS && validate_relay_url(&value).is_ok() {
                    relays.push(normalize_relay_url(&value));
                }
            }
            "secret" => secret = Some(value.to_string()),
            _ => {}
        }
    }

    Ok((pubkey, relays, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bunker_url_roundtrip() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let relays = vec!["wss://relay.damus.io/".to_string()];

        let url = generate_bunker_url(&pubkey, &relays, Some("mysecret"));
        let (parsed_pk, parsed_relays, secret) = parse_bunker_url(&url).unwrap();

        assert_eq!(pubkey, parsed_pk);
        assert_eq!(parsed_relays[0], relays[0]);
        assert_eq!(secret, Some("mysecret".into()));
    }

    #[test]
    fn test_bunker_url_multiple_relays() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let relays = vec![
            "wss://relay.damus.io/".to_string(),
            "wss://relay.primal.net/".to_string(),
        ];

        let url = generate_bunker_url(&pubkey, &relays, Some("mysecret"));
        let (parsed_pk, parsed_relays, secret) = parse_bunker_url(&url).unwrap();

        assert_eq!(pubkey, parsed_pk);
        assert_eq!(parsed_relays, relays);
        assert_eq!(secret, Some("mysecret".into()));
    }

    #[test]
    fn test_bunker_url_secret_with_special_chars() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let relays = vec!["wss://relay.damus.io/".to_string()];
        let secret = "pass&word=special chars+more";

        let url = generate_bunker_url(&pubkey, &relays, Some(secret));
        assert!(!url.contains("pass&word"));

        let (_, _, parsed_secret) = parse_bunker_url(&url).unwrap();
        assert_eq!(parsed_secret, Some(secret.into()));
    }

    #[test]
    fn test_parse_nostrconnect_basic() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let uri = format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.damus.io&secret=abcdef0123456789&name=My+Client",
            pubkey.to_hex()
        );

        let req = parse_nostrconnect_uri(&uri).unwrap();
        assert_eq!(req.client_pubkey, pubkey);
        assert_eq!(req.relays, vec!["wss://relay.damus.io/"]);
        assert_eq!(req.secret, "abcdef0123456789");
        assert_eq!(req.name.as_deref(), Some("My Client"));
    }

    #[test]
    fn test_parse_nostrconnect_multiple_relays() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let uri = format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay1.example.com&relay=wss%3A%2F%2Frelay2.example.com&secret=abcdef0123456789",
            pubkey.to_hex()
        );

        let req = parse_nostrconnect_uri(&uri).unwrap();
        assert_eq!(req.relays.len(), 2);
        assert_eq!(req.secret, "abcdef0123456789");
    }

    #[test]
    fn test_parse_nostrconnect_with_perms() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let uri = format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example.com&secret=abcdef0123456789&perms=sign_event%3A1%2Cnip44_encrypt",
            pubkey.to_hex()
        );

        let req = parse_nostrconnect_uri(&uri).unwrap();
        assert_eq!(req.perms.as_deref(), Some("sign_event:1,nip44_encrypt"));
    }

    #[test]
    fn test_parse_nostrconnect_missing_secret() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let uri = format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example.com",
            pubkey.to_hex()
        );

        assert!(parse_nostrconnect_uri(&uri).is_err());
    }

    #[test]
    fn test_parse_nostrconnect_short_secret() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let uri = format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example.com&secret=short",
            pubkey.to_hex()
        );

        assert!(parse_nostrconnect_uri(&uri).is_err());
    }

    #[test]
    fn test_parse_nostrconnect_missing_relay() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let uri = format!(
            "nostrconnect://{}?secret=abcdef0123456789",
            pubkey.to_hex()
        );

        assert!(parse_nostrconnect_uri(&uri).is_err());
    }

    #[test]
    fn test_parse_nostrconnect_wrong_scheme() {
        assert!(parse_nostrconnect_uri("bunker://abc?secret=x").is_err());
        assert!(parse_nostrconnect_uri("https://example.com").is_err());
    }

    #[test]
    fn test_parse_nostrconnect_invalid_pubkey() {
        let uri = "nostrconnect://notahexpubkey?relay=wss%3A%2F%2Frelay.example.com&secret=abcdef0123456789";
        assert!(parse_nostrconnect_uri(uri).is_err());
    }

    #[test]
    fn test_parse_nostrconnect_rejects_non_wss_relay() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let uri = format!(
            "nostrconnect://{}?relay=ws%3A%2F%2Frelay.example.com&secret=abcdef0123456789",
            pubkey.to_hex()
        );
        assert!(parse_nostrconnect_uri(&uri).is_err());
    }

    #[test]
    fn test_sanitize_display_name() {
        assert_eq!(sanitize_display_name("Good Name"), "Good Name");
        assert_eq!(sanitize_display_name("Has\x00null"), "Hasnull");
        assert_eq!(
            sanitize_display_name(&"x".repeat(100)),
            "x".repeat(MAX_DISPLAY_NAME_LEN)
        );
        assert_eq!(sanitize_display_name("A\u{200B}B"), "AB");
    }
}
