// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use nostr_sdk::prelude::*;

pub fn generate_bunker_url(pubkey: &PublicKey, relay_url: &str, secret: Option<&str>) -> String {
    let relay = urlencoding::encode(relay_url);
    let mut url = format!("bunker://{}?relay={relay}", pubkey.to_hex());

    if let Some(s) = secret {
        let secret = urlencoding::encode(s);
        url.push_str(&format!("&secret={secret}"));
    }

    url
}

#[cfg(test)]
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
            "relay" => relays.push(value.to_string()),
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
        let relay = "wss://relay.damus.io";

        let url = generate_bunker_url(&pubkey, relay, Some("mysecret"));
        let (parsed_pk, relays, secret) = parse_bunker_url(&url).unwrap();

        assert_eq!(pubkey, parsed_pk);
        assert_eq!(relays[0], relay);
        assert_eq!(secret, Some("mysecret".into()));
    }

    #[test]
    fn test_bunker_url_secret_with_special_chars() {
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let relay = "wss://relay.damus.io";
        let secret = "pass&word=special chars+more";

        let url = generate_bunker_url(&pubkey, relay, Some(secret));
        assert!(!url.contains("pass&word"));

        let (_, _, parsed_secret) = parse_bunker_url(&url).unwrap();
        assert_eq!(parsed_secret, Some(secret.into()));
    }
}
