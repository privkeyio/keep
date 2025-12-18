#![forbid(unsafe_code)]

use nostr_sdk::prelude::*;

pub fn generate_bunker_url(pubkey: &PublicKey, relay_url: &str, secret: Option<&str>) -> String {
    let mut url = format!("bunker://{}", pubkey.to_hex());

    let encoded_relay = urlencoding::encode(relay_url);
    url.push_str(&format!("?relay={}", encoded_relay));

    if let Some(s) = secret {
        url.push_str(&format!("&secret={}", s));
    }

    url
}

pub fn parse_bunker_url(bunker_url: &str) -> Result<(PublicKey, Vec<String>, Option<String>), String> {
    if !bunker_url.starts_with("bunker://") {
        return Err("Invalid bunker URL: must start with bunker://".into());
    }

    let url = ::url::Url::parse(bunker_url).map_err(|e| format!("Invalid URL: {}", e))?;

    let pubkey_hex = url.host_str().ok_or("Missing pubkey in URL")?;
    let pubkey =
        PublicKey::from_hex(pubkey_hex).map_err(|e| format!("Invalid pubkey: {}", e))?;

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
}
