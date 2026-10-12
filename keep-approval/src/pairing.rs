// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The pairing URI the host shows, as a QR code and as text:
//!
//! ```text
//! keep-approver:v1?gateway=<channel npub>&secret=<hex>&relay=<url>&relay=<url>
//! ```
//!
//! The parameters come in that order, each once but `relay`, which comes
//! one or more times. Relay URLs are `wss://` or `ws://` and hold only
//! characters that need no escaping in a query, so the URI has one form.

use nostr::nips::nip19::{FromBech32, ToBech32};
use nostr::PublicKey;
use zeroize::Zeroizing;

use crate::messages::{AnchorState, Frozen, Pairing};
use crate::{invalid, malformed, Hex32, Result};

/// What every pairing URI starts with.
pub const PREFIX: &str = "keep-approver:v1?";

/// The most relays a pairing URI names.
pub const MAX_RELAYS: usize = 8;

/// The longest relay URL.
pub const MAX_RELAY_LEN: usize = 256;

/// A pairing session, as the phone scans it.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingUri {
    /// The gateway's channel public key, x-only.
    pub gateway: [u8; 32],
    /// The session's one-use secret.
    pub secret: Zeroizing<[u8; 32]>,
    /// The relays to reach the gateway on.
    pub relays: Vec<String>,
}

impl std::fmt::Debug for PairingUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingUri")
            .field("gateway", &Hex32(self.gateway))
            .field("relays", &self.relays)
            .finish_non_exhaustive()
    }
}

/// Check a relay URL: `wss://` or `ws://`, a host, at most
/// [`MAX_RELAY_LEN`] bytes, and only letters, digits and `-._~:/[]@`.
pub fn check_relay(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .ok_or_else(|| malformed("a relay URL is wss:// or ws://"))?;
    if rest.is_empty() || rest.starts_with('/') || url.len() > MAX_RELAY_LEN {
        return Err(malformed("a relay URL names a host"));
    }
    if !rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~:/[]".contains(&b))
    {
        return Err(malformed(
            "a relay URL holds a character a URI would escape",
        ));
    }
    Ok(())
}

impl PairingUri {
    /// The URI, after checking the relays. It holds the secret, so it is
    /// wiped when dropped.
    pub fn to_uri(&self) -> Result<Zeroizing<String>> {
        check_relays(&self.relays)?;
        let gateway = PublicKey::from_slice(&self.gateway)
            .map_err(|_| malformed("gateway key"))?
            .to_bech32()
            .map_err(|_| malformed("gateway key"))?;
        let secret = Zeroizing::new(hex::encode(&self.secret[..]));
        let mut uri = Zeroizing::new(String::with_capacity(
            PREFIX.len()
                + gateway.len()
                + 80
                + self.relays.iter().map(|r| r.len() + 7).sum::<usize>(),
        ));
        uri.push_str(PREFIX);
        uri.push_str("gateway=");
        uri.push_str(&gateway);
        uri.push_str("&secret=");
        uri.push_str(&secret);
        for relay in &self.relays {
            uri.push_str("&relay=");
            uri.push_str(relay);
        }
        Ok(uri)
    }

    /// Parse a pairing URI strictly: the prefix, then `gateway`, `secret`
    /// and one to [`MAX_RELAYS`] distinct `relay`s, in that order and
    /// nothing else.
    pub fn parse(uri: &str) -> Result<Self> {
        let query = uri
            .strip_prefix(PREFIX)
            .ok_or_else(|| malformed("not a keep-approver v1 URI"))?;
        let mut params = query.split('&').map(|p| {
            p.split_once('=')
                .ok_or_else(|| malformed("a URI parameter has no value"))
        });
        let mut next = |name: &str| -> Result<&str> {
            match params.next().transpose()? {
                Some((n, value)) if n == name => Ok(value),
                _ => Err(malformed(format!("expected the {name} parameter"))),
            }
        };
        let gateway = next("gateway")?;
        if gateway.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(malformed("the gateway key is lowercase"));
        }
        let gateway = PublicKey::from_bech32(gateway)
            .map_err(|_| malformed("the gateway is not an npub"))?
            .to_bytes();
        let hex = next("secret")?;
        if !crate::codec::is_lower_hex(hex, 32) {
            return Err(malformed("the secret is 32 bytes of lowercase hex"));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(hex, secret.as_mut()).map_err(|_| malformed("secret"))?;
        let mut relays: Vec<String> = Vec::new();
        for param in params {
            match param? {
                ("relay", relay) => relays.push(relay.to_string()),
                _ => return Err(malformed("only relay parameters follow the secret")),
            }
        }
        check_relays(&relays)?;
        Ok(Self {
            gateway,
            secret,
            relays,
        })
    }
}

/// What a phone takes from the gateway's `paired` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paired {
    pub relays: Vec<String>,
    pub deadline_secs: u64,
    pub anchor: AnchorState,
    pub frozen: Frozen,
}

/// Check the gateway's answer to a phone's `pair`: a `paired` naming the
/// phone's own two keys, one to [`MAX_RELAYS`] distinct relays that pass
/// [`check_relay`], and a deadline the protocol allows. A `refused` is an
/// error carrying its reason, which the phone shows through
/// [`crate::approver::shown`].
pub fn check_paired(
    message: &Pairing,
    transport: &[u8; 32],
    approver: &[u8; 33],
) -> Result<Paired> {
    match message {
        Pairing::Paired {
            transport: t,
            approver: a,
            relays,
            deadline_secs,
            anchor,
            frozen,
            ..
        } => {
            if t.0 != *transport || a.0 != *approver {
                return Err(invalid("paired names another device's keys"));
            }
            check_relays(relays)?;
            if !crate::binding::DEADLINE_SECS.contains(deadline_secs) {
                return Err(invalid("paired names a deadline out of range"));
            }
            Ok(Paired {
                relays: relays.clone(),
                deadline_secs: *deadline_secs,
                anchor: anchor.clone(),
                frozen: frozen.clone(),
            })
        }
        Pairing::Refused { reason, .. } => Err(invalid(format!(
            "pairing refused: {}",
            crate::approver::shown(reason, crate::approver::GATEWAY_TEXT_CHARS).text
        ))),
        Pairing::Pair { .. } => Err(invalid("not the gateway's answer")),
    }
}

fn check_relays(relays: &[String]) -> Result<()> {
    if relays.is_empty() || relays.len() > MAX_RELAYS {
        return Err(malformed(format!(
            "a pairing URI names 1 to {MAX_RELAYS} relays"
        )));
    }
    for (i, relay) in relays.iter().enumerate() {
        check_relay(relay)?;
        if relays[..i].contains(relay) {
            return Err(malformed("a relay is named twice"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    fn sample() -> PairingUri {
        PairingUri {
            gateway: Keys::generate().public_key().to_bytes(),
            secret: Zeroizing::new([7; 32]),
            relays: vec![
                "wss://relay.example.com".into(),
                "ws://127.0.0.1:7777/inbox".into(),
            ],
        }
    }

    #[test]
    fn a_uri_round_trips() {
        let p = sample();
        let uri = p.to_uri().unwrap().to_string();
        assert!(uri.starts_with("keep-approver:v1?gateway=npub1"), "{uri}");
        assert!(uri.contains(&format!("&secret={}&relay=wss://", "07".repeat(32))));
        assert_eq!(PairingUri::parse(&uri).unwrap(), p);
        let shown = format!("{p:?}");
        assert!(!shown.contains(&"07".repeat(32)), "{shown}");
    }

    #[test]
    fn anything_else_is_refused() {
        let uri = sample().to_uri().unwrap().to_string();
        let (head, relays) = uri.split_once("&relay=").unwrap();
        let bad = [
            uri.replace("keep-approver:v1?", "keep-approver:v2?"),
            uri.replace("gateway=", "gw="),
            uri.to_uppercase(),
            {
                let (prefix, npub) = head.split_once("gateway=").unwrap();
                let (npub, secret) = npub.split_once('&').unwrap();
                format!(
                    "{prefix}gateway={}&{secret}&relay={relays}",
                    npub.to_uppercase()
                )
            },
            head.to_string(),
            format!("{uri}&extra=1"),
            format!("{uri}&relay=wss://relay.example.com"),
            format!("{uri}&relay"),
            uri.replace("&secret=", "&secret=0"),
            uri.replace("&secret=07", "&secret=0G"),
            uri.replace("&secret=07", "&secret=0A"),
            // Parameters out of order.
            {
                let (gateway, rest) = head.strip_prefix(PREFIX).unwrap().split_once('&').unwrap();
                format!("{PREFIX}{rest}&{gateway}&relay={relays}")
            },
            uri.replace("wss://relay.example.com", "https://relay.example.com"),
            uri.replace("wss://relay.example.com", "wss://"),
            uri.replace("wss://relay.example.com", "wss:///path"),
            uri.replace("wss://relay.example.com", "wss://relay.example.com/?a=b"),
            uri.replace("wss://relay.example.com", "wss://relay.example.com/a%20b"),
            uri.replace("wss://relay.example.com", "wss://relay.example.com#x"),
            uri.replace(
                "wss://relay.example.com",
                "wss://relay.example.com@evil.example",
            ),
            uri.replace(
                "wss://relay.example.com",
                &format!("wss://{}", "a".repeat(MAX_RELAY_LEN)),
            ),
        ];
        for b in &bad {
            assert!(PairingUri::parse(b).is_err(), "{b}");
        }
        let mut many = sample();
        many.relays = (0..=MAX_RELAYS)
            .map(|i| format!("wss://r{i}.example.com"))
            .collect();
        assert!(many.to_uri().is_err());
        many.relays.pop();
        assert!(PairingUri::parse(&many.to_uri().unwrap()).is_ok());
        let mut none = sample();
        none.relays.clear();
        assert!(none.to_uri().is_err());
    }

    /// A phone takes a `paired` only for its own two keys, with relays it
    /// would accept and a deadline in range; a `refused` is an error
    /// carrying its reason, shown without hidden characters.
    #[test]
    fn a_paired_message_is_checked() {
        use crate::messages::{AnchorState, Frozen, V1};
        use crate::{Hex32, Hex33};
        let paired = |relays: Vec<&str>, deadline: u64| Pairing::Paired {
            v: V1,
            transport: Hex32([1; 32]),
            approver: Hex33([2; 33]),
            relays: relays.into_iter().map(String::from).collect(),
            deadline_secs: deadline,
            anchor: AnchorState {
                seq: 1,
                head: Hex32([0; 32]),
                prev: None,
                wallets: vec![],
            },
            frozen: Frozen {
                epoch: 0,
                all: false,
                credentials: vec![],
                unfrozen: vec![],
            },
        };
        let ok = check_paired(&paired(vec!["wss://r.example"], 120), &[1; 32], &[2; 33]).unwrap();
        assert_eq!(ok.relays, ["wss://r.example"]);
        for (message, transport, approver) in [
            (paired(vec!["wss://r.example"], 120), [9; 32], [2; 33]),
            (paired(vec!["wss://r.example"], 120), [1; 32], [9; 33]),
            (paired(vec![], 120), [1; 32], [2; 33]),
            (paired(vec!["https://r.example"], 120), [1; 32], [2; 33]),
            (
                paired(vec!["wss://r.example", "wss://r.example"], 120),
                [1; 32],
                [2; 33],
            ),
            (paired(vec!["wss://r.example"], 29), [1; 32], [2; 33]),
            (paired(vec!["wss://r.example"], 121), [1; 32], [2; 33]),
        ] {
            assert!(
                check_paired(&message, &transport, &approver).is_err(),
                "{message:?}"
            );
        }
        let refused = Pairing::Refused {
            v: V1,
            reason: "expired\u{202e}gnirap".into(),
        };
        let err = check_paired(&refused, &[1; 32], &[2; 33])
            .unwrap_err()
            .to_string();
        assert!(err.contains("expiredgnirap"), "{err}");
    }
}
