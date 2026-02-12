// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};

/// Maximum number of relays per category per share.
pub const MAX_RELAYS: usize = 10;

/// Maximum length of a relay URL.
pub const MAX_RELAY_URL_LENGTH: usize = 256;

/// Relay configuration for a FROST share, keyed by group public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    /// The FROST group public key this config belongs to.
    pub group_pubkey: [u8; 32],
    /// FROST coordination relay URLs.
    pub frost_relays: Vec<String>,
    /// Profile / NIP-46 relay URLs.
    pub profile_relays: Vec<String>,
}

impl RelayConfig {
    /// Create a new empty relay config for a group.
    pub fn new(group_pubkey: [u8; 32]) -> Self {
        Self {
            group_pubkey,
            frost_relays: Vec::new(),
            profile_relays: Vec::new(),
        }
    }

    /// Create a relay config with default FROST relays.
    pub fn with_defaults(group_pubkey: [u8; 32]) -> Self {
        Self {
            group_pubkey,
            frost_relays: default_frost_relays(),
            profile_relays: Vec::new(),
        }
    }
}

/// Default FROST coordination relays.
pub fn default_frost_relays() -> Vec<String> {
    vec![
        "wss://relay.primal.net/".into(),
        "wss://relay.nsec.app/".into(),
        "wss://relay.damus.io/".into(),
        "wss://nos.lol/".into(),
    ]
}

/// Normalize a relay URL: trim whitespace, lowercase scheme+host, ensure trailing slash.
pub fn normalize_relay_url(url: &str) -> String {
    let url = url.trim();
    let url = if url.ends_with('/') {
        url.to_string()
    } else {
        format!("{url}/")
    };
    if let Some(idx) = url.find("://") {
        let scheme = url[..idx].to_lowercase();
        let rest = &url[idx + 3..];
        let host_end = rest.find('/').unwrap_or(rest.len());
        let host = rest[..host_end].to_lowercase();
        let path = &rest[host_end..];
        format!("{scheme}://{host}{path}")
    } else {
        url
    }
}

/// Validate a relay URL is a valid wss:// URL pointing to a public host.
pub fn validate_relay_url(url: &str) -> Result<(), String> {
    if url.len() > MAX_RELAY_URL_LENGTH {
        return Err("URL too long".into());
    }

    let rest = url
        .strip_prefix("wss://")
        .ok_or("Must use wss:// protocol")?;

    if rest.is_empty() {
        return Err("Missing host".into());
    }

    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port_str) = if host_port.starts_with('[') {
        // IPv6 bracket notation: [::1]:port or [::1]
        match host_port.find(']') {
            Some(bracket_end) => {
                let host = &host_port[..=bracket_end];
                let remainder = &host_port[bracket_end + 1..];
                let port = remainder.strip_prefix(':').unwrap_or("");
                (host, port)
            }
            None => return Err("Unclosed IPv6 bracket".into()),
        }
    } else if let Some(colon_pos) = host_port.rfind(':') {
        let host = &host_port[..colon_pos];
        if host.contains(':') {
            return Err("Invalid unbracketed IPv6 address".into());
        }
        (host, &host_port[colon_pos + 1..])
    } else {
        (host_port, "")
    };
    if !port_str.is_empty() {
        match port_str.parse::<u16>() {
            Ok(0) => return Err("Invalid port".into()),
            Ok(_) => {}
            Err(_) => return Err("Invalid port".into()),
        }
    }

    if host.is_empty() {
        return Err("Missing host".into());
    }

    if host.starts_with('[') {
        if !host.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '[' || c == ']' || c == ':'
        }) {
            return Err("Invalid host characters".into());
        }
    } else if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("Invalid host characters".into());
    }

    if is_internal_host(host) {
        return Err("Internal addresses not allowed".into());
    }

    Ok(())
}

fn is_internal_host(host: &str) -> bool {
    let host = host.to_lowercase();

    // Strip brackets for IPv6
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host);

    // Strip trailing dot (FQDN bypass)
    let bare = bare.strip_suffix('.').unwrap_or(bare);

    // Try parsing as IPv6
    if let Ok(addr) = bare.parse::<std::net::Ipv6Addr>() {
        if let Some(mapped_v4) = addr.to_ipv4_mapped() {
            return mapped_v4.is_loopback()
                || mapped_v4.is_private()
                || mapped_v4.is_link_local()
                || mapped_v4.is_unspecified()
                || is_cgn(mapped_v4);
        }
        return bare.starts_with("fc")
            || bare.starts_with("fd")
            || bare.starts_with("fe80:")
            || bare.starts_with("fe80%")
            || addr.is_loopback()
            || addr.is_unspecified()
            || addr.is_multicast();
    }

    // Try parsing as IPv4
    if let Ok(addr) = bare.parse::<std::net::Ipv4Addr>() {
        return addr.is_loopback()
            || addr.is_private()
            || addr.is_link_local()
            || addr.is_unspecified()
            || is_cgn(addr)
            || is_private_172(bare);
    }

    // Hostname checks
    const FORBIDDEN: &[&str] = &["localhost"];

    FORBIDDEN.contains(&bare) || bare.ends_with(".local") || bare.ends_with(".localhost")
}

fn is_cgn(addr: std::net::Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_private_172(host: &str) -> bool {
    host.strip_prefix("172.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|s| s.parse::<u8>().ok())
        .is_some_and(|octet| (16..=31).contains(&octet))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_relay_urls() {
        assert!(validate_relay_url("wss://relay.example.com/").is_ok());
        assert!(validate_relay_url("wss://relay.example.com").is_ok());
        assert!(validate_relay_url("wss://relay.example.com:443/").is_ok());
        assert!(validate_relay_url("wss://relay.example.com:8080").is_ok());
        assert!(validate_relay_url("wss://nos.lol/").is_ok());
    }

    #[test]
    fn rejects_non_wss() {
        assert!(validate_relay_url("ws://relay.example.com").is_err());
        assert!(validate_relay_url("http://relay.example.com").is_err());
        assert!(validate_relay_url("relay.example.com").is_err());
    }

    #[test]
    fn rejects_empty_and_too_long() {
        assert!(validate_relay_url("wss://").is_err());
        let long_url = format!("wss://{}.example.com", "a".repeat(300));
        assert!(validate_relay_url(&long_url).is_err());
    }

    #[test]
    fn rejects_invalid_ports() {
        assert!(validate_relay_url("wss://relay.example.com:0").is_err());
        assert!(validate_relay_url("wss://relay.example.com:abc").is_err());
        assert!(validate_relay_url("wss://relay.example.com:99999").is_err());
    }

    #[test]
    fn rejects_internal_ipv4() {
        assert!(validate_relay_url("wss://127.0.0.1/").is_err());
        assert!(validate_relay_url("wss://127.0.0.2/").is_err());
        assert!(validate_relay_url("wss://10.0.0.1/").is_err());
        assert!(validate_relay_url("wss://192.168.1.1/").is_err());
        assert!(validate_relay_url("wss://172.16.0.1/").is_err());
        assert!(validate_relay_url("wss://172.31.255.255/").is_err());
        assert!(validate_relay_url("wss://169.254.169.254/").is_err());
        assert!(validate_relay_url("wss://0.0.0.0/").is_err());
    }

    #[test]
    fn rejects_localhost_variants() {
        assert!(validate_relay_url("wss://localhost/").is_err());
        assert!(validate_relay_url("wss://LOCALHOST/").is_err());
        assert!(validate_relay_url("wss://something.localhost/").is_err());
        assert!(validate_relay_url("wss://host.local/").is_err());
    }

    #[test]
    fn rejects_trailing_dot_bypass() {
        assert!(validate_relay_url("wss://localhost./").is_err());
    }

    #[test]
    fn rejects_ipv6_internal() {
        assert!(validate_relay_url("wss://[::1]/").is_err());
        assert!(validate_relay_url("wss://[::ffff:127.0.0.1]/").is_err());
        assert!(validate_relay_url("wss://[::ffff:10.0.0.1]/").is_err());
        assert!(validate_relay_url("wss://[fc00::1]/").is_err());
        assert!(validate_relay_url("wss://[fd00::1]/").is_err());
        assert!(validate_relay_url("wss://[fe80::1]/").is_err());
        assert!(validate_relay_url("wss://[ff02::1]/").is_err());
    }

    #[test]
    fn allows_public_172() {
        assert!(validate_relay_url("wss://172.15.0.1/").is_ok());
        assert!(validate_relay_url("wss://172.32.0.1/").is_ok());
    }

    #[test]
    fn rejects_cgn_range() {
        assert!(validate_relay_url("wss://100.64.0.1/").is_err());
        assert!(validate_relay_url("wss://100.127.255.255/").is_err());
        // Outside CGN range - should be allowed
        assert!(validate_relay_url("wss://100.63.0.1/").is_ok());
        assert!(validate_relay_url("wss://100.128.0.1/").is_ok());
    }

    #[test]
    fn rejects_ipv6_mapped_cgn() {
        assert!(validate_relay_url("wss://[::ffff:100.64.0.1]/").is_err());
        assert!(validate_relay_url("wss://[::ffff:100.127.255.255]/").is_err());
    }

    #[test]
    fn ipv6_with_port() {
        assert!(validate_relay_url("wss://[::1]:443/").is_err());
    }

    #[test]
    fn no_false_positives_on_hostnames() {
        assert!(validate_relay_url("wss://fflogs.example.com/").is_ok());
        assert!(validate_relay_url("wss://fdsecurity.com/").is_ok());
        assert!(validate_relay_url("wss://fe80x.example.com/").is_ok());
    }

    #[test]
    fn unclosed_ipv6_bracket() {
        assert!(validate_relay_url("wss://[::1/").is_err());
    }

    #[test]
    fn rejects_unbracketed_ipv6() {
        assert!(validate_relay_url("wss://::1/").is_err());
        assert!(validate_relay_url("wss://fc00::1/").is_err());
        assert!(validate_relay_url("wss://fe80::1/").is_err());
    }

    #[test]
    fn normalize_adds_trailing_slash() {
        assert_eq!(
            normalize_relay_url("wss://relay.example.com"),
            "wss://relay.example.com/"
        );
        assert_eq!(
            normalize_relay_url("wss://relay.example.com/"),
            "wss://relay.example.com/"
        );
    }

    #[test]
    fn normalize_lowercases_host() {
        assert_eq!(
            normalize_relay_url("wss://RELAY.Example.COM/"),
            "wss://relay.example.com/"
        );
        assert_eq!(
            normalize_relay_url("wss://RELAY.Example.COM:8080/"),
            "wss://relay.example.com:8080/"
        );
    }

    #[test]
    fn normalize_deduplicates_urls() {
        assert_eq!(
            normalize_relay_url("wss://relay.example.com"),
            normalize_relay_url("wss://relay.example.com/")
        );
        assert_eq!(
            normalize_relay_url("wss://Relay.Example.COM/"),
            normalize_relay_url("wss://relay.example.com/")
        );
    }

    #[test]
    fn normalize_trims_whitespace() {
        assert_eq!(
            normalize_relay_url("  wss://relay.example.com/  "),
            "wss://relay.example.com/"
        );
    }
}
