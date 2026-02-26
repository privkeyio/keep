// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    let result = if let Some(idx) = url.find("://") {
        let scheme = url[..idx].to_lowercase();
        let rest = &url[idx + 3..];
        let host_end = rest.find('/').unwrap_or(rest.len());
        let host = rest[..host_end].to_lowercase();
        let path = &rest[host_end..];
        format!("{scheme}://{host}{path}")
    } else {
        url.to_string()
    };
    if result.ends_with('/') {
        result
    } else {
        format!("{result}/")
    }
}

/// Whether the `allow-internal` Cargo feature is active.
pub const ALLOW_INTERNAL_HOSTS: bool = cfg!(feature = "allow-internal");

/// Validate a relay URL is a valid wss:// URL pointing to a public host.
pub fn validate_relay_url(url: &str) -> Result<(), String> {
    validate_relay_url_inner(url, false)
}

/// Like [`validate_relay_url`] but permits internal/private addresses.
pub fn validate_relay_url_allow_internal(url: &str) -> Result<(), String> {
    validate_relay_url_inner(url, true)
}

fn validate_relay_url_inner(url: &str, allow_internal: bool) -> Result<(), String> {
    if url.len() > MAX_RELAY_URL_LENGTH {
        return Err("URL too long".into());
    }

    let rest = url
        .strip_prefix("wss://")
        .or_else(|| {
            if cfg!(feature = "allow-ws") {
                url.strip_prefix("ws://")
            } else {
                None
            }
        })
        .ok_or("Must use wss:// protocol")?;

    if rest.is_empty() {
        return Err("Missing host".into());
    }

    let host_port = rest.split('/').next().unwrap_or(rest);
    if host_port.contains('@') {
        return Err("Userinfo not allowed in relay URLs".into());
    }

    let (host, port_str) = if host_port.starts_with('[') {
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
        let port = port_str.parse::<u16>().map_err(|_| "Invalid port")?;
        if port == 0 {
            return Err("Invalid port".into());
        }
    }

    if host.is_empty() {
        return Err("Missing host".into());
    }

    let valid_host_char = |c: char| {
        c.is_ascii_alphanumeric()
            || c == '.'
            || c == '-'
            || (host.starts_with('[') && (c == '[' || c == ']' || c == ':'))
    };
    if !host.chars().all(valid_host_char) {
        return Err("Invalid host characters".into());
    }

    if !allow_internal && is_internal_host(host) {
        return Err("Internal addresses not allowed".into());
    }

    Ok(())
}

/// Check if a resolved IP address is internal/private/reserved.
///
/// Use this after DNS resolution to prevent DNS rebinding attacks where
/// a hostname passes URL validation but resolves to an internal IP.
pub fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => is_internal_v4(*addr),
        IpAddr::V6(addr) => is_internal_v6(addr),
    }
}

fn is_internal_v6(addr: &Ipv6Addr) -> bool {
    if let Some(v4) = to_embedded_v4(addr) {
        return is_internal_v4(v4);
    }
    let s = addr.segments();
    (s[0] & 0xfe00) == 0xfc00        // ULA fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (s[0] & 0xffc0) == 0xfec0 // site-local fec0::/10 (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation 2001:db8::/32
        || addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
}

fn to_embedded_v4(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return Some(mapped);
    }
    let s = addr.segments();
    let o = addr.octets();
    let tail_v4 = || Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    // IPv4-compatible (::x.x.x.x) — deprecated but still exploitable
    if s[..6] == [0, 0, 0, 0, 0, 0] {
        return Some(tail_v4());
    }
    // NAT64 Well-Known Prefix 64:ff9b::/96 (RFC 6052)
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(tail_v4());
    }
    // 6to4 (2002::/16) — IPv4 embedded in bits 16-47
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    // Teredo (2001:0000::/32) — IPv4 XOR'd in last 32 bits
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return Some(Ipv4Addr::new(
            o[12] ^ 0xff,
            o[13] ^ 0xff,
            o[14] ^ 0xff,
            o[15] ^ 0xff,
        ));
    }
    None
}

fn is_internal_v4(addr: Ipv4Addr) -> bool {
    addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.is_multicast()
        || addr.octets()[0] == 0
        || is_cgn(addr)
        || is_special_purpose_v4(addr)
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

    if let Ok(addr) = bare.parse::<Ipv6Addr>() {
        return is_internal_v6(&addr);
    }

    if let Ok(addr) = bare.parse::<Ipv4Addr>() {
        return is_internal_v4(addr);
    }

    const FORBIDDEN: &[&str] = &["localhost"];

    if FORBIDDEN.contains(&bare)
        || bare.ends_with(".local")
        || bare.ends_with(".localhost")
        || bare.ends_with(".arpa")
        || bare.ends_with(".onion")
    {
        return true;
    }

    // Reject single-label hostnames (no dots) to prevent SSRF to internal names
    !bare.contains('.')
}

fn is_cgn(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_special_purpose_v4(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    // TEST-NET-1 192.0.2.0/24 (RFC 5737)
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
    // TEST-NET-2 198.51.100.0/24 (RFC 5737)
    || (o[0] == 198 && o[1] == 51 && o[2] == 100)
    // TEST-NET-3 203.0.113.0/24 (RFC 5737)
    || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    // Benchmarking 198.18.0.0/15 (RFC 2544)
    || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
    // Reserved 240.0.0.0/4
    || o[0] >= 240
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
        if cfg!(feature = "allow-ws") {
            assert!(validate_relay_url("ws://relay.example.com").is_ok());
        } else {
            assert!(validate_relay_url("ws://relay.example.com").is_err());
        }
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
        // IPv4-compatible (::x.x.x.x) — exercises to_embedded_v4 deprecated-compat path
        assert!(validate_relay_url("wss://[::7f00:1]/").is_err()); // ::127.0.0.1
        assert!(validate_relay_url("wss://[::a00:1]/").is_err()); // ::10.0.0.1
                                                                  // NAT64 Well-Known Prefix 64:ff9b::/96 — exercises to_embedded_v4 NAT64 path
        assert!(validate_relay_url("wss://[64:ff9b::7f00:1]/").is_err()); // embeds 127.0.0.1
        assert!(validate_relay_url("wss://[64:ff9b::a00:1]/").is_err()); // embeds 10.0.0.1
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

    #[test]
    fn rejects_single_label_hostnames() {
        assert!(validate_relay_url("wss://intranet/").is_err());
        assert!(validate_relay_url("wss://fileserver/").is_err());
        assert!(validate_relay_url("wss://router/").is_err());
    }

    #[test]
    fn rejects_special_purpose_ipv4() {
        // TEST-NET-1
        assert!(validate_relay_url("wss://192.0.2.1/").is_err());
        // TEST-NET-2
        assert!(validate_relay_url("wss://198.51.100.1/").is_err());
        // TEST-NET-3
        assert!(validate_relay_url("wss://203.0.113.1/").is_err());
        // Benchmarking
        assert!(validate_relay_url("wss://198.18.0.1/").is_err());
        assert!(validate_relay_url("wss://198.19.255.255/").is_err());
        // Reserved
        assert!(validate_relay_url("wss://240.0.0.1/").is_err());
        assert!(validate_relay_url("wss://255.255.255.255/").is_err());
    }

    #[test]
    fn rejects_ipv6_mapped_special_purpose() {
        assert!(validate_relay_url("wss://[::ffff:192.0.2.1]/").is_err());
        assert!(validate_relay_url("wss://[::ffff:198.51.100.1]/").is_err());
        assert!(validate_relay_url("wss://[::ffff:240.0.0.1]/").is_err());
    }

    #[test]
    fn is_internal_ip_blocks_private() {
        use std::net::IpAddr;
        assert!(is_internal_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"169.254.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"0.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"100.64.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"240.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"::1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"fc00::1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"fe80::1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(
            &"::ffff:127.0.0.1".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn is_internal_ip_allows_public() {
        use std::net::IpAddr;
        assert!(!is_internal_ip(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!is_internal_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()));
        assert!(!is_internal_ip(&"2607:f8b0::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn allows_nearby_public_ranges() {
        assert!(validate_relay_url("wss://192.0.3.1/").is_ok());
        assert!(validate_relay_url("wss://198.51.101.1/").is_ok());
        assert!(validate_relay_url("wss://203.0.114.1/").is_ok());
        assert!(validate_relay_url("wss://198.17.0.1/").is_ok());
        assert!(validate_relay_url("wss://198.20.0.1/").is_ok());
    }

    #[test]
    fn rejects_ipv4_multicast() {
        assert!(validate_relay_url("wss://224.0.0.1/").is_err());
        assert!(validate_relay_url("wss://239.255.255.255/").is_err());
    }

    #[test]
    fn rejects_this_network_range() {
        assert!(validate_relay_url("wss://0.1.2.3/").is_err());
        assert!(validate_relay_url("wss://0.255.255.255/").is_err());
    }

    #[test]
    fn is_internal_ip_blocks_ipv4_compatible_v6() {
        use std::net::IpAddr;
        assert!(is_internal_ip(&"::7f00:1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"::a00:1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(&"::c0a8:101".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn is_internal_ip_blocks_multicast_v4() {
        use std::net::IpAddr;
        assert!(is_internal_ip(&"224.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(
            &"239.255.255.255".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn is_internal_ip_blocks_this_network() {
        use std::net::IpAddr;
        assert!(is_internal_ip(&"0.1.2.3".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn is_internal_ip_blocks_nat64_wkp() {
        use std::net::IpAddr;
        // 64:ff9b::a00:1 embeds 10.0.0.1 (private)
        assert!(is_internal_ip(&"64:ff9b::a00:1".parse::<IpAddr>().unwrap()));
        // 64:ff9b::7f00:1 embeds 127.0.0.1 (loopback)
        assert!(is_internal_ip(
            &"64:ff9b::7f00:1".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn is_internal_ip_blocks_6to4() {
        use std::net::IpAddr;
        // 2002:7f00:0001::1 embeds 127.0.0.1
        assert!(is_internal_ip(
            &"2002:7f00:0001::1".parse::<IpAddr>().unwrap()
        ));
        // 2002:0a00:0001::1 embeds 10.0.0.1
        assert!(is_internal_ip(&"2002:a00:1::1".parse::<IpAddr>().unwrap()));
        // 2002:c0a8:0101::1 embeds 192.168.1.1
        assert!(is_internal_ip(
            &"2002:c0a8:101::1".parse::<IpAddr>().unwrap()
        ));
        // Public 6to4: 2002:0808:0808::1 embeds 8.8.8.8
        assert!(!is_internal_ip(
            &"2002:808:808::1".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn is_internal_ip_blocks_teredo() {
        use std::net::IpAddr;
        // Teredo: 2001:0000:x:x:x:x:XXXX:XXXX where last 32 bits are XOR'd IPv4
        // XOR'd 127.0.0.1 = 0x80ff:fffe
        assert!(is_internal_ip(
            &"2001:0000:0000:0000:0000:0000:80ff:fffe"
                .parse::<IpAddr>()
                .unwrap()
        ));
        // XOR'd 10.0.0.1 = 0xf5ff:fffe
        assert!(is_internal_ip(
            &"2001:0000:0000:0000:0000:0000:f5ff:fffe"
                .parse::<IpAddr>()
                .unwrap()
        ));
        // XOR'd 8.8.8.8 = 0xf7f7:f7f7 (public, should NOT be internal)
        assert!(!is_internal_ip(
            &"2001:0000:0000:0000:0000:0000:f7f7:f7f7"
                .parse::<IpAddr>()
                .unwrap()
        ));
    }

    #[test]
    fn rejects_6to4_embedded_internal() {
        assert!(validate_relay_url("wss://[2002:7f00:1::1]/").is_err());
        assert!(validate_relay_url("wss://[2002:a00:1::1]/").is_err());
        assert!(validate_relay_url("wss://[2002:c0a8:101::1]/").is_err());
    }

    #[test]
    fn rejects_teredo_embedded_internal() {
        // Teredo embedding 127.0.0.1 (XOR'd)
        assert!(validate_relay_url("wss://[2001:0000::80ff:fffe]/").is_err());
        // Teredo embedding 10.0.0.1 (XOR'd)
        assert!(validate_relay_url("wss://[2001:0000::f5ff:fffe]/").is_err());
    }

    #[test]
    fn is_internal_ip_blocks_documentation_prefix() {
        use std::net::IpAddr;
        assert!(is_internal_ip(&"2001:db8::1".parse::<IpAddr>().unwrap()));
        assert!(is_internal_ip(
            &"2001:db8:ffff::1".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn rejects_userinfo_in_url() {
        assert!(validate_relay_url("wss://user@relay.example.com/").is_err());
        assert!(validate_relay_url("wss://user:pass@relay.example.com/").is_err());
        assert!(validate_relay_url("wss://evil.com@relay.example.com/").is_err());
    }

    #[test]
    fn rejects_arpa_and_onion_tlds() {
        assert!(validate_relay_url("wss://host.arpa/").is_err());
        assert!(validate_relay_url("wss://10.in-addr.arpa/").is_err());
        assert!(validate_relay_url("wss://hidden.onion/").is_err());
    }

    #[test]
    fn rejects_mixed_case_trailing_dot() {
        assert!(validate_relay_url("wss://LocalHost./").is_err());
        assert!(validate_relay_url("wss://LOCALHOST./").is_err());
    }
}
