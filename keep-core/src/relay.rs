// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

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
    /// FROST coordination relay URLs (wss://).
    pub frost_relays: Vec<String>,
    /// Profile / NIP-46 relay URLs (wss://).
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

/// Validate a relay URL.
///
/// Returns Ok(()) if the URL is a valid wss:// URL pointing to a public host.
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
    let host = if let Some(colon_pos) = host_port.rfind(':') {
        let port_str = &host_port[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            if port == 0 {
                return Err("Invalid port".into());
            }
        }
        &host_port[..colon_pos]
    } else {
        host_port
    };

    if host.is_empty() {
        return Err("Missing host".into());
    }

    if !host.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '[' || c == ']' || c == ':'
    }) {
        return Err("Invalid host characters".into());
    }

    if is_internal_host(host) {
        return Err("Internal addresses not allowed".into());
    }

    Ok(())
}

fn is_internal_host(host: &str) -> bool {
    let host = host.to_lowercase();

    const FORBIDDEN: &[&str] = &[
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "[::1]",
        "169.254.169.254",
    ];

    FORBIDDEN.contains(&host.as_str())
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("169.254.")
        || is_private_172(host.as_str())
}

fn is_private_172(host: &str) -> bool {
    host.strip_prefix("172.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|s| s.parse::<u8>().ok())
        .is_some_and(|octet| (16..=31).contains(&octet))
}
