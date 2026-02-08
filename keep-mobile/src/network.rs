// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use subtle::ConstantTimeEq;

use crate::error::KeepMobileError;
use crate::types::PeerStatus;

pub(crate) fn validate_relay_url(relay_url: &str) -> Result<(), KeepMobileError> {
    let parsed = url::Url::parse(relay_url).map_err(|_| KeepMobileError::InvalidRelayUrl {
        msg: "Invalid URL format".into(),
    })?;

    if parsed.scheme() != "wss" {
        return Err(KeepMobileError::InvalidRelayUrl {
            msg: "Must use wss:// protocol".into(),
        });
    }

    let host = parsed.host_str().ok_or(KeepMobileError::InvalidRelayUrl {
        msg: "Missing host".into(),
    })?;

    if is_internal_host(host) {
        return Err(KeepMobileError::InvalidRelayUrl {
            msg: "Internal addresses not allowed".into(),
        });
    }

    Ok(())
}

pub(crate) fn convert_peer_status(status: keep_frost_net::PeerStatus) -> PeerStatus {
    match status {
        keep_frost_net::PeerStatus::Online => PeerStatus::Online,
        keep_frost_net::PeerStatus::Offline => PeerStatus::Offline,
        keep_frost_net::PeerStatus::Unknown => PeerStatus::Unknown,
    }
}

pub(crate) fn validate_hex_pubkey(key: &str) -> Result<(), KeepMobileError> {
    if key.len() != 64 {
        return Err(KeepMobileError::InvalidShare {
            msg: "Group pubkey must be 64 hex characters".into(),
        });
    }
    if !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KeepMobileError::InvalidShare {
            msg: "Group pubkey must be valid hex".into(),
        });
    }
    Ok(())
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

pub(crate) fn parse_loopback_proxy(
    host: &str,
    port: u16,
) -> Result<std::net::SocketAddr, KeepMobileError> {
    let ip: std::net::IpAddr = match host {
        "localhost" => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        _ => host
            .parse()
            .map_err(|_| KeepMobileError::InvalidRelayUrl {
                msg: "Invalid proxy host".into(),
            })?,
    };

    if !ip.is_loopback() {
        return Err(KeepMobileError::InvalidRelayUrl {
            msg: "Proxy must be a loopback address".into(),
        });
    }

    Ok(std::net::SocketAddr::new(ip, port))
}

pub(crate) fn parse_warden_pubkey(
    pubkey_hex: &str,
) -> Result<[u8; crate::policy::POLICY_PUBKEY_LEN], KeepMobileError> {
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|e| KeepMobileError::InvalidPolicy {
        msg: format!("Invalid hex: {e}"),
    })?;

    pubkey_bytes
        .try_into()
        .map_err(|_| KeepMobileError::InvalidPolicy {
            msg: format!(
                "Warden pubkey must be {} bytes",
                crate::policy::POLICY_PUBKEY_LEN
            ),
        })
}

fn is_internal_host(host: &str) -> bool {
    let host = host.to_lowercase();

    const FORBIDDEN_EXACT: &[&str] = &[
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "[::1]",
        "169.254.169.254",
    ];

    FORBIDDEN_EXACT.contains(&host.as_str())
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("169.254.")
        || is_private_ipv4_range(&host, "100.", 64..=127)
        || is_private_ipv4_range(&host, "172.", 16..=31)
        || is_private_ipv6(&host)
}

fn is_private_ipv4_range(host: &str, prefix: &str, range: std::ops::RangeInclusive<u8>) -> bool {
    host.strip_prefix(prefix)
        .and_then(|rest| rest.split('.').next())
        .and_then(|s| s.parse::<u8>().ok())
        .is_some_and(|octet| range.contains(&octet))
}

fn is_private_ipv6(host: &str) -> bool {
    let normalized = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    if let Ok(addr) = normalized.parse::<std::net::Ipv6Addr>() {
        if let Some(mapped_v4) = addr.to_ipv4_mapped() {
            return mapped_v4.is_loopback() || mapped_v4.is_private() || mapped_v4.is_link_local();
        }
    }

    normalized.starts_with("fc")
        || normalized.starts_with("fd")
        || normalized.starts_with("fe80:")
        || normalized.starts_with("fe80%")
}
