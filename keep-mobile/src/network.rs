// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use subtle::ConstantTimeEq;

use crate::error::KeepMobileError;
use crate::types::PeerStatus;

pub(crate) fn validate_relay_url(relay_url: &str) -> Result<(), KeepMobileError> {
    keep_core::relay::validate_relay_url(relay_url)
        .map_err(|msg| KeepMobileError::InvalidRelayUrl { msg })
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
        _ => host.parse().map_err(|_| KeepMobileError::InvalidRelayUrl {
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
