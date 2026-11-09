// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use crate::error::KeepMobileError;
use crate::types::PeerStatus;

pub(crate) fn validate_relay_url(relay_url: &str) -> Result<(), KeepMobileError> {
    keep_core::relay::validate_relay_url(relay_url)
        .map_err(|msg| KeepMobileError::InvalidRelayUrl { msg })
}

/// Relays held to the rules every other relay here is: `wss://`, no userinfo,
/// and not an internal address, which the pinned transport would refuse anyway
/// with an error that does not say why. Internal addresses pass only where the
/// transport lets them through too, in test builds.
pub(crate) fn validate_relay_urls(relays: &[String]) -> Result<(), KeepMobileError> {
    let validate = if keep_core::relay::ALLOW_INTERNAL_HOSTS {
        keep_core::relay::validate_relay_url_allow_internal
    } else {
        keep_core::relay::validate_relay_url
    };
    relays
        .iter()
        .try_for_each(|r| validate(r).map_err(|msg| KeepMobileError::InvalidRelayUrl { msg }))
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

pub(crate) fn parse_warden_pubkey_bytes(
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

pub(crate) fn parse_warden_pubkey(
    pubkey_hex: &str,
) -> Result<[u8; crate::policy::POLICY_PUBKEY_LEN], KeepMobileError> {
    let pubkey = parse_warden_pubkey_bytes(pubkey_hex)?;
    // A key that is not a curve point can never sign, so trusting one would
    // spend an epoch, or the first-warden slot, on a warden that cannot act.
    k256::schnorr::VerifyingKey::from_bytes(&pubkey).map_err(|_| {
        KeepMobileError::InvalidPolicy {
            msg: "Warden pubkey is not a valid key".into(),
        }
    })?;
    Ok(pubkey)
}
