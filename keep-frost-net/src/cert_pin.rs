// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use keep_core::relay::is_internal_ip;

use crate::error::{FrostNetError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub type SpkiHash = [u8; 32];

#[derive(Clone, Debug, Default)]
pub struct CertificatePinSet {
    /// One or more accepted SPKI hashes per hostname. Multiple pins let an
    /// operator stage a backup pin (RFC 7469) before rotating a relay's
    /// certificate, so both the current and next key verify during the
    /// overlap instead of a rotation hard-failing every connection.
    pins: HashMap<String, Vec<SpkiHash>>,
}

impl CertificatePinSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an accepted pin for `hostname`. Additive and de-duplicated: an
    /// existing pin for the host is retained (so a rotation can pre-stage the
    /// next key alongside the current one), and adding the same hash twice is
    /// a no-op.
    pub fn add_pin(&mut self, hostname: String, hash: SpkiHash) {
        let entry = self.pins.entry(hostname).or_default();
        if !entry.contains(&hash) {
            entry.push(hash);
        }
    }

    /// All accepted pins for `hostname` (empty slice if none).
    pub fn get_pins(&self, hostname: &str) -> &[SpkiHash] {
        self.pins.get(hostname).map_or(&[], Vec::as_slice)
    }

    /// Whether `hostname` has at least one pin (used to gate TOFU).
    pub fn is_pinned(&self, hostname: &str) -> bool {
        self.pins.get(hostname).is_some_and(|v| !v.is_empty())
    }

    pub fn remove_pin(&mut self, hostname: &str) -> Option<Vec<SpkiHash>> {
        self.pins.remove(hostname)
    }

    pub fn pins(&self) -> &HashMap<String, Vec<SpkiHash>> {
        &self.pins
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

pub async fn verify_relay_certificate(
    relay_url: &str,
    pins: &CertificatePinSet,
) -> Result<(SpkiHash, Option<(String, SpkiHash)>)> {
    let url = url::Url::parse(relay_url)
        .map_err(|e| FrostNetError::Transport(format!("Invalid relay URL: {e}")))?;

    if url.scheme() != "wss" {
        return Err(FrostNetError::Transport(format!(
            "Expected wss:// scheme, got {}://",
            url.scheme()
        )));
    }

    let hostname = url
        .host_str()
        .ok_or_else(|| FrostNetError::Transport("Missing hostname".into()))?
        .to_string();

    let port = url.port_or_known_default().unwrap_or(443);
    let addr = if hostname.contains(':') {
        format!("[{hostname}]:{port}")
    } else {
        format!("{hostname}:{port}")
    };

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(hostname.as_str())
        .map_err(|_| FrostNetError::Transport(format!("Invalid server name: {hostname}")))?
        .to_owned();

    let resolve_addr = addr.clone();
    let addrs: Vec<SocketAddr> = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            resolve_addr
                .to_socket_addrs()
                .ok()
                .map(|iter| iter.collect::<Vec<SocketAddr>>())
                .filter(|v| !v.is_empty())
        }),
    )
    .await
    .map_err(|_| FrostNetError::Timeout(format!("DNS resolve {addr}")))?
    .map_err(|e| FrostNetError::Transport(format!("DNS resolve {addr}: {e}")))?
    .ok_or_else(|| FrostNetError::Transport(format!("No addresses for {addr}")))?;

    let safe_addrs: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| !is_internal_ip(&a.ip()))
        .collect();
    if safe_addrs.is_empty() {
        return Err(FrostNetError::Transport(format!(
            "Relay {hostname} resolves to internal addresses only"
        )));
    }

    let tcp_stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&safe_addrs[..]))
        .await
        .map_err(|_| FrostNetError::Timeout(format!("TCP connect to {addr}")))?
        .map_err(|e| FrostNetError::Transport(format!("TCP connect to {addr}: {e}")))?;

    let tls_stream =
        tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| FrostNetError::Timeout(format!("TLS handshake with {hostname}")))?
            .map_err(|e| FrostNetError::Transport(format!("TLS handshake with {hostname}: {e}")))?;

    let (_, server_conn) = tls_stream.get_ref();
    let leaf_cert = server_conn
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| FrostNetError::Transport(format!("No certificates from {hostname}")))?;

    let spki_bytes = extract_spki_from_der(leaf_cert.as_ref()).ok_or_else(|| {
        FrostNetError::Transport(format!("Failed to parse certificate from {hostname}"))
    })?;

    let spki_hash = hash_spki(spki_bytes);

    let expected = pins.get_pins(&hostname);
    if expected.is_empty() {
        // Trust-on-first-use: no pin yet, surface the observed hash to pin.
        return Ok((spki_hash, Some((hostname, spki_hash))));
    }
    // Accept if the observed hash matches ANY pinned key (current or a staged
    // backup). Fold the constant-time comparisons without short-circuiting so
    // the match position does not leak via timing.
    let mut matched = subtle::Choice::from(0u8);
    for pin in expected {
        matched |= spki_hash.ct_eq(pin);
    }
    if !bool::from(matched) {
        return Err(FrostNetError::CertificatePinMismatch {
            hostname,
            expected: "***".into(),
            actual: hex::encode(spki_hash),
        });
    }
    Ok((spki_hash, None))
}

fn hash_spki(spki_der: &[u8]) -> SpkiHash {
    Sha256::digest(spki_der).into()
}

fn extract_spki_from_der(cert_der: &[u8]) -> Option<&[u8]> {
    let content = read_der_sequence(cert_der)?;
    let tbs_content = read_der_sequence(content)?;

    let mut pos = tbs_content;

    if !pos.is_empty() && pos[0] == 0xA0 {
        pos = skip_der_element(pos)?;
    }

    for _ in 0..5 {
        pos = skip_der_element(pos)?;
    }

    let element_len = der_element_total_len(pos)?;
    Some(&pos[..element_len])
}

fn read_der_sequence(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }
    let (content_start, content_len) = read_der_length(&data[1..])?;
    let start = 1 + content_start;
    if start + content_len > data.len() {
        return None;
    }
    Some(&data[start..start + content_len])
}

fn skip_der_element(data: &[u8]) -> Option<&[u8]> {
    let total = der_element_total_len(data)?;
    Some(&data[total..])
}

fn der_element_total_len(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let (content_start, content_len) = read_der_length(&data[1..])?;
    let total = 1 + content_start + content_len;
    if total > data.len() {
        return None;
    }
    Some(total)
}

fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        return Some((1, first as usize));
    }
    if first == 0x80 {
        return None;
    }
    let num_bytes = (first & 0x7F) as usize;
    if num_bytes > 4 || num_bytes + 1 > data.len() {
        return None;
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = len.checked_shl(8)?.checked_add(data[1 + i] as usize)?;
    }
    if num_bytes == 1 && len < 0x80 {
        return None;
    }
    if num_bytes > 1 && data[1] == 0 {
        return None;
    }
    Some((1 + num_bytes, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_set_operations() {
        let mut pins = CertificatePinSet::new();
        assert!(pins.is_empty());

        let hash = [42u8; 32];
        pins.add_pin("relay.example.com".into(), hash);
        assert!(pins.is_pinned("relay.example.com"));
        assert_eq!(pins.get_pins("relay.example.com"), &[hash]);
        assert!(!pins.is_empty());

        let removed = pins.remove_pin("relay.example.com");
        assert_eq!(removed, Some(vec![hash]));
        assert!(pins.is_empty());
    }

    #[test]
    fn test_multi_pin_for_rotation() {
        // A host can hold a current pin plus a staged backup; adding is
        // additive and de-duplicated, and both are accepted.
        let mut pins = CertificatePinSet::new();
        let current = [1u8; 32];
        let backup = [2u8; 32];
        pins.add_pin("relay.example.com".into(), current);
        pins.add_pin("relay.example.com".into(), backup);
        pins.add_pin("relay.example.com".into(), current); // dedup, no-op
        assert_eq!(pins.get_pins("relay.example.com"), &[current, backup]);
        assert!(pins.get_pins("other.example.com").is_empty());
        assert!(!pins.is_pinned("other.example.com"));
    }

    #[test]
    fn test_der_length_short_form() {
        assert_eq!(read_der_length(&[0x05]), Some((1, 5)));
        assert_eq!(read_der_length(&[0x7F]), Some((1, 127)));
    }

    #[test]
    fn test_der_length_long_form() {
        assert_eq!(read_der_length(&[0x81, 0x80]), Some((2, 128)));
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00]), Some((3, 256)));
    }

    #[test]
    fn test_der_length_invalid() {
        assert_eq!(read_der_length(&[]), None);
        assert_eq!(read_der_length(&[0x80]), None);
    }

    #[test]
    fn test_der_length_rejects_non_canonical() {
        assert_eq!(read_der_length(&[0x81, 0x05]), None);
        assert_eq!(read_der_length(&[0x82, 0x00, 0x80]), None);
    }
}
