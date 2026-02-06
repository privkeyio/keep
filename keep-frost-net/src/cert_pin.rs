// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::{FrostNetError, Result};

pub type SpkiHash = [u8; 32];

#[derive(Clone, Debug, Default)]
pub struct CertificatePinSet {
    pins: HashMap<String, SpkiHash>,
}

impl CertificatePinSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_pin(&mut self, hostname: String, hash: SpkiHash) {
        self.pins.insert(hostname, hash);
    }

    pub fn get_pin(&self, hostname: &str) -> Option<&SpkiHash> {
        self.pins.get(hostname)
    }

    pub fn remove_pin(&mut self, hostname: &str) -> Option<SpkiHash> {
        self.pins.remove(hostname)
    }

    pub fn pins(&self) -> &HashMap<String, SpkiHash> {
        &self.pins
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

pub async fn verify_relay_certificate(
    relay_url: &str,
    pins: &mut CertificatePinSet,
) -> Result<SpkiHash> {
    let url = url::Url::parse(relay_url)
        .map_err(|e| FrostNetError::Transport(format!("Invalid relay URL: {}", e)))?;

    let hostname = url
        .host_str()
        .ok_or_else(|| FrostNetError::Transport("Missing hostname".into()))?
        .to_string();

    let port = url.port_or_known_default().unwrap_or(443);
    let addr = format!("{}:{}", hostname, port);

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(hostname.as_str())
        .map_err(|_| FrostNetError::Transport(format!("Invalid server name: {}", hostname)))?
        .to_owned();

    let tcp_stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| FrostNetError::Timeout(format!("TCP connect to {}", addr)))?
        .map_err(|e| FrostNetError::Transport(format!("TCP connect to {}: {}", addr, e)))?;

    let tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .map_err(|_| FrostNetError::Timeout(format!("TLS handshake with {}", hostname)))?
    .map_err(|e| FrostNetError::Transport(format!("TLS handshake with {}: {}", hostname, e)))?;

    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn
        .peer_certificates()
        .ok_or_else(|| FrostNetError::Transport(format!("No certificates from {}", hostname)))?;

    let leaf_cert = certs
        .first()
        .ok_or_else(|| FrostNetError::Transport(format!("Empty cert chain from {}", hostname)))?;

    let spki_bytes = extract_spki_from_der(leaf_cert.as_ref()).ok_or_else(|| {
        FrostNetError::Transport(format!("Failed to parse certificate from {}", hostname))
    })?;

    let spki_hash = hash_spki(spki_bytes);

    if let Some(expected) = pins.get_pin(&hostname) {
        if spki_hash != *expected {
            return Err(FrostNetError::CertificatePinMismatch {
                hostname,
                expected: hex::encode(expected),
                actual: hex::encode(spki_hash),
            });
        }
    } else {
        pins.add_pin(hostname, spki_hash);
    }

    Ok(spki_hash)
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
        Some((1, first as usize))
    } else if first == 0x80 {
        None
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || num_bytes + 1 > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = len.checked_shl(8)?.checked_add(data[1 + i] as usize)?;
        }
        Some((1 + num_bytes, len))
    }
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
        assert_eq!(pins.get_pin("relay.example.com"), Some(&hash));
        assert!(!pins.is_empty());

        let removed = pins.remove_pin("relay.example.com");
        assert_eq!(removed, Some(hash));
        assert!(pins.is_empty());
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
}
