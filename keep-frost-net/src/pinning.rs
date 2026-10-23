// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! SPKI-pinning TLS certificate verifier.
//!
//! [`PinningServerCertVerifier`] plugs into a `rustls::ClientConfig` so the pin
//! check runs *inside the same TLS handshake* that carries the relay data,
//! rather than on a throwaway probe connection opened before the real socket.
//! A probe-then-connect design is a TOCTOU: an on-path attacker can serve a
//! benign certificate to the probe and a different one to the real connection.
//!
//! Pinning is layered strictly *on top of* standard validation, never in place
//! of it: [`PinningServerCertVerifier::verify_server_cert`] first delegates to a
//! `WebPkiServerVerifier` (full trust-anchor chain, validity window, hostname)
//! and only then enforces the SPKI pin on the leaf that just passed. A cert
//! that fails standard validation is rejected before the pin logic runs, so
//! enabling pinning can only tighten trust, never loosen it. (No CRL revocation
//! is configured, matching a typical TLS client; any OCSP staple the peer sends
//! is still passed through to the standard validator.)

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::error::FrostNetError;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::cert_pin::{self, CertificatePinSet, SpkiHash};

/// Why a live handshake refused a relay on pin policy.
///
/// The discriminant is covered by the pin-rejection audit HMAC, so it is
/// append-only: renumber one and every entry already written fails verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PinRejection {
    /// The certificate's key does not match a pin on record.
    Mismatch = 1,
    /// Strict mode, and this host has no pin on record.
    Missing = 2,
}

impl PinRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mismatch => "mismatch",
            Self::Missing => "missing",
        }
    }

    pub fn explanation(self) -> &'static str {
        match self {
            Self::Mismatch => "its certificate does not match the pinned key",
            Self::Missing => "strict pinning has no pin on record for it",
        }
    }

    pub(crate) fn discriminant(self) -> u8 {
        self as u8
    }
}

/// Called on the handshake thread when a pin check starts refusing a host.
///
/// Must not block, panic, or call back into the verifier. Invoked once per
/// host and reason until a later handshake for that host succeeds.
pub type PinFailureHook = Arc<dyn Fn(&str, PinRejection) + Send + Sync>;

/// A hostname, or a bracketed IP literal, short enough to store.
pub(crate) fn acceptable_relay_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
}

/// A `rustls` server-certificate verifier that adds SPKI pinning on top of
/// standard WebPKI validation. See the module docs for the layering guarantee.
#[derive(Clone)]
pub struct PinningServerCertVerifier {
    /// Standard validator, consulted first. A `dyn` so the pin logic can be
    /// unit-tested against a stub validator without a live certificate chain.
    inner: Arc<dyn ServerCertVerifier>,
    /// Accepted pins, shared with the caller and only ever READ here. The live
    /// handshake enforces what is on record; it never records anything itself.
    /// Learning a pin belongs to the pre-flight probe, which runs under the
    /// caller's pin lock and can do storage I/O. Keeping this path read-only is
    /// what stops a handshake from writing trust into the set the UI owns.
    pins: Arc<Mutex<CertificatePinSet>>,
    /// Strict mode: reject a host with no pin on record instead of accepting it
    /// on standard validation alone, closing the first-connection window.
    /// Mirrors `verify_relay_certificate`'s `require_pinned`.
    require_pinned: bool,
    /// Hosts already logged as accepted-with-no-pin, so the relay pool's
    /// reconnect loop does not repeat the same warning for the whole session.
    warned_unpinned: Arc<Mutex<HashSet<String>>>,
    /// Hosts currently refused, so a reconnect reports the transition once.
    /// Cleared when a later handshake for that host succeeds.
    failed: Arc<Mutex<HashSet<(String, PinRejection)>>>,
    on_failure: Option<PinFailureHook>,
}

impl fmt::Debug for PinningServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinningServerCertVerifier")
            .field("require_pinned", &self.require_pinned)
            .finish_non_exhaustive()
    }
}

impl PinningServerCertVerifier {
    /// Build a verifier that validates against `roots` (typically the WebPKI
    /// roots) and then enforces the SPKI pin. Returns an error if no root
    /// anchors are supplied (an empty root store is rejected by rustls rather
    /// than silently trusting everything).
    ///
    /// Resolves the crypto provider from the process default, which panics if
    /// none is installed. Library entry points reached across the UniFFI
    /// boundary must use [`Self::new_with_provider`] instead.
    pub fn new(
        roots: Arc<RootCertStore>,
        pins: Arc<Mutex<CertificatePinSet>>,
        require_pinned: bool,
    ) -> Result<Self, rustls::client::VerifierBuilderError> {
        let inner = WebPkiServerVerifier::builder(roots).build()?;
        Ok(Self::from_parts(inner, pins, require_pinned))
    }

    /// As [`Self::new`], but with the crypto provider supplied rather than
    /// resolved from the process default. `WebPkiServerVerifier::builder`
    /// resolves it with `get_default_or_install_from_crate_features`, which
    /// PANICS when nothing is installed and the crate features are ambiguous,
    /// and they are ambiguous here because both `ring` and `aws-lc-rs` reach
    /// rustls through the relay stack.
    pub fn new_with_provider(
        roots: Arc<RootCertStore>,
        pins: Arc<Mutex<CertificatePinSet>>,
        require_pinned: bool,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, rustls::client::VerifierBuilderError> {
        let inner = WebPkiServerVerifier::builder_with_provider(roots, provider).build()?;
        Ok(Self::from_parts(inner, pins, require_pinned))
    }

    fn from_parts(
        inner: Arc<WebPkiServerVerifier>,
        pins: Arc<Mutex<CertificatePinSet>>,
        require_pinned: bool,
    ) -> Self {
        Self {
            inner,
            pins,
            require_pinned,
            warned_unpinned: Arc::new(Mutex::new(HashSet::new())),
            failed: Arc::new(Mutex::new(HashSet::new())),
            on_failure: None,
        }
    }

    pub(crate) fn with_on_pin_failure(mut self, hook: PinFailureHook) -> Self {
        self.on_failure = Some(hook);
        self
    }

    /// Enforce the SPKI pin for `hostname` against the observed `spki_hash`,
    /// after standard validation has already accepted the certificate.
    ///
    /// Delegates the accept/reject decision to the shared
    /// [`cert_pin::evaluate_pin`] so a pin behaves identically here and in
    /// `verify_relay_certificate`. A mismatch, or a strict-mode host with no
    /// pin, is rejected with an application verification failure.
    ///
    /// Unlike the probe, this path never records a pin: see the `pins` field.
    fn enforce_pin(&self, hostname: &str, spki_hash: SpkiHash) -> Result<(), Error> {
        // Recover a poisoned lock rather than panicking: a prior panic while the
        // guard was held must not turn every later handshake into a panic (DoS).
        let decision = {
            let pins = self.pins.lock().unwrap_or_else(|p| p.into_inner());
            let expected = pins.get_pins(hostname);
            cert_pin::evaluate_pin(hostname, spki_hash, expected, self.require_pinned)
        };
        match decision {
            // No pin on record and strict mode is off, so standard validation
            // is all there is to go on. Accept, but deliberately do NOT record
            // the observed key: recording trust from inside a handshake is how
            // an on-path attacker holding any CA-valid certificate would get
            // itself pinned, and it would silently re-add a pin the user had
            // just cleared. Both shipped callers pre-pin every `wss` host on
            // the probe, so reaching this arm means the probe did not cover
            // this host, which is worth saying out loud.
            Ok((_, Some(_))) => {
                self.clear_failure(hostname);
                self.warn_once_unpinned(hostname);
                Ok(())
            }
            Ok((_, None)) => {
                self.clear_failure(hostname);
                Ok(())
            }
            Err(e) => {
                // The pool records a failed connection and stays up on its
                // other relays. Logged once per host, at error: the CLI's
                // default filter hides warnings, and the pool retries for the
                // life of the process. The hook turns the same transition into
                // an event and an audit entry.
                let reason = match &e {
                    FrostNetError::CertificatePinMismatch { .. } => Some(PinRejection::Mismatch),
                    FrostNetError::CertificatePinMissing { .. } => Some(PinRejection::Missing),
                    _ => None,
                };
                let first = match reason {
                    Some(reason) => self.report_failure(hostname, reason),
                    None => true,
                };
                if first {
                    tracing::error!(
                        relay_host = %hostname,
                        "TLS certificate pin check FAILED on the live relay connection; refusing it: {e}"
                    );
                }
                Err(Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
        }
    }

    /// Returns whether this is a new refusal. Repeat handshakes for a host
    /// already refused are the reconnect loop, not a new event.
    fn report_failure(&self, hostname: &str, reason: PinRejection) -> bool {
        {
            let mut failed = self.failed.lock().unwrap_or_else(|p| p.into_inner());
            if !failed.insert((hostname.to_string(), reason)) {
                return false;
            }
        }
        if let Some(hook) = &self.on_failure {
            hook(hostname, reason);
        }
        true
    }

    fn clear_failure(&self, hostname: &str) {
        let mut failed = self.failed.lock().unwrap_or_else(|p| p.into_inner());
        failed.retain(|(host, _)| host != hostname);
    }

    /// Warn the first time a host is accepted with no pin on record. The relay
    /// pool reconnects on a timer, so warning unconditionally here would repeat
    /// the same line for the life of the process.
    fn warn_once_unpinned(&self, hostname: &str) {
        let mut warned = self
            .warned_unpinned
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if warned.insert(hostname.to_string()) {
            tracing::warn!(
                relay_host = %hostname,
                "no TLS certificate pin on record for this relay; accepted on CA validation \
                 alone. Enable strict pinning to refuse un-pinned relays instead."
            );
        }
    }
}

impl ServerCertVerifier for PinningServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 1. Standard validation FIRST: trust-anchor chain, validity window,
        //    hostname match. Never bypassed.
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // 2. Extract the leaf SPKI from the exact certificate that just passed
        //    validation; fail closed if it cannot be parsed.
        let spki = cert_pin::extract_spki_from_der(end_entity.as_ref())
            .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let spki_hash = cert_pin::hash_spki(&spki);

        // 3. Enforce the SPKI pin on the validated leaf, on the same TLS session
        //    that will carry the data (no probe-vs-connect gap). The host key is
        //    normalized to match how `verify_relay_certificate` keys pins via
        //    `url::host_str()` (lowercased DNS labels, bracketed IPv6 literals),
        //    so a pin provisioned or captured by either path resolves in both.
        let hostname = match server_name {
            ServerName::DnsName(name) => name.as_ref().to_ascii_lowercase(),
            ServerName::IpAddress(ip) => match std::net::IpAddr::from(*ip) {
                addr @ std::net::IpAddr::V6(_) => format!("[{addr}]"),
                addr => addr.to_string(),
            },
            // ServerName is #[non_exhaustive]; an unrecognized name kind cannot
            // be keyed to a pin, so fail closed rather than guess a host string.
            _ => {
                return Err(Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
        };
        self.enforce_pin(&hostname, spki_hash)?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A P-256 self-signed cert (from cert_pin's fixtures), used only for its
    // parseable SPKI bytes. The stub validator below stands in for chain
    // validation, so this cert's own trust/expiry is irrelevant to these tests.
    fn cert_der() -> Vec<u8> {
        use base64::Engine;
        const CERT_B64: &str = "MIIBfTCCASOgAwIBAgIUHTPZUgNrUaDV8WbwKjVdqApCNHIwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJa2VlcC10ZXN0MB4XDTI2MDcwOTE2NDEzM1oXDTI2MDcxMDE2NDEzM1owFDESMBAGA1UEAwwJa2VlcC10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu4Nc5266JcHihyRoqfVvBOX2YfSvZ0CcpeJb8EilRnjI7YMdV7tU4pQpaBJmTJ8Om1mQ1d+HmrCwaKYTxlwzQ6NTMFEwHQYDVR0OBBYEFHjQXcwFh3SfDQ63QlR2m/p3n87kMB8GA1UdIwQYMBaAFHjQXcwFh3SfDQ63QlR2m/p3n87kMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgX734WY/RX390XIofsLw7i+xRvyZF0rYRQq/GD75jW4oCIQCyz+TfYUL8/GDcGDC+pWG961UgUjp5rGG3UiCjepovyA==";
        base64::engine::general_purpose::STANDARD
            .decode(CERT_B64)
            .unwrap()
    }

    fn cert_spki_hash() -> SpkiHash {
        cert_pin::hash_spki(&cert_pin::extract_spki_from_der(&cert_der()).unwrap())
    }

    /// Stub standard-validator: returns a fixed verdict so the pin logic can be
    /// exercised deterministically without a live trust-anchor chain.
    #[derive(Debug)]
    struct StubInner {
        accept: bool,
    }

    impl ServerCertVerifier for StubInner {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            if self.accept {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
            }
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }

    fn verifier(
        accept: bool,
        pins: CertificatePinSet,
        require_pinned: bool,
    ) -> PinningServerCertVerifier {
        PinningServerCertVerifier {
            inner: Arc::new(StubInner { accept }),
            pins: Arc::new(Mutex::new(pins)),
            require_pinned,
            warned_unpinned: Arc::new(Mutex::new(HashSet::new())),
            failed: Arc::new(Mutex::new(HashSet::new())),
            on_failure: None,
        }
    }

    fn run(v: &PinningServerCertVerifier, host: &str) -> Result<ServerCertVerified, Error> {
        let der = cert_der();
        let end_entity = CertificateDer::from(der);
        let name = ServerName::try_from(host.to_string()).unwrap();
        v.verify_server_cert(
            &end_entity,
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000)),
        )
    }

    #[test]
    fn rejects_when_standard_validation_fails_before_any_pin_check() {
        // The security-critical property: a chain the standard validator
        // rejects is refused, and pinning never gets a chance to accept it.
        // Even with a matching pin present, an untrusted chain must fail.
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), cert_spki_hash());
        let v = verifier(false, pins, false);
        let err = run(&v, "relay.example.com").unwrap_err();
        assert!(matches!(err, Error::InvalidCertificate(_)));
    }

    #[test]
    fn accepts_validated_cert_matching_existing_pin() {
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), cert_spki_hash());
        let v = verifier(true, pins, false);
        assert!(run(&v, "relay.example.com").is_ok());
    }

    #[test]
    fn rejects_validated_cert_with_mismatched_pin() {
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), [0xAAu8; 32]);
        let v = verifier(true, pins, false);
        let err = run(&v, "relay.example.com").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        ));
    }

    #[test]
    fn lenient_mode_accepts_unpinned_host_without_recording_a_pin() {
        // The live handshake must never write trust into the shared pin set:
        // that is what would let an on-path attacker with a CA-valid cert pin
        // itself, and what would resurrect a pin the user had just cleared.
        let v = verifier(true, CertificatePinSet::new(), false);
        assert!(run(&v, "relay.example.com").is_ok());
        assert!(
            v.pins
                .lock()
                .unwrap()
                .get_pins("relay.example.com")
                .is_empty(),
            "live handshake recorded a pin; it must only ever enforce them"
        );
    }

    #[test]
    fn strict_mode_rejects_unpinned_host_even_after_valid_chain() {
        let v = verifier(true, CertificatePinSet::new(), true);
        let err = run(&v, "relay.example.com").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        ));
    }

    #[test]
    fn strict_mode_accepts_matching_provisioned_pin() {
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), cert_spki_hash());
        let v = verifier(true, pins, true);
        assert!(run(&v, "relay.example.com").is_ok());
    }

    #[test]
    fn fails_closed_when_validated_leaf_spki_is_unparseable() {
        // A cert can pass the standard validator yet not parse under the SPKI
        // extractor (different parsers). That path must fail closed, never pin
        // a wrong/empty SPKI. Stub validator accepts; the leaf bytes are junk.
        let v = verifier(true, CertificatePinSet::new(), false);
        let end_entity = CertificateDer::from(b"not a certificate".to_vec());
        let name = ServerName::try_from("relay.example.com").unwrap();
        let err = v
            .verify_server_cert(
                &end_entity,
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000)),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidCertificate(CertificateError::BadEncoding)
        ));
    }

    #[test]
    fn dns_host_key_is_lowercased_to_match_url_keying() {
        // A pin provisioned under the lowercased host must resolve even when the
        // TLS ServerName carries mixed case, mirroring url::host_str() keying.
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), cert_spki_hash());
        let v = verifier(true, pins, true); // strict: only a keyed pin passes
        assert!(run(&v, "Relay.EXAMPLE.com").is_ok());
    }

    #[test]
    fn ip_address_server_name_is_keyed_under_its_literal() {
        // The IpAddress arm must key the pin under the address literal (IPv4
        // here). Strict mode proves the key matched: an un-keyed host is
        // rejected, so acceptance can only mean the provisioned pin resolved.
        let mut pins = CertificatePinSet::new();
        pins.add_pin("127.0.0.1".into(), cert_spki_hash());
        let v = verifier(true, pins, true);
        assert!(run(&v, "127.0.0.1").is_ok());
    }

    fn hooked(
        accept: bool,
        pins: Arc<Mutex<CertificatePinSet>>,
        require_pinned: bool,
        hits: Arc<Mutex<Vec<(String, PinRejection)>>>,
    ) -> PinningServerCertVerifier {
        PinningServerCertVerifier {
            inner: Arc::new(StubInner { accept }),
            pins,
            require_pinned,
            warned_unpinned: Arc::new(Mutex::new(HashSet::new())),
            failed: Arc::new(Mutex::new(HashSet::new())),
            on_failure: Some(Arc::new(move |host, reason| {
                hits.lock().unwrap().push((host.to_string(), reason));
            })),
        }
    }

    #[test]
    fn a_pin_mismatch_is_reported_once_until_a_later_handshake_succeeds() {
        let hits = Arc::new(Mutex::new(Vec::new()));
        let pins = Arc::new(Mutex::new(CertificatePinSet::new()));
        pins.lock()
            .unwrap()
            .add_pin("relay.example.com".into(), [0xAAu8; 32]);
        let v = hooked(true, Arc::clone(&pins), false, Arc::clone(&hits));

        assert!(run(&v, "relay.example.com").is_err());
        assert!(run(&v, "relay.example.com").is_err());
        assert_eq!(
            hits.lock().unwrap().as_slice(),
            [("relay.example.com".into(), PinRejection::Mismatch)]
        );

        pins.lock().unwrap().remove_pin("relay.example.com");
        pins.lock()
            .unwrap()
            .add_pin("relay.example.com".into(), cert_spki_hash());
        assert!(run(&v, "relay.example.com").is_ok());
        assert!(
            hits.lock().unwrap().len() == 1,
            "a match is not a rejection"
        );

        pins.lock().unwrap().remove_pin("relay.example.com");
        pins.lock()
            .unwrap()
            .add_pin("relay.example.com".into(), [0xAAu8; 32]);
        assert!(run(&v, "relay.example.com").is_err());
        assert_eq!(hits.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_strict_missing_pin_is_reported_once() {
        let hits = Arc::new(Mutex::new(Vec::new()));
        let v = hooked(
            true,
            Arc::new(Mutex::new(CertificatePinSet::new())),
            true,
            Arc::clone(&hits),
        );
        assert!(run(&v, "relay.example.com").is_err());
        assert!(run(&v, "relay.example.com").is_err());
        assert_eq!(
            hits.lock().unwrap().as_slice(),
            [("relay.example.com".into(), PinRejection::Missing)]
        );
    }

    #[test]
    fn a_chain_the_standard_validator_rejects_is_not_a_pin_failure() {
        let hits = Arc::new(Mutex::new(Vec::new()));
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), [0xAAu8; 32]);
        let v = hooked(false, Arc::new(Mutex::new(pins)), false, Arc::clone(&hits));
        assert!(run(&v, "relay.example.com").is_err());
        assert!(hits.lock().unwrap().is_empty());
    }
}
