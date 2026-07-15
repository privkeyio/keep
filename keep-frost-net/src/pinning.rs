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
//! `WebPkiServerVerifier` (full trust-anchor chain, validity window, hostname,
//! revocation) and only then enforces the SPKI pin on the leaf that just
//! passed. A cert that fails standard validation is rejected before the pin
//! logic runs, so enabling pinning can only tighten trust, never loosen it.

use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::cert_pin::{self, CertificatePinSet, SpkiHash};

/// Callback invoked when a host is pinned for the first time (trust-on-first-use),
/// so the caller can persist the newly observed pin. Runs inside the handshake;
/// keep it cheap and non-blocking.
pub type OnNewPin = Arc<dyn Fn(&str, &SpkiHash) + Send + Sync>;

/// A `rustls` server-certificate verifier that adds SPKI pinning on top of
/// standard WebPKI validation. See the module docs for the layering guarantee.
#[derive(Clone)]
pub struct PinningServerCertVerifier {
    /// Standard validator, consulted first. A `dyn` so the pin logic can be
    /// unit-tested against a stub validator without a live certificate chain.
    inner: Arc<dyn ServerCertVerifier>,
    /// Accepted pins, shared with the caller. On trust-on-first-use the observed
    /// pin is inserted here so later connections in this process enforce it.
    pins: Arc<Mutex<CertificatePinSet>>,
    /// Strict mode: reject a host with no pre-provisioned pin instead of
    /// trust-on-first-use, closing the first-connection window. Supplied by the
    /// caller's policy, mirroring `verify_relay_certificate`'s `require_pinned`.
    require_pinned: bool,
    /// Optional persistence hook for trust-on-first-use pins.
    on_new_pin: Option<OnNewPin>,
}

impl fmt::Debug for PinningServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinningServerCertVerifier")
            .field("require_pinned", &self.require_pinned)
            .field("has_on_new_pin", &self.on_new_pin.is_some())
            .finish_non_exhaustive()
    }
}

impl PinningServerCertVerifier {
    /// Build a verifier that validates against `roots` (typically the WebPKI
    /// roots) and then enforces the SPKI pin. Returns an error if no root
    /// anchors are supplied (an empty root store is rejected by rustls rather
    /// than silently trusting everything).
    pub fn new(
        roots: Arc<RootCertStore>,
        pins: Arc<Mutex<CertificatePinSet>>,
        require_pinned: bool,
        on_new_pin: Option<OnNewPin>,
    ) -> Result<Self, rustls::client::VerifierBuilderError> {
        let inner = WebPkiServerVerifier::builder(roots).build()?;
        Ok(Self {
            inner,
            pins,
            require_pinned,
            on_new_pin,
        })
    }

    /// Enforce the SPKI pin for `hostname` against the observed `spki_hash`,
    /// after standard validation has already accepted the certificate.
    ///
    /// Delegates the accept/reject/trust-on-first-use decision to the shared
    /// [`cert_pin::evaluate_pin`] so pinning behaves identically here and in
    /// `verify_relay_certificate`. On first sighting the pin is recorded (and
    /// the persistence hook fired); a mismatch or a strict-mode unpinned host is
    /// rejected with an application verification failure.
    fn enforce_pin(&self, hostname: &str, spki_hash: SpkiHash) -> Result<(), Error> {
        let mut pins = self.pins.lock().unwrap_or_else(|p| p.into_inner());
        let decision = {
            let expected = pins.get_pins(hostname);
            cert_pin::evaluate_pin(hostname, spki_hash, expected, self.require_pinned)
        };
        match decision {
            Ok((_, Some((host, hash)))) => {
                // Trust-on-first-use: no pin yet and strict mode is off. Record
                // the observed pin so subsequent connections this process makes
                // enforce it, then hand it to the caller to persist.
                pins.add_pin(host.clone(), hash);
                drop(pins);
                if let Some(cb) = &self.on_new_pin {
                    cb(&host, &hash);
                }
                Ok(())
            }
            Ok((_, None)) => Ok(()),
            Err(_) => Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
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
        //    hostname match, revocation. Never bypassed.
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
        //    that will carry the data (no probe-vs-connect gap).
        let hostname = match server_name {
            ServerName::DnsName(name) => name.as_ref().to_string(),
            ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        on_new_pin: Option<OnNewPin>,
    ) -> PinningServerCertVerifier {
        PinningServerCertVerifier {
            inner: Arc::new(StubInner { accept }),
            pins: Arc::new(Mutex::new(pins)),
            require_pinned,
            on_new_pin,
        }
    }

    fn run(v: &PinningServerCertVerifier, host: &str) -> Result<ServerCertVerified, Error> {
        let der = cert_der();
        let end_entity = CertificateDer::from(der);
        let name = ServerName::try_from(host.to_string()).unwrap();
        v.verify_server_cert(&end_entity, &[], &name, &[], UnixTime::since_unix_epoch(
            std::time::Duration::from_secs(1_800_000_000),
        ))
    }

    #[test]
    fn rejects_when_standard_validation_fails_before_any_pin_check() {
        // The security-critical property: a chain the standard validator
        // rejects is refused, and pinning never gets a chance to accept it.
        // Even with a matching pin present, an untrusted chain must fail.
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), cert_spki_hash());
        let v = verifier(false, pins, false, None);
        let err = run(&v, "relay.example.com").unwrap_err();
        assert!(matches!(err, Error::InvalidCertificate(_)));
    }

    #[test]
    fn accepts_validated_cert_matching_existing_pin() {
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), cert_spki_hash());
        let v = verifier(true, pins, false, None);
        assert!(run(&v, "relay.example.com").is_ok());
    }

    #[test]
    fn rejects_validated_cert_with_mismatched_pin() {
        let mut pins = CertificatePinSet::new();
        pins.add_pin("relay.example.com".into(), [0xAAu8; 32]);
        let v = verifier(true, pins, false, None);
        let err = run(&v, "relay.example.com").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        ));
    }

    #[test]
    fn tofu_pins_unknown_host_and_fires_callback() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits2 = hits.clone();
        let cb: OnNewPin = Arc::new(move |host, hash| {
            assert_eq!(host, "relay.example.com");
            assert_eq!(*hash, cert_spki_hash());
            hits2.fetch_add(1, Ordering::SeqCst);
        });
        let v = verifier(true, CertificatePinSet::new(), false, Some(cb));
        assert!(run(&v, "relay.example.com").is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "callback fired once");
        // The observed pin is now recorded, so a second connection enforces it.
        assert_eq!(
            v.pins.lock().unwrap().get_pins("relay.example.com"),
            &[cert_spki_hash()]
        );
    }

    #[test]
    fn strict_mode_rejects_unpinned_host_even_after_valid_chain() {
        let v = verifier(true, CertificatePinSet::new(), true, None);
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
        let v = verifier(true, pins, true, None);
        assert!(run(&v, "relay.example.com").is_ok());
    }
}
