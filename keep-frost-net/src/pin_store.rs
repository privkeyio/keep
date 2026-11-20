// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::cert_pin::{verify_relay_certificate, CertificatePinSet, SpkiHash};
use crate::error::{FrostNetError, Result};
use crate::pinned_transport::TlsPinning;

const FILE_NAME: &str = "cert-pins.json";

/// Longest [`RelayPinStore::probe_tolerant`] waits on any one relay, from DNS
/// through the TLS handshake, so a service's startup stays bounded however
/// many relays are down.
pub const TOLERANT_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

type Verdict = Result<(SpkiHash, Option<(String, SpkiHash)>)>;

/// A relay [`RelayPinStore::probe_tolerant`] did not pin or confirm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeSkip {
    /// The relay could not be reached. Its pin, if any, is unchanged and the
    /// live handshake still enforces it.
    Unreachable { relay: String, error: String },
    /// The relay presented a certificate that does not match its pin.
    PinMismatch { relay: String, hostname: String },
}

impl std::fmt::Display for ProbeSkip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { relay, error } => write!(f, "{relay} unreachable: {error}"),
            Self::PinMismatch { relay, .. } => {
                write!(f, "{relay} certificate does not match its pin")
            }
        }
    }
}

/// On-disk SPKI pin set for a process that has a data directory and no
/// settings UI. The live handshake reads this set and never writes it; the
/// probe below is what records a trust-on-first-use pin.
pub struct RelayPinStore {
    path: PathBuf,
    pins: Arc<Mutex<CertificatePinSet>>,
    require_pinned: bool,
}

impl RelayPinStore {
    /// Load `cert-pins.json` from `dir`. A missing file is a first run. A
    /// file that cannot be read, or that contains a pin that cannot be
    /// decoded, is refused: dropping it would let the next connection pin
    /// whatever certificate is presented.
    pub fn open(dir: &Path, require_pinned: bool) -> Result<Self> {
        let path = dir.join(FILE_NAME);
        let pins = match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => CertificatePinSet::new(),
            Err(e) => {
                return Err(FrostNetError::Transport(format!(
                    "certificate pin store {}: {e}",
                    path.display()
                )))
            }
            Ok(bytes) => {
                let (pins, malformed) =
                    CertificatePinSet::from_json_bytes(&bytes).map_err(|e| {
                        FrostNetError::Transport(format!(
                            "certificate pin store {}: {e}",
                            path.display()
                        ))
                    })?;
                if !malformed.is_empty() {
                    return Err(FrostNetError::Transport(format!(
                        "certificate pin store {} is corrupt ({})",
                        path.display(),
                        malformed.join("; ")
                    )));
                }
                pins
            }
        };
        Ok(Self {
            path,
            pins: Arc::new(Mutex::new(pins)),
            require_pinned,
        })
    }

    /// The handle the live relay socket enforces. It shares this set, so a
    /// pin the probe just recorded is the one the handshake checks.
    pub fn pinning(&self) -> TlsPinning {
        TlsPinning::new(self.pins.clone(), self.require_pinned)
    }

    pub fn is_pinned(&self, hostname: &str) -> Result<bool> {
        Ok(self.lock()?.is_pinned(hostname))
    }

    /// Learn or enforce a pin for every `wss://` relay, and persist any pin
    /// learned for the first time. A cleartext relay is skipped unless strict
    /// pinning is on, in which case it is refused before anything is dialed.
    /// The first relay that fails stops the probe.
    pub async fn probe(&self, relays: &[String], proxy: Option<SocketAddr>) -> Result<()> {
        self.check_relays(relays)?;
        for relay in relays.iter().filter(|r| r.starts_with("wss://")) {
            let snapshot = self.lock()?.clone();
            let (hash, learned) =
                verify_relay_certificate(relay, &snapshot, self.require_pinned, proxy).await?;
            if let Some(hostname) = self.record(learned)? {
                return Err(FrostNetError::CertificatePinMismatch {
                    hostname,
                    expected: "the pin on record".into(),
                    actual: hex::encode(hash),
                });
            }
        }
        Ok(())
    }

    /// Like [`probe`](Self::probe), for a long-running service that must not
    /// stop because one relay is down. Relays are probed concurrently, each
    /// within [`TOLERANT_PROBE_BUDGET`]. A relay that cannot be reached is
    /// skipped, and the live pinned handshake still enforces its pin when it
    /// connects later. A relay whose certificate does not match its pin is
    /// returned so the caller can refuse it. Still fatal are a URL the probe
    /// refuses, a cleartext or unpinned relay under strict pinning, a pin
    /// store that cannot be saved, and every relay failing. A cleartext relay,
    /// allowed only while strict pinning is off, is not probed and counts as
    /// usable.
    pub async fn probe_tolerant(
        &self,
        relays: &[String],
        proxy: Option<SocketAddr>,
    ) -> Result<Vec<ProbeSkip>> {
        let require_pinned = self.require_pinned;
        self.probe_tolerant_with(relays, move |relay, snapshot| async move {
            verify_relay_certificate(&relay, &snapshot, require_pinned, proxy).await
        })
        .await
    }

    /// Probe relays [`probe_tolerant`](Self::probe_tolerant) skipped as
    /// unreachable until each one answers, so a relay that was down at
    /// startup gets its first-use pin from a verified probe once it is back.
    /// The live handshake shares this pin set, so it enforces the pin from
    /// then on. Returns once no relay is left unreachable, or with the error
    /// that makes another round pointless.
    pub async fn pin_when_reachable(
        &self,
        relays: Vec<String>,
        proxy: Option<SocketAddr>,
        interval: std::time::Duration,
    ) -> Result<()> {
        let require_pinned = self.require_pinned;
        self.pin_when_reachable_with(relays, interval, move |relay, snapshot| async move {
            verify_relay_certificate(&relay, &snapshot, require_pinned, proxy).await
        })
        .await
    }

    async fn pin_when_reachable_with<F, Fut>(
        &self,
        mut relays: Vec<String>,
        interval: std::time::Duration,
        verify: F,
    ) -> Result<()>
    where
        F: Fn(String, CertificatePinSet) -> Fut,
        Fut: std::future::Future<Output = Verdict> + Send + 'static,
    {
        while !relays.is_empty() {
            tokio::time::sleep(interval).await;
            relays = self
                .probe_each(&relays, &verify)
                .await?
                .into_iter()
                .filter_map(|skip| match skip {
                    ProbeSkip::Unreachable { relay, .. } => Some(relay),
                    ProbeSkip::PinMismatch { .. } => None,
                })
                .collect();
        }
        Ok(())
    }

    async fn probe_tolerant_with<F, Fut>(
        &self,
        relays: &[String],
        verify: F,
    ) -> Result<Vec<ProbeSkip>>
    where
        F: Fn(String, CertificatePinSet) -> Fut,
        Fut: std::future::Future<Output = Verdict> + Send + 'static,
    {
        let skipped = self.probe_each(relays, &verify).await?;
        if !relays.is_empty() && skipped.len() == relays.len() {
            let reasons: Vec<String> = skipped.iter().map(ProbeSkip::to_string).collect();
            return Err(FrostNetError::Transport(format!(
                "no relay passed the certificate probe ({})",
                reasons.join("; ")
            )));
        }
        Ok(skipped)
    }

    async fn probe_each<F, Fut>(&self, relays: &[String], verify: &F) -> Result<Vec<ProbeSkip>>
    where
        F: Fn(String, CertificatePinSet) -> Fut,
        Fut: std::future::Future<Output = Verdict> + Send + 'static,
    {
        self.check_relays(relays)?;
        let snapshot = self.lock()?.clone();
        let mut probes = tokio::task::JoinSet::new();
        for (i, relay) in relays.iter().enumerate() {
            if relay.starts_with("wss://") {
                let probe = verify(relay.clone(), snapshot.clone());
                probes.spawn(async move {
                    let verdict = tokio::time::timeout(TOLERANT_PROBE_BUDGET, probe)
                        .await
                        .unwrap_or_else(|_| {
                            Err(FrostNetError::Timeout("certificate probe budget".into()))
                        });
                    (i, verdict)
                });
            }
        }
        let mut verdicts = Vec::new();
        while let Some(joined) = probes.join_next().await {
            verdicts.push(
                joined.map_err(|e| {
                    FrostNetError::Transport(format!("certificate probe task: {e}"))
                })?,
            );
        }
        verdicts.sort_by_key(|(i, _)| *i);
        let mut skipped = Vec::new();
        for (i, verdict) in verdicts {
            let relay = &relays[i];
            let verdict = match verdict {
                Ok((hash, learned)) => match self.record(learned)? {
                    Some(hostname) => Err(FrostNetError::CertificatePinMismatch {
                        hostname,
                        expected: "the key another probe of this host pinned".into(),
                        actual: hex::encode(hash),
                    }),
                    None => Ok(()),
                },
                Err(e) => Err(e),
            };
            match verdict {
                Ok(()) => {}
                Err(FrostNetError::CertificatePinMismatch { hostname, .. }) => {
                    tracing::error!(relay = %relay, hostname = %hostname, "relay certificate does not match its pin, refusing the relay");
                    skipped.push(ProbeSkip::PinMismatch {
                        relay: relay.clone(),
                        hostname,
                    });
                }
                Err(e @ (FrostNetError::Transport(_) | FrostNetError::Timeout(_))) => {
                    tracing::warn!(relay = %relay, error = %e, "relay unreachable for the certificate probe, skipping it");
                    skipped.push(ProbeSkip::Unreachable {
                        relay: relay.clone(),
                        error: e.to_string(),
                    });
                }
                Err(e) => return Err(e),
            }
        }
        Ok(skipped)
    }

    // Every relay the probe dials is checked before any is: it connects and
    // saves a pin, so a URL whose userinfo hides another host would reach
    // that host first. Internal hosts stay allowed for an operator's own
    // relay, and a direct dial still refuses an internal address.
    fn check_relays(&self, relays: &[String]) -> Result<()> {
        crate::install_default_crypto_provider();
        for relay in relays {
            if !relay.starts_with("wss://") {
                if self.require_pinned {
                    return Err(FrostNetError::Transport(format!(
                        "strict pinning refuses non-wss relay {relay}"
                    )));
                }
                continue;
            }
            keep_core::relay::validate_relay_url_allow_internal(relay).map_err(|e| {
                FrostNetError::Transport(format!("Rejected relay URL {relay}: {e}"))
            })?;
        }
        // Checked before dialing so strict pinning refuses an unpinned relay
        // even when it cannot be reached. Keyed the way
        // `verify_relay_certificate` keys pins.
        if self.require_pinned {
            for relay in relays {
                let hostname = url::Url::parse(relay)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
                    .ok_or_else(|| {
                        FrostNetError::Transport(format!("Rejected relay URL {relay}: no host"))
                    })?;
                if !self.lock()?.is_pinned(&hostname) {
                    return Err(FrostNetError::CertificatePinMissing { hostname });
                }
            }
        }
        Ok(())
    }

    /// Save a first-use pin. Returns the hostname when another probe of the
    /// same host already pinned a different key, which the caller treats as a
    /// mismatch: the probes compare against one snapshot taken before either
    /// pinned it.
    fn record(&self, learned: Option<(String, SpkiHash)>) -> Result<Option<String>> {
        if let Some((hostname, hash)) = learned {
            let mut pins = self.lock()?;
            if pins.is_pinned(&hostname) {
                if !pins.get_pins(&hostname).contains(&hash) {
                    return Ok(Some(hostname));
                }
            } else {
                pins.add_pin(hostname.clone(), hash);
                drop(pins);
                self.persist()?;
                tracing::info!(hostname = %hostname, "recorded relay certificate pin");
            }
        }
        Ok(None)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, CertificatePinSet>> {
        self.pins
            .lock()
            .map_err(|_| FrostNetError::Transport("certificate pin lock poisoned".into()))
    }

    fn persist(&self) -> Result<()> {
        if let Some(reasons) = corruption(&self.path)? {
            return Err(FrostNetError::Transport(format!(
                "refusing to overwrite corrupt certificate pin store ({})",
                reasons.join("; ")
            )));
        }
        let json = serde_json::to_string_pretty(&self.lock()?.to_hex_map())
            .map_err(|e| FrostNetError::Transport(format!("serialize certificate pins: {e}")))?;
        write_private(&self.path, json.as_bytes())
    }
}

/// `KEEP_STRICT_CERT_PINNING=1` or `true` turns strict pinning on for a
/// process that has no settings screen.
pub fn env_requests_strict_pinning() -> bool {
    value_requests_strict(std::env::var("KEEP_STRICT_CERT_PINNING").ok().as_deref())
}

fn value_requests_strict(value: Option<&str>) -> bool {
    matches!(value, Some("1") | Some("true") | Some("TRUE"))
}

fn corruption(path: &Path) -> Result<Option<Vec<String>>> {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(FrostNetError::Transport(format!(
            "certificate pin store {}: {e}",
            path.display()
        ))),
        Ok(bytes) => match CertificatePinSet::from_json_bytes(&bytes) {
            Ok((_, malformed)) if malformed.is_empty() => Ok(None),
            Ok((_, malformed)) => Ok(Some(malformed)),
            Err(e) => Ok(Some(vec![format!("parse error: {e}")])),
        },
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_file_name(".cert-pins.json.tmp");
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .map_err(|e| FrostNetError::Transport(format!("write {}: {e}", tmp.display())))?;
    file.write_all(data)
        .map_err(|e| FrostNetError::Transport(format!("write {}: {e}", tmp.display())))?;
    file.sync_all()
        .map_err(|e| FrostNetError::Transport(format!("sync {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| FrostNetError::Transport(format!("replace {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_missing_store_opens_empty() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        assert!(!store.is_pinned("relay.example.com").unwrap());
        assert!(!store.pinning().require_pinned());
    }

    #[test]
    fn a_recorded_pin_survives_reopen_and_strict_mode_is_on_the_handle() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        {
            let mut pins = store.lock().unwrap();
            pins.add_pin("relay.example.com".into(), [9u8; 32]);
        }
        store.persist().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(FILE_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let again = RelayPinStore::open(dir.path(), true).unwrap();
        assert!(again.is_pinned("relay.example.com").unwrap());
        assert!(again.pinning().require_pinned());
    }

    #[test]
    fn a_corrupt_store_refuses_to_open() {
        let dir = dir();
        std::fs::write(dir.path().join(FILE_NAME), b"not json").unwrap();
        assert!(RelayPinStore::open(dir.path(), false).is_err());
    }

    #[test]
    fn a_malformed_pin_refuses_to_open() {
        let dir = dir();
        std::fs::write(dir.path().join(FILE_NAME), br#"{"relay.example.com":"zz"}"#).unwrap();
        let Err(err) = RelayPinStore::open(dir.path(), false) else {
            panic!("corrupt pin store opened");
        };
        assert!(err.to_string().contains("corrupt"), "{err}");
    }

    #[tokio::test]
    async fn a_relay_with_userinfo_is_refused_before_it_is_dialed_or_pinned() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let relays = vec![
            "wss://relay.example.com".to_string(),
            "wss://relay.damus.io@evil.example".to_string(),
        ];
        let err = store
            .probe(&relays, Some(listener.local_addr().unwrap()))
            .await
            .expect_err("a relay URL with userinfo must be refused");
        assert!(err.to_string().contains("Rejected relay URL"), "{err}");
        assert_eq!(
            listener.accept().map_err(|e| e.kind()).err(),
            Some(std::io::ErrorKind::WouldBlock),
            "the probe must not reach the proxy for the host the userinfo hides"
        );
        assert!(!store.is_pinned("evil.example").unwrap());
    }

    #[tokio::test]
    async fn strict_pinning_refuses_a_cleartext_relay_before_dialing() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), true).unwrap();
        let err = store
            .probe(&["ws://127.0.0.1:1".into()], None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-wss"), "{err}");
        assert!(!dir.path().join(FILE_NAME).exists());
    }

    #[tokio::test]
    async fn strict_pinning_refuses_a_cleartext_relay_before_dialing_an_earlier_one() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), true).unwrap();
        let relays = vec![
            "wss://relay.example.com?token=abc".to_string(),
            "ws://relay.example.com".to_string(),
        ];
        let err = store
            .probe(&relays, Some(listener.local_addr().unwrap()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-wss"), "{err}");
        assert_eq!(
            listener.accept().map_err(|e| e.kind()).err(),
            Some(std::io::ErrorKind::WouldBlock)
        );
    }

    // Stands in for the TLS probe: a CA-valid relay cannot be served locally.
    // `good` learns a pin on first use, `bad` presents a key that does not
    // match its pin, and anything else cannot be reached.
    fn fake(relay: String, pins: CertificatePinSet) -> std::future::Ready<Verdict> {
        let host = url::Url::parse(&relay)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        std::future::ready(match host.as_str() {
            "good.example.com" => {
                let learned = (!pins.is_pinned(&host)).then(|| (host.clone(), [1u8; 32]));
                Ok(([1u8; 32], learned))
            }
            "bad.example.com" => Err(FrostNetError::CertificatePinMismatch {
                hostname: host,
                expected: "aa".into(),
                actual: "bb".into(),
            }),
            "slow.example.com" => Err(FrostNetError::Timeout(format!("TLS handshake with {host}"))),
            "strict.example.com" => Err(FrostNetError::CertificatePinMissing { hostname: host }),
            _ => Err(FrostNetError::Transport(format!("DNS resolve {host}:443"))),
        })
    }

    fn saved(dir: &Path) -> std::collections::HashMap<String, Vec<String>> {
        serde_json::from_slice(&std::fs::read(dir.join(FILE_NAME)).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn an_unreachable_relay_is_skipped_and_the_reachable_one_is_pinned() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let relays = vec![
            "wss://down.example.com".to_string(),
            "wss://slow.example.com".to_string(),
            "wss://good.example.com".to_string(),
        ];
        let skipped = store.probe_tolerant_with(&relays, fake).await.unwrap();
        assert_eq!(skipped.len(), 2);
        assert!(skipped
            .iter()
            .all(|s| matches!(s, ProbeSkip::Unreachable { .. })));
        assert!(store.is_pinned("good.example.com").unwrap());
        assert!(!store.is_pinned("down.example.com").unwrap());
        assert!(!store.is_pinned("slow.example.com").unwrap());
        let saved = saved(dir.path());
        assert_eq!(saved.len(), 1);
        assert!(saved.contains_key("good.example.com"));
    }

    #[tokio::test]
    async fn a_mismatched_relay_is_reported_and_its_pin_left_alone() {
        let dir = dir();
        let original = br#"{"bad.example.com":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#;
        std::fs::write(dir.path().join(FILE_NAME), original).unwrap();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let before = store.lock().unwrap().get_pins("bad.example.com").to_vec();
        let relays = vec![
            "wss://bad.example.com".to_string(),
            "wss://good.example.com".to_string(),
        ];
        let skipped = store.probe_tolerant_with(&relays, fake).await.unwrap();
        assert_eq!(
            skipped,
            vec![ProbeSkip::PinMismatch {
                relay: "wss://bad.example.com".into(),
                hostname: "bad.example.com".into(),
            }]
        );
        assert_eq!(
            store.lock().unwrap().get_pins("bad.example.com").to_vec(),
            before
        );
        let saved = saved(dir.path());
        assert_eq!(
            saved["bad.example.com"],
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()]
        );
        assert!(saved.contains_key("good.example.com"));
    }

    #[tokio::test]
    async fn every_relay_failing_still_refuses() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let relays = vec![
            "wss://down.example.com".to_string(),
            "wss://bad.example.com".to_string(),
        ];
        let err = store.probe_tolerant_with(&relays, fake).await.unwrap_err();
        assert!(err.to_string().contains("no relay passed"), "{err}");
        assert!(!dir.path().join(FILE_NAME).exists());
    }

    #[tokio::test]
    async fn every_relay_unreachable_on_the_real_probe_still_refuses() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let err = store
            .probe_tolerant(&["wss://relay.keep-probe-test.invalid".into()], None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no relay passed"), "{err}");
        assert!(!dir.path().join(FILE_NAME).exists());
    }

    #[tokio::test]
    async fn the_real_probe_skips_a_relay_it_cannot_reach() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        drop(listener);
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let relays = vec![
            "wss://down.example.com".to_string(),
            "ws://cleartext.example.com".to_string(),
        ];
        let skipped = store.probe_tolerant(&relays, Some(proxy)).await.unwrap();
        assert!(
            matches!(&skipped[..], [ProbeSkip::Unreachable { relay, .. }] if relay == "wss://down.example.com"),
            "{skipped:?}"
        );
        assert!(!dir.path().join(FILE_NAME).exists());
    }

    #[tokio::test]
    async fn strict_pinning_still_refuses_an_unpinned_relay() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), true).unwrap();
        let relays = vec![
            "wss://good.example.com".to_string(),
            "wss://strict.example.com".to_string(),
        ];
        let err = store.probe_tolerant_with(&relays, fake).await.unwrap_err();
        assert!(
            matches!(err, FrostNetError::CertificatePinMissing { .. }),
            "{err}"
        );
    }

    fn pinned_store(dir: &Path, hosts: &[&str], strict: bool) -> RelayPinStore {
        let map: std::collections::BTreeMap<&str, Vec<String>> = hosts
            .iter()
            .map(|h| (*h, vec![hex::encode([1u8; 32])]))
            .collect();
        std::fs::write(dir.join(FILE_NAME), serde_json::to_vec(&map).unwrap()).unwrap();
        RelayPinStore::open(dir, strict).unwrap()
    }

    #[tokio::test]
    async fn strict_pinning_refuses_an_unreachable_unpinned_relay_before_dialing() {
        let dir = dir();
        let store = pinned_store(dir.path(), &["good.example.com"], true);
        let dialed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = dialed.clone();
        let err = store
            .probe_tolerant_with(
                &[
                    "wss://good.example.com".to_string(),
                    "wss://down.example.com".to_string(),
                ],
                move |relay: String, pins: CertificatePinSet| {
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    fake(relay, pins)
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FrostNetError::CertificatePinMissing { hostname } if hostname == "down.example.com"),
            "{err}"
        );
        assert_eq!(dialed.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn strict_pinning_skips_an_unreachable_pinned_relay() {
        let dir = dir();
        let store = pinned_store(dir.path(), &["good.example.com", "down.example.com"], true);
        let skipped = store
            .probe_tolerant_with(
                &[
                    "wss://good.example.com".to_string(),
                    "wss://down.example.com".to_string(),
                ],
                fake,
            )
            .await
            .unwrap();
        assert!(
            matches!(&skipped[..], [ProbeSkip::Unreachable { relay, .. }] if relay == "wss://down.example.com"),
            "{skipped:?}"
        );
    }

    #[tokio::test]
    async fn the_tolerant_probe_refuses_what_the_strict_one_refuses_before_dialing() {
        let dir = dir();
        let strict = RelayPinStore::open(dir.path(), true).unwrap();
        let err = strict
            .probe_tolerant_with(&["ws://relay.example.com".into()], fake)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-wss"), "{err}");
        let lax = RelayPinStore::open(dir.path(), false).unwrap();
        let err = lax
            .probe_tolerant_with(
                &[
                    "wss://good.example.com".into(),
                    "wss://relay.damus.io@evil.example".into(),
                ],
                fake,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Rejected relay URL"), "{err}");
        assert!(!lax.is_pinned("good.example.com").unwrap());
    }

    #[tokio::test]
    async fn a_corrupt_pin_file_found_while_saving_still_refuses() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        std::fs::write(dir.path().join(FILE_NAME), b"not json").unwrap();
        let err = store
            .probe_tolerant_with(&["wss://good.example.com".into()], fake)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err}");
        assert_eq!(
            std::fs::read(dir.path().join(FILE_NAME)).unwrap(),
            b"not json"
        );
    }

    // `late.example.com` is down for the first `down_for` probes, then
    // answers like `good`.
    fn comes_back(
        down_for: usize,
    ) -> (
        Arc<std::sync::atomic::AtomicUsize>,
        impl Fn(String, CertificatePinSet) -> std::future::Ready<Verdict>,
    ) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        (calls, move |relay: String, pins: CertificatePinSet| {
            if relay == "wss://late.example.com" {
                let n = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n < down_for {
                    return std::future::ready(Err(FrostNetError::Timeout("down".into())));
                }
                let learned = (!pins.is_pinned("late.example.com"))
                    .then(|| ("late.example.com".to_string(), [3u8; 32]));
                return std::future::ready(Ok(([3u8; 32], learned)));
            }
            fake(relay, pins)
        })
    }

    #[tokio::test]
    async fn a_relay_down_at_startup_is_pinned_once_it_answers() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let (calls, verify) = comes_back(2);
        let relays = vec![
            "wss://late.example.com".to_string(),
            "wss://good.example.com".to_string(),
        ];
        let skipped = store.probe_tolerant_with(&relays, &verify).await.unwrap();
        assert!(
            matches!(&skipped[..], [ProbeSkip::Unreachable { relay, .. }] if relay == "wss://late.example.com")
        );
        assert!(!store.is_pinned("late.example.com").unwrap());

        store
            .pin_when_reachable_with(
                vec!["wss://late.example.com".into()],
                std::time::Duration::from_millis(1),
                &verify,
            )
            .await
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert!(store.is_pinned("late.example.com").unwrap());
        assert!(saved(dir.path()).contains_key("late.example.com"));
    }

    #[tokio::test]
    async fn two_urls_for_one_host_with_different_keys_pin_the_first_and_refuse_the_second() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let relays = vec![
            "wss://split.example.com:443".to_string(),
            "wss://split.example.com:444".to_string(),
            "wss://good.example.com".to_string(),
        ];
        let skipped = store
            .probe_tolerant_with(&relays, |relay: String, pins: CertificatePinSet| {
                let key = if relay.ends_with(":444") {
                    [5u8; 32]
                } else {
                    [4u8; 32]
                };
                let verdict = if relay.contains("split") {
                    let learned = (!pins.is_pinned("split.example.com"))
                        .then(|| ("split.example.com".to_string(), key));
                    Ok((key, learned))
                } else {
                    return fake(relay, pins);
                };
                std::future::ready(verdict)
            })
            .await
            .unwrap();
        assert_eq!(
            skipped,
            vec![ProbeSkip::PinMismatch {
                relay: "wss://split.example.com:444".into(),
                hostname: "split.example.com".into(),
            }]
        );
        assert_eq!(
            store.lock().unwrap().get_pins("split.example.com").to_vec(),
            vec![[4u8; 32]]
        );
    }

    #[tokio::test]
    async fn the_retry_stops_on_a_mismatch_without_touching_the_pin() {
        let dir = dir();
        let original = br#"{"bad.example.com":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#;
        std::fs::write(dir.path().join(FILE_NAME), original).unwrap();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        store
            .pin_when_reachable_with(
                vec!["wss://bad.example.com".into()],
                std::time::Duration::from_millis(1),
                fake,
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read(dir.path().join(FILE_NAME)).unwrap(), original);
    }

    #[tokio::test]
    async fn the_retry_gives_up_on_a_pin_store_it_cannot_save() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        std::fs::write(dir.path().join(FILE_NAME), b"not json").unwrap();
        let err = store
            .pin_when_reachable_with(
                vec!["wss://good.example.com".into()],
                std::time::Duration::from_millis(1),
                fake,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err}");
        assert_eq!(
            std::fs::read(dir.path().join(FILE_NAME)).unwrap(),
            b"not json"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_never_answers_is_skipped_within_the_budget() {
        let dir = dir();
        let store = RelayPinStore::open(dir.path(), false).unwrap();
        let started = tokio::time::Instant::now();
        let skipped = store
            .probe_tolerant_with(
                &[
                    "wss://good.example.com".to_string(),
                    "wss://stuck.example.com".to_string(),
                    "wss://stuck2.example.com".to_string(),
                ],
                |relay: String, pins: CertificatePinSet| async move {
                    if relay.contains("stuck") {
                        std::future::pending::<()>().await;
                    }
                    fake(relay, pins).await
                },
            )
            .await
            .unwrap();
        assert_eq!(skipped.len(), 2);
        assert!(
            started.elapsed() < TOLERANT_PROBE_BUDGET * 2,
            "stuck relays are probed concurrently"
        );
        assert!(store.is_pinned("good.example.com").unwrap());
    }

    #[test]
    fn env_strict_accepts_only_one_and_true() {
        assert!(value_requests_strict(Some("1")));
        assert!(value_requests_strict(Some("true")));
        assert!(value_requests_strict(Some("TRUE")));
        assert!(!value_requests_strict(Some("yes")));
        assert!(!value_requests_strict(Some("")));
        assert!(!value_requests_strict(None));
    }
}
