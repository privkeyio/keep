// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::cert_pin::{verify_relay_certificate, CertificatePinSet};
use crate::error::{FrostNetError, Result};
use crate::pinned_transport::TlsPinning;

const FILE_NAME: &str = "cert-pins.json";

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
    pub async fn probe(&self, relays: &[String], proxy: Option<SocketAddr>) -> Result<()> {
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
            let snapshot = self.lock()?.clone();
            let (_hash, learned) =
                verify_relay_certificate(relay, &snapshot, self.require_pinned, proxy).await?;
            if let Some((hostname, hash)) = learned {
                let mut pins = self.lock()?;
                if !pins.is_pinned(&hostname) {
                    pins.add_pin(hostname.clone(), hash);
                    drop(pins);
                    self.persist()?;
                    tracing::info!(hostname = %hostname, "recorded relay certificate pin");
                }
            }
        }
        Ok(())
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
