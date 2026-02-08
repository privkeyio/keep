// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::sync::Arc;

use frost_secp256k1_tr::keys::dkg;
use frost_secp256k1_tr::Identifier;
use tokio::sync::RwLock;

use crate::error::KeepMobileError;
use crate::types::{DkgConfig, DkgStatus};
use crate::validate_relay_url;

const MAX_DKG_PARTICIPANTS: u16 = 255;
const MAX_SHARE_NAME_LENGTH: usize = 64;
const MAX_PACKAGE_SIZE: usize = 16 * 1024;

fn validate_participant_index(
    index: u16,
    participants: u16,
    label: &str,
) -> Result<Identifier, KeepMobileError> {
    if index < 1 || index > participants {
        return Err(KeepMobileError::FrostError {
            msg: format!("{label} {index} out of range (1-{participants})"),
        });
    }
    Identifier::try_from(index).map_err(|e| KeepMobileError::FrostError {
        msg: format!("Invalid {}: {}", label.to_lowercase(), e),
    })
}

fn validate_package_size(bytes: &[u8], sender: u16) -> Result<(), KeepMobileError> {
    if bytes.len() > MAX_PACKAGE_SIZE {
        return Err(KeepMobileError::FrostError {
            msg: format!("Package from {sender} exceeds maximum size"),
        });
    }
    Ok(())
}

fn validate_share_name(name: &str) -> Result<(), KeepMobileError> {
    if name.chars().count() > MAX_SHARE_NAME_LENGTH {
        return Err(KeepMobileError::InvalidShare {
            msg: format!("Share name exceeds maximum length of {MAX_SHARE_NAME_LENGTH} characters"),
        });
    }
    Ok(())
}

#[derive(Clone)]
pub struct DkgRound1Package {
    pub participant_index: u16,
    pub package_bytes: Vec<u8>,
}

#[derive(Clone, uniffi::Record)]
pub struct DkgRound2Package {
    pub sender_index: u16,
    pub recipient_index: u16,
    pub package_bytes: Vec<u8>,
}

pub struct DkgResult {
    pub group_pubkey: String,
    pub share_export: String,
}

enum DkgState {
    NotStarted,
    Initialized {
        config: DkgConfig,
        our_identifier: Identifier,
        secret_package: Box<dkg::round1::SecretPackage>,
        round1_package: Box<dkg::round1::Package>,
    },
    Round1Complete {
        config: DkgConfig,
        secret_package: Box<dkg::round2::SecretPackage>,
        round1_packages: BTreeMap<Identifier, dkg::round1::Package>,
    },
    Complete,
    Failed {
        reason: String,
    },
}

pub struct DkgSession {
    state: Arc<RwLock<DkgState>>,
}

impl DkgSession {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(DkgState::NotStarted)),
        }
    }

    pub async fn start(&self, config: DkgConfig) -> Result<DkgRound1Package, KeepMobileError> {
        {
            let state = self.state.read().await;
            match &*state {
                DkgState::Initialized { .. } | DkgState::Round1Complete { .. } => {
                    return Err(KeepMobileError::FrostError {
                        msg: "DKG session already in progress".into(),
                    });
                }
                _ => {}
            }
        }

        for relay in &config.relays {
            validate_relay_url(relay)?;
        }

        if config.threshold < 2 {
            return Err(KeepMobileError::FrostError {
                msg: "Threshold must be at least 2".into(),
            });
        }

        if config.participants < config.threshold {
            return Err(KeepMobileError::FrostError {
                msg: "Participants must be >= threshold".into(),
            });
        }

        if config.participants > MAX_DKG_PARTICIPANTS {
            return Err(KeepMobileError::FrostError {
                msg: format!("Maximum {MAX_DKG_PARTICIPANTS} participants supported"),
            });
        }

        if config.our_index < 1 || config.our_index > config.participants {
            return Err(KeepMobileError::FrostError {
                msg: format!("Our index must be between 1 and {}", config.participants),
            });
        }

        let our_identifier =
            Identifier::try_from(config.our_index).map_err(|e| KeepMobileError::FrostError {
                msg: format!("Invalid identifier: {e}"),
            })?;

        let (secret_package, round1_package) = dkg::part1(
            our_identifier,
            config.participants,
            config.threshold,
            frost_secp256k1_tr::rand_core::OsRng,
        )
        .map_err(|e| KeepMobileError::FrostError {
            msg: format!("DKG round 1 failed: {e}"),
        })?;

        let package_bytes =
            round1_package
                .serialize()
                .map_err(|e| KeepMobileError::Serialization {
                    msg: format!("Failed to serialize round 1 package: {e}"),
                })?;

        let mut state = self.state.write().await;
        *state = DkgState::Initialized {
            config: config.clone(),
            our_identifier,
            secret_package: Box::new(secret_package),
            round1_package: Box::new(round1_package),
        };

        Ok(DkgRound1Package {
            participant_index: config.our_index,
            package_bytes,
        })
    }

    pub async fn receive_round1_packages(
        &self,
        packages: Vec<DkgRound1Package>,
    ) -> Result<Vec<DkgRound2Package>, KeepMobileError> {
        let mut state = self.state.write().await;

        let (config, our_identifier, secret_package, our_round1_package) = match &*state {
            DkgState::Initialized {
                config,
                our_identifier,
                secret_package,
                round1_package,
            } => (
                config.clone(),
                *our_identifier,
                (**secret_package).clone(),
                (**round1_package).clone(),
            ),
            DkgState::NotStarted => {
                return Err(KeepMobileError::FrostError {
                    msg: "DKG not started".into(),
                })
            }
            DkgState::Failed { reason } => {
                return Err(KeepMobileError::FrostError {
                    msg: format!("DKG failed: {reason}"),
                })
            }
            _ => {
                return Err(KeepMobileError::FrostError {
                    msg: "Invalid DKG state for round 1 packages".into(),
                })
            }
        };

        let expected_count = (config.participants - 1) as usize;
        if packages.len() != expected_count {
            return Err(KeepMobileError::FrostError {
                msg: format!(
                    "Expected {} round 1 packages, got {}",
                    expected_count,
                    packages.len()
                ),
            });
        }

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(our_identifier, our_round1_package);

        for pkg in &packages {
            validate_package_size(&pkg.package_bytes, pkg.participant_index)?;
            let identifier = validate_participant_index(
                pkg.participant_index,
                config.participants,
                "Participant index",
            )?;

            if round1_packages.contains_key(&identifier) {
                return Err(KeepMobileError::FrostError {
                    msg: format!("Duplicate participant index: {}", pkg.participant_index),
                });
            }

            let package = dkg::round1::Package::deserialize(&pkg.package_bytes).map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!(
                        "Invalid round 1 package from {}: {}",
                        pkg.participant_index, e
                    ),
                }
            })?;

            round1_packages.insert(identifier, package);
        }

        let (round2_secret, round2_packages) = dkg::part2(secret_package.clone(), &round1_packages)
            .map_err(|e| {
                *state = DkgState::Failed {
                    reason: format!("DKG round 2 failed: {e}"),
                };
                KeepMobileError::FrostError {
                    msg: format!("DKG round 2 failed: {e}"),
                }
            })?;

        let result_packages: Result<Vec<DkgRound2Package>, KeepMobileError> = round2_packages
            .iter()
            .map(|(recipient_id, pkg)| {
                let package_bytes =
                    pkg.serialize()
                        .map_err(|e| KeepMobileError::Serialization {
                            msg: format!("Failed to serialize round 2 package: {e}"),
                        })?;

                let id_bytes = recipient_id.serialize();
                let recipient_index = if id_bytes.len() >= 2 {
                    u16::from_le_bytes([id_bytes[0], id_bytes[1]])
                } else {
                    return Err(KeepMobileError::FrostError {
                        msg: "Invalid recipient identifier serialization".into(),
                    });
                };

                Ok(DkgRound2Package {
                    sender_index: config.our_index,
                    recipient_index,
                    package_bytes,
                })
            })
            .collect();

        let result = result_packages?;

        *state = DkgState::Round1Complete {
            config,
            secret_package: Box::new(round2_secret),
            round1_packages,
        };

        Ok(result)
    }

    pub async fn receive_round2_packages(
        &self,
        packages: Vec<DkgRound2Package>,
        name: &str,
        passphrase: &str,
    ) -> Result<DkgResult, KeepMobileError> {
        use keep_core::frost::{ShareExport, ShareMetadata, SharePackage};
        use zeroize::Zeroizing;

        validate_share_name(name)?;

        let mut state = self.state.write().await;

        let (config, secret_package, round1_packages) = match &*state {
            DkgState::Round1Complete {
                config,
                secret_package,
                round1_packages,
                ..
            } => (
                config.clone(),
                (**secret_package).clone(),
                round1_packages.clone(),
            ),
            DkgState::NotStarted => {
                return Err(KeepMobileError::FrostError {
                    msg: "DKG not started".into(),
                })
            }
            DkgState::Failed { reason } => {
                return Err(KeepMobileError::FrostError {
                    msg: format!("DKG failed: {reason}"),
                })
            }
            _ => {
                return Err(KeepMobileError::FrostError {
                    msg: "Invalid DKG state for round 2 packages".into(),
                })
            }
        };

        let expected_count = (config.participants - 1) as usize;
        if packages.len() != expected_count {
            return Err(KeepMobileError::FrostError {
                msg: format!(
                    "Expected {} round 2 packages, got {}",
                    expected_count,
                    packages.len()
                ),
            });
        }

        let mut round2_packages = BTreeMap::new();
        for pkg in &packages {
            validate_package_size(&pkg.package_bytes, pkg.sender_index)?;
            let sender_id =
                validate_participant_index(pkg.sender_index, config.participants, "Sender index")?;

            if round2_packages.contains_key(&sender_id) {
                return Err(KeepMobileError::FrostError {
                    msg: format!("Duplicate sender index: {}", pkg.sender_index),
                });
            }

            let package = dkg::round2::Package::deserialize(&pkg.package_bytes).map_err(|e| {
                KeepMobileError::FrostError {
                    msg: format!("Invalid round 2 package from {}: {}", pkg.sender_index, e),
                }
            })?;

            round2_packages.insert(sender_id, package);
        }

        let (key_package, pubkey_package) =
            dkg::part3(&secret_package, &round1_packages, &round2_packages).map_err(|e| {
                *state = DkgState::Failed {
                    reason: format!("DKG finalization failed: {e}"),
                };
                KeepMobileError::FrostError {
                    msg: format!("DKG finalization failed: {e}"),
                }
            })?;

        let verifying_key = pubkey_package.verifying_key();
        let serialized = verifying_key
            .serialize()
            .map_err(|e| KeepMobileError::FrostError {
                msg: format!("Failed to serialize verifying key: {e}"),
            })?;
        let vk_bytes = serialized.as_slice();

        let group_pubkey: [u8; 32] = match vk_bytes.len() {
            33 => vk_bytes[1..33].try_into().map_err(|_| KeepMobileError::FrostError {
                msg: "Failed to extract group pubkey from verifying key".into(),
            })?,
            len => {
                return Err(KeepMobileError::FrostError {
                    msg: format!("Invalid group pubkey length: {len}"),
                })
            }
        };

        let metadata = ShareMetadata::new(
            config.our_index,
            config.threshold,
            config.participants,
            group_pubkey,
            name.to_string(),
        );

        let share_package = SharePackage::new(metadata, &key_package, &pubkey_package)?;

        let passphrase = Zeroizing::new(passphrase.to_string());
        let export = ShareExport::from_share(&share_package, &passphrase)?;
        let share_export = export.to_bech32()?;

        *state = DkgState::Complete;

        Ok(DkgResult {
            group_pubkey: hex::encode(group_pubkey),
            share_export,
        })
    }

    pub async fn status(&self) -> DkgStatus {
        let state = self.state.read().await;
        match &*state {
            DkgState::NotStarted => DkgStatus::NotStarted,
            DkgState::Initialized { .. } => DkgStatus::Round1,
            DkgState::Round1Complete { .. } => DkgStatus::Round2,
            DkgState::Complete => DkgStatus::Complete,
            DkgState::Failed { reason } => DkgStatus::Failed {
                reason: reason.clone(),
            },
        }
    }

    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        *state = DkgState::NotStarted;
    }
}

impl Default for DkgSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dkg_session_initial_status() {
        let session = DkgSession::new();
        assert_eq!(session.status().await, DkgStatus::NotStarted);
    }

    #[tokio::test]
    async fn test_dkg_start_invalid_threshold() {
        let session = DkgSession::new();
        let config = DkgConfig {
            group_name: "test".to_string(),
            threshold: 1, // Invalid: must be >= 2
            participants: 3,
            our_index: 1,
            relays: vec!["wss://relay.example.com".to_string()],
        };

        let result = session.start(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dkg_start_invalid_participants() {
        let session = DkgSession::new();
        let config = DkgConfig {
            group_name: "test".to_string(),
            threshold: 3,
            participants: 2, // Invalid: participants < threshold
            our_index: 1,
            relays: vec!["wss://relay.example.com".to_string()],
        };

        let result = session.start(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dkg_start_invalid_index() {
        let session = DkgSession::new();
        let config = DkgConfig {
            group_name: "test".to_string(),
            threshold: 2,
            participants: 3,
            our_index: 5, // Invalid: index > participants
            relays: vec!["wss://relay.example.com".to_string()],
        };

        let result = session.start(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dkg_start_success() {
        let session = DkgSession::new();
        let config = DkgConfig {
            group_name: "test".to_string(),
            threshold: 2,
            participants: 3,
            our_index: 1,
            relays: vec!["wss://relay.example.com".to_string()],
        };

        let result = session.start(config).await;
        assert!(result.is_ok());
        assert_eq!(session.status().await, DkgStatus::Round1);
    }

    #[tokio::test]
    async fn test_dkg_reset() {
        let session = DkgSession::new();
        let config = DkgConfig {
            group_name: "test".to_string(),
            threshold: 2,
            participants: 3,
            our_index: 1,
            relays: vec!["wss://relay.example.com".to_string()],
        };

        session.start(config).await.unwrap();
        assert_eq!(session.status().await, DkgStatus::Round1);

        session.reset().await;
        assert_eq!(session.status().await, DkgStatus::NotStarted);
    }

    #[tokio::test]
    async fn test_dkg_start_rejects_in_progress() {
        let session = DkgSession::new();
        let config = DkgConfig {
            group_name: "test".to_string(),
            threshold: 2,
            participants: 3,
            our_index: 1,
            relays: vec!["wss://relay.example.com".to_string()],
        };

        session.start(config.clone()).await.unwrap();
        assert_eq!(session.status().await, DkgStatus::Round1);

        let result = session.start(config).await;
        assert!(result.is_err());
        match result {
            Err(KeepMobileError::FrostError { msg }) => {
                assert!(msg.contains("already in progress"));
            }
            _ => panic!("Expected FrostError with 'already in progress' message"),
        }
    }
}
