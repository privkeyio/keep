#![forbid(unsafe_code)]

use keep_core::crypto::SecretKey;
use keep_core::error::{KeepError, Result};
use keep_core::frost::StoredShare;

#[derive(Clone)]
pub struct FrostSigner {
    group_pubkey: [u8; 32],
    shares: Vec<StoredShare>,
    data_key: SecretKey,
    threshold: u16,
}

impl FrostSigner {
    pub fn new(
        group_pubkey: [u8; 32],
        shares: Vec<StoredShare>,
        data_key: SecretKey,
    ) -> Result<Self> {
        if shares.is_empty() {
            return Err(KeepError::Frost("No shares provided".into()));
        }

        let threshold = shares[0].metadata.threshold;

        if shares.len() < threshold as usize {
            return Err(KeepError::Frost(format!(
                "Need {} shares, only {} provided",
                threshold,
                shares.len()
            )));
        }

        for share in &shares {
            if share.metadata.group_pubkey != group_pubkey {
                return Err(KeepError::Frost(
                    "Share group_pubkey mismatch: all shares must belong to the same group".into(),
                ));
            }
            if share.metadata.threshold != threshold {
                return Err(KeepError::Frost(
                    "Share threshold mismatch: all shares must have the same threshold".into(),
                ));
            }
        }

        Ok(Self {
            group_pubkey,
            shares,
            data_key,
            threshold,
        })
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let mut decrypted = Vec::new();
        for stored in self.shares.iter().take(self.threshold as usize) {
            decrypted.push(stored.decrypt(&self.data_key)?);
        }

        keep_core::frost::sign_with_local_shares(&decrypted, message)
    }
}
