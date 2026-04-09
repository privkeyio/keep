// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::error::{KeepError, Result};

/// Generate a BIP-39 mnemonic phrase with the given word count (12 or 24).
pub fn generate_mnemonic(word_count: u32) -> Result<Zeroizing<String>> {
    let entropy = match word_count {
        12 => Zeroizing::new(crate::crypto::random_bytes::<16>().to_vec()),
        24 => Zeroizing::new(crate::crypto::random_bytes::<32>().to_vec()),
        _ => {
            return Err(KeepError::InvalidMnemonic(
                "word count must be 12 or 24".into(),
            ))
        }
    };

    let mnemonic =
        Mnemonic::from_entropy(&entropy).map_err(|e| KeepError::InvalidMnemonic(e.to_string()))?;

    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Validate a BIP-39 mnemonic phrase.
pub fn validate_mnemonic(phrase: &str) -> Result<()> {
    phrase
        .parse::<Mnemonic>()
        .map_err(|e| KeepError::InvalidMnemonic(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_word_mnemonic() {
        let mnemonic = generate_mnemonic(12).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        validate_mnemonic(&mnemonic).unwrap();
    }

    #[test]
    fn generate_24_word_mnemonic() {
        let mnemonic = generate_mnemonic(24).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
        validate_mnemonic(&mnemonic).unwrap();
    }

    #[test]
    fn reject_invalid_word_count() {
        assert!(generate_mnemonic(15).is_err());
        assert!(generate_mnemonic(0).is_err());
    }

    #[test]
    fn validate_known_mnemonic() {
        validate_mnemonic(
            "leader monkey parrot ring guide accident before fence cannon height naive bean",
        )
        .unwrap();
    }

    #[test]
    fn reject_invalid_mnemonic() {
        assert!(validate_mnemonic("invalid words that are not a mnemonic phrase").is_err());
    }
}
