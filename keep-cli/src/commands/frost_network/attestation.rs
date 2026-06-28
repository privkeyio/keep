// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Loading the TPM attestation policy a FROST node uses to verify a peer's
//! measured-boot state before answering its OPRF evaluation requests.
//!
//! The policy is provisioned out of band (trust-on-first-use) and pinned in a
//! TOML file: a shared PCR selection and reference digest set, plus one AK pin
//! per peer. See `keep frost network serve --attestation-config`.
//!
//! ```toml
//! # Marshalled TPML_PCR_SELECTION the peer quote must match (hex).
//! selection = "00000001000b03951800"
//! # Reference PCR digests in selection order (hex, 32 bytes each).
//! reference_pcrs = ["0000…", "0000…", "0000…", "0000…", "cf2b…", "0000…"]
//!
//! [[peer]]
//! index = 2
//! ak = "04f533…b327…"   # 65-byte uncompressed SEC1 point
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use keep_core::error::{KeepError, Result};
use keep_frost_net::TpmAttestationPolicy;

use crate::output::Output;

#[derive(Deserialize)]
struct AttestationConfig {
    selection: String,
    reference_pcrs: Vec<String>,
    #[serde(default)]
    peer: Vec<PeerPin>,
}

#[derive(Deserialize)]
struct PeerPin {
    index: u16,
    ak: String,
}

fn err(msg: impl Into<String>) -> KeepError {
    KeepError::Frost(msg.into())
}

/// Read and parse a TOML attestation policy file.
pub fn load_tpm_policy(path: &Path) -> Result<TpmAttestationPolicy> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| err(format!("read attestation config {}: {e}", path.display())))?;
    parse_tpm_policy(&text)
}

fn parse_tpm_policy(text: &str) -> Result<TpmAttestationPolicy> {
    let cfg: AttestationConfig =
        toml::from_str(text).map_err(|e| err(format!("invalid attestation config: {e}")))?;

    let selection = hex::decode(cfg.selection.trim())
        .map_err(|_| err("attestation `selection` is not valid hex"))?;
    if selection.is_empty() {
        return Err(err("attestation `selection` must not be empty"));
    }

    if cfg.reference_pcrs.is_empty() {
        return Err(err(
            "attestation `reference_pcrs` must list at least one PCR",
        ));
    }
    let mut reference_pcrs = Vec::with_capacity(cfg.reference_pcrs.len());
    for (i, p) in cfg.reference_pcrs.iter().enumerate() {
        let bytes = hex::decode(p.trim())
            .map_err(|_| err(format!("`reference_pcrs[{i}]` is not valid hex")))?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| err(format!("`reference_pcrs[{i}]` must be 32 bytes")))?;
        reference_pcrs.push(digest);
    }

    if cfg.peer.is_empty() {
        return Err(err(
            "attestation config pins no peers (add a `[[peer]]` entry)",
        ));
    }
    let mut pinned_aks = HashMap::new();
    for p in &cfg.peer {
        let ak = hex::decode(p.ak.trim())
            .map_err(|_| err(format!("peer {} `ak` is not valid hex", p.index)))?;
        if ak.len() != 65 || ak[0] != 0x04 {
            return Err(err(format!(
                "peer {} `ak` must be a 65-byte uncompressed SEC1 point (starts with 0x04)",
                p.index
            )));
        }
        if pinned_aks.insert(p.index, ak).is_some() {
            return Err(err(format!(
                "peer index {} is pinned more than once",
                p.index
            )));
        }
    }

    Ok(TpmAttestationPolicy::new(
        selection,
        reference_pcrs,
        pinned_aks,
    ))
}

/// Resolve the serve-time attestation policy from the CLI flags, fail-closed: a
/// node must either pin a policy or explicitly opt out of attestation, and it
/// cannot do both.
pub fn resolve_serve_policy(
    out: &Output,
    attestation_config: Option<&Path>,
    insecure_no_attestation: bool,
) -> Result<Option<TpmAttestationPolicy>> {
    match (attestation_config, insecure_no_attestation) {
        (Some(_), true) => Err(err(
            "--attestation-config conflicts with --insecure-no-attestation",
        )),
        (Some(path), false) => Ok(Some(load_tpm_policy(path)?)),
        (None, true) => {
            out.warn(
                "INSECURE: --insecure-no-attestation set; this node will NOT verify peer TPM \
                 attestation before answering OPRF evaluations.",
            );
            Ok(None)
        }
        (None, false) => Err(err(
            "attestation required: pass --attestation-config <FILE>, or \
             --insecure-no-attestation for test/dev only",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid config over the default selection {0,2,4,7,11,12} with one peer.
    const VALID: &str = r#"
        selection = "00000001000b03951800"
        reference_pcrs = [
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "cf2b0db7514f320c315130275a960f6e6ed80744c754c687069d7a9f55d704f0",
          "0000000000000000000000000000000000000000000000000000000000000000",
        ]
        [[peer]]
        index = 2
        ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
    "#;

    #[test]
    fn parses_valid_config() {
        let pol = parse_tpm_policy(VALID).expect("valid config");
        assert_eq!(pol.pinned_aks.len(), 1);
        assert_eq!(pol.reference_pcrs.len(), 6);
        assert_eq!(pol.pinned_aks.get(&2).unwrap().len(), 65);
    }

    #[test]
    fn rejects_no_peers() {
        let cfg = r#"
            selection = "00000001000b03951800"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    #[test]
    fn rejects_bad_ak() {
        let cfg = r#"
            selection = "00000001000b03951800"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
            [[peer]]
            index = 2
            ak = "0400"
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    #[test]
    fn rejects_short_reference_pcr() {
        let cfg = r#"
            selection = "00000001000b03951800"
            reference_pcrs = ["00ff"]
            [[peer]]
            index = 2
            ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    #[test]
    fn resolve_requires_a_choice() {
        let out = Output::new();
        // Neither flag: fail closed.
        assert!(resolve_serve_policy(&out, None, false).is_err());
    }

    #[test]
    fn resolve_rejects_both() {
        let out = Output::new();
        let path = Path::new("/nonexistent.toml");
        assert!(resolve_serve_policy(&out, Some(path), true).is_err());
    }

    #[test]
    fn resolve_insecure_opts_out() {
        let out = Output::new();
        assert!(matches!(resolve_serve_policy(&out, None, true), Ok(None)));
    }

    #[test]
    fn rejects_duplicate_peer() {
        let cfg = r#"
            selection = "00000001000b03951800"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
            [[peer]]
            index = 2
            ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
            [[peer]]
            index = 2
            ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }
}
