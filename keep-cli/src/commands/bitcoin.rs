// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::Path;

use secrecy::ExposeSecret;
use zeroize::Zeroize;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::output::Output;

use super::get_password;

pub fn cmd_bitcoin_address(
    out: &Output,
    path: &Path,
    key_name: &str,
    count: u32,
    network: &str,
) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(key_name)
        .ok_or_else(|| KeepError::KeyNotFound(key_name.into()))?;

    let mut secret = *slot.expose_secret();
    let net = parse_network(network)?;

    let signer = keep_bitcoin::BitcoinSigner::new(&mut secret, net)
        .map_err(|e| KeepError::Runtime(e.to_string()));
    secret.zeroize();
    let signer = signer?;

    out.newline();
    out.header("Bitcoin Addresses (BIP-86 Taproot)");
    out.field("Key", key_name);
    out.field("Network", network);
    out.newline();

    for i in 0..count {
        let addr = signer
            .get_receive_address(i)
            .map_err(|e| KeepError::Runtime(e.to_string()))?;
        out.info(&format!("Index {i}: {addr}"));
    }

    Ok(())
}

pub fn cmd_bitcoin_descriptor(
    out: &Output,
    path: &Path,
    key_name: &str,
    account: u32,
    network: &str,
) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(key_name)
        .ok_or_else(|| KeepError::KeyNotFound(key_name.into()))?;

    let mut secret = *slot.expose_secret();
    let net = parse_network(network)?;

    let signer = keep_bitcoin::BitcoinSigner::new(&mut secret, net)
        .map_err(|e| KeepError::Runtime(e.to_string()));
    secret.zeroize();
    let signer = signer?;

    let export = signer
        .export_descriptor(account)
        .map_err(|e| KeepError::Runtime(e.to_string()))?;

    out.newline();
    out.header("Output Descriptor (BIP-86)");
    out.field("Key", key_name);
    out.field("Account", &account.to_string());
    out.field("Network", network);
    out.field("Fingerprint", &export.fingerprint);
    out.newline();
    out.info("External descriptor (receive):");
    println!("{}", export.descriptor);
    out.newline();
    out.info("Internal descriptor (change):");
    let internal = export
        .internal_descriptor()
        .map_err(|e| KeepError::Runtime(e.to_string()))?;
    println!("{internal}");

    Ok(())
}

pub fn cmd_bitcoin_sign(
    out: &Output,
    path: &Path,
    key_name: &str,
    psbt_path: &str,
    output_path: Option<&str>,
    network: &str,
) -> Result<()> {
    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let slot = keep
        .keyring()
        .get_by_name(key_name)
        .ok_or_else(|| KeepError::KeyNotFound(key_name.into()))?;

    let mut secret = *slot.expose_secret();
    let net = parse_network(network)?;

    let signer = keep_bitcoin::BitcoinSigner::new(&mut secret, net)
        .map_err(|e| KeepError::Runtime(e.to_string()));
    secret.zeroize();
    let signer = signer?;

    let psbt_data = std::fs::read_to_string(psbt_path).map_err(|e| {
        KeepError::StorageErr(keep_core::error::StorageError::io(format!(
            "read PSBT: {e}"
        )))
    })?;

    let mut psbt = keep_bitcoin::psbt::parse_psbt_base64(psbt_data.trim())
        .map_err(|e| KeepError::Runtime(e.to_string()))?;

    let spinner = out.spinner("Signing PSBT...");
    let signed_count = signer
        .sign_psbt(&mut psbt)
        .map_err(|e| KeepError::Runtime(e.to_string()))?;
    spinner.finish();

    let signed_base64 = keep_bitcoin::psbt::serialize_psbt_base64(&psbt);

    if let Some(output) = output_path {
        std::fs::write(output, &signed_base64).map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "write output: {e}"
            )))
        })?;
        out.newline();
        out.success(&format!("Signed {signed_count} input(s)"));
        out.field("Output", output);
    } else {
        out.newline();
        out.success(&format!("Signed {signed_count} input(s)"));
        out.newline();
        println!("{signed_base64}");
    }

    Ok(())
}

pub fn cmd_bitcoin_analyze(out: &Output, psbt_path: &str, network: &str) -> Result<()> {
    let psbt_data = std::fs::read_to_string(psbt_path).map_err(|e| {
        KeepError::StorageErr(keep_core::error::StorageError::io(format!(
            "read PSBT: {e}"
        )))
    })?;

    let psbt = keep_bitcoin::psbt::parse_psbt_base64(psbt_data.trim())
        .map_err(|e| KeepError::Runtime(e.to_string()))?;

    let net = parse_network(network)?;
    let mut dummy_secret = [1u8; 32];
    let signer = keep_bitcoin::BitcoinSigner::new(&mut dummy_secret, net)
        .map_err(|e| KeepError::Runtime(e.to_string()))?;

    let analysis = signer
        .analyze_psbt(&psbt)
        .map_err(|e| KeepError::Runtime(e.to_string()))?;

    out.newline();
    out.header("PSBT Analysis");
    out.field("Inputs", &analysis.num_inputs.to_string());
    out.field("Outputs", &analysis.num_outputs.to_string());
    out.field(
        "Total Input",
        &format!("{} sats", analysis.total_input_sats),
    );
    out.field(
        "Total Output",
        &format!("{} sats", analysis.total_output_sats),
    );
    out.field("Fee", &format!("{} sats", analysis.fee_sats));

    // Loud abnormal-fee warning. A bogus PSBT with garbage witness_utxo values
    // produces a giant fee that the user might miss; surface it explicitly.
    if analysis.total_input_sats > 0 {
        let ratio = analysis.fee_sats as f64 / analysis.total_input_sats as f64;
        let pct = ratio * 100.0;
        if ratio >= 0.5 {
            out.warn(&format!(
                "ABNORMAL FEE: {:.1}% of total input ({} sats fee / {} sats input). Possible fee-burn attack or malformed PSBT; REVIEW CAREFULLY before signing.",
                pct, analysis.fee_sats, analysis.total_input_sats,
            ));
        } else if ratio >= 0.1 {
            out.warn(&format!(
                "HIGH FEE: {:.1}% of total input ({} sats fee / {} sats input). Review before signing.",
                pct, analysis.fee_sats, analysis.total_input_sats,
            ));
        } else if ratio >= 0.01 {
            out.warn(&format!(
                "Elevated fee: {:.2}% of total input ({} sats fee).",
                pct, analysis.fee_sats,
            ));
        }
    } else if analysis.fee_sats > 100_000 {
        out.warn(&format!(
            "Large fee {} sats with no input amount data; cannot compute fee ratio.",
            analysis.fee_sats,
        ));
    }
    out.newline();

    out.info("Outputs:");
    for output in &analysis.outputs {
        let addr = output.address.as_deref().unwrap_or("(unknown)");
        let change = if output.is_change { " (change)" } else { "" };
        out.info(&format!(
            "  {}: {} sats -> {}{}",
            output.index, output.amount_sats, addr, change
        ));
    }

    if !analysis.signable_inputs.is_empty() {
        out.newline();
        out.info(&format!("Signable inputs: {:?}", analysis.signable_inputs));
    }

    Ok(())
}

pub fn parse_network(s: &str) -> Result<keep_bitcoin::Network> {
    match s.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Ok(keep_bitcoin::Network::Bitcoin),
        "testnet" => Ok(keep_bitcoin::Network::Testnet),
        "signet" => Ok(keep_bitcoin::Network::Signet),
        "regtest" => Ok(keep_bitcoin::Network::Regtest),
        _ => Err(KeepError::InvalidNetwork(format!(
            "'{s}' (valid: mainnet/bitcoin, testnet, signet, regtest)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_bitcoin::Network;

    /// `parse_network` is the single chokepoint every `keep bitcoin ...`
    /// subcommand routes user input through. A regression here mis-targets
    /// every Bitcoin operation; pin all canonical aliases + case-insensitivity.
    #[test]
    fn parse_network_accepts_all_canonical_names_case_insensitive() {
        for (input, expected) in [
            ("mainnet", Network::Bitcoin),
            ("MAINNET", Network::Bitcoin),
            ("bitcoin", Network::Bitcoin),
            ("BiTcOiN", Network::Bitcoin),
            ("testnet", Network::Testnet),
            ("TESTNET", Network::Testnet),
            ("signet", Network::Signet),
            ("regtest", Network::Regtest),
        ] {
            let got = parse_network(input)
                .unwrap_or_else(|e| panic!("parse_network({input:?}) must succeed, got {e}"));
            assert_eq!(got, expected, "input {input:?}");
        }
    }

    #[test]
    fn parse_network_rejects_unknown_and_empty_inputs() {
        for input in [
            "",
            "main",
            "Bitcoin Cash",
            "mainnetwork",
            " mainnet ",
            "regt",
        ] {
            let err = parse_network(input).expect_err(&format!(
                "parse_network({input:?}) must reject unknown input"
            ));
            assert!(
                matches!(err, KeepError::InvalidNetwork(_)),
                "expected InvalidNetwork for {input:?}, got {err:?}"
            );
            assert!(
                err.to_string()
                    .contains("mainnet/bitcoin, testnet, signet, regtest"),
                "error must list every accepted option (including the bitcoin alias) for {input:?}: {err}"
            );
        }
    }
}
