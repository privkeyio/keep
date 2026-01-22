// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use secrecy::ExposeSecret;
use zeroize::Zeroize;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::output::Output;

use super::get_password;

pub fn cmd_enclave_status(out: &Output, cid: u32, local: bool) -> Result<()> {
    out.newline();
    out.header("Enclave Status");

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut nonce);

        let request = keep_enclave_host::EnclaveRequest::GetAttestation { nonce };
        match client.process_request(request) {
            keep_enclave_host::EnclaveResponse::Attestation { .. } => {
                out.success("Mock enclave is running");
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    out.field("Target CID", &cid.to_string());

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut nonce);

        match client.get_attestation(nonce) {
            Ok(_) => {
                out.success("Enclave is running and responding");
            }
            Err(e) => {
                out.error(&format!("Enclave not available: {}", e));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}

pub fn cmd_enclave_verify(
    out: &Output,
    cid: u32,
    pcr0: Option<&str>,
    pcr1: Option<&str>,
    pcr2: Option<&str>,
    local: bool,
) -> Result<()> {
    out.newline();
    out.header("Enclave Attestation Verification");

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut nonce);

        let request = keep_enclave_host::EnclaveRequest::GetAttestation { nonce };
        match client.process_request(request) {
            keep_enclave_host::EnclaveResponse::Attestation { document } => {
                out.success("Mock attestation generated");
                out.field("Document size", &format!("{} bytes", document.len()));
                out.warn("Mock attestation - not cryptographically verified");
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    out.field("Target CID", &cid.to_string());

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut nonce);

        let spinner = out.spinner("Fetching attestation...");
        let attestation_doc = client.get_attestation(nonce).map_err(|e| {
            KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
                "enclave: {}",
                e
            )))
        })?;
        spinner.finish();

        let expected_pcrs = if let (Some(p0), Some(p1), Some(p2)) = (pcr0, pcr1, pcr2) {
            Some(
                keep_enclave_host::ExpectedPcrs::from_hex(p0, p1, p2)
                    .map_err(|e| KeepError::InvalidInput(format!("invalid PCR hex: {}", e)))?,
            )
        } else {
            None
        };

        let verifier = keep_enclave_host::AttestationVerifier::new(expected_pcrs);

        let spinner = out.spinner("Verifying attestation...");
        match verifier.verify(&attestation_doc, &nonce) {
            Ok(verified) => {
                spinner.finish();
                out.success("Attestation verified!");
                out.newline();

                for (pcr_idx, pcr_val) in &verified.pcrs {
                    out.field(&format!("PCR{}", pcr_idx), &hex::encode(pcr_val));
                }
            }
            Err(e) => {
                spinner.finish();
                out.error(&format!("Verification failed: {}", e));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pcr0, pcr1, pcr2);
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}

pub fn cmd_enclave_generate_key(out: &Output, name: &str, cid: u32, local: bool) -> Result<()> {
    out.newline();
    out.header("Generate Key in Enclave");

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();

        let request = keep_enclave_host::EnclaveRequest::GenerateKey {
            name: name.to_string(),
        };
        match client.process_request(request) {
            keep_enclave_host::EnclaveResponse::PublicKey {
                pubkey,
                name: key_name,
            } => {
                let pubkey_arr: [u8; 32] = pubkey.as_slice().try_into().map_err(|_| {
                    KeepError::CryptoErr(keep_core::error::CryptoError::invalid_key(format!(
                        "expected 32 bytes, got {}",
                        pubkey.len()
                    )))
                })?;
                let npub = keep_core::keys::bytes_to_npub(&pubkey_arr);
                out.success("Key generated in mock enclave!");
                out.field("Name", &key_name);
                out.key_field("Pubkey", &npub);
                out.warn("Mock key - persisted to /tmp for local testing");
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);

        let spinner = out.spinner("Generating key in enclave...");
        let pubkey = client.generate_key(name).map_err(|e| {
            KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
                "enclave: {}",
                e
            )))
        })?;
        spinner.finish();

        let pubkey_arr: [u8; 32] = pubkey.as_slice().try_into().map_err(|_| {
            KeepError::CryptoErr(keep_core::error::CryptoError::invalid_key(format!(
                "expected 32 bytes, got {}",
                pubkey.len()
            )))
        })?;
        let npub = keep_core::keys::bytes_to_npub(&pubkey_arr);

        out.success("Key generated in enclave!");
        out.field("Name", name);
        out.key_field("Pubkey", &npub);
        out.warn("Key exists ONLY in enclave memory");
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, cid);
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}

pub fn cmd_enclave_sign(
    out: &Output,
    key: &str,
    message: &str,
    cid: u32,
    local: bool,
) -> Result<()> {
    out.newline();
    out.header("Sign in Enclave");

    let message_bytes =
        hex::decode(message).map_err(|_| KeepError::InvalidInput("invalid message hex".into()))?;

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();

        let sign_request =
            keep_enclave_host::EnclaveRequest::Sign(keep_enclave_host::SigningRequest {
                key_id: key.to_string(),
                message: message_bytes,
                event_kind: None,
                amount_sats: None,
                destination: None,
                nonce: None,
                timestamp: None,
            });

        match client.process_request(sign_request) {
            keep_enclave_host::EnclaveResponse::Signature { signature } => {
                out.success("Signature generated in mock enclave!");
                out.newline();
                println!("{}", hex::encode(&signature));
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);

        let request = keep_enclave_host::SigningRequest {
            key_id: key.to_string(),
            message: message_bytes,
            event_kind: None,
            amount_sats: None,
            destination: None,
            nonce: None,
            timestamp: None,
        };

        let spinner = out.spinner("Signing in enclave...");
        let signature = client.sign(request).map_err(|e| {
            KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
                "enclave sign: {}",
                e
            )))
        })?;
        spinner.finish();

        out.success("Signature generated!");
        out.newline();
        println!("{}", hex::encode(signature));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (key, cid);
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}

pub fn cmd_enclave_import_key(
    out: &Output,
    path: &Path,
    name: &str,
    from_vault: Option<&str>,
    cid: u32,
    local: bool,
) -> Result<()> {
    out.newline();
    out.header("Import Key to Enclave");

    let mut secret = if let Some(vault_key) = from_vault {
        out.field("Source", &format!("vault key '{}'", vault_key));

        let mut keep = Keep::open(path)?;
        let password = get_password("Enter password")?;

        let spinner = out.spinner("Unlocking vault...");
        keep.unlock(password.expose_secret())?;
        spinner.finish();

        let slot = keep
            .keyring()
            .get_by_name(vault_key)
            .ok_or_else(|| KeepError::KeyNotFound(vault_key.into()))?;

        let keypair = slot.to_nostr_keypair()?;
        keypair.secret_bytes().to_vec()
    } else {
        out.field("Source", "stdin (hex)");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read input: {}",
                e
            )))
        })?;
        let decoded =
            hex::decode(input.trim()).map_err(|_| KeepError::InvalidInput("invalid hex".into()))?;
        input.zeroize();
        decoded
    };

    if local {
        out.field("Mode", "Local (Mock)");
        let client = keep_enclave_host::MockEnclaveClient::new();

        let request = keep_enclave_host::EnclaveRequest::ImportKey {
            name: name.to_string(),
            secret: std::mem::take(&mut secret),
        };

        match client.process_request(request) {
            keep_enclave_host::EnclaveResponse::PublicKey { pubkey, .. } => {
                let npub = if pubkey.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&pubkey);
                    keep_core::keys::bytes_to_npub(&arr)
                } else {
                    hex::encode(&pubkey)
                };
                out.success("Key imported to mock enclave!");
                out.key_field("Pubkey", &npub);
                out.warn("Mock key - persisted to /tmp for local testing");
            }
            keep_enclave_host::EnclaveResponse::Error { message, .. } => {
                out.error(&format!("Mock enclave error: {}", message));
            }
            _ => {
                out.error("Unexpected response from mock enclave");
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let client = keep_enclave_host::EnclaveClient::with_cid(cid);

        let spinner = out.spinner("Importing key to enclave...");
        let result = client.import_key(name, &secret);
        secret.zeroize();
        let pubkey = result.map_err(|e| {
            KeepError::NetworkErr(keep_core::error::NetworkError::connection(format!(
                "enclave import: {}",
                e
            )))
        })?;
        spinner.finish();

        let npub = if pubkey.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pubkey);
            keep_core::keys::bytes_to_npub(&arr)
        } else {
            hex::encode(&pubkey)
        };
        out.success("Key imported to enclave!");
        out.key_field("Pubkey", &npub);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, cid);
        secret.zeroize();
        out.warn("Enclave operations only available on Linux with Nitro");
    }

    Ok(())
}
