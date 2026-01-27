// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use secrecy::ExposeSecret;
use tracing::debug;

use keep_core::error::{KeepError, Result};
use keep_core::frost::ShareExport;
use keep_core::keys::bytes_to_npub;
use keep_core::Keep;

use crate::output::Output;
use crate::ExportFormat;

use super::{get_password, get_password_with_confirm};

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_generate(
    out: &Output,
    path: &Path,
    threshold: u16,
    total_shares: u16,
    name: &str,
) -> Result<()> {
    debug!(threshold, total_shares, name, "generating FROST key");

    out.newline();
    out.warn("WARNING: Trusted dealer mode - for testing/development only.");
    out.warn("The full private key exists on this machine during generation.");
    out.warn("For production, use 'keep frost network dkg' for distributed key generation");
    out.warn("where the full key never exists on any single device.");
    out.newline();

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Generating FROST key shares...");
    let shares = keep.frost_generate(threshold, total_shares, name)?;
    spinner.finish();

    if shares.is_empty() {
        return Err(KeepError::Frost(
            "no shares returned from frost_generate".into(),
        ));
    }

    let group_pubkey = shares[0].group_pubkey();
    let npub = bytes_to_npub(group_pubkey);

    out.newline();
    out.success("Generated FROST key group!");
    out.field("Name", name);
    out.key_field("Pubkey", &npub);
    out.field("Threshold", &format!("{}-of-{}", threshold, total_shares));
    out.newline();

    for share in &shares {
        out.info(&format!(
            "Share {}: stored locally",
            share.metadata.identifier
        ));
    }

    out.newline();
    out.warn("BACKUP: Export shares to different locations for recovery!");

    Ok(())
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_split(
    out: &Output,
    path: &Path,
    key_name: &str,
    threshold: u16,
    total_shares: u16,
) -> Result<()> {
    debug!(
        key_name,
        threshold, total_shares, "splitting key into FROST shares"
    );

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let spinner = out.spinner("Splitting key into FROST shares...");
    let shares = keep.frost_split(key_name, threshold, total_shares)?;
    spinner.finish();

    if shares.is_empty() {
        return Err(KeepError::Frost(
            "no shares returned from frost_split".into(),
        ));
    }

    let group_pubkey = shares[0].group_pubkey();
    let npub = bytes_to_npub(group_pubkey);

    out.newline();
    out.success("Split key into FROST shares!");
    out.key_field("Pubkey (preserved)", &npub);
    out.field("Threshold", &format!("{}-of-{}", threshold, total_shares));
    out.newline();

    for share in &shares {
        out.info(&format!(
            "Share {}: stored locally",
            share.metadata.identifier
        ));
    }

    out.newline();
    out.warn("BACKUP: Export shares to different locations for recovery!");

    Ok(())
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_list(out: &Output, path: &Path) -> Result<()> {
    debug!("listing FROST shares");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let shares = keep.frost_list_shares()?;

    if shares.is_empty() {
        out.newline();
        out.info("No FROST shares found. Use 'keep frost generate' to create some.");
        return Ok(());
    }

    out.table_header(&[("NAME", 16), ("ID", 6), ("THRESHOLD", 12), ("PUBKEY", 28)]);

    for share in &shares {
        let npub = bytes_to_npub(&share.metadata.group_pubkey);
        let display_npub = if npub.len() > 24 {
            format!("{}...", &npub[..24])
        } else {
            npub
        };
        out.table_row(&[
            (&share.metadata.name, 16, false),
            (&share.metadata.identifier.to_string(), 6, false),
            (
                &format!(
                    "{}-of-{}",
                    share.metadata.threshold, share.metadata.total_shares
                ),
                12,
                false,
            ),
            (&display_npub, 28, true),
        ]);
    }

    out.newline();
    out.info(&format!("{} share(s) total", shares.len()));

    Ok(())
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_export(
    out: &Output,
    path: &Path,
    identifier: u16,
    group_npub: &str,
    format: ExportFormat,
) -> Result<()> {
    debug!(identifier, group = group_npub, "exporting FROST share");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let export_password =
        get_password_with_confirm("Enter passphrase for share export", "Confirm passphrase")?;

    let spinner = out.spinner("Encrypting share for export...");
    let export =
        keep.frost_export_share(&group_pubkey, identifier, export_password.expose_secret())?;
    spinner.finish();

    let (output, label) = match format {
        ExportFormat::Json => (export.to_json()?, "JSON"),
        ExportFormat::Bech32 => (export.to_bech32()?, "Bech32"),
    };

    out.newline();
    out.success("Share exported!");
    out.newline();
    out.info(&format!("Copy this export data ({label} format):"));
    out.newline();
    println!("{}", output);

    Ok(())
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_import(out: &Output, path: &Path) -> Result<()> {
    debug!("importing FROST share");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    out.info("Paste the share export data (JSON or bech32, end with empty line):");

    const MAX_INPUT_BYTES: usize = 256 * 1024;
    let mut input = String::new();
    let mut total_bytes = 0usize;
    loop {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read input: {}",
                e
            )))
        })?;
        if line.trim().is_empty() {
            break;
        }
        total_bytes = total_bytes.saturating_add(line.len());
        if total_bytes > MAX_INPUT_BYTES {
            return Err(KeepError::InvalidInput(format!(
                "input exceeds maximum size of {} bytes",
                MAX_INPUT_BYTES
            )));
        }
        input.push_str(&line);
    }

    let export = ShareExport::parse(input.trim())?;
    let import_password = get_password("Enter share passphrase")?;

    let spinner = out.spinner("Decrypting and importing share...");
    keep.frost_import_share(&export, import_password.expose_secret())?;
    spinner.finish();

    out.newline();
    out.success(&format!(
        "Imported share {} for group {}",
        export.identifier, export.group_pubkey
    ));

    Ok(())
}

#[cfg(feature = "warden")]
pub async fn check_warden_policy(
    out: &Output,
    warden_url: &str,
    group_npub: &str,
    message_hex: &str,
) -> Result<()> {
    use crate::warden::{check_policy, get_warden_token, wait_for_approval, PolicyCheckResult};

    use super::get_confirm;

    let token = get_warden_token();

    out.info("Checking Warden policy...");

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("operation".to_string(), serde_json::json!("frost_sign"));
    metadata.insert("message_hash".to_string(), serde_json::json!(message_hex));

    let result = check_policy(warden_url, token.clone(), group_npub, "", 0, Some(metadata)).await?;

    match result {
        PolicyCheckResult::Allowed => {
            out.success("Policy check passed");
            out.newline();
            Ok(())
        }
        PolicyCheckResult::Denied { rule_id, reason } => {
            out.error(&format!(
                "Policy denied signing: {} (rule: {})",
                reason, rule_id
            ));
            Err(KeepError::PermissionDenied(format!(
                "warden policy denied: {} (rule: {})",
                reason, rule_id
            )))
        }
        PolicyCheckResult::RequiresApproval {
            rule_id,
            config,
            transaction_id,
        } => {
            out.warn(&format!("Signing requires approval (rule: {})", rule_id));
            out.field("Quorum required", &config.quorum.to_string());
            out.field("Approver groups", &config.from_groups.join(", "));
            out.field(
                "Approval timeout",
                &format!("{} hours", config.timeout_hours),
            );
            out.field("Transaction ID", &transaction_id.to_string());
            out.newline();

            const MAX_WAIT_SECS: u64 = 300;
            let confirm = get_confirm(&format!(
                "Wait for approval? (will poll for up to {} seconds)",
                MAX_WAIT_SECS
            ))?;
            if !confirm {
                return Err(KeepError::UserRejected);
            }

            let spinner = out.spinner("Waiting for approval...");

            match wait_for_approval(warden_url, token, transaction_id, MAX_WAIT_SECS).await {
                Ok(true) => {
                    spinner.finish();
                    out.success("Approval granted");
                    out.newline();
                    Ok(())
                }
                Ok(false) => {
                    spinner.finish();
                    Err(KeepError::PermissionDenied("approval was denied".into()))
                }
                Err(e) => {
                    spinner.finish();
                    Err(e)
                }
            }
        }
    }
}

#[tracing::instrument(skip(out, warden_url), fields(path = %path.display()))]
pub fn cmd_frost_sign(
    out: &Output,
    path: &Path,
    message_hex: &str,
    group_id: &str,
    interactive: bool,
    warden_url: Option<&str>,
) -> Result<()> {
    debug!(
        message = message_hex,
        group = group_id,
        interactive,
        "FROST signing"
    );

    let message = hex::decode(message_hex)
        .map_err(|_| KeepError::InvalidInput("invalid message hex".into()))?;

    #[cfg(feature = "warden")]
    if let Some(url) = warden_url {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;
        rt.block_on(check_warden_policy(out, url, group_id, message_hex))?;
    }

    #[cfg(not(feature = "warden"))]
    if warden_url.is_some() {
        return Err(KeepError::NotImplemented(
            "Warden support not compiled. Rebuild with --features warden".into(),
        ));
    }

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let shares = keep.frost_list_shares()?;

    // Try to parse as npub first, otherwise look up by group name
    let group_pubkey = if group_id.starts_with("npub1") {
        keep_core::keys::npub_to_bytes(group_id)?
    } else {
        // Look up by group name
        let share = shares
            .iter()
            .find(|s| s.metadata.name == group_id)
            .ok_or_else(|| {
                KeepError::KeyNotFound(format!("No group found with name: {}", group_id))
            })?;
        share.metadata.group_pubkey
    };
    let our_shares: Vec<_> = shares
        .iter()
        .filter(|s| s.metadata.group_pubkey == group_pubkey)
        .collect();

    if our_shares.is_empty() {
        return Err(KeepError::KeyNotFound(format!(
            "No shares found for group {}",
            group_id
        )));
    }

    let threshold = our_shares[0].metadata.threshold;
    let total = our_shares[0].metadata.total_shares;

    if interactive {
        return cmd_frost_sign_interactive(out, &keep, &group_pubkey, &message, threshold, total);
    }

    if our_shares.len() < threshold as usize {
        return Err(KeepError::FrostErr(
            keep_core::error::FrostError::threshold_not_met(threshold, our_shares.len() as u16),
        ));
    }

    out.info(&format!(
        "Signing with {}-of-{} local shares",
        threshold, total
    ));

    let spinner = out.spinner("Generating signature...");
    let sig_bytes = keep.frost_sign(&group_pubkey, &message)?;
    spinner.finish();

    out.newline();
    out.success("Signature generated!");
    out.newline();
    println!("{}", hex::encode(sig_bytes));

    Ok(())
}

fn cmd_frost_sign_interactive(
    out: &Output,
    keep: &Keep,
    group_pubkey: &[u8; 32],
    message: &[u8],
    threshold: u16,
    total: u16,
) -> Result<()> {
    use frost::{round1, round2, Identifier, SigningPackage};
    use frost_secp256k1_tr as frost;
    use keep_core::frost::FrostMessage;
    use std::collections::BTreeMap;
    use std::io::{BufRead, Write};

    out.info(&format!(
        "Interactive FROST signing: {}-of-{}",
        threshold, total
    ));
    out.newline();

    let share = keep.frost_get_share(group_pubkey)?;
    let kp = share.key_package()?;
    let our_id = *kp.identifier();
    let our_id_u16 = share.metadata.identifier;

    let session_id: [u8; 32] = keep_core::crypto::blake2b_256(message);

    out.info("Round 1: Generating commitment...");
    let (our_nonces, our_commitment) =
        round1::commit(kp.signing_share(), &mut frost::rand_core::OsRng);

    let commit_bytes = our_commitment
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Serialize commitment: {}", e)))?;
    let commit_msg = FrostMessage::commitment(&session_id, our_id_u16, &commit_bytes);
    let commit_json = commit_msg.to_json()?;

    out.newline();
    out.info("Send this commitment to other signers:");
    println!("{}", commit_json);
    out.newline();

    let mut commitments: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    commitments.insert(our_id, our_commitment);

    let needed = threshold as usize - 1;
    out.info(&format!(
        "Waiting for {} commitment(s). Paste each on one line:",
        needed
    ));

    let stdin = std::io::stdin();
    for i in 0..needed {
        print!("[{}/{}] ", i + 1, needed);
        std::io::stdout().flush().ok();

        let mut line = String::new();
        stdin.lock().read_line(&mut line).map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read input: {}",
                e
            )))
        })?;

        let msg = FrostMessage::from_json(line.trim())?;
        if msg.session_id != hex::encode(session_id) {
            return Err(KeepError::Frost("Session ID mismatch".into()));
        }

        let payload = msg.payload_bytes()?;
        let commit = round1::SigningCommitments::deserialize(&payload)
            .map_err(|e| KeepError::Frost(format!("Invalid commitment: {}", e)))?;

        let id = Identifier::try_from(msg.identifier)
            .map_err(|e| KeepError::Frost(format!("Invalid identifier: {}", e)))?;
        commitments.insert(id, commit);
    }

    out.newline();
    out.info("Round 2: Generating signature share...");

    let signing_package = SigningPackage::new(commitments.clone(), message);
    let our_sig_share = round2::sign(&signing_package, &our_nonces, &kp)
        .map_err(|e| KeepError::Frost(format!("Sign failed: {}", e)))?;

    let share_bytes = our_sig_share.serialize();
    let share_msg = FrostMessage::signature_share(&session_id, our_id_u16, &share_bytes);
    let share_json = share_msg.to_json()?;

    out.newline();
    out.info("Send this signature share to the coordinator:");
    println!("{}", share_json);
    out.newline();

    let mut sig_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
    sig_shares.insert(our_id, our_sig_share);

    out.info(&format!("Waiting for {} signature share(s):", needed));

    for i in 0..needed {
        print!("[{}/{}] ", i + 1, needed);
        std::io::stdout().flush().ok();

        let mut line = String::new();
        stdin.lock().read_line(&mut line).map_err(|e| {
            KeepError::StorageErr(keep_core::error::StorageError::io(format!(
                "read input: {}",
                e
            )))
        })?;

        let msg = FrostMessage::from_json(line.trim())?;
        if msg.session_id != hex::encode(session_id) {
            return Err(KeepError::Frost("Session ID mismatch".into()));
        }

        let payload = msg.payload_bytes()?;
        let sig_share = round2::SignatureShare::deserialize(&payload)
            .map_err(|e| KeepError::Frost(format!("Invalid signature share: {}", e)))?;

        let id = Identifier::try_from(msg.identifier)
            .map_err(|e| KeepError::Frost(format!("Invalid identifier: {}", e)))?;
        sig_shares.insert(id, sig_share);
    }

    out.newline();
    out.info("Aggregating signature...");

    let pubkey_pkg = share.pubkey_package()?;
    let signature = frost::aggregate(&signing_package, &sig_shares, &pubkey_pkg)
        .map_err(|e| KeepError::Frost(format!("Aggregation failed: {}", e)))?;

    let serialized = signature
        .serialize()
        .map_err(|e| KeepError::Frost(format!("Serialize signature: {}", e)))?;
    let bytes = serialized.as_slice();
    if bytes.len() != 64 {
        return Err(KeepError::Frost("Invalid signature length".into()));
    }

    out.newline();
    out.success("Signature generated!");
    out.newline();
    println!("{}", hex::encode(bytes));

    Ok(())
}
