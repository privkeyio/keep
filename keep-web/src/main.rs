#![forbid(unsafe_code)]

mod api;
mod auth;
mod bunker;
mod state;
mod state_replication;
mod ws;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use axum::routing::{get, post};
use axum::Router;
use tokio::sync::{broadcast, Mutex};
use tower_http::services::{ServeDir, ServeFile};
use zeroize::Zeroizing;

use keep_core::Keep;

use crate::state::{AppState, BunkerInfo};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Reads a secret from `{key}_FILE` (preferred) or the `{key}` env var. A file
/// keeps the secret off the process environment (which leaks via /proc,
/// container inspection, and crash dumps). Warns if the file is group/world
/// accessible.
fn secret_from(key: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Ok(path) = std::env::var(format!("{key}_FILE")) {
        let path = path.trim();
        if !path.is_empty() {
            return Ok(Some(read_secret_file(path)?));
        }
    }
    Ok(std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty()))
}

fn read_secret_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    // The permission check is Unix-only (keep-web runs on Linux/StartOS); on
    // other platforms the file is read without the mode warning so the
    // workspace still builds (e.g. Windows CI).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path,
                mode = format!("{mode:o}"),
                "secret file is group/world accessible; tighten to 0600"
            );
        }
    }
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

/// Resolve the optional shared cluster data key (keep-state replication). Reads via
/// `secret_from` so `KEEP_STORAGE_KEY_FILE` is honored (keeps the raw key off the
/// process environment, like the password and JWT key). Returns `None` when unset,
/// `Err` when set but malformed so a misconfigured cluster node fails loudly instead
/// of silently creating a non-replicable vault.
fn shared_data_key_from_env() -> Result<Option<Zeroizing<[u8; 32]>>, Box<dyn std::error::Error>> {
    let Some(hex_key) = secret_from("KEEP_STORAGE_KEY")? else {
        return Ok(None);
    };
    Ok(Some(parse_shared_data_key(&hex_key)?))
}

/// Decode a 32-byte shared data key from hex. Rejects malformed hex, the wrong
/// length, and an all-zero key so a misconfigured node fails loudly. The generic
/// hex error avoids echoing the malformed key material back into logs.
fn parse_shared_data_key(raw: &str) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    let decoded =
        Zeroizing::new(hex::decode(raw).map_err(|_| "KEEP_STORAGE_KEY is not valid hex")?);
    if decoded.len() != 32 {
        return Err("KEEP_STORAGE_KEY must be 32 bytes (64 hex chars)".into());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded);
    if key.iter().all(|&b| b == 0) {
        return Err("KEEP_STORAGE_KEY must not be all zero".into());
    }
    Ok(key)
}

fn parse_relays(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Resolve the FROST group to co-sign for. Precedence: an explicit
/// `KEEP_FROST_GROUP` npub, then the persisted active-share selection (the same
/// key keep-desktop/keep-android use), then the first group present (which is
/// persisted as the new default). The operator can switch the active group from
/// the Web Admin. `Ok(None)` means genuine first-run (no shares → setup mode);
/// `Err` only for a malformed `KEEP_FROST_GROUP` npub.
fn resolve_group(
    keep: &Keep,
    explicit: Option<&str>,
) -> Result<Option<([u8; 32], String)>, String> {
    if let Some(npub) = explicit {
        let bytes = keep_core::keys::npub_to_bytes(npub)
            .map_err(|e| format!("invalid KEEP_FROST_GROUP npub: {e}"))?;
        return Ok(Some((bytes, npub.to_string())));
    }
    let shares = match keep.frost_list_shares() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "frost_list_shares failed; treating as no shares");
            Vec::new()
        }
    };
    let mut groups: Vec<[u8; 32]> = shares.iter().map(|s| s.metadata.group_pubkey).collect();
    groups.sort();
    groups.dedup();
    if groups.is_empty() {
        return Ok(None);
    }
    // Honor the operator's persisted selection: the same active-share key that
    // keep-desktop and keep-android use, if it still names a held group.
    if let Some(active_hex) = keep.get_active_share_key() {
        if let Some(g) = groups.iter().find(|g| hex::encode(g) == active_hex) {
            return Ok(Some((*g, keep_core::keys::bytes_to_npub(g))));
        }
    }
    // No valid selection: default to the first group and persist it, so the box
    // co-signs immediately instead of erroring on ambiguity. The operator can
    // switch which group is served from the Web Admin.
    let g = groups[0];
    if let Err(e) = keep.set_active_share_key(Some(&hex::encode(g))) {
        tracing::warn!(error = %e, "failed to persist default active group");
    }
    Ok(Some((g, keep_core::keys::bytes_to_npub(&g))))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    keep_frost_net::install_default_crypto_provider();

    let vault_path = PathBuf::from(env_or("KEEP_PATH", "/data"));
    let bunker_relays = parse_relays(&env_or(
        "KEEP_BUNKER_RELAY",
        &env_or("KEEP_RELAY", "wss://bucket.coracle.social"),
    ));
    let frost_group = std::env::var("KEEP_FROST_GROUP").ok();
    // Fail-closed: signing is off until the operator explicitly enables it
    // (env at boot or the live kill switch).
    let auto_approve = env_or("KEEP_FROST_AUTO_APPROVE", "false") == "true";
    let ui_dir = PathBuf::from(env_or("KEEP_WEB_UI_DIR", "ui/dist"));
    let listen: SocketAddr = env_or("KEEP_WEB_LISTEN", "0.0.0.0:8080").parse()?;
    let password = secret_from("KEEP_PASSWORD")?
        .ok_or("KEEP_PASSWORD or KEEP_PASSWORD_FILE must be set for headless unlock")?;

    // First-run provisioning: create the vault if this is a fresh install
    // (e.g. first StartOS boot) rather than crashing.
    let mut keep = match Keep::open(&vault_path) {
        Ok(k) => k,
        Err(keep_core::error::KeepError::NotFound(_)) => {
            tracing::info!(path = %vault_path.display(), "no vault found; creating");
            match shared_data_key_from_env()? {
                Some(key) => {
                    tracing::info!(
                        "creating vault with shared cluster data key (keep-state replication)"
                    );
                    Keep::create_with_shared_data_key(
                        &vault_path,
                        &password,
                        keep_core::crypto::Argon2Params::DEFAULT,
                        *key,
                    )?
                }
                None => {
                    tracing::info!(
                        "KEEP_STORAGE_KEY not set; creating vault with a per-node random data key (non-replicable)"
                    );
                    Keep::create(&vault_path, &password)?
                }
            }
        }
        Err(e) => return Err(e.into()),
    };
    keep.unlock(&password)?;
    tracing::info!(path = %vault_path.display(), "vault unlocked");

    let (events, _) = broadcast::channel(256);
    let approvals = Arc::new(StdMutex::new(HashMap::new()));
    // Kill switch shared with the co-signer policy. A persisted toggle (set via
    // the live kill switch) wins; otherwise fall back to the boot default so a
    // restart doesn't silently re-enable signing.
    let signing_flag_path = state::signing_flag_path(&vault_path);
    let initial_enabled = state::read_signing_flag(&signing_flag_path).unwrap_or(auto_approve);
    let signing_enabled = Arc::new(std::sync::atomic::AtomicBool::new(initial_enabled));
    // Set if the active share is deleted at runtime; bars re-enabling signing.
    let signer_retired = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Resolve which FROST group this node co-signs for: an explicit
    // KEEP_FROST_GROUP, otherwise the single group present in the vault.
    // Auto-resolution avoids the chicken-and-egg of needing the group npub
    // before the share has been imported.
    let resolved_group = resolve_group(&keep, frost_group.as_deref())?;

    // Single-key mode puts the full primary key on this box (no threshold
    // security), so it requires both the opt-in flag and an explicit
    // acknowledgement to guard against accidental enablement.
    let allow_single_key = env_or("KEEP_ALLOW_SINGLE_KEY", "false") == "true";
    let single_key_ack = env_or("KEEP_SINGLE_KEY_ACK", "") == "i-understand";
    if allow_single_key && !single_key_ack {
        tracing::warn!(
            "KEEP_ALLOW_SINGLE_KEY set without KEEP_SINGLE_KEY_ACK=i-understand; refusing single-key mode"
        );
    }
    let single_key = allow_single_key && single_key_ack;

    let mut node = None;
    let mut active_identifier = None;
    let bunker_info = if let Some((group_pubkey, group_npub)) = resolved_group {
        match keep.frost_get_share(&group_pubkey) {
            Ok(share) => {
                active_identifier = Some(share.metadata.identifier);
                let frost_relays = parse_relays(&env_or("KEEP_FROST_RELAY", ""));
                let frost_relays = if frost_relays.is_empty() {
                    bunker_relays.clone()
                } else {
                    frost_relays
                };
                let handle = bunker::spawn_network_frost(
                    bunker::NetworkConfig {
                        share,
                        group_pubkey,
                        group_npub,
                        frost_relays,
                        bunker_relays,
                        enabled: signing_enabled.clone(),
                        bunker_secret: state::load_or_create_bunker_secret(&vault_path)?,
                        transport_key: state::load_or_create_transport_key(&vault_path)?,
                    },
                    events.clone(),
                    approvals.clone(),
                )
                .map_err(|e| format!("failed to start co-signer: {e}"))?;
                node = Some(handle.node);
                handle.info
            }
            Err(_) => {
                tracing::warn!(group = %group_npub, "group configured but no share present; setup mode");
                BunkerInfo::setup()
            }
        }
    } else if single_key && keep.keyring().get_primary().is_some() {
        // Explicit opt-in: sign with the vault's primary key alone (no
        // threshold security: the full key lives on this box).
        tracing::warn!("KEEP_ALLOW_SINGLE_KEY set; single-key bunker (no threshold security)");
        // Transfer ownership of the keyring into the bunker thread; `keep`'s
        // keyring is intentionally left empty afterwards (the bunker is the
        // only thing that signs in this mode; don't read keep.keyring() below).
        let keyring = Arc::new(Mutex::new(std::mem::take(keep.keyring_mut())));
        let bunker_secret = state::load_or_create_bunker_secret(&vault_path)?;
        bunker::spawn_single_key(
            keyring,
            bunker_relays,
            bunker_secret,
            events.clone(),
            approvals.clone(),
        )
        .map_err(|e| format!("failed to start bunker: {e}"))?
    } else {
        // Nothing to sign with yet: serve the admin UI so the operator can
        // import a share, then restart the service to start the co-signer.
        tracing::info!("no FROST share available; serving in setup mode");
        BunkerInfo::setup()
    };
    let keep = Arc::new(Mutex::new(keep));

    // keep-state replication over the mesh relay (opt-in via KEEP_STATE_RELAY, e.g. the on-box wisp).
    // The active publishes each vault-state write under a shared cluster identity; a standby consumes
    // and reconstructs. The relay is a trusted local/mesh address, so it is validated with the
    // allow-internal guard (a mesh IP is not public), and ws:// still needs KEEP_ALLOW_WS=1.
    if let Ok(state_relay) = std::env::var("KEEP_STATE_RELAY") {
        if !state_relay.trim().is_empty() {
            keep_core::relay::validate_relay_url_allow_internal(&state_relay)
                .map_err(|e| format!("KEEP_STATE_RELAY invalid: {e}"))?;
            let identity = state_replication::load_state_identity()?;
            let role = env_or("KEEP_STATE_ROLE", "active");
            state_replication::spawn(keep.clone(), state_relay, identity, &role).await?;
            tracing::info!(role = %role, "keep-state replication enabled");
        }
    }

    tracing::info!(mode = %bunker_info.mode, "started");

    let state = AppState {
        keep,
        bunker: bunker_info,
        active_identifier,
        events,
        approvals,
        ws_tickets: state::TicketStore::default(),
        signing_enabled,
        signer_retired,
        signing_flag_path,
        node,
        switching: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    let serve_index = ServeFile::new(ui_dir.join("index.html"));
    let static_files = ServeDir::new(&ui_dir).fallback(serve_index);

    // Fail-closed bearer-token gate on every sensitive /api/* route.
    let auth_token = auth::AuthToken::resolve(secret_from("KEEP_WEB_AUTH_TOKEN")?);

    let authed = Router::new()
        .route("/api/bunker", get(api::bunker))
        .route("/api/shares", get(api::shares))
        .route("/api/shares/import", post(api::import_share))
        .route("/api/shares/export", post(api::export_share))
        .route("/api/shares/delete", post(api::delete_share))
        .route("/api/shares/rename", post(api::rename_share))
        .route("/api/active-group", post(api::set_active_group))
        .route("/api/signing-log", get(api::signing_log))
        .route("/api/peers", get(api::peers))
        .route(
            "/api/killswitch",
            get(api::killswitch_status).post(api::set_killswitch),
        )
        .route("/api/approvals/{id}", post(api::resolve_approval))
        .route("/api/ws-ticket", post(api::ws_ticket))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            auth_token,
            auth::require_auth,
        ));

    // Unauthenticated: health for StartOS/Docker probes; the WS upgrade gates
    // itself on a single-use ticket (minted via the authed /api/ws-ticket) so
    // the durable token never appears in a URL or proxy access log.
    let public = Router::new()
        .route("/api/health", get(api::health))
        .route("/api/events", get(ws::events))
        .with_state(state);

    let app = public.merge(authed).fallback_service(static_files);

    tracing::info!(%listen, "serving web admin");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::Keep;
    use tempfile::tempdir;

    fn unlocked_keep(dir: &std::path::Path) -> Keep {
        let mut keep = Keep::create(&dir.join("vault"), "password").unwrap();
        keep.unlock("password").unwrap();
        keep
    }

    #[test]
    fn resolve_no_shares_is_setup() {
        let dir = tempdir().unwrap();
        let keep = unlocked_keep(dir.path());
        assert!(resolve_group(&keep, None).unwrap().is_none());
    }

    #[test]
    fn resolve_single_group() {
        let dir = tempdir().unwrap();
        let mut keep = unlocked_keep(dir.path());
        let g = *keep.frost_generate(2, 3, "g").unwrap()[0].group_pubkey();
        assert_eq!(resolve_group(&keep, None).unwrap().unwrap().0, g);
    }

    #[test]
    fn resolve_multiple_defaults_and_persists() {
        let dir = tempdir().unwrap();
        let mut keep = unlocked_keep(dir.path());
        keep.frost_generate(2, 3, "a").unwrap();
        keep.frost_generate(2, 3, "b").unwrap();
        // Must not error on ambiguity: pick a default and persist it.
        let (bytes, _) = resolve_group(&keep, None).unwrap().unwrap();
        assert_eq!(
            keep.get_active_share_key().as_deref(),
            Some(hex::encode(bytes).as_str())
        );
    }

    #[test]
    fn resolve_honors_active_selection() {
        let dir = tempdir().unwrap();
        let mut keep = unlocked_keep(dir.path());
        let a = *keep.frost_generate(2, 3, "a").unwrap()[0].group_pubkey();
        let b = *keep.frost_generate(2, 3, "b").unwrap()[0].group_pubkey();
        let default = resolve_group(&keep, None).unwrap().unwrap().0;
        let other = if default == a { b } else { a };
        keep.set_active_share_key(Some(&hex::encode(other)))
            .unwrap();
        assert_eq!(resolve_group(&keep, None).unwrap().unwrap().0, other);
    }

    #[test]
    fn resolve_explicit_override_wins() {
        let dir = tempdir().unwrap();
        let mut keep = unlocked_keep(dir.path());
        let a = *keep.frost_generate(2, 3, "a").unwrap()[0].group_pubkey();
        let npub = keep_core::keys::bytes_to_npub(&a);
        assert_eq!(resolve_group(&keep, Some(&npub)).unwrap().unwrap().0, a);
    }

    #[test]
    fn parse_shared_data_key_valid() {
        let hex_key = hex::encode([7u8; 32]);
        let key = parse_shared_data_key(&hex_key).unwrap();
        assert_eq!(*key, [7u8; 32]);
    }

    #[test]
    fn parse_shared_data_key_bad_hex() {
        assert!(parse_shared_data_key("zz").is_err());
    }

    #[test]
    fn parse_shared_data_key_wrong_length() {
        assert!(parse_shared_data_key(&hex::encode([1u8; 31])).is_err());
        assert!(parse_shared_data_key(&hex::encode([1u8; 33])).is_err());
    }

    #[test]
    fn parse_shared_data_key_all_zero() {
        assert!(parse_shared_data_key(&hex::encode([0u8; 32])).is_err());
    }
}
