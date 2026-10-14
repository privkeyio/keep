// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `ssh_sign`, the gateway's side: a request to sign is checked against the
//! key's SSH rule (see [`crate::ssh::check_request`]), recorded, and signed
//! here. The key never leaves the gateway.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keep_core::secret::SecretKind;
use serde_json::{json, Value};

use super::inject::{hex_sha256, refused};
use super::{only_args, parse_secret_id, tools, Refusal, Served, State};
use crate::gateway::GrantedCredential;
use crate::policy::secret_entry;
use crate::scope::Operation;
use crate::ssh::{check_request, fingerprint, public_key_text, Signing, SshKey, MAX_BINDINGS};

/// The most data a request may ask to have signed: a login request or SSHSIG
/// data is far smaller.
pub(crate) const MAX_DATA: usize = 16 * 1024;
/// The longest session binding a request carries.
pub(crate) const MAX_BINDING: usize = 4 * 1024;

fn base64_arg(value: Option<&Value>, max: usize) -> Option<Vec<u8>> {
    B64.decode(value?.as_str()?).ok().filter(|b| b.len() <= max)
}

impl State {
    /// The SSH key secret `id` holds, if it is a plain one keep generated.
    pub(super) fn ssh_key(&self, id: &[u8; 32]) -> Option<SshKey> {
        let seed = self.keep.use_secret(id, &[SecretKind::SshKey]).ok()?;
        SshKey::from_seed(&seed)
    }

    /// `list_secrets`' view of an SSH key: its public key, when it can be
    /// used.
    pub(super) fn ssh_public_key(&self, id: &[u8; 32]) -> Option<String> {
        public_key_text(&self.ssh_key(id)?.public_blob())
    }

    pub(super) fn ssh_sign(
        &mut self,
        granted: &GrantedCredential,
        args: &Value,
        now: u64,
    ) -> Served {
        only_args(args, &["secret", "data", "flags", "bindings"])?;
        let secret = args
            .get("secret")
            .and_then(Value::as_str)
            .and_then(parse_secret_id)
            .ok_or_else(|| Refusal::params("secret must be a secret id, 64 lowercase hex"))?;
        let data = base64_arg(args.get("data"), MAX_DATA)
            .ok_or_else(|| Refusal::params("data must be base64, at most 16 KiB decoded"))?;
        // Flags only select RSA signature algorithms.
        let flags_set = match args.get("flags") {
            None | Some(Value::Null) => false,
            Some(v) if v.as_u64() == Some(0) => false,
            Some(v) if v.as_u64().is_some_and(|f| f <= u64::from(u32::MAX)) => true,
            Some(_) => return Err(Refusal::params("flags must be a 32-bit unsigned integer")),
        };
        let bindings: Vec<Vec<u8>> = match args.get("bindings") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) if items.len() <= MAX_BINDINGS => items
                .iter()
                .map(|item| base64_arg(Some(item), MAX_BINDING))
                .collect::<Option<_>>()
                .ok_or_else(|| Refusal::params("each binding must be base64, at most 4 KiB"))?,
            Some(_) => {
                return Err(Refusal::params(format!(
                    "bindings must be a list of at most {MAX_BINDINGS}"
                )))
            }
        };
        let entry = secret_entry(&granted.grant, Operation::SshSign, &secret).map_err(refused)?;
        let Some(rule) = &entry.ssh else {
            return Err(refused("not an SSH key"));
        };
        if flags_set {
            return Err(refused("signature flags, which only RSA keys take"));
        }
        let key = self
            .ssh_key(&secret)
            .ok_or_else(|| refused("that SSH key cannot be used"))?;
        let signing = check_request(rule, &key.public_blob(), &data, &bindings).map_err(refused)?;
        let detail = match &signing {
            Signing::Login { user, host } => format!(
                "secret {} login {user} host {} data sha256 {}",
                hex::encode(&secret[..16]),
                fingerprint(host),
                hex_sha256(&data)
            ),
            Signing::Sshsig { namespace } => format!(
                "secret {} sshsig {namespace} data sha256 {}",
                hex::encode(&secret[..16]),
                hex_sha256(&data)
            ),
        };
        self.served(granted, tools::SSH_SIGN, &detail, now)?;
        Ok(json!({ "signature": B64.encode(key.sign(&data)) }))
    }
}
