use iced::Task;

use crate::message::{Identity, IdentityKind, Message};
use crate::screen::shares::ShareEntry;
use crate::screen::{relay, shares, Screen};

use super::{lock_keep, parse_hex_key, App, ToastKind};

impl App {
    pub(crate) fn collect_identities(&self, shares: &[ShareEntry]) -> Vec<Identity> {
        let mut identities: Vec<Identity> = Vec::new();
        let mut seen_groups: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for share in shares {
            if let Some(&idx) = seen_groups.get(&share.group_pubkey_hex) {
                if let IdentityKind::Frost {
                    ref mut share_count,
                    ..
                } = identities[idx].kind
                {
                    *share_count += 1;
                }
            } else {
                seen_groups.insert(share.group_pubkey_hex.clone(), identities.len());
                identities.push(Identity {
                    pubkey_hex: share.group_pubkey_hex.clone(),
                    npub: share.npub.clone(),
                    name: share.name.clone(),
                    kind: IdentityKind::Frost {
                        threshold: share.threshold,
                        total_shares: share.total_shares,
                        share_count: 1,
                    },
                });
            }
        }

        let guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_ref() {
            if let Ok(keys) = keep.list_keys() {
                for key in keys {
                    if key.key_type != keep_core::keys::KeyType::Nostr {
                        continue;
                    }
                    let hex = hex::encode(key.pubkey);
                    if !seen_groups.contains_key(&hex) {
                        seen_groups.insert(hex.clone(), identities.len());
                        identities.push(Identity {
                            pubkey_hex: hex,
                            npub: keep_core::keys::bytes_to_npub(&key.pubkey),
                            name: key.name,
                            kind: IdentityKind::Nsec,
                        });
                    }
                }
            }
        }

        identities
    }

    pub(crate) fn refresh_identities(&mut self, shares: &[ShareEntry]) {
        self.identities = self.collect_identities(shares);
        if self.active_share_hex.is_none() && self.identities.len() == 1 {
            let hex = self.identities[0].pubkey_hex.clone();
            let guard = lock_keep(&self.keep);
            if let Some(keep) = guard.as_ref() {
                let _ = keep.set_active_share_key(Some(&hex));
            }
            drop(guard);
            self.active_share_hex = Some(hex);
        }
    }

    pub(crate) fn handle_identity_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ToggleIdentitySwitcher => {
                self.identity_switcher_open = !self.identity_switcher_open;
                if !self.identity_switcher_open {
                    self.delete_identity_confirm = None;
                }
                Task::none()
            }
            Message::SwitchIdentity(pubkey_hex) => {
                if self.active_share_hex.as_deref() == Some(&pubkey_hex) {
                    return Task::none();
                }

                self.save_relay_urls();
                self.save_bunker_relays();

                self.handle_disconnect_relay();
                self.stop_bunker();

                if let Some(key) = parse_hex_key(&pubkey_hex) {
                    let config = {
                        let guard = lock_keep(&self.keep);
                        guard.as_ref().map(|keep| {
                            keep.get_relay_config_or_default(&key)
                                .unwrap_or_else(|_| keep_core::RelayConfig::with_defaults(key))
                        })
                    };
                    if let Some(config) = config {
                        self.apply_relay_config(config);
                    }
                }

                {
                    let guard = lock_keep(&self.keep);
                    if let Some(keep) = guard.as_ref() {
                        let _ = keep.set_active_share_key(Some(&pubkey_hex));
                    }
                }

                let is_nsec = self
                    .identities
                    .iter()
                    .any(|i| i.pubkey_hex == pubkey_hex && matches!(i.kind, IdentityKind::Nsec));
                if is_nsec {
                    if let Some(pubkey_bytes) = parse_hex_key(&pubkey_hex) {
                        let mut guard = lock_keep(&self.keep);
                        if let Some(keep) = guard.as_mut() {
                            let _ = keep.keyring_mut().set_primary(pubkey_bytes);
                        }
                    }
                }

                self.active_share_hex = Some(pubkey_hex);
                self.identity_switcher_open = false;
                self.delete_identity_confirm = None;

                let shares = self.current_shares();
                match &self.screen {
                    Screen::ShareList(_) => {
                        self.screen = Screen::ShareList(shares::State::new(
                            shares,
                            self.active_share_hex.clone(),
                        ));
                    }
                    Screen::Relay(_) => {
                        self.screen = Screen::Relay(relay::State::new(
                            shares,
                            self.relay_urls.clone(),
                            self.frost_status.clone(),
                            self.frost_peers.clone(),
                            self.pending_sign_display.clone(),
                            self.frost_event_log.clone(),
                        ));
                    }
                    Screen::Bunker(_) => {
                        self.screen = Screen::Bunker(Box::new(self.create_bunker_screen()));
                    }
                    Screen::NsecKeys(_) => {
                        self.set_nsec_keys_screen();
                    }
                    _ => {}
                }

                self.set_toast("Identity switched".into(), ToastKind::Success);
                Task::none()
            }
            Message::RequestDeleteIdentity(pubkey_hex) => {
                self.delete_identity_confirm = Some(pubkey_hex);
                Task::none()
            }
            Message::ConfirmDeleteIdentity(pubkey_hex) => {
                self.delete_identity_confirm = None;

                let identity = self
                    .identities
                    .iter()
                    .find(|i| i.pubkey_hex == pubkey_hex)
                    .cloned();
                let Some(identity) = identity else {
                    self.set_toast("Identity not found".into(), ToastKind::Error);
                    return Task::none();
                };

                let is_active = self.active_share_hex.as_deref() == Some(&pubkey_hex);
                if is_active {
                    self.handle_disconnect_relay();
                    self.stop_bunker();
                }

                let result = match &identity.kind {
                    IdentityKind::Frost { .. } => {
                        let shares = self.current_shares();
                        let group_shares: Vec<_> = shares
                            .iter()
                            .filter(|s| s.group_pubkey_hex == pubkey_hex)
                            .collect();
                        let total = group_shares.len();
                        let mut deleted = 0usize;
                        let mut delete_err: Option<String> = None;
                        for share in &group_shares {
                            let res = {
                                let mut guard = lock_keep(&self.keep);
                                guard.as_mut().map(|keep| {
                                    keep.frost_delete_share(&share.group_pubkey, share.identifier)
                                })
                            };
                            match res {
                                Some(Ok(())) => deleted += 1,
                                Some(Err(e)) => {
                                    delete_err = Some(super::friendly_err(e));
                                    break;
                                }
                                None => {
                                    delete_err = Some("Vault is locked".into());
                                    break;
                                }
                            }
                        }
                        if let Some(err_msg) = delete_err {
                            self.refresh_shares();
                            self.set_toast(
                                format!("Deleted {deleted}/{total} shares: {err_msg}"),
                                ToastKind::Error,
                            );
                            false
                        } else {
                            true
                        }
                    }
                    IdentityKind::Nsec => {
                        let Some(pubkey_bytes) = parse_hex_key(&pubkey_hex) else {
                            return Task::none();
                        };
                        let delete_result = {
                            let mut guard = lock_keep(&self.keep);
                            guard.as_mut().map(|keep| keep.delete_key(&pubkey_bytes))
                        };
                        match delete_result {
                            Some(Ok(())) => true,
                            Some(Err(e)) => {
                                self.set_toast(super::friendly_err(e), ToastKind::Error);
                                false
                            }
                            None => {
                                self.set_toast("Vault is locked".into(), ToastKind::Error);
                                false
                            }
                        }
                    }
                };

                if result {
                    if let Some(key) = parse_hex_key(&pubkey_hex) {
                        let guard = lock_keep(&self.keep);
                        if let Some(keep) = guard.as_ref() {
                            let _ = keep.delete_relay_config(&key);
                        }
                    }
                    self.refresh_shares();
                    self.set_toast(format!("'{}' deleted", identity.name), ToastKind::Success);
                }

                Task::none()
            }
            Message::CancelDeleteIdentity => {
                self.delete_identity_confirm = None;
                Task::none()
            }
            _ => Task::none(),
        }
    }
}
