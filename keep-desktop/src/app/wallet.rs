use iced::Task;
use tracing::{info, warn};

use crate::message::Message;
use crate::screen::wallet::{self, DescriptorProgress, SetupPhase};
use crate::screen::Screen;

use super::util::with_keep_blocking;
use super::{friendly_err, App, ToastKind, MAX_ACTIVE_COORDINATIONS};

impl App {
    pub(crate) fn handle_wallet_message(&mut self, msg: wallet::Message) -> Task<Message> {
        let Screen::Wallet(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            wallet::Event::StartSetup => {
                let shares = self.current_shares();
                if let Screen::Wallet(s) = &mut self.screen {
                    s.begin_setup(shares);
                }
                Task::none()
            }
            wallet::Event::BeginCoordination => self.begin_descriptor_coordination(),
            wallet::Event::CancelSetup { session_id } => {
                if let Some(sid) = session_id {
                    self.active_coordinations.remove(&sid);
                    if let Some(node) = self.get_frost_node() {
                        node.cancel_descriptor_session(&sid);
                    }
                }
                Task::none()
            }
            wallet::Event::StartAnnounce => {
                if let Screen::Wallet(s) = &mut self.screen {
                    s.begin_announce();
                }
                Task::none()
            }
            wallet::Event::SubmitAnnounce {
                xpub,
                fingerprint,
                label,
            } => {
                let Some(node) = self.get_frost_node() else {
                    if let Screen::Wallet(s) = &mut self.screen {
                        s.announce_not_connected();
                    }
                    return Task::none();
                };

                let announced = keep_frost_net::AnnouncedXpub {
                    xpub,
                    fingerprint,
                    label: if label.is_empty() { None } else { Some(label) },
                };

                Task::perform(
                    async move {
                        node.announce_xpubs(vec![announced])
                            .await
                            .map_err(|e| format!("{e}"))
                    },
                    Message::WalletAnnounceResult,
                )
            }
            wallet::Event::CopyDescriptor(desc) => iced::clipboard::write(desc),
            wallet::Event::SubmitRegister {
                group_pubkey,
                external_descriptor,
                device_uri,
                wallet_name,
            } => self.begin_register_on_device(
                group_pubkey,
                external_descriptor,
                device_uri,
                wallet_name,
            ),
            wallet::Event::RejectPsbt(session_id) => {
                Task::done(Message::RejectPsbtSignature(session_id))
            }
        }
    }

    pub(crate) fn handle_wallet_global_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::WalletsLoaded(result) => {
                match result {
                    Ok(wallets) => {
                        let mut ws = wallet::State::new(wallets);
                        ws.peer_xpubs = self.peer_xpubs.clone();
                        ws.pending_psbt_signatures = self.pending_psbt_signatures.clone();
                        self.screen = Screen::Wallet(ws);
                    }
                    Err(e) => {
                        self.set_toast(e, ToastKind::Error);
                    }
                }
                Task::none()
            }
            Message::WalletSessionStarted(result) => {
                match result {
                    Ok((session_id, group_pubkey, network, _expected_participants)) => {
                        let on_wallet_screen = matches!(
                            self.screen,
                            Screen::Wallet(wallet::State { setup: Some(_), .. })
                        );
                        if !on_wallet_screen {
                            if let Some(node) = self.get_frost_node() {
                                node.cancel_descriptor_session(&session_id);
                            }
                        } else if self.active_coordinations.len() >= MAX_ACTIVE_COORDINATIONS {
                            if let Some(node) = self.get_frost_node() {
                                node.cancel_descriptor_session(&session_id);
                            }
                            if let Screen::Wallet(wallet::State { setup: Some(s), .. }) =
                                &mut self.screen
                            {
                                s.phase = SetupPhase::Coordinating(DescriptorProgress::Failed(
                                    "Too many active coordinations".to_string(),
                                ));
                            }
                        } else {
                            self.active_coordinations.insert(
                                session_id,
                                super::ActiveCoordination {
                                    group_pubkey,
                                    network,
                                    is_initiator: true,
                                },
                            );
                            if let Screen::Wallet(wallet::State { setup: Some(s), .. }) =
                                &mut self.screen
                            {
                                s.session_id = Some(session_id);
                            }
                        }
                    }
                    Err(e) => {
                        if let Screen::Wallet(wallet::State { setup: Some(s), .. }) =
                            &mut self.screen
                        {
                            s.phase =
                                SetupPhase::Coordinating(DescriptorProgress::Failed(e.clone()));
                            s.error = Some(e);
                        }
                    }
                }
                Task::none()
            }
            Message::WalletDescriptorProgress(progress, session_id) => {
                if let Some(sid) = session_id {
                    if matches!(progress, DescriptorProgress::Failed(_)) {
                        self.active_coordinations.remove(&sid);
                    }
                    self.update_wallet_setup(&sid, |setup| {
                        setup.phase = SetupPhase::Coordinating(progress);
                    });
                } else if matches!(progress, DescriptorProgress::Contributed) {
                    if let Screen::Wallet(wallet::State { setup: Some(s), .. }) = &mut self.screen {
                        s.phase = SetupPhase::Coordinating(progress);
                    }
                }
                Task::none()
            }
            Message::WalletAnnounceResult(result) => {
                match result {
                    Ok(()) => {
                        if let Screen::Wallet(s) = &mut self.screen {
                            s.announce_submitted();
                        }
                    }
                    Err(e) => {
                        if let Screen::Wallet(s) = &mut self.screen {
                            s.announce_failed(e);
                        }
                    }
                }
                Task::none()
            }
            Message::WalletRegisterResult(result) => {
                match result {
                    Ok(()) => {
                        if let Screen::Wallet(s) = &mut self.screen {
                            s.register_submitted();
                        }
                        self.set_toast("Wallet registered on device".into(), ToastKind::Success);
                    }
                    Err(e) => {
                        if let Screen::Wallet(s) = &mut self.screen {
                            s.register_failed(e);
                        }
                    }
                }
                Task::none()
            }
            Message::RejectPsbtSignature(session_id) => {
                let Some(node) = self.get_frost_node() else {
                    self.set_toast("Relay not connected".into(), ToastKind::Error);
                    return Task::none();
                };
                Task::perform(
                    async move {
                        node.abort_psbt_session(session_id, "rejected by signer")
                            .await
                            .map_err(|e| format!("{e}"))
                    },
                    move |r| Message::RejectPsbtSignatureResult(session_id, r),
                )
            }
            Message::RejectPsbtSignatureResult(session_id, result) => {
                self.pending_psbt_signatures
                    .retain(|e| e.session_id != session_id);
                if let Screen::Wallet(s) = &mut self.screen {
                    s.pending_psbt_signatures
                        .retain(|e| e.session_id != session_id);
                }
                match result {
                    Ok(()) => {
                        self.set_toast("PSBT rejected".into(), ToastKind::Success);
                    }
                    Err(e) => {
                        self.set_toast(format!("PSBT reject failed: {e}"), ToastKind::Error);
                    }
                }
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn begin_register_on_device(
        &mut self,
        group_pubkey: [u8; 32],
        external_descriptor: String,
        device_uri: String,
        wallet_name: String,
    ) -> Task<Message> {
        let multipath = match keep_bitcoin::multipath_from_external(&external_descriptor) {
            Ok(m) => m,
            Err(e) => {
                if let Screen::Wallet(s) = &mut self.screen {
                    s.register_failed(format!("build multipath descriptor: {e}"));
                }
                return Task::none();
            }
        };
        if multipath.len() > keep_nip46::MAX_DESCRIPTOR_LEN {
            if let Screen::Wallet(s) = &mut self.screen {
                s.register_failed(format!(
                    "descriptor exceeds {} bytes",
                    keep_nip46::MAX_DESCRIPTOR_LEN
                ));
            }
            return Task::none();
        }

        let keep_arc = self.keep.clone();
        let group_hex = hex::encode(group_pubkey);

        Task::perform(
            async move {
                let client = keep_nip46::Nip46Client::connect_to(&device_uri)
                    .await
                    .map_err(|e| {
                        warn!(group = %group_hex, "NIP-46 connect failed: {e}");
                        format!("connect: {e}")
                    })?;
                let signer = client.signer_pubkey();
                let signer_hex = hex::encode(signer.to_bytes());

                let register_outcome = async {
                    client.connect().await.map_err(|e| {
                        warn!(
                            group = %group_hex,
                            signer = %signer_hex,
                            "NIP-46 handshake failed: {e}",
                        );
                        format!("handshake: {e}")
                    })?;
                    client
                        .register_wallet(&wallet_name, &multipath)
                        .await
                        .map_err(|e| {
                            warn!(
                                group = %group_hex,
                                signer = %signer_hex,
                                "register_wallet rejected: {e}",
                            );
                            format!("register_wallet: {e}")
                        })
                }
                .await;

                client.disconnect().await;
                let response = register_outcome?;

                let signer_bytes = signer.to_bytes();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let group_hex_for_save = group_hex.clone();
                let signer_hex_for_save = signer_hex.clone();
                let wallet_name_saved = wallet_name.clone();
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Failed to save registration", move |keep| {
                        keep.upsert_device_registration(
                            &group_pubkey,
                            keep_core::DeviceRegistration {
                                signer_pubkey: signer_bytes,
                                wallet_name: wallet_name_saved,
                                hmac: response.hmac.clone(),
                                registered_at: now,
                            },
                        )
                        .map_err(friendly_err)
                    })
                })
                .await
                .map_err(|_| {
                    warn!(
                        group = %group_hex_for_save,
                        signer = %signer_hex_for_save,
                        "spawn_blocking for upsert_device_registration failed",
                    );
                    "Background task failed".to_string()
                })??;

                info!(
                    group = %group_hex,
                    signer = %signer_hex,
                    wallet_name = %wallet_name,
                    "wallet registered on device",
                );
                Ok::<(), String>(())
            },
            Message::WalletRegisterResult,
        )
    }

    pub(crate) fn begin_descriptor_coordination(&mut self) -> Task<Message> {
        use crate::message::ConnectionStatus;
        use keep_frost_net::{KeySlot, PolicyTier, WalletPolicy};

        let (share, network, policy) = match &mut self.screen {
            Screen::Wallet(wallet::State { setup: Some(s), .. }) => {
                let Some(idx) = s.selected_share else {
                    s.error = Some("Select a share".into());
                    return Task::none();
                };
                let Some(share) = s.shares.get(idx).cloned() else {
                    s.error = Some("Invalid share selection".into());
                    return Task::none();
                };

                let mut tiers = Vec::new();
                for tier_cfg in &s.tiers {
                    let threshold: u32 = match tier_cfg.threshold.parse() {
                        Ok(v) if v >= 1 && v <= share.total_shares as u32 => v,
                        _ => {
                            s.error = Some("Invalid threshold value".into());
                            return Task::none();
                        }
                    };
                    let timelock_months: u32 = match tier_cfg.timelock_months.parse() {
                        Ok(v) if v > 0 => v,
                        _ => {
                            s.error = Some("Invalid timelock value".into());
                            return Task::none();
                        }
                    };

                    let key_slots = (1..=share.total_shares)
                        .map(|i| KeySlot::Participant { share_index: i })
                        .collect();

                    tiers.push(PolicyTier {
                        threshold,
                        key_slots,
                        timelock_months,
                    });
                }

                let policy = WalletPolicy {
                    recovery_tiers: tiers,
                };

                s.error = None;
                (share, s.network.clone(), policy)
            }
            _ => return Task::none(),
        };

        if !matches!(self.frost_status, ConnectionStatus::Connected) {
            if let Screen::Wallet(wallet::State { setup: Some(s), .. }) = &mut self.screen {
                s.error = Some("Connect to relay first".into());
            }
            return Task::none();
        }

        let Some(node) = self.get_frost_node() else {
            if let Screen::Wallet(wallet::State { setup: Some(s), .. }) = &mut self.screen {
                s.error = Some("Relay node not available".into());
            }
            return Task::none();
        };

        let expected_total = keep_frost_net::participant_indices(&policy).len();

        if let Screen::Wallet(wallet::State { setup: Some(s), .. }) = &mut self.screen {
            s.phase = SetupPhase::Coordinating(DescriptorProgress::WaitingContributions {
                received: 1,
                expected: expected_total,
            });
        }

        let keep_arc = self.keep.clone();
        let net = network.clone();
        let group_pubkey = share.group_pubkey;

        Task::perform(
            async move {
                let (xpub_str, fingerprint_str) = crate::frost::derive_xpub(
                    keep_arc,
                    share.group_pubkey,
                    share.identifier,
                    net.clone(),
                )
                .await?;

                let session_id = node
                    .request_descriptor(policy, &net, &xpub_str, &fingerprint_str)
                    .await
                    .map_err(|e| format!("{e}"))?;

                Ok::<([u8; 32], [u8; 32], String, usize), String>((
                    session_id,
                    group_pubkey,
                    net,
                    expected_total,
                ))
            },
            Message::WalletSessionStarted,
        )
    }
}
