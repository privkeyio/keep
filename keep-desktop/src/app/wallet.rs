use iced::Task;

use crate::message::Message;
use crate::screen::wallet::{self, DescriptorProgress, SetupPhase};
use crate::screen::Screen;

use super::{App, ToastKind, MAX_ACTIVE_COORDINATIONS};

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
        }
    }

    pub(crate) fn handle_wallet_global_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::WalletsLoaded(result) => {
                match result {
                    Ok(wallets) => {
                        let mut ws = wallet::State::new(wallets);
                        ws.peer_xpubs = self.peer_xpubs.clone();
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
            _ => Task::none(),
        }
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
