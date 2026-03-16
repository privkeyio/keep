use iced::Task;

use crate::message::Message;
use crate::screen::settings::SettingsScreen;
use crate::screen::Screen;
use crate::screen::{create, import, relay};

use super::{lock_keep, App};

impl App {
    pub(crate) fn handle_navigation_message(&mut self, message: Message) -> Task<Message> {
        if !matches!(message, Message::GoBack | Message::GoToExport(..)) {
            self.distribute_state = None;
            self.distribute_export_id = None;
        }
        self.stop_scanner();
        self.copy_feedback_until = None;
        match message {
            Message::GoToCreate => {
                let existing_names: Vec<String> = self
                    .current_shares()
                    .iter()
                    .map(|s| s.name.clone())
                    .collect();
                self.screen = Screen::Create(create::State::new(existing_names));
                Task::none()
            }
            Message::GoToImport => {
                self.import_return_to_nsec = matches!(self.screen, Screen::NsecKeys(_));
                self.screen = Screen::Import(import::State::new(self.build_import_summaries()));
                Task::none()
            }
            Message::GoToExport(index) => {
                let shares = self.current_shares();
                if let Some(share) = shares.get(index).cloned() {
                    self.screen =
                        Screen::Export(Box::new(crate::screen::export::State::new(share)));
                }
                Task::none()
            }
            Message::NavigateShares => {
                if matches!(self.screen, Screen::ShareList(_)) {
                    return Task::none();
                }
                self.set_share_screen(self.current_shares());
                Task::none()
            }
            Message::GoBack => {
                if let Some(dist_state) = self.distribute_state.take() {
                    self.distribute_export_id = None;
                    self.screen = Screen::Distribute(dist_state);
                    return Task::none();
                }
                let return_to_nsec = matches!(self.screen, Screen::ExportNcryptsec(_))
                    || (matches!(self.screen, Screen::Import(_)) && self.import_return_to_nsec);
                if return_to_nsec {
                    self.import_return_to_nsec = false;
                    self.set_nsec_keys_screen();
                } else {
                    self.set_share_screen(self.current_shares());
                }
                Task::none()
            }
            Message::NavigateNsecKeys => {
                if matches!(self.screen, Screen::NsecKeys(_)) {
                    return Task::none();
                }
                self.set_nsec_keys_screen();
                Task::none()
            }
            Message::NavigateWallets => {
                if matches!(self.screen, Screen::Wallet(_)) {
                    return Task::none();
                }
                let keep_arc = self.keep.clone();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let guard = lock_keep(&keep_arc);
                            let Some(keep) = guard.as_ref() else {
                                return Err("Keep not available".to_string());
                            };
                            keep.list_wallet_descriptors()
                                .map(|ds| {
                                    ds.iter()
                                        .map(crate::screen::wallet::WalletEntry::from_descriptor)
                                        .collect()
                                })
                                .map_err(super::friendly_err)
                        })
                        .await
                        .map_err(|_| "Background task failed".to_string())?
                    },
                    Message::WalletsLoaded,
                )
            }
            Message::NavigateRelay => {
                if matches!(self.screen, Screen::Relay(_)) {
                    return Task::none();
                }
                self.screen = Screen::Relay(relay::State::new(
                    self.current_shares(),
                    self.relay_urls.clone(),
                    self.frost_status.clone(),
                    self.frost_peers.clone(),
                    self.pending_sign_display.clone(),
                    self.frost_event_log.clone(),
                ));
                Task::none()
            }
            Message::NavigateBunker => {
                if matches!(self.screen, Screen::Bunker(_)) {
                    return Task::none();
                }
                self.screen = Screen::Bunker(Box::new(self.create_bunker_screen()));
                Task::none()
            }
            #[cfg(unix)]
            Message::NavigateLocalSigner => {
                if matches!(self.screen, Screen::LocalSigner(_)) {
                    return Task::none();
                }
                self.screen = Screen::LocalSigner(self.create_local_signer_screen());
                Task::none()
            }
            Message::NavigateSettings => {
                if matches!(self.screen, Screen::Settings(_)) {
                    return Task::none();
                }
                self.screen = Screen::Settings(SettingsScreen::new(
                    self.settings.auto_lock_secs,
                    self.settings.clipboard_clear_secs,
                    self.keep_path.display().to_string(),
                    self.proxy_enabled,
                    self.proxy_port,
                    self.settings.kill_switch_active,
                    self.settings.minimize_to_tray,
                    self.settings.start_minimized,
                    self.has_tray,
                    self.cert_pin_display_entries(),
                ));
                Task::none()
            }
            Message::Lock => self.do_lock(),
            _ => Task::none(),
        }
    }

    pub(crate) fn handle_window_close(&mut self, id: iced::window::Id) -> Task<Message> {
        if self.settings.minimize_to_tray && self.has_tray {
            self.window_visible = false;
            iced::window::set_mode(id, iced::window::Mode::Hidden)
        } else {
            self.handle_disconnect_relay();
            self.stop_bunker();
            #[cfg(unix)]
            self.stop_local_signer();
            iced::exit()
        }
    }

    pub(crate) fn handle_tray_show(&mut self) -> Task<Message> {
        if self.window_visible {
            return iced::window::oldest().and_then(iced::window::gain_focus);
        }
        self.window_visible = true;
        iced::window::oldest().and_then(|id| {
            Task::batch([
                iced::window::set_mode(id, iced::window::Mode::Windowed),
                iced::window::gain_focus(id),
            ])
        })
    }

    pub(crate) fn handle_tray_toggle_bunker(&mut self) -> Task<Message> {
        if self.bunker.is_some() {
            self.handle_bunker_stop()
        } else if lock_keep(&self.keep).is_none() {
            self.set_toast("Vault is locked".into(), super::ToastKind::Error);
            self.handle_tray_show()
        } else {
            self.handle_bunker_start()
        }
    }

    pub(crate) fn handle_tray_quit(&mut self) -> Task<Message> {
        self.handle_disconnect_relay();
        self.stop_bunker();
        #[cfg(unix)]
        self.stop_local_signer();
        iced::exit()
    }

    pub(crate) fn sync_tray_status(&mut self) {
        let Some(ref tray) = self.tray else {
            return;
        };
        let connected = matches!(
            self.frost_status,
            crate::message::ConnectionStatus::Connected
        );
        if connected != self.tray_last_connected {
            tray.update_status(connected);
            self.tray_last_connected = connected;
        }
        let bunker_running = self.bunker.is_some();
        if bunker_running != self.tray_last_bunker {
            tray.update_bunker_label(bunker_running);
            self.tray_last_bunker = bunker_running;
        }
    }

    pub(crate) fn poll_tray_events(&self) -> Vec<crate::tray::TrayEvent> {
        self.tray
            .as_ref()
            .map(|tray| tray.event_rx.try_iter().collect())
            .unwrap_or_default()
    }

    pub(crate) fn notify_sign_request(&self, _req: &crate::message::PendingSignRequest) {
        if !self.window_visible {
            let tx = self.tray.as_ref().map(|t| &t.event_tx);
            crate::tray::send_sign_request_notification(tx);
        }
    }

    pub(crate) fn notify_bunker_approval(
        &self,
        display: &crate::screen::bunker::PendingApprovalDisplay,
    ) {
        if !self.window_visible {
            let tx = self.tray.as_ref().map(|t| &t.event_tx);
            crate::tray::send_approval_notification(&display.app_name, &display.method, tx);
        }
    }
}
