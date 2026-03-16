use std::sync::atomic::Ordering;

use iced::Task;
use zeroize::Zeroizing;

use crate::message::{ConnectionStatus, Message};
use crate::screen::Screen;

use super::{friendly_err, lock_keep, save_cert_pins, save_settings, App, ToastKind};

impl App {
    pub(crate) fn handle_settings_message_new(
        &mut self,
        msg: crate::screen::settings::Message,
    ) -> Task<Message> {
        use crate::screen::settings::Event;
        let Screen::Settings(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            Event::AutoLockChanged(secs) => {
                self.settings.auto_lock_secs = secs;
                if let Screen::Settings(s) = &mut self.screen {
                    s.auto_lock_secs = secs;
                }
            }
            Event::ClipboardClearChanged(secs) => {
                self.settings.clipboard_clear_secs = secs;
                if secs == 0 {
                    self.clipboard_clear_at = None;
                }
                if let Screen::Settings(s) = &mut self.screen {
                    s.clipboard_clear_secs = secs;
                }
            }
            Event::ProxyToggled(enabled) => {
                self.proxy_enabled = enabled;
                let frost_active = matches!(
                    self.frost_status,
                    ConnectionStatus::Connected | ConnectionStatus::Connecting
                );
                let bunker_active = self.bunker.is_some();
                self.save_proxy_config();
                if let Screen::Settings(s) = &mut self.screen {
                    s.proxy_enabled = self.proxy_enabled;
                }
                let mut tasks = Vec::new();
                if frost_active {
                    tasks.push(self.handle_reconnect_relay());
                }
                if bunker_active {
                    self.stop_bunker();
                    tasks.push(self.handle_bunker_start());
                }
                if !tasks.is_empty() {
                    let label = if enabled { "enabled" } else { "disabled" };
                    self.set_toast(
                        format!("Proxy {label}, reconnecting..."),
                        ToastKind::Success,
                    );
                }
                save_settings(&self.keep_path, &self.settings);
                return Task::batch(tasks);
            }
            Event::ProxyPortChanged(port) => {
                self.proxy_port = port;
                self.save_proxy_config();
                if let Screen::Settings(s) = &mut self.screen {
                    s.sync_proxy_port(self.proxy_port);
                }
                if self.proxy_enabled {
                    let frost_active = matches!(
                        self.frost_status,
                        ConnectionStatus::Connected | ConnectionStatus::Connecting
                    );
                    let bunker_active = self.bunker.is_some();
                    let mut tasks = Vec::new();
                    if frost_active {
                        tasks.push(self.handle_reconnect_relay());
                    }
                    if bunker_active {
                        self.stop_bunker();
                        tasks.push(self.handle_bunker_start());
                    }
                    if !tasks.is_empty() {
                        self.set_toast(
                            format!("Proxy port changed to {port}, reconnecting..."),
                            ToastKind::Success,
                        );
                        return Task::batch(tasks);
                    }
                }
                return Task::none();
            }
            Event::MinimizeToTrayToggled(v) => {
                self.settings.minimize_to_tray = v;
                if let Screen::Settings(s) = &mut self.screen {
                    s.minimize_to_tray = v;
                }
                if !v && !self.window_visible {
                    self.window_visible = true;
                    save_settings(&self.keep_path, &self.settings);
                    return iced::window::oldest().and_then(|id| {
                        Task::batch([
                            iced::window::set_mode(id, iced::window::Mode::Windowed),
                            iced::window::gain_focus(id),
                        ])
                    });
                }
            }
            Event::StartMinimizedToggled(v) => {
                self.settings.start_minimized = v;
                if let Screen::Settings(s) = &mut self.screen {
                    s.start_minimized = v;
                }
            }
            Event::KillSwitchActivate => {
                return self.handle_kill_switch_activate();
            }
            Event::KillSwitchDeactivate(password) => {
                return self.handle_kill_switch_deactivate(password);
            }
            Event::CertPinClear(hostname) => {
                let ok = if let Ok(mut pins) = self.certificate_pins.lock() {
                    pins.remove_pin(&hostname);
                    save_cert_pins(&self.keep_path, &pins);
                    true
                } else {
                    false
                };
                if ok {
                    self.sync_cert_pins_to_screen();
                    self.set_toast(format!("Cleared pin for {hostname}"), ToastKind::Success);
                } else {
                    self.set_toast("Failed to clear pin".into(), ToastKind::Error);
                }
                return Task::none();
            }
            Event::BackupExport(passphrase) => {
                return self.handle_backup_export(passphrase);
            }
            Event::RestoreStart => {
                return self.handle_restore_file_pick();
            }
            Event::RestoreVerify(passphrase) => {
                return self.handle_restore_verify(passphrase);
            }
            Event::RestoreSubmit {
                passphrase,
                vault_password,
            } => {
                return self.handle_restore_submit(passphrase, vault_password);
            }
            Event::CertPinClearAll => {
                let ok = if let Ok(mut pins) = self.certificate_pins.lock() {
                    *pins = keep_frost_net::CertificatePinSet::new();
                    save_cert_pins(&self.keep_path, &pins);
                    true
                } else {
                    false
                };
                if ok {
                    self.sync_cert_pins_to_screen();
                    if let Screen::Settings(s) = &mut self.screen {
                        s.clear_all_pins_done();
                    }
                    self.set_toast("Cleared all certificate pins".into(), ToastKind::Success);
                } else {
                    self.set_toast("Failed to clear pins".into(), ToastKind::Error);
                }
                return Task::none();
            }
        }
        save_settings(&self.keep_path, &self.settings);
        Task::none()
    }

    pub(crate) fn sync_cert_pins_to_screen(&mut self) {
        let entries = self.cert_pin_display_entries();
        if let Screen::Settings(s) = &mut self.screen {
            s.certificate_pins = entries;
        }
    }

    pub(crate) fn handle_cert_pin_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::CertPinMismatchDismiss => {
                self.pin_mismatch = None;
                self.pin_mismatch_confirm = false;
            }
            Message::CertPinMismatchClearAndRetry => {
                self.pin_mismatch_confirm = true;
            }
            Message::CertPinMismatchConfirmClear => {
                self.pin_mismatch_confirm = false;
                let Some(mismatch) = self.pin_mismatch.as_ref() else {
                    return Task::none();
                };
                let ok = if let Ok(mut pins) = self.certificate_pins.lock() {
                    pins.remove_pin(&mismatch.hostname);
                    save_cert_pins(&self.keep_path, &pins);
                    true
                } else {
                    false
                };
                if !ok {
                    self.set_toast("Failed to clear pin".into(), ToastKind::Error);
                    return Task::none();
                }
                self.pin_mismatch = None;
                self.sync_cert_pins_to_screen();
                let mut tasks = Vec::new();
                if matches!(self.frost_status, ConnectionStatus::Error(_)) {
                    tasks.push(self.handle_reconnect_relay());
                }
                if self.bunker.is_none() && self.bunker_cert_pin_failed {
                    self.bunker_cert_pin_failed = false;
                    tasks.push(self.handle_bunker_start());
                }
                return Task::batch(tasks);
            }
            _ => {}
        }
        Task::none()
    }

    pub(crate) fn cert_pin_display_entries(&self) -> Vec<(String, String)> {
        let Ok(pins) = self.certificate_pins.lock() else {
            return Vec::new();
        };
        let mut entries: Vec<(String, String)> = pins
            .pins()
            .iter()
            .map(|(host, hash)| (host.clone(), hex::encode(hash)))
            .collect();
        entries.sort_unstable();
        entries
    }

    pub(crate) fn handle_kill_switch_activate(&mut self) -> Task<Message> {
        let result = {
            let mut guard = lock_keep(&self.keep);
            match guard.as_mut() {
                None => Err("Vault is locked".to_string()),
                Some(keep) => keep.set_kill_switch(true).map_err(friendly_err),
            }
        };
        if let Err(e) = result {
            self.set_toast(e, ToastKind::Error);
            return Task::none();
        }
        self.settings.kill_switch_active = true;
        save_settings(&self.keep_path, &self.settings);
        self.kill_switch.store(true, Ordering::Release);

        self.log_kill_switch_event(true);
        self.handle_disconnect_relay();
        self.stop_bunker();
        #[cfg(unix)]
        self.stop_local_signer();

        if let Screen::Settings(s) = &mut self.screen {
            s.kill_switch_activated();
        }
        self.set_toast(
            "Kill switch activated - all signing blocked".into(),
            ToastKind::Success,
        );
        Task::none()
    }

    pub(crate) fn handle_kill_switch_deactivate(
        &mut self,
        password: Zeroizing<String>,
    ) -> Task<Message> {
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let guard = lock_keep(&keep_arc);
                    match guard.as_ref() {
                        None => Err("Vault is locked".to_string()),
                        Some(keep) => keep.verify_password(&password).map_err(friendly_err),
                    }
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::KillSwitchDeactivateResult,
        )
    }

    pub(crate) fn handle_kill_switch_deactivate_result(
        &mut self,
        result: Result<(), String>,
    ) -> Task<Message> {
        match result {
            Ok(()) => {
                let result = {
                    let mut guard = lock_keep(&self.keep);
                    match guard.as_mut() {
                        None => Err("Vault is locked".to_string()),
                        Some(keep) => keep.set_kill_switch(false).map_err(friendly_err),
                    }
                };
                if let Err(e) = result {
                    if let Screen::Settings(s) = &mut self.screen {
                        s.kill_switch_deactivate_failed(e);
                    }
                    return Task::none();
                }
                self.kill_switch.store(false, Ordering::Release);
                self.settings.kill_switch_active = false;
                save_settings(&self.keep_path, &self.settings);
                self.log_kill_switch_event(false);
                if let Screen::Settings(s) = &mut self.screen {
                    s.kill_switch_deactivated();
                }
                self.set_toast(
                    "Kill switch deactivated - signing re-enabled".into(),
                    ToastKind::Success,
                );
            }
            Err(e) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.kill_switch_deactivate_failed(e);
                }
            }
        }
        Task::none()
    }

    pub(crate) fn log_kill_switch_event(&self, activated: bool) {
        use keep_core::audit::{SigningAuditEntry, SigningDecision, SigningRequestType};
        let (decision, reason) = if activated {
            (SigningDecision::Denied, "activated")
        } else {
            (SigningDecision::Approved, "deactivated")
        };
        let mut guard = lock_keep(&self.keep);
        if let Some(keep) = guard.as_mut() {
            let hash = keep.signing_audit_last_hash().unwrap_or([0u8; 32]);
            let entry = SigningAuditEntry::new(
                SigningRequestType::KillSwitch,
                decision,
                false,
                "desktop".into(),
                hash,
            )
            .with_reason(reason);
            if let Err(e) = keep.signing_audit_log(entry) {
                tracing::warn!("Failed to log kill switch event: {e}");
            }
        }
    }
}
