use std::time::{Duration, Instant};

use iced::Task;
use keep_core::frost::ShareExport;
use rand::RngExt as _;
use tracing::error;
use zeroize::{Zeroize, Zeroizing};

use crate::message::{ExportData, Message, ShareIdentity};
use crate::screen::shares::ShareEntry;
use crate::screen::{
    create, distribute, export, export_ncryptsec, import, nsec_keys, recovery, scanner, shares,
    Screen,
};

use super::{
    collect_shares, friendly_err, lock_keep, with_keep_blocking, App, ToastKind, IMPORT_COOLDOWN,
    TOAST_DURATION_SECS,
};

impl App {
    pub(crate) fn handle_share_list_message(&mut self, msg: shares::Message) -> Task<Message> {
        let Screen::ShareList(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            shares::Event::GoToExport(i) => self.handle_navigation_message(Message::GoToExport(i)),
            shares::Event::GoToCreate => self.handle_navigation_message(Message::GoToCreate),
            shares::Event::GoToImport => self.handle_navigation_message(Message::GoToImport),
            shares::Event::ActivateShare(hex) => {
                self.handle_identity_message(Message::SwitchIdentity(hex))
            }
            shares::Event::GoToRecover {
                threshold,
                total_shares,
                group_display,
                group_pubkey,
                identifier,
            } => {
                self.screen = Screen::Recovery(recovery::State::new(
                    threshold,
                    total_shares,
                    group_display,
                    group_pubkey,
                ));
                let keep_arc = self.keep.clone();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let mut passphrase_bytes = [0u8; 32];
                            rand::rng().fill(&mut passphrase_bytes[..]);
                            let passphrase = Zeroizing::new(hex::encode(passphrase_bytes));
                            passphrase_bytes.zeroize();
                            with_keep_blocking(
                                &keep_arc,
                                "Failed to export vault share",
                                move |keep| {
                                    let export = keep
                                        .frost_export_share(&group_pubkey, identifier, &passphrase)
                                        .map_err(|e| e.to_string())?;
                                    let bech32 = export
                                        .to_bech32()
                                        .map(Zeroizing::new)
                                        .map_err(|e| e.to_string())?;
                                    Ok((bech32, passphrase))
                                },
                            )
                        })
                        .await
                        .map_err(|_| "Background task failed".to_string())?
                    },
                    Message::VaultShareExported,
                )
            }
            shares::Event::CopyNpub(npub) => self.handle_copy_npub(npub),
            shares::Event::ConfirmDelete(id) => {
                self.handle_delete(id);
                Task::none()
            }
        }
    }

    pub(crate) fn handle_create_message(&mut self, msg: create::Message) -> Task<Message> {
        let Screen::Create(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            create::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            create::Event::Create {
                name,
                threshold,
                total,
                nsec,
            } => self.handle_create_keyset_validated(name, threshold, total, nsec),
        }
    }

    pub(crate) fn handle_create_result(
        &mut self,
        result: Result<Vec<ShareEntry>, String>,
    ) -> Task<Message> {
        match result {
            Ok(shares) => {
                let all_shares = self.current_shares();
                self.cached_share_count = all_shares.len();
                self.refresh_identities(&all_shares);
                self.screen = Screen::Distribute(distribute::State::new(shares));
                Task::none()
            }
            Err(e) => {
                self.screen.set_loading_error(e);
                Task::none()
            }
        }
    }

    pub(crate) fn handle_distribute_message(&mut self, msg: distribute::Message) -> Task<Message> {
        let Screen::Distribute(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            distribute::Event::ExportQr(share) => {
                let identifier = share.identifier;
                if let Screen::Distribute(state) = std::mem::replace(
                    &mut self.screen,
                    Screen::ShareList(shares::State::new(vec![], None)),
                ) {
                    self.distribute_state = Some(state);
                }
                self.distribute_export_id = Some(identifier);
                self.screen = Screen::Export(Box::new(export::State::new(share)));
                Task::none()
            }
            distribute::Event::Finish => {
                self.distribute_state = None;
                self.distribute_export_id = None;
                self.set_share_screen(self.current_shares());
                self.set_toast("Keyset created!".into(), ToastKind::Success);
                Task::none()
            }
        }
    }

    pub(crate) fn handle_export_message(&mut self, msg: export::Message) -> Task<Message> {
        let Screen::Export(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            export::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            export::Event::Generate { share, passphrase } => {
                self.handle_generate_export_validated(share, passphrase)
            }
            export::Event::CopyToClipboard(t) => self.handle_copy_sensitive(t),
            export::Event::Reset => {
                self.copy_feedback_until = None;
                if let Screen::Export(s) = &mut self.screen {
                    s.reset();
                }
                Task::none()
            }
        }
    }

    pub(crate) fn handle_import_message(&mut self, msg: import::Message) -> Task<Message> {
        let Screen::Import(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            import::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            import::Event::ScannerOpen => {
                self.stop_scanner();
                self.open_scanner();
                Task::none()
            }
            import::Event::ImportShare {
                data,
                passphrase,
                name,
            } => self.handle_import_share(data, passphrase, name),
            import::Event::ImportNsec { data, name } => self.handle_import_nsec(data, name),
            import::Event::ImportNcryptsec {
                data,
                password,
                name,
            } => self.handle_import_ncryptsec(data, password, name),
        }
    }

    pub(crate) fn handle_recovery_message(&mut self, msg: recovery::Message) -> Task<Message> {
        let Screen::Recovery(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            recovery::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            recovery::Event::ScanShare(slot) => {
                if let Screen::Recovery(state) = std::mem::replace(
                    &mut self.screen,
                    Screen::ShareList(shares::State::new(vec![], None)),
                ) {
                    self.scanner_recovery = Some((state, slot));
                }
                self.stop_scanner();
                self.open_scanner();
                Task::none()
            }
            recovery::Event::Recover {
                share_data,
                passphrases,
                expected_group_pubkey,
            } => self.handle_recover_nsec(share_data, passphrases, expected_group_pubkey),
            recovery::Event::CopyToClipboard(text) => self.handle_copy_sensitive(text),
        }
    }

    pub(crate) fn handle_recover_nsec(
        &mut self,
        share_data: Vec<Zeroizing<String>>,
        passphrases: Vec<Zeroizing<String>>,
        expected_group_pubkey: [u8; 32],
    ) -> Task<Message> {
        const RECOVERY_COOLDOWN: Duration = Duration::from_secs(5);
        if self
            .last_recovery_attempt
            .is_some_and(|t| t.elapsed() < RECOVERY_COOLDOWN)
        {
            if let Screen::Recovery(s) = &mut self.screen {
                s.recovery_failed("Please wait before trying again".to_string());
            }
            return Task::none();
        }
        self.last_recovery_attempt = Some(Instant::now());
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    keep_core::frost::recover_nsec(
                        &share_data,
                        &passphrases,
                        Some(&expected_group_pubkey),
                    )
                    .map_err(|e| e.to_string())
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::RecoveryResult,
        )
    }

    pub(crate) fn handle_recovery_result(
        &mut self,
        result: Result<Zeroizing<String>, String>,
    ) -> Task<Message> {
        let s = match &mut self.screen {
            Screen::Recovery(s) => s,
            _ => {
                if let Some((ref mut state, _)) = self.scanner_recovery {
                    state
                } else {
                    return Task::none();
                }
            }
        };
        match result {
            Ok(nsec) => s.recovery_succeeded(nsec),
            Err(e) => s.recovery_failed(e),
        }
        Task::none()
    }

    pub(crate) fn handle_vault_share_exported(
        &mut self,
        result: Result<(Zeroizing<String>, Zeroizing<String>), String>,
    ) -> Task<Message> {
        let Screen::Recovery(s) = &mut self.screen else {
            self.pending_vault_share = Some(result);
            return Task::none();
        };
        match result {
            Ok((bech32, passphrase)) => s.set_vault_share(bech32, passphrase),
            Err(e) => {
                error!("Vault share auto-export failed: {e}");
                s.recovery_failed("Could not auto-export vault share; add it manually".to_string());
            }
        }
        Task::none()
    }

    pub(crate) fn consume_pending_vault_share(&mut self) {
        if let Some(result) = self.pending_vault_share.take() {
            if let Screen::Recovery(s) = &mut self.screen {
                match result {
                    Ok((bech32, passphrase)) => s.set_vault_share(bech32, passphrase),
                    Err(e) => {
                        error!("Vault share auto-export failed: {e}");
                        s.recovery_failed(
                            "Could not auto-export vault share; add it manually".to_string(),
                        );
                    }
                }
            }
        }
    }

    pub(crate) fn handle_scanner_message(&mut self, msg: scanner::Message) -> Task<Message> {
        let Screen::Scanner(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            scanner::Event::Close => {
                self.stop_scanner();
                if let Some((state, _)) = self.scanner_recovery.take() {
                    self.screen = Screen::Recovery(state);
                    self.consume_pending_vault_share();
                } else {
                    self.scanner_recovery = None;
                    self.pending_vault_share = None;
                    self.screen = Screen::Import(import::State::new(self.build_import_summaries()));
                }
                Task::none()
            }
            scanner::Event::Retry => {
                self.stop_scanner();
                self.open_scanner();
                Task::none()
            }
        }
    }

    pub(crate) fn open_scanner(&mut self) {
        use crate::screen::scanner::{self, ScannerScreen};

        let scanner = ScannerScreen::new();
        let active = scanner.camera_active.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(3);
        scanner::start_camera(active, tx);
        self.scanner_rx = Some(rx);
        self.screen = Screen::Scanner(scanner);
    }

    pub(crate) fn stop_scanner(&mut self) {
        if let Screen::Scanner(s) = &self.screen {
            s.stop_camera();
        }
        self.scanner_rx = None;
    }

    pub(crate) fn drain_scanner_events(&mut self) {
        use crate::screen::scanner::CameraEvent;

        let rx = match &mut self.scanner_rx {
            Some(rx) => rx,
            None => return,
        };

        let mut last_frame: Option<CameraEvent> = None;
        let mut events: Vec<CameraEvent> = Vec::new();

        while let Ok(event) = rx.try_recv() {
            match &event {
                CameraEvent::Frame { .. } => last_frame = Some(event),
                _ => events.push(event),
            }
        }

        for event in events {
            self.apply_scanner_event(event);
        }
        if let Some(frame) = last_frame {
            self.apply_scanner_event(frame);
        }
    }

    pub(crate) fn apply_scanner_event(&mut self, event: crate::screen::scanner::CameraEvent) {
        use crate::screen::scanner::{CameraEvent, ScannerStatus};

        if let Screen::Scanner(s) = &mut self.screen {
            match event {
                CameraEvent::Ready => {
                    s.status = ScannerStatus::Scanning;
                }
                CameraEvent::Frame {
                    rgba,
                    width,
                    height,
                    decoded,
                } => {
                    s.frame_handle =
                        Some(iced::widget::image::Handle::from_rgba(width, height, rgba));

                    if let Some(content) = decoded {
                        if let Some(result) = s.process_qr_content(&content) {
                            s.stop_camera();
                            self.scanner_rx = None;
                            if let Some((mut state, slot)) = self.scanner_recovery.take() {
                                state.set_share_input(slot, Zeroizing::new(result));
                                self.screen = Screen::Recovery(state);
                                self.consume_pending_vault_share();
                            } else {
                                let import =
                                    import::State::with_data(result, self.build_import_summaries());
                                self.screen = Screen::Import(import);
                            }
                        }
                    }
                }
                CameraEvent::Error(e) => {
                    s.status = ScannerStatus::Error(e);
                }
            }
        }
    }

    pub(crate) fn handle_shares_result(
        &mut self,
        result: Result<Vec<ShareEntry>, String>,
    ) -> Task<Message> {
        match result {
            Ok(shares) => {
                self.reconcile_kill_switch();
                self.set_share_screen(shares);
                self.load_config_from_vault();
                if let Some(request) = super::take_pending_nostrconnect() {
                    return self.process_pending_nostrconnect(request);
                }
                let mut tasks = Vec::new();
                if self.settings.bunker_auto_start && !self.settings.kill_switch_active {
                    tasks.push(self.handle_bunker_start());
                }
                #[cfg(unix)]
                if self.settings.local_signer_auto_start && !self.settings.kill_switch_active {
                    tasks.push(self.handle_local_signer_start());
                }
                if !tasks.is_empty() {
                    return Task::batch(tasks);
                }
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    pub(crate) fn handle_import_result(
        &mut self,
        result: Result<(Vec<ShareEntry>, String), String>,
    ) -> Task<Message> {
        match result {
            Ok((shares, name)) => {
                self.set_share_screen(shares);
                self.set_toast(
                    format!("'{name}' imported successfully"),
                    ToastKind::Success,
                );
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    pub(crate) fn handle_delete(&mut self, id: ShareIdentity) {
        let group_hex = hex::encode(id.group_pubkey);
        if self.active_share_hex.as_deref() == Some(group_hex.as_str()) {
            self.handle_disconnect_relay();
            self.stop_bunker();
        }
        let result = {
            let mut guard = lock_keep(&self.keep);
            match guard.as_mut() {
                Some(keep) => Ok(keep.frost_delete_share(&id.group_pubkey, id.identifier)),
                None => Err("Vault is locked".to_string()),
            }
        };
        let result = match result {
            Ok(inner) => inner.map_err(friendly_err),
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => self.refresh_shares(),
            Err(e) => {
                if let Screen::ShareList(s) = &mut self.screen {
                    s.clear_delete_confirm();
                }
                self.set_toast(e, ToastKind::Error);
            }
        }
    }

    pub(crate) fn handle_create_keyset_validated(
        &mut self,
        name: String,
        threshold: u16,
        total: u16,
        nsec: Option<Zeroizing<String>>,
    ) -> Task<Message> {
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(
                        &keep_arc,
                        "Internal error during keyset creation",
                        move |keep| {
                            if let Some(nsec) = nsec {
                                let pubkey =
                                    keep.import_nsec(nsec.trim(), &name).map_err(friendly_err)?;
                                if let Err(e) = keep.frost_split(&name, threshold, total) {
                                    let split_err = friendly_err(e);
                                    if let Err(del_err) = keep.delete_key(&pubkey) {
                                        return Err(format!(
                                            "{split_err} (rollback also failed: {})",
                                            friendly_err(del_err)
                                        ));
                                    }
                                    return Err(split_err);
                                }
                            } else {
                                keep.frost_generate(threshold, total, &name)
                                    .map_err(friendly_err)?;
                            }
                            collect_shares(keep).map(|shares| {
                                shares.into_iter().filter(|s| s.name == name).collect()
                            })
                        },
                    )
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::CreateResult,
        )
    }

    pub(crate) fn handle_copy_npub(&self, npub: String) -> Task<Message> {
        iced::clipboard::write(npub)
    }

    pub(crate) fn handle_generate_export_validated(
        &mut self,
        share: ShareEntry,
        passphrase: Zeroizing<String>,
    ) -> Task<Message> {
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during export", move |keep| {
                        let export = keep
                            .frost_export_share(&share.group_pubkey, share.identifier, &passphrase)
                            .map_err(friendly_err)?;
                        let bech32 = export
                            .to_bech32()
                            .map(Zeroizing::new)
                            .map_err(friendly_err)?;
                        let frames: Vec<Zeroizing<String>> = export
                            .to_animated_frames(600)
                            .map_err(friendly_err)?
                            .into_iter()
                            .map(Zeroizing::new)
                            .collect();
                        Ok(ExportData { bech32, frames })
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::ExportGenerated,
        )
    }

    pub(crate) fn handle_copy_sensitive(&mut self, data: Zeroizing<String>) -> Task<Message> {
        self.start_clipboard_timer();
        self.copy_feedback_until = Some(Instant::now() + Duration::from_secs(TOAST_DURATION_SECS));
        match &mut self.screen {
            Screen::Export(s) => s.copied = true,
            Screen::ExportNcryptsec(s) => s.copied = true,
            _ => {}
        }
        iced::clipboard::write((*data).clone())
    }

    pub(crate) fn handle_export_generated(
        &mut self,
        result: Result<ExportData, String>,
    ) -> Task<Message> {
        match result {
            Ok(data) => {
                if let Some(id) = self.distribute_export_id.take() {
                    if let Some(state) = &mut self.distribute_state {
                        state.mark_exported(id);
                    }
                }
                if let Screen::Export(s) = &mut self.screen {
                    s.set_export(data.bech32, data.frames);
                }
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    pub(crate) fn check_import_cooldown(&mut self) -> bool {
        if self
            .last_import_attempt
            .is_some_and(|t| t.elapsed() < IMPORT_COOLDOWN)
        {
            self.screen
                .set_loading_error("Please wait before trying again".to_string());
            return false;
        }
        self.last_import_attempt = Some(Instant::now());
        true
    }

    pub(crate) fn handle_import_share(
        &mut self,
        data: Zeroizing<String>,
        passphrase: Zeroizing<String>,
        name: String,
    ) -> Task<Message> {
        if !self.check_import_cooldown() {
            return Task::none();
        }
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during import", move |keep| {
                        let export = ShareExport::parse(&data).map_err(friendly_err)?;
                        keep.frost_import_share(&export, &passphrase, &name)
                            .map_err(friendly_err)?;
                        let shares = collect_shares(keep)?;
                        Ok((shares, name))
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::ImportResult,
        )
    }

    pub(crate) fn handle_import_nsec(
        &mut self,
        data: Zeroizing<String>,
        name: String,
    ) -> Task<Message> {
        if !self.check_import_cooldown() {
            return Task::none();
        }
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during import", move |keep| {
                        keep.import_nsec(data.trim(), &name).map_err(friendly_err)?;
                        let shares = collect_shares(keep)?;
                        Ok((shares, name))
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::ImportNsecResult,
        )
    }

    pub(crate) fn handle_import_nsec_result(
        &mut self,
        result: Result<(Vec<ShareEntry>, String), String>,
    ) -> Task<Message> {
        match result {
            Ok((shares, name)) => {
                self.cached_share_count = shares.len();
                self.refresh_identities(&shares);
                self.set_nsec_keys_screen();
                self.set_toast(
                    format!("'{name}' imported successfully"),
                    ToastKind::Success,
                );
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    pub(crate) fn handle_import_ncryptsec(
        &mut self,
        data: Zeroizing<String>,
        password: Zeroizing<String>,
        name: String,
    ) -> Task<Message> {
        if !self.check_import_cooldown() {
            return Task::none();
        }
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during import", move |keep| {
                        let mut secret = keep_core::keys::nip49::decrypt(data.trim(), &password)
                            .map_err(friendly_err)?;
                        keep.import_secret_bytes(&mut secret, &name)
                            .map_err(friendly_err)?;
                        let shares = collect_shares(keep)?;
                        Ok((shares, name))
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::ImportNcryptsecResult,
        )
    }

    pub(crate) fn handle_go_to_export_ncryptsec(&mut self, pubkey_hex: String) -> Task<Message> {
        let identity = self.identities.iter().find(|i| i.pubkey_hex == pubkey_hex);
        if let Some(id) = identity {
            self.screen = Screen::ExportNcryptsec(Box::new(export_ncryptsec::State::new(
                id.pubkey_hex.clone(),
                id.name.clone(),
                id.npub.clone(),
            )));
        }
        Task::none()
    }

    pub(crate) fn handle_ncryptsec_export_message(
        &mut self,
        msg: export_ncryptsec::Message,
    ) -> Task<Message> {
        let Screen::ExportNcryptsec(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            export_ncryptsec::Event::GoBack => self.handle_navigation_message(Message::GoBack),
            export_ncryptsec::Event::Generate {
                pubkey_hex,
                password,
            } => self.handle_generate_ncryptsec(pubkey_hex, password),
            export_ncryptsec::Event::CopyToClipboard(t) => self.handle_copy_sensitive(t),
            export_ncryptsec::Event::Reset => {
                self.copy_feedback_until = None;
                if let Screen::ExportNcryptsec(s) = &mut self.screen {
                    s.reset();
                }
                Task::none()
            }
        }
    }

    pub(crate) fn handle_generate_ncryptsec(
        &mut self,
        pubkey_hex: String,
        password: Zeroizing<String>,
    ) -> Task<Message> {
        let Some(pubkey_bytes) = hex::decode(&pubkey_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            self.screen.set_loading_error("Invalid public key".into());
            return Task::none();
        };

        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Internal error during export", move |keep| {
                        let ncryptsec = keep
                            .export_ncryptsec(&pubkey_bytes, &password)
                            .map_err(friendly_err)?;
                        Ok(ExportData {
                            bech32: Zeroizing::new(ncryptsec),
                            frames: Vec::new(),
                        })
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::NcryptsecGenerated,
        )
    }

    pub(crate) fn handle_ncryptsec_generated(
        &mut self,
        result: Result<ExportData, String>,
    ) -> Task<Message> {
        match result {
            Ok(data) => {
                if let Screen::ExportNcryptsec(s) = &mut self.screen {
                    s.set_result(data.bech32);
                }
            }
            Err(e) => self.screen.set_loading_error(e),
        }
        Task::none()
    }

    pub(crate) fn handle_nsec_keys_message(&mut self, msg: nsec_keys::Message) -> Task<Message> {
        let Screen::NsecKeys(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            nsec_keys::Event::GoToImport => self.handle_navigation_message(Message::GoToImport),
            nsec_keys::Event::ActivateKey(hex) => {
                self.handle_identity_message(Message::SwitchIdentity(hex))
            }
            nsec_keys::Event::ExportNcryptsec(hex) => self.handle_go_to_export_ncryptsec(hex),
            nsec_keys::Event::CopyNpub(npub) => self.handle_copy_npub(npub),
            nsec_keys::Event::ConfirmDelete(hex) => self.handle_nsec_key_delete(hex),
        }
    }

    pub(crate) fn handle_nsec_key_delete(&mut self, hex: String) -> Task<Message> {
        let Screen::NsecKeys(s) = &self.screen else {
            return Task::none();
        };
        let Some(key) = s.keys().iter().find(|k| k.pubkey_hex == hex) else {
            return Task::none();
        };
        let (pubkey, name) = (key.pubkey, key.name.clone());
        if self.active_share_hex.as_deref() == Some(hex.as_str()) {
            self.handle_disconnect_relay();
            self.stop_bunker();
        }
        let delete_result = {
            let mut guard = lock_keep(&self.keep);
            guard.as_mut().map(|keep| keep.delete_key(&pubkey))
        };
        match delete_result {
            Some(Ok(())) => {
                {
                    let guard = lock_keep(&self.keep);
                    if let Some(keep) = guard.as_ref() {
                        let _ = keep.delete_relay_config(&pubkey);
                    }
                }
                self.refresh_shares();
                self.set_toast(format!("'{name}' deleted"), ToastKind::Success);
            }
            Some(Err(e)) => {
                if let Screen::NsecKeys(s) = &mut self.screen {
                    s.clear_delete_confirm();
                }
                self.set_toast(friendly_err(e), ToastKind::Error);
            }
            None => {
                if let Screen::NsecKeys(s) = &mut self.screen {
                    s.clear_delete_confirm();
                }
                self.set_toast("Vault locked or unavailable".into(), ToastKind::Error);
            }
        }
        Task::none()
    }
}
