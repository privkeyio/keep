use iced::Task;
use keep_core::backup::BackupInfo;
use zeroize::Zeroizing;

use crate::message::Message;
use crate::screen::Screen;

use super::{friendly_err, with_keep_blocking, write_private_bytes, App, ToastKind};

impl App {
    pub(crate) fn handle_backup_export(&mut self, passphrase: Zeroizing<String>) -> Task<Message> {
        let keep_arc = self.keep.clone();
        Task::perform(
            async move {
                let dialog = rfd::AsyncFileDialog::new()
                    .set_file_name("keep-backup.kbak")
                    .set_title("Save Vault Backup");
                let Some(handle) = dialog.save_file().await else {
                    return Err("Cancelled".into());
                };
                let path = handle.path().to_path_buf();
                let filename = path
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "backup".into());
                let pass = passphrase.clone();
                let (backup_data, info) = tokio::task::spawn_blocking(move || {
                    with_keep_blocking(&keep_arc, "Backup failed", move |keep| {
                        let data = keep_core::backup::create_backup(keep, &passphrase)
                            .map_err(friendly_err)?;
                        let info =
                            keep_core::backup::verify_backup(&data, &pass).map_err(friendly_err)?;
                        Ok((data, info))
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())??;
                tokio::task::spawn_blocking(move || write_private_bytes(&path, &backup_data))
                    .await
                    .map_err(|_| "Background task failed".to_string())?
                    .map_err(|e| format!("Failed to write backup: {e}"))?;
                Ok((filename, info))
            },
            Message::BackupResult,
        )
    }

    pub(crate) fn handle_backup_result(
        &mut self,
        result: Result<(String, BackupInfo), String>,
    ) -> Task<Message> {
        match result {
            Ok((filename, info)) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.backup_completed(info);
                }
                self.set_toast(format!("Backup saved to {filename}"), ToastKind::Success);
            }
            Err(ref e) if e == "Cancelled" => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.backup_loading = false;
                }
            }
            Err(e) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.backup_failed(e.clone());
                }
                self.set_toast(e, ToastKind::Error);
            }
        }
        Task::none()
    }

    pub(crate) fn handle_restore_file_pick(&mut self) -> Task<Message> {
        Task::perform(
            async {
                let dialog = rfd::AsyncFileDialog::new()
                    .add_filter("Keep Backup", &["kbak"])
                    .set_title("Open Vault Backup");
                match dialog.pick_file().await {
                    Some(handle) => {
                        let meta = std::fs::metadata(handle.path())
                            .map_err(|e| format!("Failed to read file: {e}"))?;
                        if meta.len() > keep_core::backup::MAX_BACKUP_SIZE as u64 {
                            return Err(format!(
                                "Backup file too large ({} bytes, max {})",
                                meta.len(),
                                keep_core::backup::MAX_BACKUP_SIZE
                            ));
                        }
                        let name = handle.file_name();
                        let data = handle.read().await;
                        Ok((name, data))
                    }
                    None => Err("Cancelled".to_string()),
                }
            },
            |result: Result<(String, Vec<u8>), String>| match result {
                Ok((name, data)) => Message::RestoreFileLoaded(name, data),
                Err(_) => Message::Settings(crate::screen::settings::Message::RestoreCancel),
            },
        )
    }

    pub(crate) fn handle_restore_verify(
        &mut self,
        passphrase: Zeroizing<String>,
    ) -> Task<Message> {
        let Screen::Settings(s) = &self.screen else {
            return Task::none();
        };
        let Some((_, data)) = s.restore_file.as_ref() else {
            return Task::none();
        };
        let data = data.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    keep_core::backup::verify_backup(&data, &passphrase).map_err(friendly_err)
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::RestoreVerified,
        )
    }

    pub(crate) fn handle_restore_verified(
        &mut self,
        result: Result<BackupInfo, String>,
    ) -> Task<Message> {
        let Screen::Settings(s) = &mut self.screen else {
            return Task::none();
        };
        if !s.can_accept_restore_result() {
            return Task::none();
        }
        match result {
            Ok(info) => s.restore_verified(info),
            Err(e) => {
                let toast_msg = e.clone();
                s.restore_verify_failed(e);
                self.set_toast(toast_msg, ToastKind::Error);
            }
        }
        Task::none()
    }

    pub(crate) fn handle_restore_submit(
        &mut self,
        passphrase: Zeroizing<String>,
        vault_password: Zeroizing<String>,
    ) -> Task<Message> {
        let file_data = if let Screen::Settings(s) = &self.screen {
            s.restore_file.as_ref().map(|(_, data)| data.clone())
        } else {
            None
        };
        let Some(data) = file_data else {
            return Task::none();
        };
        let keep_path = self.keep_path.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                    let suffix: u32 = rand::random();
                    let restore_dir =
                        keep_path.with_file_name(format!("keep-restored-{ts}-{suffix:08x}"));
                    let info = keep_core::backup::restore_backup(
                        &data,
                        &passphrase,
                        &restore_dir,
                        &vault_password,
                    )
                    .map_err(friendly_err)?;
                    let summary = format!(
                        "Restored {} keys, {} shares, {} descriptors to {}",
                        info.key_count,
                        info.share_count,
                        info.descriptor_count,
                        restore_dir.display()
                    );
                    Ok((summary, info))
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            Message::RestoreResult,
        )
    }

    pub(crate) fn handle_restore_result(
        &mut self,
        result: Result<(String, BackupInfo), String>,
    ) -> Task<Message> {
        if let Screen::Settings(s) = &self.screen {
            if !s.can_accept_restore_result() {
                return Task::none();
            }
        } else {
            return Task::none();
        }
        match result {
            Ok((summary, info)) => {
                if let Screen::Settings(s) = &mut self.screen {
                    s.restore_completed(info);
                }
                self.set_toast(summary, ToastKind::Success);
            }
            Err(e) => {
                let toast_msg = e.clone();
                if let Screen::Settings(s) = &mut self.screen {
                    s.restore_failed(e);
                }
                self.set_toast(toast_msg, ToastKind::Error);
            }
        }
        Task::none()
    }
}
