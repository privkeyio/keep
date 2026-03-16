use std::sync::{Arc, Mutex};

use iced::Task;
use keep_core::Keep;

use crate::message::{AuditLoadResult, Message};
use crate::screen::signing_audit::{ChainStatus, SigningAuditScreen};
use crate::screen::Screen;

use super::{friendly_err, lock_keep, to_display_entry, App, ToastKind};

impl App {
    pub(crate) fn load_audit_page(
        keep_arc: Arc<Mutex<Option<Keep>>>,
        offset: usize,
        caller: Option<String>,
        on_done: fn(Result<AuditLoadResult, String>) -> Message,
    ) -> Task<Message> {
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let guard = lock_keep(&keep_arc);
                    let keep = guard
                        .as_ref()
                        .ok_or_else(|| "Vault is locked".to_string())?;
                    let page_size = SigningAuditScreen::page_size();
                    let (entries, callers, count) = keep
                        .signing_audit_read_page_with_metadata(offset, page_size, caller.as_deref())
                        .map_err(friendly_err)?;
                    let has_more = entries.len() == page_size;
                    let display = entries.into_iter().map(to_display_entry).collect();
                    Ok(AuditLoadResult {
                        entries: display,
                        callers,
                        count,
                        has_more,
                    })
                })
                .await
                .map_err(|_| "Background task failed".to_string())?
            },
            on_done,
        )
    }

    pub(crate) fn handle_signing_audit_message(
        &mut self,
        msg: crate::screen::signing_audit::Message,
    ) -> Task<Message> {
        let Screen::SigningAudit(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        match event {
            crate::screen::signing_audit::Event::FilterChanged(caller) => {
                if let Screen::SigningAudit(s) = &mut self.screen {
                    s.selected_caller = caller.clone();
                    s.entries.clear();
                    s.loading = true;
                    s.has_more = false;
                }
                Self::load_audit_page(self.keep.clone(), 0, caller, Message::AuditLoaded)
            }
            crate::screen::signing_audit::Event::LoadMore => {
                let (offset, caller) = match &mut self.screen {
                    Screen::SigningAudit(s) => {
                        if s.loading || !s.has_more {
                            return Task::none();
                        }
                        s.loading = true;
                        (s.entries.len(), s.selected_caller.clone())
                    }
                    _ => return Task::none(),
                };
                Self::load_audit_page(self.keep.clone(), offset, caller, Message::AuditPageLoaded)
            }
        }
    }

    pub(crate) fn handle_audit_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::NavigateAudit => {
                if matches!(self.screen, Screen::SigningAudit(_)) {
                    return Task::none();
                }
                self.screen = Screen::SigningAudit(SigningAuditScreen::new());
                let load_task =
                    Self::load_audit_page(self.keep.clone(), 0, None, Message::AuditLoaded);
                let keep_arc = self.keep.clone();
                let verify_task = Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let guard = lock_keep(&keep_arc);
                            let keep = guard
                                .as_ref()
                                .ok_or_else(|| "Vault is locked".to_string())?;
                            keep.signing_audit_verify_chain().map_err(friendly_err)
                        })
                        .await
                        .map_err(|_| "Background task failed".to_string())?
                    },
                    Message::AuditChainVerified,
                );
                Task::batch([load_task, verify_task])
            }
            Message::AuditLoaded(result) => {
                match result {
                    Ok(data) => {
                        if let Screen::SigningAudit(s) = &mut self.screen {
                            s.entries = data.entries;
                            s.callers = data.callers;
                            s.entry_count = data.count;
                            s.has_more = data.has_more;
                            s.loading = false;
                            s.load_error = None;
                        }
                    }
                    Err(e) => {
                        if let Screen::SigningAudit(s) = &mut self.screen {
                            s.loading = false;
                            tracing::warn!("Audit log load failed: {e}");
                            s.load_error = Some(e);
                        }
                    }
                }
                Task::none()
            }
            Message::AuditChainVerified(result) => {
                if let Screen::SigningAudit(s) = &mut self.screen {
                    s.chain_status = match result {
                        Ok((true, count)) => {
                            s.entry_count = count;
                            ChainStatus::Valid(count)
                        }
                        Ok((false, _)) => ChainStatus::Invalid,
                        Err(e) => {
                            tracing::warn!("Chain verification failed: {e}");
                            ChainStatus::Error(e)
                        }
                    };
                }
                Task::none()
            }
            Message::AuditPageLoaded(result) => {
                match result {
                    Ok(data) => {
                        if let Screen::SigningAudit(s) = &mut self.screen {
                            s.entries.extend(data.entries);
                            s.has_more = data.has_more;
                            s.loading = false;
                        }
                    }
                    Err(e) => {
                        if let Screen::SigningAudit(s) = &mut self.screen {
                            s.loading = false;
                        }
                        self.set_toast(e, ToastKind::Error);
                    }
                }
                Task::none()
            }
            _ => Task::none(),
        }
    }
}
