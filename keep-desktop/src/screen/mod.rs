// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod bunker;
pub mod create;
pub mod export;
pub mod import;
pub mod layout;
pub mod relay;
pub mod settings;
pub mod shares;
pub mod signing_audit;
pub mod unlock;
pub mod wallet;

use crate::message::Message;

pub enum Screen {
    Unlock(unlock::UnlockScreen),
    ShareList(shares::ShareListScreen),
    Create(create::CreateScreen),
    Export(Box<export::ExportScreen>),
    Import(import::ImportScreen),
    Wallet(wallet::WalletScreen),
    Relay(relay::RelayScreen),
    Bunker(Box<bunker::BunkerScreen>),
    SigningAudit(signing_audit::SigningAuditScreen),
    Settings(settings::SettingsScreen),
}

impl Screen {
    pub fn view(&self, pending_requests: usize) -> iced::Element<Message> {
        match self {
            Screen::Unlock(s) => s.view(),
            Screen::ShareList(s) => s.view(pending_requests),
            Screen::Create(s) => s.view(pending_requests),
            Screen::Export(s) => s.view(pending_requests),
            Screen::Import(s) => s.view(pending_requests),
            Screen::Wallet(s) => s.view(pending_requests),
            Screen::Relay(s) => s.view(),
            Screen::Bunker(s) => s.view(),
            Screen::SigningAudit(s) => s.view(pending_requests),
            Screen::Settings(s) => s.view(),
        }
    }

    pub fn set_loading_error(&mut self, error: String) {
        match self {
            Screen::Unlock(s) => {
                s.loading = false;
                s.error = Some(error);
            }
            Screen::Create(s) => {
                s.loading = false;
                s.error = Some(error);
            }
            Screen::Export(s) => {
                s.loading = false;
                s.error = Some(error);
            }
            Screen::Import(s) => {
                s.loading = false;
                s.error = Some(error);
            }
            Screen::Bunker(s) => {
                s.starting = false;
                s.error = Some(error);
            }
            Screen::ShareList(_)
            | Screen::Wallet(_)
            | Screen::Relay(_)
            | Screen::SigningAudit(_)
            | Screen::Settings(_) => {}
        }
    }
}
