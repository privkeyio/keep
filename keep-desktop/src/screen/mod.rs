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
    pub fn view(
        &self,
        pending_requests: usize,
        kill_switch_active: bool,
    ) -> iced::Element<Message> {
        match self {
            Screen::Unlock(s) => s.view(),
            Screen::ShareList(s) => s.view(pending_requests, kill_switch_active),
            Screen::Create(s) => s.view(pending_requests, kill_switch_active),
            Screen::Export(s) => s.view(pending_requests, kill_switch_active),
            Screen::Import(s) => s.view(pending_requests, kill_switch_active),
            Screen::Wallet(s) => s.view(pending_requests, kill_switch_active),
            Screen::Relay(s) => s.view(kill_switch_active),
            Screen::Bunker(s) => s.view(kill_switch_active),
            Screen::SigningAudit(s) => s.view(pending_requests, kill_switch_active),
            Screen::Settings(s) => s.view(pending_requests),
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
