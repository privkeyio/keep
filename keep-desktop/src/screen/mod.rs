// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod create;
pub mod export;
pub mod import;
pub mod layout;
pub mod relay;
pub mod shares;
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
}

impl Screen {
    pub fn view(&self) -> iced::Element<Message> {
        match self {
            Screen::Unlock(s) => s.view(),
            Screen::ShareList(s) => s.view(),
            Screen::Create(s) => s.view(),
            Screen::Export(s) => s.view(),
            Screen::Import(s) => s.view(),
            Screen::Wallet(s) => s.view(),
            Screen::Relay(s) => s.view(),
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
            Screen::ShareList(_) | Screen::Wallet(_) | Screen::Relay(_) => {}
        }
    }
}
