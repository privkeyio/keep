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
use layout::{NavItem, SidebarState};

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
    pub fn view<'a>(
        &'a self,
        sidebar_state: &SidebarState<'a>,
        share_count: Option<usize>,
        pending_requests: usize,
        kill_switch_active: bool,
    ) -> iced::Element<'a, Message> {
        let (nav, content, count) = match self {
            Screen::Unlock(s) => return s.view(),
            Screen::ShareList(s) => (NavItem::Shares, s.view_content(), share_count),
            Screen::Create(s) => (NavItem::Create, s.view_content(), None),
            Screen::Export(s) => (NavItem::Shares, s.view_content(), None),
            Screen::Import(s) => (NavItem::Import, s.view_content(), None),
            Screen::Wallet(s) => (NavItem::Wallets, s.view_content(), None),
            Screen::Relay(s) => (NavItem::Relay, s.view_content(), None),
            Screen::Bunker(s) => (NavItem::Bunker, s.view_content(), None),
            Screen::SigningAudit(s) => (NavItem::Audit, s.view_content(), None),
            Screen::Settings(s) => (NavItem::Settings, s.view_content(), None),
        };
        layout::with_sidebar(
            nav,
            content,
            sidebar_state,
            count,
            pending_requests,
            kill_switch_active,
        )
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
