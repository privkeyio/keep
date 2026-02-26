// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod bunker;
pub mod create;
pub mod export;
pub mod export_ncryptsec;
pub mod import;
pub mod layout;
pub mod nsec_keys;
pub mod relay;
pub mod scanner;
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
    ExportNcryptsec(Box<export_ncryptsec::ExportNcryptsecScreen>),
    Import(import::ImportScreen),
    Scanner(scanner::ScannerScreen),
    Wallet(wallet::WalletScreen),
    Relay(relay::RelayScreen),
    Bunker(Box<bunker::BunkerScreen>),
    NsecKeys(nsec_keys::NsecKeysScreen),
    SigningAudit(signing_audit::SigningAuditScreen),
    Settings(settings::SettingsScreen),
}

impl Screen {
    pub fn view<'a>(
        &'a self,
        sidebar_state: &SidebarState<'a>,
        share_count: Option<usize>,
        nsec_count: Option<usize>,
        pending_requests: usize,
        kill_switch_active: bool,
    ) -> iced::Element<'a, Message> {
        let (nav, content) = match self {
            Screen::Unlock(s) => return s.view(),
            Screen::ShareList(s) => (NavItem::Shares, s.view_content()),
            Screen::Create(s) => (NavItem::Create, s.view_content()),
            Screen::Export(s) => (NavItem::Shares, s.view_content()),
            Screen::ExportNcryptsec(s) => (NavItem::NsecKeys, s.view_content()),
            Screen::Import(s) => (NavItem::Import, s.view_content()),
            Screen::Scanner(s) => (NavItem::Import, s.view_content()),
            Screen::Wallet(s) => (NavItem::Wallets, s.view_content()),
            Screen::Relay(s) => (NavItem::Relay, s.view_content()),
            Screen::Bunker(s) => (NavItem::Bunker, s.view_content()),
            Screen::NsecKeys(s) => (NavItem::NsecKeys, s.view_content()),
            Screen::SigningAudit(s) => (NavItem::Audit, s.view_content()),
            Screen::Settings(s) => (NavItem::Settings, s.view_content()),
        };
        layout::with_sidebar(
            nav,
            content,
            sidebar_state,
            share_count,
            nsec_count,
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
            Screen::ExportNcryptsec(s) => {
                s.loading = false;
                s.error = Some(error);
            }
            Screen::Import(s) => {
                s.loading = false;
                s.error = Some(error);
            }
            Screen::Scanner(_) => {}
            Screen::Bunker(s) => {
                s.starting = false;
                s.error = Some(error);
            }
            Screen::ShareList(_)
            | Screen::NsecKeys(_)
            | Screen::Wallet(_)
            | Screen::Relay(_)
            | Screen::SigningAudit(_)
            | Screen::Settings(_) => {}
        }
    }
}
