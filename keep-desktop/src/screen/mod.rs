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

pub use keep_core::display::format_timestamp;

pub fn truncate_npub(npub: &str) -> String {
    keep_core::display::truncate_str(npub, 12, 6)
}

pub enum Screen {
    Unlock(unlock::State),
    ShareList(shares::State),
    Create(create::State),
    Export(Box<export::State>),
    ExportNcryptsec(Box<export_ncryptsec::State>),
    Import(import::State),
    Scanner(scanner::ScannerScreen),
    Wallet(wallet::State),
    Relay(relay::State),
    Bunker(Box<bunker::State>),
    NsecKeys(nsec_keys::State),
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
            Screen::Unlock(s) => return s.view().map(Message::Unlock),
            Screen::ShareList(s) => (NavItem::Shares, s.view().map(Message::ShareList)),
            Screen::Create(s) => (NavItem::Create, s.view().map(Message::Create)),
            Screen::Export(s) => (NavItem::Shares, s.view().map(Message::Export)),
            Screen::ExportNcryptsec(s) => {
                (NavItem::NsecKeys, s.view().map(Message::ExportNcryptsec))
            }
            Screen::Import(s) => (NavItem::Import, s.view().map(Message::Import)),
            Screen::Scanner(s) => (NavItem::Import, s.view().map(Message::Scanner)),
            Screen::Wallet(s) => (NavItem::Wallets, s.view().map(Message::Wallet)),
            Screen::Relay(s) => (NavItem::Relay, s.view().map(Message::Relay)),
            Screen::Bunker(s) => (NavItem::Bunker, s.view().map(Message::Bunker)),
            Screen::NsecKeys(s) => (NavItem::NsecKeys, s.view().map(Message::NsecKeys)),
            Screen::SigningAudit(s) => (NavItem::Audit, s.view().map(Message::SigningAudit)),
            Screen::Settings(s) => (NavItem::Settings, s.view().map(Message::Settings)),
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
                s.unlock_failed(error);
            }
            Screen::Create(s) => {
                s.create_failed(error);
            }
            Screen::Export(s) => {
                s.export_failed(error);
            }
            Screen::ExportNcryptsec(s) => {
                s.export_failed(error);
            }
            Screen::Import(s) => {
                s.import_failed(error);
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
