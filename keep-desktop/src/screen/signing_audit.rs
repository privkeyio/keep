// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use iced::widget::{button, column, container, pick_list, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::theme;

const PAGE_SIZE: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerOption {
    pub full: Option<String>,
    pub display: String,
}

impl fmt::Display for CallerOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

#[derive(Debug, Clone)]
pub struct AuditDisplayEntry {
    pub timestamp: i64,
    pub request_type: String,
    pub decision: String,
    pub was_automatic: bool,
    pub caller: String,
    pub caller_name: Option<String>,
    pub event_kind: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    Verifying,
    Valid(usize),
    Invalid,
    Error(String),
}

pub struct SigningAuditScreen {
    pub entries: Vec<AuditDisplayEntry>,
    pub chain_status: ChainStatus,
    pub load_error: Option<String>,
    pub callers: Vec<String>,
    pub selected_caller: Option<String>,
    pub has_more: bool,
    pub loading: bool,
    pub entry_count: usize,
}

impl SigningAuditScreen {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            chain_status: ChainStatus::Verifying,
            load_error: None,
            callers: Vec::new(),
            selected_caller: None,
            has_more: false,
            loading: true,
            entry_count: 0,
        }
    }

    pub fn page_size() -> usize {
        PAGE_SIZE
    }

    pub fn view_content(&self) -> Element<'_, Message> {
        let title = theme::heading("Signing History");
        let subtitle = theme::muted("View past signing requests and decisions");

        let chain_indicator = self.chain_status_row();

        let mut content = column![title, subtitle, chain_indicator].spacing(theme::space::SM);

        if !self.callers.is_empty() {
            content = content.push(self.filter_row());
        }

        if self.entries.is_empty() {
            let label = if self.loading {
                "Loading..."
            } else if self.load_error.is_some() {
                "Failed to load signing history"
            } else {
                "No signing history"
            };
            content = content.push(
                container(
                    text(label)
                        .size(theme::size::BODY)
                        .color(theme::color::TEXT_MUTED),
                )
                .center_x(Length::Fill)
                .padding(theme::space::XXXL),
            );
        } else {
            let mut entries_col = column![].spacing(theme::space::SM);
            for entry in &self.entries {
                entries_col = entries_col.push(self.entry_card(entry));
            }

            if self.has_more {
                let label = if self.loading {
                    "Loading..."
                } else {
                    "Load more"
                };
                let load_more = button(
                    text(label)
                        .size(theme::size::SMALL)
                        .width(Length::Fill)
                        .align_x(Alignment::Center),
                )
                .on_press_maybe((!self.loading).then_some(Message::AuditLoadMore))
                .style(theme::secondary_button)
                .padding([theme::space::SM, theme::space::LG])
                .width(Length::Fill);
                entries_col = entries_col.push(load_more);
            }

            content = content.push(entries_col);
        }

        let padded = content.padding(theme::space::LG).width(Length::Fill);

        let inner = scrollable(padded).width(Length::Fill).height(Length::Fill);

        inner.into()
    }

    fn chain_status_row(&self) -> Element<'_, Message> {
        let (status_text, color) = match &self.chain_status {
            ChainStatus::Verifying => ("Verifying chain...".to_string(), theme::color::TEXT_MUTED),
            ChainStatus::Valid(count) => (
                format!("Chain verified ({count} entries)"),
                theme::color::SUCCESS,
            ),
            ChainStatus::Invalid => (
                "Tampering detected in audit log".to_string(),
                theme::color::ERROR,
            ),
            ChainStatus::Error(_) => (
                "Unable to verify chain integrity".to_string(),
                theme::color::ERROR,
            ),
        };

        row![text(status_text).size(theme::size::SMALL).color(color)]
            .align_y(Alignment::Center)
            .into()
    }

    fn filter_row(&self) -> Element<'_, Message> {
        let all_option = CallerOption {
            full: None,
            display: "All clients".to_string(),
        };
        let mut options = vec![all_option.clone()];
        for c in &self.callers {
            options.push(CallerOption {
                full: Some(c.clone()),
                display: truncate_hex(c),
            });
        }

        let selected = match &self.selected_caller {
            Some(c) => options.iter().find(|o| o.full.as_ref() == Some(c)).cloned(),
            None => Some(all_option),
        };

        let picker = pick_list(options, selected, |opt: CallerOption| {
            Message::AuditFilterChanged(opt.full)
        })
        .text_size(theme::size::SMALL)
        .width(Length::Fixed(250.0));

        container(
            row![
                text("Filter by client")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                Space::new().width(theme::space::SM),
                picker,
            ]
            .align_y(Alignment::Center),
        )
        .into()
    }

    fn entry_card<'a>(&self, entry: &'a AuditDisplayEntry) -> Element<'a, Message> {
        let is_approved = entry.decision == "approved";
        let card_style = if is_approved {
            theme::card_style
        } else {
            theme::warning_style
        };

        let request_label = format_request_type(&entry.request_type);

        let decision_color = if is_approved {
            theme::color::SUCCESS
        } else {
            theme::color::ERROR
        };
        let decision_label = if is_approved { "Allowed" } else { "Denied" };

        let mut badge_row = row![].spacing(theme::space::XS).align_y(Alignment::Center);

        if entry.was_automatic {
            badge_row = badge_row.push(
                container(
                    text("Auto")
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_MUTED),
                )
                .style(theme::card_style)
                .padding([2.0, theme::space::SM]),
            );
        }

        badge_row = badge_row.push(
            container(
                text(decision_label)
                    .size(theme::size::TINY)
                    .color(decision_color),
            )
            .style(if is_approved {
                theme::badge_style
            } else {
                theme::warning_style
            })
            .padding([2.0, theme::space::SM]),
        );

        let header = row![
            text(request_label)
                .size(theme::size::BODY)
                .color(theme::color::TEXT),
            Space::new().width(Length::Fill),
            badge_row,
        ]
        .align_y(Alignment::Center);

        let caller_display = entry.caller_name.as_deref().unwrap_or(&entry.caller);
        let caller_text = text(truncate_hex(caller_display))
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let mut detail_row = row![caller_text].spacing(theme::space::MD);

        if let Some(kind) = entry.event_kind {
            detail_row = detail_row.push(
                text(format_event_kind(kind))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );
        }

        let timestamp = chrono::DateTime::from_timestamp(entry.timestamp, 0)
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string())
            .unwrap_or_else(|| entry.timestamp.to_string());

        let time_text = text(timestamp)
            .size(theme::size::TINY)
            .color(theme::color::TEXT_DIM);

        container(column![header, detail_row, time_text].spacing(theme::space::XS))
            .style(card_style)
            .padding(theme::space::MD)
            .width(Length::Fill)
            .into()
    }
}

fn truncate_hex(s: &str) -> String {
    if s.len() <= 20 || !s.is_ascii() {
        return s.to_string();
    }
    format!("{}...{}", &s[..8], &s[s.len() - 6..])
}

fn format_request_type(rt: &str) -> String {
    match rt {
        "connect" => "Connect".to_string(),
        "get_public_key" => "Get Public Key".to_string(),
        "sign_event" => "Sign Event".to_string(),
        "nip04_encrypt" => "NIP-04 Encrypt".to_string(),
        "nip04_decrypt" => "NIP-04 Decrypt".to_string(),
        "nip44_encrypt" => "NIP-44 Encrypt".to_string(),
        "nip44_decrypt" => "NIP-44 Decrypt".to_string(),
        "disconnect" => "Disconnect".to_string(),
        other => other.replace('_', " "),
    }
}

fn format_event_kind(kind: u32) -> String {
    let name = match kind {
        0 => "User Metadata",
        1 => "Short Text Note",
        3 => "Follows",
        4 => "Encrypted DM",
        5 => "Event Deletion",
        6 => "Repost",
        7 => "Reaction",
        9 => "Chat Message",
        13 => "Seal",
        14 => "Direct Message",
        16 => "Generic Repost",
        1059 => "Gift Wrap",
        1063 => "File Metadata",
        1111 => "Comment",
        9734 => "Zap Request",
        9735 => "Zap",
        10000 => "Mute List",
        10002 => "Relay List",
        22242 => "Client Auth",
        24133 => "Nostr Connect",
        27235 => "HTTP Auth",
        30023 => "Long-form Content",
        30078 => "App Data",
        _ => return format!("Kind {kind}"),
    };
    format!("{name} (kind {kind})")
}
