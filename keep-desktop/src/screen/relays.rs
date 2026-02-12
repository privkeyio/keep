// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};
use keep_core::relay::{self, MAX_RELAYS};

use crate::message::Message;
use crate::screen::layout::{self, NavItem};
use crate::theme;

#[derive(Debug, Clone)]
pub struct RelayShareEntry {
    pub group_pubkey: [u8; 32],
    pub group_hex: String,
    pub name: String,
    pub frost_relays: Vec<String>,
    pub profile_relays: Vec<String>,
}

pub struct RelayScreen {
    pub shares: Vec<RelayShareEntry>,
    pub expanded: Option<usize>,
    pub frost_input: String,
    pub profile_input: String,
    pub error: Option<String>,
}

impl RelayScreen {
    pub fn new(shares: Vec<RelayShareEntry>) -> Self {
        Self {
            shares,
            expanded: None,
            frost_input: String::new(),
            profile_input: String::new(),
            error: None,
        }
    }

    pub fn view(&self) -> Element<Message> {
        let title = theme::heading("Relay Configuration");

        let mut content = column![title].spacing(theme::space::MD);

        if self.shares.is_empty() {
            let empty = column![
                text("No shares configured")
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT_MUTED),
                text("Create or import a FROST share to configure relays.")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_DIM),
            ]
            .align_x(Alignment::Center)
            .spacing(theme::space::SM);

            content = content.push(
                container(empty)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill),
            );
        } else {
            let mut list = column![].spacing(theme::space::SM);
            for (i, entry) in self.shares.iter().enumerate() {
                list = list.push(self.share_relay_card(i, entry));
            }
            content = content.push(scrollable(list).height(Length::Fill));
        }

        let inner = container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill);

        layout::with_sidebar(NavItem::Relays, inner.into(), None)
    }

    fn share_relay_card<'a>(
        &'a self,
        i: usize,
        entry: &'a RelayShareEntry,
    ) -> Element<'a, Message> {
        let truncated = &entry.group_hex[..16.min(entry.group_hex.len())];

        let arrow = if self.expanded == Some(i) { "v" } else { ">" };
        let name_btn = button(
            text(format!("{arrow} {}", entry.name))
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
        )
        .on_press(Message::ToggleRelayDetails(i))
        .style(theme::text_button)
        .padding(0);

        let relay_count = entry.frost_relays.len() + entry.profile_relays.len();
        let count_text = text(format!(
            "{} relay{}",
            relay_count,
            if relay_count == 1 { "" } else { "s" }
        ))
        .size(theme::size::SMALL)
        .color(theme::color::TEXT_MUTED);

        let hex_text = text(truncated.to_owned())
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_DIM);

        let header_top =
            row![name_btn, Space::new().width(Length::Fill), count_text].align_y(Alignment::Center);

        let header_info = column![header_top, hex_text].spacing(theme::space::XS);

        let mut card_content = column![header_info].spacing(theme::space::SM);

        if self.expanded == Some(i) {
            card_content = card_content.push(self.relay_section(
                i,
                "FROST Coordination Relays",
                "Used for threshold signing communication between share holders",
                "No FROST relays configured",
                &entry.frost_relays,
                &self.frost_input,
                Message::FrostRelayInputChanged,
                Message::AddFrostRelay(i),
                Message::RemoveFrostRelay,
            ));
            card_content = card_content.push(Space::new().height(theme::space::SM));
            card_content = card_content.push(self.relay_section(
                i,
                "Profile / NIP-46 Relays",
                "Used for profile data and remote signing connections",
                "No profile relays configured",
                &entry.profile_relays,
                &self.profile_input,
                Message::ProfileRelayInputChanged,
                Message::AddProfileRelay(i),
                Message::RemoveProfileRelay,
            ));

            if let Some(ref err) = self.error {
                card_content = card_content.push(theme::error_text(err));
            }
        }

        container(card_content)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    #[allow(clippy::too_many_arguments)]
    fn relay_section<'a>(
        &'a self,
        share_idx: usize,
        title: &'a str,
        description: &'a str,
        empty_label: &'a str,
        relays: &'a [String],
        input_value: &'a str,
        on_input: fn(String) -> Message,
        on_add: Message,
        on_remove: impl Fn(usize, String) -> Message,
    ) -> Element<'a, Message> {
        let mut section = column![
            text(title)
                .size(theme::size::BODY)
                .color(theme::color::TEXT),
            text(description)
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM),
        ]
        .spacing(theme::space::XS);

        if relays.is_empty() {
            section = section.push(
                text(empty_label)
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );
        } else {
            for relay in relays {
                let display = relay.strip_prefix("wss://").unwrap_or(relay);
                let relay_row = row![
                    text(display)
                        .size(theme::size::SMALL)
                        .color(theme::color::TEXT_MUTED),
                    Space::new().width(Length::Fill),
                    button(text("x").size(theme::size::TINY))
                        .on_press(on_remove(share_idx, relay.clone()))
                        .style(theme::danger_button)
                        .padding([2.0, theme::space::SM]),
                ]
                .align_y(Alignment::Center)
                .spacing(theme::space::SM);
                section = section.push(relay_row);
            }
        }

        if relays.len() < MAX_RELAYS && self.expanded == Some(share_idx) {
            let input = text_input("wss://relay.example.com", input_value)
                .on_input(on_input)
                .padding(theme::space::SM)
                .width(Length::Fill);

            let add_btn = button(text("Add").size(theme::size::SMALL))
                .on_press(on_add)
                .style(theme::primary_button)
                .padding([theme::space::XS, theme::space::MD]);

            let input_row = row![input, add_btn]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center);

            section = section.push(input_row);
        } else if relays.len() >= MAX_RELAYS {
            section = section.push(
                text(format!("Maximum of {MAX_RELAYS} relays reached"))
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
            );
        }

        section.into()
    }
}

pub fn validate_and_normalize(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("wss://{trimmed}")
    };
    let url = relay::normalize_relay_url(&with_scheme);
    relay::validate_relay_url(&url)?;
    Ok(url)
}
