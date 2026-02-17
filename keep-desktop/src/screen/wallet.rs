// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::screen::shares::ShareEntry;
use crate::theme;

#[derive(Debug, Clone)]
pub struct WalletEntry {
    #[allow(dead_code)]
    pub group_pubkey: [u8; 32],
    pub group_hex: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub network: String,
    pub created_at: u64,
}

impl WalletEntry {
    pub fn from_descriptor(d: &keep_core::WalletDescriptor) -> Self {
        let group_hex = hex::encode(d.group_pubkey);
        Self {
            group_pubkey: d.group_pubkey,
            group_hex,
            external_descriptor: d.external_descriptor.clone(),
            internal_descriptor: d.internal_descriptor.clone(),
            network: d.network.clone(),
            created_at: d.created_at,
        }
    }

    fn truncated_hex(&self) -> &str {
        self.group_hex.get(..16).unwrap_or(&self.group_hex)
    }
}

#[derive(Debug, Clone)]
pub struct TierConfig {
    pub threshold: String,
    pub timelock_months: String,
}

impl Default for TierConfig {
    fn default() -> Self {
        Self {
            threshold: "2".into(),
            timelock_months: "6".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DescriptorProgress {
    WaitingContributions {
        received: usize,
        expected: usize,
    },
    Contributed,
    Finalizing,
    #[allow(dead_code)]
    WaitingAcks {
        received: usize,
        expected: usize,
    },
    Complete,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum SetupPhase {
    Configure,
    Coordinating(DescriptorProgress),
}

pub struct WalletScreen {
    pub descriptors: Vec<WalletEntry>,
    pub expanded: Option<usize>,
    pub setup: Option<SetupState>,
}

pub struct SetupState {
    pub shares: Vec<ShareEntry>,
    pub selected_share: Option<usize>,
    pub network: String,
    pub tiers: Vec<TierConfig>,
    pub phase: SetupPhase,
    pub error: Option<String>,
    pub session_id: Option<[u8; 32]>,
}

impl WalletScreen {
    pub fn new(descriptors: Vec<WalletEntry>) -> Self {
        Self {
            descriptors,
            expanded: None,
            setup: None,
        }
    }

    pub fn view_content(&self) -> Element<Message> {
        if let Some(setup) = &self.setup {
            return self.view_setup(setup);
        }

        let setup_btn = button(text("Setup Wallet").size(theme::size::BODY))
            .style(theme::primary_button)
            .padding([theme::space::SM, theme::space::LG])
            .on_press(Message::WalletStartSetup);

        let title_row = row![
            theme::heading("Wallet Descriptors"),
            Space::new().width(Length::Fill),
            setup_btn,
        ]
        .align_y(Alignment::Center);

        let mut content = column![title_row].spacing(theme::space::MD);

        if self.descriptors.is_empty() {
            let empty = column![
                text("No wallet descriptors yet")
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT_MUTED),
                text("Use Setup Wallet to coordinate a descriptor with your peers.")
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
            for (i, entry) in self.descriptors.iter().enumerate() {
                list = list.push(self.wallet_card(i, entry));
            }
            content = content.push(scrollable(list).height(Length::Fill));
        }

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_setup<'a>(&'a self, setup: &'a SetupState) -> Element<'a, Message> {
        match &setup.phase {
            SetupPhase::Configure => self.view_configure(setup),
            SetupPhase::Coordinating(progress) => self.view_coordinating(progress),
        }
    }

    fn view_configure<'a>(&self, setup: &'a SetupState) -> Element<'a, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::WalletCancelSetup)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Setup Wallet")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text("Configure the wallet policy and coordinate with connected peers")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let mut share_col = column![theme::label("Share")].spacing(theme::space::XS);
        for (i, share) in setup.shares.iter().enumerate() {
            let label = format!(
                "{} (share {}/{})",
                share.name, share.identifier, share.total_shares
            );
            let style = if setup.selected_share == Some(i) {
                theme::primary_button
            } else {
                theme::secondary_button
            };
            share_col = share_col.push(
                button(text(label).size(theme::size::SMALL))
                    .on_press(Message::WalletSelectShare(i))
                    .style(style)
                    .padding([theme::space::XS, theme::space::SM]),
            );
        }

        let network_label = theme::label("Network");
        let network_options = ["signet", "testnet", "bitcoin"];
        let mut network_row = row![].spacing(theme::space::SM);
        for net in &network_options {
            let style = if setup.network == *net {
                theme::primary_button
            } else {
                theme::secondary_button
            };
            network_row = network_row.push(
                button(text(*net).size(theme::size::SMALL))
                    .on_press(Message::WalletNetworkChanged(net.to_string()))
                    .style(style)
                    .padding([theme::space::XS, theme::space::SM]),
            );
        }

        let mut tiers_col = column![theme::label("Recovery Tiers")].spacing(theme::space::SM);

        for (i, tier) in setup.tiers.iter().enumerate() {
            let threshold_input = text_input("2", &tier.threshold)
                .on_input(move |v| Message::WalletThresholdChanged(format!("{i}:{v}")))
                .padding(theme::space::SM)
                .width(60);

            let timelock_input = text_input("6", &tier.timelock_months)
                .on_input(move |v| Message::WalletTimelockChanged(format!("{i}:{v}")))
                .padding(theme::space::SM)
                .width(60);

            let mut tier_row = row![
                text(format!("Tier {}", i + 1))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT),
                text("threshold:")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                threshold_input,
                text("timelock (months):")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                timelock_input,
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            if setup.tiers.len() > 1 {
                tier_row = tier_row.push(
                    button(text("Remove").size(theme::size::TINY))
                        .on_press(Message::WalletRemoveTier(i))
                        .style(theme::danger_button)
                        .padding([2.0, theme::space::SM]),
                );
            }

            tiers_col = tiers_col.push(
                container(tier_row)
                    .style(theme::card_style)
                    .padding(theme::space::MD)
                    .width(Length::Fill),
            );
        }

        let add_tier_btn = button(text("+ Add Tier").size(theme::size::SMALL))
            .on_press(Message::WalletAddTier)
            .style(theme::secondary_button)
            .padding([theme::space::XS, theme::space::SM]);

        let max_threshold = setup
            .selected_share
            .and_then(|i| setup.shares.get(i))
            .map(|s| s.total_shares as u32)
            .unwrap_or(0);
        let can_begin = setup.selected_share.is_some()
            && setup.tiers.iter().all(|t| {
                t.threshold
                    .parse::<u32>()
                    .is_ok_and(|v| v >= 1 && v <= max_threshold)
                    && t.timelock_months.parse::<u32>().is_ok_and(|v| v > 0)
            });

        let mut begin_btn = button(text("Begin Coordination").size(theme::size::BODY))
            .style(theme::primary_button)
            .padding(theme::space::MD);
        if can_begin {
            begin_btn = begin_btn.on_press(Message::WalletBeginCoordination);
        }

        let mut content = column![
            header,
            subtitle,
            Space::new().height(theme::space::SM),
            share_col,
            Space::new().height(theme::space::SM),
            network_label,
            network_row,
            Space::new().height(theme::space::SM),
            tiers_col,
            add_tier_btn,
            Space::new().height(theme::space::MD),
            begin_btn,
        ]
        .spacing(theme::space::XS);

        if let Some(err) = &setup.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        container(scrollable(content))
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_coordinating(&self, progress: &DescriptorProgress) -> Element<'_, Message> {
        let back_btn = button(text("< Cancel").size(theme::size::BODY))
            .on_press(Message::WalletCancelSetup)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Wallet Coordination")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let (status_text, status_color) = match progress {
            DescriptorProgress::WaitingContributions { received, expected } => (
                format!("Waiting for contributions ({received}/{expected})"),
                theme::color::WARNING,
            ),
            DescriptorProgress::Contributed => ("Contribution sent".into(), theme::color::PRIMARY),
            DescriptorProgress::Finalizing => {
                ("Finalizing descriptor...".into(), theme::color::PRIMARY)
            }
            DescriptorProgress::WaitingAcks { received, expected } => (
                format!("Waiting for acknowledgements ({received}/{expected})"),
                theme::color::WARNING,
            ),
            DescriptorProgress::Complete => (
                "Descriptor coordination complete".into(),
                theme::color::SUCCESS,
            ),
            DescriptorProgress::Failed(err) => (format!("Failed: {err}"), theme::color::ERROR),
        };

        let status_badge = container(
            text(status_text)
                .size(theme::size::BODY)
                .color(status_color),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill);

        let hint = match progress {
            DescriptorProgress::WaitingContributions { .. } => {
                "Peers need to contribute their extended public keys."
            }
            DescriptorProgress::Contributed => "Waiting for the initiator to finalize.",
            DescriptorProgress::Finalizing => "Building the final wallet descriptor.",
            DescriptorProgress::WaitingAcks { .. } => {
                "Peers are verifying and acknowledging the descriptor."
            }
            DescriptorProgress::Complete => "The wallet descriptor has been stored.",
            DescriptorProgress::Failed(_) => "You can cancel and try again.",
        };

        let content = column![
            header,
            Space::new().height(theme::space::MD),
            status_badge,
            Space::new().height(theme::space::SM),
            text(hint)
                .size(theme::size::SMALL)
                .color(theme::color::TEXT_DIM),
        ]
        .spacing(theme::space::XS);

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn wallet_card<'a>(&self, i: usize, entry: &'a WalletEntry) -> Element<'a, Message> {
        let network_badge = container(
            text(&entry.network)
                .size(theme::size::TINY)
                .color(theme::color::PRIMARY),
        )
        .style(theme::badge_style)
        .padding([2.0, theme::space::SM]);

        let hex_text = text(entry.truncated_hex())
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let arrow = if self.expanded == Some(i) { "v" } else { ">" };
        let name_btn = button(
            text(format!("{arrow} {}", entry.truncated_hex()))
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
        )
        .on_press(Message::ToggleWalletDetails(i))
        .style(theme::text_button)
        .padding(0);

        let header_top =
            row![name_btn, Space::new().width(Length::Fill)].align_y(Alignment::Center);

        let header_info = column![
            header_top,
            row![network_badge, hex_text]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center),
        ]
        .spacing(theme::space::XS);

        let mut card_content = column![header_info].spacing(theme::space::SM);

        if self.expanded == Some(i) {
            let ext_row = row![
                text("External:")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                button(text("Copy").size(theme::size::TINY))
                    .on_press(Message::CopyDescriptor(entry.external_descriptor.clone()))
                    .style(theme::secondary_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            let ext_value = text(&entry.external_descriptor)
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let int_row = row![
                text("Internal:")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                button(text("Copy").size(theme::size::TINY))
                    .on_press(Message::CopyDescriptor(entry.internal_descriptor.clone()))
                    .style(theme::secondary_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            let int_value = text(&entry.internal_descriptor)
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let hex_full = text(format!("Group key: {}", entry.group_hex))
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let created = DateTime::<Utc>::from_timestamp(entry.created_at as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| entry.created_at.to_string());
            let created_text = text(format!("Created: {created}"))
                .size(theme::size::SMALL)
                .color(theme::color::TEXT_MUTED);

            let details = column![
                ext_row,
                ext_value,
                int_row,
                int_value,
                hex_full,
                created_text
            ]
            .spacing(theme::space::XS);

            card_content = card_content.push(details);
        }

        container(card_content)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }
}
