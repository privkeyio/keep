// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashMap;

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};
use keep_frost_net::AnnouncedXpub;
use keep_frost_net::{MAX_XPUB_LABEL_LENGTH, MAX_XPUB_LENGTH, VALID_XPUB_PREFIXES};

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
    WaitingContributions { received: usize, expected: usize },
    Contributed,
    Finalizing,
    WaitingAcks { received: usize, expected: usize },
    Complete,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum SetupPhase {
    Configure,
    Coordinating(DescriptorProgress),
}

pub struct AnnounceState {
    pub xpub: String,
    pub fingerprint: String,
    pub label: String,
    pub error: Option<String>,
    pub submitting: bool,
}

#[derive(Clone, Debug)]
pub enum Message {
    ToggleDetails(usize),
    StartSetup,
    SelectShare(usize),
    NetworkChanged(String),
    ThresholdChanged(String),
    TimelockChanged(String),
    AddTier,
    RemoveTier(usize),
    BeginCoordination,
    CancelSetup,
    StartAnnounce,
    XpubChanged(String),
    FingerprintChanged(String),
    LabelChanged(String),
    CancelAnnounce,
    SubmitAnnounce,
    CopyDescriptor(String),
}

pub enum Event {
    StartSetup,
    BeginCoordination,
    CancelSetup {
        session_id: Option<[u8; 32]>,
    },
    StartAnnounce,
    SubmitAnnounce {
        xpub: String,
        fingerprint: String,
        label: String,
    },
    CopyDescriptor(String),
}

pub struct State {
    pub descriptors: Vec<WalletEntry>,
    pub expanded: Option<usize>,
    pub setup: Option<SetupState>,
    pub announce: Option<AnnounceState>,
    pub peer_xpubs: HashMap<u16, Vec<AnnouncedXpub>>,
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

impl State {
    pub fn new(descriptors: Vec<WalletEntry>) -> Self {
        Self {
            descriptors,
            expanded: None,
            setup: None,
            announce: None,
            peer_xpubs: HashMap::new(),
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::ToggleDetails(i) => {
                self.expanded = if self.expanded == Some(i) {
                    None
                } else {
                    Some(i)
                };
                None
            }
            Message::StartSetup => Some(Event::StartSetup),
            Message::SelectShare(i) => {
                if let Some(s) = &mut self.setup {
                    s.selected_share = Some(i);
                }
                None
            }
            Message::NetworkChanged(n) => {
                if keep_frost_net::VALID_NETWORKS.contains(&n.as_str()) {
                    if let Some(s) = &mut self.setup {
                        s.network = n;
                    }
                }
                None
            }
            Message::ThresholdChanged(encoded) => {
                self.update_tier_field(&encoded, |tier, val| tier.threshold = val);
                None
            }
            Message::TimelockChanged(encoded) => {
                self.update_tier_field(&encoded, |tier, val| tier.timelock_months = val);
                None
            }
            Message::AddTier => {
                if let Some(s) = &mut self.setup {
                    if s.tiers.len() < 5 {
                        s.tiers.push(TierConfig::default());
                    }
                }
                None
            }
            Message::RemoveTier(i) => {
                if let Some(s) = &mut self.setup {
                    if s.tiers.len() > 1 && i < s.tiers.len() {
                        s.tiers.remove(i);
                    }
                }
                None
            }
            Message::BeginCoordination => Some(Event::BeginCoordination),
            Message::CancelSetup => {
                let session_id = self.setup.as_ref().and_then(|s| s.session_id);
                self.setup = None;
                Some(Event::CancelSetup { session_id })
            }
            Message::StartAnnounce => Some(Event::StartAnnounce),
            Message::XpubChanged(v) => {
                if let Some(a) = &mut self.announce {
                    a.xpub = v.chars().take(MAX_XPUB_LENGTH).collect();
                }
                None
            }
            Message::FingerprintChanged(v) => {
                if let Some(a) = &mut self.announce {
                    a.fingerprint = v
                        .chars()
                        .filter(|c| c.is_ascii_hexdigit())
                        .take(8)
                        .collect();
                }
                None
            }
            Message::LabelChanged(v) => {
                if let Some(a) = &mut self.announce {
                    a.label = v.chars().take(MAX_XPUB_LABEL_LENGTH).collect();
                }
                None
            }
            Message::CancelAnnounce => {
                self.announce = None;
                None
            }
            Message::SubmitAnnounce => {
                let Some(a) = &mut self.announce else {
                    return None;
                };
                let xpub = a.xpub.trim().to_string();
                let fingerprint = a.fingerprint.trim().to_string();
                let label = a.label.trim().to_string();
                a.submitting = true;
                a.error = None;
                Some(Event::SubmitAnnounce {
                    xpub,
                    fingerprint,
                    label,
                })
            }
            Message::CopyDescriptor(desc) => Some(Event::CopyDescriptor(desc)),
        }
    }

    fn update_tier_field(&mut self, encoded: &str, f: impl FnOnce(&mut TierConfig, String)) {
        if let Some(s) = &mut self.setup {
            if let Some((idx_str, val)) = encoded.split_once(':') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    if let Some(tier) = s.tiers.get_mut(idx) {
                        f(tier, val.to_string());
                    }
                }
            }
        }
    }

    pub fn begin_setup(&mut self, shares: Vec<ShareEntry>) {
        let selected = if shares.len() == 1 { Some(0) } else { None };
        self.setup = Some(SetupState {
            shares,
            selected_share: selected,
            network: "signet".into(),
            tiers: vec![TierConfig::default()],
            phase: SetupPhase::Configure,
            error: None,
            session_id: None,
        });
    }

    pub fn begin_announce(&mut self) {
        self.announce = Some(AnnounceState {
            xpub: String::new(),
            fingerprint: String::new(),
            label: String::new(),
            error: None,
            submitting: false,
        });
    }

    pub fn announce_submitted(&mut self) {
        self.announce = None;
    }

    pub fn announce_failed(&mut self, error: String) {
        if let Some(a) = &mut self.announce {
            a.error = Some(error);
            a.submitting = false;
        }
    }

    pub fn announce_not_connected(&mut self) {
        if let Some(a) = &mut self.announce {
            a.error = Some("Relay not connected".into());
            a.submitting = false;
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        if let Some(announce) = &self.announce {
            return self.view_announce(announce);
        }

        if let Some(setup) = &self.setup {
            return self.view_setup(setup);
        }

        let setup_btn = button(text("Setup Wallet").size(theme::size::BODY))
            .style(theme::primary_button)
            .padding([theme::space::SM, theme::space::LG])
            .on_press(Message::StartSetup);

        let announce_btn = button(text("Announce Recovery Keys").size(theme::size::BODY))
            .style(theme::secondary_button)
            .padding([theme::space::SM, theme::space::LG])
            .on_press(Message::StartAnnounce);

        let title_row = row![
            theme::heading("Wallet Descriptors"),
            Space::new().width(Length::Fill),
            announce_btn,
            setup_btn,
        ]
        .spacing(theme::space::SM)
        .align_y(Alignment::Center);

        let mut content = column![title_row].spacing(theme::space::MD);

        let mut list = column![].spacing(theme::space::SM);

        if self.descriptors.is_empty() {
            list = list.push(
                container(
                    column![
                        text("No wallet descriptors yet")
                            .size(theme::size::BODY)
                            .color(theme::color::TEXT_MUTED),
                        text("Use Setup Wallet to coordinate a descriptor with your peers.")
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_DIM),
                    ]
                    .align_x(Alignment::Center)
                    .spacing(theme::space::SM),
                )
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            );
        } else {
            for (i, entry) in self.descriptors.iter().enumerate() {
                list = list.push(self.wallet_card(i, entry));
            }
        }

        if !self.peer_xpubs.is_empty() {
            list = list.push(self.peer_xpubs_card());
        }

        content = content.push(scrollable(list).height(Length::Fill));

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
            .on_press(Message::CancelSetup)
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
                    .on_press(Message::SelectShare(i))
                    .style(style)
                    .padding([theme::space::XS, theme::space::SM]),
            );
        }

        let network_label = theme::label("Network");
        let network_options = ["signet", "testnet", "regtest", "bitcoin"];
        let mut network_row = row![].spacing(theme::space::SM);
        for net in &network_options {
            let style = if setup.network == *net {
                theme::primary_button
            } else {
                theme::secondary_button
            };
            network_row = network_row.push(
                button(text(*net).size(theme::size::SMALL))
                    .on_press(Message::NetworkChanged(net.to_string()))
                    .style(style)
                    .padding([theme::space::XS, theme::space::SM]),
            );
        }

        let mut tiers_col = column![theme::label("Recovery Tiers")].spacing(theme::space::SM);

        for (i, tier) in setup.tiers.iter().enumerate() {
            let threshold_input = text_input("2", &tier.threshold)
                .on_input(move |v| Message::ThresholdChanged(format!("{i}:{v}")))
                .padding(theme::space::SM)
                .width(60);

            let timelock_input = text_input("6", &tier.timelock_months)
                .on_input(move |v| Message::TimelockChanged(format!("{i}:{v}")))
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
                        .on_press(Message::RemoveTier(i))
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
            .on_press(Message::AddTier)
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
            begin_btn = begin_btn.on_press(Message::BeginCoordination);
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
            .on_press(Message::CancelSetup)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Wallet Coordination")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let (status_text, status_color, hint) = match progress {
            DescriptorProgress::WaitingContributions { received, expected } => (
                format!("Waiting for contributions ({received}/{expected})"),
                theme::color::WARNING,
                "Peers need to contribute their extended public keys.",
            ),
            DescriptorProgress::Contributed => (
                "Contribution sent".into(),
                theme::color::PRIMARY,
                "Waiting for the initiator to finalize.",
            ),
            DescriptorProgress::Finalizing => (
                "Finalizing descriptor...".into(),
                theme::color::PRIMARY,
                "Building the final wallet descriptor.",
            ),
            DescriptorProgress::WaitingAcks { received, expected } => (
                format!("Waiting for acknowledgements ({received}/{expected})"),
                theme::color::WARNING,
                "Peers are verifying and acknowledging the descriptor.",
            ),
            DescriptorProgress::Complete => (
                "Descriptor coordination complete".into(),
                theme::color::SUCCESS,
                "The wallet descriptor has been stored.",
            ),
            DescriptorProgress::Failed(err) => (
                format!("Failed: {err}"),
                theme::color::ERROR,
                "You can cancel and try again.",
            ),
        };

        let status_badge = container(
            text(status_text)
                .size(theme::size::BODY)
                .color(status_color),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill);

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
        .on_press(Message::ToggleDetails(i))
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

            let created = i64::try_from(entry.created_at)
                .map(keep_core::display::format_timestamp)
                .unwrap_or_else(|_| entry.created_at.to_string());
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

    fn view_announce<'a>(&self, state: &'a AnnounceState) -> Element<'a, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::CancelAnnounce)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Announce Recovery Key")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text("Share a recovery xpub with your FROST group peers")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let xpub_input = text_input("tpub...", &state.xpub)
            .on_input(Message::XpubChanged)
            .padding(theme::space::SM);

        let fp_input = text_input("8 hex chars", &state.fingerprint)
            .on_input(Message::FingerprintChanged)
            .padding(theme::space::SM)
            .width(120);

        let label_input = text_input("e.g. coldcard-backup", &state.label)
            .on_input(Message::LabelChanged)
            .padding(theme::space::SM);

        let xpub_valid = VALID_XPUB_PREFIXES
            .iter()
            .any(|p| state.xpub.starts_with(p));
        let fp_valid = state.fingerprint.len() == 8
            && state.fingerprint.chars().all(|c| c.is_ascii_hexdigit());
        let can_submit = xpub_valid && fp_valid && !state.submitting;

        let mut submit_btn = button(text("Announce").size(theme::size::BODY))
            .style(theme::primary_button)
            .padding([theme::space::SM, theme::space::LG]);
        if can_submit {
            submit_btn = submit_btn.on_press(Message::SubmitAnnounce);
        }

        let mut content = column![
            header,
            subtitle,
            Space::new().height(theme::space::SM),
            theme::label("Extended Public Key"),
            xpub_input,
            Space::new().height(theme::space::XS),
            theme::label("Fingerprint"),
            fp_input,
            Space::new().height(theme::space::XS),
            theme::label("Label (optional)"),
            label_input,
            Space::new().height(theme::space::MD),
            submit_btn,
        ]
        .spacing(theme::space::XS);

        if let Some(err) = &state.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        container(scrollable(content))
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn peer_xpubs_card(&self) -> Element<'_, Message> {
        let title = text("Announced Recovery Keys")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let mut content = column![title].spacing(theme::space::SM);

        let mut indices: Vec<_> = self.peer_xpubs.keys().copied().collect();
        indices.sort();

        for idx in indices {
            let xpubs = &self.peer_xpubs[&idx];
            let share_label = text(format!("Share {idx}"))
                .size(theme::size::BODY)
                .color(theme::color::TEXT);

            let mut share_col = column![share_label].spacing(theme::space::XS);

            for xpub in xpubs {
                let display = if xpub.xpub.chars().count() > 32 {
                    let prefix: String = xpub.xpub.chars().take(32).collect();
                    format!("{prefix}...")
                } else {
                    xpub.xpub.clone()
                };

                let mut xpub_row = row![
                    text(display)
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_DIM),
                    text(&xpub.fingerprint)
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_MUTED),
                ]
                .spacing(theme::space::SM);

                if let Some(label) = &xpub.label {
                    xpub_row = xpub_row.push(
                        text(label)
                            .size(theme::size::TINY)
                            .color(theme::color::TEXT_MUTED),
                    );
                }

                share_col = share_col.push(xpub_row);
            }

            content = content.push(share_col);
        }

        container(content)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }
}
