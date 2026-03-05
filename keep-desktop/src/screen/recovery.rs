// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::borrow::Cow;
use std::fmt;
use std::time::{Duration, Instant};

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::theme;

#[derive(Clone)]
pub enum Message {
    ShareInputChanged(usize, Zeroizing<String>),
    PassphraseChanged(usize, Zeroizing<String>),
    AddShareInput,
    RemoveShareInput(usize),
    ScanShare(usize),
    Recover,
    ToggleNsecVisibility,
    CopyNsec,
    ClearNsec,
    AutoClearTick,
    GoBack,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShareInputChanged(i, _) => f.debug_tuple("ShareInputChanged").field(i).finish(),
            Self::PassphraseChanged(i, _) => f.debug_tuple("PassphraseChanged").field(i).finish(),
            Self::AddShareInput => f.write_str("AddShareInput"),
            Self::RemoveShareInput(i) => f.debug_tuple("RemoveShareInput").field(i).finish(),
            Self::ScanShare(i) => f.debug_tuple("ScanShare").field(i).finish(),
            Self::Recover => f.write_str("Recover"),
            Self::ToggleNsecVisibility => f.write_str("ToggleNsecVisibility"),
            Self::CopyNsec => f.write_str("CopyNsec"),
            Self::ClearNsec => f.write_str("ClearNsec"),
            Self::AutoClearTick => f.write_str("AutoClearTick"),
            Self::GoBack => f.write_str("GoBack"),
        }
    }
}

pub enum Event {
    GoBack,
    ScanShare(usize),
    Recover {
        share_data: Vec<Zeroizing<String>>,
        passphrases: Vec<Zeroizing<String>>,
        expected_group_pubkey: [u8; 32],
    },
    CopyToClipboard(Zeroizing<String>),
}

pub struct State {
    share_inputs: Vec<Zeroizing<String>>,
    passphrase_inputs: Vec<Zeroizing<String>>,
    vault_slot: bool,
    threshold: u16,
    total_shares: u16,
    group_display: String,
    group_pubkey: [u8; 32],
    recovered_nsec: Option<Zeroizing<String>>,
    clear_deadline: Option<Instant>,
    nsec_visible: bool,
    loading: bool,
    error: Option<String>,
}

impl State {
    pub fn new(
        threshold: u16,
        total_shares: u16,
        group_display: String,
        group_pubkey: [u8; 32],
    ) -> Self {
        let count = threshold as usize;
        Self {
            share_inputs: vec![Zeroizing::new(String::new()); count],
            passphrase_inputs: vec![Zeroizing::new(String::new()); count],
            vault_slot: false,
            threshold,
            total_shares,
            group_display,
            group_pubkey,
            recovered_nsec: None,
            clear_deadline: None,
            nsec_visible: false,
            loading: false,
            error: None,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::ShareInputChanged(i, val) => {
                if let Some(slot) = self.share_inputs.get_mut(i) {
                    *slot = val;
                }
                None
            }
            Message::PassphraseChanged(i, val) => {
                if let Some(slot) = self.passphrase_inputs.get_mut(i) {
                    *slot = val;
                }
                None
            }
            Message::AddShareInput => {
                if self.share_inputs.len() < self.total_shares as usize {
                    self.share_inputs.push(Zeroizing::new(String::new()));
                    self.passphrase_inputs.push(Zeroizing::new(String::new()));
                }
                None
            }
            Message::RemoveShareInput(i) => {
                let is_vault = self.vault_slot && i == 0;
                if self.share_inputs.len() > 1 && i < self.share_inputs.len() && !is_vault {
                    self.share_inputs.remove(i);
                    self.passphrase_inputs.remove(i);
                }
                None
            }
            Message::ScanShare(i) => {
                if i < self.share_inputs.len() {
                    Some(Event::ScanShare(i))
                } else {
                    None
                }
            }
            Message::Recover => {
                if !self.can_recover() {
                    return None;
                }
                self.clear_nsec();
                self.loading = true;
                self.error = None;
                Some(Event::Recover {
                    share_data: self.share_inputs.clone(),
                    passphrases: self.passphrase_inputs.clone(),
                    expected_group_pubkey: self.group_pubkey,
                })
            }
            Message::ToggleNsecVisibility => {
                self.nsec_visible = !self.nsec_visible;
                None
            }
            Message::CopyNsec => self
                .recovered_nsec
                .as_ref()
                .map(|nsec| Event::CopyToClipboard(nsec.clone())),
            Message::ClearNsec => {
                self.clear_nsec();
                None
            }
            Message::AutoClearTick => {
                if self.clear_deadline.is_some_and(|d| Instant::now() >= d) {
                    self.clear_nsec();
                }
                None
            }
            Message::GoBack => Some(Event::GoBack),
        }
    }

    fn can_recover(&self) -> bool {
        !self.loading
            && (self.share_inputs.len() as u16) >= self.threshold
            && self.share_inputs.iter().all(|s| !s.trim().is_empty())
            && self.passphrase_inputs.iter().all(|p| !p.is_empty())
    }

    fn clear_nsec(&mut self) {
        self.recovered_nsec = None;
        self.clear_deadline = None;
        self.nsec_visible = false;
    }

    pub fn has_active_timer(&self) -> bool {
        self.clear_deadline.is_some()
    }

    pub fn set_share_input(&mut self, slot: usize, data: Zeroizing<String>) {
        if let Some(input) = self.share_inputs.get_mut(slot) {
            *input = data;
        }
    }

    pub fn set_vault_share(&mut self, bech32: Zeroizing<String>, passphrase: Zeroizing<String>) {
        if !self.share_inputs.is_empty() {
            self.share_inputs[0] = bech32;
            self.passphrase_inputs[0] = passphrase;
            self.vault_slot = true;
        }
    }

    pub fn recovery_succeeded(&mut self, nsec: Zeroizing<String>) {
        self.recovered_nsec = Some(nsec);
        self.clear_deadline = Some(Instant::now() + Duration::from_secs(30));
        self.loading = false;
        self.vault_slot = false;
        self.error = None;
        for input in &mut self.share_inputs {
            *input = Zeroizing::new(String::new());
        }
        for input in &mut self.passphrase_inputs {
            *input = Zeroizing::new(String::new());
        }
    }

    pub fn recovery_failed(&mut self, error: String) {
        self.loading = false;
        self.error = Some(error);
    }

    pub fn view(&self) -> Element<'_, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::GoBack)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Recover nsec")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let warning = text(
            "Recovering combines threshold shares into a single private key. \
             This key is a single point of failure \u{2014} handle with extreme care. \
             It will not be saved.",
        )
        .size(theme::size::SMALL)
        .color(theme::color::ERROR);

        let info = text(format!(
            "Need {} of {} shares for {}",
            self.threshold, self.total_shares, self.group_display,
        ))
        .size(theme::size::BODY)
        .color(theme::color::TEXT_MUTED);

        let mut content = column![header, warning, info, Space::new().height(theme::space::SM)]
            .spacing(theme::space::XS);

        for i in 0..self.share_inputs.len() {
            let is_vault = self.vault_slot && i == 0;

            let label_text = if is_vault {
                format!("Share {} (from vault)", i + 1)
            } else {
                format!("Share {}", i + 1)
            };
            let label = text(label_text)
                .size(theme::size::SMALL)
                .color(if is_vault {
                    theme::color::SUCCESS
                } else {
                    theme::color::TEXT
                });

            let mut share_input = text_input("kshare1...", &self.share_inputs[i])
                .padding(theme::space::MD)
                .width(Length::Fill);
            if !is_vault {
                share_input =
                    share_input.on_input(move |s| Message::ShareInputChanged(i, Zeroizing::new(s)));
            }

            let mut pass_input = text_input("Passphrase", &self.passphrase_inputs[i])
                .secure(true)
                .padding(theme::space::MD)
                .width(Length::Fill);
            if !is_vault {
                pass_input =
                    pass_input.on_input(move |s| Message::PassphraseChanged(i, Zeroizing::new(s)));
            }

            let mut share_row = row![share_input, pass_input]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center);

            if !is_vault {
                let scan_btn = button(text("Scan").size(theme::size::SMALL))
                    .on_press(Message::ScanShare(i))
                    .style(theme::secondary_button)
                    .padding([theme::space::XS, theme::space::SM]);
                share_row = share_row.push(scan_btn);
            }

            if self.share_inputs.len() > 1 && !is_vault {
                let remove_btn = button(text("x").size(theme::size::SMALL))
                    .on_press(Message::RemoveShareInput(i))
                    .style(theme::text_button)
                    .padding([theme::space::XS, theme::space::SM]);
                share_row = share_row.push(remove_btn);
            }

            content = content.push(label).push(share_row);
        }

        let can_add = self.share_inputs.len() < self.total_shares as usize;
        if can_add {
            content = content.push(
                button(text("+ Add share").size(theme::size::SMALL))
                    .on_press(Message::AddShareInput)
                    .style(theme::text_button)
                    .padding([theme::space::XS, theme::space::SM]),
            );
        }

        content = content.push(Space::new().height(theme::space::MD));

        let can_recover = self.can_recover();

        if self.loading {
            content = content.push(theme::label("Recovering..."));
        } else {
            content = content.push(
                button(text("Recover").size(theme::size::BODY))
                    .on_press_maybe(can_recover.then_some(Message::Recover))
                    .style(theme::primary_button)
                    .padding(theme::space::MD),
            );
        }

        if let Some(nsec) = &self.recovered_nsec {
            let display: Cow<'_, str> = if self.nsec_visible {
                Cow::Borrowed(nsec.as_str())
            } else {
                Cow::Owned("\u{2022}".repeat(24))
            };

            let toggle_label = if self.nsec_visible { "Hide" } else { "Reveal" };
            let toggle_btn = button(text(toggle_label).size(theme::size::SMALL))
                .on_press(Message::ToggleNsecVisibility)
                .style(theme::text_button)
                .padding([theme::space::XS, theme::space::SM]);

            let copy_btn = button(text("Copy").size(theme::size::SMALL))
                .on_press(Message::CopyNsec)
                .style(theme::secondary_button)
                .padding([theme::space::XS, theme::space::SM]);

            let clear_btn = button(text("Clear").size(theme::size::SMALL))
                .on_press(Message::ClearNsec)
                .style(theme::danger_button)
                .padding([theme::space::XS, theme::space::SM]);

            let mut result_section = column![
                Space::new().height(theme::space::MD),
                theme::label("Recovered nsec"),
                text(display)
                    .size(theme::size::BODY)
                    .color(theme::color::SUCCESS),
                row![toggle_btn, copy_btn, clear_btn]
                    .spacing(theme::space::SM)
                    .align_y(Alignment::Center),
            ]
            .spacing(theme::space::XS);

            if let Some(deadline) = self.clear_deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let secs = remaining.as_secs();
                result_section = result_section.push(
                    text(format!(
                        "Auto-clears in {}s \u{2014} copy to a secure password manager",
                        secs
                    ))
                    .size(theme::size::SMALL)
                    .color(theme::color::WARNING),
                );
            }

            content = content.push(result_section);
        }

        if let Some(err) = &self.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
