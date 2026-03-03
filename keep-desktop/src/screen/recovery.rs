// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

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
    Recover,
    ToggleNsecVisibility,
    CopyNsec,
    ClearNsec,
    GoBack,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShareInputChanged(i, _) => f.debug_tuple("ShareInputChanged").field(i).finish(),
            Self::PassphraseChanged(i, _) => f.debug_tuple("PassphraseChanged").field(i).finish(),
            Self::AddShareInput => f.write_str("AddShareInput"),
            Self::RemoveShareInput(i) => f.debug_tuple("RemoveShareInput").field(i).finish(),
            Self::Recover => f.write_str("Recover"),
            Self::ToggleNsecVisibility => f.write_str("ToggleNsecVisibility"),
            Self::CopyNsec => f.write_str("CopyNsec"),
            Self::ClearNsec => f.write_str("ClearNsec"),
            Self::GoBack => f.write_str("GoBack"),
        }
    }
}

pub enum Event {
    GoBack,
    Recover {
        share_data: Vec<Zeroizing<String>>,
        passphrases: Vec<Zeroizing<String>>,
    },
    CopyToClipboard(Zeroizing<String>),
}

pub struct State {
    share_inputs: Vec<Zeroizing<String>>,
    passphrase_inputs: Vec<Zeroizing<String>>,
    threshold: u16,
    total_shares: u16,
    group_display: String,
    recovered_nsec: Option<Zeroizing<String>>,
    nsec_visible: bool,
    loading: bool,
    error: Option<String>,
}

impl State {
    pub fn new(threshold: u16, total_shares: u16, group_display: String) -> Self {
        let count = threshold as usize;
        Self {
            share_inputs: vec![Zeroizing::new(String::new()); count],
            passphrase_inputs: vec![Zeroizing::new(String::new()); count],
            threshold,
            total_shares,
            group_display,
            recovered_nsec: None,
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
                if self.share_inputs.len() > 1 {
                    if i < self.share_inputs.len() {
                        self.share_inputs.remove(i);
                        self.passphrase_inputs.remove(i);
                    }
                }
                None
            }
            Message::Recover => {
                if self.loading {
                    return None;
                }
                if (self.share_inputs.len() as u16) < self.threshold {
                    return None;
                }
                if self.share_inputs.iter().any(|s| s.trim().is_empty()) {
                    return None;
                }
                if self.passphrase_inputs.iter().any(|p| p.is_empty()) {
                    return None;
                }
                self.loading = true;
                self.error = None;
                Some(Event::Recover {
                    share_data: self.share_inputs.clone(),
                    passphrases: self.passphrase_inputs.clone(),
                })
            }
            Message::ToggleNsecVisibility => {
                self.nsec_visible = !self.nsec_visible;
                None
            }
            Message::CopyNsec => {
                if let Some(nsec) = &self.recovered_nsec {
                    Some(Event::CopyToClipboard(nsec.clone()))
                } else {
                    None
                }
            }
            Message::ClearNsec => {
                self.recovered_nsec = None;
                self.nsec_visible = false;
                None
            }
            Message::GoBack => Some(Event::GoBack),
        }
    }

    pub fn recovery_succeeded(&mut self, nsec: String) {
        self.recovered_nsec = Some(Zeroizing::new(nsec));
        self.loading = false;
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
            let label = text(format!("Share {}", i + 1))
                .size(theme::size::SMALL)
                .color(theme::color::TEXT);

            let idx = i;
            let share_input = text_input("kshare1...", &self.share_inputs[i])
                .on_input(move |s| Message::ShareInputChanged(idx, Zeroizing::new(s)))
                .padding(theme::space::MD)
                .width(Length::Fill);

            let idx = i;
            let pass_input = text_input("Passphrase", &self.passphrase_inputs[i])
                .on_input(move |s| Message::PassphraseChanged(idx, Zeroizing::new(s)))
                .secure(true)
                .padding(theme::space::MD)
                .width(Length::Fill);

            let mut share_row = row![share_input, pass_input]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center);

            if self.share_inputs.len() > 1 {
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

        let can_recover = !self.loading
            && self.share_inputs.len() >= self.threshold as usize
            && self.share_inputs.iter().all(|s| !s.trim().is_empty())
            && self.passphrase_inputs.iter().all(|p| !p.is_empty());

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
            let display = if self.nsec_visible {
                nsec.as_str().to_string()
            } else {
                "\u{2022}".repeat(24)
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

            let result_section = column![
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
