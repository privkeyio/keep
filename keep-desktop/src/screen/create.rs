// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::screen::layout::{self, NavItem};
use crate::theme;

pub struct CreateScreen {
    pub name: String,
    pub threshold: String,
    pub total: String,
    pub error: Option<String>,
    pub loading: bool,
}

impl CreateScreen {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            threshold: "2".into(),
            total: "3".into(),
            error: None,
            loading: false,
        }
    }

    pub fn view(&self) -> Element<Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::GoBack)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Create Keyset")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle =
            text("Generate a new FROST threshold signing keyset to distribute across your devices")
                .size(theme::size::SMALL)
                .color(theme::color::TEXT_MUTED);

        let name_input = text_input("Keyset name (e.g. my-keyset)", &self.name)
            .on_input(Message::CreateNameChanged)
            .padding(theme::space::MD)
            .width(theme::size::INPUT_WIDTH);

        let threshold_input = text_input("2", &self.threshold)
            .on_input(Message::CreateThresholdChanged)
            .padding(theme::space::MD)
            .width(80);

        let total_input = text_input("3", &self.total)
            .on_input(Message::CreateTotalChanged)
            .padding(theme::space::MD)
            .width(80);

        let threshold_row = row![
            theme::label("Threshold:"),
            threshold_input,
            theme::label("of"),
            total_input,
            theme::label("shares"),
        ]
        .spacing(theme::space::SM)
        .align_y(Alignment::Center);

        let name_valid = !self.name.is_empty() && self.name.len() <= 64;
        let threshold_val: Option<u16> = self
            .threshold
            .parse()
            .ok()
            .filter(|v| (2..=255).contains(v));
        let total_val: Option<u16> = self.total.parse().ok().filter(|&v| v <= 255);
        let total_valid = matches!((threshold_val, total_val), (Some(t), Some(n)) if n >= t);
        let can_create = name_valid && threshold_val.is_some() && total_valid;

        let mut content = column![
            header,
            subtitle,
            Space::new().height(theme::space::LG),
            theme::label("Name"),
            name_input,
            Space::new().height(theme::space::MD),
            theme::label("Signing Threshold"),
            threshold_row,
        ]
        .spacing(theme::space::XS);

        if self.name.len() > 64 {
            content = content.push(theme::error_text("Name must be 64 characters or fewer"));
        }
        if !self.threshold.is_empty() && threshold_val.is_none() {
            content = content.push(theme::error_text("Threshold must be between 2 and 255"));
        }
        if !self.total.is_empty() {
            let total_error = match total_val {
                None => Some("Total must be a number between 1 and 255"),
                Some(n) if threshold_val.is_some_and(|t| n < t) => {
                    Some("Total must be >= threshold")
                }
                _ => None,
            };
            if let Some(msg) = total_error {
                content = content.push(theme::error_text(msg));
            }
        }

        if let (Some(t), Some(n)) = (threshold_val, total_val) {
            if n >= t {
                let summary = format!(
                    "Any {t} of {n} devices can sign together. You'll need to export each share to a separate device."
                );
                content = content.push(
                    container(
                        text(summary)
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT),
                    )
                    .style(theme::badge_style)
                    .padding(theme::space::MD)
                    .width(theme::size::INPUT_WIDTH),
                );
            }
        } else {
            content = content.push(
                theme::muted("Choose how many devices are needed to sign (threshold) out of the total number of shares."),
            );
        }

        content = content.push(Space::new().height(theme::space::SM));

        if self.loading {
            content = content.push(theme::label("Generating keyset..."));
        } else {
            let mut btn = button(text("Create Keyset").size(theme::size::BODY))
                .style(theme::primary_button)
                .padding(theme::space::MD);
            if can_create {
                btn = btn.on_press(Message::CreateKeyset);
            }
            content = content.push(btn);
        }

        if let Some(err) = &self.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        let inner = container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill);

        layout::with_sidebar(NavItem::Create, inner.into(), None)
    }
}
