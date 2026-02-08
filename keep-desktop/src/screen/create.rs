// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;

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
        let back_btn = button(text("< Back")).on_press(Message::GoBack).padding(8);
        let title = text("Create Keyset").size(24);
        let header = row![back_btn, Space::new().width(10), title].align_y(Alignment::Center);

        let name_input = text_input("Keyset name (e.g. my-keyset)", &self.name)
            .on_input(Message::CreateNameChanged)
            .padding(10)
            .width(400);

        let threshold_input = text_input("2", &self.threshold)
            .on_input(Message::CreateThresholdChanged)
            .padding(10)
            .width(80);

        let total_input = text_input("3", &self.total)
            .on_input(Message::CreateTotalChanged)
            .on_submit(Message::CreateKeyset)
            .padding(10)
            .width(80);

        let threshold_row = row![
            text("Threshold:").size(14),
            threshold_input,
            text("of").size(14),
            total_input,
            text("shares").size(14),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let hint = text("A 2-of-3 keyset means any 2 of 3 devices can sign together.")
            .size(12)
            .color(iced::Color::from_rgb(0.5, 0.5, 0.5));

        let name_valid = !self.name.is_empty() && self.name.len() <= 64;
        let threshold_val: Option<u16> = self
            .threshold
            .parse()
            .ok()
            .filter(|v| (2..=255).contains(v));
        let total_val: Option<u16> = self.total.parse().ok().filter(|&v| v <= 255);
        let total_valid = matches!((threshold_val, total_val), (Some(t), Some(n)) if n >= t);
        let can_create = name_valid && threshold_val.is_some() && total_valid;

        let error_color = iced::Color::from_rgb(0.8, 0.2, 0.2);

        let mut content = column![
            header,
            Space::new().height(20),
            text("Name").size(14),
            name_input,
            Space::new().height(10),
            threshold_row,
        ]
        .spacing(5);

        if self.name.len() > 64 {
            content = content.push(
                text("Name must be 64 characters or fewer")
                    .size(12)
                    .color(error_color),
            );
        }
        if !self.threshold.is_empty() && threshold_val.is_none() {
            content = content.push(
                text("Threshold must be between 2 and 255")
                    .size(12)
                    .color(error_color),
            );
        }
        if !self.total.is_empty() {
            let total_error = if total_val.is_some() && !total_valid {
                Some("Total must be >= threshold")
            } else if total_val.is_none() && self.total.parse::<u16>().is_ok() {
                Some("Total must be 255 or fewer")
            } else if total_val.is_none() {
                Some("Total must be a valid number")
            } else {
                None
            };
            if let Some(msg) = total_error {
                content = content.push(text(msg).size(12).color(error_color));
            }
        }

        content = content.push(hint);
        content = content.push(Space::new().height(10));

        if self.loading {
            content = content.push(text("Generating keyset...").size(14));
        } else {
            let mut btn = button(text("Create Keyset")).padding(10);
            if can_create {
                btn = btn.on_press(Message::CreateKeyset);
            }
            content = content.push(btn);
        }

        if let Some(err) = &self.error {
            content = content.push(text(err.as_str()).size(14).color(error_color));
        }

        container(content)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
