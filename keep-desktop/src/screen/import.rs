// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::message::Message;

pub struct ImportScreen {
    pub data: String,
    pub passphrase: Zeroizing<String>,
    pub error: Option<String>,
    pub loading: bool,
}

impl ImportScreen {
    pub fn new() -> Self {
        Self {
            data: String::new(),
            passphrase: Zeroizing::new(String::new()),
            error: None,
            loading: false,
        }
    }

    pub fn view(&self) -> Element<Message> {
        let back_btn = button(text("< Back")).on_press(Message::GoBack).padding(8);
        let title = text("Import Share").size(24);

        let header = row![back_btn, Space::with_width(10), title].align_y(Alignment::Center);

        let data_input = text_input("Paste kshare1... or JSON here", &self.data)
            .on_input(Message::ImportDataChanged)
            .padding(10)
            .width(Length::Fill);

        let passphrase_input = text_input("Decryption passphrase", &self.passphrase)
            .on_input(|s| Message::ImportPassphraseChanged(Zeroizing::new(s)))
            .on_submit(Message::ImportShare)
            .secure(true)
            .padding(10)
            .width(400);

        let can_import = !self.data.is_empty() && !self.passphrase.is_empty();

        let mut content = column![
            header,
            Space::with_height(20),
            text("Share data").size(14),
            data_input,
            Space::with_height(10),
            text("Passphrase").size(14),
            passphrase_input,
            Space::with_height(10),
        ]
        .spacing(5);

        if self.loading {
            content = content.push(text("Importing...").size(14));
        } else {
            let mut btn = button(text("Import")).padding(10);
            if can_import {
                btn = btn.on_press(Message::ImportShare);
            }
            content = content.push(btn);
        }

        if let Some(err) = &self.error {
            content = content.push(
                text(err.as_str())
                    .size(14)
                    .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
            );
        }

        container(content)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
