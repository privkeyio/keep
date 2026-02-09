// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, text, text_input, Space};
use iced::{Element, Length};
use zeroize::Zeroizing;

use crate::message::Message;
use crate::screen::layout::{self, NavItem};
use crate::theme;

pub struct ImportScreen {
    pub data: Zeroizing<String>,
    pub passphrase: Zeroizing<String>,
    pub error: Option<String>,
    pub loading: bool,
}

impl ImportScreen {
    pub fn new() -> Self {
        Self {
            data: Zeroizing::new(String::new()),
            passphrase: Zeroizing::new(String::new()),
            error: None,
            loading: false,
        }
    }

    pub fn view(&self) -> Element<Message> {
        let title = theme::heading("Import Share");

        let data_input = text_input("Paste kshare1... or JSON here", &self.data)
            .on_input(|s| Message::ImportDataChanged(Zeroizing::new(s)))
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
            title,
            Space::new().height(theme::space::XL),
            theme::label("Share data"),
            data_input,
        ]
        .spacing(theme::space::XS);

        let trimmed = self.data.trim();
        if !trimmed.is_empty() {
            if trimmed.starts_with("kshare1") {
                content = content.push(theme::success_text("Encrypted bech32 share detected"));
            } else if trimmed.starts_with('{') {
                content = content.push(theme::success_text("JSON format detected"));
            } else {
                content = content.push(theme::error_text("Expected kshare1... or JSON format"));
            }
        }

        content = content
            .push(Space::new().height(theme::space::MD))
            .push(theme::label("Passphrase"))
            .push(passphrase_input)
            .push(Space::new().height(theme::space::MD));

        if self.loading {
            content = content.push(theme::label("Importing..."));
        } else {
            let mut btn = button(text("Import").size(theme::size::BODY))
                .style(theme::primary_button)
                .padding(theme::space::MD);
            if can_import {
                btn = btn.on_press(Message::ImportShare);
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

        layout::with_sidebar(NavItem::Import, inner.into())
    }
}
