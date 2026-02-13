// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
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
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::GoBack)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Import Share")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text("Paste a share exported from Keep Desktop or Keep Android")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let data_input = text_input("Paste kshare1... or JSON here", &self.data)
            .on_input(|s| Message::ImportDataChanged(Zeroizing::new(s)))
            .padding(theme::space::MD)
            .width(Length::Fill);

        let trimmed_data = self.data.trim();
        let recognized_format =
            trimmed_data.starts_with("kshare1") || trimmed_data.starts_with('{');
        let can_import = recognized_format && !self.passphrase.is_empty();

        let passphrase_input = text_input("Decryption passphrase", &self.passphrase)
            .on_input(|s| Message::ImportPassphraseChanged(Zeroizing::new(s)))
            .on_submit_maybe(can_import.then_some(Message::ImportShare))
            .secure(true)
            .padding(theme::space::MD)
            .width(theme::size::INPUT_WIDTH);

        let mut content = column![
            header,
            subtitle,
            Space::new().height(theme::space::LG),
            theme::label("Share data"),
            data_input,
        ]
        .spacing(theme::space::XS);

        if !trimmed_data.is_empty() {
            if trimmed_data.starts_with("kshare1") {
                content = content.push(theme::success_text("Encrypted bech32 share detected"));
            } else if trimmed_data.starts_with('{') {
                content = content.push(theme::success_text("JSON format detected"));
            } else {
                content = content.push(theme::error_text("Expected kshare1... or JSON format"));
            }
        } else {
            content = content.push(
                text("Accepts kshare1... (bech32) or JSON format")
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
            );
        }

        content = content
            .push(Space::new().height(theme::space::MD))
            .push(theme::label("Passphrase"))
            .push(
                text("Enter the passphrase used when exporting the share")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            )
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

        layout::with_sidebar(NavItem::Import, inner.into(), None, 0)
    }
}
