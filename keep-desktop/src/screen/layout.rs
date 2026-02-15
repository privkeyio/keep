// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, text, Space};
use iced::{Element, Length};

use crate::message::Message;
use crate::theme;

#[derive(PartialEq)]
pub enum NavItem {
    Shares,
    Create,
    Import,
    Wallets,
    Relay,
    Bunker,
    Audit,
    Settings,
}

enum NavBadge {
    None,
    Count(usize),
    Notification(usize),
}

pub fn with_sidebar_kill_switch<'a>(
    active: NavItem,
    content: Element<'a, Message>,
    share_count: Option<usize>,
    pending_requests: usize,
    kill_switch_active: bool,
) -> Element<'a, Message> {
    let relay_badge = if pending_requests > 0 {
        NavBadge::Notification(pending_requests)
    } else {
        NavBadge::None
    };
    let share_badge = match share_count {
        Some(n) => NavBadge::Count(n),
        None => NavBadge::None,
    };

    let nav_items: Vec<(&str, Message, NavItem, NavBadge)> = vec![
        (
            "Shares",
            Message::NavigateShares,
            NavItem::Shares,
            share_badge,
        ),
        (
            "Create",
            Message::GoToCreate,
            NavItem::Create,
            NavBadge::None,
        ),
        (
            "Import",
            Message::GoToImport,
            NavItem::Import,
            NavBadge::None,
        ),
        (
            "Wallets",
            Message::NavigateWallets,
            NavItem::Wallets,
            NavBadge::None,
        ),
        ("Relay", Message::NavigateRelay, NavItem::Relay, relay_badge),
        (
            "Bunker",
            Message::NavigateBunker,
            NavItem::Bunker,
            NavBadge::None,
        ),
        (
            "Audit",
            Message::NavigateAudit,
            NavItem::Audit,
            NavBadge::None,
        ),
        (
            "Settings",
            Message::NavigateSettings,
            NavItem::Settings,
            NavBadge::None,
        ),
    ];

    let mut nav = column![].spacing(theme::space::XS);
    for (label, msg, item, badge) in nav_items {
        let is_active = item == active;
        let style: fn(&iced::Theme, button::Status) -> button::Style = if is_active {
            theme::nav_button_active
        } else {
            theme::nav_button
        };

        let nav_label: Element<'a, Message> = match badge {
            NavBadge::Count(count) => row![
                text(label).size(theme::size::BODY),
                Space::new().width(Length::Fill),
                text(count.to_string())
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_DIM),
            ]
            .width(Length::Fill)
            .align_y(iced::Alignment::Center)
            .into(),
            NavBadge::Notification(count) => row![
                text(label).size(theme::size::BODY),
                Space::new().width(Length::Fill),
                container(
                    text(count.to_string())
                        .size(theme::size::TINY)
                        .color(iced::Color::WHITE),
                )
                .style(theme::notification_badge_style)
                .padding([1.0, 6.0]),
            ]
            .width(Length::Fill)
            .align_y(iced::Alignment::Center)
            .into(),
            NavBadge::None => text(label)
                .size(theme::size::BODY)
                .width(Length::Fill)
                .into(),
        };

        nav = nav.push(
            button(nav_label)
                .on_press_maybe((!is_active).then_some(msg))
                .style(style)
                .padding([theme::space::SM, theme::space::MD])
                .width(Length::Fill),
        );
    }

    let lock_btn = button(text("Lock").size(theme::size::BODY).width(Length::Fill))
        .on_press(Message::Lock)
        .style(theme::text_button)
        .padding([theme::space::SM, theme::space::MD])
        .width(Length::Fill);

    let mut sidebar_col = column![
        text("Keep")
            .size(theme::size::TITLE)
            .color(theme::color::TEXT),
        Space::new().height(theme::space::LG),
        nav,
    ]
    .padding(theme::space::LG)
    .height(Length::Fill);

    if kill_switch_active {
        let banner = container(
            text("SIGNING BLOCKED")
                .size(theme::size::TINY)
                .color(iced::Color::WHITE),
        )
        .style(theme::kill_switch_banner_style)
        .padding([theme::space::XS, theme::space::SM])
        .width(Length::Fill)
        .center_x(Length::Fill);

        sidebar_col = sidebar_col
            .push(Space::new().height(theme::space::SM))
            .push(banner);
    }

    sidebar_col = sidebar_col
        .push(Space::new().height(Length::Fill))
        .push(lock_btn);

    let sidebar = container(sidebar_col)
        .style(theme::sidebar_style)
        .width(theme::size::SIDEBAR_WIDTH)
        .height(Length::Fill);

    let main = container(content)
        .style(theme::page_bg)
        .width(Length::Fill)
        .height(Length::Fill);

    row![sidebar, main].into()
}
