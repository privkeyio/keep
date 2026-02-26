// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Element, Length};

use crate::message::{Identity, IdentityKind, Message};
use crate::theme;

fn identity_color(pubkey_hex: &str) -> iced::Color {
    let bytes: Vec<u8> = (0..6.min(pubkey_hex.len()))
        .step_by(2)
        .filter_map(|i| {
            pubkey_hex
                .get(i..i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();
    let r = *bytes.first().unwrap_or(&128);
    let g = *bytes.get(1).unwrap_or(&128);
    let b = *bytes.get(2).unwrap_or(&128);
    let lum = 0.299 * r as f32 + 0.587 * g as f32 + 0.114 * b as f32;
    let boost = if lum < 100.0 { 0.3 } else { 0.0 };
    iced::Color::from_rgb(
        (r as f32 / 255.0 + boost).min(1.0),
        (g as f32 / 255.0 + boost).min(1.0),
        (b as f32 / 255.0 + boost).min(1.0),
    )
}

#[derive(PartialEq)]
pub enum NavItem {
    Shares,
    NsecKeys,
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

pub struct SidebarState<'a> {
    pub identities: &'a [Identity],
    pub active_identity: Option<&'a str>,
    pub switcher_open: bool,
    pub delete_confirm: Option<&'a str>,
}

pub fn with_sidebar<'a>(
    active: NavItem,
    content: Element<'a, Message>,
    sidebar_state: &SidebarState<'a>,
    share_count: Option<usize>,
    nsec_count: Option<usize>,
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
    let nsec_badge = match nsec_count {
        Some(n) => NavBadge::Count(n),
        None => NavBadge::None,
    };

    let nav_items: Vec<(&str, Message, NavItem, NavBadge)> = vec![
        (
            "FROST Shares",
            Message::NavigateShares,
            NavItem::Shares,
            share_badge,
        ),
        (
            "Nsec Keys",
            Message::NavigateNsecKeys,
            NavItem::NsecKeys,
            nsec_badge,
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

    let identity_section = identity_switcher(sidebar_state);

    let mut sidebar_col = column![
        text("Keep")
            .size(theme::size::TITLE)
            .color(theme::color::TEXT),
        identity_section,
        Space::new().height(theme::space::SM),
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

fn identity_switcher<'a>(state: &SidebarState<'a>) -> Element<'a, Message> {
    if state.identities.is_empty() {
        return Space::new().height(0).into();
    }

    let active = state
        .identities
        .iter()
        .find(|i| state.active_identity == Some(i.pubkey_hex.as_str()));

    let toggle_label = match active {
        Some(id) => {
            let kind_tag = match &id.kind {
                IdentityKind::Frost { .. } => "FROST",
                IdentityKind::Nsec => "nsec",
            };
            column![
                text(&id.name)
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT),
                text(format!("{} {}", kind_tag, id.truncated_npub()))
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
            ]
            .spacing(1.0)
        }
        None => column![text("No identity")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED),],
    };

    let arrow = if state.switcher_open { "v" } else { ">" };
    let toggle_btn = button(
        row![
            toggle_label,
            Space::new().width(Length::Fill),
            text(arrow)
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM),
        ]
        .align_y(iced::Alignment::Center)
        .width(Length::Fill),
    )
    .on_press(Message::ToggleIdentitySwitcher)
    .style(theme::text_button)
    .padding([theme::space::XS, theme::space::SM])
    .width(Length::Fill);

    if !state.switcher_open {
        return toggle_btn.into();
    }

    let mut list = column![].spacing(2.0);
    for id in state.identities {
        let is_active = state.active_identity == Some(id.pubkey_hex.as_str());
        let is_deleting = state.delete_confirm == Some(id.pubkey_hex.as_str());

        if is_deleting {
            let confirm_row = column![
                text(format!("Delete '{}'?", id.name))
                    .size(theme::size::TINY)
                    .color(theme::color::ERROR),
                row![
                    button(text("Yes").size(theme::size::TINY))
                        .on_press(Message::ConfirmDeleteIdentity(id.pubkey_hex.clone()))
                        .style(theme::danger_button)
                        .padding([2.0, theme::space::SM]),
                    button(text("No").size(theme::size::TINY))
                        .on_press(Message::CancelDeleteIdentity)
                        .style(theme::secondary_button)
                        .padding([2.0, theme::space::SM]),
                ]
                .spacing(theme::space::XS),
            ]
            .spacing(2.0);
            list = list.push(
                container(confirm_row)
                    .padding([theme::space::XS, theme::space::SM])
                    .width(Length::Fill),
            );
            continue;
        }

        let kind_tag = match &id.kind {
            IdentityKind::Frost {
                threshold,
                total_shares,
                ..
            } => format!("{threshold}-of-{total_shares}"),
            IdentityKind::Nsec => "nsec".into(),
        };

        let name_col = column![
            text(&id.name).size(theme::size::TINY).color(if is_active {
                theme::color::PRIMARY
            } else {
                theme::color::TEXT
            }),
            text(kind_tag).size(9.0).color(theme::color::TEXT_DIM),
        ]
        .spacing(0.0);

        let dot_color = identity_color(&id.pubkey_hex);
        let mut item_row = row![].align_y(iced::Alignment::Center).width(Length::Fill);

        item_row = item_row.push(text("\u{25CF}").size(theme::size::TINY).color(dot_color));
        item_row = item_row.push(Space::new().width(4.0));

        item_row = item_row.push(name_col);
        item_row = item_row.push(Space::new().width(Length::Fill));

        if id.kind == IdentityKind::Nsec {
            item_row = item_row.push(
                button(text("ncryptsec").size(9.0))
                    .on_press(Message::GoToExportNcryptsec(id.pubkey_hex.clone()))
                    .style(theme::secondary_button)
                    .padding([1.0, 4.0]),
            );
            item_row = item_row.push(Space::new().width(2.0));
        }

        if !is_active && state.identities.len() > 1 {
            item_row = item_row.push(
                button(text("x").size(9.0))
                    .on_press(Message::RequestDeleteIdentity(id.pubkey_hex.clone()))
                    .style(theme::text_button)
                    .padding([0.0, 2.0]),
            );
        }

        let style: fn(&iced::Theme, button::Status) -> button::Style = if is_active {
            theme::nav_button_active
        } else {
            theme::nav_button
        };

        let switch_btn = button(item_row)
            .on_press_maybe((!is_active).then(|| Message::SwitchIdentity(id.pubkey_hex.clone())))
            .style(style)
            .padding([theme::space::XS, theme::space::SM])
            .width(Length::Fill);

        list = list.push(switch_btn);
    }

    let identity_list =
        container(scrollable(list).height(Length::Fill).width(Length::Fill)).max_height(200.0);

    column![toggle_btn, identity_list].spacing(2.0).into()
}
