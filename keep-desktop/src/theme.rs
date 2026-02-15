// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, container, text};
use iced::{Background, Border, Color, Shadow, Theme, Vector};

pub mod color {
    use iced::Color;

    pub const BG: Color = Color::from_rgb(0.11, 0.11, 0.14);
    pub const SURFACE: Color = Color::from_rgb(0.16, 0.16, 0.20);
    pub const SURFACE_HOVER: Color = Color::from_rgb(0.20, 0.20, 0.25);
    pub const SIDEBAR: Color = Color::from_rgb(0.13, 0.13, 0.16);
    pub const PRIMARY: Color = Color::from_rgb(0.30, 0.65, 0.45);
    pub const PRIMARY_HOVER: Color = Color::from_rgb(0.35, 0.72, 0.50);
    pub const DANGER: Color = Color::from_rgb(0.80, 0.25, 0.25);
    pub const DANGER_HOVER: Color = Color::from_rgb(0.85, 0.30, 0.30);
    pub const TEXT: Color = Color::from_rgb(0.90, 0.90, 0.92);
    pub const TEXT_MUTED: Color = Color::from_rgb(0.55, 0.55, 0.58);
    pub const TEXT_DIM: Color = Color::from_rgb(0.40, 0.40, 0.43);
    pub const SUCCESS: Color = Color::from_rgb(0.25, 0.65, 0.35);
    pub const ERROR: Color = Color::from_rgb(0.80, 0.25, 0.25);
    pub const WARNING: Color = Color::from_rgb(0.85, 0.65, 0.20);
    pub const BORDER: Color = Color::from_rgb(0.25, 0.25, 0.30);
}

pub mod space {
    pub const XS: f32 = 4.0;
    pub const SM: f32 = 8.0;
    pub const MD: f32 = 12.0;
    pub const LG: f32 = 16.0;
    pub const XL: f32 = 20.0;
    pub const XXXL: f32 = 32.0;
}

pub mod size {
    pub const TITLE: f32 = 22.0;
    pub const HEADING: f32 = 18.0;
    pub const BODY: f32 = 14.0;
    pub const SMALL: f32 = 12.0;
    pub const TINY: f32 = 11.0;
    pub const SIDEBAR_WIDTH: f32 = 180.0;
    pub const INPUT_WIDTH: f32 = 400.0;
}

pub fn card_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(color::SURFACE)),
        border: Border {
            color: color::BORDER,
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: Color::BLACK,
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        text_color: Some(color::TEXT),
        snap: false,
    }
}

pub fn sidebar_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(color::SIDEBAR)),
        ..Default::default()
    }
}

pub fn page_bg(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(color::BG)),
        ..Default::default()
    }
}

pub fn primary_button(theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(Background::Color(color::PRIMARY)),
        text_color: Color::WHITE,
        border: Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..button::primary(theme, status)
    };
    match status {
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(color::PRIMARY_HOVER)),
            ..base
        },
        button::Status::Disabled => button::Style {
            background: Some(Background::Color(color::BORDER)),
            text_color: color::TEXT_DIM,
            ..base
        },
        _ => base,
    }
}

pub fn secondary_button(theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(Background::Color(color::SURFACE)),
        text_color: color::TEXT,
        border: Border {
            color: color::BORDER,
            width: 1.0,
            radius: 6.0.into(),
        },
        ..button::secondary(theme, status)
    };
    match status {
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(color::SURFACE_HOVER)),
            ..base
        },
        button::Status::Disabled => button::Style {
            text_color: color::TEXT_DIM,
            ..base
        },
        _ => base,
    }
}

pub fn danger_button(theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(Background::Color(color::DANGER)),
        text_color: Color::WHITE,
        border: Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..button::primary(theme, status)
    };
    match status {
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(color::DANGER_HOVER)),
            ..base
        },
        button::Status::Disabled => button::Style {
            background: Some(Background::Color(color::BORDER)),
            text_color: color::TEXT_DIM,
            ..base
        },
        _ => base,
    }
}

pub fn nav_button(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Some(Background::Color(color::SURFACE_HOVER)),
        _ => None,
    };
    button::Style {
        background: bg,
        text_color: color::TEXT_MUTED,
        border: Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn nav_button_active(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => color::SURFACE_HOVER,
        _ => color::SURFACE,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: color::PRIMARY,
        border: Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn text_button(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: None,
        text_color: match status {
            button::Status::Hovered => color::TEXT,
            button::Status::Disabled => color::TEXT_DIM,
            _ => color::TEXT_MUTED,
        },
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn heading(s: &str) -> text::Text {
    text(s).size(size::HEADING).color(color::TEXT)
}

pub fn label(s: &str) -> text::Text {
    text(s).size(size::BODY).color(color::TEXT)
}

pub fn muted(s: &str) -> text::Text {
    text(s).size(size::SMALL).color(color::TEXT_MUTED)
}

pub fn error_text(s: &str) -> text::Text {
    text(s).size(size::BODY).color(color::ERROR)
}

pub fn success_text(s: &str) -> text::Text {
    text(s).size(size::BODY).color(color::SUCCESS)
}

pub fn warning_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.80, 0.25, 0.25, 0.10))),
        border: Border {
            color: color::ERROR,
            width: 1.0,
            radius: 6.0.into(),
        },
        text_color: Some(color::ERROR),
        ..Default::default()
    }
}

pub fn notification_badge_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(color::ERROR)),
        border: Border {
            radius: 8.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn badge_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.30, 0.65, 0.45, 0.15))),
        border: Border {
            color: color::PRIMARY,
            width: 1.0,
            radius: 12.0.into(),
        },
        text_color: Some(color::PRIMARY),
        ..Default::default()
    }
}

pub fn active_card_style(theme: &Theme) -> container::Style {
    container::Style {
        border: Border {
            color: color::PRIMARY,
            width: 2.0,
            radius: 8.0.into(),
        },
        ..card_style(theme)
    }
}

pub fn active_badge(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(color::PRIMARY)),
        border: Border {
            radius: 12.0.into(),
            ..Default::default()
        },
        text_color: Some(Color::WHITE),
        ..Default::default()
    }
}

pub fn kill_switch_card_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.80, 0.25, 0.25, 0.10))),
        border: Border {
            color: color::DANGER,
            width: 2.0,
            radius: 8.0.into(),
        },
        text_color: Some(color::TEXT),
        ..Default::default()
    }
}

pub fn kill_switch_badge_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(color::DANGER)),
        border: Border {
            radius: 8.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn kill_switch_banner_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(color::DANGER)),
        ..Default::default()
    }
}
