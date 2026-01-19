// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hidden volume support for plausible deniability.
//!
//! This module provides encrypted storage with an optional hidden volume
//! that is cryptographically indistinguishable from random data.

mod header;
pub mod volume;

pub use volume::{HiddenStorage, VolumeType};
