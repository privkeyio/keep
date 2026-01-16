//! Hidden volume support for plausible deniability.
//!
//! This module provides encrypted storage with an optional hidden volume
//! that is cryptographically indistinguishable from random data.

pub(crate) mod header;
pub mod volume;

pub use header::{DATA_START_OFFSET, HEADER_SIZE, HIDDEN_HEADER_OFFSET};
pub use volume::{HiddenStorage, VolumeType};
