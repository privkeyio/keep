// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

pub mod audit;
pub mod bunker;
pub mod error;
pub mod frost_signer;
pub mod handler;
pub mod permissions;
pub mod rate_limit;
pub mod server;
pub mod types;

pub use audit::{AuditAction, AuditEntry, AuditLog};
pub use bunker::generate_bunker_url;
pub use error::Result;
pub use frost_signer::{FrostSigner, NetworkFrostSigner};
pub use handler::SignerHandler;
pub use permissions::{AppPermission, Permission, PermissionManager};
pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use server::{Server, ServerConfig};
pub use types::{ApprovalRequest, LogEvent, ServerCallbacks};
