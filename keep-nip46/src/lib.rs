// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

pub mod audit;
pub mod bunker;
pub mod client;
pub mod error;
pub mod frost_signer;
pub mod handler;
#[cfg(unix)]
pub mod local_server;
pub mod permissions;
pub mod rate_limit;
pub mod server;
pub mod types;

pub use audit::{AuditAction, AuditEntry, AuditLog};
pub use bunker::{
    generate_bunker_url, parse_bunker_url, parse_nostrconnect_uri, NostrConnectRequest,
};
pub use client::{
    contains_control_chars, DeviceInfo, DeviceKind, Nip46Client, RegisterWalletResponse,
    GET_DEVICE_INFO_TIMEOUT, MAX_CAPABILITIES, MAX_CAPABILITY_LEN, MAX_DESCRIPTOR_LEN,
    MAX_DEVICE_INFO_JSON_LEN, MAX_DEVICE_KIND_LEN, MAX_FIRMWARE_VERSION_LEN, MAX_WALLET_NAME_LEN,
};
pub use error::Result;
pub use frost_signer::{FrostSigner, NetworkFrostSigner};
pub use handler::SignerHandler;
#[cfg(unix)]
pub use local_server::{LocalServer, LocalServerConfig};
pub use permissions::{AppPermission, Permission, PermissionDuration, PermissionManager};
pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use server::{Server, ServerConfig};
pub use types::{ApprovalRequest, LogEvent, ServerCallbacks};
