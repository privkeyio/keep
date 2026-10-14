// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Using vault secrets without revealing them: the grants that say where a
//! secret may be sent, and the checks on each request and response.

pub mod addr;
pub mod rule;
pub mod scan;
pub mod wire;
#[cfg(all(feature = "mcp", target_os = "linux"))]
pub mod worker;
