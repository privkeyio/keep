#![forbid(unsafe_code)]

pub mod client;
pub mod entropy;
pub mod error;
pub mod frost;
pub mod manager;
pub mod rate_limit;
pub mod scope;
pub mod session;

#[cfg(feature = "mcp")]
pub mod mcp;

pub use client::{AgentClient, ApprovalStatus, PendingSession};
pub use entropy::{get_entropy, is_nitro_enclave};
pub use error::{AgentError, Result};
pub use frost::{FrostCommitment, FrostCoordinator, FrostParticipant, FrostSignatureShare};
pub use manager::SessionManager;
pub use rate_limit::{RateLimitConfig, RateLimitStatus, RateLimiter};
pub use scope::{Operation, SessionScope};
pub use session::{AgentSession, SessionConfig, SessionInfo, SessionMetadata, SessionToken};
