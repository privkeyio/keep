#![forbid(unsafe_code)]

mod server;
mod tools;

pub use server::McpServer;
pub use tools::{ToolDefinition, ToolResult};
