use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod security;
pub mod certgen;

/// Shared encryption key for all clients and server
/// In production, this should be securely distributed
pub const SHARED_ENCRYPTION_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Message types that can be sent between client and server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Client registration with user ID
    Register { user_id: String },
    /// Registration response
    RegisterResponse { success: bool, error: Option<String> },
    /// Chat message to specific user (encrypted)
    ChatMessage {
        from: String,
        to: String,
        encrypted_content: String,
        timestamp: DateTime<Utc>,
    },
    /// Broadcast message to all users (encrypted)
    BroadcastMessage {
        from: String,
        encrypted_content: String,
        timestamp: DateTime<Utc>,
    },
    /// Typing indicator
    TypingIndicator { from: String, to: String },
    /// User list request
    ListUsers,
    /// User list response
    UserListResponse { users: Vec<String> },
    /// Error message
    Error { message: String },
    /// Disconnect notification
    Disconnect { user_id: String },
}

impl Message {
    /// Serialize message to JSON string
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Deserialize message from JSON string
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Client information stored on server
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub user_id: String,
    pub sender: tokio::sync::mpsc::UnboundedSender<Message>,
}

/// Server configuration
pub const DEFAULT_PORT: u16 = 8000;
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// Security constants
pub const MAX_MESSAGE_LENGTH: usize = 1000;
pub const MAX_USER_ID_LENGTH: usize = 20;
pub const MIN_USER_ID_LENGTH: usize = 3;
pub const RATE_LIMIT_REQUESTS: usize = 10;
pub const RATE_LIMIT_WINDOW_SECONDS: u64 = 60;