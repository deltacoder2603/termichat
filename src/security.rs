use anyhow::{Context, Result};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use base64::{Engine as _, engine::general_purpose};
use bcrypt::{hash, verify, DEFAULT_COST};
use rand::RngCore;
use regex::Regex;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;


/// Security configuration
pub struct SecurityConfig {
    pub encryption_key: [u8; 32],
    pub tls_config: Option<ServerConfig>,
}

impl SecurityConfig {
    /// Create a new security configuration
    pub fn new() -> Result<Self> {
        let mut encryption_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut encryption_key);
        
        Ok(Self {
            encryption_key,
            tls_config: None,
        })
    }

    /// Load TLS configuration from certificate files
    pub fn with_tls(mut self, cert_path: &str, key_path: &str) -> Result<Self> {
        let cert_file = File::open(cert_path)
            .context("Failed to open certificate file")?;
        let key_file = File::open(key_path)
            .context("Failed to open private key file")?;

        let mut cert_reader = BufReader::new(cert_file);
        let mut key_reader = BufReader::new(key_file);

        let cert_chain = certs(&mut cert_reader)
            .context("Failed to read certificate chain")?
            .into_iter()
            .map(Certificate)
            .collect();

        let mut keys = pkcs8_private_keys(&mut key_reader)
            .context("Failed to read private key")?;

        if keys.is_empty() {
            return Err(anyhow::anyhow!("No private keys found"));
        }

        let key = PrivateKey(keys.remove(0));

        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("Failed to create TLS configuration")?;

        self.tls_config = Some(tls_config);
        Ok(self)
    }
}

/// Message encryption utilities
#[derive(Clone)]
pub struct MessageEncryption {
    cipher: Aes256Gcm,
}

impl MessageEncryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    /// Encrypt a message
    pub fn encrypt(&self, message: &str) -> Result<String> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, message.as_bytes())
            .map_err(|_| anyhow::anyhow!("Failed to encrypt message"))?;

        let mut combined = Vec::new();
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(general_purpose::STANDARD.encode(combined))
    }

    /// Decrypt a message
    pub fn decrypt(&self, encrypted_message: &str) -> Result<String> {
        let combined = general_purpose::STANDARD
            .decode(encrypted_message)
            .context("Failed to decode base64")?;

        if combined.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted message format"));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Failed to decrypt message"))?;

        String::from_utf8(plaintext)
            .context("Failed to convert decrypted data to string")
    }
}

/// Input validation utilities
#[derive(Debug)]
pub struct InputValidator {
    user_id_regex: Regex,
    message_regex: Regex,
}

impl InputValidator {
    pub fn new() -> Self {
        Self {
            user_id_regex: Regex::new(r"^[a-zA-Z0-9_-]{3,20}$").unwrap(),
            message_regex: Regex::new(r"^[\x20-\x7E]{1,1000}$").unwrap(),
        }
    }

    /// Validate user ID
    pub fn validate_user_id(&self, user_id: &str) -> Result<()> {
        if !self.user_id_regex.is_match(user_id) {
            return Err(anyhow::anyhow!(
                "User ID must be 3-20 characters long and contain only letters, numbers, underscores, and hyphens"
            ));
        }
        Ok(())
    }

    /// Validate message content
    pub fn validate_message(&self, message: &str) -> Result<()> {
        if message.is_empty() {
            return Err(anyhow::anyhow!("Message cannot be empty"));
        }

        if !self.message_regex.is_match(message) {
            return Err(anyhow::anyhow!(
                "Message contains invalid characters or is too long (max 1000 characters)"
            ));
        }

        // Check for potential injection patterns
        let dangerous_patterns = [
            "javascript:", "data:", "vbscript:", "onload=", "onerror=",
            "<script", "</script>", "eval(", "document.cookie",
        ];

        let lower_message = message.to_lowercase();
        for pattern in &dangerous_patterns {
            if lower_message.contains(pattern) {
                return Err(anyhow::anyhow!("Message contains potentially dangerous content"));
            }
        }

        Ok(())
    }

    /// Sanitize user input
    pub fn sanitize_input(&self, input: &str) -> String {
        // Remove null bytes and control characters
        input
            .chars()
            .filter(|&c| c != '\0' && !c.is_control())
            .collect()
    }
}

/// Password utilities
pub struct PasswordUtils;

impl PasswordUtils {
    /// Hash a password
    pub fn hash_password(password: &str) -> Result<String> {
        hash(password, DEFAULT_COST)
            .context("Failed to hash password")
    }

    /// Verify a password against a hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
        verify(password, hash)
            .context("Failed to verify password")
    }

    /// Validate password strength
    pub fn validate_password(password: &str) -> Result<()> {
        if password.len() < 8 {
            return Err(anyhow::anyhow!("Password must be at least 8 characters long"));
        }

        if password.len() > 128 {
            return Err(anyhow::anyhow!("Password is too long (max 128 characters)"));
        }

        // Check for common weak passwords
        let weak_passwords = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "hello",
        ];

        let lower_password = password.to_lowercase();
        for weak in &weak_passwords {
            if lower_password == *weak {
                return Err(anyhow::anyhow!("Password is too common"));
            }
        }

        Ok(())
    }
}

/// Rate limiting utilities
#[derive(Debug)]
pub struct RateLimiter {
    requests: std::collections::HashMap<String, Vec<std::time::Instant>>,
    max_requests: usize,
    window_duration: std::time::Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: std::collections::HashMap::new(),
            max_requests,
            window_duration: std::time::Duration::from_secs(window_seconds),
        }
    }

    /// Check if a request is allowed
    pub fn is_allowed(&mut self, identifier: &str) -> bool {
        let now = std::time::Instant::now();
        let window_start = now - self.window_duration;

        let requests = self.requests.entry(identifier.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        requests.retain(|&time| time >= window_start);

        if requests.len() < self.max_requests {
            requests.push(now);
            true
        } else {
            false
        }
    }
} 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encryption() {
        let encryption = MessageEncryption::new(&[1u8; 32]);
        let message = "Hello, secure world!";
        
        let encrypted = encryption.encrypt(message).unwrap();
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_input_validation() {
        let validator = InputValidator::new();
        
        // Valid user IDs
        assert!(validator.validate_user_id("alice").is_ok());
        assert!(validator.validate_user_id("user123").is_ok());
        assert!(validator.validate_user_id("test_user").is_ok());
        
        // Invalid user IDs
        assert!(validator.validate_user_id("ab").is_err()); // too short
        assert!(validator.validate_user_id("very_long_username_that_exceeds_limit").is_err()); // too long
        assert!(validator.validate_user_id("user@name").is_err()); // invalid character
        
        // Valid messages
        assert!(validator.validate_message("Hello, world!").is_ok());
        assert!(validator.validate_message("Test message 123").is_ok());
        
        // Invalid messages
        assert!(validator.validate_message("").is_err()); // empty
        assert!(validator.validate_message(&"x".repeat(1001)).is_err()); // too long
        assert!(validator.validate_message("Hello\x00world").is_err()); // null byte
    }

    #[test]
    fn test_password_validation() {
        // Valid passwords
        assert!(PasswordUtils::validate_password("password123").is_ok());
        assert!(PasswordUtils::validate_password("MySecurePass!").is_ok());
        
        // Invalid passwords
        assert!(PasswordUtils::validate_password("123").is_err()); // too short
        assert!(PasswordUtils::validate_password("password").is_err()); // too common
        assert!(PasswordUtils::validate_password(&"x".repeat(129)).is_err()); // too long
    }

    #[test]
    fn test_rate_limiting() {
        let mut limiter = RateLimiter::new(3, 1); // 3 requests per second
        
        // Should allow first 3 requests
        assert!(limiter.is_allowed("user1"));
        assert!(limiter.is_allowed("user1"));
        assert!(limiter.is_allowed("user1"));
        
        // Should block 4th request
        assert!(!limiter.is_allowed("user1"));
        
        // Different user should still be allowed
        assert!(limiter.is_allowed("user2"));
    }
} 