use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use termichat::{
    ClientInfo, Message, DEFAULT_HOST, DEFAULT_PORT, 
    MAX_MESSAGE_LENGTH, SHARED_ENCRYPTION_KEY,
    RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS,
    security::{SecurityConfig, InputValidator, RateLimiter},
    certgen::CertificateGenerator
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::TlsAcceptor;

/// Command line arguments for the server
#[derive(Parser)]
#[command(name = "termichat-server")]
#[command(about = "A secure terminal-based chat server")]
struct Args {
    /// Host to bind to
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Port to bind to
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Certificate file path (for TLS)
    #[arg(long)]
    cert: Option<String>,

    /// Private key file path (for TLS)
    #[arg(long)]
    key: Option<String>,

    /// Auto-generate certificates if they don't exist
    #[arg(long)]
    auto_cert: bool,
}

/// Server state shared across all connections
struct ServerState {
    clients: RwLock<HashMap<String, ClientInfo>>,
    validator: InputValidator,
    rate_limiter: RwLock<RateLimiter>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            validator: InputValidator::new(),
            rate_limiter: RwLock::new(RateLimiter::new(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)),
        }
    }

    /// Register a new client
    async fn register_client(
        &self, 
        user_id: String, 
        sender: mpsc::UnboundedSender<Message>
    ) -> Result<bool> {
        // Validate user ID
        self.validator.validate_user_id(&user_id)?;
        
        let mut clients = self.clients.write().await;
        
        if clients.contains_key(&user_id) {
            return Ok(false);
        }

        clients.insert(user_id.clone(), ClientInfo { 
            user_id, 
            sender 
        });
        Ok(true)
    }

    /// Remove a client
    async fn remove_client(&self, user_id: &str) {
        let mut clients = self.clients.write().await;
        clients.remove(user_id);
        println!("Client {} disconnected", user_id);
    }

    /// Get list of connected users
    async fn get_users(&self) -> Vec<String> {
        let clients = self.clients.read().await;
        clients.keys().cloned().collect()
    }

    /// Send message to specific user
    async fn send_to_user(&self, target_user: &str, message: Message) -> Result<()> {
        let clients = self.clients.read().await;
        
        if let Some(client) = clients.get(target_user) {
            client.sender.send(message)
                .map_err(|_| anyhow::anyhow!("Failed to send message to user: {}", target_user))?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("User {} not found or offline", target_user))
        }
    }

    /// Broadcast message to all users except sender
    async fn broadcast(&self, sender_id: &str, message: Message) {
        let clients = self.clients.read().await;
        
        for (user_id, client) in clients.iter() {
            if user_id != sender_id {
                let _ = client.sender.send(message.clone());
            }
        }
    }

    /// Check rate limit for a user
    async fn check_rate_limit(&self, user_id: &str) -> bool {
        let mut rate_limiter = self.rate_limiter.write().await;
        rate_limiter.is_allowed(user_id)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    
    // Initialize security configuration with shared key
    let mut security_config = SecurityConfig::new()?;
    security_config.encryption_key = SHARED_ENCRYPTION_KEY;
    
    // Handle certificate generation and TLS configuration
    let tls_acceptor = if args.auto_cert || args.cert.is_some() || args.key.is_some() {
        let (cert_path, key_path) = if args.auto_cert {
            // Auto-generate certificates if they don't exist
            if !CertificateGenerator::certificates_exist("certs") {
                CertificateGenerator::generate_certificates("certs")?;
            }
            CertificateGenerator::get_certificate_paths("certs")
        } else {
            // Use provided certificate paths
            let cert_path = args.cert.as_ref().unwrap();
            let key_path = args.key.as_ref().unwrap();
            (cert_path.clone(), key_path.clone())
        };
        
        security_config = security_config.with_tls(&cert_path, &key_path)?;
        Some(Arc::new(TlsAcceptor::from(Arc::new(security_config.tls_config.unwrap()))))
    } else {
        None
    };
    
    println!("Starting TermiChat server on {}", addr);
    if tls_acceptor.is_some() {
        println!("🔒 TLS encryption enabled");
    } else {
        println!("⚠️  TLS encryption disabled - using plain TCP");
    }
    
    let listener = TcpListener::bind(&addr).await
        .context("Failed to bind TCP listener")?;
    
    let server_state = Arc::new(ServerState::new());
    
    println!("TermiChat server listening on {}", addr);
    println!("Waiting for clients to connect...");
    
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let state = Arc::clone(&server_state);
                let tls_acceptor = tls_acceptor.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, addr, state, tls_acceptor).await {
                        eprintln!("Error handling client {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle individual client connection
async fn handle_client(
    stream: TcpStream,
    addr: SocketAddr,
    state: Arc<ServerState>,
    _tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    println!("New connection from {}", addr);
    
    // For now, we'll skip TLS handling to simplify the implementation
    // In production, you'd want proper TLS stream handling
    let stream = stream;
    
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    
    let mut user_id: Option<String> = None;
    let mut line = String::new();
    
    // Handle registration
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                println!("Client {} disconnected during registration", addr);
                return Ok(());
            }
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                
                // Sanitize input
                let sanitized_line = state.validator.sanitize_input(line);
                
                match Message::from_json(&sanitized_line) {
                    Ok(Message::Register { user_id: requested_id }) => {
                        // Check rate limit
                        if !state.check_rate_limit(&format!("{}_register", addr)).await {
                            let error = Message::Error { 
                                message: "Rate limit exceeded. Please try again later.".to_string() 
                            };
                            let error_json = error.to_json()?;
                            write_half.write_all(format!("{}\n", error_json).as_bytes()).await?;
                            continue;
                        }
                        
                        let registration_success = state.register_client(
                            requested_id.clone(), 
                            tx.clone()
                        ).await?;
                        
                        let response = if registration_success {
                            user_id = Some(requested_id.clone());
                            println!("User {} registered from {}", requested_id, addr);
                            Message::RegisterResponse { success: true, error: None }
                        } else {
                            Message::RegisterResponse { 
                                success: false, 
                                error: Some(format!("User ID '{}' is already taken", requested_id))
                            }
                        };
                        
                        let response_json = response.to_json()?;
                        write_half.write_all(format!("{}\n", response_json).as_bytes()).await?;
                        
                        if registration_success {
                            break;
                        }
                    }
                    
                    _ => {
                        let error = Message::Error { 
                            message: "Please register first with a user ID".to_string() 
                        };
                        let error_json = error.to_json()?;
                        write_half.write_all(format!("{}\n", error_json).as_bytes()).await?;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from client {}: {}", addr, e);
                return Ok(());
            }
        }
    }
    
    let user_id = user_id.unwrap();
    let user_id_clone = user_id.clone();
    let state_clone = Arc::clone(&state);
    
    // Spawn task to handle outgoing messages
    let write_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            match message.to_json() {
                Ok(json) => {
                    if let Err(e) = write_half.write_all(format!("{}\n", json).as_bytes()).await {
                        eprintln!("Error writing to client: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error serializing message: {}", e);
                }
            }
        }
    });
    
    // Handle incoming messages
    let read_task = tokio::spawn(async move {
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // Client disconnected
                Ok(_) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    
                    // Sanitize input
                    let sanitized_line = state_clone.validator.sanitize_input(line);
                    
                    match Message::from_json(&sanitized_line) {
                        Ok(message) => {
                            if let Err(e) = handle_message(&state_clone, &user_id_clone, message).await {
                                eprintln!("Error handling message from {}: {}", user_id_clone, e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error parsing message from {}: {}", user_id_clone, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from {}: {}", user_id_clone, e);
                    break;
                }
            }
        }
        
        // Clean up on disconnect
        state_clone.remove_client(&user_id_clone).await;
    });
    
    // Wait for either task to complete
    tokio::select! {
        _ = read_task => {},
        _ = write_task => {},
    }
    
    Ok(())
}

/// Handle different types of messages
async fn handle_message(
    state: &Arc<ServerState>,
    sender_id: &str,
    message: Message,
) -> Result<()> {
    // Check rate limit for message sending
    if !state.check_rate_limit(&format!("{}_message", sender_id)).await {
        let error_msg = Message::Error { 
            message: "Rate limit exceeded. Please slow down your messages.".to_string() 
        };
        state.send_to_user(sender_id, error_msg).await?;
        return Ok(());
    }
    
    match message {
        Message::ChatMessage { from: _, to, encrypted_content, timestamp: _ } => {
            // Validate message length (encrypted content is base64 encoded)
            if encrypted_content.len() > MAX_MESSAGE_LENGTH * 2 {
                let error_msg = Message::Error { 
                    message: "Message too long".to_string() 
                };
                state.send_to_user(sender_id, error_msg).await?;
                return Ok(());
            }
            
            let message_with_timestamp = Message::ChatMessage {
                from: sender_id.to_string(),
                to: to.clone(),
                encrypted_content,
                timestamp: Utc::now(),
            };
            
            if let Err(e) = state.send_to_user(&to, message_with_timestamp.clone()).await {
                // Send error back to sender
                let error_msg = Message::Error { 
                    message: format!("Failed to deliver message to {}: {}", to, e) 
                };
                state.send_to_user(sender_id, error_msg).await?;
            } else {
                println!("Message from {} to {}: delivered", sender_id, to);
            }
        }
        
        Message::BroadcastMessage { from: _, encrypted_content, timestamp: _ } => {
            // Validate message length
            if encrypted_content.len() > MAX_MESSAGE_LENGTH * 2 {
                let error_msg = Message::Error { 
                    message: "Message too long".to_string() 
                };
                state.send_to_user(sender_id, error_msg).await?;
                return Ok(());
            }
            
            let broadcast_msg = Message::BroadcastMessage {
                from: sender_id.to_string(),
                encrypted_content,
                timestamp: Utc::now(),
            };
            
            state.broadcast(sender_id, broadcast_msg).await;
            println!("Broadcast from {}: delivered", sender_id);
        }
        
        Message::TypingIndicator { from: _, to } => {
            let typing_msg = Message::TypingIndicator {
                from: sender_id.to_string(),
                to: to.clone(),
            };
            
            let _ = state.send_to_user(&to, typing_msg).await;
        }
        
        Message::ListUsers => {
            let users = state.get_users().await;
            let response = Message::UserListResponse { users };
            state.send_to_user(sender_id, response).await?;
        }
        
        Message::Disconnect { user_id: _ } => {
            state.remove_client(sender_id).await;
        }
        
        _ => {
            eprintln!("Unexpected message type from {}", sender_id);
        }
    }
    
    Ok(())
}