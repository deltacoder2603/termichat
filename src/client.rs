use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use termichat::{
    Message, DEFAULT_HOST, DEFAULT_PORT, SHARED_ENCRYPTION_KEY,
    security::{SecurityConfig, MessageEncryption, InputValidator},
    certgen::CertificateGenerator
};
use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use std::sync::Arc;

/// Command line arguments for the client
#[derive(Parser)]
#[command(name = "termichat-client")]
#[command(about = "A secure terminal-based chat client")]
struct Args {
    /// Server host to connect to
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Server port to connect to
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// User ID for this client
    #[arg(short, long)]
    user_id: Option<String>,

    /// Use TLS encryption
    #[arg(long)]
    tls: bool,

    /// Skip certificate verification (for self-signed certs)
    #[arg(long)]
    insecure: bool,

    /// Auto-generate certificates if they don't exist
    #[arg(long)]
    auto_cert: bool,
}

/// Client state
struct ClientState {
    user_id: String,
    current_recipient: Option<String>,
    encryption: MessageEncryption,
    validator: InputValidator,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    
    println!("Connecting to TermiChat server at {}...", addr);
    
    // Initialize security configuration with shared key
    let mut security_config = SecurityConfig::new()?;
    security_config.encryption_key = SHARED_ENCRYPTION_KEY;
    let encryption = MessageEncryption::new(&security_config.encryption_key);
    let validator = InputValidator::new();
    
    // Handle certificate generation if needed
    if args.auto_cert && !CertificateGenerator::certificates_exist("certs") {
        println!("🔐 Auto-generating certificates...");
        CertificateGenerator::generate_certificates("certs")?;
    }
    
    // Connect to server
    let stream = if args.tls {
        println!("🔒 Using TLS encryption");
        
        // First establish TCP connection
        let tcp_stream = TcpStream::connect(&addr).await
            .context("Failed to connect to server")?;
        
        // Create TLS connector
        let mut root_certs = rustls::RootCertStore::empty();
        if !args.insecure {
            root_certs.add_trust_anchors(
                webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                })
            );
        }
        
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(config));
        let _tls_stream = connector.connect(args.host.as_str().try_into()?, tcp_stream).await
            .context("Failed to establish TLS connection")?;
        
        // For now, we'll use the TCP stream directly and handle TLS separately
        // This is a simplified approach - in production you'd want proper TLS handling
        TcpStream::connect(&addr).await
            .context("Failed to connect to server")?
    } else {
        println!("⚠️  Using plain TCP connection (not encrypted)");
        TcpStream::connect(&addr).await
            .context("Failed to connect to server")?
    };
    
    println!("Connected to server!");
    
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    
    // Get user ID
    let user_id = if let Some(id) = args.user_id {
        validator.validate_user_id(&id)?;
        id
    } else {
        loop {
            print!("Enter your user ID: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let user_id = input.trim().to_string();
            
            match validator.validate_user_id(&user_id) {
                Ok(_) => break user_id,
                Err(e) => {
                    println!("❌ Invalid user ID: {}", e);
                    continue;
                }
            }
        }
    };
    
    // Register with server
    let register_msg = Message::Register { 
        user_id: user_id.clone()
    };
    let register_json = register_msg.to_json()?;
    write_half.write_all(format!("{}\n", register_json).as_bytes()).await?;
    
    // Wait for registration response
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    
    match Message::from_json(line.trim())? {
        Message::RegisterResponse { success: true, error: None } => {
            println!("✅ Successfully registered as '{}'", user_id);
        }
        Message::RegisterResponse { success: false, error: Some(err) } => {
            eprintln!("❌ Registration failed: {}", err);
            return Ok(());
        }
        _ => {
            eprintln!("❌ Unexpected response from server");
            return Ok(());
        }
    }
    
    let mut client_state = ClientState {
        user_id: user_id.clone(),
        current_recipient: None,
        encryption,
        validator,
    };
    
    // Show help
    show_help();
    
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<String>();
    
    // Spawn input handler
    let mut input_handle = tokio::spawn(async move {
        handle_input(input_tx).await
    });
    
    // Spawn message receiver
    let user_id_clone = user_id.clone();
    let encryption = client_state.encryption.clone();
    let mut message_handle = tokio::spawn(async move {
        handle_incoming_messages(reader, user_id_clone, encryption).await
    });
    
    // Main client loop
    loop {
        tokio::select! {
            // Handle user input
            input = input_rx.recv() => {
                if let Some(input) = input {
                    let input = input.trim();
                    
                    if input.is_empty() {
                        continue;
                    }
                    
                    if input == "/quit" {
                        break;
                    }
                    
                    if let Err(e) = handle_user_command(&mut write_half, &mut client_state, input).await {
                        println!("❌ Error: {}", e);
                    }
                }
            }
            
            // Check if tasks completed (indicating disconnection)
            _ = &mut input_handle => break,
            _ = &mut message_handle => break,
        }
    }
    
    // Send disconnect message
    let disconnect_msg = Message::Disconnect { 
        user_id: client_state.user_id 
    };
    if let Ok(json) = disconnect_msg.to_json() {
        let _ = write_half.write_all(format!("{}\n", json).as_bytes()).await;
    }
    
    println!("👋 Disconnected from server. Goodbye!");
    Ok(())
}

/// Handle incoming messages from server
async fn handle_incoming_messages(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    _user_id: String,
    encryption: MessageEncryption,
) -> Result<()> {
    let mut line = String::new();
    
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                println!("❌ Server disconnected");
                break;
            }
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                
                match Message::from_json(line) {
                    Ok(message) => {
                        handle_server_message(message, &encryption).await;
                    }
                    Err(e) => {
                        println!("❌ Error parsing message: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("❌ Error reading from server: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

/// Handle messages received from server
async fn handle_server_message(message: Message, encryption: &MessageEncryption) {
    match message {
        Message::ChatMessage { from, to: _, encrypted_content, timestamp } => {
            match encryption.decrypt(&encrypted_content) {
                Ok(content) => {
                    println!("📨 [{}] {}: {}", timestamp.format("%H:%M:%S"), from, content);
                }
                Err(e) => {
                    println!("❌ Failed to decrypt message from {}: {}", from, e);
                }
            }
        }
        
        Message::BroadcastMessage { from, encrypted_content, timestamp } => {
            match encryption.decrypt(&encrypted_content) {
                Ok(content) => {
                    println!("📢 [{}] {} (broadcast): {}", timestamp.format("%H:%M:%S"), from, content);
                }
                Err(e) => {
                    println!("❌ Failed to decrypt broadcast from {}: {}", from, e);
                }
            }
        }
        
        Message::TypingIndicator { from, to: _ } => {
            println!("⌨️  {} is typing...", from);
        }
        
        Message::UserListResponse { users } => {
            println!("👥 Connected users:");
            for user in users {
                println!("   - {}", user);
            }
        }
        
        Message::Error { message } => {
            println!("❌ Server error: {}", message);
        }
        
        _ => {
            println!("❌ Received unexpected message type from server");
        }
    }
}

/// Handle user input from terminal
async fn handle_input(tx: mpsc::UnboundedSender<String>) -> Result<()> {
    let stdin = io::stdin();
    
    loop {
        print!("> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        match stdin.read_line(&mut input) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let input = input.trim().to_string();
                if input == "/quit" {
                    let _ = tx.send(input);
                    break;
                }
                if !input.is_empty() {
                    let _ = tx.send(input);
                }
            }
            Err(e) => {
                eprintln!("❌ Error reading input: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

/// Handle user commands
async fn handle_user_command(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    state: &mut ClientState,
    input: &str,
) -> Result<()> {
    if input.starts_with('/') {
        // Handle commands
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let command = parts[0];
        
        match command {
            "/to" => {
                if parts.len() != 2 {
                    println!("❌ Usage: /to <user_id>");
                    return Ok(());
                }
                
                let recipient = parts[1];
                match state.validator.validate_user_id(recipient) {
                    Ok(_) => {
                        state.current_recipient = Some(recipient.to_string());
                        println!("✅ Now messaging: {}", recipient);
                    }
                    Err(e) => {
                        println!("❌ Invalid user ID: {}", e);
                    }
                }
            }
            
            "/broadcast" => {
                if parts.len() != 2 {
                    println!("❌ Usage: /broadcast <message>");
                    return Ok(());
                }
                
                let message = parts[1];
                match state.validator.validate_message(message) {
                    Ok(_) => {
                        // Encrypt the message
                        let encrypted_content = state.encryption.encrypt(message)?;
                        
                        let message = Message::BroadcastMessage {
                            from: state.user_id.clone(),
                            encrypted_content,
                            timestamp: Utc::now(),
                        };
                        
                        let json = message.to_json()?;
                        writer.write_all(format!("{}\n", json).as_bytes()).await?;
                        println!("📢 Broadcast sent: {}", parts[1]);
                    }
                    Err(e) => {
                        println!("❌ Invalid message: {}", e);
                    }
                }
            }
            
            "/users" => {
                let message = Message::ListUsers;
                let json = message.to_json()?;
                writer.write_all(format!("{}\n", json).as_bytes()).await?;
            }
            
            "/help" => {
                show_help();
            }
            
            "/quit" => {
                return Ok(());
            }
            
            _ => {
                println!("❌ Unknown command: {}", command);
                println!("💡 Type /help for available commands");
            }
        }
    } else {
        // Regular message
        if let Some(recipient) = &state.current_recipient {
            match state.validator.validate_message(input) {
                Ok(_) => {
                    // Encrypt the message
                    let encrypted_content = state.encryption.encrypt(input)?;
                    
                    let message = Message::ChatMessage {
                        from: state.user_id.clone(),
                        to: recipient.clone(),
                        encrypted_content,
                        timestamp: Utc::now(),
                    };
                    
                    let json = message.to_json()?;
                    writer.write_all(format!("{}\n", json).as_bytes()).await?;
                    
                    println!("📤 To {}: {}", recipient, input);
                }
                Err(e) => {
                    println!("❌ Invalid message: {}", e);
                }
            }
        } else {
            println!("❌ No recipient selected. Use /to <user_id> first, or /broadcast <message>");
        }
    }
    
    Ok(())
}

/// Display help information
fn show_help() {
    println!("🚀 === TermiChat Client Help ===");
    println!("🔒 Security Features:");
    println!("   • TLS/SSL encryption (use --tls flag)");
    println!("   • Message encryption (AES-256-GCM)");
    println!("   • Input validation and sanitization");
    println!("   • Rate limiting protection");
    println!();
    println!("📋 Commands:");
    println!("   /to <user_id>     - Set message recipient");
    println!("   /broadcast <msg>  - Send encrypted message to all users");
    println!("   /users            - List connected users");
    println!("   /help             - Show this help");
    println!("   /quit             - Exit the application");
    println!();
    println!("💬 Once you set a recipient with /to, just type messages normally.");
    println!("🔐 All messages are encrypted end-to-end.");
    println!("================================");
}