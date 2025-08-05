use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Certificate generation utilities
pub struct CertificateGenerator;

impl CertificateGenerator {
    /// Generate self-signed certificates for TermiChat
    pub fn generate_certificates(cert_dir: &str) -> Result<()> {
        let cert_path = Path::new(cert_dir);
        
        // Create certificate directory if it doesn't exist
        if !cert_path.exists() {
            fs::create_dir_all(cert_path)
                .context("Failed to create certificate directory")?;
        }
        
        let cert_file = cert_path.join("server.crt");
        let key_file = cert_path.join("server.key");
        
        // Check if certificates already exist
        if cert_file.exists() && key_file.exists() {
            println!("✅ Certificates already exist in {}", cert_dir);
            return Ok(());
        }
        
        println!("🔐 Generating self-signed certificates...");
        
        // Generate private key using OpenSSL
        let key_output = std::process::Command::new("openssl")
            .args(&["genrsa", "-out", key_file.to_str().unwrap(), "2048"])
            .output()
            .context("Failed to generate private key. Make sure OpenSSL is installed.")?;
        
        if !key_output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to generate private key: {}",
                String::from_utf8_lossy(&key_output.stderr)
            ));
        }
        
        // Generate certificate signing request
        let csr_file = cert_path.join("server.csr");
        let csr_output = std::process::Command::new("openssl")
            .args(&[
                "req", "-new", "-key", key_file.to_str().unwrap(),
                "-out", csr_file.to_str().unwrap(),
                "-subj", "/C=US/ST=State/L=City/O=TermiChat/CN=localhost"
            ])
            .output()
            .context("Failed to generate certificate signing request")?;
        
        if !csr_output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to generate CSR: {}",
                String::from_utf8_lossy(&csr_output.stderr)
            ));
        }
        
        // Generate self-signed certificate
        let cert_output = std::process::Command::new("openssl")
            .args(&[
                "x509", "-req", "-days", "365",
                "-in", csr_file.to_str().unwrap(),
                "-signkey", key_file.to_str().unwrap(),
                "-out", cert_file.to_str().unwrap()
            ])
            .output()
            .context("Failed to generate self-signed certificate")?;
        
        if !cert_output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to generate certificate: {}",
                String::from_utf8_lossy(&cert_output.stderr)
            ));
        }
        
        // Clean up CSR file
        if csr_file.exists() {
            fs::remove_file(csr_file)
                .context("Failed to remove CSR file")?;
        }
        
        println!("✅ Certificates generated successfully!");
        println!("📁 Certificate files:");
        println!("   - {} (certificate)", cert_file.display());
        println!("   - {} (private key)", key_file.display());
        println!();
        println!("🚀 To run the server with TLS:");
        println!("   cargo run --bin server -- --cert {} --key {}", 
                cert_file.display(), key_file.display());
        println!();
        println!("🔗 To connect with TLS client:");
        println!("   cargo run --bin client -- --tls --insecure");
        
        Ok(())
    }
    
    /// Check if certificates exist
    pub fn certificates_exist(cert_dir: &str) -> bool {
        let cert_path = Path::new(cert_dir);
        let cert_file = cert_path.join("server.crt");
        let key_file = cert_path.join("server.key");
        
        cert_file.exists() && key_file.exists()
    }
    
    /// Get certificate and key paths
    pub fn get_certificate_paths(cert_dir: &str) -> (String, String) {
        let cert_path = Path::new(cert_dir);
        let cert_file = cert_path.join("server.crt");
        let key_file = cert_path.join("server.key");
        
        (cert_file.to_string_lossy().to_string(), key_file.to_string_lossy().to_string())
    }
} 