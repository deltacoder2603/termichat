use anyhow::Result;
use clap::Parser;
use termichat::certgen::CertificateGenerator;

/// Generate self-signed certificates for TermiChat
#[derive(Parser)]
#[command(name = "generate-certs")]
#[command(about = "Generate self-signed certificates for TermiChat")]
struct Args {
    /// Certificate directory
    #[arg(short, long, default_value = "certs")]
    cert_dir: String,
    
    /// Force regeneration even if certificates exist
    #[arg(short, long)]
    force: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    if args.force {
        // Remove existing certificates
        let cert_path = std::path::Path::new(&args.cert_dir);
        let cert_file = cert_path.join("server.crt");
        let key_file = cert_path.join("server.key");
        
        if cert_file.exists() {
            std::fs::remove_file(cert_file)?;
        }
        if key_file.exists() {
            std::fs::remove_file(key_file)?;
        }
        
        println!("🗑️  Removed existing certificates");
    }
    
    CertificateGenerator::generate_certificates(&args.cert_dir)?;
    
    Ok(())
} 