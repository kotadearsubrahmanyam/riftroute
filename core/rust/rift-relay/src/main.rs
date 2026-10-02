use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use clap::{Parser, Subcommand};

use rift_relay::auth::AuthManager;
use rift_relay::config::RelayConfig;
use rift_relay::identity::IdentityManager;
use rift_relay::server::RelayServer;

#[derive(Parser)]
#[command(name = "rift-relay", version = "0.1.0", about = "RiftRoute Controlled Linux & Cross-Platform Relay Daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Initialize cryptographic identity and default configuration for this relay")]
    Init {
        #[arg(long, help = "Optional custom relay ID (e.g. relay_in_mum_01)")]
        relay_id: Option<String>,

        #[arg(long, default_value = "data/relay/identity.json", help = "Path to write cryptographic identity JSON")]
        identity_path: PathBuf,

        #[arg(long, default_value = "data/relay/config.json", help = "Path to write relay configuration JSON")]
        config_path: PathBuf,
    },

    #[command(about = "Start and run the RiftRoute relay daemon service")]
    Run {
        #[arg(short, long, default_value = "data/relay/config.json", help = "Path to relay configuration file")]
        config: PathBuf,

        #[arg(short, long, help = "Override listen IP address")]
        listen: Option<String>,

        #[arg(short, long, help = "Override control port")]
        port: Option<u16>,

        #[arg(long, help = "Allow probing loopback and private IPs (test mode only)")]
        allow_private: bool,
    },

    #[command(about = "Display local relay identity and configuration status")]
    Status {
        #[arg(short, long, default_value = "data/relay/config.json", help = "Path to relay configuration file")]
        config: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init {
            relay_id,
            identity_path,
            config_path,
        }) => {
            println!("=== INITIALIZING RIFTROUTE RELAY CRYPTOGRAPHIC IDENTITY ===");
            let (_signing_key, identity) = IdentityManager::generate(relay_id.as_deref());

            if let Err(e) = IdentityManager::save_identity(&identity, &identity_path) {
                eprintln!("[ERROR] Failed to save identity file: {}", e);
                exit(1);
            }

            let mut config = RelayConfig::default();
            config.relay_id = identity.relay_id.clone();
            config.identity_path = identity_path.clone();

            if let Err(e) = config.save_to_file(&config_path) {
                eprintln!("[ERROR] Failed to save configuration file: {}", e);
                exit(1);
            }

            println!("Relay ID:             {}", identity.relay_id);
            println!("Public Key (Hex):     {}", identity.public_key_hex);
            println!("Identity Fingerprint: {}", identity.fingerprint);
            println!("Identity File:        {}", identity_path.display());
            println!("Configuration File:   {}", config_path.display());
            println!("Relay initialization successful.");
        }

        Some(Commands::Run {
            config,
            listen,
            port,
            allow_private,
        }) => {
            let mut cfg = if config.exists() {
                RelayConfig::load_from_file(&config).unwrap_or_else(|e| {
                    eprintln!("[ERROR] Failed to load config from {}: {}", config.display(), e);
                    exit(1);
                })
            } else {
                println!("[WARN] Config file {} not found; using defaults.", config.display());
                RelayConfig::default()
            };

            if let Some(l) = listen {
                cfg.listen_address = l;
            }
            if let Some(p) = port {
                cfg.control_port = p;
            }
            if allow_private {
                cfg.allow_private_targets = true;
            }

            // Load identity
            let (_signing_key, identity) = if cfg.identity_path.exists() {
                IdentityManager::load_identity(&cfg.identity_path).unwrap_or_else(|e| {
                    eprintln!("[ERROR] Failed to load identity {}: {}", cfg.identity_path.display(), e);
                    exit(1);
                })
            } else {
                println!("[WARN] Identity not found; generating transient identity...");
                let (k, id) = IdentityManager::generate(Some(&cfg.relay_id));
                let _ = IdentityManager::save_identity(&id, &cfg.identity_path);
                (k, id)
            };

            println!("=== RIFTROUTE RELAY SERVICE STARTING ===");
            println!("Relay ID:             {}", identity.relay_id);
            println!("Fingerprint:          {}", identity.fingerprint);
            println!("Listen Address:       {}:{}", cfg.listen_address, cfg.control_port);
            println!("Authorized Clients:   {}", cfg.authorized_clients.len());
            println!("Allow Private/Test:   {}", cfg.allow_private_targets);

            let auth_mgr = AuthManager::new(
                identity.relay_id.clone(),
                cfg.authorized_clients.clone(),
                cfg.challenge_ttl_seconds,
                cfg.session_ttl_minutes,
            );

            let stop_signal = Arc::new(AtomicBool::new(false));
            let server = RelayServer::new(cfg, auth_mgr, identity.public_key_hex.clone(), Some(stop_signal));

            if let Err(e) = server.run() {
                eprintln!("[FATAL] Relay server error: {}", e);
                exit(1);
            }
        }

        Some(Commands::Status { config }) => {
            if !config.exists() {
                eprintln!("[ERROR] Config file {} does not exist", config.display());
                exit(1);
            }
            let cfg = RelayConfig::load_from_file(&config).unwrap();
            println!("=== RIFTROUTE RELAY STATUS ===");
            println!("Relay ID:             {}", cfg.relay_id);
            println!("Listen:               {}:{}", cfg.listen_address, cfg.control_port);
            println!("Identity File:        {}", cfg.identity_path.display());
            println!("Location:             {}, {}, {}", cfg.location.city, cfg.location.region, cfg.location.country);
            println!("Provider:             {}", cfg.location.provider);
            println!("Provenance:           {:?}", cfg.location.provenance);
            println!("Authorized Clients:   {}", cfg.authorized_clients.len());
        }

        None => {
            eprintln!("Usage: rift-relay <COMMAND>\n\nFor more information, try '--help'.");
            exit(1);
        }
    }
}
