use std::thread;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::Parser;
use log::LevelFilter;
use tokio::fs::File;
use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use wireguard_keys::Pubkey;

use service::{ServerConfig, WireguardService};
use crate::firewall::Firewall;

use crate::service::{FirewallCommand, WireguardCommand};
use crate::vpn::VPN;

mod service;
mod vpn;
mod firewall;

// TODO: read this from a CLI arg
const CAPACITY: usize = 1000;


async fn read_file(filename: &String) -> io::Result<Vec<u8>> {
    let mut file = File::open(filename).await?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await?;
    Ok(contents)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(default_value = "[::]:443")]
    listen_address: String,

    #[arg(default_value = "cacert.pem")]
    ca_cert: String,

    #[arg(default_value = "serverkey.pem")]
    tls_key: String,

    #[arg(default_value = "servercert.pem")]
    tls_cert: String,

    #[arg(default_value = "wg0")]
    wireguard_device: String,

    #[arg(default_value = "wg.key")]
    wireguard_public_key: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Info)
        .init();

    let args = Args::parse();
    let addr = args.listen_address
        .parse()
        .unwrap_or_else(|_| {
            log::error!("Invalid --address: {}", args.listen_address);
            std::process::exit(1);
        });

    let client_ca = read_file(&args.ca_cert)
        .await
        .unwrap_or_else(|_| {
            log::error!("Error reading {}", &args.ca_cert);
            std::process::exit(1);
        });

    let tls_certificate = read_file(&args.tls_cert)
        .await
        .unwrap_or_else(|_| {
            log::error!("Error reading TLS certificate: {}", &args.tls_cert);
            std::process::exit(1);
        });

    let tls_key = read_file(&args.tls_key)
        .await
        .unwrap_or_else(|_| {
            log::error!("Error reading TLS key: {}", &args.tls_key);
            std::process::exit(1);
        });


    let wireguard_public_key = read_file(&args.wireguard_public_key)
        .await
        .unwrap_or_else(|e| {
            log::error!("Error reading Wireguard private key: {}", e);
            std::process::exit(1);
        });

    let wireguard_public_key = BASE64_STANDARD.decode(&wireguard_public_key)?;

    let (wg_tx, mut wg_rx) = mpsc::channel::<WireguardCommand>(CAPACITY);
    let (fw_tx, mut fw_rx) = mpsc::channel::<FirewallCommand>(CAPACITY);

    let config = ServerConfig {
        client_ca,
        tls_certificate,
        tls_key,
        wireguard_device: args.wireguard_device.clone(),
        wg_tx,
        fw_tx,
    };

    // We don't want concurrent tokio tasks updating Wireguard at the same time.
    // Instead, we send commands as they come in and process them in a dedicated thread.
    // Use channels instead of mutexes to eliminate the risk of deadlock, improve performance
    // and avoid returning unnecessary errors to clients.
    let vpn = VPN::new(
        args.wireguard_device.clone(),
        Pubkey::new(wireguard_public_key.try_into().unwrap()),
    );
    thread::spawn(move || {
        vpn.wait_for_commands_blocking(&mut wg_rx);
    });

    // Just like Wireguard, we don't want to update the firewall concurrently, so we do it with
    // single threaded ownership.
    let firewall = Firewall::new(
        args.wireguard_device,
        "wgprcd".to_string(),
        "wgprcd".to_string(),
    );
    thread::spawn(move || {
        firewall.wait_for_commands_blocking(&mut fw_rx);
    });

    log::info!("Listening on {}", addr);
    WireguardService::server(config)?
        .serve(addr)
        .await
        .unwrap_or_else(|e| {
            log::error!("Error listening on {}: {}", addr, e);
            std::process::exit(1);
        });

    Ok(())
}
