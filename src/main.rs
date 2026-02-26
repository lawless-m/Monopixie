mod bootconfig;
mod config;
mod dhcp;
mod http;
mod tftp;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "pxe-boot-server")]
#[command(about = "PXE boot server providing DHCP, TFTP, and HTTP for thin client booting")]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config = config::Config::load(&cli.config)?;
    info!("configuration loaded from {}", cli.config.display());

    // Log the generated GRUB config for inspection
    let grub_cfg = bootconfig::generate_grub_cfg(&config);
    info!("generated GRUB config:\n{}", grub_cfg);

    let config = Arc::new(config);

    let mut set = tokio::task::JoinSet::new();

    set.spawn(dhcp::run(config.clone()));
    set.spawn(tftp::run(config.clone()));
    set.spawn(http::run(config.clone()));

    // Wait for any task to finish — all should run forever, so any exit is an error
    if let Some(result) = set.join_next().await {
        match result {
            Ok(Ok(())) => {
                error!("a service task exited unexpectedly");
            }
            Ok(Err(e)) => {
                error!("a service task failed: {:#}", e);
            }
            Err(e) => {
                error!("a service task panicked: {}", e);
            }
        }
        std::process::exit(1);
    }

    Ok(())
}
