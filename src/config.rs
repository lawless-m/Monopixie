use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub dhcp: DhcpConfig,
    pub tftp: TftpConfig,
    pub http: HttpConfig,
    pub iscsi: IscsiConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct NetworkConfig {
    pub interface: String,
    pub server_ip: String,
    pub netmask: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DhcpConfig {
    pub client_mac: String,
    pub client_ip: String,
    pub lease_seconds: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TftpConfig {
    pub root: PathBuf,
    pub bios_bootfile: String,
    pub uefi_bootfile: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    pub port: u16,
    pub root: PathBuf,
    pub kernel: String,
    pub initrd: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IscsiConfig {
    pub target_iqn: String,
    pub target_ip: String,
    pub target_port: u16,
    pub lun: u32,
    pub initiator_iqn: String,
    pub root_uuid: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Validate IP addresses parse correctly
        self.network
            .server_ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid server_ip: {}", self.network.server_ip))?;
        self.dhcp
            .client_ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid client_ip: {}", self.dhcp.client_ip))?;
        self.network
            .netmask
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid netmask: {}", self.network.netmask))?;
        self.iscsi
            .target_ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid iscsi target_ip: {}", self.iscsi.target_ip))?;

        // Validate MAC address format (six colon-separated hex pairs)
        let mac_parts: Vec<&str> = self.dhcp.client_mac.split(':').collect();
        if mac_parts.len() != 6 {
            anyhow::bail!(
                "invalid client_mac: expected 6 hex pairs, got {}",
                mac_parts.len()
            );
        }
        for part in &mac_parts {
            if part.len() != 2 || u8::from_str_radix(part, 16).is_err() {
                anyhow::bail!("invalid client_mac: bad hex pair '{}'", part);
            }
        }

        // Validate paths exist
        if !self.tftp.root.exists() {
            anyhow::bail!("tftp root does not exist: {}", self.tftp.root.display());
        }
        if !self.http.root.exists() {
            anyhow::bail!("http root does not exist: {}", self.http.root.display());
        }

        Ok(())
    }

    /// Parse the configured client MAC into 6 bytes.
    pub fn client_mac_bytes(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        for (i, part) in self.dhcp.client_mac.split(':').enumerate() {
            mac[i] = u8::from_str_radix(part, 16).unwrap();
        }
        mac
    }
}
