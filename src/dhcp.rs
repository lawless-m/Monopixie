use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::config::Config;

// DHCP message types
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

// DHCP opcodes
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

// DHCP options
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DHCP_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_LEASE_TIME: u8 = 51;
const OPT_TFTP_SERVER: u8 = 66;
const OPT_BOOTFILE: u8 = 67;
const OPT_CLIENT_ARCH: u8 = 93;
const OPT_END: u8 = 255;

// Magic cookie
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

// Client architecture types (Option 93)
const ARCH_BIOS: u16 = 0x0000;
const ARCH_EFI_X64: u16 = 0x0007;

pub async fn run(config: Arc<Config>) -> Result<()> {
    let bind_addr = format!("{}:67", config.network.server_ip);
    let socket = UdpSocket::bind(&bind_addr).await?;
    socket.set_broadcast(true)?;
    info!("DHCP server listening on {}", bind_addr);

    let expected_mac = config.client_mac_bytes();
    let mut buf = vec![0u8; 1500];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        if len < 240 {
            debug!("ignoring short packet ({} bytes) from {}", len, src);
            continue;
        }

        // Check opcode is BOOTREQUEST
        if buf[0] != BOOTREQUEST {
            continue;
        }

        // Extract client MAC (bytes 28..34)
        let client_mac: [u8; 6] = buf[28..34].try_into().unwrap();
        if client_mac != expected_mac {
            debug!(
                "ignoring DHCP from unknown MAC {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                client_mac[0], client_mac[1], client_mac[2],
                client_mac[3], client_mac[4], client_mac[5]
            );
            continue;
        }

        // Parse options
        let options = match parse_options(&buf[240..len]) {
            Some(opts) => opts,
            None => {
                debug!("failed to parse DHCP options from {}", src);
                continue;
            }
        };

        let msg_type = match options.message_type {
            Some(t) => t,
            None => continue,
        };

        let mac_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            client_mac[0], client_mac[1], client_mac[2],
            client_mac[3], client_mac[4], client_mac[5]
        );

        // Determine bootfile based on client architecture
        let bootfile = match options.client_arch {
            Some(ARCH_EFI_X64) => {
                info!("DHCP {} from {} (UEFI x86-64)", msg_type_name(msg_type), mac_str);
                &config.tftp.uefi_bootfile
            }
            Some(ARCH_BIOS) => {
                info!("DHCP {} from {} (BIOS)", msg_type_name(msg_type), mac_str);
                &config.tftp.bios_bootfile
            }
            Some(arch) => {
                warn!("DHCP {} from {} (unknown arch 0x{:04X}, defaulting to BIOS)", msg_type_name(msg_type), mac_str, arch);
                &config.tftp.bios_bootfile
            }
            None => {
                info!("DHCP {} from {} (no arch option, defaulting to BIOS)", msg_type_name(msg_type), mac_str);
                &config.tftp.bios_bootfile
            }
        };

        let xid = &buf[4..8];
        let response_type = match msg_type {
            DHCP_DISCOVER => DHCP_OFFER,
            DHCP_REQUEST => DHCP_ACK,
            _ => {
                debug!("ignoring DHCP message type {}", msg_type);
                continue;
            }
        };

        let response = build_response(&config, xid, &client_mac, response_type, bootfile)?;

        info!(
            "sending DHCP {} to {}",
            msg_type_name(response_type),
            mac_str
        );

        // Send to broadcast address since client doesn't have an IP yet
        socket.send_to(&response, "255.255.255.255:68").await?;
    }
}

struct ParsedOptions {
    message_type: Option<u8>,
    client_arch: Option<u16>,
}

fn parse_options(data: &[u8]) -> Option<ParsedOptions> {
    // Check magic cookie
    if data.len() < 4 || data[0..4] != MAGIC_COOKIE {
        return None;
    }

    let mut opts = ParsedOptions {
        message_type: None,
        client_arch: None,
    };

    let mut i = 4;
    while i < data.len() {
        let opt = data[i];
        if opt == OPT_END {
            break;
        }
        if opt == 0 {
            // Padding
            i += 1;
            continue;
        }
        if i + 1 >= data.len() {
            break;
        }
        let opt_len = data[i + 1] as usize;
        if i + 2 + opt_len > data.len() {
            break;
        }
        let opt_data = &data[i + 2..i + 2 + opt_len];

        match opt {
            OPT_DHCP_MSG_TYPE if opt_len == 1 => {
                opts.message_type = Some(opt_data[0]);
            }
            OPT_CLIENT_ARCH if opt_len >= 2 => {
                opts.client_arch = Some(u16::from_be_bytes([opt_data[0], opt_data[1]]));
            }
            _ => {}
        }

        i += 2 + opt_len;
    }

    Some(opts)
}

fn build_response(
    config: &Config,
    xid: &[u8],
    client_mac: &[u8; 6],
    msg_type: u8,
    bootfile: &str,
) -> Result<Vec<u8>> {
    let server_ip: Ipv4Addr = config.network.server_ip.parse()?;
    let client_ip: Ipv4Addr = config.dhcp.client_ip.parse()?;
    let netmask: Ipv4Addr = config.network.netmask.parse()?;

    let mut pkt = vec![0u8; 576]; // minimum DHCP packet

    // Header
    pkt[0] = BOOTREPLY;          // op
    pkt[1] = 1;                   // htype (Ethernet)
    pkt[2] = 6;                   // hlen (MAC length)
    pkt[3] = 0;                   // hops
    pkt[4..8].copy_from_slice(xid); // xid
    // secs (8..10) = 0
    // flags (10..12) = 0

    // yiaddr (your IP address) — the IP we're giving the client
    pkt[16..20].copy_from_slice(&client_ip.octets());

    // siaddr (server IP address) — TFTP server
    pkt[20..24].copy_from_slice(&server_ip.octets());

    // chaddr (client hardware address)
    pkt[28..34].copy_from_slice(client_mac);

    // sname (server host name) — bytes 44..108, leave zero

    // file (boot file name) — bytes 108..236
    let bootfile_bytes = bootfile.as_bytes();
    let copy_len = bootfile_bytes.len().min(128);
    pkt[108..108 + copy_len].copy_from_slice(&bootfile_bytes[..copy_len]);

    // Options start at byte 236
    let mut opts = Vec::new();

    // Magic cookie
    opts.extend_from_slice(&MAGIC_COOKIE);

    // Option 53: DHCP Message Type
    opts.extend_from_slice(&[OPT_DHCP_MSG_TYPE, 1, msg_type]);

    // Option 54: Server Identifier
    opts.extend_from_slice(&[OPT_SERVER_ID, 4]);
    opts.extend_from_slice(&server_ip.octets());

    // Option 51: Lease Time
    opts.extend_from_slice(&[OPT_LEASE_TIME, 4]);
    opts.extend_from_slice(&config.dhcp.lease_seconds.to_be_bytes());

    // Option 1: Subnet Mask
    opts.extend_from_slice(&[OPT_SUBNET_MASK, 4]);
    opts.extend_from_slice(&netmask.octets());

    // Option 3: Router (our server IP)
    opts.extend_from_slice(&[OPT_ROUTER, 4]);
    opts.extend_from_slice(&server_ip.octets());

    // Option 66: TFTP Server Name
    let server_ip_str = config.network.server_ip.as_bytes();
    opts.push(OPT_TFTP_SERVER);
    opts.push(server_ip_str.len() as u8);
    opts.extend_from_slice(server_ip_str);

    // Option 67: Bootfile Name
    opts.push(OPT_BOOTFILE);
    opts.push(bootfile_bytes.len() as u8);
    opts.extend_from_slice(bootfile_bytes);

    // End
    opts.push(OPT_END);

    // Place options at offset 236
    let options_start = 236;
    if options_start + opts.len() > pkt.len() {
        pkt.resize(options_start + opts.len(), 0);
    }
    pkt[options_start..options_start + opts.len()].copy_from_slice(&opts);
    pkt.truncate(options_start + opts.len());

    Ok(pkt)
}

fn msg_type_name(t: u8) -> &'static str {
    match t {
        DHCP_DISCOVER => "DISCOVER",
        DHCP_OFFER => "OFFER",
        DHCP_REQUEST => "REQUEST",
        DHCP_ACK => "ACK",
        _ => "UNKNOWN",
    }
}
