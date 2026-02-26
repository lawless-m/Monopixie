use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::config::Config;

// TFTP opcodes
const OP_RRQ: u16 = 1;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;
const OP_OACK: u16 = 6;

// TFTP error codes
const ERR_FILE_NOT_FOUND: u16 = 1;
const ERR_ACCESS_VIOLATION: u16 = 2;

const DEFAULT_BLOCK_SIZE: usize = 512;

pub async fn run(config: Arc<Config>) -> Result<()> {
    let bind_addr = format!("{}:69", config.network.server_ip);
    let socket = UdpSocket::bind(&bind_addr).await?;
    info!("TFTP server listening on {}", bind_addr);

    let mut buf = vec![0u8; 1024];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        if len < 2 {
            continue;
        }

        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        if opcode != OP_RRQ {
            debug!("ignoring non-RRQ opcode {} from {}", opcode, src);
            continue;
        }

        let config = config.clone();
        let packet = buf[2..len].to_vec();
        tokio::spawn(async move {
            if let Err(e) = handle_rrq(&config, src, &packet).await {
                error!("TFTP transfer to {} failed: {}", src, e);
            }
        });
    }
}

async fn handle_rrq(config: &Config, client: SocketAddr, data: &[u8]) -> Result<()> {
    // Parse filename and mode from null-terminated strings
    let mut fields = data.split(|&b| b == 0).filter(|s| !s.is_empty());
    let filename = match fields.next() {
        Some(f) => String::from_utf8_lossy(f).to_string(),
        None => {
            anyhow::bail!("RRQ missing filename");
        }
    };
    let _mode = fields.next(); // "octet" or "netascii"; we always serve binary

    // Check for blksize option
    let mut blksize = DEFAULT_BLOCK_SIZE;
    let mut requested_blksize = false;
    while let Some(opt_name) = fields.next() {
        let opt_name_str = String::from_utf8_lossy(opt_name).to_ascii_lowercase();
        if let Some(opt_val) = fields.next() {
            let opt_val_str = String::from_utf8_lossy(opt_val);
            if opt_name_str == "blksize" {
                if let Ok(size) = opt_val_str.parse::<usize>() {
                    blksize = size.clamp(8, 65464);
                    requested_blksize = true;
                }
            }
        }
    }

    info!("TFTP RRQ: {} from {}", filename, client);

    // Resolve path and prevent traversal
    let file_path = config.tftp.root.join(&filename);
    let canonical = match file_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            send_error(&client, ERR_FILE_NOT_FOUND, "file not found").await?;
            anyhow::bail!("file not found: {}", filename);
        }
    };

    let root_canonical = config.tftp.root.canonicalize()?;
    if !canonical.starts_with(&root_canonical) {
        warn!("TFTP path traversal attempt blocked: {}", filename);
        send_error(&client, ERR_ACCESS_VIOLATION, "access denied").await?;
        anyhow::bail!("path traversal: {}", filename);
    }

    let file_data = match tokio::fs::read(&canonical).await {
        Ok(d) => d,
        Err(_) => {
            send_error(&client, ERR_FILE_NOT_FOUND, "file not found").await?;
            anyhow::bail!("cannot read: {}", filename);
        }
    };

    // Bind a new ephemeral socket for this transfer (TFTP spec requirement)
    let transfer_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let timeout = Duration::from_secs(config.tftp.timeout_seconds);

    // If client requested blksize, send OACK first
    if requested_blksize {
        let oack = build_oack(blksize);
        transfer_socket.send_to(&oack, client).await?;

        // Wait for ACK of block 0
        if !wait_for_ack(&transfer_socket, 0, timeout).await? {
            anyhow::bail!("timeout waiting for ACK of OACK");
        }
    }

    // Send file in blocks
    let chunks: Vec<&[u8]> = file_data.chunks(blksize).collect();
    let total_blocks = if chunks.is_empty() { 1 } else { chunks.len() };

    for (i, chunk) in chunks.iter().enumerate() {
        let block_num = (i + 1) as u16;
        let packet = build_data_packet(block_num, chunk);

        let mut retries = 0;
        loop {
            transfer_socket.send_to(&packet, client).await?;
            if wait_for_ack(&transfer_socket, block_num, timeout).await? {
                break;
            }
            retries += 1;
            if retries >= 5 {
                anyhow::bail!("max retries exceeded for block {}", block_num);
            }
            debug!("retransmitting block {} to {}", block_num, client);
        }
    }

    // If file size is exact multiple of blksize, send a zero-length terminator
    if !file_data.is_empty() && file_data.len() % blksize == 0 {
        let block_num = (total_blocks + 1) as u16;
        let packet = build_data_packet(block_num, &[]);
        transfer_socket.send_to(&packet, client).await?;
        let _ = wait_for_ack(&transfer_socket, block_num, timeout).await;
    }

    info!(
        "TFTP transfer complete: {} ({} bytes, {} blocks) to {}",
        filename,
        file_data.len(),
        total_blocks,
        client
    );
    Ok(())
}

fn build_data_packet(block: u16, data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(4 + data.len());
    pkt.extend_from_slice(&OP_DATA.to_be_bytes());
    pkt.extend_from_slice(&block.to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}

fn build_oack(blksize: usize) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&OP_OACK.to_be_bytes());
    pkt.extend_from_slice(b"blksize\0");
    pkt.extend_from_slice(blksize.to_string().as_bytes());
    pkt.push(0);
    pkt
}

async fn wait_for_ack(socket: &UdpSocket, expected_block: u16, timeout: Duration) -> Result<bool> {
    let mut buf = [0u8; 4];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            if len >= 4 {
                let opcode = u16::from_be_bytes([buf[0], buf[1]]);
                let block = u16::from_be_bytes([buf[2], buf[3]]);
                if opcode == OP_ACK && block == expected_block {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Ok(false), // timeout
    }
}

async fn send_error(client: &SocketAddr, code: u16, msg: &str) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&OP_ERROR.to_be_bytes());
    pkt.extend_from_slice(&code.to_be_bytes());
    pkt.extend_from_slice(msg.as_bytes());
    pkt.push(0);
    socket.send_to(&pkt, client).await?;
    Ok(())
}
