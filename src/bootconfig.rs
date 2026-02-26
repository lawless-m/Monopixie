use crate::config::Config;

/// Generate a GRUB configuration file from the application config.
///
/// The generated config boots immediately (no menu timeout) into a Debian
/// system over iSCSI, passing all necessary kernel parameters for network
/// setup and iSCSI initiator configuration.
pub fn generate_grub_cfg(config: &Config) -> String {
    let server_ip = &config.network.server_ip;
    let http_port = config.http.port;
    let http_base = format!("(http,{server_ip}:{http_port})");

    let kernel_path = format!("{http_base}/{}", config.http.kernel);
    let initrd_path = format!("{http_base}/{}", config.http.initrd);

    let client_ip = &config.dhcp.client_ip;
    let netmask = &config.network.netmask;
    let ip_arg = format!("ip={client_ip}::{server_ip}:{netmask}::eth0:none");

    let iscsi = &config.iscsi;

    format!(
        "\
set timeout=0
set default=0

menuentry \"Debian (iSCSI)\" {{
    linux {kernel_path} \\
        root=UUID={root_uuid} \\
        {ip_arg} \\
        ISCSI_INITIATOR={initiator_iqn} \\
        ISCSI_TARGET_NAME={target_iqn} \\
        ISCSI_TARGET_IP={target_ip} \\
        ISCSI_TARGET_PORT={target_port} \\
        rd.iscsi.initiator={initiator_iqn} \\
        rd.iscsi.target.name={target_iqn} \\
        rd.iscsi.target.ip={target_ip} \\
        rd.iscsi.target.port={target_port} \\
        rd.iscsi.target.lun={lun} \\
        quiet
    initrd {initrd_path}
}}
",
        root_uuid = iscsi.root_uuid,
        initiator_iqn = iscsi.initiator_iqn,
        target_iqn = iscsi.target_iqn,
        target_ip = iscsi.target_ip,
        target_port = iscsi.target_port,
        lun = iscsi.lun,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use std::path::PathBuf;

    fn test_config() -> Config {
        Config {
            network: NetworkConfig {
                interface: "eth0".into(),
                server_ip: "10.11.12.1".into(),
                netmask: "255.255.255.0".into(),
            },
            dhcp: DhcpConfig {
                client_mac: "AA:BB:CC:DD:EE:FF".into(),
                client_ip: "10.11.12.2".into(),
                lease_seconds: 86400,
            },
            tftp: TftpConfig {
                root: PathBuf::from("/srv/pxe/tftp"),
                bios_bootfile: "grub/i386-pc/core.0".into(),
                uefi_bootfile: "grub/x86_64-efi/grubnetx64.efi".into(),
                timeout_seconds: 5,
            },
            http: HttpConfig {
                port: 8080,
                root: PathBuf::from("/srv/pxe/http"),
                kernel: "debian/vmlinuz".into(),
                initrd: "debian/initrd.img".into(),
            },
            iscsi: IscsiConfig {
                target_iqn: "iqn.2024-01.local.laptop:debian-thinclient".into(),
                target_ip: "10.11.12.1".into(),
                target_port: 3260,
                lun: 0,
                initiator_iqn: "iqn.2024-01.local.thinclient:initiator".into(),
                root_uuid: "abcd-1234-efgh-5678".into(),
            },
        }
    }

    #[test]
    fn grub_cfg_contains_kernel_and_initrd() {
        let cfg = generate_grub_cfg(&test_config());
        assert!(cfg.contains("(http,10.11.12.1:8080)/debian/vmlinuz"));
        assert!(cfg.contains("(http,10.11.12.1:8080)/debian/initrd.img"));
    }

    #[test]
    fn grub_cfg_contains_iscsi_params() {
        let cfg = generate_grub_cfg(&test_config());
        assert!(cfg.contains("ISCSI_INITIATOR=iqn.2024-01.local.thinclient:initiator"));
        assert!(cfg.contains("ISCSI_TARGET_NAME=iqn.2024-01.local.laptop:debian-thinclient"));
        assert!(cfg.contains("ISCSI_TARGET_IP=10.11.12.1"));
        assert!(cfg.contains("ISCSI_TARGET_PORT=3260"));
        assert!(cfg.contains("root=UUID=abcd-1234-efgh-5678"));
    }

    #[test]
    fn grub_cfg_contains_ip_arg() {
        let cfg = generate_grub_cfg(&test_config());
        assert!(cfg.contains("ip=10.11.12.2::10.11.12.1:255.255.255.0::eth0:none"));
    }

    #[test]
    fn grub_cfg_contains_dracut_params() {
        let cfg = generate_grub_cfg(&test_config());
        assert!(cfg.contains("rd.iscsi.initiator=iqn.2024-01.local.thinclient:initiator"));
        assert!(cfg.contains("rd.iscsi.target.name=iqn.2024-01.local.laptop:debian-thinclient"));
        assert!(cfg.contains("rd.iscsi.target.lun=0"));
    }
}
