use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use netmeter::export;
use netmeter::monitor::{format_bytes, format_link_speed, format_rate, sample_once};
use netmeter::net::{
    adapters, all_connections, process_info, sum_hardware_up_octets, tcp_global_stats_v4,
    AdapterInfo, Protocol, RawConnection, TcpState,
};
use netmeter::install::{default_install_dir, start_menu_shortcut_path};
use netmeter::position::{bottom_right, taskbar_dock_pos, work_area};
use netmeter::security::{inspect_connection, is_local_or_private, port_label, AlertSeverity};

#[test]
fn formatting_units_are_accurate() {
    assert_eq!(format_rate(512.0), "512 B/s");
    assert_eq!(format_rate(1536.0), "1.5 KB/s");
    assert_eq!(format_rate(2.5 * 1024.0 * 1024.0), "2.5 MB/s");

    assert_eq!(format_bytes(900), "900 B");
    assert_eq!(format_bytes(2048), "2.00 KB");
    assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MB");

    assert_eq!(format_link_speed(0), "N/A");
    assert_eq!(format_link_speed(1_000_000_000), "1.0 Gbps");
    assert_eq!(format_link_speed(100_000_000), "100 Mbps");
}

#[test]
fn security_ip_and_port_classification() {
    assert!(is_local_or_private(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(is_local_or_private(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
    assert!(is_local_or_private(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    assert!(is_local_or_private(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!is_local_or_private(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));

    assert_eq!(port_label(443), Some("HTTPS/TLS"));
    assert_eq!(port_label(7680), Some("DeliveryOpt"));
    assert_eq!(port_label(445), Some("SMB"));
    assert_eq!(port_label(5355), Some("LLMNR"));
}

#[test]
fn security_flags_lolbin_and_risky_outbound_ports() {
    let lolbin_public = RawConnection {
        protocol: Protocol::Tcp4,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        local_port: 51234,
        remote_addr: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        remote_port: Some(443),
        state: Some(TcpState::Established),
        pid: 9999,
    };
    let alert = inspect_connection(&lolbin_public, "powershell.exe").expect("should flag LOLBin");
    assert_eq!(alert.severity, AlertSeverity::High);

    let smb_public = RawConnection {
        protocol: Protocol::Tcp4,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        local_port: 51235,
        remote_addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        remote_port: Some(445),
        state: Some(TcpState::Established),
        pid: 1234,
    };
    let smb_alert = inspect_connection(&smb_public, "explorer.exe").expect("should flag public SMB");
    assert_eq!(smb_alert.severity, AlertSeverity::High);

    let normal_browser = RawConnection {
        protocol: Protocol::Tcp4,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        local_port: 51236,
        remote_addr: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        remote_port: Some(443),
        state: Some(TcpState::Established),
        pid: 4321,
    };
    assert!(inspect_connection(&normal_browser, "msedge.exe").is_none());
}

#[test]
fn hardware_up_filter_avoids_double_counting() {
    let list = vec![
        AdapterInfo {
            luid: 1,
            index: 1,
            alias: "Ethernet".into(),
            description: "Real NIC".into(),
            is_hardware: true,
            is_up: true,
            mtu: 1500,
            rx_link_bps: 1_000_000_000,
            tx_link_bps: 1_000_000_000,
            in_octets: 1000,
            out_octets: 500,
            in_errors: 0,
            out_errors: 0,
            in_discards: 0,
            out_discards: 0,
        },
        AdapterInfo {
            luid: 2,
            index: 2,
            alias: "WFP LightWeight Filter".into(),
            description: "Filter row".into(),
            is_hardware: false,
            is_up: true,
            mtu: 1500,
            rx_link_bps: 1_000_000_000,
            tx_link_bps: 1_000_000_000,
            in_octets: 1000,
            out_octets: 500,
            in_errors: 0,
            out_errors: 0,
            in_discards: 0,
            out_discards: 0,
        },
        AdapterInfo {
            luid: 3,
            index: 3,
            alias: "Disconnected NIC".into(),
            description: "Down".into(),
            is_hardware: true,
            is_up: false,
            mtu: 1500,
            rx_link_bps: 0,
            tx_link_bps: 0,
            in_octets: 9999,
            out_octets: 9999,
            in_errors: 0,
            out_errors: 0,
            in_discards: 0,
            out_discards: 0,
        },
    ];
    assert_eq!(sum_hardware_up_octets(&list), (1000, 500));
}

#[test]
fn live_windows_networking_apis_work() {
    let ifaces = adapters();
    assert!(!ifaces.is_empty(), "expected at least loopback/adapters");

    let conns = all_connections();
    assert!(!conns.is_empty(), "expected active TCP/UDP endpoints on Windows");

    let stats = tcp_global_stats_v4().expect("GetTcpStatisticsEx should succeed");
    assert!(stats.in_segs > 0 || stats.out_segs > 0 || stats.active_opens > 0);

    let self_meta = process_info(std::process::id());
    assert!(!self_meta.name.is_empty());
    assert!(self_meta.path.is_some());

    let wa = work_area();
    assert!(wa.right > wa.left && wa.bottom > wa.top);
    let pos = bottom_right([232.0, 76.0], 1.25, 10.0);
    assert!(pos[0] >= 0.0 && pos[1] >= 0.0);
    let tb_pos = taskbar_dock_pos([234.0, 40.0], 1.25);
    assert!(tb_pos[0] >= 0.0 && tb_pos[1] >= 0.0);

    let inst_dir = default_install_dir();
    assert!(inst_dir.ends_with("NetMeter"));
    assert!(start_menu_shortcut_path().is_some());
}

#[test]
fn snapshot_and_export_roundtrip() {
    let snap = sample_once(Duration::from_millis(120));
    assert!(!snap.adapters.is_empty());
    assert!(!snap.connections.is_empty());

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("netmeter_test_{}", std::process::id()));
    let json_path = dir.join("snap.json");
    let csv_path = dir.join("conns.csv");

    export::export_json(&snap, &json_path).expect("export json");
    export::export_connections_csv(&snap, &csv_path).expect("export csv");

    let json_text = std::fs::read_to_string(&json_path).unwrap();
    assert!(json_text.contains("down_bps"));
    let csv_text = std::fs::read_to_string(&csv_path).unwrap();
    assert!(csv_text.starts_with("timestamp,protocol,local_addr"));

    let _ = std::fs::remove_dir_all(&dir);
}
