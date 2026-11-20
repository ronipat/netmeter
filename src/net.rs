//! Windows IP Helper, WinSock, and Process inspection APIs.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetExtendedTcpTable, GetExtendedUdpTable, GetIfTable2, GetTcpStatisticsEx,
    MIB_IF_ROW2, MIB_IF_TABLE2, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPSTATS_LH, MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_CLOSED,
    MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_DELETE_TCB,
    MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1, MIB_TCP_STATE_FIN_WAIT2,
    MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD,
    MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    socklen_t, GetNameInfoW, WSAStartup, AF_INET, AF_INET6, IN6_ADDR, IN_ADDR, NI_NAMEREQD,
    SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, WSADATA,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Network interface snapshot from `GetIfTable2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterInfo {
    pub luid: u64,
    pub index: u32,
    pub alias: String,
    pub description: String,
    /// `true` when `InterfaceAndOperStatusFlags.HardwareInterface` (bit 0) is set.
    /// Filtering virtual/filter adapters avoids 2-4x double-counting.
    pub is_hardware: bool,
    pub is_up: bool,
    pub mtu: u32,
    pub rx_link_bps: u64,
    pub tx_link_bps: u64,
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
}

fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end]).trim().to_string()
}

/// Enumerate all adapters from `GetIfTable2`.
pub fn adapters() -> Vec<AdapterInfo> {
    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2(&mut table) != NO_ERROR || table.is_null() {
            return Vec::new();
        }
        let rows: &[MIB_IF_ROW2] =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);

        let result = rows
            .iter()
            .map(|row| {
                let is_hardware = (row.InterfaceAndOperStatusFlags._bitfield & 0x1) != 0;
                let is_up = row.OperStatus == IfOperStatusUp;
                AdapterInfo {
                    luid: row.InterfaceLuid.Value,
                    index: row.InterfaceIndex,
                    alias: utf16_z_to_string(&row.Alias),
                    description: utf16_z_to_string(&row.Description),
                    is_hardware,
                    is_up,
                    mtu: row.Mtu,
                    rx_link_bps: row.ReceiveLinkSpeed,
                    tx_link_bps: row.TransmitLinkSpeed,
                    in_octets: row.InOctets,
                    out_octets: row.OutOctets,
                    in_errors: row.InErrors,
                    out_errors: row.OutErrors,
                    in_discards: row.InDiscards,
                    out_discards: row.OutDiscards,
                }
            })
            .collect();

        FreeMibTable(table as *const _);
        result
    }
}

/// Sum `(in_octets, out_octets)` across physical adapters that are currently Up.
pub fn sum_hardware_up_octets(list: &[AdapterInfo]) -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for a in list {
        if a.is_hardware && a.is_up {
            rx = rx.saturating_add(a.in_octets);
            tx = tx.saturating_add(a.out_octets);
        }
    }
    (rx, tx)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp4 => write!(f, "TCP4"),
            Protocol::Tcp6 => write!(f, "TCP6"),
            Protocol::Udp4 => write!(f, "UDP4"),
            Protocol::Udp6 => write!(f, "UDP6"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown(u32),
}

impl TcpState {
    pub fn from_raw(raw: u32) -> Self {
        match raw as i32 {
            x if x == MIB_TCP_STATE_CLOSED.0 => TcpState::Closed,
            x if x == MIB_TCP_STATE_LISTEN.0 => TcpState::Listen,
            x if x == MIB_TCP_STATE_SYN_SENT.0 => TcpState::SynSent,
            x if x == MIB_TCP_STATE_SYN_RCVD.0 => TcpState::SynRcvd,
            x if x == MIB_TCP_STATE_ESTAB.0 => TcpState::Established,
            x if x == MIB_TCP_STATE_FIN_WAIT1.0 => TcpState::FinWait1,
            x if x == MIB_TCP_STATE_FIN_WAIT2.0 => TcpState::FinWait2,
            x if x == MIB_TCP_STATE_CLOSE_WAIT.0 => TcpState::CloseWait,
            x if x == MIB_TCP_STATE_CLOSING.0 => TcpState::Closing,
            x if x == MIB_TCP_STATE_LAST_ACK.0 => TcpState::LastAck,
            x if x == MIB_TCP_STATE_TIME_WAIT.0 => TcpState::TimeWait,
            x if x == MIB_TCP_STATE_DELETE_TCB.0 => TcpState::DeleteTcb,
            _ => TcpState::Unknown(raw),
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRcvd => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT1",
            TcpState::FinWait2 => "FIN_WAIT2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::DeleteTcb => "DELETE_TCB",
            TcpState::Unknown(v) => return write!(f, "UNKNOWN({v})"),
        };
        f.write_str(s)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawConnection {
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: Option<TcpState>,
    pub pid: u32,
}

fn port_from_dword(dw: u32) -> u16 {
    u16::from_be(dw as u16)
}

/// Enumerate all IPv4 and IPv6 TCP connections and UDP endpoints with owning PIDs.
pub fn all_connections() -> Vec<RawConnection> {
    let mut out = Vec::with_capacity(256);
    collect_tcp4(&mut out);
    collect_tcp6(&mut out);
    collect_udp4(&mut out);
    collect_udp6(&mut out);
    out
}

fn collect_tcp4(out: &mut Vec<RawConnection>) {
    unsafe {
        let mut size = 0u32;
        let mut buf: Vec<u32> = Vec::new();
        for _ in 0..8 {
            let ptr = if buf.is_empty() {
                None
            } else {
                Some(buf.as_mut_ptr() as *mut _)
            };
            let rc = GetExtendedTcpTable(
                ptr,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if rc == NO_ERROR.0 && !buf.is_empty() {
                break;
            }
            if rc != ERROR_INSUFFICIENT_BUFFER.0 && rc != NO_ERROR.0 {
                return;
            }
            buf.resize(size as usize / 4 + 2, 0);
        }
        if buf.is_empty() {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows: &[MIB_TCPROW_OWNER_PID] =
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for r in rows {
            out.push(RawConnection {
                protocol: Protocol::Tcp4,
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))),
                local_port: port_from_dword(r.dwLocalPort),
                remote_addr: Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwRemoteAddr)))),
                remote_port: Some(port_from_dword(r.dwRemotePort)),
                state: Some(TcpState::from_raw(r.dwState)),
                pid: r.dwOwningPid,
            });
        }
    }
}

fn collect_tcp6(out: &mut Vec<RawConnection>) {
    unsafe {
        let mut size = 0u32;
        let mut buf: Vec<u32> = Vec::new();
        for _ in 0..8 {
            let ptr = if buf.is_empty() {
                None
            } else {
                Some(buf.as_mut_ptr() as *mut _)
            };
            let rc = GetExtendedTcpTable(
                ptr,
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if rc == NO_ERROR.0 && !buf.is_empty() {
                break;
            }
            if rc != ERROR_INSUFFICIENT_BUFFER.0 && rc != NO_ERROR.0 {
                return;
            }
            buf.resize(size as usize / 4 + 2, 0);
        }
        if buf.is_empty() {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows: &[MIB_TCP6ROW_OWNER_PID] =
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for r in rows {
            out.push(RawConnection {
                protocol: Protocol::Tcp6,
                local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                local_port: port_from_dword(r.dwLocalPort),
                remote_addr: Some(IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr))),
                remote_port: Some(port_from_dword(r.dwRemotePort)),
                state: Some(TcpState::from_raw(r.dwState)),
                pid: r.dwOwningPid,
            });
        }
    }
}

fn collect_udp4(out: &mut Vec<RawConnection>) {
    unsafe {
        let mut size = 0u32;
        let mut buf: Vec<u32> = Vec::new();
        for _ in 0..8 {
            let ptr = if buf.is_empty() {
                None
            } else {
                Some(buf.as_mut_ptr() as *mut _)
            };
            let rc = GetExtendedUdpTable(
                ptr,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if rc == NO_ERROR.0 && !buf.is_empty() {
                break;
            }
            if rc != ERROR_INSUFFICIENT_BUFFER.0 && rc != NO_ERROR.0 {
                return;
            }
            buf.resize(size as usize / 4 + 2, 0);
        }
        if buf.is_empty() {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows: &[MIB_UDPROW_OWNER_PID] =
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for r in rows {
            out.push(RawConnection {
                protocol: Protocol::Udp4,
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))),
                local_port: port_from_dword(r.dwLocalPort),
                remote_addr: None,
                remote_port: None,
                state: None,
                pid: r.dwOwningPid,
            });
        }
    }
}

fn collect_udp6(out: &mut Vec<RawConnection>) {
    unsafe {
        let mut size = 0u32;
        let mut buf: Vec<u32> = Vec::new();
        for _ in 0..8 {
            let ptr = if buf.is_empty() {
                None
            } else {
                Some(buf.as_mut_ptr() as *mut _)
            };
            let rc = GetExtendedUdpTable(
                ptr,
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if rc == NO_ERROR.0 && !buf.is_empty() {
                break;
            }
            if rc != ERROR_INSUFFICIENT_BUFFER.0 && rc != NO_ERROR.0 {
                return;
            }
            buf.resize(size as usize / 4 + 2, 0);
        }
        if buf.is_empty() {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows: &[MIB_UDP6ROW_OWNER_PID] =
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for r in rows {
            out.push(RawConnection {
                protocol: Protocol::Udp6,
                local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                local_port: port_from_dword(r.dwLocalPort),
                remote_addr: None,
                remote_port: None,
                state: None,
                pid: r.dwOwningPid,
            });
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TcpGlobalStats {
    pub curr_estab: u32,
    pub active_opens: u32,
    pub passive_opens: u32,
    pub attempt_fails: u32,
    pub estab_resets: u32,
    pub in_segs: u32,
    pub out_segs: u32,
    pub retrans_segs: u32,
    pub in_errs: u32,
    pub out_rsts: u32,
}

/// Read global IPv4 TCP stack counters via `GetTcpStatisticsEx` (retransmissions, resets, errors).
pub fn tcp_global_stats_v4() -> Option<TcpGlobalStats> {
    unsafe {
        let mut stats = MIB_TCPSTATS_LH::default();
        if GetTcpStatisticsEx(&mut stats, AF_INET.0 as u32) != NO_ERROR.0 {
            return None;
        }
        Some(TcpGlobalStats {
            curr_estab: stats.dwCurrEstab,
            active_opens: stats.dwActiveOpens,
            passive_opens: stats.dwPassiveOpens,
            attempt_fails: stats.dwAttemptFails,
            estab_resets: stats.dwEstabResets,
            in_segs: stats.dwInSegs,
            out_segs: stats.dwOutSegs,
            retrans_segs: stats.dwRetransSegs,
            in_errs: stats.dwInErrs,
            out_rsts: stats.dwOutRsts,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessMeta {
    pub name: String,
    pub path: Option<String>,
}

/// Query `(executable_name, full_path)` for a PID.
pub fn process_info(pid: u32) -> ProcessMeta {
    if pid == 0 {
        return ProcessMeta {
            name: "Idle".into(),
            path: None,
        };
    }
    if pid == 4 {
        return ProcessMeta {
            name: "System".into(),
            path: Some("NT Kernel & System / HTTP.sys".into()),
        };
    }
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return ProcessMeta {
                name: format!("PID {pid}"),
                path: None,
            };
        };
        let mut buf = [0u16; 512];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        if ok.is_err() || len == 0 {
            return ProcessMeta {
                name: format!("PID {pid}"),
                path: None,
            };
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
        ProcessMeta {
            name,
            path: Some(path),
        }
    }
}

/// Cached resolver for PID -> `ProcessMeta`.
#[derive(Default)]
pub struct ProcessCache {
    map: HashMap<u32, ProcessMeta>,
}

impl ProcessCache {
    pub fn get(&mut self, pid: u32) -> ProcessMeta {
        if let Some(cached) = self.map.get(&pid) {
            return cached.clone();
        }
        let info = process_info(pid);
        // Only cache real resolved names so transient processes don't pin stale PIDs forever.
        if info.path.is_some() || pid == 0 || pid == 4 {
            if self.map.len() > 2048 {
                self.map.clear();
            }
            self.map.insert(pid, info.clone());
        }
        info
    }
}

fn ensure_wsa() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| unsafe {
        let mut data = WSADATA::default();
        let _ = WSAStartup(0x0202, &mut data);
    });
}

/// Reverse DNS lookup using WinSock `GetNameInfoW(..., NI_NAMEREQD)`.
/// Returns `None` for unspecified/loopback addresses or if no PTR record exists.
pub fn reverse_dns(ip: IpAddr) -> Option<String> {
    if ip.is_unspecified() || ip.is_loopback() {
        return None;
    }
    ensure_wsa();

    let mut host = [0u16; 256];
    unsafe {
        let rc = match ip {
            IpAddr::V4(v4) => {
                let mut sa = SOCKADDR_IN::default();
                sa.sin_family = AF_INET;
                sa.sin_addr = IN_ADDR {
                    S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                };
                GetNameInfoW(
                    &sa as *const SOCKADDR_IN as *const SOCKADDR,
                    socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32),
                    Some(&mut host),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
            IpAddr::V6(v6) => {
                let mut sa = SOCKADDR_IN6::default();
                sa.sin6_family = AF_INET6;
                sa.sin6_addr = IN6_ADDR {
                    u: windows::Win32::Networking::WinSock::IN6_ADDR_0 {
                        Byte: v6.octets(),
                    },
                };
                GetNameInfoW(
                    &sa as *const SOCKADDR_IN6 as *const SOCKADDR,
                    socklen_t(std::mem::size_of::<SOCKADDR_IN6>() as i32),
                    Some(&mut host),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        };
        if rc != 0 {
            return None;
        }
    }

    let name = utf16_z_to_string(&host);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}
