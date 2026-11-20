//! Security heuristics, port labeling, and triage checks based on Windows network research.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::net::{RawConnection, TcpState};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Warning,
    High,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionAlert {
    pub severity: AlertSeverity,
    pub reason: String,
}

/// Living-off-the-land / scripting binaries whose outbound network connections warrant review.
const LOLBINS: &[&str] = &[
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "certutil.exe",
    "wscript.exe",
    "cscript.exe",
    "bitsadmin.exe",
    "cmd.exe",
    "wmic.exe",
    "msbuild.exe",
    "installutil.exe",
];

/// Returns `true` if `ip` is unspecified, loopback, RFC1918 private, or link-local/ULA.
pub fn is_local_or_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || ((v6.segments()[0] & 0xffc0) == 0xfe80) // link-local fe80::/10
                || ((v6.segments()[0] & 0xfe00) == 0xfc00) // ULA fc00::/7
        }
    }
}

/// Human-friendly label for common Windows & Internet ports.
pub fn port_label(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("FTP"),
        22 => Some("SSH/SFTP"),
        23 => Some("Telnet"),
        25 | 587 => Some("SMTP"),
        53 => Some("DNS"),
        67 | 68 => Some("DHCP"),
        80 => Some("HTTP"),
        88 => Some("Kerberos"),
        123 => Some("NTP"),
        135 => Some("RPC EPM"),
        137..=139 => Some("NetBIOS"),
        389 | 636 => Some("LDAP/S"),
        443 => Some("HTTPS/TLS"),
        445 => Some("SMB"),
        1433 => Some("MSSQL"),
        1900 => Some("SSDP"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        3702 => Some("WSD"),
        5040 => Some("CDPSvc"),
        5353 => Some("mDNS"),
        5355 => Some("LLMNR"),
        5432 => Some("PostgreSQL"),
        5985 | 5986 => Some("WinRM"),
        7680 => Some("DeliveryOpt"),
        8080 | 8443 => Some("HTTP-Alt"),
        _ => None,
    }
}

/// Evaluate a connection and return a security alert if any heuristic triggers.
pub fn inspect_connection(conn: &RawConnection, process_name: &str) -> Option<ConnectionAlert> {
    let lower = process_name.to_ascii_lowercase();
    let is_lolbin = LOLBINS.iter().any(|&b| lower == b);

    let is_listening = conn.state == Some(TcpState::Listen);
    if is_listening {
        if is_lolbin {
            return Some(ConnectionAlert {
                severity: AlertSeverity::High,
                reason: format!("Unusual listening socket from {process_name} on port {}", conn.local_port),
            });
        }
        return None;
    }

    if let (Some(remote_ip), Some(remote_port)) = (conn.remote_addr, conn.remote_port) {
        if remote_ip.is_unspecified() || remote_ip.is_loopback() {
            return None;
        }

        let is_public = !is_local_or_private(remote_ip);

        if is_lolbin && is_public {
            return Some(ConnectionAlert {
                severity: AlertSeverity::High,
                reason: format!(
                    "Living-off-the-land binary ({process_name}) talking to public IP {remote_ip}:{remote_port}"
                ),
            });
        }

        if is_lolbin {
            return Some(ConnectionAlert {
                severity: AlertSeverity::Warning,
                reason: format!(
                    "Script/admin tool ({process_name}) connected to {remote_ip}:{remote_port}"
                ),
            });
        }

        if is_public {
            match remote_port {
                445 => {
                    return Some(ConnectionAlert {
                        severity: AlertSeverity::High,
                        reason: format!("Outbound SMB (445) to public IP {remote_ip}"),
                    });
                }
                3389 => {
                    return Some(ConnectionAlert {
                        severity: AlertSeverity::Warning,
                        reason: format!("Outbound RDP (3389) to public IP {remote_ip}"),
                    });
                }
                5985 | 5986 => {
                    return Some(ConnectionAlert {
                        severity: AlertSeverity::Warning,
                        reason: format!("Outbound WinRM ({remote_port}) to public IP {remote_ip}"),
                    });
                }
                23 | 135 | 137..=139 => {
                    return Some(ConnectionAlert {
                        severity: AlertSeverity::High,
                        reason: format!(
                            "Cleartext/legacy admin port ({remote_port}) to public IP {remote_ip}"
                        ),
                    });
                }
                _ => {}
            }
        }
    }

    None
}
