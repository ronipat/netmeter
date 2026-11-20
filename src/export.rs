//! Snapshot export utilities (JSON and CSV).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use crate::monitor::MonitorSnapshot;

/// Export the full snapshot to a pretty-printed JSON file.
pub fn export_json(snap: &MonitorSnapshot, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(snap)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(path, json)
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

/// Export all active connections and security flags to a CSV file.
pub fn export_connections_csv(snap: &MonitorSnapshot, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::from(
        "timestamp,protocol,local_addr,local_port,remote_addr,remote_port,remote_host,state,pid,process_name,process_path,service,alert_severity,alert_reason\n",
    );
    let ts = snap.timestamp.to_rfc3339();
    for c in &snap.connections {
        let remote_addr = c.remote_addr.map(|a| a.to_string()).unwrap_or_default();
        let remote_port = c.remote_port.map(|p| p.to_string()).unwrap_or_default();
        let remote_host = c.remote_host.as_deref().unwrap_or("");
        let state = c.state.map(|s| s.to_string()).unwrap_or_else(|| "UDP".into());
        let ppath = c.process_path.as_deref().unwrap_or("");
        let svc = c.port_service.as_deref().unwrap_or("");
        let (sev, reason) = match &c.alert {
            Some(a) => (format!("{:?}", a.severity), a.reason.as_str()),
            None => (String::new(), ""),
        };
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&ts),
            c.protocol,
            csv_escape(&c.local_addr.to_string()),
            c.local_port,
            csv_escape(&remote_addr),
            remote_port,
            csv_escape(remote_host),
            csv_escape(&state),
            c.pid,
            csv_escape(&c.process_name),
            csv_escape(ppath),
            csv_escape(svc),
            csv_escape(&sev),
            csv_escape(reason),
        );
    }
    fs::write(path, out)
}
