//! Background network sampler, rate calculations, history ring buffer, and async reverse-DNS cache.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::net::{
    self, AdapterInfo, ProcessCache, Protocol, TcpGlobalStats, TcpState,
};
use crate::security::{self, ConnectionAlert};

#[cfg(feature = "etw")]
use crate::etw;

pub const HISTORY_CAPACITY: usize = 120;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct RateSample {
    pub down_bps: f64,
    pub up_bps: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterSnapshot {
    pub info: AdapterInfo,
    pub down_bps: f64,
    pub up_bps: f64,
    pub session_rx_bytes: u64,
    pub session_tx_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRow {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub established_count: usize,
    pub listening_count: usize,
    pub udp_count: usize,
    pub total_sockets: usize,
    pub down_bps: Option<f64>,
    pub up_bps: Option<f64>,
    pub session_rx_bytes: Option<u64>,
    pub session_tx_bytes: Option<u64>,
    pub alert_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionRow {
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub remote_host: Option<String>,
    pub state: Option<TcpState>,
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub port_service: Option<String>,
    pub alert: Option<ConnectionAlert>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TcpStateSummary {
    pub established: usize,
    pub listen: usize,
    pub time_wait: usize,
    pub close_wait: usize,
    pub syn_sent: usize,
    pub other: usize,
    pub udp_total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorSnapshot {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub down_bps: f64,
    pub up_bps: f64,
    pub peak_down_bps: f64,
    pub peak_up_bps: f64,
    pub session_rx_bytes: u64,
    pub session_tx_bytes: u64,
    pub selected_adapter_luid: Option<u64>,
    pub adapters: Vec<AdapterSnapshot>,
    pub history: VecDeque<RateSample>,
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<ConnectionRow>,
    pub alert_count: usize,
    pub tcp_summary: TcpStateSummary,
    pub tcp_stats: Option<TcpGlobalStats>,
    pub etw_active: bool,
    pub etw_status: String,
    pub paused: bool,
}

impl Default for MonitorSnapshot {
    fn default() -> Self {
        Self {
            seq: 0,
            timestamp: Utc::now(),
            down_bps: 0.0,
            up_bps: 0.0,
            peak_down_bps: 0.0,
            peak_up_bps: 0.0,
            session_rx_bytes: 0,
            session_tx_bytes: 0,
            selected_adapter_luid: None,
            adapters: Vec::new(),
            history: VecDeque::with_capacity(HISTORY_CAPACITY),
            processes: Vec::new(),
            connections: Vec::new(),
            alert_count: 0,
            tcp_summary: TcpStateSummary::default(),
            tcp_stats: None,
            etw_active: false,
            etw_status: "Initializing...".into(),
            paused: false,
        }
    }
}

pub struct MonitorControl {
    paused: AtomicBool,
    reset_requested: AtomicBool,
    selected_adapter_luid: Mutex<Option<u64>>,
    rdns_enabled: AtomicBool,
    rdns_cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    rdns_tx: mpsc::SyncSender<IpAddr>,
}

impl MonitorControl {
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }

    pub fn toggle_paused(&self) -> bool {
        let next = !self.is_paused();
        self.set_paused(next);
        next
    }

    pub fn request_reset(&self) {
        self.reset_requested.store(true, Ordering::Relaxed);
    }

    pub fn selected_adapter(&self) -> Option<u64> {
        *self.selected_adapter_luid.lock().unwrap()
    }

    pub fn set_selected_adapter(&self, luid: Option<u64>) {
        *self.selected_adapter_luid.lock().unwrap() = luid;
    }

    pub fn is_rdns_enabled(&self) -> bool {
        self.rdns_enabled.load(Ordering::Relaxed)
    }

    pub fn set_rdns_enabled(&self, enabled: bool) {
        self.rdns_enabled.store(enabled, Ordering::Relaxed);
    }

    fn queue_rdns(&self, ip: IpAddr) {
        if !self.is_rdns_enabled() || ip.is_unspecified() || ip.is_loopback() {
            return;
        }
        let cache = self.rdns_cache.lock().unwrap();
        if cache.contains_key(&ip) {
            return;
        }
        drop(cache);
        let _ = self.rdns_tx.try_send(ip);
    }

    fn lookup_rdns(&self, ip: IpAddr) -> Option<String> {
        self.rdns_cache
            .lock()
            .unwrap()
            .get(&ip)
            .cloned()
            .flatten()
    }
}

pub struct MonitorHandle {
    pub snapshot: Arc<Mutex<MonitorSnapshot>>,
    pub control: Arc<MonitorControl>,
}

/// Format bytes/sec into a concise human-readable string.
pub fn format_rate(bytes_per_sec: f64) -> String {
    const UNITS: [&str; 4] = ["B/s", "KB/s", "MB/s", "GB/s"];
    let mut v = bytes_per_sec.max(0.0);
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Format cumulative byte count into a concise human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

/// Format link speed in bits per second (e.g. `1.0 Gbps`, `100 Mbps`).
pub fn format_link_speed(bits_per_sec: u64) -> String {
    if bits_per_sec == 0 {
        return "N/A".into();
    }
    if bits_per_sec >= 1_000_000_000 {
        format!("{:.1} Gbps", bits_per_sec as f64 / 1_000_000_000.0)
    } else if bits_per_sec >= 1_000_000 {
        format!("{:.0} Mbps", bits_per_sec as f64 / 1_000_000.0)
    } else if bits_per_sec >= 1_000 {
        format!("{:.0} Kbps", bits_per_sec as f64 / 1_000.0)
    } else {
        format!("{bits_per_sec} bps")
    }
}

fn spawn_rdns_worker(cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>) -> mpsc::SyncSender<IpAddr> {
    let (tx, rx) = mpsc::sync_channel::<IpAddr>(64);
    thread::Builder::new()
        .name("netmeter-rdns".into())
        .spawn(move || {
            let mut in_flight: HashSet<IpAddr> = HashSet::new();
            while let Ok(ip) = rx.recv() {
                if !in_flight.insert(ip) {
                    continue;
                }
                {
                    let map = cache.lock().unwrap();
                    if map.contains_key(&ip) {
                        in_flight.remove(&ip);
                        continue;
                    }
                }
                let resolved = net::reverse_dns(ip);
                let mut map = cache.lock().unwrap();
                if map.len() > 2048 {
                    map.clear();
                }
                map.insert(ip, resolved);
                in_flight.remove(&ip);
            }
        })
        .expect("spawn rdns worker");
    tx
}

pub fn start_monitor() -> MonitorHandle {
    let rdns_cache = Arc::new(Mutex::new(HashMap::new()));
    let rdns_tx = spawn_rdns_worker(Arc::clone(&rdns_cache));

    let control = Arc::new(MonitorControl {
        paused: AtomicBool::new(false),
        reset_requested: AtomicBool::new(false),
        selected_adapter_luid: Mutex::new(None),
        rdns_enabled: AtomicBool::new(true),
        rdns_cache,
        rdns_tx,
    });

    let snapshot = Arc::new(Mutex::new(MonitorSnapshot::default()));
    let snap_bg = Arc::clone(&snapshot);
    let ctrl_bg = Arc::clone(&control);

    thread::Builder::new()
        .name("netmeter-sampler".into())
        .spawn(move || {
            #[cfg(feature = "etw")]
            let (etw_session, etw_active, etw_status) = match etw::start_session() {
                Ok(s) => (Some(s), true, "Active (per-process bytes/s)".to_string()),
                Err(err) => (
                    None,
                    false,
                    format!("Inactive (run as Admin for per-process bytes/s: {err})"),
                ),
            };
            #[cfg(not(feature = "etw"))]
            let (etw_active, etw_status) = (false, "Disabled at compile time".to_string());

            let initial_adapters = net::adapters();
            let mut prev_octets: HashMap<u64, (u64, u64)> = initial_adapters
                .iter()
                .map(|a| (a.luid, (a.in_octets, a.out_octets)))
                .collect();
            let mut baseline_octets: HashMap<u64, (u64, u64)> = prev_octets.clone();
            let mut prev_time = Instant::now();
            let mut proc_cache = ProcessCache::default();
            let mut history: VecDeque<RateSample> = VecDeque::with_capacity(HISTORY_CAPACITY);
            let mut peak_down = 0.0f64;
            let mut peak_up = 0.0f64;

            #[cfg(feature = "etw")]
            let mut prev_etw: HashMap<u32, (u64, u64)> = HashMap::new();
            #[cfg(feature = "etw")]
            let mut baseline_etw: HashMap<u32, (u64, u64)> = HashMap::new();

            let mut seq_counter: u64 = 0;
            let mut first_tick = true;
            loop {
                if first_tick {
                    first_tick = false;
                    thread::sleep(Duration::from_millis(100));
                } else {
                    thread::sleep(Duration::from_secs(1));
                }

                if ctrl_bg.reset_requested.swap(false, Ordering::Relaxed) {
                    let cur = net::adapters();
                    baseline_octets = cur
                        .iter()
                        .map(|a| (a.luid, (a.in_octets, a.out_octets)))
                        .collect();
                    prev_octets = baseline_octets.clone();
                    peak_down = 0.0;
                    peak_up = 0.0;
                    history.clear();
                    #[cfg(feature = "etw")]
                    if let Some(ref s) = etw_session {
                        if let Ok(map) = s.counters.lock() {
                            baseline_etw = map.clone();
                            prev_etw = map.clone();
                        }
                    }
                    prev_time = Instant::now();
                }

                if ctrl_bg.is_paused() {
                    let mut guard = snap_bg.lock().unwrap();
                    if !guard.paused {
                        guard.paused = true;
                        seq_counter = seq_counter.wrapping_add(1);
                        guard.seq = seq_counter;
                    }
                    prev_time = Instant::now();
                    continue;
                }

                let elapsed = prev_time.elapsed().as_secs_f64().max(0.05);
                prev_time = Instant::now();

                let raw_adapters = net::adapters();
                let mut adapter_snaps = Vec::with_capacity(raw_adapters.len());

                let mut total_down_bps = 0.0;
                let mut total_up_bps = 0.0;
                let mut total_session_rx = 0u64;
                let mut total_session_tx = 0u64;

                let selected_luid = ctrl_bg.selected_adapter();

                for info in raw_adapters {
                    let (prev_rx, prev_tx) = prev_octets
                        .get(&info.luid)
                        .copied()
                        .unwrap_or((info.in_octets, info.out_octets));
                    let (base_rx, base_tx) = baseline_octets
                        .entry(info.luid)
                        .or_insert((info.in_octets, info.out_octets));

                    // Handle counter wrap/reset if an adapter bounces
                    if info.in_octets < *base_rx {
                        *base_rx = info.in_octets;
                    }
                    if info.out_octets < *base_tx {
                        *base_tx = info.out_octets;
                    }

                    let down_bps = info.in_octets.saturating_sub(prev_rx) as f64 / elapsed;
                    let up_bps = info.out_octets.saturating_sub(prev_tx) as f64 / elapsed;
                    let session_rx = info.in_octets.saturating_sub(*base_rx);
                    let session_tx = info.out_octets.saturating_sub(*base_tx);

                    prev_octets.insert(info.luid, (info.in_octets, info.out_octets));

                    let include = match selected_luid {
                        Some(target) => info.luid == target,
                        None => info.is_hardware && info.is_up,
                    };
                    if include {
                        total_down_bps += down_bps;
                        total_up_bps += up_bps;
                        total_session_rx = total_session_rx.saturating_add(session_rx);
                        total_session_tx = total_session_tx.saturating_add(session_tx);
                    }

                    adapter_snaps.push(AdapterSnapshot {
                        info,
                        down_bps,
                        up_bps,
                        session_rx_bytes: session_rx,
                        session_tx_bytes: session_tx,
                    });
                }

                // Sort adapters: physical & up first, then by alias
                adapter_snaps.sort_by(|a, b| {
                    b.info
                        .is_hardware
                        .cmp(&a.info.is_hardware)
                        .then_with(|| b.info.is_up.cmp(&a.info.is_up))
                        .then_with(|| a.info.alias.cmp(&b.info.alias))
                });

                peak_down = peak_down.max(total_down_bps);
                peak_up = peak_up.max(total_up_bps);

                if history.len() >= HISTORY_CAPACITY {
                    history.pop_front();
                }
                history.push_back(RateSample {
                    down_bps: total_down_bps,
                    up_bps: total_up_bps,
                });

                // ETW per-process delta
                #[cfg(feature = "etw")]
                let etw_snapshot: Option<HashMap<u32, (f64, f64, u64, u64)>> =
                    if let Some(ref s) = etw_session {
                        let current = s.counters.lock().map(|m| m.clone()).unwrap_or_default();
                        let mut per_pid = HashMap::with_capacity(current.len());
                        for (pid, (rx, tx)) in &current {
                            let (prx, ptx) = prev_etw.get(pid).copied().unwrap_or((0, 0));
                            let (brx, btx) = baseline_etw.get(pid).copied().unwrap_or((0, 0));
                            let drx = rx.saturating_sub(prx) as f64 / elapsed;
                            let dtx = tx.saturating_sub(ptx) as f64 / elapsed;
                            let srx = rx.saturating_sub(brx);
                            let stx = tx.saturating_sub(btx);
                            per_pid.insert(*pid, (drx, dtx, srx, stx));
                        }
                        prev_etw = current;
                        Some(per_pid)
                    } else {
                        None
                    };
                #[cfg(not(feature = "etw"))]
                let etw_snapshot: Option<HashMap<u32, (f64, f64, u64, u64)>> = None;

                let raw_conns = net::all_connections();
                let mut tcp_summary = TcpStateSummary::default();
                let mut conn_rows = Vec::with_capacity(raw_conns.len());
                let mut proc_agg: HashMap<u32, ProcessRow> = HashMap::new();
                let mut alert_count = 0usize;

                for c in raw_conns {
                    let meta = proc_cache.get(c.pid);
                    let alert = security::inspect_connection(&c, &meta.name);
                    if alert.is_some() {
                        alert_count += 1;
                    }

                    let remote_host = c.remote_addr.and_then(|ip| {
                        ctrl_bg.queue_rdns(ip);
                        ctrl_bg.lookup_rdns(ip)
                    });

                    let port_service = c
                        .remote_port
                        .filter(|&p| p > 0)
                        .and_then(security::port_label)
                        .or_else(|| security::port_label(c.local_port))
                        .map(str::to_string);

                    match c.state {
                        Some(TcpState::Established) => tcp_summary.established += 1,
                        Some(TcpState::Listen) => tcp_summary.listen += 1,
                        Some(TcpState::TimeWait) => tcp_summary.time_wait += 1,
                        Some(TcpState::CloseWait) => tcp_summary.close_wait += 1,
                        Some(TcpState::SynSent) => tcp_summary.syn_sent += 1,
                        Some(_) => tcp_summary.other += 1,
                        None => tcp_summary.udp_total += 1,
                    }

                    let entry = proc_agg.entry(c.pid).or_insert_with(|| {
                        let (down_bps, up_bps, srx, stx) = etw_snapshot
                            .as_ref()
                            .and_then(|m| m.get(&c.pid))
                            .map(|&(d, u, rx, tx)| (Some(d), Some(u), Some(rx), Some(tx)))
                            .unwrap_or_else(|| {
                                if etw_active {
                                    (Some(0.0), Some(0.0), Some(0), Some(0))
                                } else {
                                    (None, None, None, None)
                                }
                            });

                        ProcessRow {
                            pid: c.pid,
                            name: meta.name.clone(),
                            path: meta.path.clone(),
                            established_count: 0,
                            listening_count: 0,
                            udp_count: 0,
                            total_sockets: 0,
                            down_bps,
                            up_bps,
                            session_rx_bytes: srx,
                            session_tx_bytes: stx,
                            alert_count: 0,
                        }
                    });

                    entry.total_sockets += 1;
                    match c.state {
                        Some(TcpState::Established) => entry.established_count += 1,
                        Some(TcpState::Listen) => entry.listening_count += 1,
                        None => entry.udp_count += 1,
                        _ => {}
                    }
                    if alert.is_some() {
                        entry.alert_count += 1;
                    }

                    conn_rows.push(ConnectionRow {
                        protocol: c.protocol,
                        local_addr: c.local_addr,
                        local_port: c.local_port,
                        remote_addr: c.remote_addr,
                        remote_port: c.remote_port,
                        remote_host,
                        state: c.state,
                        pid: c.pid,
                        process_name: meta.name,
                        process_path: meta.path,
                        port_service,
                        alert,
                    });
                }

                // Also add any PIDs seen by ETW that currently have no open sockets (bursty UDP/short-lived TCP)
                if let Some(ref map) = etw_snapshot {
                    for (&pid, &(drx, dtx, srx, stx)) in map {
                        if (drx > 0.0 || dtx > 0.0 || srx > 0 || stx > 0)
                            && !proc_agg.contains_key(&pid)
                        {
                            let meta = proc_cache.get(pid);
                            proc_agg.insert(
                                pid,
                                ProcessRow {
                                    pid,
                                    name: meta.name,
                                    path: meta.path,
                                    established_count: 0,
                                    listening_count: 0,
                                    udp_count: 0,
                                    total_sockets: 0,
                                    down_bps: Some(drx),
                                    up_bps: Some(dtx),
                                    session_rx_bytes: Some(srx),
                                    session_tx_bytes: Some(stx),
                                    alert_count: 0,
                                },
                            );
                        }
                    }
                }

                let mut processes: Vec<ProcessRow> = proc_agg.into_values().collect();
                processes.sort_by(|a, b| {
                    if etw_active {
                        let a_rate = a.down_bps.unwrap_or(0.0) + a.up_bps.unwrap_or(0.0);
                        let b_rate = b.down_bps.unwrap_or(0.0) + b.up_bps.unwrap_or(0.0);
                        b_rate
                            .partial_cmp(&a_rate)
                            .unwrap_or(std::cmp::Ordering::Equal)
                            .then_with(|| b.established_count.cmp(&a.established_count))
                            .then_with(|| b.total_sockets.cmp(&a.total_sockets))
                    } else {
                        b.established_count
                            .cmp(&a.established_count)
                            .then_with(|| b.total_sockets.cmp(&a.total_sockets))
                            .then_with(|| a.name.cmp(&b.name))
                    }
                });

                // Sort connections: alerts first, then Established, then Listen, then others
                conn_rows.sort_by(|a, b| {
                    b.alert
                        .is_some()
                        .cmp(&a.alert.is_some())
                        .then_with(|| {
                            let rank = |s: Option<TcpState>| match s {
                                Some(TcpState::Established) => 0,
                                Some(TcpState::Listen) => 1,
                                Some(_) => 2,
                                None => 3,
                            };
                            rank(a.state).cmp(&rank(b.state))
                        })
                        .then_with(|| a.process_name.cmp(&b.process_name))
                });

                let tcp_stats = net::tcp_global_stats_v4();
                seq_counter = seq_counter.wrapping_add(1);

                let next_snap = MonitorSnapshot {
                    seq: seq_counter,
                    timestamp: Utc::now(),
                    down_bps: total_down_bps,
                    up_bps: total_up_bps,
                    peak_down_bps: peak_down,
                    peak_up_bps: peak_up,
                    session_rx_bytes: total_session_rx,
                    session_tx_bytes: total_session_tx,
                    selected_adapter_luid: selected_luid,
                    adapters: adapter_snaps,
                    history: history.clone(),
                    processes,
                    connections: conn_rows,
                    alert_count,
                    tcp_summary,
                    tcp_stats,
                    etw_active,
                    etw_status: etw_status.clone(),
                    paused: false,
                };

                *snap_bg.lock().unwrap() = next_snap;
            }
        })
        .expect("spawn sampler thread");

    MonitorHandle { snapshot, control }
}

/// Capture a single synchronous snapshot over `interval` (useful for CLI `--once` and tests).
pub fn sample_once(interval: Duration) -> MonitorSnapshot {
    let before = net::adapters();
    let t0 = Instant::now();
    thread::sleep(interval);
    let elapsed = t0.elapsed().as_secs_f64().max(0.05);
    let after = net::adapters();

    let before_map: HashMap<u64, (u64, u64)> = before
        .iter()
        .map(|a| (a.luid, (a.in_octets, a.out_octets)))
        .collect();

    let mut total_down = 0.0;
    let mut total_up = 0.0;
    let mut adapter_snaps = Vec::with_capacity(after.len());

    for info in after {
        let (rx0, tx0) = before_map
            .get(&info.luid)
            .copied()
            .unwrap_or((info.in_octets, info.out_octets));
        let down_bps = info.in_octets.saturating_sub(rx0) as f64 / elapsed;
        let up_bps = info.out_octets.saturating_sub(tx0) as f64 / elapsed;
        if info.is_hardware && info.is_up {
            total_down += down_bps;
            total_up += up_bps;
        }
        adapter_snaps.push(AdapterSnapshot {
            info,
            down_bps,
            up_bps,
            session_rx_bytes: 0,
            session_tx_bytes: 0,
        });
    }

    let mut proc_cache = ProcessCache::default();
    let raw_conns = net::all_connections();
    let mut tcp_summary = TcpStateSummary::default();
    let mut proc_agg: HashMap<u32, ProcessRow> = HashMap::new();
    let mut conn_rows = Vec::with_capacity(raw_conns.len());
    let mut alert_count = 0usize;

    for c in raw_conns {
        let meta = proc_cache.get(c.pid);
        let alert = security::inspect_connection(&c, &meta.name);
        if alert.is_some() {
            alert_count += 1;
        }
        let port_service = c
            .remote_port
            .filter(|&p| p > 0)
            .and_then(security::port_label)
            .or_else(|| security::port_label(c.local_port))
            .map(str::to_string);

        match c.state {
            Some(TcpState::Established) => tcp_summary.established += 1,
            Some(TcpState::Listen) => tcp_summary.listen += 1,
            Some(TcpState::TimeWait) => tcp_summary.time_wait += 1,
            Some(TcpState::CloseWait) => tcp_summary.close_wait += 1,
            Some(TcpState::SynSent) => tcp_summary.syn_sent += 1,
            Some(_) => tcp_summary.other += 1,
            None => tcp_summary.udp_total += 1,
        }

        let entry = proc_agg.entry(c.pid).or_insert_with(|| ProcessRow {
            pid: c.pid,
            name: meta.name.clone(),
            path: meta.path.clone(),
            established_count: 0,
            listening_count: 0,
            udp_count: 0,
            total_sockets: 0,
            down_bps: None,
            up_bps: None,
            session_rx_bytes: None,
            session_tx_bytes: None,
            alert_count: 0,
        });
        entry.total_sockets += 1;
        match c.state {
            Some(TcpState::Established) => entry.established_count += 1,
            Some(TcpState::Listen) => entry.listening_count += 1,
            None => entry.udp_count += 1,
            _ => {}
        }
        if alert.is_some() {
            entry.alert_count += 1;
        }

        conn_rows.push(ConnectionRow {
            protocol: c.protocol,
            local_addr: c.local_addr,
            local_port: c.local_port,
            remote_addr: c.remote_addr,
            remote_port: c.remote_port,
            remote_host: None,
            state: c.state,
            pid: c.pid,
            process_name: meta.name,
            process_path: meta.path,
            port_service,
            alert,
        });
    }

    let mut processes: Vec<ProcessRow> = proc_agg.into_values().collect();
    processes.sort_by(|a, b| {
        b.established_count
            .cmp(&a.established_count)
            .then_with(|| b.total_sockets.cmp(&a.total_sockets))
    });

    let mut history = VecDeque::with_capacity(1);
    history.push_back(RateSample {
        down_bps: total_down,
        up_bps: total_up,
    });

    MonitorSnapshot {
        seq: 1,
        timestamp: Utc::now(),
        down_bps: total_down,
        up_bps: total_up,
        peak_down_bps: total_down,
        peak_up_bps: total_up,
        session_rx_bytes: 0,
        session_tx_bytes: 0,
        selected_adapter_luid: None,
        adapters: adapter_snaps,
        history,
        processes,
        connections: conn_rows,
        alert_count,
        tcp_summary,
        tcp_stats: net::tcp_global_stats_v4(),
        etw_active: false,
        etw_status: "Single-shot sample".into(),
        paused: false,
    }
}
