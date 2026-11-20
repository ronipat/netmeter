//! Optional: per-process bytes from Windows Kernel Network ETW.
//! Primary path uses `KernelTrace` (`EVENT_TRACE_FLAG_NETWORK_TCPIP` for TcpIp + UdpIp, matching
//! Windows Resource Monitor), with automatic fallback to `Microsoft-Windows-Kernel-Network`
//! (`MatchAnyKeyword = 0x30` for IPv4 + IPv6).
//! Requires administrator rights at runtime; gracefully degrades when run unprivileged.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ferrisetw::parser::Parser;
use ferrisetw::provider::kernel_providers::{KernelProvider, TCP_IP_PROVIDER};
use ferrisetw::provider::Provider;
use ferrisetw::trace::{stop_trace_by_name, KernelTrace, UserTrace};
use ferrisetw::{EventRecord, SchemaLocator, GUID};

/// `pid -> (bytes_received, bytes_sent)` cumulative since ETW trace started.
pub type PerProcessBytes = Arc<Mutex<HashMap<u32, (u64, u64)>>>;

const KERNEL_NETWORK_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
/// `KERNEL_NETWORK_KEYWORD_IPV4 (0x10) | KERNEL_NETWORK_KEYWORD_IPV6 (0x20)`
const KERNEL_NETWORK_KEYWORDS_IP: u64 = 0x30;
const TRACE_SESSION_NAME: &str = "NetMeterKernelNetwork";

/// Classic MOF UDP kernel provider GUID (`bf3a50c5-a9c9-4988-a005-2df0b7c80f80`) with
/// `EVENT_TRACE_FLAG_NETWORK_TCPIP` (`0x0001_0000`).
const UDP_IP_PROVIDER: KernelProvider = KernelProvider::new(
    GUID::from_values(
        0xbf3a50c5,
        0xa9c9,
        0x4988,
        [0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80],
    ),
    0x0001_0000,
);

#[allow(dead_code)]
enum ActiveTrace {
    Kernel(KernelTrace),
    User(UserTrace),
}

pub struct EtwSession {
    pub counters: PerProcessBytes,
    pub events_seen: Arc<AtomicU64>,
    _trace: ActiveTrace,
}

fn record_packet(
    counters: &PerProcessBytes,
    events_seen: &AtomicU64,
    record: &EventRecord,
    locator: &SchemaLocator,
    sent: bool,
) {
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let Ok(size) = parser.try_parse::<u32>("size") else {
        return;
    };
    if size == 0 {
        return;
    }
    let pid = match parser.try_parse::<u32>("PID") {
        Ok(p) => p,
        Err(_) => {
            let hdr_pid = record.process_id();
            if hdr_pid == u32::MAX {
                return;
            }
            hdr_pid
        }
    };

    events_seen.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut map) = counters.lock() {
        let entry = map.entry(pid).or_insert((0, 0));
        if sent {
            entry.1 = entry.1.saturating_add(size as u64);
        } else {
            entry.0 = entry.0.saturating_add(size as u64);
        }
    }
}

fn start_kernel_trace(
    counters: PerProcessBytes,
    events_seen: Arc<AtomicU64>,
) -> Result<KernelTrace, String> {
    let tcp_counters = Arc::clone(&counters);
    let tcp_events = Arc::clone(&events_seen);
    let tcp_provider = Provider::kernel(&TCP_IP_PROVIDER)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            // Classic MOF TcpIp opcodes:
            // 10 = SendIPV4, 26 = SendIPV6, 11 = RecvIPV4, 27 = RecvIPV6
            let sent = match record.opcode() {
                10 | 26 => true,
                11 | 27 => false,
                _ => return,
            };
            record_packet(&tcp_counters, &tcp_events, record, locator, sent);
        })
        .build();

    let udp_counters = Arc::clone(&counters);
    let udp_events = Arc::clone(&events_seen);
    let udp_provider = Provider::kernel(&UDP_IP_PROVIDER)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            // Classic MOF UdpIp opcodes:
            // 10 = SendIPV4, 26 = SendIPV6, 11 = RecvIPV4, 27 = RecvIPV6
            let sent = match record.opcode() {
                10 | 26 => true,
                11 | 27 => false,
                _ => return,
            };
            record_packet(&udp_counters, &udp_events, record, locator, sent);
        })
        .build();

    KernelTrace::new()
        .named(String::from(TRACE_SESSION_NAME))
        .enable(tcp_provider)
        .enable(udp_provider)
        .start_and_process()
        .map_err(|e| format!("{e:?}"))
}

fn start_user_trace(
    counters: PerProcessBytes,
    events_seen: Arc<AtomicU64>,
) -> Result<UserTrace, String> {
    let provider = Provider::by_guid(KERNEL_NETWORK_GUID)
        .any(KERNEL_NETWORK_KEYWORDS_IP)
        .level(4)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            // Microsoft-Windows-Kernel-Network event IDs:
            // 10/26 = TCP send v4/v6, 11/27 = TCP receive v4/v6,
            // 42/58 = UDP send v4/v6, 43/59 = UDP receive v4/v6
            let sent = match record.event_id() {
                10 | 26 | 42 | 58 => true,
                11 | 27 | 43 | 59 => false,
                _ => return,
            };
            record_packet(&counters, &events_seen, record, locator, sent);
        })
        .build();

    UserTrace::new()
        .named(String::from(TRACE_SESSION_NAME))
        .enable(provider)
        .start_and_process()
        .map_err(|e| format!("{e:?}"))
}

/// Start listening to Windows Kernel Network ETW events.
/// Returns `Err` if the current process lacks Administrator / Performance Log Users rights.
pub fn start_session() -> Result<EtwSession, String> {
    // Clean up any orphaned session left behind by a forced termination
    let _ = stop_trace_by_name(TRACE_SESSION_NAME);

    let counters: PerProcessBytes = Arc::new(Mutex::new(HashMap::new()));
    let events_seen = Arc::new(AtomicU64::new(0));

    match start_kernel_trace(Arc::clone(&counters), Arc::clone(&events_seen)) {
        Ok(trace) => Ok(EtwSession {
            counters,
            events_seen,
            _trace: ActiveTrace::Kernel(trace),
        }),
        Err(kernel_err) => {
            let _ = stop_trace_by_name(TRACE_SESSION_NAME);
            match start_user_trace(Arc::clone(&counters), Arc::clone(&events_seen)) {
                Ok(trace) => Ok(EtwSession {
                    counters,
                    events_seen,
                    _trace: ActiveTrace::User(trace),
                }),
                Err(user_err) => Err(format!("kernel={kernel_err}; user={user_err}")),
            }
        }
    }
}
