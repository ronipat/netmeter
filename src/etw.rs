//! Optional: per-process bytes from the `Microsoft-Windows-Kernel-Network` ETW provider.
//! Requires administrator rights at runtime; gracefully degrades when run unprivileged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::{stop_trace_by_name, UserTrace};
use ferrisetw::{EventRecord, SchemaLocator};

/// `pid -> (bytes_received, bytes_sent)` cumulative since ETW trace started.
pub type PerProcessBytes = Arc<Mutex<HashMap<u32, (u64, u64)>>>;

const KERNEL_NETWORK_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
const TRACE_SESSION_NAME: &str = "NetMeterKernelNetwork";

pub struct EtwSession {
    pub counters: PerProcessBytes,
    _trace: UserTrace,
}

/// Start listening to `Microsoft-Windows-Kernel-Network` ETW events.
/// Returns `Err` if the current process lacks Administrator / Performance Log Users rights.
pub fn start_session() -> Result<EtwSession, String> {
    // Clean up any orphaned session left behind by a forced termination
    let _ = stop_trace_by_name(TRACE_SESSION_NAME);

    let counters: PerProcessBytes = Arc::new(Mutex::new(HashMap::new()));
    let counters_cb = Arc::clone(&counters);

    let provider = Provider::by_guid(KERNEL_NETWORK_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            // Event IDs for Microsoft-Windows-Kernel-Network:
            // 10/26 = TCP send v4/v6, 11/27 = TCP receive v4/v6,
            // 42/58 = UDP send v4/v6, 43/59 = UDP receive v4/v6
            let sent = match record.event_id() {
                10 | 26 | 42 | 58 => true,
                11 | 27 | 43 | 59 => false,
                _ => return,
            };
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let (Ok(pid), Ok(size)) = (
                parser.try_parse::<u32>("PID"),
                parser.try_parse::<u32>("size"),
            ) else {
                return;
            };
            if let Ok(mut map) = counters_cb.try_lock() {
                let entry = map.entry(pid).or_insert((0, 0));
                if sent {
                    entry.1 = entry.1.saturating_add(size as u64);
                } else {
                    entry.0 = entry.0.saturating_add(size as u64);
                }
            }
        })
        .build();

    let trace = UserTrace::new()
        .named(String::from(TRACE_SESSION_NAME))
        .enable(provider)
        .start_and_process()
        .map_err(|e| format!("{e:?}"))?;

    Ok(EtwSession {
        counters,
        _trace: trace,
    })
}
