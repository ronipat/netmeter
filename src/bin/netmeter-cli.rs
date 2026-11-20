use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use netmeter::export;
use netmeter::monitor::{format_bytes, format_link_speed, format_rate, sample_once, start_monitor, MonitorSnapshot};

struct CliArgs {
    watch: bool,
    count: Option<usize>,
    interval_ms: u64,
    json: bool,
    alerts_only: bool,
    export_json: Option<PathBuf>,
    export_csv: Option<PathBuf>,
    help: bool,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut out = CliArgs {
        watch: false,
        count: None,
        interval_ms: 1000,
        json: false,
        alerts_only: false,
        export_json: None,
        export_csv: None,
        help: false,
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--watch" | "-w" => out.watch = true,
            "--once" => out.watch = false,
            "--json" => out.json = true,
            "--alerts" => out.alerts_only = true,
            "--help" | "-h" => out.help = true,
            "--count" | "-n" => {
                let v = args.next().ok_or("--count requires a number")?;
                out.count = Some(v.parse().map_err(|_| "invalid --count value")?);
            }
            "--interval-ms" => {
                let v = args.next().ok_or("--interval-ms requires milliseconds")?;
                out.interval_ms = v.parse::<u64>().map_err(|_| "invalid --interval-ms value")?.max(100);
            }
            "--export-json" => {
                let v = args.next().ok_or("--export-json requires a file path")?;
                out.export_json = Some(PathBuf::from(v));
            }
            "--export-csv" => {
                let v = args.next().ok_or("--export-csv requires a file path")?;
                out.export_csv = Some(PathBuf::from(v));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(out)
}

fn print_usage() {
    println!(
        "netmeter-cli - Windows Network Traffic Monitor (CLI)\n\n\
         USAGE:\n  netmeter-cli [OPTIONS]\n\n\
         OPTIONS:\n  \
           --once                 Capture one sample and exit (default)\n  \
           --watch, -w            Continuously print live samples every interval\n  \
           --count, -n <N>        Stop after N samples in --watch mode\n  \
           --interval-ms <MS>     Sampling interval in ms (default: 1000)\n  \
           --json                 Output full snapshot as JSON\n  \
           --alerts               Highlight/print security triage alerts\n  \
           --export-json <PATH>   Save JSON snapshot to PATH\n  \
           --export-csv <PATH>    Save connections CSV to PATH\n  \
           --help, -h             Show this help"
    );
}

fn print_human(snap: &MonitorSnapshot, alerts_only: bool) {
    println!(
        "=== Net Meter Snapshot [{}] ===",
        snap.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Throughput:  ↓ {}   ↑ {}   (Peak: ↓ {}  ↑ {})",
        format_rate(snap.down_bps),
        format_rate(snap.up_bps),
        format_rate(snap.peak_down_bps),
        format_rate(snap.peak_up_bps),
    );
    println!(
        "Sockets:     TCP Estab={}  Listen={}  TIME_WAIT={}  CLOSE_WAIT={}  UDP={}  Alerts={}",
        snap.tcp_summary.established,
        snap.tcp_summary.listen,
        snap.tcp_summary.time_wait,
        snap.tcp_summary.close_wait,
        snap.tcp_summary.udp_total,
        snap.alert_count
    );
    println!("ETW Status:  {}", snap.etw_status);

    if alerts_only {
        println!("\nSecurity Alerts ({}):", snap.alert_count);
        let mut any = false;
        for c in snap.connections.iter().filter(|c| c.alert.is_some()) {
            any = true;
            let a = c.alert.as_ref().unwrap();
            println!(
                "  [{:?}] {} (PID {}) -> {} | {}",
                a.severity,
                c.process_name,
                c.pid,
                c.remote_addr
                    .map(|ip| format!("{ip}:{}", c.remote_port.unwrap_or(0)))
                    .unwrap_or_else(|| "*".into()),
                a.reason
            );
        }
        if !any {
            println!("  None detected.");
        }
        return;
    }

    println!("\nPhysical Up Adapters:");
    for a in snap
        .adapters
        .iter()
        .filter(|a| a.info.is_hardware && a.info.is_up)
    {
        println!(
            "  - {} ({}) | Link {} | ↓ {}  ↑ {} | Total ↓ {}  ↑ {} | Err {}/{}",
            a.info.alias,
            a.info.description,
            format_link_speed(a.info.rx_link_bps),
            format_rate(a.down_bps),
            format_rate(a.up_bps),
            format_bytes(a.info.in_octets),
            format_bytes(a.info.out_octets),
            a.info.in_errors,
            a.info.out_errors
        );
    }

    println!("\nTop Processes:");
    for p in snap.processes.iter().take(10) {
        if let (Some(d), Some(u)) = (p.down_bps, p.up_bps) {
            println!(
                "  - {:<24} PID {:<6} Estab {:<3} Listen {:<3} UDP {:<3} ↓ {:<10} ↑ {}",
                p.name, p.pid, p.established_count, p.listening_count, p.udp_count, format_rate(d), format_rate(u)
            );
        } else {
            println!(
                "  - {:<24} PID {:<6} Estab {:<3} Listen {:<3} UDP {:<3}",
                p.name, p.pid, p.established_count, p.listening_count, p.udp_count
            );
        }
    }

    if let Some(st) = &snap.tcp_stats {
        println!(
            "\nTCPv4 Stack: CurrEstab={} ActiveOpens={} RetransSegs={} OutRsts={} InErrs={}",
            st.curr_estab, st.active_opens, st.retrans_segs, st.out_rsts, st.in_errs
        );
    }
}

fn handle_exports(snap: &MonitorSnapshot, args: &CliArgs) -> Result<(), String> {
    if let Some(ref p) = args.export_json {
        export::export_json(snap, p).map_err(|e| format!("JSON export failed: {e}"))?;
        eprintln!("Exported JSON snapshot to {}", p.display());
    }
    if let Some(ref p) = args.export_csv {
        export::export_connections_csv(snap, p).map_err(|e| format!("CSV export failed: {e}"))?;
        eprintln!("Exported CSV connections to {}", p.display());
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("Error: {err}");
            print_usage();
            return ExitCode::from(2);
        }
    };

    if args.help {
        print_usage();
        return ExitCode::SUCCESS;
    }

    if !args.watch {
        let snap = sample_once(Duration::from_millis(args.interval_ms));
        if let Err(e) = handle_exports(&snap, &args) {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
        if args.json {
            match serde_json::to_string_pretty(&snap) {
                Ok(j) => println!("{j}"),
                Err(e) => {
                    eprintln!("JSON serialization error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            print_human(&snap, args.alerts_only);
        }
        return ExitCode::SUCCESS;
    }

    let handle = start_monitor();
    let max_iters = args.count.unwrap_or(usize::MAX);
    for i in 0..max_iters {
        thread::sleep(Duration::from_millis(args.interval_ms));
        let snap = handle.snapshot.lock().unwrap().clone();
        if i == max_iters.saturating_sub(1) {
            if let Err(e) = handle_exports(&snap, &args) {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
        if args.json {
            if let Ok(j) = serde_json::to_string(&snap) {
                println!("{j}");
            }
        } else {
            print_human(&snap, args.alerts_only);
            println!();
        }
    }

    ExitCode::SUCCESS
}
