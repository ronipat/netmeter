# NetMeter — Windows Network Traffic Monitor (Rust)

A lightweight, native Windows network traffic monitoring application and CLI written in Rust.

## Features

- **Windows System Tray App (`netmeter.exe`)**
  - Dynamic 32×32 tray icon displaying live **In (RX)** and **Out (TX)** activity bars with hover tooltip.
  - Compact rounded tray popup menu with live In/Out rates, session totals, established socket count, 3-option theme selector (**Dark**, **White**, **Cartoon**), **Start with Windows** toggle, **Open Full Monitor**, and **Quit**.
  - Runs the tray icon on a dedicated Win32 message-pump thread for zero UI freezes.

- **4-Tab Real-Time Dashboard**
  - **Overview**: 4 color-coded KPI cards (In, Out, Active Sockets, Security Triage), interface selector, smooth Catmull-Rom 120-second waveform chart, and full-height active processes table.
  - **Processes**: Per-PID process attribution (`OpenProcess` + `QueryFullProcessImageNameW`), socket breakdown (Established / Listening / UDP), executable paths, and optional kernel ETW per-process byte rates.
  - **Connections**: Live IPv4/IPv6 TCP & UDP socket viewer (`GetExtendedTcpTable` / `GetExtendedUdpTable`) with search, protocol/state filters, non-blocking reverse DNS (`GetNameInfoW`), port service labels, and security triage alerts.
  - **Adapters & Diagnostics**: Physical vs. virtual/filter interface table (`GetIfTable2`, filtering `HardwareInterface` to prevent double-counting), link speeds, errors/discards, IPv4 TCP stack health (`GetTcpStatisticsEx`), and JSON/CSV export.

- **3 Themes & 2 Languages**: **Dark**, **White**, and **Cartoon** (cel-shaded comic style with orange waveform), plus **English** and **Bahasa Indonesia**, all persisted under `HKCU\Software\NetMeter`.

- **Optional Kernel ETW Throughput (`src/etw.rs`)**
  - Listens to `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`) via `ferrisetw` when run as Administrator; gracefully degrades when run unprivileged.

- **Headless CLI (`netmeter-cli.exe`)**
  - Supports `--once`, `--watch [-n COUNT]`, `--json`, `--alerts`, `--export-json <PATH>`, and `--export-csv <PATH>`.

- **Native Windows Installer (`netmeter-setup.exe` / `build-installer.ps1`)**
  - Builds a self-contained `dist\NetMeter-Setup.exe` with GUI wizard, silent CLI mode, UAC elevation, Desktop/Start Menu shortcuts, Windows Installed Apps registration, optional user `PATH` & auto-start, and a clean uninstaller that automatically stops running instances.

## Build from Source

```powershell
# Run unit & live Windows API tests
cargo test

# Build release binaries (netmeter.exe, netmeter-cli.exe) and self-contained dist\NetMeter-Setup.exe
powershell -ExecutionPolicy Bypass -File .\build-installer.ps1
```

## Install / Uninstall

```powershell
# Interactive GUI installer
.\dist\NetMeter-Setup.exe

# Silent install / uninstall (auto-elevates via UAC)
.\dist\install.bat
.\dist\uninstall.bat
```
