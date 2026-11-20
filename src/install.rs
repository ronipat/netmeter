//! Windows installation, Start Menu / Desktop shortcuts, Auto-Start, PATH, and Add/Remove Programs registration.

use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HWND, LPARAM, WPARAM};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD,
    REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE,
};
use windows::Win32::System::Threading::{
    OpenEventW, OpenProcess, SetEvent, TerminateProcess, WaitForSingleObject, EVENT_MODIFY_STATE,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};
use windows::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, PostMessageW, SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG,
    SW_SHOWNORMAL, WM_CLOSE, WM_SETTINGCHANGE,
};

const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const UNINSTALL_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NetMeter";
const PREFS_SUBKEY: &str = r"Software\NetMeter";
const RUN_VALUE_NAME: &str = "NetMeter";
const APP_NAME: &str = "Net Meter";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn reg_write_sz(subkey: &str, name: &str, value: &str, expand: bool) -> Result<(), String> {
    let sub_w = to_wide_null(subkey);
    let name_w = to_wide_null(name);
    let val_w = to_wide_null(value);
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(val_w.as_ptr() as *const u8, val_w.len() * 2) };

    unsafe {
        let mut hkey = HKEY::default();
        let rc = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if rc != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW({subkey}) failed: {rc:?}"));
        }
        let kind = if expand { REG_EXPAND_SZ } else { REG_SZ };
        let rc2 = RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, kind, Some(bytes));
        let _ = RegCloseKey(hkey);
        if rc2 != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW({name}) failed: {rc2:?}"));
        }
    }
    Ok(())
}

fn reg_write_dword(subkey: &str, name: &str, value: u32) -> Result<(), String> {
    let sub_w = to_wide_null(subkey);
    let name_w = to_wide_null(name);
    let bytes = value.to_le_bytes();

    unsafe {
        let mut hkey = HKEY::default();
        let rc = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if rc != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW({subkey}) failed: {rc:?}"));
        }
        let rc2 = RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, REG_DWORD, Some(&bytes));
        let _ = RegCloseKey(hkey);
        if rc2 != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW({name}) failed: {rc2:?}"));
        }
    }
    Ok(())
}

fn reg_read_string(subkey: &str, name: &str) -> Option<String> {
    let sub_w = to_wide_null(subkey);
    let name_w = to_wide_null(name);
    unsafe {
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(sub_w.as_ptr()), 0, KEY_READ, &mut hkey)
            != ERROR_SUCCESS
        {
            return None;
        }
        let mut size = 0u32;
        let mut kind = REG_VALUE_TYPE::default();
        let rc = RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        );
        if rc != ERROR_SUCCESS || size < 2 {
            let _ = RegCloseKey(hkey);
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc2 = RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        let _ = RegCloseKey(hkey);
        if rc2 != ERROR_SUCCESS {
            return None;
        }
        let u16s: Vec<u16> = buf[..size as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let end = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
        Some(String::from_utf16_lossy(&u16s[..end]))
    }
}

fn reg_delete_value(subkey: &str, name: &str) {
    let sub_w = to_wide_null(subkey);
    let name_w = to_wide_null(name);
    unsafe {
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub_w.as_ptr()),
            0,
            KEY_WRITE,
            &mut hkey,
        ) == ERROR_SUCCESS
        {
            let _ = RegDeleteValueW(hkey, PCWSTR(name_w.as_ptr()));
            let _ = RegCloseKey(hkey);
        }
    }
}

fn reg_delete_tree(subkey: &str) {
    let sub_w = to_wide_null(subkey);
    unsafe {
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(sub_w.as_ptr()));
    }
}

pub fn default_install_dir() -> PathBuf {
    program_files_install_dir()
}

pub fn user_appdata_install_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local).join("Programs").join("NetMeter")
    } else if let Ok(profile) = std::env::var("USERPROFILE") {
        PathBuf::from(profile).join("NetMeter")
    } else {
        PathBuf::from(r"C:\NetMeter")
    }
}

pub fn program_files_install_dir() -> PathBuf {
    if let Ok(pf) = std::env::var("ProgramFiles") {
        PathBuf::from(pf).join("NetMeter")
    } else {
        PathBuf::from(r"C:\Program Files\NetMeter")
    }
}

pub fn is_elevated() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

/// Relaunch the current executable with Windows UAC elevation (`runas`).
pub fn relaunch_elevated(args: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let exe_w = to_wide_null(&exe.display().to_string());
    let args_w = to_wide_null(args);
    let rc = unsafe {
        ShellExecuteW(
            HWND::default(),
            w!("runas"),
            PCWSTR(exe_w.as_ptr()),
            if args.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR(args_w.as_ptr())
            },
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if (rc.0 as isize) <= 32 {
        return Err(format!("UAC elevation cancelled or failed (code {})", rc.0 as isize));
    }
    Ok(())
}

/// Open a native Windows folder picker dialog.
pub fn pick_folder(initial: &str) -> Option<String> {
    let esc = initial.replace('\'', "''");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; \
         $d = New-Object System.Windows.Forms.FolderBrowserDialog; \
         $d.Description = 'Select Net Meter installation folder'; \
         $d.SelectedPath = '{}'; \
         if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{ Write-Output $d.SelectedPath }}",
        esc
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-STA", "-Command", &script])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

pub fn start_menu_shortcut_path() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(|appdata| {
        PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Net Meter.lnk")
    })
}

pub fn desktop_shortcut_path() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .ok()
        .map(|p| PathBuf::from(p).join("Desktop").join("Net Meter.lnk"))
}

pub fn is_autostart_enabled() -> bool {
    reg_read_string(RUN_SUBKEY, RUN_VALUE_NAME).is_some()
}

pub fn set_autostart(enabled: bool, exe_path: &Path) -> Result<(), String> {
    if enabled {
        let quoted = format!("\"{}\"", exe_path.display());
        reg_write_sz(RUN_SUBKEY, RUN_VALUE_NAME, &quoted, false)
    } else {
        reg_delete_value(RUN_SUBKEY, RUN_VALUE_NAME);
        Ok(())
    }
}

pub fn installed_location() -> Option<PathBuf> {
    reg_read_string(UNINSTALL_SUBKEY, "InstallLocation").map(PathBuf::from)
}

pub fn register_uninstall_entry(
    install_dir: &Path,
    uninstall_cmd: &str,
    icon_path: &Path,
    estimated_kb: u32,
) -> Result<(), String> {
    reg_write_sz(UNINSTALL_SUBKEY, "DisplayName", APP_NAME, false)?;
    reg_write_sz(UNINSTALL_SUBKEY, "DisplayVersion", APP_VERSION, false)?;
    reg_write_sz(UNINSTALL_SUBKEY, "Publisher", "Net Meter", false)?;
    reg_write_sz(
        UNINSTALL_SUBKEY,
        "InstallLocation",
        &install_dir.display().to_string(),
        false,
    )?;
    reg_write_sz(
        UNINSTALL_SUBKEY,
        "DisplayIcon",
        &icon_path.display().to_string(),
        false,
    )?;
    reg_write_sz(UNINSTALL_SUBKEY, "UninstallString", uninstall_cmd, false)?;
    reg_write_dword(UNINSTALL_SUBKEY, "EstimatedSize", estimated_kb)?;
    reg_write_dword(UNINSTALL_SUBKEY, "NoModify", 1)?;
    reg_write_dword(UNINSTALL_SUBKEY, "NoRepair", 1)?;
    Ok(())
}

pub fn unregister_uninstall_entry() {
    reg_delete_tree(UNINSTALL_SUBKEY);
}

pub fn unregister_prefs() {
    reg_delete_tree(PREFS_SUBKEY);
}

fn broadcast_env_change() {
    unsafe {
        let env_w = w!("Environment");
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(env_w.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            1500,
            None,
        );
    }
}

pub fn add_to_user_path(dir: &Path) -> Result<(), String> {
    let dir_str = dir.display().to_string();
    let current = reg_read_string("Environment", "Path").unwrap_or_default();
    let exists = current
        .split(';')
        .any(|p| p.trim().eq_ignore_ascii_case(dir_str.trim()));
    if exists {
        return Ok(());
    }
    let updated = if current.trim().is_empty() {
        dir_str
    } else if current.trim_end().ends_with(';') {
        format!("{current}{dir_str}")
    } else {
        format!("{current};{dir_str}")
    };
    reg_write_sz("Environment", "Path", &updated, true)?;
    broadcast_env_change();
    Ok(())
}

pub fn remove_from_user_path(dir: &Path) -> Result<(), String> {
    let dir_str = dir.display().to_string();
    let Some(current) = reg_read_string("Environment", "Path") else {
        return Ok(());
    };
    let filtered: Vec<&str> = current
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case(&dir_str))
        .collect();
    let updated = filtered.join(";");
    reg_write_sz("Environment", "Path", &updated, true)?;
    broadcast_env_change();
    Ok(())
}

pub fn create_shortcut(
    lnk_path: &Path,
    target_exe: &Path,
    icon_path: &Path,
    working_dir: &Path,
    description: &str,
) -> Result<(), String> {
    if let Some(parent) = lnk_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create shortcut dir: {e}"))?;
    }
    let esc = |s: &str| s.replace('\'', "''");
    let script = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{}'); \
         $s.TargetPath = '{}'; \
         $s.WorkingDirectory = '{}'; \
         $s.IconLocation = '{},0'; \
         $s.Description = '{}'; \
         $s.Save()",
        esc(&lnk_path.display().to_string()),
        esc(&target_exe.display().to_string()),
        esc(&working_dir.display().to_string()),
        esc(&icon_path.display().to_string()),
        esc(description),
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("powershell shortcut failed: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(())
}

pub const QUIT_EVENT_NAME: &str = "Local\\NetMeterQuitSignal";

fn find_pids_by_names(targets: &[&str]) -> Vec<u32> {
    let mut pids = Vec::new();
    let self_pid = std::process::id();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return pids;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe = String::from_utf16_lossy(&entry.szExeFile[..len]).to_ascii_lowercase();
                if entry.th32ProcessID != self_pid && targets.iter().any(|&t| exe == t) {
                    pids.push(entry.th32ProcessID);
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    pids
}

pub fn is_netmeter_running() -> bool {
    !find_pids_by_names(&["netmeter.exe"]).is_empty()
}

pub fn signal_netmeter_quit() {
    let ev_w = to_wide_null(QUIT_EVENT_NAME);
    unsafe {
        if let Ok(h) = OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(ev_w.as_ptr())) {
            let _ = SetEvent(h);
            let _ = CloseHandle(h);
        }
    }
}

/// Gracefully closes (via named quit event & `WM_CLOSE`), then force-terminates any remaining
/// `netmeter.exe` and `netmeter-cli.exe` instances via Win32 `TerminateProcess` + `taskkill`.
/// Returns `true` if no `netmeter.exe` process remains running.
pub fn stop_running_netmeter() -> bool {
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // 1. Signal the dedicated quit event so running NetMeter cleans up its tray icon & exits.
    signal_netmeter_quit();

    // 2. Also post WM_CLOSE in case a tray/hidden window is listening.
    let title_w = to_wide_null("Net Meter");
    unsafe {
        if let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(title_w.as_ptr())) {
            let _ = PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
        }
    }

    for _ in 0..8 {
        if !is_netmeter_running() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(60));
    }

    // 3. Force-terminate any remaining netmeter.exe / netmeter-cli.exe processes directly.
    for pid in find_pids_by_names(&["netmeter.exe", "netmeter-cli.exe"]) {
        unsafe {
            if let Ok(h) = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) {
                let _ = TerminateProcess(h, 0);
                let _ = WaitForSingleObject(h, 800);
                let _ = CloseHandle(h);
            }
        }
    }

    if is_netmeter_running() {
        for img in ["netmeter.exe", "netmeter-cli.exe"] {
            let _ = Command::new("taskkill")
                .args(["/IM", img, "/T", "/F"])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        }
        for _ in 0..10 {
            if !is_netmeter_running() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    !is_netmeter_running()
}

pub fn remove_shortcuts() {
    if let Some(p) = start_menu_shortcut_path() {
        let _ = fs::remove_file(p);
    }
    if let Some(p) = desktop_shortcut_path() {
        let _ = fs::remove_file(p);
    }
}

pub fn load_theme_pref() -> String {
    reg_read_string(PREFS_SUBKEY, "Theme").unwrap_or_else(|| "dark".into())
}

pub fn save_theme_pref(theme_name: &str) {
    let _ = reg_write_sz(PREFS_SUBKEY, "Theme", theme_name, false);
}
