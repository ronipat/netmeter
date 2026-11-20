#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use eframe::egui::{self, Color32, RichText};
use netmeter::app_icon_data;
use netmeter::install;
use netmeter::theme::{self, BG, EMERALD, TEXT_MAIN, TEXT_MUTED};

#[cfg(feature = "embed-payload")]
const PAYLOAD_GUI: &[u8] = include_bytes!("../../target/release/netmeter.exe");
#[cfg(feature = "embed-payload")]
const PAYLOAD_CLI: &[u8] = include_bytes!("../../target/release/netmeter-cli.exe");
const PAYLOAD_ICO: &[u8] = include_bytes!("../../assets/netmeter.ico");

#[derive(Clone)]
struct InstallOpts {
    install_dir: String,
    autostart: bool,
    start_menu: bool,
    desktop_shortcut: bool,
    add_to_path: bool,
    launch_after: bool,
}

impl Default for InstallOpts {
    fn default() -> Self {
        Self {
            install_dir: install::default_install_dir().display().to_string(),
            autostart: false,
            start_menu: false,
            desktop_shortcut: true,
            add_to_path: false,
            launch_after: true,
        }
    }
}

fn portable_fallback_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("NetMeter")
}

fn write_payload_bin(name: &str, dest: &Path) -> Result<u64, String> {
    #[cfg(feature = "embed-payload")]
    {
        let bytes = match name {
            "netmeter.exe" => PAYLOAD_GUI,
            "netmeter-cli.exe" => PAYLOAD_CLI,
            _ => return Err(format!("Unknown payload: {name}")),
        };
        fs::write(dest, bytes).map_err(|e| format!("Failed writing {}: {e}", dest.display()))?;
        return Ok(bytes.len() as u64);
    }
    #[cfg(not(feature = "embed-payload"))]
    {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        let candidates = [
            exe_dir.join(name),
            PathBuf::from("target").join("release").join(name),
            PathBuf::from("netmeter").join("target").join("release").join(name),
        ];
        let src = candidates
            .iter()
            .find(|p| p.exists())
            .ok_or_else(|| format!("Could not locate {name} next to installer"))?;
        fs::copy(src, dest)
            .map_err(|e| format!("Failed copying {} -> {}: {e}", src.display(), dest.display()))
    }
}

fn perform_install(opts: &InstallOpts) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let dir = PathBuf::from(opts.install_dir.trim());
    if dir.as_os_str().is_empty() {
        return Err("Install directory cannot be empty".into());
    }

    if !install::stop_running_netmeter() {
        return Err(
            "Could not stop running Net Meter (Access is denied; Administrator rights required)"
                .into(),
        );
    }
    fs::create_dir_all(&dir).map_err(|e| format!("Create install dir: {e}"))?;
    log.push(format!("Install directory: {}", dir.display()));

    let gui_dest = dir.join("netmeter.exe");
    let cli_dest = dir.join("netmeter-cli.exe");
    let ico_dest = dir.join("netmeter.ico");
    let uninst_dest = dir.join("uninstall.exe");

    let gui_sz = write_payload_bin("netmeter.exe", &gui_dest)?;
    let cli_sz = write_payload_bin("netmeter-cli.exe", &cli_dest)?;
    fs::write(&ico_dest, PAYLOAD_ICO)
        .map_err(|e| format!("Write {}: {e}", ico_dest.display()))?;

    if let Ok(self_exe) = std::env::current_exe() {
        if self_exe != uninst_dest {
            let _ = fs::copy(&self_exe, &uninst_dest);
        }
    }
    log.push("Installed netmeter.exe, netmeter-cli.exe, netmeter.ico".into());

    let est_kb = ((gui_sz + cli_sz + PAYLOAD_ICO.len() as u64) / 1024).max(1024) as u32;
    let uninstall_cmd = format!("\"{}\" --uninstall", uninst_dest.display());
    match install::register_uninstall_entry(&dir, &uninstall_cmd, &ico_dest, est_kb) {
        Ok(()) => log.push("Registered in Windows Installed Apps (Add/Remove Programs)".into()),
        Err(e) => log.push(format!("Warning (Apps registration skipped): {e}")),
    }

    if opts.start_menu {
        if let Some(lnk) = install::start_menu_shortcut_path() {
            match install::create_shortcut(
                &lnk,
                &gui_dest,
                &ico_dest,
                &dir,
                "Net Meter — Windows Network Traffic Monitor",
            ) {
                Ok(()) => log.push(format!("Created Start Menu shortcut: {}", lnk.display())),
                Err(e) => log.push(format!("Warning (Start Menu shortcut skipped): {e}")),
            }
        }
    }

    if opts.desktop_shortcut {
        if let Some(lnk) = install::desktop_shortcut_path() {
            match install::create_shortcut(
                &lnk,
                &gui_dest,
                &ico_dest,
                &dir,
                "Net Meter — Windows Network Traffic Monitor",
            ) {
                Ok(()) => log.push(format!("Created Desktop shortcut: {}", lnk.display())),
                Err(e) => log.push(format!("Warning (Desktop shortcut skipped): {e}")),
            }
        }
    }

    if opts.autostart {
        match install::set_autostart(true, &gui_dest) {
            Ok(()) => log.push("Enabled Start with Windows (HKCU Run)".into()),
            Err(e) => log.push(format!("Warning (Auto-start skipped): {e}")),
        }
    } else {
        let _ = install::set_autostart(false, &gui_dest);
        log.push("Auto-start with Windows left disabled".into());
    }

    if opts.add_to_path {
        match install::add_to_user_path(&dir) {
            Ok(()) => log.push("Added NetMeter to user PATH (netmeter-cli available in terminal)".into()),
            Err(e) => log.push(format!("Warning (PATH update skipped): {e}")),
        }
    }

    if opts.launch_after {
        Command::new(&gui_dest)
            .current_dir(&dir)
            .spawn()
            .map_err(|e| format!("Failed launching Net Meter: {e}"))?;
        log.push("Launched Net Meter in Windows system tray".into());
    }

    Ok(log)
}

fn schedule_dir_cleanup(dir: &Path) {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let _ = std::env::set_current_dir(std::env::temp_dir());
    let dir_str = dir.display().to_string().replace('"', "");
    let raw = format!("/C \"ping 127.0.0.1 -n 3 > nul & rmdir /S /Q \"{dir_str}\"\"");
    let _ = Command::new("cmd")
        .raw_arg(&raw)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

fn perform_uninstall(
    target_dir: Option<&Path>,
    defer_dir_cleanup: bool,
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    let mut log = Vec::new();
    let dir = target_dir
        .map(Path::to_path_buf)
        .or_else(install::installed_location)
        .unwrap_or_else(install::default_install_dir);

    if !install::stop_running_netmeter() {
        return Err(
            "Could not stop running Net Meter (Access is denied; Administrator rights required)"
                .into(),
        );
    }
    log.push("Stopped running Net Meter instance".into());

    let _ = install::set_autostart(false, &dir.join("netmeter.exe"));
    install::unregister_uninstall_entry();
    install::unregister_prefs();
    install::remove_shortcuts();
    let _ = install::remove_from_user_path(&dir);
    log.push("Removed Registry entries, Start Menu/Desktop shortcuts, and PATH".into());

    for file in ["netmeter.exe", "netmeter-cli.exe", "netmeter.ico"] {
        let p = dir.join(file);
        if p.exists() {
            fs::remove_file(&p)
                .map_err(|e| format!("Failed removing {}: {e}", p.display()))?;
        }
    }

    let mut deferred = None;
    if dir.exists() {
        let _ = std::env::set_current_dir(std::env::temp_dir());
        if fs::remove_dir_all(&dir).is_ok() {
            log.push(format!("Removed {}", dir.display()));
        } else if defer_dir_cleanup {
            deferred = Some(dir.clone());
            log.push(format!(
                "Will remove {} automatically when you close this window",
                dir.display()
            ));
        } else {
            schedule_dir_cleanup(&dir);
            log.push(format!("Scheduled cleanup of {}", dir.display()));
        }
    }

    Ok((log, deferred))
}

fn elevated_args_from_opts(opts: &InstallOpts, auto_install: bool) -> String {
    let mut parts = Vec::new();
    let escaped_dir = opts.install_dir.replace('"', "");
    parts.push(format!("--dir \"{escaped_dir}\""));
    if opts.autostart {
        parts.push("--autostart".into());
    } else {
        parts.push("--no-autostart".into());
    }
    if opts.start_menu {
        parts.push("--start-menu".into());
    } else {
        parts.push("--no-start-menu".into());
    }
    if opts.desktop_shortcut {
        parts.push("--desktop".into());
    } else {
        parts.push("--no-desktop".into());
    }
    if opts.add_to_path {
        parts.push("--path".into());
    } else {
        parts.push("--no-path".into());
    }
    if opts.launch_after {
        parts.push("--launch".into());
    } else {
        parts.push("--no-launch".into());
    }
    if auto_install {
        parts.push("--auto-install".into());
    }
    parts.join(" ")
}

struct SetupApp {
    is_uninstall_mode: bool,
    is_elevated: bool,
    opts: InstallOpts,
    finished: bool,
    error: Option<String>,
    log: Vec<String>,
    pending_dir_cleanup: Option<PathBuf>,
}

impl eframe::App for SetupApp {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(ref dir) = self.pending_dir_cleanup {
            schedule_dir_cleanup(dir);
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(18.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    theme::draw_hub_logo(ui, 30.0);
                    ui.vertical(|ui| {
                        ui.heading(
                            RichText::new(if self.is_uninstall_mode {
                                "Uninstall NetMeter"
                            } else {
                                "NetMeter — Windows Installer"
                            })
                            .color(TEXT_MAIN)
                            .size(19.0),
                        );
                        ui.label(
                            RichText::new("Windows System Tray Network Traffic Monitor (In / Out)")
                                .color(TEXT_MUTED),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        if self.is_elevated {
                            theme::status_pill(ui, "Admin", EMERALD, theme::SURFACE);
                        } else if ui
                            .button("Restart as Admin")
                            .on_hover_text("Elevate with Windows UAC (fixes Access Denied or sandboxed launches)")
                            .clicked()
                        {
                            let arg = if self.is_uninstall_mode {
                                "--uninstall"
                            } else {
                                ""
                            };
                            match install::relaunch_elevated(arg) {
                                Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                                Err(e) => self.error = Some(e),
                            }
                        }
                    });
                });

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                if !self.finished {
                    if self.is_uninstall_mode {
                        let dir = install::installed_location()
                            .unwrap_or_else(install::default_install_dir);
                        ui.label(format!(
                            "This will stop Net Meter and remove it from:\n{}",
                            dir.display()
                        ));
                        ui.add_space(14.0);
                        ui.horizontal(|ui| {
                            if ui.button("Uninstall Net Meter").clicked() {
                                match perform_uninstall(Some(&dir), true) {
                                    Ok((l, deferred)) => {
                                        self.log = l;
                                        self.pending_dir_cleanup = deferred;
                                        self.finished = true;
                                        self.error = None;
                                    }
                                    Err(e)
                                        if !self.is_elevated
                                            && (e.contains("Access is denied")
                                                || e.contains("os error 5")) =>
                                    {
                                        let dir_esc = dir.display().to_string().replace('"', "");
                                        let args = format!(
                                            "--uninstall --auto-uninstall --dir \"{dir_esc}\""
                                        );
                                        match install::relaunch_elevated(&args) {
                                            Ok(()) => {
                                                ctx.send_viewport_cmd(egui::ViewportCommand::Close)
                                            }
                                            Err(_) => self.error = Some(e),
                                        }
                                    }
                                    Err(e) => self.error = Some(e),
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                        });
                    } else {
                        ui.label("Install Folder:");
                        ui.horizontal(|ui| {
                            let avail = (ui.available_width() - 78.0).max(160.0);
                            ui.add_sized(
                                [avail, 22.0],
                                egui::TextEdit::singleline(&mut self.opts.install_dir),
                            );
                            if ui.button("Browse...").clicked() {
                                if let Some(picked) = install::pick_folder(&self.opts.install_dir) {
                                    self.opts.install_dir = picked;
                                }
                            }
                        });

                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.weak("Presets:");
                            if ui.small_button("Program Files (Default)").clicked() {
                                self.opts.install_dir =
                                    install::program_files_install_dir().display().to_string();
                            }
                            if ui.small_button("User AppData").clicked() {
                                self.opts.install_dir =
                                    install::user_appdata_install_dir().display().to_string();
                            }
                            if ui.small_button("Portable Here").clicked() {
                                self.opts.install_dir =
                                    portable_fallback_dir().display().to_string();
                            }
                        });

                        ui.add_space(8.0);

                        ui.checkbox(
                            &mut self.opts.autostart,
                            "Start Net Meter automatically with Windows",
                        );
                        ui.checkbox(&mut self.opts.start_menu, "Create Start Menu shortcut");
                        ui.checkbox(
                            &mut self.opts.desktop_shortcut,
                            "Create Desktop shortcut",
                        );
                        ui.checkbox(
                            &mut self.opts.add_to_path,
                            "Add netmeter-cli.exe to user PATH",
                        );
                        ui.checkbox(
                            &mut self.opts.launch_after,
                            "Launch Net Meter in Windows system tray after install",
                        );

                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            if ui
                                .button(
                                    RichText::new("Install Net Meter")
                                        .strong()
                                        .color(Color32::from_rgb(80, 220, 140)),
                                )
                                .clicked()
                            {
                                match perform_install(&self.opts) {
                                    Ok(l) => {
                                        self.log = l;
                                        self.finished = true;
                                        self.error = None;
                                    }
                                    Err(e)
                                        if !self.is_elevated
                                            && (e.contains("Access is denied")
                                                || e.contains("os error 5")) =>
                                    {
                                        // Automatically trigger Windows UAC elevation preserving selected options
                                        let args = elevated_args_from_opts(&self.opts, true);
                                        match install::relaunch_elevated(&args) {
                                            Ok(()) => {
                                                ctx.send_viewport_cmd(egui::ViewportCommand::Close)
                                            }
                                            Err(_) => self.error = Some(e),
                                        }
                                    }
                                    Err(e) => self.error = Some(e),
                                }
                            }
                            if install::installed_location().is_some()
                                && ui.button("Uninstall Existing").clicked()
                            {
                                self.is_uninstall_mode = true;
                            }
                            if ui.button("Cancel").clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                        });
                    }
                } else {
                    ui.label(
                        RichText::new(if self.is_uninstall_mode {
                            "Uninstallation complete."
                        } else {
                            "Installation complete!"
                        })
                        .color(Color32::from_rgb(80, 215, 130))
                        .size(16.0)
                        .strong(),
                    );
                    ui.add_space(8.0);
                    egui::ScrollArea::vertical().max_height(190.0).show(ui, |ui| {
                        for line in &self.log {
                            if line.starts_with("Warning") {
                                ui.label(
                                    RichText::new(format!("• {line}"))
                                        .color(Color32::from_rgb(245, 185, 65)),
                                );
                            } else {
                                ui.label(format!("• {line}"));
                            }
                        }
                    });
                    ui.add_space(10.0);
                    if ui.button("Finish & Close").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }

                if let Some(ref err) = self.error {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!("Error: {err}"))
                            .color(Color32::from_rgb(245, 95, 95)),
                    );
                    if err.contains("Access is denied") || err.contains("os error 5") {
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.weak(
                                "Tip: Launched from a restricted/sandboxed shell? Elevate via UAC or use 'Portable Here':",
                            );
                            if !self.is_elevated
                                && ui
                                    .button(
                                        RichText::new("Restart as Administrator (UAC)")
                                            .color(Color32::from_rgb(100, 175, 255))
                                            .strong(),
                                    )
                                    .clicked()
                            {
                                let arg = if self.is_uninstall_mode {
                                    "--uninstall"
                                } else {
                                    ""
                                };
                                match install::relaunch_elevated(arg) {
                                    Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                                    Err(e) => self.error = Some(e),
                                }
                            }
                        });
                    }
                }
            });
    }
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let silent = args.iter().any(|a| a == "--silent" || a == "-s");
    let uninstall = args.iter().any(|a| a == "--uninstall");
    let install_cli = args.iter().any(|a| a == "--install");
    let auto_install = args.iter().any(|a| a == "--auto-install");
    let auto_uninstall = args.iter().any(|a| a == "--auto-uninstall");

    let mut opts = InstallOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" if i + 1 < args.len() => {
                opts.install_dir = args[i + 1].clone();
                i += 1;
            }
            "--autostart" => opts.autostart = true,
            "--no-autostart" => opts.autostart = false,
            "--start-menu" => opts.start_menu = true,
            "--no-start-menu" => opts.start_menu = false,
            "--desktop" => opts.desktop_shortcut = true,
            "--no-desktop" => opts.desktop_shortcut = false,
            "--path" => opts.add_to_path = true,
            "--no-path" => opts.add_to_path = false,
            "--launch" => opts.launch_after = true,
            "--no-launch" => opts.launch_after = false,
            _ => {}
        }
        i += 1;
    }

    if silent && uninstall {
        if let Err(e) = perform_uninstall(Some(Path::new(&opts.install_dir)), false) {
            eprintln!("Uninstall failed: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if silent || install_cli {
        match perform_install(&opts) {
            Ok(log) => {
                for line in log {
                    println!("{line}");
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("Install failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(if uninstall {
                "Uninstall Net Meter"
            } else {
                "Net Meter Setup"
            })
            .with_icon(Arc::new(app_icon_data()))
            .with_inner_size([560.0, 410.0])
            .with_resizable(false),
        ..Default::default()
    };

    let elevated = install::is_elevated();
    let (init_finished, init_error, init_log, init_deferred) = if auto_uninstall {
        let dir = PathBuf::from(opts.install_dir.trim());
        match perform_uninstall(Some(&dir), true) {
            Ok((l, deferred)) => (true, None, l, deferred),
            Err(e) => (false, Some(e), Vec::new(), None),
        }
    } else if auto_install {
        match perform_install(&opts) {
            Ok(l) => (true, None, l, None),
            Err(e) => (false, Some(e), Vec::new(), None),
        }
    } else {
        (false, None, Vec::new(), None)
    };

    eframe::run_native(
        "Net Meter Setup",
        options,
        Box::new(move |cc| {
            theme::apply_9router_theme(&cc.egui_ctx);
            Ok(Box::new(SetupApp {
                is_uninstall_mode: uninstall,
                is_elevated: elevated,
                opts,
                finished: init_finished,
                error: init_error,
                log: init_log,
                pending_dir_cleanup: init_deferred,
            }))
        }),
    )
}
