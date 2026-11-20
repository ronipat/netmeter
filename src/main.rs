// No console window in release builds; Windows System Tray network monitor application.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Local;
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Stroke, Vec2};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MsgWaitForMultipleObjects, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    QS_ALLINPUT,
};

use netmeter::app_icon_data;
use netmeter::export;
use netmeter::install;
use netmeter::monitor::{
    format_bytes, format_link_speed, format_rate, start_monitor, MonitorControl, MonitorHandle,
    MonitorSnapshot, ProcessRow, RateSample,
};
use netmeter::net::{Protocol, TcpState};
use netmeter::position::{self, CornerPref};
use netmeter::security::AlertSeverity;
use netmeter::theme::{self, Palette, ThemeMode};

const APP_TITLE: &str = "Net Meter";
const HIDDEN_POS: [f32; 2] = [-10000.0, -10000.0];
const HIDDEN_SIZE: [f32; 2] = [1.0, 1.0];
const MENU_SIZE: [f32; 2] = [258.0, 274.0];
const DASH_SIZE: [f32; 2] = [980.0, 660.0];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    TrayHidden,
    TrayMenu,
    Dashboard,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MenuAction {
    OpenMonitor,
    SetTheme(ThemeMode),
    ToggleAutostart,
    ExitApp,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DashTab {
    Overview,
    Processes,
    Connections,
    Adapters,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProtoFilter {
    All,
    Tcp,
    Udp,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StateFilter {
    All,
    Established,
    Listening,
    AlertsOnly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessSort {
    TrafficOrSockets,
    Name,
    Pid,
    Alerts,
}

fn quantize_level(bps: f64, paused: bool) -> usize {
    if paused || bps < 256.0 {
        return 3;
    }
    let log = (bps / 1024.0).max(1.0).log10();
    ((log / 5.0).clamp(0.12, 1.0) * 22.0).round() as usize
}

/// Generate a crisp 32x32 RGBA tray icon matching 9Router's palette.
fn render_tray_icon_levels(rx_h: usize, tx_h: usize, paused: bool, has_alert: bool) -> Icon {
    const W: usize = 32;
    const H: usize = 32;
    let mut rgba = vec![0u8; W * H * 4];

    let set_px = |buf: &mut [u8], x: usize, y: usize, c: [u8; 4]| {
        if x < W && y < H {
            let idx = (y * W + x) * 4;
            buf[idx..idx + 4].copy_from_slice(&c);
        }
    };

    let bg = [26, 26, 26, 255];
    let border = if paused {
        [107, 114, 128, 255]
    } else if has_alert {
        [245, 158, 11, 255]
    } else {
        [229, 106, 74, 255]
    };

    for y in 1..H - 1 {
        for x in 1..W - 1 {
            let corner = (x == 1 || x == W - 2) && (y == 1 || y == H - 2);
            if corner {
                continue;
            }
            let is_edge = x == 1 || x == W - 2 || y == 1 || y == H - 2;
            set_px(&mut rgba, x, y, if is_edge { border } else { bg });
        }
    }

    let rx_color = if paused {
        [107, 114, 128, 255]
    } else {
        [16, 185, 129, 255]
    };
    let tx_color = if paused {
        [90, 96, 108, 255]
    } else {
        [56, 189, 248, 255]
    };

    for dy in 0..rx_h {
        let y = H - 5 - dy;
        for x in 6..14 {
            set_px(&mut rgba, x, y, rx_color);
        }
    }
    for dy in 0..tx_h {
        let y = H - 5 - dy;
        for x in 18..26 {
            set_px(&mut rgba, x, y, tx_color);
        }
    }

    Icon::from_rgba(rgba, W as u32, H as u32).expect("valid 32x32 icon")
}

fn build_tray() -> Result<TrayIcon, String> {
    let icon = render_tray_icon_levels(3, 3, false, false);
    TrayIconBuilder::new()
        .with_tooltip("NetMeter — Click for menu")
        .with_icon(icon)
        .build()
        .map_err(|e| format!("{e}"))
}

struct TrayRuntime {
    has_tray: bool,
    tray_rx: mpsc::Receiver<TrayIconEvent>,
    stop: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

/// Spawn a dedicated Win32 thread for the System Tray icon so `Shell_NotifyIconW` calls
/// never block the `eframe` UI message loop when Windows Explorer is busy.
fn start_tray_worker(
    snapshot: Arc<Mutex<MonitorSnapshot>>,
    wake_ctx: egui::Context,
) -> TrayRuntime {
    let (ready_tx, ready_rx) = mpsc::sync_channel::<bool>(1);
    let (event_tx, event_rx) = mpsc::channel::<TrayIconEvent>();
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let done_bg = Arc::clone(&done);

    TrayIconEvent::set_event_handler(Some(move |event| {
        let should_wake = matches!(
            event,
            TrayIconEvent::Click {
                button: MouseButton::Left | MouseButton::Right,
                button_state: MouseButtonState::Up,
                ..
            } | TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            }
        );
        let _ = event_tx.send(event);
        if should_wake {
            wake_ctx.request_repaint();
        }
    }));

    let _ = thread::Builder::new()
        .name("netmeter-tray".into())
        .spawn(move || {
            let tray = match build_tray() {
                Ok(t) => {
                    let _ = ready_tx.send(true);
                    t
                }
                Err(err) => {
                    eprintln!("Tray icon unavailable ({err}); opening dashboard directly.");
                    done_bg.store(true, Ordering::Release);
                    let _ = ready_tx.send(false);
                    return;
                }
            };

            let quit_ev: Option<HANDLE> = unsafe {
                let mut wide: Vec<u16> = install::QUIT_EVENT_NAME.encode_utf16().collect();
                wide.push(0);
                CreateEventW(None, true, false, PCWSTR(wide.as_ptr())).ok()
            };

            let mut last_update = Instant::now() - Duration::from_secs(10);
            let mut last_icon_key: (usize, usize, bool, bool) = (3, 3, false, false);
            let mut last_tip = String::new();
            let mut signaled_quit = false;

            while !stop_bg.load(Ordering::Relaxed) {
                unsafe {
                    let mut msg = MSG::default();
                    while PeekMessageW(&mut msg, HWND::default(), 0, 0, PM_REMOVE).as_bool() {
                        let _ = TranslateMessage(&msg);
                        let _ = DispatchMessageW(&msg);
                    }
                }

                if last_update.elapsed() >= Duration::from_secs(2) {
                    last_update = Instant::now();
                    if let Ok(guard) = snapshot.try_lock() {
                        let rx_h = quantize_level(guard.down_bps, guard.paused);
                        let tx_h = quantize_level(guard.up_bps, guard.paused);
                        let has_alert = guard.alert_count > 0;
                        let key = (rx_h, tx_h, guard.paused, has_alert);

                        let tip = if guard.paused {
                            "NetMeter (Paused)".to_string()
                        } else if has_alert {
                            format!(
                                "NetMeter | In {}  Out {} | {} alert(s)",
                                format_rate(guard.down_bps),
                                format_rate(guard.up_bps),
                                guard.alert_count
                            )
                        } else {
                            format!(
                                "NetMeter | In {}  Out {} | Session {} / {}",
                                format_rate(guard.down_bps),
                                format_rate(guard.up_bps),
                                format_bytes(guard.session_rx_bytes),
                                format_bytes(guard.session_tx_bytes)
                            )
                        };
                        drop(guard);

                        if key != last_icon_key {
                            last_icon_key = key;
                            let icon = render_tray_icon_levels(key.0, key.1, key.2, key.3);
                            let _ = tray.set_icon(Some(icon));
                        }
                        if tip != last_tip {
                            last_tip = tip;
                            let _ = tray.set_tooltip(Some(&last_tip));
                        }
                    }
                }

                unsafe {
                    if let Some(ev) = quit_ev {
                        let res = MsgWaitForMultipleObjects(Some(&[ev]), false, 100, QS_ALLINPUT);
                        if res == WAIT_OBJECT_0 {
                            signaled_quit = true;
                            break;
                        }
                    } else {
                        let _ = MsgWaitForMultipleObjects(None, false, 100, QS_ALLINPUT);
                    }
                }
            }

            drop(tray);
            if let Some(ev) = quit_ev {
                unsafe {
                    let _ = CloseHandle(ev);
                }
            }
            done_bg.store(true, Ordering::Release);
            if signaled_quit {
                std::process::exit(0);
            }
        });

    let has_tray = ready_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(false);
    if !has_tray {
        let _ = thread::Builder::new()
            .name("netmeter-quit-watch".into())
            .spawn(move || unsafe {
                let mut wide: Vec<u16> = install::QUIT_EVENT_NAME.encode_utf16().collect();
                wide.push(0);
                if let Ok(ev) = CreateEventW(None, true, false, PCWSTR(wide.as_ptr())) {
                    if WaitForSingleObject(ev, INFINITE) == WAIT_OBJECT_0 {
                        let _ = CloseHandle(ev);
                        std::process::exit(0);
                    }
                    let _ = CloseHandle(ev);
                }
            });
    }
    TrayRuntime {
        has_tray,
        tray_rx: event_rx,
        stop,
        done,
    }
}

fn default_export_dir() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        return PathBuf::from(profile).join("Documents").join("NetMeter");
    }
    PathBuf::from("exports")
}

#[derive(Clone, Copy)]
enum MenuIconKind {
    Monitor,
    Startup(bool),
    Exit,
}

fn draw_9router_menu_row(
    ui: &mut egui::Ui,
    pal: Palette,
    icon: MenuIconKind,
    label: &str,
    trailing_badge: Option<(&str, Color32)>,
    accent: Option<Color32>,
) -> bool {
    let width = ui.available_width();
    let height = 27.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::click());

    if resp.hovered() {
        ui.painter().rect_filled(rect, 7.0, pal.surface_2);
        ui.painter()
            .rect_stroke(rect, 7.0, Stroke::new(1.0_f32, pal.border));
    } else {
        ui.painter()
            .rect_filled(rect, 7.0, Color32::from_rgba_unmultiplied(0, 0, 0, 0));
        ui.painter()
            .rect_stroke(rect, 7.0, Stroke::new(1.0_f32, pal.border_subtle));
    }

    let fg = accent.unwrap_or(pal.text_main);
    let painter = ui.painter();
    let ic = Pos2::new(rect.left() + 15.0, rect.center().y);
    let stroke = Stroke::new(1.4_f32, fg);

    match icon {
        MenuIconKind::Monitor => {
            let box_rect = Rect::from_center_size(ic, Vec2::new(13.0, 10.0));
            painter.rect_stroke(box_rect, 2.0, Stroke::new(1.5_f32, pal.accent));
            painter.line_segment(
                [
                    Pos2::new(ic.x - 3.5, box_rect.bottom() + 2.5),
                    Pos2::new(ic.x + 3.5, box_rect.bottom() + 2.5),
                ],
                Stroke::new(1.5_f32, pal.accent),
            );
        }
        MenuIconKind::Startup(checked) => {
            let box_rect = Rect::from_center_size(ic, Vec2::new(13.0, 13.0));
            if checked {
                painter.rect_filled(box_rect, 3.5, pal.emerald);
                let chk = Stroke::new(1.8_f32, pal.check_fg);
                painter.line_segment(
                    [
                        Pos2::new(ic.x - 3.5, ic.y + 0.2),
                        Pos2::new(ic.x - 0.8, ic.y + 3.0),
                    ],
                    chk,
                );
                painter.line_segment(
                    [
                        Pos2::new(ic.x - 0.8, ic.y + 3.0),
                        Pos2::new(ic.x + 4.0, ic.y - 2.8),
                    ],
                    chk,
                );
            } else {
                painter.rect_stroke(box_rect, 3.5, Stroke::new(1.3_f32, pal.text_subtle));
            }
        }
        MenuIconKind::Exit => {
            let r = 4.2;
            painter.line_segment(
                [Pos2::new(ic.x - r, ic.y - r), Pos2::new(ic.x + r, ic.y + r)],
                stroke,
            );
            painter.line_segment(
                [Pos2::new(ic.x + r, ic.y - r), Pos2::new(ic.x - r, ic.y + r)],
                stroke,
            );
        }
    }

    painter.text(
        Pos2::new(rect.left() + 31.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(12.5),
        fg,
    );

    if let Some((badge, badge_col)) = trailing_badge {
        painter.text(
            Pos2::new(rect.right() - 10.0, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            badge,
            egui::FontId::proportional(11.0),
            badge_col,
        );
    }

    resp.clicked()
}

struct NetMeterApp {
    handle: MonitorHandle,
    cached_snap: MonitorSnapshot,
    has_tray: bool,
    tray_rx: mpsc::Receiver<TrayIconEvent>,
    tray_stop: Arc<AtomicBool>,
    tray_done: Arc<AtomicBool>,
    mode: ViewMode,
    tab: DashTab,
    theme_mode: ThemeMode,
    autostart_enabled: bool,
    menu_opened_at: Instant,
    menu_saw_focus: bool,
    last_snap_at: Instant,
    last_anim_at: Instant,
    anim_down_bps: f64,
    anim_up_bps: f64,
    smooth_max_rate: f64,
    pulse_phase: f32,
    search_query: String,
    proto_filter: ProtoFilter,
    state_filter: StateFilter,
    process_sort: ProcessSort,
    show_virtual_adapters: bool,
    status_banner: Option<(String, Instant)>,
}

impl NetMeterApp {
    fn new(handle: MonitorHandle, tray: TrayRuntime, theme_mode: ThemeMode) -> Self {
        let initial_mode = if tray.has_tray {
            ViewMode::TrayHidden
        } else {
            ViewMode::Dashboard
        };
        let cached_snap = handle
            .snapshot
            .try_lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        Self {
            handle,
            cached_snap,
            has_tray: tray.has_tray,
            tray_rx: tray.tray_rx,
            tray_stop: tray.stop,
            tray_done: tray.done,
            mode: initial_mode,
            tab: DashTab::Overview,
            theme_mode,
            autostart_enabled: install::is_autostart_enabled(),
            menu_opened_at: Instant::now(),
            menu_saw_focus: false,
            last_snap_at: Instant::now(),
            last_anim_at: Instant::now(),
            anim_down_bps: 0.0,
            anim_up_bps: 0.0,
            smooth_max_rate: 1024.0,
            pulse_phase: 0.0,
            search_query: String::new(),
            proto_filter: ProtoFilter::All,
            state_filter: StateFilter::All,
            process_sort: ProcessSort::TrafficOrSockets,
            show_virtual_adapters: false,
            status_banner: None,
        }
    }

    fn pal(&self) -> Palette {
        theme::palette(self.theme_mode)
    }

    fn set_theme(&mut self, ctx: &egui::Context, mode: ThemeMode) {
        if self.theme_mode == mode {
            return;
        }
        self.theme_mode = mode;
        theme::apply_theme(ctx, self.theme_mode);
        install::save_theme_pref(self.theme_mode.as_pref());
    }

    fn control(&self) -> &Arc<MonitorControl> {
        &self.handle.control
    }

    fn popup_pos_for_click(&self, ctx: &egui::Context, click_px_x: Option<f64>) -> [f32; 2] {
        let scale = ctx.pixels_per_point().max(1.0);
        let wa = position::work_area();
        let wa_left = wa.left as f32 / scale;
        let wa_top = wa.top as f32 / scale;
        let wa_right = wa.right as f32 / scale;
        let wa_bottom = wa.bottom as f32 / scale;

        let x = match click_px_x {
            Some(px) => ((px as f32 / scale) - MENU_SIZE[0] * 0.5)
                .clamp(wa_left + 8.0, (wa_right - MENU_SIZE[0] - 8.0).max(wa_left + 8.0)),
            None => (wa_right - MENU_SIZE[0] - 8.0).max(wa_left + 8.0),
        };
        let y = (wa_bottom - MENU_SIZE[1] - 8.0).max(wa_top + 8.0);
        [x, y]
    }

    fn show_tray_menu(&mut self, ctx: &egui::Context, click_px_x: Option<f64>) {
        let pos = self.popup_pos_for_click(ctx, click_px_x);
        self.mode = ViewMode::TrayMenu;
        self.menu_opened_at = Instant::now();
        self.menu_saw_focus = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Resizable(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Decorations(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(Vec2::new(1.0, 1.0)));
        ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
            egui::WindowLevel::AlwaysOnTop,
        ));
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(MENU_SIZE.into()));
        ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(Pos2::new(pos[0], pos[1])));
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        position::set_window_corner_preference(APP_TITLE, CornerPref::Round);
    }

    fn hide_to_tray(&mut self, ctx: &egui::Context) {
        if !self.has_tray {
            return;
        }
        self.mode = ViewMode::TrayHidden;
        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Resizable(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Decorations(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(Vec2::new(1.0, 1.0)));
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(HIDDEN_SIZE.into()));
        ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(Pos2::new(
            HIDDEN_POS[0],
            HIDDEN_POS[1],
        )));
    }

    fn open_dashboard(&mut self, ctx: &egui::Context) {
        let scale = ctx.pixels_per_point();
        let [x, y] = position::center_in_work_area(DASH_SIZE, scale);
        self.autostart_enabled = install::is_autostart_enabled();
        self.mode = ViewMode::Dashboard;
        ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
            egui::WindowLevel::Normal,
        ));
        ctx.send_viewport_cmd(egui::ViewportCommand::Decorations(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Resizable(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(Vec2::new(580.0, 440.0)));
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(DASH_SIZE.into()));
        ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(Pos2::new(x, y)));
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        position::set_window_corner_preference(APP_TITLE, CornerPref::Default);
    }

    fn shutdown_tray_cleanly(&self) {
        self.tray_stop.store(true, Ordering::Relaxed);
        if self.has_tray {
            let start = Instant::now();
            while !self.tray_done.load(Ordering::Acquire)
                && start.elapsed() < Duration::from_millis(200)
            {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    fn exit_app(&mut self, ctx: &egui::Context) {
        self.shutdown_tray_cleanly();
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        std::process::exit(0);
    }

    fn toggle_autostart(&mut self) {
        let next = !self.autostart_enabled;
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("netmeter.exe"));
        match install::set_autostart(next, &exe) {
            Ok(()) => {
                self.autostart_enabled = next;
                self.set_banner(if next {
                    "Enabled Start with Windows".into()
                } else {
                    "Disabled Start with Windows".into()
                });
            }
            Err(e) => self.set_banner(format!("Auto-start update failed: {e}")),
        }
    }

    fn set_banner(&mut self, msg: String) {
        self.status_banner = Some((msg, Instant::now()));
    }

    fn do_export_json(&mut self, snap: &MonitorSnapshot) {
        let name = format!(
            "netmeter-snapshot-{}.json",
            Local::now().format("%Y%m%d-%H%M%S")
        );
        let path = default_export_dir().join(name);
        match export::export_json(snap, &path) {
            Ok(()) => self.set_banner(format!("Saved JSON snapshot to {}", path.display())),
            Err(e) => self.set_banner(format!("Export failed: {e}")),
        }
    }

    fn do_export_csv(&mut self, snap: &MonitorSnapshot) {
        let name = format!(
            "netmeter-connections-{}.csv",
            Local::now().format("%Y%m%d-%H%M%S")
        );
        let path = default_export_dir().join(name);
        match export::export_connections_csv(snap, &path) {
            Ok(()) => self.set_banner(format!("Saved CSV connections to {}", path.display())),
            Err(e) => self.set_banner(format!("Export failed: {e}")),
        }
    }

    fn process_tray_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.tray_rx.try_recv() {
            match event {
                TrayIconEvent::Click {
                    button: MouseButton::Left | MouseButton::Right,
                    button_state: MouseButtonState::Up,
                    position,
                    ..
                } => {
                    if self.mode == ViewMode::TrayMenu
                        && self.menu_opened_at.elapsed() > Duration::from_millis(150)
                    {
                        self.hide_to_tray(ctx);
                    } else {
                        self.show_tray_menu(ctx, Some(position.x));
                    }
                }
                TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                } => {
                    self.open_dashboard(ctx);
                }
                _ => {}
            }
        }
    }

    fn catmull_rom_subdivide(pts: &[Pos2], min_y: f32, max_y: f32, steps: usize) -> Vec<Pos2> {
        if pts.len() < 3 {
            return pts.to_vec();
        }
        let mut out = Vec::with_capacity((pts.len() - 1) * steps + 1);
        for i in 0..pts.len() - 1 {
            let p0 = if i == 0 { pts[0] } else { pts[i - 1] };
            let p1 = pts[i];
            let p2 = pts[i + 1];
            let p3 = if i + 2 < pts.len() {
                pts[i + 2]
            } else {
                pts[pts.len() - 1]
            };

            for s in 0..steps {
                let t = s as f32 / steps as f32;
                let t2 = t * t;
                let t3 = t2 * t;
                let x = 0.5
                    * ((2.0 * p1.x)
                        + (-p0.x + p2.x) * t
                        + (2.0 * p0.x - 5.0 * p1.x + 4.0 * p2.x - p3.x) * t2
                        + (-p0.x + 3.0 * p1.x - 3.0 * p2.x + p3.x) * t3);
                let y = 0.5
                    * ((2.0 * p1.y)
                        + (-p0.y + p2.y) * t
                        + (2.0 * p0.y - 5.0 * p1.y + 4.0 * p2.y - p3.y) * t2
                        + (-p0.y + 3.0 * p1.y - 3.0 * p2.y + p3.y) * t3);
                out.push(Pos2::new(x, y.clamp(min_y, max_y)));
            }
        }
        if let Some(&last) = pts.last() {
            out.push(Pos2::new(last.x, last.y.clamp(min_y, max_y)));
        }
        out
    }

    fn draw_sparkline(
        &self,
        ui: &mut egui::Ui,
        pal: Palette,
        rect: Rect,
        history: &std::collections::VecDeque<RateSample>,
        is_paused: bool,
        show_grid: bool,
    ) {
        let painter = ui.painter_at(rect);
        if pal.is_cartoon {
            let shadow = rect.translate(Vec2::new(3.0, 3.0));
            painter.rect_filled(
                shadow,
                pal.card_rounding - 2.0,
                Color32::from_rgba_unmultiplied(pal.border.r(), pal.border.g(), pal.border.b(), 36),
            );
        }
        painter.rect_filled(rect, pal.card_rounding - 2.0, pal.bg_alt);
        if pal.is_cartoon {
            // Subtle comic halftone dot pattern across the cartoon chart backdrop
            let dot_col = Color32::from_rgba_unmultiplied(pal.border.r(), pal.border.g(), pal.border.b(), 20);
            let mut y = rect.top() + 10.0;
            let mut row = 0;
            while y < rect.bottom() - 6.0 {
                let mut x = rect.left() + if row % 2 == 0 { 10.0 } else { 20.0 };
                while x < rect.right() - 8.0 {
                    painter.circle_filled(Pos2::new(x, y), 1.3, dot_col);
                    x += 20.0;
                }
                y += 14.0;
                row += 1;
            }
        }
        painter.rect_stroke(
            rect,
            pal.card_rounding - 2.0,
            Stroke::new(pal.border_width, pal.border),
        );

        let max_rate = self.smooth_max_rate.max(1024.0);

        if show_grid {
            for frac in [0.25, 0.5, 0.75] {
                let y = rect.bottom() - rect.height() * frac;
                painter.line_segment(
                    [Pos2::new(rect.left() + 1.0, y), Pos2::new(rect.right() - 1.0, y)],
                    Stroke::new(1.0_f32, pal.border_subtle),
                );
            }
            painter.text(
                Pos2::new(rect.left() + 10.0, rect.top() + 7.0),
                egui::Align2::LEFT_TOP,
                format!("Scale max: {}", format_rate(max_rate)),
                egui::FontId::monospace(10.5),
                pal.text_muted,
            );
        }

        if history.len() < 2 {
            return;
        }

        let n = history.len();
        let inner_left = rect.left() + 6.0;
        let inner_w = (rect.width() - 16.0).max(1.0);
        let dx = inner_w / (n.saturating_sub(1).max(1) as f32);
        let pad_top = if show_grid { 24.0 } else { 4.0 };
        let base_y = rect.bottom() - 5.0;
        let min_y = rect.top() + pad_top;
        let usable_h = (base_y - min_y).max(4.0);

        // Smooth sub-tick horizontal slide between 1-second samples (only when live)
        let slide = if is_paused {
            0.0
        } else {
            (self.last_snap_at.elapsed().as_secs_f32() / 1.0).clamp(0.0, 1.0) * (dx * 0.45)
        };

        let mut down_raw = Vec::with_capacity(n);
        let mut up_raw = Vec::with_capacity(n);

        for (i, sample) in history.iter().enumerate() {
            let is_last = i + 1 == n;
            let (d_val, u_val) = if is_last && !is_paused {
                (self.anim_down_bps, self.anim_up_bps)
            } else {
                (sample.down_bps, sample.up_bps)
            };
            let x = (inner_left + i as f32 * dx - slide).max(inner_left);
            let dy = (d_val / max_rate).clamp(0.0, 1.0) as f32 * usable_h;
            let uy = (u_val / max_rate).clamp(0.0, 1.0) as f32 * usable_h;
            down_raw.push(Pos2::new(x, base_y - dy));
            up_raw.push(Pos2::new(x, base_y - uy));
        }

        let down_pts = Self::catmull_rom_subdivide(&down_raw, min_y, base_y, 5);
        let up_pts = Self::catmull_rom_subdivide(&up_raw, min_y, base_y, 5);

        let in_wave_col = if pal.is_cartoon {
            Color32::from_rgb(255, 118, 24)
        } else {
            pal.emerald
        };
        let out_wave_col = pal.sky;

        // Smooth area shading under waveform curves
        if down_pts.len() >= 2 {
            let down_fill = Color32::from_rgba_unmultiplied(
                in_wave_col.r(),
                in_wave_col.g(),
                in_wave_col.b(),
                if pal.is_cartoon { 68 } else { 36 },
            );
            let mut mesh = egui::Mesh::default();
            for (idx, pt) in down_pts.iter().enumerate() {
                mesh.colored_vertex(*pt, down_fill);
                mesh.colored_vertex(Pos2::new(pt.x, base_y), Color32::TRANSPARENT);
                if idx + 1 < down_pts.len() {
                    let i0 = (idx * 2) as u32;
                    mesh.add_triangle(i0, i0 + 1, i0 + 2);
                    mesh.add_triangle(i0 + 1, i0 + 3, i0 + 2);
                }
            }
            painter.add(egui::Shape::mesh(mesh));
        }
        if up_pts.len() >= 2 {
            let up_fill = Color32::from_rgba_unmultiplied(
                out_wave_col.r(),
                out_wave_col.g(),
                out_wave_col.b(),
                if pal.is_cartoon { 48 } else { 28 },
            );
            let mut mesh = egui::Mesh::default();
            for (idx, pt) in up_pts.iter().enumerate() {
                mesh.colored_vertex(*pt, up_fill);
                mesh.colored_vertex(Pos2::new(pt.x, base_y), Color32::TRANSPARENT);
                if idx + 1 < up_pts.len() {
                    let i0 = (idx * 2) as u32;
                    mesh.add_triangle(i0, i0 + 1, i0 + 2);
                    mesh.add_triangle(i0 + 1, i0 + 3, i0 + 2);
                }
            }
            painter.add(egui::Shape::mesh(mesh));
        }

        if down_pts.len() >= 2 {
            let last_down = *down_pts.last().unwrap();
            if pal.is_cartoon && show_grid {
                painter.add(egui::Shape::line(
                    down_pts.clone(),
                    Stroke::new(5.8_f32, pal.border),
                ));
            }
            painter.add(egui::Shape::line(
                down_pts,
                Stroke::new(
                    if show_grid {
                        if pal.is_cartoon { 3.4_f32 } else { 2.3_f32 }
                    } else {
                        1.4_f32
                    },
                    in_wave_col,
                ),
            ));
            if !is_paused {
                let r_pulse = 3.5 + self.pulse_phase * 5.5;
                let alpha = ((1.0 - self.pulse_phase) * 165.0) as u8;
                painter.circle_stroke(
                    last_down,
                    r_pulse,
                    Stroke::new(
                        1.5_f32,
                        Color32::from_rgba_unmultiplied(
                            in_wave_col.r(),
                            in_wave_col.g(),
                            in_wave_col.b(),
                            alpha,
                        ),
                    ),
                );
            }
            if pal.is_cartoon {
                painter.circle_filled(last_down, 5.6, pal.border);
                painter.circle_filled(last_down, 3.8, in_wave_col);
                painter.circle_filled(
                    Pos2::new(last_down.x - 1.1, last_down.y - 1.1),
                    1.3,
                    Color32::WHITE,
                );
            } else {
                painter.circle_filled(last_down, 3.3, in_wave_col);
            }
        }
        if up_pts.len() >= 2 {
            let last_up = *up_pts.last().unwrap();
            if pal.is_cartoon && show_grid {
                painter.add(egui::Shape::line(
                    up_pts.clone(),
                    Stroke::new(5.0_f32, pal.border),
                ));
            }
            painter.add(egui::Shape::line(
                up_pts,
                Stroke::new(
                    if show_grid {
                        if pal.is_cartoon { 2.9_f32 } else { 2.0_f32 }
                    } else {
                        1.2_f32
                    },
                    out_wave_col,
                ),
            ));
            if !is_paused {
                let r_pulse = 3.0 + self.pulse_phase * 5.0;
                let alpha = ((1.0 - self.pulse_phase) * 145.0) as u8;
                painter.circle_stroke(
                    last_up,
                    r_pulse,
                    Stroke::new(
                        1.3_f32,
                        Color32::from_rgba_unmultiplied(
                            out_wave_col.r(),
                            out_wave_col.g(),
                            out_wave_col.b(),
                            alpha,
                        ),
                    ),
                );
            }
            if pal.is_cartoon {
                painter.circle_filled(last_up, 5.0, pal.border);
                painter.circle_filled(last_up, 3.3, out_wave_col);
                painter.circle_filled(
                    Pos2::new(last_up.x - 1.0, last_up.y - 1.0),
                    1.1,
                    Color32::WHITE,
                );
            } else {
                painter.circle_filled(last_up, 2.9, out_wave_col);
            }
        }
    }

    fn render_tray_menu(&mut self, ctx: &egui::Context, snap: &MonitorSnapshot) {
        let is_paused = self.control().is_paused() || snap.paused;
        let focused = ctx.input(|i| i.focused);
        if focused {
            self.menu_saw_focus = true;
        } else if self.menu_saw_focus && self.menu_opened_at.elapsed() > Duration::from_millis(280) {
            self.hide_to_tray(ctx);
            return;
        }

        if self.menu_opened_at.elapsed() > Duration::from_millis(350) {
            if let Some(outer) = ctx.input(|i| i.viewport().outer_rect) {
                if position::is_left_mouse_pressed_outside_rect(
                    outer.left(),
                    outer.top(),
                    outer.right(),
                    outer.bottom(),
                    ctx.pixels_per_point(),
                ) {
                    self.hide_to_tray(ctx);
                    return;
                }
            }
        }

        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.hide_to_tray(ctx);
            return;
        }

        let pal = self.pal();
        let mut pending_action: Option<MenuAction> = None;
        let autostart_enabled = self.autostart_enabled;

        let menu_frame = egui::Frame::none()
            .fill(pal.bg)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(10.0)
            .inner_margin(egui::Margin {
                left: 8.0,
                right: 8.0,
                top: 8.0,
                bottom: 10.0,
            });

        egui::CentralPanel::default()
            .frame(menu_frame)
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                ui.horizontal(|ui| {
                    theme::draw_hub_logo_with(ui, 19.0, pal);
                    ui.label(
                        RichText::new("NetMeter")
                            .color(pal.text_main)
                            .size(13.0)
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (lbl, col) = if is_paused {
                            ("Paused", pal.text_muted)
                        } else if snap.alert_count > 0 {
                            ("Alert", pal.amber)
                        } else {
                            ("Live", pal.emerald)
                        };
                        theme::status_pill_with(ui, lbl, col, pal.surface, pal);
                    });
                });

                egui::Frame::none()
                    .fill(pal.surface)
                    .stroke(Stroke::new(1.0_f32, pal.border))
                    .rounding(8.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.columns(2, |cols| {
                            cols[0].vertical(|ui| {
                                ui.label(RichText::new("IN (RX)").color(pal.text_muted).size(9.5).strong());
                                ui.label(
                                    RichText::new(if is_paused {
                                        "PAUSED".to_string()
                                    } else {
                                        format_rate(snap.down_bps)
                                    })
                                    .color(pal.emerald)
                                    .monospace()
                                    .size(12.5)
                                    .strong(),
                                );
                            });
                            cols[1].vertical(|ui| {
                                ui.label(RichText::new("OUT (TX)").color(pal.text_muted).size(9.5).strong());
                                ui.label(
                                    RichText::new(if is_paused {
                                        "PAUSED".to_string()
                                    } else {
                                        format_rate(snap.up_bps)
                                    })
                                    .color(pal.sky)
                                    .monospace()
                                    .size(12.5)
                                    .strong(),
                                );
                            });
                        });

                        ui.add_space(3.0);
                        let (div, _) = ui.allocate_exact_size(
                            Vec2::new(ui.available_width(), 1.0),
                            egui::Sense::hover(),
                        );
                        ui.painter().line_segment(
                            [div.left_center(), div.right_center()],
                            Stroke::new(1.0_f32, pal.border_subtle),
                        );
                        ui.add_space(2.0);

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "Session: {} / {}",
                                    format_bytes(snap.session_rx_bytes),
                                    format_bytes(snap.session_tx_bytes)
                                ))
                                .color(pal.text_muted)
                                .size(10.0),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new(format!("{} Estab", snap.tcp_summary.established))
                                            .color(pal.text_subtle)
                                            .size(10.0),
                                    );
                                },
                            );
                        });
                    });

                if draw_9router_menu_row(
                    ui,
                    pal,
                    MenuIconKind::Monitor,
                    "Open Full Monitor",
                    Some((">", pal.accent)),
                    None,
                ) {
                    pending_action = Some(MenuAction::OpenMonitor);
                }

                // 3-option Theme selector inside Tray menu (Dark / White / Cartoon)
                egui::Frame::none()
                    .fill(pal.surface)
                    .stroke(Stroke::new(1.0_f32, pal.border_subtle))
                    .rounding(8.0)
                    .inner_margin(egui::Margin::symmetric(7.0, 4.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new("Theme").color(pal.text_muted).size(10.0).strong());
                        ui.add_space(2.0);
                        ui.columns(3, |cols| {
                            for (idx, (mode, lbl)) in [
                                (ThemeMode::Dark, "Dark"),
                                (ThemeMode::Light, "White"),
                                (ThemeMode::Cartoon, "Cartoon"),
                            ]
                            .into_iter()
                            .enumerate()
                            {
                                let active = self.theme_mode == mode;
                                let btn = egui::Button::new(
                                    RichText::new(lbl)
                                        .color(if active { pal.text_main } else { pal.text_muted })
                                        .size(11.0)
                                        .strong(),
                                )
                                .fill(if active { pal.surface_2 } else { pal.bg_alt })
                                .stroke(Stroke::new(
                                    1.0_f32,
                                    if active { pal.border } else { pal.border_subtle },
                                ))
                                .rounding(6.0);
                                if cols[idx].add_sized([cols[idx].available_width(), 21.0], btn).clicked() {
                                    pending_action = Some(MenuAction::SetTheme(mode));
                                }
                            }
                        });
                    });

                if draw_9router_menu_row(
                    ui,
                    pal,
                    MenuIconKind::Startup(autostart_enabled),
                    "Start with Windows",
                    Some((
                        if autostart_enabled { "On" } else { "Off" },
                        if autostart_enabled { pal.emerald } else { pal.text_subtle },
                    )),
                    None,
                ) {
                    pending_action = Some(MenuAction::ToggleAutostart);
                }

                ui.add_space(1.0);
                let (div_rect, _) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), 1.0),
                    egui::Sense::hover(),
                );
                ui.painter().line_segment(
                    [div_rect.left_center(), div_rect.right_center()],
                    Stroke::new(1.0_f32, pal.border_subtle),
                );
                ui.add_space(1.0);

                if draw_9router_menu_row(
                    ui,
                    pal,
                    MenuIconKind::Exit,
                    "Quit",
                    None,
                    Some(pal.danger),
                ) {
                    pending_action = Some(MenuAction::ExitApp);
                }
            });

        if let Some(action) = pending_action {
            match action {
                MenuAction::OpenMonitor => self.open_dashboard(ctx),
                MenuAction::SetTheme(mode) => self.set_theme(ctx, mode),
                MenuAction::ToggleAutostart => self.toggle_autostart(),
                MenuAction::ExitApp => self.exit_app(ctx),
            }
        }
    }

    fn render_dashboard(&mut self, ctx: &egui::Context, snap: &MonitorSnapshot) {
        let pal = self.pal();
        let mut requested_theme: Option<ThemeMode> = None;
        let is_paused = self.control().is_paused();
        let is_fullscreen = ctx.input(|i| i.viewport().fullscreen.unwrap_or(false));

        if ctx.input(|i| i.key_pressed(egui::Key::F11)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(!is_fullscreen));
        }
        if self.has_tray && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.hide_to_tray(ctx);
            return;
        }

        let frame = egui::Frame::none()
            .fill(pal.bg)
            .inner_margin(egui::Margin::same(14.0));

        egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
            // Eye-catchy 1px-bordered Header Card
            let header_card = egui::Frame::none()
                .fill(pal.surface)
                .stroke(Stroke::new(pal.border_width, pal.border))
                .rounding(pal.card_rounding)
                .inner_margin(egui::Margin::symmetric(12.0, 9.0));

            let header_resp = header_card.show(ui, |ui| {
                let top_avail_w = ui.available_width();
                egui::ScrollArea::horizontal()
                    .id_salt("dash_header_scroll")
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.set_min_width(top_avail_w);
                        ui.horizontal(|ui| {
                            theme::draw_hub_logo_with(ui, 30.0, pal);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 0.0;
                                ui.label(
                                    RichText::new("NetMeter")
                                        .color(pal.text_main)
                                        .size(17.5)
                                        .strong(),
                                );
                                ui.label(
                                    RichText::new("Smart Windows Traffic & Socket Monitor")
                                        .color(pal.text_muted)
                                        .size(11.0),
                                );
                            });

                            ui.add_space(8.0);
                            if snap.etw_active {
                                theme::status_pill_with(
                                    ui,
                                    "ETW Active",
                                    pal.emerald,
                                    pal.bg_alt,
                                    pal,
                                );
                            } else {
                                theme::status_pill_with(
                                    ui,
                                    "Standard Mode",
                                    pal.amber,
                                    pal.bg_alt,
                                    pal,
                                );
                            }

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let exit_btn = egui::Button::new(
                                        RichText::new("Exit").color(pal.text_main).strong(),
                                    )
                                    .fill(pal.bg_alt)
                                    .stroke(Stroke::new(1.0_f32, pal.border))
                                    .rounding(7.0);
                                    let exit_tip = if self.has_tray {
                                        "Hide window to Windows system tray (use Quit in tray menu to exit)"
                                    } else {
                                        "Exit Net Meter"
                                    };
                                    if ui
                                        .add(exit_btn)
                                        .on_hover_text(exit_tip)
                                        .clicked()
                                    {
                                        if self.has_tray {
                                            self.hide_to_tray(ctx);
                                        } else {
                                            self.exit_app(ctx);
                                        }
                                    }

                                    let pause_lbl = if is_paused { "Start" } else { "Pause" };
                                    let pause_btn = egui::Button::new(
                                        RichText::new(pause_lbl)
                                            .color(if is_paused {
                                                pal.emerald
                                            } else {
                                                pal.text_main
                                            })
                                            .strong(),
                                    )
                                    .fill(pal.bg_alt)
                                    .stroke(Stroke::new(1.0_f32, pal.border))
                                    .rounding(7.0);
                                    if ui.add(pause_btn).clicked() {
                                        let now_paused = self.control().toggle_paused();
                                        self.cached_snap.paused = now_paused;
                                        ctx.request_repaint();
                                    }

                                    // Explicit 1px-bordered Auto-start toggle chip with clear checkmark
                                    let checked = self.autostart_enabled;
                                    let (auto_rect, auto_resp) = ui.allocate_exact_size(
                                        Vec2::new(104.0, 26.0),
                                        egui::Sense::click(),
                                    );
                                    let bg = if auto_resp.hovered() {
                                        pal.surface_2
                                    } else {
                                        pal.bg_alt
                                    };
                                    ui.painter().rect_filled(auto_rect, 7.0, bg);
                                    ui.painter().rect_stroke(
                                        auto_rect,
                                        7.0,
                                        Stroke::new(1.0_f32, pal.border),
                                    );
                                    let box_rect = Rect::from_center_size(
                                        Pos2::new(auto_rect.left() + 14.0, auto_rect.center().y),
                                        Vec2::splat(13.0),
                                    );
                                    if checked {
                                        ui.painter().rect_filled(box_rect, 3.0, pal.emerald);
                                        let chk = Stroke::new(1.8_f32, pal.check_fg);
                                        ui.painter().line_segment(
                                            [
                                                Pos2::new(
                                                    box_rect.center().x - 3.5,
                                                    box_rect.center().y + 0.2,
                                                ),
                                                Pos2::new(
                                                    box_rect.center().x - 0.8,
                                                    box_rect.center().y + 3.0,
                                                ),
                                            ],
                                            chk,
                                        );
                                        ui.painter().line_segment(
                                            [
                                                Pos2::new(
                                                    box_rect.center().x - 0.8,
                                                    box_rect.center().y + 3.0,
                                                ),
                                                Pos2::new(
                                                    box_rect.center().x + 4.0,
                                                    box_rect.center().y - 2.8,
                                                ),
                                            ],
                                            chk,
                                        );
                                    } else {
                                        ui.painter().rect_stroke(
                                            box_rect,
                                            3.0,
                                            Stroke::new(1.0_f32, pal.border),
                                        );
                                    }
                                    ui.painter().text(
                                        Pos2::new(auto_rect.left() + 26.0, auto_rect.center().y),
                                        egui::Align2::LEFT_CENTER,
                                        "Auto-start",
                                        egui::FontId::proportional(12.5),
                                        pal.text_main,
                                    );
                                    if auto_resp
                                        .on_hover_text("Start Net Meter automatically with Windows")
                                        .clicked()
                                    {
                                        self.toggle_autostart();
                                        ctx.request_repaint();
                                    }
                                },
                            );
                        });
                    });
            });
            theme::draw_cartoon_shadow(ui, header_resp.response.rect, pal.card_rounding, pal);

            ui.add_space(8.0);

            let nav_resp = egui::Frame::none()
                .fill(pal.bg_alt)
                .stroke(Stroke::new(pal.border_width, pal.border))
                .rounding(pal.card_rounding)
                .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                .show(ui, |ui| {
                    let nav_avail_w = ui.available_width();
                    egui::ScrollArea::horizontal()
                        .id_salt("dash_nav_scroll")
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.set_min_width(nav_avail_w);
                            ui.horizontal(|ui| {
                                let tabs = [
                                    (DashTab::Overview, "Overview".to_string()),
                                    (
                                        DashTab::Processes,
                                        format!("Processes ({})", snap.processes.len()),
                                    ),
                                    (
                                        DashTab::Connections,
                                        format!("Connections ({})", snap.connections.len()),
                                    ),
                                    (
                                        DashTab::Adapters,
                                        format!("Adapters & Diagnostics ({})", snap.adapters.len()),
                                    ),
                                ];
                                for (t, label) in tabs {
                                    let active = self.tab == t;
                                    let btn = egui::Button::new(
                                        RichText::new(label)
                                            .color(if active {
                                                pal.text_main
                                            } else {
                                                pal.text_muted
                                            })
                                            .strong(),
                                    )
                                    .fill(if active {
                                        pal.surface_2
                                    } else {
                                        Color32::TRANSPARENT
                                    })
                                    .stroke(if active {
                                        Stroke::new(1.0_f32, pal.border)
                                    } else {
                                        Stroke::new(1.0_f32, pal.border_subtle)
                                    })
                                    .rounding(7.0);
                                    if ui.add(btn).clicked() {
                                        self.tab = t;
                                    }
                                }

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        // Theme dropdown selector (Dark / White / Cartoon)
                                        let mut chosen_theme = self.theme_mode;
                                        egui::ComboBox::from_id_salt("app_theme_select")
                                            .selected_text(self.theme_mode.label())
                                            .width(88.0)
                                            .show_ui(ui, |ui| {
                                                ui.selectable_value(
                                                    &mut chosen_theme,
                                                    ThemeMode::Dark,
                                                    "Dark",
                                                );
                                                ui.selectable_value(
                                                    &mut chosen_theme,
                                                    ThemeMode::Light,
                                                    "White",
                                                );
                                                ui.selectable_value(
                                                    &mut chosen_theme,
                                                    ThemeMode::Cartoon,
                                                    "Cartoon",
                                                );
                                            });
                                        if chosen_theme != self.theme_mode {
                                            requested_theme = Some(chosen_theme);
                                        }
                                        ui.label(
                                            RichText::new("Theme:").color(pal.text_muted).small(),
                                        );

                                        if snap.alert_count > 0 {
                                            ui.separator();
                                            let alert_btn = egui::Button::new(
                                                RichText::new(format!(
                                                    "! {} Security Alert(s)",
                                                    snap.alert_count
                                                ))
                                                .color(pal.amber)
                                                .strong(),
                                            )
                                            .fill(pal.surface)
                                            .stroke(Stroke::new(1.0_f32, pal.border))
                                            .rounding(99.0);
                                            if ui.add(alert_btn).clicked() {
                                                self.tab = DashTab::Connections;
                                                self.state_filter = StateFilter::AlertsOnly;
                                            }
                                        }
                                    },
                                );
                            });
                        });
                });
            theme::draw_cartoon_shadow(ui, nav_resp.response.rect, pal.card_rounding, pal);

            if let Some((msg, ts)) = &self.status_banner {
                if ts.elapsed() < Duration::from_secs(6) {
                    ui.add_space(6.0);
                    ui.label(RichText::new(msg).color(pal.emerald).small());
                } else {
                    self.status_banner = None;
                }
            }

            ui.add_space(10.0);

            match self.tab {
                DashTab::Overview => self.render_tab_overview(ui, pal, snap),
                DashTab::Processes => self.render_tab_processes(ui, pal, snap),
                DashTab::Connections => self.render_tab_connections(ui, pal, snap),
                DashTab::Adapters => self.render_tab_adapters(ui, pal, snap),
            }
        });

        if let Some(mode) = requested_theme {
            self.set_theme(ctx, mode);
        }
    }

    fn kpi_card(
        ui: &mut egui::Ui,
        pal: Palette,
        title: &str,
        value: &str,
        sub: &str,
        badge: &str,
        accent_color: Color32,
        width: f32,
    ) {
        let card_resp = egui::Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(pal.border_width, pal.border))
            .rounding(pal.card_rounding)
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    let inner_w = (width - 26.0).max(175.0);
                    ui.set_min_width(inner_w);
                    ui.set_max_width(inner_w);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        let (dot_rect, _) =
                            ui.allocate_exact_size(Vec2::splat(9.0), egui::Sense::hover());
                        if pal.is_cartoon {
                            ui.painter().circle_filled(dot_rect.center(), 4.5, pal.border);
                            ui.painter().circle_filled(dot_rect.center(), 3.2, accent_color);
                        } else {
                            ui.painter()
                                .circle_filled(dot_rect.center(), 3.5, accent_color);
                        }
                        ui.label(RichText::new(title).color(pal.text_muted).size(11.5).strong());

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            theme::tag_badge(ui, badge, accent_color, pal.border, pal.bg_alt);
                        });
                    });
                    ui.add_space(5.0);
                    ui.label(
                        RichText::new(value)
                            .color(accent_color)
                            .size(21.0)
                            .monospace()
                            .strong(),
                    );
                    ui.add_space(5.0);
                    let (div, _) = ui.allocate_exact_size(
                        Vec2::new(inner_w, 1.0),
                        egui::Sense::hover(),
                    );
                    ui.painter().line_segment(
                        [div.left_center(), div.right_center()],
                        Stroke::new(1.0_f32, pal.border_subtle),
                    );
                    ui.add_space(4.0);
                    ui.label(RichText::new(sub).color(pal.text_subtle).size(11.0));
                });
            });
        theme::draw_cartoon_shadow(ui, card_resp.response.rect, pal.card_rounding, pal);
    }

    fn render_tab_overview(&mut self, ui: &mut egui::Ui, pal: Palette, snap: &MonitorSnapshot) {
        let avail_w = ui.available_width();
        let card_w = ((avail_w - 24.0) / 4.0).max(205.0);
        let is_paused = self.control().is_paused();
        let disp_down = if is_paused {
            snap.down_bps
        } else {
            self.anim_down_bps
        };
        let disp_up = if is_paused {
            snap.up_bps
        } else {
            self.anim_up_bps
        };
        egui::ScrollArea::horizontal()
            .id_salt("overview_kpi_scroll")
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    Self::kpi_card(
                        ui,
                        pal,
                        "In (Download)",
                        &format_rate(disp_down),
                        &format!(
                            "Peak {} | Session {}",
                            format_rate(snap.peak_down_bps),
                            format_bytes(snap.session_rx_bytes)
                        ),
                        "RX",
                        pal.emerald,
                        card_w,
                    );
                    Self::kpi_card(
                        ui,
                        pal,
                        "Out (Upload)",
                        &format_rate(disp_up),
                        &format!(
                            "Peak {} | Session {}",
                            format_rate(snap.peak_up_bps),
                            format_bytes(snap.session_tx_bytes)
                        ),
                        "TX",
                        pal.sky,
                        card_w,
                    );
                    Self::kpi_card(
                        ui,
                        pal,
                        "Active Sockets",
                        &format!("{} Estab", snap.tcp_summary.established),
                        &format!(
                            "Listen {} | TW {} | UDP {}",
                            snap.tcp_summary.listen,
                            snap.tcp_summary.time_wait,
                            snap.tcp_summary.udp_total
                        ),
                        "TCP/UDP",
                        pal.accent,
                        card_w,
                    );
                    Self::kpi_card(
                        ui,
                        pal,
                        "Security Triage",
                        &format!("{} Flagged", snap.alert_count),
                        if snap.alert_count == 0 {
                            "No LOLBin / risky ports"
                        } else {
                            "Click Alert pill to inspect"
                        },
                        if snap.alert_count > 0 { "ALERT" } else { "SAFE" },
                        if snap.alert_count > 0 { pal.amber } else { pal.violet },
                        card_w,
                    );
                });
            });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("Monitored interface:").color(pal.text_muted));
            let current_label = match snap.selected_adapter_luid {
                None => "All Physical Up Adapters".to_string(),
                Some(luid) => snap
                    .adapters
                    .iter()
                    .find(|a| a.info.luid == luid)
                    .map(|a| format!("{} ({})", a.info.alias, a.info.description))
                    .unwrap_or_else(|| format!("Adapter {luid}")),
            };
            egui::ComboBox::from_id_salt("adapter_select")
                .selected_text(current_label)
                .width(380.0)
                .show_ui(ui, |ui| {
                    let selected = snap.selected_adapter_luid;
                    if ui
                        .selectable_label(selected.is_none(), "All Physical Up Adapters")
                        .clicked()
                    {
                        self.control().set_selected_adapter(None);
                    }
                    for a in &snap.adapters {
                        if !a.info.is_up {
                            continue;
                        }
                        let tag = if a.info.is_hardware { "Physical" } else { "Virtual" };
                        let label = format!("[{tag}] {} — {}", a.info.alias, a.info.description);
                        if ui
                            .selectable_label(selected == Some(a.info.luid), label)
                            .clicked()
                        {
                            self.control().set_selected_adapter(Some(a.info.luid));
                        }
                    }
                });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let in_leg_col = if pal.is_cartoon {
                    Color32::from_rgb(255, 118, 24)
                } else {
                    pal.emerald
                };
                ui.label(RichText::new("Out (TX)").color(pal.sky).small().strong());
                ui.label(RichText::new("In (RX)").color(in_leg_col).small().strong());
                ui.label(RichText::new("120s Waveform:").color(pal.text_muted).small());
            });
        });

        ui.add_space(4.0);
        let (chart_rect, _) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), 155.0), egui::Sense::hover());
        self.draw_sparkline(ui, pal, chart_rect, &snap.history, is_paused, true);

        ui.add_space(10.0);

        // Full-width & full-height card down to the bottom app border
        let full_w = ui.available_width();
        let full_h = ui.available_height().max(120.0);
        egui::Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(10.0)
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.set_min_size(Vec2::new((full_w - 26.0).max(200.0), (full_h - 26.0).max(90.0)));
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Top Active Processes").color(pal.text_main).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        theme::tag_badge(
                            ui,
                            &format!("{} procs", snap.processes.len()),
                            pal.text_muted,
                            pal.border,
                            pal.bg_alt,
                        );
                    });
                });
                ui.add_space(6.0);
                let (hr, _) =
                    ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), egui::Sense::hover());
                ui.painter().line_segment(
                    [hr.left_center(), hr.right_center()],
                    Stroke::new(1.0_f32, pal.border),
                );
                ui.add_space(6.0);

                let inner_w = ui.available_width();
                let col_w = (inner_w / if snap.etw_active { 7.4 } else { 5.4 }).max(70.0);
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Grid::new("overview_procs")
                            .striped(true)
                            .min_col_width(col_w)
                            .spacing([14.0, 5.0])
                            .show(ui, |ui| {
                                ui.label(RichText::new("Process").color(pal.text_muted).strong());
                                ui.label(RichText::new("PID").color(pal.text_muted).strong());
                                ui.label(RichText::new("Established").color(pal.text_muted).strong());
                                ui.label(RichText::new("Listening").color(pal.text_muted).strong());
                                ui.label(RichText::new("UDP").color(pal.text_muted).strong());
                                if snap.etw_active {
                                    ui.label(RichText::new("In Rate").color(pal.emerald).strong());
                                    ui.label(RichText::new("Out Rate").color(pal.sky).strong());
                                }
                                ui.end_row();

                                for p in &snap.processes {
                                    ui.label(&p.name);
                                    ui.monospace(p.pid.to_string());
                                    ui.monospace(p.established_count.to_string());
                                    ui.monospace(p.listening_count.to_string());
                                    ui.monospace(p.udp_count.to_string());
                                    if snap.etw_active {
                                        ui.monospace(
                                            p.down_bps.map(format_rate).unwrap_or_else(|| "-".into()),
                                        );
                                        ui.monospace(
                                            p.up_bps.map(format_rate).unwrap_or_else(|| "-".into()),
                                        );
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            });
    }

    fn render_tab_processes(&mut self, ui: &mut egui::Ui, pal: Palette, snap: &MonitorSnapshot) {
        if !snap.etw_active {
            egui::Frame::none()
                .fill(pal.bg_alt)
                .stroke(Stroke::new(1.0_f32, pal.border))
                .rounding(8.0)
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        RichText::new(
                            "Per-process byte rates use ETW (Microsoft-Windows-Kernel-Network), which requires Administrator rights. Running unprivileged shows live socket counts and executable paths.",
                        )
                        .color(pal.amber)
                        .small(),
                    );
                });
            ui.add_space(8.0);
        }

        egui::Frame::none()
            .fill(pal.bg_alt)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Filter:").color(pal.text_muted));
                    ui.text_edit_singleline(&mut self.search_query);
                    ui.add_space(12.0);
                    ui.label(RichText::new("Sort:").color(pal.text_muted));
                    egui::ComboBox::from_id_salt("proc_sort")
                        .selected_text(match self.process_sort {
                            ProcessSort::TrafficOrSockets => "Activity",
                            ProcessSort::Name => "Name",
                            ProcessSort::Pid => "PID",
                            ProcessSort::Alerts => "Alerts",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.process_sort,
                                ProcessSort::TrafficOrSockets,
                                "Activity",
                            );
                            ui.selectable_value(&mut self.process_sort, ProcessSort::Name, "Name");
                            ui.selectable_value(&mut self.process_sort, ProcessSort::Pid, "PID");
                            ui.selectable_value(&mut self.process_sort, ProcessSort::Alerts, "Alerts");
                        });
                });
            });

        ui.add_space(8.0);
        let q = self.search_query.to_ascii_lowercase();
        let mut rows: Vec<&ProcessRow> = snap
            .processes
            .iter()
            .filter(|p| {
                q.is_empty()
                    || p.name.to_ascii_lowercase().contains(&q)
                    || p.pid.to_string().contains(&q)
                    || p.path
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains(&q)
            })
            .collect();

        match self.process_sort {
            ProcessSort::TrafficOrSockets => {}
            ProcessSort::Name => {
                rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            }
            ProcessSort::Pid => rows.sort_by_key(|p| p.pid),
            ProcessSort::Alerts => rows.sort_by(|a, b| b.alert_count.cmp(&a.alert_count)),
        }

        let full_w = ui.available_width();
        let full_h = ui.available_height().max(120.0);
        egui::Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(10.0)
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.set_min_size(Vec2::new((full_w - 26.0).max(200.0), (full_h - 26.0).max(90.0)));
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Process Activity").color(pal.text_main).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        theme::tag_badge(
                            ui,
                            &format!("{} visible", rows.len()),
                            pal.text_muted,
                            pal.border,
                            pal.bg_alt,
                        );
                    });
                });
                ui.add_space(5.0);
                let (hr, _) =
                    ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), egui::Sense::hover());
                ui.painter().line_segment(
                    [hr.left_center(), hr.right_center()],
                    Stroke::new(1.0_f32, pal.border),
                );
                ui.add_space(5.0);
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Grid::new("proc_table")
                            .striped(true)
                            .spacing([14.0, 5.0])
                            .show(ui, |ui| {
                                ui.label(RichText::new("Process").color(pal.text_muted).strong());
                                ui.label(RichText::new("PID").color(pal.text_muted).strong());
                                ui.label(RichText::new("Estab").color(pal.text_muted).strong());
                                ui.label(RichText::new("Listen").color(pal.text_muted).strong());
                                ui.label(RichText::new("UDP").color(pal.text_muted).strong());
                                if snap.etw_active {
                                    ui.label(RichText::new("In Speed").color(pal.emerald).strong());
                                    ui.label(RichText::new("Out Speed").color(pal.sky).strong());
                                    ui.label(RichText::new("Session In").color(pal.text_muted).strong());
                                    ui.label(RichText::new("Session Out").color(pal.text_muted).strong());
                                }
                                ui.label(RichText::new("Alerts").color(pal.text_muted).strong());
                                ui.label(RichText::new("Executable Path").color(pal.text_muted).strong());
                                ui.end_row();

                                for p in rows {
                                    ui.label(&p.name);
                                    ui.monospace(p.pid.to_string());
                                    ui.monospace(p.established_count.to_string());
                                    ui.monospace(p.listening_count.to_string());
                                    ui.monospace(p.udp_count.to_string());
                                    if snap.etw_active {
                                        ui.monospace(
                                            p.down_bps.map(format_rate).unwrap_or_else(|| "-".into()),
                                        );
                                        ui.monospace(
                                            p.up_bps.map(format_rate).unwrap_or_else(|| "-".into()),
                                        );
                                        ui.monospace(
                                            p.session_rx_bytes
                                                .map(format_bytes)
                                                .unwrap_or_else(|| "-".into()),
                                        );
                                        ui.monospace(
                                            p.session_tx_bytes
                                                .map(format_bytes)
                                                .unwrap_or_else(|| "-".into()),
                                        );
                                    }
                                    if p.alert_count > 0 {
                                        ui.label(
                                            RichText::new(format!("! {}", p.alert_count)).color(pal.amber),
                                        );
                                    } else {
                                        ui.label(RichText::new("0").color(pal.text_subtle));
                                    }
                                    ui.label(
                                        RichText::new(p.path.as_deref().unwrap_or("-"))
                                            .color(pal.text_subtle)
                                            .small(),
                                    );
                                    ui.end_row();
                                }
                            });
                    });
            });
    }

    fn render_tab_connections(&mut self, ui: &mut egui::Ui, pal: Palette, snap: &MonitorSnapshot) {
        egui::Frame::none()
            .fill(pal.bg_alt)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Search:").color(pal.text_muted));
                    ui.text_edit_singleline(&mut self.search_query);

                    ui.separator();
                    ui.selectable_value(&mut self.proto_filter, ProtoFilter::All, "All Proto");
                    ui.selectable_value(&mut self.proto_filter, ProtoFilter::Tcp, "TCP");
                    ui.selectable_value(&mut self.proto_filter, ProtoFilter::Udp, "UDP");

                    ui.separator();
                    ui.selectable_value(&mut self.state_filter, StateFilter::All, "All States");
                    ui.selectable_value(
                        &mut self.state_filter,
                        StateFilter::Established,
                        "Established",
                    );
                    ui.selectable_value(
                        &mut self.state_filter,
                        StateFilter::Listening,
                        "Listening",
                    );
                    ui.selectable_value(
                        &mut self.state_filter,
                        StateFilter::AlertsOnly,
                        "Alerts Only",
                    );

                    ui.separator();
                    let mut rdns = self.control().is_rdns_enabled();
                    if ui.checkbox(&mut rdns, "Reverse DNS").changed() {
                        self.control().set_rdns_enabled(rdns);
                    }
                });
            });

        ui.add_space(8.0);
        let q = self.search_query.to_ascii_lowercase();

        let full_w = ui.available_width();
        let full_h = ui.available_height().max(120.0);
        egui::Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(10.0)
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.set_min_size(Vec2::new((full_w - 26.0).max(200.0), (full_h - 26.0).max(90.0)));
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Active Sockets & Endpoints").color(pal.text_main).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        theme::tag_badge(
                            ui,
                            &format!("{} total", snap.connections.len()),
                            pal.text_muted,
                            pal.border,
                            pal.bg_alt,
                        );
                    });
                });
                ui.add_space(5.0);
                let (hr, _) =
                    ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), egui::Sense::hover());
                ui.painter().line_segment(
                    [hr.left_center(), hr.right_center()],
                    Stroke::new(1.0_f32, pal.border),
                );
                ui.add_space(5.0);
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Grid::new("conn_table")
                            .striped(true)
                            .spacing([12.0, 5.0])
                            .show(ui, |ui| {
                                ui.label(RichText::new("Proto").color(pal.text_muted).strong());
                                ui.label(RichText::new("Process").color(pal.text_muted).strong());
                                ui.label(RichText::new("PID").color(pal.text_muted).strong());
                                ui.label(RichText::new("Local Endpoint").color(pal.text_muted).strong());
                                ui.label(RichText::new("Remote Endpoint").color(pal.text_muted).strong());
                                ui.label(RichText::new("Host / Service").color(pal.text_muted).strong());
                                ui.label(RichText::new("State").color(pal.text_muted).strong());
                                ui.label(RichText::new("Triage").color(pal.text_muted).strong());
                                ui.end_row();

                                for c in &snap.connections {
                                    match self.proto_filter {
                                        ProtoFilter::All => {}
                                        ProtoFilter::Tcp => {
                                            if !matches!(c.protocol, Protocol::Tcp4 | Protocol::Tcp6) {
                                                continue;
                                            }
                                        }
                                        ProtoFilter::Udp => {
                                            if !matches!(c.protocol, Protocol::Udp4 | Protocol::Udp6) {
                                                continue;
                                            }
                                        }
                                    }

                                    match self.state_filter {
                                        StateFilter::All => {}
                                        StateFilter::Established => {
                                            if c.state != Some(TcpState::Established) {
                                                continue;
                                            }
                                        }
                                        StateFilter::Listening => {
                                            if c.state != Some(TcpState::Listen) {
                                                continue;
                                            }
                                        }
                                        StateFilter::AlertsOnly => {
                                            if c.alert.is_none() {
                                                continue;
                                            }
                                        }
                                    }

                                    let local_s = format!("{}:{}", c.local_addr, c.local_port);
                                    let remote_s = match (c.remote_addr, c.remote_port) {
                                        (Some(ip), Some(p)) => format!("{ip}:{p}"),
                                        _ => "*:*".into(),
                                    };

                                    if !q.is_empty() {
                                        let hit = c.process_name.to_ascii_lowercase().contains(&q)
                                            || c.pid.to_string().contains(&q)
                                            || local_s.to_ascii_lowercase().contains(&q)
                                            || remote_s.to_ascii_lowercase().contains(&q)
                                            || c.remote_host
                                                .as_deref()
                                                .unwrap_or("")
                                                .to_ascii_lowercase()
                                                .contains(&q)
                                            || c.port_service
                                                .as_deref()
                                                .unwrap_or("")
                                                .to_ascii_lowercase()
                                                .contains(&q);
                                        if !hit {
                                            continue;
                                        }
                                    }

                                    let proto_str = c.protocol.to_string();
                                    let proto_col = match c.protocol {
                                        Protocol::Tcp4 | Protocol::Tcp6 => pal.sky,
                                        Protocol::Udp4 | Protocol::Udp6 => pal.accent,
                                    };
                                    theme::tag_badge(ui, &proto_str, proto_col, pal.border, pal.bg_alt);
                                    ui.label(&c.process_name);
                                    ui.monospace(c.pid.to_string());
                                    ui.monospace(local_s);
                                    ui.monospace(remote_s);

                                    let host_svc = match (&c.remote_host, &c.port_service) {
                                        (Some(h), Some(s)) => format!("{h} [{s}]"),
                                        (Some(h), None) => h.clone(),
                                        (None, Some(s)) => format!("[{s}]"),
                                        (None, None) => "-".into(),
                                    };
                                    ui.label(host_svc);

                                    let state_str = c
                                        .state
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| "UDP".into());
                                    let state_col = match c.state {
                                        Some(TcpState::Established) => pal.emerald,
                                        Some(TcpState::Listen) => pal.sky,
                                        _ => pal.text_muted,
                                    };
                                    theme::tag_badge(ui, &state_str, state_col, pal.border, pal.bg_alt);

                                    match &c.alert {
                                        Some(alert) => {
                                            let col = match alert.severity {
                                                AlertSeverity::High => pal.danger,
                                                AlertSeverity::Warning => pal.amber,
                                            };
                                            let tint = Color32::from_rgba_unmultiplied(
                                                col.r(),
                                                col.g(),
                                                col.b(),
                                                26,
                                            );
                                            ui.horizontal(|ui| {
                                                theme::tag_badge(ui, "! Alert", col, pal.border, tint);
                                            })
                                            .response
                                            .on_hover_text(&alert.reason);
                                        }
                                        None => {
                                            theme::tag_badge(
                                                ui,
                                                "OK",
                                                pal.emerald,
                                                pal.border_subtle,
                                                pal.bg_alt,
                                            );
                                        }
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            });
    }

    fn render_tab_adapters(&mut self, ui: &mut egui::Ui, pal: Palette, snap: &MonitorSnapshot) {
        egui::Frame::none()
            .fill(pal.bg_alt)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.checkbox(
                        &mut self.show_virtual_adapters,
                        "Show virtual / filter / down adapters",
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let csv_btn = egui::Button::new("Export Connections (CSV)")
                            .fill(pal.surface)
                            .stroke(Stroke::new(1.0_f32, pal.border))
                            .rounding(7.0);
                        if ui.add(csv_btn).clicked() {
                            self.do_export_csv(snap);
                        }
                        let json_btn = egui::Button::new("Export Snapshot (JSON)")
                            .fill(pal.surface)
                            .stroke(Stroke::new(1.0_f32, pal.border))
                            .rounding(7.0);
                        if ui.add(json_btn).clicked() {
                            self.do_export_json(snap);
                        }
                    });
                });
            });

        ui.add_space(8.0);
        let full_w = ui.available_width();
        let table_outer_h = (ui.available_height() - 108.0).max(140.0);
        let table_inner_h = (table_outer_h - 26.0).max(100.0);
        egui::Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(10.0)
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.set_min_size(Vec2::new((full_w - 26.0).max(200.0), table_inner_h));
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .max_height(table_inner_h)
                    .show(ui, |ui| {
                        egui::Grid::new("adapter_table")
                            .striped(true)
                            .spacing([12.0, 5.0])
                            .show(ui, |ui| {
                                ui.label(RichText::new("Alias").color(pal.text_muted).strong());
                                ui.label(RichText::new("Type").color(pal.text_muted).strong());
                                ui.label(RichText::new("State").color(pal.text_muted).strong());
                                ui.label(RichText::new("Link Speed").color(pal.text_muted).strong());
                                ui.label(RichText::new("In Rate").color(pal.emerald).strong());
                                ui.label(RichText::new("Out Rate").color(pal.sky).strong());
                                ui.label(RichText::new("Total In").color(pal.text_muted).strong());
                                ui.label(RichText::new("Total Out").color(pal.text_muted).strong());
                                ui.label(
                                    RichText::new("Errors (In/Out)")
                                        .color(pal.text_muted)
                                        .strong(),
                                );
                                ui.label(
                                    RichText::new("Discards (In/Out)")
                                        .color(pal.text_muted)
                                        .strong(),
                                );
                                ui.label(RichText::new("Description").color(pal.text_muted).strong());
                                ui.end_row();

                                for a in &snap.adapters {
                                    if !self.show_virtual_adapters
                                        && (!a.info.is_hardware || !a.info.is_up)
                                    {
                                        continue;
                                    }
                                    ui.label(&a.info.alias);
                                    if a.info.is_hardware {
                                        theme::tag_badge(
                                            ui,
                                            "Physical",
                                            pal.sky,
                                            pal.border,
                                            pal.bg_alt,
                                        );
                                    } else {
                                        theme::tag_badge(
                                            ui,
                                            "Virtual",
                                            pal.text_muted,
                                            pal.border_subtle,
                                            pal.bg_alt,
                                        );
                                    }
                                    if a.info.is_up {
                                        theme::tag_badge(
                                            ui,
                                            "Up",
                                            pal.emerald,
                                            pal.border,
                                            pal.bg_alt,
                                        );
                                    } else {
                                        theme::tag_badge(
                                            ui,
                                            "Down",
                                            pal.text_subtle,
                                            pal.border_subtle,
                                            pal.bg_alt,
                                        );
                                    }
                                    ui.monospace(format_link_speed(a.info.rx_link_bps));
                                    ui.monospace(format_rate(a.down_bps));
                                    ui.monospace(format_rate(a.up_bps));
                                    ui.monospace(format_bytes(a.info.in_octets));
                                    ui.monospace(format_bytes(a.info.out_octets));
                                    ui.monospace(format!("{}/{}", a.info.in_errors, a.info.out_errors));
                                    ui.monospace(format!(
                                        "{}/{}",
                                        a.info.in_discards, a.info.out_discards
                                    ));
                                    ui.label(
                                        RichText::new(&a.info.description)
                                            .color(pal.text_subtle)
                                            .small(),
                                    );
                                    ui.end_row();
                                }
                            });
                    });
            });

        ui.add_space(8.0);
        let rem_h = ui.available_height().max(64.0);
        egui::Frame::none()
            .fill(pal.bg_alt)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(10.0)
            .inner_margin(egui::Margin::same(10.0))
            .show(ui, |ui| {
                ui.set_min_size(Vec2::new((full_w - 22.0).max(200.0), (rem_h - 22.0).max(46.0)));
                ui.label(
                    RichText::new("Windows IPv4 TCP Stack Health (GetTcpStatisticsEx)")
                        .color(pal.text_main)
                        .strong(),
                );
                ui.add_space(4.0);
                let (hr, _) =
                    ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), egui::Sense::hover());
                ui.painter().line_segment(
                    [hr.left_center(), hr.right_center()],
                    Stroke::new(1.0_f32, pal.border_subtle),
                );
                ui.add_space(4.0);
                if let Some(st) = &snap.tcp_stats {
                    let retransmit_pct = if st.out_segs > 0 {
                        (st.retrans_segs as f64 / st.out_segs as f64) * 100.0
                    } else {
                        0.0
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui.monospace(format!("CurrEstab: {}", st.curr_estab));
                        ui.separator();
                        ui.monospace(format!("ActiveOpens: {}", st.active_opens));
                        ui.separator();
                        ui.monospace(format!("PassiveOpens: {}", st.passive_opens));
                        ui.separator();
                        ui.monospace(format!("AttemptFails: {}", st.attempt_fails));
                        ui.separator();
                        ui.monospace(format!("EstabResets: {}", st.estab_resets));
                        ui.separator();
                        ui.monospace(format!(
                            "RetransSegs: {} ({retransmit_pct:.2}%)",
                            st.retrans_segs
                        ));
                        ui.separator();
                        ui.monospace(format!("InErrs: {}", st.in_errs));
                        ui.separator();
                        ui.monospace(format!("OutRsts: {}", st.out_rsts));
                    });
                } else {
                    ui.label(RichText::new("TCP stack statistics unavailable.").color(pal.text_subtle));
                }
            });
    }
}

impl eframe::App for NetMeterApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [0.0, 0.0, 0.0, 0.0]
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown_tray_cleanly();
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_tray_events(ctx);

        if let Ok(guard) = self.handle.snapshot.try_lock() {
            if guard.seq != self.cached_snap.seq {
                self.cached_snap = guard.clone();
                self.last_snap_at = Instant::now();
            }
        }
        let snap = self.cached_snap.clone();
        let is_paused = self.control().is_paused();

        // Smooth animation interpolation for waveform curves, KPI readouts, and endpoint pulse
        let dt = self.last_anim_at.elapsed().as_secs_f64().clamp(0.001, 0.25);
        self.last_anim_at = Instant::now();
        if !is_paused {
            let alpha = 1.0 - (-dt * 7.5).exp();
            self.anim_down_bps += (snap.down_bps - self.anim_down_bps) * alpha;
            self.anim_up_bps += (snap.up_bps - self.anim_up_bps) * alpha;

            let target_max = snap
                .history
                .iter()
                .fold(1024.0_f64, |acc, s| acc.max(s.down_bps).max(s.up_bps));
            let scale_alpha = 1.0 - (-dt * 4.5).exp();
            self.smooth_max_rate += (target_max - self.smooth_max_rate) * scale_alpha;

            self.pulse_phase = (self.pulse_phase + dt as f32 * 0.95) % 1.0;
        }

        match self.mode {
            ViewMode::TrayHidden => {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.exit_app(ctx);
                    return;
                }
                // Keep window off-screen with NO repaint timer:
                // 0% CPU and 0 OpenGL frames while sleeping, yet RedrawRequested wakes instantly
                // when the tray thread calls wake_ctx.request_repaint().
                egui::CentralPanel::default()
                    .frame(egui::Frame::none())
                    .show(ctx, |_ui| {});
            }
            ViewMode::TrayMenu => {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.exit_app(ctx);
                    return;
                }
                self.render_tray_menu(ctx, &snap);
                ctx.request_repaint_after(Duration::from_millis(90));
            }
            ViewMode::Dashboard => {
                self.render_dashboard(ctx, &snap);
                let interval_ms = if self.tab == DashTab::Overview && !is_paused {
                    33 // ~30 FPS smooth fluid waveform & pulse animation
                } else {
                    400
                };
                ctx.request_repaint_after(Duration::from_millis(interval_ms));
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    let handle = start_monitor();
    let initial_theme = ThemeMode::from_pref(&install::load_theme_pref());

    let options = eframe::NativeOptions {
        vsync: false,
        persist_window: false,
        run_and_return: false,
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_TITLE)
            .with_icon(Arc::new(app_icon_data()))
            .with_inner_size(HIDDEN_SIZE)
            .with_position(HIDDEN_POS)
            .with_decorations(false)
            .with_transparent(false)
            .with_resizable(false)
            .with_window_level(egui::WindowLevel::AlwaysOnTop)
            .with_taskbar(false),
        ..Default::default()
    };

    eframe::run_native(
        APP_TITLE,
        options,
        Box::new(move |cc| {
            theme::apply_theme(&cc.egui_ctx, initial_theme);
            let tray = start_tray_worker(
                Arc::clone(&handle.snapshot),
                cc.egui_ctx.clone(),
            );
            if !tray.has_tray {
                let scale = cc.egui_ctx.pixels_per_point();
                let [x, y] = position::center_in_work_area(DASH_SIZE, scale);
                cc.egui_ctx
                    .send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                        egui::WindowLevel::Normal,
                    ));
                cc.egui_ctx
                    .send_viewport_cmd(egui::ViewportCommand::Decorations(true));
                cc.egui_ctx
                    .send_viewport_cmd(egui::ViewportCommand::Resizable(true));
                cc.egui_ctx
                    .send_viewport_cmd(egui::ViewportCommand::MinInnerSize(Vec2::new(
                        580.0, 440.0,
                    )));
                cc.egui_ctx
                    .send_viewport_cmd(egui::ViewportCommand::InnerSize(DASH_SIZE.into()));
                cc.egui_ctx
                    .send_viewport_cmd(egui::ViewportCommand::OuterPosition(Pos2::new(x, y)));
                cc.egui_ctx
                    .send_viewport_cmd(egui::ViewportCommand::Visible(true));
            }
            Ok(Box::new(NetMeterApp::new(handle, tray, initial_theme)))
        }),
    )
}
