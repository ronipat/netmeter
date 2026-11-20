//! DPI-aware Windows taskbar docking, work-area placement, and full-screen suppression helpers.

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, POINT, RECT};
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DEFAULT, DWMWCP_DONOTROUND,
    DWMWCP_ROUND, DWM_WINDOW_CORNER_PREFERENCE,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON};
use windows::Win32::UI::Shell::{
    SHQueryUserNotificationState, QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, FindWindowExW, FindWindowW, GetCursorPos, GetWindowRect,
    SetForegroundWindow, SetWindowPos, ShowWindowAsync, SystemParametersInfoW, HWND_TOPMOST,
    SPI_GETWORKAREA, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SW_SHOW, SW_SHOWNA,
    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DockMode {
    /// Sits directly on the Windows taskbar right next to the system tray (`TrayNotifyWnd`).
    OnTaskbar,
    /// Sits cleanly just above the taskbar in the bottom-right corner of the work area.
    AboveTaskbar,
}

/// The primary monitor's work area in physical pixels (screen minus taskbar).
pub fn work_area() -> RECT {
    let mut rect = RECT::default();
    unsafe {
        let _ = SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some(&mut rect as *mut RECT as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        );
    }
    rect
}

/// Top-left position (in egui logical points) placing a `size`-point window
/// in the bottom-right corner of the work area, inset by `margin` points.
pub fn bottom_right(size: [f32; 2], pixels_per_point: f32, margin: f32) -> [f32; 2] {
    let scale = if pixels_per_point > 0.0 {
        pixels_per_point
    } else {
        1.0
    };
    let wa = work_area();
    let right = wa.right as f32 / scale;
    let bottom = wa.bottom as f32 / scale;
    [
        (right - size[0] - margin).max(wa.left as f32 / scale),
        (bottom - size[1] - margin).max(wa.top as f32 / scale),
    ]
}

/// Compute top-left position (in egui logical points) directly inside the Windows taskbar
/// immediately to the left of the system tray (`TrayNotifyWnd`), or fallback to `bottom_right`
/// if the taskbar is auto-hidden or non-bottom.
pub fn taskbar_dock_pos(size: [f32; 2], pixels_per_point: f32) -> [f32; 2] {
    let scale = if pixels_per_point > 0.0 {
        pixels_per_point
    } else {
        1.0
    };

    unsafe {
        if let Ok(tray_wnd) = FindWindowW(w!("Shell_TrayWnd"), PCWSTR::null()) {
            let mut tb_rect = RECT::default();
            if GetWindowRect(tray_wnd, &mut tb_rect).is_ok() {
                let tb_h = (tb_rect.bottom - tb_rect.top) as f32 / scale;
                let tb_w = (tb_rect.right - tb_rect.left) as f32 / scale;
                // Only dock inside horizontal bottom/top taskbars with normal height (32..80pt)
                if tb_w > tb_h && (28.0..=90.0).contains(&tb_h) {
                    let right_anchor = match FindWindowExW(
                        tray_wnd,
                        HWND::default(),
                        w!("TrayNotifyWnd"),
                        PCWSTR::null(),
                    ) {
                        Ok(notify_wnd) => {
                            let mut nr = RECT::default();
                            if GetWindowRect(notify_wnd, &mut nr).is_ok() && nr.left > tb_rect.left
                            {
                                nr.left as f32 / scale
                            } else {
                                tb_rect.right as f32 / scale - 160.0
                            }
                        }
                        Err(_) => tb_rect.right as f32 / scale - 160.0,
                    };

                    let tb_top = tb_rect.top as f32 / scale;
                    let x = (right_anchor - size[0] - 6.0).max(tb_rect.left as f32 / scale + 4.0);
                    let y = tb_top + ((tb_h - size[1]) * 0.5).max(1.0);
                    return [x, y];
                }
            }
        }
    }

    bottom_right(size, scale, 8.0)
}

/// Gently re-asserts `HWND_TOPMOST` without stealing keyboard focus so the taskbar
/// traffic widget stays visible above `Shell_TrayWnd`.
pub fn keep_topmost_no_activate(window_title: &str) {
    let mut wide: Vec<u16> = window_title.encode_utf16().collect();
    wide.push(0);
    unsafe {
        if let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(wide.as_ptr())) {
            let _ = SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
        }
    }
}

/// Bring our window to the foreground (used when opening the tray popup or full monitor).
pub fn force_foreground_window(window_title: &str) {
    let mut wide: Vec<u16> = window_title.encode_utf16().collect();
    wide.push(0);
    unsafe {
        if let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(wide.as_ptr())) {
            let _ = ShowWindowAsync(hwnd, SW_SHOW);
            let _ = BringWindowToTop(hwnd);
            let _ = SetForegroundWindow(hwnd);
        }
    }
}

/// Asynchronously un-hide the main window from a background tray thread so winit
/// delivers `RedrawRequested` even when the window was hidden with `Visible(false)`.
pub fn wake_window_async(window_title: &str) {
    let mut wide: Vec<u16> = window_title.encode_utf16().collect();
    wide.push(0);
    unsafe {
        if let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(wide.as_ptr())) {
            let _ = ShowWindowAsync(hwnd, SW_SHOWNA);
        }
    }
}

/// Returns `true` if a physical left mouse button is pressed while the cursor is outside
/// the popup window's logical `outer_rect` (zero `FindWindowW` calls).
pub fn is_left_mouse_pressed_outside_rect(
    left: f32,
    top: f32,
    right: f32,
    bottom: f32,
    pixels_per_point: f32,
) -> bool {
    let scale = pixels_per_point.max(1.0);
    unsafe {
        let l_down = (GetAsyncKeyState(VK_LBUTTON.0 as i32) as u16 & 0x8000) != 0;
        if !l_down {
            return false;
        }
        let mut pt = POINT::default();
        if GetCursorPos(&mut pt).is_err() {
            return false;
        }
        let lx = pt.x as f32 / scale;
        let ly = pt.y as f32 / scale;
        lx < left || lx > right || ly < top || ly > bottom
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CornerPref {
    Default,
    Sharp,
    Round,
}

/// Set Windows 11 DWM corner preference on the window.
pub fn set_window_corner_preference(window_title: &str, mode: CornerPref) {
    let mut wide: Vec<u16> = window_title.encode_utf16().collect();
    wide.push(0);
    let pref: DWM_WINDOW_CORNER_PREFERENCE = match mode {
        CornerPref::Default => DWMWCP_DEFAULT,
        CornerPref::Sharp => DWMWCP_DONOTROUND,
        CornerPref::Round => DWMWCP_ROUND,
    };
    unsafe {
        if let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(wide.as_ptr())) {
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_WINDOW_CORNER_PREFERENCE,
                &pref as *const DWM_WINDOW_CORNER_PREFERENCE as *const _,
                std::mem::size_of::<DWM_WINDOW_CORNER_PREFERENCE>() as u32,
            );
        }
    }
}

/// Center position (in egui logical points) within the work area for the expanded dashboard.
pub fn center_in_work_area(size: [f32; 2], pixels_per_point: f32) -> [f32; 2] {
    let scale = if pixels_per_point > 0.0 {
        pixels_per_point
    } else {
        1.0
    };
    let wa = work_area();
    let left = wa.left as f32 / scale;
    let top = wa.top as f32 / scale;
    let width = (wa.right - wa.left) as f32 / scale;
    let height = (wa.bottom - wa.top) as f32 / scale;
    [
        left + ((width - size[0]) * 0.5).max(0.0),
        top + ((height - size[1]) * 0.5).max(0.0),
    ]
}

/// Returns `true` when Windows reports a full-screen exclusive D3D app or busy presentation mode.
pub fn is_fullscreen_active() -> bool {
    unsafe {
        match SHQueryUserNotificationState() {
            Ok(state) => state == QUNS_RUNNING_D3D_FULL_SCREEN || state == QUNS_BUSY,
            Err(_) => false,
        }
    }
}
