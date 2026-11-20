pub mod export;
pub mod i18n;
pub mod install;
pub mod monitor;
pub mod net;
pub mod position;
pub mod security;
pub mod theme;

#[cfg(feature = "etw")]
pub mod etw;

/// Embedded 64x64 RGBA application icon for eframe window / Windows taskbar.
pub fn app_icon_data() -> eframe::egui::IconData {
    let rgba = include_bytes!("../assets/icon_64.rgba").to_vec();
    eframe::egui::IconData {
        rgba,
        width: 64,
        height: 64,
    }
}
