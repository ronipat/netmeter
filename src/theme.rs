//! 9Router-inspired Dark, White, and Cartoon design tokens, shared egui theme, and vector brand mark.

use eframe::egui::{self, Color32, Pos2, Rect, Rounding, Stroke, Vec2};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeMode {
    Dark,
    Light,
    Cartoon,
}

impl ThemeMode {
    pub fn from_pref(s: &str) -> Self {
        if s.eq_ignore_ascii_case("light") || s.eq_ignore_ascii_case("white") {
            ThemeMode::Light
        } else if s.eq_ignore_ascii_case("cartoon") {
            ThemeMode::Cartoon
        } else {
            ThemeMode::Dark
        }
    }

    pub fn as_pref(self) -> &'static str {
        match self {
            ThemeMode::Dark => "dark",
            ThemeMode::Light => "light",
            ThemeMode::Cartoon => "cartoon",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ThemeMode::Dark => "Dark",
            ThemeMode::Light => "White",
            ThemeMode::Cartoon => "Cartoon",
        }
    }

    pub fn next(self) -> Self {
        match self {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Cartoon,
            ThemeMode::Cartoon => ThemeMode::Dark,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub bg_alt: Color32,
    pub surface: Color32,
    pub surface_2: Color32,
    pub border: Color32,
    pub border_subtle: Color32,
    pub text_main: Color32,
    pub text_muted: Color32,
    pub text_subtle: Color32,
    pub accent: Color32,
    pub emerald: Color32,
    pub sky: Color32,
    pub violet: Color32,
    pub amber: Color32,
    pub danger: Color32,
    pub extreme_bg: Color32,
    pub hover_bg: Color32,
    pub check_fg: Color32,
    pub card_rounding: f32,
    pub border_width: f32,
    pub is_cartoon: bool,
}

pub const DARK_PALETTE: Palette = Palette {
    bg: Color32::from_rgb(22, 23, 26),
    bg_alt: Color32::from_rgb(30, 31, 35),
    surface: Color32::from_rgb(36, 37, 42),
    surface_2: Color32::from_rgb(47, 49, 56),
    border: Color32::from_rgb(66, 70, 80),
    border_subtle: Color32::from_rgb(50, 53, 61),
    text_main: Color32::from_rgb(241, 243, 247),
    text_muted: Color32::from_rgb(163, 171, 184),
    text_subtle: Color32::from_rgb(115, 123, 138),
    accent: Color32::from_rgb(229, 106, 74),
    emerald: Color32::from_rgb(16, 185, 129),
    sky: Color32::from_rgb(56, 189, 248),
    violet: Color32::from_rgb(168, 85, 247),
    amber: Color32::from_rgb(245, 158, 11),
    danger: Color32::from_rgb(239, 68, 68),
    extreme_bg: Color32::from_rgb(18, 19, 22),
    hover_bg: Color32::from_rgb(58, 60, 68),
    check_fg: Color32::from_rgb(18, 22, 20),
    card_rounding: 10.0,
    border_width: 1.0,
    is_cartoon: false,
};

pub const LIGHT_PALETTE: Palette = Palette {
    bg: Color32::from_rgb(247, 247, 249),
    bg_alt: Color32::from_rgb(240, 242, 246),
    surface: Color32::from_rgb(255, 255, 255),
    surface_2: Color32::from_rgb(234, 237, 242),
    border: Color32::from_rgb(203, 209, 219),
    border_subtle: Color32::from_rgb(226, 230, 237),
    text_main: Color32::from_rgb(15, 18, 24),
    text_muted: Color32::from_rgb(88, 96, 110),
    text_subtle: Color32::from_rgb(120, 128, 142),
    accent: Color32::from_rgb(224, 98, 66),
    emerald: Color32::from_rgb(5, 150, 105),
    sky: Color32::from_rgb(2, 132, 199),
    violet: Color32::from_rgb(124, 58, 237),
    amber: Color32::from_rgb(217, 119, 6),
    danger: Color32::from_rgb(220, 38, 38),
    extreme_bg: Color32::from_rgb(238, 240, 244),
    hover_bg: Color32::from_rgb(226, 230, 238),
    check_fg: Color32::from_rgb(255, 255, 255),
    card_rounding: 10.0,
    border_width: 1.0,
    is_cartoon: false,
};

pub const CARTOON_PALETTE: Palette = Palette {
    bg: Color32::from_rgb(252, 250, 244),           // bright comic paper cream
    bg_alt: Color32::from_rgb(236, 243, 255),       // colorful pastel sky tint
    surface: Color32::from_rgb(255, 255, 255),      // crisp white comic card
    surface_2: Color32::from_rgb(218, 234, 255),    // colorful pastel blue active
    border: Color32::from_rgb(38, 36, 46),          // heavy comic ink outline
    border_subtle: Color32::from_rgb(138, 146, 168),// crisp slate hairline
    text_main: Color32::from_rgb(24, 24, 34),       // deep comic ink
    text_muted: Color32::from_rgb(76, 82, 102),     // slate ink
    text_subtle: Color32::from_rgb(106, 114, 134),
    accent: Color32::from_rgb(130, 68, 245),        // vibrant cartoon purple (no orange)
    emerald: Color32::from_rgb(0, 184, 107),        // punchy comic green
    sky: Color32::from_rgb(29, 122, 252),           // bold cartoon cobalt blue
    violet: Color32::from_rgb(225, 29, 116),        // vivid cartoon magenta-pink
    amber: Color32::from_rgb(234, 179, 8),          // bright comic gold
    danger: Color32::from_rgb(239, 35, 60),         // punchy cartoon red
    extreme_bg: Color32::from_rgb(232, 240, 255),
    hover_bg: Color32::from_rgb(226, 238, 255),
    check_fg: Color32::from_rgb(255, 255, 255),
    card_rounding: 14.0,
    border_width: 2.0,
    is_cartoon: true,
};

pub const BG: Color32 = DARK_PALETTE.bg;
pub const BG_ALT: Color32 = DARK_PALETTE.bg_alt;
pub const SURFACE: Color32 = DARK_PALETTE.surface;
pub const SURFACE_2: Color32 = DARK_PALETTE.surface_2;
pub const BORDER: Color32 = DARK_PALETTE.border;
pub const BORDER_SUBTLE: Color32 = DARK_PALETTE.border_subtle;
pub const TEXT_MAIN: Color32 = DARK_PALETTE.text_main;
pub const TEXT_MUTED: Color32 = DARK_PALETTE.text_muted;
pub const TEXT_SUBTLE: Color32 = DARK_PALETTE.text_subtle;
pub const ACCENT: Color32 = DARK_PALETTE.accent;
pub const EMERALD: Color32 = DARK_PALETTE.emerald;
pub const SKY: Color32 = DARK_PALETTE.sky;
pub const AMBER: Color32 = DARK_PALETTE.amber;
pub const DANGER: Color32 = DARK_PALETTE.danger;

pub fn palette(mode: ThemeMode) -> Palette {
    match mode {
        ThemeMode::Dark => DARK_PALETTE,
        ThemeMode::Light => LIGHT_PALETTE,
        ThemeMode::Cartoon => CARTOON_PALETTE,
    }
}

/// Apply 9Router's Dark, White, or Cartoon palette to an `egui::Context`.
pub fn apply_theme(ctx: &egui::Context, mode: ThemeMode) {
    let pal = palette(mode);
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 5.0);

    let mut v = match mode {
        ThemeMode::Dark => egui::Visuals::dark(),
        ThemeMode::Light | ThemeMode::Cartoon => egui::Visuals::light(),
    };
    let round = Rounding::same(pal.card_rounding);
    let ctrl_round = Rounding::same((pal.card_rounding - 2.0).max(7.0));
    v.override_text_color = Some(pal.text_main);
    v.panel_fill = pal.bg;
    v.window_fill = pal.surface;
    v.faint_bg_color = pal.bg_alt;
    v.extreme_bg_color = pal.extreme_bg;
    v.code_bg_color = pal.bg_alt;
    v.window_rounding = round;
    v.window_stroke = Stroke::new(pal.border_width, pal.border);
    v.menu_rounding = round;

    v.widgets.noninteractive.bg_fill = pal.surface;
    v.widgets.noninteractive.weak_bg_fill = pal.bg_alt;
    v.widgets.noninteractive.bg_stroke = Stroke::new(pal.border_width, pal.border);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, pal.text_muted);
    v.widgets.noninteractive.rounding = ctrl_round;

    v.widgets.inactive.bg_fill = pal.surface_2;
    v.widgets.inactive.weak_bg_fill = pal.surface;
    v.widgets.inactive.bg_stroke = Stroke::new(pal.border_width, pal.border);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, pal.text_main);
    v.widgets.inactive.rounding = ctrl_round;

    v.widgets.hovered.bg_fill = pal.hover_bg;
    v.widgets.hovered.weak_bg_fill = pal.surface_2;
    v.widgets.hovered.bg_stroke = Stroke::new(pal.border_width, pal.border);
    v.widgets.hovered.fg_stroke = Stroke::new(1.2_f32, pal.text_main);
    v.widgets.hovered.rounding = ctrl_round;

    v.widgets.active.bg_fill = pal.surface_2;
    v.widgets.active.weak_bg_fill = pal.surface_2;
    v.widgets.active.bg_stroke = Stroke::new(pal.border_width, pal.border);
    v.widgets.active.fg_stroke = Stroke::new(1.5_f32, pal.text_main);
    v.widgets.active.rounding = ctrl_round;

    v.selection.bg_fill = Color32::from_rgba_unmultiplied(156, 163, 175, 45);
    v.selection.stroke = Stroke::new(pal.border_width, pal.border);

    style.visuals = v;
    ctx.set_style(style);
}

pub fn apply_9router_theme(ctx: &egui::Context) {
    apply_theme(ctx, ThemeMode::Dark);
}

/// Draw a 9Router-style coral hub emblem (`size` x `size` points).
pub fn draw_hub_logo(ui: &mut egui::Ui, size: f32) {
    draw_hub_logo_with(ui, size, DARK_PALETTE);
}

pub fn draw_hub_logo_with(ui: &mut egui::Ui, size: f32, pal: Palette) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let p = ui.painter();
    let r_box = (pal.card_rounding - 3.0).max(6.0);
    if pal.is_cartoon {
        p.rect_filled(rect.translate(Vec2::new(2.0, 2.0)), r_box, pal.border);
        p.rect_filled(rect, r_box, pal.surface_2);
    } else {
        p.rect_filled(rect, r_box, pal.bg_alt);
    }
    p.rect_stroke(rect, r_box, Stroke::new(pal.border_width, pal.border));

    let c = rect.center();
    let r = size * 0.27;
    let nodes = [
        Pos2::new(c.x, c.y - r),
        Pos2::new(c.x + r * 0.88, c.y + r * 0.65),
        Pos2::new(c.x - r * 0.88, c.y + r * 0.65),
    ];
    for n in nodes {
        if pal.is_cartoon {
            p.line_segment([c, n], Stroke::new(2.8_f32, pal.border));
        }
        p.line_segment([c, n], Stroke::new(1.5_f32, pal.accent));
        if pal.is_cartoon {
            p.circle_filled(n, 3.0, pal.border);
            p.circle_filled(n, 1.9, pal.surface);
        } else {
            p.circle_filled(n, 2.0, pal.text_main);
        }
    }
    if pal.is_cartoon {
        p.circle_filled(c, 4.0, pal.border);
        p.circle_filled(c, 2.8, pal.accent);
    } else {
        p.circle_filled(c, 2.8, pal.accent);
    }
}

/// Draw a subtle cel-shaded cartoon shadow behind a card rect when `pal.is_cartoon` is active.
pub fn draw_cartoon_shadow(ui: &egui::Ui, rect: Rect, rounding: f32, pal: Palette) {
    if pal.is_cartoon {
        let shadow_rect = rect.translate(Vec2::new(4.0, 4.0));
        ui.painter().rect_filled(
            shadow_rect,
            rounding,
            Color32::from_rgba_unmultiplied(pal.border.r(), pal.border.g(), pal.border.b(), 58),
        );
    }
}

/// Draw a rounded status pill badge (e.g. `Live`, `ETW Active`, `Standard`).
pub fn status_pill(ui: &mut egui::Ui, text: &str, dot_color: Color32, bg: Color32) {
    status_pill_with(ui, text, dot_color, bg, DARK_PALETTE);
}

pub fn status_pill_with(
    ui: &mut egui::Ui,
    text: &str,
    dot_color: Color32,
    bg: Color32,
    pal: Palette,
) {
    egui::Frame::none()
        .fill(bg)
        .stroke(Stroke::new(pal.border_width, pal.border))
        .rounding(Rounding::same(99.0))
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 5.0;
                let (dot_rect, _) =
                    ui.allocate_exact_size(Vec2::splat(7.0), egui::Sense::hover());
                ui.painter().circle_filled(dot_rect.center(), 3.2, dot_color);
                ui.label(egui::RichText::new(text).color(pal.text_main).size(11.0));
            });
        });
}

/// Compact 1px-bordered tag badge used inside tables (Protocol, State, Triage).
pub fn tag_badge(ui: &mut egui::Ui, text: &str, fg: Color32, border_col: Color32, bg: Color32) {
    egui::Frame::none()
        .fill(bg)
        .stroke(Stroke::new(1.0_f32, border_col))
        .rounding(Rounding::same(6.0))
        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(fg).monospace().size(11.0));
        });
}
