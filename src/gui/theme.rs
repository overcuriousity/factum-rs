//! Colors and fonts, chosen for long, focused reading sessions:
//!
//! - dark text on a light background is the default for daytime work (positive polarity reads better:
//!   Buchner & Baumgartner 2007, Piepenbrock et al. 2013/2014); the dark theme is for dim rooms
//! - off-white and off-black instead of pure #fff/#000, which reduces halation for astigmatic readers
//! - neutral greys with one accent color; saturated color only for status, always together with a symbol
//!   (✓ / ⚠ / ✗), never by color alone (WCAG 1.4.1); status hues follow the Okabe–Ito color-blind-safe palette
//! - body and secondary text ≥ 7:1 contrast, metadata ≥ 4.5:1 in both themes
//! - Atkinson Hyperlegible Next for text (letter differentiation: Il1, O0), JetBrains Mono for hashes,
//!   timestamps, key ids and IoCs; 16 px note text, about 70 characters per line
//! - the log is a flat list separated by hairlines, not a stack of boxed cards: spacing carries the grouping (the
//!   gap inside a note is smaller than the gap between notes, Gestalt proximity; grouping matters more than
//!   whitespace, Tullis 1983), so more entries fit on screen; corners are square or 2 px, a style choice without
//!   a usability cost

use std::sync::Arc;

use egui::{Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle, Theme, Visuals};

pub const THEMES: [&str; 3] = ["system", "light", "dark"];

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub surface: Color32,
    pub border: Color32,
    pub text: Color32,
    pub secondary: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    /// text on accent-filled buttons
    pub on_accent: Color32,
    pub ok: Color32,
    pub warn: Color32,
    pub warn_soft: Color32,
    pub fail: Color32,
    pub tag: Color32,
    pub tag_soft: Color32,
}

const fn hex(value: u32) -> Color32 {
    Color32::from_rgb((value >> 16) as u8, (value >> 8) as u8, value as u8)
}

pub const LIGHT: Palette = Palette {
    bg: hex(0xf7f6f2),
    panel: hex(0xefede7),
    surface: hex(0xfdfcf9),
    border: hex(0xd3d0c8),
    text: hex(0x1c1f24),
    secondary: hex(0x454b54),
    muted: hex(0x5e646e),
    accent: hex(0x1f5fad),
    accent_soft: hex(0xe1eaf5),
    on_accent: hex(0xffffff),
    ok: hex(0x00704f),
    warn: hex(0x8a5a00),
    warn_soft: hex(0xf8eed9),
    fail: hex(0xb03a0c),
    tag: hex(0x7b3f8f),
    tag_soft: hex(0xf1e7f4),
};

pub const DARK: Palette = Palette {
    bg: hex(0x17191d),
    panel: hex(0x1b1d22),
    surface: hex(0x1f2227),
    border: hex(0x3a3f47),
    text: hex(0xe4e2dd),
    secondary: hex(0xb6bac2),
    muted: hex(0x959ba5),
    accent: hex(0x7eb0ee),
    accent_soft: hex(0x253549),
    on_accent: hex(0x17191d),
    ok: hex(0x4fc59e),
    warn: hex(0xe3b04b),
    warn_soft: hex(0x3a2f19),
    fail: hex(0xff8c6b),
    tag: hex(0xd3a1d0),
    tag_soft: hex(0x352736),
};

pub fn palette(dark: bool) -> &'static Palette {
    if dark { &DARK } else { &LIGHT }
}

pub const NOTE_SIZE: f32 = 16.0;
pub const BODY_SIZE: f32 = 14.5;
pub const SMALL_SIZE: f32 = 12.5;
pub const MONO_SIZE: f32 = 12.5;
/// note cards stop growing at about 70 characters per line
pub const MAX_CARD_WIDTH: f32 = 760.0;

pub fn bold() -> FontFamily {
    FontFamily::Name("bold".into())
}

pub fn italic() -> FontFamily {
    FontFamily::Name("italic".into())
}

pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let mut add = |name: &str, bytes: &'static [u8]| {
        fonts
            .font_data
            .insert(name.to_string(), Arc::new(FontData::from_static(bytes)));
    };
    add(
        "atkinson",
        include_bytes!("../../assets/fonts/AtkinsonHyperlegibleNext-Regular.ttf"),
    );
    add(
        "atkinson-bold",
        include_bytes!("../../assets/fonts/AtkinsonHyperlegibleNext-SemiBold.ttf"),
    );
    add(
        "atkinson-italic",
        include_bytes!("../../assets/fonts/AtkinsonHyperlegibleNext-Italic.ttf"),
    );
    add(
        "jetbrains",
        include_bytes!("../../assets/fonts/JetBrainsMono-Regular.ttf"),
    );
    // egui's own fonts stay as fallbacks (emoji, symbols)
    let defaults = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let with_fallbacks = |first: &str| {
        let mut list = vec![first.to_string(), "jetbrains".to_string()];
        list.extend(defaults.iter().cloned());
        list
    };
    fonts
        .families
        .insert(FontFamily::Proportional, with_fallbacks("atkinson"));
    fonts.families.insert(bold(), with_fallbacks("atkinson-bold"));
    fonts.families.insert(italic(), with_fallbacks("atkinson-italic"));
    let mut mono = vec!["jetbrains".to_string()];
    mono.extend(fonts.families.get(&FontFamily::Monospace).cloned().unwrap_or_default());
    mono.push("atkinson".into());
    fonts.families.insert(FontFamily::Monospace, mono);
    ctx.set_fonts(fonts);
}

fn visuals(dark: bool) -> Visuals {
    let p = palette(dark);
    let mut visuals = if dark { Visuals::dark() } else { Visuals::light() };
    visuals.panel_fill = p.bg;
    visuals.window_fill = p.surface;
    visuals.window_stroke = Stroke::new(1.0, p.border);
    visuals.extreme_bg_color = p.surface;
    visuals.text_edit_bg_color = Some(p.surface);
    visuals.faint_bg_color = p.panel;
    visuals.code_bg_color = p.panel;
    visuals.hyperlink_color = p.accent;
    visuals.warn_fg_color = p.warn;
    visuals.error_fg_color = p.fail;
    visuals.override_text_color = None;
    visuals.selection.bg_fill = p.accent_soft;
    visuals.selection.stroke = Stroke::new(1.0, p.accent);
    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_fill = p.bg;
    widgets.noninteractive.weak_bg_fill = p.bg;
    widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    for (state, fill) in [
        (&mut widgets.inactive, p.surface),
        (&mut widgets.hovered, p.accent_soft),
        (&mut widgets.active, p.accent_soft),
        (&mut widgets.open, p.accent_soft),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.fg_stroke = Stroke::new(1.0, p.text);
    }
    widgets.inactive.bg_stroke = Stroke::new(1.0, p.border);
    widgets.hovered.bg_stroke = Stroke::new(1.0, p.accent);
    widgets.active.bg_stroke = Stroke::new(1.5, p.accent);
    for state in [
        &mut widgets.noninteractive,
        &mut widgets.inactive,
        &mut widgets.hovered,
        &mut widgets.active,
        &mut widgets.open,
    ] {
        state.corner_radius = CornerRadius::same(2);
    }
    visuals.window_corner_radius = CornerRadius::same(2);
    visuals.menu_corner_radius = CornerRadius::same(2);
    visuals
}

/// Applies the light and the dark style; which one is shown follows the theme preference.
pub fn apply(ctx: &egui::Context, theme: &str) {
    for (egui_theme, dark) in [(Theme::Light, false), (Theme::Dark, true)] {
        ctx.style_mut_of(egui_theme, |style| {
            style.visuals = visuals(dark);
            style.text_styles = [
                (TextStyle::Heading, FontId::new(18.0, bold())),
                (TextStyle::Body, FontId::new(BODY_SIZE, FontFamily::Proportional)),
                (TextStyle::Button, FontId::new(BODY_SIZE, FontFamily::Proportional)),
                (TextStyle::Small, FontId::new(SMALL_SIZE, FontFamily::Proportional)),
                (TextStyle::Monospace, FontId::new(MONO_SIZE, FontFamily::Monospace)),
            ]
            .into();
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(10.0, 4.0);
            style.spacing.interact_size.y = 26.0;
        });
    }
    ctx.set_theme(match theme {
        "light" => egui::ThemePreference::Light,
        "dark" => egui::ThemePreference::Dark,
        _ => egui::ThemePreference::System,
    });
}

pub fn is_dark(ctx: &egui::Context) -> bool {
    ctx.theme() == Theme::Dark
}

pub fn current(ctx: &egui::Context) -> &'static Palette {
    palette(is_dark(ctx))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luminance(color: Color32) -> f64 {
        let channel = |c: u8| {
            let c = c as f64 / 255.0;
            if c <= 0.03928 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
    }

    #[test]
    fn text_colors_meet_wcag() {
        for p in [&LIGHT, &DARK] {
            for background in [p.bg, p.surface, p.panel] {
                assert!(contrast(p.text, background) >= 7.0);
                assert!(contrast(p.secondary, background) >= 7.0);
                for color in [p.muted, p.accent, p.ok, p.warn, p.fail, p.tag] {
                    assert!(contrast(color, background) >= 4.5, "{color:?} on {background:?}");
                }
            }
            assert!(contrast(p.warn, p.warn_soft) >= 4.5);
            assert!(contrast(p.tag, p.tag_soft) >= 4.5 && contrast(p.text, p.accent_soft) >= 7.0);
            assert!(contrast(p.on_accent, p.accent) >= 4.5);
        }
    }
}
