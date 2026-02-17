/// RGB color tuple.
pub type Rgb = (u8, u8, u8);

pub const RESET: &str = "\x1b[0m";

/// ANSI truecolor foreground escape.
pub fn fg(r: u8, g: u8, b: u8) -> String {
    format!("\x1b[38;2;{};{};{}m", r, g, b)
}

/// Shorthand: Rgb → ANSI foreground escape.
pub fn ansi(col: Rgb) -> String {
    fg(col.0, col.1, col.2)
}

/// Linearly interpolate a single channel.
fn mix_channel(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 * (1.0 - t) + b as f32 * t) as u8
}

/// Interpolate between two colors.
pub fn mix(a: Rgb, b: Rgb, t: f32) -> Rgb {
    let t = t.clamp(0.0, 1.0);
    (mix_channel(a.0, b.0, t), mix_channel(a.1, b.1, t), mix_channel(a.2, b.2, t))
}

/// Dim a color toward a dark background (20, 20, 30).
pub fn dim(col: Rgb, t: f32) -> Rgb {
    mix(col, (20, 20, 30), t)
}

// ── Design system palette ────────────────────────────────

pub const CYAN:   Rgb = (125, 211, 252);
pub const PURPLE: Rgb = (196, 181, 253);
pub const TEAL:   Rgb = (94, 234, 212);
pub const GREEN:  Rgb = (134, 239, 172);
pub const MUTED:  Rgb = (133, 133, 173);
pub const BRIGHT: Rgb = (244, 244, 255);
