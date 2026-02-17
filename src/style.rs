use crate::config::{ColorConfig, parse_hex_color};
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

static USE_COLOR: AtomicBool = AtomicBool::new(true);
static IS_TTY: AtomicBool = AtomicBool::new(true);
static PALETTE: OnceLock<[(u8, u8, u8); 12]> = OnceLock::new();

/// Initialize the color palette from config. Call once at startup.
pub(crate) fn init_colors(config: &ColorConfig) {
    let defaults = ColorConfig::default();
    let parse_or = |hex: &str, fallback: &str| -> (u8, u8, u8) {
        parse_hex_color(hex).unwrap_or_else(|| parse_hex_color(fallback).unwrap())
    };
    let palette = [
        parse_or(&config.green, &defaults.green),     // 0
        parse_or(&config.cyan, &defaults.cyan),        // 1
        parse_or(&config.yellow, &defaults.yellow),    // 2
        parse_or(&config.red, &defaults.red),          // 3
        parse_or(&config.purple, &defaults.purple),    // 4
        parse_or(&config.orange, &defaults.orange),    // 5
        parse_or(&config.pink, &defaults.pink),        // 6
        parse_or(&config.teal, &defaults.teal),        // 7
        parse_or(&config.fg, &defaults.fg),            // 8
        parse_or(&config.muted, &defaults.muted),      // 9
        parse_or(&config.dim, &defaults.dim),          // 10
        parse_or(&config.bright, &defaults.bright),    // 11
    ];
    let _ = PALETTE.set(palette);
}

fn pal(index: usize) -> (u8, u8, u8) {
    PALETTE.get().map(|p| p[index]).unwrap_or_else(|| {
        // Hardcoded defaults if init_colors was never called
        [
            (134, 239, 172), (125, 211, 252), (253, 230, 138), (252, 165, 165),
            (196, 181, 253), (253, 186, 116), (249, 168, 212), (94, 234, 212),
            (200, 200, 224), (107, 107, 141), (68, 68, 102), (238, 238, 245),
        ][index]
    })
}

pub(crate) fn set_use_color(enabled: bool) {
    USE_COLOR.store(enabled, Ordering::Relaxed);
}

pub(crate) fn use_color() -> bool {
    USE_COLOR.load(Ordering::Relaxed)
}

pub(crate) fn detect_tty() {
    IS_TTY.store(std::io::stdout().is_terminal(), Ordering::Relaxed);
}

pub(crate) fn is_tty() -> bool {
    IS_TTY.load(Ordering::Relaxed)
}

fn style_if_enabled<T, F>(value: T, style: F) -> String
where
    T: std::fmt::Display,
    F: FnOnce(String) -> String,
{
    let text = value.to_string();
    if use_color() { style(text) } else { text }
}

// Truecolor palette from design system (configurable via config file)
pub(crate) fn c_green<T: std::fmt::Display>(value: T) -> String {
    let c = pal(0);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_cyan<T: std::fmt::Display>(value: T) -> String {
    let c = pal(1);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_yellow<T: std::fmt::Display>(value: T) -> String {
    let c = pal(2);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_red<T: std::fmt::Display>(value: T) -> String {
    let c = pal(3);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

#[allow(dead_code)]
pub(crate) fn c_purple<T: std::fmt::Display>(value: T) -> String {
    let c = pal(4);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

#[allow(dead_code)]
pub(crate) fn c_orange<T: std::fmt::Display>(value: T) -> String {
    let c = pal(5);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

#[allow(dead_code)]
pub(crate) fn c_pink<T: std::fmt::Display>(value: T) -> String {
    let c = pal(6);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

#[allow(dead_code)]
pub(crate) fn c_teal<T: std::fmt::Display>(value: T) -> String {
    let c = pal(7);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_fg<T: std::fmt::Display>(value: T) -> String {
    let c = pal(8);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_muted<T: std::fmt::Display>(value: T) -> String {
    let c = pal(9);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_dim<T: std::fmt::Display>(value: T) -> String {
    let c = pal(10);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

#[allow(dead_code)]
pub(crate) fn c_bright<T: std::fmt::Display>(value: T) -> String {
    let c = pal(11);
    style_if_enabled(value, |s| s.truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_bold_green<T: std::fmt::Display>(value: T) -> String {
    let c = pal(0);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_bold_yellow<T: std::fmt::Display>(value: T) -> String {
    let c = pal(2);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_bold_red<T: std::fmt::Display>(value: T) -> String {
    let c = pal(3);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_bold_bright<T: std::fmt::Display>(value: T) -> String {
    let c = pal(11);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

#[allow(dead_code)]
pub(crate) fn c_bold_cyan<T: std::fmt::Display>(value: T) -> String {
    let c = pal(1);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_bold_purple<T: std::fmt::Display>(value: T) -> String {
    let c = pal(4);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn c_bold_orange<T: std::fmt::Display>(value: T) -> String {
    let c = pal(5);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

// Badge functions: colored text (terminal can't do bg blocks reliably, use bold colored text)
pub(crate) fn badge_pass<T: std::fmt::Display>(value: T) -> String {
    let c = pal(0);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn badge_warn<T: std::fmt::Display>(value: T) -> String {
    let c = pal(2);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn badge_fail<T: std::fmt::Display>(value: T) -> String {
    let c = pal(3);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

pub(crate) fn badge_info<T: std::fmt::Display>(value: T) -> String {
    let c = pal(1);
    style_if_enabled(value, |s| s.bold().truecolor(c.0, c.1, c.2).to_string())
}

// Score bar per design system: █ filled, ░ empty, 10 chars
// Thresholds: 8-10 green, 5-7 yellow, 0-4 red
pub(crate) fn score_bar(score: u32, max: u32) -> String {
    let bar_len = 10;
    let filled = if max > 0 {
        ((score as f64 / max as f64) * bar_len as f64).round() as usize
    } else {
        0
    };
    let empty = bar_len - filled;
    let bar = format!(
        "{}{}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(empty)
    );
    let score_text = format!("{}/{}", score, max);
    if use_color() {
        let color = if filled >= 8 {
            pal(0) // green
        } else if filled >= 5 {
            pal(2) // yellow
        } else {
            pal(3) // red
        };
        let dim = pal(10);
        format!(
            "{} {}",
            bar.truecolor(color.0, color.1, color.2),
            score_text.truecolor(dim.0, dim.1, dim.2)
        )
    } else {
        format!("{} {}", bar, score_text)
    }
}

pub(crate) fn with_commas(num: u64) -> String {
    let raw = num.to_string();
    let len = raw.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in raw.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub(crate) fn make_spinner(msg: &str, no_color: bool) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    let template = if no_color {
        "{spinner} {msg}"
    } else {
        "{spinner:.cyan} {msg}"
    };
    let style = ProgressStyle::with_template(template)
        .unwrap_or_else(|_| ProgressStyle::default_spinner())
        .tick_strings(&["\u{25D0}", "\u{25D3}", "\u{25D1}", "\u{25D2}"]);
    spinner.set_style(style);
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_message(msg.to_string());
    spinner
}

// Section header: icon + title + horizontal rule filling remaining width
pub(crate) fn format_section_header(icon: &str, title: &str) -> String {
    let term_width = terminal_width();
    let show_icon = is_tty() && !icon.is_empty();
    let icon_width = if show_icon { 2 } else { 0 }; // emoji can be 2-wide
    let prefix_len = if show_icon { icon_width + 1 } else { 0 } + title.len() + 1;
    let rule_len = if term_width > prefix_len + 2 {
        term_width - prefix_len - 1
    } else {
        10
    };
    let rule = "\u{2500}".repeat(rule_len);
    if use_color() {
        if show_icon {
            format!(
                "{} {} {}",
                icon,
                c_bold_bright(title),
                c_dim(rule)
            )
        } else {
            format!(
                "{} {}",
                c_bold_bright(title),
                c_dim(rule)
            )
        }
    } else {
        format!("{} {}", title, rule)
    }
}

pub(crate) fn terminal_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
}

/// Count visible characters, skipping ANSI escape sequences (`\x1b[...m`).
pub(crate) fn visible_len(s: &str) -> usize {
    let mut len = 0usize;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            len += 1;
        }
    }
    len
}

/// Truncate a string to `max` bytes, respecting UTF-8 char boundaries.
/// If truncated, appends "..." so the total visible text ≤ max.
pub(crate) fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max.saturating_sub(3);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Strip C0 control chars (except space), C1 controls, and ANSI escape
/// sequences from server-controlled strings to prevent terminal injection.
pub(crate) fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' || ch == 'H' || ch == 'J' || ch == 'K' || ch == 'A' || ch == 'B' || ch == 'C' || ch == 'D' {
                in_escape = false;
            }
            continue;
        }
        if ch == '\x1b' {
            in_escape = true;
            continue;
        }
        // Allow printable chars and common whitespace (space, tab, newline)
        if ch == ' ' || ch == '\t' || ch == '\n' || (!ch.is_control() && !('\u{0080}'..='\u{009F}').contains(&ch)) {
            out.push(ch);
        }
    }
    out
}

/// Pad a string containing ANSI codes to a target *visible* width.
/// `align`: `'<'` left, `'^'` center, `'>'` right.
pub(crate) fn pad_visible(s: &str, target_width: usize, align: char) -> String {
    let vis = visible_len(s);
    if vis >= target_width {
        return s.to_string();
    }
    let pad = target_width - vis;
    match align {
        '>' => format!("{}{}", " ".repeat(pad), s),
        '^' => {
            let left = pad / 2;
            let right = pad - left;
            format!("{}{}{}", " ".repeat(left), s, " ".repeat(right))
        }
        _ => format!("{}{}", s, " ".repeat(pad)),
    }
}
