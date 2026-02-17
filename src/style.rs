use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static USE_COLOR: AtomicBool = AtomicBool::new(true);
static IS_TTY: AtomicBool = AtomicBool::new(true);

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

// Truecolor palette from design system
pub(crate) fn c_green<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(134, 239, 172).to_string())
}

pub(crate) fn c_cyan<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(125, 211, 252).to_string())
}

pub(crate) fn c_yellow<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(253, 230, 138).to_string())
}

pub(crate) fn c_red<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(252, 165, 165).to_string())
}

pub(crate) fn c_purple<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(196, 181, 253).to_string())
}

pub(crate) fn c_orange<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(253, 186, 116).to_string())
}

pub(crate) fn c_pink<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(249, 168, 212).to_string())
}

pub(crate) fn c_teal<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(94, 234, 212).to_string())
}

pub(crate) fn c_fg<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(200, 200, 224).to_string())
}

pub(crate) fn c_muted<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(107, 107, 141).to_string())
}

pub(crate) fn c_dim<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(68, 68, 102).to_string())
}

pub(crate) fn c_bright<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.truecolor(238, 238, 245).to_string())
}

pub(crate) fn c_bold_green<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(134, 239, 172).to_string())
}

pub(crate) fn c_bold_yellow<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(253, 230, 138).to_string())
}

pub(crate) fn c_bold_red<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(252, 165, 165).to_string())
}

pub(crate) fn c_bold_bright<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(238, 238, 245).to_string())
}

pub(crate) fn c_bold_cyan<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(125, 211, 252).to_string())
}

pub(crate) fn c_bold_purple<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(196, 181, 253).to_string())
}

pub(crate) fn c_bold_orange<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(253, 186, 116).to_string())
}

// Badge functions: colored text (terminal can't do bg blocks reliably, use bold colored text)
pub(crate) fn badge_pass<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(134, 239, 172).to_string())
}

pub(crate) fn badge_warn<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(253, 230, 138).to_string())
}

pub(crate) fn badge_fail<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(252, 165, 165).to_string())
}

pub(crate) fn badge_info<T: std::fmt::Display>(value: T) -> String {
    style_if_enabled(value, |s| s.bold().truecolor(125, 211, 252).to_string())
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
            (134, 239, 172) // green
        } else if filled >= 5 {
            (253, 230, 138) // yellow
        } else {
            (252, 165, 165) // red
        };
        format!(
            "{} {}",
            bar.truecolor(color.0, color.1, color.2),
            score_text.truecolor(68, 68, 102)
        )
    } else {
        format!("{} {}", bar, score_text)
    }
}

pub(crate) fn with_commas(num: u64) -> String {
    let raw = num.to_string();
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    for (i, ch) in raw.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
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
