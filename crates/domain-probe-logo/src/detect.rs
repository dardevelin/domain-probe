use std::io::IsTerminal;

/// Check if the terminal supports truecolor (24-bit) ANSI escapes.
pub fn supports_truecolor() -> bool {
    if !std::io::stdout().is_terminal() {
        return false;
    }
    let ct = std::env::var("COLORTERM").unwrap_or_default();
    if ct == "truecolor" || ct == "24bit" {
        return true;
    }
    let tp = std::env::var("TERM_PROGRAM").unwrap_or_default();
    matches!(
        tp.as_str(),
        "Kitty" | "WezTerm" | "ghostty" | "iTerm.app" | "vscode" | "Hyper" | "Alacritty"
    )
}

/// Check if stdout is a TTY.
pub fn is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Get terminal width, defaulting to 80.
pub fn term_width() -> usize {
    crossterm::terminal::size().map(|(w, _)| w as usize).unwrap_or(80)
}
