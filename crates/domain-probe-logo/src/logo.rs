//! Domain-probe diamond logo: static rendering, spin animation, and unfold transition.

use crate::color::*;
use crate::easing::lerp;
use crate::frame::{Frame, pad_to, colored_bar, render_pieces};
use crate::piece::Piece;

/// Number of rows the diamond occupies.
pub const ROWS: usize = 5;

/// Center column of the diamond.
const CENTER: usize = 4;

/// Column where "domain-probe" text is anchored.
const TEXT_COL: usize = 11;

// ── Static rendering ─────────────────────────────────────

/// Print the logo as plain ASCII (pipe-safe, no color).
pub fn ascii() {
    println!("  /\\");
    println!(" /  \\");
    println!("<    > domain-probe");
    println!(" \\  /");
    println!("  \\/");
}

/// Print the logo with truecolor ANSI escapes.
pub fn truecolor() {
    let frame = build_spin_frame(0.0);
    for line in &frame.lines {
        println!("{}", line);
    }
}

/// Print the logo, auto-detecting terminal capabilities.
pub fn print() {
    if crate::detect::supports_truecolor() {
        truecolor();
    } else {
        ascii();
    }
}

// ── Spin frames ──────────────────────────────────────────

/// Build a single spin frame at rotation angle θ (radians).
///
/// θ=0 → front face, θ=π → back face.
/// The diamond compresses horizontally by |cos(θ)| and the
/// back face shows reversed/dimmed colors.
pub fn build_spin_frame(theta: f32) -> Frame<ROWS> {
    let cos_t = theta.cos();
    let scale = cos_t.abs();
    let is_back = cos_t < 0.0;
    let fade = if is_back { 0.25 + (1.0 - scale) * 0.35 } else { (1.0 - scale) * 0.3 };

    let (c_top, c_eq_l, c_eq_m, c_eq_r, c_bot) = if is_back {
        (GREEN, GREEN, TEAL, PURPLE, CYAN)
    } else {
        (CYAN, PURPLE, TEAL, GREEN, GREEN)
    };

    let fc = |col: Rgb| -> String { ansi(dim(col, fade)) };

    let hw: Vec<usize> = [1.0_f32, 2.0, 3.0, 2.0, 1.0]
        .iter()
        .map(|w| (w * scale).round().max(0.0) as usize)
        .collect();

    let mut lines: [String; ROWS] = Default::default();

    // Edge-on
    if hw.iter().all(|&w| w == 0) {
        let sp = " ".repeat(CENTER);
        let fe = fc(if is_back { TEAL } else { CYAN });
        lines[0] = format!("{sp}{fe}│{RESET}");
        lines[1] = format!("{sp}{fe}┃{RESET}");
        let dp = format!("{sp}{fe}◆{RESET}");
        lines[2] = format!("{} {}domain{}-probe{}",
            pad_to(&dp, TEXT_COL), ansi(MUTED), ansi(BRIGHT), RESET);
        lines[3] = format!("{sp}{fe}┃{RESET}");
        lines[4] = format!("{sp}{fe}│{RESET}");
        return Frame { lines };
    }

    // Row 0: top apex
    {
        let h = hw[0];
        let top_point = if is_back { '▾' } else { '▴' };
        if h >= 1 {
            let sp = " ".repeat(CENTER.saturating_sub(h));
            lines[0] = format!("{sp}{}╱╲{}", fc(c_top), RESET);
        } else {
            let sp = " ".repeat(CENTER);
            lines[0] = format!("{sp}{}{}{}",  fc(c_top), top_point, RESET);
        }
    }

    // Row 1: upper body
    {
        let h = hw[1];
        let sp = " ".repeat(CENTER.saturating_sub(h));
        match h {
            0 => { lines[1] = format!("{}{}│{}", " ".repeat(CENTER), fc(c_top), RESET); }
            1 => { lines[1] = format!("{sp}{}╱╲{}", fc(c_top), RESET); }
            _ => { lines[1] = format!("{sp}{}╱{}╲{}", fc(c_top), " ".repeat(2*h-2), RESET); }
        }
    }

    // Row 2: equator + text
    {
        let h = hw[2];
        let sp = " ".repeat(CENTER.saturating_sub(h));
        let dp = match h {
            0 => format!("{}{}◆{}", " ".repeat(CENTER), fc(c_eq_l), RESET),
            1 => format!("{sp}{}◇{}◇{}", fc(c_eq_l), fc(c_eq_r), RESET),
            _ => {
                let bar = "━".repeat(2*h-2);
                format!("{sp}{}◇{}{}{}◇{}", fc(c_eq_l), fc(c_eq_m), bar, fc(c_eq_r), RESET)
            }
        };
        lines[2] = format!("{} {}domain{}-probe{}",
            pad_to(&dp, TEXT_COL), ansi(MUTED), ansi(BRIGHT), RESET);
    }

    // Row 3: lower body
    {
        let h = hw[3];
        let sp = " ".repeat(CENTER.saturating_sub(h));
        let bot_point = if is_back { '▴' } else { '▾' };
        match h {
            0 => { lines[3] = format!("{}{}{}{}",  " ".repeat(CENTER), fc(c_bot), bot_point, RESET); }
            1 => { lines[3] = format!("{sp}{}╲╱{}", fc(c_bot), RESET); }
            _ => { lines[3] = format!("{sp}{}╲{}╱{}", fc(c_bot), " ".repeat(2*h-2), RESET); }
        }
    }

    // Row 4: bottom apex
    {
        let h = hw[4];
        let bot_point = if is_back { '▴' } else { '▾' };
        if h >= 1 && hw[3] > 1 {
            let sp = " ".repeat(CENTER.saturating_sub(h));
            lines[4] = format!("{sp}{}╲╱{}", fc(c_bot), RESET);
        } else {
            lines[4] = format!("{}{}{}{}",  " ".repeat(CENTER), fc(c_bot), bot_point, RESET);
        }
    }

    Frame { lines }
}

/// Generate `count` spin frames for one full Y-axis rotation.
pub fn spin_frames(count: usize) -> Vec<Frame<ROWS>> {
    (0..count)
        .map(|i| build_spin_frame((i as f32 / count as f32) * 2.0 * std::f32::consts::PI))
        .collect()
}

// ── Unfold transition ────────────────────────────────────

/// Generate the unfold animation: the diamond deconstructs into
/// a full-width colored separator bar.
///
/// Characters peel off the diamond rightward, dropping to the
/// equator row and flattening into ━ segments. Top pieces go
/// first, then bottom, then the equator stretches to fill.
/// Build the set of animated pieces for the unfold transition.
///
/// Returns pieces with normalized time (0.0–1.0). The caller
/// can sample at any `t` via [`render_pieces`] to get the frame
/// at that point — enabling time-budgeted rendering.
pub fn unfold_pieces(term_width: usize) -> Vec<Piece> {
    let c0 = CENTER as f32;
    let tw = term_width as f32;
    let mut pieces: Vec<Piece> = Vec::new();

    // Equator bar pieces (stretch last)
    pieces.push(Piece {
        start_col: c0 - 3.0, start_row: 2.0,
        end_col: 0.0, end_row: 2.0,
        start_glyph: '◇', end_glyph: '━',
        color: PURPLE,
        t_start: 0.70, t_end: 0.95,
    });
    for j in 0..4 {
        pieces.push(Piece {
            start_col: c0 - 2.0 + j as f32, start_row: 2.0,
            end_col: lerp(c0 - 2.0, tw * 0.45, (j as f32 + 0.5) / 4.0), end_row: 2.0,
            start_glyph: '━', end_glyph: '━',
            color: TEAL,
            t_start: 0.75, t_end: 0.95,
        });
    }
    pieces.push(Piece {
        start_col: c0 + 2.0, start_row: 2.0,
        end_col: tw * 0.55, end_row: 2.0,
        start_glyph: '◇', end_glyph: '━',
        color: GREEN,
        t_start: 0.70, t_end: 0.95,
    });

    // Top apex → rightward
    pieces.push(Piece {
        start_col: c0 - 1.0, start_row: 0.0,
        end_col: tw * 0.60, end_row: 2.0,
        start_glyph: '╱', end_glyph: '━',
        color: CYAN,
        t_start: 0.0, t_end: 0.22,
    });
    pieces.push(Piece {
        start_col: c0, start_row: 0.0,
        end_col: tw * 0.65, end_row: 2.0,
        start_glyph: '╲', end_glyph: '━',
        color: CYAN,
        t_start: 0.03, t_end: 0.25,
    });

    // Upper body → rightward
    pieces.push(Piece {
        start_col: c0 - 2.0, start_row: 1.0,
        end_col: tw * 0.70, end_row: 2.0,
        start_glyph: '╱', end_glyph: '━',
        color: CYAN,
        t_start: 0.15, t_end: 0.37,
    });
    pieces.push(Piece {
        start_col: c0 + 1.0, start_row: 1.0,
        end_col: tw * 0.75, end_row: 2.0,
        start_glyph: '╲', end_glyph: '━',
        color: CYAN,
        t_start: 0.18, t_end: 0.40,
    });

    // Bottom apex → rightward
    pieces.push(Piece {
        start_col: c0 - 1.0, start_row: 4.0,
        end_col: tw * 0.80, end_row: 2.0,
        start_glyph: '╲', end_glyph: '━',
        color: GREEN,
        t_start: 0.30, t_end: 0.52,
    });
    pieces.push(Piece {
        start_col: c0, start_row: 4.0,
        end_col: tw * 0.85, end_row: 2.0,
        start_glyph: '╱', end_glyph: '━',
        color: GREEN,
        t_start: 0.33, t_end: 0.55,
    });

    // Lower body → rightward
    pieces.push(Piece {
        start_col: c0 - 2.0, start_row: 3.0,
        end_col: tw * 0.90, end_row: 2.0,
        start_glyph: '╲', end_glyph: '━',
        color: GREEN,
        t_start: 0.45, t_end: 0.67,
    });
    pieces.push(Piece {
        start_col: c0 + 1.0, start_row: 3.0,
        end_col: tw * 0.95, end_row: 2.0,
        start_glyph: '╱', end_glyph: '━',
        color: GREEN,
        t_start: 0.48, t_end: 0.70,
    });

    pieces
}

/// Pre-render unfold frames (for `--frames` debug dump).
pub fn unfold_frames(count: usize, term_width: usize) -> Vec<[String; ROWS]> {
    let pieces = unfold_pieces(term_width);
    let mut frames: Vec<[String; ROWS]> = Vec::new();
    for i in 0..=count {
        let t = i as f32 / count as f32;
        frames.push(render_pieces::<ROWS>(&pieces, t, term_width));
    }
    let mut final_frame: [String; ROWS] = Default::default();
    final_frame[2] = colored_bar(&[PURPLE, CYAN, TEAL, GREEN, TEAL], term_width);
    frames.push(final_frame);
    frames
}

// The old `animate()` function has been replaced by `Timeline`.
// Use `Timeline::new(ROWS).spin(...).hold(...).unfold(...).run()` instead.
