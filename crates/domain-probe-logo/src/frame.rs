use crate::color::{Rgb, ansi, RESET};
use crate::piece::Piece;

/// A fixed-height frame of pre-rendered terminal lines.
pub struct Frame<const N: usize> {
    pub lines: [String; N],
}

/// Visible length of a string (ignoring ANSI escape sequences).
pub fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_esc = false;
    for ch in s.chars() {
        if ch == '\x1b' { in_esc = true; continue; }
        if in_esc { if ch == 'm' { in_esc = false; } continue; }
        len += 1;
    }
    len
}

/// Pad a string (accounting for ANSI escapes) to a target visible width.
pub fn pad_to(s: &str, target: usize) -> String {
    let vl = visible_len(s);
    if vl >= target { s.to_string() }
    else { format!("{}{}", s, " ".repeat(target - vl)) }
}

/// Render a set of animated pieces into a fixed-height grid at time `t`.
///
/// Each piece is sampled at `t` to get its (col, row, glyph), then
/// placed on a `rows × width` character grid. The result is an array
/// of ANSI-colored strings, one per row.
pub fn render_pieces<const N: usize>(pieces: &[Piece], t: f32, width: usize) -> [String; N] {
    let mut grid: Vec<Vec<Option<(char, Rgb)>>> = vec![vec![None; width]; N];

    for p in pieces {
        let (col, row, glyph) = p.at(t);
        let r = row.round() as isize;
        let c_pos = col.round() as isize;
        if r >= 0 && r < N as isize && c_pos >= 0 && c_pos < width as isize {
            grid[r as usize][c_pos as usize] = Some((glyph, p.color));
        }
    }

    let mut lines: [String; N] = std::array::from_fn(|_| String::new());
    for r in 0..N {
        let mut s = String::new();
        let mut last_col = 0;
        for col in 0..width {
            if let Some((glyph, color)) = grid[r][col] {
                if col > last_col {
                    s.push_str(&" ".repeat(col - last_col));
                }
                s.push_str(&format!("{}{}{}", ansi(color), glyph, RESET));
                last_col = col + 1;
            }
        }
        lines[r] = s;
    }
    lines
}

/// Build a solid colored bar across `width` columns, split into
/// equal segments of the given colors.
pub fn colored_bar(colors: &[Rgb], width: usize) -> String {
    let seg = width / colors.len();
    let rem = width % colors.len();
    let mut bar = String::new();
    for (i, &col) in colors.iter().enumerate() {
        let len = seg + if i < rem { 1 } else { 0 };
        bar.push_str(&format!("{}{}", ansi(col), "━".repeat(len)));
    }
    bar.push_str(RESET);
    bar
}
