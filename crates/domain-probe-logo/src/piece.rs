use crate::color::Rgb;
use crate::easing::{lerp, ease_out};

/// An animated character piece that travels from a start position
/// to an end position over a time window, with glyph transitions.
///
/// Time values (`t_start`, `t_end`) are normalized 0.0–1.0 within
/// the overall animation timeline.
#[derive(Clone)]
pub struct Piece {
    pub start_col: f32,
    pub start_row: f32,
    pub end_col: f32,
    pub end_row: f32,
    pub start_glyph: char,
    pub end_glyph: char,
    pub color: Rgb,
    pub t_start: f32,
    pub t_end: f32,
}

impl Piece {
    /// Sample this piece at time `t`, returning (col, row, glyph).
    ///
    /// Before `t_start` the piece is at its start position.
    /// After `t_end` the piece is at its end position.
    /// In between, position is ease-out interpolated and the glyph
    /// transitions through a mid-glyph (e.g. ╱ → / → ━).
    pub fn at(&self, t: f32) -> (f32, f32, char) {
        if t <= self.t_start {
            return (self.start_col, self.start_row, self.start_glyph);
        }
        if t >= self.t_end {
            return (self.end_col, self.end_row, self.end_glyph);
        }
        let local = (t - self.t_start) / (self.t_end - self.t_start);
        let eased = ease_out(local);
        let col = lerp(self.start_col, self.end_col, eased);
        let row = lerp(self.start_row, self.end_row, eased);
        let glyph = if local < 0.3 {
            self.start_glyph
        } else if local < 0.6 {
            mid_glyph(self.start_glyph, self.end_glyph)
        } else {
            self.end_glyph
        };
        (col, row, glyph)
    }
}

/// Pick a transitional glyph between start and end.
/// ╱ → / → ━, ╲ → \ → ━, etc.
fn mid_glyph(start: char, end: char) -> char {
    match start {
        '╱' => '/',
        '╲' => '\\',
        _ => end,
    }
}
