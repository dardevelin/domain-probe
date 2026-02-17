/// Linear interpolation.
pub fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

/// Quadratic ease-out (decelerates).
pub fn ease_out(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(2)
}

/// Quadratic ease-in (accelerates).
pub fn ease_in(t: f32) -> f32 {
    t * t
}

/// Quadratic ease-in-out.
pub fn ease_in_out(t: f32) -> f32 {
    if t < 0.5 {
        2.0 * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(2) / 2.0
    }
}
