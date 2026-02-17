//! Animation timeline — chainable, cancellable, time-budgeted animation steps.
//!
//! Each step is constrained to a **time budget**. The renderer samples the
//! animation at whatever `t` corresponds to the current wall-clock time,
//! skipping frames as needed to stay on schedule. If the machine is fast
//! enough, every frame renders smoothly; if it's slow, frames are dropped
//! rather than falling behind.
//!
//! For open-ended steps (like "spin until download completes"), the animation
//! loops until a [`Signal`] fires, then the timeline advances.
//!
//! # Example
//!
//! ```no_run
//! use domain_probe_logo::timeline::{Timeline, Signal};
//! use domain_probe_logo::logo;
//! use std::time::Duration;
//!
//! let done = Signal::new();
//! let done_clone = done.clone();
//!
//! std::thread::spawn(move || {
//!     std::thread::sleep(Duration::from_secs(2));
//!     done_clone.fire();
//! });
//!
//! Timeline::new(logo::ROWS)
//!     .spin_until(done)                          // spin until signal
//!     .hold(Duration::from_millis(300))           // brief pause
//!     .unfold(Duration::from_millis(800))         // unfold in 800ms
//!     .run();
//! ```

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use crossterm::{cursor, terminal, execute, queue};

use crate::logo::{self, ROWS};
use crate::frame::colored_bar;
use crate::color::*;

/// Minimum time between frame renders (~60fps cap).
const MIN_FRAME_INTERVAL: Duration = Duration::from_millis(16);

/// A signal that can be fired from another thread to advance the timeline.
#[derive(Clone)]
pub struct Signal {
    fired: Arc<AtomicBool>,
}

impl Signal {
    pub fn new() -> Self {
        Self { fired: Arc::new(AtomicBool::new(false)) }
    }

    /// Fire the signal, causing any step waiting on it to complete.
    pub fn fire(&self) {
        self.fired.store(true, Ordering::Release);
    }

    /// Check if the signal has been fired.
    pub fn is_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }
}

impl Default for Signal {
    fn default() -> Self { Self::new() }
}

/// When a step should end.
enum StepEnd {
    /// Run for a fixed duration.
    Timed(Duration),
    /// Run until a signal fires (with an optional max duration).
    Signal { signal: Signal, max: Option<Duration> },
}

impl StepEnd {
    fn is_done(&self, elapsed: Duration) -> bool {
        match self {
            Self::Timed(d) => elapsed >= *d,
            Self::Signal { signal, max } => {
                if signal.is_fired() { return true; }
                if let Some(m) = max
                    && elapsed >= *m { return true; }
                false
            }
        }
    }
}

/// What to render during a step.
enum StepKind {
    /// Y-axis spin. Loops continuously; one full rotation per `cycle` duration.
    Spin { cycle: Duration },
    /// Hold on the static front-face logo.
    Hold,
    /// Unfold into separator bar over its time budget.
    Unfold,
}

struct StepDef {
    kind: StepKind,
    end: StepEnd,
}

/// A chainable, time-budgeted animation timeline.
pub struct Timeline {
    steps: Vec<StepDef>,
    rows: usize,
}

impl Timeline {
    /// Create a new timeline. `rows` is the vertical height reserved.
    pub fn new(rows: usize) -> Self {
        Self { steps: Vec::new(), rows }
    }

    /// Spin for a fixed duration.
    /// `cycle` controls how long one full rotation takes (default 1.4s).
    pub fn spin(mut self, duration: Duration) -> Self {
        self.steps.push(StepDef {
            kind: StepKind::Spin { cycle: Duration::from_millis(1400) },
            end: StepEnd::Timed(duration),
        });
        self
    }

    /// Spin with a custom cycle speed for a fixed duration.
    pub fn spin_with_cycle(mut self, duration: Duration, cycle: Duration) -> Self {
        self.steps.push(StepDef {
            kind: StepKind::Spin { cycle },
            end: StepEnd::Timed(duration),
        });
        self
    }

    /// Spin until a signal fires (indefinite).
    pub fn spin_until(mut self, signal: Signal) -> Self {
        self.steps.push(StepDef {
            kind: StepKind::Spin { cycle: Duration::from_millis(1400) },
            end: StepEnd::Signal { signal, max: None },
        });
        self
    }

    /// Spin until a signal fires, capped at `max` duration.
    pub fn spin_until_or(mut self, signal: Signal, max: Duration) -> Self {
        self.steps.push(StepDef {
            kind: StepKind::Spin { cycle: Duration::from_millis(1400) },
            end: StepEnd::Signal { signal, max: Some(max) },
        });
        self
    }

    /// Hold the static front-face logo for a duration.
    pub fn hold(mut self, duration: Duration) -> Self {
        self.steps.push(StepDef {
            kind: StepKind::Hold,
            end: StepEnd::Timed(duration),
        });
        self
    }

    /// Unfold the diamond into a separator bar within a time budget.
    pub fn unfold(mut self, duration: Duration) -> Self {
        self.steps.push(StepDef {
            kind: StepKind::Unfold,
            end: StepEnd::Timed(duration),
        });
        self
    }

    /// Run the full timeline, rendering to stdout.
    pub fn run(self) {
        let mut stdout = io::stdout();
        let height = self.rows as u16;

        execute!(stdout, cursor::Hide).ok();
        for _ in 0..height { println!(); }

        for step in &self.steps {
            let start = Instant::now();

            match &step.kind {
                StepKind::Spin { cycle } => {
                    let cycle_secs = cycle.as_secs_f32();
                    let frame_count = 24usize;
                    let frames = logo::spin_frames(frame_count);

                    loop {
                        if step.end.is_done(start.elapsed()) { break; }
                        let elapsed = start.elapsed().as_secs_f32();
                        let cycle_pos = (elapsed % cycle_secs) / cycle_secs;
                        let idx = (cycle_pos * frame_count as f32) as usize % frame_count;

                        let frame = &frames[idx];
                        draw_frame(&mut stdout, height, &frame.lines);
                        sleep_until_next_frame(start);
                    }

                    // Settle to front face so the next step starts clean
                    let front = logo::build_spin_frame(0.0);
                    draw_frame(&mut stdout, height, &front.lines);
                }

                StepKind::Hold => {
                    let front = logo::build_spin_frame(0.0);
                    draw_frame(&mut stdout, height, &front.lines);

                    loop {
                        if step.end.is_done(start.elapsed()) { break; }
                        std::thread::sleep(MIN_FRAME_INTERVAL);
                    }
                }

                StepKind::Unfold => {
                    let tw = crate::detect::term_width();
                    let pieces = logo::unfold_pieces(tw);
                    let budget = match &step.end {
                        StepEnd::Timed(d) => d.as_secs_f32(),
                        _ => 1.5, // fallback
                    };

                    loop {
                        let elapsed = start.elapsed().as_secs_f32();
                        if elapsed >= budget { break; }

                        // Map wall-clock → normalized t (0.0–1.0)
                        let t = (elapsed / budget).min(1.0);
                        let lines = crate::frame::render_pieces::<ROWS>(&pieces, t, tw);
                        draw_frame(&mut stdout, height, &lines);
                        sleep_until_next_frame(start);
                    }

                    // Final frame: solid bar, then collapse to 1 row
                    let bar = colored_bar(&[PURPLE, CYAN, TEAL, GREEN, TEAL], tw);
                    let mut final_lines: [String; ROWS] = Default::default();
                    final_lines[2] = bar;
                    draw_frame(&mut stdout, height, &final_lines);

                    // Collapse vertical space
                    queue!(stdout, cursor::MoveUp(height)).ok();
                    queue!(stdout, terminal::Clear(terminal::ClearType::CurrentLine)).ok();
                    writeln!(stdout, "{}", final_lines[2]).ok();
                    for _ in 1..ROWS {
                        queue!(stdout, terminal::Clear(terminal::ClearType::CurrentLine)).ok();
                        writeln!(stdout).ok();
                    }
                    queue!(stdout, cursor::MoveUp(height - 1)).ok();
                    stdout.flush().ok();
                }
            }
        }

        execute!(stdout, cursor::Show).ok();
    }
}

/// Draw a set of lines into the reserved vertical space.
fn draw_frame(stdout: &mut io::Stdout, height: u16, lines: &[String]) {
    queue!(stdout, cursor::MoveUp(height)).ok();
    for line in lines.iter() {
        queue!(stdout, terminal::Clear(terminal::ClearType::CurrentLine)).ok();
        writeln!(stdout, "{}", line).ok();
    }
    // Clear any remaining rows
    for _ in lines.len()..(height as usize) {
        queue!(stdout, terminal::Clear(terminal::ClearType::CurrentLine)).ok();
        writeln!(stdout).ok();
    }
    stdout.flush().ok();
}

/// Sleep until the next frame boundary (~60fps), accounting for render time.
fn sleep_until_next_frame(step_start: Instant) {
    let elapsed = step_start.elapsed();
    let interval_ns = MIN_FRAME_INTERVAL.as_nanos();
    let next_ns = ((elapsed.as_nanos() / interval_ns) + 1) * interval_ns;
    let next = Duration::from_nanos(next_ns as u64);
    let remaining = next.saturating_sub(elapsed);
    if !remaining.is_zero() {
        std::thread::sleep(remaining);
    }
}
