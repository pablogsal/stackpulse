//! Sample error statistics for tracking profiling failures.
//!
//! This module provides types for tracking and reporting the various
//! error conditions that can cause sample failures during profiling.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Categories of sample failures for statistics tracking.
///
/// Each variant is a distinct native-unwinding failure reason. Discriminants
/// are the dense range `0..ALL.len()` so they double as indices into the
/// fixed-size counter array in [`SampleErrorStats`]; the `const` assertion
/// below enforces that invariant at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SampleErrorKind {
    /// Failed to capture thread registers
    NativeRegisterCapture = 0,
    /// Failed to read native stack memory
    NativeStackRead = 1,
    /// Native stack copy was too small and unwind was truncated
    NativeStackTruncated = 2,
    /// Framehop error: unwinding did not advance frame/stack pointer
    NativeFramehopDidNotAdvance = 3,
    /// Framehop error: return address became NULL
    NativeFramehopReturnAddressNull = 4,
    /// Framehop error: frame pointer unwinding moved backwards
    NativeFramehopMovedBackwards = 5,
    /// Framehop error: integer overflow during unwind calculations
    NativeFramehopIntegerOverflow = 6,
    /// Perf sample did not include user register state
    NativeUserRegistersMissing = 7,
}

/// Number of error kinds; sizes the counter array. Derived from
/// [`SampleErrorKind::ALL`] so it can never drift from the enum.
const ERROR_KIND_COUNT: usize = SampleErrorKind::ALL.len();
const NATIVE_UNWINDING_CATEGORY: &str = "Native Unwinding";

// Enforce that each variant's discriminant equals its index in `ALL`, so
// `kind as usize` is always a valid, unique slot in the counter array.
const _: () = {
    let mut i = 0;
    while i < SampleErrorKind::ALL.len() {
        assert!(
            SampleErrorKind::ALL[i] as usize == i,
            "SampleErrorKind discriminants must be the dense range 0..ALL.len()",
        );
        i += 1;
    }
};

impl SampleErrorKind {
    /// All variants for iteration, in discriminant order.
    pub const ALL: &'static [SampleErrorKind] = &[
        SampleErrorKind::NativeRegisterCapture,
        SampleErrorKind::NativeStackRead,
        SampleErrorKind::NativeStackTruncated,
        SampleErrorKind::NativeFramehopDidNotAdvance,
        SampleErrorKind::NativeFramehopReturnAddressNull,
        SampleErrorKind::NativeFramehopMovedBackwards,
        SampleErrorKind::NativeFramehopIntegerOverflow,
        SampleErrorKind::NativeUserRegistersMissing,
    ];

    /// Short human-readable description.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::NativeRegisterCapture => "Register capture failed",
            Self::NativeStackRead => "Stack read failed",
            Self::NativeStackTruncated => "Stack copy too small (truncated unwind)",
            Self::NativeFramehopDidNotAdvance => "Framehop: did not advance",
            Self::NativeFramehopReturnAddressNull => "Framehop: return address is NULL",
            Self::NativeFramehopMovedBackwards => "Framehop: frame pointer moved backwards",
            Self::NativeFramehopIntegerOverflow => "Framehop: integer overflow",
            Self::NativeUserRegistersMissing => "User registers missing",
        }
    }
}

impl fmt::Display for SampleErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Minimum interval between debug log emissions for the same error kind.
///
/// Sampling errors fire on a hot loop (~100 Hz × N threads × M frames),
/// so we throttle per-kind to roughly one debug log per second per kind.
/// A new failure of a *different* kind logs immediately.
const SAMPLE_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(1);

/// Atomic counters for sample error statistics.
///
/// Uses a fixed-size array indexed by [`SampleErrorKind`] discriminant
/// for O(1) access with no allocations. Thread-safe via atomic operations.
#[derive(Debug)]
pub struct SampleErrorStats {
    counts: [AtomicU64; ERROR_KIND_COUNT],
    /// Per-kind throttle for debug log emission.
    last_logged: Mutex<[Option<Instant>; ERROR_KIND_COUNT]>,
}

impl SampleErrorStats {
    /// Create new stats with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            last_logged: Mutex::new([None; ERROR_KIND_COUNT]),
        }
    }

    /// Record an error occurrence. O(1), zero-allocation.
    #[inline]
    pub fn record(&self, kind: SampleErrorKind) {
        self.counts[kind as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Record an error occurrence and emit a rate-limited debug log with context.
    ///
    /// `context` is a closure invoked only when the throttle allows a log to fire,
    /// so callers pay the format cost only when the event is emitted. Per-kind
    /// throttling means a new failure of a different kind logs immediately while
    /// repeated failures of the same kind collapse to ~1 log per second.
    pub fn record_with_log(&self, kind: SampleErrorKind, context: impl FnOnce() -> String) {
        self.record(kind);
        if tracing::enabled!(target: "stackpulse::sampler::error", tracing::Level::DEBUG)
            && self.should_log(kind)
        {
            tracing::debug!(
                target: "stackpulse::sampler::error",
                kind = %kind,
                category = NATIVE_UNWINDING_CATEGORY,
                context = %context(),
                "sample error recorded"
            );
        }
    }

    fn should_log(&self, kind: SampleErrorKind) -> bool {
        let mut guard = match self.last_logged.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let slot = &mut guard[kind as usize];
        match *slot {
            Some(prev) if now.duration_since(prev) < SAMPLE_ERROR_LOG_INTERVAL => false,
            _ => {
                *slot = Some(now);
                true
            }
        }
    }

    /// Get count for a specific error kind.
    #[inline]
    pub fn get(&self, kind: SampleErrorKind) -> u64 {
        self.counts[kind as usize].load(Ordering::Relaxed)
    }

    /// Total errors across all categories.
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Check if any errors were recorded.
    pub fn has_errors(&self) -> bool {
        self.counts.iter().any(|c| c.load(Ordering::Relaxed) > 0)
    }

    /// Iterate over all non-zero error counts.
    pub fn iter_nonzero(&self) -> impl Iterator<Item = (SampleErrorKind, u64)> + '_ {
        SampleErrorKind::ALL.iter().filter_map(|&kind| {
            let count = self.get(kind);
            if count > 0 {
                Some((kind, count))
            } else {
                None
            }
        })
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        for counter in &self.counts {
            counter.store(0, Ordering::Relaxed);
        }
        match self.last_logged.lock() {
            Ok(mut guard) => guard.fill(None),
            Err(poisoned) => poisoned.into_inner().fill(None),
        }
    }
}

impl Default for SampleErrorStats {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SampleErrorStats {
    fn clone(&self) -> Self {
        let new = Self::new();
        for (i, counter) in self.counts.iter().enumerate() {
            new.counts[i].store(counter.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        new
    }
}

/// Format error statistics for display.
pub struct ErrorStatsFormatter<'a> {
    stats: &'a SampleErrorStats,
    total_samples: u64,
    successful_samples: u64,
}

impl<'a> ErrorStatsFormatter<'a> {
    /// Create a new formatter.
    pub fn new(stats: &'a SampleErrorStats, total_samples: u64, successful_samples: u64) -> Self {
        Self {
            stats,
            total_samples,
            successful_samples,
        }
    }

    fn progress_bar(percentage: f64) -> String {
        const WIDTH: usize = 20;
        let filled = ((percentage / 100.0) * WIDTH as f64).round() as usize;
        let empty = WIDTH.saturating_sub(filled);
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }
}

impl fmt::Display for ErrorStatsFormatter<'_> {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MIN_DESCRIPTION_WIDTH: usize = 24;
        let total_errors = self.stats.total();
        let entries: Vec<_> = self.stats.iter_nonzero().collect();
        let desc_width = entries
            .iter()
            .map(|(kind, _)| kind.description().len() + 1)
            .max()
            .unwrap_or(MIN_DESCRIPTION_WIDTH)
            .max(MIN_DESCRIPTION_WIDTH);

        writeln!(w, "\nOverview:")?;
        writeln!(
            w,
            "  Total samples:       {}",
            format_number(self.total_samples)
        )?;
        writeln!(
            w,
            "  Successful:          {} ({:.2}%)",
            format_number(self.successful_samples),
            percentage(self.successful_samples, self.total_samples)
        )?;
        writeln!(
            w,
            "  Sample errors:       {} ({:.2}%)",
            format_number(total_errors),
            percentage(total_errors, self.total_samples)
        )?;

        if total_errors == 0 {
            writeln!(w, "\n  No sample errors recorded")?;
            return Ok(());
        }

        writeln!(w, "\n{NATIVE_UNWINDING_CATEGORY}:")?;
        for (kind, count) in &entries {
            let pct_of_errors = percentage(*count, total_errors);
            let pct_of_samples = percentage(*count, self.total_samples);
            let bar = Self::progress_bar(pct_of_errors);

            writeln!(
                w,
                "  {:3} {:<desc_width$} {:>8} ({:>5.1}% of errors, {:>5.2}% of samples)  {}",
                "●",
                format!("{}:", kind.description()),
                format_number(*count),
                pct_of_errors,
                pct_of_samples,
                bar
            )?;
        }

        Ok(())
    }
}

fn percentage(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64 * 100.0
    }
}

/// Format a number with thousand separators.
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminants_match_all_order() {
        for (i, kind) in SampleErrorKind::ALL.iter().enumerate() {
            assert_eq!(
                *kind as usize, i,
                "{kind:?} discriminant must equal its ALL index"
            );
        }
        assert_eq!(SampleErrorKind::ALL.len(), ERROR_KIND_COUNT);
    }

    #[test]
    fn test_new_stats_are_zero() {
        let stats = SampleErrorStats::new();
        for kind in SampleErrorKind::ALL {
            assert_eq!(stats.get(*kind), 0, "{kind:?} should start at 0");
        }
        assert_eq!(stats.total(), 0);
        assert!(!stats.has_errors());
    }

    #[test]
    fn test_record_and_get() {
        let stats = SampleErrorStats::new();

        stats.record(SampleErrorKind::NativeStackRead);
        assert_eq!(stats.get(SampleErrorKind::NativeStackRead), 1);
        assert!(stats.has_errors());

        stats.record(SampleErrorKind::NativeStackRead);
        assert_eq!(stats.get(SampleErrorKind::NativeStackRead), 2);

        stats.record(SampleErrorKind::NativeRegisterCapture);
        assert_eq!(stats.get(SampleErrorKind::NativeRegisterCapture), 1);
        assert_eq!(stats.get(SampleErrorKind::NativeFramehopIntegerOverflow), 0);
        assert_eq!(stats.total(), 3);
    }

    #[test]
    fn test_iter_nonzero_empty() {
        let stats = SampleErrorStats::new();
        let nonzero: Vec<_> = stats.iter_nonzero().collect();
        assert!(nonzero.is_empty());
    }

    #[test]
    fn test_iter_nonzero() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::NativeStackTruncated);
        stats.record(SampleErrorKind::NativeStackTruncated);
        stats.record(SampleErrorKind::NativeFramehopDidNotAdvance);

        let nonzero: Vec<_> = stats.iter_nonzero().collect();
        assert_eq!(nonzero.len(), 2);

        assert!(nonzero.contains(&(SampleErrorKind::NativeStackTruncated, 2)));
        assert!(nonzero.contains(&(SampleErrorKind::NativeFramehopDidNotAdvance, 1)));
    }

    #[test]
    fn test_iter_nonzero_preserves_order() {
        let stats = SampleErrorStats::new();
        // Record the higher-discriminant kind first.
        stats.record(SampleErrorKind::NativeFramehopIntegerOverflow);
        stats.record(SampleErrorKind::NativeRegisterCapture);

        let nonzero: Vec<_> = stats.iter_nonzero().collect();

        assert_eq!(nonzero[0].0, SampleErrorKind::NativeRegisterCapture);
        assert_eq!(nonzero[1].0, SampleErrorKind::NativeFramehopIntegerOverflow);
    }

    #[test]
    fn test_reset() {
        let stats = SampleErrorStats::new();

        for kind in SampleErrorKind::ALL {
            stats.record(*kind);
            stats.record(*kind);
        }

        assert!(stats.has_errors());
        assert_eq!(stats.total(), (SampleErrorKind::ALL.len() * 2) as u64);

        stats.reset();

        assert!(!stats.has_errors());
        assert_eq!(stats.total(), 0);
        for kind in SampleErrorKind::ALL {
            assert_eq!(stats.get(*kind), 0);
        }
    }

    #[test]
    fn test_clone() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::NativeStackRead);
        stats.record(SampleErrorKind::NativeRegisterCapture);

        let cloned = stats.clone();

        assert_eq!(cloned.get(SampleErrorKind::NativeStackRead), 1);
        assert_eq!(cloned.get(SampleErrorKind::NativeRegisterCapture), 1);
        assert_eq!(cloned.total(), 2);
    }

    #[test]
    fn test_clone_independence() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::NativeStackRead);

        let cloned = stats.clone();

        stats.record(SampleErrorKind::NativeStackRead);
        stats.record(SampleErrorKind::NativeRegisterCapture);

        assert_eq!(cloned.get(SampleErrorKind::NativeStackRead), 1);
        assert_eq!(cloned.get(SampleErrorKind::NativeRegisterCapture), 0);
        assert_eq!(cloned.total(), 1);

        assert_eq!(stats.get(SampleErrorKind::NativeStackRead), 2);
        assert_eq!(stats.get(SampleErrorKind::NativeRegisterCapture), 1);
        assert_eq!(stats.total(), 3);
    }

    #[test]
    fn test_formatter_no_errors() {
        let stats = SampleErrorStats::new();
        let formatter = ErrorStatsFormatter::new(&stats, 1000, 1000);

        let output = formatter.to_string();

        assert_eq!(
            output,
            "\nOverview:\n  Total samples:       1,000\n  Successful:          1,000 (100.00%)\n  Sample errors:       0 (0.00%)\n\n  No sample errors recorded\n"
        );
    }

    #[test]
    fn test_formatter_with_errors() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::NativeStackRead);
        stats.record(SampleErrorKind::NativeStackRead);
        stats.record(SampleErrorKind::NativeRegisterCapture);
        stats.record(SampleErrorKind::NativeFramehopMovedBackwards);

        let formatter = ErrorStatsFormatter::new(&stats, 100, 96);

        let output = formatter.to_string();

        assert_eq!(
            output,
            concat!(
                "\nOverview:\n",
                "  Total samples:       100\n",
                "  Successful:          96 (96.00%)\n",
                "  Sample errors:       4 (4.00%)\n",
                "\nNative Unwinding:\n",
                "  ●   Register capture failed:                        1 ( 25.0% of errors,  1.00% of samples)  █████░░░░░░░░░░░░░░░\n",
                "  ●   Stack read failed:                              2 ( 50.0% of errors,  2.00% of samples)  ██████████░░░░░░░░░░\n",
                "  ●   Framehop: frame pointer moved backwards:        1 ( 25.0% of errors,  1.00% of samples)  █████░░░░░░░░░░░░░░░\n",
            )
        );
    }

    #[test]
    fn test_concurrent_recording() {
        use std::sync::Arc;
        use std::thread;

        let stats = Arc::new(SampleErrorStats::new());
        let num_threads: u64 = 4;
        let records_per_thread: u64 = 1000;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let stats = Arc::clone(&stats);
                thread::spawn(move || {
                    for _ in 0..records_per_thread {
                        stats.record(SampleErrorKind::NativeStackRead);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            stats.get(SampleErrorKind::NativeStackRead),
            num_threads * records_per_thread
        );
    }
}
