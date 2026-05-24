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
/// Each variant represents a distinct failure reason that can occur
/// during stack sampling. These are designed to be distinguishable
/// for debugging and optimization purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SampleErrorKind {
    // Stack Chunks (0-9)
    /// Stack chunk size is 0 or exceeds 64MB limit
    StackChunkInvalidSize = 0,
    /// Failed to read stack chunk from remote memory
    StackChunkReadFailure = 1,
    /// Stack chunk list cycle detected (corrupted remote memory)
    StackChunkCycle = 2,
    /// Too many stack chunks (possible corrupted chunk list)
    StackChunkTooMany = 3,

    // Frame Parsing (10-19)
    /// Unknown frame owner type
    FrameUnknownOwner = 10,
    /// Failed to parse the initial frame in a chain (generic fallback)
    FrameParseFailure = 11,
    /// Initial frame had null code object address
    FrameInitialNullCode = 12,
    /// Initial frame was owned by a frame object (e.g. sys._getframe() keeping it alive)
    FrameInitialFrameObjectOwned = 13,
    /// Initial frame had an invalid owner value (likely memory corruption)
    FrameInitialGarbageOwner = 14,

    // Frame Chain (20-29)
    /// Too many frames in chain (>1024, possible infinite loop)
    FrameChainTooMany = 20,
    /// Broken frame chain (expected vs actual address mismatch)
    FrameChainBroken = 21,
    /// Incomplete walk (didn't reach base frame)
    FrameChainIncomplete = 22,

    // Code Objects (30-39)
    /// Failed to read code object from remote memory
    CodeObjectReadFailure = 30,
    /// NULL TLBC pointer (free-threaded Python)
    CodeObjectTlbcNull = 31,
    /// Invalid TLBC array size
    CodeObjectTlbcInvalidSize = 32,

    // Thread State (40-49)
    /// Failed to read thread state from remote memory
    ThreadStateReadFailure = 40,

    // Native Unwinding (50-59)
    /// Failed to capture thread registers
    NativeRegisterCapture = 50,
    /// Failed to read native stack memory
    NativeStackRead = 51,
    /// Native stack copy was too small and unwind was truncated
    NativeStackTruncated = 52,
    /// Framehop error: unwinding did not advance frame/stack pointer
    NativeFramehopDidNotAdvance = 53,
    /// Framehop error: return address became NULL
    NativeFramehopReturnAddressNull = 54,
    /// Framehop error: frame pointer unwinding moved backwards
    NativeFramehopMovedBackwards = 55,
    /// Framehop error: integer overflow during unwind calculations
    NativeFramehopIntegerOverflow = 56,

    // Stack Merging (60-69)
    /// More Python frame groups than native eval frames during merge
    MergeTooManyPythonFrames = 60,
    /// Fewer Python frame groups than native eval frames during merge
    MergeTooFewPythonFrames = 61,

    // Thread List (70-79)
    /// Thread list cycle detected (corrupted remote memory)
    ThreadListCycle = 70,
    /// Too many threads (>4096, possible corrupted thread list)
    ThreadListTooMany = 71,
}

/// Number of error kinds (must match the last discriminant + 1)
const ERROR_KIND_COUNT: usize = 72;

impl SampleErrorKind {
    /// All variants for iteration, ordered by category for grouped display.
    pub const ALL: &'static [SampleErrorKind] = &[
        SampleErrorKind::StackChunkInvalidSize,
        SampleErrorKind::StackChunkReadFailure,
        SampleErrorKind::StackChunkCycle,
        SampleErrorKind::StackChunkTooMany,
        SampleErrorKind::FrameUnknownOwner,
        SampleErrorKind::FrameParseFailure,
        SampleErrorKind::FrameInitialNullCode,
        SampleErrorKind::FrameInitialFrameObjectOwned,
        SampleErrorKind::FrameInitialGarbageOwner,
        SampleErrorKind::FrameChainTooMany,
        SampleErrorKind::FrameChainBroken,
        SampleErrorKind::FrameChainIncomplete,
        SampleErrorKind::CodeObjectReadFailure,
        SampleErrorKind::CodeObjectTlbcNull,
        SampleErrorKind::CodeObjectTlbcInvalidSize,
        SampleErrorKind::ThreadStateReadFailure,
        SampleErrorKind::NativeRegisterCapture,
        SampleErrorKind::NativeStackRead,
        SampleErrorKind::NativeStackTruncated,
        SampleErrorKind::NativeFramehopDidNotAdvance,
        SampleErrorKind::NativeFramehopReturnAddressNull,
        SampleErrorKind::NativeFramehopMovedBackwards,
        SampleErrorKind::NativeFramehopIntegerOverflow,
        SampleErrorKind::MergeTooManyPythonFrames,
        SampleErrorKind::MergeTooFewPythonFrames,
        SampleErrorKind::ThreadListCycle,
        SampleErrorKind::ThreadListTooMany,
    ];

    /// Category name for grouping in display.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::StackChunkInvalidSize
            | Self::StackChunkReadFailure
            | Self::StackChunkCycle
            | Self::StackChunkTooMany => "Stack Chunks",
            Self::FrameUnknownOwner
            | Self::FrameParseFailure
            | Self::FrameInitialNullCode
            | Self::FrameInitialFrameObjectOwned
            | Self::FrameInitialGarbageOwner => "Frame Parsing",
            Self::FrameChainTooMany | Self::FrameChainBroken | Self::FrameChainIncomplete => {
                "Frame Chain"
            }
            Self::CodeObjectReadFailure
            | Self::CodeObjectTlbcNull
            | Self::CodeObjectTlbcInvalidSize => "Code Objects",
            Self::ThreadStateReadFailure => "Thread State",
            Self::NativeRegisterCapture
            | Self::NativeStackRead
            | Self::NativeStackTruncated
            | Self::NativeFramehopDidNotAdvance
            | Self::NativeFramehopReturnAddressNull
            | Self::NativeFramehopMovedBackwards
            | Self::NativeFramehopIntegerOverflow => "Native Unwinding",
            Self::MergeTooManyPythonFrames | Self::MergeTooFewPythonFrames => "Stack Merging",
            Self::ThreadListCycle | Self::ThreadListTooMany => "Thread List",
        }
    }

    /// Short human-readable description.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::StackChunkInvalidSize => "Invalid chunk size",
            Self::StackChunkReadFailure => "Chunk read failure",
            Self::FrameUnknownOwner => "Unknown frame owner",
            Self::FrameChainTooMany => "Too many frames",
            Self::FrameChainBroken => "Broken chain",
            Self::FrameChainIncomplete => "Incomplete walk",
            Self::CodeObjectReadFailure | Self::ThreadStateReadFailure => "Read failure",
            Self::CodeObjectTlbcNull => "NULL TLBC pointer",
            Self::CodeObjectTlbcInvalidSize => "Invalid TLBC size",
            Self::NativeRegisterCapture => "Register capture failed",
            Self::NativeStackRead => "Stack read failed",
            Self::NativeStackTruncated => "Stack copy too small (truncated unwind)",
            Self::NativeFramehopDidNotAdvance => "Framehop: did not advance",
            Self::NativeFramehopReturnAddressNull => "Framehop: return address is NULL",
            Self::NativeFramehopMovedBackwards => "Framehop: frame pointer moved backwards",
            Self::NativeFramehopIntegerOverflow => "Framehop: integer overflow",
            Self::MergeTooManyPythonFrames => "Too many Python frames for native eval slots",
            Self::MergeTooFewPythonFrames => "Too few Python frames for native eval slots",
            Self::ThreadListCycle => "Cycle detected",
            Self::ThreadListTooMany => "Too many threads",
            Self::StackChunkCycle => "Chunk list cycle",
            Self::StackChunkTooMany => "Too many chunks",
            Self::FrameParseFailure => "Initial frame parse failed",
            Self::FrameInitialNullCode => "Initial frame: null code object",
            Self::FrameInitialFrameObjectOwned => {
                "Initial frame: held by frame object (sys._getframe)"
            }
            Self::FrameInitialGarbageOwner => "Initial frame: invalid owner (memory corruption)",
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
        if self.should_log(kind) {
            tracing::debug!(
                target: "stackpulse::sampler::error",
                kind = %kind,
                category = kind.category(),
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

/// Snapshot of per-kind counters for emitting periodic delta summaries.
#[derive(Debug, Clone)]
pub struct SampleErrorSnapshot {
    counts: [u64; ERROR_KIND_COUNT],
}

impl Default for SampleErrorSnapshot {
    fn default() -> Self {
        Self {
            counts: [0u64; ERROR_KIND_COUNT],
        }
    }
}

impl SampleErrorSnapshot {
    /// Take a snapshot of the current counter state.
    #[must_use]
    pub fn capture(stats: &SampleErrorStats) -> Self {
        let mut counts = [0u64; ERROR_KIND_COUNT];
        for (i, counter) in stats.counts.iter().enumerate() {
            counts[i] = counter.load(Ordering::Relaxed);
        }
        Self { counts }
    }

    /// Iterate over kinds whose counter increased since `previous`.
    pub fn delta_iter<'a>(
        &'a self,
        previous: &'a Self,
    ) -> impl Iterator<Item = (SampleErrorKind, u64)> + 'a {
        SampleErrorKind::ALL.iter().filter_map(move |&kind| {
            let cur = self.counts[kind as usize];
            let prev = previous.counts[kind as usize];
            if cur > prev {
                Some((kind, cur - prev))
            } else {
                None
            }
        })
    }

    /// Total errors across all categories in this snapshot.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }
}

/// Format error statistics for display.
///
/// Groups errors by category with counts and percentages.
/// Includes progress bars for visual representation.
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

    /// Generate a progress bar string.
    fn progress_bar(percentage: f64, width: usize) -> String {
        let filled = ((percentage / 100.0) * width as f64).round() as usize;
        let empty = width.saturating_sub(filled);
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }

    /// Write formatted stats to the provided writer.
    ///
    /// # Errors
    /// Returns a `fmt::Error` if writing to the output fails.
    pub fn write_to(&self, w: &mut impl fmt::Write) -> fmt::Result {
        let total_errors = self.stats.total();
        let entries: Vec<_> = self.stats.iter_nonzero().collect();
        let desc_width = entries
            .iter()
            .map(|(kind, _)| kind.description().len() + 1) // include trailing ':'
            .max()
            .unwrap_or(24)
            .max(24);

        // Overview section
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
            if self.total_samples > 0 {
                // Stats counters converted to f64 for percentage display
                self.successful_samples as f64 / self.total_samples as f64 * 100.0
            } else {
                0.0
            }
        )?;
        writeln!(
            w,
            "  Sample errors:       {} ({:.2}%)",
            format_number(total_errors),
            if self.total_samples > 0 {
                // Stats counters converted to f64 for percentage display
                total_errors as f64 / self.total_samples as f64 * 100.0
            } else {
                0.0
            }
        )?;

        if total_errors == 0 {
            writeln!(w, "\n  No sample errors recorded")?;
            return Ok(());
        }

        // Group by category
        let mut current_category = "";
        for (kind, count) in &entries {
            let category = kind.category();
            if category != current_category {
                writeln!(w, "\n{category}:")?;
                current_category = category;
            }

            // Stats counters converted to f64 for percentage display
            let pct_of_errors = (*count as f64 / total_errors as f64) * 100.0;
            let pct_of_samples = if self.total_samples > 0 {
                (*count as f64 / self.total_samples as f64) * 100.0
            } else {
                0.0
            };
            let bar = Self::progress_bar(pct_of_errors, 20);

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
    fn test_category_grouping() {
        // Verify that related errors share categories
        assert_eq!(
            SampleErrorKind::StackChunkInvalidSize.category(),
            SampleErrorKind::StackChunkReadFailure.category()
        );
        assert_eq!(
            SampleErrorKind::StackChunkCycle.category(),
            SampleErrorKind::StackChunkInvalidSize.category()
        );
        assert_eq!(
            SampleErrorKind::StackChunkTooMany.category(),
            SampleErrorKind::StackChunkInvalidSize.category()
        );
        assert_eq!(
            SampleErrorKind::FrameChainTooMany.category(),
            SampleErrorKind::FrameChainIncomplete.category()
        );
        assert_eq!(
            SampleErrorKind::FrameUnknownOwner.category(),
            SampleErrorKind::FrameParseFailure.category()
        );
        assert_eq!(
            SampleErrorKind::NativeRegisterCapture.category(),
            SampleErrorKind::NativeStackRead.category()
        );
    }

    // SampleErrorStats basic operations

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

        stats.record(SampleErrorKind::FrameChainIncomplete);
        assert_eq!(stats.get(SampleErrorKind::FrameChainIncomplete), 1);
        assert!(stats.has_errors());

        stats.record(SampleErrorKind::FrameChainIncomplete);
        assert_eq!(stats.get(SampleErrorKind::FrameChainIncomplete), 2);

        stats.record(SampleErrorKind::StackChunkReadFailure);
        assert_eq!(stats.get(SampleErrorKind::StackChunkReadFailure), 1);
        assert_eq!(stats.get(SampleErrorKind::FrameUnknownOwner), 0);
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
        stats.record(SampleErrorKind::FrameChainBroken);
        stats.record(SampleErrorKind::FrameChainBroken);
        stats.record(SampleErrorKind::MergeTooManyPythonFrames);

        let nonzero: Vec<_> = stats.iter_nonzero().collect();
        assert_eq!(nonzero.len(), 2);

        assert!(nonzero.contains(&(SampleErrorKind::FrameChainBroken, 2)));
        assert!(nonzero.contains(&(SampleErrorKind::MergeTooManyPythonFrames, 1)));
    }

    #[test]
    fn test_iter_nonzero_preserves_order() {
        let stats = SampleErrorStats::new();
        // Record in reverse order
        stats.record(SampleErrorKind::MergeTooManyPythonFrames);
        stats.record(SampleErrorKind::StackChunkInvalidSize);

        let nonzero: Vec<_> = stats.iter_nonzero().collect();

        // Should be in ALL order, not recording order
        assert_eq!(nonzero[0].0, SampleErrorKind::StackChunkInvalidSize);
        assert_eq!(nonzero[1].0, SampleErrorKind::MergeTooManyPythonFrames);
    }

    // SampleErrorStats reset

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

    // SampleErrorStats clone

    #[test]
    fn test_clone() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::FrameChainIncomplete);
        stats.record(SampleErrorKind::StackChunkReadFailure);

        let cloned = stats.clone();

        // Clone has same values
        assert_eq!(cloned.get(SampleErrorKind::FrameChainIncomplete), 1);
        assert_eq!(cloned.get(SampleErrorKind::StackChunkReadFailure), 1);
        assert_eq!(cloned.total(), 2);
    }

    #[test]
    fn test_clone_independence() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::FrameChainIncomplete);

        let cloned = stats.clone();

        // Modify original
        stats.record(SampleErrorKind::FrameChainIncomplete);
        stats.record(SampleErrorKind::StackChunkReadFailure);

        // Clone is unaffected
        assert_eq!(cloned.get(SampleErrorKind::FrameChainIncomplete), 1);
        assert_eq!(cloned.get(SampleErrorKind::StackChunkReadFailure), 0);
        assert_eq!(cloned.total(), 1);

        // Original has new values
        assert_eq!(stats.get(SampleErrorKind::FrameChainIncomplete), 2);
        assert_eq!(stats.get(SampleErrorKind::StackChunkReadFailure), 1);
        assert_eq!(stats.total(), 3);
    }

    // ErrorStatsFormatter tests

    #[test]
    fn test_formatter_no_errors() {
        let stats = SampleErrorStats::new();
        let formatter = ErrorStatsFormatter::new(&stats, 1000, 1000);

        let mut output = String::new();
        formatter.write_to(&mut output).unwrap();

        assert!(output.contains("Total samples:"));
        assert!(output.contains("1,000"));
        assert!(output.contains("No sample errors recorded"));
    }

    #[test]
    fn test_formatter_with_errors() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::FrameChainIncomplete);
        stats.record(SampleErrorKind::FrameChainIncomplete);
        stats.record(SampleErrorKind::StackChunkReadFailure);

        let formatter = ErrorStatsFormatter::new(&stats, 100, 97);

        let mut output = String::new();
        formatter.write_to(&mut output).unwrap();

        assert!(output.contains("Total samples:"));
        assert!(output.contains("100"));
        assert!(output.contains("Successful:"));
        assert!(output.contains("97"));
        assert!(output.contains("Sample errors:"));
        assert!(output.contains("Frame Chain:"));
        assert!(output.contains("Incomplete walk:"));
        assert!(output.contains("Stack Chunks:"));
    }

    #[test]
    fn test_formatter_errors_add_up() {
        let stats = SampleErrorStats::new();
        for _ in 0..50 {
            stats.record(SampleErrorKind::CodeObjectReadFailure);
        }
        for _ in 0..30 {
            stats.record(SampleErrorKind::MergeTooManyPythonFrames);
        }
        for _ in 0..20 {
            stats.record(SampleErrorKind::FrameChainIncomplete);
        }

        let formatter = ErrorStatsFormatter::new(&stats, 1000, 900);

        let mut output = String::new();
        formatter.write_to(&mut output).unwrap();

        assert!(output.contains("Sample errors:"));
        assert!(output.contains("100"));
    }

    #[test]
    fn test_formatter_categories_grouped() {
        let stats = SampleErrorStats::new();
        // Add errors from different categories
        stats.record(SampleErrorKind::StackChunkInvalidSize);
        stats.record(SampleErrorKind::StackChunkReadFailure);
        stats.record(SampleErrorKind::FrameChainBroken);
        stats.record(SampleErrorKind::MergeTooManyPythonFrames);

        let formatter = ErrorStatsFormatter::new(&stats, 100, 96);

        let mut output = String::new();
        formatter.write_to(&mut output).unwrap();

        // Verify category headers appear
        assert!(output.contains("Stack Chunks:"));
        assert!(output.contains("Frame Chain:"));
        assert!(output.contains("Stack Merging:"));
    }

    #[test]
    fn test_formatter_percentages() {
        let stats = SampleErrorStats::new();
        // Add 80 of one type, 20 of another = 80% and 20% of errors
        // With 1000 total samples: 8% and 2% of samples
        for _ in 0..80 {
            stats.record(SampleErrorKind::FrameChainIncomplete);
        }
        for _ in 0..20 {
            stats.record(SampleErrorKind::StackChunkReadFailure);
        }

        let formatter = ErrorStatsFormatter::new(&stats, 1000, 900);

        let mut output = String::new();
        formatter.write_to(&mut output).unwrap();

        // Check percentage of errors
        assert!(output.contains("80.0% of errors"));
        assert!(output.contains("20.0% of errors"));
        // Check percentage of samples
        assert!(output.contains("8.00% of samples"));
        assert!(output.contains("2.00% of samples"));
    }

    #[test]
    fn test_formatter_progress_bars_are_aligned() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::NativeFramehopMovedBackwards);
        stats.record(SampleErrorKind::NativeFramehopDidNotAdvance);
        stats.record(SampleErrorKind::MergeTooManyPythonFrames);

        let formatter = ErrorStatsFormatter::new(&stats, 1000, 997);
        let mut output = String::new();
        formatter.write_to(&mut output).unwrap();

        let lines: Vec<&str> = output
            .lines()
            .filter(|line| line.contains("Framehop:") || line.contains("Too many Python"))
            .collect();
        assert_eq!(lines.len(), 3);

        let bar_start = |line: &str| {
            line.find('█')
                .or_else(|| line.find('░'))
                .expect("formatted line should contain a progress bar")
        };

        let first = bar_start(lines[0]);
        assert_eq!(bar_start(lines[1]), first);
        assert_eq!(bar_start(lines[2]), first);
    }

    // Thread safety (basic verification)

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
                        stats.record(SampleErrorKind::FrameChainIncomplete);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            stats.get(SampleErrorKind::FrameChainIncomplete),
            num_threads * records_per_thread
        );
    }
}
