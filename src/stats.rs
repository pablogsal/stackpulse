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
#[non_exhaustive]
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
    pub fn count(&self, kind: SampleErrorKind) -> u64 {
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
    pub fn nonzero_counts(&self) -> impl Iterator<Item = (SampleErrorKind, u64)> + '_ {
        SampleErrorKind::ALL.iter().filter_map(|&kind| {
            let count = self.count(kind);
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
            assert_eq!(stats.count(*kind), 0, "{kind:?} should start at 0");
        }
        assert_eq!(stats.total(), 0);
        assert!(!stats.has_errors());
        assert!(stats.nonzero_counts().next().is_none());
    }

    #[test]
    fn test_record_and_get() {
        let stats = SampleErrorStats::new();

        stats.record(SampleErrorKind::NativeStackRead);
        assert_eq!(stats.count(SampleErrorKind::NativeStackRead), 1);
        assert!(stats.has_errors());

        stats.record(SampleErrorKind::NativeStackRead);
        assert_eq!(stats.count(SampleErrorKind::NativeStackRead), 2);

        stats.record(SampleErrorKind::NativeRegisterCapture);
        assert_eq!(stats.count(SampleErrorKind::NativeRegisterCapture), 1);
        assert_eq!(
            stats.count(SampleErrorKind::NativeFramehopIntegerOverflow),
            0
        );
        assert_eq!(stats.total(), 3);
    }

    #[test]
    fn test_nonzero_counts() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::NativeStackTruncated);
        stats.record(SampleErrorKind::NativeStackTruncated);
        stats.record(SampleErrorKind::NativeFramehopDidNotAdvance);

        let nonzero: Vec<_> = stats.nonzero_counts().collect();
        assert_eq!(nonzero.len(), 2);

        assert!(nonzero.contains(&(SampleErrorKind::NativeStackTruncated, 2)));
        assert!(nonzero.contains(&(SampleErrorKind::NativeFramehopDidNotAdvance, 1)));
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
            assert_eq!(stats.count(*kind), 0);
        }
    }

    #[test]
    fn test_clone() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::NativeStackRead);
        stats.record(SampleErrorKind::NativeRegisterCapture);

        let cloned = stats.clone();

        assert_eq!(cloned.count(SampleErrorKind::NativeStackRead), 1);
        assert_eq!(cloned.count(SampleErrorKind::NativeRegisterCapture), 1);
        assert_eq!(cloned.total(), 2);
    }

    #[test]
    fn test_clone_independence() {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::NativeStackRead);

        let cloned = stats.clone();

        stats.record(SampleErrorKind::NativeStackRead);
        stats.record(SampleErrorKind::NativeRegisterCapture);

        assert_eq!(cloned.count(SampleErrorKind::NativeStackRead), 1);
        assert_eq!(cloned.count(SampleErrorKind::NativeRegisterCapture), 0);
        assert_eq!(cloned.total(), 1);

        assert_eq!(stats.count(SampleErrorKind::NativeStackRead), 2);
        assert_eq!(stats.count(SampleErrorKind::NativeRegisterCapture), 1);
        assert_eq!(stats.total(), 3);
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
            stats.count(SampleErrorKind::NativeStackRead),
            num_threads * records_per_thread
        );
    }
}
