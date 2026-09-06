use std::io::{self, Write};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::*;
use crate::spool::{ClockOrigin, LiveReader, Spool};

/// Processes included in the recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessScope {
    /// Record the selected process and its threads.
    Process,
    /// Include accessible existing descendants and subsequent child processes.
    Descendants,
}

/// Initial attachment policy for a process that has already executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachPolicy {
    /// Read initial mappings without stopping the target.
    Running,
    /// Stop the target while establishing its initial mapping snapshot.
    StopWhileAttaching,
}

/// Recorder configuration, validated when attaching or preparing a launch.
#[derive(Clone, Debug)]
pub struct RecorderBuilder {
    options: RecorderOptions,
    policy: AttachPolicy,
    publish_interval: Duration,
}

impl RecorderBuilder {
    pub(super) fn new(rate: SampleRate) -> Self {
        Self {
            options: RecorderOptions::new(rate),
            policy: AttachPolicy::StopWhileAttaching,
            publish_interval: Duration::from_millis(500),
        }
    }

    /// Set the user-stack snapshot size in bytes.
    pub fn stack_size(mut self, bytes: u32) -> Self {
        self.options.stack_size = bytes;
        self
    }
    /// Set the target per-CPU perf data-ring capacity in stack-sized records.
    ///
    /// Capacity is the larger of the configured stack snapshot and system page
    /// size, times this count, with a floor large enough for any perf record and
    /// power-of-two page rounding. On 4 KiB-page hosts, the default count of 32
    /// gives a 1 MiB ring for the default 32 KiB stack and a 2 MiB ring for a
    /// 64 KiB stack. Memory is pinned per CPU. Values
    /// requiring more than 256 MiB per CPU are rejected. Zero selects the
    /// default. If mmap fails with `EPERM` or `ENOMEM`, attach progressively
    /// halves the ring down to the minimum valid capacity. All per-CPU rings
    /// in one recorder also share a 1 GiB aggregate data budget; effective
    /// capacities are available in [`RecordingSummary`].
    pub fn ring_buffer_stacks(mut self, stacks: u32) -> Self {
        self.options.ring_stacks = normalized_ring_stacks(stacks);
        self
    }
    /// Include kernel frames when permitted by the operating system.
    pub fn include_kernel(mut self, include: bool) -> Self {
        self.options.include_kernel = include;
        self
    }
    /// Select which processes are observed.
    pub fn scope(mut self, scope: ProcessScope) -> Self {
        self.options.inherit_child_processes = scope == ProcessScope::Descendants;
        self
    }
    /// Select initial mapping consistency.
    pub fn attach_policy(mut self, policy: AttachPolicy) -> Self {
        self.policy = policy;
        self
    }
    /// Set publication cadence while the recorder is being polled.
    pub fn publish_interval(mut self, interval: Duration) -> Self {
        self.publish_interval = interval;
        self
    }

    fn mode(&self) -> AttachMode {
        match self.policy {
            AttachPolicy::Running => AttachMode::Running,
            AttachPolicy::StopWhileAttaching => AttachMode::StopWhileAttaching,
        }
    }

    /// Attach and write to an owned file spool.
    pub fn attach(self, pid: crate::Pid, spool: Spool) -> crate::Result<Recorder> {
        let disposable = spool.disposable;
        let mut recorder = self.attach_writer(pid, spool.into_writer())?;
        recorder.disposable = disposable;
        Ok(recorder)
    }

    /// Attach with a custom writer, which has no file-reader capability.
    ///
    /// ```compile_fail
    /// use std::{fs::File, io::BufWriter};
    /// use stackpulse::{Pid, Recorder, SampleRate};
    ///
    /// fn capture(pid: Pid, output: BufWriter<File>) -> stackpulse::Result<()> {
    ///     let mut recorder = Recorder::builder(SampleRate::hz(99)?)
    ///         .attach_writer(pid, output)?;
    ///     let reader = recorder.take_reader()?;
    ///     Ok(())
    /// }
    /// ```
    pub fn attach_writer<W: Write>(self, pid: crate::Pid, writer: W) -> crate::Result<Recorder<W>> {
        let mode = self.mode();
        let inherit_children = self.options.inherit_child_processes;
        let mut recorder = Recorder::attach_with_writer(pid, writer, mode, self.options)?;
        recorder.publish_interval = self.publish_interval;
        if inherit_children {
            for child in crate::children::discover_all_descendants(pid) {
                if let Err(error) = recorder.attach_process(child, mode) {
                    recorder.check_failure().map_err(|_| error)?;
                }
            }
        }
        Ok(recorder)
    }

    /// Prepare capture before allowing the launched child to execute.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ErrorKind::ProcessLaunch`] when the child cannot be
    /// created. Recorder setup failures retain their own error category.
    pub fn prepare(
        self,
        launch: process::Launch,
        spool: Spool,
    ) -> crate::Result<PreparedRecording> {
        let disposable = spool.disposable;
        let child = launch
            .suspend()
            .map_err(|error| crate::Error::new(crate::ErrorKind::ProcessLaunch, error))?;
        let mut recorder = Recorder::attach_with_writer(
            child.pid(),
            spool.into_writer(),
            AttachMode::OnExec,
            self.options,
        )?;
        recorder.disposable = disposable;
        recorder.publish_interval = self.publish_interval;
        Ok(PreparedRecording { recorder, child })
    }
}

/// Capture metadata derived once from the selected rate and clock pair.
#[derive(Clone, Debug)]
pub struct RecordingMetadata {
    pub(super) started_at: SystemTime,
    pub(super) nominal_rate: NonZeroU32,
    pub(super) nominal_interval: Duration,
}

impl RecordingMetadata {
    pub(super) fn new(options: &RecorderOptions, origin: ClockOrigin) -> io::Result<Self> {
        let rate = options.sample_rate.resolve()?;
        let nominal_rate = NonZeroU32::new(rate)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sample rate is zero"))?;
        Ok(Self {
            started_at: origin.wall_time,
            nominal_rate,
            nominal_interval: Duration::from_secs_f64(1.0 / f64::from(rate)),
        })
    }
    /// Wall-clock time paired with the recorder's monotonic origin.
    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }
    /// Initial configured rate; subsequently opened counters may clamp lower.
    pub fn nominal_rate(&self) -> NonZeroU32 {
        self.nominal_rate
    }
    /// Nominal interval derived from the initial configured rate.
    pub fn nominal_interval(&self) -> Duration {
        self.nominal_interval
    }
}

/// A suspended child and the recorder armed for its first exec.
pub struct PreparedRecording {
    recorder: Recorder,
    child: process::SuspendedLaunchedProcess,
}

impl PreparedRecording {
    /// The child process that will execute.
    pub fn pid(&self) -> crate::Pid {
        self.child.pid()
    }
    /// Metadata already available before starting the child.
    pub fn metadata(&self) -> &RecordingMetadata {
        self.recorder.metadata()
    }
    /// Take the recording's sole linked reader before executing the child.
    pub fn take_reader(&mut self) -> crate::Result<LiveReader> {
        self.recorder.take_reader()
    }
    /// Execute the child and transfer ownership of capture and child handles.
    pub fn start(self) -> crate::Result<(Recorder, process::Child)> {
        let Self { recorder, child } = self;
        match child.unsuspend_and_run() {
            Ok(child) => Ok((recorder, child)),
            Err(error) => {
                let cleanup = recorder.finish();
                match cleanup {
                    Ok(_) => Err(error),
                    Err(cleanup) => Err(crate::error::with_cleanup_error(
                        error.into(),
                        io::Error::other(cleanup),
                    )
                    .into()),
                }
            }
        }
    }
}

/// Final capture diagnostics remain available when shutdown fails.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct FinishError {
    pub(super) summary: Box<RecordingSummary>,
    #[source]
    pub(super) source: Arc<crate::Error>,
}

impl FinishError {
    /// Final counters, including work completed before the failure.
    pub fn summary(&self) -> &RecordingSummary {
        &self.summary
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct SharedFailure(#[source] pub Arc<crate::Error>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn prepare_distinguishes_launch_and_recorder_setup_errors() {
        let directory = TempDir::new("prepare-errors");
        let spool = || {
            Spool::retained(std::fs::File::create(directory.path().join("capture")).unwrap())
                .unwrap()
        };
        let error = Recorder::builder(SampleRate::hz(99).unwrap())
            .prepare(
                process::Launch::new("unused").args(["invalid\0argument"]),
                spool(),
            )
            .err()
            .expect("NUL argument must fail before launching");
        assert_eq!(error.kind(), crate::ErrorKind::ProcessLaunch);
        assert_eq!(
            error.io_error().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(error.to_string().contains("nul byte"));
        let source = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<crate::Error>()
            .unwrap();
        assert_eq!(source.kind(), crate::ErrorKind::InvalidInput);

        let error = Recorder::builder(SampleRate::hz(99).unwrap())
            .stack_size(u32::MAX)
            .prepare(process::Launch::new("unused"), spool())
            .err()
            .expect("invalid stack size must fail recorder setup");
        assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
        assert_eq!(
            error.io_error().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(error.to_string().contains("sample_user_stack"));
    }
}
