//! Ordered semantic observation of spool writes.

use std::io;

use super::{
    invalid_data, FrameMode, FrameRecord, ModuleRecord, PythonRuntimeRecord, SampleRecord,
    StackNodeRecord,
};

/// A raw frame in the compact form emitted by the spool writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamedFrame {
    /// A frame tied to a module id.
    Pinned {
        /// Module id.
        module_id: u32,
        /// Address in the module file-offset coordinate space.
        file_relative_ip: u64,
    },
    /// A frame resolved against the module state at this stream position.
    Unpinned {
        /// Absolute instruction pointer.
        abs_ip: u64,
        /// Whether this is a kernel frame.
        is_kernel: bool,
    },
    /// The native unwinder stopped before reaching the stack root.
    TruncatedStackMarker,
}

impl StreamedFrame {
    pub(super) fn from_frame(frame: &FrameRecord) -> Self {
        if frame.is_truncated_stack_marker() {
            Self::TruncatedStackMarker
        } else if let Some(module_id) = frame.module_id {
            Self::Pinned {
                module_id,
                file_relative_ip: frame.file_relative_ip,
            }
        } else {
            Self::Unpinned {
                abs_ip: frame.abs_ip,
                is_kernel: frame.mode == FrameMode::Kernel,
            }
        }
    }
}

/// One typed record, delivered in exactly the order it was committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpoolRecord {
    /// Spool timeline metadata. This is always the first record.
    Header {
        /// Profile timeline anchor in microseconds.
        start_timestamp_us: u64,
        /// Sample interval metadata in microseconds.
        sample_interval_us: u64,
    },
    /// A newly active module mapping.
    Module(ModuleRecord),
    /// A newly interned frame. Its id is its zero-based position among frames.
    Frame(StreamedFrame),
    /// A newly interned stack node. Its id is its zero-based position among stacks.
    Stack {
        /// Parent stack node, or `None` for a root.
        prefix: Option<u32>,
        /// Interned frame id.
        frame_id: u32,
    },
    /// A newly interned thread identity.
    Thread {
        /// Process id.
        process_id: i32,
        /// Thread id.
        thread_id: u64,
    },
    /// A captured sample.
    Sample {
        /// Monotonic timestamp in nanoseconds.
        timestamp_ns: u64,
        /// Interned thread index.
        thread_index: u32,
        /// Interned stack id.
        stack_id: u32,
    },
    /// A Python runtime status change.
    PythonRuntime(PythonRuntimeRecord),
    /// All user modules belonging to a process became inactive.
    DeactivateProcessModules {
        /// Process id.
        process_id: i32,
    },
    /// One module became inactive.
    DeactivateModule {
        /// Module id.
        module_id: u32,
    },
}

/// Whether a record sink remains attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkOutcome {
    /// Continue observing records.
    Continue,
    /// Permanently detach this sink without affecting an authoritative spool.
    Abandon,
}

/// Non-blocking observer called on the perf-drain thread.
///
/// Implementations should use a bounded queue and return [`SinkOutcome::Abandon`]
/// if they cannot enqueue immediately.
pub trait SpoolRecordSink: Send {
    /// Observe one committed record.
    fn on_record(&mut self, record: SpoolRecord) -> SinkOutcome;
}

impl SpoolRecordSink for std::sync::mpsc::SyncSender<SpoolRecord> {
    fn on_record(&mut self, record: SpoolRecord) -> SinkOutcome {
        match self.try_send(record) {
            Ok(()) => SinkOutcome::Continue,
            Err(_) => SinkOutcome::Abandon,
        }
    }
}

/// Incrementally reconstructs the definition tables needed by a live consumer.
#[derive(Default)]
pub struct StreamReplayState {
    start_timestamp_us: u64,
    sample_interval_us: u64,
    modules: Vec<ModuleRecord>,
    frames: Vec<FrameRecord>,
    stacks: Vec<StackNodeRecord>,
    threads: Vec<(i32, u64)>,
    samples: Vec<SampleRecord>,
    python_runtime_records: Vec<PythonRuntimeRecord>,
    first_sample_timestamp_ns: Option<u64>,
}

impl StreamReplayState {
    /// Create empty replay state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a record and retain sample metadata.
    pub fn apply(&mut self, record: SpoolRecord) -> io::Result<Option<SampleRecord>> {
        self.apply_inner(record, true)
    }

    /// Apply a record without retaining sample metadata.
    pub fn apply_transient(&mut self, record: SpoolRecord) -> io::Result<Option<SampleRecord>> {
        self.apply_inner(record, false)
    }

    fn apply_inner(
        &mut self,
        record: SpoolRecord,
        retain_sample: bool,
    ) -> io::Result<Option<SampleRecord>> {
        match record {
            SpoolRecord::Header {
                start_timestamp_us,
                sample_interval_us,
            } => {
                self.start_timestamp_us = start_timestamp_us;
                self.sample_interval_us = sample_interval_us;
            }
            SpoolRecord::Module(mut module) => {
                module.id = u32::try_from(self.modules.len())
                    .map_err(|_| invalid_data("module id too large"))?;
                self.modules.push(module);
            }
            SpoolRecord::Frame(frame) => self.frames.push(self.decode_frame(frame)?),
            SpoolRecord::Stack { prefix, frame_id } => {
                if frame_id as usize >= self.frames.len() {
                    return Err(invalid_data("stack references missing frame"));
                }
                if prefix.is_some_and(|id| id as usize >= self.stacks.len()) {
                    return Err(invalid_data("stack references missing prefix"));
                }
                let depth = prefix.map_or(1, |id| self.stacks[id as usize].depth.saturating_add(1));
                self.stacks.push(StackNodeRecord {
                    prefix,
                    frame_id,
                    depth,
                });
            }
            SpoolRecord::Thread {
                process_id,
                thread_id,
            } => {
                self.threads.push((process_id, thread_id));
            }
            SpoolRecord::Sample {
                timestamp_ns,
                thread_index,
                stack_id,
            } => {
                let &(process_id, thread_id) = self
                    .threads
                    .get(thread_index as usize)
                    .ok_or_else(|| invalid_data("sample references missing thread"))?;
                if stack_id as usize >= self.stacks.len() {
                    return Err(invalid_data("sample references missing stack"));
                }
                let sample = SampleRecord {
                    timestamp_ns,
                    process_id,
                    thread_id,
                    stack_id,
                };
                self.first_sample_timestamp_ns.get_or_insert(timestamp_ns);
                if retain_sample {
                    self.samples.push(sample.clone());
                }
                return Ok(Some(sample));
            }
            SpoolRecord::PythonRuntime(record) => self.python_runtime_records.push(record),
            SpoolRecord::DeactivateProcessModules { .. } | SpoolRecord::DeactivateModule { .. } => {
            }
        }
        Ok(None)
    }

    fn decode_frame(&self, frame: StreamedFrame) -> io::Result<FrameRecord> {
        match frame {
            StreamedFrame::TruncatedStackMarker => Ok(FrameRecord::truncated_stack_marker()),
            StreamedFrame::Unpinned { abs_ip, is_kernel } => Ok(FrameRecord {
                module_id: None,
                file_relative_ip: abs_ip,
                abs_ip,
                mode: if is_kernel {
                    FrameMode::Kernel
                } else {
                    FrameMode::User
                },
            }),
            StreamedFrame::Pinned {
                module_id,
                file_relative_ip,
            } => {
                let module = self
                    .modules
                    .get(module_id as usize)
                    .ok_or_else(|| invalid_data("frame references missing module"))?;
                let offset = file_relative_ip
                    .checked_sub(module.file_offset)
                    .ok_or_else(|| invalid_data("frame precedes module file offset"))?;
                let span = module
                    .end
                    .checked_sub(module.start)
                    .ok_or_else(|| invalid_data("module end precedes start"))?;
                if offset >= span {
                    return Err(invalid_data("frame outside module"));
                }
                Ok(FrameRecord {
                    module_id: Some(module_id),
                    file_relative_ip,
                    abs_ip: module.start + offset,
                    mode: if module.is_kernel {
                        FrameMode::Kernel
                    } else {
                        FrameMode::User
                    },
                })
            }
        }
    }

    /// Timeline anchor in microseconds.
    #[must_use]
    pub fn start_timestamp_us(&self) -> u64 {
        self.start_timestamp_us
    }

    /// Sample interval metadata in microseconds.
    #[must_use]
    pub fn sample_interval_us(&self) -> u64 {
        self.sample_interval_us
    }

    /// Modules observed so far.
    #[must_use]
    pub fn modules(&self) -> &[ModuleRecord] {
        &self.modules
    }

    /// Frames observed so far.
    #[must_use]
    pub fn frames(&self) -> &[FrameRecord] {
        &self.frames
    }

    /// Retained samples.
    #[must_use]
    pub fn samples(&self) -> &[SampleRecord] {
        &self.samples
    }

    /// Python runtime records observed so far.
    #[must_use]
    pub fn python_runtime_records(&self) -> &[PythonRuntimeRecord] {
        &self.python_runtime_records
    }

    /// Convert a sample timestamp to profile time in microseconds.
    #[must_use]
    pub fn timestamp_us(&self, sample: &SampleRecord) -> u64 {
        let first = self
            .first_sample_timestamp_ns
            .unwrap_or(sample.timestamp_ns);
        self.start_timestamp_us
            .saturating_add(sample.timestamp_ns.saturating_sub(first) / 1_000)
    }

    /// Expand a stack into `(frame_id, frame)` pairs, leaf first.
    pub fn stack_frame_ids(
        &self,
        stack_id: u32,
        out: &mut Vec<(u32, FrameRecord)>,
    ) -> io::Result<()> {
        out.clear();
        let mut current = Some(stack_id);
        while let Some(id) = current {
            let node = self
                .stacks
                .get(id as usize)
                .ok_or_else(|| invalid_data("missing stack node"))?;
            let frame = *self
                .frames
                .get(node.frame_id as usize)
                .ok_or_else(|| invalid_data("missing stack frame"))?;
            out.push((node.frame_id, frame));
            current = node.prefix;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::spool::{ModulePath, PerfSpoolReader, PerfSpoolWriter};
    use crate::test_support::TempDir;

    struct SharedSink(Arc<Mutex<Vec<SpoolRecord>>>);

    impl SpoolRecordSink for SharedSink {
        fn on_record(&mut self, record: SpoolRecord) -> SinkOutcome {
            self.0.lock().unwrap().push(record);
            SinkOutcome::Continue
        }
    }

    fn module(id: u32, path: &str) -> ModuleRecord {
        ModuleRecord {
            id,
            process_id: 7,
            start: 0x4000,
            end: 0x5000,
            file_offset: 0,
            inode: u64::from(id) + 1,
            device_major: 8,
            device_minor: 1,
            inode_generation: 0,
            path: ModulePath::from(path),
            is_kernel: false,
        }
    }

    fn frame(abs_ip: u64) -> FrameRecord {
        FrameRecord {
            module_id: None,
            file_relative_ip: abs_ip,
            abs_ip,
            mode: FrameMode::User,
        }
    }

    fn write_scenario<W: std::io::Write>(writer: &mut PerfSpoolWriter<W>) {
        writer.write_module(&module(0, "/old.so")).unwrap();
        writer.write_python_runtime(900, 7, true).unwrap();
        writer
            .write_sample_frames(1_000, 7, 11, [frame(0x4100), frame(0x4200)])
            .unwrap();
        writer.write_module_deactivation_one(0).unwrap();
        writer.write_module(&module(1, "/new.so")).unwrap();
        writer
            .write_sample_frames(2_000, 7, 12, [frame(0x4100)])
            .unwrap();
        writer.flush().unwrap();
    }

    fn observed_writer<W: std::io::Write>(
        output: W,
    ) -> (PerfSpoolWriter<W>, Arc<Mutex<Vec<SpoolRecord>>>) {
        let records = Arc::new(Mutex::new(Vec::new()));
        let mut writer = PerfSpoolWriter::from_writer(output, 123, 10).unwrap();
        writer.set_record_sink(Box::new(SharedSink(Arc::clone(&records))));
        (writer, records)
    }

    #[test]
    fn observer_preserves_spool_bytes_and_record_order() {
        let mut plain = PerfSpoolWriter::from_writer(Vec::new(), 123, 10).unwrap();
        write_scenario(&mut plain);
        let plain = plain.into_inner();

        let (mut observed, records) = observed_writer(Vec::new());
        write_scenario(&mut observed);
        let observed = observed.into_inner();
        assert_eq!(plain, observed);

        let records = records.lock().unwrap();
        assert!(matches!(records[0], SpoolRecord::Header { .. }));
        assert!(matches!(records[1], SpoolRecord::Module(_)));
        assert!(matches!(records[2], SpoolRecord::PythonRuntime(_)));
        let first_sample = records
            .iter()
            .position(|r| matches!(r, SpoolRecord::Sample { .. }))
            .unwrap();
        assert!(records[3..first_sample]
            .iter()
            .any(|r| matches!(r, SpoolRecord::Frame(_))));
        assert!(records[3..first_sample]
            .iter()
            .any(|r| matches!(r, SpoolRecord::Stack { .. })));
        assert!(records[3..first_sample]
            .iter()
            .any(|r| matches!(r, SpoolRecord::Thread { .. })));
        assert!(matches!(
            records[first_sample + 1],
            SpoolRecord::DeactivateModule { module_id: 0 }
        ));
    }

    #[test]
    fn streamed_replay_matches_batch_reader() {
        let (mut writer, records) = observed_writer(Vec::new());
        write_scenario(&mut writer);
        let bytes = writer.into_inner();
        let dir = TempDir::new("semantic-stream-parity");
        let path = dir.path().join("profile.stackpulse");
        std::fs::write(&path, bytes).unwrap();
        let reader = PerfSpoolReader::open(path).unwrap();

        let mut state = StreamReplayState::new();
        for record in records.lock().unwrap().iter().cloned() {
            state.apply(record).unwrap();
        }
        assert_eq!(state.start_timestamp_us(), reader.start_timestamp_us());
        assert_eq!(state.sample_interval_us(), reader.sample_interval_us());
        assert_eq!(state.modules(), reader.modules());
        assert_eq!(state.frames(), reader.frames());
        assert_eq!(state.samples(), reader.samples());
        assert_eq!(
            state.python_runtime_records(),
            reader.python_runtime_records()
        );

        let mut streamed = Vec::new();
        let mut batch = Vec::new();
        for sample in state.samples() {
            state
                .stack_frame_ids(sample.stack_id, &mut streamed)
                .unwrap();
            reader.stack_frames(sample.stack_id, &mut batch).unwrap();
            assert_eq!(
                streamed.iter().map(|(_, frame)| *frame).collect::<Vec<_>>(),
                batch
            );
        }
    }

    #[test]
    fn discard_output_reconstructs_complete_profile() {
        let (mut writer, records) = observed_writer(std::io::sink());
        write_scenario(&mut writer);
        assert!(writer.has_record_sink());

        let mut state = StreamReplayState::new();
        for record in records.lock().unwrap().iter().cloned() {
            state.apply(record).unwrap();
        }
        assert_eq!(state.samples().len(), 2);
        assert_eq!(state.modules().len(), 2);
        assert_eq!(state.frames().len(), 3);
    }

    #[test]
    fn bounded_channel_overflow_is_distinguishable() {
        let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 123, 10).unwrap();
        writer.set_record_sink(Box::new(sender));
        assert!(writer.has_record_sink());
        writer.write_module(&module(0, "/old.so")).unwrap();
        assert!(!writer.has_record_sink());
        assert!(writer.record_sink_abandoned());
    }
}
