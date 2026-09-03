use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use rustc_hash::FxHashSet;

use super::{
    invalid_data, next_source_id, read_frame, read_index_within, read_module_mmap, read_process_id,
    read_python_runtime, read_sample, read_stack_node, read_thread, MmapSpoolCursor, ModulePath,
    PythonRuntimeRecord, SampleRecord, SampleStack, SpoolDefinitions, ThreadRecord, REC_FRAME,
    REC_MODULE, REC_MODULE_DEACTIVATE, REC_MODULE_DEACTIVATE_ONE, REC_PYTHON_RUNTIME, REC_SAMPLE,
    REC_STACK, REC_THREAD,
};

/// Incremental reader for an append-only StackPulse spool.
///
/// Each complete record is decoded once. A record cut off at the visible end
/// of the file is retried after the writer appends the rest of it.
/// Definitions are retained for the life of the reader, while sample storage
/// is bounded and reused between polls.
pub struct Tail {
    file: File,
    mmap: Arc<Mmap>,
    position: usize,
    definitions: SpoolDefinitions,
    threads: Vec<ThreadRecord>,
    last_timestamp_ns: u64,
    first_sample_timestamp_ns: Option<u64>,
    sample_count: usize,
    samples: Vec<SampleRecord>,
    initial_samples_pending: bool,
    observed_processes: Vec<crate::Pid>,
    observed_process_set: FxHashSet<crate::Pid>,
    mapping_processes: Vec<crate::Pid>,
    mapping_process_set: FxHashSet<crate::Pid>,
    definitions_changed: bool,
    kernel_changed: bool,
}

impl std::fmt::Debug for Tail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Tail")
            .field("position", &self.position)
            .field("modules", &self.definitions.modules.len())
            .field("frames", &self.definitions.frames.len())
            .field("samples", &self.sample_count)
            .finish_non_exhaustive()
    }
}

/// Samples and definition changes decoded by one [`Tail::poll`].
///
/// The batch borrows reusable storage from its reader. Dropping it permits the
/// next poll to clear that storage while retaining its capacity.
pub struct TailBatch<'a> {
    tail: &'a Tail,
    modules: Range<usize>,
    frames: Range<usize>,
    python_runtime_records: Range<usize>,
    definitions_changed: bool,
    kernel_changed: bool,
}

impl std::fmt::Debug for TailBatch<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TailBatch")
            .field("samples", &self.tail.samples.len())
            .field("modules", &self.modules.len())
            .field("frames", &self.frames.len())
            .field("python_runtime_records", &self.python_runtime_records.len())
            .field("kernel_changed", &self.kernel_changed)
            .finish()
    }
}

impl Tail {
    /// Open a growing spool and decode its current complete prefix.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-spool error for malformed input, or an I/O category
    /// when the file cannot be opened or mapped.
    pub fn open(path: impl AsRef<Path>) -> crate::Result<Self> {
        Self::open_inner(path).map_err(crate::Error::spool)
    }

    fn open_inner(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        // SAFETY: module paths are copied into owned storage before a remap can
        // release this mapping. The current mapping stays alive for every
        // cursor that borrows it.
        let mmap = Arc::new(unsafe { Mmap::map(&file)? });
        let mut cursor = MmapSpoolCursor::new(Arc::clone(&mmap));
        cursor.check_magic()?;
        let start_timestamp_us = cursor.read_varint::<u64>()?;
        let sample_interval_us = cursor.read_varint::<u64>()?;
        let position = cursor.position;
        let mut tail = Self {
            file,
            mmap,
            position,
            definitions: SpoolDefinitions {
                source_id: next_source_id(),
                start_timestamp_us,
                sample_interval_us,
                modules: Vec::new(),
                frames: Vec::new(),
                frame_contexts: super::SpoolFrameModuleContexts::default(),
                stack_nodes: Vec::new(),
                python_runtime_records: Vec::new(),
                truncated_tail: false,
            },
            threads: Vec::new(),
            last_timestamp_ns: 0,
            first_sample_timestamp_ns: None,
            sample_count: 0,
            samples: Vec::new(),
            initial_samples_pending: true,
            observed_processes: Vec::new(),
            observed_process_set: FxHashSet::default(),
            mapping_processes: Vec::new(),
            mapping_process_set: FxHashSet::default(),
            definitions_changed: false,
            kernel_changed: false,
        };
        tail.parse_available()?;

        // A symbolizer built before the first poll starts from all definitions
        // decoded above. The first batch therefore reports only its samples.
        tail.mapping_processes.clear();
        tail.mapping_process_set.clear();
        tail.definitions_changed = false;
        tail.kernel_changed = false;
        Ok(tail)
    }

    /// Configure a symbolizer bound to this growing spool.
    ///
    /// Call [`crate::Symbolizer::update`] with every batch before resolving
    /// that batch's stacks.
    #[must_use]
    pub fn symbolizer(&self) -> crate::SymbolizerBuilder<'_> {
        crate::SymbolizerBuilder::for_tail(self)
    }

    /// Decode records appended since the previous poll.
    ///
    /// The returned batch borrows storage owned by this reader. A poll with no
    /// appended records performs no allocation once the reader is warm.
    /// Call [`TailBatch::has_more`] to determine whether another complete
    /// batch may already be visible. It does not indicate whether the writer
    /// is still active.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-spool error for malformed appended data. Shrinking or
    /// replacing the file is rejected because tailing supports append only.
    pub fn poll(&mut self) -> crate::Result<TailBatch<'_>> {
        self.poll_inner().map_err(crate::Error::spool)
    }

    fn poll_inner(&mut self) -> io::Result<TailBatch<'_>> {
        let initial = std::mem::take(&mut self.initial_samples_pending);
        let module_start = self.definitions.modules.len();
        let frame_start = self.definitions.frames.len();
        let python_runtime_start = self.definitions.python_runtime_records.len();

        if !initial {
            self.samples.clear();
            self.observed_processes.clear();
            self.observed_process_set.clear();
            self.mapping_processes.clear();
            self.mapping_process_set.clear();
            self.definitions_changed = false;
            self.kernel_changed = false;
            self.remap_if_grown()?;
            self.parse_available()?;
        }

        Ok(TailBatch {
            tail: self,
            modules: module_start..self.definitions.modules.len(),
            frames: frame_start..self.definitions.frames.len(),
            python_runtime_records: python_runtime_start
                ..self.definitions.python_runtime_records.len(),
            definitions_changed: self.definitions_changed,
            kernel_changed: self.kernel_changed,
        })
    }

    /// Return the profile timeline anchor in microseconds.
    #[must_use]
    pub fn start_timestamp_us(&self) -> Option<u64> {
        (self.definitions.start_timestamp_us != 0).then_some(self.definitions.start_timestamp_us)
    }

    /// Return the optional sample interval metadata in microseconds.
    #[must_use]
    pub fn sample_interval_us(&self) -> Option<u64> {
        (self.definitions.sample_interval_us != 0).then_some(self.definitions.sample_interval_us)
    }

    /// Return code areas decoded so far.
    #[must_use]
    pub fn modules(&self) -> &[super::ModuleRecord] {
        &self.definitions.modules
    }

    /// Return frame definitions decoded so far.
    #[must_use]
    pub fn frames(&self) -> &[super::FrameRecord] {
        &self.definitions.frames
    }

    /// Return process and thread identities decoded so far.
    #[must_use]
    pub fn threads(&self) -> &[ThreadRecord] {
        &self.threads
    }

    /// Return Python-runtime status records decoded so far.
    #[must_use]
    pub fn python_runtime_records(&self) -> &[PythonRuntimeRecord] {
        &self.definitions.python_runtime_records
    }

    /// Return the total number of samples decoded across all polls.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.sample_count
    }

    /// Convert a sample timestamp to the profile timeline in microseconds.
    #[must_use]
    pub fn timestamp_us(&self, sample: &SampleRecord) -> Option<u64> {
        let anchor = self.start_timestamp_us()?;
        let first = self
            .first_sample_timestamp_ns
            .unwrap_or(sample.timestamp_ns);
        Some(anchor.saturating_add(sample.timestamp_ns.saturating_sub(first) / 1_000))
    }

    pub(crate) fn source_id(&self) -> u64 {
        self.definitions.source_id
    }

    pub(crate) fn frame_module_contexts(&self) -> super::SpoolFrameModuleContexts {
        self.definitions.frame_contexts.clone()
    }

    fn observe_process(&mut self, process: crate::Pid) {
        if self.observed_process_set.insert(process) {
            self.observed_processes.push(process);
        }
    }

    fn observe_mapping_process(&mut self, process: crate::Pid) {
        self.observe_process(process);
        if self.mapping_process_set.insert(process) {
            self.mapping_processes.push(process);
        }
    }

    fn remap_if_grown(&mut self) -> io::Result<()> {
        let file_len = usize::try_from(self.file.metadata()?.len())
            .map_err(|_| invalid_data("spool file is too large to map"))?;
        if file_len < self.mmap.len() {
            return Err(invalid_data("spool file shrank while being tailed"));
        }
        if file_len > self.mmap.len() {
            // SAFETY: see `open_inner`; decoded paths never borrow an old map.
            self.mmap = Arc::new(unsafe { Mmap::map(&self.file)? });
        }
        Ok(())
    }

    fn parse_available(&mut self) -> io::Result<()> {
        let mut cursor = MmapSpoolCursor::at_position(Arc::clone(&self.mmap), self.position);
        loop {
            let record_start = cursor.position;
            let Some(tag) = cursor.read_tag()? else {
                break;
            };
            let parsed = (|| -> io::Result<()> {
                match tag {
                    REC_MODULE => {
                        let mut module =
                            read_module_mmap(&mut cursor, self.definitions.modules.len())?;
                        module.path = ModulePath::from(module.path.as_str());
                        let process = module.pid();
                        self.kernel_changed |= module.is_kernel();
                        self.definitions.modules.push(module);
                        self.definitions.frame_contexts.push_module();
                        if let Some(process) = process {
                            self.observe_mapping_process(process);
                        }
                        self.definitions_changed = true;
                    }
                    REC_FRAME => {
                        let module_limit = self.definitions.modules.len();
                        let frame = read_frame(
                            &mut cursor,
                            &self.definitions.modules,
                            self.definitions.frames.len(),
                        )?;
                        self.kernel_changed |= frame.mode == super::FrameMode::Kernel;
                        self.definitions.frames.push(frame);
                        self.definitions.frame_contexts.push_frame(module_limit);
                        self.definitions_changed = true;
                    }
                    REC_STACK => self.definitions.stack_nodes.push(read_stack_node(
                        &mut cursor,
                        &self.definitions.stack_nodes,
                        self.definitions.frames.len(),
                    )?),
                    REC_THREAD => self
                        .threads
                        .push(read_thread(&mut cursor, self.threads.len())?),
                    REC_SAMPLE => {
                        let sample = read_sample(
                            &mut cursor,
                            &self.threads,
                            self.definitions.stack_nodes.len(),
                            &mut self.last_timestamp_ns,
                        )?;
                        self.first_sample_timestamp_ns
                            .get_or_insert(sample.timestamp_ns);
                        self.sample_count = self
                            .sample_count
                            .checked_add(1)
                            .ok_or_else(|| invalid_data("sample count exceeds address space"))?;
                        self.observe_process(sample.process_id);
                        self.samples.push(sample);
                    }
                    REC_PYTHON_RUNTIME => {
                        let record = read_python_runtime(&mut cursor)?;
                        self.observe_process(record.process_id);
                        self.definitions.python_runtime_records.push(record);
                    }
                    REC_MODULE_DEACTIVATE => {
                        let process_id = read_process_id(&mut cursor)?;
                        let process = crate::Pid::try_from(process_id)
                            .map_err(|error| invalid_data(error.to_string()))?;
                        self.definitions.frame_contexts.deactivate_process(
                            &self.definitions.modules,
                            process_id,
                            self.definitions.frames.len(),
                        );
                        self.observe_mapping_process(process);
                        self.definitions_changed = true;
                    }
                    REC_MODULE_DEACTIVATE_ONE => {
                        let module_id = read_index_within(
                            &mut cursor,
                            self.definitions.modules.len(),
                            "module deactivation",
                        )?;
                        let process = self.definitions.modules[module_id].pid();
                        self.kernel_changed |= self.definitions.modules[module_id].is_kernel();
                        self.definitions
                            .frame_contexts
                            .deactivate_module(module_id, self.definitions.frames.len());
                        if let Some(process) = process {
                            self.observe_mapping_process(process);
                        }
                        self.definitions_changed = true;
                    }
                    other => return Err(invalid_data(format!("unknown spool record tag {other}"))),
                }
                Ok(())
            })();
            if let Err(error) = parsed {
                if error.kind() == io::ErrorKind::UnexpectedEof && cursor.at_eof() {
                    cursor.position = record_start;
                    break;
                }
                return Err(error);
            }
            self.position = cursor.position;
        }
        Ok(())
    }
}

impl<'a> TailBatch<'a> {
    /// Return samples decoded by this poll.
    #[must_use]
    pub fn samples(&self) -> &[SampleRecord] {
        &self.tail.samples
    }

    /// Iterate over this poll's samples with borrowed raw frames.
    pub fn stacks(&self) -> impl ExactSizeIterator<Item = SampleStack<'a>> + '_ {
        self.tail
            .samples
            .iter()
            .copied()
            .map(|sample| self.tail.definitions.sample_stack(sample))
    }

    /// Return processes observed in samples or definition updates.
    #[must_use]
    pub fn processes(&self) -> &[crate::Pid] {
        &self.tail.observed_processes
    }

    /// Return module definitions added by this poll.
    #[must_use]
    pub fn modules(&self) -> &[super::ModuleRecord] {
        &self.tail.definitions.modules[self.modules.clone()]
    }

    /// Return frame definitions added by this poll.
    #[must_use]
    pub fn frames(&self) -> &[super::FrameRecord] {
        &self.tail.definitions.frames[self.frames.clone()]
    }

    /// Return Python-runtime records added by this poll.
    #[must_use]
    pub fn python_runtime_records(&self) -> &[PythonRuntimeRecord] {
        &self.tail.definitions.python_runtime_records[self.python_runtime_records.clone()]
    }

    /// Convert a sample timestamp to the profile timeline in microseconds.
    #[must_use]
    pub fn timestamp_us(&self, sample: &SampleRecord) -> Option<u64> {
        self.tail.timestamp_us(sample)
    }

    pub(crate) fn source_id(&self) -> u64 {
        self.tail.definitions.source_id
    }

    pub(crate) fn all_modules(&self) -> &[super::ModuleRecord] {
        &self.tail.definitions.modules
    }

    pub(crate) fn all_frames(&self) -> &[super::FrameRecord] {
        &self.tail.definitions.frames
    }

    pub(crate) fn frame_module_contexts(&self) -> super::SpoolFrameModuleContexts {
        self.tail.definitions.frame_contexts.clone()
    }

    pub(crate) fn mapping_processes(&self) -> &[crate::Pid] {
        &self.tail.mapping_processes
    }

    pub(crate) fn definitions_changed(&self) -> bool {
        self.definitions_changed
    }

    pub(crate) fn kernel_changed(&self) -> bool {
        self.kernel_changed
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::spool::{
        FrameMode, FrameRecord, ModulePath, ModuleRecord, PerfSpoolWriter, Snapshot,
    };
    use crate::test_support::TempDir;

    fn module() -> ModuleRecord {
        ModuleRecord::new(
            0,
            crate::Pid::new(7).unwrap(),
            0x1000..0x2000,
            0,
            ModulePath::from("/tmp/test.so"),
        )
        .unwrap()
        .file_identity(0, 0, 1, 0)
    }

    fn frame() -> FrameRecord {
        FrameRecord {
            module_id: Some(0),
            file_relative_ip: 0x10,
            abs_ip: 0x1010,
            mode: FrameMode::User,
        }
    }

    #[test]
    fn polls_flushed_prefixes_and_matches_finished_reader() {
        let dir = TempDir::new("tail-prefixes");
        let path = dir.path().join("recording.spool");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer.flush().unwrap();
        let mut tail = Tail::open(&path).unwrap();
        assert!(tail.poll().unwrap().samples().is_empty());

        writer.write_module(&module()).unwrap();
        writer.write_sample_frames(1_000, 7, 8, [frame()]).unwrap();
        writer.flush().unwrap();
        let first = tail.poll().unwrap();
        assert_eq!(first.samples().len(), 1);
        assert_eq!(first.timestamp_us(&first.samples()[0]), Some(123));

        writer.write_sample_frames(3_000, 7, 8, [frame()]).unwrap();
        writer.flush().unwrap();
        let second = tail.poll().unwrap();
        assert_eq!(second.timestamp_us(&second.samples()[0]), Some(125));
        drop(writer);

        let finished = Snapshot::open(&path).unwrap();
        assert_eq!(tail.modules(), finished.modules());
        assert_eq!(tail.frames(), finished.frames());
        assert_eq!(tail.sample_count(), finished.samples().len());
    }

    #[test]
    fn retries_a_sample_cut_off_mid_record_without_double_delta() {
        let dir = TempDir::new("tail-partial-sample");
        let path = dir.path().join("recording.spool");
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 10).unwrap();
        writer
            .write_sample_frames(
                1_000,
                7,
                8,
                [FrameRecord {
                    module_id: None,
                    file_relative_ip: 0,
                    abs_ip: 0x1010,
                    mode: FrameMode::User,
                }],
            )
            .unwrap();
        let bytes = writer.into_inner();
        let split = bytes.len() - 1;
        std::fs::write(&path, &bytes[..split]).unwrap();

        let mut tail = Tail::open(&path).unwrap();
        assert!(tail.poll().unwrap().samples().is_empty());
        let mut append = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        append.write_all(&bytes[split..]).unwrap();
        append.flush().unwrap();
        let batch = tail.poll().unwrap();
        assert_eq!(batch.samples().len(), 1);
        assert_eq!(batch.samples()[0].timestamp_ns, 1_000);
    }
}
