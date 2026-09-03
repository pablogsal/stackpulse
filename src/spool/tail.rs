use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::native_module::ExactImageStore;

use super::{
    decode_spool_record, invalid_data, next_source_id, DecodedSpoolRecord, MmapSpoolCursor,
    SampleRecord, SampleStack, SpoolDefinitions, ThreadRecord,
};

const MAX_BATCH_SAMPLES: usize = 16 * 1024;

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
    samples: Vec<SampleRecord>,
    initial_samples_pending: bool,
    observed_processes: Vec<crate::Pid>,
    observed_process_set: FxHashSet<crate::Pid>,
    retired_processes: Vec<crate::Pid>,
    retired_modules: Vec<u32>,
    active_modules_by_process: FxHashMap<crate::Pid, Vec<usize>>,
    kernel_mappings_changed: bool,
    more_available: bool,
    exact_images: Option<ExactImageStore>,
}

impl std::fmt::Debug for Tail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Tail")
            .field("position", &self.position)
            .field("modules", &self.definitions.modules.len())
            .field("frames", &self.definitions.frames.len())
            .field("pending_samples", &self.samples.len())
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
}

impl std::fmt::Debug for TailBatch<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TailBatch")
            .field("samples", &self.tail.samples.len())
            .field("modules", &self.modules.len())
            .field("frames", &self.frames.len())
            .field("kernel_mappings_changed", &self.kernel_mappings_changed())
            .finish()
    }
}

impl Tail {
    /// Open a growing spool and decode its current complete prefix.
    ///
    /// The writer must flush the spool header before this call.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-spool error for malformed input, or an I/O category
    /// when the file cannot be opened or mapped.
    pub fn open(path: impl AsRef<Path>) -> crate::Result<Self> {
        Self::open_inner(path).map_err(crate::Error::spool)
    }

    fn open_inner(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::from_file_inner(File::open(path)?, None)
    }

    pub(crate) fn from_file(file: File, exact_images: ExactImageStore) -> crate::Result<Self> {
        Self::from_file_inner(file, Some(exact_images)).map_err(crate::Error::spool)
    }

    fn from_file_inner(file: File, exact_images: Option<ExactImageStore>) -> io::Result<Self> {
        // SAFETY: the spool's existing bytes remain immutable under Tail's
        // append-only contract. Each cursor retains its mapping, and decoded
        // module paths are copied before a remap can release the old one.
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
            samples: Vec::new(),
            initial_samples_pending: true,
            observed_processes: Vec::new(),
            observed_process_set: FxHashSet::default(),
            retired_processes: Vec::new(),
            retired_modules: Vec::new(),
            active_modules_by_process: FxHashMap::default(),
            kernel_mappings_changed: false,
            more_available: false,
            exact_images,
        };
        tail.more_available = tail.parse_available()?;

        // A symbolizer built before the first poll starts from all definitions
        // decoded above. Mapping additions therefore need no update, while
        // retirements remain in the first batch so their resources can be
        // released after its historical samples are resolved.
        tail.kernel_mappings_changed = false;
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
    /// The first poll returns samples that were already complete when the tail
    /// was opened. Later polls return only newly appended samples.
    ///
    /// The returned batch borrows storage owned by this reader. A poll with no
    /// appended records performs no allocation once the reader is warm.
    /// Call [`TailBatch::has_more`] to determine whether another complete
    /// batch may already be visible. It does not indicate whether the writer
    /// is still active.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-spool error for malformed appended data. Shrinking
    /// the opened file is rejected because tailing supports append only.
    pub fn poll(&mut self) -> crate::Result<TailBatch<'_>> {
        self.poll_inner().map_err(crate::Error::spool)
    }

    fn poll_inner(&mut self) -> io::Result<TailBatch<'_>> {
        let initial = std::mem::take(&mut self.initial_samples_pending);
        let module_start = self.definitions.modules.len();
        let frame_start = self.definitions.frames.len();

        if initial {
            let mapped_len = self.mmap.len();
            self.remap_if_grown()?;
            self.more_available |= self.mmap.len() > mapped_len;
        } else {
            self.samples.clear();
            self.observed_processes.clear();
            self.observed_process_set.clear();
            self.retired_processes.clear();
            self.retired_modules.clear();
            self.kernel_mappings_changed = false;
            self.remap_if_grown()?;
            self.more_available = self.parse_available()?;
        }

        Ok(TailBatch {
            tail: self,
            modules: module_start..self.definitions.modules.len(),
            frames: frame_start..self.definitions.frames.len(),
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

    pub(crate) fn modules(&self) -> &[super::ModuleRecord] {
        &self.definitions.modules
    }

    pub(crate) fn frames(&self) -> &[super::FrameRecord] {
        &self.definitions.frames
    }

    fn timestamp_us(&self, sample: &SampleRecord) -> Option<u64> {
        let anchor = self.start_timestamp_us()?;
        let first = self
            .first_sample_timestamp_ns
            .unwrap_or(sample.timestamp_ns);
        Some(anchor.saturating_add(sample.timestamp_ns.saturating_sub(first) / 1_000))
    }

    pub(crate) fn source_id(&self) -> u64 {
        self.definitions.source_id
    }

    pub(crate) fn exact_images(&self) -> Option<ExactImageStore> {
        self.exact_images.clone()
    }

    pub(crate) fn frame_module_contexts(&self) -> super::SpoolFrameModuleContexts {
        self.definitions.frame_contexts.clone()
    }

    fn observe_process(&mut self, process: crate::Pid) {
        if self.observed_processes.last() != Some(&process)
            && self.observed_process_set.insert(process)
        {
            self.observed_processes.push(process);
        }
    }

    fn remap_if_grown(&mut self) -> io::Result<()> {
        let file_len = usize::try_from(self.file.metadata()?.len())
            .map_err(|_| invalid_data("spool file is too large to map"))?;
        if file_len < self.mmap.len() {
            return Err(invalid_data("spool file shrank while being tailed"));
        }
        if file_len > self.mmap.len() {
            // SAFETY: see `open_inner`; the mapped prefix is immutable and
            // decoded paths never borrow an old mapping.
            self.mmap = Arc::new(unsafe { Mmap::map(&self.file)? });
        }
        Ok(())
    }

    fn parse_available(&mut self) -> io::Result<bool> {
        let mut cursor = MmapSpoolCursor::at_position(Arc::clone(&self.mmap), self.position);
        loop {
            let record = match decode_spool_record(
                &mut cursor,
                &self.definitions.modules,
                self.definitions.frames.len(),
                &self.definitions.stack_nodes,
                &self.threads,
                &mut self.last_timestamp_ns,
            ) {
                Ok(Some(record)) => record,
                Ok(None) => break,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && cursor.at_eof() => {
                    break;
                }
                Err(error) => return Err(error),
            };
            let ends_batch = matches!(
                &record,
                DecodedSpoolRecord::DeactivateProcess(_) | DecodedSpoolRecord::DeactivateModule(_)
            );
            match record {
                DecodedSpoolRecord::Module(module) => {
                    let process = module.pid();
                    let module_index = self.definitions.modules.len();
                    self.kernel_mappings_changed |= module.is_kernel();
                    self.definitions.modules.push(module);
                    self.definitions.frame_contexts.push_module();
                    if let Some(process) = process {
                        self.active_modules_by_process
                            .entry(process)
                            .or_default()
                            .push(module_index);
                        self.observe_process(process);
                    }
                }
                DecodedSpoolRecord::Frame(frame) => {
                    let module_limit = self.definitions.modules.len();
                    self.definitions.frames.push(frame);
                    self.definitions.frame_contexts.push_frame(module_limit);
                }
                DecodedSpoolRecord::Stack(stack) => self.definitions.stack_nodes.push(stack),
                DecodedSpoolRecord::Thread(thread) => self.threads.push(thread),
                DecodedSpoolRecord::Sample(sample) => {
                    self.first_sample_timestamp_ns
                        .get_or_insert(sample.timestamp_ns);
                    self.observe_process(sample.process_id);
                    self.samples.push(sample);
                }
                DecodedSpoolRecord::PythonRuntime(record) => {
                    self.observe_process(record.process_id);
                }
                DecodedSpoolRecord::DeactivateProcess(process_id) => {
                    for module_index in self
                        .active_modules_by_process
                        .remove(&process_id)
                        .unwrap_or_default()
                    {
                        self.retired_modules
                            .push(self.definitions.modules[module_index].id);
                        self.definitions
                            .frame_contexts
                            .deactivate_module(module_index, self.definitions.frames.len());
                    }
                    self.observe_process(process_id);
                    self.retired_processes.push(process_id);
                }
                DecodedSpoolRecord::DeactivateModule(module_id) => {
                    let module = &self.definitions.modules[module_id];
                    let process = module.pid();
                    self.retired_modules.push(module.id);
                    self.kernel_mappings_changed |= module.is_kernel();
                    self.definitions
                        .frame_contexts
                        .deactivate_module(module_id, self.definitions.frames.len());
                    if let Some(process) = process {
                        if let Some(modules) = self.active_modules_by_process.get_mut(&process) {
                            modules.retain(|&active| active != module_id);
                            if modules.is_empty() {
                                self.active_modules_by_process.remove(&process);
                            }
                        }
                        self.observe_process(process);
                    }
                }
            }
            self.position = cursor.position;
            if self.samples.len() == MAX_BATCH_SAMPLES || ends_batch {
                return Ok(self.position < self.mmap.len());
            }
        }
        Ok(false)
    }
}

impl<'a> TailBatch<'a> {
    #[cfg(test)]
    pub(crate) fn samples(&self) -> &[SampleRecord] {
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

    /// Return the process IDs observed in this batch.
    ///
    /// IDs are deduplicated in first-seen order and include sample, module,
    /// Python-runtime, and mapping-retirement records.
    #[must_use]
    pub fn processes(&self) -> &[crate::Pid] {
        &self.tail.observed_processes
    }

    /// Return whether another poll can decode an already-visible batch.
    ///
    /// Consumers should poll again without waiting when this is true. This
    /// keeps each sample batch bounded when the writer gets ahead.
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.tail.more_available
    }

    pub(crate) fn modules(&self) -> &[super::ModuleRecord] {
        &self.tail.definitions.modules[self.modules.clone()]
    }

    pub(crate) fn frames(&self) -> &[super::FrameRecord] {
        &self.tail.definitions.frames[self.frames.clone()]
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

    pub(crate) fn retired_processes(&self) -> &[crate::Pid] {
        &self.tail.retired_processes
    }

    pub(crate) fn retired_modules(&self) -> &[u32] {
        &self.tail.retired_modules
    }

    pub(crate) fn frame_contexts_changed(&self) -> bool {
        !self.modules.is_empty() || !self.frames.is_empty() || !self.tail.retired_modules.is_empty()
    }

    pub(crate) fn kernel_mappings_changed(&self) -> bool {
        self.tail.kernel_mappings_changed
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

    fn assert_no_invalidation(invalidation: crate::symbolize::Invalidation<'_>) {
        assert!(!invalidation.all());
        assert!(invalidation.processes().next().is_none());
    }

    #[test]
    fn polls_flushed_prefixes_and_matches_finished_reader() {
        let dir = TempDir::new("tail-prefixes");
        let path = dir.path().join("recording.spool");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer.flush().unwrap();
        let mut tail = Tail::open(&path).unwrap();
        assert!(format!("{tail:?}").contains("pending_samples: 0"));
        assert_eq!(tail.start_timestamp_us(), Some(123));
        assert_eq!(tail.sample_interval_us(), Some(10));
        let mut symbolizer = tail
            .symbolizer()
            .disable_perf_maps()
            .stack_cache(crate::StackCache::External)
            .build()
            .unwrap();
        let initial = tail.poll().unwrap();
        assert!(initial.samples().is_empty());
        assert!(!initial.has_more());
        assert!(initial.processes().is_empty());
        let other_tail = Tail::open(&path).unwrap();
        let mut other_symbolizer = other_tail.symbolizer().build().unwrap();
        let error = other_symbolizer
            .update(&initial)
            .err()
            .expect("a symbolizer must reject batches from another tail");
        assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
        assert_no_invalidation(symbolizer.update(&initial).unwrap());

        writer.write_module(&module()).unwrap();
        writer.write_sample_frames(1_000, 7, 8, [frame()]).unwrap();
        writer.write_python_runtime(1_500, 9, true).unwrap();
        writer.flush().unwrap();
        let first = tail.poll().unwrap();
        assert!(format!("{first:?}").contains("samples: 1"));
        assert_eq!(first.samples().len(), 1);
        assert_eq!(
            first.processes(),
            &[crate::Pid::new(7).unwrap(), crate::Pid::new(9).unwrap()]
        );
        assert_eq!(first.timestamp_us(&first.samples()[0]), Some(123));
        assert!(!symbolizer.update(&first).unwrap().all());
        let native_backend = symbolizer.has_native_backend();
        let mut stack = symbolizer.resolve(first.stacks().next().unwrap()).unwrap();
        assert_eq!(stack.is_cacheable(), !native_backend);
        assert!(stack.next_with_id().is_some());
        assert!(stack.next().is_none());

        writer.write_sample_frames(3_000, 7, 8, [frame()]).unwrap();
        writer.write_module_deactivation(7).unwrap();
        writer.flush().unwrap();
        let second = tail.poll().unwrap();
        assert_eq!(second.timestamp_us(&second.samples()[0]), Some(125));
        symbolizer.update(&second).unwrap();
        assert_eq!(
            symbolizer
                .resolve(second.stacks().next().unwrap())
                .unwrap()
                .len(),
            1
        );

        let after_retirement = tail.poll().unwrap();
        let invalidation = symbolizer.update(&after_retirement).unwrap();
        let pid = crate::Pid::new(7).unwrap();
        assert_eq!(invalidation.processes().collect::<Vec<_>>(), vec![pid]);
        assert!(invalidation.affects_process(pid));
        drop(writer);

        let finished = Snapshot::open(&path).unwrap();
        assert_eq!(tail.modules(), finished.modules());
        assert_eq!(tail.frames(), finished.frames());
        assert_eq!(finished.samples().len(), 2);
        assert_eq!(finished.python_runtime_records().len(), 1);

        let mut append = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        append.write_all(&[u8::MAX]).unwrap();
        append.flush().unwrap();
        let error = tail.poll().unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::CorruptSpool);
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
        {
            let batch = tail.poll().unwrap();
            let mut stacks = batch.stacks();
            let stack = stacks.next().expect("expected one sample");
            assert!(stacks.next().is_none());
            assert_eq!(stack.sample().timestamp_ns, 1_000);
        }

        append.set_len(8).unwrap();
        let error = tail.poll().unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::CorruptSpool);
    }
}
