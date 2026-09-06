use std::ops::Deref;
use std::path::PathBuf;
use std::time::Duration;

use rustc_hash::FxHashMap;

use crate::spool::{LiveReader, ReadStatus, Sample, Stack, StackKey, TailBatch};
use crate::{Pid, Result};

use super::{
    Invalidation, KernelSymbolSource, NativeSymbolizer, ResolvedStack, StackCache, Symbolizer,
    SymbolizerBuilder, SymbolizerInput,
};

#[must_use]
#[derive(Debug)]
/// Configures symbolization while reserving exclusive access to a live reader.
pub struct SessionBuilder<'reader> {
    reader: &'reader mut LiveReader,
    options: SymbolizerBuilder<'static>,
}

impl LiveReader {
    /// Configure a session that returns this reader's samples with current symbols.
    pub fn symbolizer(&mut self) -> SessionBuilder<'_> {
        SessionBuilder {
            reader: self,
            options: SymbolizerBuilder::for_modules(&[]),
        }
    }
}

impl<'reader> SessionBuilder<'reader> {
    /// Resolve user frames without consulting process perf-map files.
    pub fn disable_perf_maps(mut self) -> Self {
        self.options = self.options.disable_perf_maps();
        self
    }

    /// Limit perf-map lookups to the supplied processes.
    pub fn perf_maps_for(mut self, processes: impl IntoIterator<Item = Pid>) -> Self {
        self.options = self.options.perf_maps_for(processes);
        self
    }

    /// Locate process perf maps in this directory instead of `/tmp`.
    pub fn perf_map_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        self.options = self.options.perf_map_dir(directory);
        self
    }

    /// Construct a native backend lazily for each process that needs one.
    pub fn native<S>(mut self, factory: impl FnMut(Pid) -> S + 'static) -> Self
    where
        S: NativeSymbolizer + 'static,
    {
        self.options = self.options.native(factory);
        self
    }

    /// Construct process backends lazily, allowing a failed construction to retry.
    pub fn try_native<S, E>(
        mut self,
        factory: impl FnMut(Pid) -> std::result::Result<S, E> + 'static,
    ) -> Self
    where
        S: NativeSymbolizer + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.options = self.options.try_native(factory);
        self
    }

    /// Choose matching kernel symbols or disable kernel symbol resolution.
    pub fn kernel_symbols(mut self, source: KernelSymbolSource) -> Self {
        self.options = self.options.kernel_symbols(source);
        self
    }

    /// Build the session without advancing the reader.
    ///
    /// Construction errors release the reader for another attempt or recovery.
    pub fn build(self) -> Result<Session<'reader>> {
        let symbolizer = SymbolizerBuilder {
            input: SymbolizerInput::Spool(self.reader.tail()),
            ..self.options
        }
        .build()?;
        Ok(Session {
            reader: self.reader,
            symbolizer,
        })
    }
}

/// Exclusively borrows a live reader while maintaining its symbol sources.
#[derive(Debug)]
pub struct Session<'reader> {
    reader: &'reader mut LiveReader,
    symbolizer: Symbolizer,
}

impl<'reader> Session<'reader> {
    /// Observe publication backlog, reclamation, and retained definitions.
    pub fn stats(&self) -> crate::spool::ReaderStats {
        self.reader.stats()
    }

    /// Retain up to `capacity` caller-produced values, with automatic invalidation.
    ///
    /// Zero capacity disables retention. A full cache is cleared on insertion
    /// of another stable value; this does not reset any caller-owned arena.
    pub fn cache_stacks<T>(mut self, capacity: usize) -> CachedSession<'reader, T> {
        self.symbolizer.stack_cache_mode = StackCache::External;
        self.symbolizer.clear_stack_resolution_cache();
        CachedSession {
            session: self,
            cache: TransformedStacks::new(capacity),
        }
    }

    /// Wait for a published batch and apply its symbol-source changes once.
    ///
    /// A refresh failure leaves the next published batch available for retry.
    /// The preceding batch and its samples must be released before advancing.
    ///
    /// ```compile_fail
    /// use std::time::Duration;
    /// use stackpulse::spool::{LiveReader, ReadStatus};
    ///
    /// fn overlapping_batches(reader: &mut LiveReader) -> stackpulse::Result<()> {
    ///     let mut session = reader.symbolizer().build()?;
    ///     let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO)? else {
    ///         return Ok(());
    ///     };
    ///     let sample = batch.samples().next().unwrap();
    ///     let next = session.poll(Duration::ZERO)?;
    ///     batch.resolve(sample.stack())?;
    ///     Ok(())
    /// }
    /// ```
    pub fn poll(&mut self, timeout: Duration) -> Result<ReadStatus<LiveBatch<'_>>> {
        self.symbolizer.refresh_native_sources()?;
        match self.reader.poll(timeout)? {
            ReadStatus::Batch(batch) => {
                let invalidation = self.symbolizer.update(&batch)?;
                let invalidated_all = invalidation.all();
                Ok(ReadStatus::Batch(LiveBatch {
                    batch,
                    symbolizer: &mut self.symbolizer,
                    invalidated_all,
                }))
            }
            ReadStatus::Pending => Ok(ReadStatus::Pending),
            ReadStatus::Finished(summary) => Ok(ReadStatus::Finished(summary)),
        }
    }
}

/// A batch keeps its source storage and symbolizer borrowed until released.
#[derive(Debug)]
pub struct LiveBatch<'batch> {
    batch: TailBatch<'batch>,
    symbolizer: &'batch mut Symbolizer,
    invalidated_all: bool,
}

impl<'batch> LiveBatch<'batch> {
    /// Iterate samples without borrowing the batch's mutable resolver.
    pub fn samples(&self) -> impl ExactSizeIterator<Item = Sample<'batch>> + 'batch {
        self.batch.samples()
    }

    /// Borrow the processes observed in this batch's samples and lifecycle records.
    pub fn processes(&self) -> &[Pid] {
        self.batch.processes()
    }

    /// Resolve a stack from this source, borrowing reusable resolution storage.
    pub fn resolve(&mut self, stack: Stack<'batch>) -> Result<ResolvedStack<'_>> {
        self.symbolizer.resolve(stack)
    }

    fn invalidation(&self) -> Invalidation<'_> {
        Invalidation {
            all: self.invalidated_all,
            processes: &self.symbolizer.invalidated_process_ids,
        }
    }
}

/// Maintains bounded caller-produced stack values across live batches.
///
/// Clearing these values does not release resources owned by a caller's arena.
#[derive(Debug)]
pub struct CachedSession<'reader, T> {
    session: Session<'reader>,
    cache: TransformedStacks<T>,
}

impl<T> CachedSession<'_, T> {
    /// Observe publication backlog, reclamation, and retained definitions.
    pub fn stats(&self) -> crate::spool::ReaderStats {
        self.session.stats()
    }

    /// Advance the session and invalidate affected transformed values automatically.
    pub fn poll(&mut self, timeout: Duration) -> Result<ReadStatus<CachedBatch<'_, T>>> {
        match self.session.poll(timeout)? {
            ReadStatus::Batch(batch) => {
                self.cache.invalidate(&batch.invalidation());
                Ok(ReadStatus::Batch(CachedBatch {
                    batch,
                    cache: &mut self.cache,
                }))
            }
            ReadStatus::Pending => Ok(ReadStatus::Pending),
            ReadStatus::Finished(summary) => Ok(ReadStatus::Finished(summary)),
        }
    }

    /// Release cached values without resetting resources in a caller-owned arena.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

#[derive(Debug)]
/// A published batch with exclusive access to its transformed-stack cache.
pub struct CachedBatch<'batch, T> {
    batch: LiveBatch<'batch>,
    cache: &'batch mut TransformedStacks<T>,
}

impl<'batch, T> CachedBatch<'batch, T> {
    /// Iterate samples while permitting cache lookups and resolution through the batch.
    pub fn samples(&self) -> impl ExactSizeIterator<Item = Sample<'batch>> + 'batch {
        self.batch.samples()
    }

    /// Borrow the processes observed in this batch's samples and lifecycle records.
    pub fn processes(&self) -> &[Pid] {
        self.batch.processes()
    }

    /// Look up a transformed stack without resolving frames on a cache hit.
    ///
    /// A foreign source is rejected before accessing the cache. Dropping a
    /// vacant or resolved entry does not insert a value.
    pub fn entry<'entry>(
        &'entry mut self,
        stack: Stack<'batch>,
    ) -> Result<StackEntry<'entry, 'batch, T>> {
        if self.batch.symbolizer.source_id != Some(stack.key().source_id()) {
            return Err(crate::Error::message(
                crate::ErrorKind::InvalidInput,
                "stack belongs to a different spool source",
            ));
        }
        if let Some(index) = self.cache.indices.get(&stack.key()).copied() {
            let value = &self.cache.values[index].1;
            return Ok(StackEntry::Occupied(value));
        }
        Ok(StackEntry::Vacant(VacantStack {
            stack,
            symbolizer: self.batch.symbolizer,
            cache: self.cache,
        }))
    }

    /// Release cached handles before resetting their caller-owned arena.
    ///
    /// An outstanding entry must first release its borrows.
    ///
    /// ```compile_fail
    /// use std::time::Duration;
    /// use stackpulse::spool::{LiveReader, ReadStatus};
    /// use stackpulse::symbolize::StackEntry;
    ///
    /// fn reset_with_live_entry(reader: &mut LiveReader) -> stackpulse::Result<()> {
    ///     let mut session = reader.symbolizer().build()?.cache_stacks::<usize>(4);
    ///     let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO)? else {
    ///         return Ok(());
    ///     };
    ///     let sample = batch.samples().next().unwrap();
    ///     let entry = batch.entry(sample.stack())?;
    ///     batch.clear_cache();
    ///     if let StackEntry::Vacant(entry) = entry {
    ///         entry.resolve()?.insert(1);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

#[derive(Debug)]
/// Either a retained transformed value or an unresolved cache miss.
pub enum StackEntry<'entry, 'batch, T> {
    /// A value retained from an earlier stable resolution.
    Occupied(&'entry T),
    /// A stack that must be resolved before a transformed value can be inserted.
    Vacant(VacantStack<'entry, 'batch, T>),
}

#[derive(Debug)]
/// Reserves the raw stack and resolver while the caller decides whether to prepare it.
pub struct VacantStack<'entry, 'batch, T> {
    stack: Stack<'batch>,
    symbolizer: &'entry mut Symbolizer,
    cache: &'entry mut TransformedStacks<T>,
}

impl<'entry, 'batch, T> VacantStack<'entry, 'batch, T> {
    /// Release the entry's borrows so its caller can reset a collector arena.
    pub fn into_stack(self) -> Stack<'batch> {
        self.stack
    }

    /// Resolve this miss while preserving its identity and insertion eligibility.
    pub fn resolve(self) -> Result<ResolvedEntry<'entry, T>> {
        let key = self.stack.key();
        let frames = self.symbolizer.resolve(self.stack)?;
        Ok(ResolvedEntry {
            frames,
            key,
            cache: self.cache,
        })
    }
}

#[derive(Debug)]
/// Holds a resolved miss until its caller inserts a value or rejects the sample.
pub struct ResolvedEntry<'entry, T> {
    frames: ResolvedStack<'entry>,
    key: StackKey,
    cache: &'entry mut TransformedStacks<T>,
}

impl<'entry, T> ResolvedEntry<'entry, T> {
    /// Borrow the complete resolved collection, including its frame cache keys.
    pub fn stack(&self) -> &ResolvedStack<'entry> {
        &self.frames
    }

    /// Provisional results remain owned by the returned guard and are not cached.
    pub fn insert(self, value: T) -> StackValue<'entry, T> {
        if self.frames.is_cacheable() && self.cache.capacity != 0 {
            StackValue::Cached(self.cache.insert(self.key, value))
        } else {
            StackValue::Transient(value)
        }
    }
}

#[derive(Debug)]
/// A transformed value borrowed from the cache or owned for this lookup only.
pub enum StackValue<'entry, T> {
    /// A stable value retained by the session.
    Cached(&'entry T),
    /// A provisional value, or a value produced with cache retention disabled.
    Transient(T),
}

impl<T> Deref for StackValue<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Cached(value) => value,
            Self::Transient(value) => value,
        }
    }
}

impl<T> AsRef<T> for StackValue<'_, T> {
    fn as_ref(&self) -> &T {
        self
    }
}

#[derive(Debug)]
struct TransformedStacks<T> {
    indices: FxHashMap<StackKey, usize>,
    values: Vec<(StackKey, T)>,
    capacity: usize,
}

impl<T> TransformedStacks<T> {
    fn new(capacity: usize) -> Self {
        Self {
            indices: FxHashMap::default(),
            values: Vec::new(),
            capacity,
        }
    }

    fn insert(&mut self, key: StackKey, value: T) -> &T {
        if self.indices.len() == self.capacity {
            self.clear();
        }
        let index = self.values.len();
        self.values.push((key, value));
        self.indices.insert(key, index);
        &self.values[index].1
    }

    fn invalidate(&mut self, invalidation: &Invalidation<'_>) {
        if invalidation.all() {
            self.clear();
        } else if invalidation.processes().next().is_some() {
            let mut index = 0;
            while index < self.values.len() {
                let key = self.values[index].0;
                if invalidation.affects_process(key.process_id()) {
                    self.indices.remove(&key);
                    let removed = self.values.swap_remove(index);
                    if let Some((moved, _)) = self.values.get(index) {
                        self.indices.insert(*moved, index);
                    }
                    drop(removed);
                } else {
                    index += 1;
                }
            }
        }
    }

    fn clear(&mut self) {
        self.indices.clear();
        self.values.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs::File;
    use std::io::BufWriter;
    use std::rc::Rc;

    use crate::native_module::ExactImageStore;
    use crate::spool::{FrameMode, FrameRecord, PerfSpoolWriter, Publisher};
    use crate::symbolize::NativeBatch;
    use crate::test_support::TempDir;

    use super::*;

    type Writer = PerfSpoolWriter<BufWriter<File>>;

    struct RefreshBackend {
        fail: Rc<Cell<bool>>,
        generation: Rc<Cell<u64>>,
    }

    impl NativeSymbolizer for RefreshBackend {
        type Error = std::io::Error;

        fn symbolize(&mut self, _batch: NativeBatch<'_>) -> std::io::Result<()> {
            Ok(())
        }

        fn refresh(&mut self) -> std::io::Result<u64> {
            if self.fail.replace(false) {
                Err(std::io::Error::other("temporary refresh failure"))
            } else {
                Ok(self.generation.get())
            }
        }
    }

    fn write_sample(writer: &mut Writer, timestamp: u64, pid: i32, address: u64) {
        writer
            .write_sample_frames(
                timestamp,
                pid,
                pid as u64,
                [FrameRecord {
                    module_id: None,
                    file_relative_ip: address,
                    abs_ip: address,
                    mode: FrameMode::User,
                }],
            )
            .unwrap();
    }

    fn publish(writer: &mut Writer, publisher: &Publisher) {
        writer.flush().unwrap();
        publisher.publish(writer.position());
    }

    fn fixture(samples: &[(i32, u64)]) -> (TempDir, Writer, Publisher, LiveReader) {
        let directory = TempDir::new("symbolize-session");
        let path = directory.path().join("recording.spool");
        let mut writer = PerfSpoolWriter::create(path, 1, 10).unwrap();
        for (index, &(pid, address)) in samples.iter().enumerate() {
            write_sample(&mut writer, index as u64 + 1, pid, address);
        }
        let publisher = Publisher::new();
        publish(&mut writer, &publisher);
        let reader = LiveReader::new(
            writer.open_reader().unwrap(),
            None,
            ExactImageStore::default(),
            publisher.clone(),
        )
        .unwrap();
        (directory, writer, publisher, reader)
    }

    fn cached(reader: &mut LiveReader, capacity: usize) -> CachedSession<'_, usize> {
        reader
            .symbolizer()
            .disable_perf_maps()
            .kernel_symbols(KernelSymbolSource::Disabled)
            .build()
            .unwrap()
            .cache_stacks(capacity)
    }

    #[test]
    fn rejected_miss_remains_available_and_accepted_stack_is_reused() {
        let (_directory, _writer, _publisher, mut reader) =
            fixture(&[(100, 0x1000), (100, 0x1000), (100, 0x1000)]);
        let mut session = cached(&mut reader, 4);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("published samples produce a batch");
        };
        let mut samples = batch.samples();
        let first = samples.next().unwrap();
        let StackEntry::Vacant(entry) = batch.entry(first.stack()).unwrap() else {
            panic!("the first stack has not been prepared");
        };
        let resolved = entry.resolve().unwrap();
        assert_eq!(resolved.stack().len(), 1);

        let second = samples.next().unwrap();
        let StackEntry::Vacant(entry) = batch.entry(second.stack()).unwrap() else {
            panic!("rejecting a sample does not insert a prepared stack");
        };
        let value = entry.resolve().unwrap().insert(17);
        assert!(matches!(value, StackValue::Cached(&17)));
        assert_eq!(*value, 17);
        let third = samples.next().unwrap();
        let value = match batch.entry(third.stack()).unwrap() {
            StackEntry::Occupied(value) => value,
            StackEntry::Vacant(_) => panic!("the accepted stack is retained"),
        };
        assert_eq!(*value, 17);
    }

    #[test]
    fn capacity_is_bounded_and_zero_capacity_returns_owned_values() {
        let (_directory, _writer, _publisher, mut reader) =
            fixture(&[(100, 0x1000), (100, 0x2000), (100, 0x3000), (100, 0x1000)]);
        let mut session = cached(&mut reader, 2);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("published samples produce a batch");
        };
        for (index, sample) in batch.samples().enumerate() {
            let StackEntry::Vacant(entry) = batch.entry(sample.stack()).unwrap() else {
                panic!("capacity rollover removed the original stack");
            };
            assert_eq!(*entry.resolve().unwrap().insert(index), index);
            assert!(batch.cache.indices.len() <= 2);
            assert!(batch.cache.values.len() <= 2);
        }

        let (_directory, _writer, _publisher, mut reader) =
            fixture(&[(100, 0x1000), (100, 0x1000)]);
        let mut session = cached(&mut reader, 0);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("published samples produce a batch");
        };
        for sample in batch.samples() {
            let StackEntry::Vacant(entry) = batch.entry(sample.stack()).unwrap() else {
                panic!("zero capacity does not retain values");
            };
            let value = entry.resolve().unwrap().insert(23);
            assert!(matches!(value, StackValue::Transient(23)));
            assert_eq!(*value, 23);
        }
        assert!(batch.cache.indices.is_empty());
        assert!(batch.cache.values.is_empty());
    }

    #[test]
    fn vacant_entry_can_release_borrows_for_collector_reset() {
        let (_directory, _writer, _publisher, mut reader) =
            fixture(&[(100, 0x1000), (100, 0x2000)]);
        let mut session = cached(&mut reader, 2);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("published samples produce a batch");
        };
        let mut samples = batch.samples();
        let first = samples.next().unwrap();
        let StackEntry::Vacant(entry) = batch.entry(first.stack()).unwrap() else {
            panic!("the first stack has not been prepared");
        };
        entry.resolve().unwrap().insert(7);
        let second = samples.next().unwrap();
        let StackEntry::Vacant(entry) = batch.entry(second.stack()).unwrap() else {
            panic!("the second stack has not been prepared");
        };
        let stack = entry.into_stack();
        batch.clear_cache();
        assert!(batch.cache.indices.is_empty());
        let StackEntry::Vacant(entry) = batch.entry(stack).unwrap() else {
            panic!("reset permits preparation of the retained raw stack");
        };
        assert_eq!(*entry.resolve().unwrap().insert(9), 9);
    }

    #[test]
    fn perf_map_changes_automatically_invalidate_only_the_owning_process() {
        let stacks = [
            (100, 0x1000),
            (101, 0x2000),
            (100, 0x1001),
            (102, 0x3000),
            (100, 0x1002),
        ];
        let (directory, mut writer, publisher, mut reader) = fixture(&stacks);
        let map = directory.path().join("perf-100.map");
        std::fs::write(&map, "1000 10 before\n").unwrap();
        let mut session = reader
            .symbolizer()
            .perf_map_dir(directory.path())
            .kernel_symbols(KernelSymbolSource::Disabled)
            .build()
            .unwrap()
            .cache_stacks(stacks.len());
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("published samples produce a batch");
        };
        for sample in batch.samples() {
            let StackEntry::Vacant(entry) = batch.entry(sample.stack()).unwrap() else {
                panic!("the initial stacks have not been prepared");
            };
            entry.resolve().unwrap().insert(sample.pid());
        }
        std::fs::write(&map, "1000 10 changed-name\n").unwrap();
        for (index, &(pid, address)) in stacks.iter().enumerate() {
            write_sample(&mut writer, 6 + index as u64, pid, address);
        }
        publish(&mut writer, &publisher);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("newly published samples produce a batch");
        };
        assert_eq!(batch.cache.indices.len(), 2);
        assert_eq!(batch.cache.values.len(), 2);
        for sample in batch.samples() {
            if sample.pid().get() == 100 {
                let StackEntry::Vacant(entry) = batch.entry(sample.stack()).unwrap() else {
                    panic!("the changed perf map invalidates its prepared stacks");
                };
                let resolved = entry.resolve().unwrap();
                assert_eq!(
                    resolved.stack().frames().next().unwrap().name(),
                    Some("changed-name")
                );
                resolved.insert(sample.pid());
            } else {
                let StackEntry::Occupied(value) = batch.entry(sample.stack()).unwrap() else {
                    panic!("another process retains its prepared stack");
                };
                assert_eq!(*value, sample.pid());
            }
        }
        assert_eq!(batch.cache.values.len(), stacks.len());
    }

    #[test]
    fn retirement_is_applied_after_the_previous_batch_is_released() {
        let (_directory, mut writer, publisher, mut reader) = fixture(&[(100, 0x1000)]);
        let mut session = cached(&mut reader, 2);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("published samples produce a batch");
        };
        let sample = batch.samples().next().unwrap();
        let StackEntry::Vacant(entry) = batch.entry(sample.stack()).unwrap() else {
            panic!("the initial stack has not been prepared");
        };
        entry.resolve().unwrap().insert(7);
        write_sample(&mut writer, 2, 100, 0x1000);
        writer.write_module_deactivation(100).unwrap();
        write_sample(&mut writer, 3, 100, 0x1000);
        publish(&mut writer, &publisher);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("the retirement batch contains a historical sample");
        };
        let sample = batch.samples().next().unwrap();
        assert!(matches!(
            batch.entry(sample.stack()).unwrap(),
            StackEntry::Occupied(_)
        ));
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("the following batch contains a new sample");
        };
        assert!(batch.cache.indices.is_empty());
        let sample = batch.samples().next().unwrap();
        assert!(matches!(
            batch.entry(sample.stack()).unwrap(),
            StackEntry::Vacant(_)
        ));
    }

    #[test]
    fn failed_builder_and_finished_session_release_the_reader() {
        let (directory, writer, publisher, mut reader) = fixture(&[(100, 0x1000)]);
        let failed = reader
            .symbolizer()
            .kernel_symbols(KernelSymbolSource::File(directory.path().join("missing")))
            .build();
        assert!(failed.is_err());
        drop(failed);
        let mut session = cached(&mut reader, 1);
        assert!(matches!(
            session.poll(Duration::ZERO).unwrap(),
            ReadStatus::Batch(_)
        ));
        assert!(matches!(
            session.poll(Duration::ZERO).unwrap(),
            ReadStatus::Pending
        ));
        publisher.finish(writer.position(), crate::RecordingSummary::default());
        assert!(matches!(
            session.poll(Duration::ZERO).unwrap(),
            ReadStatus::Finished(_)
        ));
        drop(session);
        assert!(matches!(
            reader.poll(Duration::ZERO).unwrap(),
            ReadStatus::Finished(_)
        ));
    }

    #[test]
    fn foreign_stack_is_rejected_before_transformed_cache_lookup() {
        let (_directory, _writer, _publisher, mut reader) = fixture(&[(100, 0x1000)]);
        let (_other_directory, _other_writer, _other_publisher, mut other) =
            fixture(&[(100, 0x1000)]);
        let mut session = cached(&mut reader, 1);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("published samples produce a batch");
        };
        let ReadStatus::Batch(foreign) = other.poll(Duration::ZERO).unwrap() else {
            panic!("the other source contains a sample");
        };
        let sample = foreign.samples().next().unwrap();
        let error = batch.entry(sample.stack()).err().unwrap();
        assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
        assert!(batch.cache.indices.is_empty());
    }

    #[test]
    fn provisional_results_are_owned_and_do_not_fill_the_transformed_cache() {
        let (directory, mut writer, publisher, mut reader) = fixture(&[]);
        let mut session = reader
            .symbolizer()
            .disable_perf_maps()
            .kernel_symbols(KernelSymbolSource::Disabled)
            .native(|_| RefreshBackend {
                fail: Rc::new(Cell::new(false)),
                generation: Rc::new(Cell::new(0)),
            })
            .build()
            .unwrap()
            .cache_stacks(2);
        assert!(matches!(
            session.poll(Duration::ZERO).unwrap(),
            ReadStatus::Batch(_)
        ));
        let module = crate::spool::ModuleRecord {
            id: 0,
            owner: crate::spool::ModuleOwner::Process(Pid::new(100).unwrap()),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: directory.path().join("temporarily-missing-image").into(),
        };
        writer.write_module(&module).unwrap();
        write_sample(&mut writer, 1, 100, 0x1010);
        write_sample(&mut writer, 2, 100, 0x1010);
        publish(&mut writer, &publisher);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("newly published samples produce a batch");
        };
        let mut samples = batch.samples();
        let first = samples.next().unwrap();
        let StackEntry::Vacant(entry) = batch.entry(first.stack()).unwrap() else {
            panic!("the initial stack has not been prepared");
        };
        let resolved = entry.resolve().unwrap();
        assert!(!resolved.stack().is_cacheable());
        let value = resolved.insert(11);
        assert!(matches!(value, StackValue::Transient(11)));
        assert_eq!(*value, 11);
        let second = samples.next().unwrap();
        assert!(matches!(
            batch.entry(second.stack()).unwrap(),
            StackEntry::Vacant(_)
        ));
        assert!(batch.cache.indices.is_empty());
    }

    #[test]
    fn failed_native_refresh_does_not_consume_or_invalidate_the_next_batch() {
        let (_directory, mut writer, publisher, mut reader) = fixture(&[(100, 0x1000)]);
        let fail = Rc::new(Cell::new(false));
        let generation = Rc::new(Cell::new(0));
        let mut session = cached(&mut reader, 2);
        session.session.symbolizer.native_symbolizers.insert(
            100,
            crate::symbols::erase_native_symbolizer(RefreshBackend {
                fail: Rc::clone(&fail),
                generation: Rc::clone(&generation),
            }),
        );
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("published samples produce a batch");
        };
        let sample = batch.samples().next().unwrap();
        let StackEntry::Vacant(entry) = batch.entry(sample.stack()).unwrap() else {
            panic!("the initial stack has not been prepared");
        };
        entry.resolve().unwrap().insert(7);
        let consumed = session.stats().consumed_bytes;
        write_sample(&mut writer, 2, 100, 0x1000);
        publish(&mut writer, &publisher);
        fail.set(true);
        generation.set(1);
        let error = session.poll(Duration::ZERO).unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::NativeSymbolizer);
        assert_eq!(session.stats().consumed_bytes, consumed);
        assert_eq!(session.cache.indices.len(), 1);
        let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
            panic!("retry receives the unread published batch");
        };
        let sample = batch.samples().next().unwrap();
        assert_eq!(sample.monotonic_timestamp(), Duration::from_nanos(2));
        assert!(matches!(
            batch.entry(sample.stack()).unwrap(),
            StackEntry::Vacant(_)
        ));
    }
}
