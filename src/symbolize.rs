//! Resolves stack frames recorded in perf spool files into displayable profile
//! frames.
//!
//! Spool records mostly contain process ids, raw instruction pointers (program
//! counters), and module mappings, not final symbol names. This module chooses
//! the symbol source for each frame: Python perf maps for JIT frames, ELF/native
//! symbolizers for user-space modules, and the kernel submodule for kernel
//! addresses. The rest of the crate consumes resolved frames without needing to
//! know which backend produced each symbol.

use std::ops::Range;
use std::path::PathBuf;
use std::slice;
#[cfg(test)]
use std::sync::Arc;

use crate::profile::{
    FrameFlags, FrameKind, NativeFrame, NativeSymbol, ResolvedFrame, SourceLocation, SymbolOrigin,
};
#[cfg(feature = "builtin-wholesym")]
use crate::symbols::default_native_symbolizer_factory;
use crate::symbols::{erase_native_symbolizer, ErasedNativeSymbolizer, NativeSymbolizerFactory};
pub use crate::symbols::{
    NativeFileIdentity, NativeImageId, NativeLookup, NativeModule, NativeSymbolizer, NativeSymbols,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::native_module::{ElfLoadError, ElfSectionCache};
use crate::spool::{
    self, FrameMode, FrameModuleRef, FrameRecord, ModuleRecord, Replay, SampleStack, Snapshot,
    SpoolFrameModuleContexts, StackKey,
};

mod kernel;
mod perf_map;
#[cfg(any(test, feature = "bench-support"))]
pub(crate) use kernel::bench_parse_sparse_kernel_symbols;
#[cfg(test)]
use kernel::KernelSymbol;
use kernel::{KernelSymbolTable, ResolvedKernelSymbol};
use perf_map::{
    find_perf_map_symbol, load_perf_map, perf_map_module_allowed, perf_map_symbol_to_frame,
    PerfMap, PerfMapProcesses, PerfMapSymbol,
};

#[derive(Debug, thiserror::Error)]
enum NativeContractError {
    #[error("native symbolizer returned {actual} results for {expected} requests")]
    ResultCount { expected: usize, actual: usize },
    #[error("resolved frame was not cached")]
    MissingCachedFrame,
    #[error("native lookup was queued without a backend factory")]
    MissingFactory,
    #[error("native backend was not retained after construction")]
    MissingBackend,
}

impl NativeContractError {
    fn into_public(self) -> crate::Error {
        crate::Error::new(crate::ErrorKind::NativeSymbolizer, self)
    }
}

/// Resolves raw profile frames into displayable frames.
///
/// A symbolizer is intentionally single-threaded and may be `!Send`. Keep it
/// on the worker thread that owns symbolization instead of placing it behind a
/// lock.
pub struct Symbolizer {
    source_id: Option<u64>,
    modules: SymbolizerModules,
    perf_map_processes: PerfMapProcesses,
    perf_map_dir: PathBuf,
    elf_sections: ElfSectionCache,
    native_symbolizers: FxHashMap<i32, Box<dyn ErasedNativeSymbolizer>>,
    native_modules: FxHashMap<u32, NativeModule>,
    native_batch_modules: FxHashMap<u32, NativeModule>,
    retryable_native_modules: FxHashSet<u32>,
    unsupported_native_modules: FxHashSet<u32>,
    native_requests: Vec<NativeLookup>,
    native_results: Vec<NativeSymbols>,
    pending_frames: Vec<PendingFrame>,
    pending_frame_keys: FxHashSet<(i32, FrameCacheKey)>,
    transient_frame_keys: Vec<(i32, FrameCacheKey)>,
    transient_frame_slots: FxHashMap<(i32, FrameCacheKey), usize>,
    vacant_frame_slots: Vec<usize>,
    perf_map_cache: FxHashMap<i32, Option<PerfMap>>,
    kernel_symbols: Option<KernelSymbolTable>,
    spool_frame_contexts: Option<SpoolFrameModuleContexts>,
    frame_cache: FxHashMap<(i32, FrameCacheKey), Range<usize>>,
    resolved_frames: Vec<ResolvedFrame>,
    resolved_stack_frame_ids: Vec<usize>,
    stack_cache_mode: StackCache,
    stack_cache: FxHashMap<StackKey, Range<usize>>,
    resolved_stack_scratch: Vec<usize>,
    native_factory: Option<NativeSymbolizerFactory>,
}

struct ModuleMetadata {
    path: Option<std::rc::Rc<str>>,
    basename_start: usize,
    is_python_runtime: bool,
}

fn format_hex_suffix(prefix: &str, value: u64) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digits = (u64::BITS - value.leading_zeros()).max(1).div_ceil(4) as usize;
    let mut output = String::with_capacity(prefix.len() + 3 + digits);
    output.push_str(prefix);
    output.push_str("+0x");
    for digit in (0..digits).rev() {
        let nibble = ((value >> (digit * 4)) & 0xf) as usize;
        output.push(char::from(HEX[nibble]));
    }
    output
}

#[derive(Default)]
struct SymbolizerModules {
    records: Vec<ModuleRecord>,
    metadata: Vec<ModuleMetadata>,
    index_by_id: FxHashMap<u32, usize>,
}

impl SymbolizerModules {
    fn new(mut records: Vec<ModuleRecord>) -> crate::Result<Self> {
        let original_len = records.len();
        let last = records.pop();
        let mut metadata = Vec::with_capacity(original_len);
        let mut index_by_id = FxHashMap::with_capacity_and_hasher(original_len, Default::default());
        for (index, record) in records.iter().enumerate() {
            if index_by_id.insert(record.id, index).is_some() {
                return Err(crate::Error::message(
                    crate::ErrorKind::InvalidInput,
                    format!("duplicate module id {}", record.id),
                ));
            }
            metadata.push(module_metadata(record));
        }
        let mut modules = Self {
            records,
            metadata,
            index_by_id,
        };
        if let Some(record) = last {
            modules.push(record)?;
        }
        Ok(modules)
    }

    fn push(&mut self, record: ModuleRecord) -> crate::Result<()> {
        if self.index_by_id.contains_key(&record.id) {
            return Err(crate::Error::message(
                crate::ErrorKind::InvalidInput,
                format!("duplicate module id {}", record.id),
            ));
        }
        let index = self.records.len();
        self.metadata.push(module_metadata(&record));
        self.index_by_id.insert(record.id, index);
        self.records.push(record);
        Ok(())
    }

    fn records(&self) -> &[ModuleRecord] {
        &self.records
    }

    fn get(&self, id: u32) -> Option<&ModuleRecord> {
        self.index_by_id
            .get(&id)
            .and_then(|&index| self.records.get(index))
    }

    fn metadata(&self, id: u32) -> Option<&ModuleMetadata> {
        self.index_by_id
            .get(&id)
            .and_then(|&index| self.metadata.get(index))
    }

    fn get_with_metadata(&self, id: u32) -> Option<(&ModuleRecord, &ModuleMetadata)> {
        let index = *self.index_by_id.get(&id)?;
        Some((self.records.get(index)?, self.metadata.get(index)?))
    }

    fn get_with_metadata_mut(&mut self, id: u32) -> Option<(&ModuleRecord, &mut ModuleMetadata)> {
        let index = *self.index_by_id.get(&id)?;
        Some((self.records.get(index)?, self.metadata.get_mut(index)?))
    }
}

fn module_metadata(record: &ModuleRecord) -> ModuleMetadata {
    let path = record.path.as_str();
    let basename_start = crate::profile::basename_start(path);
    ModuleMetadata {
        path: None,
        basename_start,
        is_python_runtime: crate::is_python_module(&path[basename_start..]),
    }
}

impl std::fmt::Debug for Symbolizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Symbolizer")
            .field("modules", &self.modules.records.len())
            .field("resolved_frames", &self.resolved_frames.len())
            .field("cached_stacks", &self.stack_cache.len())
            .field("stack_cache", &self.stack_cache_mode)
            .field("native_backend", &self.native_factory.is_some())
            .finish_non_exhaustive()
    }
}

enum SymbolizerInput<'a> {
    Modules(&'a [ModuleRecord]),
    OwnedModules(Vec<ModuleRecord>),
    Spool(&'a dyn SpoolSymbolizationInput),
}

trait SpoolSymbolizationInput {
    fn source_id(&self) -> u64;
    fn modules(&self) -> &[ModuleRecord];
    fn frames(&self) -> &[FrameRecord];
    fn frame_module_contexts(&self) -> SpoolFrameModuleContexts;
}

impl SpoolSymbolizationInput for Snapshot {
    fn source_id(&self) -> u64 {
        self.source_id()
    }
    fn modules(&self) -> &[ModuleRecord] {
        self.modules()
    }

    fn frames(&self) -> &[FrameRecord] {
        self.frames()
    }

    fn frame_module_contexts(&self) -> SpoolFrameModuleContexts {
        self.frame_module_contexts()
    }
}

impl SpoolSymbolizationInput for Replay {
    fn source_id(&self) -> u64 {
        self.source_id()
    }
    fn modules(&self) -> &[ModuleRecord] {
        self.modules()
    }

    fn frames(&self) -> &[FrameRecord] {
        self.frames()
    }

    fn frame_module_contexts(&self) -> SpoolFrameModuleContexts {
        self.frame_module_contexts()
    }
}

/// Configures a [`Symbolizer`].
pub struct SymbolizerBuilder<'a> {
    input: SymbolizerInput<'a>,
    perf_map_processes: PerfMapProcesses,
    perf_map_dir: PathBuf,
    native_factory: Option<NativeSymbolizerFactory>,
    kernel_symbols: KernelSymbolSource,
    stack_cache: StackCache,
}

impl std::fmt::Debug for SymbolizerBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let input = match self.input {
            SymbolizerInput::Modules(_) => "borrowed modules",
            SymbolizerInput::OwnedModules(_) => "owned modules",
            SymbolizerInput::Spool(_) => "spool",
        };
        f.debug_struct("SymbolizerBuilder")
            .field("input", &input)
            .field("perf_map_dir", &self.perf_map_dir)
            .field("kernel_symbols", &self.kernel_symbols)
            .field("stack_cache", &self.stack_cache)
            .field("custom_native_backend", &self.native_factory.is_some())
            .finish()
    }
}

/// Selects where kernel symbols are read during symbolizer construction.
#[non_exhaustive]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub enum KernelSymbolSource {
    /// Use the analysis host's `/proc/kallsyms` and `System.map` fallback.
    #[default]
    Host,
    /// Read a preserved `kallsyms` file whose addresses match the recording.
    File(PathBuf),
    /// Leave kernel frames unresolved.
    Disabled,
}

/// Selects which layer owns resolved-stack caching.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum StackCache {
    /// StackPulse retains resolved stack ranges for ordinary consumers.
    #[default]
    Internal,
    /// The caller caches prepared stacks; StackPulse retains only frame results.
    External,
}

impl<'a> SymbolizerBuilder<'a> {
    fn with_input(input: SymbolizerInput<'a>) -> Self {
        Self {
            input,
            perf_map_processes: PerfMapProcesses::All,
            perf_map_dir: PathBuf::from("/tmp"),
            native_factory: None,
            kernel_symbols: KernelSymbolSource::Host,
            stack_cache: StackCache::Internal,
        }
    }

    /// Configure symbolization for a module list.
    #[must_use]
    pub fn for_modules(modules: &'a [ModuleRecord]) -> Self {
        Self::with_input(SymbolizerInput::Modules(modules))
    }

    /// Configure symbolization for a loaded spool.
    #[must_use]
    pub(crate) fn for_spool(reader: &'a Snapshot) -> Self {
        Self::with_input(SymbolizerInput::Spool(reader))
    }

    /// Configure symbolization for a sequential spool replay.
    #[must_use]
    pub(crate) fn for_replay(reader: &'a Replay) -> Self {
        Self::with_input(SymbolizerInput::Spool(reader))
    }

    /// Disable Python perf-map lookup.
    #[must_use]
    pub fn disable_perf_maps(mut self) -> Self {
        self.perf_map_processes = PerfMapProcesses::Pids(FxHashSet::default());
        self
    }

    /// Restrict Python perf-map lookup to selected processes.
    #[must_use]
    pub fn perf_maps_for(mut self, processes: impl IntoIterator<Item = crate::Pid>) -> Self {
        self.perf_map_processes = PerfMapProcesses::Pids(processes.into_iter().collect());
        self
    }

    /// Read preserved `perf-PID.map` files from `directory`.
    #[must_use]
    pub fn perf_map_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        self.perf_map_dir = directory.into();
        self
    }

    /// Use a caller-supplied native symbolizer factory.
    ///
    /// The factory runs lazily, at most once per process id, when a resolve
    /// call first needs native symbols for that process.
    #[must_use]
    pub fn native<S>(mut self, mut factory: impl FnMut(crate::Pid) -> S + 'static) -> Self
    where
        S: NativeSymbolizer + 'static,
    {
        self.native_factory = Some(Box::new(move |process_id| {
            Ok(erase_native_symbolizer(factory(process_id)))
        }));
        self
    }

    /// Use a caller-supplied native symbolizer factory that may fail.
    ///
    /// The factory runs lazily and its first successful result is retained per
    /// process id. A factory error is returned by that resolve call; a later
    /// resolve may retry construction.
    #[must_use]
    pub fn try_native<S, E>(
        mut self,
        mut factory: impl FnMut(crate::Pid) -> Result<S, E> + 'static,
    ) -> Self
    where
        S: NativeSymbolizer + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.native_factory = Some(Box::new(move |process_id| {
            factory(process_id)
                .map(|symbolizer| erase_native_symbolizer(symbolizer))
                .map_err(|error| Box::new(error) as crate::symbols::NativeBackendError)
        }));
        self
    }

    /// Select the kernel symbol source.
    ///
    /// A preserved file should contain the same address-bearing `kallsyms`
    /// data that was visible on the recording host. This avoids accidentally
    /// resolving a cross-host profile against the analysis host's kernel.
    #[must_use]
    pub fn kernel_symbols(mut self, source: KernelSymbolSource) -> Self {
        self.kernel_symbols = source;
        self
    }

    /// Select the owner of resolved-stack caching.
    #[must_use]
    pub fn stack_cache(mut self, stack_cache: StackCache) -> Self {
        self.stack_cache = stack_cache;
        self
    }

    /// Build the configured symbolizer.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for duplicate module IDs, or an I/O
    /// error when an explicit kernel symbol file cannot be loaded.
    pub fn build(self) -> crate::Result<Symbolizer> {
        let native_factory = self.native_factory;
        #[cfg(feature = "builtin-wholesym")]
        let native_factory = native_factory.or_else(|| Some(default_native_symbolizer_factory()));
        let mut symbolizer = match self.input {
            SymbolizerInput::Modules(modules) => Symbolizer::with_perf_map_processes_inner(
                modules.to_vec(),
                self.perf_map_processes,
                self.perf_map_dir,
                native_factory,
                &self.kernel_symbols,
            )?,
            SymbolizerInput::OwnedModules(modules) => Symbolizer::with_perf_map_processes_inner(
                modules,
                self.perf_map_processes,
                self.perf_map_dir,
                native_factory,
                &self.kernel_symbols,
            )?,
            SymbolizerInput::Spool(reader) => Symbolizer::for_spool_inner(
                reader,
                self.perf_map_processes,
                self.perf_map_dir,
                native_factory,
                &self.kernel_symbols,
            )?,
        };
        symbolizer.stack_cache_mode = self.stack_cache;
        Ok(symbolizer)
    }
}

impl SymbolizerBuilder<'static> {
    /// Configure symbolization by transferring ownership of a module table.
    ///
    /// This avoids copying the table when it was assembled by the caller.
    #[must_use]
    pub fn from_modules(modules: Vec<ModuleRecord>) -> Self {
        Self::with_input(SymbolizerInput::OwnedModules(modules))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum FrameCacheKey {
    Spool(u32),
    Raw(FrameRecord),
}

struct PendingFrame {
    cache_key: (i32, FrameCacheKey),
    frame: FrameRecord,
    resolution: PendingResolution,
    transient: bool,
}

#[derive(Default)]
struct NativeLookupPreparation {
    request_index: Option<usize>,
    transient: bool,
}

enum PendingResolution {
    PerfMap(ResolvedFrame),
    Native {
        module: Option<(u32, u64)>,
        request_index: Option<usize>,
    },
}

/// Borrowed resolved frames for one sample stack.
pub struct ResolvedStack<'a> {
    frames: &'a [ResolvedFrame],
    ids: slice::Iter<'a, usize>,
}

impl<'a> Iterator for ResolvedStack<'a> {
    type Item = &'a ResolvedFrame;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().map(|&id| &self.frames[id])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}

impl ExactSizeIterator for ResolvedStack<'_> {
    fn len(&self) -> usize {
        self.ids.len()
    }
}

impl std::iter::FusedIterator for ResolvedStack<'_> {}

impl Symbolizer {
    /// Create a resolver for the modules in a profile.
    #[cfg(test)]
    fn new(modules: &[ModuleRecord]) -> Self {
        SymbolizerBuilder::for_modules(modules)
            .build()
            .expect("valid test modules")
    }

    fn for_spool_inner(
        reader: &dyn SpoolSymbolizationInput,
        perf_map_processes: PerfMapProcesses,
        perf_map_dir: PathBuf,
        native_factory: Option<NativeSymbolizerFactory>,
        kernel_source: &KernelSymbolSource,
    ) -> crate::Result<Self> {
        let mut symbolizer = Self::with_perf_map_processes_inner(
            reader.modules().to_vec(),
            perf_map_processes,
            perf_map_dir,
            native_factory,
            kernel_source,
        )?;
        symbolizer.source_id = Some(reader.source_id());
        symbolizer.kernel_symbols = match kernel_source {
            KernelSymbolSource::Host => Some(kernel::load_sparse_kernel_symbols_for_spool(
                reader
                    .frames()
                    .iter()
                    .filter_map(|frame| (frame.mode == FrameMode::Kernel).then_some(frame.abs_ip)),
                reader.modules(),
            )),
            KernelSymbolSource::File(_) | KernelSymbolSource::Disabled => {
                symbolizer.kernel_symbols.take()
            }
        };
        symbolizer.spool_frame_contexts = Some(reader.frame_module_contexts());
        let frame_count = reader.frames().len();
        symbolizer.frame_cache.reserve(frame_count);
        symbolizer.resolved_frames.reserve(frame_count);
        Ok(symbolizer)
    }

    fn with_perf_map_processes_inner(
        modules: Vec<ModuleRecord>,
        perf_map_processes: PerfMapProcesses,
        perf_map_dir: PathBuf,
        native_factory: Option<NativeSymbolizerFactory>,
        kernel_source: &KernelSymbolSource,
    ) -> crate::Result<Self> {
        let modules = SymbolizerModules::new(modules)?;
        let kernel_symbols = match kernel_source {
            KernelSymbolSource::Host => None,
            KernelSymbolSource::File(path) => Some(kernel::load_kernel_symbols_from_path(path)?),
            KernelSymbolSource::Disabled => Some(KernelSymbolTable::empty()),
        };
        Ok(Self {
            source_id: None,
            modules,
            perf_map_processes,
            perf_map_dir,
            elf_sections: ElfSectionCache::default(),
            native_symbolizers: FxHashMap::default(),
            native_modules: FxHashMap::default(),
            native_batch_modules: FxHashMap::default(),
            retryable_native_modules: FxHashSet::default(),
            unsupported_native_modules: FxHashSet::default(),
            native_requests: Vec::new(),
            native_results: Vec::new(),
            pending_frames: Vec::new(),
            pending_frame_keys: FxHashSet::default(),
            transient_frame_keys: Vec::new(),
            transient_frame_slots: FxHashMap::default(),
            vacant_frame_slots: Vec::new(),
            perf_map_cache: FxHashMap::default(),
            kernel_symbols,
            spool_frame_contexts: None,
            frame_cache: FxHashMap::default(),
            resolved_frames: Vec::new(),
            resolved_stack_frame_ids: Vec::new(),
            stack_cache_mode: StackCache::Internal,
            stack_cache: FxHashMap::default(),
            resolved_stack_scratch: Vec::new(),
            native_factory,
        })
    }

    /// Return whether native ELF symbolization has a configured backend.
    ///
    /// This is `false` with `--no-default-features` unless the builder's
    /// [`native`](SymbolizerBuilder::native) method supplied one. Kernel and
    /// perf-map resolution remain available independently.
    #[must_use]
    pub fn has_native_backend(&self) -> bool {
        self.native_factory.is_some()
    }

    /// Resolve one sample stack and borrow its resolved frames.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when `stack` belongs to another spool.
    /// Native backend failures and output-contract violations use
    /// [`ErrorKind::NativeSymbolizer`](crate::ErrorKind::NativeSymbolizer).
    pub fn resolve(&mut self, stack: SampleStack<'_>) -> crate::Result<ResolvedStack<'_>> {
        let (key, sample, mut frames) = stack.into_parts();
        match self.source_id {
            Some(source_id) if !key.belongs_to(source_id) => {
                return Err(crate::Error::message(
                    crate::ErrorKind::InvalidInput,
                    "sample stack belongs to a different spool source",
                ));
            }
            None => self.source_id = Some(key.source_id()),
            Some(_) => {}
        }

        if self.stack_cache_mode == StackCache::Internal {
            if let Some(range) = self.stack_cache.get(&key).cloned() {
                return Ok(ResolvedStack {
                    frames: &self.resolved_frames,
                    ids: self.resolved_stack_frame_ids[range].iter(),
                });
            }
        }

        self.begin_frame_batch(frames.len());
        let mut pending = frames.clone();
        while let Some(frame_ref) = pending.next_with_id() {
            self.prepare_frame(
                sample.process_id.get(),
                *frame_ref.frame,
                FrameCacheKey::Spool(frame_ref.id),
                Some(frame_ref.id),
            );
        }
        self.finish_frame_batch(sample.process_id.get())?;

        if self.stack_cache_mode == StackCache::Internal && self.transient_frame_keys.is_empty() {
            let start = self.resolved_stack_frame_ids.len();
            while let Some(frame_ref) = frames.next_with_id() {
                let frame_ids = self.cached_frame_ids(
                    sample.process_id.get(),
                    FrameCacheKey::Spool(frame_ref.id),
                )?;
                self.resolved_stack_frame_ids.extend(frame_ids);
            }
            let range = start..self.resolved_stack_frame_ids.len();
            self.stack_cache.insert(key, range.clone());
            return Ok(ResolvedStack {
                frames: &self.resolved_frames,
                ids: self.resolved_stack_frame_ids[range].iter(),
            });
        }

        self.resolved_stack_scratch.clear();
        while let Some(frame_ref) = frames.next_with_id() {
            let frame_ids =
                self.cached_frame_ids(sample.process_id.get(), FrameCacheKey::Spool(frame_ref.id))?;
            self.resolved_stack_scratch.extend(frame_ids);
        }
        self.clear_transient_frame_cache();
        Ok(ResolvedStack {
            frames: &self.resolved_frames,
            ids: self.resolved_stack_scratch.iter(),
        })
    }

    /// Resolve a caller-owned raw frame slice without retaining a stack entry.
    ///
    /// # Errors
    ///
    /// Native backend failures and output-contract violations use
    /// [`ErrorKind::NativeSymbolizer`](crate::ErrorKind::NativeSymbolizer).
    pub fn resolve_raw(
        &mut self,
        process_id: crate::Pid,
        frames: &[FrameRecord],
    ) -> crate::Result<ResolvedStack<'_>> {
        self.begin_frame_batch(frames.len());
        for frame in frames {
            if frame.mode == FrameMode::TruncatedStackMarker && !frame.is_truncated_stack_marker() {
                return Err(crate::Error::message(
                    crate::ErrorKind::InvalidInput,
                    "invalid truncated stack marker frame",
                ));
            }
            self.prepare_frame(process_id.get(), *frame, FrameCacheKey::Raw(*frame), None);
        }
        self.finish_frame_batch(process_id.get())?;
        self.resolved_stack_scratch.clear();
        self.resolved_stack_scratch.reserve(frames.len());
        for frame in frames {
            let frame_ids = self.cached_frame_ids(process_id.get(), FrameCacheKey::Raw(*frame))?;
            self.resolved_stack_scratch.extend(frame_ids);
        }
        self.clear_transient_frame_cache();
        Ok(ResolvedStack {
            frames: &self.resolved_frames,
            ids: self.resolved_stack_scratch.iter(),
        })
    }

    #[cfg(test)]
    fn resolve_cached_frame_ref(&mut self, process_id: i32, frame: &FrameRecord) -> &ResolvedFrame {
        let frame_ids = self
            .resolve_cached_frame_ids(process_id, frame, FrameCacheKey::Raw(*frame), None)
            .expect("test native symbolizer succeeds");
        &self.resolved_frames[frame_ids.start]
    }

    #[cfg(test)]
    fn resolve_cached_frame_ids(
        &mut self,
        process_id: i32,
        frame: &FrameRecord,
        cache_key: FrameCacheKey,
        spool_frame_id: Option<u32>,
    ) -> crate::Result<Range<usize>> {
        let cache_key = (process_id, cache_key);
        if let Some(frame_ids) = self.frame_cache.get(&cache_key) {
            return Ok(frame_ids.clone());
        }
        self.begin_frame_batch(1);
        self.prepare_frame(process_id, *frame, cache_key.1, spool_frame_id);
        self.finish_frame_batch(process_id)?;
        let frame_ids = self.cached_frame_ids(process_id, cache_key.1);
        self.clear_transient_frame_cache();
        frame_ids
    }

    fn cached_frame_ids(
        &self,
        process_id: i32,
        cache_key: FrameCacheKey,
    ) -> crate::Result<Range<usize>> {
        self.frame_cache
            .get(&(process_id, cache_key))
            .cloned()
            .ok_or_else(|| NativeContractError::MissingCachedFrame.into_public())
    }

    #[cfg(test)]
    fn resolve_frame(&mut self, process_id: i32, frame: &FrameRecord) -> ResolvedFrame {
        self.resolve_cached_frame_ref(process_id, frame).clone()
    }

    fn begin_frame_batch(&mut self, frame_count: usize) {
        self.clear_frame_batch();
        self.pending_frames.reserve(frame_count);
        self.pending_frame_keys.reserve(frame_count);
    }

    fn clear_frame_batch(&mut self) {
        self.clear_transient_frame_cache();
        self.pending_frames.clear();
        self.pending_frame_keys.clear();
        self.native_requests.clear();
        self.native_results.clear();
        self.native_batch_modules.clear();
        self.retryable_native_modules.clear();
    }

    fn clear_transient_frame_cache(&mut self) {
        for key in self.transient_frame_keys.drain(..) {
            self.frame_cache.remove(&key);
        }
    }

    fn prepare_frame(
        &mut self,
        process_id: i32,
        frame: FrameRecord,
        frame_key: FrameCacheKey,
        spool_frame_id: Option<u32>,
    ) {
        let cache_key = (process_id, frame_key);
        if self.frame_cache.contains_key(&cache_key) || !self.pending_frame_keys.insert(cache_key) {
            return;
        }

        if let Some(module_id) = frame.module_id.filter(|&module_id| {
            self.module_by_id(module_id)
                .is_some_and(|module| !perf_map_module_allowed(module))
        }) {
            let module = (module_id, frame.file_relative_ip);
            let native = self.prepare_native_lookup(process_id, module_id, frame.abs_ip);
            self.pending_frames.push(PendingFrame {
                cache_key,
                frame,
                resolution: PendingResolution::Native {
                    module: Some(module),
                    request_index: native.request_index,
                },
                transient: native.transient,
            });
            return;
        }

        let perf_map_symbol =
            if self.perf_maps_allowed_for(process_id) && frame.mode == FrameMode::User {
                self.lookup_perf_map_symbol(process_id, frame.abs_ip)
            } else {
                None
            };

        if let Some((symbol, perf_map_module)) = perf_map_symbol {
            let blocked_module = self
                .module_for_frame(process_id, &frame, spool_frame_id)
                .and_then(|module| {
                    (!perf_map_module_allowed(module.module))
                        .then_some((module.module.id, module.file_relative_ip))
                });
            if let Some(module) = blocked_module {
                let request_index = self.prepare_native_lookup(process_id, module.0, frame.abs_ip);
                self.pending_frames.push(PendingFrame {
                    cache_key,
                    frame,
                    resolution: PendingResolution::Native {
                        module: Some(module),
                        request_index: request_index.request_index,
                    },
                    transient: request_index.transient,
                });
                return;
            }

            self.pending_frames.push(PendingFrame {
                cache_key,
                frame,
                resolution: PendingResolution::PerfMap(perf_map_symbol_to_frame(
                    frame.abs_ip,
                    symbol,
                    perf_map_module,
                )),
                transient: false,
            });
            return;
        }
        let module = self.module_key_for_frame(process_id, &frame, spool_frame_id);
        let native = module
            .as_ref()
            .map_or_else(NativeLookupPreparation::default, |(module_id, _)| {
                self.prepare_native_lookup(process_id, *module_id, frame.abs_ip)
            });
        self.pending_frames.push(PendingFrame {
            cache_key,
            frame,
            resolution: PendingResolution::Native {
                module,
                request_index: native.request_index,
            },
            transient: native.transient,
        });
    }

    fn prepare_native_lookup(
        &mut self,
        process_id: i32,
        module_id: u32,
        absolute_address: u64,
    ) -> NativeLookupPreparation {
        let Some((module, metadata)) = self.modules.get_with_metadata(module_id) else {
            return NativeLookupPreparation::default();
        };
        if module.pid().is_none_or(|pid| pid.get() != process_id)
            || self.native_factory.is_none()
            || self.unsupported_native_modules.contains(&module.id)
        {
            return NativeLookupPreparation::default();
        }
        if self.retryable_native_modules.contains(&module.id) {
            return NativeLookupPreparation {
                transient: true,
                ..NativeLookupPreparation::default()
            };
        }
        let is_python_runtime = metadata.is_python_runtime;
        if !self.native_batch_modules.contains_key(&module.id) {
            if module.path.is_empty()
                || (module.path.is_bracketed_mapping() && !module.path.is_vdso())
            {
                self.unsupported_native_modules.insert(module.id);
                return NativeLookupPreparation::default();
            }
            let batch_module = if let Some(template) = self.native_modules.get(&module.id) {
                let image_file = match self.elf_sections.acquire_file(module) {
                    Ok(file) => Some(file),
                    Err(ElfLoadError::Retryable) => {
                        self.retryable_native_modules.insert(module.id);
                        None
                    }
                    Err(ElfLoadError::Unsupported) => None,
                };
                template.with_image_file(image_file)
            } else {
                let mapping = match self.elf_sections.load_mapping(module) {
                    Ok(mapping) => mapping,
                    Err(ElfLoadError::Retryable) => {
                        self.retryable_native_modules.insert(module.id);
                        return NativeLookupPreparation {
                            transient: true,
                            ..NativeLookupPreparation::default()
                        };
                    }
                    Err(ElfLoadError::Unsupported) => {
                        self.unsupported_native_modules.insert(module.id);
                        return NativeLookupPreparation::default();
                    }
                };
                let Some(image_base) = mapping.image_base else {
                    self.unsupported_native_modules.insert(module.id);
                    return NativeLookupPreparation::default();
                };
                let image_file = mapping.file;
                if image_file.is_none() && !module.path.is_vdso() {
                    return NativeLookupPreparation {
                        transient: true,
                        ..NativeLookupPreparation::default()
                    };
                }
                let template = NativeModule::new(
                    module.path.clone(),
                    image_base,
                    is_python_runtime,
                    NativeFileIdentity::new(
                        module.device_major,
                        module.device_minor,
                        module.inode,
                        module.inode_generation,
                    ),
                    module.id,
                    mapping.image_token,
                );
                let batch_module = template.with_image_file(image_file);
                self.native_modules.insert(module.id, template);
                batch_module
            };
            self.native_batch_modules.insert(module.id, batch_module);
        }
        let transient = self.retryable_native_modules.contains(&module.id);
        let Some(pid) = crate::Pid::new(process_id) else {
            return NativeLookupPreparation::default();
        };
        let Some(native_module) = self.native_batch_modules.get(&module.id) else {
            return NativeLookupPreparation::default();
        };
        let Some(image_address) = native_module.image_base().svma_for_avma(absolute_address) else {
            return NativeLookupPreparation::default();
        };
        let Some(relative_address) = native_module
            .image_base()
            .relative_address(absolute_address)
        else {
            return NativeLookupPreparation::default();
        };
        let request_index = self.native_requests.len();
        self.native_requests.push(NativeLookup {
            process_id: pid,
            module: native_module.clone(),
            absolute_address,
            relative_address,
            image_address,
        });
        NativeLookupPreparation {
            request_index: Some(request_index),
            transient,
        }
    }

    fn finish_frame_batch(&mut self, process_id: i32) -> crate::Result<()> {
        if !self.native_requests.is_empty() {
            self.native_results.reserve(self.native_requests.len());
            let process_id = crate::Pid::try_from(process_id)
                .map_err(|error| crate::Error::new(crate::ErrorKind::InvalidInput, error))?;
            if !self.native_symbolizers.contains_key(&process_id.get()) {
                let Some(factory) = self.native_factory.as_mut() else {
                    self.clear_frame_batch();
                    return Err(NativeContractError::MissingFactory.into_public());
                };
                let backend = match factory(process_id) {
                    Ok(backend) => backend,
                    Err(error) => {
                        self.clear_frame_batch();
                        return Err(crate::Error::native(error));
                    }
                };
                self.native_symbolizers.insert(process_id.get(), backend);
            }
            let Some(backend) = self.native_symbolizers.get_mut(&process_id.get()) else {
                self.clear_frame_batch();
                return Err(NativeContractError::MissingBackend.into_public());
            };
            if let Err(error) = backend.symbolize(&self.native_requests, &mut self.native_results) {
                self.clear_frame_batch();
                return Err(crate::Error::native(error));
            }
            if self.native_results.len() != self.native_requests.len() {
                let expected = self.native_requests.len();
                let actual = self.native_results.len();
                self.clear_frame_batch();
                return Err(NativeContractError::ResultCount { expected, actual }.into_public());
            }
            self.native_requests.clear();
            self.native_batch_modules.clear();
        }

        let mut pending_frames = std::mem::take(&mut self.pending_frames);
        let mut native_results = std::mem::take(&mut self.native_results);
        for pending in pending_frames.drain(..) {
            let appended_start = self.resolved_frames.len();
            let mut retry = false;
            match pending.resolution {
                PendingResolution::PerfMap(frame) => self.resolved_frames.push(frame),
                PendingResolution::Native {
                    module,
                    request_index,
                } => {
                    let symbols = request_index
                        .and_then(|index| native_results.get_mut(index))
                        .map(std::mem::take)
                        .filter(|symbols| !symbols.is_empty());
                    retry = pending.transient && symbols.is_none();
                    self.append_native_frames(&pending.frame, module, symbols);
                }
            }
            let appended_range = appended_start..self.resolved_frames.len();
            let previous_slot = self.transient_frame_slots.remove(&pending.cache_key);
            let frame_range = if appended_range.len() == 1 {
                let reusable_slot = previous_slot.or_else(|| self.vacant_frame_slots.pop());
                if let Some(slot) = reusable_slot {
                    if let Some(replacement) = self.resolved_frames.pop() {
                        self.resolved_frames[slot] = replacement;
                        slot..slot + 1
                    } else {
                        appended_range
                    }
                } else {
                    appended_range
                }
            } else {
                if let Some(slot) = previous_slot {
                    self.vacant_frame_slots.push(slot);
                }
                appended_range
            };
            let frame_start = frame_range.start;
            self.frame_cache.insert(pending.cache_key, frame_range);
            if retry {
                self.transient_frame_slots
                    .insert(pending.cache_key, frame_start);
                self.transient_frame_keys.push(pending.cache_key);
            }
        }
        native_results.clear();
        self.native_results = native_results;
        self.pending_frames = pending_frames;
        self.native_requests.clear();
        self.native_batch_modules.clear();
        self.retryable_native_modules.clear();
        Ok(())
    }

    fn module_key_for_frame(
        &self,
        process_id: i32,
        frame: &FrameRecord,
        spool_frame_id: Option<u32>,
    ) -> Option<(u32, u64)> {
        self.module_for_frame(process_id, frame, spool_frame_id)
            .map(|module| (module.module.id, module.file_relative_ip))
    }

    fn module_for_frame(
        &self,
        process_id: i32,
        frame: &FrameRecord,
        spool_frame_id: Option<u32>,
    ) -> Option<FrameModuleRef<'_>> {
        if let Some(module_id) = frame.module_id {
            return Some(FrameModuleRef {
                module: self.module_by_id(module_id)?,
                file_relative_ip: frame.file_relative_ip,
            });
        }
        match (self.spool_frame_contexts.as_ref(), spool_frame_id) {
            (Some(contexts), Some(frame_id)) => {
                let context = contexts.for_frame_id(frame_id)?;
                spool::module_for_frame_with_context(
                    self.modules.records(),
                    contexts,
                    context,
                    process_id,
                    frame,
                )
            }
            _ => spool::module_for_frame_unbounded(self.modules.records(), process_id, frame),
        }
    }

    fn module_by_id(&self, module_id: u32) -> Option<&ModuleRecord> {
        self.modules.get(module_id)
    }

    #[cfg(test)]
    fn resolve_native_frame(
        &mut self,
        frame: &FrameRecord,
        module: Option<(ModuleRecord, u64)>,
    ) -> NativeFrame {
        let module = module.map(|(module, offset)| (module.id, offset));
        let start = self.resolved_frames.len();
        self.append_native_frames(frame, module, None);
        let ResolvedFrame::Native(frame) = self.resolved_frames[start].clone() else {
            unreachable!("native resolution only appends native frames")
        };
        frame
    }

    fn append_native_frames(
        &mut self,
        frame: &FrameRecord,
        module: Option<(u32, u64)>,
        symbols: Option<NativeSymbols>,
    ) {
        if frame.is_truncated_stack_marker() {
            self.resolved_frames
                .push(ResolvedFrame::Native(NativeFrame::truncated_stack_marker()));
            return;
        }
        let is_kernel_frame = frame.mode == FrameMode::Kernel
            || module.as_ref().is_some_and(|(module_id, _)| {
                self.modules
                    .get(*module_id)
                    .is_some_and(ModuleRecord::is_kernel)
            });

        match (is_kernel_frame, module) {
            (false, None) => {
                self.resolved_frames
                    .push(ResolvedFrame::Native(NativeFrame::from_address(
                        frame.abs_ip,
                    )));
            }
            (true, _) => {
                // Unresolved kernel frames get offset 0: the fallback name
                // already embeds the absolute PC.
                let (symbol_name, module_name, offset, origin) =
                    match self.resolve_kernel(frame.abs_ip) {
                        Some(symbol) => (
                            symbol.name,
                            symbol.module,
                            symbol.offset,
                            SymbolOrigin::KernelSymbols,
                        ),
                        None => (
                            format_hex_suffix("[kernel]", frame.abs_ip),
                            "[kernel]".to_owned(),
                            0,
                            SymbolOrigin::AddressOnly,
                        ),
                    };
                let symbol =
                    NativeSymbol::new(symbol_name, SourceLocation::default(), module_name, offset);
                self.resolved_frames
                    .push(ResolvedFrame::Native(NativeFrame {
                        pc: frame.abs_ip,
                        symbol: Some(symbol),
                        kind: FrameKind::Kernel,
                        origin,
                        flags: FrameFlags::empty(),
                    }));
            }
            (false, Some((module_id, file_relative_ip))) => {
                let is_python_runtime = frame.mode == FrameMode::User
                    && self
                        .modules
                        .metadata(module_id)
                        .is_some_and(|metadata| metadata.is_python_runtime);
                if let Some(symbols) = symbols {
                    self.resolved_frames
                        .extend(symbols.into_symbols().map(|symbol| {
                            let mut flags = FrameFlags::empty();
                            flags.set(FrameFlags::PYTHON_RUNTIME, is_python_runtime);
                            flags.set(FrameFlags::HIDDEN_DEFAULT, symbol.should_ignore());
                            ResolvedFrame::Native(NativeFrame {
                                pc: frame.abs_ip,
                                symbol: Some(symbol),
                                kind: FrameKind::Native,
                                origin: SymbolOrigin::Elf,
                                flags,
                            })
                        }));
                    return;
                }

                let Some((module, module_metadata)) = self.modules.get_with_metadata_mut(module_id)
                else {
                    self.resolved_frames
                        .push(ResolvedFrame::Native(NativeFrame::from_address(
                            frame.abs_ip,
                        )));
                    return;
                };
                let path = module_metadata
                    .path
                    .get_or_insert_with(|| module.path.as_str().into());
                let symbol_name =
                    format_hex_suffix(&path[module_metadata.basename_start..], file_relative_ip);
                // Pseudo-symbol without a function: the name embeds the
                // file-relative address, so the function offset is 0.
                let symbol = NativeSymbol::new(
                    symbol_name,
                    SourceLocation::default(),
                    std::rc::Rc::clone(path),
                    0,
                );
                let symbol = if is_python_runtime {
                    symbol.hidden_by_default()
                } else {
                    symbol
                };
                self.resolved_frames
                    .push(ResolvedFrame::Native(NativeFrame {
                        pc: frame.abs_ip,
                        symbol: Some(symbol),
                        kind: FrameKind::Native,
                        origin: SymbolOrigin::AddressOnly,
                        flags: if is_python_runtime {
                            FrameFlags::PYTHON_RUNTIME | FrameFlags::HIDDEN_DEFAULT
                        } else {
                            FrameFlags::empty()
                        },
                    }));
            }
        }
    }

    fn resolve_kernel(&mut self, abs_ip: u64) -> Option<ResolvedKernelSymbol> {
        let symbols = self
            .kernel_symbols
            .get_or_insert_with(kernel::load_shared_kernel_symbols);
        kernel::resolve_kernel_symbol(symbols, abs_ip)
    }

    fn perf_maps_allowed_for(&self, process_id: i32) -> bool {
        match &self.perf_map_processes {
            PerfMapProcesses::All => true,
            PerfMapProcesses::Pids(processes) => crate::Pid::try_from(process_id)
                .is_ok_and(|process_id| processes.contains(&process_id)),
        }
    }

    fn lookup_perf_map_symbol(
        &mut self,
        process_id: i32,
        abs_ip: u64,
    ) -> Option<(PerfMapSymbol, std::rc::Rc<str>)> {
        self.perf_map_cache
            .entry(process_id)
            .or_insert_with(|| load_perf_map(&self.perf_map_dir, process_id))
            .as_ref()
            .and_then(|perf_map| find_perf_map_symbol(perf_map, abs_ip))
            .map(|(symbol, module)| (symbol.clone(), module.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::rc::Rc;

    use crate::spool::{ModuleOwner, PerfSpoolWriter};

    use super::*;

    fn user_owner(pid: i32) -> ModuleOwner {
        ModuleOwner::Process(crate::Pid::new(pid).unwrap())
    }

    fn test_process_id(sequence: i32) -> i32 {
        1_500_000_000 + sequence
    }

    fn temp_perf_map_path(process_id: i32) -> String {
        format!("/tmp/perf-{process_id}.map")
    }

    fn frame(abs_ip: u64) -> FrameRecord {
        FrameRecord {
            module_id: None,
            file_relative_ip: abs_ip,
            abs_ip,
            mode: FrameMode::User,
        }
    }

    fn pinned_frame(module_id: u32, abs_ip: u64) -> FrameRecord {
        FrameRecord {
            module_id: Some(module_id),
            file_relative_ip: 8,
            abs_ip,
            mode: FrameMode::User,
        }
    }

    fn module_with_path(id: u32, process_id: i32, start: u64, path: &str) -> ModuleRecord {
        ModuleRecord {
            id,
            owner: user_owner(process_id),
            start,
            end: start + 0x1000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.into(),
        }
    }

    fn current_executable_module(id: u32, process_id: i32) -> ModuleRecord {
        let executable = std::env::current_exe().expect("current test executable");
        let maps = fs::read_to_string("/proc/self/maps").expect("current process maps");
        let executable_path = executable.to_string_lossy();
        let region = crate::proc_maps::parse_iter(&maps)
            .find(|region| region.is_executable && region.path == executable_path)
            .expect("executable mapping");
        ModuleRecord {
            id,
            owner: user_owner(process_id),
            start: region.address.start,
            end: region.address.end,
            file_offset: region.file_offset,
            inode: region.inode,
            device_major: region.device_major,
            device_minor: region.device_minor,
            inode_generation: 0,
            path: region.path.into(),
        }
    }

    type RecordedBatches = Rc<RefCell<Vec<Vec<(u64, u64)>>>>;

    struct RecordingNativeSymbolizer {
        batches: RecordedBatches,
    }

    impl NativeSymbolizer for RecordingNativeSymbolizer {
        type Error = std::convert::Infallible;

        fn symbolize(
            &mut self,
            requests: &[NativeLookup],
            output: &mut Vec<NativeSymbols>,
        ) -> Result<(), Self::Error> {
            self.batches.borrow_mut().push(
                requests
                    .iter()
                    .map(|request| (request.absolute_address(), request.relative_address()))
                    .collect(),
            );
            output.extend(requests.iter().map(|_| NativeSymbols::unresolved()));
            Ok(())
        }
    }

    struct CountingNativeSymbolizer {
        calls: Rc<Cell<usize>>,
    }

    impl NativeSymbolizer for CountingNativeSymbolizer {
        type Error = std::convert::Infallible;

        fn symbolize(
            &mut self,
            requests: &[NativeLookup],
            output: &mut Vec<NativeSymbols>,
        ) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            output.extend(requests.iter().map(|request| {
                NativeSymbols::one(NativeSymbol::new(
                    "resolved-after-retry",
                    SourceLocation::default(),
                    request.module().name_rc().clone(),
                    0,
                ))
            }));
            Ok(())
        }
    }

    struct DescriptorRecordingSymbolizer {
        descriptors: Rc<RefCell<Vec<bool>>>,
    }

    impl NativeSymbolizer for DescriptorRecordingSymbolizer {
        type Error = std::convert::Infallible;

        fn symbolize(
            &mut self,
            requests: &[NativeLookup],
            output: &mut Vec<NativeSymbols>,
        ) -> Result<(), Self::Error> {
            self.descriptors.borrow_mut().extend(
                requests
                    .iter()
                    .map(|request| request.module().image_path().is_some()),
            );
            output.extend(requests.iter().map(|request| {
                NativeSymbols::one(NativeSymbol::new(
                    "cached-image",
                    SourceLocation::default(),
                    request.module().name_rc().clone(),
                    0,
                ))
            }));
            Ok(())
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("sentinel native-symbolizer failure")]
    struct SentinelNativeError;

    struct FailingNativeSymbolizer;

    impl NativeSymbolizer for FailingNativeSymbolizer {
        type Error = SentinelNativeError;

        fn symbolize(
            &mut self,
            _requests: &[NativeLookup],
            _output: &mut Vec<NativeSymbols>,
        ) -> Result<(), Self::Error> {
            Err(SentinelNativeError)
        }
    }

    struct EmptyNativeSymbolizer;

    impl NativeSymbolizer for EmptyNativeSymbolizer {
        type Error = std::convert::Infallible;

        fn symbolize(
            &mut self,
            _requests: &[NativeLookup],
            _output: &mut Vec<NativeSymbols>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn native_backend_error_keeps_its_concrete_source() {
        let pid = crate::Pid::try_from(std::process::id()).expect("current pid");
        let module = current_executable_module(0, pid.get());
        let frame = pinned_frame(0, module.start + 8);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(|_| FailingNativeSymbolizer)
            .build()
            .unwrap();

        let error = match symbolizer.resolve_raw(pid, &[frame]) {
            Err(error) => error,
            Ok(_) => panic!("failing backend unexpectedly resolved the frame"),
        };

        assert_eq!(error.kind(), crate::ErrorKind::NativeSymbolizer);
        assert!(std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<SentinelNativeError>())
            .is_some());
    }

    #[test]
    fn native_factory_error_is_reported_without_panicking() {
        let pid = crate::Pid::try_from(std::process::id()).expect("current pid");
        let module = current_executable_module(0, pid.get());
        let frame = pinned_frame(0, module.start + 8);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .try_native(
                |_| -> Result<FailingNativeSymbolizer, SentinelNativeError> {
                    Err(SentinelNativeError)
                },
            )
            .build()
            .unwrap();

        let error = match symbolizer.resolve_raw(pid, &[frame]) {
            Err(error) => error,
            Ok(_) => panic!("failing factory unexpectedly resolved the frame"),
        };

        assert_eq!(error.kind(), crate::ErrorKind::NativeSymbolizer);
        assert!(std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<SentinelNativeError>())
            .is_some());
    }

    #[test]
    fn wrong_native_result_count_is_rejected() {
        let pid = crate::Pid::try_from(std::process::id()).expect("current pid");
        let module = current_executable_module(0, pid.get());
        let frame = pinned_frame(0, module.start + 8);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(|_| EmptyNativeSymbolizer)
            .build()
            .unwrap();

        let error = match symbolizer.resolve_raw(pid, &[frame]) {
            Err(error) => error,
            Ok(_) => panic!("invalid backend result count was accepted"),
        };
        assert_eq!(error.kind(), crate::ErrorKind::NativeSymbolizer);
        assert_eq!(
            error.to_string(),
            "native symbolizer returned 0 results for 1 requests"
        );
    }

    #[test]
    fn native_cache_misses_are_batched_and_cached() {
        let pid = crate::Pid::try_from(std::process::id()).expect("current pid");
        let module = current_executable_module(0, pid.get());
        let frames = [
            pinned_frame(0, module.start + 8),
            pinned_frame(0, module.start + 16),
        ];
        let batches = Rc::new(RefCell::new(Vec::new()));
        let backend_batches = Rc::clone(&batches);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(move |_| RecordingNativeSymbolizer {
                batches: Rc::clone(&backend_batches),
            })
            .build()
            .unwrap();

        assert_eq!(symbolizer.resolve_raw(pid, &frames).unwrap().count(), 2);
        let recorded = batches.borrow();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].len(), 2);
        assert_eq!(recorded[0][0].0, frames[0].abs_ip);
        assert_eq!(recorded[0][1].0, frames[1].abs_ip);
        assert_eq!(recorded[0][1].1 - recorded[0][0].1, 8);
        drop(recorded);

        assert_eq!(symbolizer.resolve_raw(pid, &frames).unwrap().count(), 2);
        assert_eq!(batches.borrow().len(), 1);
    }

    #[test]
    fn transient_module_open_is_retried_without_retaining_image_descriptors() {
        let temp = crate::test_support::TempDir::new("symbolize-native-retry");
        let path = temp.path().join("late-image");
        let pid = crate::Pid::new(2_000_000_000).unwrap();
        let mut module = current_executable_module(0, pid.get());
        module.inode = 0;
        module.device_major = 0;
        module.device_minor = 0;
        module.path = path.to_string_lossy().into_owned().into();
        let frames = [
            pinned_frame(0, module.start + 8),
            pinned_frame(0, module.start + 16),
        ];
        let calls = Rc::new(Cell::new(0));
        let backend_calls = Rc::clone(&calls);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(move |_| CountingNativeSymbolizer {
                calls: Rc::clone(&backend_calls),
            })
            .build()
            .unwrap();

        let first = symbolizer
            .resolve_raw(pid, &frames)
            .unwrap()
            .next()
            .unwrap();
        assert!(matches!(
            first,
            ResolvedFrame::Native(frame) if frame.origin == SymbolOrigin::AddressOnly
        ));
        assert_eq!(calls.get(), 0);
        assert!(symbolizer.native_modules.is_empty());
        assert!(symbolizer.unsupported_native_modules.is_empty());

        fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let second = symbolizer
            .resolve_raw(pid, &frames)
            .unwrap()
            .next()
            .unwrap();
        assert_eq!(second.display_name(), "resolved-after-retry");
        assert_eq!(calls.get(), 1);
        assert_eq!(symbolizer.resolved_frames.len(), frames.len());
        assert!(symbolizer.native_batch_modules.is_empty());
        assert!(symbolizer
            .native_modules
            .values()
            .all(|module| module.image_path().is_none()));

        assert_eq!(symbolizer.resolve_raw(pid, &frames).unwrap().count(), 2);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn permanent_module_open_failure_is_cached_after_one_retry() {
        let temp = crate::test_support::TempDir::new("symbolize-native-permanent-miss");
        let path = temp.path().join("missing-image");
        let pid = crate::Pid::new(2_000_000_000).unwrap();
        let mut module = current_executable_module(0, pid.get());
        module.inode = 0;
        module.device_major = 0;
        module.device_minor = 0;
        module.path = path.to_string_lossy().into_owned().into();
        let module_id = module.id;
        let frame = pinned_frame(0, module.start + 8);
        let calls = Rc::new(Cell::new(0));
        let backend_calls = Rc::clone(&calls);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(move |_| CountingNativeSymbolizer {
                calls: Rc::clone(&backend_calls),
            })
            .build()
            .unwrap();

        assert_eq!(symbolizer.resolve_raw(pid, &[frame]).unwrap().count(), 1);
        assert!(!symbolizer.unsupported_native_modules.contains(&module_id));
        assert_eq!(symbolizer.resolve_raw(pid, &[frame]).unwrap().count(), 1);
        assert!(symbolizer.unsupported_native_modules.contains(&module_id));
        let resolved_frame_count = symbolizer.resolved_frames.len();

        assert_eq!(symbolizer.resolve_raw(pid, &[frame]).unwrap().count(), 1);
        assert_eq!(symbolizer.resolved_frames.len(), resolved_frame_count);
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn invalid_elf_failure_is_cached_without_retrying() {
        let temp = crate::test_support::TempDir::new("symbolize-native-invalid-elf");
        let path = temp.path().join("invalid-image");
        fs::write(&path, b"not an elf").unwrap();
        let pid = crate::Pid::new(2_000_000_000).unwrap();
        let mut module = current_executable_module(0, pid.get());
        module.inode = 0;
        module.device_major = 0;
        module.device_minor = 0;
        module.path = path.to_string_lossy().into_owned().into();
        let module_id = module.id;
        let frame = pinned_frame(0, module.start + 8);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(|_| EmptyNativeSymbolizer)
            .build()
            .unwrap();

        assert_eq!(symbolizer.resolve_raw(pid, &[frame]).unwrap().count(), 1);
        assert!(symbolizer.unsupported_native_modules.contains(&module_id));
        let resolved_frame_count = symbolizer.resolved_frames.len();

        assert_eq!(symbolizer.resolve_raw(pid, &[frame]).unwrap().count(), 1);
        assert_eq!(symbolizer.resolved_frames.len(), resolved_frame_count);
    }

    #[test]
    fn cached_native_backend_can_resolve_after_the_image_disappears() {
        let temp = crate::test_support::TempDir::new("symbolize-native-cached-image");
        let path = temp.path().join("image");
        fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let pid = crate::Pid::new(2_000_000_000).unwrap();
        let mut module = current_executable_module(0, pid.get());
        module.inode = 0;
        module.device_major = 0;
        module.device_minor = 0;
        module.path = path.to_string_lossy().into_owned().into();
        let first = pinned_frame(0, module.start + 8);
        let second = pinned_frame(0, module.start + 16);
        let descriptors = Rc::new(RefCell::new(Vec::new()));
        let backend_descriptors = Rc::clone(&descriptors);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(move |_| DescriptorRecordingSymbolizer {
                descriptors: Rc::clone(&backend_descriptors),
            })
            .build()
            .unwrap();

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[first])
                .unwrap()
                .next()
                .unwrap()
                .display_name(),
            "cached-image"
        );
        fs::remove_file(&path).unwrap();
        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[second])
                .unwrap()
                .next()
                .unwrap()
                .display_name(),
            "cached-image"
        );
        assert_eq!(&*descriptors.borrow(), &[true, false]);

        assert_eq!(symbolizer.resolve_raw(pid, &[second]).unwrap().count(), 1);
        assert_eq!(&*descriptors.borrow(), &[true, false]);
    }

    #[test]
    fn module_ids_are_not_treated_as_slice_indexes() {
        let process_id = 42;
        let module = module_with_path(7, process_id, 0x1000, "/stable-seven.so");
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .build()
            .unwrap();
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(7, 0x1008));
        let invalid = symbolizer.resolve_frame(process_id, &pinned_frame(0, 0x1008));

        assert_eq!(resolved.display_name(), "stable-seven.so+0x8");
        assert!(matches!(
            invalid,
            ResolvedFrame::Native(frame) if frame.symbol.is_none()
        ));
    }

    #[test]
    fn reordered_dense_module_ids_select_the_matching_record() {
        let process_id = 42;
        let modules = [
            module_with_path(1, process_id, 0x1000, "/module-one.so"),
            module_with_path(0, process_id, 0x2000, "/module-zero.so"),
        ];
        let mut symbolizer = SymbolizerBuilder::for_modules(&modules)
            .disable_perf_maps()
            .build()
            .unwrap();
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(0, 0x2008));

        assert_eq!(resolved.display_name(), "module-zero.so+0x8");
    }

    #[test]
    fn duplicate_module_ids_are_rejected_at_build() {
        let process_id = 42;
        let mut modules = vec![module_with_path(7, process_id, 0x1000, "/first-seven.so")];
        for id in 1..7 {
            modules.push(module_with_path(
                id,
                process_id,
                0x2000 + u64::from(id) * 0x1000,
                "/filler.so",
            ));
        }
        modules.push(module_with_path(7, process_id, 0x9000, "/index-seven.so"));
        let error = SymbolizerBuilder::for_modules(&modules)
            .disable_perf_maps()
            .build()
            .unwrap_err();

        assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "duplicate module id 7");
    }

    #[test]
    fn sparse_ids_use_the_module_fallback_path() {
        let process_id = 42;
        let module = module_with_path(7, process_id, 0x1000, "[anon:sparse-seven]");
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .build()
            .unwrap();
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(7, 0x1008));

        assert_eq!(resolved.display_name(), "[anon:sparse-seven]+0x8");
    }

    #[test]
    fn python_perf_map_symbols_win() {
        let process_id = test_process_id(0);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "1000 10 py::work:/tmp/app.py\n").expect("write perf map");

        let mut symbolizer = Symbolizer::new(&[]);
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x1004));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Python(frame) => {
                assert_eq!(frame.func_name.as_ref(), "work");
                assert_eq!(frame.file_name(), "/tmp/app.py");
            }
            ResolvedFrame::Native(_) => panic!("expected Python perf-map frame"),
        }
    }

    #[test]
    fn python_perf_map_symbols_respect_declared_ranges() {
        let process_id = test_process_id(9);
        let path = temp_perf_map_path(process_id);
        fs::write(
            &path,
            "1000 c py::first:/tmp/app.py\n1020 c py::second:/tmp/app.py\n",
        )
        .expect("write perf map");

        let mut symbolizer = Symbolizer::new(&[]);
        let first = symbolizer.resolve_frame(process_id, &frame(0x1008));
        let gap = symbolizer.resolve_frame(process_id, &frame(0x100e));
        let second = symbolizer.resolve_frame(process_id, &frame(0x1024));
        let _ = fs::remove_file(&path);

        assert!(matches!(
            first,
            ResolvedFrame::Python(frame) if frame.func_name.as_ref() == "first"
        ));
        assert!(matches!(
            gap,
            ResolvedFrame::Native(frame) if frame.symbol.is_none()
        ));
        assert!(matches!(
            second,
            ResolvedFrame::Python(frame) if frame.func_name.as_ref() == "second"
        ));
    }

    #[test]
    fn native_perf_map_symbols_win_without_module() {
        let process_id = test_process_id(1);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "2000 20 jit_func\n").expect("write perf map");

        let mut symbolizer = Symbolizer::new(&[]);
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x2008));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Native(frame) => {
                assert_eq!(frame.kind, FrameKind::Native);
                assert_eq!(frame.origin, SymbolOrigin::PerfMap);
                assert_eq!(frame.flags, FrameFlags::JIT);
                let symbol = frame.symbol.expect("perf-map native symbol");
                assert_eq!(symbol.name(), "jit_func");
                assert_eq!(symbol.module.as_ref(), temp_perf_map_path(process_id));
                assert_eq!(symbol.offset, 8);
            }
            ResolvedFrame::Python(_) => panic!("expected native perf-map frame"),
        }
    }

    #[test]
    fn perf_map_symbols_can_be_disabled() {
        let process_id = test_process_id(2);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "2800 20 py::stale:/tmp/stale.py\n").expect("write perf map");

        let mut symbolizer = SymbolizerBuilder::for_modules(&[])
            .disable_perf_maps()
            .build()
            .unwrap();
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x2808));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Native(frame) => assert!(frame.symbol.is_none()),
            ResolvedFrame::Python(_) => panic!("stale perf-map frame should be ignored"),
        }
    }

    #[test]
    fn perf_map_symbols_can_be_limited_to_processes() {
        let allowed_process = i32::MAX - i32::try_from(std::process::id()).unwrap_or(1) - 20;
        let blocked_process = allowed_process - 1;
        let allowed_path = temp_perf_map_path(allowed_process);
        let blocked_path = temp_perf_map_path(blocked_process);
        fs::write(&allowed_path, "2900 20 py::allowed:/tmp/allowed.py\n")
            .expect("write allowed perf map");
        fs::write(&blocked_path, "2900 20 py::blocked:/tmp/blocked.py\n")
            .expect("write blocked perf map");

        let mut symbolizer = SymbolizerBuilder::for_modules(&[])
            .perf_maps_for([crate::Pid::new(allowed_process).unwrap()])
            .build()
            .unwrap();
        let allowed = symbolizer.resolve_frame(allowed_process, &frame(0x2908));
        let blocked = symbolizer.resolve_frame(blocked_process, &frame(0x2908));
        let _ = fs::remove_file(&allowed_path);
        let _ = fs::remove_file(&blocked_path);

        match allowed {
            ResolvedFrame::Python(frame) => assert_eq!(frame.func_name.as_ref(), "allowed"),
            ResolvedFrame::Native(_) => panic!("expected allowed Python perf-map frame"),
        }
        match blocked {
            ResolvedFrame::Native(frame) => assert!(frame.symbol.is_none()),
            ResolvedFrame::Python(_) => panic!("unexpected blocked Python perf-map frame"),
        }
    }

    #[test]
    fn perf_map_symbols_do_not_override_non_python_modules() {
        let process_id = test_process_id(4);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "4000 20 py::fake_after_exec:/tmp/fake.py\n").expect("write perf map");
        let module = module_with_path(0, process_id, 0x4000, "/bin/bash");
        let mut symbolizer = Symbolizer::new(&[module]);
        let resolved = symbolizer.resolve_frame(
            process_id,
            &FrameRecord {
                module_id: Some(0),
                file_relative_ip: 0x8,
                abs_ip: 0x4008,
                mode: FrameMode::User,
            },
        );
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Native(frame) => {
                assert_eq!(frame.kind, FrameKind::Native);
                assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
                assert!(!frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(!frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                assert!(!frame.is_python_runtime());
                assert_ne!(frame.display_name(), "fake_after_exec");
            }
            ResolvedFrame::Python(_) => panic!("non-Python module should block perf-map symbol"),
        }
    }

    #[test]
    fn perf_map_symbols_do_not_override_file_backed_python_modules() {
        let process_id = test_process_id(11);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "4000 20 py::stale:/tmp/stale.py\n").expect("write perf map");
        let module = module_with_path(0, process_id, 0x4000, "/usr/lib/libpython3.13.so.1.0");
        let mut symbolizer = Symbolizer::new(&[module]);
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(0, 0x4008));
        let _ = fs::remove_file(&path);

        assert!(matches!(
            resolved,
            ResolvedFrame::Native(frame) if frame.origin == SymbolOrigin::AddressOnly
        ));
    }

    #[test]
    fn perf_map_symbols_do_not_override_late_resolved_non_python_modules() {
        let process_id = test_process_id(6);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "5000 20 py::fake_after_exec:/tmp/fake.py\n").expect("write perf map");
        let module = module_with_path(0, process_id, 0x5000, "/bin/bash");
        let mut symbolizer = Symbolizer::new(&[module]);
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x5008));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Native(frame) => {
                assert_eq!(frame.kind, FrameKind::Native);
                assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
                assert!(!frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(!frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                assert!(!frame.is_python_runtime());
                assert_ne!(frame.display_name(), "fake_after_exec");
            }
            ResolvedFrame::Python(_) => {
                panic!("late-resolved non-Python module should block perf-map symbol")
            }
        }
    }

    #[test]
    fn perf_map_symbols_do_not_override_memfd_mappings_by_default() {
        let process_id = test_process_id(10);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "5800 20 jit_memfd\n").expect("write perf map");
        let module = module_with_path(0, process_id, 0x5800, "/memfd:jit-code");
        let mut symbolizer = Symbolizer::new(&[module]);
        let resolved = symbolizer.resolve_frame(
            process_id,
            &FrameRecord {
                module_id: Some(0),
                file_relative_ip: 0x8,
                abs_ip: 0x5808,
                mode: FrameMode::User,
            },
        );
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Native(frame) => {
                assert_ne!(frame.origin, SymbolOrigin::PerfMap);
                assert!(!frame.flags.contains(FrameFlags::JIT));
            }
            ResolvedFrame::Python(_) => panic!("memfd module should block perf-map symbol"),
        }
    }

    #[test]
    fn perf_map_symbols_can_override_anonymous_python_code_mappings() {
        let process_id = test_process_id(7);
        let path = temp_perf_map_path(process_id);
        fs::write(
            &path,
            "6000 20 py::anon_code:/tmp/app.py\n7000 20 py::perf_anon_code:/tmp/app.py\n",
        )
        .expect("write perf map");
        let bracket_anon = module_with_path(0, process_id, 0x6000, "[anon]");
        let perf_anon = module_with_path(1, process_id, 0x7000, "//anon");
        let mut symbolizer = Symbolizer::new(&[bracket_anon, perf_anon]);
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x6008));
        let resolved_perf_anon = symbolizer.resolve_frame(process_id, &frame(0x7008));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Python(frame) => assert_eq!(frame.func_name.as_ref(), "anon_code"),
            ResolvedFrame::Native(_) => {
                panic!("anonymous Python code should allow perf-map symbol")
            }
        }
        match resolved_perf_anon {
            ResolvedFrame::Python(frame) => assert_eq!(frame.func_name.as_ref(), "perf_anon_code"),
            ResolvedFrame::Native(_) => {
                panic!("perf anonymous Python code should allow perf-map symbol")
            }
        }
    }

    #[test]
    fn perf_map_symbols_cover_perf_anonymous_mapping_names() {
        let process_id = test_process_id(12);
        let path = temp_perf_map_path(process_id);
        let mapping_paths = [
            "[heap]",
            "[stack:42]",
            "/dev/zero (deleted)",
            "/anon_hugepage (deleted)",
            "/SYSV00000000 (deleted)",
        ];
        let mut map = String::new();
        let mut modules = Vec::new();
        for (id, mapping_path) in mapping_paths.into_iter().enumerate() {
            let start = 0x9000 + id as u64 * 0x1000;
            map.push_str(&format!("{start:x} 20 jit_{id}\n"));
            modules.push(module_with_path(id as u32, process_id, start, mapping_path));
        }
        fs::write(&path, map).expect("write perf map");
        let mut symbolizer = Symbolizer::new(&modules);

        for (id, module) in modules.iter().enumerate() {
            let resolved =
                symbolizer.resolve_frame(process_id, &pinned_frame(id as u32, module.start + 8));
            assert!(matches!(
                resolved,
                ResolvedFrame::Native(frame) if frame.origin == SymbolOrigin::PerfMap
            ));
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn resolved_frames_are_cached_across_stacks() {
        let process_id = test_process_id(5);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "3000 20 jit_func\n").expect("write perf map");

        let mut symbolizer = Symbolizer::new(&[]);
        let frame = frame(0x3008);
        let first = symbolizer
            .resolve_cached_frame_ref(process_id, &frame)
            .display_name();
        let second = symbolizer
            .resolve_cached_frame_ref(process_id, &frame)
            .display_name();
        let _ = fs::remove_file(&path);

        assert_eq!(symbolizer.frame_cache.len(), 1);
        assert_eq!(first, second);
    }

    #[test]
    fn python_runtime_modules_are_classified_and_hidden_by_default() {
        let process_id = test_process_id(8);
        let module = module_with_path(0, process_id, 0x8000, "/usr/bin/python3");
        let mut symbolizer = Symbolizer::new(&[module]);

        let resolved = symbolizer.resolve_frame(
            process_id,
            &FrameRecord {
                module_id: Some(0),
                file_relative_ip: 0x18,
                abs_ip: 0x8018,
                mode: FrameMode::User,
            },
        );

        match resolved {
            ResolvedFrame::Native(frame) => {
                assert_eq!(frame.kind, FrameKind::Native);
                assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
                assert!(frame.is_python_runtime());
                assert!(frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                let symbol = frame.symbol.expect("fallback Python runtime symbol");
                assert!(symbol.should_ignore());
            }
            ResolvedFrame::Python(_) => panic!("Python runtime module should stay native"),
        }
    }

    #[test]
    fn native_runtime_and_hidden_flags_are_independent() {
        let process_id = 42;
        let python = module_with_path(0, process_id, 0x8000, "/usr/bin/python3");
        let native = module_with_path(1, process_id, 0x9000, "/usr/lib/libworker.so");
        let mut symbolizer = Symbolizer::new(&[python.clone(), native.clone()]);
        let visible = NativeSymbol::new("visible", SourceLocation::default(), "python3", 0);
        let hidden = NativeSymbol::new("hidden", SourceLocation::default(), "libworker.so", 0)
            .hidden_by_default();

        symbolizer.append_native_frames(
            &pinned_frame(0, 0x8008),
            Some((python.id, 8)),
            Some(NativeSymbols::new(vec![visible])),
        );
        symbolizer.append_native_frames(
            &pinned_frame(1, 0x9008),
            Some((native.id, 8)),
            Some(NativeSymbols::new(vec![hidden])),
        );

        let ResolvedFrame::Native(python_frame) = &symbolizer.resolved_frames[0] else {
            panic!("expected native Python-runtime frame")
        };
        assert!(python_frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
        assert!(!python_frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
        assert!(python_frame.is_python_runtime());

        let ResolvedFrame::Native(hidden_frame) = &symbolizer.resolved_frames[1] else {
            panic!("expected hidden native frame")
        };
        assert!(!hidden_frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
        assert!(hidden_frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
        assert!(!hidden_frame.is_python_runtime());
    }

    #[test]
    fn resolve_raw_rejects_malformed_truncated_marker() {
        let pid = crate::Pid::new(42).unwrap();
        let mut symbolizer = Symbolizer::new(&[]);
        let malformed = FrameRecord {
            abs_ip: 1,
            ..FrameRecord::truncated_stack_marker()
        };

        let error = match symbolizer.resolve_raw(pid, &[malformed]) {
            Ok(_) => panic!("malformed marker was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
    }

    #[test]
    fn kernel_frames_use_kernel_fallback_when_kallsyms_unavailable() {
        let mut symbolizer = Symbolizer::new(&[]);
        symbolizer.kernel_symbols = Some(KernelSymbolTable::Full(Arc::from([])));
        let frame = FrameRecord {
            module_id: None,
            file_relative_ip: 0xffff_ffff_8000_1234,
            abs_ip: 0xffff_ffff_8000_1234,
            mode: FrameMode::Kernel,
        };

        let resolved = symbolizer.resolve_native_frame(&frame, None);

        assert_eq!(resolved.kind, FrameKind::Kernel);
        assert_eq!(resolved.origin, SymbolOrigin::AddressOnly);
        let symbol = resolved.symbol.expect("kernel fallback symbol");
        assert_eq!(symbol.name(), "[kernel]+0xffffffff80001234");
        assert_eq!(symbol.module.as_ref(), "[kernel]");
        assert_eq!(symbol.offset, 0);
    }

    #[test]
    fn resolved_kernel_symbols_carry_within_function_offsets() {
        let mut symbolizer = Symbolizer::new(&[]);
        symbolizer.kernel_symbols = Some(KernelSymbolTable::Full(Arc::from([KernelSymbol {
            address: 0xffff_ffff_8100_0000,
            name: "vfs_read".to_owned(),
            module: None,
        }])));
        let frame = FrameRecord {
            module_id: None,
            file_relative_ip: 0xffff_ffff_8100_0014,
            abs_ip: 0xffff_ffff_8100_0014,
            mode: FrameMode::Kernel,
        };

        let resolved = symbolizer.resolve_native_frame(&frame, None);

        let symbol = resolved.symbol.expect("resolved kernel symbol");
        assert_eq!(symbol.name(), "vfs_read+0x14");
        assert_eq!(symbol.module.as_ref(), "[kernel]");
        assert_eq!(symbol.offset, 0x14);
    }

    #[test]
    fn truncated_stack_markers_resolve_to_flagged_sentinels() {
        let mut symbolizer = Symbolizer::new(&[]);

        let marker = symbolizer.resolve_native_frame(&FrameRecord::truncated_stack_marker(), None);
        let null_pc = symbolizer.resolve_native_frame(
            &FrameRecord {
                module_id: None,
                file_relative_ip: 0,
                abs_ip: 0,
                mode: FrameMode::User,
            },
            None,
        );

        assert!(marker.flags.contains(FrameFlags::TRUNCATED_STACK));
        assert_eq!(marker.display_name(), "<stack truncated>");
        assert_eq!(null_pc.display_name(), "<0x0>");
        assert!(null_pc.flags.is_empty());
        assert_ne!(marker, null_pc);
    }

    #[test]
    fn kernel_resolution_preserves_module_name() {
        let mut symbolizer = Symbolizer::new(&[]);
        symbolizer.kernel_symbols = Some(KernelSymbolTable::Full(Arc::from([
            wireguard_kernel_symbol(),
        ])));
        let frame = wireguard_kernel_frame();

        let resolved = symbolizer.resolve_native_frame(&frame, None);

        assert_wireguard_kernel_frame(&resolved);
    }

    #[test]
    fn spool_symbolizer_preserves_kernel_module_name() {
        let path = temp_symbolize_spool_path("kernel-module-symbol");
        let frame = wireguard_kernel_frame();
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let _stack_id = writer
            .write_sample_frames(1_000, 7, 11, [frame])
            .unwrap()
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = Snapshot::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let mut symbolizer = reader.symbolizer().build().unwrap();
        symbolizer.kernel_symbols = Some(KernelSymbolTable::Sparse(Arc::from([(
            frame.abs_ip,
            wireguard_kernel_symbol(),
        )])));

        let stack = reader.stacks().next().expect("sample stack");
        let resolved: Vec<_> = symbolizer.resolve(stack).unwrap().cloned().collect();

        assert_eq!(resolved.len(), 1);
        let ResolvedFrame::Native(frame) = &resolved[0] else {
            panic!("expected native kernel frame");
        };
        assert_wireguard_kernel_frame(frame);
    }

    #[test]
    fn sample_stack_without_stack_cache_keeps_per_process_frame_cache() {
        let path = temp_symbolize_spool_path("sample-stack-without-stack-cache");
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let first_stack_id = writer
            .write_sample_frames(1_000, 7, 11, [frame(0x1500)])
            .unwrap()
            .unwrap();
        let second_stack_id = writer
            .write_sample_frames(2_000, 8, 12, [frame(0x1500)])
            .unwrap()
            .unwrap();
        assert_eq!(first_stack_id, second_stack_id);
        writer.flush().unwrap();
        drop(writer);

        let reader = Snapshot::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let mut symbolizer = SymbolizerBuilder::for_spool(&reader)
            .disable_perf_maps()
            .stack_cache(StackCache::External)
            .build()
            .unwrap();

        for stack in reader.stacks() {
            assert_eq!(symbolizer.resolve(stack).unwrap().count(), 1);
        }

        assert_eq!(symbolizer.frame_cache.len(), 2);
        assert_eq!(symbolizer.resolved_frames.len(), 2);
        assert!(symbolizer.stack_cache.is_empty());
        assert!(symbolizer.resolved_stack_frame_ids.is_empty());
    }

    fn write_future_module_spool(label: &str) -> (std::path::PathBuf, u32) {
        let path = temp_symbolize_spool_path(label);
        let frame = frame(0x1500);
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let stack_id = writer
            .write_sample_frames(1_000, 7, 11, [frame])
            .unwrap()
            .unwrap();
        writer
            .write_module(&ModuleRecord {
                id: 0,
                owner: user_owner(7),
                start: 0x1000,
                end: 0x2000,
                file_offset: 0,
                inode: 1,
                device_major: 0,
                device_minor: 0,
                inode_generation: 0,
                path: "/future".into(),
            })
            .unwrap();
        writer.flush().unwrap();
        drop(writer);
        (path, stack_id)
    }

    fn assert_future_module_unresolved(
        reader: &Snapshot,
        mut symbolizer: Symbolizer,
        stack_id: u32,
    ) {
        let stack = reader
            .stacks()
            .find(|stack| stack.sample().stack_id == stack_id)
            .expect("sample stack");
        let resolved = symbolizer.resolve(stack).unwrap().next().cloned();
        let ResolvedFrame::Native(frame) = resolved.expect("resolved frame") else {
            panic!("expected native address-only frame");
        };
        assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
        assert!(frame.symbol.is_none());
    }

    #[test]
    fn spool_symbolizer_does_not_resolve_moduleless_frames_to_future_modules() {
        let (path, stack_id) = write_future_module_spool("future-module");
        let reader = Snapshot::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let symbolizer = SymbolizerBuilder::for_spool(&reader)
            .disable_perf_maps()
            .build()
            .unwrap();
        assert_future_module_unresolved(&reader, symbolizer, stack_id);
    }

    #[test]
    fn module_builder_binds_to_the_first_spool_source() {
        let (first_path, _) = write_future_module_spool("source-binding-first");
        let (second_path, _) = write_future_module_spool("source-binding-second");
        let first = Snapshot::open(&first_path).unwrap();
        let second = Snapshot::open(&second_path).unwrap();
        let _ = std::fs::remove_file(first_path);
        let _ = std::fs::remove_file(second_path);
        let mut symbolizer = SymbolizerBuilder::for_modules(first.modules())
            .disable_perf_maps()
            .build()
            .unwrap();

        assert!(symbolizer.resolve(first.stacks().next().unwrap()).is_ok());
        let error = match symbolizer.resolve(second.stacks().next().unwrap()) {
            Ok(_) => panic!("stack from another source was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
    }

    #[test]
    fn replay_symbolizer_keeps_recorded_frame_module_context() {
        let (path, _) = write_future_module_spool("replay-future-module");
        let reader = Replay::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let mut symbolizer = reader.symbolizer().build().unwrap();
        let stack = reader.stacks().next().expect("sample");
        let resolved = symbolizer.resolve(stack).unwrap().next().cloned();
        let ResolvedFrame::Native(frame) = resolved.expect("resolved frame") else {
            panic!("expected native address-only frame");
        };
        assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
        assert!(frame.symbol.is_none());
    }

    #[test]
    fn spool_symbolizer_with_pid_restricted_perf_maps_keeps_frame_limits() {
        let (path, stack_id) = write_future_module_spool("future-module-pid-filter");
        let reader = Snapshot::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let symbolizer = SymbolizerBuilder::for_spool(&reader)
            .perf_maps_for([crate::Pid::new(7).unwrap()])
            .build()
            .unwrap();
        assert_future_module_unresolved(&reader, symbolizer, stack_id);
    }

    #[test]
    fn spool_symbolizer_recorded_python_perf_maps_survive_exit_marker() {
        let process_id = i32::MAX - i32::try_from(std::process::id()).unwrap_or(1);
        let perf_map_path = temp_perf_map_path(process_id);
        fs::write(&perf_map_path, "5900 20 py::kept:/tmp/app.py\n").expect("write perf map");

        let path = temp_symbolize_spool_path("python-perf-map-exit-marker");
        let frame = frame(0x5908);
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer.write_python_runtime(0, process_id, true).unwrap();
        writer
            .write_sample_frames(1, process_id, 11, [frame])
            .unwrap();
        writer.write_python_runtime(2, process_id, false).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = Snapshot::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let mut symbolizer = SymbolizerBuilder::for_spool(&reader)
            .perf_maps_for(
                reader
                    .python_runtime_records()
                    .iter()
                    .filter_map(|runtime| runtime.is_python_runtime.then_some(runtime.process_id)),
            )
            .build()
            .unwrap();
        let resolved = symbolizer.resolve_frame(process_id, &frame);
        let _ = fs::remove_file(&perf_map_path);

        match resolved {
            ResolvedFrame::Python(frame) => assert_eq!(frame.func_name.as_ref(), "kept"),
            ResolvedFrame::Native(_) => panic!("expected recorded Python perf-map frame"),
        }
    }

    fn wireguard_kernel_frame() -> FrameRecord {
        FrameRecord {
            module_id: None,
            file_relative_ip: 0xffff_ffff_c001_0014,
            abs_ip: 0xffff_ffff_c001_0014,
            mode: FrameMode::Kernel,
        }
    }

    fn wireguard_kernel_symbol() -> KernelSymbol {
        KernelSymbol {
            address: 0xffff_ffff_c001_0000,
            name: "wg_packet_tx_worker".to_owned(),
            module: Some("[wireguard]".to_owned()),
        }
    }

    fn assert_wireguard_kernel_frame(frame: &NativeFrame) {
        let symbol = frame.symbol.as_ref().expect("kernel module symbol");
        assert_eq!(frame.kind, FrameKind::Kernel);
        assert_eq!(symbol.name(), "wg_packet_tx_worker+0x14");
        assert_eq!(symbol.module.as_ref(), "[wireguard]");
    }

    fn temp_symbolize_spool_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "stackpulse-symbolize-{name}-{}.spool",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }
}
