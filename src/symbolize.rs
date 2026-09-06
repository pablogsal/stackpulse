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
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Arc;

pub use crate::module_base::ModuleImageBase;
use crate::profile::{
    AddressSpace, Frame, FrameFlags, FrameKey, NativeFrame, NativeSymbol, ResolvedStack,
    SymbolOrigin,
};
#[cfg(feature = "builtin-wholesym")]
use crate::symbols::default_native_symbolizer_factory;
use crate::symbols::{
    erase_native_symbolizer, normalized_module_path, ErasedNativeSymbolizer,
    NativeSymbolizerFactory,
};
pub use crate::symbols::{
    NativeBatch, NativeFileIdentity, NativeImage, NativeImageId, NativeImageSource, NativeLookup,
    NativeMapping, NativeSymbolizer, NativeSymbols, NativeSymbolsIntoIter,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::native_module::{ElfLoadError, ElfSectionCache, ExactImageStore};
use crate::spool::{
    self, FrameMode, FrameModuleRef, FrameRecord, ModuleRecord, Replay, Snapshot,
    SpoolFrameModuleContexts, StackKey, Tail, TailBatch,
};

#[cfg(test)]
mod native_refresh_tests;

mod session;
pub use session::{
    CachedBatch, CachedSession, LiveBatch, ResolvedEntry, Session, SessionBuilder, StackEntry,
    StackValue, VacantStack,
};

mod kernel;
mod perf_map;
#[cfg(any(test, feature = "bench-support"))]
pub(crate) use kernel::bench_parse_sparse_kernel_symbols;
#[cfg(test)]
use kernel::KernelSymbol;
use kernel::{KernelSymbolTable, ResolvedKernelSymbol};
use perf_map::{
    find_perf_map_symbol, load_perf_map, perf_map_file_identity, perf_map_module_allowed,
    perf_map_symbol_to_frame, PerfMap, PerfMapFileIdentity, PerfMapProcesses, PerfMapSymbol,
};

static NEXT_SYMBOLIZER_ID: AtomicU64 = AtomicU64::new(1);

const LIVE_RESOLVED_FRAME_LIMIT: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
enum NativeContractError {
    #[error("resolved frame was not cached")]
    CacheMiss,
    #[error("native lookup was queued without a backend factory")]
    FactoryUnavailable,
    #[error("native backend was not retained after construction")]
    BackendUnavailable,
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
    identity: u64,
    source_id: Option<u64>,
    modules: SymbolizerModules,
    perf_map_processes: PerfMapProcesses,
    perf_map_dir: PathBuf,
    elf_sections: ElfSectionCache,
    native_symbolizers: FxHashMap<i32, Box<dyn ErasedNativeSymbolizer>>,
    native_generation_by_process: FxHashMap<i32, u64>,
    staged_native_generations: Vec<(i32, u64)>,
    native_changed_process_ids: FxHashSet<crate::Pid>,
    native_modules: FxHashMap<u32, NativeMapping>,
    native_batch_modules: FxHashMap<u32, NativeMapping>,
    retryable_native_modules: FxHashSet<u32>,
    unsupported_native_modules: FxHashSet<u32>,
    native_requests: Vec<NativeLookup>,
    native_results: Vec<NativeSymbols>,
    pending_frames: Vec<PendingFrame>,
    pending_frame_keys: FxHashSet<(i32, FrameCacheKey)>,
    transient_frame_keys: Vec<(i32, FrameCacheKey)>,
    transient_frame_slots: FxHashMap<(i32, FrameCacheKey), usize>,
    vacant_frame_slots: Vec<usize>,
    perf_maps: FxHashMap<i32, PerfMapState>,
    tracks_perf_map_updates: bool,
    pending_retired_processes: Vec<crate::Pid>,
    pending_retired_modules: Vec<u32>,
    inactive_modules: FxHashSet<u32>,
    kernel_symbols: Option<KernelSymbolTable>,
    refresh_host_kernel_symbols: bool,
    spool_frame_contexts: Option<SpoolFrameModuleContexts>,
    frame_cache: FxHashMap<(i32, FrameCacheKey), ResolvedFrameRange>,
    resolved_frames: Vec<Frame>,
    resolved_frame_ids: Vec<FrameKey>,
    resolution_cache_limit: Option<usize>,
    next_resolved_frame_id: u64,
    resolved_stack_frame_ids: Vec<usize>,
    stack_cache_mode: StackCache,
    stack_cache: FxHashMap<StackKey, Range<usize>>,
    resolved_stack_scratch: Vec<usize>,
    invalidated_process_ids: FxHashSet<crate::Pid>,
    perf_map_changed_process_ids: FxHashSet<crate::Pid>,
    mapping_changed_process_ids: FxHashSet<i32>,
    native_factory: Option<NativeSymbolizerFactory>,
}

struct PerfMapState {
    identity: Option<PerfMapFileIdentity>,
    map: Option<PerfMap>,
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
    fn new(records: Vec<ModuleRecord>) -> crate::Result<Self> {
        let mut metadata = Vec::with_capacity(records.len());
        let mut index_by_id =
            FxHashMap::with_capacity_and_hasher(records.len(), Default::default());
        for (index, record) in records.iter().enumerate() {
            if index_by_id.insert(record.id, index).is_some() {
                return Err(crate::Error::message(
                    crate::ErrorKind::InvalidInput,
                    format!("duplicate module id {}", record.id),
                ));
            }
            metadata.push(module_metadata(record));
        }
        Ok(Self {
            records,
            metadata,
            index_by_id,
        })
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
    let path = normalized_module_path(&record.path).to_string_lossy();
    let basename_start = crate::profile::basename_start(&path);
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
    Spool(&'a dyn SpoolSymbolizationInput),
}

trait SpoolSymbolizationInput {
    fn source_id(&self) -> u64;
    fn modules(&self) -> &[ModuleRecord];
    fn frames(&self) -> &[FrameRecord];
    fn frame_module_contexts(&self) -> SpoolFrameModuleContexts;
    fn is_growing(&self) -> bool {
        false
    }
    fn exact_images(&self) -> Option<ExactImageStore> {
        None
    }
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

impl SpoolSymbolizationInput for Tail {
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

    fn is_growing(&self) -> bool {
        true
    }

    fn exact_images(&self) -> Option<ExactImageStore> {
        self.exact_images()
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

/// Selects where kernel symbols are read.
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
pub(crate) enum StackCache {
    /// StackPulse retains resolved stack ranges for ordinary consumers.
    #[default]
    Internal,
    /// The caller caches prepared stacks; StackPulse retains only frame results.
    External,
}

/// Prepared-stack invalidation caused by one live tail update.
///
/// This is relevant when the builder uses [`StackCache::External`]. Apply it
/// before looking up or inserting prepared stacks from the updated batch.
pub(crate) struct Invalidation<'a> {
    all: bool,
    processes: &'a FxHashSet<crate::Pid>,
}

impl Invalidation<'_> {
    /// Return whether every externally cached stack must be discarded.
    #[must_use]
    pub fn all(&self) -> bool {
        self.all
    }

    /// Iterate over processes whose externally cached stacks must be discarded.
    pub fn processes(&self) -> impl Iterator<Item = crate::Pid> + '_ {
        self.processes.iter().copied()
    }

    /// Return whether cached stacks for `process` must be discarded.
    #[must_use]
    pub fn affects_process(&self, process: crate::Pid) -> bool {
        self.all || self.processes.contains(&process)
    }
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
    pub(crate) fn for_modules(modules: &'a [ModuleRecord]) -> Self {
        Self::with_input(SymbolizerInput::Modules(modules))
    }

    /// Configure symbolization for a loaded spool.
    #[must_use]
    pub(crate) fn for_spool(reader: &'a Snapshot) -> Self {
        Self::for_spool_input(reader)
    }

    /// Configure symbolization for a sequential spool replay.
    #[must_use]
    pub(crate) fn for_replay(reader: &'a Replay) -> Self {
        Self::for_spool_input(reader)
    }

    /// Configure symbolization for an append-only spool tail.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn for_tail(reader: &'a Tail) -> Self {
        Self::for_spool_input(reader)
    }

    fn for_spool_input(reader: &'a dyn SpoolSymbolizationInput) -> Self {
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
    #[cfg(test)]
    pub(crate) fn stack_cache(mut self, stack_cache: StackCache) -> Self {
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum FrameCacheKey {
    Spool(u32),
    #[cfg(any(test, feature = "bench-support"))]
    Raw(FrameRecord),
}

struct PendingFrame {
    cache_key: (i32, FrameCacheKey),
    frame: FrameRecord,
    resolution: PendingResolution,
    transient: bool,
    perf_map_dependent: bool,
}

#[derive(Clone)]
struct ResolvedFrameRange {
    indices: Range<usize>,
    perf_map_dependent: bool,
}

impl ResolvedFrameRange {
    fn indices(&self) -> Range<usize> {
        self.indices.clone()
    }

    fn len(&self) -> usize {
        self.indices.len()
    }

    fn relocate(&mut self, start: usize) {
        self.indices = start..start + self.len();
    }
}

#[derive(Default)]
struct NativeLookupPreparation {
    request_index: Option<usize>,
    transient: bool,
}

enum PendingResolution {
    PerfMap(Frame),
    Native {
        module: Option<(u32, u64)>,
        request_index: Option<usize>,
    },
}

fn prepare_native_mapping(
    module: &ModuleRecord,
    is_python_runtime: bool,
    elf_sections: &mut ElfSectionCache,
    native_modules: &mut FxHashMap<u32, NativeMapping>,
) -> Result<Option<NativeMapping>, ElfLoadError> {
    let is_vdso = module.path() == std::path::Path::new("[vdso]");
    if module.path.as_os_str().is_empty()
        || (module.path.as_os_str().as_encoded_bytes().starts_with(b"[") && !is_vdso)
    {
        return Err(ElfLoadError::Unsupported);
    }
    if let Some(template) = native_modules.get(&module.id) {
        let image = match elf_sections.acquire_image(module) {
            Ok(image) => Some(image),
            Err(ElfLoadError::Unsupported) if is_vdso => None,
            Err(error) => return Err(error),
        };
        return Ok(Some(template.with_image(image)));
    }
    let mapping = elf_sections.load_mapping(module)?;
    let image_base = mapping.image_base.ok_or(ElfLoadError::Unsupported)?;
    if mapping.image.is_none() && !is_vdso {
        return Ok(None);
    }
    let template = NativeMapping::from_recording(
        module.path.clone(),
        module.start..module.end,
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
    let batch_module = template.with_image(mapping.image);
    native_modules.insert(module.id, template);
    Ok(Some(batch_module))
}

fn retain_ranges<T>(values: &mut Vec<T>, ranges: impl IntoIterator<Item = Range<usize>>) {
    let mut old_index = 0;
    let mut ranges = ranges.into_iter().peekable();
    values.retain(|_| {
        while ranges.peek().is_some_and(|range| old_index >= range.end) {
            ranges.next();
        }
        let retained = ranges
            .peek()
            .is_some_and(|range| range.contains(&old_index));
        old_index += 1;
        retained
    });
}

impl Symbolizer {
    /// Create a resolver for the modules in a profile.
    #[cfg(test)]
    fn new(modules: &[ModuleRecord]) -> Self {
        SymbolizerBuilder::for_modules(modules)
            .perf_map_dir(std::env::temp_dir())
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
        if let Some(images) = reader.exact_images() {
            symbolizer.elf_sections = ElfSectionCache::using_exact_images(images);
        }
        symbolizer.source_id = Some(reader.source_id());
        if matches!(kernel_source, KernelSymbolSource::Host) {
            let addresses = reader
                .frames()
                .iter()
                .filter_map(|frame| (frame.mode == FrameMode::Kernel).then_some(frame.abs_ip));
            if reader.is_growing() {
                symbolizer.load_live_kernel_symbols(addresses, reader.modules());
            } else {
                symbolizer.kernel_symbols = Some(kernel::load_sparse_kernel_symbols_for_spool(
                    addresses,
                    reader.modules(),
                ));
            }
        }
        if reader.is_growing() {
            symbolizer.resolution_cache_limit = Some(LIVE_RESOLVED_FRAME_LIMIT);
        }
        symbolizer.tracks_perf_map_updates = reader.is_growing();
        symbolizer.spool_frame_contexts = Some(reader.frame_module_contexts());
        let frame_count = reader.frames().len();
        symbolizer.frame_cache.reserve(frame_count);
        symbolizer.resolved_frames.reserve(frame_count);
        symbolizer.resolved_frame_ids.reserve(frame_count);
        Ok(symbolizer)
    }

    fn load_live_kernel_symbols(
        &mut self,
        addresses: impl Iterator<Item = u64>,
        modules: &[ModuleRecord],
    ) {
        let mut addresses = addresses.peekable();
        if addresses.peek().is_none() {
            return;
        }
        let symbols = kernel::load_shared_kernel_symbols();
        self.kernel_symbols = Some(if symbols.is_empty() {
            kernel::load_sparse_kernel_symbols_for_spool(addresses, modules)
        } else {
            self.refresh_host_kernel_symbols = false;
            symbols
        });
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
            identity: NEXT_SYMBOLIZER_ID.fetch_add(1, Ordering::Relaxed),
            source_id: None,
            modules,
            perf_map_processes,
            perf_map_dir,
            elf_sections: ElfSectionCache::default(),
            native_symbolizers: FxHashMap::default(),
            native_generation_by_process: FxHashMap::default(),
            staged_native_generations: Vec::new(),
            native_changed_process_ids: FxHashSet::default(),
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
            perf_maps: FxHashMap::default(),
            tracks_perf_map_updates: false,
            pending_retired_processes: Vec::new(),
            pending_retired_modules: Vec::new(),
            inactive_modules: FxHashSet::default(),
            kernel_symbols,
            refresh_host_kernel_symbols: matches!(kernel_source, KernelSymbolSource::Host),
            spool_frame_contexts: None,
            frame_cache: FxHashMap::default(),
            resolved_frames: Vec::new(),
            resolved_frame_ids: Vec::new(),
            resolution_cache_limit: None,
            next_resolved_frame_id: 0,
            resolved_stack_frame_ids: Vec::new(),
            stack_cache_mode: StackCache::Internal,
            stack_cache: FxHashMap::default(),
            resolved_stack_scratch: Vec::new(),
            invalidated_process_ids: FxHashSet::default(),
            perf_map_changed_process_ids: FxHashSet::default(),
            mapping_changed_process_ids: FxHashSet::default(),
            native_factory,
        })
    }

    pub(crate) fn refresh_native_sources(&mut self) -> crate::Result<()> {
        self.staged_native_generations.clear();
        for (&process, backend) in &mut self.native_symbolizers {
            if self
                .pending_retired_processes
                .iter()
                .any(|retired| retired.get() == process)
            {
                continue;
            }
            let generation = match backend.refresh() {
                Ok(generation) => generation,
                Err(error) => {
                    self.staged_native_generations.clear();
                    return Err(crate::Error::native(error));
                }
            };
            self.staged_native_generations.push((process, generation));
        }
        Ok(())
    }

    fn invalidate_refreshed_native_sources(&mut self) {
        self.native_changed_process_ids.clear();
        for &(process, generation) in &self.staged_native_generations {
            if self.native_generation_by_process.get(&process) != Some(&generation) {
                if let Some(process) = crate::Pid::new(process) {
                    self.invalidated_process_ids.insert(process);
                    self.native_changed_process_ids.insert(process);
                }
            }
        }
    }

    /// Apply each batch exactly once, before resolving its stacks.
    pub(crate) fn update<'a>(
        &'a mut self,
        batch: &TailBatch<'_>,
    ) -> crate::Result<Invalidation<'a>> {
        if self.source_id != Some(batch.source_id()) {
            return Err(crate::Error::message(
                crate::ErrorKind::InvalidInput,
                "tail batch belongs to a different spool source",
            ));
        }

        self.invalidated_process_ids.clear();
        self.invalidate_refreshed_native_sources();
        self.perf_map_changed_process_ids.clear();
        self.mapping_changed_process_ids.clear();
        for module_id in self.pending_retired_modules.drain(..) {
            if let Some(process) = self.modules.get(module_id).and_then(ModuleRecord::pid) {
                self.mapping_changed_process_ids.insert(process.get());
                if let (Some(symbolizer), Some(module)) = (
                    self.native_symbolizers.get_mut(&process.get()),
                    self.native_modules.get(&module_id),
                ) {
                    symbolizer.retire_mapping(module);
                }
            }
            self.inactive_modules.insert(module_id);
            self.native_modules.remove(&module_id);
            self.unsupported_native_modules.remove(&module_id);
            self.retryable_native_modules.remove(&module_id);
            self.elf_sections.remove(module_id);
        }
        for process in self.pending_retired_processes.drain(..) {
            self.invalidated_process_ids.insert(process);
            self.native_symbolizers.remove(&process.get());
            self.native_generation_by_process.remove(&process.get());
            self.perf_maps.remove(&process.get());
        }

        let new_modules = batch.modules();
        if !new_modules.is_empty() {
            for module in new_modules {
                if let Some(process) = module.pid() {
                    self.mapping_changed_process_ids.insert(process.get());
                }
                self.modules.push(module.clone())?;
            }
        }
        #[cfg(any(test, feature = "bench-support"))]
        if !self.mapping_changed_process_ids.is_empty() {
            self.frame_cache.retain(|(process_id, key), _| {
                !matches!(key, FrameCacheKey::Raw(_))
                    || !self.mapping_changed_process_ids.contains(process_id)
            });
        }
        if batch.frame_contexts_changed() {
            self.spool_frame_contexts = Some(batch.frame_module_contexts());
        }

        for process in batch.processes() {
            if !self.perf_maps_allowed_for(process.get()) {
                continue;
            }
            let identity = perf_map_file_identity(&self.perf_map_dir, process.get());
            if batch.retired_processes().contains(process) && identity.is_none() {
                self.perf_maps.entry(process.get()).or_insert(PerfMapState {
                    identity: None,
                    map: None,
                });
                continue;
            }
            let state = self.perf_maps.entry(process.get());
            let had_map = matches!(state, std::collections::hash_map::Entry::Occupied(_));
            let state = state.or_insert_with(|| PerfMapState {
                identity,
                map: load_perf_map(&self.perf_map_dir, process.get()),
            });
            let retry_failed_load = identity.is_some() && state.map.is_none();
            let changed = state.identity != identity;
            let recovered = if had_map && (changed || retry_failed_load) {
                let map = load_perf_map(&self.perf_map_dir, process.get());
                let recovered = retry_failed_load && map.is_some();
                state.identity = identity;
                state.map = map;
                recovered
            } else {
                false
            };
            if (changed && had_map) || recovered {
                self.invalidated_process_ids.insert(*process);
                self.perf_map_changed_process_ids.insert(*process);
            }
        }

        let initialize_kernel = self.refresh_host_kernel_symbols && self.kernel_symbols.is_none();
        if initialize_kernel {
            self.load_live_kernel_symbols(
                batch
                    .frames()
                    .iter()
                    .filter_map(|frame| (frame.mode == FrameMode::Kernel).then_some(frame.abs_ip)),
                batch.all_modules(),
            );
        }
        let kernel_changed = batch.kernel_mappings_changed() && self.refresh_host_kernel_symbols;
        let resolution_cache_full = self.resolution_cache_full();
        let all = kernel_changed;
        if kernel_changed && !initialize_kernel {
            self.kernel_symbols = Some(kernel::load_sparse_kernel_symbols_for_spool(
                batch
                    .all_frames()
                    .iter()
                    .filter_map(|frame| (frame.mode == FrameMode::Kernel).then_some(frame.abs_ip)),
                batch.all_modules(),
            ));
        } else if self.refresh_host_kernel_symbols && !initialize_kernel {
            if let Some(symbols) = self.kernel_symbols.as_mut() {
                kernel::extend_sparse_kernel_symbols_for_spool(
                    symbols,
                    batch.frames().iter().filter_map(|frame| {
                        (frame.mode == FrameMode::Kernel).then_some(frame.abs_ip)
                    }),
                    batch.all_modules(),
                );
            }
        }
        if kernel_changed || resolution_cache_full {
            self.clear_resolution_cache();
        } else if !self.invalidated_process_ids.is_empty() {
            self.frame_cache.retain(|&(process_id, _), cached| {
                let Some(process) = crate::Pid::new(process_id) else {
                    return true;
                };
                !self.invalidated_process_ids.contains(&process)
                    || (self.perf_map_changed_process_ids.contains(&process)
                        && !self.native_changed_process_ids.contains(&process)
                        && !cached.perf_map_dependent)
            });
            if self.stack_cache_mode == StackCache::Internal {
                self.stack_cache
                    .retain(|key, _| !self.invalidated_process_ids.contains(&key.process_id()));
                self.compact_resolved_stack_frame_ids();
            }
            self.compact_resolved_frames_if_needed();
        }

        // This batch can contain samples immediately before retirement. Drop
        // process-owned symbol state only after callers have resolved them.
        self.pending_retired_processes
            .extend_from_slice(batch.retired_processes());
        self.pending_retired_modules
            .extend_from_slice(batch.retired_modules());
        for (process, generation) in self.staged_native_generations.drain(..) {
            self.native_generation_by_process
                .insert(process, generation);
        }
        Ok(Invalidation {
            all,
            processes: &self.invalidated_process_ids,
        })
    }

    fn clear_resolution_cache(&mut self) {
        self.clear_transient_frame_cache();
        self.transient_frame_slots.clear();
        self.vacant_frame_slots.clear();
        self.frame_cache.clear();
        self.resolved_frames.clear();
        self.resolved_frame_ids.clear();
        self.clear_stack_resolution_cache();
    }

    fn resolution_cache_full(&self) -> bool {
        self.resolution_cache_limit.is_some_and(|limit| {
            self.resolved_frames.len() >= limit
                || self.resolved_stack_frame_ids.len() >= limit
                || self.stack_cache.len() >= limit
        })
    }

    fn clear_stack_resolution_cache(&mut self) {
        self.stack_cache.clear();
        self.resolved_stack_frame_ids.clear();
        self.resolved_stack_scratch.clear();
    }

    fn compact_resolved_stack_frame_ids(&mut self) {
        let retained = self.stack_cache.values().map(Range::len).sum::<usize>();
        if retained == self.resolved_stack_frame_ids.len() {
            return;
        }
        let mut ranges = self
            .stack_cache
            .iter()
            .map(|(&key, range)| (key, range.clone()))
            .collect::<Vec<_>>();
        ranges.sort_unstable_by_key(|(_, range)| range.start);

        let mut next = 0;
        for (key, range) in ranges {
            let len = range.len();
            self.resolved_stack_frame_ids.copy_within(range, next);
            self.stack_cache.insert(key, next..next + len);
            next += len;
        }
        self.resolved_stack_frame_ids.truncate(next);
    }

    fn compact_resolved_frames_if_needed(&mut self) {
        const MIN_STALE_FRAMES: usize = 4_096;

        let retained = self
            .frame_cache
            .values()
            .map(ResolvedFrameRange::len)
            .sum::<usize>();
        let stale = self.resolved_frames.len().saturating_sub(retained);
        if stale == 0 || (stale < MIN_STALE_FRAMES && stale < retained / 2) {
            return;
        }

        // Retry slots are indices into `resolved_frames`. Compaction changes
        // those indices, so a later retry must append a fresh result.
        self.transient_frame_slots.clear();
        self.vacant_frame_slots.clear();

        let mut cached_frames = self.frame_cache.values_mut().collect::<Vec<_>>();
        cached_frames.sort_unstable_by_key(|range| range.indices.start);
        retain_ranges(
            &mut self.resolved_frames,
            cached_frames.iter().map(|range| range.indices()),
        );
        retain_ranges(
            &mut self.resolved_frame_ids,
            cached_frames.iter().map(|range| range.indices()),
        );
        let mut next = 0;
        for range in cached_frames {
            let len = range.len();
            range.relocate(next);
            next += len;
        }
        debug_assert_eq!(self.resolved_frames.len(), next);
        debug_assert_eq!(self.resolved_frame_ids.len(), next);

        // Frame results remain cached, but stack indices change during
        // compaction and must be rebuilt on the next lookup.
        self.clear_stack_resolution_cache();
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
    /// A result can be provisional when opening a validated native image fails
    /// with a retryable error. StackPulse does not permanently cache that
    /// fallback frame, so resolving the stack again after the image becomes
    /// available can return more specific symbols. Managed sessions also keep
    /// provisional results out of their transformed-stack cache.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when `stack` belongs to another spool.
    /// Native backend failures use
    /// [`ErrorKind::NativeSymbolizer`](crate::ErrorKind::NativeSymbolizer).
    pub fn resolve(&mut self, stack: spool::Stack<'_>) -> crate::Result<ResolvedStack<'_>> {
        let key = stack.key();
        let process = stack.pid();
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
                    frame_ids: &self.resolved_frame_ids,
                    indices: &self.resolved_stack_frame_ids[range],
                    cacheable: true,
                });
            }
        }

        if self.resolution_cache_full() {
            self.clear_resolution_cache();
        }

        let mut frames = stack.raw_frames();
        self.begin_frame_batch(frames.len());
        let mut pending = frames.clone();
        while let Some(frame_ref) = pending.next_with_id() {
            self.prepare_frame(
                process.get(),
                *frame_ref.frame,
                FrameCacheKey::Spool(frame_ref.id),
                Some(frame_ref.id),
            );
        }
        self.finish_frame_batch(process.get())?;

        if self.stack_cache_mode == StackCache::Internal && self.transient_frame_keys.is_empty() {
            let start = self.resolved_stack_frame_ids.len();
            while let Some(frame_ref) = frames.next_with_id() {
                let frame_ids =
                    self.cached_frame_ids(process.get(), FrameCacheKey::Spool(frame_ref.id))?;
                self.resolved_stack_frame_ids.extend(frame_ids);
            }
            let range = start..self.resolved_stack_frame_ids.len();
            self.stack_cache.insert(key, range.clone());
            return Ok(ResolvedStack {
                frames: &self.resolved_frames,
                frame_ids: &self.resolved_frame_ids,
                indices: &self.resolved_stack_frame_ids[range],
                cacheable: true,
            });
        }

        let cacheable = self.transient_frame_keys.is_empty();
        self.resolved_stack_scratch.clear();
        while let Some(frame_ref) = frames.next_with_id() {
            let frame_ids =
                self.cached_frame_ids(process.get(), FrameCacheKey::Spool(frame_ref.id))?;
            self.resolved_stack_scratch.extend(frame_ids);
        }
        self.clear_transient_frame_cache();
        Ok(ResolvedStack {
            frames: &self.resolved_frames,
            frame_ids: &self.resolved_frame_ids,
            indices: &self.resolved_stack_scratch,
            cacheable,
        })
    }

    /// Resolve a caller-owned raw frame slice without retaining a stack entry.
    ///
    /// A fallback caused by a retryable native-image open failure is
    /// provisional and can improve on a later call.
    ///
    /// # Errors
    ///
    /// Native backend failures use
    /// [`ErrorKind::NativeSymbolizer`](crate::ErrorKind::NativeSymbolizer).
    #[cfg(any(test, feature = "bench-support"))]
    pub(crate) fn resolve_raw(
        &mut self,
        process_id: crate::Pid,
        frames: &[FrameRecord],
    ) -> crate::Result<ResolvedStack<'_>> {
        if frames.iter().any(|frame| {
            frame.mode == FrameMode::TruncatedStackMarker && !frame.is_truncated_stack_marker()
        }) {
            return Err(crate::Error::message(
                crate::ErrorKind::InvalidInput,
                "invalid truncated stack marker frame",
            ));
        }
        if self.resolution_cache_full() {
            self.clear_resolution_cache();
        }
        self.begin_frame_batch(frames.len());
        for frame in frames {
            self.prepare_frame(process_id.get(), *frame, FrameCacheKey::Raw(*frame), None);
        }
        self.finish_frame_batch(process_id.get())?;
        let cacheable = self.transient_frame_keys.is_empty();
        self.resolved_stack_scratch.clear();
        self.resolved_stack_scratch.reserve(frames.len());
        for frame in frames {
            let frame_ids = self.cached_frame_ids(process_id.get(), FrameCacheKey::Raw(*frame))?;
            self.resolved_stack_scratch.extend(frame_ids);
        }
        self.clear_transient_frame_cache();
        Ok(ResolvedStack {
            frames: &self.resolved_frames,
            frame_ids: &self.resolved_frame_ids,
            indices: &self.resolved_stack_scratch,
            cacheable,
        })
    }

    #[cfg(test)]
    fn resolve_cached_frame_ref(&mut self, process_id: i32, frame: &FrameRecord) -> &Frame {
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
        if let Some(cached) = self.frame_cache.get(&cache_key) {
            return Ok(cached.indices());
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
            .map(ResolvedFrameRange::indices)
            .ok_or_else(|| NativeContractError::CacheMiss.into_public())
    }

    #[cfg(test)]
    fn resolve_frame(&mut self, process_id: i32, frame: &FrameRecord) -> Frame {
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
                perf_map_dependent: false,
            });
            return;
        }

        let perf_map_dependent =
            self.perf_maps_allowed_for(process_id) && frame.mode == FrameMode::User;
        let perf_map_symbol = if perf_map_dependent {
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
                    perf_map_dependent: false,
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
                perf_map_dependent: true,
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
            perf_map_dependent,
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
        if !self.native_batch_modules.contains_key(&module.id) {
            match prepare_native_mapping(
                module,
                metadata.is_python_runtime,
                &mut self.elf_sections,
                &mut self.native_modules,
            ) {
                Ok(Some(mapping)) => {
                    self.native_batch_modules.insert(module.id, mapping);
                }
                Ok(None) => {
                    return NativeLookupPreparation {
                        transient: true,
                        ..NativeLookupPreparation::default()
                    };
                }
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
            }
        }
        let Some(pid) = crate::Pid::new(process_id) else {
            return NativeLookupPreparation::default();
        };
        let Some(native_module) = self.native_batch_modules.get(&module.id) else {
            return NativeLookupPreparation::default();
        };
        let Some(request) = NativeLookup::new(pid, native_module.clone(), absolute_address) else {
            return NativeLookupPreparation::default();
        };
        let request_index = self.native_requests.len();
        self.native_requests.push(request);
        NativeLookupPreparation {
            request_index: Some(request_index),
            transient: false,
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "resolved frames and their IDs are appended and removed together"
    )]
    fn finish_frame_batch(&mut self, process_id: i32) -> crate::Result<()> {
        if !self.native_requests.is_empty() {
            self.native_results
                .resize_with(self.native_requests.len(), NativeSymbols::default);
            let process_id = crate::Pid::try_from(process_id)
                .map_err(|error| crate::Error::new(crate::ErrorKind::InvalidInput, error))?;
            if !self.native_symbolizers.contains_key(&process_id.get()) {
                let Some(factory) = self.native_factory.as_mut() else {
                    self.clear_frame_batch();
                    return Err(NativeContractError::FactoryUnavailable.into_public());
                };
                let mut backend = match factory(process_id) {
                    Ok(backend) => backend,
                    Err(error) => {
                        self.clear_frame_batch();
                        return Err(crate::Error::native(error));
                    }
                };
                let generation = match backend.refresh() {
                    Ok(generation) => generation,
                    Err(error) => {
                        self.clear_frame_batch();
                        return Err(crate::Error::native(error));
                    }
                };
                self.native_generation_by_process
                    .insert(process_id.get(), generation);
                self.native_symbolizers.insert(process_id.get(), backend);
            }
            let Some(backend) = self.native_symbolizers.get_mut(&process_id.get()) else {
                self.clear_frame_batch();
                return Err(NativeContractError::BackendUnavailable.into_public());
            };
            if let Err(error) = backend.symbolize(NativeBatch::new(
                &self.native_requests,
                &mut self.native_results,
            )) {
                self.clear_frame_batch();
                return Err(crate::Error::native(error));
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
                PendingResolution::PerfMap(frame) => self.push_resolved_frame(frame),
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
                        let replacement_id = self
                            .resolved_frame_ids
                            .pop()
                            .expect("every resolved frame has an ID");
                        self.resolved_frame_ids[slot] = replacement_id;
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
            self.frame_cache.insert(
                pending.cache_key,
                ResolvedFrameRange {
                    indices: frame_range,
                    perf_map_dependent: pending.perf_map_dependent,
                },
            );
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

    #[expect(
        clippy::expect_used,
        reason = "a process cannot produce u64::MAX unique resolved frames"
    )]
    fn push_resolved_frame(&mut self, frame: Frame) {
        let id = FrameKey {
            owner: self.identity,
            serial: self.next_resolved_frame_id,
        };
        self.next_resolved_frame_id = self
            .next_resolved_frame_id
            .checked_add(1)
            .expect("resolved frame ID space exhausted");
        self.resolved_frames.push(frame);
        self.resolved_frame_ids.push(id);
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
            (Some(contexts), Some(frame_id)) => spool::module_for_frame_with_context(
                self.modules.records(),
                contexts,
                frame_id,
                process_id,
                frame,
            ),
            _ => spool::module_for_frame_unbounded(
                self.modules.records(),
                process_id,
                frame,
                |module| !self.inactive_modules.contains(&module.id),
            ),
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
        let Frame::Native(frame) = self.resolved_frames[start].clone() else {
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
            self.push_resolved_frame(Frame::TruncatedStack);
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
                self.push_resolved_frame(Frame::Native(NativeFrame::from_address(frame.abs_ip)));
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
                let symbol = NativeSymbol::new(symbol_name, module_name).with_offset(offset);
                self.push_resolved_frame(Frame::Native(NativeFrame {
                    pc: frame.abs_ip,
                    symbol: Some(symbol),
                    address_space: AddressSpace::Kernel,
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
                    for symbol in symbols {
                        let mut flags = FrameFlags::empty();
                        flags.set(FrameFlags::PYTHON_RUNTIME, is_python_runtime);
                        flags.set(FrameFlags::HIDDEN_DEFAULT, symbol.is_hidden_by_default());
                        self.push_resolved_frame(Frame::Native(NativeFrame {
                            pc: frame.abs_ip,
                            symbol: Some(symbol),
                            address_space: AddressSpace::User,
                            origin: SymbolOrigin::Elf,
                            flags,
                        }));
                    }
                    return;
                }

                let Some((module, module_metadata)) = self.modules.get_with_metadata_mut(module_id)
                else {
                    self.push_resolved_frame(Frame::Native(NativeFrame::from_address(
                        frame.abs_ip,
                    )));
                    return;
                };
                let path = module_metadata.path.get_or_insert_with(|| {
                    normalized_module_path(&module.path)
                        .to_string_lossy()
                        .as_ref()
                        .into()
                });
                let symbol_name =
                    format_hex_suffix(&path[module_metadata.basename_start..], file_relative_ip);
                // Pseudo-symbol without a function: the name embeds the
                // file-relative address, so the function offset is 0.
                let symbol = NativeSymbol::new(symbol_name, std::rc::Rc::clone(path));
                let symbol = if is_python_runtime {
                    symbol.hidden_by_default()
                } else {
                    symbol
                };
                self.push_resolved_frame(Frame::Native(NativeFrame {
                    pc: frame.abs_ip,
                    symbol: Some(symbol),
                    address_space: AddressSpace::User,
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
        self.perf_maps
            .entry(process_id)
            .or_insert_with(|| PerfMapState {
                identity: self
                    .tracks_perf_map_updates
                    .then(|| perf_map_file_identity(&self.perf_map_dir, process_id))
                    .flatten(),
                map: load_perf_map(&self.perf_map_dir, process_id),
            })
            .map
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
        std::env::temp_dir()
            .join(format!("perf-{process_id}.map"))
            .to_string_lossy()
            .into_owned()
    }

    fn frame(abs_ip: u64) -> FrameRecord {
        FrameRecord {
            module_id: None,
            file_relative_ip: abs_ip,
            abs_ip,
            mode: FrameMode::User,
        }
    }

    #[test]
    fn frame_compaction_preserves_inline_chains_and_keys_across_stale_gaps() {
        let mut symbolizer = Symbolizer::new(&[]);
        let inline: NativeSymbols = [
            NativeSymbol::new("inner", "module"),
            NativeSymbol::new("outer", "module"),
        ]
        .into_iter()
        .collect();
        let mut expected = inline
            .into_iter()
            .map(|symbol| {
                Frame::Native(NativeFrame {
                    pc: 0x1000,
                    symbol: Some(symbol),
                    address_space: AddressSpace::User,
                    origin: SymbolOrigin::Elf,
                    flags: FrameFlags::empty(),
                })
            })
            .collect::<Vec<_>>();
        expected.push(Frame::Native(NativeFrame::from_address(0x2000)));
        let stale = Frame::Native(NativeFrame::from_address(0x3000));
        for frame in [
            stale.clone(),
            expected[0].clone(),
            expected[1].clone(),
            stale.clone(),
            expected[2].clone(),
            stale,
        ] {
            symbolizer.push_resolved_frame(frame);
        }
        let expected_keys = [1, 2, 4].map(|index| symbolizer.resolved_frame_ids[index]);
        let inline_key = (7, FrameCacheKey::Raw(frame(0x1000)));
        let outer_key = (7, FrameCacheKey::Raw(frame(0x2000)));
        symbolizer.frame_cache.insert(
            inline_key,
            ResolvedFrameRange {
                indices: 1..3,
                perf_map_dependent: false,
            },
        );
        symbolizer.frame_cache.insert(
            outer_key,
            ResolvedFrameRange {
                indices: 4..5,
                perf_map_dependent: true,
            },
        );
        symbolizer
            .transient_frame_slots
            .insert((7, FrameCacheKey::Raw(frame(0x3000))), 3);
        symbolizer.vacant_frame_slots.extend([0, 5]);
        symbolizer.resolved_stack_frame_ids.extend([1, 2, 4]);
        symbolizer.resolved_stack_scratch.extend([4, 1, 2]);

        symbolizer.compact_resolved_frames_if_needed();

        assert_eq!(symbolizer.resolved_frames, expected);
        assert_eq!(symbolizer.resolved_frame_ids, expected_keys);
        assert_eq!(symbolizer.frame_cache[&inline_key].indices(), 0..2);
        assert_eq!(symbolizer.frame_cache[&outer_key].indices(), 2..3);
        assert!(symbolizer.frame_cache[&outer_key].perf_map_dependent);
        assert!(symbolizer.transient_frame_slots.is_empty());
        assert!(symbolizer.vacant_frame_slots.is_empty());
        assert!(symbolizer.resolved_stack_frame_ids.is_empty());
        assert!(symbolizer.resolved_stack_scratch.is_empty());
        let resolved = symbolizer
            .resolve_raw(crate::Pid::new(7).unwrap(), &[frame(0x1000), frame(0x2000)])
            .unwrap();
        assert_eq!(
            resolved.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            expected_keys
        );
        assert_eq!(resolved.frames().cloned().collect::<Vec<_>>(), expected);
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
            path: std::path::Path::new(path).into(),
        }
    }

    pub(super) fn current_executable_module(id: u32, process_id: i32) -> ModuleRecord {
        let executable = std::env::current_exe().expect("current test executable");
        let maps = fs::read_to_string("/proc/self/maps").expect("current process maps");
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&executable).unwrap();
        let region = crate::proc_maps::parse_iter(&maps)
            .find(|region| region.is_executable && region.path == executable)
            .expect("executable mapping");
        ModuleRecord {
            id,
            owner: user_owner(process_id),
            start: region.address.start,
            end: region.address.end,
            file_offset: region.file_offset,
            inode: metadata.ino(),
            device_major: libc::major(metadata.dev()) as u32,
            device_minor: libc::minor(metadata.dev()) as u32,
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

        fn symbolize(&mut self, batch: NativeBatch<'_>) -> Result<(), Self::Error> {
            self.batches.borrow_mut().push(
                batch
                    .lookups()
                    .iter()
                    .map(|request| (request.absolute_address(), request.relative_address()))
                    .collect(),
            );
            Ok(())
        }
    }

    struct RetirementRecordingSymbolizer {
        retired_modules: Rc<RefCell<Vec<u32>>>,
    }

    impl NativeSymbolizer for RetirementRecordingSymbolizer {
        type Error = std::convert::Infallible;

        fn symbolize(&mut self, _batch: NativeBatch<'_>) -> Result<(), Self::Error> {
            Ok(())
        }

        fn retire_mapping(&mut self, module: &NativeMapping) {
            self.retired_modules.borrow_mut().push(module.mapping_id());
        }
    }

    struct CountingNativeSymbolizer {
        calls: Rc<Cell<usize>>,
    }

    impl NativeSymbolizer for CountingNativeSymbolizer {
        type Error = std::convert::Infallible;

        fn symbolize(&mut self, mut batch: NativeBatch<'_>) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            for (request, output) in batch.entries() {
                *output = NativeSymbols::from(NativeSymbol::new(
                    "resolved-after-retry",
                    request.mapping().name_rc().clone(),
                ));
            }
            Ok(())
        }
    }

    struct DescriptorRecordingSymbolizer {
        descriptors: Rc<RefCell<Vec<bool>>>,
    }

    impl NativeSymbolizer for DescriptorRecordingSymbolizer {
        type Error = std::convert::Infallible;

        fn symbolize(&mut self, mut batch: NativeBatch<'_>) -> Result<(), Self::Error> {
            self.descriptors.borrow_mut().extend(
                batch
                    .lookups()
                    .iter()
                    .map(|request| request.mapping().image_path().is_some()),
            );
            for (request, output) in batch.entries() {
                *output = NativeSymbols::from(NativeSymbol::new(
                    "cached-image",
                    request.mapping().name_rc().clone(),
                ));
            }
            Ok(())
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("sentinel native-symbolizer failure")]
    struct SentinelNativeError;

    struct FailingNativeSymbolizer;

    impl NativeSymbolizer for FailingNativeSymbolizer {
        type Error = SentinelNativeError;

        fn symbolize(&mut self, _batch: NativeBatch<'_>) -> Result<(), Self::Error> {
            Err(SentinelNativeError)
        }
    }

    struct EmptyNativeSymbolizer;

    impl NativeSymbolizer for EmptyNativeSymbolizer {
        type Error = std::convert::Infallible;

        fn symbolize(&mut self, _batch: NativeBatch<'_>) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn resolved_frame_keys_are_scoped_to_the_owner_and_never_reused() {
        let pid = crate::Pid::new(7).unwrap();
        let mut first = SymbolizerBuilder::for_modules(&[])
            .disable_perf_maps()
            .build()
            .unwrap();
        let mut second = SymbolizerBuilder::for_modules(&[])
            .disable_perf_maps()
            .build()
            .unwrap();
        let frame = frame(0x1234);
        let first_key = first
            .resolve_raw(pid, &[frame])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .0;
        let second_key = second
            .resolve_raw(pid, &[frame])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .0;
        assert_ne!(first_key, second_key);
        first.clear_resolution_cache();
        let refreshed_key = first
            .resolve_raw(pid, &[frame])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .0;
        assert_ne!(first_key, refreshed_key);
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
    fn unfilled_native_entries_remain_unresolved() {
        let pid = crate::Pid::try_from(std::process::id()).unwrap();
        let module = current_executable_module(0, pid.get());
        let frame = pinned_frame(0, module.start + 8);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(|_| EmptyNativeSymbolizer)
            .build()
            .unwrap();
        let resolved = symbolizer.resolve_raw(pid, &[frame]).unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(matches!(resolved.frames().next(), Some(Frame::Native(_))));
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

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &frames)
                .unwrap()
                .frames()
                .count(),
            2
        );
        let recorded = batches.borrow();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].len(), 2);
        assert_eq!(recorded[0][0].0, frames[0].abs_ip);
        assert_eq!(recorded[0][1].0, frames[1].abs_ip);
        assert_eq!(recorded[0][1].1 - recorded[0][0].1, 8);
        drop(recorded);

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &frames)
                .unwrap()
                .frames()
                .count(),
            2
        );
        assert_eq!(batches.borrow().len(), 1);
    }

    #[test]
    fn live_module_retirement_notifies_backend_without_invalidating_stack() {
        let temp = crate::test_support::TempDir::new("symbolize-narrow-invalidation");
        let path = temp.path().join("recording.spool");
        let pid = crate::Pid::try_from(std::process::id()).unwrap();
        let retired_modules = Rc::new(RefCell::new(Vec::new()));
        let backend_retired_modules = Rc::clone(&retired_modules);
        let mut writer = PerfSpoolWriter::create(&path, 0, 10).unwrap();
        writer.flush().unwrap();
        let mut tail = Tail::open(&path).unwrap();
        assert_eq!(tail.poll().unwrap().samples().count(), 0);
        let mut symbolizer = tail
            .symbolizer()
            .stack_cache(StackCache::External)
            .disable_perf_maps()
            .native(move |_| RetirementRecordingSymbolizer {
                retired_modules: Rc::clone(&backend_retired_modules),
            })
            .build()
            .unwrap();

        let module = current_executable_module(0, pid.get());
        let frame = pinned_frame(0, module.start + 8);
        writer.write_module(&module).unwrap();
        writer.flush().unwrap();
        {
            let batch = tail.poll().unwrap();
            let invalidation = symbolizer.update(&batch).unwrap();
            assert!(!invalidation.all());
            assert!(!invalidation.affects_process(pid));
        }
        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[frame])
                .unwrap()
                .frames()
                .count(),
            1
        );

        writer.write_module_deactivation_one(0).unwrap();
        writer.flush().unwrap();
        {
            let batch = tail.poll().unwrap();
            let invalidation = symbolizer.update(&batch).unwrap();
            assert!(!invalidation.affects_process(pid));
        }
        assert!(retired_modules.borrow().is_empty());
        let batch = tail.poll().unwrap();
        let invalidation = symbolizer.update(&batch).unwrap();
        assert!(!invalidation.affects_process(pid));
        assert_eq!(&*retired_modules.borrow(), &[0]);
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
        module.path = path.as_path().into();
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
            .frames()
            .next()
            .unwrap();
        assert!(matches!(
            first,
            Frame::Native(frame) if frame.origin == SymbolOrigin::AddressOnly
        ));
        assert_eq!(calls.get(), 0);
        assert!(symbolizer.native_modules.is_empty());
        assert!(symbolizer.unsupported_native_modules.is_empty());

        fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let second = symbolizer
            .resolve_raw(pid, &frames)
            .unwrap()
            .frames()
            .next()
            .unwrap();
        assert_eq!(second.to_string(), "resolved-after-retry");
        assert_eq!(calls.get(), 1);
        assert_eq!(symbolizer.resolved_frames.len(), frames.len());
        assert!(symbolizer.native_batch_modules.is_empty());
        assert!(symbolizer
            .native_modules
            .values()
            .all(|module| module.image_path().is_none()));

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &frames)
                .unwrap()
                .frames()
                .count(),
            2
        );
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
        module.path = path.as_path().into();
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

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert!(!symbolizer.unsupported_native_modules.contains(&module_id));
        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert!(symbolizer.unsupported_native_modules.contains(&module_id));
        let resolved_frame_count = symbolizer.resolved_frames.len();

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
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
        module.path = path.as_path().into();
        let module_id = module.id;
        let frame = pinned_frame(0, module.start + 8);
        let mut symbolizer = SymbolizerBuilder::for_modules(&[module])
            .disable_perf_maps()
            .native(|_| EmptyNativeSymbolizer)
            .build()
            .unwrap();

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert!(symbolizer.unsupported_native_modules.contains(&module_id));
        let resolved_frame_count = symbolizer.resolved_frames.len();

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert_eq!(symbolizer.resolved_frames.len(), resolved_frame_count);
    }

    #[test]
    fn cached_native_backend_is_not_called_after_the_image_disappears() {
        let temp = crate::test_support::TempDir::new("symbolize-native-cached-image");
        let path = temp.path().join("image");
        fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let pid = crate::Pid::new(2_000_000_000).unwrap();
        let mut module = current_executable_module(0, pid.get());
        module.inode = 0;
        module.device_major = 0;
        module.device_minor = 0;
        module.path = path.as_path().into();
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
                .frames()
                .next()
                .unwrap()
                .to_string(),
            "cached-image"
        );
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            symbolizer.resolve_raw(pid, &[second]).unwrap().frames().next(),
            Some(Frame::Native(frame)) if frame.origin == SymbolOrigin::AddressOnly
        ));
        assert_eq!(&*descriptors.borrow(), &[true]);

        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[second])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert_eq!(&*descriptors.borrow(), &[true]);
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

        assert_eq!(resolved.to_string(), "stable-seven.so+0x8");
        assert!(matches!(
            invalid,
            Frame::Native(frame) if frame.symbol.is_none()
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

        assert_eq!(resolved.to_string(), "module-zero.so+0x8");
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

        assert_eq!(resolved.to_string(), "[anon:sparse-seven]+0x8");
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
            Frame::Python(frame) => {
                assert_eq!(frame.func_name.as_ref(), "work");
                assert_eq!(frame.file_name(), "/tmp/app.py");
            }
            Frame::Native(_) | Frame::TruncatedStack => panic!("expected Python perf-map frame"),
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
            Frame::Python(frame) if frame.func_name.as_ref() == "first"
        ));
        assert!(matches!(
            gap,
            Frame::Native(frame) if frame.symbol.is_none()
        ));
        assert!(matches!(
            second,
            Frame::Python(frame) if frame.func_name.as_ref() == "second"
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
            Frame::Native(frame) => {
                assert_eq!(frame.address_space, AddressSpace::User);
                assert_eq!(frame.origin, SymbolOrigin::PerfMap);
                assert_eq!(frame.flags, FrameFlags::JIT);
                let symbol = frame.symbol.expect("perf-map native symbol");
                assert_eq!(symbol.name(), "jit_func");
                assert_eq!(symbol.module.as_ref(), temp_perf_map_path(process_id));
                assert_eq!(symbol.offset, 8);
            }
            Frame::Python(_) | Frame::TruncatedStack => panic!("expected native perf-map frame"),
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
            Frame::Native(frame) => assert!(frame.symbol.is_none()),
            Frame::Python(_) | Frame::TruncatedStack => {
                panic!("stale perf-map frame should be ignored")
            }
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
            .perf_map_dir(std::env::temp_dir())
            .perf_maps_for([crate::Pid::new(allowed_process).unwrap()])
            .build()
            .unwrap();
        let allowed = symbolizer.resolve_frame(allowed_process, &frame(0x2908));
        let blocked = symbolizer.resolve_frame(blocked_process, &frame(0x2908));
        let _ = fs::remove_file(&allowed_path);
        let _ = fs::remove_file(&blocked_path);

        match allowed {
            Frame::Python(frame) => assert_eq!(frame.func_name.as_ref(), "allowed"),
            Frame::Native(_) | Frame::TruncatedStack => {
                panic!("expected allowed Python perf-map frame")
            }
        }
        match blocked {
            Frame::Native(frame) => assert!(frame.symbol.is_none()),
            Frame::Python(_) | Frame::TruncatedStack => {
                panic!("unexpected blocked Python perf-map frame")
            }
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
            Frame::Native(frame) => {
                assert_eq!(frame.address_space, AddressSpace::User);
                assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
                assert!(!frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(!frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                assert!(!frame.is_python_runtime());
                assert_ne!(frame.to_string(), "fake_after_exec");
            }
            Frame::Python(_) | Frame::TruncatedStack => {
                panic!("non-Python module should block perf-map symbol")
            }
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
            Frame::Native(frame) if frame.origin == SymbolOrigin::AddressOnly
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
            Frame::Native(frame) => {
                assert_eq!(frame.address_space, AddressSpace::User);
                assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
                assert!(!frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(!frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                assert!(!frame.is_python_runtime());
                assert_ne!(frame.to_string(), "fake_after_exec");
            }
            Frame::Python(_) | Frame::TruncatedStack => {
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
            Frame::Native(frame) => {
                assert_ne!(frame.origin, SymbolOrigin::PerfMap);
                assert!(!frame.flags.contains(FrameFlags::JIT));
            }
            Frame::Python(_) | Frame::TruncatedStack => {
                panic!("memfd module should block perf-map symbol")
            }
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
            Frame::Python(frame) => assert_eq!(frame.func_name.as_ref(), "anon_code"),
            Frame::Native(_) | Frame::TruncatedStack => {
                panic!("anonymous Python code should allow perf-map symbol")
            }
        }
        match resolved_perf_anon {
            Frame::Python(frame) => assert_eq!(frame.func_name.as_ref(), "perf_anon_code"),
            Frame::Native(_) | Frame::TruncatedStack => {
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
                Frame::Native(frame) if frame.origin == SymbolOrigin::PerfMap
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
        let cached_frame = frame(0x3008);
        let first = symbolizer
            .resolve_cached_frame_ref(process_id, &cached_frame)
            .to_string();
        let second = symbolizer
            .resolve_cached_frame_ref(process_id, &cached_frame)
            .to_string();

        symbolizer.resolution_cache_limit = Some(1);
        let replacement = frame(0x4008);
        assert_eq!(
            symbolizer
                .resolve_raw(crate::Pid::new(process_id).unwrap(), &[replacement])
                .unwrap()
                .frames()
                .count(),
            1
        );
        let _ = fs::remove_file(&path);

        assert_eq!(symbolizer.frame_cache.len(), 1);
        assert_eq!(first, second);
        assert!(symbolizer
            .frame_cache
            .contains_key(&(process_id, FrameCacheKey::Raw(replacement))));
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
            Frame::Native(frame) => {
                assert_eq!(frame.address_space, AddressSpace::User);
                assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
                assert!(frame.is_python_runtime());
                assert!(frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                let symbol = frame.symbol.expect("fallback Python runtime symbol");
                assert!(symbol.is_hidden_by_default());
            }
            Frame::Python(_) | Frame::TruncatedStack => {
                panic!("Python runtime module should stay native")
            }
        }
    }

    #[test]
    fn native_runtime_and_hidden_flags_are_independent() {
        let process_id = 42;
        let python = module_with_path(0, process_id, 0x8000, "/usr/bin/python3");
        let native = module_with_path(1, process_id, 0x9000, "/usr/lib/libworker.so");
        let mut symbolizer = Symbolizer::new(&[python.clone(), native.clone()]);
        let visible = NativeSymbol::new("visible", "python3");
        let hidden = NativeSymbol::new("hidden", "libworker.so").hidden_by_default();

        symbolizer.append_native_frames(
            &pinned_frame(0, 0x8008),
            Some((python.id, 8)),
            Some(NativeSymbols::from(vec![visible])),
        );
        symbolizer.append_native_frames(
            &pinned_frame(1, 0x9008),
            Some((native.id, 8)),
            Some(NativeSymbols::from(vec![hidden])),
        );

        let Frame::Native(python_frame) = &symbolizer.resolved_frames[0] else {
            panic!("expected native Python-runtime frame")
        };
        assert!(python_frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
        assert!(!python_frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
        assert!(python_frame.is_python_runtime());

        let Frame::Native(hidden_frame) = &symbolizer.resolved_frames[1] else {
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

        assert_eq!(resolved.address_space, AddressSpace::Kernel);
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
    fn truncation_is_distinct_from_a_zero_address() {
        let mut symbolizer = Symbolizer::new(&[]);

        symbolizer.append_native_frames(&FrameRecord::truncated_stack_marker(), None, None);
        let marker = symbolizer.resolved_frames[0].clone();
        let null_pc = symbolizer.resolve_native_frame(
            &FrameRecord {
                module_id: None,
                file_relative_ip: 0,
                abs_ip: 0,
                mode: FrameMode::User,
            },
            None,
        );

        assert_eq!(marker, Frame::TruncatedStack);
        assert_eq!(marker.to_string(), "<stack truncated>");
        assert_eq!(null_pc.to_string(), "<0x0>");
        assert!(null_pc.flags.is_empty());
        assert_ne!(marker, Frame::Native(null_pc));
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

        let stack = reader.samples().next().expect("sample stack");
        let resolved: Vec<_> = symbolizer
            .resolve(stack.stack())
            .unwrap()
            .frames()
            .cloned()
            .collect();

        assert_eq!(resolved.len(), 1);
        let Frame::Native(frame) = &resolved[0] else {
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

        for stack in reader.samples() {
            assert_eq!(
                symbolizer.resolve(stack.stack()).unwrap().frames().count(),
                1
            );
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
                path: std::path::Path::new("/future").into(),
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
            .samples()
            .find(|stack| stack.sample().stack_id == stack_id)
            .expect("sample stack");
        let resolved = symbolizer
            .resolve(stack.stack())
            .unwrap()
            .frames()
            .next()
            .cloned();
        let Frame::Native(frame) = resolved.expect("resolved frame") else {
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

        assert!(symbolizer
            .resolve(first.samples().next().unwrap().stack())
            .is_ok());
        let error = match symbolizer.resolve(second.samples().next().unwrap().stack()) {
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
        let stack = reader.samples().next().expect("sample");
        let resolved = symbolizer
            .resolve(stack.stack())
            .unwrap()
            .frames()
            .next()
            .cloned();
        let Frame::Native(frame) = resolved.expect("resolved frame") else {
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
            .perf_map_dir(std::env::temp_dir())
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
            Frame::Python(frame) => assert_eq!(frame.func_name.as_ref(), "kept"),
            Frame::Native(_) | Frame::TruncatedStack => {
                panic!("expected recorded Python perf-map frame")
            }
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
        assert_eq!(frame.address_space, AddressSpace::Kernel);
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

    #[test]
    fn live_host_kernel_symbols_load_when_the_first_kernel_frame_arrives() {
        let temp = crate::test_support::TempDir::new("lazy-live-kernel");
        let path = temp.path().join("recording.spool");
        let mut writer = PerfSpoolWriter::create(&path, 0, 10).unwrap();
        writer.flush().unwrap();
        let mut tail = Tail::open(&path).unwrap();
        let mut symbolizer = tail.symbolizer().disable_perf_maps().build().unwrap();
        assert!(symbolizer.kernel_symbols.is_none());
        symbolizer.update(&tail.poll().unwrap()).unwrap();

        let address = 0xffff_ffff_8100_0108;
        writer
            .write_module(&ModuleRecord::kernel(0, address..address + 4096, "[kernel]").unwrap())
            .unwrap();
        writer.write_sample_frames(1, 7, 7, [frame(4096)]).unwrap();
        writer.flush().unwrap();
        let batch = tail.poll().unwrap();
        symbolizer.update(&batch).unwrap();
        assert!(symbolizer.kernel_symbols.is_none());
        assert_eq!(
            symbolizer
                .resolve(batch.samples().next().unwrap().stack())
                .unwrap()
                .len(),
            1
        );

        for timestamp in [2, 3] {
            writer
                .write_sample_frames(
                    timestamp,
                    7,
                    7,
                    [FrameRecord {
                        module_id: Some(0),
                        file_relative_ip: 0,
                        abs_ip: address,
                        mode: FrameMode::Kernel,
                    }],
                )
                .unwrap();
            writer.flush().unwrap();
            let batch = tail.poll().unwrap();
            symbolizer.update(&batch).unwrap();
            assert!(symbolizer.kernel_symbols.is_some());
            let resolved = symbolizer
                .resolve(batch.samples().next().unwrap().stack())
                .unwrap();
            let frames: Vec<_> = resolved
                .frames()
                .map(|frame| match frame {
                    Frame::Native(frame) => (frame.pc, frame.address_space),
                    _ => panic!("kernel sample resolved to a non-native frame"),
                })
                .collect();
            assert_eq!(frames, [(address, AddressSpace::Kernel)]);
        }
    }

    #[test]
    fn perf_map_growth_preserves_unrelated_elf_frames() {
        use std::io::Write as _;
        let temp = crate::test_support::TempDir::new("perf-map-eviction");
        let path = temp.path().join("recording.spool");
        let pid_i32 = i32::try_from(std::process::id()).unwrap();
        let pid = crate::Pid::new(pid_i32).unwrap();
        let other_pid_i32 = pid_i32.checked_add(1).unwrap();
        let other_pid = crate::Pid::new(other_pid_i32).unwrap();
        let perf_map = temp.path().join(format!("perf-{pid_i32}.map"));
        fs::write(&perf_map, "1000 10 existing_jit_symbol\n").unwrap();
        let calls = Rc::new(Cell::new(0));
        let backend_calls = Rc::clone(&calls);
        let mut writer = PerfSpoolWriter::create(&path, 0, 10).unwrap();
        writer.flush().unwrap();
        let mut tail = Tail::open(&path).unwrap();
        assert_eq!(tail.poll().unwrap().samples().count(), 0);
        let mut symbolizer = tail
            .symbolizer()
            .stack_cache(StackCache::External)
            .perf_map_dir(temp.path())
            .native(move |_| CountingNativeSymbolizer {
                calls: Rc::clone(&backend_calls),
            })
            .build()
            .unwrap();
        let module = current_executable_module(0, pid_i32);
        let other_module = current_executable_module(1, other_pid_i32);
        let elf_frame = FrameRecord {
            module_id: Some(0),
            file_relative_ip: module.file_offset + 8,
            abs_ip: module.start + 8,
            mode: FrameMode::User,
        };
        let other_elf_frame = FrameRecord {
            module_id: Some(1),
            file_relative_ip: other_module.file_offset + 8,
            abs_ip: other_module.start + 8,
            mode: FrameMode::User,
        };
        writer.write_module(&module).unwrap();
        writer.write_module(&other_module).unwrap();
        writer.flush().unwrap();
        {
            let batch = tail.poll().unwrap();
            let invalidation = symbolizer.update(&batch).unwrap();
            assert!(!invalidation.affects_process(pid));
        }
        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[elf_frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            symbolizer
                .resolve_raw(other_pid, &[other_elf_frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert_eq!(calls.get(), 2);
        let jit_frame = frame(0x2000);
        let unresolved = symbolizer
            .resolve_raw(pid, &[jit_frame])
            .unwrap()
            .frames()
            .next()
            .unwrap();
        assert!(matches!(unresolved, Frame::Native(frame) if frame.symbol.is_none()));

        let mut file = fs::OpenOptions::new().append(true).open(&perf_map).unwrap();
        file.write_all(b"2000 10 jitted_fn_b\n").unwrap();
        drop(file);
        writer
            .write_sample_frames(1_000, pid_i32, 1, [elf_frame])
            .unwrap();
        writer.flush().unwrap();
        {
            let batch = tail.poll().unwrap();
            let invalidation = symbolizer.update(&batch).unwrap();
            assert!(
                invalidation.affects_process(pid),
                "perf map growth invalidates the pid again"
            );
        }
        assert_eq!(
            symbolizer
                .resolve_raw(pid, &[elf_frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert_eq!(
            calls.get(),
            2,
            "perf map growth must preserve cached ELF frames"
        );
        assert_eq!(
            symbolizer
                .resolve_raw(other_pid, &[other_elf_frame])
                .unwrap()
                .frames()
                .count(),
            1
        );
        assert_eq!(calls.get(), 2, "other processes must remain cached");
        let resolved = symbolizer
            .resolve_raw(pid, &[jit_frame])
            .unwrap()
            .frames()
            .next()
            .unwrap();
        assert!(matches!(
            resolved,
            Frame::Native(frame)
                if frame.symbol.as_ref().is_some_and(|symbol| symbol.name() == "jitted_fn_b")
        ));

        writer.write_module_deactivation(pid_i32).unwrap();
        writer.flush().unwrap();
        let batch = tail.poll().unwrap();
        symbolizer.update(&batch).unwrap();
        let batch = tail.poll().unwrap();
        let invalidation = symbolizer.update(&batch).unwrap();
        assert!(invalidation.affects_process(pid));
        assert!(!symbolizer
            .frame_cache
            .contains_key(&(pid_i32, FrameCacheKey::Raw(elf_frame))));
        assert!(symbolizer
            .frame_cache
            .contains_key(&(other_pid_i32, FrameCacheKey::Raw(other_elf_frame))));
    }
}
