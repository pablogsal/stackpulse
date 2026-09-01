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

pub use crate::module_base::ModuleImageBase;
use crate::profile::{
    FrameFlags, FrameKind, NativeFrame, NativeSymbol, ResolvedFrame, SourceLocation, SymbolOrigin,
};
#[cfg(feature = "builtin-wholesym")]
use crate::symbols::default_native_symbolizer_factory;
use crate::symbols::{erase_native_symbolizer, ErasedNativeSymbolizer, NativeSymbolizerFactory};
pub use crate::symbols::{
    NativeFileIdentity, NativeLookup, NativeModule, NativeSymbolizer, NativeSymbols,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::native_module::{ElfSectionCache, LoadedElfMapping};
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
    find_perf_map_symbol, load_perf_map, module_display_name, perf_map_module_allowed,
    perf_map_symbol_to_frame, PerfMapProcesses, PerfMapSymbol,
};

#[derive(Debug, thiserror::Error)]
enum NativeContractError {
    #[error("native lookup batch spans more than one process")]
    MixedProcesses,
    #[error("native symbolizer factory is missing")]
    MissingFactory,
    #[error("native symbolizer backend was not constructed")]
    MissingBackend,
    #[error("native symbolizer returned {actual} results for {expected} requests")]
    ResultCount { expected: usize, actual: usize },
    #[error("resolved frame was not cached")]
    MissingCachedFrame,
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
    modules: Vec<ModuleRecord>,
    module_index_by_id: FxHashMap<u32, usize>,
    perf_map_processes: PerfMapProcesses,
    perf_map_dir: PathBuf,
    elf_sections: ElfSectionCache,
    native_symbolizers: FxHashMap<i32, Box<dyn ErasedNativeSymbolizer>>,
    native_modules: FxHashMap<u32, NativeModule>,
    unsupported_native_modules: FxHashSet<u32>,
    native_requests: Vec<NativeLookup>,
    native_results: Vec<NativeSymbols>,
    pending_frames: Vec<PendingFrame>,
    pending_frame_keys: FxHashSet<(i32, FrameCacheKey)>,
    perf_map_cache: FxHashMap<i32, Option<Vec<PerfMapSymbol>>>,
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

impl std::fmt::Debug for Symbolizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Symbolizer")
            .field("modules", &self.modules.len())
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
    /// Configure symbolization for a module list.
    #[must_use]
    pub fn for_modules(modules: &'a [ModuleRecord]) -> Self {
        Self {
            input: SymbolizerInput::Modules(modules),
            perf_map_processes: PerfMapProcesses::All,
            perf_map_dir: PathBuf::from("/tmp"),
            native_factory: None,
            kernel_symbols: KernelSymbolSource::Host,
            stack_cache: StackCache::Internal,
        }
    }

    /// Configure symbolization for a loaded spool.
    #[must_use]
    pub(crate) fn for_spool(reader: &'a Snapshot) -> Self {
        Self {
            input: SymbolizerInput::Spool(reader),
            perf_map_processes: PerfMapProcesses::All,
            perf_map_dir: PathBuf::from("/tmp"),
            native_factory: None,
            kernel_symbols: KernelSymbolSource::Host,
            stack_cache: StackCache::Internal,
        }
    }

    /// Configure symbolization for a sequential spool replay.
    #[must_use]
    pub(crate) fn for_replay(reader: &'a Replay) -> Self {
        Self {
            input: SymbolizerInput::Spool(reader),
            perf_map_processes: PerfMapProcesses::All,
            perf_map_dir: PathBuf::from("/tmp"),
            native_factory: None,
            kernel_symbols: KernelSymbolSource::Host,
            stack_cache: StackCache::Internal,
        }
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
    #[must_use]
    pub fn native<S>(mut self, mut factory: impl FnMut(crate::Pid) -> S + 'static) -> Self
    where
        S: NativeSymbolizer + 'static,
    {
        self.native_factory = Some(Box::new(move |process_id| {
            erase_native_symbolizer(factory(process_id))
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
        Self {
            input: SymbolizerInput::OwnedModules(modules),
            perf_map_processes: PerfMapProcesses::All,
            perf_map_dir: PathBuf::from("/tmp"),
            native_factory: None,
            kernel_symbols: KernelSymbolSource::Host,
            stack_cache: StackCache::Internal,
        }
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
}

enum PendingResolution {
    PerfMap(ResolvedFrame),
    Native {
        module: Option<(ModuleRecord, u64)>,
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
        self.ids.next().and_then(|&id| self.frames.get(id))
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
        Ok(symbolizer)
    }

    fn with_perf_map_processes_inner(
        modules: Vec<ModuleRecord>,
        perf_map_processes: PerfMapProcesses,
        perf_map_dir: PathBuf,
        native_factory: Option<NativeSymbolizerFactory>,
        kernel_source: &KernelSymbolSource,
    ) -> crate::Result<Self> {
        let mut module_index_by_id = FxHashMap::default();
        for (index, module) in modules.iter().enumerate() {
            if module_index_by_id.insert(module.id, index).is_some() {
                return Err(crate::Error::message(
                    crate::ErrorKind::InvalidInput,
                    format!("duplicate module id {}", module.id),
                ));
            }
        }
        let kernel_symbols = match kernel_source {
            KernelSymbolSource::Host => None,
            KernelSymbolSource::File(path) => Some(kernel::load_kernel_symbols_from_path(path)?),
            KernelSymbolSource::Disabled => Some(KernelSymbolTable::empty()),
        };
        Ok(Self {
            source_id: None,
            modules,
            module_index_by_id,
            perf_map_processes,
            perf_map_dir,
            elf_sections: ElfSectionCache::default(),
            native_symbolizers: FxHashMap::default(),
            native_modules: FxHashMap::default(),
            unsupported_native_modules: FxHashSet::default(),
            native_requests: Vec::new(),
            native_results: Vec::new(),
            pending_frames: Vec::new(),
            pending_frame_keys: FxHashSet::default(),
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
        if self
            .source_id
            .is_some_and(|source_id| !key.belongs_to(source_id))
        {
            return Err(crate::Error::message(
                crate::ErrorKind::InvalidInput,
                "sample stack belongs to a different spool source",
            ));
        }

        if self.stack_cache_mode == StackCache::Internal {
            if let Some(range) = self.stack_cache.get(&key).cloned() {
                return Ok(ResolvedStack {
                    frames: &self.resolved_frames,
                    ids: self.resolved_stack_frame_ids[range].iter(),
                });
            }
            self.begin_frame_batch();
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

        self.begin_frame_batch();
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
        self.resolved_stack_scratch.clear();
        while let Some(frame_ref) = frames.next_with_id() {
            let frame_ids =
                self.cached_frame_ids(sample.process_id.get(), FrameCacheKey::Spool(frame_ref.id))?;
            self.resolved_stack_scratch.extend(frame_ids);
        }
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
        self.begin_frame_batch();
        for frame in frames {
            self.prepare_frame(process_id.get(), *frame, FrameCacheKey::Raw(*frame), None);
        }
        self.finish_frame_batch(process_id.get())?;
        self.resolved_stack_scratch.clear();
        for frame in frames {
            let frame_ids = self.cached_frame_ids(process_id.get(), FrameCacheKey::Raw(*frame))?;
            self.resolved_stack_scratch.extend(frame_ids);
        }
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
        self.begin_frame_batch();
        self.prepare_frame(process_id, *frame, cache_key.1, spool_frame_id);
        self.finish_frame_batch(process_id)?;
        self.cached_frame_ids(process_id, cache_key.1)
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

    fn begin_frame_batch(&mut self) {
        self.pending_frames.clear();
        self.pending_frame_keys.clear();
        self.native_requests.clear();
        self.native_results.clear();
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

        if let Some(module) = frame
            .module_id
            .and_then(|module_id| self.module_by_id(module_id))
            .filter(|module| !perf_map_module_allowed(module))
        {
            let module = (module.clone(), frame.file_relative_ip);
            let request_index = self.prepare_native_lookup(process_id, &module.0, frame.abs_ip);
            self.pending_frames.push(PendingFrame {
                cache_key,
                frame,
                resolution: PendingResolution::Native {
                    module: Some(module),
                    request_index,
                },
            });
            return;
        }

        let perf_map_symbol =
            if self.perf_maps_allowed_for(process_id) && frame.mode == FrameMode::User {
                self.lookup_perf_map_symbol(process_id, frame.abs_ip)
            } else {
                None
            };

        if let Some(symbol) = perf_map_symbol {
            let blocked_module = self
                .module_for_frame(process_id, &frame, spool_frame_id)
                .and_then(|module| {
                    (!perf_map_module_allowed(module.module)).then(|| module.into_owned())
                });
            if let Some(module) = blocked_module {
                let request_index = self.prepare_native_lookup(process_id, &module.0, frame.abs_ip);
                self.pending_frames.push(PendingFrame {
                    cache_key,
                    frame,
                    resolution: PendingResolution::Native {
                        module: Some(module),
                        request_index,
                    },
                });
                return;
            }

            self.pending_frames.push(PendingFrame {
                cache_key,
                frame,
                resolution: PendingResolution::PerfMap(perf_map_symbol_to_frame(
                    process_id,
                    frame.abs_ip,
                    symbol,
                    &self.perf_map_dir,
                )),
            });
            return;
        }
        let module = self.owned_module_for_frame(process_id, &frame, spool_frame_id);
        let request_index = module
            .as_ref()
            .and_then(|(module, _)| self.prepare_native_lookup(process_id, module, frame.abs_ip));
        self.pending_frames.push(PendingFrame {
            cache_key,
            frame,
            resolution: PendingResolution::Native {
                module,
                request_index,
            },
        });
    }

    fn prepare_native_lookup(
        &mut self,
        process_id: i32,
        module: &ModuleRecord,
        absolute_address: u64,
    ) -> Option<usize> {
        if module.is_kernel
            || module.process_id != process_id
            || self.native_factory.is_none()
            || self.unsupported_native_modules.contains(&module.id)
        {
            return None;
        }
        if !self.native_modules.contains_key(&module.id) {
            let Some(LoadedElfMapping {
                image_base: Some(image_base),
                ..
            }) = self.elf_sections.load_mapping(module)
            else {
                self.unsupported_native_modules.insert(module.id);
                return None;
            };
            self.native_modules.insert(
                module.id,
                NativeModule::new(
                    module.path.as_path().to_path_buf(),
                    image_base,
                    crate::is_python_runtime_module_path(&module.path),
                    NativeFileIdentity::new(
                        module.device_major,
                        module.device_minor,
                        module.inode,
                        module.inode_generation,
                    ),
                    module.id,
                ),
            );
        }
        let pid = crate::Pid::try_from(process_id).ok()?;
        let native_module = self.native_modules.get(&module.id)?;
        let image_address = native_module.image_base().svma_for_avma(absolute_address)?;
        let relative_address = native_module
            .image_base()
            .relative_address(absolute_address)?;
        let request_index = self.native_requests.len();
        self.native_requests.push(NativeLookup {
            process_id: pid,
            module: native_module.clone(),
            absolute_address,
            relative_address,
            image_address,
        });
        Some(request_index)
    }

    fn finish_frame_batch(&mut self, process_id: i32) -> crate::Result<()> {
        if !self.native_requests.is_empty() {
            let process_id = crate::Pid::try_from(process_id)
                .map_err(|error| crate::Error::new(crate::ErrorKind::InvalidInput, error))?;
            if self
                .native_requests
                .iter()
                .any(|request| request.process_id() != process_id)
            {
                self.begin_frame_batch();
                return Err(NativeContractError::MixedProcesses.into_public());
            }
            if !self.native_symbolizers.contains_key(&process_id.get()) {
                let Some(factory) = self.native_factory.as_mut() else {
                    self.begin_frame_batch();
                    return Err(NativeContractError::MissingFactory.into_public());
                };
                self.native_symbolizers
                    .insert(process_id.get(), factory(process_id));
            }
            let Some(backend) = self.native_symbolizers.get_mut(&process_id.get()) else {
                self.begin_frame_batch();
                return Err(NativeContractError::MissingBackend.into_public());
            };
            if let Err(error) = backend.symbolize(&self.native_requests, &mut self.native_results) {
                self.begin_frame_batch();
                return Err(crate::Error::native(error));
            }
            if self.native_results.len() != self.native_requests.len() {
                let expected = self.native_requests.len();
                let actual = self.native_results.len();
                self.begin_frame_batch();
                return Err(NativeContractError::ResultCount { expected, actual }.into_public());
            }
        }

        let mut pending_frames = std::mem::take(&mut self.pending_frames);
        let mut native_results = std::mem::take(&mut self.native_results);
        for pending in pending_frames.drain(..) {
            let start = self.resolved_frames.len();
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
                    self.append_native_frames(&pending.frame, module, symbols);
                }
            }
            self.frame_cache
                .insert(pending.cache_key, start..self.resolved_frames.len());
        }
        native_results.clear();
        self.native_results = native_results;
        self.pending_frames = pending_frames;
        self.native_requests.clear();
        Ok(())
    }

    fn owned_module_for_frame(
        &self,
        process_id: i32,
        frame: &FrameRecord,
        spool_frame_id: Option<u32>,
    ) -> Option<(ModuleRecord, u64)> {
        self.module_for_frame(process_id, frame, spool_frame_id)
            .map(FrameModuleRef::into_owned)
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
                    &self.modules,
                    contexts,
                    context,
                    process_id,
                    frame,
                )
            }
            _ => spool::module_for_frame_unbounded(&self.modules, process_id, frame),
        }
    }

    fn module_by_id(&self, module_id: u32) -> Option<&ModuleRecord> {
        self.module_index_by_id
            .get(&module_id)
            .and_then(|&index| self.modules.get(index))
    }

    #[cfg(test)]
    fn resolve_native_frame(
        &mut self,
        frame: &FrameRecord,
        module: Option<(ModuleRecord, u64)>,
    ) -> NativeFrame {
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
        module: Option<(ModuleRecord, u64)>,
        symbols: Option<NativeSymbols>,
    ) {
        if frame.is_truncated_stack_marker() {
            self.resolved_frames
                .push(ResolvedFrame::Native(NativeFrame::truncated_stack_marker()));
            return;
        }
        let is_kernel_frame =
            frame.mode == FrameMode::Kernel || module.as_ref().is_some_and(|(m, _)| m.is_kernel);

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
                            format!("[kernel]+0x{:x}", frame.abs_ip),
                            "[kernel]".to_owned(),
                            0,
                            SymbolOrigin::AddressOnly,
                        ),
                    };
                let symbol = NativeSymbol::new(
                    symbol_name,
                    SourceLocation::default(),
                    module_name,
                    offset,
                    false,
                    false,
                );
                self.resolved_frames
                    .push(ResolvedFrame::Native(NativeFrame {
                        pc: frame.abs_ip,
                        sp: 0,
                        symbol: Some(symbol),
                        is_python_runtime: false,
                        kind: FrameKind::Kernel,
                        origin,
                        flags: FrameFlags::empty(),
                    }));
            }
            (false, Some((module, file_relative_ip))) => {
                if let Some(symbols) = symbols {
                    self.resolved_frames
                        .extend(symbols.into_vec().into_iter().map(|symbol| {
                            let is_python_runtime = symbol.should_ignore;
                            ResolvedFrame::Native(NativeFrame {
                                pc: frame.abs_ip,
                                sp: 0,
                                symbol: Some(symbol),
                                is_python_runtime,
                                kind: FrameKind::Native,
                                origin: SymbolOrigin::Elf,
                                flags: if is_python_runtime {
                                    FrameFlags::PYTHON_RUNTIME | FrameFlags::HIDDEN_DEFAULT
                                } else {
                                    FrameFlags::empty()
                                },
                            })
                        }));
                    return;
                }

                let is_python_runtime = frame.mode == FrameMode::User
                    && crate::is_python_runtime_module_path(&module.path);
                let symbol_name = format!(
                    "{}+0x{:x}",
                    module_display_name(&module.path),
                    file_relative_ip
                );
                // Pseudo-symbol without a function: the name embeds the
                // file-relative address, so the function offset is 0.
                let symbol = NativeSymbol::new(
                    symbol_name.clone(),
                    SourceLocation::default(),
                    module.path,
                    0,
                    crate::symbols::is_eval_frame(&symbol_name),
                    is_python_runtime,
                );
                self.resolved_frames
                    .push(ResolvedFrame::Native(NativeFrame {
                        pc: frame.abs_ip,
                        sp: 0,
                        symbol: Some(symbol),
                        is_python_runtime,
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

    fn lookup_perf_map_symbol(&mut self, process_id: i32, abs_ip: u64) -> Option<PerfMapSymbol> {
        self.perf_map_cache
            .entry(process_id)
            .or_insert_with(|| load_perf_map(&self.perf_map_dir, process_id))
            .as_ref()
            .and_then(|symbols| find_perf_map_symbol(symbols, abs_ip))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::rc::Rc;

    use crate::spool::PerfSpoolWriter;

    use super::*;

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
            process_id,
            start,
            end: start + 0x1000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.into(),
            is_kernel: false,
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
            process_id,
            start: region.address.start,
            end: region.address.end,
            file_offset: region.file_offset,
            inode: region.inode,
            device_major: region.device_major,
            device_minor: region.device_minor,
            inode_generation: 0,
            path: region.path.into(),
            is_kernel: false,
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
        let process_id = -(std::process::id() as i32);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "1000 10 py::work:/tmp/app.py\n").expect("write perf map");

        let mut symbolizer = Symbolizer::new(&[]);
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x1004));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Python(frame) => {
                assert_eq!(frame.func_name.as_ref(), "work");
                assert_eq!(frame.file_name.as_ref(), "/tmp/app.py");
            }
            ResolvedFrame::Native(_) => panic!("expected Python perf-map frame"),
        }
    }

    #[test]
    fn python_perf_map_symbols_respect_declared_ranges() {
        let process_id = -(std::process::id() as i32) - 9;
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
        let process_id = -(std::process::id() as i32) - 1;
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
                assert_eq!(symbol.name.as_ref(), "jit_func");
                assert_eq!(symbol.module.as_ref(), temp_perf_map_path(process_id));
                assert_eq!(symbol.offset, 8);
            }
            ResolvedFrame::Python(_) => panic!("expected native perf-map frame"),
        }
    }

    #[test]
    fn perf_map_symbols_can_be_disabled() {
        let process_id = -(std::process::id() as i32) - 2;
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
        let process_id = -(std::process::id() as i32) - 4;
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
                assert!(!frame.is_python_runtime);
                assert_ne!(frame.display_name(), "fake_after_exec");
            }
            ResolvedFrame::Python(_) => panic!("non-Python module should block perf-map symbol"),
        }
    }

    #[test]
    fn perf_map_symbols_do_not_override_file_backed_python_modules() {
        let process_id = -(std::process::id() as i32) - 11;
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
        let process_id = -(std::process::id() as i32) - 6;
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
                assert!(!frame.is_python_runtime);
                assert_ne!(frame.display_name(), "fake_after_exec");
            }
            ResolvedFrame::Python(_) => {
                panic!("late-resolved non-Python module should block perf-map symbol")
            }
        }
    }

    #[test]
    fn perf_map_symbols_do_not_override_memfd_mappings_by_default() {
        let process_id = -(std::process::id() as i32) - 10;
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
        let process_id = -(std::process::id() as i32) - 7;
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
        let process_id = -(std::process::id() as i32) - 12;
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
        let process_id = -(std::process::id() as i32) - 5;
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
        let process_id = -(std::process::id() as i32) - 8;
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
                assert!(frame.is_python_runtime);
                assert!(frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                let symbol = frame.symbol.expect("fallback Python runtime symbol");
                assert!(symbol.should_ignore);
            }
            ResolvedFrame::Python(_) => panic!("Python runtime module should stay native"),
        }
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
        assert_eq!(symbol.name.as_ref(), "[kernel]+0xffffffff80001234");
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
        assert_eq!(symbol.name.as_ref(), "vfs_read+0x14");
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
                process_id: 7,
                start: 0x1000,
                end: 0x2000,
                file_offset: 0,
                inode: 1,
                device_major: 0,
                device_minor: 0,
                inode_generation: 0,
                path: "/future".into(),
                is_kernel: false,
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
        assert_eq!(symbol.name.as_ref(), "wg_packet_tx_worker+0x14");
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
