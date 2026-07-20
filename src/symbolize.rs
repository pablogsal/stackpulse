//! Resolves stack frames recorded in perf spool files into displayable profile
//! frames.
//!
//! Spool records mostly contain process ids, raw instruction pointers (program
//! counters), and module mappings, not final symbol names. This module chooses
//! the symbol source for each frame: Python perf maps for JIT frames, ELF/native
//! symbolizers for user-space modules, and the kernel submodule for kernel
//! addresses. The rest of the crate consumes resolved frames without needing to
//! know which backend produced each symbol.

use std::fs;
use std::ops::Range;
use std::path::Path;
#[cfg(test)]
use std::sync::Arc;

use crate::profile::{
    FrameFlags, FrameKind, LocationInfo, NativeFrame, NativeSymbol, PythonFrame, ResolvedFrame,
    SourceLocation, SymbolOrigin,
};
use crate::symbols::{
    default_native_symbolizer_factory, NativeSymbolizer, NativeSymbolizerFactory, SymModule,
    SymbolsRc,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::native_module::{ElfSectionCache, LoadedElfMapping};
use crate::spool::{
    self, FrameMode, FrameModuleRef, FrameRecord, ModuleRecord, PerfSpoolReader, SampleStack,
    SpoolFrameModuleContexts, StackFrameRefs,
};

mod kernel;
#[cfg(any(test, feature = "bench-support"))]
pub(crate) use kernel::bench_parse_sparse_kernel_symbols;
#[cfg(test)]
use kernel::KernelSymbol;
use kernel::{KernelSymbolTable, ResolvedKernelSymbol};

/// Resolves raw profile frames into displayable frames.
pub struct PerfSymbolizer {
    modules: Vec<ModuleRecord>,
    module_index_by_id: FxHashMap<u32, usize>,
    perf_map_processes: PerfMapProcesses,
    elf_sections: ElfSectionCache,
    native_symbolizers: Vec<NativeSymbolizerGroup>,
    native_symbolizer_by_module: FxHashMap<u32, usize>,
    unsupported_native_modules: FxHashSet<u32>,
    perf_map_cache: FxHashMap<i32, Option<Vec<PerfMapSymbol>>>,
    kernel_symbols: Option<KernelSymbolTable>,
    spool_frame_contexts: Option<SpoolFrameModuleContexts>,
    frame_cache: FxHashMap<(i32, FrameCacheKey), Range<usize>>,
    resolved_frames: Vec<ResolvedFrame>,
    resolved_stack_frame_ids: Vec<usize>,
    stack_cache: FxHashMap<(i32, u32), Range<usize>>,
    native_factory: NativeSymbolizerFactory,
}

/// Which processes may use Python perf-map lookups.
pub(crate) enum PerfMapProcesses {
    /// Allow perf-map lookup for every process.
    All,
    /// Allow perf-map lookup only for the listed process ids.
    Pids(FxHashSet<i32>),
}

impl From<bool> for PerfMapProcesses {
    fn from(allow_perf_maps: bool) -> Self {
        if allow_perf_maps {
            Self::All
        } else {
            Self::Pids(FxHashSet::default())
        }
    }
}

#[derive(Clone)]
struct PerfMapSymbol {
    start: u64,
    end: u64,
    name: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum FrameCacheKey {
    Spool(u32),
    Raw(FrameRecord),
}

struct NativeSymbolizerGroup {
    process_id: i32,
    modules: Vec<NativeSymbolizerModule>,
    symbolizer: Box<dyn NativeSymbolizer>,
}

#[derive(Clone)]
struct NativeSymbolizerModule {
    info: SymModule,
    identity: NativeFileIdentity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeFileIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    inode_generation: u64,
}

impl From<&ModuleRecord> for NativeFileIdentity {
    fn from(module: &ModuleRecord) -> Self {
        Self {
            device_major: module.device_major,
            device_minor: module.device_minor,
            inode: module.inode,
            inode_generation: module.inode_generation,
        }
    }
}

fn sym_module_for_mapping(module: &ModuleRecord, loaded: &LoadedElfMapping) -> SymModule {
    SymModule {
        path: module.path.as_path().to_path_buf(),
        avma_range: module.start..module.end,
        image_base: loaded.image_base,
        is_executable: true,
        is_python_runtime: false,
    }
}

impl PerfSymbolizer {
    /// Create a resolver for the modules in a profile.
    pub fn new(modules: &[ModuleRecord]) -> Self {
        Self::with_perf_maps(modules, true)
    }

    /// Create a resolver and choose whether Python perf-map lookup is allowed.
    pub fn with_perf_maps(modules: &[ModuleRecord], allow_perf_maps: bool) -> Self {
        Self::with_perf_map_processes_inner(
            modules,
            allow_perf_maps.into(),
            default_native_symbolizer_factory(),
        )
    }

    /// Create a resolver that only uses Python perf maps for selected processes.
    pub fn with_perf_map_processes(
        modules: &[ModuleRecord],
        processes: impl IntoIterator<Item = i32>,
    ) -> Self {
        Self::with_perf_map_processes_inner(
            modules,
            PerfMapProcesses::Pids(processes.into_iter().collect()),
            default_native_symbolizer_factory(),
        )
    }

    /// Create a resolver with a caller-supplied native symbolizer factory.
    ///
    /// The factory is invoked once per non-overlapping process module group;
    /// each returned [`NativeSymbolizer`] is responsible for ELF/Mach-O
    /// symbolization of the modules in that group. Kernel frames and
    /// `/tmp/perf-PID.map` lookups remain handled internally by
    /// `PerfSymbolizer`.
    ///
    /// Use this when integrating with an external symbolizer (debuginfod,
    /// custom debug-dir policy, alternate symbol backends) instead of the
    /// bundled wholesym-backed default.
    pub fn with_native_factory(
        modules: &[ModuleRecord],
        allow_perf_maps: bool,
        native_factory: NativeSymbolizerFactory,
    ) -> Self {
        Self::with_perf_map_processes_inner(modules, allow_perf_maps.into(), native_factory)
    }

    /// Create a resolver for a loaded spool, using its kernel PCs for sparse kallsyms loading.
    pub fn for_spool(reader: &PerfSpoolReader) -> Self {
        Self::for_spool_with_perf_maps(reader, true)
    }

    /// Create a resolver for a loaded spool and choose whether Python perf maps are allowed.
    pub fn for_spool_with_perf_maps(reader: &PerfSpoolReader, allow_perf_maps: bool) -> Self {
        Self::for_spool_with_native_factory(
            reader,
            allow_perf_maps,
            default_native_symbolizer_factory(),
        )
    }

    /// Create a spool-backed resolver that only uses Python perf maps for selected processes.
    pub fn for_spool_with_perf_map_processes(
        reader: &PerfSpoolReader,
        processes: impl IntoIterator<Item = i32>,
    ) -> Self {
        Self::for_spool_inner(
            reader,
            PerfMapProcesses::Pids(processes.into_iter().collect()),
            default_native_symbolizer_factory(),
        )
    }

    /// Create a spool-backed resolver that restricts Python perf maps to
    /// processes recorded as Python runtimes at least once.
    pub fn for_spool_with_recorded_python_perf_maps(reader: &PerfSpoolReader) -> Self {
        Self::for_spool_with_perf_map_processes(
            reader,
            reader
                .process_execs()
                .iter()
                .filter_map(|exec| exec.is_python_runtime.then_some(exec.process_id)),
        )
    }

    /// Spool-backed resolver with a caller-supplied native symbolizer factory.
    pub fn for_spool_with_native_factory(
        reader: &PerfSpoolReader,
        allow_perf_maps: bool,
        native_factory: NativeSymbolizerFactory,
    ) -> Self {
        Self::for_spool_inner(reader, allow_perf_maps.into(), native_factory)
    }

    fn for_spool_inner(
        reader: &PerfSpoolReader,
        perf_map_processes: PerfMapProcesses,
        native_factory: NativeSymbolizerFactory,
    ) -> Self {
        let mut symbolizer = Self::with_perf_map_processes_inner(
            reader.modules(),
            perf_map_processes,
            native_factory,
        );
        symbolizer.kernel_symbols = Some(kernel::load_sparse_kernel_symbols_for_spool(
            reader.kernel_frame_addresses(),
            reader.modules(),
        ));
        symbolizer.spool_frame_contexts = Some(reader.frame_module_contexts());
        symbolizer
    }

    fn with_perf_map_processes_inner(
        modules: &[ModuleRecord],
        perf_map_processes: PerfMapProcesses,
        native_factory: NativeSymbolizerFactory,
    ) -> Self {
        let mut module_index_by_id = FxHashMap::default();
        let mut duplicate_ids = FxHashSet::default();
        for (index, module) in modules.iter().enumerate() {
            if module_index_by_id.insert(module.id, index).is_some() {
                duplicate_ids.insert(module.id);
            }
        }
        for id in duplicate_ids {
            module_index_by_id.remove(&id);
        }
        Self {
            modules: modules.to_vec(),
            module_index_by_id,
            perf_map_processes,
            elf_sections: ElfSectionCache::default(),
            native_symbolizers: Vec::new(),
            native_symbolizer_by_module: FxHashMap::default(),
            unsupported_native_modules: FxHashSet::default(),
            perf_map_cache: FxHashMap::default(),
            kernel_symbols: None,
            spool_frame_contexts: None,
            frame_cache: FxHashMap::default(),
            resolved_frames: Vec::new(),
            resolved_stack_frame_ids: Vec::new(),
            stack_cache: FxHashMap::default(),
            native_factory,
        }
    }

    fn for_each_resolved_frame(
        &mut self,
        process_id: i32,
        stack_id: u32,
        frames: StackFrameRefs<'_>,
        mut visit: impl FnMut(&ResolvedFrame),
    ) -> usize {
        let cache_key = (process_id, stack_id);
        if let Some(frame_ids) = self.stack_cache.get(&cache_key) {
            for &frame_id in &self.resolved_stack_frame_ids[frame_ids.clone()] {
                visit(&self.resolved_frames[frame_id]);
            }
            return frame_ids.end - frame_ids.start;
        }

        let start = self.resolved_stack_frame_ids.len();
        let mut frames = frames;
        while let Some(frame_ref) = frames.next_with_id() {
            let resolved_ids = self.resolve_cached_frame_ids(
                process_id,
                frame_ref.frame,
                FrameCacheKey::Spool(frame_ref.id),
                Some(frame_ref.id),
            );
            for frame_id in resolved_ids {
                visit(&self.resolved_frames[frame_id]);
                self.resolved_stack_frame_ids.push(frame_id);
            }
        }
        let frame_ids = start..self.resolved_stack_frame_ids.len();
        let count = frame_ids.end - frame_ids.start;
        self.stack_cache.insert(cache_key, frame_ids);
        count
    }

    /// Resolve one borrowed [`SampleStack`] and visit each resolved frame.
    pub fn for_each_sample_stack(
        &mut self,
        stack: SampleStack<'_>,
        visit: impl FnMut(&ResolvedFrame),
    ) -> usize {
        self.for_each_resolved_frame(
            stack.sample.process_id,
            stack.sample.stack_id,
            stack.frames,
            visit,
        )
    }

    /// Resolve a raw frame slice and visit each resolved frame without
    /// materializing a resolved stack.
    ///
    /// Use [`Self::for_each_sample_stack`] when frames come from a
    /// [`PerfSpoolReader`], because spool-backed resolution can use recorded
    /// module context for moduleless frames. This slice method is useful for
    /// synthetic stacks, examples, and callers that already own raw frames.
    pub fn for_each_resolved_frame_slice(
        &mut self,
        process_id: i32,
        frames: &[FrameRecord],
        mut visit: impl FnMut(&ResolvedFrame),
    ) -> usize {
        let mut count = 0;
        for frame in frames {
            let resolved_ids =
                self.resolve_cached_frame_ids(process_id, frame, FrameCacheKey::Raw(*frame), None);
            for frame_id in resolved_ids {
                visit(&self.resolved_frames[frame_id]);
                count += 1;
            }
        }
        count
    }

    #[cfg(test)]
    fn resolve_cached_frame_ref(&mut self, process_id: i32, frame: &FrameRecord) -> &ResolvedFrame {
        let frame_ids =
            self.resolve_cached_frame_ids(process_id, frame, FrameCacheKey::Raw(*frame), None);
        &self.resolved_frames[frame_ids.start]
    }

    fn resolve_cached_frame_ids(
        &mut self,
        process_id: i32,
        frame: &FrameRecord,
        cache_key: FrameCacheKey,
        spool_frame_id: Option<u32>,
    ) -> Range<usize> {
        let cache_key = (process_id, cache_key);
        if let Some(frame_ids) = self.frame_cache.get(&cache_key) {
            return frame_ids.clone();
        }
        let frames = self.resolve_frames(process_id, frame, spool_frame_id);
        let start = self.resolved_frames.len();
        self.resolved_frames.extend(frames);
        let frame_ids = start..self.resolved_frames.len();
        self.frame_cache.insert(cache_key, frame_ids.clone());
        frame_ids
    }

    #[cfg(test)]
    fn resolve_frame(&mut self, process_id: i32, frame: &FrameRecord) -> ResolvedFrame {
        self.resolve_frames(process_id, frame, None)
            .into_iter()
            .next()
            .expect("frame resolution returns at least one frame")
    }

    fn resolve_frames(
        &mut self,
        process_id: i32,
        frame: &FrameRecord,
        spool_frame_id: Option<u32>,
    ) -> Vec<ResolvedFrame> {
        if let Some(module) = frame
            .module_id
            .and_then(|module_id| self.module_by_id(module_id))
            .filter(|module| !perf_map_module_allowed(module))
        {
            return self
                .resolve_native_frames(frame, Some((module.clone(), frame.rel_ip)))
                .into_iter()
                .map(ResolvedFrame::Native)
                .collect();
        }

        let perf_map_symbol =
            if self.perf_maps_allowed_for(process_id) && frame.mode == FrameMode::User {
                self.lookup_perf_map_symbol(process_id, frame.abs_ip)
            } else {
                None
            };

        if let Some(symbol) = perf_map_symbol.as_ref() {
            let blocked_module = self
                .module_for_frame(process_id, frame, spool_frame_id)
                .and_then(|module| {
                    (!perf_map_module_allowed(module.module)).then(|| module.into_owned())
                });
            if let Some(module) = blocked_module {
                return self
                    .resolve_native_frames(frame, Some(module))
                    .into_iter()
                    .map(ResolvedFrame::Native)
                    .collect();
            }

            return vec![perf_map_symbol_to_frame(process_id, frame.abs_ip, symbol)];
        }
        let module = self.owned_module_for_frame(process_id, frame, spool_frame_id);
        self.resolve_native_frames(frame, module)
            .into_iter()
            .map(ResolvedFrame::Native)
            .collect()
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
                rel_ip: frame.rel_ip,
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
        self.resolve_native_frames(frame, module)
            .into_iter()
            .next()
            .expect("native frame resolution returns at least one frame")
    }

    fn resolve_native_frames(
        &mut self,
        frame: &FrameRecord,
        module: Option<(ModuleRecord, u64)>,
    ) -> Vec<NativeFrame> {
        if frame.is_truncated_stack_marker() {
            return vec![NativeFrame::truncated_stack_marker()];
        }
        let is_kernel_frame =
            frame.mode == FrameMode::Kernel || module.as_ref().is_some_and(|(m, _)| m.is_kernel);

        match (is_kernel_frame, module) {
            (false, None) => vec![NativeFrame::from_address(frame.abs_ip)],
            (true, _) => {
                // Unresolved kernel frames get offset 0: the fallback name
                // already embeds the absolute PC.
                let (symbol_name, module_name, offset) = match self.resolve_kernel(frame.abs_ip) {
                    Some(symbol) => (symbol.name, symbol.module, symbol.offset),
                    None => (
                        format!("[kernel]+0x{:x}", frame.abs_ip),
                        "[kernel]".to_owned(),
                        0,
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
                vec![NativeFrame {
                    pc: frame.abs_ip,
                    sp: 0,
                    symbol: Some(symbol),
                    is_python_runtime: false,
                    kind: FrameKind::Kernel,
                    origin: SymbolOrigin::KernelSymbols,
                    flags: FrameFlags::empty(),
                }]
            }
            (false, Some((module, rel_ip))) => {
                if let Some(symbols) = self.resolve_module_symbols(&module, frame.abs_ip) {
                    return symbols
                        .iter()
                        .map(|symbol| {
                            let is_python_runtime = symbol.should_ignore;
                            NativeFrame {
                                pc: frame.abs_ip,
                                sp: 0,
                                symbol: Some(symbol.clone()),
                                is_python_runtime,
                                kind: FrameKind::Native,
                                origin: SymbolOrigin::Elf,
                                flags: if is_python_runtime {
                                    FrameFlags::PYTHON_RUNTIME | FrameFlags::HIDDEN_DEFAULT
                                } else {
                                    FrameFlags::empty()
                                },
                            }
                        })
                        .collect();
                }

                let is_python_runtime = frame.mode == FrameMode::User
                    && crate::is_python_runtime_module_path(&module.path);
                let symbol_name = format!("{}+0x{:x}", module_display_name(&module.path), rel_ip);
                // Pseudo-symbol without a function: the name embeds the
                // module-relative address, so the function offset is 0.
                let symbol = NativeSymbol::new(
                    symbol_name.clone(),
                    SourceLocation::default(),
                    module.path,
                    0,
                    crate::symbols::is_eval_frame(&symbol_name),
                    is_python_runtime,
                );
                vec![NativeFrame {
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
                }]
            }
        }
    }

    fn resolve_module_symbols(&mut self, module: &ModuleRecord, abs_ip: u64) -> Option<SymbolsRc> {
        let symbolizer = self.ensure_native_symbolizer_for_module(module)?;
        let symbols = symbolizer.symbolize_one(abs_ip);
        (!symbols.is_empty()).then_some(symbols)
    }

    fn ensure_native_symbolizer_for_module(
        &mut self,
        module: &ModuleRecord,
    ) -> Option<&mut Box<dyn NativeSymbolizer>> {
        if self.unsupported_native_modules.contains(&module.id) {
            return None;
        }

        if !self.native_symbolizer_by_module.contains_key(&module.id) {
            self.create_native_symbolizer_for_module(module)?;
        }

        let group_idx = *self.native_symbolizer_by_module.get(&module.id)?;
        self.native_symbolizers
            .get_mut(group_idx)
            .map(|group| &mut group.symbolizer)
    }

    fn create_native_symbolizer_for_module(&mut self, module: &ModuleRecord) -> Option<()> {
        let Some(loaded) = self.elf_sections.load_mapping(module) else {
            self.unsupported_native_modules.insert(module.id);
            return None;
        };
        let requested_module = sym_module_for_mapping(module, &loaded);
        if let Some(idx) = self
            .native_symbolizers
            .iter()
            .position(|group| group.has_equivalent(module, &requested_module))
        {
            // Mapping generations get distinct spool module ids, but an
            // unchanged ELF at the same layout can share its symbol manager.
            // This keeps rapid dlclose/dlopen reuse bounded.
            self.native_symbolizer_by_module.insert(module.id, idx);
            return Some(());
        }
        if let Some(idx) = self
            .native_symbolizers
            .iter()
            .position(|group| group.can_add(module.process_id, &requested_module))
        {
            let group = &mut self.native_symbolizers[idx];
            group.modules.push(NativeSymbolizerModule {
                info: requested_module,
                identity: module.into(),
            });
            group.symbolizer.set_modules(
                group
                    .modules
                    .iter()
                    .map(|module| module.info.clone())
                    .collect(),
            );
            self.native_symbolizer_by_module.insert(module.id, idx);
            return Some(());
        }

        let mut grouped_modules = vec![(
            module.id,
            NativeSymbolizerModule {
                info: requested_module,
                identity: module.into(),
            },
        )];
        let candidates: Vec<_> = self
            .modules
            .iter()
            .filter(|candidate| {
                candidate.id != module.id
                    && candidate.process_id == module.process_id
                    && !candidate.is_kernel
                    && !self.native_symbolizer_by_module.contains_key(&candidate.id)
                    && !self.unsupported_native_modules.contains(&candidate.id)
            })
            .cloned()
            .collect();
        for candidate in candidates {
            let Some(loaded) = self.elf_sections.load_mapping(&candidate) else {
                self.unsupported_native_modules.insert(candidate.id);
                continue;
            };
            let sym_module = sym_module_for_mapping(&candidate, &loaded);
            if grouped_modules.iter().all(|(_, existing)| {
                !ranges_overlap(&existing.info.avma_range, &sym_module.avma_range)
            }) {
                grouped_modules.push((
                    candidate.id,
                    NativeSymbolizerModule {
                        info: sym_module,
                        identity: (&candidate).into(),
                    },
                ));
            }
        }

        let modules: Vec<_> = grouped_modules
            .iter()
            .map(|(_, module)| module.info.clone())
            .collect();
        let mut symbolizer = (self.native_factory)(module.process_id);
        symbolizer.set_modules(modules.clone());
        let idx = self.native_symbolizers.len();
        self.native_symbolizers.push(NativeSymbolizerGroup {
            process_id: module.process_id,
            modules: grouped_modules
                .iter()
                .map(|(_, module)| module.clone())
                .collect(),
            symbolizer,
        });
        for (module_id, _) in grouped_modules {
            self.native_symbolizer_by_module.insert(module_id, idx);
        }
        Some(())
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
            PerfMapProcesses::Pids(processes) => processes.contains(&process_id),
        }
    }

    fn lookup_perf_map_symbol(&mut self, process_id: i32, abs_ip: u64) -> Option<PerfMapSymbol> {
        self.perf_map_cache
            .entry(process_id)
            .or_insert_with(|| load_perf_map(process_id))
            .as_ref()
            .and_then(|symbols| find_perf_map_symbol(symbols, abs_ip))
            .cloned()
    }
}

fn perf_map_module_allowed(module: &ModuleRecord) -> bool {
    is_perf_map_mapping(&module.path)
}

impl NativeSymbolizerGroup {
    fn has_equivalent(&self, record: &ModuleRecord, module: &SymModule) -> bool {
        let identity = NativeFileIdentity::from(record);
        self.process_id == record.process_id
            && identity.inode != 0
            && self.modules.iter().any(|existing| {
                existing.identity == identity
                    && existing.info.path == module.path
                    && existing.info.avma_range == module.avma_range
                    && existing.info.image_base == module.image_base
                    && existing.info.is_executable == module.is_executable
                    && existing.info.is_python_runtime == module.is_python_runtime
            })
    }

    fn can_add(&self, process_id: i32, module: &SymModule) -> bool {
        self.process_id == process_id
            && self
                .modules
                .iter()
                .all(|existing| !ranges_overlap(&existing.info.avma_range, &module.avma_range))
    }
}

fn ranges_overlap(left: &std::ops::Range<u64>, right: &std::ops::Range<u64>) -> bool {
    left.start < right.end && right.start < left.end
}

fn find_perf_map_symbol(symbols: &[PerfMapSymbol], address: u64) -> Option<&PerfMapSymbol> {
    symbols[..symbols.partition_point(|s| s.start <= address)]
        .iter()
        .rfind(|s| address < s.end)
}

fn perf_map_symbol_to_frame(process_id: i32, abs_ip: u64, symbol: &PerfMapSymbol) -> ResolvedFrame {
    if let Some((func, file)) = parse_python_perf_map_symbol(&symbol.name) {
        return ResolvedFrame::Python(PythonFrame::new(
            file,
            LocationInfo::default(),
            func,
            None,
            false,
        ));
    }
    let native_symbol = NativeSymbol::new(
        symbol.name.clone(),
        SourceLocation::default(),
        format!("/tmp/perf-{process_id}.map"),
        abs_ip.saturating_sub(symbol.start),
        false,
        false,
    );
    ResolvedFrame::Native(NativeFrame {
        pc: abs_ip,
        sp: 0,
        symbol: Some(native_symbol),
        is_python_runtime: false,
        kind: FrameKind::Native,
        origin: SymbolOrigin::PerfMap,
        flags: FrameFlags::JIT,
    })
}

fn parse_python_perf_map_symbol(name: &str) -> Option<(&str, &str)> {
    let body = name.strip_prefix("py::")?.trim();
    if body.is_empty() {
        return None;
    }

    let colon_index = body.find(':');
    let space_index = body.find(' ');
    let (func, file) = match (colon_index, space_index) {
        (Some(colon), Some(space)) if colon < space => (&body[..colon], &body[colon + 1..]),
        (Some(colon), None) => (&body[..colon], &body[colon + 1..]),
        (_, Some(space)) => (&body[..space], &body[space + 1..]),
        (None, None) => (body, "~"),
    };

    let func = func.trim();
    if func.is_empty() {
        return None;
    }

    let file = strip_python_perf_map_line_suffix(file.trim());
    Some((func, if file.is_empty() { "~" } else { file }))
}

fn strip_python_perf_map_line_suffix(file: &str) -> &str {
    if let Some((path, line)) = file.rsplit_once(':') {
        if !path.is_empty() && line.chars().all(|c| c.is_ascii_digit()) {
            return path;
        }
    }
    file
}

fn is_perf_map_mapping(path: &str) -> bool {
    path == "//anon"
        || path == "[anon]"
        || path.starts_with("[anon:")
        || path == "[heap]"
        || path.starts_with("[stack")
        || path.starts_with("/dev/zero")
        || path.starts_with("/anon_hugepage")
        || path.starts_with("/SYSV")
}

fn module_display_name(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

fn load_perf_map(process_id: i32) -> Option<Vec<PerfMapSymbol>> {
    let mut symbols: Vec<PerfMapSymbol> = fs::read_to_string(format!("/tmp/perf-{process_id}.map"))
        .ok()?
        .lines()
        .filter_map(parse_perf_map_line)
        .collect();
    symbols.sort_by_key(|s| s.start);
    Some(symbols)
}

fn parse_perf_map_line(line: &str) -> Option<PerfMapSymbol> {
    let (start, rest) = take_ascii_field(line)?;
    let (len, name) = take_ascii_field(rest)?;
    if name.is_empty() {
        return None;
    }
    let start = u64::from_str_radix(start.trim_start_matches("0x"), 16).ok()?;
    let len = u64::from_str_radix(len.trim_start_matches("0x"), 16).ok()?;
    if len == 0 {
        return None;
    }
    let end = start.checked_add(len)?;
    Some(PerfMapSymbol {
        start,
        end,
        name: name.to_string(),
    })
}

fn take_ascii_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let end = input.find(|c: char| c.is_ascii_whitespace())?;
    Some((&input[..end], &input[end + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::test_fixtures::fake_hard_case_section_info;
    use crate::spool::PerfSpoolWriter;
    use std::os::unix::fs::MetadataExt;

    fn temp_perf_map_path(process_id: i32) -> String {
        format!("/tmp/perf-{process_id}.map")
    }

    fn frame(abs_ip: u64) -> FrameRecord {
        FrameRecord {
            module_id: None,
            rel_ip: abs_ip,
            abs_ip,
            mode: FrameMode::User,
        }
    }

    fn pinned_frame(module_id: u32, abs_ip: u64) -> FrameRecord {
        FrameRecord {
            module_id: Some(module_id),
            rel_ip: 8,
            abs_ip,
            mode: FrameMode::User,
        }
    }

    fn executable_module(id: u32, process_id: i32, start: u64) -> ModuleRecord {
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
            path: std::env::current_exe()
                .expect("current test executable")
                .to_string_lossy()
                .into_owned()
                .into(),
            is_kernel: false,
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

    #[test]
    fn sym_module_mapping_preserves_the_previous_linux_defaults() {
        let module = module_with_path(7, 42, 0x1000, "/tmp/libpython3.12.so");
        let image_base = crate::ModuleImageBase::new(0x1000, 0);
        let loaded = LoadedElfMapping {
            image_base: Some(image_base),
            sections: fake_hard_case_section_info(),
        };

        let sym_module = sym_module_for_mapping(&module, &loaded);

        assert_eq!(sym_module.path, module.path.as_path());
        assert_eq!(sym_module.avma_range, module.start..module.end);
        assert_eq!(sym_module.image_base, Some(image_base));
        assert!(sym_module.is_executable);
        assert!(!sym_module.is_python_runtime);
    }

    #[test]
    fn native_symbolizer_is_reused_for_non_overlapping_modules_in_same_process() {
        let mut symbolizer = PerfSymbolizer::new(&[]);
        let first = executable_module(1, 42, 0x1000);
        let second = executable_module(2, 42, 0x3000);
        let overlapping = executable_module(3, 42, 0x1800);
        let other_process = executable_module(4, 43, 0x1000);

        assert!(symbolizer
            .ensure_native_symbolizer_for_module(&first)
            .is_some());
        assert!(symbolizer
            .ensure_native_symbolizer_for_module(&second)
            .is_some());
        assert_eq!(symbolizer.native_symbolizers.len(), 1);
        assert_eq!(symbolizer.native_symbolizers[0].modules.len(), 2);

        assert!(symbolizer
            .ensure_native_symbolizer_for_module(&overlapping)
            .is_some());
        assert_eq!(symbolizer.native_symbolizers.len(), 2);

        assert!(symbolizer
            .ensure_native_symbolizer_for_module(&other_process)
            .is_some());
        assert_eq!(symbolizer.native_symbolizers.len(), 3);
    }

    #[test]
    fn module_ids_are_not_treated_as_slice_indexes() {
        let process_id = 42;
        let module = module_with_path(7, process_id, 0x1000, "/stable-seven.so");
        let mut symbolizer = PerfSymbolizer::with_perf_maps(&[module], false);
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(7, 0x1008));
        let invalid = symbolizer.resolve_frame(process_id, &pinned_frame(0, 0x1008));

        assert_eq!(resolved.func_name(), "stable-seven.so+0x8");
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
        let mut symbolizer = PerfSymbolizer::with_perf_maps(&modules, false);
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(0, 0x2008));

        assert_eq!(resolved.func_name(), "module-zero.so+0x8");
    }

    #[test]
    fn duplicate_module_ids_are_ambiguous() {
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
        let mut symbolizer = PerfSymbolizer::with_perf_maps(&modules, false);
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(7, 0x9008));

        assert!(matches!(
            resolved,
            ResolvedFrame::Native(frame) if frame.symbol.is_none()
        ));
    }

    #[test]
    fn sparse_ids_use_the_module_fallback_path() {
        let process_id = 42;
        let module = module_with_path(7, process_id, 0x1000, "[anon:sparse-seven]");
        let mut symbolizer = PerfSymbolizer::with_perf_maps(&[module], false);
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(7, 0x1008));

        assert_eq!(resolved.func_name(), "[anon:sparse-seven]+0x8");
    }

    #[test]
    fn native_symbolizer_reuses_only_same_file_identity() {
        let mut symbolizer = PerfSymbolizer::new(&[]);
        let mut first = executable_module(1, 42, 0x1000);
        let metadata = std::fs::metadata(first.path.as_path()).unwrap();
        first.inode = metadata.ino();
        first.device_major = libc::major(metadata.dev());
        first.device_minor = libc::minor(metadata.dev());
        first.inode_generation = 7;
        let mut same_file_generation = first.clone();
        same_file_generation.id = 2;
        let mut replaced_file = first.clone();
        replaced_file.id = 3;
        replaced_file.inode_generation += 1;

        let requested_module = {
            let loaded = symbolizer.elf_sections.load_mapping(&first).unwrap();
            sym_module_for_mapping(&first, &loaded)
        };

        assert!(symbolizer
            .ensure_native_symbolizer_for_module(&first)
            .is_some());
        assert!(symbolizer
            .ensure_native_symbolizer_for_module(&same_file_generation)
            .is_some());
        assert_eq!(symbolizer.native_symbolizers.len(), 1);
        assert_eq!(
            symbolizer.native_symbolizer_by_module[&same_file_generation.id],
            0
        );

        assert!(!symbolizer.native_symbolizers[0].has_equivalent(&replaced_file, &requested_module));
    }

    #[test]
    fn native_symbolizer_group_is_preseeded_from_known_modules() {
        let first = executable_module(1, 42, 0x1000);
        let second = executable_module(2, 42, 0x3000);
        let overlapping = executable_module(3, 42, 0x1800);
        let other_process = executable_module(4, 43, 0x5000);
        let mut symbolizer = PerfSymbolizer::new(&[
            first.clone(),
            second.clone(),
            overlapping.clone(),
            other_process.clone(),
        ]);

        assert!(symbolizer
            .ensure_native_symbolizer_for_module(&first)
            .is_some());

        assert_eq!(symbolizer.native_symbolizers.len(), 1);
        assert_eq!(symbolizer.native_symbolizers[0].modules.len(), 2);
        assert_eq!(
            symbolizer.native_symbolizer_by_module.get(&first.id),
            Some(&0)
        );
        assert_eq!(
            symbolizer.native_symbolizer_by_module.get(&second.id),
            Some(&0)
        );
        assert!(!symbolizer
            .native_symbolizer_by_module
            .contains_key(&overlapping.id));
        assert!(!symbolizer
            .native_symbolizer_by_module
            .contains_key(&other_process.id));

        assert!(symbolizer
            .ensure_native_symbolizer_for_module(&second)
            .is_some());
        assert_eq!(symbolizer.native_symbolizers.len(), 1);
    }

    #[test]
    fn python_perf_map_symbols_win() {
        let process_id = -(std::process::id() as i32);
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "1000 10 py::work:/tmp/app.py\n").expect("write perf map");

        let mut symbolizer = PerfSymbolizer::new(&[]);
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

        let mut symbolizer = PerfSymbolizer::new(&[]);
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

        let mut symbolizer = PerfSymbolizer::new(&[]);
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

        let mut symbolizer = PerfSymbolizer::with_perf_maps(&[], false);
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x2808));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Native(frame) => assert!(frame.symbol.is_none()),
            ResolvedFrame::Python(_) => panic!("stale perf-map frame should be ignored"),
        }
    }

    #[test]
    fn perf_map_symbols_can_be_limited_to_processes() {
        let allowed_process = -(std::process::id() as i32) - 3;
        let blocked_process = allowed_process - 1;
        let allowed_path = temp_perf_map_path(allowed_process);
        let blocked_path = temp_perf_map_path(blocked_process);
        fs::write(&allowed_path, "2900 20 py::allowed:/tmp/allowed.py\n")
            .expect("write allowed perf map");
        fs::write(&blocked_path, "2900 20 py::blocked:/tmp/blocked.py\n")
            .expect("write blocked perf map");

        let mut symbolizer = PerfSymbolizer::with_perf_map_processes(&[], [allowed_process]);
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
    fn overflowing_perf_map_range_does_not_match() {
        assert!(parse_perf_map_line("1000 ffffffffffffffff overflow_symbol").is_none());
    }

    #[test]
    fn perf_map_fields_accept_ascii_whitespace() {
        for (line, expected_name) in [
            ("1000 10 controlled name", "controlled name"),
            ("1000  10 controlled name", "controlled name"),
            ("1000\t10\tcontrolled name", "controlled name"),
            (" \t1000 \t 10 controlled name", "controlled name"),
            ("1000 10  controlled name", " controlled name"),
            ("1000 10\t\tcontrolled name", "\tcontrolled name"),
        ] {
            let symbol = parse_perf_map_line(line).expect("valid perf-map entry");
            assert_eq!(symbol.start, 0x1000);
            assert_eq!(symbol.end, 0x1010);
            assert_eq!(symbol.name, expected_name);
        }
    }

    #[test]
    fn malformed_perf_map_fields_are_rejected() {
        for line in [
            "",
            "1000",
            "1000 10",
            "1000 10 ",
            "1000 0 symbol",
            "not-hex 10 symbol",
            "1000 not-hex symbol",
            "1000\u{a0}10 symbol",
        ] {
            assert!(parse_perf_map_line(line).is_none(), "accepted {line:?}");
        }
    }

    #[test]
    fn perf_map_symbols_do_not_override_non_python_modules() {
        let process_id = -(std::process::id() as i32) - 4;
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "4000 20 py::fake_after_exec:/tmp/fake.py\n").expect("write perf map");
        let module = module_with_path(0, process_id, 0x4000, "/bin/bash");
        let mut symbolizer = PerfSymbolizer::new(&[module]);
        let resolved = symbolizer.resolve_frame(
            process_id,
            &FrameRecord {
                module_id: Some(0),
                rel_ip: 0x8,
                abs_ip: 0x4008,
                mode: FrameMode::User,
            },
        );
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Native(frame) => {
                assert_eq!(frame.kind, FrameKind::Native);
                assert_eq!(frame.origin, SymbolOrigin::Elf);
                assert!(!frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(!frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                assert!(!frame.is_python_runtime);
                assert_ne!(frame.func_name(), "fake_after_exec");
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
        let mut symbolizer = PerfSymbolizer::new(&[module]);
        let resolved = symbolizer.resolve_frame(process_id, &pinned_frame(0, 0x4008));
        let _ = fs::remove_file(&path);

        assert!(matches!(
            resolved,
            ResolvedFrame::Native(frame) if frame.origin == SymbolOrigin::Elf
        ));
    }

    #[test]
    fn perf_map_symbols_do_not_override_late_resolved_non_python_modules() {
        let process_id = -(std::process::id() as i32) - 6;
        let path = temp_perf_map_path(process_id);
        fs::write(&path, "5000 20 py::fake_after_exec:/tmp/fake.py\n").expect("write perf map");
        let module = module_with_path(0, process_id, 0x5000, "/bin/bash");
        let mut symbolizer = PerfSymbolizer::new(&[module]);
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x5008));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Native(frame) => {
                assert_eq!(frame.kind, FrameKind::Native);
                assert_eq!(frame.origin, SymbolOrigin::Elf);
                assert!(!frame.flags.contains(FrameFlags::PYTHON_RUNTIME));
                assert!(!frame.flags.contains(FrameFlags::HIDDEN_DEFAULT));
                assert!(!frame.is_python_runtime);
                assert_ne!(frame.func_name(), "fake_after_exec");
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
        let mut symbolizer = PerfSymbolizer::new(&[module]);
        let resolved = symbolizer.resolve_frame(
            process_id,
            &FrameRecord {
                module_id: Some(0),
                rel_ip: 0x8,
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
        let mut symbolizer = PerfSymbolizer::new(&[bracket_anon, perf_anon]);
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
        let mut symbolizer = PerfSymbolizer::new(&modules);

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

        let mut symbolizer = PerfSymbolizer::new(&[]);
        let frame = frame(0x3008);
        let first = symbolizer
            .resolve_cached_frame_ref(process_id, &frame)
            .func_name();
        let second = symbolizer
            .resolve_cached_frame_ref(process_id, &frame)
            .func_name();
        let _ = fs::remove_file(&path);

        assert_eq!(symbolizer.frame_cache.len(), 1);
        assert_eq!(first, second);
    }

    #[test]
    fn python_runtime_modules_are_classified_and_hidden_by_default() {
        let process_id = -(std::process::id() as i32) - 8;
        let module = module_with_path(0, process_id, 0x8000, "/usr/bin/python3");
        let mut symbolizer = PerfSymbolizer::new(&[module]);

        let resolved = symbolizer.resolve_frame(
            process_id,
            &FrameRecord {
                module_id: Some(0),
                rel_ip: 0x18,
                abs_ip: 0x8018,
                mode: FrameMode::User,
            },
        );

        match resolved {
            ResolvedFrame::Native(frame) => {
                assert_eq!(frame.kind, FrameKind::Native);
                assert_eq!(frame.origin, SymbolOrigin::Elf);
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
        let mut symbolizer = PerfSymbolizer::new(&[]);
        symbolizer.kernel_symbols = Some(KernelSymbolTable::Full(Arc::from([])));
        let frame = FrameRecord {
            module_id: None,
            rel_ip: 0xffff_ffff_8000_1234,
            abs_ip: 0xffff_ffff_8000_1234,
            mode: FrameMode::Kernel,
        };

        let resolved = symbolizer.resolve_native_frame(&frame, None);

        assert_eq!(resolved.kind, FrameKind::Kernel);
        assert_eq!(resolved.origin, SymbolOrigin::KernelSymbols);
        let symbol = resolved.symbol.expect("kernel fallback symbol");
        assert_eq!(symbol.name.as_ref(), "[kernel]+0xffffffff80001234");
        assert_eq!(symbol.module.as_ref(), "[kernel]");
        assert_eq!(symbol.offset, 0);
    }

    #[test]
    fn resolved_kernel_symbols_carry_within_function_offsets() {
        let mut symbolizer = PerfSymbolizer::new(&[]);
        symbolizer.kernel_symbols = Some(KernelSymbolTable::Full(Arc::from([KernelSymbol {
            address: 0xffff_ffff_8100_0000,
            name: "vfs_read".to_owned(),
            module: None,
        }])));
        let frame = FrameRecord {
            module_id: None,
            rel_ip: 0xffff_ffff_8100_0014,
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
        let mut symbolizer = PerfSymbolizer::new(&[]);

        let marker = symbolizer.resolve_native_frame(&FrameRecord::truncated_stack_marker(), None);
        let null_pc = symbolizer.resolve_native_frame(
            &FrameRecord {
                module_id: None,
                rel_ip: 0,
                abs_ip: 0,
                mode: FrameMode::User,
            },
            None,
        );

        assert!(marker.flags.contains(FrameFlags::TRUNCATED_STACK));
        assert_eq!(marker.func_name(), "<stack truncated>");
        assert_eq!(null_pc.func_name(), "<0x0>");
        assert!(null_pc.flags.is_empty());
        assert_ne!(marker, null_pc);
    }

    #[test]
    fn kernel_resolution_preserves_module_name() {
        let mut symbolizer = PerfSymbolizer::new(&[]);
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
        let stack_id = writer
            .write_sample_frames(1_000, 7, 11, [frame])
            .unwrap()
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let mut symbolizer = PerfSymbolizer::new(reader.modules());
        symbolizer.kernel_symbols = Some(KernelSymbolTable::Sparse(Arc::from([(
            frame.abs_ip,
            wireguard_kernel_symbol(),
        )])));

        let raw_frames = reader.stack_frame_refs(stack_id).unwrap();
        let mut resolved = Vec::new();
        symbolizer.for_each_resolved_frame(7, stack_id, raw_frames, |frame| {
            resolved.push(frame.clone());
        });

        assert_eq!(resolved.len(), 1);
        let ResolvedFrame::Native(frame) = &resolved[0] else {
            panic!("expected native kernel frame");
        };
        assert_wireguard_kernel_frame(frame);
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
        reader: &PerfSpoolReader,
        mut symbolizer: PerfSymbolizer,
        stack_id: u32,
    ) {
        let mut resolved = None;
        symbolizer.for_each_resolved_frame(
            7,
            stack_id,
            reader.stack_frame_refs(stack_id).unwrap(),
            |frame| resolved = Some(frame.clone()),
        );
        let ResolvedFrame::Native(frame) = resolved.expect("resolved frame") else {
            panic!("expected native address-only frame");
        };
        assert_eq!(frame.origin, SymbolOrigin::AddressOnly);
        assert!(frame.symbol.is_none());
    }

    #[test]
    fn spool_symbolizer_does_not_resolve_moduleless_frames_to_future_modules() {
        let (path, stack_id) = write_future_module_spool("future-module");
        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let symbolizer = PerfSymbolizer::for_spool_with_perf_maps(&reader, false);
        assert_future_module_unresolved(&reader, symbolizer, stack_id);
    }

    #[test]
    fn spool_symbolizer_with_pid_restricted_perf_maps_keeps_frame_limits() {
        let (path, stack_id) = write_future_module_spool("future-module-pid-filter");
        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let symbolizer = PerfSymbolizer::for_spool_with_perf_map_processes(&reader, [7]);
        assert_future_module_unresolved(&reader, symbolizer, stack_id);
    }

    #[test]
    fn spool_symbolizer_recorded_python_perf_maps_survive_exit_marker() {
        let process_id = -(std::process::id() as i32) - 11;
        let perf_map_path = temp_perf_map_path(process_id);
        fs::write(&perf_map_path, "5900 20 py::kept:/tmp/app.py\n").expect("write perf map");

        let path = temp_symbolize_spool_path("python-perf-map-exit-marker");
        let frame = frame(0x5908);
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        writer.write_process_exec(0, process_id, true).unwrap();
        writer
            .write_sample_frames(1, process_id, 11, [frame])
            .unwrap();
        writer.write_process_exec(2, process_id, false).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let mut symbolizer = PerfSymbolizer::for_spool_with_recorded_python_perf_maps(&reader);
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
            rel_ip: 0xffff_ffff_c001_0014,
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
