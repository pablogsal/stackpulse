use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use memchr::memchr;

use crate::profile::{
    FrameFlags, FrameKind, LocationInfo, NativeFrame, NativeSymbol, PythonFrame, ResolvedFrame,
    SourceLocation, SymbolOrigin,
};
use crate::symbols::{
    default_native_symbolizer_factory, NativeSymbolizer, NativeSymbolizerFactory, SymModule,
    SymbolsRc,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::native_module::ElfSectionCache;
use crate::spool::{
    self, FrameMode, FrameModuleRef, FrameRecord, ModuleRecord, PerfSpoolReader,
    SpoolFrameModuleContexts, StackFrameRefs,
};

/// Resolves raw profile frames into displayable frames.
pub struct PerfSymbolizer {
    modules: Vec<ModuleRecord>,
    perf_map_processes: PerfMapProcesses,
    elf_sections: ElfSectionCache,
    native_symbolizers: Vec<NativeSymbolizerGroup>,
    native_symbolizer_by_module: FxHashMap<u32, usize>,
    unsupported_native_modules: FxHashSet<u32>,
    perf_map_cache: FxHashMap<i32, Option<Vec<PerfMapSymbol>>>,
    kernel_symbols: Option<KernelSymbolTable>,
    spool_frame_contexts: Option<SpoolFrameModuleContexts>,
    frame_cache: FxHashMap<(i32, FrameCacheKey), Box<[usize]>>,
    resolved_frames: Vec<ResolvedFrame>,
    stack_cache: FxHashMap<(i32, u32), Box<[usize]>>,
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
struct KernelSymbol {
    address: u64,
    name: String,
    module: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelSymbolName<'a> {
    name: &'a [u8],
    module: Option<&'a [u8]>,
}

struct ResolvedKernelSymbol {
    name: String,
    module: String,
    // Byte offset of the instruction within the resolved kernel function.
    offset: u64,
}

#[derive(Clone)]
enum KernelSymbolTable {
    Full(Arc<[KernelSymbol]>),
    Sparse(Arc<[(u64, KernelSymbol)]>),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SparseKernelSymbolCacheKey {
    kernel_id: Arc<str>,
    addresses: Arc<[u64]>,
}

/// Process-global cache of sparse kernel symbol lookups, bounded FIFO. Hits
/// only happen for byte-identical kernel address sets (same spool reopened),
/// so a small capacity covers the useful cases while keeping long-running
/// services that open many distinct profiles from accumulating dead entries.
#[derive(Default)]
struct SparseKernelSymbolCache {
    entries: FxHashMap<SparseKernelSymbolCacheKey, Arc<[(u64, KernelSymbol)]>>,
    insertion_order: VecDeque<SparseKernelSymbolCacheKey>,
}

const SPARSE_KERNEL_SYMBOL_CACHE_CAP: usize = 16;

impl SparseKernelSymbolCache {
    fn get(&self, key: &SparseKernelSymbolCacheKey) -> Option<Arc<[(u64, KernelSymbol)]>> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: SparseKernelSymbolCacheKey, value: Arc<[(u64, KernelSymbol)]>) {
        if self.entries.insert(key.clone(), value).is_none() {
            self.insertion_order.push_back(key);
            if self.insertion_order.len() > SPARSE_KERNEL_SYMBOL_CACHE_CAP {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.entries.remove(&oldest);
                }
            }
        }
    }
}

#[derive(Clone)]
struct PerfMapSymbol {
    start: u64,
    end: u64,
    lookup_end: u64,
    name: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum FrameCacheKey {
    Spool(u32),
    Raw(FrameRecord),
}

struct NativeSymbolizerGroup {
    process_id: i32,
    modules: Vec<SymModule>,
    symbolizer: Box<dyn NativeSymbolizer>,
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
        symbolizer.kernel_symbols =
            Some(load_sparse_kernel_symbols(reader.kernel_frame_addresses()));
        symbolizer.spool_frame_contexts = Some(reader.frame_module_contexts());
        symbolizer
    }

    fn with_perf_map_processes_inner(
        modules: &[ModuleRecord],
        perf_map_processes: PerfMapProcesses,
        native_factory: NativeSymbolizerFactory,
    ) -> Self {
        Self {
            modules: modules.to_vec(),
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
            stack_cache: FxHashMap::default(),
            native_factory,
        }
    }

    /// Resolve borrowed raw frames and visit each resolved frame without
    /// materializing a resolved stack.
    ///
    /// This is the hot path for profile aggregation: resolved frames are owned
    /// by the symbolizer's frame cache and borrowed only for the callback.
    pub fn for_each_resolved_frame(
        &mut self,
        process_id: i32,
        stack_id: u32,
        mut frames: StackFrameRefs<'_>,
        mut visit: impl FnMut(&ResolvedFrame),
    ) -> usize {
        let cache_key = (process_id, stack_id);
        if let Some(frame_ids) = self.stack_cache.get(&cache_key) {
            for &frame_id in frame_ids.iter() {
                visit(&self.resolved_frames[frame_id]);
            }
            return frame_ids.len();
        }

        let mut frame_ids = Vec::with_capacity(frames.len());
        while let Some((frame_id, frame)) = frames.next_with_id() {
            let resolved_ids = self.resolve_cached_frame_ids(
                process_id,
                frame,
                FrameCacheKey::Spool(frame_id),
                Some(frame_id),
            );
            for frame_id in resolved_ids.iter().copied() {
                visit(&self.resolved_frames[frame_id]);
                frame_ids.push(frame_id);
            }
        }
        let count = frame_ids.len();
        self.stack_cache
            .insert(cache_key, frame_ids.into_boxed_slice());
        count
    }

    #[doc(hidden)]
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
            for frame_id in resolved_ids.iter().copied() {
                visit(&self.resolved_frames[frame_id]);
                count += 1;
            }
        }
        count
    }

    #[cfg(test)]
    fn resolve_cached_frame_ref(&mut self, process_id: i32, frame: &FrameRecord) -> &ResolvedFrame {
        let frame_id =
            self.resolve_cached_frame_ids(process_id, frame, FrameCacheKey::Raw(*frame), None)[0];
        &self.resolved_frames[frame_id]
    }

    fn resolve_cached_frame_ids(
        &mut self,
        process_id: i32,
        frame: &FrameRecord,
        cache_key: FrameCacheKey,
        spool_frame_id: Option<u32>,
    ) -> Box<[usize]> {
        let cache_key = (process_id, cache_key);
        if let Some(frame_ids) = self.frame_cache.get(&cache_key) {
            return frame_ids.clone();
        }
        let frame_ids = self
            .resolve_frames(process_id, frame, spool_frame_id)
            .into_vec()
            .into_iter()
            .map(|resolved| {
                let frame_id = self.resolved_frames.len();
                self.resolved_frames.push(resolved);
                frame_id
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.frame_cache.insert(cache_key, frame_ids.clone());
        frame_ids
    }

    #[cfg(test)]
    fn resolve_frame(&mut self, process_id: i32, frame: &FrameRecord) -> ResolvedFrame {
        self.resolve_frames(process_id, frame, None)
            .into_vec()
            .into_iter()
            .next()
            .expect("frame resolution returns at least one frame")
    }

    fn resolve_frames(
        &mut self,
        process_id: i32,
        frame: &FrameRecord,
        spool_frame_id: Option<u32>,
    ) -> Box<[ResolvedFrame]> {
        if let Some(module) = frame
            .module_id
            .and_then(|module_id| self.modules.get(module_id as usize))
            .filter(|module| !perf_map_module_allowed(module))
        {
            return self
                .resolve_native_frames(frame, Some((module.clone(), frame.rel_ip)))
                .into_iter()
                .map(ResolvedFrame::Native)
                .collect::<Vec<_>>()
                .into_boxed_slice();
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
                    .collect::<Vec<_>>()
                    .into_boxed_slice();
            }

            return vec![perf_map_symbol_to_frame(process_id, frame.abs_ip, symbol)]
                .into_boxed_slice();
        }
        let module = self.owned_module_for_frame(process_id, frame, spool_frame_id);
        self.resolve_native_frames(frame, module)
            .into_iter()
            .map(ResolvedFrame::Native)
            .collect::<Vec<_>>()
            .into_boxed_slice()
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
        let Some((module_info, _section_info)) = self.elf_sections.module_info(module) else {
            self.unsupported_native_modules.insert(module.id);
            return None;
        };
        let requested_module = SymModule::from(&module_info);
        if let Some(idx) = self
            .native_symbolizers
            .iter()
            .position(|group| group.can_add(module.process_id, &requested_module))
        {
            let group = &mut self.native_symbolizers[idx];
            group.modules.push(requested_module);
            group.symbolizer.set_modules(group.modules.clone());
            self.native_symbolizer_by_module.insert(module.id, idx);
            return Some(());
        }

        let mut grouped_modules = vec![(module.id, requested_module)];
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
            let Some((module_info, _section_info)) = self.elf_sections.module_info(&candidate)
            else {
                self.unsupported_native_modules.insert(candidate.id);
                continue;
            };
            let sym_module = SymModule::from(&module_info);
            if grouped_modules
                .iter()
                .all(|(_, existing)| !ranges_overlap(&existing.avma_range, &sym_module.avma_range))
            {
                grouped_modules.push((candidate.id, sym_module));
            }
        }

        let modules: Vec<_> = grouped_modules
            .iter()
            .map(|(_, module)| module.clone())
            .collect();
        let mut symbolizer = (self.native_factory)(module.process_id);
        symbolizer.set_modules(modules.clone());
        let idx = self.native_symbolizers.len();
        self.native_symbolizers.push(NativeSymbolizerGroup {
            process_id: module.process_id,
            modules,
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
            .get_or_insert_with(load_shared_kernel_symbols);
        let symbol = find_kernel_symbol_in_table(symbols, abs_ip)?;
        let offset = abs_ip.saturating_sub(symbol.address);
        Some(ResolvedKernelSymbol {
            name: format_symbol(&symbol.name, offset),
            module: symbol
                .module
                .clone()
                .unwrap_or_else(|| "[kernel]".to_owned()),
            offset,
        })
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
    crate::is_python_runtime_module_path(&module.path) || is_anonymous_module(&module.path)
}

impl NativeSymbolizerGroup {
    fn can_add(&self, process_id: i32, module: &SymModule) -> bool {
        self.process_id == process_id
            && self
                .modules
                .iter()
                .all(|existing| !ranges_overlap(&existing.avma_range, &module.avma_range))
    }
}

fn ranges_overlap(left: &std::ops::Range<u64>, right: &std::ops::Range<u64>) -> bool {
    left.start < right.end && right.start < left.end
}

fn format_symbol(name: &str, offset: u64) -> String {
    if offset == 0 {
        name.to_owned()
    } else {
        format!("{name}+0x{offset:x}")
    }
}

fn find_kernel_symbol(symbols: &[KernelSymbol], address: u64) -> Option<&KernelSymbol> {
    symbols[..symbols.partition_point(|s| s.address <= address)].last()
}

fn find_kernel_symbol_in_table(symbols: &KernelSymbolTable, address: u64) -> Option<&KernelSymbol> {
    match symbols {
        KernelSymbolTable::Full(symbols) => find_kernel_symbol(symbols, address),
        KernelSymbolTable::Sparse(symbols) => symbols
            .binary_search_by_key(&address, |(address, _)| *address)
            .ok()
            .map(|idx| &symbols[idx].1),
    }
}

fn find_perf_map_symbol(symbols: &[PerfMapSymbol], address: u64) -> Option<&PerfMapSymbol> {
    symbols[..symbols.partition_point(|s| s.start <= address)]
        .iter()
        .rfind(|s| address < s.lookup_end)
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

fn is_anonymous_module(path: &str) -> bool {
    path == "[anon]" || path == "//anon" || path.starts_with("[anon:")
}

fn module_display_name(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

fn load_kernel_symbols() -> io::Result<Vec<KernelSymbol>> {
    let data = fs::read("/proc/kallsyms")?;
    Ok(parse_kernel_symbols(&data))
}

/// Warn once, process-wide, when kernel symbolization is unavailable, from
/// whichever kallsyms load path (full or sparse) hits the problem first.
fn warn_kallsyms_unusable(err: Option<&io::Error>) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| match err {
        Some(err) => tracing::warn!(
            "Failed to read /proc/kallsyms: {err}; kernel frames will not be symbolized"
        ),
        None => tracing::warn!(
            "No usable kernel symbols in /proc/kallsyms (kptr_restrict or perf_event_paranoid may hide addresses); kernel frames will not be symbolized"
        ),
    });
}

fn parse_kernel_symbols(data: &[u8]) -> Vec<KernelSymbol> {
    let mut symbols = Vec::new();
    let mut text_addr = None;

    for (address, name) in KallSymIter::new(data) {
        if should_include_kernel_symbol(&mut text_addr, address, name) {
            symbols.push(kernel_symbol_from_name(address, name));
        }
    }
    symbols.sort_by_key(|s| s.address);
    symbols.dedup_by_key(|s| s.address);
    symbols
}

fn load_sparse_kernel_symbols(addresses: impl IntoIterator<Item = u64>) -> KernelSymbolTable {
    let mut addresses: Vec<_> = addresses.into_iter().collect();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return KernelSymbolTable::Sparse(Arc::from([]));
    }

    let cache_key = SparseKernelSymbolCacheKey {
        kernel_id: running_kernel_cache_id(),
        addresses: Arc::from(addresses.clone().into_boxed_slice()),
    };
    if let Ok(cache) = sparse_kernel_symbol_cache().lock() {
        if let Some(symbols) = cache.get(&cache_key) {
            return KernelSymbolTable::Sparse(symbols);
        }
    }

    let symbols = match load_sparse_kernel_symbols_from_file(&addresses) {
        Ok(symbols) => symbols,
        Err(err) => {
            warn_kallsyms_unusable(Some(&err));
            return KernelSymbolTable::Sparse(Arc::from([]));
        }
    };
    if symbols.is_empty() {
        warn_kallsyms_unusable(None);
    }
    let symbols = Arc::from(symbols.into_boxed_slice());
    if let Ok(mut cache) = sparse_kernel_symbol_cache().lock() {
        cache.insert(cache_key, Arc::clone(&symbols));
    }
    KernelSymbolTable::Sparse(symbols)
}

fn sparse_kernel_symbol_cache() -> &'static Mutex<SparseKernelSymbolCache> {
    static CACHE: OnceLock<Mutex<SparseKernelSymbolCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(SparseKernelSymbolCache::default()))
}

fn running_kernel_cache_id() -> Arc<str> {
    static CACHE_ID: OnceLock<Arc<str>> = OnceLock::new();
    Arc::clone(CACHE_ID.get_or_init(|| {
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| "unknown".to_owned())
            .into()
    }))
}

fn load_sparse_kernel_symbols_from_file(
    requested_addresses: &[u64],
) -> io::Result<Vec<(u64, KernelSymbol)>> {
    let file = fs::File::open("/proc/kallsyms")?;
    let mut reader = io::BufReader::with_capacity(1024 * 1024, file);
    match parse_sparse_kernel_symbols_sorted_streaming(&mut reader, requested_addresses)? {
        Some(symbols) => Ok(symbols),
        None => fs::read("/proc/kallsyms")
            .map(|data| parse_sparse_kernel_symbols_unsorted(&data, requested_addresses)),
    }
}

/// In-memory entry point for benches and tests. Drives the same streaming
/// sorted scanner the production load path uses, falling back to the unsorted
/// parser when the data is detected to be out of order.
fn parse_sparse_kernel_symbols(
    data: &[u8],
    requested_addresses: &[u64],
) -> Vec<(u64, KernelSymbol)> {
    match parse_sparse_kernel_symbols_sorted_streaming(
        &mut io::Cursor::new(data),
        requested_addresses,
    ) {
        Ok(Some(symbols)) => symbols,
        _ => parse_sparse_kernel_symbols_unsorted(data, requested_addresses),
    }
}

pub(crate) fn bench_parse_sparse_kernel_symbols(
    data: &[u8],
    requested_addresses: &[u64],
    rounds: u64,
) -> usize {
    let mut checksum = 0usize;
    for _ in 0..rounds {
        let symbols = parse_sparse_kernel_symbols(data, requested_addresses);
        for (requested, symbol) in symbols {
            checksum = checksum
                .wrapping_add(requested as usize)
                .wrapping_add(symbol.address as usize)
                .wrapping_add(symbol.name.len());
        }
    }
    checksum
}

fn parse_sparse_kernel_symbols_unsorted(
    data: &[u8],
    requested_addresses: &[u64],
) -> Vec<(u64, KernelSymbol)> {
    let symbols = parse_kernel_symbols(data);
    requested_addresses
        .iter()
        .filter_map(|&address| {
            find_kernel_symbol(&symbols, address)
                .cloned()
                .map(|symbol| (address, symbol))
        })
        .collect()
}

fn parse_sparse_kernel_symbols_sorted_streaming(
    reader: &mut impl BufRead,
    requested_addresses: &[u64],
) -> io::Result<Option<Vec<(u64, KernelSymbol)>>> {
    let mut scan = SparseKernelSymbolScan::new(requested_addresses);
    let mut carry = Vec::new();

    loop {
        let mut consumed = 0;
        let mut unsorted = false;
        {
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                if !carry.is_empty() {
                    match scan.process_line(&carry) {
                        SparseScanState::Continue => {}
                        SparseScanState::Unsorted => return Ok(None),
                    }
                }
                return Ok(Some(scan.finish()));
            }

            while consumed < buffer.len() {
                let tail = &buffer[consumed..];
                let Some(newline) = memchr(b'\n', tail) else {
                    carry.extend_from_slice(tail);
                    consumed = buffer.len();
                    break;
                };
                let line_end = consumed + newline + 1;
                let state = if carry.is_empty() {
                    scan.process_line(&buffer[consumed..line_end])
                } else {
                    carry.extend_from_slice(&buffer[consumed..line_end]);
                    let state = scan.process_line(&carry);
                    carry.clear();
                    state
                };
                consumed = line_end;
                if let SparseScanState::Unsorted = state {
                    unsorted = true;
                    break;
                }
            }
        }
        reader.consume(consumed);
        if unsorted {
            return Ok(None);
        }
    }
}

struct SparseKernelSymbolScan<'a> {
    requested_addresses: &'a [u64],
    result: Vec<(u64, KernelSymbol)>,
    request_idx: usize,
    text_addr: Option<u64>,
    last_address: Option<u64>,
    last_symbol: Option<KernelSymbol>,
}

enum SparseScanState {
    Continue,
    Unsorted,
}

impl<'a> SparseKernelSymbolScan<'a> {
    fn new(requested_addresses: &'a [u64]) -> Self {
        Self {
            requested_addresses,
            result: Vec::with_capacity(requested_addresses.len()),
            request_idx: 0,
            text_addr: None,
            last_address: None,
            last_symbol: None,
        }
    }

    fn process_line(&mut self, line: &[u8]) -> SparseScanState {
        let Some((address, name)) = parse_kernel_symbol_line_bytes(line) else {
            return SparseScanState::Continue;
        };
        if !should_include_kernel_symbol(&mut self.text_addr, address, name) {
            return SparseScanState::Continue;
        }
        if self.last_address.is_some_and(|last| address < last) {
            return SparseScanState::Unsorted;
        }
        self.last_address = Some(address);

        while self.request_idx < self.requested_addresses.len()
            && self.requested_addresses[self.request_idx] < address
        {
            if let Some(symbol) = &self.last_symbol {
                self.result
                    .push((self.requested_addresses[self.request_idx], symbol.clone()));
            }
            self.request_idx += 1;
        }
        if self.request_idx >= self.requested_addresses.len() {
            return SparseScanState::Continue;
        }
        if self
            .last_symbol
            .as_ref()
            .is_none_or(|symbol| symbol.address != address)
        {
            self.last_symbol = Some(kernel_symbol_from_name(address, name));
        }
        SparseScanState::Continue
    }

    fn finish(mut self) -> Vec<(u64, KernelSymbol)> {
        while self.request_idx < self.requested_addresses.len() {
            if let Some(symbol) = &self.last_symbol {
                self.result
                    .push((self.requested_addresses[self.request_idx], symbol.clone()));
            }
            self.request_idx += 1;
        }
        self.result
    }
}

fn parse_kernel_symbol_line_bytes(line: &[u8]) -> Option<(u64, KernelSymbolName<'_>)> {
    let (address, address_len) = parse_hex_u64(line)?;
    let name_start = address_len.checked_add(3)?;
    let name_and_rest = line.get(name_start..)?;
    let line_len = memchr(b'\n', name_and_rest).unwrap_or(name_and_rest.len());
    let line = &name_and_rest[..line_len];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    Some((address, parse_kernel_symbol_name(line)))
}

struct KallSymIter<'a> {
    remaining: &'a [u8],
}

impl<'a> KallSymIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }
}

impl<'a> Iterator for KallSymIter<'a> {
    type Item = (u64, KernelSymbolName<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        // Skip unparsable lines rather than ending iteration: one malformed
        // line must not drop every symbol after it.
        while !self.remaining.is_empty() {
            let line_len = memchr(b'\n', self.remaining)
                .map(|idx| idx + 1)
                .unwrap_or(self.remaining.len());
            let line = &self.remaining[..line_len];
            self.remaining = self.remaining.get(line_len..).unwrap_or_default();
            if let Some((address, name)) = parse_kernel_symbol_line_bytes(line) {
                return Some((address, name));
            }
        }
        None
    }
}

fn parse_hex_u64(input: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    let mut len = 0;
    for &byte in input.iter().take(16) {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => break,
        };
        value = (value << 4) | u64::from(digit);
        len += 1;
    }
    (len != 0).then_some((value, len))
}

fn should_include_kernel_symbol(
    text_addr: &mut Option<u64>,
    address: u64,
    name: KernelSymbolName<'_>,
) -> bool {
    if address == 0 {
        return false;
    }
    if text_addr.is_none() && name.name == b"_text" {
        *text_addr = Some(address);
    }
    name.module.is_some() || text_addr.is_some_and(|anchor| address >= anchor)
}

fn parse_kernel_symbol_name(name: &[u8]) -> KernelSymbolName<'_> {
    if name.last() == Some(&b']') {
        if let Some(bracket_start) = name.iter().rposition(|&byte| byte == b'[') {
            let module = &name[bracket_start + 1..name.len() - 1];
            if !module.is_empty() {
                return KernelSymbolName {
                    name: trim_ascii_end(&name[..bracket_start]),
                    module: Some(module),
                };
            }
        }
    }
    KernelSymbolName { name, module: None }
}

fn trim_ascii_end(mut data: &[u8]) -> &[u8] {
    while data.last().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
        data = &data[..data.len() - 1];
    }
    data
}

fn kernel_symbol_from_name(address: u64, name: KernelSymbolName<'_>) -> KernelSymbol {
    KernelSymbol {
        address,
        name: kernel_symbol_name_to_string(name.name),
        module: name.module.map(kernel_symbol_module_to_string),
    }
}

fn kernel_symbol_name_to_string(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn kernel_symbol_module_to_string(module: &[u8]) -> String {
    format!("[{}]", String::from_utf8_lossy(module))
}

fn load_shared_kernel_symbols() -> KernelSymbolTable {
    static KERNEL_SYMBOLS: OnceLock<Arc<[KernelSymbol]>> = OnceLock::new();
    KernelSymbolTable::Full(Arc::clone(KERNEL_SYMBOLS.get_or_init(|| {
        let symbols = match load_kernel_symbols() {
            Ok(symbols) => symbols,
            Err(err) => {
                warn_kallsyms_unusable(Some(&err));
                Vec::new()
            }
        };
        if symbols.is_empty() {
            warn_kallsyms_unusable(None);
        }
        Arc::from(symbols.into_boxed_slice())
    })))
}

fn load_perf_map(process_id: i32) -> Option<Vec<PerfMapSymbol>> {
    let mut symbols: Vec<PerfMapSymbol> = fs::read_to_string(format!("/tmp/perf-{process_id}.map"))
        .ok()?
        .lines()
        .filter_map(parse_perf_map_line)
        .collect();
    symbols.sort_by_key(|s| s.start);
    infer_python_trampoline_slot_ranges(&mut symbols);
    Some(symbols)
}

fn parse_perf_map_line(line: &str) -> Option<PerfMapSymbol> {
    let mut parts = line.splitn(3, ' ');
    let (start, len, name) = (parts.next()?, parts.next()?, parts.next()?);
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
        lookup_end: end,
        name: name.to_string(),
    })
}

fn infer_python_trampoline_slot_ranges(symbols: &mut [PerfMapSymbol]) {
    for i in 0..symbols.len() {
        if !symbols[i].name.starts_with("py::") {
            continue;
        }

        if let Some(slot_size) = python_trampoline_slot_size(symbols, i) {
            if let Some(slot_end) = symbols[i].start.checked_add(slot_size) {
                symbols[i].lookup_end = symbols[i].lookup_end.max(slot_end);
            }
        }
    }
}

fn python_trampoline_slot_size(symbols: &[PerfMapSymbol], index: usize) -> Option<u64> {
    let symbol = symbols.get(index)?;
    let code_size = symbol.end.checked_sub(symbol.start)?;
    let next_delta = symbols.get(index + 1).and_then(|next| {
        next.name
            .starts_with("py::")
            .then(|| next.start.checked_sub(symbol.start))?
    });
    let previous_delta = index.checked_sub(1).and_then(|previous_index| {
        let previous = &symbols[previous_index];
        previous
            .name
            .starts_with("py::")
            .then(|| symbol.start.checked_sub(previous.start))?
    });
    let slot_size = next_delta.or(previous_delta)?;
    (code_size < slot_size && slot_size <= 0x100 && slot_size.is_power_of_two())
        .then_some(slot_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::PerfSpoolWriter;

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

    fn executable_module(id: u32, process_id: i32, start: u64) -> ModuleRecord {
        ModuleRecord {
            id,
            process_id,
            start,
            end: start + 0x1000,
            file_offset: 0,
            inode: 0,
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
            path: path.into(),
            is_kernel: false,
        }
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
    fn python_perf_map_symbols_cover_trampoline_return_slot() {
        let process_id = -(std::process::id() as i32) - 9;
        let path = temp_perf_map_path(process_id);
        fs::write(
            &path,
            "1000 c py::first:/tmp/app.py\n1020 c py::second:/tmp/app.py\n",
        )
        .expect("write perf map");

        let mut symbolizer = PerfSymbolizer::new(&[]);
        let resolved = symbolizer.resolve_frame(process_id, &frame(0x100e));
        let _ = fs::remove_file(&path);

        match resolved {
            ResolvedFrame::Python(frame) => {
                assert_eq!(frame.func_name.as_ref(), "first");
                assert_eq!(frame.file_name.as_ref(), "/tmp/app.py");
            }
            ResolvedFrame::Native(_) => panic!("expected Python trampoline slot frame"),
        }
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
    fn parses_kernel_symbol_lines() {
        let mut iter = KallSymIter::new(
            b"ffffffff89800000 T _text\nffffffff89800137 t syscall_return [kernel]\n",
        );

        let (address, name) = iter.next().expect("_text symbol");
        assert_eq!(address, 0xffff_ffff_8980_0000);
        assert_eq!(name.name, b"_text");
        assert_eq!(name.module, None);

        let (address, name) = iter.next().expect("module symbol");
        assert_eq!(address, 0xffff_ffff_8980_0137);
        assert_eq!(name.name, b"syscall_return");
        assert_eq!(name.module, Some(b"kernel".as_slice()));
        assert_eq!(KallSymIter::new(b"not-an-address T broken\n").next(), None);
    }

    #[test]
    fn kernel_symbol_iterator_skips_unparsable_lines() {
        let mut iter = KallSymIter::new(
            b"ffffffff89800000 T _text\nnot-an-address T broken\nffffffff89800137 t syscall_return\n",
        );

        assert_eq!(iter.next().expect("_text symbol").0, 0xffff_ffff_8980_0000);
        assert_eq!(
            iter.next().expect("symbol after bad line").0,
            0xffff_ffff_8980_0137
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn zeroed_kernel_symbols_are_ignored() {
        let kallsyms = b"0000000000000000 T _text\n\
                         0000000000000000 t schedule\n\
                         0000000000000000 t module_symbol [module]\n";

        assert!(parse_kernel_symbols(kallsyms).is_empty());
        assert!(parse_sparse_kernel_symbols(kallsyms, &[0xffff_ffff_8000_1234]).is_empty());

        let mut reader = io::Cursor::new(kallsyms);
        let sparse =
            parse_sparse_kernel_symbols_sorted_streaming(&mut reader, &[0xffff_ffff_8000_1234])
                .unwrap()
                .unwrap();
        assert!(sparse.is_empty());
    }

    #[test]
    fn kernel_symbols_keep_module_symbols_before_text() {
        let kallsyms = b"ffff800001717020 t tls_update  [tls]\n\
                         ffff8000081e0000 T _text\n\
                         ffff8000081f0000 t core_symbol\n";
        let symbols = parse_kernel_symbols(kallsyms);

        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[0].name, "tls_update");
        assert_eq!(symbols[0].module.as_deref(), Some("[tls]"));
        assert_eq!(symbols[1].name, "_text");
        assert_eq!(symbols[1].module, None);
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

    #[test]
    fn sparse_kernel_symbols_keep_only_requested_addresses() {
        let kallsyms = b"ffffffff89800000 T _text\n\
                         ffffffff89800100 T first\n\
                         ffffffff89800100 t duplicate\n\
                         ffffffff89800200 t second [kernel]\n";
        let symbols = parse_sparse_kernel_symbols(
            kallsyms,
            &[
                0xffff_ffff_8980_0000,
                0xffff_ffff_8980_0101,
                0xffff_ffff_8980_01ff,
                0xffff_ffff_8980_0204,
            ],
        );

        assert_eq!(symbols.len(), 4);
        assert_eq!(symbols[0].1.name, "_text");
        assert_eq!(symbols[1].1.name, "first");
        assert_eq!(symbols[2].1.name, "first");
        assert_eq!(symbols[3].1.name, "second");
        assert_eq!(symbols[3].1.module.as_deref(), Some("[kernel]"));
        assert_eq!(symbols[1].1.address, 0xffff_ffff_8980_0100);
    }

    #[test]
    fn sparse_kernel_symbols_keep_module_symbols_before_text() {
        let kallsyms = b"ffff800001717020 t tls_update [tls]\n\
                         ffff8000081e0000 T _text\n\
                         ffff8000081f0000 t core_symbol\n";
        let symbols =
            parse_sparse_kernel_symbols(kallsyms, &[0xffff_8000_0171_7024, 0xffff_8000_081e_0004]);

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].1.name, "tls_update");
        assert_eq!(symbols[0].1.module.as_deref(), Some("[tls]"));
        assert_eq!(symbols[1].1.name, "_text");
        assert_eq!(symbols[1].1.module, None);
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
    fn streaming_sparse_kernel_symbols_detects_late_unsorted_lines() {
        let kallsyms = b"ffffffff89800000 T _text\n\
                         ffffffff89803000 T late\n\
                         ffffffff89802000 T middle\n";
        let mut reader = io::Cursor::new(kallsyms);
        let symbols =
            parse_sparse_kernel_symbols_sorted_streaming(&mut reader, &[0xffff_ffff_8980_2500])
                .unwrap();

        assert!(symbols.is_none());
        assert_eq!(reader.position() as usize, kallsyms.len());
    }

    #[test]
    fn sparse_kernel_symbols_handle_unsorted_kallsyms() {
        let kallsyms = b"ffffffff89800000 T _text\n\
                         ffffffff89803000 T late\n\
                         ffffffff89802000 T middle\n";
        let symbols = parse_sparse_kernel_symbols(kallsyms, &[0xffff_ffff_8980_2500]);

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].1.name, "middle");
    }
}
