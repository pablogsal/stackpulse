use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use memchr::memchr;

use crate::profile::{
    FrameFlags, FrameKind, LocationInfo, NativeFrame, NativeSymbol, PythonFrame, ResolvedFrame,
    SourceLocation, StackFrames, SymbolOrigin,
};
use crate::symbols::{SymModule, SymbolizerWrapper};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::native_module::ElfSectionCache;
use crate::spool::{FrameMode, FrameRecord, ModuleRecord, PerfSpoolReader};

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
    frame_cache: FxHashMap<(i32, FrameRecord), ResolvedFrame>,
    stack_cache: FxHashMap<(i32, u32), StackFrames>,
}

/// Which processes may use Python perf-map lookups.
pub enum PerfMapProcesses {
    /// Allow perf-map lookup for every process.
    All,
    /// Allow perf-map lookup only for the listed process ids.
    Pids(FxHashSet<i32>),
}

#[derive(Clone)]
struct KernelSymbol {
    address: u64,
    name: String,
}

#[derive(Clone)]
enum KernelSymbolTable {
    Full(Arc<[KernelSymbol]>),
    Sparse(Arc<[(u64, KernelSymbol)]>),
}

#[derive(Clone)]
struct PerfMapSymbol {
    start: u64,
    end: u64,
    name: String,
}

struct NativeSymbolizerGroup {
    process_id: i32,
    modules: Vec<SymModule>,
    symbolizer: SymbolizerWrapper,
}

impl PerfSymbolizer {
    /// Create a resolver for the modules in a profile.
    pub fn new(modules: &[ModuleRecord]) -> Self {
        Self::with_perf_maps(modules, true)
    }

    /// Create a resolver and choose whether Python perf-map lookup is allowed.
    pub fn with_perf_maps(modules: &[ModuleRecord], allow_perf_maps: bool) -> Self {
        let perf_map_processes = if allow_perf_maps {
            PerfMapProcesses::All
        } else {
            PerfMapProcesses::Pids(FxHashSet::default())
        };
        Self::with_perf_map_processes_inner(modules, perf_map_processes)
    }

    /// Create a resolver that only uses Python perf maps for selected processes.
    pub fn with_perf_map_processes(
        modules: &[ModuleRecord],
        processes: impl IntoIterator<Item = i32>,
    ) -> Self {
        Self::with_perf_map_processes_inner(
            modules,
            PerfMapProcesses::Pids(processes.into_iter().collect()),
        )
    }

    /// Create a resolver for a loaded spool, using its kernel PCs for sparse kallsyms loading.
    pub fn for_spool(reader: &PerfSpoolReader) -> Self {
        Self::for_spool_with_perf_maps(reader, true)
    }

    /// Create a resolver for a loaded spool and choose whether Python perf maps are allowed.
    pub fn for_spool_with_perf_maps(reader: &PerfSpoolReader, allow_perf_maps: bool) -> Self {
        let perf_map_processes = if allow_perf_maps {
            PerfMapProcesses::All
        } else {
            PerfMapProcesses::Pids(FxHashSet::default())
        };
        let mut symbolizer =
            Self::with_perf_map_processes_inner(reader.modules(), perf_map_processes);
        symbolizer.kernel_symbols =
            Some(load_sparse_kernel_symbols(reader.kernel_frame_addresses()));
        symbolizer
    }

    fn with_perf_map_processes_inner(
        modules: &[ModuleRecord],
        perf_map_processes: PerfMapProcesses,
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
            frame_cache: FxHashMap::default(),
            stack_cache: FxHashMap::default(),
        }
    }

    /// Resolve `frames` for one sample, caching by process and stack id.
    pub fn stack_to_cached_frames(
        &mut self,
        process_id: i32,
        stack_id: u32,
        frames: &[FrameRecord],
    ) -> StackFrames {
        self.stack_refs_to_cached_frames(process_id, stack_id, frames.iter())
    }

    /// Resolve borrowed raw frames for one sample, caching by process and stack id.
    pub fn stack_refs_to_cached_frames<'a>(
        &mut self,
        process_id: i32,
        stack_id: u32,
        frames: impl IntoIterator<Item = &'a FrameRecord>,
    ) -> StackFrames {
        let cache_key = (process_id, stack_id);
        if let Some(frames) = self.stack_cache.get(&cache_key) {
            return Arc::clone(frames);
        }
        let frames = self.stack_refs_to_frames(process_id, frames);
        self.stack_cache.insert(cache_key, Arc::clone(&frames));
        frames
    }

    fn stack_to_frames(&mut self, process_id: i32, sample_frames: &[FrameRecord]) -> StackFrames {
        self.stack_refs_to_frames(process_id, sample_frames.iter())
    }

    fn stack_refs_to_frames<'a>(
        &mut self,
        process_id: i32,
        sample_frames: impl IntoIterator<Item = &'a FrameRecord>,
    ) -> StackFrames {
        let frames = sample_frames
            .into_iter()
            .map(|frame| self.resolve_cached_frame(process_id, frame))
            .collect::<Vec<_>>();
        Arc::from(frames.into_boxed_slice())
    }

    fn resolve_cached_frame(&mut self, process_id: i32, frame: &FrameRecord) -> ResolvedFrame {
        let cache_key = (process_id, *frame);
        if let Some(cached) = self.frame_cache.get(&cache_key) {
            return cached.clone();
        }
        let resolved = self.resolve_frame(process_id, frame);
        self.frame_cache.insert(cache_key, resolved.clone());
        resolved
    }

    fn resolve_frame(&mut self, process_id: i32, frame: &FrameRecord) -> ResolvedFrame {
        let perf_maps_allowed =
            self.perf_maps_allowed_for(process_id) && frame.mode == FrameMode::User;
        let perf_map_frame_allowed =
            perf_maps_allowed && self.perf_map_frame_allowed(process_id, frame);
        if perf_map_frame_allowed {
            if let Some(symbol) = self.resolve_perf_map(process_id, frame.abs_ip).cloned() {
                return perf_map_symbol_to_frame(process_id, frame.abs_ip, &symbol);
            }
        }
        ResolvedFrame::Native(self.resolve_native_frame(process_id, frame))
    }

    fn resolve_native_frame(&mut self, process_id: i32, frame: &FrameRecord) -> NativeFrame {
        let module = self
            .module_for_frame(process_id, frame)
            .map(|(m, rel_ip)| (m.clone(), rel_ip));
        let is_kernel_frame =
            frame.mode == FrameMode::Kernel || module.as_ref().is_some_and(|(m, _)| m.is_kernel);

        match (is_kernel_frame, module) {
            (false, None) => NativeFrame::from_address(frame.abs_ip),
            (true, _) => {
                let symbol_name = self
                    .resolve_kernel(frame.abs_ip)
                    .unwrap_or_else(|| format!("[kernel]+0x{:x}", frame.abs_ip));
                let symbol = NativeSymbol::new(
                    symbol_name,
                    SourceLocation::default(),
                    "[kernel]",
                    frame.abs_ip,
                    false,
                    false,
                );
                NativeFrame {
                    pc: frame.abs_ip,
                    sp: 0,
                    symbol: Some(symbol),
                    is_python_runtime: false,
                    kind: FrameKind::Kernel,
                    origin: SymbolOrigin::KernelSymbols,
                    flags: FrameFlags::empty(),
                }
            }
            (false, Some((module, rel_ip))) => {
                if let Some(symbol) = self.resolve_module_symbol(&module, frame.abs_ip) {
                    let is_python_runtime = symbol.should_ignore;
                    return NativeFrame {
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
                    };
                }

                let is_python_runtime =
                    frame.mode == FrameMode::User && is_python_runtime_module(&module.path);
                let symbol_name = format!("{}+0x{:x}", module_display_name(&module.path), rel_ip);
                let symbol = NativeSymbol::new(
                    symbol_name.clone(),
                    SourceLocation::default(),
                    module.path,
                    rel_ip,
                    is_eval_frame(&symbol_name),
                    is_python_runtime,
                );
                NativeFrame {
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
                }
            }
        }
    }

    fn module_for_frame(
        &self,
        process_id: i32,
        frame: &FrameRecord,
    ) -> Option<(&ModuleRecord, u64)> {
        if let Some(module_id) = frame.module_id {
            return Some((self.modules.get(module_id as usize)?, frame.rel_ip));
        }
        let module = self.modules.iter().rev().find(|m| {
            let owned_by = match frame.mode {
                FrameMode::Kernel => m.is_kernel,
                FrameMode::User => !m.is_kernel && m.process_id == process_id,
            };
            owned_by && m.start <= frame.abs_ip && frame.abs_ip < m.end
        })?;
        Some((
            module,
            frame
                .abs_ip
                .saturating_sub(module.start)
                .saturating_add(module.file_offset),
        ))
    }

    fn resolve_module_symbol(
        &mut self,
        module: &ModuleRecord,
        abs_ip: u64,
    ) -> Option<NativeSymbol> {
        let symbolizer = self.ensure_native_symbolizer_for_module(module)?;
        let symbols_batch = symbolizer.symbolize_batch(&[abs_ip]);
        symbols_batch.into_iter().next()?.first().cloned()
    }

    fn ensure_native_symbolizer_for_module(
        &mut self,
        module: &ModuleRecord,
    ) -> Option<&mut SymbolizerWrapper> {
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
        let mut symbolizer = SymbolizerWrapper::new(module.process_id as u32);
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

    fn resolve_kernel(&mut self, abs_ip: u64) -> Option<String> {
        let symbols = self
            .kernel_symbols
            .get_or_insert_with(load_shared_kernel_symbols);
        let symbol = find_kernel_symbol_in_table(symbols, abs_ip)?;
        Some(format_symbol(
            &symbol.name,
            abs_ip.saturating_sub(symbol.address),
        ))
    }

    fn resolve_perf_map(&mut self, process_id: i32, abs_ip: u64) -> Option<&PerfMapSymbol> {
        let symbols = self
            .perf_map_cache
            .entry(process_id)
            .or_insert_with(|| load_perf_map(process_id))
            .as_ref()?;
        find_perf_map_symbol(symbols, abs_ip)
    }

    fn perf_maps_allowed_for(&self, process_id: i32) -> bool {
        match &self.perf_map_processes {
            PerfMapProcesses::All => true,
            PerfMapProcesses::Pids(processes) => processes.contains(&process_id),
        }
    }

    fn perf_map_frame_allowed(&self, process_id: i32, frame: &FrameRecord) -> bool {
        self.module_for_frame(process_id, frame)
            .is_none_or(|(module, _)| {
                is_python_runtime_module(&module.path) || is_anonymous_module(&module.path)
            })
    }
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
        .rev()
        .find(|s| address < s.end)
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
    let body = name.strip_prefix("py::")?;
    Some(body.rsplit_once(':').unwrap_or((body, "~")))
}

fn is_python_runtime_module(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new(path))
        .to_str()
        .is_some_and(crate::is_python_module)
}

fn is_anonymous_module(path: &str) -> bool {
    path == "[anon]" || path == "//anon" || path.starts_with("[anon:")
}

fn is_eval_frame(name: &str) -> bool {
    name.contains("PyEval_EvalFrameDefault")
        || name.contains("PyEval_EvalFrameEx")
        || ((name.starts_with("_TAIL_CALL_") || name.starts_with("TAIL_CALL_"))
            && name.contains(".llvm."))
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

fn parse_kernel_symbols(data: &[u8]) -> Vec<KernelSymbol> {
    let mut symbols = Vec::new();
    let mut text_addr = None;
    let mut last_address = None;
    let mut sorted = true;

    for (address, name) in KallSymIter::new(data) {
        if text_addr.is_none() && name == b"_text" {
            text_addr = Some(address);
        }
        if text_addr.is_some_and(|anchor| address >= anchor) {
            if last_address.is_some_and(|last| address < last) {
                sorted = false;
            }
            last_address = Some(address);
            symbols.push(KernelSymbol {
                address,
                name: kernel_symbol_name_to_string(name),
            });
        }
    }
    if !sorted {
        symbols.sort_by_key(|s| s.address);
    }
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
    let symbols = load_sparse_kernel_symbols_from_file(&addresses).unwrap_or_default();
    KernelSymbolTable::Sparse(Arc::from(symbols.into_boxed_slice()))
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

fn parse_sparse_kernel_symbols(
    data: &[u8],
    requested_addresses: &[u64],
) -> Vec<(u64, KernelSymbol)> {
    if kernel_symbols_sorted_after_text(data) {
        parse_sparse_kernel_symbols_sorted(data, requested_addresses)
    } else {
        parse_sparse_kernel_symbols_unsorted(data, requested_addresses)
    }
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
        let mut stop = None;
        {
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                if !carry.is_empty() {
                    match scan.process_line(&carry) {
                        SparseScanState::Continue => {}
                        SparseScanState::Done => return Ok(Some(scan.finish())),
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
                match state {
                    SparseScanState::Continue => {}
                    SparseScanState::Done => {
                        stop = Some(true);
                        break;
                    }
                    SparseScanState::Unsorted => {
                        stop = Some(false);
                        break;
                    }
                }
            }
        }
        reader.consume(consumed);
        match stop {
            Some(true) => return Ok(Some(scan.finish())),
            Some(false) => return Ok(None),
            None => {}
        }
    }
}

struct SparseKernelSymbolScan<'a> {
    requested_addresses: &'a [u64],
    result: Vec<(u64, KernelSymbol)>,
    request_idx: usize,
    text_addr: Option<u64>,
    last_address: Option<u64>,
    last_symbol_address: Option<u64>,
    last_symbol_name: Vec<u8>,
}

enum SparseScanState {
    Continue,
    Done,
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
            last_symbol_address: None,
            last_symbol_name: Vec::new(),
        }
    }

    fn process_line(&mut self, line: &[u8]) -> SparseScanState {
        let Some((address, name)) = parse_kernel_symbol_line_bytes(line) else {
            return SparseScanState::Continue;
        };
        if self.text_addr.is_none() {
            if name == b"_text" {
                self.text_addr = Some(address);
            } else {
                return SparseScanState::Continue;
            }
        }
        if self.text_addr.is_some_and(|anchor| address < anchor) {
            return SparseScanState::Continue;
        }
        if self.last_address.is_some_and(|last| address < last) {
            return SparseScanState::Unsorted;
        }
        self.last_address = Some(address);

        while self.request_idx < self.requested_addresses.len()
            && self.requested_addresses[self.request_idx] < address
        {
            if let Some(symbol_address) = self.last_symbol_address {
                self.result.push((
                    self.requested_addresses[self.request_idx],
                    KernelSymbol {
                        address: symbol_address,
                        name: kernel_symbol_name_to_string(&self.last_symbol_name),
                    },
                ));
            }
            self.request_idx += 1;
        }
        if self.request_idx >= self.requested_addresses.len() {
            return SparseScanState::Done;
        }
        if self.last_symbol_address != Some(address) {
            self.last_symbol_address = Some(address);
            self.last_symbol_name.clear();
            self.last_symbol_name.extend_from_slice(name);
        }
        SparseScanState::Continue
    }

    fn finish(mut self) -> Vec<(u64, KernelSymbol)> {
        while self.request_idx < self.requested_addresses.len() {
            if let Some(symbol_address) = self.last_symbol_address {
                self.result.push((
                    self.requested_addresses[self.request_idx],
                    KernelSymbol {
                        address: symbol_address,
                        name: kernel_symbol_name_to_string(&self.last_symbol_name),
                    },
                ));
            }
            self.request_idx += 1;
        }
        self.result
    }
}

fn parse_sparse_kernel_symbols_sorted(
    data: &[u8],
    requested_addresses: &[u64],
) -> Vec<(u64, KernelSymbol)> {
    let mut result = Vec::with_capacity(requested_addresses.len());
    let mut request_idx = 0;
    let mut text_addr = None;
    let mut last_symbol: Option<(u64, &[u8])> = None;

    for (address, name) in KallSymIter::new(data) {
        if text_addr.is_none() {
            if name == b"_text" {
                text_addr = Some(address);
            } else {
                continue;
            }
        }
        if text_addr.is_some_and(|anchor| address < anchor) {
            continue;
        }

        while request_idx < requested_addresses.len() && requested_addresses[request_idx] < address
        {
            if let Some((symbol_address, symbol_name)) = last_symbol {
                result.push((
                    requested_addresses[request_idx],
                    KernelSymbol {
                        address: symbol_address,
                        name: kernel_symbol_name_to_string(symbol_name),
                    },
                ));
            }
            request_idx += 1;
        }
        if request_idx >= requested_addresses.len() {
            break;
        }
        if last_symbol.is_none_or(|(last_address, _)| last_address != address) {
            last_symbol = Some((address, name));
        }
    }

    while request_idx < requested_addresses.len() {
        if let Some((symbol_address, symbol_name)) = last_symbol {
            result.push((
                requested_addresses[request_idx],
                KernelSymbol {
                    address: symbol_address,
                    name: kernel_symbol_name_to_string(symbol_name),
                },
            ));
        }
        request_idx += 1;
    }

    result
}

fn kernel_symbols_sorted_after_text(data: &[u8]) -> bool {
    let mut text_addr = None;
    let mut last_address = None;
    for (address, name) in KallSymIter::new(data) {
        if text_addr.is_none() && name == b"_text" {
            text_addr = Some(address);
        }
        if text_addr.is_some_and(|anchor| address >= anchor) {
            if last_address.is_some_and(|last| address < last) {
                return false;
            }
            last_address = Some(address);
        }
    }
    true
}

fn parse_kernel_symbol_line_bytes(line: &[u8]) -> Option<(u64, &[u8])> {
    let (address, address_len) = parse_hex_u64(line)?;
    let name_start = address_len.checked_add(3)?;
    let name_and_rest = line.get(name_start..)?;
    let line_len = memchr(b'\n', name_and_rest).unwrap_or(name_and_rest.len());
    let line = &name_and_rest[..line_len];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    Some((address, kernel_symbol_name_without_module(line)))
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
    type Item = (u64, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let line_len = memchr(b'\n', self.remaining)
            .map(|idx| idx + 1)
            .unwrap_or(self.remaining.len());
        let line = &self.remaining[..line_len];
        self.remaining = self.remaining.get(line_len..).unwrap_or_default();
        let (address, name) = parse_kernel_symbol_line_bytes(line)?;
        Some((address, name))
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

fn kernel_symbol_name_without_module(name: &[u8]) -> &[u8] {
    memchr(b' ', name).map_or(name, |idx| &name[..idx])
}

fn kernel_symbol_name_to_string(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn load_shared_kernel_symbols() -> KernelSymbolTable {
    static KERNEL_SYMBOLS: OnceLock<Arc<[KernelSymbol]>> = OnceLock::new();
    KernelSymbolTable::Full(Arc::clone(KERNEL_SYMBOLS.get_or_init(|| {
        Arc::from(load_kernel_symbols().unwrap_or_default().into_boxed_slice())
    })))
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
    Some(PerfMapSymbol {
        start,
        end: start.saturating_add(len),
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let first = symbolizer.resolve_cached_frame(process_id, &frame);
        let second = symbolizer.resolve_cached_frame(process_id, &frame);
        let _ = fs::remove_file(&path);

        assert_eq!(symbolizer.frame_cache.len(), 1);
        assert_eq!(first.func_name(), second.func_name());
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

        let resolved = symbolizer.resolve_native_frame(1, &frame);

        assert_eq!(resolved.kind, FrameKind::Kernel);
        assert_eq!(resolved.origin, SymbolOrigin::KernelSymbols);
        let symbol = resolved.symbol.expect("kernel fallback symbol");
        assert_eq!(symbol.name.as_ref(), "[kernel]+0xffffffff80001234");
        assert_eq!(symbol.module.as_ref(), "[kernel]");
    }

    #[test]
    fn parses_kernel_symbol_lines() {
        let mut iter = KallSymIter::new(
            b"ffffffff89800000 T _text\nffffffff89800137 t syscall_return [kernel]\n",
        );

        assert_eq!(
            iter.next(),
            Some((0xffff_ffff_8980_0000, b"_text".as_slice()))
        );
        assert_eq!(
            iter.next(),
            Some((0xffff_ffff_8980_0137, b"syscall_return".as_slice()))
        );
        assert_eq!(KallSymIter::new(b"not-an-address T broken\n").next(), None);
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
        assert_eq!(symbols[1].1.address, 0xffff_ffff_8980_0100);
    }

    #[test]
    fn streaming_sparse_kernel_symbols_stop_after_requested_addresses() {
        let kallsyms = b"ffffffff89800000 T _text\n\
                         ffffffff89800100 T first\n\
                         ffffffff89800200 t second [kernel]\n\
                         ffffffff89800300 T late\n\
                         ffffffff89800400 T very_late\n";
        let mut reader = io::Cursor::new(kallsyms);
        let symbols = parse_sparse_kernel_symbols_sorted_streaming(
            &mut reader,
            &[0xffff_ffff_8980_0101, 0xffff_ffff_8980_0204],
        )
        .unwrap()
        .unwrap();

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].1.name, "first");
        assert_eq!(symbols[1].1.name, "second");
        assert!((reader.position() as usize) < kallsyms.len());
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
