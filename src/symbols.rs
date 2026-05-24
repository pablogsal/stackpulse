//! Native stack frame symbolization.
//!
//! This module provides address-to-symbol resolution for native stack frames.
//! It handles caching and batch symbolization.

use crate::{ModuleImageBase, NativeSymbol, SourceLocation};

#[cfg(target_os = "linux")]
use crate::linux::elf_types::ModuleInfo as LinuxModuleInfo;
#[cfg(target_os = "macos")]
use crate::macos::map_file_readonly;
#[cfg(target_os = "macos")]
use crate::macos::ModuleInfo as MacOSModuleInfo;
#[cfg(target_os = "macos")]
use memmap2::Mmap;
#[cfg(target_os = "macos")]
use object::Object;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};
#[cfg(target_os = "linux")]
use wholesym::CodeId;
#[cfg(target_os = "macos")]
use wholesym::MultiArchDisambiguator;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use wholesym::{
    AddressInfo, LookupAddress, SymbolManager, SymbolManagerConfig, SymbolMap as WholeSymbolMap,
};

use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::collections::{BTreeMap, BTreeSet, HashSet};
#[cfg(target_os = "macos")]
use std::ops::Bound;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Module information for symbolization.
///
/// Each `SymModule` represents a single memory mapping with a mapping-specific
/// `avma_range` and an optional resolved image base.
/// Symbolization computes the address form required by the active backend from
/// that shared image base (`SVMA` on Linux, `Relative` on macOS). Unresolved
/// mappings are skipped.
#[derive(Clone)]
pub struct SymModule {
    pub path: PathBuf,
    pub avma_range: Range<u64>,
    pub image_base: Option<ModuleImageBase>,
    /// Whether this mapping has executable permissions.
    /// Non-executable mappings (data sections) should not be symbolized.
    pub is_executable: bool,
    /// Whether this module is the Python runtime binary/shared library.
    pub is_python_runtime: bool,
}

#[cfg(target_os = "linux")]
impl From<&LinuxModuleInfo> for SymModule {
    fn from(module: &LinuxModuleInfo) -> Self {
        Self {
            path: module.path.clone(),
            avma_range: module.avma_range.clone(),
            image_base: module.image_base,
            is_executable: module.is_executable,
            is_python_runtime: false,
        }
    }
}

#[cfg(target_os = "macos")]
impl From<&MacOSModuleInfo> for SymModule {
    fn from(module: &MacOSModuleInfo) -> Self {
        Self {
            path: module.path.clone(),
            avma_range: module.avma_range.clone(),
            image_base: Some(ModuleImageBase::new(
                module.base_avma,
                module
                    .section_info
                    .as_ref()
                    .map_or(0, |info| info.base_svma),
            )),
            is_executable: true,
            is_python_runtime: false,
        }
    }
}

type SymModuleLayoutKey = (Range<u64>, Option<ModuleImageBase>, bool, bool);

fn sym_module_layout_key(module: &SymModule) -> SymModuleLayoutKey {
    (
        module.avma_range.clone(),
        module.image_base,
        module.is_executable,
        module.is_python_runtime,
    )
}

fn sym_module_layouts_by_path(modules: &[SymModule]) -> HashMap<&Path, Vec<SymModuleLayoutKey>> {
    let mut layouts = HashMap::new();
    for module in modules {
        layouts
            .entry(module.path.as_path())
            .or_insert_with(Vec::new)
            .push(sym_module_layout_key(module));
    }
    layouts
}

#[derive(Clone, Copy)]
struct ModuleAddressIndexEntry {
    start: u64,
    end: u64,
    module_index: usize,
}

fn build_module_address_index(modules: &[SymModule]) -> Box<[ModuleAddressIndexEntry]> {
    let mut index: Vec<_> = modules
        .iter()
        .enumerate()
        .map(|(module_index, module)| ModuleAddressIndexEntry {
            start: module.avma_range.start,
            end: module.avma_range.end,
            module_index,
        })
        .collect();
    index.sort_by_key(|entry| entry.start);
    debug_assert!(
        index.windows(2).all(|w| w[0].end <= w[1].start),
        "module_address_index must be non-overlapping for binary search",
    );
    index.into_boxed_slice()
}

/// Cached symbols - wrapped in Rc for cheap cloning
pub type SymbolsRc = Rc<[NativeSymbol]>;

fn symbols_rc(symbols: Vec<NativeSymbol>) -> SymbolsRc {
    Rc::from(symbols.into_boxed_slice())
}

/// Symbols that indicate the Python eval loop.
///
/// Different symbol sources disagree on whether the leading Mach-O underscore
/// is present, so we accept both spellings.
const EVAL_FRAME_SYMBOLS: &[&str] = &[
    "_PyEval_EvalFrameDefault",
    "PyEval_EvalFrameDefault",
    "PyEval_EvalFrameEx",
];

#[inline]
fn is_eval_frame(func_name: &str) -> bool {
    if EVAL_FRAME_SYMBOLS.iter().any(|sym| func_name.contains(sym)) {
        return true;
    }
    (func_name.starts_with("_TAIL_CALL_") || func_name.starts_with("TAIL_CALL_"))
        && func_name.contains(".llvm.")
}

/// Check if a module path is the Python runtime itself (the `python` binary or
/// `libpythonX.Y.so`), as opposed to extension modules and third-party libs.
#[inline]
fn is_python_runtime_module(module_path: impl AsRef<Path>) -> bool {
    module_path
        .as_ref()
        .file_name()
        .unwrap_or_else(|| module_path.as_ref().as_os_str())
        .to_str()
        .is_some_and(crate::is_python_module)
}

fn mark_python_runtime_modules(modules: &mut [SymModule]) {
    for module in modules {
        module.is_python_runtime = is_python_runtime_module(module.path.as_path());
    }
}

/// Standard system debug directory on Linux.
#[cfg(target_os = "linux")]
const DEFAULT_DEBUG_DIR: &str = "/usr/lib/debug";

/// Parse debug directories from environment.
/// Priority: `STACKPULSE_DEBUG_DIRS` (runtime) > `STACKPULSE_DEFAULT_DEBUG_DIRS` (build-time) > /usr/lib/debug
#[cfg(target_os = "linux")]
fn parse_debug_dirs() -> Vec<PathBuf> {
    let dirs_str = std::env::var("STACKPULSE_DEBUG_DIRS")
        .ok()
        .or_else(|| option_env!("STACKPULSE_DEFAULT_DEBUG_DIRS").map(String::from));

    let dirs: Vec<PathBuf> = match dirs_str {
        Some(s) if !s.is_empty() => s
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
        _ => {
            // Use default system debug directory
            let default_dir = PathBuf::from(DEFAULT_DEBUG_DIR);
            if default_dir.exists() {
                vec![default_dir]
            } else {
                Vec::new()
            }
        }
    };

    if !dirs.is_empty() {
        tracing::trace!(name: "Local debug dirs", "Using {} local debug directories", dirs.len());
    }
    dirs
}

/// Look up a debug file in local .build-id directories.
///
/// Returns a concrete debug file path if one of the configured roots contains
/// a `.build-id/<xx>/<rest>.debug` entry for the build ID.
#[cfg(target_os = "linux")]
fn lookup_local_debug_file(build_id: &str, search_dirs: &[PathBuf]) -> Option<PathBuf> {
    let expected_relative_path = standard_build_id_debug_path(build_id)?;

    tracing::trace!(
        name: "Debug file search",
        "Looking up build-id {} in {} local directories",
        build_id,
        search_dirs.len()
    );

    for base_dir in search_dirs {
        let path = base_dir.join(
            expected_relative_path
                .strip_prefix(DEFAULT_DEBUG_DIR)
                .unwrap_or(&expected_relative_path),
        );
        tracing::trace!(name: "Local debug path", "Trying local debug path: {}", path.display());

        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() && meta.len() > 0 => {
                tracing::trace!(name: "Local debug found", "Found local debug file: {}", path.display());
                return Some(path);
            }
            Ok(meta) if meta.len() == 0 => {
                tracing::trace!(
                    name: "Local debug empty",
                    "Skipping empty debug file: {} (likely stale cache entry)",
                    path.display()
                );
            }
            _ => {}
        }
    }
    tracing::trace!(name: "Local debug not found", "No local debug file found for build-id {}", build_id);
    None
}

#[cfg(target_os = "linux")]
fn standard_build_id_debug_path(build_id: &str) -> Option<PathBuf> {
    if build_id.len() <= 2 {
        return None;
    }
    let (dir_part, file_part) = build_id.split_at(2);
    Some(
        PathBuf::from(DEFAULT_DEBUG_DIR)
            .join(".build-id")
            .join(dir_part)
            .join(format!("{file_part}.debug")),
    )
}

#[cfg(all(target_os = "linux", feature = "debuginfod"))]
fn default_debuginfod_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("STACKPULSE_DEBUGINFOD_CACHE_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(path).join("stackpulse").join("debuginfod");
    }
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path)
            .join(".cache")
            .join("stackpulse")
            .join("debuginfod");
    }
    std::env::temp_dir().join("stackpulse-debuginfod")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn build_symbol_manager_config(
    debug_dirs: &[PathBuf],
    redirect_paths: &[(PathBuf, PathBuf)],
) -> SymbolManagerConfig {
    let mut config = SymbolManagerConfig::new();

    #[cfg(target_os = "linux")]
    {
        for (source, dest) in redirect_paths {
            config = config.redirect_path_for_testing(source.clone(), dest.clone());
        }
        for dir in debug_dirs {
            config = config.extra_symbol_directory(dir.clone());
        }
        #[cfg(feature = "debuginfod")]
        if std::env::var_os("DEBUGINFOD_URLS").is_some() {
            let cache_dir = default_debuginfod_cache_dir();
            config = config
                .use_debuginfod(true)
                .debuginfod_cache_dir_if_not_installed(cache_dir);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = debug_dirs;
        let _ = redirect_paths;
        config = config.use_spotlight(true);
    }

    config
}

#[cfg(target_os = "linux")]
fn discover_linux_debug_file_redirect(
    runtime: &TokioRuntime,
    path: &Path,
    debug_dirs: &[PathBuf],
) -> Option<(PathBuf, PathBuf)> {
    if debug_dirs.is_empty() {
        return None;
    }

    let library_info =
        match runtime.block_on(SymbolManager::library_info_for_binary_at_path(path, None)) {
            Ok(info) => info,
            Err(err) => {
                tracing::trace!(
                    name: "wholesym library info failed",
                    module = %path.display(),
                    error = %err,
                    "Skipping custom debug-dir redirect discovery"
                );
                return None;
            }
        };

    let build_id = linux_build_id_string(&library_info)?;
    let standard_path = standard_build_id_debug_path(&build_id)?;
    let actual_path = lookup_local_debug_file(&build_id, debug_dirs)?;
    (actual_path != standard_path).then_some((standard_path, actual_path))
}

#[cfg(target_os = "linux")]
fn linux_build_id_string(info: &wholesym::LibraryInfo) -> Option<String> {
    match &info.code_id {
        Some(CodeId::ElfBuildId(build_id)) => Some(build_id.to_string()),
        _ => None,
    }
}

/// Wrapper around symbolization with caching.
///
/// Note: NOT thread-safe. Each thread needs its own `SymbolizerWrapper` instance.
pub struct SymbolizerWrapper {
    /// Loaded modules for symbolization
    modules: Vec<SymModule>,

    /// Sorted by `start`, non-overlapping; see `find_module_index`.
    module_address_index: Box<[ModuleAddressIndexEntry]>,

    /// Resolved symbols by address. Only attributed addresses are stored;
    /// every key MUST also appear in `cache_keys_by_path` for its path.
    cache: HashMap<u64, SymbolsRc>,

    /// Per-path index into `cache` for selective eviction on layout change.
    cache_keys_by_path: HashMap<PathBuf, Vec<u64>>,

    /// Whether to include inlined frames
    include_inlines: bool,

    /// Local debug directories for `.build-id` lookup (Linux only).
    #[cfg(target_os = "linux")]
    local_debug_dirs: Box<[PathBuf]>,

    /// Cached redirect mappings keyed by module path (Linux only).
    /// Maps module path -> (standard_debug_path, actual_debug_path).
    #[cfg(target_os = "linux")]
    redirect_cache: HashMap<PathBuf, (PathBuf, PathBuf)>,

    /// Parsed symbol tables (macOS only)
    /// Maps module path -> sorted symbol list
    #[cfg(target_os = "macos")]
    symbol_tables: HashMap<PathBuf, SymbolTable>,

    /// Loaded dyld shared cache mmaps reused across system-library lookups.
    #[cfg(target_os = "macos")]
    dyld_shared_caches: Option<Box<[DyldSharedCacheData]>>,

    /// Shared symbol manager used for symbolization.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    symbol_manager: SymbolManager,

    /// Loaded wholesym maps keyed by module path.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    symbol_maps: HashMap<PathBuf, Option<WholeSymbolMap>>,

    /// Tokio runtime for wholesym async APIs.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    runtime: TokioRuntime,
}

/// A symbol table for a single module (macOS)
#[cfg(target_os = "macos")]
struct SymbolTable {
    /// Sorted list of function ranges in relative-address space.
    symbols: Box<[SymbolEntry]>,
}

#[cfg(target_os = "macos")]
struct SymbolEntry {
    start: u64,
    end: Option<u64>,
    name: String,
}

#[cfg(target_os = "macos")]
struct DyldSharedCacheData {
    path: PathBuf,
    root: Mmap,
    subcaches: Box<[Mmap]>,
}

#[cfg(target_os = "macos")]
impl DyldSharedCacheData {
    fn load(path: PathBuf) -> Option<Self> {
        Some(Self {
            root: map_file_readonly(&path).ok()?,
            subcaches: load_dyld_subcaches(&path),
            path,
        })
    }

    fn load_symbol_table(&self, module_path: &str) -> Option<SymbolTable> {
        let subcaches: Vec<&[u8]> = self.subcaches.iter().map(|mmap| &mmap[..]).collect();
        let cache = object::read::macho::DyldCache::<object::Endianness, _>::parse(
            &self.root[..],
            &subcaches,
        )
        .ok()?;
        let image = cache
            .images()
            .find(|image| image.path() == Ok(module_path))?;
        let object = image.parse_object().ok()?;
        let (data, header_offset) = image.image_data_and_offset().ok()?;
        let image_base = get_image_base(&object);
        let sym_table = build_symbol_table(
            &object,
            image_base,
            MachOData::new(data, header_offset, object.is_64()),
        );
        (!sym_table.symbols.is_empty()).then_some(sym_table)
    }
}

#[cfg(target_os = "macos")]
impl SymbolTable {
    fn new() -> Self {
        Self {
            symbols: Box::default(),
        }
    }

    fn lookup(&self, addr: u64) -> Option<&str> {
        if self.symbols.is_empty() {
            return None;
        }

        match self
            .symbols
            .binary_search_by_key(&addr, |entry| entry.start)
        {
            Ok(idx) => self.symbols[idx]
                .contains(addr)
                .then_some(self.symbols[idx].name.as_str()),
            Err(idx) => {
                if idx > 0 {
                    let entry = &self.symbols[idx - 1];
                    entry.contains(addr).then_some(entry.name.as_str())
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl SymbolEntry {
    fn contains(&self, addr: u64) -> bool {
        match self.end {
            Some(end) => addr >= self.start && addr < end,
            None => addr >= self.start,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct MachOData<'a> {
    data: &'a [u8],
    header_offset: u64,
    is_64: bool,
}

#[cfg(target_os = "macos")]
impl<'a> MachOData<'a> {
    fn new(data: &'a [u8], header_offset: u64, is_64: bool) -> Self {
        Self {
            data,
            header_offset,
            is_64,
        }
    }

    fn get_function_starts(&self) -> Option<Box<[u64]>> {
        let data = self.function_start_data()?;
        let mut function_starts = Vec::new();
        let mut previous = 0u64;
        let mut bytes = data;

        while let Some((delta, rest)) = read_uleb128(bytes) {
            if delta == 0 {
                break;
            }
            previous = previous.checked_add(delta)?;
            function_starts.push(previous);
            bytes = rest;
        }

        Some(function_starts.into_boxed_slice())
    }

    fn function_start_data(&self) -> Option<&'a [u8]> {
        use object::macho::{MachHeader32, MachHeader64};
        use object::read::macho::MachHeader;
        use object::Endianness;

        if self.is_64 {
            let header = MachHeader64::<Endianness>::parse(self.data, self.header_offset).ok()?;
            extract_linkedit_section(header, self.data, self.header_offset)
        } else {
            let header = MachHeader32::<Endianness>::parse(self.data, self.header_offset).ok()?;
            extract_linkedit_section(header, self.data, self.header_offset)
        }
    }
}

#[cfg(target_os = "macos")]
fn extract_linkedit_section<'a, H: object::read::macho::MachHeader>(
    header: &H,
    data: &'a [u8],
    header_offset: u64,
) -> Option<&'a [u8]> {
    use object::macho::{LinkeditDataCommand, LC_FUNCTION_STARTS};

    let endian = header.endian().ok()?;
    let mut commands = header.load_commands(endian, data, header_offset).ok()?;
    while let Ok(Some(command)) = commands.next() {
        if command.cmd() == LC_FUNCTION_STARTS {
            let command: &LinkeditDataCommand<_> = command.data().ok()?;
            let offset: u64 = command.dataoff.get(endian).into();
            let size: u64 = command.datasize.get(endian).into();
            let end = offset.checked_add(size)?;
            return data.get(offset as usize..end as usize);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn read_uleb128(mut bytes: &[u8]) -> Option<(u64, &[u8])> {
    const CONTINUATION_BIT: u8 = 1 << 7;

    let mut result = 0u64;
    let mut shift = 0u32;

    while !bytes.is_empty() {
        let byte = bytes[0];
        bytes = &bytes[1..];
        if shift == 63 && byte != 0x00 && byte != 0x01 {
            return None;
        }

        result |= u64::from(byte & !CONTINUATION_BIT) << shift;
        if byte & CONTINUATION_BIT == 0 {
            return Some((result, bytes));
        }
        shift += 7;
    }

    None
}

/// Extract a short module name from a path (file name, or full path as fallback).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn module_name_rc(path: &Path) -> Rc<str> {
    crate::path_to_name(path).into()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn build_native_symbol(
    name: String,
    source: SourceLocation,
    module: &Rc<str>,
    offset: u64,
    is_python_runtime: bool,
) -> NativeSymbol {
    let name_str: Rc<str> = name.into();
    let module_basename_start = crate::profile::basename_start(module);
    let file_basename_start = source
        .file
        .as_deref()
        .map_or(0, crate::profile::basename_start);
    NativeSymbol {
        is_eval_frame: is_eval_frame(&name_str),
        name: name_str,
        file: source.file,
        line: source.line,
        column: source.column,
        function_start_line: source.function_start_line,
        function_start_column: source.function_start_column,
        module: Rc::clone(module),
        module_basename_start,
        file_basename_start,
        offset,
        should_ignore: is_python_runtime,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn build_native_symbols_from_wholesym(
    addr_info: AddressInfo,
    symbol_map: &WholeSymbolMap,
    module: &Rc<str>,
    module_offset: u64,
    is_python_runtime: bool,
    include_inlines: bool,
) -> Vec<NativeSymbol> {
    let fallback_name = symbol_map
        .resolve_symbol_name(addr_info.symbol.name)
        .into_owned();
    let fallback_symbol = move |source: SourceLocation| {
        build_native_symbol(
            fallback_name.clone(),
            source,
            module,
            module_offset,
            is_python_runtime,
        )
    };

    let frame_capacity = addr_info.frames.as_ref().map_or(1, |frames| {
        if include_inlines {
            frames.len().max(1)
        } else {
            usize::from(!frames.is_empty())
        }
    });
    let mut symbols = Vec::with_capacity(frame_capacity);
    let mut push_frame_symbol = |frame: wholesym::FrameDebugInfo| {
        let file = frame
            .file_path
            .map(|path| symbol_map.resolve_source_file_path(path))
            .map(|path| Rc::<str>::from(path.display_path().into_owned()));
        let source = SourceLocation {
            file,
            line: frame.line_number,
            column: frame.column_number,
            function_start_line: frame.function_start_line,
            function_start_column: frame.function_start_column,
        };
        let symbol = match frame.function {
            Some(function) => build_native_symbol(
                symbol_map.resolve_function_name(function).into_owned(),
                source,
                module,
                module_offset,
                is_python_runtime,
            ),
            None => fallback_symbol(source),
        };
        symbols.push(symbol);
    };

    if let Some(frames) = addr_info.frames {
        let mut frames = frames.into_iter();
        if include_inlines {
            for frame in frames {
                push_frame_symbol(frame);
            }
        } else if let Some(frame) = frames.next() {
            push_frame_symbol(frame);
        }
    }

    if symbols.is_empty() {
        symbols.push(fallback_symbol(SourceLocation::default()));
    }
    symbols
}

impl SymbolizerWrapper {
    /// Create a new symbolizer for the given process.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn new(_pid: u32) -> Self {
        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime for Linux symbolization");
        let local_debug_dirs = parse_debug_dirs();
        let symbol_manager =
            SymbolManager::with_config(build_symbol_manager_config(&local_debug_dirs, &[]));
        let local_debug_dirs = local_debug_dirs.into_boxed_slice();

        Self {
            modules: Vec::new(),
            module_address_index: Box::default(),
            cache: HashMap::new(),
            cache_keys_by_path: HashMap::new(),
            include_inlines: true,
            local_debug_dirs,
            redirect_cache: HashMap::new(),
            symbol_manager,
            symbol_maps: HashMap::new(),
            runtime,
        }
    }

    /// Create a new symbolizer for the given process.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn new(_pid: u32) -> Self {
        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime for macOS symbolization");
        let symbol_manager = SymbolManager::with_config(build_symbol_manager_config(&[], &[]));

        Self {
            modules: Vec::new(),
            module_address_index: Box::default(),
            cache: HashMap::new(),
            cache_keys_by_path: HashMap::new(),
            include_inlines: true,
            symbol_tables: HashMap::new(),
            dyld_shared_caches: None,
            symbol_manager,
            symbol_maps: HashMap::new(),
            runtime,
        }
    }

    /// Enable or disable inline frame expansion
    pub fn set_include_inlines(&mut self, include: bool) {
        if self.include_inlines == include {
            return;
        }
        self.include_inlines = include;
        self.cache.clear();
        self.cache_keys_by_path.clear();
    }

    fn cache_insert(&mut self, addr: u64, path: &Path, value: SymbolsRc) {
        self.cache.insert(addr, value);
        self.cache_keys_by_path
            .entry(path.to_path_buf())
            .or_default()
            .push(addr);
    }

    fn evict_cache_for_path(&mut self, path: &Path) {
        if let Some(keys) = self.cache_keys_by_path.remove(path) {
            for addr in keys {
                self.cache.remove(&addr);
            }
        }
    }

    /// Drop all per-path state for `path`. On Linux, returns `true` when a
    /// debug-file redirect was removed (caller must rebuild `SymbolManager`).
    #[cfg(target_os = "linux")]
    fn evict_path_state(&mut self, path: &Path) -> bool {
        self.evict_cache_for_path(path);
        self.symbol_maps.remove(path);
        self.redirect_cache.remove(path).is_some()
    }

    #[cfg(target_os = "macos")]
    fn evict_path_state(&mut self, path: &Path) {
        self.evict_cache_for_path(path);
        self.symbol_maps.remove(path);
        self.symbol_tables.remove(path);
    }

    /// Set modules for symbolization.
    ///
    /// Diffs old vs new module paths to avoid re-loading symbol maps for
    /// modules that haven't changed. Only evicts entries for removed modules;
    /// Linux debug-file redirects are discovered lazily during symbol loading.
    pub fn set_modules(&mut self, mut modules: Vec<SymModule>) {
        mark_python_runtime_modules(&mut modules);

        let old_layouts = sym_module_layouts_by_path(&self.modules);
        let new_layouts = sym_module_layouts_by_path(&modules);
        let mut evicted: Vec<PathBuf> = Vec::new();
        for (path, old) in &old_layouts {
            match new_layouts.get(*path) {
                None => evicted.push((*path).to_path_buf()),
                Some(new) if new != old => evicted.push((*path).to_path_buf()),
                _ => {}
            }
        }

        #[cfg(target_os = "linux")]
        {
            let mut redirects_evicted = false;
            for path in &evicted {
                redirects_evicted |= self.evict_path_state(path);
            }
            if redirects_evicted {
                self.rebuild_symbol_manager();
            }
        }
        #[cfg(target_os = "macos")]
        for path in &evicted {
            self.evict_path_state(path);
        }

        self.modules = modules;
        self.rebuild_module_address_index();
    }

    pub fn update_modules_for_path(&mut self, path: &Path, mut modules: Box<[SymModule]>) {
        mark_python_runtime_modules(modules.as_mut());

        let unchanged = self
            .modules
            .iter()
            .filter(|module| module.path == path)
            .map(sym_module_layout_key)
            .eq(modules.iter().map(sym_module_layout_key));
        if unchanged {
            return;
        }

        #[cfg(target_os = "linux")]
        if self.evict_path_state(path) {
            self.rebuild_symbol_manager();
        }
        #[cfg(target_os = "macos")]
        self.evict_path_state(path);

        self.modules.retain(|module| module.path != path);
        self.modules.extend(modules.into_vec());
        self.rebuild_module_address_index();
    }

    fn rebuild_module_address_index(&mut self) {
        self.module_address_index = build_module_address_index(&self.modules);
    }

    fn find_module_index(&self, addr: u64, executable_only: bool) -> Option<usize> {
        let idx = self
            .module_address_index
            .partition_point(|entry| entry.start <= addr);
        let entry = self.module_address_index.get(idx.checked_sub(1)?)?;
        if addr >= entry.end {
            return None;
        }
        let module = &self.modules[entry.module_index];
        (!executable_only || module.is_executable).then_some(entry.module_index)
    }

    #[cfg(target_os = "linux")]
    fn rebuild_symbol_manager(&mut self) {
        let all_redirects: Vec<(PathBuf, PathBuf)> =
            self.redirect_cache.values().cloned().collect();
        self.symbol_manager = SymbolManager::with_config(build_symbol_manager_config(
            &self.local_debug_dirs,
            &all_redirects,
        ));
    }

    /// Resolve a batch of instruction addresses to symbol information.
    #[cfg(target_os = "linux")]
    pub fn symbolize_batch(&mut self, addrs: &[u64]) -> Vec<SymbolsRc> {
        if addrs.is_empty() {
            return Vec::new();
        }

        let empty = symbols_rc(Vec::new());
        let mut results: Vec<SymbolsRc> = vec![Rc::clone(&empty); addrs.len()];
        for (idx, &addr) in addrs.iter().enumerate() {
            if let Some(cached) = self.cache.get(&addr) {
                results[idx] = Rc::clone(cached);
                continue;
            }

            let Some(module_idx) = self.find_module_index(addr, true) else {
                continue;
            };
            let module = &self.modules[module_idx];
            let path = module.path.clone();
            let image_base_opt = module.image_base;
            let is_python_runtime = module.is_python_runtime;
            let Some(image_base) = image_base_opt else {
                self.cache_insert(addr, &path, Rc::clone(&empty));
                continue;
            };

            let svma = image_base.svma_for_avma(addr);
            let module_offset = image_base.relative_address(addr);
            let module_rc = module_name_rc(&path);

            let symbols = self
                .symbolize_with_wholesym(
                    &path,
                    LookupAddress::Svma(svma),
                    module_offset,
                    &module_rc,
                    is_python_runtime,
                )
                .unwrap_or_default();

            let symbols_rc = symbols_rc(symbols);
            self.cache_insert(addr, &path, Rc::clone(&symbols_rc));
            results[idx] = symbols_rc;
        }

        results
    }

    /// Resolve a batch of instruction addresses to symbol information.
    #[cfg(target_os = "macos")]
    pub fn symbolize_batch(&mut self, addrs: &[u64]) -> Vec<SymbolsRc> {
        if addrs.is_empty() {
            return Vec::new();
        }

        let empty = symbols_rc(Vec::new());
        let mut results: Vec<SymbolsRc> = vec![Rc::clone(&empty); addrs.len()];

        for (idx, &addr) in addrs.iter().enumerate() {
            if let Some(cached) = self.cache.get(&addr) {
                results[idx] = Rc::clone(cached);
                continue;
            }

            let Some(module_idx) = self.find_module_index(addr, false) else {
                continue;
            };
            let module = &self.modules[module_idx];
            let path = module.path.clone();
            let image_base_opt = module.image_base;
            let is_python_runtime = module.is_python_runtime;
            let Some(image_base) = image_base_opt else {
                self.cache_insert(addr, &path, Rc::clone(&empty));
                continue;
            };

            let relative_addr = image_base.relative_address(addr);
            let module_rc = module_name_rc(&path);

            if !is_macos_system_library(&path) {
                if let Ok(relative_lookup) = u32::try_from(relative_addr) {
                    if let Some(symbols) = self.symbolize_with_wholesym(
                        &path,
                        LookupAddress::Relative(relative_lookup),
                        relative_addr,
                        &module_rc,
                        is_python_runtime,
                    ) {
                        let symbols_rc = symbols_rc(symbols);
                        self.cache_insert(addr, &path, Rc::clone(&symbols_rc));
                        results[idx] = symbols_rc;
                        continue;
                    }
                }
            }

            if !self.symbol_tables.contains_key(&path) {
                let sym_table = self.load_symbol_table_for_module(&path);
                self.symbol_tables.insert(path.clone(), sym_table);
            }

            let mut symbols = Vec::new();
            if let Some(sym_table) = self.symbol_tables.get(&path) {
                if let Some(name) = sym_table.lookup(relative_addr) {
                    let is_eval = is_eval_frame(name);
                    let module_basename_start = crate::profile::basename_start(&module_rc);
                    symbols.push(NativeSymbol {
                        name: name.into(),
                        file: None,
                        line: None,
                        column: None,
                        function_start_line: None,
                        function_start_column: None,
                        module: Rc::clone(&module_rc),
                        module_basename_start,
                        file_basename_start: 0,
                        offset: relative_addr,
                        is_eval_frame: is_eval,
                        should_ignore: is_python_runtime,
                    });
                }
            }

            let symbols_rc = symbols_rc(symbols);
            self.cache_insert(addr, &path, Rc::clone(&symbols_rc));
            results[idx] = symbols_rc;
        }

        results
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn symbolize_with_wholesym(
        &mut self,
        path: &Path,
        lookup_address: LookupAddress,
        module_offset: u64,
        module_rc: &Rc<str>,
        is_python_runtime: bool,
    ) -> Option<Vec<NativeSymbol>> {
        self.ensure_symbol_map_loaded(path);
        let symbol_map = self.symbol_maps.get(path).and_then(|map| map.as_ref())?;
        let addr_info = self.runtime.block_on(symbol_map.lookup(lookup_address))?;
        Some(build_native_symbols_from_wholesym(
            addr_info,
            symbol_map,
            module_rc,
            module_offset,
            is_python_runtime,
            self.include_inlines,
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn ensure_symbol_map_loaded(&mut self, path: &Path) {
        if !self.symbol_maps.contains_key(path) {
            #[cfg(target_os = "linux")]
            self.prefetch_linux_debug_redirects([path]);

            #[cfg(target_os = "macos")]
            let disambiguator = Some(MultiArchDisambiguator::BestMatchForNative);
            #[cfg(target_os = "linux")]
            let disambiguator = None;
            let loaded = self.runtime.block_on(
                self.symbol_manager
                    .load_symbol_map_for_binary_at_path(path, disambiguator),
            );
            if let Err(err) = &loaded {
                tracing::debug!(
                    name: "wholesym load failed",
                    module = %path.display(),
                    error = %err,
                    "wholesym failed to load symbols for module"
                );
            }
            self.symbol_maps.insert(path.to_path_buf(), loaded.ok());
        }
    }

    /// Discover and cache debug-file redirects for `paths` (skipping ones
    /// already cached); rebuild the `SymbolManager` once if anything new.
    #[cfg(target_os = "linux")]
    pub fn prefetch_linux_debug_redirects<P>(&mut self, paths: impl IntoIterator<Item = P>)
    where
        P: AsRef<Path>,
    {
        let mut discovered = false;
        for path in paths {
            let path = path.as_ref();
            if self.redirect_cache.contains_key(path) {
                continue;
            }
            if let Some(redirect) =
                discover_linux_debug_file_redirect(&self.runtime, path, &self.local_debug_dirs)
            {
                self.redirect_cache.insert(path.to_path_buf(), redirect);
                discovered = true;
            }
        }
        if discovered {
            self.rebuild_symbol_manager();
        }
    }

    #[cfg(target_os = "macos")]
    fn dyld_shared_caches(&mut self) -> &[DyldSharedCacheData] {
        let caches = self.dyld_shared_caches.get_or_insert_with(|| {
            dyld_shared_cache_candidate_paths()
                .filter_map(DyldSharedCacheData::load)
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });
        &caches[..]
    }

    #[cfg(target_os = "macos")]
    fn load_symbol_table_for_module(&mut self, module_path: &Path) -> SymbolTable {
        if is_macos_system_library(module_path) {
            if let Some(sym_table) =
                load_symbols_from_dyld_shared_cache(module_path, self.dyld_shared_caches())
            {
                return sym_table;
            }
        }

        load_symbols_from_file(module_path)
    }
}

#[cfg(target_os = "macos")]
fn is_macos_system_library(path: &Path) -> bool {
    let path = path.to_string_lossy();
    path.starts_with("/usr/") || path.starts_with("/System/")
}

#[cfg(target_os = "macos")]
fn dyld_shared_cache_candidate_paths() -> impl Iterator<Item = PathBuf> {
    #[cfg(target_arch = "aarch64")]
    const ARCHES: &[&str] = &["arm64e", "arm64"];
    #[cfg(target_arch = "x86_64")]
    const ARCHES: &[&str] = &["x86_64h", "x86_64"];

    [
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
        "/System/Library/dyld",
    ]
    .into_iter()
    .flat_map(|dir| {
        ARCHES
            .iter()
            .map(move |arch| PathBuf::from(format!("{dir}/dyld_shared_cache_{arch}")))
    })
}

#[cfg(target_os = "macos")]
fn with_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

#[cfg(target_os = "macos")]
fn load_dyld_subcaches(root_path: &Path) -> Box<[Mmap]> {
    let mut subcaches = Vec::with_capacity(8);

    for index in 1.. {
        let plain = with_path_suffix(root_path, &format!(".{index}"));
        let padded = with_path_suffix(root_path, &format!(".{index:02}"));
        if let Some(mmap) = map_file_readonly(&plain)
            .ok()
            .or_else(|| map_file_readonly(&padded).ok())
        {
            subcaches.push(mmap);
        } else {
            break;
        }
    }

    if let Ok(symbols_cache) = map_file_readonly(&with_path_suffix(root_path, ".symbols")) {
        subcaches.push(symbols_cache);
    }

    subcaches.into_boxed_slice()
}

#[cfg(target_os = "macos")]
fn load_symbols_from_dyld_shared_cache(
    module_path: &Path,
    dyld_shared_caches: &[DyldSharedCacheData],
) -> Option<SymbolTable> {
    let module_path = module_path.to_str()?;

    for cache in dyld_shared_caches {
        if let Some(sym_table) = cache.load_symbol_table(module_path) {
            tracing::debug!(
                name: "Symbols loaded",
                module = module_path,
                cache = %cache.path.display(),
                count = sym_table.symbols.len(),
                "Loaded symbols from dyld shared cache"
            );
            return Some(sym_table);
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn insert_symbol_name(symbols: &mut BTreeMap<u64, String>, addr: u64, name: &str) {
    let name = name.strip_prefix('_').unwrap_or(name);
    symbols.entry(addr).or_insert_with(|| name.to_string());
}

#[cfg(target_os = "macos")]
fn next_boundary_after(boundaries: &BTreeSet<u64>, start: u64) -> Option<u64> {
    boundaries
        .range((Bound::Excluded(start), Bound::Unbounded))
        .next()
        .copied()
}

#[cfg(target_os = "macos")]
fn build_symbol_table(
    obj: &object::File<'_>,
    image_base: u64,
    macho_data: MachOData<'_>,
) -> SymbolTable {
    use object::{ObjectSection, ObjectSymbol, SectionFlags, SectionKind, SymbolKind};

    let executable_sections: HashSet<_> = obj
        .sections()
        .filter_map(|section| match (section.kind(), section.flags()) {
            (SectionKind::Text, _) => Some(section.index()),
            (SectionKind::UninitializedData, SectionFlags::Elf { sh_flags })
                if sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0 =>
            {
                Some(section.index())
            }
            _ => None,
        })
        .collect();

    let mut symbols_by_start = BTreeMap::<u64, String>::new();
    let mut boundaries = BTreeSet::<u64>::new();

    for symbol in obj.symbols().chain(obj.dynamic_symbols()) {
        if symbol.address() == 0 {
            continue;
        }
        match symbol.kind() {
            SymbolKind::Text => {}
            SymbolKind::Label if symbol.size() != 0 => {}
            _ => continue,
        }
        if !matches!(symbol.section_index(), Some(idx) if executable_sections.contains(&idx)) {
            continue;
        }

        let Some(start) = symbol.address().checked_sub(image_base) else {
            continue;
        };
        boundaries.insert(start);
        if let Some(end) = start.checked_add(symbol.size()) {
            if symbol.size() != 0 {
                boundaries.insert(end);
            }
        }

        if let Ok(name) = symbol.name() {
            insert_symbol_name(&mut symbols_by_start, start, name);
        }
    }

    if let Ok(exports) = obj.exports() {
        for export in exports {
            let Some(start) = export.address().checked_sub(image_base) else {
                continue;
            };
            boundaries.insert(start);
            let name = String::from_utf8_lossy(export.name());
            insert_symbol_name(&mut symbols_by_start, start, &name);
        }
    }

    if let Some(function_starts) = macho_data.get_function_starts() {
        boundaries.extend(function_starts.iter().copied());
    }

    boundaries.extend(obj.sections().filter_map(|section| {
        (section.kind() == SectionKind::Text)
            .then(|| {
                section
                    .address()
                    .checked_add(section.size())?
                    .checked_sub(image_base)
            })
            .flatten()
    }));

    SymbolTable {
        symbols: symbols_by_start
            .into_iter()
            .map(|(start, name)| SymbolEntry {
                start,
                end: next_boundary_after(&boundaries, start),
                name,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    }
}

/// Load symbols from a file, handling both regular Mach-O and fat (universal) binaries.
#[cfg(target_os = "macos")]
fn load_symbols_from_file(path: &Path) -> SymbolTable {
    use object::{FileKind, Object};

    let mmap = match map_file_readonly(path) {
        Ok(mmap) => mmap,
        Err(e) => {
            tracing::debug!(
                name: "Binary read failed",
                "Failed to read {}: {}",
                path.display(),
                e
            );
            return SymbolTable::new();
        }
    };

    // Detect file kind to handle fat binaries
    let kind = match FileKind::parse(&mmap[..]) {
        Ok(k) => k,
        Err(e) => {
            tracing::debug!(name: "File kind detection failed", "Failed to detect file kind for {}: {}", path.display(), e);
            return SymbolTable::new();
        }
    };

    let obj_data: &[u8] = match kind {
        FileKind::MachOFat32 | FileKind::MachOFat64 => {
            // Fat binary - extract the native architecture slice
            if let Some(slice) = crate::macos::native_macho_slice(&mmap[..]) {
                slice
            } else {
                tracing::debug!(name: "Fat binary arch mismatch", "No matching architecture in fat binary: {}", path.display());
                return SymbolTable::new();
            }
        }
        _ => &mmap[..],
    };

    match object::File::parse(obj_data) {
        Ok(obj) => {
            let image_base = get_image_base(&obj);
            let sym_table =
                build_symbol_table(&obj, image_base, MachOData::new(obj_data, 0, obj.is_64()));
            tracing::debug!(
                name: "Symbols loaded",
                "Loaded {} symbols from {} (image_base=0x{:x})",
                sym_table.symbols.len(),
                path.display(),
                image_base
            );
            for (i, entry) in sym_table.symbols.iter().take(5).enumerate() {
                tracing::trace!(
                    name: "Symbol entry",
                    "  Symbol {}: 0x{:x}-{:?} {}",
                    i,
                    entry.start,
                    entry.end,
                    entry.name
                );
            }
            sym_table
        }
        Err(e) => {
            tracing::debug!(
                name: "Mach-O parse failed",
                "Failed to parse {}: {}",
                path.display(),
                e
            );
            SymbolTable::new()
        }
    }
}

/// Get the image base address for relative address calculation.
/// For Mach-O, this is typically the __TEXT segment's vmaddr.
#[cfg(target_os = "macos")]
fn get_image_base(obj: &object::File<'_>) -> u64 {
    use object::{Object, ObjectSegment};

    // For Mach-O, find the __TEXT segment's vmaddr
    for segment in obj.segments() {
        if let Ok(Some(name)) = segment.name() {
            if name == "__TEXT" {
                return segment.address();
            }
        }
    }

    // Fallback: use 0 (symbols are already absolute)
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_eval_frame_tail_call_variants() {
        assert!(is_eval_frame("_TAIL_CALL_BINARY_OP.llvm.1234567890"));
        assert!(is_eval_frame("TAIL_CALL_CALL.llvm.9000656869750701268"));
        assert!(!is_eval_frame("TAIL_CALL_CALL"));
        assert!(!is_eval_frame("some_function.llvm.123"));
    }

    #[cfg(target_os = "linux")]
    fn test_sym_module_with_range(path: &str, avma_range: Range<u64>) -> SymModule {
        SymModule {
            path: PathBuf::from(path),
            avma_range,
            image_base: Some(ModuleImageBase::new(0, 0)),
            is_executable: true,
            is_python_runtime: false,
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_symbol_table_lookup() {
        let table = SymbolTable {
            symbols: vec![
                SymbolEntry {
                    start: 0x1000,
                    end: Some(0x1800),
                    name: "func_a".to_string(),
                },
                SymbolEntry {
                    start: 0x2000,
                    end: Some(0x2800),
                    name: "func_b".to_string(),
                },
                SymbolEntry {
                    start: 0x3000,
                    end: None,
                    name: "func_c".to_string(),
                },
            ]
            .into_boxed_slice(),
        };

        // Exact match
        assert_eq!(table.lookup(0x1000), Some("func_a"));

        // Within func_a's range
        assert_eq!(table.lookup(0x1500), Some("func_a"));

        // Gap between func_a and func_b should not overreach.
        assert_eq!(table.lookup(0x1900), None);

        // Within func_b's range
        assert_eq!(table.lookup(0x2500), Some("func_b"));

        // Before first symbol
        assert_eq!(table.lookup(0x500), None);

        // After last symbol
        assert_eq!(table.lookup(0x4000), Some("func_c"));
    }

    #[test]
    fn test_build_id_path_construction() {
        // Test the hex encoding and path construction logic used by lookup_local_debug_file
        // Build ID: 00db9c4d7f584f8f622578265ba9abd86723710f (20 bytes)
        let build_id: Vec<u8> = vec![
            0x00, 0xdb, 0x9c, 0x4d, 0x7f, 0x58, 0x4f, 0x8f, 0x62, 0x25, 0x78, 0x26, 0x5b, 0xa9,
            0xab, 0xd8, 0x67, 0x23, 0x71, 0x0f,
        ];

        let hex_id: String = build_id.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex_id, "00db9c4d7f584f8f622578265ba9abd86723710f");

        let (dir_part, file_part) = (&hex_id[..2], &hex_id[2..]);
        assert_eq!(dir_part, "00");
        assert_eq!(file_part, "db9c4d7f584f8f622578265ba9abd86723710f");

        // Verify path construction matches expected .build-id layout
        let base_dir = PathBuf::from("/usr/lib/debug");
        let path = base_dir
            .join(".build-id")
            .join(dir_part)
            .join(format!("{file_part}.debug"));
        assert_eq!(
            path,
            PathBuf::from(
                "/usr/lib/debug/.build-id/00/db9c4d7f584f8f622578265ba9abd86723710f.debug"
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_lookup_local_debug_file_uses_configured_root() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("stackpulse-symbols-{unique}"));
        let debug_root = root.join("custom-debug-root");
        let build_id = "00db9c4d7f584f8f622578265ba9abd86723710f";
        let debug_file = debug_root
            .join(".build-id")
            .join("00")
            .join("db9c4d7f584f8f622578265ba9abd86723710f.debug");

        std::fs::create_dir_all(debug_file.parent().unwrap()).unwrap();
        std::fs::write(&debug_file, b"not-empty").unwrap();

        let found = lookup_local_debug_file(build_id, std::slice::from_ref(&debug_root));
        assert_eq!(found, Some(debug_file.clone()));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_set_modules_evicts_only_changed_paths_from_symbol_cache() {
        let keep = PathBuf::from("/tmp/libkeep.so");
        let removed = PathBuf::from("/tmp/libremoved.so");
        let added = PathBuf::from("/tmp/libadded.so");

        let mut symbolizer = SymbolizerWrapper::new(0);
        symbolizer.local_debug_dirs = Box::default();
        symbolizer.modules = vec![
            test_sym_module_with_range(keep.to_str().unwrap(), 0x1000..0x2000),
            test_sym_module_with_range(removed.to_str().unwrap(), 0x3000..0x4000),
        ];
        let keep_symbol = symbols_rc(vec![build_native_symbol(
            "cached".to_string(),
            SourceLocation::default(),
            &module_name_rc(&keep),
            0,
            false,
        )]);
        symbolizer.cache_insert(0x1234, &keep, keep_symbol);
        symbolizer.cache_insert(0x3456, &removed, symbols_rc(Vec::new()));
        symbolizer.symbol_maps.insert(keep.clone(), None);
        symbolizer.symbol_maps.insert(removed.clone(), None);
        symbolizer.redirect_cache.insert(
            keep.clone(),
            (
                PathBuf::from("/usr/lib/debug/.build-id/aa/keep.debug"),
                PathBuf::from("/tmp/debug/keep.debug"),
            ),
        );
        symbolizer.redirect_cache.insert(
            removed.clone(),
            (
                PathBuf::from("/usr/lib/debug/.build-id/bb/removed.debug"),
                PathBuf::from("/tmp/debug/removed.debug"),
            ),
        );

        symbolizer.set_modules(vec![
            test_sym_module_with_range(keep.to_str().unwrap(), 0x1000..0x2000),
            test_sym_module_with_range(added.to_str().unwrap(), 0x5000..0x6000),
        ]);

        assert!(symbolizer.cache.contains_key(&0x1234));
        assert!(!symbolizer.cache.contains_key(&0x3456));
        assert!(symbolizer.cache_keys_by_path.contains_key(&keep));
        assert!(!symbolizer.cache_keys_by_path.contains_key(&removed));
        assert!(symbolizer.symbol_maps.contains_key(&keep));
        assert!(!symbolizer.symbol_maps.contains_key(&removed));
        assert!(!symbolizer.symbol_maps.contains_key(&added));
        assert!(symbolizer.redirect_cache.contains_key(&keep));
        assert!(!symbolizer.redirect_cache.contains_key(&removed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_update_modules_for_path_evicts_only_that_path_from_symbol_cache() {
        let keep = PathBuf::from("/tmp/libkeep.so");
        let changed = PathBuf::from("/tmp/libchanged.so");
        let mut symbolizer = SymbolizerWrapper::new(0);
        symbolizer.local_debug_dirs = Box::default();
        symbolizer.set_modules(vec![
            test_sym_module_with_range(keep.to_str().unwrap(), 0x1000..0x2000),
            test_sym_module_with_range(changed.to_str().unwrap(), 0x3000..0x4000),
        ]);
        symbolizer.cache_insert(0x1234, &keep, symbols_rc(Vec::new()));
        symbolizer.cache_insert(0x3456, &changed, symbols_rc(Vec::new()));
        symbolizer.symbol_maps.insert(keep.clone(), None);
        symbolizer.symbol_maps.insert(changed.clone(), None);

        symbolizer.update_modules_for_path(
            &changed,
            vec![test_sym_module_with_range(
                changed.to_str().unwrap(),
                0x5000..0x6000,
            )]
            .into_boxed_slice(),
        );

        assert!(symbolizer.cache.contains_key(&0x1234));
        assert!(!symbolizer.cache.contains_key(&0x3456));
        assert!(symbolizer.cache_keys_by_path.contains_key(&keep));
        assert!(!symbolizer.cache_keys_by_path.contains_key(&changed));
        assert!(symbolizer.symbol_maps.contains_key(&keep));
        assert!(!symbolizer.symbol_maps.contains_key(&changed));
        assert_eq!(
            symbolizer.find_module_index(0x5555, true),
            Some(
                symbolizer
                    .modules
                    .iter()
                    .position(|module| module.path == changed)
                    .unwrap()
            )
        );
    }

    // ── is_python_runtime_module tests ──────────────────────────────────

    #[test]
    fn test_python_runtime_libpython_shared_lib() {
        assert!(is_python_runtime_module("/usr/lib/libpython3.13.so.1.0"));
        assert!(is_python_runtime_module("/usr/lib/libpython3.so"));
        assert!(is_python_runtime_module("/usr/lib/libpython3.13.so"));
        assert!(is_python_runtime_module("libpython3.13.so.1.0"));
        assert!(is_python_runtime_module(
            "/opt/python/3.15/lib/libpython3.15.so.1.0"
        ));
    }

    #[test]
    fn test_python_runtime_python_binary() {
        assert!(is_python_runtime_module("/usr/bin/python3"));
        assert!(is_python_runtime_module("/usr/bin/python3.13"));
        assert!(is_python_runtime_module("/usr/bin/python"));
        assert!(is_python_runtime_module("python3"));
        assert!(is_python_runtime_module("python3.15"));
        assert!(is_python_runtime_module("python"));
    }

    #[test]
    fn test_cpython_extensions_not_hidden() {
        // C extensions use the .cpython-XXX convention — these must NOT be hidden
        assert!(!is_python_runtime_module(
            "/usr/lib/python3.13/lib-dynload/_ctypes.cpython-313-aarch64-linux-gnu.so"
        ));
        assert!(!is_python_runtime_module(
            "_multiarray_umath.cpython-315-x86_64-linux-gnu.so"
        ));
        assert!(!is_python_runtime_module(
            "/home/user/.venv/lib/python3.13/site-packages/numpy/core/_multiarray_umath.cpython-313-x86_64-linux-gnu.so"
        ));
        assert!(!is_python_runtime_module(
            "_ssl.cpython-313-x86_64-linux-gnu.so"
        ));
        assert!(!is_python_runtime_module(
            "/usr/lib/python3.13/lib-dynload/_hashlib.cpython-313-aarch64-linux-gnu.so"
        ));
        assert!(!is_python_runtime_module(
            "_blake2.cpython-313-aarch64-linux-gnu.so"
        ));
    }

    #[test]
    fn test_non_python_libraries_not_hidden() {
        assert!(!is_python_runtime_module("/usr/lib/libc.so.6"));
        assert!(!is_python_runtime_module("/usr/lib/libstdc++.so.6"));
        assert!(!is_python_runtime_module("/usr/lib/libm.so.6"));
        assert!(!is_python_runtime_module("/usr/lib/libz.so.1"));
        assert!(!is_python_runtime_module("libc.so.6"));
        assert!(!is_python_runtime_module("/usr/lib/libssl.so.3"));
        assert!(!is_python_runtime_module("/usr/lib/libffi.so.8.2.0"));
        assert!(!is_python_runtime_module("/usr/lib/libpython_embedder.so"));
        assert!(!is_python_runtime_module("/usr/lib/libpython_plugin.so.1"));
    }

    #[test]
    fn test_edge_cases() {
        // Bare module name (no path)
        assert!(is_python_runtime_module("libpython3.13.so"));
        assert!(is_python_runtime_module("python3"));

        // Should not match things that just happen to end with "python"
        assert!(!is_python_runtime_module("/usr/bin/bpython"));
        assert!(!is_python_runtime_module("/usr/bin/ipython"));
        assert!(!is_python_runtime_module("/usr/bin/python3-config"));
        assert!(!is_python_runtime_module("/usr/bin/pythonw"));
        assert!(!is_python_runtime_module("/usr/bin/python311d"));
        assert!(!is_python_runtime_module("python3.13m"));
        assert!(!is_python_runtime_module("python.3"));

        // Empty / weird
        assert!(!is_python_runtime_module(""));
        assert!(!is_python_runtime_module("/"));
    }
}
