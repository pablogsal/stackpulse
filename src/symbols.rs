//! Native stack frame symbolization.
//!
//! This module provides address-to-symbol resolution for native stack frames.
//! It handles caching and batch symbolization.

use crate::{ModuleImageBase, NativeSymbol, SourceLocation};

#[cfg(target_os = "linux")]
use crate::linux::elf_types::ModuleInfo as LinuxModuleInfo;
#[cfg(target_os = "linux")]
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};
#[cfg(target_os = "linux")]
use wholesym::CodeId;
#[cfg(target_os = "linux")]
use wholesym::{
    FramesLookupResult, LookupAddress, SymbolManager, SymbolManagerConfig,
    SymbolMap as WholeSymbolMap,
};

use std::collections::HashMap;
use std::ops::Range;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
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
    /// On-disk path of the mapped object file (ELF on Linux, Mach-O on macOS).
    pub path: PathBuf,
    /// Absolute virtual memory address range this mapping occupies in the
    /// target process. Both endpoints are process-absolute, not file offsets.
    pub avma_range: Range<u64>,
    /// Image-base anchor used to translate sampled instruction pointers into
    /// the address form expected by the symbol backend. `None` means the
    /// image base could not be resolved and the mapping must be skipped.
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(unix)]
fn file_identity(path: &Path) -> Option<FileIdentity> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.size(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

fn module_file_identities(modules: &[SymModule]) -> HashMap<PathBuf, Option<FileIdentity>> {
    let mut identities = HashMap::new();
    for module in modules {
        identities
            .entry(module.path.clone())
            .or_insert_with(|| file_identity(&module.path));
    }
    identities
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

/// Plug-in interface for native (ELF/Mach-O) module symbolization.
///
/// `PerfSymbolizer` owns kernel-frame resolution (via `/proc/kallsyms`) and
/// JIT/Python perf-map resolution (via `/tmp/perf-PID.map`). Native module
/// symbolization is delegated to an implementor of this trait, allowing
/// callers (e.g. Chronon) to supply their own debug-info/debuginfod policy
/// instead of stackpulse's bundled wholesym-backed `SymbolizerWrapper`.
///
/// One implementor is created per non-overlapping process module group via
/// the factory passed to [`crate::PerfSymbolizer::with_native_factory`].
/// Implementors keep their own per-module symbol-map cache; stackpulse calls
/// `set_modules` whenever the module set changes and `symbolize_one` for
/// each native frame address.
pub trait NativeSymbolizer {
    /// Replace the module set this symbolizer should resolve against.
    /// Implementors should invalidate per-module caches for paths no longer
    /// present and reuse caches for paths that are unchanged.
    fn set_modules(&mut self, modules: Vec<SymModule>);

    /// Resolve a single absolute instruction pointer to zero or more symbols
    /// (multiple symbols when inline frames are expanded; innermost first).
    /// Returns an empty slice when the address is not attributable.
    fn symbolize_one(&mut self, addr: u64) -> SymbolsRc;
}

#[cfg(target_os = "linux")]
impl NativeSymbolizer for SymbolizerWrapper {
    fn set_modules(&mut self, modules: Vec<SymModule>) {
        SymbolizerWrapper::set_modules(self, modules);
    }

    fn symbolize_one(&mut self, addr: u64) -> SymbolsRc {
        SymbolizerWrapper::symbolize_one(self, addr)
    }
}

/// Factory that produces a [`NativeSymbolizer`] for a given process id.
/// `PerfSymbolizer` calls this once per non-overlapping module group.
pub type NativeSymbolizerFactory = Box<dyn FnMut(i32) -> Box<dyn NativeSymbolizer>>;

/// Default factory: returns stackpulse's bundled wholesym-backed
/// `SymbolizerWrapper`, configured from `STACKPULSE_*` env vars.
#[cfg(target_os = "linux")]
#[must_use]
pub fn default_native_symbolizer_factory() -> NativeSymbolizerFactory {
    Box::new(|pid: i32| -> Box<dyn NativeSymbolizer> {
        Box::new(SymbolizerWrapper::new(pid as u32))
    })
}

/// Symbols that indicate the Python eval loop.
const EVAL_FRAME_SYMBOLS: &[&str] = &["PyEval_EvalFrameDefault", "PyEval_EvalFrameEx"];

#[inline]
pub(crate) fn is_eval_frame(func_name: &str) -> bool {
    if EVAL_FRAME_SYMBOLS.iter().any(|sym| func_name.contains(sym)) {
        return true;
    }
    (func_name.starts_with("_TAIL_CALL_") || func_name.starts_with("TAIL_CALL_"))
        && func_name.contains(".llvm.")
}

fn mark_python_runtime_modules(modules: &mut [SymModule]) {
    for module in modules {
        module.is_python_runtime = crate::is_python_runtime_module_path(&module.path);
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

#[cfg(target_os = "linux")]
fn build_symbol_manager_config(
    debug_dirs: &[PathBuf],
    redirect_paths: &[(PathBuf, PathBuf)],
) -> SymbolManagerConfig {
    let mut config = SymbolManagerConfig::new();

    for (source, dest) in redirect_paths {
        config = config.redirect_path_for_testing(source.clone(), dest.clone());
    }
    for dir in debug_dirs {
        config = config.extra_symbols_directory(dir.clone());
    }
    #[cfg(feature = "debuginfod")]
    if std::env::var_os("DEBUGINFOD_URLS").is_some() {
        let cache_dir = default_debuginfod_cache_dir();
        config = config
            .use_debuginfod(true)
            .debuginfod_cache_dir_if_not_installed(cache_dir);
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

    let library_info = match block_on_runtime(
        runtime,
        SymbolManager::library_info_for_binary_at_path(path, None),
    ) {
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

    /// File identities captured when module state was installed.
    module_file_identities: HashMap<PathBuf, Option<FileIdentity>>,

    /// Sorted by `start`, non-overlapping; see `find_module_index`.
    module_address_index: Box<[ModuleAddressIndexEntry]>,

    /// Resolved symbols by address. Only attributed addresses are stored;
    /// every key MUST also appear in `cache_keys_by_path` for its path.
    cache: HashMap<u64, SymbolsRc>,

    /// Per-path index into `cache` for selective eviction on layout change.
    cache_keys_by_path: HashMap<PathBuf, Vec<u64>>,

    /// Local debug directories for `.build-id` lookup (Linux only).
    #[cfg(target_os = "linux")]
    local_debug_dirs: Box<[PathBuf]>,

    /// Cached redirect mappings keyed by module path (Linux only).
    /// Maps module path -> (standard_debug_path, actual_debug_path).
    #[cfg(target_os = "linux")]
    redirect_cache: HashMap<PathBuf, (PathBuf, PathBuf)>,

    /// Shared symbol manager used for symbolization.
    #[cfg(target_os = "linux")]
    symbol_manager: SymbolManager,

    /// Loaded wholesym maps keyed by module path.
    #[cfg(target_os = "linux")]
    symbol_maps: HashMap<PathBuf, Option<WholeSymbolMap>>,

    /// Tokio runtime for wholesym async APIs. Wrapped so Drop can hand it to
    /// `shutdown_background`, which is safe even inside another tokio runtime
    /// (a plain runtime drop there panics mid-unwind and aborts the process).
    #[cfg(target_os = "linux")]
    runtime: std::mem::ManuallyDrop<TokioRuntime>,
}

#[cfg(target_os = "linux")]
impl Drop for SymbolizerWrapper {
    fn drop(&mut self) {
        let runtime = unsafe { std::mem::ManuallyDrop::take(&mut self.runtime) };
        runtime.shutdown_background();
    }
}

/// Run `future` on `runtime` from any thread. `Runtime::block_on` panics when
/// the calling thread is already driving a tokio runtime (e.g. a consumer
/// symbolizing from inside an async task); in that case run the blocking wait
/// on a temporary OS thread instead.
#[cfg(target_os = "linux")]
fn block_on_runtime<F>(runtime: &TokioRuntime, future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    if tokio::runtime::Handle::try_current().is_err() {
        return runtime.block_on(future);
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| runtime.block_on(future))
            .join()
            .expect("symbolization future panicked")
    })
}

/// Extract a short module name from a path (file name, or full path as fallback).
#[cfg(target_os = "linux")]
fn module_name_rc(path: &Path) -> Rc<str> {
    crate::path_to_name(path).into()
}

#[cfg(target_os = "linux")]
fn build_native_symbol(
    name: String,
    source: SourceLocation,
    module: &Rc<str>,
    offset: u64,
    is_python_runtime: bool,
) -> NativeSymbol {
    let name_str: Rc<str> = name.into();
    let module_basename_start = crate::profile::basename_start(module);
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
        offset,
        inline_depth: 0,
        should_ignore: is_python_runtime,
    }
}

#[cfg(target_os = "linux")]
#[inline]
fn inline_depth_for_frame(frame_count: usize, index: usize) -> u16 {
    u16::try_from(frame_count.saturating_sub(index + 1)).unwrap_or(u16::MAX)
}

#[cfg(target_os = "linux")]
fn build_native_symbols_from_wholesym_parts(
    symbol_name: String,
    frames: Option<Vec<wholesym::FrameDebugInfo>>,
    module: &Rc<str>,
    function_offset: u64,
    is_python_runtime: bool,
) -> Vec<NativeSymbol> {
    let fallback_name = symbol_name;
    let fallback_symbol = move |source: SourceLocation| {
        build_native_symbol(
            fallback_name.clone(),
            source,
            module,
            function_offset,
            is_python_runtime,
        )
    };

    let frame_capacity = frames.as_ref().map_or(1, |frames| frames.len().max(1));
    let mut symbols = Vec::with_capacity(frame_capacity);
    let mut push_frame_symbol = |frame: wholesym::FrameDebugInfo, inline_depth| {
        let file = frame
            .file_path
            .map(|path| Rc::<str>::from(path.display_path()));
        let source = SourceLocation {
            file,
            line: frame.line_number,
            column: None,
            function_start_line: None,
            function_start_column: None,
        };
        let symbol = match frame.function {
            Some(function) => {
                build_native_symbol(function, source, module, function_offset, is_python_runtime)
            }
            None => fallback_symbol(source),
        };
        let mut symbol = symbol;
        symbol.inline_depth = inline_depth;
        symbols.push(symbol);
    };

    if let Some(frames) = frames {
        let frame_count = frames.len();
        for (index, frame) in frames.into_iter().enumerate() {
            let inline_depth = inline_depth_for_frame(frame_count, index);
            push_frame_symbol(frame, inline_depth);
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
            module_file_identities: HashMap::new(),
            module_address_index: Box::default(),
            cache: HashMap::new(),
            cache_keys_by_path: HashMap::new(),
            local_debug_dirs,
            redirect_cache: HashMap::new(),
            symbol_manager,
            symbol_maps: HashMap::new(),
            runtime: std::mem::ManuallyDrop::new(runtime),
        }
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

    /// Set modules for symbolization.
    ///
    /// Diffs old vs new module paths to avoid re-loading symbol maps for
    /// modules that haven't changed. Only evicts entries for removed modules;
    /// Linux debug-file redirects are discovered lazily during symbol loading.
    pub fn set_modules(&mut self, mut modules: Vec<SymModule>) {
        mark_python_runtime_modules(&mut modules);

        let old_layouts = sym_module_layouts_by_path(&self.modules);
        let new_layouts = sym_module_layouts_by_path(&modules);
        let new_file_identities = module_file_identities(&modules);
        let mut evicted: Vec<PathBuf> = Vec::new();
        for (path, old) in &old_layouts {
            match new_layouts.get(*path) {
                None => evicted.push((*path).to_path_buf()),
                Some(new) if new != old => evicted.push((*path).to_path_buf()),
                Some(_) => {
                    let old_identity = self
                        .module_file_identities
                        .get(*path)
                        .copied()
                        .unwrap_or(None);
                    let new_identity = new_file_identities.get(*path).copied().unwrap_or(None);
                    if old_identity != new_identity {
                        evicted.push((*path).to_path_buf());
                    }
                }
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

        self.modules = modules;
        self.module_file_identities = new_file_identities;
        self.rebuild_module_address_index();
    }

    #[cfg(test)]
    pub fn update_modules_for_path(&mut self, path: &Path, mut modules: Box<[SymModule]>) {
        mark_python_runtime_modules(modules.as_mut());

        let old_identity = self
            .module_file_identities
            .get(path)
            .copied()
            .unwrap_or(None);
        let new_identity = file_identity(path);
        let unchanged = self
            .modules
            .iter()
            .filter(|module| module.path == path)
            .map(sym_module_layout_key)
            .eq(modules.iter().map(sym_module_layout_key))
            && old_identity == new_identity;
        if unchanged {
            return;
        }

        #[cfg(target_os = "linux")]
        if self.evict_path_state(path) {
            self.rebuild_symbol_manager();
        }

        self.modules.retain(|module| module.path != path);
        self.modules.extend(modules.into_vec());
        if self.modules.iter().any(|module| module.path == path) {
            self.module_file_identities
                .insert(path.to_path_buf(), new_identity);
        } else {
            self.module_file_identities.remove(path);
        }
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

    /// Resolve one instruction address to symbol information.
    #[cfg(target_os = "linux")]
    pub fn symbolize_one(&mut self, addr: u64) -> SymbolsRc {
        if let Some(cached) = self.cache.get(&addr) {
            return Rc::clone(cached);
        }

        let empty = symbols_rc(Vec::new());
        let Some(module_idx) = self.find_module_index(addr, true) else {
            return empty;
        };
        let module = &self.modules[module_idx];
        let path = module.path.clone();
        let image_base_opt = module.image_base;
        let is_python_runtime = module.is_python_runtime;
        let Some(image_base) = image_base_opt else {
            self.cache_insert(addr, &path, Rc::clone(&empty));
            return empty;
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
        symbols_rc
    }

    #[cfg(target_os = "linux")]
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
        let addr_info = symbol_map.lookup_sync(lookup_address)?;
        let frames = match addr_info.frames {
            Some(FramesLookupResult::Available(frames)) => Some(frames),
            Some(FramesLookupResult::External(external)) => {
                block_on_runtime(&self.runtime, symbol_map.lookup_external(&external))
            }
            None => None,
        };
        // symbol.address is the function start in the same relative space as
        // module_offset, so this is the documented within-function offset.
        let function_offset = module_offset.saturating_sub(u64::from(addr_info.symbol.address));
        Some(build_native_symbols_from_wholesym_parts(
            addr_info.symbol.name,
            frames,
            module_rc,
            function_offset,
            is_python_runtime,
        ))
    }

    #[cfg(target_os = "linux")]
    fn ensure_symbol_map_loaded(&mut self, path: &Path) {
        if !self.symbol_maps.contains_key(path) {
            self.prefetch_linux_debug_redirects([path]);

            let disambiguator = None;
            let loaded = block_on_runtime(
                &self.runtime,
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
    fn prefetch_linux_debug_redirects<P>(&mut self, paths: impl IntoIterator<Item = P>)
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
    #[test]
    fn test_inline_depth_for_innermost_first_frames() {
        assert_eq!(inline_depth_for_frame(3, 0), 2);
        assert_eq!(inline_depth_for_frame(3, 1), 1);
        assert_eq!(inline_depth_for_frame(3, 2), 0);
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
    fn test_set_modules_evicts_same_path_when_file_identity_changes() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("stackpulse-symbol-cache-{unique}"));
        let path = root.join("libchanged.so");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&path, b"old").unwrap();

        let mut symbolizer = SymbolizerWrapper::new(0);
        symbolizer.local_debug_dirs = Box::default();
        let module = test_sym_module_with_range(path.to_str().unwrap(), 0x1000..0x2000);
        symbolizer.set_modules(vec![module.clone()]);
        symbolizer.cache_insert(0x1234, &path, symbols_rc(Vec::new()));
        symbolizer.symbol_maps.insert(path.clone(), None);

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"new").unwrap();

        symbolizer.set_modules(vec![module]);

        assert!(!symbolizer.cache.contains_key(&0x1234));
        assert!(!symbolizer.cache_keys_by_path.contains_key(&path));
        assert!(!symbolizer.symbol_maps.contains_key(&path));

        std::fs::remove_dir_all(root).unwrap();
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

    // ── is_python_runtime_module_path tests ─────────────────────────────

    #[test]
    fn test_python_runtime_libpython_shared_lib() {
        assert!(crate::is_python_runtime_module_path(
            "/usr/lib/libpython3.13.so.1.0"
        ));
        assert!(crate::is_python_runtime_module_path(
            "/usr/lib/libpython3.so"
        ));
        assert!(crate::is_python_runtime_module_path(
            "/usr/lib/libpython3.13.so"
        ));
        assert!(crate::is_python_runtime_module_path("libpython3.13.so.1.0"));
        assert!(crate::is_python_runtime_module_path(
            "/opt/python/3.15/lib/libpython3.15.so.1.0"
        ));
    }

    #[test]
    fn test_python_runtime_python_binary() {
        assert!(crate::is_python_runtime_module_path("/usr/bin/python3"));
        assert!(crate::is_python_runtime_module_path("/usr/bin/python3.13"));
        assert!(crate::is_python_runtime_module_path("/usr/bin/python"));
        assert!(crate::is_python_runtime_module_path("python3"));
        assert!(crate::is_python_runtime_module_path("python3.15"));
        assert!(crate::is_python_runtime_module_path("python"));
    }

    #[test]
    fn test_cpython_extensions_not_hidden() {
        // C extensions use the .cpython-XXX convention; these must NOT be hidden
        assert!(!crate::is_python_runtime_module_path(
            "/usr/lib/python3.13/lib-dynload/_ctypes.cpython-313-aarch64-linux-gnu.so"
        ));
        assert!(!crate::is_python_runtime_module_path(
            "_multiarray_umath.cpython-315-x86_64-linux-gnu.so"
        ));
        assert!(!crate::is_python_runtime_module_path(
            "/home/user/.venv/lib/python3.13/site-packages/numpy/core/_multiarray_umath.cpython-313-x86_64-linux-gnu.so"
        ));
        assert!(!crate::is_python_runtime_module_path(
            "_ssl.cpython-313-x86_64-linux-gnu.so"
        ));
        assert!(!crate::is_python_runtime_module_path(
            "/usr/lib/python3.13/lib-dynload/_hashlib.cpython-313-aarch64-linux-gnu.so"
        ));
        assert!(!crate::is_python_runtime_module_path(
            "_blake2.cpython-313-aarch64-linux-gnu.so"
        ));
    }

    #[test]
    fn test_non_python_libraries_not_hidden() {
        assert!(!crate::is_python_runtime_module_path("/usr/lib/libc.so.6"));
        assert!(!crate::is_python_runtime_module_path(
            "/usr/lib/libstdc++.so.6"
        ));
        assert!(!crate::is_python_runtime_module_path("/usr/lib/libm.so.6"));
        assert!(!crate::is_python_runtime_module_path("/usr/lib/libz.so.1"));
        assert!(!crate::is_python_runtime_module_path("libc.so.6"));
        assert!(!crate::is_python_runtime_module_path(
            "/usr/lib/libssl.so.3"
        ));
        assert!(!crate::is_python_runtime_module_path(
            "/usr/lib/libffi.so.8.2.0"
        ));
        assert!(!crate::is_python_runtime_module_path(
            "/usr/lib/libpython_embedder.so"
        ));
        assert!(!crate::is_python_runtime_module_path(
            "/usr/lib/libpython_plugin.so.1"
        ));
    }

    #[test]
    fn test_edge_cases() {
        // Bare module name (no path)
        assert!(crate::is_python_runtime_module_path("libpython3.13.so"));
        assert!(crate::is_python_runtime_module_path("python3"));

        // Should not match things that just happen to end with "python"
        assert!(!crate::is_python_runtime_module_path("/usr/bin/bpython"));
        assert!(!crate::is_python_runtime_module_path("/usr/bin/ipython"));
        assert!(!crate::is_python_runtime_module_path(
            "/usr/bin/python3-config"
        ));
        assert!(!crate::is_python_runtime_module_path("/usr/bin/pythonw"));
        assert!(!crate::is_python_runtime_module_path("/usr/bin/python311d"));
        assert!(!crate::is_python_runtime_module_path("python3.13m"));
        assert!(!crate::is_python_runtime_module_path("python.3"));

        // Empty / weird
        assert!(!crate::is_python_runtime_module_path(""));
        assert!(!crate::is_python_runtime_module_path("/"));
    }
}
