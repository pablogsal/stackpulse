//! Native address-to-symbol resolution.

use crate::module_base::ModuleImageBase;
use crate::profile::NativeSymbol;
#[cfg(feature = "builtin-wholesym")]
use crate::profile::SourceLocation;

#[cfg(feature = "builtin-wholesym")]
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};
#[cfg(feature = "builtin-wholesym")]
use wholesym::CodeId;
#[cfg(feature = "builtin-wholesym")]
use wholesym::{
    FramesLookupResult, LookupAddress, SymbolManager, SymbolManagerConfig,
    SymbolMap as WholeSymbolMap,
};

#[cfg(feature = "builtin-wholesym")]
use std::cell::RefCell;
#[cfg(feature = "builtin-wholesym")]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Module information for symbolization.
#[derive(Clone, Debug)]
pub struct NativeModule(Rc<NativeModuleData>);

#[derive(Debug)]
pub(crate) struct NativeModuleData {
    pub(crate) path: PathBuf,
    pub(crate) image_base: ModuleImageBase,
    pub(crate) is_python_runtime: bool,
    pub(crate) file_identity: NativeFileIdentity,
    pub(crate) mapping_id: u32,
}

/// Stable recorded identity for a native image.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NativeFileIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    inode_generation: u64,
}

impl NativeModule {
    pub(crate) fn new(
        path: PathBuf,
        image_base: ModuleImageBase,
        is_python_runtime: bool,
        file_identity: NativeFileIdentity,
        mapping_id: u32,
    ) -> Self {
        Self(Rc::new(NativeModuleData {
            path,
            image_base,
            is_python_runtime,
            file_identity,
            mapping_id,
        }))
    }
}

impl NativeModule {
    /// Return the mapped object's recorded path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0.path
    }

    /// Return whether this image is the Python runtime.
    #[must_use]
    pub fn is_python_runtime(&self) -> bool {
        self.0.is_python_runtime
    }

    pub(crate) fn image_base(&self) -> ModuleImageBase {
        self.0.image_base
    }

    /// Return the recorded filesystem identity.
    #[must_use]
    pub fn file_identity(&self) -> NativeFileIdentity {
        self.0.file_identity
    }

    /// Return the spool-local mapping generation identifier.
    #[must_use]
    pub fn mapping_id(&self) -> u32 {
        self.0.mapping_id
    }
}

impl NativeFileIdentity {
    pub(crate) const fn new(
        device_major: u32,
        device_minor: u32,
        inode: u64,
        inode_generation: u64,
    ) -> Self {
        Self {
            device_major,
            device_minor,
            inode,
            inode_generation,
        }
    }

    /// Return the recorded device major number.
    #[must_use]
    pub const fn device_major(self) -> u32 {
        self.device_major
    }

    /// Return the recorded device minor number.
    #[must_use]
    pub const fn device_minor(self) -> u32 {
        self.device_minor
    }

    /// Return the recorded inode.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }

    /// Return the recorded inode generation.
    #[must_use]
    pub const fn inode_generation(self) -> u64 {
        self.inode_generation
    }
}

/// One exact native lookup selected by StackPulse.
#[derive(Clone, Debug)]
pub struct NativeLookup {
    pub(crate) process_id: crate::Pid,
    pub(crate) module: NativeModule,
    pub(crate) absolute_address: u64,
    pub(crate) relative_address: u64,
    pub(crate) image_address: u64,
}

impl NativeLookup {
    /// Return the process that owns the mapping.
    #[must_use]
    pub fn process_id(&self) -> crate::Pid {
        self.process_id
    }

    /// Return the exact module selected for this address.
    #[must_use]
    pub fn module(&self) -> &NativeModule {
        &self.module
    }

    /// Return the sampled process-absolute address.
    #[must_use]
    pub fn absolute_address(&self) -> u64 {
        self.absolute_address
    }

    /// Return the address relative to the image base.
    #[must_use]
    pub fn relative_address(&self) -> u64 {
        self.relative_address
    }

    /// Return the static virtual address used for debug lookup.
    #[must_use]
    pub fn image_address(&self) -> u64 {
        self.image_address
    }

    /// Return the image identity selected for this lookup.
    #[must_use]
    pub fn file_identity(&self) -> NativeFileIdentity {
        self.module.file_identity()
    }

    /// Return the spool-local mapping generation identifier.
    #[must_use]
    pub fn mapping_id(&self) -> u32 {
        self.module.mapping_id()
    }
}

/// Owned inline-expanded symbols for one native lookup.
#[derive(Clone, Debug, Default)]
pub struct NativeSymbols(Vec<NativeSymbol>);

impl NativeSymbols {
    /// Construct a resolved result from innermost-first symbols.
    #[must_use]
    pub fn new(symbols: Vec<NativeSymbol>) -> Self {
        Self(symbols)
    }

    /// Construct an unresolved result without allocation.
    #[must_use]
    pub const fn unresolved() -> Self {
        Self(Vec::new())
    }

    /// Borrow the resolved inline chain.
    #[must_use]
    pub fn as_slice(&self) -> &[NativeSymbol] {
        &self.0
    }

    /// Return whether no native symbol was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn into_vec(self) -> Vec<NativeSymbol> {
        self.0
    }
}

/// Plug-in interface for batched native symbolization.
pub trait NativeSymbolizer {
    /// Backend error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolve every request and append one ordered result per request.
    fn symbolize(
        &mut self,
        requests: &[NativeLookup],
        output: &mut Vec<NativeSymbols>,
    ) -> Result<(), Self::Error>;
}

pub(crate) trait ErasedNativeSymbolizer {
    fn symbolize(
        &mut self,
        requests: &[NativeLookup],
        output: &mut Vec<NativeSymbols>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

struct NativeSymbolizerAdapter<S>(S);

impl<S: NativeSymbolizer> ErasedNativeSymbolizer for NativeSymbolizerAdapter<S> {
    fn symbolize(
        &mut self,
        requests: &[NativeLookup],
        output: &mut Vec<NativeSymbols>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0
            .symbolize(requests, output)
            .map_err(|error| Box::new(error) as _)
    }
}

pub(crate) fn erase_native_symbolizer(
    symbolizer: impl NativeSymbolizer + 'static,
) -> Box<dyn ErasedNativeSymbolizer> {
    Box::new(NativeSymbolizerAdapter(symbolizer))
}

#[cfg(feature = "builtin-wholesym")]
impl NativeSymbolizer for SymbolizerWrapper {
    type Error = std::convert::Infallible;

    fn symbolize(
        &mut self,
        requests: &[NativeLookup],
        output: &mut Vec<NativeSymbols>,
    ) -> Result<(), Self::Error> {
        output.reserve(requests.len());
        output.extend(
            requests
                .iter()
                .map(|request| self.symbolize_lookup(request)),
        );
        Ok(())
    }
}

#[cfg(feature = "builtin-wholesym")]
struct SharedSymbolizerWrapper(Rc<RefCell<Option<SymbolizerWrapper>>>);

#[cfg(feature = "builtin-wholesym")]
impl NativeSymbolizer for SharedSymbolizerWrapper {
    type Error = std::convert::Infallible;

    fn symbolize(
        &mut self,
        requests: &[NativeLookup],
        output: &mut Vec<NativeSymbols>,
    ) -> Result<(), Self::Error> {
        self.0
            .borrow_mut()
            .get_or_insert_with(SymbolizerWrapper::new)
            .symbolize(requests, output)
    }
}

pub(crate) type NativeSymbolizerFactory =
    Box<dyn FnMut(crate::Pid) -> Box<dyn ErasedNativeSymbolizer>>;

/// Factory for StackPulse's bundled Wholesym backend.
#[cfg(feature = "builtin-wholesym")]
#[must_use]
pub(crate) fn default_native_symbolizer_factory() -> NativeSymbolizerFactory {
    let shared = Rc::new(RefCell::new(None));
    Box::new(move |_pid| erase_native_symbolizer(SharedSymbolizerWrapper(Rc::clone(&shared))))
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

#[cfg(feature = "builtin-wholesym")]
/// Standard system debug directory on Linux.
#[cfg(feature = "builtin-wholesym")]
const DEFAULT_DEBUG_DIR: &str = "/usr/lib/debug";

/// Parse debug directories from environment.
/// Priority: `STACKPULSE_DEBUG_DIRS` (runtime) > `STACKPULSE_DEFAULT_DEBUG_DIRS` (build-time) > /usr/lib/debug
#[cfg(feature = "builtin-wholesym")]
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
#[cfg(feature = "builtin-wholesym")]
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

#[cfg(feature = "builtin-wholesym")]
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

#[cfg(feature = "builtin-wholesym")]
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

#[cfg(feature = "builtin-wholesym")]
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

#[cfg(feature = "builtin-wholesym")]
fn linux_build_id_string(info: &wholesym::LibraryInfo) -> Option<String> {
    match &info.code_id {
        Some(CodeId::ElfBuildId(build_id)) => Some(build_id.to_string()),
        _ => None,
    }
}

/// Wrapper around symbolization with caching.
///
/// Note: NOT thread-safe. Each thread needs its own `SymbolizerWrapper` instance.
#[cfg(feature = "builtin-wholesym")]
struct SymbolizerWrapper {
    /// Local debug directories for `.build-id` lookup (Linux only).
    local_debug_dirs: Box<[PathBuf]>,

    /// Cached redirect mappings keyed by module path (Linux only).
    /// Maps module path -> (standard_debug_path, actual_debug_path).
    redirect_cache: HashMap<PathBuf, (PathBuf, PathBuf)>,

    /// Shared symbol manager used for symbolization.
    symbol_manager: SymbolManager,

    /// Loaded wholesym maps keyed by recorded file identity. A mapping-local
    /// key is used when the spool has no stable filesystem identity.
    symbol_maps: HashMap<NativeImageKey, Option<WholeSymbolMap>>,

    /// Tokio runtime for wholesym async APIs. Wrapped so Drop can hand it to
    /// `shutdown_background`, which is safe even inside another tokio runtime
    /// (a plain runtime drop there panics mid-unwind and aborts the process).
    runtime: std::mem::ManuallyDrop<TokioRuntime>,
}

#[cfg(feature = "builtin-wholesym")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum NativeImageKey {
    File(NativeFileIdentity),
    Mapping { path: PathBuf, id: u32 },
}

#[cfg(feature = "builtin-wholesym")]
impl NativeImageKey {
    fn for_lookup(lookup: &NativeLookup) -> Self {
        let identity = lookup.file_identity();
        if identity.inode() != 0 || identity.device_major() != 0 || identity.device_minor() != 0 {
            Self::File(identity)
        } else {
            Self::Mapping {
                path: lookup.module().path().to_path_buf(),
                id: lookup.mapping_id(),
            }
        }
    }
}

#[cfg(feature = "builtin-wholesym")]
impl Drop for SymbolizerWrapper {
    fn drop(&mut self) {
        // SAFETY: Drop runs once, and ManuallyDrop prevents any second drop of
        // the runtime after ownership is moved into shutdown_background.
        let runtime = unsafe { std::mem::ManuallyDrop::take(&mut self.runtime) };
        runtime.shutdown_background();
    }
}

/// Run `future` on `runtime` from any thread. `Runtime::block_on` panics when
/// the calling thread is already driving a tokio runtime (e.g. a consumer
/// symbolizing from inside an async task); in that case run the blocking wait
/// on a temporary OS thread instead.
#[cfg(feature = "builtin-wholesym")]
fn block_on_runtime<F>(runtime: &TokioRuntime, future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    if tokio::runtime::Handle::try_current().is_err() {
        return runtime.block_on(future);
    }
    std::thread::scope(
        |scope| match scope.spawn(|| runtime.block_on(future)).join() {
            Ok(output) => output,
            Err(payload) => std::panic::resume_unwind(payload),
        },
    )
}

/// Extract a short module name from a path (file name, or full path as fallback).
#[cfg(feature = "builtin-wholesym")]
fn module_name_rc(path: &Path) -> Rc<str> {
    crate::path_to_name(path).into()
}

#[cfg(feature = "builtin-wholesym")]
fn build_native_symbol(
    name: String,
    source: SourceLocation,
    module: &Rc<str>,
    offset: u64,
    is_python_runtime: bool,
) -> NativeSymbol {
    let name_str: Rc<str> = name.into();
    NativeSymbol {
        is_eval_frame: is_eval_frame(&name_str),
        name: name_str,
        source,
        module: Rc::clone(module),
        offset,
        inline_depth: 0,
        should_ignore: is_python_runtime,
    }
}

#[cfg(feature = "builtin-wholesym")]
#[inline]
fn inline_depth_for_frame(frame_count: usize, index: usize) -> u16 {
    u16::try_from(frame_count.saturating_sub(index + 1)).unwrap_or(u16::MAX)
}

#[cfg(feature = "builtin-wholesym")]
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

#[cfg(feature = "builtin-wholesym")]
impl SymbolizerWrapper {
    /// Create a symbolizer with the configured debug-file search paths.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "the infallible NativeSymbolizer factory cannot report Tokio runtime construction failure"
    )]
    fn new() -> Self {
        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime for Linux symbolization");
        let local_debug_dirs = parse_debug_dirs();
        let symbol_manager =
            SymbolManager::with_config(build_symbol_manager_config(&local_debug_dirs, &[]));
        let local_debug_dirs = local_debug_dirs.into_boxed_slice();

        Self {
            local_debug_dirs,
            redirect_cache: HashMap::new(),
            symbol_manager,
            symbol_maps: HashMap::new(),
            runtime: std::mem::ManuallyDrop::new(runtime),
        }
    }

    fn rebuild_symbol_manager(&mut self) {
        let all_redirects: Vec<(PathBuf, PathBuf)> =
            self.redirect_cache.values().cloned().collect();
        self.symbol_manager = SymbolManager::with_config(build_symbol_manager_config(
            &self.local_debug_dirs,
            &all_redirects,
        ));
    }

    fn symbolize_lookup(&mut self, lookup: &NativeLookup) -> NativeSymbols {
        let module = lookup.module();
        let module_rc = module_name_rc(module.path());
        let image = NativeImageKey::for_lookup(lookup);
        let symbols = self
            .symbolize_with_wholesym(
                image,
                module.path(),
                LookupAddress::Svma(lookup.image_address()),
                lookup.relative_address(),
                &module_rc,
                module.is_python_runtime(),
            )
            .unwrap_or_default();
        NativeSymbols::new(symbols)
    }

    fn symbolize_with_wholesym(
        &mut self,
        image: NativeImageKey,
        path: &Path,
        lookup_address: LookupAddress,
        module_offset: u64,
        module_rc: &Rc<str>,
        is_python_runtime: bool,
    ) -> Option<Vec<NativeSymbol>> {
        self.ensure_symbol_map_loaded(image.clone(), path);
        let symbol_map = self.symbol_maps.get(&image).and_then(|map| map.as_ref())?;
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

    fn ensure_symbol_map_loaded(&mut self, image: NativeImageKey, path: &Path) {
        if !self.symbol_maps.contains_key(&image) {
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
            self.symbol_maps.insert(image, loaded.ok());
        }
    }

    /// Discover and cache debug-file redirects for `paths` (skipping ones
    /// already cached); rebuild the `SymbolManager` once if anything new.
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

#[cfg(all(test, feature = "builtin-wholesym"))]
mod tests {
    use super::*;

    #[test]
    fn block_on_runtime_falls_back_to_a_thread_inside_tokio() {
        let outer = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let inner = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // Inside a tokio context Runtime::block_on would panic; the scoped
        // thread fallback must still run the future to completion.
        let value = outer.block_on(async { block_on_runtime(&inner, async { 41 + 1 }) });
        assert_eq!(value, 42);

        // Outside any context the plain block_on path is taken.
        assert_eq!(block_on_runtime(&inner, async { 7 }), 7);
    }

    #[test]
    fn test_is_eval_frame_tail_call_variants() {
        assert!(is_eval_frame("_TAIL_CALL_BINARY_OP.llvm.1234567890"));
        assert!(is_eval_frame("TAIL_CALL_CALL.llvm.9000656869750701268"));
        assert!(!is_eval_frame("TAIL_CALL_CALL"));
        assert!(!is_eval_frame("some_function.llvm.123"));
    }

    #[test]
    fn test_inline_depth_for_innermost_first_frames() {
        assert_eq!(inline_depth_for_frame(3, 0), 2);
        assert_eq!(inline_depth_for_frame(3, 1), 1);
        assert_eq!(inline_depth_for_frame(3, 2), 0);
    }

    #[test]
    fn test_build_id_path_construction() {
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
        assert!(crate::is_python_runtime_module_path("libpython3.13.so"));
        assert!(crate::is_python_runtime_module_path("python3"));

        assert!(!crate::is_python_runtime_module_path("/usr/bin/bpython"));
        assert!(!crate::is_python_runtime_module_path("/usr/bin/ipython"));
        assert!(!crate::is_python_runtime_module_path(
            "/usr/bin/python3-config"
        ));
        assert!(!crate::is_python_runtime_module_path("/usr/bin/pythonw"));
        assert!(!crate::is_python_runtime_module_path("/usr/bin/python311d"));
        assert!(!crate::is_python_runtime_module_path("python3.13m"));
        assert!(!crate::is_python_runtime_module_path("python.3"));

        assert!(!crate::is_python_runtime_module_path(""));
        assert!(!crate::is_python_runtime_module_path("/"));
    }
}
