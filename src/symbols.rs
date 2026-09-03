//! Native address-to-symbol resolution.

use crate::module_base::ModuleImageBase;
use crate::profile::NativeSymbol;
#[cfg(feature = "builtin-wholesym")]
use crate::profile::SourceLocation;
use crate::spool::ModulePath;

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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static NEXT_SYNTHETIC_IMAGE_ID: AtomicU64 = AtomicU64::new(1 << 63);

/// Module information for symbolization.
#[derive(Clone, Debug)]
pub struct NativeModule {
    data: Rc<NativeModuleData>,
    image: Option<Arc<NativeImage>>,
}

#[derive(Debug)]
pub(crate) struct NativeImage {
    path: PathBuf,
    file: Arc<std::fs::File>,
}

impl NativeImage {
    #[cfg(target_os = "linux")]
    pub(crate) fn new(file: Arc<std::fs::File>) -> Self {
        use std::os::fd::AsRawFd;

        Self {
            path: PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
            file,
        }
    }

    pub(crate) fn file(&self) -> &std::fs::File {
        &self.file
    }
}

#[derive(Debug)]
pub(crate) struct NativeModuleData {
    pub(crate) path: ModulePath,
    pub(crate) name: Rc<str>,
    pub(crate) address_range: std::ops::Range<u64>,
    pub(crate) image_base: ModuleImageBase,
    pub(crate) is_python_runtime: bool,
    pub(crate) file_identity: NativeFileIdentity,
    pub(crate) mapping_id: u32,
    pub(crate) image_id: NativeImageId,
}

/// Stable recorded identity for a native image.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NativeFileIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    inode_generation: u64,
}

/// Opaque identity of the exact validated image used for symbolization.
///
/// Values are comparable within one [`crate::Symbolizer`] and let a backend
/// share parsed image data without using a pathname or mapping address as a
/// weaker key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NativeImageId(u64);

impl NativeModule {
    /// Construct a module value for testing a custom native symbolizer.
    ///
    /// `mapping_id` should be unique within the synthetic spool fixture. Each
    /// call receives a distinct opaque [`NativeImageId`], even when its path
    /// and file identity match another module. The synthetic module has an
    /// image base of zero, is not marked as a Python runtime, and has no
    /// [`Self::image_path`]. Recorded modules are constructed by StackPulse.
    #[must_use]
    pub fn new(
        path: impl Into<ModulePath>,
        file_identity: NativeFileIdentity,
        mapping_id: u32,
    ) -> Self {
        Self::from_recording(
            path.into(),
            0..u64::MAX,
            ModuleImageBase::new(0, 0),
            false,
            file_identity,
            mapping_id,
            NEXT_SYNTHETIC_IMAGE_ID.fetch_add(1, Ordering::Relaxed),
        )
    }

    pub(crate) fn from_recording(
        path: ModulePath,
        address_range: std::ops::Range<u64>,
        image_base: ModuleImageBase,
        is_python_runtime: bool,
        file_identity: NativeFileIdentity,
        mapping_id: u32,
        image_token: u64,
    ) -> Self {
        let normalized_path = normalized_module_path(path.as_str());
        let name = crate::path_name(Path::new(normalized_path)).into();
        Self {
            data: Rc::new(NativeModuleData {
                path,
                name,
                address_range,
                image_base,
                is_python_runtime,
                file_identity,
                mapping_id,
                image_id: NativeImageId(image_token),
            }),
            image: None,
        }
    }

    pub(crate) fn with_image(&self, image: Option<Arc<NativeImage>>) -> Self {
        Self {
            data: Rc::clone(&self.data),
            image,
        }
    }
}

impl NativeModule {
    /// Return the path stored in the recording.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.data.path.as_path()
    }

    /// Return the recorded path without Linux's `" (deleted)"` suffix.
    #[must_use]
    pub fn normalized_path(&self) -> &Path {
        Path::new(normalized_module_path(self.data.path.as_str()))
    }

    /// Borrow the shared module display name without copying it.
    #[must_use]
    pub fn name_rc(&self) -> &Rc<str> {
        &self.data.name
    }

    /// Return a process-local path to the exact validated mapped image.
    ///
    /// This is `Some` only on Linux when StackPulse successfully reopened and
    /// retained the file backing a recorded mapping. It is `None` for synthetic
    /// modules, anonymous or deleted mappings that could not be reopened, and
    /// modules loaded from a spool without a validated file descriptor. The
    /// returned `/proc/self/fd/...` path remains valid while this module is
    /// alive and can differ from [`Self::path`].
    #[must_use]
    pub fn image_path(&self) -> Option<&Path> {
        self.image.as_ref().map(|image| image.path.as_path())
    }

    /// Return the process-absolute address range for this mapping.
    #[must_use]
    pub fn address_range(&self) -> std::ops::Range<u64> {
        self.data.address_range.clone()
    }

    /// Return the correlated runtime and static image bases.
    #[must_use]
    pub fn image_base(&self) -> ModuleImageBase {
        self.data.image_base
    }

    /// Return whether this image is the Python runtime.
    #[must_use]
    pub fn is_python_runtime(&self) -> bool {
        self.data.is_python_runtime
    }

    /// Return the recorded filesystem identity.
    #[must_use]
    pub fn file_identity(&self) -> NativeFileIdentity {
        self.data.file_identity
    }

    /// Return the spool-local mapping generation identifier.
    #[must_use]
    pub fn mapping_id(&self) -> u32 {
        self.data.mapping_id
    }

    /// Return the exact image identity selected by StackPulse.
    #[must_use]
    pub fn image_id(&self) -> NativeImageId {
        self.data.image_id
    }
}

pub(crate) fn normalized_module_path(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

impl NativeFileIdentity {
    /// Construct a recorded filesystem identity.
    ///
    /// Use zeros for fields unavailable in a synthetic test fixture.
    #[must_use]
    pub const fn new(
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
    /// Construct one request for testing a custom native symbolizer.
    ///
    /// The addresses have the same meanings as their accessors. StackPulse
    /// computes them for recorded frames; fixture authors are responsible for
    /// keeping them consistent with the synthetic module.
    #[must_use]
    pub fn new(
        process_id: crate::Pid,
        module: NativeModule,
        absolute_address: u64,
        relative_address: u64,
        image_address: u64,
    ) -> Self {
        Self {
            process_id,
            module,
            absolute_address,
            relative_address,
            image_address,
        }
    }

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

    /// Return the exact image identity selected by StackPulse.
    #[must_use]
    pub fn image_id(&self) -> NativeImageId {
        self.module.image_id()
    }
}

/// Owned inline-expanded symbols for one native lookup.
#[derive(Debug, Default)]
pub struct NativeSymbols(NativeSymbolStorage);

#[derive(Debug, Default)]
enum NativeSymbolStorage {
    #[default]
    Unresolved,
    One(NativeSymbol),
    Many(Vec<NativeSymbol>),
}

impl NativeSymbols {
    /// Construct a resolved result from innermost-first symbols.
    #[must_use]
    pub fn new(mut symbols: Vec<NativeSymbol>) -> Self {
        set_inline_depths(&mut symbols);
        match symbols.len() {
            0 => Self::unresolved(),
            1 => symbols.pop().map_or_else(Self::unresolved, |symbol| {
                Self(NativeSymbolStorage::One(symbol))
            }),
            _ => Self(NativeSymbolStorage::Many(symbols)),
        }
    }

    /// Construct a single-symbol result without allocating a vector.
    #[must_use]
    pub fn one(mut symbol: NativeSymbol) -> Self {
        symbol.set_inline_depth(0);
        Self(NativeSymbolStorage::One(symbol))
    }

    /// Construct an unresolved result without allocation.
    #[must_use]
    pub const fn unresolved() -> Self {
        Self(NativeSymbolStorage::Unresolved)
    }

    /// Borrow the resolved inline chain.
    #[must_use]
    pub fn as_slice(&self) -> &[NativeSymbol] {
        match &self.0 {
            NativeSymbolStorage::Unresolved => &[],
            NativeSymbolStorage::One(symbol) => std::slice::from_ref(symbol),
            NativeSymbolStorage::Many(symbols) => symbols,
        }
    }

    /// Return whether no native symbol was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self.0, NativeSymbolStorage::Unresolved)
    }

    pub(crate) fn into_symbols(self) -> NativeSymbolsIntoIter {
        match self.0 {
            NativeSymbolStorage::Unresolved => NativeSymbolsIntoIter::Unresolved,
            NativeSymbolStorage::One(symbol) => NativeSymbolsIntoIter::One(Some(symbol)),
            NativeSymbolStorage::Many(symbols) => NativeSymbolsIntoIter::Many(symbols.into_iter()),
        }
    }
}

fn set_inline_depths(symbols: &mut [NativeSymbol]) {
    let count = symbols.len();
    for (index, symbol) in symbols.iter_mut().enumerate() {
        symbol.set_inline_depth(count - index - 1);
    }
}

pub(crate) enum NativeSymbolsIntoIter {
    Unresolved,
    One(Option<NativeSymbol>),
    Many(std::vec::IntoIter<NativeSymbol>),
}

impl Iterator for NativeSymbolsIntoIter {
    type Item = NativeSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Unresolved => None,
            Self::One(symbol) => symbol.take(),
            Self::Many(symbols) => symbols.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = match self {
            Self::Unresolved => 0,
            Self::One(symbol) => usize::from(symbol.is_some()),
            Self::Many(symbols) => symbols.len(),
        };
        (len, Some(len))
    }
}

impl ExactSizeIterator for NativeSymbolsIntoIter {}

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

    /// Release mapping-specific state after a live tail retires a module.
    ///
    /// Other mappings can still refer to the same [`NativeModule::image_id`],
    /// so shared parsed-image state should remain until its final mapping is
    /// retired. The module reference is valid only for this call.
    fn retire_module(&mut self, _module: &NativeModule) {}
}

pub(crate) trait ErasedNativeSymbolizer {
    fn symbolize(
        &mut self,
        requests: &[NativeLookup],
        output: &mut Vec<NativeSymbols>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn retire_module(&mut self, module: &NativeModule);
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

    fn retire_module(&mut self, module: &NativeModule) {
        self.0.retire_module(module);
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
        self.register_mappings(requests);
        self.preload_symbol_maps(requests);
        output.reserve(requests.len());
        output.extend(
            requests
                .iter()
                .map(|request| self.symbolize_lookup(request)),
        );
        Ok(())
    }

    fn retire_module(&mut self, module: &NativeModule) {
        if !self.mappings.remove(&module.mapping_id()) {
            return;
        }
        let image = module.image_id();
        let Some(references) = self.image_mapping_counts.get_mut(&image) else {
            return;
        };
        *references -= 1;
        if *references == 0 {
            self.image_mapping_counts.remove(&image);
            self.symbol_maps.remove(&image);
            self.redirect_cache.remove(&image);
        }
    }
}

#[cfg(feature = "builtin-wholesym")]
struct SharedSymbolizerWrapper(Rc<RefCell<Option<SymbolizerWrapper>>>);

#[cfg(feature = "builtin-wholesym")]
impl NativeSymbolizer for SharedSymbolizerWrapper {
    type Error = std::io::Error;

    fn symbolize(
        &mut self,
        requests: &[NativeLookup],
        output: &mut Vec<NativeSymbols>,
    ) -> Result<(), Self::Error> {
        let mut shared = self.0.borrow_mut();
        let Some(symbolizer) = shared.as_mut() else {
            return Err(std::io::Error::other(
                "shared native symbolizer was not initialized",
            ));
        };
        symbolizer
            .symbolize(requests, output)
            .map_err(|error| match error {})
    }

    fn retire_module(&mut self, module: &NativeModule) {
        if let Some(symbolizer) = self.0.borrow_mut().as_mut() {
            symbolizer.retire_module(module);
        }
    }
}

pub(crate) type NativeBackendError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type NativeSymbolizerFactory =
    Box<dyn FnMut(crate::Pid) -> Result<Box<dyn ErasedNativeSymbolizer>, NativeBackendError>>;

/// Factory for StackPulse's bundled Wholesym backend.
#[cfg(feature = "builtin-wholesym")]
#[must_use]
pub(crate) fn default_native_symbolizer_factory() -> NativeSymbolizerFactory {
    let shared = Rc::new(RefCell::new(None));
    Box::new(move |_pid| {
        if shared.borrow().is_none() {
            *shared.borrow_mut() = Some(SymbolizerWrapper::try_new()?);
        }
        Ok(erase_native_symbolizer(SharedSymbolizerWrapper(Rc::clone(
            &shared,
        ))))
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

    /// Cached debug-file redirects keyed by validated image identity.
    redirect_cache: HashMap<NativeImageId, Option<(PathBuf, PathBuf)>>,

    /// Shared symbol manager used for symbolization.
    symbol_manager: SymbolManager,

    /// Loaded wholesym maps keyed by StackPulse's validated image identity.
    symbol_maps: HashMap<NativeImageId, Option<WholeSymbolMap>>,

    mappings: HashSet<u32>,
    image_mapping_counts: HashMap<NativeImageId, usize>,

    /// Tokio runtime for wholesym async APIs. Wrapped so Drop can hand it to
    /// `shutdown_background`, which is safe even inside another tokio runtime
    /// (a plain runtime drop there panics mid-unwind and aborts the process).
    runtime: std::mem::ManuallyDrop<TokioRuntime>,
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

#[cfg(feature = "builtin-wholesym")]
fn build_native_symbol(
    name: impl Into<Rc<str>>,
    source: SourceLocation,
    module: &Rc<str>,
    offset: u64,
    is_python_runtime: bool,
) -> NativeSymbol {
    let symbol = NativeSymbol::new(name, source, Rc::clone(module), offset);
    if is_python_runtime {
        symbol.hidden_by_default()
    } else {
        symbol
    }
}

#[cfg(feature = "builtin-wholesym")]
fn build_native_symbols_from_wholesym_parts(
    symbol_name: String,
    frames: Option<Vec<wholesym::FrameDebugInfo>>,
    module: &Rc<str>,
    function_offset: u64,
    is_python_runtime: bool,
) -> NativeSymbols {
    let frame_parts = |frame: wholesym::FrameDebugInfo| {
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
        (frame.function, source)
    };

    match frames {
        None => NativeSymbols::one(build_native_symbol(
            symbol_name,
            SourceLocation::default(),
            module,
            function_offset,
            is_python_runtime,
        )),
        Some(mut frames) if frames.len() == 1 => {
            let Some(frame) = frames.pop() else {
                return NativeSymbols::one(build_native_symbol(
                    symbol_name,
                    SourceLocation::default(),
                    module,
                    function_offset,
                    is_python_runtime,
                ));
            };
            let (function, source) = frame_parts(frame);
            NativeSymbols::one(build_native_symbol(
                function.unwrap_or(symbol_name),
                source,
                module,
                function_offset,
                is_python_runtime,
            ))
        }
        Some(frames) if frames.is_empty() => NativeSymbols::one(build_native_symbol(
            symbol_name,
            SourceLocation::default(),
            module,
            function_offset,
            is_python_runtime,
        )),
        Some(frames) => {
            let fallback_name = frames
                .iter()
                .any(|frame| frame.function.is_none())
                .then(|| Rc::<str>::from(symbol_name));
            let symbols = frames
                .into_iter()
                .map(|frame| {
                    let (function, source) = frame_parts(frame);
                    let name = match function {
                        Some(function) => Rc::<str>::from(function),
                        None => fallback_name.as_ref().map_or_else(Rc::default, Rc::clone),
                    };
                    build_native_symbol(name, source, module, function_offset, is_python_runtime)
                })
                .collect();
            NativeSymbols::new(symbols)
        }
    }
}

#[cfg(feature = "builtin-wholesym")]
impl SymbolizerWrapper {
    /// Create a symbolizer with the configured debug-file search paths.
    fn try_new() -> std::io::Result<Self> {
        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()?;
        let local_debug_dirs = parse_debug_dirs();
        let symbol_manager =
            SymbolManager::with_config(build_symbol_manager_config(&local_debug_dirs, &[]));
        let local_debug_dirs = local_debug_dirs.into_boxed_slice();

        Ok(Self {
            local_debug_dirs,
            redirect_cache: HashMap::new(),
            symbol_manager,
            symbol_maps: HashMap::new(),
            mappings: HashSet::new(),
            image_mapping_counts: HashMap::new(),
            runtime: std::mem::ManuallyDrop::new(runtime),
        })
    }

    fn register_mappings(&mut self, requests: &[NativeLookup]) {
        for request in requests {
            let mapping = request.module().mapping_id();
            if !self.mappings.insert(mapping) {
                continue;
            }
            let image = request.image_id();
            *self.image_mapping_counts.entry(image).or_default() += 1;
        }
    }

    fn rebuild_symbol_manager(&mut self, binary_redirects: &[(PathBuf, PathBuf)]) {
        let mut all_redirects: Vec<(PathBuf, PathBuf)> = self
            .redirect_cache
            .values()
            .filter_map(|redirect| redirect.clone())
            .collect();
        all_redirects.extend_from_slice(binary_redirects);
        self.symbol_manager = SymbolManager::with_config(build_symbol_manager_config(
            &self.local_debug_dirs,
            &all_redirects,
        ));
    }

    fn symbolize_lookup(&mut self, lookup: &NativeLookup) -> NativeSymbols {
        let module = lookup.module();
        let image = lookup.image_id();
        self.symbolize_with_wholesym(
            image,
            LookupAddress::Svma(lookup.image_address()),
            lookup.relative_address(),
            module.name_rc(),
            module.is_python_runtime(),
        )
        .unwrap_or_default()
    }

    fn symbolize_with_wholesym(
        &mut self,
        image: NativeImageId,
        lookup_address: LookupAddress,
        module_offset: u64,
        module_rc: &Rc<str>,
        is_python_runtime: bool,
    ) -> Option<NativeSymbols> {
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

    /// Load new images through their recorded paths while redirecting each
    /// binary read to StackPulse's validated descriptor. Images with the same
    /// recorded path are loaded in separate rounds because a redirect source
    /// can name only one exact file at a time.
    fn preload_symbol_maps(&mut self, requests: &[NativeLookup]) {
        let mut queued_images = HashSet::new();
        let mut pending: Vec<&NativeLookup> = requests
            .iter()
            .filter(|request| {
                !self.symbol_maps.contains_key(&request.image_id())
                    && queued_images.insert(request.image_id())
            })
            .collect();

        while !pending.is_empty() {
            let mut logical_paths = HashSet::new();
            let mut binary_redirects = Vec::new();
            let mut round = Vec::new();
            let mut deferred = Vec::new();

            for request in pending.drain(..) {
                let image = request.image_id();
                let module = request.module();
                let Some(image_path) = module.image_path() else {
                    self.symbol_maps.insert(image, None);
                    continue;
                };
                if !logical_paths.insert(module.normalized_path()) {
                    deferred.push(request);
                    continue;
                }
                self.redirect_cache.entry(image).or_insert_with(|| {
                    discover_linux_debug_file_redirect(
                        &self.runtime,
                        image_path,
                        &self.local_debug_dirs,
                    )
                });
                binary_redirects.push((
                    module.normalized_path().to_path_buf(),
                    image_path.to_path_buf(),
                ));
                round.push(request);
            }

            self.rebuild_symbol_manager(&binary_redirects);
            for request in round {
                let image = request.image_id();
                let module = request.module();
                let path = module.normalized_path();
                let loaded = self.load_symbol_map(path, module.image_path().unwrap_or(path));
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
            pending = deferred;
        }
    }

    fn load_symbol_map(
        &mut self,
        logical_path: &Path,
        image_path: &Path,
    ) -> Result<WholeSymbolMap, wholesym::Error> {
        let mut library_info = block_on_runtime(
            &self.runtime,
            SymbolManager::library_info_for_binary_at_path(image_path, None),
        )?;
        let Some(logical_path) = logical_path.to_str() else {
            return block_on_runtime(
                &self.runtime,
                self.symbol_manager
                    .load_symbol_map_for_binary_at_path(image_path, None),
            );
        };
        let logical_name = Path::new(logical_path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned);
        library_info.path = Some(logical_path.to_owned());
        library_info.debug_path = Some(logical_path.to_owned());
        if let Some(logical_name) = logical_name {
            library_info.name = Some(logical_name.clone());
            library_info.debug_name = Some(logical_name);
        }
        let (Some(debug_name), Some(debug_id)) =
            (library_info.debug_name.clone(), library_info.debug_id)
        else {
            return block_on_runtime(
                &self.runtime,
                self.symbol_manager
                    .load_symbol_map_for_binary_at_path(image_path, None),
            );
        };
        self.symbol_manager.add_known_library(library_info);
        block_on_runtime(
            &self.runtime,
            self.symbol_manager.load_symbol_map(&debug_name, debug_id),
        )
    }
}

#[cfg(all(test, feature = "builtin-wholesym"))]
mod tests {
    use super::*;

    #[test]
    fn public_native_fixture_constructors_preserve_identity_and_addresses() {
        let identity = NativeFileIdentity::new(8, 1, 42, 3);
        let first = NativeModule::new("/fixture/libexample.so (deleted)", identity, 7);
        let second = NativeModule::new("/fixture/libexample.so (deleted)", identity, 8);
        assert_ne!(first.image_id(), second.image_id());
        assert_eq!(first.file_identity(), identity);
        assert_eq!(first.mapping_id(), 7);
        assert_eq!(first.path(), Path::new("/fixture/libexample.so (deleted)"));
        assert_eq!(first.normalized_path(), Path::new("/fixture/libexample.so"));
        assert!(first.image_path().is_none());

        let pid = crate::Pid::new(42).unwrap();
        let lookup = NativeLookup::new(pid, first, 0x1200, 0x200, 0x2200);
        assert_eq!(lookup.process_id(), pid);
        assert_eq!(lookup.absolute_address(), 0x1200);
        assert_eq!(lookup.relative_address(), 0x200);
        assert_eq!(lookup.image_address(), 0x2200);
        assert_eq!(lookup.file_identity(), identity);
        assert_eq!(lookup.mapping_id(), 7);
    }

    #[test]
    fn shared_image_state_outlives_each_mapping() {
        let identity = NativeFileIdentity::new(8, 1, 42, 3);
        let module = |mapping_id| {
            NativeModule::from_recording(
                "/fixture/libexample.so".into(),
                0..u64::MAX,
                ModuleImageBase::new(0, 0),
                false,
                identity,
                mapping_id,
                99,
            )
        };
        let first = module(7);
        let second = module(8);
        let pid = crate::Pid::new(42).unwrap();
        let requests = [
            NativeLookup::new(pid, first.clone(), 1, 1, 1),
            NativeLookup::new(pid, second.clone(), 2, 2, 2),
        ];
        let mut symbolizer = SymbolizerWrapper::try_new().unwrap();
        symbolizer.register_mappings(&requests);
        symbolizer.symbol_maps.insert(first.image_id(), None);
        symbolizer.redirect_cache.insert(first.image_id(), None);

        symbolizer.retire_module(&first);
        assert!(symbolizer.symbol_maps.contains_key(&second.image_id()));
        symbolizer.retire_module(&second);
        assert!(!symbolizer.symbol_maps.contains_key(&second.image_id()));
        assert!(!symbolizer.redirect_cache.contains_key(&second.image_id()));
    }

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
    fn build_id_path_uses_the_standard_debug_layout() {
        assert_eq!(
            standard_build_id_debug_path("00db9c4d7f584f8f622578265ba9abd86723710f"),
            Some(PathBuf::from(
                "/usr/lib/debug/.build-id/00/db9c4d7f584f8f622578265ba9abd86723710f.debug"
            ))
        );
        assert_eq!(standard_build_id_debug_path("00"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validated_fd_loading_preserves_the_logical_debuglink_directory() {
        use object::{Object, ObjectSymbol};
        use std::process::Command;

        if Command::new("cc").arg("--version").output().is_err()
            || Command::new("objcopy").arg("--version").output().is_err()
        {
            return;
        }

        let temp = crate::test_support::TempDir::new("symbols-debuglink");
        let source = temp.path().join("fixture.c");
        let binary = temp.path().join("libfixture.so");
        let debug = temp.path().join("libfixture.so.debug");
        std::fs::write(
            &source,
            b"__attribute__((noinline,visibility(\"default\")))\nint stackpulse_debuglink_target(int value) { return value + 1; }\n",
        )
        .unwrap();
        assert!(Command::new("cc")
            .args(["-shared", "-fPIC", "-g", "-O0"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("objcopy")
            .arg("--only-keep-debug")
            .arg(&binary)
            .arg(&debug)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("objcopy")
            .arg("--strip-debug")
            .arg("--add-gnu-debuglink=libfixture.so.debug")
            .arg("libfixture.so")
            .current_dir(temp.path())
            .status()
            .unwrap()
            .success());

        let bytes = std::fs::read(&binary).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let address = object
            .dynamic_symbols()
            .find(|symbol| symbol.name() == Ok("stackpulse_debuglink_target"))
            .map(|symbol| symbol.address())
            .unwrap();
        let file = Arc::new(std::fs::File::open(&binary).unwrap());
        let module = NativeModule::from_recording(
            binary.to_string_lossy().into_owned().into(),
            0..u64::MAX,
            ModuleImageBase::new(0, 0),
            false,
            NativeFileIdentity::new(0, 0, 0, 0),
            0,
            0,
        )
        .with_image(Some(Arc::new(NativeImage::new(file))));
        let replacement = temp.path().join("replacement");
        std::fs::write(&replacement, b"replacement").unwrap();
        std::fs::rename(&replacement, &binary).unwrap();
        let request = NativeLookup {
            process_id: crate::Pid::try_from(std::process::id()).unwrap(),
            module,
            absolute_address: address,
            relative_address: address,
            image_address: address,
        };
        let mut symbolizer = SymbolizerWrapper::try_new().unwrap();
        let mut output = Vec::new();

        symbolizer.symbolize(&[request], &mut output).unwrap();

        assert_eq!(output.len(), 1);
        assert!(
            output[0]
                .as_slice()
                .iter()
                .any(|symbol| symbol.source.file.is_some() && symbol.source.line.is_some()),
            "resolved symbols: {:?}",
            output[0]
        );
    }

    #[test]
    fn native_symbols_assign_innermost_first_inline_depths() {
        let symbol = |name| NativeSymbol::new(name, SourceLocation::default(), "module", 0);
        let symbols = NativeSymbols::new(vec![symbol("inner"), symbol("middle"), symbol("outer")]);

        assert_eq!(
            symbols
                .as_slice()
                .iter()
                .map(NativeSymbol::inline_depth)
                .collect::<Vec<_>>(),
            [2, 1, 0]
        );
        assert_eq!(
            NativeSymbols::one(symbol("only")).as_slice()[0].inline_depth(),
            0
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
