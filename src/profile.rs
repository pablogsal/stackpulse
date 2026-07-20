use std::rc::Rc;

use bitflags::bitflags;

/// High-level frame category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FrameKind {
    /// Python frame.
    Python,
    /// Native user-space frame.
    Native,
    /// Kernel frame.
    Kernel,
    /// Frame that could not be classified.
    Unknown,
}

/// Where a symbol name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymbolOrigin {
    /// File-backed symbol information.
    Elf,
    /// Python perf-map entry.
    PerfMap,
    /// Kernel symbol table.
    KernelSymbols,
    /// Address-only fallback.
    AddressOnly,
}

bitflags! {
    /// Per-frame classification flags attached to every [`ResolvedFrame`].
    ///
    /// Flags are additive. Consumers commonly use these to hide
    /// implementation-detail frames in default views (see
    /// [`Self::HIDDEN_DEFAULT`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FrameFlags: u32 {
        /// Frame is from the Python runtime binary or `libpython`.
        const PYTHON_RUNTIME = 1 << 0;
        /// Frame should be hidden from default flame-graph / report views.
        const HIDDEN_DEFAULT = 1 << 2;
        /// Frame came from a JIT-emitted code region (perf-map entry).
        const JIT = 1 << 3;
        /// Sentinel frame marking where native unwinding stopped because the
        /// captured stack bytes were exhausted (`stack_size` too small for
        /// the full stack), not a real (or failed) address resolution.
        const TRUNCATED_STACK = 1 << 4;
    }
}

/// Optional source-position information attached to a [`PythonFrame`].
///
/// A value of `-1` for any field means "unknown"; this matches the CPython
/// convention for missing position attributes on code objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocationInfo {
    /// 1-based starting line number (`-1` if unknown).
    pub lineno: i32,
    /// 1-based ending line number (`-1` if unknown).
    pub end_lineno: i32,
    /// 0-based starting column offset in bytes (`-1` if unknown).
    pub column: i32,
    /// 0-based ending column offset in bytes (`-1` if unknown).
    pub end_column: i32,
}

impl Default for LocationInfo {
    fn default() -> Self {
        const UNKNOWN: i32 = -1;
        Self {
            lineno: UNKNOWN,
            end_lineno: UNKNOWN,
            column: UNKNOWN,
            end_column: UNKNOWN,
        }
    }
}

/// A resolved Python frame.
///
/// Produced from a CPython perf-map entry (with `PYTHONPERFSUPPORT=1`) plus
/// any inlined source-position info CPython provides. `Rc<str>` is used for
/// the file and function strings so identical entries from repeated samples
/// share one allocation across a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonFrame {
    /// Source file as recorded by CPython. May be absolute, relative, or a
    /// pseudo-path such as `<frozen importlib._bootstrap>`.
    pub file_name: Rc<str>,
    /// Source position information for the frame (line/column ranges).
    pub location: LocationInfo,
    /// Resolved function or method name.
    pub func_name: Rc<str>,
    /// Last executed bytecode opcode, if available.
    pub opcode: Option<u8>,
    /// Whether this frame is the entry point of a Python call (top of an
    /// eval-loop activation, not an inlined or continuation frame).
    pub is_entry: bool,
    /// Byte offset into [`Self::file_name`] where the basename begins;
    /// use [`Self::basename`] to read it.
    pub basename_start: usize,
}

impl PythonFrame {
    /// Construct a resolved Python frame, precomputing the basename offset.
    #[must_use]
    pub fn new(
        file_name: &str,
        location: LocationInfo,
        func_name: &str,
        opcode: Option<u8>,
        is_entry: bool,
    ) -> Self {
        let basename_start = self::basename_start(file_name);
        Self {
            file_name: file_name.into(),
            location,
            func_name: func_name.into(),
            opcode,
            is_entry,
            basename_start,
        }
    }

    /// Final path component of [`Self::file_name`] (filename only).
    #[inline]
    #[must_use]
    pub fn basename(&self) -> &str {
        &self.file_name[self.basename_start..]
    }
}

/// Optional source-position info attached to a [`NativeSymbol`].
///
/// All fields are `Option` because DWARF, debuginfod, and address-only
/// fallbacks each provide different subsets. Callers should treat any missing
/// field as "unknown" rather than "zero".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceLocation {
    /// Source file path (absolute or compiler-relative).
    pub file: Option<Rc<str>>,
    /// 1-based line number of the sampled instruction.
    pub line: Option<u32>,
    /// 1-based column number of the sampled instruction.
    pub column: Option<u32>,
    /// 1-based line where the enclosing function starts.
    pub function_start_line: Option<u32>,
    /// 1-based column where the enclosing function starts.
    pub function_start_column: Option<u32>,
}

/// A resolved native or kernel symbol.
///
/// One [`NativeFrame`] may resolve to multiple `NativeSymbol`s when inline
/// frames are expanded; the innermost callee is listed first and
/// [`Self::inline_depth`] grows outward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSymbol {
    /// Demangled symbol name (function/method).
    pub name: Rc<str>,
    /// Source position information, when available.
    pub source: SourceLocation,
    /// On-disk path of the owning module (binary or shared library).
    pub module: Rc<str>,
    /// Byte offset of the instruction within its enclosing function.
    ///
    /// `0` for fallback pseudo-symbols whose [`Self::name`] already embeds an
    /// address (`module+0x...`, `[kernel]+0x...`). For inline expansions the
    /// offset is relative to the outermost function's start.
    pub offset: u64,
    /// Nesting depth for inline expansions: `0` is the outermost enclosing
    /// function, higher values are deeper inlined frames (the highest being
    /// the innermost, sampled expansion).
    pub inline_depth: u16,
    /// Whether this symbol is the CPython bytecode evaluation loop.
    pub is_eval_frame: bool,
    /// Whether default views should hide this symbol (matches
    /// [`FrameFlags::HIDDEN_DEFAULT`] semantics).
    pub should_ignore: bool,
}

impl NativeSymbol {
    /// Build a [`NativeSymbol`] for the innermost (non-inline) frame,
    /// with its source and module metadata.
    #[must_use]
    pub fn new(
        name: impl Into<Rc<str>>,
        source: SourceLocation,
        module: impl Into<Rc<str>>,
        offset: u64,
        is_eval_frame: bool,
        should_ignore: bool,
    ) -> Self {
        let module = module.into();
        Self {
            name: name.into(),
            source,
            module,
            offset,
            inline_depth: 0,
            is_eval_frame,
            should_ignore,
        }
    }

    /// Final path component of [`Self::module`].
    #[inline]
    #[must_use]
    pub fn module_basename(&self) -> &str {
        &self.module[basename_start(&self.module)..]
    }
}

/// A resolved native, kernel, or address-only frame.
///
/// Carries the raw program counter and stack pointer from the sample plus
/// whatever symbol metadata was recovered (or `None` when address-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFrame {
    /// Absolute program counter sampled from the target.
    pub pc: u64,
    /// Stack pointer at the time of the sample (`0` if not recorded).
    pub sp: u64,
    /// Resolved symbol, if symbolization succeeded.
    pub symbol: Option<NativeSymbol>,
    /// Whether the owning module is the Python runtime
    /// (see [`is_python_module`](crate::is_python_module)).
    pub is_python_runtime: bool,
    /// High-level category: native, kernel, or unknown.
    pub kind: FrameKind,
    /// Where the symbol info came from (ELF, perf-map, kallsyms, address-only).
    pub origin: SymbolOrigin,
    /// Classification flags shared with [`PythonFrame`] consumers.
    pub flags: FrameFlags,
}

impl NativeFrame {
    /// Build an address-only [`NativeFrame`] for an IP that could not be
    /// symbolized. `kind` is set to [`FrameKind::Unknown`] and `origin` to
    /// [`SymbolOrigin::AddressOnly`].
    #[must_use]
    pub fn from_address(pc: u64) -> Self {
        Self {
            pc,
            sp: 0,
            symbol: None,
            is_python_runtime: false,
            kind: FrameKind::Unknown,
            origin: SymbolOrigin::AddressOnly,
            flags: FrameFlags::empty(),
        }
    }

    /// Sentinel resolved frame for a truncated-stack marker (see
    /// [`crate::FrameRecord::truncated_stack_marker`]): the unwinder ran out
    /// of captured stack bytes before reaching the root. Distinguishable from
    /// a failed resolve via [`FrameFlags::TRUNCATED_STACK`].
    #[must_use]
    pub fn truncated_stack_marker() -> Self {
        Self {
            pc: 0,
            sp: 0,
            symbol: Some(NativeSymbol::new(
                "<stack truncated>",
                SourceLocation::default(),
                "",
                0,
                false,
                false,
            )),
            is_python_runtime: false,
            kind: FrameKind::Unknown,
            origin: SymbolOrigin::AddressOnly,
            flags: FrameFlags::TRUNCATED_STACK,
        }
    }

    /// Display name for the frame: the resolved symbol name, or the
    /// hex-formatted `pc` (`<0xCAFEBABE>`) when no symbol was recovered.
    #[must_use]
    pub fn func_name(&self) -> String {
        self.symbol
            .as_ref()
            .map_or_else(|| format!("<0x{:x}>", self.pc), |s| s.name.to_string())
    }
}

/// A resolved frame from a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedFrame {
    /// Python frame.
    Python(PythonFrame),
    /// Native, kernel, or address-only frame.
    Native(NativeFrame),
}

impl ResolvedFrame {
    /// Display name across both variants: Python function name or the
    /// native frame's [`NativeFrame::func_name`].
    #[must_use]
    pub fn func_name(&self) -> String {
        match self {
            Self::Python(frame) => frame.func_name.to_string(),
            Self::Native(frame) => frame.func_name(),
        }
    }
}

/// Byte offset of the basename within `path`.
///
/// Returns the index of the first character after the last `/`, or `0` if
/// `path` has no separators. UTF-8 safe because `/` cannot appear inside a
/// multi-byte sequence.
#[inline]
#[must_use]
pub fn basename_start(path: &str) -> usize {
    memchr::memrchr(b'/', path.as_bytes()).map_or(0, |i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_python_location_uses_documented_sentinel() {
        assert_eq!(
            LocationInfo::default(),
            LocationInfo {
                lineno: -1,
                end_lineno: -1,
                column: -1,
                end_column: -1,
            }
        );
    }

    #[test]
    fn python_frame_basename_handles_long_ascii_path() {
        let path = format!("{}/leaf.py", "a".repeat(70_000));
        let frame = PythonFrame::new(&path, LocationInfo::default(), "f", None, false);

        assert_eq!(frame.basename_start, path.rfind('/').unwrap() + 1);
        assert_eq!(frame.basename(), "leaf.py");
    }

    #[test]
    fn python_frame_basename_handles_long_utf8_path() {
        let path = format!("{}é/leaf.py", "a".repeat(65_534));
        let frame = PythonFrame::new(&path, LocationInfo::default(), "f", None, false);

        assert_eq!(frame.basename_start, path.rfind('/').unwrap() + 1);
        assert_eq!(frame.basename(), "leaf.py");
    }

    #[test]
    fn basename_start_reports_offsets_above_u16_max() {
        let path = format!("{}/leaf.py", "a".repeat(70_000));

        assert_eq!(basename_start(&path), path.rfind('/').unwrap() + 1);
    }
}
