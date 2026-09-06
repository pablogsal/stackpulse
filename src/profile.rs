use std::rc::Rc;

use bitflags::bitflags;

/// Return whether a basename names a Python executable or runtime library.
#[must_use]
pub fn is_python_runtime_basename(name: &str) -> bool {
    crate::is_python_module(name)
}

/// Address space containing a native instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressSpace {
    /// User-space instruction.
    User,
    /// Kernel-space instruction.
    Kernel,
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
    /// Per-frame classification flags attached to every [`Frame`].
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

    }
}

/// Optional source positions reported by CPython.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PythonSourceLocation {
    /// Starting line number. CPython may use zero for artificial instructions.
    pub line: Option<u32>,
    /// Ending line number, when available.
    pub end_line: Option<u32>,
    /// Zero-based starting column offset in UTF-8 bytes.
    pub column: Option<u32>,
    /// Zero-based ending column offset in UTF-8 bytes.
    pub end_column: Option<u32>,
}

/// A resolved Python frame.
///
/// Produced from a CPython perf-map entry (with `PYTHONPERFSUPPORT=1`) plus
/// any inlined source-position info CPython provides. `Rc<str>` is used for
/// the file and function strings so identical entries from repeated samples
/// share one allocation across a profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PythonFrame {
    /// Source file as recorded by CPython. May be absolute, relative, or a
    /// pseudo-path such as `<frozen importlib._bootstrap>`.
    file_name: Rc<str>,
    /// Source position information for the frame (line/column ranges).
    pub location: PythonSourceLocation,
    /// Resolved function or method name.
    pub func_name: Rc<str>,
    /// Last executed bytecode opcode, if available.
    pub opcode: Option<u8>,
    /// Classification flags for this frame.
    pub flags: FrameFlags,
    basename_start: usize,
}

impl PythonFrame {
    /// Construct a resolved Python frame.
    #[must_use]
    pub fn new(file_name: impl Into<Rc<str>>, func_name: impl Into<Rc<str>>) -> Self {
        let file_name = file_name.into();
        let basename_start = basename_start(&file_name);
        Self {
            file_name,
            location: PythonSourceLocation::default(),
            func_name: func_name.into(),
            opcode: None,
            flags: FrameFlags::empty(),
            basename_start,
        }
    }

    /// Borrow the source file recorded by CPython.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Borrow the shared source filename without copying it.
    #[must_use]
    pub fn file_name_rc(&self) -> &Rc<str> {
        &self.file_name
    }

    /// Set classification flags for this frame.
    #[must_use]
    pub fn with_flags(mut self, flags: FrameFlags) -> Self {
        self.flags = flags;
        self
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
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
/// frames are expanded. The innermost callee is listed first; its
/// [`Self::inline_depth`] is the largest and decreases toward the outer frame.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeSymbol {
    /// Demangled symbol name (function/method).
    name: Rc<str>,
    /// Source position information, when available.
    pub source: SourceLocation,
    /// Display name of the owning module (binary or shared library).
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
    inline_depth: u32,
    /// Whether this symbol is the CPython bytecode evaluation loop.
    is_eval_frame: bool,
    /// Whether default views should hide this symbol (matches
    /// [`FrameFlags::HIDDEN_DEFAULT`] semantics).
    is_hidden_by_default: bool,
}

impl NativeSymbol {
    /// Construct a symbol with unknown source positions and zero function offset.
    #[must_use]
    pub fn new(name: impl Into<Rc<str>>, module: impl Into<Rc<str>>) -> Self {
        let name = name.into();
        Self {
            is_eval_frame: crate::symbols::is_eval_frame(&name),
            name,
            source: SourceLocation::default(),
            module: module.into(),
            offset: 0,
            inline_depth: 0,
            is_hidden_by_default: false,
        }
    }

    /// Set the available source positions.
    #[must_use]
    pub fn with_source(mut self, source: SourceLocation) -> Self {
        self.source = source;
        self
    }

    /// Set the instruction's byte offset within its enclosing function.
    #[must_use]
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }

    /// Mark this symbol as hidden in default views.
    #[must_use]
    pub fn hidden_by_default(mut self) -> Self {
        self.is_hidden_by_default = true;
        self
    }

    /// Borrow the demangled symbol name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Borrow the shared demangled symbol name without copying it.
    #[must_use]
    pub fn name_rc(&self) -> &Rc<str> {
        &self.name
    }

    /// Nesting depth within an innermost-first inline chain.
    #[must_use]
    pub const fn inline_depth(&self) -> u32 {
        self.inline_depth
    }

    /// Whether this symbol is the CPython bytecode evaluation loop.
    #[must_use]
    pub const fn is_eval_frame(&self) -> bool {
        self.is_eval_frame
    }

    /// Whether default views should hide this symbol.
    #[must_use]
    pub const fn is_hidden_by_default(&self) -> bool {
        self.is_hidden_by_default
    }

    pub(crate) fn set_inline_depth(&mut self, depth: usize) {
        self.inline_depth = u32::try_from(depth).unwrap_or(u32::MAX);
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
/// Carries the raw program counter plus whatever symbol metadata was recovered
/// (or `None` when address-only).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeFrame {
    /// Absolute program counter sampled from the target.
    pub pc: u64,
    /// Resolved symbol, if symbolization succeeded.
    pub symbol: Option<NativeSymbol>,
    /// High-level category: native, kernel, or unknown.
    pub address_space: AddressSpace,
    /// Where the symbol info came from (ELF, perf-map, kallsyms, address-only).
    pub origin: SymbolOrigin,
    /// Classification flags shared with [`PythonFrame`] consumers.
    pub flags: FrameFlags,
}

impl NativeFrame {
    /// Build an address-only [`NativeFrame`] for an IP that could not be
    /// symbolized. `address_space` is set to [`AddressSpace::User`] and `origin` to
    /// [`SymbolOrigin::AddressOnly`].
    #[must_use]
    pub fn from_address(pc: u64) -> Self {
        Self {
            pc,
            symbol: None,
            address_space: AddressSpace::User,
            origin: SymbolOrigin::AddressOnly,
            flags: FrameFlags::empty(),
        }
    }

    /// Borrow the resolved symbol name without allocating.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.symbol.as_ref().map(NativeSymbol::name)
    }

    /// Whether the owning module is the Python runtime.
    #[must_use]
    pub fn is_python_runtime(&self) -> bool {
        self.flags.contains(FrameFlags::PYTHON_RUNTIME)
    }
}

/// A resolved frame from a profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Frame {
    /// Python frame.
    Python(PythonFrame),
    /// Native, kernel, or address-only frame.
    Native(NativeFrame),
    /// The captured stack bytes ended before the stack root.
    TruncatedStack,
}

impl Frame {
    /// Borrow the resolved name without allocating.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Python(frame) => Some(&frame.func_name),
            Self::Native(frame) => frame.name(),
            Self::TruncatedStack => Some("<stack truncated>"),
        }
    }
}

impl std::fmt::Display for PythonFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.func_name)
    }
}

impl std::fmt::Display for NativeFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name() {
            Some(name) => formatter.write_str(name),
            None => write!(formatter, "<0x{:x}>", self.pc),
        }
    }
}

impl std::fmt::Display for Frame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Python(frame) => formatter.write_str(&frame.func_name),
            Self::Native(frame) => frame.fmt(formatter),
            Self::TruncatedStack => formatter.write_str("<stack truncated>"),
        }
    }
}

/// Owner-qualified identity of a resolved frame, never reused by its symbolizer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FrameKey {
    pub(crate) owner: u64,
    pub(crate) serial: u64,
}

/// Borrowed resolved frames for one sampled stack.
#[derive(Clone, Debug)]
pub struct ResolvedStack<'a> {
    pub(crate) frames: &'a [Frame],
    pub(crate) frame_ids: &'a [FrameKey],
    pub(crate) indices: &'a [usize],
    pub(crate) cacheable: bool,
}

impl<'a> ResolvedStack<'a> {
    /// Number of resolved frames, including inline expansions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Whether the stack contains no resolved frames.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Whether symbol-derived values may be cached until the next invalidation.
    #[must_use]
    pub fn is_cacheable(&self) -> bool {
        self.cacheable
    }

    /// Iterate over owner-qualified frame keys and their frames.
    pub fn iter(&self) -> ResolvedStackIter<'a> {
        ResolvedStackIter {
            frames: self.frames,
            frame_ids: self.frame_ids,
            indices: self.indices.iter(),
        }
    }

    /// Iterate over frames without their cache keys.
    pub fn frames(
        &self,
    ) -> impl ExactSizeIterator<Item = &'a Frame> + DoubleEndedIterator + std::iter::FusedIterator
    {
        let frames = self.frames;
        self.indices.iter().map(move |&index| &frames[index])
    }
}

/// Iterator over a resolved stack's frame keys and borrowed frames.
#[derive(Clone, Debug)]
pub struct ResolvedStackIter<'a> {
    frames: &'a [Frame],
    frame_ids: &'a [FrameKey],
    indices: std::slice::Iter<'a, usize>,
}

impl<'a> Iterator for ResolvedStackIter<'a> {
    type Item = (FrameKey, &'a Frame);

    fn next(&mut self) -> Option<Self::Item> {
        let &index = self.indices.next()?;
        Some((self.frame_ids[index], &self.frames[index]))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.indices.size_hint()
    }
}

impl DoubleEndedIterator for ResolvedStackIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let &index = self.indices.next_back()?;
        Some((self.frame_ids[index], &self.frames[index]))
    }
}

impl ExactSizeIterator for ResolvedStackIter<'_> {}
impl std::iter::FusedIterator for ResolvedStackIter<'_> {}

impl<'a> IntoIterator for ResolvedStack<'a> {
    type Item = (FrameKey, &'a Frame);
    type IntoIter = ResolvedStackIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &ResolvedStack<'a> {
    type Item = (FrameKey, &'a Frame);
    type IntoIter = ResolvedStackIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Byte offset of the basename within `path`.
///
/// Returns the index of the first character after the last `/`, or `0` if
/// `path` has no separators. UTF-8 safe because `/` cannot appear inside a
/// multi-byte sequence.
#[inline]
#[must_use]
pub(crate) fn basename_start(path: &str) -> usize {
    memchr::memrchr(b'/', path.as_bytes()).map_or(0, |i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_collection_has_independent_double_ended_iterators() {
        let frames = [
            Frame::Native(NativeFrame::from_address(1)),
            Frame::TruncatedStack,
        ];
        let ids = [
            FrameKey {
                owner: 1,
                serial: 0,
            },
            FrameKey {
                owner: 1,
                serial: 1,
            },
        ];
        let resolved = ResolvedStack {
            frames: &frames,
            frame_ids: &ids,
            indices: &[1, 0, 1],
            cacheable: true,
        };
        let mut iter = resolved.iter();
        assert_eq!(iter.next().unwrap(), (ids[1], &frames[1]));
        assert_eq!(iter.next_back().unwrap(), (ids[1], &frames[1]));
        assert_eq!(iter.len(), 1);
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved.frames().count(), 3);
        assert_eq!(iter.next().unwrap(), (ids[0], &frames[0]));
        assert!(iter.next().is_none());
        assert!(iter.next_back().is_none());
    }

    #[test]
    fn native_symbol_construction_reuses_shared_strings() {
        let name: Rc<str> = "_PyEval_EvalFrameDefault".into();
        let module: Rc<str> = "/usr/bin/python3".into();
        let file: Rc<str> = "Python/ceval.c".into();
        let source = SourceLocation {
            file: Some(Rc::clone(&file)),
            line: Some(42),
            ..SourceLocation::default()
        };
        let allocations = allocation_counter::measure(|| {
            let symbol = NativeSymbol::new(Rc::clone(&name), Rc::clone(&module))
                .with_source(source)
                .with_offset(17)
                .hidden_by_default();
            assert!(Rc::ptr_eq(symbol.name_rc(), &name));
            assert!(Rc::ptr_eq(&symbol.module, &module));
            assert!(Rc::ptr_eq(symbol.source.file.as_ref().unwrap(), &file));
            assert_eq!(symbol.source.line, Some(42));
            assert_eq!(symbol.offset, 17);
            assert!(symbol.is_eval_frame());
            assert!(symbol.is_hidden_by_default());
        });
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn python_frame_basename_handles_long_utf8_path() {
        let path = format!("{}é/leaf.py", "a".repeat(65_534));
        let frame = PythonFrame::new(path.as_str(), "f");

        assert_eq!(frame.basename(), "leaf.py");
    }

    #[test]
    fn native_symbol_basename_follows_mutated_module_path() {
        let mut symbol = NativeSymbol::new("f", "/old/f.so");
        symbol.module = "new.so".into();

        assert_eq!(symbol.module_basename(), "new.so");
    }
}
