use std::rc::Rc;
use std::sync::Arc;

use bitflags::bitflags;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    Python,
    Native,
    Kernel,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolOrigin {
    Elf,
    PerfMap,
    KernelSymbols,
    AddressOnly,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FrameFlags: u32 {
        const PYTHON_RUNTIME = 1 << 0;
        const PYTHON_EVAL = 1 << 1;
        const HIDDEN_DEFAULT = 1 << 2;
        const JIT = 1 << 3;
        const ANONYMOUS = 1 << 4;
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocationInfo {
    pub lineno: i32,
    pub end_lineno: i32,
    pub column: i32,
    pub end_column: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonFrame {
    pub file_name: Rc<str>,
    pub location: LocationInfo,
    pub func_name: Rc<str>,
    pub opcode: Option<u8>,
    pub is_entry: bool,
    pub basename_start: u16,
}

impl PythonFrame {
    #[must_use]
    pub fn new(
        file_name: &str,
        location: LocationInfo,
        func_name: &str,
        opcode: Option<u8>,
        is_entry: bool,
    ) -> Self {
        let basename_start = memchr::memrchr(b'/', file_name.as_bytes())
            .map_or(0, |i| u16::try_from(i + 1).unwrap_or(u16::MAX));
        Self {
            file_name: file_name.into(),
            location,
            func_name: func_name.into(),
            opcode,
            is_entry,
            basename_start,
        }
    }

    #[inline]
    #[must_use]
    pub fn basename(&self) -> &str {
        &self.file_name[self.basename_start as usize..]
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceLocation {
    pub file: Option<Rc<str>>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub function_start_line: Option<u32>,
    pub function_start_column: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSymbol {
    pub name: Rc<str>,
    pub file: Option<Rc<str>>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub function_start_line: Option<u32>,
    pub function_start_column: Option<u32>,
    pub module: Rc<str>,
    pub module_basename_start: u16,
    pub file_basename_start: u16,
    pub offset: u64,
    pub is_eval_frame: bool,
    pub should_ignore: bool,
}

impl NativeSymbol {
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
        let module_basename_start = basename_start(&module);
        let file_basename_start = source.file.as_deref().map_or(0, basename_start);
        Self {
            name: name.into(),
            file: source.file,
            line: source.line,
            column: source.column,
            function_start_line: source.function_start_line,
            function_start_column: source.function_start_column,
            module,
            module_basename_start,
            file_basename_start,
            offset,
            is_eval_frame,
            should_ignore,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFrame {
    pub pc: u64,
    pub sp: u64,
    pub symbol: Option<NativeSymbol>,
    pub is_python_runtime: bool,
    pub kind: FrameKind,
    pub origin: SymbolOrigin,
    pub flags: FrameFlags,
}

impl NativeFrame {
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

    #[must_use]
    pub fn func_name(&self) -> String {
        self.symbol
            .as_ref()
            .map_or_else(|| format!("<0x{:x}>", self.pc), |s| s.name.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedFrame {
    Python(PythonFrame),
    Native(NativeFrame),
}

impl ResolvedFrame {
    #[must_use]
    pub fn func_name(&self) -> String {
        match self {
            Self::Python(frame) => frame.func_name.to_string(),
            Self::Native(frame) => frame.func_name(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStack {
    pub frames: Arc<[ResolvedFrame]>,
}

impl ResolvedStack {
    #[must_use]
    pub fn with_frames(frames: Vec<ResolvedFrame>) -> Self {
        Self {
            frames: Arc::from(frames.into_boxed_slice()),
        }
    }
}

pub type StackFrames = Arc<[ResolvedFrame]>;

#[inline]
#[must_use]
pub fn basename_start(path: &str) -> u16 {
    path.as_bytes()
        .iter()
        .rposition(|&b| b == b'/')
        .map_or(0, |i| u16::try_from(i + 1).unwrap_or(u16::MAX))
}
