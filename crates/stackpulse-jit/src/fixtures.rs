//! Source fixtures for consumer JIT tests.

/// GNU assembler source for a Linux x86-64 function with configurable CFI.
///
/// Write this to a `.S` file and compile it with `cc`. Define `FUNCTION_NAME`
/// (default `first`) and `CFA_OFFSET` (zero omits CFI). `ZERO_SIZE_ALIASES`
/// adds aliases for symbol-range tests.
pub const GDB_JIT_OVERLAY_SOURCE: &str = include_str!("tests/overlay.S");
