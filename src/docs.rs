//! Task-oriented StackPulse documentation.

/// Tutorials for attaching, startup capture, and stack aggregation.
#[doc = include_str!("../docs/tutorials.md")]
pub mod tutorials {}

/// Recipes for configuration, child processes, symbols, and diagnostics.
#[doc = include_str!("../docs/how-to.md")]
pub mod how_to {}

/// Complete type, option, feature, and format-invariant reference.
#[doc = include_str!("../docs/reference.md")]
pub mod reference {}

/// Design rationale for sampling, unwinding, module tracking, and overhead.
#[doc = include_str!("../docs/explanation.md")]
pub mod explanation {}

/// The stable SPULSE file-format contract and compatibility policy.
#[doc = include_str!("../docs/spool-format.md")]
pub mod spool_format {}
