#![doc = include_str!("../docs/tutorials.md")]
#![doc = include_str!("../docs/how-to.md")]
#![doc = include_str!("../docs/reference.md")]
#![doc = include_str!("../docs/explanation.md")]
#![doc = include_str!("../docs/spool-format.md")]

// Preserve the old documentation paths without listing them as API modules.
#[doc(hidden)]
pub mod tutorials {}

#[doc(hidden)]
pub mod how_to {}

#[doc(hidden)]
pub mod reference {}

#[doc(hidden)]
pub mod explanation {}

#[doc(hidden)]
pub mod spool_format {}
