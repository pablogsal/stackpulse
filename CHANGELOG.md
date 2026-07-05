# Changelog

## 0.1.2 - 2026-07-05

### Fixed

- Recording and profile reads are more resilient to malformed ELF data and truncated spool files.
- Truncated stack markers are preserved when reading and symbolizing profiles.
- Child and forked process profiling is more reliable and respects live kernel perf frequency limits.
- Symbolization works correctly when called from inside an existing Tokio runtime.
- Kernel symbolization handles malformed or unavailable kernel symbol data more gracefully.
- `NativeSymbol::offset` and `inline_depth` documentation now match their actual meanings.

### Changed

- Examples, tutorials, API docs, and reference docs were updated for the current recorder and symbolizer behavior.

### Performance

- Perf event draining and symbolization are faster on repeated or high-volume profiles.
