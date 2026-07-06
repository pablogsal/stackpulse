# Changelog

## 0.1.4 - 2026-07-06

### Fixed

- Perf-mode native unwinding now resolves ELF image bases correctly for large executable mappings that span multiple load segments.
- Perf-mode module tracking now reconciles executable mappings from `/proc/<pid>/maps` when a sampled user address is not covered by the current module table.

## 0.1.3 - 2026-07-06

### Fixed

- Kernel frames resolve more reliably when kernel symbol data is sparse or only partially available.
- Truncated user stacks are reported consistently when perf samples are missing user-register state or contain a truncated user callchain tail.
- Missing user-register samples are counted separately as `NativeUserRegistersMissing` instead of being grouped with generic register-capture failures.

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
