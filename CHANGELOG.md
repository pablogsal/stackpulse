# Changelog

## 0.2.0 - 2026-07-18

### Fixed

- ELF image-base correlation accepts legitimate page-rounded load-segment tails while rejecting ambiguous shared boundary pages.
- Process-image changes, overlapping executable remaps, and lost perf lifecycle records now rebuild stale module and Framehop state.
- Exact-address DSO reuse and partial `MAP_FIXED` replacements now retain correct module generations and surviving VMA fragments.
- LOST recovery now runs at a forward event boundary, rescans every tracked image, and repairs missed child/thread bookkeeping.
- Thread-group leader exit no longer tears down profiling state while sibling threads are still running.
- Exited process perf and pidfd state is released promptly, preventing descriptor exhaustion under process churn.
- 32-bit perf register samples no longer enter the native 64-bit unwinder.
- Transient and deleted mapped ELF files can be retried and opened through `/proc/<pid>/map_files` while the target is alive.
- Unresolved or invalid image bases no longer poison symbol caches or produce wrapped AVMA/SVMA translations.
- Live native unwinding now consumes canonical assigned module IDs instead of aliasing unrelated ELF files through ID zero.
- Device and inode-generation identity are retained across MMAP2 events, profile files, and symbolizer reuse.
- vDSO mappings now provide ELF unwind information when the target mapping is readable.
- Attaching waits for the complete thread group to stop and resumes only processes Stackpulse stopped itself.

### Performance

- Perf recording no longer requests non-executable MMAP traffic that Stackpulse does not consume.
- Sampling counters share bounded output rings instead of allocating a full mmap ring for every CPU/task pair.
- Repeated mappings of the same ELF reuse symbolizer state, keeping high-churn `dlopen` workloads bounded.

### Changed

- `ModuleRecord` now exposes device and inode-generation identity for mapped files.
- New profiles use spool format `SPULSE3`; the reader remains compatible with `SPULSE1` and `SPULSE2` profiles.

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
