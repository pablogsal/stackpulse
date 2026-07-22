# Changelog

## 0.5.2 - 2026-07-22

### Fixed

- Deleted executable mappings created by libhugetlbfs reuse a byte-validated, identity-pinned main-executable image for live DWARF unwinding and, while its original UTF-8 executable path remains available, replay symbolization. This retains the original `PT_LOAD` offset discarded by the hugepage copy.

### Changed

- New profiles use spool format `SPULSE4` to retain separate mapped and symbol-source identities. The 0.5.2 reader remains compatible with `SPULSE1`, `SPULSE2`, and `SPULSE3` profiles; older readers cannot open `SPULSE4` profiles.

## 0.5.1 - 2026-07-21

### Fixed

- ELF image-base correlation preserves valid page-rounded executable mapping tails when a following `PT_LOAD` begins in the shared file page, retains mappings made executable with `mprotect`, and rejects ambiguous shared-page heads.
- Empty or overflowing ELF file ranges no longer participate in load-segment correlation, and overflowing module-relative addresses remain unassociated during both recording and spool replay.
- User samples without usable unwind registers can recover missed mappings from their sampled instruction pointer without treating hypervisor or guest addresses as host user addresses.

## 0.5.0 - 2026-07-20

### Changed

- The doc-hidden benchmark API now requires the non-default `bench-support` feature, and benchmark fixtures are generated through the current `SPULSE3` writer instead of a duplicate legacy encoder.
- `PerfSymbolizerBuilder` replaces the combinatorial symbolizer constructors; spool samples and Python-runtime records now use names that match their contents; native source fields are grouped under `SourceLocation`; and `ModuleImageBase` exposes only checked address translation.
- Removed the unused public `Error` wrapper. Internal ELF parsing continues to preserve the affected path and parser source inside an `InvalidData` I/O error.

## 0.4.0 - 2026-07-19

### Fixed

- Launched commands honor their configured `PATH`, stop recording promptly when they exit, and preserve their real exit status.
- Valid user-stack sizes are aligned for perf, unsupported guest sampling is retried without guest events, and sparse CPU identifiers are preserved when sysfs is unavailable.
- Events from multiple rings retain previous-round ordering; lost-event totals include every event, unchanged mappings survive loss recovery, and exited-process event descriptors are retired.
- Mixed kernel/user callchains preserve each context's activation address, and DWARF recording no longer splices in an incompatible perf user callchain.
- Invalid or unusable `.eh_frame_hdr` indexes fall back to Framehop's existing `.eh_frame` index construction instead of losing valid unwind data.
- Perf-map symbols keep their declared ranges, accept perf's ASCII field separators, cover perf's anonymous/no-DSO mapping classes, and no longer override known file-backed modules.
- Kernel symbols use perf's type, ignored-label, and equal-address selection rules in both full and sparse loading.
- Proc-map pathnames remain verbatim, including literal ` (deleted)` suffixes, and pinned frames resolve modules by stable ID rather than vector position.
- Final profile-write failures are reported, unknown Python positions retain their documented sentinel, and Gecko output no longer labels Python frames as JavaScript.

### Changed

- The minimum supported kernel is Linux 6.0; no compatibility path is provided for older kernels.

## 0.3.0 - 2026-07-18

### Fixed

- Perf output rings retain a live poll anchor after their owning task exits, preventing high-frequency samples from waiting on the periodic drain timeout.
- Ring-buffer sizing uses the runtime page size instead of assuming 4 KiB pages.
- Attach success now reports resume failures instead of silently leaving a target stopped.
- Hardware-to-software event fallback is limited to unavailable hardware counters and preserves unrelated OS errors.
- Repeated attachment to the same process generation is idempotent instead of opening duplicate counters.
- Process snapshots verify the leader identity after thread enumeration, closing a PID-reuse race.
- Thread enumeration propagates directory-entry errors instead of returning a partial snapshot.

### Changed

- `Error` is non-exhaustive and replaces the stringly `RuntimeError` variant with `ElfParse(ElfParseError)`, which exposes the affected path and preserves the parser source chain; the unused public `Result` alias was removed.
- Perf events now use one fixed-CPU member representation and one bounded output ring per CPU.
- Removed unused hidden live-recording benchmark helpers.

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
