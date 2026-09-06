# Configuration and integration

Use `Recorder::builder(rate)` with a validated `SampleRate`. Select stack bytes,
ring-buffer capacity, kernel inclusion, `ProcessScope`, attach policy, and
publication interval before `attach` or `prepare`. `attach_writer` accepts any
`Write` implementation and does not expose a file-reader capability.

Metadata records the initial nominal sampling rate and its `Duration` interval.
It is not a claim that every perf counter has one globally effective rate:
newly opened counters can encounter a different kernel limit.

`pause` and `resume` preserve the desired capture state when additional threads
or processes are attached. `poll` performs bounded reconciliation. Its activity
summary is an observation of external processes, not a race-free process-tree
snapshot.

A `process::Process` handle opens a pidfd. Its polling and signals refer to that
process identity even after the numeric PID is reused. Process discovery is a
best-effort snapshot of a changing tree.

# Native backends

A backend implements `NativeSymbolizer` with its own associated error type.
Use `batch.lookups()` for bulk preparation and `batch.entries()` to fill paired
results. Empty `NativeSymbols` is unresolved. `From<NativeSymbol>`,
`FromIterator<NativeSymbol>`, `AsRef`, and `IntoIterator` support ordinary Rust
collection code without allocating for zero or one symbol.

A backend's `refresh` generation must remain changed until the session observes
it successfully. An edge-triggered boolean loses notifications when another
backend fails during the same update. Return backend errors directly so their
sources remain available.
