StackPulse records Linux CPU stack samples and resolves native, Python, JIT,
and kernel frames. Capture writes a compact spool; consumers can replay a
finished recording or process published batches while capture continues.

# Record and replay

```rust,no_run
use std::fs::File;
use std::time::{Duration, Instant};
use stackpulse::{Pid, Recorder, SampleRate, Snapshot, Spool};
# fn run(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
let mut recorder = Recorder::builder(SampleRate::hz(99)?)
    .stack_size(60 * 1024)
    .attach(Pid::try_from(pid)?, Spool::retained(File::create("profile.spool")?)?)?;

let deadline = Instant::now() + Duration::from_secs(10);
while Instant::now() < deadline {
    let activity = recorder.poll(Duration::from_millis(100))?;
    if activity.active_processes() == 0 && !activity.pending_events() {
        break;
    }
}
recorder.finish()?;

let recording = Snapshot::open("profile.spool")?;
let mut symbols = recording.symbolizer().build()?;
for sample in recording.samples() {
    let stack = symbols.resolve(sample.stack())?;
    for frame in stack.frames() {
        println!("{frame}");
    }
}
# Ok(())
# }
```

# Public modules

| Module | Responsibility |
| --- | --- |
| [`record`] | Recorder configuration, preparation, progress, diagnostics, and completion errors. |
| [`process`] | Validated IDs, child launching, identity-bound process handles, and discovery. |
| [`spool`] | Storage policy, publication-aware live readers, replay, samples, and raw stacks. |
| [`symbolize`] | Source-bound resolution, live sessions, transformed stack caches, and native backends. |
| [`profile`] | Resolved frame collections, frame identities, and symbol/source metadata. |

A [`spool::Sample`] is one observation with a PID, TID, monotonic timestamp,
optional correlated wall time, and an interned [`spool::Stack`]. Its stack
contains raw frames joined with the mappings recorded for that process.
[`profile::ResolvedStack`] is a repeatable borrowed collection; `frames()`
yields frames and `iter()` yields their owner-qualified cache keys as well.

# Live processing

A recorder creates one [`LiveReader`] through `take_reader()`. Move the reader
into your replay worker, then build its symbolization session there. Capture
continues on the recording thread. Polling the recorder services its configured
publication interval; StackPulse does not create a background capture thread.

```rust,no_run
use std::time::Duration;
use stackpulse::{LiveReader, ReadStatus};
# fn replay(reader: &mut LiveReader) -> Result<(), Box<dyn std::error::Error>> {
let mut session = reader.symbolizer().build()?;
loop {
    match session.poll(Duration::from_millis(100))? {
        ReadStatus::Batch(mut batch) => {
            for sample in batch.samples() {
                for frame in batch.resolve(sample.stack())?.frames() {
                    println!("{frame}");
                }
            }
        }
        ReadStatus::Pending => {}
        ReadStatus::Finished(_) => break,
    }
}
# Ok(())
# }
```

A batch borrows its session exclusively. Finish using its samples and resolved
frames before polling again. The session applies symbol updates before exposing
samples, and checks fallible native refreshes before advancing the reader.

`Spool::retained(file)` preserves replay from the beginning.
`Spool::disposable(file)` authorizes the linked reader to reclaim complete
pages from the preceding delivered batch when it advances. Unsupported hole
punching is remembered; other reclamation errors are returned before advancing.
Drive the reader through `Finished` to reclaim the final batch. Dropping a batch
does not perform filesystem I/O.

[`ReadStatus::Pending`] means temporary exhaustion. `Finished` means the
producer finished successfully and all published data has been consumed.
Abandoned or failed recording returns an error after its valid published
prefix. An external [`Tail`] has no producer completion channel and must be
driven according to the external writer's lifecycle.

# Prepared stack values

Use `session.cache_stacks::<T>(capacity)` when your collector can reuse a
prepared representation. StackPulse owns the bounded cache, process
invalidation, and the rule that provisional resolutions cannot be retained.
A zero capacity disables storage.

```rust,no_run
use stackpulse::{LiveReader, ReadStatus};
use stackpulse::symbolize::StackEntry;
use std::time::Duration;
# fn replay(reader: &mut LiveReader) -> Result<(), Box<dyn std::error::Error>> {
let mut session = reader.symbolizer().build()?.cache_stacks::<Vec<String>>(4096);
if let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO)? {
    for sample in batch.samples() {
        match batch.entry(sample.stack())? {
            StackEntry::Occupied(value) => println!("{value:?}"),
            StackEntry::Vacant(entry) => {
                let resolved = entry.resolve()?;
                let value = resolved.stack().frames().map(ToString::to_string).collect();
                let prepared = resolved.insert(value);
                println!("{:?}", &*prepared);
            }
        }
    }
}
# Ok(())
# }
```

On a miss, callers may inspect resolved frames and reject a sample before
allocating their prepared value. `insert` returns a guard borrowing a cached
value or owning a transient value. Cache hits do not resolve symbols.

The cache bounds its stored values, not a collector's independent handle arena.
Before resetting such an arena, flush pending samples, call `batch.clear_cache()`,
and reset the collector. Consume an outstanding vacant entry with `into_stack()`
to release its borrow before that sequence, then reacquire the entry.

# Native symbolization

Supply `native(factory)` or `try_native(factory)` to replace the optional
built-in backend. [`symbolize::NativeSymbolizer`] receives a
[`symbolize::NativeBatch`] with immutable lookup requests and paired mutable
results. Return a persistent generation from `refresh()` when previously
resolved symbols may have changed. The live session invalidates affected
processes before callers can reuse their prepared stacks.

[`symbolize::NativeImage`] retains an open file and implements `AsFd`; use
`proc_path()` for engines that require a path. Keep the image owner alive while
using its descriptor or path. Mapping retirement does not invalidate another
mapping's retained image owner. File identity does not promise immutable file
contents.

Native filesystem paths preserve operating-system bytes. Python source names
remain strings because they may be pseudo-filenames rather than filesystem
paths. Native runtime classification and default visibility are independent.
Truncation is [`profile::Frame::TruncatedStack`], not an address-only frame.

# Frame metadata

Construct symbols from their name and module; attach source positions and offsets
when available. Shared `Rc<str>` inputs retain their existing string allocations.

```rust
use stackpulse::profile::{NativeSymbol, PythonFrame, PythonSourceLocation, SourceLocation};

let symbol = NativeSymbol::new("evaluate", "libpython.so")
    .with_source(SourceLocation { line: Some(42), ..Default::default() })
    .with_offset(16);

let mut frame = PythonFrame::new("worker.py", "run");
frame.location = PythonSourceLocation {
    line: Some(42),
    column: Some(0),
    ..Default::default()
};
assert!(!symbol.is_hidden_by_default());
```

Python positions use `None` for unknown coordinates and zero-based byte columns.
Native source columns retain their separate one-based convention. Borrowed frame
accessors expose strings without copying; shared string accessors allow collectors
to retain the same allocation after the resolved stack borrow ends.

# Errors and resources

`recorder.last_poll()` returns the previous poll summary without performing I/O.
`record::max_sample_rate()` returns `io::Result<u64>` so callers can propagate a
failed kernel-limit read or explicitly choose a fallback.

[`Error`] preserves a category, source, and available OS/frequency-limit details.
[`record::FinishError`] retains final recording counters and the cleanup error
chain. A terminal writer failure prevents new records; a custom writer can
still perform its own work during `Drop`. Live readers only consume successfully
published complete-record offsets.

Disk reclamation does not reclaim the decoded definition tables needed by later
samples. Observe reader statistics when operating long-running recordings.
Linux perf permissions and kernel symbol visibility remain host requirements.
