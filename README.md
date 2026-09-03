<div align="center">
  <img src="https://raw.githubusercontent.com/pablogsal/stackpulse/main/.github/pages/stackpulse-logo.png" alt="StackPulse crab serving a stack of pancakes" width="325"><br>
  A Rust library for building Linux profilers with <code>perf_event</code>.<br>
  <a href="https://pablogsal.com/stackpulse/"><strong>Documentation</strong></a><br><br>
  <a href="https://github.com/pablogsal/stackpulse/actions/workflows/ci.yml"><img src="https://github.com/pablogsal/stackpulse/actions/workflows/ci.yml/badge.svg?branch=main" alt="Checks"></a>
  <a href="https://app.codecov.io/github/pablogsal/stackpulse"><img src="https://codecov.io/gh/pablogsal/stackpulse/graph/badge.svg?branch=main" alt="Coverage"></a>
  <a href="https://app.codspeed.io/pablogsal/stackpulse"><img src="https://img.shields.io/endpoint?url=https://codspeed.io/badge.json" alt="CodSpeed"></a>
  <a href="https://crates.io/crates/stackpulse"><img src="https://img.shields.io/crates/v/stackpulse.svg" alt="crates.io"></a>
  <a href="https://docs.rs/stackpulse"><img src="https://docs.rs/stackpulse/badge.svg" alt="docs.rs"></a>
</div>

StackPulse records CPU stack samples from Linux processes and writes them to a
compact file. Profiles can be replayed after capture or tailed incrementally
while recording. StackPulse resolves native, Python, JIT, and kernel frames
into names and source locations for your profiler.

StackPulse is a library, not a command-line tool, and it requires Linux 6.0 or
newer.

## Install

```toml
[dependencies]
stackpulse = "0.9"
```

## Record a profile

Attach to a running process or launch one under the recorder. While the target
runs, call `poll` to drain samples into a spool file. Open that file with
`Snapshot`, then pass its stacks to `Symbolizer`. The resulting frames are
ready for your aggregator, UI, or exporter.

For example, to record for ten seconds and read back one stack:

```rust,no_run
use std::time::{Duration, Instant};

use stackpulse::{AttachMode, Pid, Recorder, RecorderOptions, SampleRate, Snapshot};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_pid: u32 = std::env::args().nth(1).expect("pid").parse()?;
    let pid = Pid::try_from(raw_pid)?;

    let mut recorder = Recorder::attach(
        pid,
        "profile.spool",
        AttachMode::StopWhileAttaching,
        RecorderOptions::new(SampleRate::hz(99)?).stack_size(60 * 1024),
    )?;

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && recorder.process_is_active(pid)? {
        recorder.poll(Duration::from_millis(100))?;
    }
    recorder.finish()?;

    let reader = Snapshot::open("profile.spool")?;
    let mut symbolizer = reader.symbolizer().build()?;

    if let Some(stack) = reader.stacks().next() {
        for frame in symbolizer.resolve(stack)? {
            println!("{}", frame.display_name());
        }
    }

    Ok(())
}
```

Read the [hosted documentation](https://pablogsal.com/stackpulse/) or build it
locally with `make doc`.

## Support

| Capability | Support |
| --- | --- |
| Operating system | Linux 6.0 or newer |
| Architectures | x86-64 and AArch64 |
| Native stacks | DWARF and frame-pointer unwinding through Framehop |
| Native symbols | Bundled `wholesym` backend or a caller-supplied symbolizer |
| Dynamic runtimes | Python perf maps and Python runtime frames |
| Kernel stacks | `/proc/kallsyms` and `System.map` fallback |
| Profile files | Reads and writes SPULSE3 |
| Rust version | 1.88 or newer |

## Development

```sh
make check          # cargo check
make test           # unit tests
make fmt            # format the crate
make fmt-check      # verify formatting
make clippy         # lint with warnings as errors
make coverage       # terminal coverage summary
make coverage-html  # HTML coverage report
make ci             # run the local quality gate
```

If the coverage helper is missing, `make coverage` prints the install command.

You can pass extra cargo flags through `CARGO_FLAGS`:

```sh
make test CARGO_FLAGS="--features debuginfod"
make coverage CARGO_FLAGS="--features debuginfod"
```

## Cargo features

| Feature | Default | Provides |
| --- | --- | --- |
| `builtin-wholesym` | Yes | Native symbolization through `wholesym` and Tokio |
| `debuginfod` | No | Remote debug-file lookup when `DEBUGINFOD_URLS` is set |
| `bench-support` | No | Hidden synthetic fixtures used by the benchmark suite |

Consumers that supply `SymbolizerBuilder::native` can disable default features
to omit `wholesym` and Tokio.

Two environment variables tune the default backend: `STACKPULSE_DEBUG_DIRS`
overrides local debug-file search roots, and
`STACKPULSE_DEBUGINFOD_CACHE_DIR` overrides the debuginfod cache directory.

## Permissions

User-space sampling often works with the default perf permissions. Kernel frames,
high sample rates, and restrictive `perf_event_paranoid` settings may require
`CAP_PERFMON` or a sysctl change.

## License

Licensed under the MIT license.
