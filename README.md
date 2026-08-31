<div align="center">
  <img src="https://raw.githubusercontent.com/pablogsal/stackpulse/main/.github/pages/stackpulse-logo.jpg" alt="StackPulse crab serving a stack of pancakes" width="325"><br>
  Linux <code>perf_event</code> stack sampling, native unwinding, symbolization,
  and compact profile spooling.<br>
  <a href="https://pablogsal.com/stackpulse/"><strong>Documentation</strong></a><br><br>
  <a href="https://github.com/pablogsal/stackpulse/actions/workflows/ci.yml"><img src="https://github.com/pablogsal/stackpulse/actions/workflows/ci.yml/badge.svg?branch=main" alt="Checks"></a>
  <a href="https://app.codecov.io/github/pablogsal/stackpulse"><img src="https://codecov.io/gh/pablogsal/stackpulse/graph/badge.svg?branch=main" alt="Coverage"></a>
  <a href="https://app.codspeed.io/pablogsal/stackpulse"><img src="https://img.shields.io/endpoint?url=https://codspeed.io/badge.json" alt="CodSpeed"></a>
  <a href="https://crates.io/crates/stackpulse"><img src="https://img.shields.io/crates/v/stackpulse.svg" alt="crates.io"></a>
  <a href="https://docs.rs/stackpulse"><img src="https://docs.rs/stackpulse/badge.svg" alt="docs.rs"></a>
</div>

`stackpulse` samples a Linux process over time and writes the raw stacks to a
compact file. Read that file later to resolve native, Python, JIT, and kernel
frames into names and source locations suitable for a profiler UI.

The library requires Linux 6.0 or newer. It is not a command-line tool.

## Install

```toml
[dependencies]
stackpulse = "0.8"
```

## How recording works

Attach to a process, sample it while it runs, then read the saved profile back.
The profile can include regular application code, Python frames, child
processes, and kernel frames when the machine allows them.

The flow has five steps:

1. Start or attach to a process.
2. Record samples into a spool file.
3. Read the file back.
4. Convert the recorded frames into readable names.
5. Build your own report, flame graph, UI, or export format on top.

## Example

Record briefly, then read back one stack:

```rust,no_run
use std::time::{Duration, Instant};

use stackpulse::{
    AttachMode, PerfRecorder, PerfRecorderOptions, PerfSpoolReader, PerfSymbolizer,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid = std::env::args().nth(1).expect("pid").parse()?;

    let mut rec = PerfRecorder::attach(
        pid,
        "profile.spool",
        AttachMode::StopAttachEnableResume,
        PerfRecorderOptions {
            frequency: 99,
            stack_size: 60 * 1024,
            ..PerfRecorderOptions::default()
        },
    )?;

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && rec.process_is_active(pid as i32) {
        rec.wait()?;
        rec.consume_available()?;
    }
    rec.finish()?;

    let reader = PerfSpoolReader::open("profile.spool")?;
    let mut symbols = PerfSymbolizer::for_spool(&reader);

    if let Some(stack) = reader.sample_stacks().next() {
        symbols.for_each_sample_stack(stack, |frame| {
            println!("{}", frame.func_name());
        });
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
| Native symbols | Bundled Wholesym backend or a caller-supplied symbolizer |
| Dynamic runtimes | Python perf maps and Python runtime frames |
| Kernel stacks | `/proc/kallsyms` and `System.map` fallback |
| Profile files | Writes SPULSE3; reads SPULSE1, SPULSE2, and SPULSE3 |
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
| `builtin-wholesym` | Yes | Native symbolization through Wholesym and Tokio |
| `debuginfod` | No | Remote debug-file lookup when `DEBUGINFOD_URLS` is set |
| `bench-support` | No | Hidden synthetic fixtures used by the benchmark suite |

Consumers that supply `PerfSymbolizerBuilder::native_symbolizer_factory` can
disable default features to omit Wholesym and Tokio. `STACKPULSE_DEBUG_DIRS`
overrides local debug-file search roots, and
`STACKPULSE_DEBUGINFOD_CACHE_DIR` overrides the debuginfod cache directory.

## Permissions

User-space sampling often works with the default perf permissions. Kernel frames,
high sample rates, and restrictive `perf_event_paranoid` settings may require
`CAP_PERFMON` or a sysctl change.

## License

Licensed under the MIT license.
