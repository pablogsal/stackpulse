# stackpulse

[![CI](https://github.com/pablogsal/stackpulse/actions/workflows/ci.yml/badge.svg)](https://github.com/pablogsal/stackpulse/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pablogsal/stackpulse/branch/main/graph/badge.svg)](https://codecov.io/gh/pablogsal/stackpulse)

`stackpulse` records what a Linux process is doing over time by taking regular
stack samples and saving them to a compact file. You can read that file later
and turn the raw frames into function names, source locations where available,
and a shape that is easier to display in a profiler UI.

The library requires Linux 6.0 or newer. It is not a command-line tool.

## The Idea

Attach to a process, sample it while it runs, then read the saved profile back.
The profile can include regular application code, Python frames, child
processes, and kernel frames when the machine allows them.

In practice the flow is:

1. Start or attach to a process.
2. Record samples into a profile file.
3. Read the file back.
4. Convert the recorded frames into readable names.
5. Build your own report, flame graph, UI, or export format on top.

## Example

Record briefly, then read back one stack:

```rust
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

For the API reference, build the Rust docs with `make doc`.

## Development

The Makefile is intentionally plain. No banners, no wrapper scripts.

```sh
make check          # cargo check
make test           # unit tests
make fmt            # format the crate
make fmt-check      # verify formatting
make clippy         # lint with warnings as errors
make coverage       # terminal coverage summary
make coverage-html  # HTML coverage report
make ci             # fmt-check, clippy, test
```

If the coverage helper is missing, `make coverage` prints the install command.

You can pass extra cargo flags through `CARGO_FLAGS`:

```sh
make test CARGO_FLAGS="--features debuginfod"
make coverage CARGO_FLAGS="--features debuginfod"
```

## Feature flags

`debuginfod` enables debuginfod lookup in the default native symbolizer when
`DEBUGINFOD_URLS` is set. `STACKPULSE_DEBUG_DIRS` overrides local debug-file
search roots, and `STACKPULSE_DEBUGINFOD_CACHE_DIR` overrides the debuginfod
cache directory.

## Notes

Most application recordings work without special setup. Kernel frames, very high
sample rates, or stricter system settings may need extra permissions.

## License

Licensed under the MIT license.
