# stackpulse

[![CI](https://github.com/pablogsal/stackpulse/actions/workflows/ci.yml/badge.svg)](https://github.com/pablogsal/stackpulse/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pablogsal/stackpulse/branch/main/graph/badge.svg)](https://codecov.io/gh/pablogsal/stackpulse)

`stackpulse` records what a Linux process is doing over time by taking regular
stack samples and saving them to a compact file. You can read that file later
and turn the raw frames into function names, source locations where available,
and a shape that is easier to display in a profiler UI.

The library is Linux-only for now. It is not a command-line tool.

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

    rec.wait()?;
    rec.consume_available()?;
    rec.finish()?;

    let reader = PerfSpoolReader::open("profile.spool")?;
    let mut symbols = PerfSymbolizer::new(reader.modules());

    if let Some(sample) = reader.samples().first() {
        let raw_frames = reader.stack_frame_refs(sample.stack_id)?;
        let frames = symbols.stack_refs_to_cached_frames(
            sample.process_id,
            sample.stack_id,
            raw_frames,
        );

        for frame in frames.iter() {
            println!("{}", frame.func_name());
        }
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

## Notes

Most application recordings work without special setup. Kernel frames, very high
sample rates, or stricter system settings may need extra permissions.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license.
