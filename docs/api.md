# Usage

The Rust docs are the API reference:

```sh
make doc
```

A small end-to-end example:

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
    let mut raw_frames = Vec::new();

    if let Some(sample) = reader.samples().first() {
        reader.stack_frames(sample.stack_id, &mut raw_frames)?;
        let frames = symbols.stack_to_cached_frames(
            sample.process_id,
            sample.stack_id,
            &raw_frames,
        );

        for frame in frames.iter() {
            println!("{}", frame.func_name());
        }
    }

    Ok(())
}
```
