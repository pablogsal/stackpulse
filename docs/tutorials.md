# Launch a recording

`PreparedRecording` owns the suspended child and its armed recorder. Dropping
it before `start` releases and reaps the child. `start` consumes preparation and
returns the recorder and a child handle with a stable PID and repeatable wait.

```rust,no_run
use std::fs::File;
use std::time::Duration;
use stackpulse::{Recorder, SampleRate, Spool};
use stackpulse::process::Launch;
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let prepared = Recorder::builder(SampleRate::hz(99)?)
    .prepare(Launch::new("python3").arg("work.py").env("PYTHONPERFSUPPORT", "1"),
             Spool::retained(File::create("profile.spool")?)?)?;
let (mut recorder, mut child) = prepared.start()?;
loop {
    recorder.poll(Duration::from_millis(100))?;
    if child.try_wait()?.is_some() { break; }
}
let summary = recorder.finish()?;
println!("recorded {} samples", summary.samples);
# Ok(())
# }
```

The launch description supports a program, arguments, and environment overrides.
It does not reconstruct a `std::process::Command` from incomplete getters.
