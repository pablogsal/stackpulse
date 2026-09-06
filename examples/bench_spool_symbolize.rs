use std::path::PathBuf;
use std::time::Instant;

use stackpulse::profile::Frame;
use stackpulse::spool::{RawFrame, Sample};
use stackpulse::{Replay, Snapshot, Symbolizer};

#[derive(Clone, Copy, Debug)]
enum Mode {
    Open,
    Read,
    Symbolize,
}

#[derive(Clone, Copy, Debug)]
enum ReaderMode {
    Eager,
    Replay,
}

#[derive(Debug)]
struct Options {
    spool: PathBuf,
    iterations: usize,
    mode: Mode,
    reader: ReaderMode,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_options()?;
    let started = Instant::now();
    let mut checksum = 0_usize;
    let mut samples = 0_usize;
    let mut frames = 0_usize;

    for _ in 0..options.iterations {
        if matches!(options.reader, ReaderMode::Replay) {
            let reader = Replay::open(&options.spool)?;
            checksum = checksum
                .wrapping_add(reader.modules().len())
                .wrapping_add(reader.samples().len());
            samples += reader.sample_count();
            match options.mode {
                Mode::Open => {}
                Mode::Read => {
                    for stack in reader.samples() {
                        let raw_stack = stack.stack();
                        let raw_frames = raw_stack.frames();
                        frames += raw_frames.len();
                        checksum = checksum.wrapping_add(raw_frame_score(raw_frames));
                    }
                }
                Mode::Symbolize => {
                    let mut symbolizer = reader.symbolizer().disable_perf_maps().build()?;
                    symbolize_samples(
                        reader.samples(),
                        &mut symbolizer,
                        &mut frames,
                        &mut checksum,
                    );
                }
            }
        } else {
            let reader = Snapshot::open(&options.spool)?;
            checksum = checksum
                .wrapping_add(reader.modules().len())
                .wrapping_add(reader.samples().len());
            samples += reader.samples().len();
            match options.mode {
                Mode::Open => {}
                Mode::Read => {
                    for stack in reader.samples() {
                        let raw_stack = stack.stack();
                        let raw_frames = raw_stack.frames();
                        frames += raw_frames.len();
                        checksum = checksum.wrapping_add(raw_frame_score(raw_frames));
                    }
                }
                Mode::Symbolize => {
                    let mut symbolizer = reader.symbolizer().disable_perf_maps().build()?;
                    symbolize_samples(
                        reader.samples(),
                        &mut symbolizer,
                        &mut frames,
                        &mut checksum,
                    );
                }
            }
        }
    }

    std::hint::black_box(checksum);
    println!(
        "reader={:?} mode={:?} iterations={} samples={} frames={} checksum={} elapsed_ms={:.2}",
        options.reader,
        options.mode,
        options.iterations,
        samples,
        frames,
        checksum,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

fn symbolize_samples<'a>(
    stacks: impl IntoIterator<Item = Sample<'a>>,
    symbolizer: &mut Symbolizer,
    frames: &mut usize,
    checksum: &mut usize,
) {
    for stack in stacks {
        let mut stack_checksum = 0_usize;
        let resolved = symbolizer.resolve(stack.stack()).expect("symbolize stack");
        let count = resolved.len();
        for frame in resolved.frames() {
            stack_checksum = stack_checksum.wrapping_add(resolved_frame_score(frame));
        }
        *frames += count;
        *checksum = checksum.wrapping_add(stack_checksum);
    }
}

fn parse_options() -> Result<Options, Box<dyn std::error::Error>> {
    let mut spool = PathBuf::from("mini_profile.spool");
    let mut iterations = 1000;
    let mut mode = Mode::Symbolize;
    let mut reader = ReaderMode::Eager;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--spool" => {
                spool = args.next().ok_or("missing value for --spool")?.into();
            }
            "--iterations" => {
                iterations = args
                    .next()
                    .ok_or("missing value for --iterations")?
                    .parse()?;
            }
            "--read-only" => mode = Mode::Read,
            "--open-only" => mode = Mode::Open,
            "--symbolize" => mode = Mode::Symbolize,
            "--replay" => reader = ReaderMode::Replay,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }

    Ok(Options {
        spool,
        iterations,
        mode,
        reader,
    })
}

fn print_usage() {
    eprintln!(
        "usage: cargo run --release --example bench_spool_symbolize -- [--spool PATH] [--iterations N] [--open-only|--read-only|--symbolize] [--replay]"
    );
}

fn raw_frame_score<'a>(frames: impl IntoIterator<Item = RawFrame<'a>>) -> usize {
    frames.into_iter().fold(0usize, |score, frame| {
        score.wrapping_add(match frame {
            RawFrame::Native {
                address, mapping, ..
            } => {
                address as usize
                    ^ mapping.map_or(0, |mapping| mapping.file_relative_address() as usize)
            }
            RawFrame::TruncatedStack => 1,
        })
    })
}

fn resolved_frame_score(frame: &Frame) -> usize {
    match frame {
        Frame::Python(frame) => frame
            .file_name()
            .len()
            .wrapping_add(frame.func_name.len())
            .wrapping_add(frame.location.line.unwrap_or(0) as usize),
        Frame::TruncatedStack => 0,
        Frame::Native(frame) => {
            let symbol_score = frame.symbol.as_ref().map_or(0, |symbol| {
                symbol
                    .name()
                    .len()
                    .wrapping_add(symbol.module.len())
                    .wrapping_add(symbol.offset as usize)
            });
            (frame.pc as usize).wrapping_add(symbol_score)
        }
    }
}
