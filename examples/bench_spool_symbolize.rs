use std::path::PathBuf;
use std::time::Instant;

use stackpulse::profile::ResolvedFrame;
use stackpulse::spool::{FrameRecord, SampleStack};
use stackpulse::{Replay, Snapshot, StackCache, Symbolizer};

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
    without_stack_cache: bool,
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
                .wrapping_add(reader.python_runtime_records().len());
            samples += reader.sample_count();
            match options.mode {
                Mode::Open => {}
                Mode::Read => {
                    for stack in reader.stacks() {
                        let raw_frames = stack.frames();
                        frames += raw_frames.len();
                        checksum = checksum.wrapping_add(raw_frame_score(raw_frames));
                    }
                }
                Mode::Symbolize => {
                    let mut symbolizer = reader
                        .symbolizer()
                        .disable_perf_maps()
                        .stack_cache(if options.without_stack_cache {
                            StackCache::External
                        } else {
                            StackCache::Internal
                        })
                        .build()?;
                    symbolize_samples(reader.stacks(), &mut symbolizer, &mut frames, &mut checksum);
                }
            }
        } else {
            let reader = Snapshot::open(&options.spool)?;
            checksum = checksum
                .wrapping_add(reader.modules().len())
                .wrapping_add(reader.python_runtime_records().len());
            samples += reader.samples().len();
            match options.mode {
                Mode::Open => {}
                Mode::Read => {
                    for stack in reader.stacks() {
                        let raw_frames = stack.frames();
                        frames += raw_frames.len();
                        checksum = checksum.wrapping_add(raw_frame_score(raw_frames));
                    }
                }
                Mode::Symbolize => {
                    let mut symbolizer = reader
                        .symbolizer()
                        .disable_perf_maps()
                        .stack_cache(if options.without_stack_cache {
                            StackCache::External
                        } else {
                            StackCache::Internal
                        })
                        .build()?;
                    symbolize_samples(reader.stacks(), &mut symbolizer, &mut frames, &mut checksum);
                }
            }
        }
    }

    std::hint::black_box(checksum);
    println!(
        "reader={:?} stack_cache={} mode={:?} iterations={} samples={} frames={} checksum={} elapsed_ms={:.2}",
        options.reader,
        if options.without_stack_cache {
            "disabled"
        } else {
            "enabled"
        },
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
    stacks: impl IntoIterator<Item = SampleStack<'a>>,
    symbolizer: &mut Symbolizer,
    frames: &mut usize,
    checksum: &mut usize,
) {
    for stack in stacks {
        let mut stack_checksum = 0_usize;
        let resolved = symbolizer.resolve(stack).expect("symbolize stack");
        let count = resolved.len();
        for frame in resolved {
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
    let mut without_stack_cache = false;
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
            "--without-stack-cache" => without_stack_cache = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    if without_stack_cache && !matches!(mode, Mode::Symbolize) {
        return Err("--without-stack-cache requires --symbolize".into());
    }

    Ok(Options {
        spool,
        iterations,
        mode,
        reader,
        without_stack_cache,
    })
}

fn print_usage() {
    eprintln!(
        "usage: cargo run --release --example bench_spool_symbolize -- [--spool PATH] [--iterations N] [--open-only|--read-only|--symbolize] [--replay] [--without-stack-cache]"
    );
}

fn raw_frame_score<'a>(frames: impl IntoIterator<Item = &'a FrameRecord>) -> usize {
    frames.into_iter().fold(0, |score, frame| {
        score
            .wrapping_add(frame.abs_ip as usize)
            .wrapping_add(frame.file_relative_ip as usize)
            .wrapping_add(frame.module_id.unwrap_or(u32::MAX) as usize)
    })
}

fn resolved_frame_score(frame: &ResolvedFrame) -> usize {
    match frame {
        ResolvedFrame::Python(frame) => frame
            .file_name()
            .len()
            .wrapping_add(frame.func_name.len())
            .wrapping_add(frame.location.lineno as usize),
        ResolvedFrame::Native(frame) => {
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
