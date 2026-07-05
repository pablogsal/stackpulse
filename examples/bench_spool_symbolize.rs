use std::path::PathBuf;
use std::time::Instant;

use stackpulse::{FrameRecord, PerfSpoolReader, PerfSymbolizer, ResolvedFrame};

#[derive(Clone, Copy, Debug)]
enum Mode {
    Read,
    Symbolize,
}

#[derive(Debug)]
struct Options {
    spool: PathBuf,
    iterations: usize,
    mode: Mode,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_options()?;
    let started = Instant::now();
    let mut checksum = 0_usize;
    let mut samples = 0_usize;
    let mut frames = 0_usize;

    for _ in 0..options.iterations {
        let reader = PerfSpoolReader::open(&options.spool)?;
        checksum = checksum
            .wrapping_add(reader.modules().len())
            .wrapping_add(reader.process_execs().len());
        samples += reader.samples().len();

        match options.mode {
            Mode::Read => {
                for stack in reader.sample_stacks() {
                    frames += stack.frames.len();
                    checksum = checksum.wrapping_add(raw_frame_score(stack.frames));
                }
            }
            Mode::Symbolize => {
                let mut symbolizer = PerfSymbolizer::for_spool_with_perf_maps(&reader, false);
                symbolize_samples(&reader, &mut symbolizer, &mut frames, &mut checksum);
            }
        }
    }

    std::hint::black_box(checksum);
    println!(
        "mode={:?} iterations={} samples={} frames={} checksum={} elapsed_ms={:.2}",
        options.mode,
        options.iterations,
        samples,
        frames,
        checksum,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

fn symbolize_samples(
    reader: &PerfSpoolReader,
    symbolizer: &mut PerfSymbolizer,
    frames: &mut usize,
    checksum: &mut usize,
) {
    for stack in reader.sample_stacks() {
        let mut stack_checksum = 0_usize;
        let count = symbolizer.for_each_sample_stack(stack, |frame| {
            stack_checksum = stack_checksum.wrapping_add(resolved_frame_score(frame));
        });
        *frames += count;
        *checksum = checksum.wrapping_add(stack_checksum);
    }
}

fn parse_options() -> Result<Options, Box<dyn std::error::Error>> {
    let mut spool = PathBuf::from("mini_profile.spool");
    let mut iterations = 1000;
    let mut mode = Mode::Symbolize;
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
            "--symbolize" => mode = Mode::Symbolize,
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
    })
}

fn print_usage() {
    eprintln!(
        "usage: cargo run --release --example bench_spool_symbolize -- [--spool PATH] [--iterations N] [--read-only|--symbolize]"
    );
}

fn raw_frame_score<'a>(frames: impl IntoIterator<Item = &'a FrameRecord>) -> usize {
    frames.into_iter().fold(0, |score, frame| {
        score
            .wrapping_add(frame.abs_ip as usize)
            .wrapping_add(frame.rel_ip as usize)
            .wrapping_add(frame.module_id.unwrap_or(u32::MAX) as usize)
    })
}

fn resolved_frame_score(frame: &ResolvedFrame) -> usize {
    match frame {
        ResolvedFrame::Python(frame) => frame
            .file_name
            .len()
            .wrapping_add(frame.func_name.len())
            .wrapping_add(frame.location.lineno as usize),
        ResolvedFrame::Native(frame) => {
            let symbol_score = frame.symbol.as_ref().map_or(0, |symbol| {
                symbol
                    .name
                    .len()
                    .wrapping_add(symbol.module.len())
                    .wrapping_add(symbol.offset as usize)
            });
            (frame.pc as usize).wrapping_add(symbol_score)
        }
    }
}
