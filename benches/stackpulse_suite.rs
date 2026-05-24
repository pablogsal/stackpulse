use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use integer_encoding::VarIntWriter;
use rustc_hash::FxHashMap;
use stackpulse::profile::{basename_start, LocationInfo, PythonFrame};
use stackpulse::{
    is_python_module, path_to_name, ErrorStatsFormatter, FrameMode, FrameRecord, ModuleImageBase,
    ModulePath, ModuleRecord, NativeFrame, PerfSpoolReader, PerfSymbolizer, ResolvedFrame,
    SampleErrorKind, SampleErrorStats,
};

const MAGIC: &[u8; 8] = b"CHPERF2\0";
const REC_MODULE: u8 = 1;
const REC_FRAME: u8 = 2;
const REC_STACK: u8 = 3;
const REC_THREAD: u8 = 4;
const REC_SAMPLE: u8 = 5;
const REC_PROCESS_EXEC: u8 = 6;
const NONE_U32: u32 = u32::MAX;
const FIXTURE_VERSION: u32 = 8;

const OPEN_BATCH: u64 = 8;
const BORROWED_ITERATE_BATCH: u64 = 64;
const EXPANDED_ITERATE_BATCH: u64 = 16;
const METADATA_BATCH: u64 = 4096;
const WRITE_BATCH: u64 = 4;
const SPOOL_SYMBOLIZE_BATCH: u64 = 32;
const ADDRESS_CACHE_BATCH: u64 = 2048;
const PERF_MAP_BATCH: u64 = 256;
const NATIVE_ELF_FRAMES: usize = 32;
const HELPER_BATCH: u64 = 512;
const ERROR_STATS_BATCH: u64 = 128;
const SAMPLES: usize = 31;
const WARMUP_TIME: Duration = Duration::from_secs(2);
const MEASUREMENT_TIME: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
struct ScenarioSpec {
    name: &'static str,
    processes: usize,
    modules_per_process: usize,
    samples: usize,
    unique_stacks: usize,
    stack_depth: usize,
    include_kernel: bool,
    include_python: bool,
    include_process_execs: bool,
}

const SPOOL_SCENARIOS: &[ScenarioSpec] = &[
    ScenarioSpec {
        name: "hot_stack_reuse",
        processes: 1,
        modules_per_process: 4,
        samples: 16_384,
        unique_stacks: 16,
        stack_depth: 16,
        include_kernel: false,
        include_python: false,
        include_process_execs: false,
    },
    ScenarioSpec {
        name: "many_unique_stacks",
        processes: 2,
        modules_per_process: 6,
        samples: 4_096,
        unique_stacks: 4_096,
        stack_depth: 32,
        include_kernel: false,
        include_python: false,
        include_process_execs: true,
    },
    ScenarioSpec {
        name: "deep_native_stacks",
        processes: 1,
        modules_per_process: 5,
        samples: 2_048,
        unique_stacks: 64,
        stack_depth: 96,
        include_kernel: false,
        include_python: false,
        include_process_execs: false,
    },
    ScenarioSpec {
        name: "python_kernel_mix",
        processes: 3,
        modules_per_process: 6,
        samples: 4_096,
        unique_stacks: 256,
        stack_depth: 48,
        include_kernel: true,
        include_python: true,
        include_process_execs: true,
    },
];

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(SAMPLES)
        .warm_up_time(WARMUP_TIME)
        .measurement_time(MEASUREMENT_TIME)
        .noise_threshold(0.02)
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets =
        bench_spool_open,
        bench_spool_iteration,
        bench_spool_write,
        bench_symbolization,
        bench_helpers
}
criterion_main!(benches);

fn bench_spool_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("stackpulse_cpu/spool/open");
    group.sampling_mode(SamplingMode::Flat);
    for spec in SPOOL_SCENARIOS {
        let path = ensure_spool_fixture(*spec);
        let bytes = fs::metadata(&path).expect("synthetic spool metadata").len();
        group.throughput(Throughput::Bytes(bytes * OPEN_BATCH));
        group.bench_function(BenchmarkId::from_parameter(spec.name), |b| {
            b.iter(|| {
                let mut checksum = 0usize;
                for _ in 0..OPEN_BATCH {
                    let reader =
                        PerfSpoolReader::open(black_box(&path)).expect("open synthetic spool");
                    checksum = checksum
                        .wrapping_add(reader.modules().len())
                        .wrapping_add(reader.samples().len())
                        .wrapping_add(reader.process_execs().len());
                }
                black_box(checksum)
            });
        });
    }
    group.finish();
}

fn bench_spool_iteration(c: &mut Criterion) {
    let readers: Vec<_> = SPOOL_SCENARIOS
        .iter()
        .map(|spec| {
            (
                *spec,
                PerfSpoolReader::open(ensure_spool_fixture(*spec)).expect("open synthetic spool"),
            )
        })
        .collect();

    let borrowed_frame_count = readers
        .iter()
        .map(|(spec, _)| spec.samples as u64 * spec.stack_depth as u64)
        .sum::<u64>()
        * BORROWED_ITERATE_BATCH;

    let mut borrowed = c.benchmark_group("stackpulse_cpu/spool/iterate/borrowed_stack_frame_refs");
    borrowed.sampling_mode(SamplingMode::Flat);
    borrowed.throughput(Throughput::Elements(borrowed_frame_count));
    borrowed.bench_function("all_scenarios", |b| {
        b.iter(|| {
            let mut checksum = 0usize;
            let mut frames = 0usize;
            for _ in 0..BORROWED_ITERATE_BATCH {
                for (_, reader) in &readers {
                    for sample in reader.samples() {
                        for frame in reader
                            .stack_frame_refs(sample.stack_id)
                            .expect("borrow synthetic stack")
                        {
                            frames += 1;
                            checksum = checksum.wrapping_add(raw_frame_score(frame));
                        }
                    }
                }
            }
            black_box(checksum ^ frames)
        });
    });
    borrowed.finish();

    let mut expanded_group =
        c.benchmark_group("stackpulse_cpu/spool/iterate/expanded_stack_frames");
    expanded_group.sampling_mode(SamplingMode::Flat);
    for (spec, reader) in &readers {
        let expanded_frame_count =
            spec.samples as u64 * spec.stack_depth as u64 * EXPANDED_ITERATE_BATCH;

        expanded_group.throughput(Throughput::Elements(expanded_frame_count));
        expanded_group.bench_function(BenchmarkId::from_parameter(spec.name), |b| {
            b.iter(|| {
                let mut expanded = Vec::with_capacity(spec.stack_depth);
                let mut checksum = 0usize;
                let mut frames = 0usize;
                for _ in 0..EXPANDED_ITERATE_BATCH {
                    for sample in reader.samples() {
                        reader
                            .stack_frames(sample.stack_id, &mut expanded)
                            .expect("expand synthetic stack");
                        frames += expanded.len();
                        checksum = checksum.wrapping_add(raw_frames_score(&expanded));
                    }
                }
                black_box(checksum ^ frames)
            });
        });
    }
    expanded_group.finish();

    let metadata_elements = readers
        .iter()
        .map(|(_, reader)| reader.samples().len() as u64)
        .sum::<u64>()
        * METADATA_BATCH;

    let mut metadata = c.benchmark_group("stackpulse_cpu/spool/iterate/sample_metadata");
    metadata.sampling_mode(SamplingMode::Flat);
    metadata.throughput(Throughput::Elements(metadata_elements));
    metadata.bench_function("all_scenarios", |b| {
        b.iter(|| {
            let mut checksum = 0usize;
            for _ in 0..METADATA_BATCH {
                for (_, reader) in &readers {
                    for sample in reader.samples() {
                        checksum = checksum
                            .wrapping_add(reader.timestamp_us(sample) as usize)
                            .wrapping_add(sample.process_id as usize)
                            .wrapping_add(sample.thread_id as usize)
                            .wrapping_add(sample.stack_id as usize);
                    }
                    for module in reader.modules() {
                        let path = module.path.as_str();
                        checksum = checksum
                            .wrapping_add(path.len())
                            .wrapping_add(usize::from(is_python_module(basename(path))));
                    }
                }
            }
            black_box(checksum)
        });
    });
    metadata.finish();
}

fn bench_spool_write(c: &mut Criterion) {
    let cases: Vec<_> = SPOOL_SCENARIOS
        .iter()
        .map(|spec| {
            let bytes = fs::metadata(ensure_spool_fixture(*spec))
                .expect("synthetic spool metadata")
                .len();
            (*spec, bytes as usize, bytes)
        })
        .collect();
    let bytes = cases.iter().map(|(_, _, bytes)| *bytes).sum::<u64>();

    let mut group = c.benchmark_group("stackpulse_cpu/spool/write_memory");
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Bytes(bytes * WRITE_BATCH));
    group.bench_function("all_scenarios", |b| {
        b.iter(|| {
            let mut checksum = 0usize;
            for _ in 0..WRITE_BATCH {
                for (spec, capacity, _) in &cases {
                    checksum = checksum.wrapping_add(
                        write_synthetic_spool_to_memory(black_box(*spec), *capacity)
                            .expect("write synthetic spool to memory"),
                    );
                }
            }
            black_box(checksum)
        });
    });
    group.finish();
}

fn bench_symbolization(c: &mut Criterion) {
    let address_stacks = address_only_stacks(256, 32, FrameMode::User, 0x7000_0000);
    let mut address_group = c.benchmark_group("stackpulse_cpu/symbolize/address_only");
    address_group.sampling_mode(SamplingMode::Flat);
    address_group.throughput(Throughput::Elements(total_frames(&address_stacks) as u64));
    address_group.bench_function("unique_stacks", |b| {
        b.iter(|| {
            let mut symbolizer = PerfSymbolizer::with_perf_maps(&[], false);
            let mut checksum = 0usize;
            for (stack_id, frames) in address_stacks.iter().enumerate() {
                checksum = checksum.wrapping_add(resolved_frames_score(
                    &symbolizer.stack_to_cached_frames(42, stack_id as u32, frames),
                ));
            }
            black_box(checksum)
        });
    });

    let mut warm_symbolizer = PerfSymbolizer::with_perf_maps(&[], false);
    for (stack_id, frames) in address_stacks.iter().enumerate() {
        let _ = warm_symbolizer.stack_to_cached_frames(42, stack_id as u32, frames);
    }
    address_group.throughput(Throughput::Elements(
        address_stacks.len() as u64 * ADDRESS_CACHE_BATCH,
    ));
    address_group.bench_function("warm_stack_cache", |b| {
        b.iter(|| {
            let mut checksum = 0usize;
            for _ in 0..ADDRESS_CACHE_BATCH {
                for (stack_id, frames) in address_stacks.iter().enumerate() {
                    checksum = checksum.wrapping_add(resolved_frames_light_score(
                        &warm_symbolizer.stack_to_cached_frames(42, stack_id as u32, frames),
                    ));
                }
            }
            black_box(checksum)
        });
    });
    address_group.finish();

    let mut spool_symbolizers: Vec<_> =
        [SPOOL_SCENARIOS[0], SPOOL_SCENARIOS[1], SPOOL_SCENARIOS[3]]
            .into_iter()
            .map(|spec| {
                let reader = PerfSpoolReader::open(ensure_spool_fixture(spec))
                    .expect("open synthetic spool");
                let mut symbolizer = PerfSymbolizer::with_perf_maps(reader.modules(), false);
                let _ = symbolize_reader(&reader, &mut symbolizer);
                (spec, reader, symbolizer)
            })
            .collect();
    let spool_symbolize_frames = spool_symbolizers
        .iter()
        .map(|(spec, _, _)| spec.samples as u64 * spec.stack_depth as u64)
        .sum::<u64>()
        * SPOOL_SYMBOLIZE_BATCH;

    let mut spool_group =
        c.benchmark_group("stackpulse_cpu/symbolize/spool_samples_warm_stack_cache");
    spool_group.sampling_mode(SamplingMode::Flat);
    spool_group.throughput(Throughput::Elements(spool_symbolize_frames));
    spool_group.bench_function("all_scenarios", |b| {
        b.iter(|| {
            let mut checksum = 0usize;
            for _ in 0..SPOOL_SYMBOLIZE_BATCH {
                for (_, reader, symbolizer) in &mut spool_symbolizers {
                    checksum = checksum.wrapping_add(symbolize_reader(reader, symbolizer));
                }
            }
            black_box(checksum)
        });
    });
    spool_group.finish();

    let perf_map = PerfMapFixture::new(512);
    let mut perf_map_group = c.benchmark_group("stackpulse_cpu/symbolize/python_perf_map");
    perf_map_group.sampling_mode(SamplingMode::Flat);
    perf_map_group.throughput(Throughput::Elements(
        perf_map.frames.len() as u64 * PERF_MAP_BATCH,
    ));
    perf_map_group.bench_function("python_perf_map", |b| {
        b.iter(|| {
            let mut symbolizer = PerfSymbolizer::new(&[]);
            let mut checksum = 0usize;
            for stack_id in 0..PERF_MAP_BATCH {
                checksum = checksum.wrapping_add(resolved_frames_light_score(
                    &symbolizer.stack_to_cached_frames(
                        perf_map.process_id,
                        stack_id as u32,
                        &perf_map.frames,
                    ),
                ));
            }
            black_box(checksum)
        });
    });
    perf_map_group.finish();

    if let Some((modules, frames)) = current_exe_symbolization_fixture() {
        let mut native_group = c.benchmark_group("stackpulse_cpu/symbolize/native_elf");
        native_group.sampling_mode(SamplingMode::Flat);
        native_group.throughput(Throughput::Elements(frames.len() as u64));
        native_group.bench_function("cold_current_exe_batch", |b| {
            b.iter(|| {
                let mut symbolizer = PerfSymbolizer::with_perf_maps(&modules, false);
                black_box(resolved_frames_score(&symbolizer.stack_to_cached_frames(
                    std::process::id() as i32,
                    0,
                    &frames,
                )))
            });
        });
        native_group.finish();
    }
}

fn bench_helpers(c: &mut Criterion) {
    let module_names = [
        "python",
        "python3",
        "python3.12",
        "python3.13t",
        "Python3.12",
        "libpython3.12.so",
        "libpython3.12.so.1.0",
        "libpython3.13t.so",
        "libpython3.12.dylib",
        "pypy3",
        "python3.12-config",
        "libpythonx.so",
        "libnotpython3.12.so",
    ];
    let paths = [
        PathBuf::from("/usr/bin/python3.12"),
        PathBuf::from("/opt/stackpulse/lib/libworker.so"),
        PathBuf::from("[kernel.kallsyms]"),
        PathBuf::from("/tmp/a path/deleted.so"),
        PathBuf::from("relative-name"),
    ];
    let basename_inputs = [
        "/tmp/app.py",
        "/very/long/path/with/many/segments/module.py",
        "no/slash/after/first",
        "filename_only",
        "/usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0",
    ];
    let frames = resolved_frame_matrix();
    let bases = module_image_base_inputs();

    let mut group = c.benchmark_group("stackpulse_cpu/helpers");
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Elements(HELPER_BATCH));
    group.bench_function("profile_and_path_helpers", |b| {
        b.iter(|| {
            let mut checksum = 0usize;
            for _ in 0..HELPER_BATCH {
                for name in module_names {
                    checksum = checksum.wrapping_add(usize::from(is_python_module(name)));
                }
                for path in &paths {
                    checksum = checksum.wrapping_add(path_to_name(path).len());
                }
                for input in basename_inputs {
                    checksum = checksum.wrapping_add(basename_start(input) as usize);
                }
                for frame in &frames {
                    checksum = checksum.wrapping_add(frame.func_name().len());
                }
                for (base, avma) in &bases {
                    checksum = checksum
                        .wrapping_add(base.relative_address(*avma) as usize)
                        .wrapping_add(base.svma_for_avma(*avma) as usize);
                }
            }
            black_box(checksum)
        });
    });

    group.throughput(Throughput::Elements(ERROR_STATS_BATCH));
    group.bench_function("sample_error_stats", |b| {
        b.iter(|| {
            let mut checksum = 0usize;
            for _ in 0..ERROR_STATS_BATCH {
                let stats = dense_error_stats();
                stats.record(SampleErrorKind::FrameChainIncomplete);
                let mut output = String::new();
                ErrorStatsFormatter::new(&stats, 100_000, 97_000)
                    .write_to(&mut output)
                    .expect("format dense stats");
                checksum = checksum.wrapping_add(stats.total() as usize ^ output.len());
            }
            black_box(checksum)
        });
    });
    group.finish();
}

fn ensure_spool_fixture(spec: ScenarioSpec) -> PathBuf {
    let dir = fixture_dir();
    fs::create_dir_all(&dir).expect("create synthetic fixture directory");
    let path = dir.join(format!("{}-v{FIXTURE_VERSION}.spool", spec.name));
    if path.exists() {
        return path;
    }

    let tmp_path = dir.join(format!(
        "{}-v{FIXTURE_VERSION}.{}.tmp",
        spec.name,
        std::process::id()
    ));
    write_synthetic_spool(&tmp_path, spec).expect("write synthetic spool fixture");
    fs::rename(&tmp_path, &path).expect("install immutable synthetic spool fixture");
    path
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("stackpulse-bench-fixtures")
}

fn write_synthetic_spool(path: &Path, spec: ScenarioSpec) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = SyntheticSpoolWriter::create(path, 1_700_000_000_000_000, 1_000)?;
    write_synthetic_spool_records(&mut writer, spec)?;
    writer.flush()
}

fn write_synthetic_spool_to_memory(spec: ScenarioSpec, capacity: usize) -> io::Result<usize> {
    let mut writer =
        SyntheticSpoolWriter::memory_with_capacity(1_700_000_000_000_000, 1_000, capacity)?;
    write_synthetic_spool_records(&mut writer, spec)?;
    writer.flush()?;
    Ok(writer.into_inner().len())
}

fn write_synthetic_spool_records<W: Write>(
    writer: &mut SyntheticSpoolWriter<W>,
    spec: ScenarioSpec,
) -> io::Result<()> {
    let modules = synthetic_modules(spec);
    for module in &modules {
        writer.write_module(module)?;
    }
    if spec.include_process_execs {
        for process in 0..spec.processes {
            writer.write_process_exec(
                10_000 + process as u64,
                process_id(process),
                spec.include_python && process % 2 == 0,
            )?;
        }
    }

    let kernel_module_id = modules.iter().find(|m| m.is_kernel).map(|m| m.id);
    let mut stack = Vec::with_capacity(spec.stack_depth);
    for sample_idx in 0..spec.samples {
        let process_idx = sample_idx % spec.processes;
        let process_id = process_id(process_idx);
        let variant = sample_idx % spec.unique_stacks;
        stack.clear();

        for depth in 0..spec.stack_depth {
            let use_kernel = kernel_module_id.is_some() && depth + 1 == spec.stack_depth;
            let frame = if use_kernel && sample_idx % 3 == 0 {
                let module = &modules[kernel_module_id.expect("kernel module id") as usize];
                frame_in_module(module, variant, depth, FrameMode::Kernel)
            } else {
                let module_offset = (variant + depth * 3) % spec.modules_per_process;
                let module_idx = process_idx * spec.modules_per_process + module_offset;
                frame_in_module(&modules[module_idx], variant, depth, FrameMode::User)
            };
            stack.push(frame);
        }

        writer.write_sample_frames(
            1_000_000 + sample_idx as u64 * 1_000,
            process_id,
            thread_id(process_idx, sample_idx),
            &stack,
        )?;
    }
    Ok(())
}

fn synthetic_modules(spec: ScenarioSpec) -> Vec<ModuleRecord> {
    let mut modules = Vec::with_capacity(
        spec.processes * spec.modules_per_process + usize::from(spec.include_kernel),
    );

    for process in 0..spec.processes {
        let process_id = process_id(process);
        let process_base = 0x1000_0000_0000 + process as u64 * 0x1000_0000;
        for index in 0..spec.modules_per_process {
            let id = modules.len() as u32;
            let start = process_base + index as u64 * 0x0010_0000;
            modules.push(ModuleRecord {
                id,
                process_id,
                start,
                end: start + 0x000c_0000,
                file_offset: (index as u64 % 4) * 0x1000,
                inode: 100_000 + id as u64,
                path: module_path(spec, process, index),
                is_kernel: false,
            });
        }
    }

    if spec.include_kernel {
        let id = modules.len() as u32;
        modules.push(ModuleRecord {
            id,
            process_id: -1,
            start: 0xffff_ffff_8000_0000,
            end: 0xffff_ffff_9000_0000,
            file_offset: 0,
            inode: 0,
            path: ModulePath::from("[kernel.kallsyms]"),
            is_kernel: true,
        });
    }

    modules
}

fn module_path(spec: ScenarioSpec, process: usize, index: usize) -> ModulePath {
    if spec.include_python {
        match index {
            0 => return ModulePath::from(format!("/opt/python/process-{process}/python3.12")),
            1 => return ModulePath::from("[anon:python-code]"),
            2 => return ModulePath::from(format!("/tmp/stackpulse-app-{process}.py")),
            _ => {}
        }
    }
    ModulePath::from(format!("/opt/stackpulse/lib/libbench-{process}-{index}.so"))
}

fn frame_in_module(
    module: &ModuleRecord,
    variant: usize,
    depth: usize,
    fallback_mode: FrameMode,
) -> FrameRecord {
    let span = module.end - module.start;
    let offset = ((variant as u64 * 131) + (depth as u64 * 67)) % span.saturating_sub(0x100);
    let rel_ip = module.file_offset + offset;
    let abs_ip = module.start + offset;
    FrameRecord {
        module_id: Some(module.id),
        rel_ip,
        abs_ip,
        mode: if module.is_kernel {
            FrameMode::Kernel
        } else {
            fallback_mode
        },
    }
}

fn process_id(index: usize) -> i32 {
    10_000 + index as i32
}

fn thread_id(process_idx: usize, sample_idx: usize) -> u64 {
    process_id(process_idx) as u64 * 10 + (sample_idx % 8) as u64
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn address_only_stacks(
    stacks: usize,
    depth: usize,
    mode: FrameMode,
    base: u64,
) -> Vec<Vec<FrameRecord>> {
    (0..stacks)
        .map(|stack_id| {
            (0..depth)
                .map(|depth| {
                    let abs_ip = base + stack_id as u64 * 0x1000 + depth as u64 * 0x30 + 8;
                    FrameRecord {
                        module_id: None,
                        rel_ip: abs_ip,
                        abs_ip,
                        mode,
                    }
                })
                .collect()
        })
        .collect()
}

fn total_frames(stacks: &[Vec<FrameRecord>]) -> usize {
    stacks.iter().map(Vec::len).sum()
}

fn symbolize_reader(reader: &PerfSpoolReader, symbolizer: &mut PerfSymbolizer) -> usize {
    let mut checksum = 0usize;
    for sample in reader.samples() {
        let raw = reader
            .stack_frame_refs(sample.stack_id)
            .expect("borrow synthetic stack");
        let resolved =
            symbolizer.stack_refs_to_cached_frames(sample.process_id, sample.stack_id, raw);
        checksum = checksum.wrapping_add(resolved_frames_score(&resolved));
    }
    checksum
}

fn raw_frames_score(frames: &[FrameRecord]) -> usize {
    frames.iter().fold(0usize, |score, frame| {
        score.wrapping_add(raw_frame_score(frame))
    })
}

fn raw_frame_score(frame: &FrameRecord) -> usize {
    frame
        .abs_ip
        .wrapping_add(frame.rel_ip)
        .wrapping_add(u64::from(frame.module_id.unwrap_or(u32::MAX))) as usize
}

fn resolved_frames_score(frames: &[ResolvedFrame]) -> usize {
    frames.iter().fold(0usize, |score, frame| {
        score.wrapping_add(resolved_frame_score(frame))
    })
}

fn resolved_frames_light_score(frames: &[ResolvedFrame]) -> usize {
    let first = frames.first().map_or(0, resolved_frame_score);
    let last = frames.last().map_or(0, resolved_frame_score);
    frames.len().wrapping_add(first).wrapping_add(last)
}

fn resolved_frame_score(frame: &ResolvedFrame) -> usize {
    match frame {
        ResolvedFrame::Python(frame) => frame
            .file_name
            .len()
            .wrapping_add(frame.func_name.len())
            .wrapping_add(frame.location.lineno as usize),
        ResolvedFrame::Native(frame) => {
            let symbol_score = frame.symbol.as_ref().map_or(0usize, |symbol| {
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

fn resolved_frame_matrix() -> Vec<ResolvedFrame> {
    vec![
        ResolvedFrame::Native(NativeFrame::from_address(0x1000)),
        ResolvedFrame::Native(NativeFrame::from_address(0x1010)),
        ResolvedFrame::Python(PythonFrame::new(
            "/tmp/stackpulse/app.py",
            LocationInfo {
                lineno: 42,
                end_lineno: 43,
                column: 1,
                end_column: 8,
            },
            "stackpulse_busy_leaf",
            None,
            false,
        )),
        ResolvedFrame::Python(PythonFrame::new(
            "/tmp/stackpulse/app.py",
            LocationInfo::default(),
            "stackpulse_busy_middle",
            Some(2),
            false,
        )),
    ]
}

fn module_image_base_inputs() -> Vec<(ModuleImageBase, u64)> {
    (0..128)
        .map(|index| {
            let avma = 0x7fff_0000_0000 + index * 0x20_000;
            let svma = 0x1000 + index * 0x10;
            (ModuleImageBase::new(avma, svma), avma + 0x1234)
        })
        .collect()
}

fn dense_error_stats() -> SampleErrorStats {
    let stats = SampleErrorStats::new();
    for (index, kind) in SampleErrorKind::ALL.iter().enumerate() {
        for _ in 0..(index + 1) {
            stats.record(*kind);
        }
    }
    stats
}

fn current_exe_symbolization_fixture() -> Option<(Vec<ModuleRecord>, Vec<FrameRecord>)> {
    let exe = std::env::current_exe().ok()?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    let abs_ip = native_symbol_probe_addr();
    let maps = fs::read_to_string("/proc/self/maps").ok()?;
    let (start, end, file_offset, inode) = find_current_exe_mapping(&maps, &exe, abs_ip)?;
    let rel_ip = file_offset + abs_ip.saturating_sub(start);
    let module = ModuleRecord {
        id: 0,
        process_id: std::process::id() as i32,
        start,
        end,
        file_offset,
        inode,
        path: exe.to_string_lossy().into_owned().into(),
        is_kernel: false,
    };
    let frames = current_exe_frame_batch(start, end, file_offset, abs_ip);
    let frames = if frames.is_empty() {
        vec![FrameRecord {
            module_id: Some(0),
            rel_ip,
            abs_ip,
            mode: FrameMode::User,
        }]
    } else {
        frames
    };
    Some((vec![module], frames))
}

fn current_exe_frame_batch(
    start: u64,
    end: u64,
    file_offset: u64,
    center: u64,
) -> Vec<FrameRecord> {
    if start >= end {
        return Vec::new();
    }

    let last = end - 1;
    let half = NATIVE_ELF_FRAMES as i64 / 2;
    (0..NATIVE_ELF_FRAMES)
        .map(|index| {
            let delta = (index as i64 - half) * 8;
            let abs_ip = if delta < 0 {
                center.saturating_sub((-delta) as u64)
            } else {
                center.saturating_add(delta as u64)
            }
            .clamp(start, last);
            FrameRecord {
                module_id: Some(0),
                rel_ip: file_offset + abs_ip.saturating_sub(start),
                abs_ip,
                mode: FrameMode::User,
            }
        })
        .collect()
}

fn find_current_exe_mapping(maps: &str, exe: &Path, abs_ip: u64) -> Option<(u64, u64, u64, u64)> {
    maps.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let range = fields.next()?;
        let perms = fields.next()?;
        let file_offset = u64::from_str_radix(fields.next()?, 16).ok()?;
        let _dev = fields.next()?;
        let inode = fields.next()?.parse().ok()?;
        let path = fields.collect::<Vec<_>>().join(" ");
        if !perms.as_bytes().get(2).is_some_and(|b| *b == b'x') {
            return None;
        }
        if !path_matches_current_exe(&path, exe) {
            return None;
        }
        let (start, end) = range.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        (start <= abs_ip && abs_ip < end).then_some((start, end, file_offset, inode))
    })
}

fn path_matches_current_exe(path: &str, exe: &Path) -> bool {
    let path = Path::new(path);
    path == exe || fs::canonicalize(path).is_ok_and(|canonical| canonical == exe)
}

#[inline(never)]
fn native_symbol_probe_addr() -> u64 {
    native_symbol_probe_addr as *const () as usize as u64
}

struct PerfMapFixture {
    process_id: i32,
    path: PathBuf,
    frames: Vec<FrameRecord>,
}

impl PerfMapFixture {
    fn new(symbols: usize) -> Self {
        let process_id = -(std::process::id() as i32) - 20_000;
        let path = PathBuf::from(format!("/tmp/perf-{process_id}.map"));
        let mut text = String::new();
        let mut frames = Vec::with_capacity(symbols);
        let base = 0x5000_0000;
        for index in 0..symbols {
            let start = base + index as u64 * 0x40;
            text.push_str(&format!(
                "{start:x} 40 py::bench_func_{index}:/tmp/stackpulse_bench.py\n"
            ));
            frames.push(FrameRecord {
                module_id: None,
                rel_ip: start + 8,
                abs_ip: start + 8,
                mode: FrameMode::User,
            });
        }
        fs::write(&path, text).expect("write synthetic perf map");
        Self {
            process_id,
            path,
            frames,
        }
    }
}

impl Drop for PerfMapFixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct SyntheticSpoolWriter<W: Write> {
    writer: W,
    last_timestamp_ns: u64,
    frame_cache: FxHashMap<FrameRecord, u32>,
    stack_cache: FxHashMap<(u32, u32), u32>,
    thread_cache: FxHashMap<(i32, u64), u32>,
}

impl SyntheticSpoolWriter<BufWriter<File>> {
    fn create(path: &Path, start_timestamp_us: u64, sample_interval_us: u64) -> io::Result<Self> {
        let mut writer = Self {
            writer: BufWriter::new(File::create(path)?),
            last_timestamp_ns: 0,
            frame_cache: FxHashMap::default(),
            stack_cache: FxHashMap::default(),
            thread_cache: FxHashMap::default(),
        };
        writer.writer.write_all(MAGIC)?;
        writer.writer.write_varint(start_timestamp_us)?;
        writer.writer.write_varint(sample_interval_us)?;
        Ok(writer)
    }
}

impl SyntheticSpoolWriter<Vec<u8>> {
    fn memory_with_capacity(
        start_timestamp_us: u64,
        sample_interval_us: u64,
        capacity: usize,
    ) -> io::Result<Self> {
        let mut writer = Self {
            writer: Vec::with_capacity(capacity.max(1024)),
            last_timestamp_ns: 0,
            frame_cache: FxHashMap::default(),
            stack_cache: FxHashMap::default(),
            thread_cache: FxHashMap::default(),
        };
        writer.writer.write_all(MAGIC)?;
        writer.writer.write_varint(start_timestamp_us)?;
        writer.writer.write_varint(sample_interval_us)?;
        Ok(writer)
    }
}

impl<W: Write> SyntheticSpoolWriter<W> {
    fn write_module(&mut self, module: &ModuleRecord) -> io::Result<()> {
        self.writer.write_all(&[REC_MODULE])?;
        self.writer.write_varint(module.id as u64)?;
        self.writer.write_varint(module.process_id as i64)?;
        self.writer.write_varint(module.start)?;
        self.writer.write_varint(module.end)?;
        self.writer.write_varint(module.file_offset)?;
        self.writer.write_varint(module.inode)?;
        self.writer.write_all(&[u8::from(module.is_kernel)])?;
        write_bytes(&mut self.writer, module.path.as_bytes())
    }

    fn write_sample_frames(
        &mut self,
        timestamp_ns: u64,
        process_id: i32,
        thread_id: u64,
        frames: &[FrameRecord],
    ) -> io::Result<Option<u32>> {
        let Some(stack_id) = self.intern_stack(frames)? else {
            return Ok(None);
        };
        let thread_id = self.intern_thread(process_id, thread_id)?;
        let delta = timestamp_ns as i64 - self.last_timestamp_ns as i64;
        self.last_timestamp_ns = timestamp_ns;

        self.writer.write_all(&[REC_SAMPLE])?;
        self.writer.write_varint(delta)?;
        self.writer.write_varint(u64::from(thread_id))?;
        self.writer.write_varint(u64::from(stack_id))?;
        Ok(Some(stack_id))
    }

    fn write_process_exec(
        &mut self,
        timestamp_ns: u64,
        process_id: i32,
        is_python_runtime: bool,
    ) -> io::Result<()> {
        self.writer.write_all(&[REC_PROCESS_EXEC])?;
        self.writer.write_varint(timestamp_ns)?;
        self.writer.write_varint(i64::from(process_id))?;
        self.writer.write_all(&[u8::from(is_python_runtime)])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    fn into_inner(self) -> W {
        self.writer
    }

    fn intern_thread(&mut self, process_id: i32, thread_id: u64) -> io::Result<u32> {
        let key = (process_id, thread_id);
        if let Some(&id) = self.thread_cache.get(&key) {
            return Ok(id);
        }
        let id = self.thread_cache.len() as u32;
        self.writer.write_all(&[REC_THREAD])?;
        self.writer.write_varint(u64::from(id))?;
        self.writer.write_varint(i64::from(process_id))?;
        self.writer.write_varint(thread_id)?;
        self.thread_cache.insert(key, id);
        Ok(id)
    }

    fn intern_frame(&mut self, frame: &FrameRecord) -> io::Result<u32> {
        if let Some(&id) = self.frame_cache.get(frame) {
            return Ok(id);
        }
        let id = self.frame_cache.len() as u32;
        self.writer.write_all(&[REC_FRAME])?;
        self.writer.write_varint(u64::from(id))?;
        write_compact_frame(&mut self.writer, frame)?;
        self.frame_cache.insert(*frame, id);
        Ok(id)
    }

    fn intern_stack(&mut self, frames: &[FrameRecord]) -> io::Result<Option<u32>> {
        let mut prefix = NONE_U32;
        let mut saw_frame = false;
        for frame in frames.iter().rev() {
            saw_frame = true;
            let frame_id = self.intern_frame(frame)?;
            let key = (prefix, frame_id);
            if let Some(&stack_id) = self.stack_cache.get(&key) {
                prefix = stack_id;
                continue;
            }
            let stack_id = self.stack_cache.len() as u32;
            self.writer.write_all(&[REC_STACK])?;
            self.writer.write_varint(u64::from(stack_id))?;
            self.writer.write_varint(u64::from(prefix))?;
            self.writer.write_varint(u64::from(frame_id))?;
            self.stack_cache.insert(key, stack_id);
            prefix = stack_id;
        }
        Ok(saw_frame.then_some(prefix))
    }
}

fn write_compact_frame(writer: &mut impl Write, frame: &FrameRecord) -> io::Result<()> {
    let (tag, address) = match frame.module_id {
        Some(module_id) => (u64::from(module_id) << 1, frame.rel_ip),
        None => (
            1 | (u64::from(frame.mode == FrameMode::Kernel) << 1),
            frame.abs_ip,
        ),
    };
    writer.write_varint(tag)?;
    writer.write_varint(address).map(drop)
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_varint(bytes.len() as u64)?;
    writer.write_all(bytes)
}
