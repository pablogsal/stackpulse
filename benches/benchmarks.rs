use codspeed_criterion_compat::{black_box, criterion_group, criterion_main, Criterion};
use std::path::Path;

use stackpulse::elf::{
    compute_vma_bias, file_ranges_correlate, find_load_segment_for_file_offset, LoadSegment,
};
use stackpulse::proc_maps;
use stackpulse::profile::{self, LocationInfo, NativeFrame, PythonFrame};
use stackpulse::{
    is_python_module, path_to_name, ErrorStatsFormatter, ModuleImageBase, SampleErrorKind,
    SampleErrorStats,
};

// ---------------------------------------------------------------------------
// ELF segment lookup and VMA bias computation
// ---------------------------------------------------------------------------

fn rust_pie_segments() -> Vec<LoadSegment> {
    vec![
        LoadSegment {
            p_offset: 0x0000000000000000,
            p_filesz: 0x13c04,
            p_memsz: 0x13c04,
            p_vaddr: 0x0000000000000000,
            p_flags: 0x4,
        },
        LoadSegment {
            p_offset: 0x0000000000013c10,
            p_filesz: 0x400b0,
            p_memsz: 0x400b0,
            p_vaddr: 0x0000000000014c10,
            p_flags: 0x5,
        },
        LoadSegment {
            p_offset: 0x0000000000053cc0,
            p_filesz: 0x02e98,
            p_memsz: 0x03340,
            p_vaddr: 0x0000000000055cc0,
            p_flags: 0x6,
        },
        LoadSegment {
            p_offset: 0x0000000000056b58,
            p_filesz: 0x009c0,
            p_memsz: 0x00a98,
            p_vaddr: 0x0000000000059b58,
            p_flags: 0x6,
        },
    ]
}

fn bench_elf(c: &mut Criterion) {
    let mut group = c.benchmark_group("elf");
    let segments = rust_pie_segments();

    group.bench_function("find_load_segment/code_boundary", |b| {
        b.iter(|| find_load_segment_for_file_offset(black_box(&segments), black_box(0x13000)));
    });

    group.bench_function("find_load_segment/readonly", |b| {
        b.iter(|| find_load_segment_for_file_offset(black_box(&segments), black_box(0x0)));
    });

    group.bench_function("find_load_segment/data", |b| {
        b.iter(|| find_load_segment_for_file_offset(black_box(&segments), black_box(0x53000)));
    });

    group.bench_function("find_load_segment/miss", |b| {
        b.iter(|| find_load_segment_for_file_offset(black_box(&segments), black_box(0x1000000)));
    });

    group.bench_function("compute_vma_bias", |b| {
        b.iter(|| {
            compute_vma_bias(
                black_box(0x13c10),
                black_box(0x14c10),
                black_box(0x13000),
                black_box(0x555555568000),
            )
        });
    });

    group.bench_function("file_ranges_correlate/contained", |b| {
        b.iter(|| {
            file_ranges_correlate(
                black_box(0x13c10),
                black_box(0x400b0),
                black_box(0x13000),
                black_box(0x41000),
            )
        });
    });

    group.bench_function("file_ranges_correlate/disjoint", |b| {
        b.iter(|| {
            file_ranges_correlate(
                black_box(0x13c10),
                black_box(0x400b0),
                black_box(0x100000),
                black_box(0x1000),
            )
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// /proc/pid/maps parsing
// ---------------------------------------------------------------------------

const SAMPLE_MAPS: &str = "\
00400000-0040c000 r-xp 00000000 08:02 1321238                            /usr/bin/cat
0060b000-0060c000 r--p 0000b000 08:02 1321238                            /usr/bin/cat
0060c000-0060d000 rw-p 0000c000 08:02 1321238                            /usr/bin/cat
0060d000-0062e000 rw-p 00000000 00:00 0                                  [heap]
7ffff5600000-7ffff5800000 rw-p 00000000 00:00 0
7ffff672c000-7ffff69db000 r--s 00001ac2 1f:33 1335289                    /usr/lib/locale/locale-archive
7ffff6a00000-7ffff6a28000 r--p 00000000 08:02 1052789                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff6a28000-7ffff6bb0000 r-xp 00028000 08:02 1052789                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff6bb0000-7ffff6bff000 r--p 001b0000 08:02 1052789                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff6bff000-7ffff6c03000 r--p 001fe000 08:02 1052789                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff6c03000-7ffff6c05000 rw-p 00202000 08:02 1052789                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff6c05000-7ffff6c12000 rw-p 00000000 00:00 0
7ffff6fb9000-7ffff6fbe000 rw-p 00000000 00:00 0
7ffff6fbe000-7ffff6fc2000 r--p 00000000 00:00 0                          [vvar]
7ffff6fc2000-7ffff6fc4000 r-xp 00000000 00:00 0                          [vdso]
7ffff6fc4000-7ffff6fc6000 r--p 00000000 08:02 1052785                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff6fc6000-7ffff6ff0000 r-xp 00002000 08:02 1052785                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff6ff0000-7ffff6ffb000 r--p 0002c000 08:02 1052785                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff6ffc000-7ffff6ffe000 r--p 00037000 08:02 1052785                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff6ffe000-7ffff7000000 rw-p 00039000 08:02 1052785                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
";

fn bench_proc_maps(c: &mut Criterion) {
    let mut group = c.benchmark_group("proc_maps");

    group.bench_function("parse/21_regions", |b| {
        b.iter(|| proc_maps::parse(black_box(SAMPLE_MAPS)));
    });

    group.bench_function("parse_line/executable", |b| {
        let line =
            "00400000-0040c000 r-xp 00000000 08:02 1321238                            /usr/bin/cat";
        b.iter(|| proc_maps::parse_line(black_box(line)));
    });

    group.bench_function("parse_line/anonymous", |b| {
        let line = "7ffff5600000-7ffff5800000 rw-p 00000000 00:00 0";
        b.iter(|| proc_maps::parse_line(black_box(line)));
    });

    group.bench_function("parse_line/long_path", |b| {
        let line = "7ffff6a28000-7ffff6bb0000 r-xp 00028000 08:02 1052789                    /usr/lib/x86_64-linux-gnu/libc.so.6";
        b.iter(|| proc_maps::parse_line(black_box(line)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Python module name detection
// ---------------------------------------------------------------------------

fn bench_is_python_module(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_python_module");

    group.bench_function("python3.12", |b| {
        b.iter(|| is_python_module(black_box("python3.12")));
    });

    group.bench_function("libpython3.12.so.1.0", |b| {
        b.iter(|| is_python_module(black_box("libpython3.12.so.1.0")));
    });

    group.bench_function("libpython3.13t.so", |b| {
        b.iter(|| is_python_module(black_box("libpython3.13t.so")));
    });

    group.bench_function("not_python", |b| {
        b.iter(|| is_python_module(black_box("libstdc++.so.6")));
    });

    group.bench_function("python_bare", |b| {
        b.iter(|| is_python_module(black_box("python")));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Path operations
// ---------------------------------------------------------------------------

fn bench_path_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_operations");

    group.bench_function("path_to_name/short", |b| {
        let path = Path::new("/usr/bin/cat");
        b.iter(|| path_to_name(black_box(path)));
    });

    group.bench_function("path_to_name/long", |b| {
        let path = Path::new("/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30");
        b.iter(|| path_to_name(black_box(path)));
    });

    group.bench_function("basename_start/short", |b| {
        b.iter(|| profile::basename_start(black_box("/usr/bin/cat")));
    });

    group.bench_function("basename_start/long", |b| {
        b.iter(|| {
            profile::basename_start(black_box("/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30"))
        });
    });

    group.bench_function("basename_start/no_slash", |b| {
        b.iter(|| profile::basename_start(black_box("libstdc++.so.6")));
    });

    group.bench_function("basename_start/deep", |b| {
        b.iter(|| {
            profile::basename_start(black_box(
                "/home/user/.local/lib/python3.12/site-packages/numpy/core/_multiarray_umath.cpython-312-x86_64-linux-gnu.so",
            ))
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Error statistics
// ---------------------------------------------------------------------------

fn bench_error_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("error_stats");

    group.bench_function("record", |b| {
        let stats = SampleErrorStats::new();
        b.iter(|| stats.record(black_box(SampleErrorKind::FrameChainIncomplete)));
    });

    group.bench_function("total/empty", |b| {
        let stats = SampleErrorStats::new();
        b.iter(|| stats.total());
    });

    group.bench_function("total/populated", |b| {
        let stats = SampleErrorStats::new();
        for kind in SampleErrorKind::ALL {
            for _ in 0..100 {
                stats.record(*kind);
            }
        }
        b.iter(|| stats.total());
    });

    group.bench_function("iter_nonzero/sparse", |b| {
        let stats = SampleErrorStats::new();
        stats.record(SampleErrorKind::FrameChainIncomplete);
        stats.record(SampleErrorKind::StackChunkReadFailure);
        b.iter(|| stats.iter_nonzero().count());
    });

    group.bench_function("iter_nonzero/dense", |b| {
        let stats = SampleErrorStats::new();
        for kind in SampleErrorKind::ALL {
            stats.record(*kind);
        }
        b.iter(|| stats.iter_nonzero().count());
    });

    group.bench_function("has_errors/empty", |b| {
        let stats = SampleErrorStats::new();
        b.iter(|| stats.has_errors());
    });

    group.bench_function("has_errors/populated", |b| {
        let stats = SampleErrorStats::new();
        // Record on the last kind so has_errors scans all counters
        stats.record(SampleErrorKind::ThreadListTooMany);
        b.iter(|| stats.has_errors());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Error stats formatting
// ---------------------------------------------------------------------------

fn bench_error_stats_formatter(c: &mut Criterion) {
    let mut group = c.benchmark_group("error_stats_formatter");

    group.bench_function("format/no_errors", |b| {
        let stats = SampleErrorStats::new();
        let formatter = ErrorStatsFormatter::new(&stats, 1000, 1000);
        b.iter(|| {
            let mut output = String::with_capacity(512);
            formatter.write_to(&mut output).unwrap();
            output
        });
    });

    group.bench_function("format/with_errors", |b| {
        let stats = SampleErrorStats::new();
        for _ in 0..80 {
            stats.record(SampleErrorKind::FrameChainIncomplete);
        }
        for _ in 0..50 {
            stats.record(SampleErrorKind::CodeObjectReadFailure);
        }
        for _ in 0..20 {
            stats.record(SampleErrorKind::StackChunkReadFailure);
        }
        for _ in 0..10 {
            stats.record(SampleErrorKind::NativeStackTruncated);
        }
        let formatter = ErrorStatsFormatter::new(&stats, 1000, 840);
        b.iter(|| {
            let mut output = String::with_capacity(2048);
            formatter.write_to(&mut output).unwrap();
            output
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Module image base address arithmetic
// ---------------------------------------------------------------------------

fn bench_module_image_base(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_image_base");

    group.bench_function("relative_address", |b| {
        let base = ModuleImageBase::new(0x555555554000, 0x0);
        b.iter(|| base.relative_address(black_box(0x555555568c10)));
    });

    group.bench_function("svma_for_avma", |b| {
        let base = ModuleImageBase::new(0x555555554000, 0x1000);
        b.iter(|| base.svma_for_avma(black_box(0x555555568c10)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Frame construction
// ---------------------------------------------------------------------------

fn bench_frame_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_construction");

    group.bench_function("python_frame_new", |b| {
        let location = LocationInfo {
            lineno: 42,
            end_lineno: 42,
            column: 8,
            end_column: 20,
        };
        b.iter(|| {
            PythonFrame::new(
                black_box("/usr/lib/python3.12/importlib/__init__.py"),
                location,
                black_box("import_module"),
                None,
                false,
            )
        });
    });

    group.bench_function("native_frame_from_address", |b| {
        b.iter(|| NativeFrame::from_address(black_box(0x555555568c10)));
    });

    group.bench_function("native_frame_func_name/no_symbol", |b| {
        let frame = NativeFrame::from_address(0x555555568c10);
        b.iter(|| frame.func_name());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_elf,
    bench_proc_maps,
    bench_is_python_module,
    bench_path_operations,
    bench_error_stats,
    bench_error_stats_formatter,
    bench_module_image_base,
    bench_frame_construction,
);
criterion_main!(benches);
