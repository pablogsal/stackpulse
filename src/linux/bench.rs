use std::io;

use super::sorter::EventSorter;
use super::{
    finish_prepared_event, perf_event, prepare_event, record_module, ConvertRegs,
    ConvertRegsNative, EventContext, PerfSummary, PreparedEvent, ProcessTable,
};
use crate::spool::{ModuleRecord, ModuleTable, PerfSpoolWriter};

const LIVE_BENCH_PROCESS_ID: u32 = 42_000;
const LIVE_BENCH_USER_BASE: u64 = 0x7000_0000_0000;
const LIVE_BENCH_KERNEL_BASE: u64 = 0xffff_ffff_8100_0000;
const LIVE_BENCH_RING_COUNT: usize = 4;

pub(crate) struct LivePerfSampleBenchFixture {
    samples: perf_event::BenchSampleBatch,
    modules: Vec<ModuleRecord>,
    spool_capacity: usize,
}

impl LivePerfSampleBenchFixture {
    pub(crate) fn event_bytes(&self) -> usize {
        self.samples.event_bytes()
    }

    pub(crate) fn sample_count(&self) -> usize {
        self.samples.sample_count()
    }
}

pub(crate) fn live_perf_sample_bench_fixture() -> LivePerfSampleBenchFixture {
    let samples = perf_event::BenchSampleBatch::new(perf_event::BenchSampleBatchSpec {
        samples: 4_096,
        user_frames: 0,
        kernel_frames: 8,
        user_regs: ConvertRegsNative::regs_mask().count_ones() as usize,
        user_stack_bytes: 512,
        process_id: LIVE_BENCH_PROCESS_ID,
        thread_count: 32,
        user_base: LIVE_BENCH_USER_BASE,
        kernel_base: LIVE_BENCH_KERNEL_BASE,
    });
    let modules = live_perf_sample_bench_modules();
    let spool_capacity = 64 * 1024 + samples.frame_count() * 16 + samples.sample_count() * 16;
    LivePerfSampleBenchFixture {
        samples,
        modules,
        spool_capacity,
    }
}

pub(crate) fn bench_parse_live_perf_samples(
    fixture: &LivePerfSampleBenchFixture,
    rounds: u64,
) -> usize {
    perf_event::bench_parse_sample_records(&fixture.samples, rounds)
}

pub(crate) fn bench_replay_live_perf_ring_records(
    fixture: &LivePerfSampleBenchFixture,
    rounds: u64,
) -> io::Result<usize> {
    let mut checksum = 0usize;
    for round in 0..rounds {
        let mut writer = PerfSpoolWriter::from_writer(
            Vec::with_capacity(fixture.spool_capacity),
            1_700_000_000_000_000 + round,
            1_000,
        )?;
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        for module in &fixture.modules {
            record_module(&mut modules, &mut processes, &mut writer, module.clone())?;
        }

        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::with_capacity(128);
        let mut lifecycle_actions = Vec::new();
        let mut sorter = EventSorter::<usize, u64, PreparedEvent>::new();
        let mut result: io::Result<()> = Ok(());
        {
            let mut ctx = EventContext {
                modules: &mut modules,
                processes: &mut processes,
                writer: &mut writer,
                summary: &mut summary,
                stack_scratch: &mut stack_scratch,
                lifecycle_actions: &mut lifecycle_actions,
                inherit_child_processes: false,
            };
            for ring in 0..LIVE_BENCH_RING_COUNT {
                sorter.begin_group(ring);
                for record in fixture
                    .samples
                    .records()
                    .iter()
                    .skip(ring)
                    .step_by(LIVE_BENCH_RING_COUNT)
                {
                    if result.is_err() {
                        break;
                    }
                    let (timestamp, prepared) =
                        fixture.samples.dispatch_event(record, &mut |event| {
                            let timestamp = event.timestamp().unwrap_or(0);
                            (timestamp, prepare_event(event, &mut ctx))
                        });
                    match prepared {
                        Ok(Some(prepared)) => sorter.push_current_group(timestamp, prepared),
                        Ok(None) => {}
                        Err(err) => {
                            result = Err(err);
                        }
                    }
                }
                while let Some(prepared) = sorter.pop() {
                    if result.is_ok() {
                        result = finish_prepared_event(prepared, &mut ctx);
                    }
                }
            }
            sorter.advance_round();
            while let Some(prepared) = sorter.force_pop() {
                if result.is_ok() {
                    result = finish_prepared_event(prepared, &mut ctx);
                }
            }
        }
        result?;

        let expected_samples = fixture.samples.sample_count() as u64;
        assert_eq!(
            summary.samples, expected_samples,
            "synthetic ring replay did not write every generated sample"
        );

        writer.flush()?;
        let bytes = writer.into_inner();
        checksum = checksum
            .wrapping_add(bytes.len())
            .wrapping_add(summary.samples as usize)
            .wrapping_add(summary.sample_events as usize)
            .wrapping_add(summary.ignored_user_callchain_frames as usize)
            .wrapping_add(lifecycle_actions.len());
    }
    Ok(checksum)
}

fn live_perf_sample_bench_modules() -> Vec<ModuleRecord> {
    vec![
        ModuleRecord {
            id: 0,
            process_id: LIVE_BENCH_PROCESS_ID as i32,
            start: LIVE_BENCH_USER_BASE,
            end: LIVE_BENCH_USER_BASE + 0x0008_0000,
            file_offset: 0,
            inode: 1_000_001,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/opt/stackpulse/live-bench/libworkload.so".into(),
            is_kernel: false,
        },
        ModuleRecord {
            id: 0,
            process_id: LIVE_BENCH_PROCESS_ID as i32,
            start: LIVE_BENCH_USER_BASE + 0x0010_0000,
            end: LIVE_BENCH_USER_BASE + 0x0018_0000,
            file_offset: 0,
            inode: 1_000_002,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/opt/stackpulse/live-bench/python3.12".into(),
            is_kernel: false,
        },
        ModuleRecord {
            id: 0,
            process_id: -1,
            start: LIVE_BENCH_KERNEL_BASE,
            end: LIVE_BENCH_KERNEL_BASE + 0x0010_0000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "[kernel.kallsyms]".into(),
            is_kernel: true,
        },
    ]
}
