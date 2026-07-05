use std::io;

use crate::linux;
use crate::spool::{FrameRecord, ModuleRecord, PerfSpoolWriter, ProcessExecRecord};

#[doc(hidden)]
pub struct BenchSpoolSample {
    pub timestamp_ns: u64,
    pub process_id: i32,
    pub thread_id: u64,
    pub frames: Vec<FrameRecord>,
}

#[doc(hidden)]
pub fn write_spool_samples_to_memory(
    modules: &[ModuleRecord],
    process_execs: &[ProcessExecRecord],
    samples: &[BenchSpoolSample],
    capacity: usize,
) -> io::Result<usize> {
    let mut writer = PerfSpoolWriter::from_writer(
        Vec::with_capacity(capacity.max(1024)),
        1_700_000_000_000_000,
        1_000,
    )?;
    for module in modules {
        writer.write_module(module)?;
    }
    for exec in process_execs {
        writer.write_process_exec(exec.timestamp_ns, exec.process_id, exec.is_python_runtime)?;
    }
    for sample in samples {
        writer.write_sample_frames(
            sample.timestamp_ns,
            sample.process_id,
            sample.thread_id,
            sample.frames.iter().copied(),
        )?;
    }
    writer.flush()?;
    Ok(writer.into_inner().len())
}

#[doc(hidden)]
pub struct LivePerfSampleFixture {
    inner: linux::LivePerfSampleBenchFixture,
}

impl LivePerfSampleFixture {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            inner: linux::live_perf_sample_bench_fixture(),
        }
    }

    #[doc(hidden)]
    pub fn event_bytes(&self) -> u64 {
        self.inner.event_bytes() as u64
    }

    #[doc(hidden)]
    pub fn sample_count(&self) -> u64 {
        self.inner.sample_count() as u64
    }

    #[doc(hidden)]
    pub fn frame_count(&self) -> u64 {
        self.inner.frame_count() as u64
    }
}

impl Default for LivePerfSampleFixture {
    fn default() -> Self {
        Self::new()
    }
}

#[doc(hidden)]
pub fn parse_live_perf_samples(fixture: &LivePerfSampleFixture, rounds: u64) -> usize {
    linux::bench_parse_live_perf_samples(&fixture.inner, rounds)
}

#[doc(hidden)]
pub fn record_live_perf_samples_to_spool(
    fixture: &LivePerfSampleFixture,
    rounds: u64,
) -> io::Result<usize> {
    linux::bench_record_live_perf_samples(&fixture.inner, rounds)
}

#[doc(hidden)]
pub fn replay_live_perf_ring_records_to_spool(
    fixture: &LivePerfSampleFixture,
    rounds: u64,
) -> io::Result<usize> {
    linux::bench_replay_live_perf_ring_records(&fixture.inner, rounds)
}

#[doc(hidden)]
pub struct SparseKernelSymbolsFixture {
    data: Vec<u8>,
    requested_addresses: Vec<u64>,
}

impl SparseKernelSymbolsFixture {
    #[doc(hidden)]
    pub fn new(symbols: usize, requested_addresses: usize) -> Self {
        let base = 0xffff_ffff_8100_0000_u64;
        let stride = 0x20_u64;
        let mut data = Vec::with_capacity(symbols * 36);
        for index in 0..symbols {
            let address = base + index as u64 * stride;
            let name = if index == 0 {
                "_text".to_string()
            } else {
                format!("bench_kernel_symbol_{index}")
            };
            data.extend_from_slice(format!("{address:016x} T {name}\n").as_bytes());
        }

        let last_symbol = symbols.saturating_sub(2).max(1);
        let mut requested = Vec::with_capacity(requested_addresses);
        for index in 0..requested_addresses {
            let symbol_index = 1 + index * last_symbol / requested_addresses.max(1);
            requested.push(base + symbol_index as u64 * stride + stride / 2);
        }
        requested.sort_unstable();
        requested.dedup();

        Self {
            data,
            requested_addresses: requested,
        }
    }

    #[doc(hidden)]
    pub fn bytes(&self) -> u64 {
        self.data.len() as u64
    }
}

#[doc(hidden)]
pub fn parse_sparse_kernel_symbols(fixture: &SparseKernelSymbolsFixture, rounds: u64) -> usize {
    crate::symbolize::bench_parse_sparse_kernel_symbols(
        &fixture.data,
        &fixture.requested_addresses,
        rounds,
    )
}
