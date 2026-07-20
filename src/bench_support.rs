use std::io::{self, Write};
use std::path::Path;

use crate::linux;
use crate::spool::{FrameRecord, ModuleRecord, PerfSpoolWriter, ProcessExecRecord};

#[doc(hidden)]
pub const CURRENT_SPOOL_MAGIC: &[u8; 8] = crate::spool::CURRENT_MAGIC;

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
    let bytes = write_spool_samples_to_writer(
        Vec::with_capacity(capacity.max(1024)),
        modules,
        process_execs,
        samples,
    )?;
    Ok(bytes.len())
}

#[doc(hidden)]
pub fn write_spool_samples_to_path(
    path: impl AsRef<Path>,
    modules: &[ModuleRecord],
    process_execs: &[ProcessExecRecord],
    samples: &[BenchSpoolSample],
) -> io::Result<()> {
    let mut writer = PerfSpoolWriter::create(path, 1_700_000_000_000_000, 1_000)?;
    write_spool_samples(&mut writer, modules, process_execs, samples)?;
    writer.flush()
}

fn write_spool_samples_to_writer<W: Write>(
    writer: W,
    modules: &[ModuleRecord],
    process_execs: &[ProcessExecRecord],
    samples: &[BenchSpoolSample],
) -> io::Result<W> {
    let mut writer = PerfSpoolWriter::from_writer(writer, 1_700_000_000_000_000, 1_000)?;
    write_spool_samples(&mut writer, modules, process_execs, samples)?;
    writer.flush()?;
    Ok(writer.into_inner())
}

fn write_spool_samples<W: Write>(
    writer: &mut PerfSpoolWriter<W>,
    modules: &[ModuleRecord],
    process_execs: &[ProcessExecRecord],
    samples: &[BenchSpoolSample],
) -> io::Result<()> {
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
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::{FrameMode, PerfSpoolReader};
    use crate::test_support::TempDir;
    use std::fs;

    #[test]
    fn writes_synthetic_spool_samples_to_memory() {
        let temp = TempDir::new("bench-spool");
        let path = temp.path().join("samples.spool");
        let module = ModuleRecord {
            id: 0,
            process_id: 42,
            start: 0x1000,
            end: 0x2000,
            file_offset: 0x100,
            inode: 7,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/tmp/libstackpulse.so".into(),
            is_kernel: false,
        };
        let exec = ProcessExecRecord {
            timestamp_ns: 1_700_000_000_000_001,
            process_id: 42,
            is_python_runtime: true,
        };
        let frame = FrameRecord {
            module_id: Some(0),
            rel_ip: 0x120,
            abs_ip: 0x1020,
            mode: FrameMode::User,
        };
        let marker = FrameRecord::truncated_stack_marker();
        let samples = [BenchSpoolSample {
            timestamp_ns: 1_700_000_000_000_002,
            process_id: 42,
            thread_id: 43,
            frames: vec![frame, marker],
        }];

        let bytes = write_spool_samples_to_writer(
            Vec::new(),
            std::slice::from_ref(&module),
            std::slice::from_ref(&exec),
            &samples,
        )
        .expect("write spool samples");
        let reported_len = write_spool_samples_to_memory(
            std::slice::from_ref(&module),
            std::slice::from_ref(&exec),
            &samples,
            bytes.len() * 2,
        )
        .expect("write sized spool samples");
        write_spool_samples_to_path(
            &path,
            std::slice::from_ref(&module),
            std::slice::from_ref(&exec),
            &samples,
        )
        .expect("persist spool bytes through real writer");
        let file_bytes = fs::read(&path).expect("read persisted spool bytes");

        let reader = PerfSpoolReader::open(&path).expect("read generated spool");

        assert_eq!(bytes.get(..8), Some(CURRENT_SPOOL_MAGIC.as_slice()));
        assert_eq!(file_bytes.get(..8), Some(CURRENT_SPOOL_MAGIC.as_slice()));
        assert_eq!(file_bytes, bytes);
        assert_eq!(reported_len, bytes.len());
        assert_eq!(reader.start_timestamp_us(), 1_700_000_000_000_000);
        assert_eq!(reader.sample_interval_us(), 1_000);
        assert_eq!(reader.modules().len(), 1);
        assert_eq!(reader.modules()[0].path.as_str(), "/tmp/libstackpulse.so");
        assert_eq!(reader.modules()[0].file_offset, 0x100);
        assert_eq!(reader.process_execs().len(), 1);
        assert_eq!(reader.process_execs()[0].timestamp_ns, exec.timestamp_ns);
        assert_eq!(reader.process_execs()[0].process_id, 42);
        assert!(reader.process_execs()[0].is_python_runtime);
        assert_eq!(reader.samples().len(), 1);
        assert_eq!(reader.samples()[0].timestamp_ns, samples[0].timestamp_ns);
        assert_eq!(reader.samples()[0].process_id, 42);
        assert_eq!(reader.samples()[0].thread_id, 43);

        let mut frames = Vec::new();
        reader
            .stack_frames(reader.samples()[0].stack_id, &mut frames)
            .expect("read sample stack");
        assert_eq!(frames, vec![frame, marker]);
    }

    #[test]
    fn sparse_kernel_symbols_fixture_builds_requested_addresses() {
        let fixture = SparseKernelSymbolsFixture::new(4, 4);
        let base = 0xffff_ffff_8100_0000_u64;
        let expected_data = concat!(
            "ffffffff81000000 T _text\n",
            "ffffffff81000020 T bench_kernel_symbol_1\n",
            "ffffffff81000040 T bench_kernel_symbol_2\n",
            "ffffffff81000060 T bench_kernel_symbol_3\n",
        );

        assert_eq!(fixture.bytes(), expected_data.len() as u64);
        assert_eq!(std::str::from_utf8(&fixture.data), Ok(expected_data));
        assert_eq!(fixture.requested_addresses, vec![base + 0x30, base + 0x50]);
        assert_eq!(
            parse_sparse_kernel_symbols(&fixture, 1),
            sparse_symbol_checksum(&[
                (base + 0x30, base + 0x20, "bench_kernel_symbol_1"),
                (base + 0x50, base + 0x40, "bench_kernel_symbol_2"),
            ])
        );
    }

    fn sparse_symbol_checksum(symbols: &[(u64, u64, &str)]) -> usize {
        symbols
            .iter()
            .fold(0usize, |checksum, (request, address, name)| {
                checksum
                    .wrapping_add(*request as usize)
                    .wrapping_add(*address as usize)
                    .wrapping_add(name.len())
            })
    }
}
