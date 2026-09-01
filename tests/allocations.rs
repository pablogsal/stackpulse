use stackpulse::bench_support::{write_spool_samples_to_path, BenchSpoolSample};
use stackpulse::spool::{FrameMode, FrameRecord};
use stackpulse::symbolize::{KernelSymbolSource, StackCache};
use stackpulse::Snapshot;

#[test]
fn cached_stack_resolution_allocates_nothing() {
    let path = std::env::temp_dir().join(format!(
        "stackpulse-allocation-contract-{}.spool",
        std::process::id()
    ));
    let samples = [BenchSpoolSample {
        timestamp_ns: 1_000,
        process_id: 7,
        thread_id: 11,
        frames: vec![frame(0x1500), frame(0x1600)],
    }];
    write_spool_samples_to_path(&path, &[], &[], &samples).unwrap();

    let reader = Snapshot::open(&path).unwrap();
    let stack = reader.stacks().next().unwrap();
    for cache in [StackCache::Internal, StackCache::External] {
        let mut symbolizer = reader
            .symbolizer()
            .disable_perf_maps()
            .kernel_symbols(KernelSymbolSource::Disabled)
            .stack_cache(cache)
            .build()
            .unwrap();
        assert_eq!(symbolizer.resolve(stack.clone()).unwrap().count(), 2);

        let allocations = allocation_counter::measure(|| {
            assert_eq!(symbolizer.resolve(stack.clone()).unwrap().count(), 2);
        });
        assert_eq!(allocations.count_total, 0, "{cache:?}");
        assert_eq!(allocations.count_current, 0, "{cache:?}");
    }

    std::fs::remove_file(path).unwrap();
}

fn frame(address: u64) -> FrameRecord {
    FrameRecord {
        module_id: None,
        file_relative_ip: address,
        abs_ip: address,
        mode: FrameMode::User,
    }
}
