use stackpulse::bench_support::{write_spool_samples_to_path, BenchSpoolSample};
use stackpulse::bench_support::{FrameMode, FrameRecord};
use stackpulse::symbolize::KernelSymbolSource;
use stackpulse::Snapshot;

#[test]
fn cloned_modules_preserve_native_paths_without_allocating() {
    use std::ffi::OsStr;
    use std::hint::black_box;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    let path = std::env::temp_dir().join(format!(
        "stackpulse-module-allocation-contract-{}.spool",
        std::process::id()
    ));
    let module_path = Path::new(OsStr::from_bytes(b"/tmp/lib-\xff.so"));
    let module = stackpulse::bench_support::module(
        0,
        stackpulse::Pid::new(7).unwrap(),
        0x1000..0x2000,
        0,
        module_path,
    )
    .unwrap();
    write_spool_samples_to_path(&path, &[module], &[], &[]).unwrap();

    let reader = Snapshot::open(&path).unwrap();
    let module = &reader.modules()[0];
    assert_eq!(module.path(), module_path);
    let allocations = allocation_counter::measure(|| {
        for _ in 0..1_000 {
            black_box(module.clone());
        }
    });
    assert_eq!(allocations.count_total, 0);

    std::fs::remove_file(path).unwrap();
}

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
    let stack = reader.samples().next().unwrap();
    {
        let mut symbolizer = reader
            .symbolizer()
            .disable_perf_maps()
            .kernel_symbols(KernelSymbolSource::Disabled)
            .build()
            .unwrap();
        assert_eq!(symbolizer.resolve(stack.stack()).unwrap().len(), 2);

        let allocations = allocation_counter::measure(|| {
            assert_eq!(symbolizer.resolve(stack.stack()).unwrap().len(), 2);
        });
        assert_eq!(allocations.count_total, 0);
        assert_eq!(allocations.count_current, 0);
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

#[test]
fn live_batches_reuse_storage_for_repeated_and_new_frames() {
    use std::fs::File;
    use std::time::Duration;

    use stackpulse::bench_support::LiveSpoolFixture;
    use stackpulse::symbolize::StackEntry;
    use stackpulse::ReadStatus;

    let path = std::env::temp_dir().join(format!(
        "stackpulse-live-allocation-contract-{}.spool",
        std::process::id()
    ));
    let (mut writer, mut reader) =
        LiveSpoolFixture::new(File::create(&path).unwrap(), false).unwrap();
    let mut session = reader
        .symbolizer()
        .disable_perf_maps()
        .build()
        .unwrap()
        .cache_stacks::<usize>(16);
    let ReadStatus::Batch(batch) = session.poll(Duration::ZERO).unwrap() else {
        panic!("initial definitions must be readable");
    };
    assert_eq!(batch.samples().len(), 0);
    let mut sample = BenchSpoolSample {
        timestamp_ns: 1_000,
        process_id: 7,
        thread_id: 11,
        frames: vec![frame(0x1500), frame(0x1600)],
    };
    for batch_index in 0..4 {
        writer.append(&sample).unwrap();
        writer.flush().unwrap();
        let allocations = allocation_counter::measure(|| {
            let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
                panic!("published sample must be readable");
            };
            assert_eq!(batch.samples().len(), 1);
            let stack = batch.samples().next().unwrap().stack();
            match batch.entry(stack).unwrap() {
                StackEntry::Occupied(value) => assert_eq!(*value, 2),
                StackEntry::Vacant(entry) => {
                    let entry = entry.resolve().unwrap();
                    let len = entry.stack().len();
                    assert_eq!(*entry.insert(len), 2);
                }
            }
        });
        if batch_index != 0 {
            assert_eq!(allocations.count_total, 0);
        }
        assert!(matches!(
            session.poll(Duration::ZERO).unwrap(),
            ReadStatus::Pending
        ));
        sample.timestamp_ns += 1_000;
    }
    let allocations = allocation_counter::measure(|| {
        for _ in 0..256 {
            sample.timestamp_ns += 1_000;
            for frame in &mut sample.frames {
                frame.abs_ip += 0x1000;
                frame.file_relative_ip = frame.abs_ip;
            }
            writer.append(&sample).unwrap();
            writer.flush().unwrap();
            let ReadStatus::Batch(mut batch) = session.poll(Duration::ZERO).unwrap() else {
                panic!("published sample must be readable");
            };
            let stack = batch.samples().next().unwrap().stack();
            let StackEntry::Vacant(entry) = batch.entry(stack).unwrap() else {
                panic!("new frames must produce a new stack");
            };
            let entry = entry.resolve().unwrap();
            assert_eq!(entry.stack().len(), 2);
            entry.insert(2);
        }
    });
    assert!(allocations.count_total < 128, "{allocations:?}");
    writer.finish().unwrap();
    assert!(matches!(
        session.poll(Duration::ZERO).unwrap(),
        ReadStatus::Finished(_)
    ));
    std::fs::remove_file(path).unwrap();
}
