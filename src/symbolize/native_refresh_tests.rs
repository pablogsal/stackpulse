use super::*;
use crate::profile::FrameKey;
use crate::spool::{FrameMode, FrameRecord, ModuleRecord};
use crate::Pid;
use std::cell::Cell;
use std::collections::HashMap;
use std::fs::File;
use std::rc::Rc;

fn own_executable_record() -> ModuleRecord {
    super::tests::current_executable_module(0, std::process::id() as i32)
}

fn symbol(name: &str) -> NativeSymbol {
    NativeSymbol::new(name, "fixture")
}

#[derive(Default)]
struct RefreshControl {
    published_generation: Cell<u64>,
    refresh_calls: Cell<usize>,
    symbol_calls: Cell<usize>,
    fail_on_call: Cell<Option<usize>>,
}

#[derive(Debug, thiserror::Error)]
#[error("controlled native refresh failure {0}")]
struct RefreshFailure(u32);

struct RefreshingBackend {
    control: Rc<RefreshControl>,
    observed_generation: u64,
}

impl crate::symbolize::NativeSymbolizer for RefreshingBackend {
    type Error = RefreshFailure;

    fn refresh(&mut self) -> Result<u64, Self::Error> {
        let call = self.control.refresh_calls.get() + 1;
        self.control.refresh_calls.set(call);
        if self.control.fail_on_call.get() == Some(call) {
            return Err(RefreshFailure(73));
        }
        self.observed_generation = self.control.published_generation.get();
        Ok(self.observed_generation)
    }

    fn symbolize(&mut self, mut batch: NativeBatch<'_>) -> Result<(), Self::Error> {
        self.control
            .symbol_calls
            .set(self.control.symbol_calls.get() + 1);
        let name = if self.observed_generation == 0 {
            "fallback"
        } else {
            "published"
        };
        for (_, output) in batch.entries() {
            *output = symbol(name).into();
        }
        Ok(())
    }
}

fn write_live_sample(
    writer: &mut crate::spool::PerfSpoolWriter<File>,
    module: &ModuleRecord,
    timestamp: u64,
) {
    let pid = module.pid().unwrap();
    writer
        .write_sample_frames(
            timestamp,
            pid.get(),
            11,
            [FrameRecord {
                module_id: Some(module.id()),
                file_relative_ip: module.file_offset() + 8,
                abs_ip: module.start + 8,
                mode: FrameMode::User,
            }],
        )
        .unwrap();
    writer.flush().unwrap();
}

#[derive(Default)]
struct PreparedCacheModel {
    stacks: HashMap<crate::spool::StackKey, String>,
    frames: HashMap<FrameKey, String>,
    preparations: usize,
}

impl PreparedCacheModel {
    fn invalidate(&mut self, invalidation: &crate::symbolize::Invalidation<'_>) {
        self.stacks
            .retain(|key, _| !invalidation.affects_process(key.process_id()));
    }

    fn resolve(
        &mut self,
        resolver: &mut crate::Symbolizer,
        stack: crate::spool::Sample<'_>,
    ) -> String {
        let key = stack.key();
        if let Some(prepared) = self.stacks.get(&key) {
            return prepared.clone();
        }
        let resolved = resolver.resolve(stack.stack()).unwrap();
        let (id, frame) = resolved.iter().next().unwrap();
        let value = self
            .frames
            .entry(id)
            .or_insert_with(|| frame.name().unwrap().to_owned())
            .clone();
        self.stacks.insert(key, value.clone());
        self.preparations += 1;
        value
    }
}

#[test]
fn refresh_invalidates_both_cache_modes_before_prepared_lookup() {
    use crate::symbolize::{KernelSymbolSource, StackCache};
    for mode in [StackCache::Internal, StackCache::External] {
        let files = crate::test_support::TempDir::new("native-refresh");
        let file = files.path().join("recording.spool");
        let mut writer =
            crate::spool::PerfSpoolWriter::from_writer(File::create(&file).unwrap(), 0, 10)
                .unwrap();
        let mut module = own_executable_record();
        module.id = 0;
        writer.write_module(&module).unwrap();
        write_live_sample(&mut writer, &module, 1);
        let mut tail = crate::Tail::open(&file).unwrap();
        let control = Rc::new(RefreshControl::default());
        let factory_control = control.clone();
        let mut resolver = tail
            .symbolizer()
            .disable_perf_maps()
            .kernel_symbols(KernelSymbolSource::Disabled)
            .stack_cache(mode)
            .native(move |_| RefreshingBackend {
                control: factory_control.clone(),
                observed_generation: 0,
            })
            .build()
            .unwrap();
        let mut prepared = PreparedCacheModel::default();
        {
            resolver.refresh_native_sources().unwrap();
            let batch = tail.poll().unwrap();
            prepared.invalidate(&resolver.update(&batch).unwrap());
            let stack = batch.samples().next().unwrap();
            assert_eq!(prepared.resolve(&mut resolver, stack), "fallback");
            assert_eq!(control.symbol_calls.get(), 1);
        }
        write_live_sample(&mut writer, &module, 2);
        {
            resolver.refresh_native_sources().unwrap();
            let batch = tail.poll().unwrap();
            let stack = batch.samples().next().unwrap();
            assert!(prepared.stacks.contains_key(&stack.key()));
            let invalidation = resolver.update(&batch).unwrap();
            assert!(!invalidation.affects_process(module.pid().unwrap()));
            prepared.invalidate(&invalidation);
            if mode == StackCache::Internal {
                assert_eq!(
                    resolver
                        .resolve(stack.stack())
                        .unwrap()
                        .frames()
                        .next()
                        .unwrap()
                        .name(),
                    Some("fallback")
                );
            }
            assert_eq!(prepared.resolve(&mut resolver, stack), "fallback");
            assert_eq!(control.symbol_calls.get(), 1);
            assert_eq!(prepared.preparations, 1);
        }
        control.published_generation.set(1);
        write_live_sample(&mut writer, &module, 3);
        {
            resolver.refresh_native_sources().unwrap();
            let batch = tail.poll().unwrap();
            let stack = batch.samples().next().unwrap();
            assert!(prepared.stacks.contains_key(&stack.key()));
            let invalidation = resolver.update(&batch).unwrap();
            assert!(invalidation.affects_process(module.pid().unwrap()));
            prepared.invalidate(&invalidation);
            assert!(!prepared.stacks.contains_key(&stack.key()));
            assert_eq!(prepared.resolve(&mut resolver, stack), "published");
            assert_eq!(control.symbol_calls.get(), 2);
            assert_eq!(prepared.preparations, 2);
            assert_eq!(prepared.frames.len(), 2);
        }
        write_live_sample(&mut writer, &module, 4);
        {
            resolver.refresh_native_sources().unwrap();
            let batch = tail.poll().unwrap();
            let invalidation = resolver.update(&batch).unwrap();
            assert!(!invalidation.affects_process(module.pid().unwrap()));
            prepared.invalidate(&invalidation);
            assert_eq!(
                prepared.resolve(&mut resolver, batch.samples().next().unwrap()),
                "published"
            );
            assert_eq!(control.symbol_calls.get(), 2);
            assert_eq!(prepared.preparations, 2);
        }
    }
}

#[test]
fn refresh_error_preserves_source_and_generations_before_tail_advance() {
    use crate::symbolize::{KernelSymbolSource, StackCache};
    let files = crate::test_support::TempDir::new("native-refresh");
    let file = files.path().join("recording.spool");
    let mut writer =
        crate::spool::PerfSpoolWriter::from_writer(File::create(&file).unwrap(), 0, 10).unwrap();
    let mut first = own_executable_record();
    first.id = 0;
    let mut second = first.clone();
    second.id = 1;
    second.set_pid(Pid::new(i32::MAX - first.pid().unwrap().get()).unwrap());
    for module in [&first, &second] {
        writer.write_module(module).unwrap();
    }
    write_live_sample(&mut writer, &first, 1);
    write_live_sample(&mut writer, &second, 2);
    let mut tail = crate::Tail::open(&file).unwrap();
    let control = Rc::new(RefreshControl::default());
    let factory_control = control.clone();
    let mut resolver = tail
        .symbolizer()
        .disable_perf_maps()
        .kernel_symbols(KernelSymbolSource::Disabled)
        .stack_cache(StackCache::External)
        .native(move |_| RefreshingBackend {
            control: factory_control.clone(),
            observed_generation: 0,
        })
        .build()
        .unwrap();
    let mut prepared = PreparedCacheModel::default();
    {
        resolver.refresh_native_sources().unwrap();
        let batch = tail.poll().unwrap();
        prepared.invalidate(&resolver.update(&batch).unwrap());
        for stack in batch.samples() {
            assert_eq!(prepared.resolve(&mut resolver, stack), "fallback");
        }
        assert_eq!(control.symbol_calls.get(), 2);
        assert_eq!(prepared.stacks.len(), 2);
    }
    control.published_generation.set(1);
    control
        .fail_on_call
        .set(Some(control.refresh_calls.get() + 2));
    write_live_sample(&mut writer, &first, 3);
    write_live_sample(&mut writer, &second, 4);
    let error = match resolver.refresh_native_sources() {
        Ok(_) => panic!("controlled second refresh must fail"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), crate::ErrorKind::NativeSymbolizer);
    let source = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<RefreshFailure>()
        .unwrap();
    assert_eq!(source.0, 73);
    assert_eq!(prepared.stacks.len(), 2);
    assert_eq!(control.symbol_calls.get(), 2);
    control.fail_on_call.set(None);
    resolver.refresh_native_sources().unwrap();
    let batch = tail.poll().unwrap();
    assert_eq!(batch.samples().len(), 2);
    let invalidation = resolver.update(&batch).unwrap();
    assert!(invalidation.affects_process(first.pid().unwrap()));
    assert!(invalidation.affects_process(second.pid().unwrap()));
    prepared.invalidate(&invalidation);
    assert!(prepared.stacks.is_empty());
    for stack in batch.samples() {
        assert_eq!(prepared.resolve(&mut resolver, stack), "published");
    }
    assert_eq!(control.symbol_calls.get(), 4);
    assert_eq!(prepared.preparations, 4);
}

#[test]
fn native_refresh_overrides_perf_map_only_frame_preservation() {
    use crate::symbolize::{KernelSymbolSource, StackCache};
    let directory = crate::test_support::TempDir::new("native-perf-refresh");
    let files = crate::test_support::TempDir::new("native-refresh");
    let file = files.path().join("recording.spool");
    let mut writer =
        crate::spool::PerfSpoolWriter::from_writer(File::create(&file).unwrap(), 0, 10).unwrap();
    let mut module = own_executable_record();
    module.id = 0;
    let map = directory
        .path()
        .join(format!("perf-{}.map", module.pid().unwrap()));
    std::fs::write(&map, "1000 20 py::first:/ordinary.py\n").unwrap();
    writer.write_module(&module).unwrap();
    write_live_sample(&mut writer, &module, 1);
    let mut tail = crate::Tail::open(&file).unwrap();
    let control = Rc::new(RefreshControl::default());
    let factory_control = control.clone();
    let mut resolver = tail
        .symbolizer()
        .perf_map_dir(directory.path())
        .kernel_symbols(KernelSymbolSource::Disabled)
        .stack_cache(StackCache::External)
        .native(move |_| RefreshingBackend {
            control: factory_control.clone(),
            observed_generation: 0,
        })
        .build()
        .unwrap();
    {
        resolver.refresh_native_sources().unwrap();
        let batch = tail.poll().unwrap();
        resolver.update(&batch).unwrap();
        assert_eq!(
            resolver
                .resolve(batch.samples().next().unwrap().stack())
                .unwrap()
                .frames()
                .next()
                .unwrap()
                .name(),
            Some("fallback")
        );
    }
    control.published_generation.set(1);
    std::fs::write(
        &map,
        "1000 20 py::first:/ordinary.py\n2000 20 py::second:/ordinary.py\n",
    )
    .unwrap();
    write_live_sample(&mut writer, &module, 2);
    resolver.refresh_native_sources().unwrap();
    let batch = tail.poll().unwrap();
    assert!(resolver
        .update(&batch)
        .unwrap()
        .affects_process(module.pid().unwrap()));
    assert_eq!(
        resolver
            .resolve(batch.samples().next().unwrap().stack())
            .unwrap()
            .frames()
            .next()
            .unwrap()
            .name(),
        Some("published")
    );
    assert_eq!(control.symbol_calls.get(), 2);
}

#[test]
fn unchanged_native_refresh_reuses_staging_allocations() {
    let directory = crate::test_support::TempDir::new("native-refresh-allocations");
    let path = directory.path().join("recording.spool");
    let mut writer =
        crate::spool::PerfSpoolWriter::from_writer(File::create(&path).unwrap(), 0, 10).unwrap();
    let module = own_executable_record();
    writer.write_module(&module).unwrap();
    write_live_sample(&mut writer, &module, 1);
    let mut tail = crate::Tail::open(&path).unwrap();
    let control = Rc::new(RefreshControl::default());
    let factory_control = Rc::clone(&control);
    let mut resolver = tail
        .symbolizer()
        .disable_perf_maps()
        .kernel_symbols(KernelSymbolSource::Disabled)
        .native(move |_| RefreshingBackend {
            control: Rc::clone(&factory_control),
            observed_generation: 0,
        })
        .build()
        .unwrap();
    {
        let batch = tail.poll().unwrap();
        resolver.update(&batch).unwrap();
        resolver
            .resolve(batch.samples().next().unwrap().stack())
            .unwrap();
    }
    resolver.refresh_native_sources().unwrap();
    for timestamp in 2..12 {
        write_live_sample(&mut writer, &module, timestamp);
        let refresh = allocation_counter::measure(|| resolver.refresh_native_sources().unwrap());
        assert_eq!(refresh.count_total, 0);
        let batch = tail.poll().unwrap();
        let update = allocation_counter::measure(|| {
            assert!(!resolver
                .update(&batch)
                .unwrap()
                .affects_process(module.pid().unwrap()));
        });
        assert_eq!(update.count_total, 0);
    }
    assert_eq!(control.symbol_calls.get(), 1);
}
