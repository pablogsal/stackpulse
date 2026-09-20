use super::*;
use crate::jit::Symbol;
use crate::linux::unwind::test_module;
use crate::spool::Snapshot;
use crate::test_support::TempDir;
use framehop::FrameAddress;
use std::cell::Cell;
use std::rc::Rc;

fn loaded(name: &str) -> Update<ElfSectionData> {
    Update::Loaded {
        path: "[jit-test]".into(),
        modules: vec![test_module(0x1000..0x1100), test_module(0x2000..0x2100)].into(),
        symbols: Some(vec![
            Symbol {
                range: 0x1000..0x1100,
                name: Some(name.into()),
            },
            Symbol {
                range: 0x2000..0x2100,
                name: None,
            },
        ]),
    }
}

#[test]
fn recorded_identities_survive_cfi_updates_retirement_and_address_reuse() {
    let mut registry = JitRegistry::default();
    let mut unwinder = NativeUnwinder::default();
    let mut modules = ModuleTable::default();
    let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
    let apply = |registry: &mut JitRegistry,
                 update,
                 unwinder: &mut NativeUnwinder,
                 modules: &mut ModuleTable,
                 writer: &mut PerfSpoolWriter<Vec<u8>>| {
        apply_update(
            &mut registry.code_ranges,
            update,
            7,
            unwinder,
            modules,
            writer,
        )
        .unwrap();
    };
    apply(
        &mut registry,
        loaded("first"),
        &mut unwinder,
        &mut modules,
        &mut writer,
    );
    let first = registry.frame(0x1008).unwrap();
    let unnamed = registry.frame(0x2008).unwrap();
    assert_eq!(first.file_relative_ip, 8);
    assert!(registry.frame(0x1100).is_none());
    assert!(registry.frame(0x1fff).is_none());
    assert!(unwinder.is_runtime_frame(FrameAddress::from_instruction_pointer(0x2008)));
    writer
        .write_sample_frames(1, 7, 7, [first, unnamed])
        .unwrap();

    apply(
        &mut registry,
        Update::Loaded {
            path: "[jit-test]".into(),
            modules: vec![test_module(0x1000..0x1100), test_module(0x2000..0x2100)].into(),
            symbols: None,
        },
        &mut unwinder,
        &mut modules,
        &mut writer,
    );
    assert_eq!(registry.frame(0x1008), Some(first));
    assert_eq!(registry.frame(0x2008), Some(unnamed));

    apply(
        &mut registry,
        Update::Removed {
            path: "[jit-test]".into(),
        },
        &mut unwinder,
        &mut modules,
        &mut writer,
    );
    assert!(registry.frame(0x1008).is_none());
    assert!(!unwinder.is_runtime_frame(FrameAddress::from_instruction_pointer(0x1008)));
    apply(
        &mut registry,
        loaded("second"),
        &mut unwinder,
        &mut modules,
        &mut writer,
    );
    let second = registry.frame(0x1008).unwrap();
    assert_ne!(first.module_id, second.module_id);
    writer.write_sample_frames(2, 7, 7, [second]).unwrap();

    let directory = TempDir::new("jit-adapter-spool");
    let path = directory.path().join("capture");
    std::fs::write(&path, writer.into_inner()).unwrap();
    let snapshot = Snapshot::open(&path).unwrap();
    assert_eq!(snapshot.modules().len(), 4);
    let recorded = |frame: FrameRecord| &snapshot.modules()[frame.module_id.unwrap() as usize];
    assert_eq!(
        &*recorded(first).jit_symbols.as_ref().unwrap()[0].name,
        "first"
    );
    assert_eq!(
        &*recorded(second).jit_symbols.as_ref().unwrap()[0].name,
        "second"
    );
    assert!(recorded(unnamed).jit_symbols.as_ref().unwrap().is_empty());
}

struct FailingWriter(Rc<Cell<bool>>);

impl io::Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.get() {
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn persistence_failure_is_returned_before_frame_or_unwind_publication() {
    let fail = Rc::new(Cell::new(false));
    let mut writer = PerfSpoolWriter::from_writer(FailingWriter(fail.clone()), 0, 0).unwrap();
    fail.set(true);
    let mut ranges = BTreeMap::new();
    let mut unwinder = NativeUnwinder::default();
    let error = apply_update(
        &mut ranges,
        loaded("failed"),
        7,
        &mut unwinder,
        &mut ModuleTable::default(),
        &mut writer,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&io::Error::from_raw_os_error(libc::ENOSPC).to_string()),
        "{error}"
    );
    assert!(ranges.is_empty());
    assert!(!unwinder.is_runtime_frame(FrameAddress::from_instruction_pointer(0x1008)));
}

#[test]
fn failed_maps_reads_wait_before_retrying() {
    let mut registry = JitRegistry::default();
    let mut unwinder = NativeUnwinder::default();
    let mut modules = ModuleTable::default();
    let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
    registry
        .refresh(-1, &mut unwinder, &mut modules, &mut writer)
        .unwrap();
    let retry = registry.maps_retry_at.unwrap();
    registry.mappings_changed();
    registry
        .refresh(-1, &mut unwinder, &mut modules, &mut writer)
        .unwrap();
    assert_eq!(registry.maps_retry_at, Some(retry));
    assert!(registry.registry.is_none());
}
