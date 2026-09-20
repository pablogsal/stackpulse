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
        let mut retired = FxHashSet::default();
        apply_update(
            &mut registry.code_ranges,
            &mut retired,
            update,
            7,
            unwinder,
            modules,
            writer,
        )
        .unwrap();
        retire_ranges(&mut registry.code_ranges, &mut retired, unwinder);
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
        &mut FxHashSet::default(),
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

#[test]
fn removals_are_batched_before_replacement_and_preserve_other_owners() {
    let mut registry = JitRegistry::default();
    let mut unwinder = NativeUnwinder::default();
    for index in 0..128 {
        let start = 0x1000 + index * 0x100;
        registry.code_ranges.insert(
            start,
            CodeRange {
                end: start + 0x100,
                module_id: index as u32,
                path: PathBuf::from(format!("[jit-{index}]")).into(),
            },
        );
        unwinder.add_jit_module(test_module(start..start + 0x100));
    }
    let mut modules = ModuleTable::default();
    let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
    let mut retired = FxHashSet::default();
    for index in 0..127 {
        apply_update(
            &mut registry.code_ranges,
            &mut retired,
            Update::Removed {
                path: format!("[jit-{index}]").into(),
            },
            7,
            &mut unwinder,
            &mut modules,
            &mut writer,
        )
        .unwrap();
    }
    // A removal batch leaves the range table untouched until publication starts.
    assert_eq!(registry.code_ranges.len(), 128);
    apply_update(
        &mut registry.code_ranges,
        &mut retired,
        Update::Loaded {
            path: "[jit-0]".into(),
            modules: vec![test_module(0x1000..0x1100)].into(),
            symbols: Some(Vec::new()),
        },
        7,
        &mut unwinder,
        &mut modules,
        &mut writer,
    )
    .unwrap();
    retire_ranges(&mut registry.code_ranges, &mut retired, &mut unwinder);
    assert_eq!(registry.code_ranges.len(), 2);
    assert!(registry.frame(0x1001).is_some());
    assert!(registry.frame(0x1101).is_none());
    assert!(registry.frame(0x8f01).is_some());
    assert!(!unwinder.is_runtime_frame(FrameAddress::from_instruction_pointer(0x1101)));
    assert!(unwinder.is_runtime_frame(FrameAddress::from_instruction_pointer(0x1001)));
}

struct TestProcess(std::process::Child);
impl Drop for TestProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn periodic_maps_read_detects_descriptor_unload_without_a_mapping_event() {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};

    let directory = TempDir::new("jit-adapter-unload");
    let source = directory.path().join("registry.c");
    let library = directory.path().join("registry.so");
    let program = directory.path().join("target");
    std::fs::write(
        &source,
        r#"
#ifdef REGISTRY_LIBRARY
struct { unsigned version, action; void *relevant, *first; } __jit_debug_descriptor = {1,0,0,0};
#else
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    int fd = open(argv[1], O_RDONLY);
    struct stat status;
    if (!library || fd < 0 || fstat(fd, &status)) return 2;
    void *view = mmap(0, status.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (view == MAP_FAILED) return 3;
    puts("loaded"); fflush(stdout);
    if (getchar() == EOF) return 0;
    if (dlclose(library)) return 4;
    puts("unloaded"); fflush(stdout);
    getchar();
    munmap(view, status.st_size);
    return 0;
}
#endif
"#,
    )
    .unwrap();
    for (output, options) in [
        (&library, &["-shared", "-fPIC", "-DREGISTRY_LIBRARY"][..]),
        (&program, &[][..]),
    ] {
        let compiled = Command::new("cc")
            .args(options)
            .arg(&source)
            .args(["-ldl", "-o"])
            .arg(output)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
    }
    let mut child = TestProcess(
        Command::new(&program)
            .arg(&library)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = std::io::BufReader::new(child.0.stdout.take().unwrap());
    let mut phase = String::new();
    output.read_line(&mut phase).unwrap();
    assert_eq!(phase, "loaded\n");
    let mut registry = JitRegistry::default();
    let mut unwinder = NativeUnwinder::default();
    let mut modules = ModuleTable::default();
    let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
    let pid = child.0.id() as i32;
    registry
        .refresh(pid, &mut unwinder, &mut modules, &mut writer)
        .unwrap();
    assert!(registry
        .mappings
        .iter()
        .any(|mapping| mapping.path == library && mapping.executable));
    assert!(!registry.registry.as_ref().unwrap().is_absent());
    let generation = registry.generation;
    child.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    phase.clear();
    output.read_line(&mut phase).unwrap();
    assert_eq!(phase, "unloaded\n");
    registry.last_maps_read = Some(Instant::now() - Duration::from_secs(2));
    registry
        .refresh(pid, &mut unwinder, &mut modules, &mut writer)
        .unwrap();
    assert!(registry.generation > generation);
    assert!(registry
        .mappings
        .iter()
        .any(|mapping| mapping.path == library && !mapping.executable));
    assert!(!registry
        .mappings
        .iter()
        .any(|mapping| mapping.path == library && mapping.executable));
    assert!(
        registry.registry.as_ref().unwrap().is_absent(),
        "unloaded descriptor must retire despite the surviving file view"
    );
}

#[test]
fn confirmed_absence_skips_periodic_maps_reads_until_an_event() {
    let mut child = std::process::Command::new("sleep")
        .arg("10")
        .spawn()
        .unwrap();
    let mut registry = JitRegistry::default();
    let mut unwinder = NativeUnwinder::default();
    let mut modules = ModuleTable::default();
    let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
    let pid = child.id() as i32;
    registry
        .refresh(pid, &mut unwinder, &mut modules, &mut writer)
        .unwrap();
    let absent = registry.registry.as_ref().unwrap().is_absent();
    let old_read = Instant::now() - Duration::from_secs(2);
    registry.last_maps_read = Some(old_read);
    registry
        .refresh(pid, &mut unwinder, &mut modules, &mut writer)
        .unwrap();
    let periodic_read = registry.last_maps_read;
    registry.mappings_changed();
    registry
        .refresh(pid, &mut unwinder, &mut modules, &mut writer)
        .unwrap();
    let event_read = registry.last_maps_read;
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(absent);
    assert_eq!(periodic_read, Some(old_read));
    assert!(event_read > periodic_read);
}
