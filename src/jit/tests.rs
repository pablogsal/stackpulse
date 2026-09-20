use super::object::{jit_symbols, JitUnwind};
use super::protocol::JitCodeEntry;
use super::*;
use crate::elf::find_section_range;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

trait Encode {
    fn encode(self) -> Vec<u8>;
}
impl Encode for JitCodeEntry {
    fn encode(self) -> Vec<u8> {
        [
            self.next_entry,
            self.prev_entry,
            self.symfile_addr,
            self.symfile_size,
        ]
        .into_iter()
        .flat_map(u64::to_ne_bytes)
        .collect()
    }
}
impl Encode for JitDescriptor {
    fn encode(self) -> Vec<u8> {
        [
            self.version.to_ne_bytes().as_slice(),
            self.action_flag.to_ne_bytes().as_slice(),
            self.relevant_entry.to_ne_bytes().as_slice(),
            self.first_entry.to_ne_bytes().as_slice(),
        ]
        .concat()
    }
}

struct MockProcess {
    pid: i32,
    memory: RefCell<BTreeMap<u64, Vec<u8>>>,
}

impl MockProcess {
    fn new(pid: i32) -> Self {
        Self {
            pid,
            memory: RefCell::default(),
        }
    }
    fn set_memory(&self, address: usize, bytes: &[u8]) {
        self.memory
            .borrow_mut()
            .insert(address as u64, bytes.to_vec());
    }
    fn set_value(&self, address: usize, value: impl Encode) {
        self.set_memory(address, &value.encode());
    }
}

impl MemoryReader for MockProcess {
    fn pid(&self) -> i32 {
        self.pid
    }
    fn read(&self, address: u64, bytes: &mut [u8]) -> std::io::Result<()> {
        let memory = self.memory.borrow();
        let data = memory
            .range(..=address)
            .next_back()
            .and_then(|(&start, data)| data.get((address - start) as usize..))
            .and_then(|data| data.get(..bytes.len()))
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        bytes.copy_from_slice(data);
        Ok(())
    }
}

struct TestMapping {
    range: std::ops::Range<u64>,
    offset: u64,
}
impl Mapping for TestMapping {
    fn range(&self) -> std::ops::Range<u64> {
        self.range.clone()
    }
    fn path(&self) -> &Path {
        Path::new("/llvm.so")
    }
    fn file_offset(&self) -> u64 {
        self.offset
    }
    fn executable(&self) -> bool {
        true
    }
    fn deleted(&self) -> bool {
        false
    }
}

fn take_updates<R: MemoryReader>(reader: &mut Registry<R, Arc<[u8]>>) -> Vec<Update<Arc<[u8]>>> {
    let mut updates = Vec::new();
    reader.drain_updates(|update| updates.push(update));
    updates
}

fn entry(next: u64, previous: u64, symfile_addr: u64, symfile_size: u64) -> JitCodeEntry {
    JitCodeEntry {
        next_entry: next,
        prev_entry: previous,
        symfile_addr,
        symfile_size,
    }
}

fn descriptor(address: u64, owner: &str) -> JitDescriptorLocation {
    JitDescriptorLocation {
        address,
        owner: PathBuf::from(owner),
        owner_file_offset: None,
        owner_identity: None,
    }
}

#[test]
fn reads_the_registered_code_linked_list() {
    let memory = MockProcess::new(1);
    let first = entry(0x2000, 0, 0x3000, 0x40);
    let second = entry(0, 0x1000, 0x4000, 0x80);
    memory.set_value(0x1000, first);
    memory.set_value(0x2000, second);

    let entries = protocol::read_entries(&memory, 0x1000).unwrap();

    assert_eq!(
        entries,
        HashMap::from_iter([(0x1000, first), (0x2000, second)])
    );
}

#[test]
fn rejects_a_cycle_in_the_registered_code_list() {
    let memory = MockProcess::new(1);
    memory.set_value(0x1000, entry(0x1000, 0, 0x3000, 0x40));

    let error = protocol::read_entries(&memory, 0x1000).unwrap_err();

    assert_eq!(error.to_string(), "GDB JIT traversal: cycle at 0x1000");
}

#[test]
fn rejects_an_inconsistent_back_link() {
    let memory = MockProcess::new(1);
    memory.set_value(0x1000, entry(0x2000, 0, 0x3000, 0x40));
    memory.set_value(0x2000, entry(0, 0x9999, 0x4000, 0x80));

    let error = protocol::read_entries(&memory, 0x1000).unwrap_err();

    assert_eq!(
        error.to_string(),
        "GDB JIT traversal: entry 0x2000 points back to 0x9999, expected 0x1000"
    );
}

#[test]
fn rejects_an_unbounded_remote_section_read() {
    let memory = MockProcess::new(1);

    let error = protocol::read_memory(&memory, 0x1000, MAX_JIT_READ_SIZE + 1).unwrap_err();

    assert_eq!(
        error.to_string(),
        "GDB JIT memory read: size 67108865 exceeds 67108864"
    );
}

#[test]
fn removing_all_descriptors_retires_registered_objects() {
    let mut reader = Registry::<_, Arc<[u8]>>::new(MockProcess::new(1));
    let id = JitObjectId {
        entry_addr: 0x1000,
        symfile_addr: 0x2000,
        symfile_size: 0x40,
    };
    reader.descriptors = vec![descriptor(0x3000, "/old.so")];
    reader.objects.insert(
        id,
        JitObject {
            code_ranges: Box::default(),
            pending_modules: Box::default(),
            symbols: Some(Vec::new()),
            image_fingerprint: 0,
            unwind: JitUnwind {
                cfi: CfiState::Absent,
                text: None,
                got: None,
            },
        },
    );
    reader.load_failures.insert(id, RetryBackoff::next(None, 0));
    reader.refresh_backoff = Some(RetryBackoff::next(None, 0));

    reader.update_descriptors(Vec::new(), &[] as &[TestMapping]);

    assert!(reader.descriptors.is_empty());
    assert!(reader.objects.is_empty());
    assert!(reader.load_failures.is_empty());
    assert!(reader.refresh_backoff.is_none());
    assert!(reader.stale_paths.contains(&id.path()));
    assert!(matches!(
        take_updates(&mut reader).as_slice(),
        [Update::Removed { .. }]
    ));
}

#[test]
fn transient_descriptor_miss_keeps_state_and_retries() {
    let mut reader = Registry::<_, Arc<[u8]>>::new(MockProcess::new(1));
    reader.descriptors = vec![descriptor(0x3000, "/proc/1/exe")];
    reader.descriptor_search_generation = Some(7);

    reader.update_descriptors(Vec::new(), &[] as &[TestMapping]);

    assert_eq!(reader.descriptors, vec![descriptor(0x3000, "/proc/1/exe")]);
    assert_eq!(reader.descriptor_search_generation, None);
}

#[test]
fn registries_are_combined_and_unregistered_objects_are_retired() {
    let memory = MockProcess::new(1);
    let mut reader = Registry::<_, Arc<[u8]>>::new(memory);
    reader.descriptors = vec![descriptor(0x100, "/app"), descriptor(0x200, "/llvm.so")];
    for (registry, node, object) in [(0x100, 0x1000, 0x3000), (0x200, 0x2000, 0x4000)] {
        reader.process.set_value(
            registry,
            JitDescriptor {
                version: 1,
                action_flag: 1,
                relevant_entry: node,
                first_entry: node,
            },
        );
        let entry = entry(0, 0, object, 0x40);
        reader.process.set_value(node as usize, entry);
        reader.objects.insert(
            JitObjectId::new(node, entry),
            JitObject {
                code_ranges: Box::default(),
                pending_modules: Box::default(),
                symbols: Some(Vec::new()),
                image_fingerprint: 0,
                unwind: JitUnwind {
                    cfi: CfiState::Absent,
                    text: None,
                    got: None,
                },
            },
        );
    }
    // WHEN both registries are polled
    reader.refresh_objects(0).unwrap();
    // THEN both registrations remain active
    assert_eq!(reader.objects.len(), 2);
    // WHEN one registry unregisters its object
    reader.process.set_value(
        0x100,
        JitDescriptor {
            version: 1,
            action_flag: 2,
            relevant_entry: 0x1000,
            first_entry: 0,
        },
    );
    reader.refresh_objects(1).unwrap();
    // THEN only that registry's object is retired
    let retained = JitObjectId::new(0x2000, entry(0, 0, 0x4000, 0x40));
    let removed = JitObjectId::new(0x1000, entry(0, 0, 0x3000, 0x40));
    assert_eq!(
        reader.objects.keys().copied().collect::<Vec<_>>(),
        [retained]
    );
    assert_eq!(reader.stale_paths, HashSet::from_iter([removed.path()]));
}

#[test]
fn retries_back_off_but_remain_retryable() {
    let start_poll = 10;

    let first = RetryBackoff::next(None, start_poll);
    let second = RetryBackoff::next(Some(first), first.retry_at);

    assert_eq!(first.retry_at, 11);
    assert_eq!(second.retry_at, 13);
}
/// Use assembler-generated instructions, ELF tables and CFI; only target memory is mocked.
#[cfg(target_arch = "x86_64")]
fn compiled_image(name: &str, cfa_offset: u8, text_address: u64, aliases: bool) -> Vec<u8> {
    use std::sync::{Mutex, OnceLock};
    type Images = HashMap<(String, u8, u64, bool), Vec<u8>>;
    static IMAGES: OnceLock<Mutex<Images>> = OnceLock::new();
    let mut images = IMAGES.get_or_init(Mutex::default).lock().unwrap();
    let key = (name.to_owned(), cfa_offset, text_address, aliases);
    images
        .entry(key)
        .or_insert_with(|| {
            let dir = crate::test_support::TempDir::new("shared-jit");
            let output = dir.path().join("overlay");
            let assembly = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/jit/tests/overlay.S");
            let mut compiler = std::process::Command::new("cc");
            compiler
                .args([
                    "-nostdlib",
                    "-no-pie",
                    "-Wl,--build-id=none",
                    "-Wl,--no-eh-frame-hdr",
                ])
                .arg(format!("-DFUNCTION_NAME={name}"))
                .arg(format!("-DCFA_OFFSET={cfa_offset}"))
                .arg(format!("-Wl,-e,{name}"))
                .arg(format!("-Wl,-Ttext=0x{text_address:x}"))
                .arg(format!(
                    "-Wl,--section-start=.eh_frame=0x{:x}",
                    text_address + 0x1000
                ));
            if aliases {
                compiler.arg("-DZERO_SIZE_ALIASES");
            }
            let compiled = compiler
                .arg(assembly)
                .arg("-o")
                .arg(&output)
                .output()
                .unwrap();
            assert!(
                compiled.status.success(),
                "{}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            std::fs::read(output).unwrap()
        })
        .clone()
}

#[cfg(target_arch = "x86_64")]
fn registered_image(name: &str) -> Vec<u8> {
    compiled_image(name, 48, 0x8000, false)
}

#[cfg(target_arch = "x86_64")]
fn live_cfi(image: &[u8]) -> (usize, &[u8]) {
    let elf = goblin::elf::Elf::parse(image).unwrap();
    let section = elf
        .section_headers
        .iter()
        .find(|section| elf.shdr_strtab.get_at(section.sh_name) == Some(".eh_frame"))
        .unwrap();
    let start = section.sh_offset as usize;
    (
        section.sh_addr as usize,
        &image[start..start + section.sh_size as usize],
    )
}

#[cfg(target_arch = "x86_64")]
fn install_cfi(memory: &MockProcess, image: &[u8]) {
    let (address, bytes) = live_cfi(image);
    memory.set_memory(address, bytes);
}

#[cfg(target_arch = "x86_64")]
fn registered_reader() -> (Registry<MockProcess, Arc<[u8]>>, JitObjectId) {
    reader_for_image(registered_image("first"))
}

#[cfg(target_arch = "x86_64")]
fn reader_for_image(image: Vec<u8>) -> (Registry<MockProcess, Arc<[u8]>>, JitObjectId) {
    let memory = MockProcess::new(1);
    memory.set_memory(0x3000, &image);
    let registration = entry(0, 0, 0x3000, image.len() as u64);
    memory.set_value(0x1000, registration);
    memory.set_value(
        0x100,
        JitDescriptor {
            version: 1,
            action_flag: 1,
            relevant_entry: 0x1000,
            first_entry: 0x1000,
        },
    );
    let mut reader = Registry::<_, Arc<[u8]>>::new(memory);
    reader.descriptors = vec![descriptor(0x100, "/fixture")];
    (reader, JitObjectId::new(0x1000, registration))
}

#[test]
#[cfg(target_arch = "x86_64")]
fn unreadable_cfi_keeps_symbols_and_late_cfi_can_be_refreshed() {
    let (mut reader, id) = registered_reader();
    reader.refresh_objects(0).unwrap();
    let object = &reader.objects[&id];
    assert!(object
        .symbols
        .as_ref()
        .unwrap()
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("first")));
    assert_eq!(object.pending_modules.len(), 1);
    assert!(matches!(object.unwind.cfi, CfiState::Unreadable { .. }));
    take_updates(&mut reader);

    install_cfi(&reader.process, &registered_image("first"));
    assert!(reader.refresh_for_address(0x8001));
    assert!(matches!(
        reader.objects[&id].unwind.cfi,
        CfiState::Loaded { .. }
    ));
    assert!(
        reader.objects[&id].symbols.is_none(),
        "CFI-only retry preserves symbol identity"
    );
    assert_eq!(reader.objects[&id].pending_modules.len(), 1);
    assert!(
        !reader.refresh_for_address(0x8001),
        "demand retries are throttled"
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn successful_revalidation_clears_retry_state_without_changing_symbols() {
    for initially_readable in [false, true] {
        // GIVEN a previously accepted object whose metadata becomes unreadable.
        let image = registered_image("first");
        let (mut reader, id) = registered_reader();
        if initially_readable {
            install_cfi(&reader.process, &image);
        }
        reader.refresh_objects(0).unwrap();
        take_updates(&mut reader);
        reader.process.set_memory(0x3000, &[]);
        reader.last_revalidation = None;
        reader.refresh_objects(1).unwrap();
        let retry_at = reader.load_failures[&id].retry_at;

        // WHEN the same image is readable again, with either new or unchanged CFI.
        reader.process.set_memory(0x3000, &image);
        install_cfi(&reader.process, &image);
        reader.refresh_objects(retry_at).unwrap();

        // THEN only the failed retry is cleared; symbol identities stay valid.
        assert!(reader.load_failures.is_empty());
        assert!(matches!(
            reader.objects[&id].unwind.cfi,
            CfiState::Loaded { .. }
        ));
        assert!(reader.objects[&id].symbols.is_none());
        assert_eq!(
            !reader.objects[&id].pending_modules.is_empty(),
            !initially_readable
        );
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn unchanged_registration_addresses_do_not_keep_replaced_symbols() {
    let (mut reader, id) = registered_reader();
    reader.refresh_objects(0).unwrap();
    reader
        .process
        .set_memory(0x3000, &registered_image("other"));
    reader.last_revalidation = None;
    reader.refresh_objects(1).unwrap();
    assert!(reader.objects[&id]
        .symbols
        .as_ref()
        .unwrap()
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("other")));
    assert!(!reader.objects[&id]
        .symbols
        .as_ref()
        .unwrap()
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("first")));
    assert!(reader.stale_paths.contains(&id.path()));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn live_cfi_changes_invalidate_previously_loaded_unwind_rules() {
    let (mut reader, id) = registered_reader();
    install_cfi(&reader.process, &registered_image("first"));
    reader.refresh_objects(0).unwrap();
    let old = match reader.objects[&id].unwind.cfi {
        CfiState::Loaded { fingerprint, .. } => fingerprint,
        _ => panic!("CFI should be loaded"),
    };
    install_cfi(&reader.process, &compiled_image("first", 8, 0x8000, false));
    reader.last_revalidation = None;
    reader.refresh_objects(1).unwrap();
    assert!(
        matches!(reader.objects[&id].unwind.cfi, CfiState::Loaded { fingerprint, .. } if fingerprint != old)
    );
    assert_eq!(reader.objects[&id].pending_modules.len(), 1);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn unknown_addresses_do_not_request_jit_reads() {
    let (mut reader, _) = registered_reader();
    reader.refresh_objects(0).unwrap();
    assert!(!reader.refresh_for_address(0xdead));
    assert!(reader.last_demand_refresh.is_some());
}

#[test]
fn rejects_overflowing_remote_address_ranges() {
    let memory = MockProcess::new(1);
    assert!(protocol::read_memory(&memory, u64::MAX, 2).is_err());
}

#[test]
#[cfg(target_arch = "x86_64")]
fn zero_sized_aliases_both_extend_to_the_next_distinct_address() {
    let bytes = compiled_image("first", 48, 0x8000, true);
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let symbols = jit_symbols(&elf, &[find_section_range(".text", &elf).unwrap()]).unwrap();
    let aliases: Vec<_> = symbols
        .iter()
        .filter(|symbol| matches!(symbol.name.as_deref(), Some("first" | "alias")))
        .collect();
    assert_eq!(aliases.len(), 2);
    assert!(aliases
        .iter()
        .all(|symbol| symbol.range == (0x8000..0x8003)));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn excessive_function_symbols_are_rejected_before_copying_names() {
    use goblin::container::{Container, Ctx, Endian};
    use goblin::elf::{section_header::SHT_SYMTAB, sym::Symtab};

    let image = registered_image("first");
    let mut elf = goblin::elf::Elf::parse(&image).unwrap();
    let section = elf
        .section_headers
        .iter()
        .find(|section| section.sh_type == SHT_SYMTAB)
        .unwrap();
    let index = elf
        .syms
        .iter()
        .position(|symbol| elf.strtab.get_at(symbol.st_name) == Some("first"))
        .unwrap();
    let size = section.sh_entsize as usize;
    let start = section.sh_offset as usize + index * size;
    // Repeat an assembler-produced record without copying its shared name.
    let count = 1_000_001;
    let symbols = image[start..start + size].repeat(count);
    elf.syms = Symtab::parse(&symbols, 0, count, Ctx::new(Container::Big, Endian::Little)).unwrap();
    let error = jit_symbols(&elf, &[find_section_range(".text", &elf).unwrap()])
        .expect_err("excessive symbol count must be rejected");
    assert_eq!(
        error.to_string(),
        "GDB JIT symbols: symbol table exceeds bounds"
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn aggregate_registry_limit_is_checked_before_reading_objects() {
    let (reader, _) = registered_reader();
    for index in 0..5 {
        let node = 0x1000 + index * 32;
        reader.process.set_value(
            node,
            entry(
                if index == 4 { 0 } else { (node + 32) as u64 },
                if index == 0 { 0 } else { (node - 32) as u64 },
                0xdead,
                MAX_JIT_READ_SIZE,
            ),
        );
    }
    let error = reader
        .read_snapshot()
        .err()
        .expect("registry exceeds 256 MiB");
    assert!(matches!(error, SnapshotError::Limit(_)));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn periodic_polls_are_throttled_and_initialization_preserves_batch_symbols() {
    let (mut reader, id) = registered_reader();
    reader.descriptor_search_generation = Some(1);
    reader.refresh(1, &[] as &[TestMapping]);
    reader
        .process
        .set_memory(0x3000, &registered_image("other"));
    reader.last_revalidation = None;
    reader.refresh(1, &[] as &[TestMapping]);
    assert!(reader.objects[&id]
        .symbols
        .as_ref()
        .unwrap()
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("first")));
    reader.last_poll = Some(Instant::now() - POLL_INTERVAL);
    reader.initialize(1, &[] as &[TestMapping]);
    assert!(reader.objects[&id]
        .symbols
        .as_ref()
        .unwrap()
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("first")));
    reader.refresh(1, &[] as &[TestMapping]);
    assert!(reader.objects[&id]
        .symbols
        .as_ref()
        .unwrap()
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("other")));
}

#[test]
fn confirmed_absence_skips_polling_until_mappings_change() {
    let mut reader = Registry::<_, Arc<[u8]>>::new(MockProcess::new(1));
    let previous_poll = Instant::now() - REVALIDATION_INTERVAL;
    reader.descriptor_search_generation = Some(7);
    reader.last_discovery = Some((7, previous_poll));
    reader.last_poll = Some(previous_poll);

    reader.refresh(7, &[] as &[TestMapping]);
    assert_eq!(reader.last_poll, Some(previous_poll));
    assert_eq!(reader.last_discovery, Some((7, previous_poll)));

    reader.refresh(8, &[] as &[TestMapping]);
    assert_ne!(reader.last_poll, Some(previous_poll));
    assert_eq!(
        reader.last_discovery.map(|(generation, _)| generation),
        Some(8)
    );
}

#[test]
fn changed_mapping_generation_bypasses_poll_throttle_but_incomplete_discovery_does_not() {
    let mut reader = Registry::<_, Arc<[u8]>>::new(MockProcess::new(i32::MAX));
    reader.descriptors = vec![descriptor(0x100, "/unloaded.so")];
    reader.descriptor_search_generation = Some(1);
    reader.last_discovery = Some((1, Instant::now()));
    reader.last_poll = Some(Instant::now());

    reader.refresh(2, &[] as &[TestMapping]);
    assert!(reader.descriptors.is_empty());
    assert_eq!(reader.last_discovery.unwrap().0, 2);
    assert!(reader.descriptor_search_generation.is_none());

    let last_poll = reader.last_poll;
    reader.refresh(2, &[] as &[TestMapping]);
    assert_eq!(reader.last_poll, last_poll);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn demand_refresh_preserves_unrelated_registrations_until_the_next_poll() {
    let (mut reader, first_id) = registered_reader();
    let second = compiled_image("first", 48, 0xa000, false);
    reader.process.set_memory(0x13000, &second);
    let second_entry = entry(0, 0, 0x13000, second.len() as u64);
    reader.process.set_value(0x2000, second_entry);
    reader.process.set_value(
        0x200,
        JitDescriptor {
            version: 1,
            action_flag: 1,
            relevant_entry: 0x2000,
            first_entry: 0x2000,
        },
    );
    reader.descriptors.push(descriptor(0x200, "/second"));
    let second_id = JitObjectId::new(0x2000, second_entry);
    reader.refresh_objects(0).unwrap();
    let retained_symbols = reader.objects[&second_id].symbols.clone().unwrap();
    take_updates(&mut reader);
    reader
        .process
        .set_memory(0x13000, &compiled_image("other", 48, 0xa000, false));
    install_cfi(&reader.process, &registered_image("first"));

    assert!(reader.refresh_for_address(0x8001));
    assert_eq!(reader.objects[&first_id].pending_modules.len(), 1);
    assert!(reader.objects[&second_id].symbols.is_none());
    assert!(retained_symbols
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("first")));
    assert!(
        !take_updates(&mut reader).iter().any(|update| matches!(
            update,
            Update::Loaded {
                symbols: Some(_),
                ..
            }
        )),
        "CFI retry must not publish symbols mid-batch"
    );

    reader.last_revalidation = None;
    reader.refresh_objects(1).unwrap();
    assert!(reader.objects[&second_id]
        .symbols
        .as_ref()
        .unwrap()
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("other")));
}

/// Count remote reads and optionally unregister during an ELF image read.
#[cfg(target_arch = "x86_64")]
struct ObservedProcess {
    memory: MockProcess,
    unregister_on_image_read: std::cell::Cell<bool>,
    reads: std::cell::Cell<usize>,
}

#[cfg(target_arch = "x86_64")]
impl MemoryReader for ObservedProcess {
    fn read(&self, address: u64, bytes: &mut [u8]) -> std::io::Result<()> {
        self.reads.set(self.reads.get() + 1);
        self.memory.read(address, bytes)?;
        if address == 0x3000 && self.unregister_on_image_read.replace(false) {
            self.memory.set_value(
                0x100,
                JitDescriptor {
                    version: 1,
                    action_flag: 2,
                    relevant_entry: 0x1000,
                    first_entry: 0,
                },
            );
        }
        Ok(())
    }
    fn pid(&self) -> i32 {
        self.memory.pid()
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn unstable_second_snapshot_discards_replacement_and_retries_later() {
    let (original, id) = registered_reader();
    let mut reader = Registry::<_, Arc<[u8]>>::new(ObservedProcess {
        memory: original.process,
        unregister_on_image_read: std::cell::Cell::new(false),
        reads: std::cell::Cell::new(0),
    });
    reader.descriptors = original.descriptors;
    reader.refresh_objects(0).unwrap();
    let retained_symbols = reader.objects[&id].symbols.clone().unwrap();
    let fingerprint = reader.objects[&id].image_fingerprint;
    take_updates(&mut reader);
    reader
        .process
        .memory
        .set_memory(0x3000, &registered_image("other"));
    reader.process.unregister_on_image_read.set(true);
    reader.last_revalidation = None;

    reader.refresh_objects(1).unwrap();
    assert_eq!(reader.objects[&id].image_fingerprint, fingerprint);
    assert!(retained_symbols
        .iter()
        .any(|symbol| symbol.name.as_deref() == Some("first")));
    assert!(take_updates(&mut reader).is_empty());

    reader.refresh_objects(2).unwrap();
    assert!(reader.objects.is_empty());
    assert!(matches!(
        take_updates(&mut reader).as_slice(),
        [Update::Removed { .. }]
    ));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn absent_cfi_retains_generated_ownership_without_retrying_a_section() {
    let (original, id) = reader_for_image(compiled_image("first", 0, 0x8000, false));
    let mut reader = Registry::<_, Arc<[u8]>>::new(ObservedProcess {
        memory: original.process,
        unregister_on_image_read: std::cell::Cell::new(false),
        reads: std::cell::Cell::new(0),
    });
    reader.descriptors = original.descriptors;
    reader.refresh_objects(0).unwrap();
    assert!(matches!(reader.objects[&id].unwind.cfi, CfiState::Absent));
    assert_eq!(reader.objects[&id].pending_modules.len(), 1);
    let updates = take_updates(&mut reader);
    assert!(updates.iter().any(|update| matches!(update,
        Update::Loaded { symbols: Some(symbols), .. }
        if symbols.iter().any(|symbol| symbol.name.as_deref() == Some("first")))));
    let reads = reader.process.reads.get();
    assert!(!reader.refresh_for_address(0x8001));
    assert_eq!(reader.process.reads.get(), reads);
    let last_refresh = reader.last_demand_refresh;
    assert!(last_refresh.is_some());
    assert!(!reader.refresh_for_address(0x8002));
    assert_eq!(reader.last_demand_refresh, last_refresh);
    assert!(take_updates(&mut reader).is_empty());
}

#[test]
#[cfg(target_arch = "x86_64")]
fn cfi_budget_is_checked_before_remote_reads_and_recovers_after_release() {
    let image = registered_image("first");
    let cfi_size = live_cfi(&image).1.len() as u64;
    let (original, id) = reader_for_image(image.clone());
    install_cfi(&original.process, &image);
    let process = ObservedProcess {
        memory: original.process,
        unregister_on_image_read: std::cell::Cell::new(false),
        reads: std::cell::Cell::new(0),
    };
    let mut remaining = cfi_size;
    let first = JitObject::<Arc<[u8]>>::load(&process, id, &mut remaining).unwrap();
    assert_eq!(remaining, 0);
    let before = process.reads.get();
    let second = JitObject::<Arc<[u8]>>::load(&process, id, &mut remaining).unwrap();
    assert!(matches!(second.unwind.cfi, CfiState::Unreadable { .. }));
    assert!(!second.symbols.as_ref().unwrap().is_empty());
    assert_eq!(
        process.reads.get() - before,
        1,
        "only the ELF image is read"
    );

    let mut scratch = Vec::new();
    let before = process.reads.get();
    assert!(second
        .inspect(&process, id, &mut scratch, &mut remaining)
        .is_err());
    assert_eq!(process.reads.get() - before, 1, "CFI retry is budgeted too");
    remaining += loaded_cfi_size(&first);
    assert!(matches!(
        second
            .inspect(&process, id, &mut scratch, &mut remaining)
            .unwrap(),
        ObjectChange::Unwind(_)
    ));
    assert_eq!(remaining, 0);

    remaining += loaded_cfi_size(&first);
    assert!(matches!(
        first
            .inspect(&process, id, &mut scratch, &mut remaining)
            .unwrap(),
        ObjectChange::Unchanged
    ));
    assert_eq!(
        remaining, cfi_size,
        "unchanged CFI does not reserve a replacement"
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn active_cfi_consumes_budget_until_its_registration_is_retired() {
    let (mut reader, first_id) = registered_reader();
    reader.refresh_objects(0).unwrap();
    // Represent an already full snapshot without allocating its CFI bytes.
    reader.objects.get_mut(&first_id).unwrap().unwind.cfi = CfiState::Loaded {
        range: 0x9000..0x9000 + MAX_JIT_TOTAL_CFI_SIZE,
        fingerprint: 0,
    };
    let second_image = compiled_image("other", 48, 0x18000, false);
    reader.process.set_memory(0x13000, &second_image);
    install_cfi(&reader.process, &second_image);
    let second = entry(0, 0x1000, 0x13000, second_image.len() as u64);
    let second_id = JitObjectId::new(0x2000, second);
    reader.process.set_value(
        0x1000,
        entry(0x2000, 0, first_id.symfile_addr, first_id.symfile_size),
    );
    reader.process.set_value(0x2000, second);
    reader.process.set_value(
        0x100,
        JitDescriptor {
            version: 1,
            action_flag: 1,
            relevant_entry: 0x2000,
            first_entry: 0x1000,
        },
    );
    reader.refresh_objects(1).unwrap();
    assert!(matches!(
        reader.objects[&second_id].unwind.cfi,
        CfiState::Unreadable { .. }
    ));
    assert!(!reader.refresh_for_address(0x18001));

    // Removing the holder makes room for the surviving object's periodic retry.
    reader.process.set_value(
        0x2000,
        entry(0, 0, second.symfile_addr, second.symfile_size),
    );
    reader.process.set_value(
        0x100,
        JitDescriptor {
            version: 1,
            action_flag: 2,
            relevant_entry: 0x1000,
            first_entry: 0x2000,
        },
    );
    reader.last_revalidation = None;
    reader.refresh_objects(2).unwrap();
    assert!(!reader.objects.contains_key(&first_id));
    assert!(matches!(
        reader.objects[&second_id].unwind.cfi,
        CfiState::Loaded { .. }
    ));

    // A full snapshot still permits replacing an existing allocation in place.
    let second_size = loaded_cfi_size(&reader.objects[&second_id]);
    reader.objects.insert(
        first_id,
        JitObject {
            code_ranges: Box::default(),
            pending_modules: Box::default(),
            symbols: Some(Vec::new()),
            image_fingerprint: 0,
            unwind: JitUnwind {
                cfi: CfiState::Loaded {
                    range: 0..MAX_JIT_TOTAL_CFI_SIZE - second_size,
                    fingerprint: 0,
                },
                text: None,
                got: None,
            },
        },
    );
    install_cfi(&reader.process, &compiled_image("other", 8, 0x18000, false));
    reader.last_demand_refresh = None;
    assert!(reader.refresh_for_address(0x18001));
    assert_eq!(
        reader.objects.values().map(loaded_cfi_size).sum::<u64>(),
        MAX_JIT_TOTAL_CFI_SIZE
    );
}

#[test]
fn descriptor_miss_retains_a_split_mapping_but_retires_a_relocated_owner() {
    let mut reader = Registry::<_, Arc<[u8]>>::new(MockProcess::new(1));
    reader.descriptors.push(JitDescriptorLocation {
        address: 0x3800,
        owner: PathBuf::from("/llvm.so"),
        owner_file_offset: Some(0x1800),
        owner_identity: None,
    });
    let mapping = |range, offset| TestMapping { range, offset };
    reader.update_descriptors(
        Vec::new(),
        &[mapping(0x2000..0x3000, 0), mapping(0x3000..0x4000, 0x1000)],
    );
    assert_eq!(
        reader.descriptors.len(),
        1,
        "split mappings still describe the same descriptor bytes"
    );
    reader.update_descriptors(Vec::new(), &[mapping(0x5000..0x7000, 0)]);
    assert!(
        reader.descriptors.is_empty(),
        "same path at another base must not retain an unreadable descriptor"
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn revalidation_reuses_storage_and_checks_the_complete_image() {
    let image = registered_image("first");
    let (mut reader, id) = reader_for_image(image.clone());
    install_cfi(&reader.process, &image);
    reader.refresh_objects(0).unwrap();
    let object = &reader.objects[&id];
    let mut scratch = Vec::with_capacity(image.len());
    let allocations = allocation_counter::measure(|| {
        for _ in 0..100 {
            let mut remaining = MAX_JIT_TOTAL_CFI_SIZE;
            assert!(matches!(
                object
                    .inspect(&reader.process, id, &mut scratch, &mut remaining)
                    .unwrap(),
                ObjectChange::Unchanged
            ));
        }
    });
    assert_eq!(allocations.count_total, 0);
    let mut changed = image.clone();
    *changed.last_mut().unwrap() ^= 1;
    reader.process.set_memory(0x3000, &changed);
    let mut remaining = MAX_JIT_TOTAL_CFI_SIZE;
    assert!(matches!(
        object
            .inspect(&reader.process, id, &mut scratch, &mut remaining)
            .unwrap(),
        ObjectChange::Image
    ));
    reader.process.set_memory(0x3000, &image[..image.len() - 1]);
    assert!(object
        .inspect(&reader.process, id, &mut scratch, &mut remaining)
        .is_err());
}

#[test]
#[cfg(target_arch = "x86_64")]
fn overlapping_registration_waits_until_the_current_owner_retires() {
    let (mut reader, first) = registered_reader();
    reader.refresh_objects(0).unwrap();
    let image = registered_image("other");
    reader.process.set_memory(0x13000, &image);
    let second_entry = entry(0, 0x1000, 0x13000, image.len() as u64);
    let second = JitObjectId::new(0x2000, second_entry);
    reader.process.set_value(
        0x1000,
        entry(0x2000, 0, first.symfile_addr, first.symfile_size),
    );
    reader.process.set_value(0x2000, second_entry);
    reader.process.set_value(
        0x100,
        JitDescriptor {
            version: 1,
            action_flag: 1,
            relevant_entry: 0x2000,
            first_entry: 0x1000,
        },
    );
    reader.refresh_objects(1).unwrap();
    assert!(reader.objects.contains_key(&first));
    assert!(!reader.objects.contains_key(&second));
    assert_eq!(reader.code_ranges[&0x8000].1, first);
    let retry = reader.load_failures[&second].retry_at;
    reader.process.set_value(
        0x2000,
        entry(0, 0, second.symfile_addr, second.symfile_size),
    );
    reader.process.set_value(
        0x100,
        JitDescriptor {
            version: 1,
            action_flag: 2,
            relevant_entry: 0x1000,
            first_entry: 0x2000,
        },
    );
    reader.refresh_objects(retry).unwrap();
    assert!(!reader.objects.contains_key(&first));
    assert!(reader.objects.contains_key(&second));
    assert_eq!(reader.code_ranges[&0x8000].1, second);
    install_cfi(&reader.process, &image);
    reader.poll_count = retry;
    assert!(reader.refresh_for_address(0x8001));
    reader.update_descriptors(Vec::new(), &[] as &[TestMapping]);
    assert!(reader.code_ranges.is_empty());
    reader.last_demand_refresh = None;
    assert!(!reader.refresh_for_address(0x8001));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn unchanged_descriptors_skip_list_reads_until_revalidation_or_retry() {
    for retry_due in [false, true] {
        let (mut reader, id) = registered_reader();
        reader.refresh_objects(0).unwrap();
        reader.process.set_memory(0x1000, &[]);
        reader.refresh_objects(1).unwrap();
        assert!(reader.objects.contains_key(&id));
        if retry_due {
            reader.load_failures.insert(id, RetryBackoff::next(None, 1));
        } else {
            reader.last_revalidation = None;
        }
        assert!(reader.refresh_objects(2).is_err());
        assert!(reader.objects.contains_key(&id));
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn failed_metadata_renews_retry_without_revalidating_every_poll() {
    let (mut reader, id) = registered_reader();
    reader.refresh_objects(0).unwrap();
    reader.process.set_memory(0x3000, &[]);
    reader.last_revalidation = None;
    reader.refresh_objects(1).unwrap();
    let revalidated = reader.last_revalidation;
    let retry = reader.load_failures[&id].retry_at;
    reader.refresh_objects(retry).unwrap();
    assert!(reader.load_failures[&id].retry_at > retry);
    assert_eq!(reader.last_revalidation, revalidated);
    assert!(reader.objects.contains_key(&id));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn demand_defers_removal_and_image_replacement_to_the_next_poll() {
    for removed in [false, true] {
        let (mut reader, id) = registered_reader();
        reader.refresh_objects(0).unwrap();
        let original = reader.objects[&id].image_fingerprint;
        if removed {
            reader.process.set_value(
                0x100,
                JitDescriptor {
                    version: 1,
                    action_flag: 2,
                    relevant_entry: 0x1000,
                    first_entry: 0,
                },
            );
        } else {
            reader
                .process
                .set_memory(0x3000, &vec![b'!'; id.symfile_size as usize]);
        }
        assert!(!reader.refresh_for_address(0x8001));
        assert_eq!(reader.objects[&id].image_fingerprint, original);
        reader.last_revalidation = None;
        reader.refresh_objects(1).unwrap();
        assert!(!reader.objects.contains_key(&id));
    }
}

#[test]
fn shared_elf_names_are_bounded_before_copying() {
    use goblin::container::{Container, Ctx, Endian};
    use goblin::elf::{
        header::{Header, ET_REL},
        section_header::{SectionHeader, SHF_ALLOC, SHF_EXECINSTR},
        sym::{Symtab, STT_FUNC},
        Elf,
    };
    use goblin::strtab::Strtab;
    const MAX_JIT_SYMBOL_NAME: usize = 1024 * 1024;
    for (count, name_len, accepted) in [
        (3, 16, true),
        (65, MAX_JIT_SYMBOL_NAME, false),
        (1, MAX_JIT_SYMBOL_NAME + 1, false),
    ] {
        let mut names = vec![b'f'; name_len + 2];
        names[0] = 0;
        names[name_len + 1] = 0;
        let mut functions = Vec::new();
        for offset in 0..count {
            // ELF64 function records all reference the same string-table entry.
            functions.extend_from_slice(&1_u32.to_le_bytes()); // st_name
            functions.extend_from_slice(&[STT_FUNC, 0]); // st_info, st_other
            functions.extend_from_slice(&1_u16.to_le_bytes()); // st_shndx
            functions.extend_from_slice(&(offset as u64).to_le_bytes()); // st_value
            functions.extend_from_slice(&1_u64.to_le_bytes()); // st_size
        }
        let ctx = Ctx::new(Container::Big, Endian::Little);
        let mut header = Header::new(ctx);
        header.e_type = ET_REL;
        let mut elf = Elf::lazy_parse(header).unwrap();
        elf.section_headers = vec![
            SectionHeader::default(),
            SectionHeader {
                sh_addr: 0x1000,
                sh_size: count as u64,
                sh_flags: u64::from(SHF_ALLOC | SHF_EXECINSTR),
                ..SectionHeader::default()
            },
        ];
        elf.syms = Symtab::parse(&functions, 0, count, ctx).unwrap();
        elf.strtab = Strtab::parse(&names, 0, names.len(), 0).unwrap();
        let range = 0x1000..0x1000 + count as u64;
        let allocations = allocation_counter::measure(|| {
            let decoded = jit_symbols(&elf, std::slice::from_ref(&range));
            if accepted {
                let decoded = decoded.unwrap();
                assert_eq!(decoded.len(), count);
                assert!(decoded
                    .iter()
                    .all(|symbol| symbol.name.as_ref().unwrap().len() == name_len));
            } else {
                assert!(
                    decoded.is_err(),
                    "{count} functions with {name_len}-byte names"
                );
            }
        });
        assert!(allocations.bytes_total < MAX_JIT_SYMBOL_NAME as u64);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn consumed_updates_do_not_publish_or_allocate_on_unchanged_captures() {
    let (mut reader, _) = registered_reader();
    reader.refresh_objects(0).unwrap();
    assert!(!take_updates(&mut reader).is_empty());
    assert!(!reader.updates_pending);
    let allocations = allocation_counter::measure(|| {
        for _ in 0..1000 {
            reader.drain_updates(|_| panic!("unchanged capture published an update"));
        }
    });
    assert_eq!(allocations.count_total, 0);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn pending_object_retry_does_not_read_or_consume_the_demand_deadline() {
    let (original, id) = registered_reader();
    let mut reader = Registry::<_, Arc<[u8]>>::new(ObservedProcess {
        memory: original.process,
        unregister_on_image_read: std::cell::Cell::new(false),
        reads: std::cell::Cell::new(0),
    });
    reader.descriptors = original.descriptors;
    reader.refresh_objects(0).unwrap();
    reader
        .load_failures
        .insert(id, RetryBackoff::next(None, 10));
    let reads = reader.process.reads.get();
    assert!(!reader.refresh_for_address(0x8001));
    assert_eq!(reader.process.reads.get(), reads);
    assert!(reader.last_demand_refresh.is_none());
    install_cfi(&reader.process.memory, &registered_image("first"));
    reader.poll_count = reader.load_failures[&id].retry_at;
    assert!(reader.refresh_for_address(0x8001));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn registry_limit_warning_resets_after_a_bounded_snapshot() {
    let (mut reader, id) = registered_reader();
    reader.descriptor_search_generation = Some(1);
    for oversized in [false, true, true, false, true] {
        reader.process.set_value(
            0x1000,
            entry(
                0,
                0,
                id.symfile_addr,
                if oversized {
                    MAX_JIT_READ_SIZE + 1
                } else {
                    id.symfile_size
                },
            ),
        );
        reader.last_poll = None;
        reader.last_revalidation = None;
        if let Some(backoff) = reader.refresh_backoff {
            reader.poll_count = backoff.retry_at;
        }
        reader.refresh(1, &[] as &[TestMapping]);
        assert_eq!(reader.limit_warned, oversized);
        assert!(
            reader.objects.contains_key(&id),
            "limit errors must preserve committed metadata"
        );
    }
    reader.update_descriptors(Vec::new(), &[] as &[TestMapping]);
    assert!(!reader.limit_warned);
}
