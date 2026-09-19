//! Registry scenarios use named registration operations; protocol encoding stays here.

use std::fs::File;
use std::ops::Range;
use std::os::unix::fs::FileExt;

use super::*;
use crate::linux::unwind::test_module;
use crate::spool::ModuleRecord;
use crate::test_support::TempDir;
use framehop::Unwinder;

const OBJECT_IMAGE: &[u8] = b"decoded fixture object";
const HEAD: ObjectId = ObjectId {
    entry: 0x200,
    address: 0x400,
    size: OBJECT_IMAGE.len() as u64,
};
const TAIL: ObjectId = ObjectId {
    entry: 0x300,
    address: 0x500,
    size: OBJECT_IMAGE.len() as u64,
};

/// A target registry backed by a sparse file, with deterministic polling time.
struct RegistryFixture {
    _directory: TempDir,
    memory: File,
    registry: JitRegistry,
    unwinder: NativeUnwinder,
    modules: ModuleTable,
    writer: PerfSpoolWriter<Vec<u8>>,
}

impl RegistryFixture {
    const DESCRIPTOR_ADDRESS: u64 = 0x100;

    fn new(entries: &[ObjectId]) -> Self {
        let directory = TempDir::new("jit-registry");
        let memory = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.path().join("memory"))
            .unwrap();
        let mut discovery = Discovery::default();
        discovery.memory = Some(memory.try_clone().unwrap());
        discovery.descriptors = vec![Self::DESCRIPTOR_ADDRESS];
        let mut fixture = Self {
            registry: JitRegistry {
                discovery,
                ..Default::default()
            },
            _directory: directory,
            memory,
            unwinder: NativeUnwinder::default(),
            modules: ModuleTable::default(),
            writer: PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap(),
        };
        fixture.write_entries(entries);
        fixture.set_head(entries.first().map_or(0, |id| id.entry));
        fixture.registry.last_descriptors = vec![(
            Self::DESCRIPTOR_ADDRESS,
            read_descriptor(&fixture.memory, Self::DESCRIPTOR_ADDRESS).unwrap(),
        )];
        fixture
    }

    /// Rewrite list membership without changing the descriptor notification.
    fn write_entries(&self, entries: &[ObjectId]) {
        for (index, id) in entries.iter().enumerate() {
            let next = entries.get(index + 1).map_or(0, |entry| entry.entry);
            let previous = index.checked_sub(1).map_or(0, |i| entries[i].entry);
            let encoded: Vec<_> = [next, previous, id.address, id.size]
                .into_iter()
                .flat_map(u64::to_ne_bytes)
                .collect();
            self.memory.write_all_at(&encoded, id.entry).unwrap();
        }
    }

    /// Publish a registration notification with the given list head.
    fn set_head(&self, first: u64) {
        self.notify(1, first, first);
    }

    /// Remove an entry and publish its unregistration notification.
    fn unregister(&self, id: ObjectId, remaining: &[ObjectId]) {
        self.write_entries(remaining);
        self.notify(2, id.entry, remaining.first().map_or(0, |id| id.entry));
    }

    /// Encode the target's latest notification in the GDB descriptor.
    fn notify(&self, action: u32, relevant: u64, first: u64) {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&1_u32.to_ne_bytes()); // Protocol version.
        encoded.extend_from_slice(&action.to_ne_bytes());
        encoded.extend_from_slice(&relevant.to_ne_bytes());
        encoded.extend_from_slice(&first.to_ne_bytes());
        self.memory
            .write_all_at(&encoded, Self::DESCRIPTOR_ADDRESS)
            .unwrap();
    }

    /// Install an already decoded registration, keeping these tests about lifecycle.
    fn publish(&mut self, id: ObjectId, code: Range<u64>) -> bool {
        self.registry
            .publish_object(
                id,
                jit_object(code),
                &mut self.unwinder,
                &mut self.modules,
                &mut self.writer,
            )
            .unwrap()
    }

    /// Run an ordinary refresh at the supplied processing time.
    fn poll(&mut self, now: Instant) {
        // No real target: failed discovery retains our injected memory and descriptors.
        self.registry
            .refresh_at(
                -1,
                &mut self.unwinder,
                &mut self.modules,
                &mut self.writer,
                now,
                None,
            )
            .unwrap();
    }

    /// Request a refresh for a failing frame, using the registry's normal clock.
    fn demand(&mut self, address: u64) -> bool {
        self.registry
            .refresh_for_frame(
                address,
                i32::MAX,
                &mut self.unwinder,
                &mut self.modules,
                &mut self.writer,
            )
            .unwrap()
    }
}

fn jit_object(code: Range<u64>) -> JitObject {
    let mut module =
        ModuleRecord::new(0, crate::Pid::new(7).unwrap(), code.clone(), 0, "jit").unwrap();
    module.jit_symbols = Some([].into());
    JitObject::test_with_module(module, test_module(code), OBJECT_IMAGE)
}

#[test]
fn oversized_registries_back_off_and_resume_after_shrinking() {
    let entries = |count: usize, size: u64| {
        (0..count)
            .map(|index| ObjectId {
                entry: 0x1000 + index as u64 * 32,
                address: 0x100000,
                size,
            })
            .collect::<Vec<_>>()
    };
    for oversized in [
        entries(4097, OBJECT_IMAGE.len() as u64),
        entries(5, 64 * 1024 * 1024),
        entries(1, 64 * 1024 * 1024 + 1),
    ] {
        let mut target = RegistryFixture::new(&oversized);
        assert!(target.publish(HEAD, 0x200000..0x201000));
        let captured = target.registry.frame(0x200000);
        let now = Instant::now();

        target.poll(now);
        let retry = now + REGISTRY_LIMIT_RETRY_INTERVAL;
        assert_eq!(target.registry.registry_retry_after, Some(retry));
        assert_eq!(target.registry.frame(0x200000), captured);
        assert!(target.registry.last_revalidation_cycle_at.is_none());

        target.set_head(0);
        target.registry.mappings_changed();
        for millis in [100, 500, 999] {
            target.poll(now + Duration::from_millis(millis));
            assert_eq!(target.registry.last_poll_attempt_at, Some(now));
            assert_eq!(target.registry.frame(0x200000), captured);
        }
        // Demand refreshes cannot bypass the registry limit either.
        assert!(!target.demand(0x200000));
        assert_eq!(target.registry.registry_retry_after, Some(retry));
        assert_eq!(target.registry.frame(0x200000), captured);

        target.poll(retry);
        assert!(target.registry.registry_retry_after.is_none());
        assert!(target.registry.frame(0x200000).is_none());
        assert_eq!(target.registry.last_revalidation_cycle_at, Some(retry));
    }
}

#[test]
fn cyclic_registries_are_read_errors_instead_of_size_limits() {
    let target = RegistryFixture::new(&[HEAD]);
    target
        .memory
        .write_all_at(&HEAD.entry.to_ne_bytes(), HEAD.entry)
        .unwrap();
    assert!(matches!(
        snapshot(&target.memory, target.registry.last_descriptors.clone()),
        Err(SnapshotError::Read(_))
    ));
}

#[test]
fn revalidation_reuses_its_buffer_and_still_checks_every_byte() {
    let mut target = RegistryFixture::new(&[HEAD]);
    assert!(target.publish(HEAD, 0x1000..0x2000));
    target
        .memory
        .write_all_at(OBJECT_IMAGE, HEAD.address)
        .unwrap();
    let object = &target.registry.objects[&HEAD];
    let mut scratch = Vec::new();
    assert!(!object
        .has_changed(&target.memory, HEAD, &mut scratch)
        .unwrap());

    let allocations = allocation_counter::measure(|| {
        for _ in 0..100 {
            assert!(!object
                .has_changed(&target.memory, HEAD, &mut scratch)
                .unwrap());
        }
    });
    assert_eq!(allocations.count_total, 0);

    // The last byte matters too; reusing storage must not shorten the fingerprint.
    target
        .memory
        .write_all_at(b"!", HEAD.address + HEAD.size - 1)
        .unwrap();
    assert!(object
        .has_changed(&target.memory, HEAD, &mut scratch)
        .unwrap());
    target.memory.set_len(HEAD.address + HEAD.size - 1).unwrap();
    assert!(object
        .has_changed(&target.memory, HEAD, &mut scratch)
        .is_err());
}

#[test]
fn recovered_metadata_reads_restore_the_regular_scan_interval() {
    let mut target = RegistryFixture::new(&[HEAD, TAIL]);
    assert!(target.publish(HEAD, 0x1000..0x2000));
    assert!(target.publish(TAIL, 0x3000..0x4000));
    let original = target.registry.frame(0x1000);
    let now = Instant::now();

    // Advertised object images are initially unreadable, so both checks back off.
    target.poll(now);
    assert_eq!(target.registry.retry_after.len(), 2);
    target
        .memory
        .write_all_at(OBJECT_IMAGE, HEAD.address)
        .unwrap();
    let retry_at = now + OBJECT_RETRY_INTERVAL;
    let tail_retry_at = retry_at + OBJECT_RETRY_INTERVAL;
    target.registry.retry_after.insert(TAIL, tail_retry_at);

    // Another scan can advance the global clock before this object's retry is due.
    target.registry.last_revalidation_cycle_at = Some(now + DESCRIPTOR_POLL_INTERVAL);
    target.poll(retry_at);
    assert_eq!(target.registry.frame(0x1000), original);
    assert!(!target.registry.retry_after.contains_key(&HEAD));
    assert_eq!(target.registry.retry_after.get(&TAIL), Some(&tail_retry_at));

    // A recovered object must not keep unchanged descriptors scanning every poll.
    assert!(!target.registry.scan_needed(
        &target.registry.last_descriptors,
        retry_at + DESCRIPTOR_POLL_INTERVAL / 2,
    ));
}

#[test]
fn failed_metadata_retries_renew_backoff_between_revalidation_cycles() {
    let mut target = RegistryFixture::new(&[HEAD]);
    assert!(target.publish(HEAD, 0x1000..0x2000));
    let now = Instant::now();
    target.poll(now);
    target.registry.last_revalidation_cycle_at = Some(now + DESCRIPTOR_POLL_INTERVAL);

    let retry_at = now + OBJECT_RETRY_INTERVAL;
    target.poll(retry_at);
    assert_eq!(
        target.registry.retry_after.get(&HEAD),
        Some(&(retry_at + OBJECT_RETRY_INTERVAL)),
    );
}

#[test]
fn mapping_changes_preserve_runtime_code_until_unregister() {
    let mut target = RegistryFixture::new(&[HEAD, TAIL]);
    target.unwinder.add_module(test_module(0x100..0x500));
    assert!(target.publish(HEAD, 0x1000..0x2000));
    assert!(target.publish(TAIL, 0x3000..0x4000));

    let mut now = Instant::now();
    target.poll(now);
    target.write_entries(&[HEAD]);
    for _ in 0..3 {
        now += DESCRIPTOR_POLL_INTERVAL;
        target.registry.mappings_changed();
        target.poll(now);
        assert_eq!(target.unwinder.max_known_code_address(), 0x2000);
    }

    target.set_head(0);
    target.poll(now + DESCRIPTOR_POLL_INTERVAL);
    assert_eq!(target.unwinder.max_known_code_address(), 0x500);
    assert!(target.registry.frame(0x1000).is_none());
}

#[test]
fn descriptor_disappearance_retires_all_runtime_ownership_and_retries() {
    let first = HEAD;
    let second = ObjectId {
        entry: 0x300,
        ..first
    };
    let mut target = RegistryFixture::new(&[first, second]);
    target.unwinder.add_module(test_module(0x100..0x500));
    assert!(target.publish(first, 0x1000..0x2000));
    assert!(target.publish(second, 0x3000..0x4000));
    let now = Instant::now();
    target.poll(now);
    assert_eq!(target.registry.retry_after.len(), 2);

    target.registry.discovery.descriptors.clear();
    target.poll(now + DESCRIPTOR_POLL_INTERVAL);

    assert!(target.registry.objects.is_empty());
    assert!(target.registry.code_ranges.is_empty());
    assert!(target.registry.last_descriptors.is_empty());
    assert!(target.registry.retry_after.is_empty());
    assert_eq!(target.unwinder.max_known_code_address(), 0x500);
    assert!(!target.registry.needs_reconciliation);
    assert_eq!(target.registry.last_revalidation_cycle_at, Some(now));
}

#[test]
fn revalidation_cycles_advance_when_object_reads_fail_or_wait_for_retry() {
    for waiting_for_retry in [false, true] {
        let id = HEAD;
        let mut target = RegistryFixture::new(&[id]);
        assert!(target.publish(id, 0x1000..0x2000));
        let original = target.registry.frame(0x1000);
        let now = Instant::now();
        let retry_at = now + OBJECT_RETRY_INTERVAL * if waiting_for_retry { 2 } else { 1 };
        if waiting_for_retry {
            target.registry.retry_after.insert(id, retry_at);
        }

        // The fixture publishes decoded objects without readable ELF images.
        target.poll(now);
        target.poll(now + DESCRIPTOR_POLL_INTERVAL);

        assert!(!target.registry.needs_reconciliation);
        assert_eq!(target.registry.last_revalidation_cycle_at, Some(now));
        assert_eq!(target.registry.retry_after.get(&id), Some(&retry_at));
        assert_eq!(target.registry.frame(0x1000), original);
        assert_eq!(target.unwinder.max_known_code_address(), 0x2000);
    }
}

#[test]
fn overlapping_registrations_wait_for_the_active_owner_to_retire() {
    let first = HEAD;
    let second = ObjectId {
        entry: 0x300,
        ..first
    };
    for code in [0x1000..0x2000, 0x1000..0x1800, 0x1800..0x3000] {
        let mut target = RegistryFixture::new(&[first]);
        assert!(target.publish(first, 0x1000..0x2000));
        let original = target.registry.frame(0x1900).unwrap();

        assert!(!target.publish(second, code.clone()));
        assert_eq!(target.registry.frame(0x1900), Some(original));
        assert_eq!(target.unwinder.max_known_code_address(), 0x2000);

        target.set_head(0);
        target.poll(Instant::now());
        assert!(target.registry.frame(0x1900).is_none());
        assert!(target.publish(second, code.clone()));
        assert_ne!(
            target.registry.frame(code.start).unwrap().module_id,
            original.module_id
        );
        assert!(target.registry.frame(code.end).is_none());
        assert_eq!(target.unwinder.max_known_code_address(), code.end);
    }
}

#[test]
fn unchanged_descriptors_skip_list_reads_until_reconciliation_or_retry() {
    for retry_pending in [false, true] {
        let head = HEAD;
        let tail = TAIL;
        let mut target = RegistryFixture::new(&[head, tail]);
        assert!(target.publish(head, 0x1000..0x2000));
        assert!(target.publish(tail, 0x3000..0x4000));
        let now = Instant::now();
        target.poll(now);

        // Miss a notification: the list changes while the descriptor stays identical.
        target.write_entries(&[head]);
        let deadline_ms = if retry_pending { 300 } else { 1000 };
        if retry_pending {
            target
                .registry
                .retry_after
                .insert(tail, now + Duration::from_millis(deadline_ms));
        }
        for millis in 1..deadline_ms {
            target.poll(now + Duration::from_millis(millis));
            assert!(target.registry.objects.contains_key(&tail));
        }

        let deadline = now + Duration::from_millis(deadline_ms);
        target.poll(deadline);
        assert!(!target.registry.objects.contains_key(&tail));
        assert!(target.registry.objects.contains_key(&head));

        target.set_head(0);
        target.poll(deadline + DESCRIPTOR_POLL_INTERVAL);
        assert!(target.registry.objects.is_empty());
    }
}

#[test]
fn changed_membership_rejects_staged_reads_without_backoff_or_retirement() {
    let head = HEAD;
    let tail = TAIL;
    let mut target = RegistryFixture::new(&[head, tail]);
    assert!(target.publish(head, 0x1000..0x2000));
    assert!(target.publish(tail, 0x3000..0x4000));
    let now = Instant::now();
    target.registry.retry_after.insert(head, now);
    target
        .memory
        .write_all_at(OBJECT_IMAGE, head.address)
        .unwrap();
    let before = target.registry.frame(0x3000);
    let snapshot = snapshot(&target.memory, target.registry.last_descriptors.clone()).unwrap();

    // The list changes while the descriptor returns to its previous values.
    target.write_entries(&[head]);
    assert!(target
        .registry
        .stage_refresh(7, snapshot, now, None)
        .is_none());
    assert_eq!(target.registry.frame(0x3000), before);
    assert_eq!(target.registry.objects.len(), 2);
    assert_eq!(target.registry.retry_after.len(), 1);
    assert_eq!(target.registry.retry_after.get(&head), Some(&now));
}

#[test]
fn demand_preserves_other_frames_until_the_next_ordinary_refresh() {
    for notified in [false, true] {
        let mut target = RegistryFixture::new(&[HEAD, TAIL]);
        assert!(target.publish(HEAD, 0x1000..0x2000));
        assert!(target.publish(TAIL, 0x3000..0x4000));
        target
            .memory
            .write_all_at(OBJECT_IMAGE, HEAD.address)
            .unwrap();
        let captured_tail = target.registry.frame(0x3000).unwrap();
        let now = Instant::now();
        target.registry.last_revalidation_cycle_at = Some(now - METADATA_REVALIDATION_INTERVAL);
        target.registry.retry_after.insert(TAIL, now);

        if notified {
            target.unregister(TAIL, &[HEAD]);
        } else {
            target.write_entries(&[HEAD]);
        }

        assert!(!target.demand(0x1000));
        assert_eq!(target.registry.frame(0x3000), Some(captured_tail));
        assert_eq!(target.unwinder.max_known_code_address(), 0x4000);
        assert_eq!(target.registry.retry_after.get(&TAIL), Some(&now));
        assert_eq!(
            target.registry.last_revalidation_cycle_at,
            Some(now - METADATA_REVALIDATION_INTERVAL)
        );
        assert!(target.registry.last_poll_attempt_at.is_none());

        target.poll(Instant::now());
        assert!(target.registry.frame(0x3000).is_none());
        assert!(target.registry.frame(0x1000).is_some());
        assert!(!target.registry.retry_after.contains_key(&TAIL));
    }
}

#[test]
fn demand_defers_removal_and_unreadable_replacements_of_captured_frames() {
    for removed in [false, true] {
        let mut target = RegistryFixture::new(&[HEAD]);
        assert!(target.publish(HEAD, 0x1000..0x2000));
        let captured = target.registry.frame(0x1000);
        if removed {
            target.set_head(0);
        } else {
            // Changed bytes are readable, but do not form a valid replacement ELF.
            target
                .memory
                .write_all_at(b"changed fixture object", HEAD.address)
                .unwrap();
        }
        assert!(!target.demand(0x1000));
        assert_eq!(target.registry.frame(0x1000), captured);
        assert!(target.registry.needs_reconciliation);
        target.poll(Instant::now());
        assert!(target.registry.frame(0x1000).is_none());
    }
}

#[test]
fn unknown_frame_does_not_read_memory_or_consume_demand_deadline() {
    let mut target = RegistryFixture::new(&[HEAD]);
    assert!(target.publish(HEAD, 0x1000..0x2000));
    target.memory.set_len(0).unwrap();

    assert!(!target.demand(0x2000));
    assert!(target.registry.last_demand_refresh_at.is_none());
    assert!(target.registry.last_poll_attempt_at.is_none());
    assert!(target.registry.retry_after.is_empty());
    assert!(target.registry.frame(0x1000).is_some());
}

#[test]
fn failed_and_unchanged_demands_are_throttled() {
    for readable in [false, true] {
        let mut target = RegistryFixture::new(&[HEAD]);
        assert!(target.publish(HEAD, 0x1000..0x2000));
        if readable {
            target
                .memory
                .write_all_at(OBJECT_IMAGE, HEAD.address)
                .unwrap();
        }
        target.registry.last_revalidation_cycle_at = Some(Instant::now());

        assert!(!target.demand(0x1000));
        let first_attempt = target.registry.last_demand_refresh_at;
        assert!(first_attempt.is_some());
        assert_eq!(target.registry.retry_after.contains_key(&HEAD), !readable);

        // If another attempt reads the descriptor, this removal would retire the object.
        target.set_head(0);
        target.registry.last_poll_attempt_at = None;
        assert!(!target.demand(0x1000));
        assert_eq!(target.registry.last_demand_refresh_at, first_attempt);
        assert!(target.registry.last_poll_attempt_at.is_none());
        assert!(target.registry.frame(0x1000).is_some());
    }
}

#[test]
fn pending_object_retry_prevents_demand_without_consuming_its_deadline() {
    let mut target = RegistryFixture::new(&[HEAD]);
    assert!(target.publish(HEAD, 0x1000..0x2000));
    let retry = Instant::now() + OBJECT_RETRY_INTERVAL;
    target.registry.retry_after.insert(HEAD, retry);
    target.set_head(0);

    assert!(!target.demand(0x1000));
    assert!(target.registry.last_demand_refresh_at.is_none());
    assert!(target.registry.last_poll_attempt_at.is_none());
    assert_eq!(target.registry.retry_after.get(&HEAD), Some(&retry));
    assert!(target.registry.frame(0x1000).is_some());
}

/// Copy linked CFI into the target address advertised by the registered ELF.
#[cfg(target_arch = "x86_64")]
fn write_live_cfi(memory: &File, image: &[u8]) {
    let elf = goblin::elf::Elf::parse(image).unwrap();
    let section = elf
        .section_headers
        .iter()
        .find(|section| elf.shdr_strtab.get_at(section.sh_name) == Some(".eh_frame"))
        .unwrap();
    let offset = usize::try_from(section.sh_offset).unwrap();
    let size = usize::try_from(section.sh_size).unwrap();
    memory
        .write_all_at(&image[offset..offset + size], section.sh_addr)
        .unwrap();
}

#[test]
#[cfg(target_arch = "x86_64")]
fn demand_refreshes_changed_live_cfi_inside_the_normal_poll_interval() {
    use crate::linux::unwind::NativeCache;
    use framehop::{FrameAddress, UnwinderWithDetails};

    let directory = TempDir::new("jit-demand-cfi");
    let initial = std::fs::read(crate::test_support::assemble_jit_overlay(
        directory.path(),
        16,
    ))
    .unwrap();
    let updated = std::fs::read(crate::test_support::assemble_jit_overlay(
        directory.path(),
        48,
    ))
    .unwrap();
    let id = ObjectId {
        entry: HEAD.entry,
        address: 0x10000,
        size: initial.len() as u64,
    };
    let mut target = RegistryFixture::new(&[id, TAIL]);
    target.memory.write_all_at(&initial, id.address).unwrap();
    write_live_cfi(&target.memory, &initial);
    let object = load_object(&target.memory, i32::MAX, id).unwrap();
    assert!(target
        .registry
        .publish_object(
            id,
            object,
            &mut target.unwinder,
            &mut target.modules,
            &mut target.writer
        )
        .unwrap());
    assert!(target.publish(TAIL, 0x3000..0x4000));
    let original_frame = target.registry.frame(0x1001).unwrap();
    let other_frame = target.registry.frame(0x3000);
    let mut cache = NativeCache::default();
    let unwind = |target: &RegistryFixture, cache: &mut NativeCache| {
        let mut regs = framehop::UnwindRegsNative::new(0x1001, 0x8000, 0x8100);
        let result = target
            .unwinder
            .unwind_frame_with_details(
                FrameAddress::from_instruction_pointer(0x1001),
                &mut regs,
                cache,
                &mut |address| match address {
                    0x8008 => Ok(0xaaaa),
                    0x8028 => Ok(0xbbbb),
                    _ => Err(()),
                },
            )
            .unwrap();
        assert_eq!(result.fallback_reason(), None);
        result.return_address()
    };
    assert_eq!(unwind(&target, &mut cache), Some(0xaaaa));

    // Only live CFI changes: the descriptor, registered ELF, and list stay identical.
    write_live_cfi(&target.memory, &updated);
    let now = Instant::now();
    target.registry.last_revalidation_cycle_at = Some(now);
    target.registry.last_poll_attempt_at = Some(now);
    target.poll(now);
    assert_eq!(unwind(&target, &mut cache), Some(0xaaaa));

    assert!(target.demand(0x1001));
    assert_eq!(unwind(&target, &mut cache), Some(0xbbbb));
    assert_ne!(
        target.registry.frame(0x1001).unwrap().module_id,
        original_frame.module_id
    );
    assert_eq!(target.registry.frame(0x3000), other_frame);
    assert!(target.registry.retry_after.is_empty());
    assert_eq!(target.registry.last_revalidation_cycle_at, Some(now));
    assert!(!target.registry.objects[&id]
        .has_changed(&target.memory, id, &mut Vec::new())
        .unwrap());
}
