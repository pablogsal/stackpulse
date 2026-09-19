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
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&1_u32.to_ne_bytes()); // Protocol version.
        encoded.extend_from_slice(&1_u32.to_ne_bytes()); // Register action.
        encoded.extend_from_slice(&first.to_ne_bytes()); // Relevant entry.
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

    fn poll(&mut self, now: Instant) {
        // No real target: failed discovery retains our injected memory and descriptors.
        self.registry
            .refresh_at(
                -1,
                &mut self.unwinder,
                &mut self.modules,
                &mut self.writer,
                now,
            )
            .unwrap();
    }
}

fn jit_object(code: Range<u64>) -> JitObject {
    let mut module =
        ModuleRecord::new(0, crate::Pid::new(7).unwrap(), code.clone(), 0, "jit").unwrap();
    module.jit_symbols = Some([].into());
    JitObject::test_with_module(module, test_module(code), OBJECT_IMAGE)
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
    assert!(target.registry.stage_refresh(7, snapshot, now).is_none());
    assert_eq!(target.registry.frame(0x3000), before);
    assert_eq!(target.registry.objects.len(), 2);
    assert_eq!(target.registry.retry_after.len(), 1);
    assert_eq!(target.registry.retry_after.get(&head), Some(&now));
}
