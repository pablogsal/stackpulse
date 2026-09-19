//! Capture live runtime modules without exposing GDB protocol details to recording.
//!
//! Refresh runs while processing samples, with deadlines based on processing time.
//! There is no background timer; registrations can come and go between checks.
//! Polling stages object reads before validating the descriptors again. Committed
//! registrations own disjoint code ranges for both frame lookup and unwinding.
//! Failed descriptor reads and inconsistent snapshots retain committed registrations.
//! Object and CFI reads are retried; spool-write failures propagate.

mod discovery;
mod object;
mod protocol;
#[cfg(test)]
mod tests;

use super::unwind::NativeUnwinder;
use crate::spool::{FrameMode, FrameRecord, ModuleTable, PerfSpoolWriter};
use discovery::Discovery;
use object::{load_object, JitObject, JitUnwind};
use protocol::{read_descriptor, snapshot, Descriptor, ObjectId, Snapshot};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, Instant};

const DESCRIPTOR_POLL_INTERVAL: Duration = Duration::from_millis(100);
const REGISTRY_SCAN_INTERVAL: Duration = Duration::from_secs(1);
const OBJECT_RETRY_INTERVAL: Duration = Duration::from_secs(1);

struct CodeRange {
    end: u64,
    module_id: u32,
}

/// Validated object reads ready to apply to committed registrations.
struct PendingRefresh {
    snapshot: Snapshot,
    replaced: FxHashSet<ObjectId>,
    loaded: Vec<(ObjectId, JitObject)>,
    reloaded_unwind: Vec<(ObjectId, JitUnwind)>,
    retry: Vec<ObjectId>,
}

/// Live runtime registrations and their frame/unwind ownership for one process.
/// The enclosing process table keeps this registry associated with the same process.
#[derive(Default)]
pub(super) struct JitRegistry {
    discovery: Discovery,
    objects: FxHashMap<ObjectId, JitObject>,
    code_ranges: BTreeMap<u64, CodeRange>,
    last_descriptors: Vec<(u64, Descriptor)>,
    last_poll_attempt_at: Option<Instant>,
    needs_reconciliation: bool,
    last_revalidation_cycle_at: Option<Instant>,
    retry_after: FxHashMap<ObjectId, Instant>,
}

impl JitRegistry {
    /// Schedule discovery and full reconciliation after executable mappings change.
    pub(super) fn mappings_changed(&mut self) {
        self.discovery.mappings_changed();
        self.needs_reconciliation = true;
    }

    /// Retire registrations and their frame/unwind ownership together.
    fn retire_objects(
        &mut self,
        unwinder: &mut NativeUnwinder,
        mut should_retire: impl FnMut(&ObjectId) -> bool,
    ) {
        let code_ranges = &mut self.code_ranges;
        self.objects.retain(|id, object| {
            if !should_retire(id) {
                return true;
            }
            for module in &object.modules {
                unwinder.remove_jit_module(module.start);
                code_ranges.remove(&module.start);
            }
            false
        });
    }

    /// Install runtime ranges even without CFI, shielding them from backing-image rules.
    fn install_unwind(unwind: &JitUnwind, unwinder: &mut NativeUnwinder) {
        for module in unwind.modules() {
            unwinder.add_jit_module(module.clone());
        }
    }

    /// Resolve a normalized user address against committed runtime ranges.
    pub(super) fn frame(&self, address: u64) -> Option<FrameRecord> {
        let (&start, range) = self.code_ranges.range(..=address).next_back()?;
        (address < range.end).then_some(FrameRecord {
            module_id: Some(range.module_id),
            file_relative_ip: address - start,
            abs_ip: address,
            mode: FrameMode::User,
        })
    }

    /// Bound full metadata reads independently of descriptor/list traffic.
    fn revalidation_due(&self, now: Instant) -> bool {
        self.last_revalidation_cycle_at
            .is_none_or(|last| now.duration_since(last) >= REGISTRY_SCAN_INTERVAL)
    }

    /// Reconcile changed descriptors, due retries, and periodically missed notifications.
    fn scan_needed(&self, descriptors: &[(u64, Descriptor)], now: Instant) -> bool {
        self.needs_reconciliation
            || descriptors != self.last_descriptors
            || self.revalidation_due(now)
            || self.retry_after.values().any(|retry| now >= *retry)
    }

    /// Refresh live metadata before unwinding; only persistence failures escape.
    /// Calls inside the poll interval leave the committed state unchanged.
    pub(super) fn refresh<W: io::Write>(
        &mut self,
        pid: i32,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<()> {
        if self.discovery.is_absent() {
            return Ok(());
        }
        self.refresh_at(pid, unwinder, modules, writer, Instant::now())
    }

    /// Poll, stage remote reads, validate consistency, then publish accepted changes.
    fn refresh_at<W: io::Write>(
        &mut self,
        pid: i32,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
        now: Instant,
    ) -> io::Result<()> {
        if self.discovery.is_absent() {
            return Ok(());
        }
        if self
            .last_poll_attempt_at
            .is_some_and(|last| now.duration_since(last) < DESCRIPTOR_POLL_INTERVAL)
        {
            return Ok(());
        }
        self.last_poll_attempt_at = Some(now);
        self.discovery.refresh_descriptors(pid, now);
        if self.discovery.descriptors.is_empty() {
            self.retire_objects(unwinder, |_| true);
            self.last_descriptors.clear();
            self.retry_after.clear();
            return Ok(());
        }
        self.discovery.open_memory(pid, now);
        let Some(memory) = &self.discovery.memory else {
            return Ok(());
        };
        let descriptors = match self
            .discovery
            .descriptors
            .iter()
            .map(|&address| Ok((address, read_descriptor(memory, address)?)))
            .collect::<io::Result<Vec<_>>>()
        {
            Ok(descriptors) => descriptors,
            Err(error) => {
                tracing::trace!(pid, %error, "could not read GDB JIT descriptors");
                return Ok(());
            }
        };
        if !self.scan_needed(&descriptors, now) {
            return Ok(());
        }
        let snapshot = match snapshot(memory, descriptors) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::trace!(pid, %error, "could not snapshot GDB JIT registry");
                return Ok(());
            }
        };
        let Some(pending) = self.stage_refresh(pid, snapshot, now) else {
            return Ok(());
        };
        self.commit_refresh(pending, now, unwinder, modules, writer)
    }

    /// Stage object reads and reject observed descriptor or membership changes.
    fn stage_refresh(&self, pid: i32, snapshot: Snapshot, now: Instant) -> Option<PendingRefresh> {
        let memory = self.discovery.memory.as_ref()?;
        let mut replaced = FxHashSet::default();
        for &(address, descriptor) in &snapshot.descriptors {
            if descriptor.action == 1 && !self.last_descriptors.contains(&(address, descriptor)) {
                // A registration can reuse the same entry and ELF allocation.
                replaced.extend(
                    self.objects
                        .keys()
                        .filter(|id| id.entry == descriptor.relevant)
                        .copied(),
                );
            }
        }
        let metadata_revalidation_due = self.revalidation_due(now);
        let mut retry = Vec::new();
        let mut loaded = Vec::new();
        let mut reloaded_unwind = Vec::new();
        for id in &snapshot.objects {
            if self.retry_after.get(id).is_some_and(|retry| now < *retry) {
                continue;
            }
            if (metadata_revalidation_due || self.retry_after.contains_key(id))
                && !replaced.contains(id)
            {
                if let Some(object) = self.objects.get(id) {
                    match object.has_changed(memory, *id) {
                        Ok(true) => {
                            replaced.insert(*id);
                        }
                        Ok(false) => {}
                        Err(error) => {
                            tracing::trace!(pid, %error, "could not revalidate GDB JIT object");
                            retry.push(*id);
                            continue;
                        }
                    }
                }
            }
            if let Some(object) = self.objects.get(id).filter(|_| !replaced.contains(id)) {
                if object.unwind.needs_retry() {
                    match object.reload_unwind(memory, *id) {
                        Ok(unwind) => reloaded_unwind.push((*id, unwind)),
                        Err(error) => {
                            tracing::trace!(pid, %error, "could not reload GDB JIT unwind data");
                            retry.push(*id);
                        }
                    }
                }
                continue;
            }
            match load_object(memory, pid, *id) {
                Ok(object) => loaded.push((*id, object)),
                Err(error) => {
                    tracing::trace!(pid, %error, "could not read GDB JIT object");
                    retry.push(*id);
                }
            }
        }
        // The target can mutate registrations while ELF and relocated CFI are copied.
        snapshot.is_current(memory).then_some(PendingRefresh {
            snapshot,
            replaced,
            loaded,
            reloaded_unwind,
            retry,
        })
    }

    /// Retire absent objects, update CFI, then publish sorted registrations.
    fn commit_refresh<W: io::Write>(
        &mut self,
        pending: PendingRefresh,
        now: Instant,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<()> {
        let PendingRefresh {
            snapshot,
            replaced,
            mut loaded,
            reloaded_unwind,
            retry,
        } = pending;
        self.retire_objects(unwinder, |id| {
            !snapshot.objects.contains(id) || replaced.contains(id)
        });
        self.last_descriptors = snapshot.descriptors;
        self.needs_reconciliation = false;
        if self.revalidation_due(now) {
            // A cycle can include objects skipped for backoff or failed reads.
            self.last_revalidation_cycle_at = Some(now);
        }
        for id in retry {
            self.retry_after.insert(id, now + OBJECT_RETRY_INTERVAL);
        }
        // Accepted attempts clear expired retries; failures above renewed theirs.
        self.retry_after
            .retain(|id, deadline| snapshot.objects.contains(id) && now < *deadline);
        for (id, unwind) in reloaded_unwind {
            if unwind.needs_retry() {
                self.retry_after.insert(id, now + OBJECT_RETRY_INTERVAL);
                continue;
            }
            if let Some(object) = self.objects.get_mut(&id) {
                Self::install_unwind(&unwind, unwinder);
                object.unwind = unwind;
                self.retry_after.remove(&id);
            }
        }
        loaded.sort_unstable_by_key(|(id, _)| (id.entry, id.address, id.size));
        for (id, object) in loaded {
            let retry_unwind = object.unwind.needs_retry();
            if !self.publish_object(id, object, unwinder, modules, writer)? || retry_unwind {
                self.retry_after.insert(id, now + OBJECT_RETRY_INTERVAL);
            }
        }
        Ok(())
    }

    /// Persist symbols before installing disjoint frame and unwind ownership.
    fn publish_object<W: io::Write>(
        &mut self,
        id: ObjectId,
        mut object: JitObject,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<bool> {
        // Keep one owner per code address so retiring an object cannot remove
        // another registration's CFI or disagree with symbol lookup.
        if object.modules.iter().any(|module| {
            self.code_ranges
                .range(..module.end)
                .next_back()
                .is_some_and(|(_, previous)| previous.end > module.start)
        }) {
            tracing::trace!(
                entry = id.entry,
                "overlapping GDB JIT registration deferred"
            );
            return Ok(false);
        }
        for module in &mut object.modules {
            modules.record_pinned_module(module, writer)?;
        }
        Self::install_unwind(&object.unwind, unwinder);
        for module in &object.modules {
            self.code_ranges.insert(
                module.start,
                CodeRange {
                    end: module.end,
                    module_id: module.id,
                },
            );
        }
        self.objects.insert(id, object);
        self.retry_after.remove(&id);
        Ok(true)
    }
}

#[cfg(test)]
impl JitRegistry {
    pub(in crate::linux) fn test_with_module(
        module: crate::spool::ModuleRecord,
        unwind: framehop::Module<crate::elf::ElfSectionData>,
        unwinder: &mut NativeUnwinder,
    ) -> Self {
        let mut registry = Self::default();
        let object = JitObject::test_with_module(module, unwind, &[]);
        let mut modules = ModuleTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        assert!(registry
            .publish_object(
                ObjectId {
                    entry: 1,
                    address: 2,
                    size: 3
                },
                object,
                unwinder,
                &mut modules,
                &mut writer
            )
            .unwrap());
        registry
    }
}
