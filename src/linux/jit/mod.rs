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
use protocol::{read_descriptor, snapshot, Descriptor, ObjectId, Snapshot, SnapshotError};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, Instant};

const DESCRIPTOR_POLL_INTERVAL: Duration = Duration::from_millis(100);
const METADATA_REVALIDATION_INTERVAL: Duration = Duration::from_secs(1);
const OBJECT_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const REGISTRY_LIMIT_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// One accepted code section, indexed by its target start address in the registry.
struct CodeRange {
    /// Exclusive target address at the end of the executable section.
    end: u64,
    /// Recorded module ID pinned onto samples so later address reuse cannot rename them.
    module_id: u32,
    /// Registration owning this section, used to refresh the object for a failing frame.
    object_id: ObjectId,
}

/// Validated object reads ready to apply to committed registrations.
struct PendingRefresh {
    /// A demand refresh updates only this registration; `None` reconciles the full list.
    requested_object: Option<ObjectId>,
    /// Descriptor values and membership rechecked after copying object metadata.
    snapshot: Snapshot,
    /// Retire these registrations even if loading their replacements failed.
    invalidated: FxHashSet<ObjectId>,
    /// Decoded new or replacement objects awaiting publication.
    /// Conflicts with another live code range can still defer publication.
    loaded: Vec<(ObjectId, JitObject)>,
    /// Retried unwind data for existing objects, preserving their recorded symbol IDs.
    /// Entries that remain unreadable schedule another retry instead of being installed.
    reloaded_unwind: Vec<(ObjectId, JitUnwind)>,
    /// Objects whose reads failed; retry deadlines are set only when this refresh commits.
    retry: Vec<ObjectId>,
}

impl PendingRefresh {
    /// Whether committing these reads changes an existing object's frame or unwind state.
    fn changes_object(&self, id: ObjectId) -> bool {
        self.invalidated.contains(&id)
            || !self.snapshot.objects.contains(&id)
            || self
                .reloaded_unwind
                .iter()
                .any(|(loaded, unwind)| *loaded == id && !unwind.needs_retry())
    }
}

/// Live runtime registrations and their frame/unwind ownership for one process.
/// The enclosing process table keeps this registry associated with the same process.
/// Deadlines use the recorder's monotonic clock, rather than sample timestamps.
#[derive(Default)]
pub(super) struct JitRegistry {
    /// Descriptor discovery, cached absence, and the target-memory handle.
    discovery: Discovery,
    /// Accepted registrations and their decoded metadata.
    /// New object reads enter this map only after snapshot validation and publication.
    objects: FxHashMap<ObjectId, JitObject>,
    /// Disjoint code sections keyed by target start address.
    /// Resolves frames to recorded modules and demand refreshes to owning registrations.
    code_ranges: BTreeMap<u64, CodeRange>,
    /// Descriptor addresses and values from the last accepted snapshot.
    /// Used to notice registration notifications, including observed entry reuse.
    last_descriptors: Vec<(u64, Descriptor)>,
    /// Time of the last ordinary poll attempt, including failed reads.
    /// Limits ordinary polls; `None` permits the first poll immediately.
    last_poll_attempt_at: Option<Instant>,
    /// Earliest ordinary or demand retry after a registry size limit was exceeded.
    /// Retained until a bounded snapshot succeeds, so each failure episode logs once.
    registry_retry_after: Option<Instant>,
    /// Executable mappings changed since the last accepted registry snapshot.
    /// Forces a list scan on an eligible poll and stays set if the refresh fails.
    needs_reconciliation: bool,
    /// Start time of the last full revalidation cycle with an accepted snapshot.
    /// The cycle can include failed reads or objects skipped for backoff; this
    /// does not mean every object is fresh. `None` makes full revalidation due.
    last_revalidation_cycle_at: Option<Instant>,
    /// Earliest retry time per object after read failures or deferred publication.
    /// Both ordinary and demand refreshes respect these recorder-clock deadlines.
    retry_after: FxHashMap<ObjectId, Instant>,
    /// Time of the last demand attempt admitted by the process and object limits.
    /// Failed and unchanged attempts also consume the limit; `None` permits the first.
    last_demand_refresh_at: Option<Instant>,
}

impl JitRegistry {
    /// Schedule discovery and full reconciliation after executable mappings change.
    pub(super) fn mappings_changed(&mut self) {
        self.discovery.mappings_changed();
        self.needs_reconciliation = true;
    }

    /// Resolve a normalized user address against committed runtime ranges.
    pub(super) fn frame(&self, address: u64) -> Option<FrameRecord> {
        let (start, range) = self.range_for_address(address)?;
        Some(FrameRecord {
            module_id: Some(range.module_id),
            file_relative_ip: address - start,
            abs_ip: address,
            mode: FrameMode::User,
        })
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
        self.refresh_at(pid, unwinder, modules, writer, Instant::now(), None)
            .map(|_| ())
    }

    /// Revalidate a known runtime frame after failure or fallback, at most once per second.
    /// Unknown addresses never trigger discovery or target-memory reads here.
    /// Return whether committed metadata changed and the captured stack should be retried.
    pub(super) fn refresh_for_frame<W: io::Write>(
        &mut self,
        address: u64,
        pid: i32,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<bool> {
        let Some((_, range)) = self.range_for_address(address) else {
            return Ok(false);
        };
        let id = range.object_id;
        let now = Instant::now();
        if self
            .last_demand_refresh_at
            .is_some_and(|last| now.duration_since(last) < OBJECT_RETRY_INTERVAL)
        {
            return Ok(false);
        }
        if self.retry_after.get(&id).is_some_and(|retry| now < *retry) {
            return Ok(false);
        }
        self.last_demand_refresh_at = Some(now);
        self.refresh_at(pid, unwinder, modules, writer, now, Some(id))
    }

    /// Find the registration that owns a normalized code address.
    fn range_for_address(&self, address: u64) -> Option<(u64, &CodeRange)> {
        let (&start, range) = self.code_ranges.range(..=address).next_back()?;
        (address < range.end).then_some((start, range))
    }

    /// Bound full metadata reads independently of descriptor/list traffic.
    fn revalidation_due(&self, now: Instant) -> bool {
        self.last_revalidation_cycle_at
            .is_none_or(|last| now.duration_since(last) >= METADATA_REVALIDATION_INTERVAL)
    }

    /// Reconcile changed descriptors, due retries, and periodically missed notifications.
    fn scan_needed(&self, descriptors: &[(u64, Descriptor)], now: Instant) -> bool {
        self.needs_reconciliation
            || descriptors != self.last_descriptors
            || self.revalidation_due(now)
            || self.retry_after.values().any(|retry| now >= *retry)
    }

    /// Poll, stage remote reads, validate consistency, then publish accepted changes.
    /// Return whether the requested object's committed state changed, if one was supplied.
    fn refresh_at<W: io::Write>(
        &mut self,
        pid: i32,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
        now: Instant,
        requested_object: Option<ObjectId>,
    ) -> io::Result<bool> {
        if self.discovery.is_absent() {
            return Ok(false);
        }
        if self.registry_retry_after.is_some_and(|retry| now < retry) {
            return Ok(false);
        }
        if requested_object.is_none()
            && self
                .last_poll_attempt_at
                .is_some_and(|last| now.duration_since(last) < DESCRIPTOR_POLL_INTERVAL)
        {
            return Ok(false);
        }
        if requested_object.is_none() {
            self.last_poll_attempt_at = Some(now);
            self.discovery.refresh_descriptors(pid, now);
        }
        if self.discovery.descriptors.is_empty() {
            if requested_object.is_some() {
                return Ok(false);
            }
            self.retire_objects(unwinder, |_| true);
            self.last_descriptors.clear();
            self.retry_after.clear();
            self.registry_retry_after = None;
            return Ok(false);
        }
        self.discovery.open_memory(pid, now);
        let Some(memory) = &self.discovery.memory else {
            return Ok(false);
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
                return Ok(false);
            }
        };
        if requested_object.is_none() && !self.scan_needed(&descriptors, now) {
            return Ok(false);
        }
        let snapshot = match snapshot(memory, descriptors) {
            Ok(snapshot) => snapshot,
            Err(error @ SnapshotError::Limit(_)) => {
                if self.registry_retry_after.is_none() {
                    tracing::warn!(pid, %error,
                        "JIT coverage is incomplete; keeping previous metadata and retrying in one second");
                }
                self.registry_retry_after = Some(now + REGISTRY_LIMIT_RETRY_INTERVAL);
                return Ok(false);
            }
            Err(error) => {
                tracing::trace!(pid, %error, "could not snapshot GDB JIT registry");
                return Ok(false);
            }
        };
        self.registry_retry_after = None;
        let Some(pending) = self.stage_refresh(pid, snapshot, now, requested_object) else {
            return Ok(false);
        };
        if let Some(id) = requested_object {
            // A captured frame can still need the old metadata after live code disappears.
            // Defer removal or an unreadable replacement until the next ordinary refresh.
            if !pending.snapshot.objects.contains(&id)
                || (pending.invalidated.contains(&id)
                    && !pending.loaded.iter().any(|(loaded, _)| *loaded == id))
            {
                self.needs_reconciliation = true;
                return Ok(false);
            }
        }
        let changed = requested_object.is_some_and(|id| pending.changes_object(id));
        self.commit_refresh(pending, now, unwinder, modules, writer)?;
        Ok(changed)
    }

    /// Stage object reads and reject observed descriptor or membership changes.
    fn stage_refresh(
        &self,
        pid: i32,
        snapshot: Snapshot,
        now: Instant,
        requested_object: Option<ObjectId>,
    ) -> Option<PendingRefresh> {
        let memory = self.discovery.memory.as_ref()?;
        let mut invalidated = FxHashSet::default();
        for &(address, descriptor) in &snapshot.descriptors {
            if descriptor.action == 1 && !self.last_descriptors.contains(&(address, descriptor)) {
                // A registration can reuse the same entry and ELF allocation.
                invalidated.extend(
                    self.objects
                        .keys()
                        .filter(|id| {
                            id.entry == descriptor.relevant
                                && requested_object.is_none_or(|requested| requested == **id)
                        })
                        .copied(),
                );
            }
        }
        let metadata_revalidation_due = self.revalidation_due(now);
        let mut retry = Vec::new();
        let mut loaded = Vec::new();
        let mut reloaded_unwind = Vec::new();
        // Reuse metadata storage within this scan without retaining large buffers per process.
        let mut scratch = Vec::new();
        for id in &snapshot.objects {
            if requested_object.is_some_and(|requested| requested != *id) {
                continue;
            }
            if self.retry_after.get(id).is_some_and(|retry| now < *retry) {
                continue;
            }
            if (metadata_revalidation_due
                || self.retry_after.contains_key(id)
                || requested_object == Some(*id))
                && !invalidated.contains(id)
            {
                if let Some(object) = self.objects.get(id) {
                    match object.has_changed(memory, *id, &mut scratch) {
                        Ok(true) => {
                            invalidated.insert(*id);
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
            if let Some(object) = self.objects.get(id).filter(|_| !invalidated.contains(id)) {
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
            requested_object,
            snapshot,
            invalidated,
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
            requested_object,
            snapshot,
            invalidated,
            mut loaded,
            reloaded_unwind,
            retry,
        } = pending;
        self.retire_objects(unwinder, |id| {
            requested_object.is_none_or(|requested| requested == *id)
                && (!snapshot.objects.contains(id) || invalidated.contains(id))
        });
        if requested_object.is_none() {
            self.last_descriptors = snapshot.descriptors;
            self.needs_reconciliation = false;
            if self.revalidation_due(now) {
                // A cycle can include objects skipped for backoff or failed reads.
                self.last_revalidation_cycle_at = Some(now);
            }
        }
        for id in retry {
            self.retry_after.insert(id, now + OBJECT_RETRY_INTERVAL);
        }
        // Accepted attempts clear expired retries; failures above renewed theirs.
        self.retry_after.retain(|id, deadline| {
            requested_object.is_some_and(|requested| requested != *id)
                || (snapshot.objects.contains(id) && now < *deadline)
        });
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
                    object_id: id,
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
