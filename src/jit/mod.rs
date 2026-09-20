//! Linux GDB JIT-interface discovery and in-memory ELF loading.
//!
//! Protocol and producer references:
//! - <https://sourceware.org/gdb/current/onlinedocs/gdb.html/JIT-Interface.html>
//! - <https://github.com/llvm/llvm-project/blob/main/llvm/lib/ExecutionEngine/GDBRegistrationListener.cpp>

mod discovery;
mod object;
mod protocol;

use discovery::{DescriptorDiscovery, JitDescriptorLocation};
use object::{CfiState, JitObject, ObjectChange};
use protocol::{JitDescriptor, JitObjectId, JitSnapshot, SnapshotError};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::collections::BTreeMap;
use std::io;
use std::ops::{Deref, Range};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Process memory used to read live registrations and relocated unwind data.
pub trait MemoryReader {
    /// Target process ID for executable discovery.
    fn pid(&self) -> i32;
    /// Fill the complete buffer from the target address, or return an error.
    fn read(&self, address: u64, buffer: &mut [u8]) -> io::Result<()>;
}

/// File identity used to reject pathname replacements during discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// Inode recorded in the process mapping.
    pub inode: u64,
    /// Device number in the operating system's native encoding.
    pub device: u64,
}

/// One mapping from the caller's current process-image snapshot.
pub trait Mapping {
    /// Half-open target address range.
    fn range(&self) -> Range<u64>;
    /// Backing image path without the procfs deleted suffix.
    fn path(&self) -> &Path;
    /// File offset corresponding to the range start.
    fn file_offset(&self) -> u64;
    /// Whether the mapping permits execution.
    fn executable(&self) -> bool;
    /// Whether the original backing image has been deleted.
    fn deleted(&self) -> bool;
    /// Recorded inode and device numbers, when the mapping source provides them.
    fn file_identity(&self) -> Option<FileIdentity> {
        None
    }
}

/// Generated function name, or an unnamed executable range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// Half-open absolute target address range.
    pub range: Range<u64>,
    /// Producer's symbol spelling; consumers may demangle it.
    pub name: Option<String>,
}

/// Accepted changes, with retirements delivered before installations.
pub enum Update<D> {
    /// This registration no longer owns code or symbol identities.
    Removed {
        /// Synthetic identity shared with its earlier installation.
        path: PathBuf,
    },
    /// Replace unwind ownership for every range belonging to this registration.
    Loaded {
        /// Synthetic identity shared by the registration's executable ranges.
        path: PathBuf,
        /// Owned modules sharing their copied unwind sections.
        modules: Box<[framehop::Module<D>]>,
        /// New symbol identity, or `None` when only unwind data changed.
        symbols: Option<Vec<Symbol>>,
    },
}

const MAX_JIT_ENTRIES: usize = 4096;
const MAX_JIT_TOTAL_SIZE: u64 = 256 * 1024 * 1024;
const MAX_JIT_TOTAL_CFI_SIZE: u64 = 256 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const REVALIDATION_INTERVAL: Duration = Duration::from_secs(1);
const MAX_JIT_READ_SIZE: u64 = 64 * 1024 * 1024;

/// Exponential retry state measured in registration polls.
#[derive(Clone, Copy, Debug)]
struct RetryBackoff {
    /// Zero-based failure index: zero for the first failure, then saturating.
    attempts: u8,
    /// First registration poll on which another attempt is permitted.
    retry_at: u64,
}

impl RetryBackoff {
    /// Schedule the next attempt, doubling delays up to eight polls.
    fn next(previous: Option<Self>, poll: u64) -> Self {
        let attempts = previous.map_or(0, |failure| failure.attempts.saturating_add(1));
        let delay = 1_u64 << u32::from(attempts.min(3));
        Self {
            attempts,
            retry_at: poll.saturating_add(delay),
        }
    }
}

/// Tracks GDB JIT registrations for one live process.
///
/// Descriptor discovery is retried when the ordinary module generation
/// changes. Registration and read failures use bounded exponential backoff.
pub struct Registry<P, D = Arc<[u8]>> {
    process: P,
    descriptors: Vec<JitDescriptorLocation>,
    /// Ordinary module generation last searched for descriptors.
    ///
    /// `None` schedules discovery on the next eligible retry.
    descriptor_search_generation: Option<u64>,
    /// Successfully parsed objects from the last committed stable snapshot.
    objects: HashMap<JitObjectId, JitObject<D>>,
    code_ranges: BTreeMap<u64, (u64, JitObjectId)>,
    limit_warned: bool,
    /// Per-object retry schedules for active registrations that failed to load.
    load_failures: HashMap<JitObjectId, RetryBackoff>,
    /// Retry schedule after a descriptor or list snapshot could not be read.
    refresh_backoff: Option<RetryBackoff>,
    /// Saturating logical clock measured in registration refresh calls.
    poll_count: u64,
    /// Synthetic module paths awaiting removal from framehop.
    stale_paths: HashSet<PathBuf>,
    updates_pending: bool,
    last_poll: Option<Instant>,
    last_discovery: Option<(u64, Instant)>,
    /// Limit early CFI checks requested by unwind failures.
    last_demand_refresh: Option<Instant>,
    last_revalidation: Option<Instant>,
    /// Accepted notifications, used to detect observed entry reuse.
    last_descriptors: Vec<(u64, JitDescriptor)>,
    discovery: DescriptorDiscovery,
    /// A raced candidate must be reconciled even if notifications stay unchanged.
    needs_reconciliation: bool,
}

impl<P: MemoryReader, D: From<Arc<[u8]>> + Deref<Target = [u8]> + Clone> Registry<P, D> {
    /// Start with no registrations; refresh using the caller's mapping snapshot.
    #[must_use]
    pub fn new(process: P) -> Self {
        Self {
            process,
            descriptors: Vec::new(),
            descriptor_search_generation: None,
            objects: HashMap::default(),
            code_ranges: BTreeMap::new(),
            limit_warned: false,
            load_failures: HashMap::default(),
            refresh_backoff: None,
            poll_count: 0,
            stale_paths: HashSet::default(),
            updates_pending: false,
            last_poll: None,
            last_discovery: None,
            last_demand_refresh: None,
            last_revalidation: None,
            last_descriptors: Vec::new(),
            discovery: DescriptorDiscovery::default(),
            needs_reconciliation: true,
        }
    }

    /// Whether complete discovery found no registry in the last mapping generation.
    /// A changed mapping generation must still be passed to `refresh`.
    pub fn is_absent(&self) -> bool {
        self.descriptor_search_generation.is_some() && self.descriptors.is_empty()
    }

    /// Consume changes coalesced since the previous drain, before capturing samples.
    /// Retirements precede loads. A CFI-only load preserves the symbol identity.
    pub fn drain_updates(&mut self, mut publish: impl FnMut(Update<D>)) {
        if !std::mem::take(&mut self.updates_pending) {
            return;
        }
        for path in self.stale_paths.drain() {
            publish(Update::Removed { path });
        }
        for (id, object) in &mut self.objects {
            if !object.pending_modules.is_empty() || object.symbols.is_some() {
                publish(Update::Loaded {
                    path: id.path(),
                    modules: std::mem::take(&mut object.pending_modules),
                    symbols: object.symbols.take(),
                });
            }
        }
    }

    /// Discover before a direct dump's first unwind; batch sampling polls separately.
    pub fn initialize(&mut self, generation: u64, modules: &[impl Mapping]) {
        if self.last_poll.is_none() {
            self.refresh(generation, modules);
        }
    }

    /// Refresh descriptor discovery and the active registration snapshot.
    ///
    /// `module_generation` gates filesystem discovery. Registration polling
    /// continues after discovery even when ordinary modules do not change.
    /// Unstable registry reads keep the previous snapshot; object failures
    /// retry with bounded backoff.
    pub fn refresh(&mut self, module_generation: u64, modules: &[impl Mapping]) {
        if self.descriptor_search_generation == Some(module_generation)
            && self.descriptors.is_empty()
        {
            return;
        }
        let now = Instant::now();
        let mappings_changed = self
            .last_discovery
            .is_some_and(|(generation, _)| generation != module_generation);
        if self
            .last_poll
            .is_some_and(|last| now.duration_since(last) < POLL_INTERVAL)
            && !mappings_changed
        {
            return;
        }
        self.last_poll = Some(now);
        if self.descriptor_search_generation != Some(module_generation)
            && self.last_discovery.is_none_or(|(generation, last)| {
                generation != module_generation || now.duration_since(last) >= REVALIDATION_INTERVAL
            })
        {
            self.last_discovery = Some((module_generation, now));
            self.descriptor_search_generation = Some(module_generation);
            let (locations, complete) = self.discovery.find(self.process.pid(), modules);
            self.update_descriptors(locations, modules);
            if !complete {
                self.descriptor_search_generation = None;
            }
        }

        if self.descriptors.is_empty() {
            return;
        }
        let poll = self.poll_count;
        self.poll_count = self.poll_count.saturating_add(1);
        if self
            .refresh_backoff
            .is_some_and(|failure| poll < failure.retry_at)
        {
            return;
        }
        match self.refresh_objects(poll) {
            Ok(()) => self.refresh_backoff = None,
            Err(error) => {
                if let SnapshotError::Limit(limit) = error {
                    self.report_limit(Some(limit));
                } else {
                    tracing::trace!(%error, "failed to refresh GDB JIT registrations");
                }
                self.refresh_backoff = Some(RetryBackoff::next(self.refresh_backoff, poll));
            }
        }
    }

    /// Refresh only the registration whose unwind rules failed, at most once per second.
    /// Other registrations keep their identities until the next ordinary poll.
    pub fn refresh_for_address(&mut self, address: u64) -> bool {
        let now = Instant::now();
        if self
            .last_demand_refresh
            .is_some_and(|last| now.duration_since(last) < REVALIDATION_INTERVAL)
        {
            return false;
        }
        let Some(&(_, id)) = self
            .code_ranges
            .range(..=address)
            .next_back()
            .map(|(_, range)| range)
            .filter(|(end, _)| address < *end)
        else {
            self.last_demand_refresh = Some(now);
            return false;
        };
        let Some(object) = self.objects.get(&id) else {
            return false;
        };
        if self
            .load_failures
            .get(&id)
            .is_some_and(|failure| self.poll_count < failure.retry_at)
        {
            return false;
        }
        self.last_demand_refresh = Some(now);
        if matches!(object.unwind.cfi, CfiState::Absent) {
            return false;
        }
        let Ok(snapshot) = self.read_snapshot() else {
            return false;
        };
        if !snapshot
            .entries
            .get(&id.entry_addr)
            .is_some_and(|entry| JitObjectId::new(id.entry_addr, *entry) == id)
        {
            return false;
        }
        let mut scratch = Vec::new();
        let retained_cfi: u64 = self.objects.values().map(loaded_cfi_size).sum();
        let mut remaining_cfi =
            MAX_JIT_TOTAL_CFI_SIZE.saturating_sub(retained_cfi - loaded_cfi_size(object));
        let update = match object.inspect(&self.process, id, &mut scratch, &mut remaining_cfi) {
            Ok(ObjectChange::Unwind(update)) => update,
            Ok(ObjectChange::Image) => {
                // Keep this batch's identity; recheck it at the next ordinary poll.
                self.last_revalidation = None;
                return false;
            }
            Err(SnapshotError::Limit(limit)) => {
                if let Some(object) = self.objects.get_mut(&id) {
                    object.unwind.cfi.mark_budget_limited();
                }
                self.report_limit(Some(limit));
                return false;
            }
            _ => return false,
        };
        if !self
            .read_snapshot()
            .is_ok_and(|current| current == snapshot)
        {
            return false;
        }
        let Some(object) = self.objects.get_mut(&id) else {
            return false;
        };
        object.apply_unwind(update);
        self.load_failures.remove(&id);
        self.updates_pending = true;
        if self.limit_warned {
            let limit = self
                .objects
                .values()
                .find_map(|object| object.unwind.cfi.budget_limit());
            self.report_limit(limit);
        }
        true
    }

    /// Read and reconcile a stable snapshot across discovered registries.
    ///
    /// Each descriptor is read again after loading remote ELF buffers. A change
    /// between those reads discards the candidate updates because the target
    /// was allowed to run throughout the operation.
    fn refresh_objects(&mut self, poll: u64) -> Result<(), SnapshotError> {
        let snapshots = protocol::read_descriptors(&self.process, &self.descriptors)?;
        let revalidate = self
            .last_revalidation
            .is_none_or(|last| last.elapsed() >= REVALIDATION_INTERVAL);
        let retry_due = self
            .load_failures
            .values()
            .any(|failure| poll >= failure.retry_at);
        if snapshots == self.last_descriptors
            && !revalidate
            && !retry_due
            && !self.needs_reconciliation
        {
            return Ok(());
        }
        let JitSnapshot {
            descriptors: snapshots,
            entries,
        } = protocol::read_snapshot(&self.process, snapshots)?;
        let changed_notifications: HashSet<_> = snapshots
            .iter()
            .filter_map(|&(address, descriptor)| {
                (descriptor.action_flag != 0
                    && self
                        .last_descriptors
                        .iter()
                        .any(|&(old_address, old)| old_address == address && old != descriptor))
                .then_some(descriptor.relevant_entry)
            })
            .collect();
        let mut invalidated = HashSet::default();
        let mut unwind_updates = Vec::new();
        let mut failed_checks = Vec::new();
        let mut checked = Vec::new();
        // Account for the complete next snapshot, including unchanged objects.
        // Replacements receive their old allocation's credit; until publication,
        // the previous and candidate snapshots can each retain this bounded amount.
        let retained_cfi: u64 = self
            .objects
            .iter()
            .filter_map(|(id, object)| {
                if entries
                    .get(&id.entry_addr)
                    .is_some_and(|&entry| JitObjectId::new(id.entry_addr, entry) == *id)
                {
                    Some(loaded_cfi_size(object))
                } else {
                    None
                }
            })
            .sum();
        let mut remaining_cfi = MAX_JIT_TOTAL_CFI_SIZE.saturating_sub(retained_cfi);
        // Reuse allocations within this refresh without retaining the largest image.
        let mut scratch = Vec::new();
        for (&id, object) in &self.objects {
            if !entries
                .get(&id.entry_addr)
                .is_some_and(|&entry| JitObjectId::new(id.entry_addr, entry) == id)
            {
                continue;
            }
            if changed_notifications.contains(&id.entry_addr) {
                invalidated.insert(id);
                remaining_cfi += loaded_cfi_size(object);
                continue;
            }
            let failure = self.load_failures.get(&id);
            if failure.is_some_and(|failure| poll < failure.retry_at)
                || (!revalidate && failure.is_none())
            {
                continue;
            }
            let before_check = remaining_cfi;
            remaining_cfi += loaded_cfi_size(object);
            match object.inspect(&self.process, id, &mut scratch, &mut remaining_cfi) {
                Ok(ObjectChange::Image) => {
                    invalidated.insert(id);
                    continue;
                }
                Ok(ObjectChange::Unwind(update)) => unwind_updates.push((id, update)),
                Ok(ObjectChange::Unchanged) => remaining_cfi = before_check,
                Err(error) => {
                    remaining_cfi = before_check;
                    tracing::trace!(error = %error, "failed to revalidate registered JIT object");
                    failed_checks.push((id, matches!(error, SnapshotError::Limit(_))));
                    continue;
                }
            }
            if failure.is_some() {
                checked.push(id);
            }
        }
        let mut pending: Vec<_> = entries
            .iter()
            .filter_map(|(&entry_addr, &entry)| {
                let id = JitObjectId::new(entry_addr, entry);
                ((!self.objects.contains_key(&id) || invalidated.contains(&id))
                    && !self
                        .load_failures
                        .get(&id)
                        .is_some_and(|failure| poll < failure.retry_at))
                .then_some(id)
            })
            .collect();
        // Budget admission and overlap resolution use the same stable order.
        pending.sort_unstable_by_key(|id| (id.entry_addr, id.symfile_addr, id.symfile_size));
        let updates: Vec<_> = pending
            .into_iter()
            .map(|id| (id, JitObject::load(&self.process, id, &mut remaining_cfi)))
            .collect();

        // The target keeps running while the remote ELF data is read. Do not
        // publish anything if a registration event raced with those reads.
        let current = self.read_snapshot()?;
        if current.descriptors != snapshots || current.entries != entries {
            self.needs_reconciliation = true;
            return Ok(());
        }
        self.needs_reconciliation = false;
        self.last_descriptors = snapshots;
        if revalidate {
            self.last_revalidation = Some(Instant::now());
        }

        let is_active = |id: &JitObjectId| {
            entries
                .get(&id.entry_addr)
                .is_some_and(|&entry| JitObjectId::new(id.entry_addr, entry) == *id)
        };
        let stale_paths = &mut self.stale_paths;
        let updates_pending = &mut self.updates_pending;
        let code_ranges = &mut self.code_ranges;
        self.objects.retain(|id, object| {
            let active = is_active(id) && !invalidated.contains(id);
            if !active {
                stale_paths.insert(id.path());
                for range in &object.code_ranges {
                    code_ranges.remove(&range.start);
                }
                *updates_pending = true;
            }
            active
        });
        self.load_failures.retain(|id, _| is_active(id));
        for id in checked {
            self.load_failures.remove(&id);
        }
        for (id, budget_limited) in failed_checks {
            if budget_limited {
                if let Some(object) = self.objects.get_mut(&id) {
                    object.unwind.cfi.mark_budget_limited();
                }
            }
            let failure = RetryBackoff::next(self.load_failures.get(&id).copied(), poll);
            self.load_failures.insert(id, failure);
        }
        for (id, update) in unwind_updates {
            if let Some(object) = self.objects.get_mut(&id) {
                object.apply_unwind(update);
                self.updates_pending = true;
            }
        }
        for (id, update) in updates {
            match update {
                Ok(object) => {
                    if object.code_ranges.iter().any(|range| {
                        self.code_ranges
                            .range(..range.end)
                            .next_back()
                            .is_some_and(|(_, (end, _))| *end > range.start)
                    }) {
                        self.load_failures.insert(
                            id,
                            RetryBackoff::next(self.load_failures.get(&id).copied(), poll),
                        );
                        continue;
                    }
                    for range in &object.code_ranges {
                        self.code_ranges.insert(range.start, (range.end, id));
                    }
                    self.objects.insert(id, object);
                    self.updates_pending = true;
                    self.load_failures.remove(&id);
                }
                Err(error) => {
                    tracing::trace!(
                            entry = format_args!("0x{:x}", id.entry_addr),
                        error = %error,
                        "failed to load registered JIT object"
                    );
                    let failure = RetryBackoff::next(self.load_failures.get(&id).copied(), poll);
                    self.load_failures.insert(id, failure);
                }
            }
        }
        let limit = self
            .objects
            .values()
            .find_map(|object| object.unwind.cfi.budget_limit());
        self.report_limit(limit);
        Ok(())
    }

    fn report_limit(&mut self, limit: Option<&'static str>) {
        if let Some(limit) = limit {
            if !self.limit_warned {
                tracing::warn!(
                    pid = self.process.pid(),
                    limit,
                    "JIT coverage is incomplete; retaining available metadata and retrying"
                );
            }
        }
        self.limit_warned = limit.is_some();
    }

    /// Read a bounded registry snapshot for validation around metadata reads.
    fn read_snapshot(&self) -> Result<JitSnapshot, SnapshotError> {
        let descriptors = protocol::read_descriptors(&self.process, &self.descriptors)?;
        protocol::read_snapshot(&self.process, descriptors)
    }

    /// Retire all registered objects while preserving removals for publication.
    fn clear_objects(&mut self) {
        self.updates_pending |= !self.objects.is_empty();
        self.stale_paths
            .extend(self.objects.keys().map(|id| id.path()));
        self.objects.clear();
        self.code_ranges.clear();
        self.limit_warned = false;
        self.load_failures.clear();
    }

    /// Update descriptors, retaining loaded owners after a transient miss.
    fn update_descriptors(
        &mut self,
        mut locations: Vec<JitDescriptorLocation>,
        modules: &[impl Mapping],
    ) {
        let executable = PathBuf::from(format!("/proc/{}/exe", self.process.pid()));
        for old in &self.descriptors {
            if !locations
                .iter()
                .any(|location| location.address == old.address)
                && (old.owner == executable
                    || modules.iter().any(|module| {
                        module.path() == old.owner
                            && module.file_identity() == old.owner_identity
                            && module.range().contains(&old.address)
                            && old.owner_file_offset.is_some_and(|offset| {
                                module
                                    .file_offset()
                                    .checked_add(old.address - module.range().start)
                                    == Some(offset)
                            })
                    }))
            {
                // Keep a loaded owner's registry if its file could not be read this time.
                self.descriptor_search_generation = None;
                locations.push(old.clone());
            }
        }
        locations.sort_unstable_by_key(|location| location.address);
        locations.dedup_by_key(|location| location.address);
        self.needs_reconciliation |= self.descriptors != locations;
        self.descriptors = locations;
        self.refresh_backoff = None;
        if self.descriptors.is_empty() {
            self.clear_objects();
        }
    }
}

fn loaded_cfi_size<D>(object: &JitObject<D>) -> u64 {
    match &object.unwind.cfi {
        CfiState::Loaded { range, .. } => range.end - range.start,
        CfiState::Absent | CfiState::Unreadable { .. } | CfiState::BudgetLimited { .. } => 0,
    }
}

fn jit_error(operation: &'static str, detail: String) -> io::Error {
    io::Error::other(format!("{operation}: {detail}"))
}

#[cfg(test)]
mod tests;
