use std::collections::BTreeSet;
use std::io::{self, Write};
use std::ops::Bound::{Excluded, Unbounded};

use rustc_hash::{FxHashMap, FxHashSet};

use super::{
    next_spool_id, FrameMode, FrameRecord, ModuleOwner, ModulePath, ModuleRecord, PerfSpoolWriter,
};

#[derive(Clone, PartialEq, Eq, Hash)]
struct ModuleIdentity {
    owner: ModuleOwner,
    start: u64,
    end: u64,
    file_offset: u64,
    inode: u64,
    device_major: u32,
    device_minor: u32,
    inode_generation: u64,
    path: ModulePath,
}

impl From<&ModuleRecord> for ModuleIdentity {
    fn from(module: &ModuleRecord) -> Self {
        Self {
            owner: module.owner,
            start: module.start,
            end: module.end,
            file_offset: module.file_offset,
            inode: module.inode,
            device_major: module.device_major,
            device_minor: module.device_minor,
            inode_generation: module.inode_generation,
            path: module.path.clone(),
        }
    }
}

#[derive(Default)]
pub(crate) struct ModuleTable {
    active: FxHashMap<u32, ModuleRecord>,
    next_id: usize,
    active_by_key: FxHashMap<ModuleIdentity, u32>,
    active_by_process: FxHashMap<i32, ProcessModules>,
    index: ModuleIndex,
    index_dirty: bool,
}

#[derive(Default)]
struct ProcessModules {
    by_start: BTreeSet<(u64, u32)>,
}

impl ProcessModules {
    fn insert(&mut self, module: &ModuleRecord) {
        self.by_start.insert((module.start, module.id));
    }

    fn remove(&mut self, module: &ModuleRecord) {
        self.by_start.remove(&(module.start, module.id));
    }

    fn len(&self) -> usize {
        self.by_start.len()
    }

    fn is_empty(&self) -> bool {
        self.by_start.is_empty()
    }
}

#[derive(Default)]
pub(crate) struct ModuleUpdate {
    pub(crate) retired: Vec<ModuleRecord>,
    pub(crate) active: Vec<ModuleActivation>,
    pub(crate) mapping_changed: bool,
}

pub(crate) struct ModuleActivation {
    pub(crate) module: ModuleRecord,
    pub(crate) source_module_id: Option<u32>,
}

pub(crate) struct ClonedProcessModules {
    pub(crate) update: ModuleUpdate,
    pub(crate) inherited_unwinder_layout: bool,
}

impl ModuleTable {
    #[cfg(test)]
    pub(crate) fn active_module_count(&self) -> usize {
        self.active.len()
    }

    #[cfg(test)]
    pub(crate) fn intern_module<W: Write>(
        &mut self,
        module: ModuleRecord,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<u32> {
        Ok(self
            .apply_module(module, writer)?
            .active
            .last()
            .map_or(u32::MAX, |activation| activation.module.id))
    }

    pub(crate) fn process_modules_match(&self, process_id: i32, snapshot: &[ModuleRecord]) -> bool {
        let active_count = self
            .active_by_process
            .get(&process_id)
            .map_or(0, ProcessModules::len);
        if active_count != snapshot.len() {
            return false;
        }
        let matched: FxHashSet<_> = snapshot
            .iter()
            .filter_map(|module| self.find_compatible_active(module))
            .collect();
        matched.len() == snapshot.len()
    }

    pub(crate) fn apply_module<W: Write>(
        &mut self,
        module: ModuleRecord,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<ModuleUpdate> {
        if module.end <= module.start {
            return Ok(ModuleUpdate::default());
        }
        if let Some(id) = self.find_compatible_active(&module) {
            return Ok(ModuleUpdate {
                active: vec![ModuleActivation {
                    module: self.active[&id].clone(),
                    source_module_id: None,
                }],
                ..ModuleUpdate::default()
            });
        }

        let mut update = ModuleUpdate {
            mapping_changed: true,
            ..ModuleUpdate::default()
        };

        // A mapping is a generation. MAP_FIXED can replace only part of an
        // existing VMA, so retire every overlap and preserve its unaffected
        // fragments before activating the replacement.
        if let Some(module_pid) = module.pid() {
            let overlapping: Vec<_> = self
                .overlapping_module_ids(module_pid.get(), &module)
                .into_iter()
                .filter_map(|id| {
                    let known = &self.active[&id];
                    module_ranges_overlap(known, &module).then(|| (id, known.clone()))
                })
                .collect();
            if !overlapping.is_empty() {
                let survivors: Vec<_> = overlapping
                    .iter()
                    .flat_map(|(id, known)| {
                        split_module_around(known, &module)
                            .into_iter()
                            .map(|module| (*id, module))
                    })
                    .collect();
                for (id, known) in overlapping {
                    let removed = self.active.remove(&id);
                    debug_assert!(removed.is_some());
                    self.active_by_key.remove(&ModuleIdentity::from(&known));
                    self.remove_process_active(&known);
                    writer.write_module_deactivation_one(id)?;
                    update.retired.push(known);
                }
                self.index_dirty = true;
                for (source_id, survivor) in survivors {
                    let id = self.intern_without_overlap(survivor, writer)?;
                    update.active.push(ModuleActivation {
                        module: self.active[&id].clone(),
                        source_module_id: Some(source_id),
                    });
                }
            }
        }

        let id = self.intern_without_overlap(module, writer)?;
        update.active.push(ModuleActivation {
            module: self.active[&id].clone(),
            source_module_id: None,
        });
        Ok(update)
    }

    fn find_compatible_active(&self, module: &ModuleRecord) -> Option<u32> {
        let key = ModuleIdentity::from(module);
        self.active_by_key.get(&key).copied().or_else(|| {
            if module.inode_generation != 0 {
                return None;
            }
            if let Some(pid) = module.pid() {
                return self
                    .active_by_process
                    .get(&pid.get())?
                    .by_start
                    .range((module.start, 0)..=(module.start, u32::MAX))
                    .map(|(_, id)| *id)
                    .find(|id| {
                        let known = &self.active[id];
                        known.inode_generation != 0
                            && same_mapping_except_inode_generation(known, module)
                    });
            }
            self.active
                .iter()
                .filter(|(_, known)| {
                    known.inode_generation != 0
                        && same_mapping_except_inode_generation(known, module)
                })
                .map(|(&id, _)| id)
                .min()
        })
    }

    fn intern_without_overlap<W: Write>(
        &mut self,
        mut module: ModuleRecord,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<u32> {
        let key = ModuleIdentity::from(&module);
        if let Some(&id) = self.active_by_key.get(&key) {
            return Ok(id);
        }
        let id = next_spool_id(self.next_id, "module")?;
        module.id = id;
        writer.write_module(&module)?;
        self.next_id += 1;
        self.active_by_key.insert(key, id);
        if let Some(pid) = module.pid() {
            self.active_by_process
                .entry(pid.get())
                .or_default()
                .insert(&module);
        }
        self.active.insert(id, module);
        self.index_dirty = true;
        Ok(id)
    }

    pub(crate) fn deactivate_process_modules<W: Write>(
        &mut self,
        process_id: i32,
        writer: &mut PerfSpoolWriter<W>,
        mut retire: impl FnMut(u32),
    ) -> io::Result<()> {
        let Some(active_ids) = self.active_by_process.remove(&process_id) else {
            return Ok(());
        };
        for &(_, id) in &active_ids.by_start {
            let module = self.active.remove(&id).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "active process module index was inconsistent",
                )
            })?;
            self.active_by_key.remove(&ModuleIdentity::from(&module));
        }
        self.index_dirty = true;
        writer.write_module_deactivation(process_id)?;
        for (_, id) in active_ids.by_start {
            retire(id);
        }
        Ok(())
    }

    pub(crate) fn process_module_ids(&self, process_id: i32) -> Vec<u32> {
        self.active_by_process
            .get(&process_id)
            .map(|modules| modules.by_start.iter().map(|(_, id)| *id).collect())
            .unwrap_or_default()
    }

    fn overlapping_module_ids(&self, process_id: i32, module: &ModuleRecord) -> Vec<u32> {
        let Some(modules) = self.active_by_process.get(&process_id) else {
            return Vec::new();
        };
        let mut overlapping = Vec::new();
        if let Some(&(_, id)) = modules
            .by_start
            .range(..=(module.start, u32::MAX))
            .next_back()
        {
            if self.active[&id].end > module.start {
                overlapping.push(id);
            }
        }
        overlapping.extend(
            modules
                .by_start
                .range((Excluded((module.start, u32::MAX)), Unbounded))
                .take_while(|(start, _)| *start < module.end)
                .map(|(_, id)| *id),
        );
        overlapping
    }

    pub(crate) fn clone_process_modules<W: Write>(
        &mut self,
        parent_process_id: i32,
        child_process_id: i32,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<ClonedProcessModules> {
        let child_pid = crate::Pid::try_from(child_process_id)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let source_ids = self.process_module_ids(parent_process_id);
        let mut combined = ModuleUpdate {
            active: Vec::with_capacity(source_ids.len()),
            ..ModuleUpdate::default()
        };
        let child_has_modules = self.active_by_process.contains_key(&child_process_id);
        for source_id in source_ids {
            let inherited = ModuleRecord {
                id: 0,
                owner: ModuleOwner::Process(child_pid),
                ..self.active[&source_id].clone()
            };
            if child_has_modules {
                let mut update = self.apply_module(inherited, writer)?;
                let activation = update.active.last_mut().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "inherited module produced no activation",
                    )
                })?;
                activation.source_module_id = Some(source_id);
                combined.mapping_changed |= update.mapping_changed;
                combined.retired.extend(update.retired);
                combined.active.extend(update.active);
            } else {
                let id = self.intern_without_overlap(inherited, writer)?;
                combined.active.push(ModuleActivation {
                    module: self.active[&id].clone(),
                    source_module_id: Some(source_id),
                });
                combined.mapping_changed = true;
            }
        }
        Ok(ClonedProcessModules {
            update: combined,
            inherited_unwinder_layout: !child_has_modules,
        })
    }

    pub(crate) fn resolve_frame(
        &mut self,
        process_id: i32,
        abs_ip: u64,
        mode: FrameMode,
    ) -> FrameRecord {
        self.rebuild_index_if_needed();
        let module = self
            .index
            .find(process_id, abs_ip, mode)
            .and_then(|id| self.active.get(&id).map(|module| (id, module)));
        let (module_id, file_relative_ip) = module
            .and_then(|(id, module)| {
                abs_ip
                    .checked_sub(module.start)?
                    .checked_add(module.file_offset)
                    .map(|file_relative_ip| (Some(id), file_relative_ip))
            })
            .unwrap_or((None, abs_ip));
        FrameRecord {
            module_id,
            file_relative_ip,
            abs_ip,
            mode,
        }
    }

    pub(crate) fn covers_user_pc(&mut self, process_id: i32, address: u64) -> bool {
        self.rebuild_index_if_needed();
        self.index
            .find(process_id, address, FrameMode::User)
            .is_some()
    }

    fn rebuild_index_if_needed(&mut self) {
        if self.index_dirty {
            let mut active_ids: Vec<_> = self.active.keys().copied().collect();
            active_ids.sort_unstable();
            self.index = ModuleIndex::build(&self.active, active_ids.into_iter());
            self.index_dirty = false;
        }
    }

    fn remove_process_active(&mut self, module: &ModuleRecord) {
        let Some(pid) = module.pid() else {
            return;
        };
        let pid = pid.get();
        if let Some(ids) = self.active_by_process.get_mut(&pid) {
            ids.remove(module);
            if ids.is_empty() {
                self.active_by_process.remove(&pid);
            }
        }
    }
}

fn module_ranges_overlap(left: &ModuleRecord, right: &ModuleRecord) -> bool {
    left.start < right.end && right.start < left.end
}

fn same_mapping_except_inode_generation(left: &ModuleRecord, right: &ModuleRecord) -> bool {
    left.owner == right.owner
        && left.start == right.start
        && left.end == right.end
        && left.file_offset == right.file_offset
        && left.inode == right.inode
        && left.device_major == right.device_major
        && left.device_minor == right.device_minor
        && left.path == right.path
}

fn split_module_around(old: &ModuleRecord, replacement: &ModuleRecord) -> Vec<ModuleRecord> {
    let mut fragments = Vec::with_capacity(2);
    if old.start < replacement.start {
        fragments.push(ModuleRecord {
            id: 0,
            end: replacement.start.min(old.end),
            ..old.clone()
        });
    }
    if replacement.end < old.end {
        let start = replacement.end.max(old.start);
        fragments.push(ModuleRecord {
            id: 0,
            start,
            file_offset: old.file_offset.saturating_add(start - old.start),
            ..old.clone()
        });
    }
    fragments
}

#[derive(Default)]
struct ModuleIndex {
    by_process: FxHashMap<i32, ModuleIndexGroup>,
    kernel: ModuleIndexGroup,
}

impl ModuleIndex {
    fn build(active: &FxHashMap<u32, ModuleRecord>, active_ids: impl Iterator<Item = u32>) -> Self {
        let mut index = Self::default();
        for id in active_ids {
            let module = &active[&id];
            let entry = ModuleIndexEntry {
                start: module.start,
                end: module.end,
                id: module.id,
            };
            match module.owner {
                ModuleOwner::Kernel => index.kernel.push(entry),
                ModuleOwner::Process(pid) => {
                    index.by_process.entry(pid.get()).or_default().push(entry);
                }
            }
        }
        index.kernel.finish();
        for group in index.by_process.values_mut() {
            group.finish();
        }
        index
    }

    fn find(&self, process_id: i32, address: u64, mode: FrameMode) -> Option<u32> {
        match mode {
            FrameMode::User => self
                .by_process
                .get(&process_id)
                .and_then(|group| group.find(address)),
            FrameMode::Kernel => self.kernel.find(address),
            FrameMode::TruncatedStackMarker => None,
        }
    }
}

#[derive(Default)]
struct ModuleIndexGroup {
    entries: Vec<ModuleIndexEntry>,
    has_overlaps: bool,
}

impl ModuleIndexGroup {
    fn push(&mut self, entry: ModuleIndexEntry) {
        self.entries.push(entry);
    }

    fn finish(&mut self) {
        let mut sorted = self.entries.clone();
        sorted.sort_by_key(|entry| (entry.start, entry.id));
        self.has_overlaps = sorted
            .windows(2)
            .any(|window| window[0].end > window[1].start);
        if !self.has_overlaps {
            self.entries = sorted;
        }
    }

    fn find(&self, address: u64) -> Option<u32> {
        if self.has_overlaps {
            return self
                .entries
                .iter()
                .rfind(|entry| entry.start <= address && address < entry.end)
                .map(|entry| entry.id);
        }
        let idx = self.entries.partition_point(|entry| entry.start <= address);
        let entry = self.entries.get(idx.checked_sub(1)?)?;
        (address < entry.end).then_some(entry.id)
    }
}

#[derive(Clone, Copy)]
struct ModuleIndexEntry {
    start: u64,
    end: u64,
    id: u32,
}
