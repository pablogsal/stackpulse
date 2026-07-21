use std::io::{self, Write};

use rustc_hash::{FxHashMap, FxHashSet};

use super::{next_spool_id, FrameMode, FrameRecord, ModulePath, ModuleRecord, PerfSpoolWriter};

#[derive(Clone, PartialEq, Eq, Hash)]
struct ModuleIdentity {
    process_id: i32,
    start: u64,
    end: u64,
    file_offset: u64,
    inode: u64,
    device_major: u32,
    device_minor: u32,
    inode_generation: u64,
    path: ModulePath,
    is_kernel: bool,
}

impl From<&ModuleRecord> for ModuleIdentity {
    fn from(module: &ModuleRecord) -> Self {
        Self {
            process_id: module.process_id,
            start: module.start,
            end: module.end,
            file_offset: module.file_offset,
            inode: module.inode,
            device_major: module.device_major,
            device_minor: module.device_minor,
            inode_generation: module.inode_generation,
            path: module.path.clone(),
            is_kernel: module.is_kernel,
        }
    }
}

struct ModuleSlot {
    module: ModuleRecord,
    active: bool,
}

#[derive(Default)]
pub(crate) struct ModuleTable {
    slots: Vec<ModuleSlot>,
    active_by_key: FxHashMap<ModuleIdentity, u32>,
    index: ModuleIndex,
    index_dirty: bool,
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

impl ModuleTable {
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
            .slots
            .iter()
            .filter(|slot| {
                slot.active && !slot.module.is_kernel && slot.module.process_id == process_id
            })
            .count();
        let matched: FxHashSet<_> = snapshot
            .iter()
            .filter_map(|module| self.find_compatible_active(module))
            .collect();
        active_count == snapshot.len() && matched.len() == snapshot.len()
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
                    module: self.slots[id as usize].module.clone(),
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
        if !module.is_kernel {
            let overlapping: Vec<_> = self
                .slots
                .iter()
                .filter(|slot| {
                    slot.active
                        && !slot.module.is_kernel
                        && slot.module.process_id == module.process_id
                        && module_ranges_overlap(&slot.module, &module)
                })
                .map(|slot| (slot.module.id, slot.module.clone()))
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
                    let slot = &mut self.slots[id as usize];
                    debug_assert!(slot.active);
                    slot.active = false;
                    self.active_by_key.remove(&ModuleIdentity::from(&known));
                    writer.write_module_deactivation_one(id)?;
                    update.retired.push(known);
                }
                self.index_dirty = true;
                for (source_id, survivor) in survivors {
                    let id = self.intern_without_overlap(survivor, writer)?;
                    update.active.push(ModuleActivation {
                        module: self.slots[id as usize].module.clone(),
                        source_module_id: Some(source_id),
                    });
                }
            }
        }

        let id = self.intern_without_overlap(module, writer)?;
        update.active.push(ModuleActivation {
            module: self.slots[id as usize].module.clone(),
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
            self.slots
                .iter()
                .find(|slot| {
                    slot.active
                        && slot.module.inode_generation != 0
                        && same_mapping_except_inode_generation(&slot.module, module)
                })
                .map(|slot| slot.module.id)
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
        let id = next_spool_id(self.slots.len(), "module")?;
        module.id = id;
        writer.write_module(&module)?;
        self.active_by_key.insert(key, id);
        self.slots.push(ModuleSlot {
            module,
            active: true,
        });
        self.index_dirty = true;
        Ok(id)
    }

    pub(crate) fn deactivate_process_modules<W: Write>(
        &mut self,
        process_id: i32,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<()> {
        let mut changed = false;
        for slot in &mut self.slots {
            if slot.module.process_id == process_id && !slot.module.is_kernel && slot.active {
                changed = true;
                slot.active = false;
                self.active_by_key
                    .remove(&ModuleIdentity::from(&slot.module));
            }
        }
        self.index_dirty |= changed;
        if changed {
            writer.write_module_deactivation(process_id)?;
        }
        Ok(())
    }

    pub(crate) fn clone_process_modules<W: Write>(
        &mut self,
        parent_process_id: i32,
        child_process_id: i32,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<Vec<ModuleUpdate>> {
        let inherited: Vec<_> = self
            .slots
            .iter()
            .filter(|slot| {
                slot.active && slot.module.process_id == parent_process_id && !slot.module.is_kernel
            })
            .map(|slot| {
                (
                    slot.module.id,
                    ModuleRecord {
                        id: 0,
                        process_id: child_process_id,
                        ..slot.module.clone()
                    },
                )
            })
            .collect();
        let mut updates = Vec::with_capacity(inherited.len());
        for (source_id, inherited) in inherited {
            let mut update = self.apply_module(inherited, writer)?;
            if let Some(activation) = update.active.last_mut() {
                activation.source_module_id = Some(source_id);
            }
            updates.push(update);
        }
        Ok(updates)
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
            .and_then(|id| self.slots.get(id as usize).map(|slot| (id, &slot.module)));
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
            self.index = ModuleIndex::build(&self.slots);
            self.index_dirty = false;
        }
    }
}

fn module_ranges_overlap(left: &ModuleRecord, right: &ModuleRecord) -> bool {
    left.start < right.end && right.start < left.end
}

fn same_mapping_except_inode_generation(left: &ModuleRecord, right: &ModuleRecord) -> bool {
    left.process_id == right.process_id
        && left.start == right.start
        && left.end == right.end
        && left.file_offset == right.file_offset
        && left.inode == right.inode
        && left.device_major == right.device_major
        && left.device_minor == right.device_minor
        && left.path == right.path
        && left.is_kernel == right.is_kernel
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
    fn build(slots: &[ModuleSlot]) -> Self {
        let mut index = Self::default();
        for slot in slots.iter().filter(|slot| slot.active) {
            let module = &slot.module;
            let entry = ModuleIndexEntry {
                start: module.start,
                end: module.end,
                id: module.id,
            };
            if module.is_kernel {
                index.kernel.push(entry);
            } else {
                index
                    .by_process
                    .entry(module.process_id)
                    .or_default()
                    .push(entry);
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
