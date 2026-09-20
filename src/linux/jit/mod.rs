//! Persist shared runtime registrations and pin sampled frames to their recorded identity.

use super::unwind::NativeUnwinder;
use crate::elf::ElfSectionData;
use crate::jit::{FileIdentity, Mapping, MemoryReader, Registry, Update};
use crate::spool::{FrameMode, FrameRecord, ModuleRecord, ModuleTable, PerfSpoolWriter};
use rustc_hash::FxHashSet;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct ProcessMemory {
    pid: i32,
    file: RefCell<Option<File>>,
}

impl MemoryReader for ProcessMemory {
    fn pid(&self) -> i32 {
        self.pid
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> io::Result<()> {
        let mut file = self.file.borrow_mut();
        let file = match *file {
            Some(ref file) => file,
            None => file.insert(File::open(format!("/proc/{}/mem", self.pid))?),
        };
        file.read_exact_at(bytes, address)
    }
}

#[derive(PartialEq, Eq)]
struct ProcessMapping {
    range: Range<u64>,
    path: PathBuf,
    offset: u64,
    executable: bool,
    deleted: bool,
    identity: FileIdentity,
}

impl Mapping for ProcessMapping {
    fn range(&self) -> Range<u64> {
        self.range.clone()
    }
    fn path(&self) -> &Path {
        &self.path
    }
    fn file_offset(&self) -> u64 {
        self.offset
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn deleted(&self) -> bool {
        self.deleted
    }
    fn file_identity(&self) -> Option<FileIdentity> {
        Some(self.identity)
    }
}

struct CodeRange {
    end: u64,
    module_id: u32,
    path: Arc<Path>,
}

#[derive(Default)]
pub(super) struct JitRegistry {
    registry: Option<Registry<ProcessMemory, ElfSectionData>>,
    mappings: Vec<ProcessMapping>,
    generation: u64,
    mappings_changed: bool,
    maps_retry_at: Option<Instant>,
    last_maps_read: Option<Instant>,
    code_ranges: BTreeMap<u64, CodeRange>,
}

impl JitRegistry {
    pub(super) fn mappings_changed(&mut self) {
        self.mappings_changed = true;
    }

    pub(super) fn frame(&self, address: u64) -> Option<FrameRecord> {
        let (&start, range) = self.code_ranges.range(..=address).next_back()?;
        (address < range.end).then_some(FrameRecord {
            module_id: Some(range.module_id),
            file_relative_ip: address - start,
            abs_ip: address,
            mode: FrameMode::User,
        })
    }

    pub(super) fn refresh<W: io::Write>(
        &mut self,
        pid: i32,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<()> {
        // Perf reports new mappings, but an unloaded descriptor owner can disappear
        // without another mapping event. Confirmed absence needs only event checks.
        let reconcile = self
            .registry
            .as_ref()
            .is_none_or(|registry| !registry.is_absent())
            && self
                .last_maps_read
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(1));
        if (reconcile || self.mappings_changed)
            && self
                .maps_retry_at
                .is_none_or(|retry| Instant::now() >= retry)
        {
            self.last_maps_read = Some(Instant::now());
            match std::fs::read(format!("/proc/{pid}/maps")) {
                Ok(maps) => {
                    let mappings = crate::proc_maps::parse_iter(&maps)
                        .filter(|region| region.inode != 0)
                        .map(|region| {
                            let bytes = region.path.as_os_str().as_bytes();
                            let linked = bytes.strip_suffix(b" (deleted)");
                            ProcessMapping {
                                range: region.address,
                                path: Path::new(OsStr::from_bytes(linked.unwrap_or(bytes))).into(),
                                offset: region.file_offset,
                                executable: region.is_executable,
                                deleted: linked.is_some(),
                                identity: FileIdentity {
                                    inode: region.inode,
                                    device: libc::makedev(region.device_major, region.device_minor),
                                },
                            }
                        })
                        .collect::<Vec<_>>();
                    if self.mappings != mappings {
                        self.mappings = mappings;
                        self.generation = self.generation.wrapping_add(1);
                    }
                    self.mappings_changed = false;
                    self.maps_retry_at = None;
                    self.registry.get_or_insert_with(|| {
                        Registry::new(ProcessMemory {
                            pid,
                            file: RefCell::new(None),
                        })
                    });
                }
                Err(_) => self.maps_retry_at = Some(Instant::now() + Duration::from_secs(1)),
            }
        }
        if let Some(registry) = &mut self.registry {
            registry.refresh(self.generation, &self.mappings);
        }
        self.apply_updates(pid, unwinder, modules, writer)
    }

    pub(super) fn refresh_for_frame<W: io::Write>(
        &mut self,
        address: u64,
        pid: i32,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<bool> {
        if self.frame(address).is_none() {
            return Ok(false);
        }
        let changed = self
            .registry
            .as_mut()
            .is_some_and(|registry| registry.refresh_for_address(address));
        self.apply_updates(pid, unwinder, modules, writer)?;
        Ok(changed)
    }

    fn apply_updates<W: io::Write>(
        &mut self,
        pid: i32,
        unwinder: &mut NativeUnwinder,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> io::Result<()> {
        let Some(registry) = &mut self.registry else {
            return Ok(());
        };
        let mut result = Ok(());
        let mut retired = FxHashSet::default();
        registry.drain_updates(|update| {
            if result.is_ok() {
                result = apply_update(
                    &mut self.code_ranges,
                    &mut retired,
                    update,
                    pid,
                    unwinder,
                    modules,
                    writer,
                );
            }
        });
        retire_ranges(&mut self.code_ranges, &mut retired, unwinder);
        result
    }
}

fn apply_update<W: io::Write>(
    code_ranges: &mut BTreeMap<u64, CodeRange>,
    retired: &mut FxHashSet<PathBuf>,
    update: Update<ElfSectionData>,
    pid: i32,
    unwinder: &mut NativeUnwinder,
    modules: &mut ModuleTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<()> {
    match update {
        Update::Removed { path } => {
            retired.insert(path);
        }
        Update::Loaded {
            path,
            modules: unwind,
            symbols,
        } => {
            retire_ranges(code_ranges, retired, unwinder);
            if let Some(symbols) = symbols {
                let path: Arc<Path> = path.into();
                let pid = crate::Pid::try_from(pid).map_err(crate::Error::from)?;
                for module in unwind.iter() {
                    let range = module.avma_range();
                    let mut recorded = ModuleRecord::new(0, pid, range.clone(), 0, &path)?;
                    recorded.jit_symbols = Some(
                        symbols
                            .iter()
                            .filter_map(|symbol| {
                                let name = symbol.name.as_ref()?;
                                range.contains(&symbol.range.start).then(|| {
                                    crate::spool::model::JitSymbol {
                                        start: symbol.range.start,
                                        end: symbol.range.end,
                                        name: name.as_str().into(),
                                    }
                                })
                            })
                            .collect(),
                    );
                    modules.record_pinned_module(&mut recorded, writer)?;
                    code_ranges.insert(
                        range.start,
                        CodeRange {
                            end: range.end,
                            module_id: recorded.id,
                            path: Arc::clone(&path),
                        },
                    );
                }
            }
            for module in unwind {
                unwinder.add_jit_module(module);
            }
        }
    }
    Ok(())
}

fn retire_ranges(
    code_ranges: &mut BTreeMap<u64, CodeRange>,
    retired: &mut FxHashSet<PathBuf>,
    unwinder: &mut NativeUnwinder,
) {
    if retired.is_empty() {
        return;
    }
    code_ranges.retain(|&start, range| {
        if retired.contains(range.path.as_ref()) {
            unwinder.remove_jit_module(start);
            false
        } else {
            true
        }
    });
    retired.clear();
}

#[cfg(test)]
mod tests;

#[cfg(test)]
impl JitRegistry {
    pub(in crate::linux) fn test_with_module(
        module: ModuleRecord,
        unwind: framehop::Module<ElfSectionData>,
        unwinder: &mut NativeUnwinder,
    ) -> Self {
        let mut registry = Self::default();
        registry.code_ranges.insert(
            module.start,
            CodeRange {
                end: module.end,
                module_id: module.id,
                path: module.path.to_path_buf().into(),
            },
        );
        unwinder.add_jit_module(unwind);
        registry
    }
}
