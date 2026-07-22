use std::fs::File;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::elf::{
    load_elf_sections_from_bytes, load_elf_sections_from_file, resolve_mapping_image_base,
    ElfSectionInfo,
};
use crate::ModuleImageBase;
use rustc_hash::FxHashMap;

use crate::spool::{ModuleRecord, VDSO_PATH};

#[derive(Clone, Default)]
pub(crate) struct ElfSectionCache {
    // Module ids are unique within a spool. Keying by id avoids reusing ELF
    // data across processes or mapping generations that happen to report the
    // same pathname and inode number in different mount namespaces.
    by_module: FxHashMap<u32, Arc<ElfSectionInfo>>,
}

pub(crate) struct LoadedElfMapping {
    pub(crate) image_base: Option<ModuleImageBase>,
    pub(crate) sections: Arc<ElfSectionInfo>,
}

impl ElfSectionCache {
    pub(crate) fn insert(&mut self, module_id: u32, sections: Arc<ElfSectionInfo>) {
        self.by_module.insert(module_id, sections);
    }

    pub(crate) fn load_mapping(&mut self, module: &ModuleRecord) -> Option<LoadedElfMapping> {
        if module.is_kernel
            || module.path.is_empty()
            || (module.path.is_bracketed_mapping() && !module.path.is_vdso())
        {
            return None;
        }

        let section_info = match self.by_module.entry(module.id) {
            std::collections::hash_map::Entry::Occupied(entry) => Arc::clone(entry.get()),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let section_info = Arc::new(if module.path.is_vdso() {
                    let bytes = local_vdso_bytes()?;
                    load_elf_sections_from_bytes(bytes, module.path.as_path()).ok()?
                } else {
                    let file = open_module_file(module)?;
                    let source_path = module.path.symbol_source().map_or_else(
                        || module.path.as_path(),
                        |source| std::path::Path::new(source.path.as_ref()),
                    );
                    let sections = load_elf_sections_from_file(&file, source_path).ok()?;
                    if let Some(source) = module.path.symbol_source() {
                        if !symbol_source_matches_file(source, &file, &sections) {
                            return None;
                        }
                    }
                    sections
                });
                Arc::clone(entry.insert(section_info))
            }
        };

        Some(LoadedElfMapping {
            image_base: resolve_image_base(module, &section_info),
            sections: section_info,
        })
    }

    pub(crate) fn remove(&mut self, module_id: u32) {
        self.by_module.remove(&module_id);
    }

    pub(crate) fn contains(&self, module_id: u32) -> bool {
        self.by_module.contains_key(&module_id)
    }

    pub(crate) fn reuse(&mut self, source_id: u32, module_id: u32) {
        if let Some(sections) = self.by_module.get(&source_id).cloned() {
            self.by_module.insert(module_id, sections);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_module.len()
    }
}

fn symbol_source_matches_file(
    source: &crate::spool::ModuleSymbolSource,
    file: &File,
    sections: &ElfSectionInfo,
) -> bool {
    if let Some(expected) = source.build_id.as_deref() {
        return sections.build_id.as_deref() == Some(expected);
    }
    file.metadata().is_ok_and(|metadata| {
        metadata.dev() == source.device
            && metadata.ino() == source.inode
            && metadata.size() == source.size
            && metadata.ctime() == source.ctime
            && metadata.ctime_nsec() == source.ctime_nsec
    })
}

pub(crate) struct DeletedMappingSourceAnchor {
    pub(crate) file_offset: u64,
    pub(crate) svma: u64,
}

pub(crate) fn deleted_mapping_source_anchor(
    module: &ModuleRecord,
    sections: &ElfSectionInfo,
) -> Option<DeletedMappingSourceAnchor> {
    let memory = File::open(format!("/proc/{}/mem", module.process_id)).ok()?;
    deleted_mapping_source_anchor_with_reader(module, sections, |address, bytes| {
        memory.read_exact_at(bytes, address)
    })
}

fn deleted_mapping_source_anchor_with_reader(
    module: &ModuleRecord,
    sections: &ElfSectionInfo,
    mut read_memory: impl FnMut(u64, &mut [u8]) -> std::io::Result<()>,
) -> Option<DeletedMappingSourceAnchor> {
    const PF_X: u32 = 0x1;
    const MINIMUM_EVIDENCE_SIZE: usize = 4 * 1024;
    const MAXIMUM_COMPARE_SIZE: usize = 64 * 1024;
    const MAXIMUM_TOTAL_COMPARE_SIZE: usize = 256 * 1024;
    const PROBE_SIZE: usize = 4 * 1024;
    const PROBE_COUNT: usize = MAXIMUM_COMPARE_SIZE / PROBE_SIZE;

    let mut matched_anchor: Option<DeletedMappingSourceAnchor> = None;
    let mut total_compare_size = 0_usize;
    for segment in sections
        .load_segments
        .iter()
        .filter(|segment| segment.p_flags & PF_X != 0)
    {
        let segment_file_end = segment.p_offset.checked_add(segment.p_filesz)?;
        let segment_file_range = segment.p_offset..segment_file_end;
        let (validation_file_range, validation_data, data_file_offset) = if let Some(file_data) =
            sections.file_data.as_ref()
        {
            (segment_file_range.clone(), file_data, 0)
        } else {
            let text_file_range = sections.text_file_range.as_ref()?;
            let text = sections.text.as_ref()?;
            if text_file_range.start < segment.p_offset || text_file_range.end > segment_file_end {
                continue;
            }
            (text_file_range.clone(), text, text_file_range.start)
        };
        let source_file_offset = segment.p_offset.checked_add(module.file_offset)?;
        let source_svma = segment.p_vaddr.checked_add(module.file_offset)?;
        let source_mapping_end =
            source_file_offset.checked_add(module.end.checked_sub(module.start)?)?;
        let compare_file_start = validation_file_range.start.max(source_file_offset);
        let compare_file_end = validation_file_range.end.min(source_mapping_end);
        if compare_file_start >= compare_file_end {
            continue;
        }
        let validation_offset =
            usize::try_from(compare_file_start.checked_sub(data_file_offset)?).ok()?;
        let compare_len =
            usize::try_from(compare_file_end.checked_sub(compare_file_start)?).ok()?;
        let validation_end = validation_offset.checked_add(compare_len)?;
        let expected = validation_data.get(validation_offset..validation_end)?;
        let validation_mapping_offset = compare_file_start.checked_sub(source_file_offset)?;
        let validation_avma = module.start.checked_add(validation_mapping_offset)?;

        if expected.len() < MINIMUM_EVIDENCE_SIZE {
            continue;
        }
        let windows = if expected.len() <= MAXIMUM_COMPARE_SIZE {
            vec![(0, expected.len())]
        } else {
            let last_start = expected.len() - PROBE_SIZE;
            (0..PROBE_COUNT)
                .map(|index| (index * last_start / (PROBE_COUNT - 1), PROBE_SIZE))
                .collect()
        };
        let compare_size = windows.iter().map(|(_, length)| length).sum::<usize>();
        let next_total = total_compare_size.checked_add(compare_size)?;
        if next_total > MAXIMUM_TOTAL_COMPARE_SIZE {
            return None;
        }
        total_compare_size = next_total;
        let mut actual = vec![0_u8; windows[0].1];
        let matches = windows.into_iter().all(|(offset, length)| {
            let Some(address) = validation_avma.checked_add(offset as u64) else {
                return false;
            };
            actual.resize(length, 0);
            read_memory(address, &mut actual).is_ok() && actual == expected[offset..offset + length]
        });
        if matches {
            let candidate = DeletedMappingSourceAnchor {
                file_offset: source_file_offset,
                svma: source_svma,
            };
            match &matched_anchor {
                None => matched_anchor = Some(candidate),
                Some(previous)
                    if previous.file_offset == candidate.file_offset
                        && previous.svma == candidate.svma => {}
                Some(_) => return None,
            }
        }
    }
    matched_anchor
}

fn local_vdso_bytes() -> Option<Arc<[u8]>> {
    const MAX_MAPPED_ELF_SIZE: u64 = 16 * 1024 * 1024;
    static VDSO: OnceLock<Arc<[u8]>> = OnceLock::new();

    // Stackpulse only sends native-register samples to Framehop. The native
    // vDSO is kernel-wide, so a local copy avoids ptrace/Yama restrictions on
    // /proc/<target>/mem while retaining the target mapping's AVMA.
    if let Some(bytes) = VDSO.get() {
        return Some(Arc::clone(bytes));
    }
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let region = crate::proc_maps::parse_iter(&maps).find(|region| region.path == VDSO_PATH)?;
    let length = region.address.end.checked_sub(region.address.start)?;
    if length == 0 || length > MAX_MAPPED_ELF_SIZE {
        return None;
    }
    let mut bytes = vec![0; usize::try_from(length).ok()?];
    let memory = File::open("/proc/self/mem").ok()?;
    memory
        .read_exact_at(&mut bytes, region.address.start)
        .ok()?;
    let bytes: Arc<[u8]> = bytes.into();
    let _ = VDSO.set(Arc::clone(&bytes));
    Some(bytes)
}

#[cfg(test)]
fn module_path_matches_inode(module: &ModuleRecord) -> bool {
    open_module_file(module).is_some()
}

fn open_module_file(module: &ModuleRecord) -> Option<File> {
    if let Some(source) = module.path.symbol_source() {
        return File::open(std::path::Path::new(source.path.as_ref())).ok();
    }
    let map_file = PathBuf::from(format!(
        "/proc/{}/map_files/{:x}-{:x}",
        module.process_id, module.start, module.end
    ));
    open_module_file_with_mapping_path(module, &map_file)
}

fn open_module_file_with_mapping_path(
    module: &ModuleRecord,
    map_file: &std::path::Path,
) -> Option<File> {
    // The proc mapping names the exact object mapped by this process and must
    // win over a textual pathname that may now refer to a replacement file or
    // resolve in a different mount namespace. The pathname remains a useful
    // fallback after the process exits and map_files disappears.
    validated_module_file(map_file, module)
        .or_else(|| validated_module_file(module.path.as_path(), module))
}

fn validated_module_file(path: &std::path::Path, module: &ModuleRecord) -> Option<File> {
    let file = File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    if module.inode != 0 && metadata.ino() != module.inode {
        return None;
    }
    if module.device_major != 0 || module.device_minor != 0 {
        let device = metadata.dev();
        if libc::major(device) != module.device_major || libc::minor(device) != module.device_minor
        {
            return None;
        }
    }
    Some(file)
}

fn resolve_image_base(
    module: &ModuleRecord,
    section_info: &ElfSectionInfo,
) -> Option<ModuleImageBase> {
    if let Some(source) = module.path.symbol_source() {
        const PF_X: u32 = 0x1;
        let anchor_is_valid = section_info.load_segments.iter().any(|segment| {
            if segment.p_flags & PF_X == 0 {
                return false;
            }
            let Some(segment_end) = segment.p_offset.checked_add(segment.p_filesz) else {
                return false;
            };
            if source.file_offset < segment.p_offset || source.file_offset >= segment_end {
                return false;
            }
            source
                .file_offset
                .checked_sub(segment.p_offset)
                .and_then(|delta| segment.p_vaddr.checked_add(delta))
                == Some(source.svma)
        });
        return anchor_is_valid.then(|| ModuleImageBase::new(module.start, source.svma));
    }
    let span = module.end.saturating_sub(module.start);
    resolve_mapping_image_base(section_info, module.file_offset, module.start, span)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::LoadSegment;
    use crate::spool::ModuleSymbolSource;

    #[test]
    fn deleted_hugetlb_mapping_matches_original_executable_segment() {
        let text: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let sections = ElfSectionInfo {
            build_id: Some(Arc::from([1_u8, 2, 3].as_slice())),
            file_data: None,
            base_svma: 0,
            text_svma: Some(0x401000..0x402000),
            text_file_range: Some(0x401000..0x402000),
            text: Some(crate::elf::ElfSectionData::owned(text.clone())),
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0x400000,
                p_filesz: 0x40200d,
                p_memsz: 0x40200d,
                p_vaddr: 0x400000,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x5c18_2a80_0000,
            end: 0x5c18_2ae0_0000,
            file_offset: 0,
            inode: 123,
            device_major: 0,
            device_minor: 0x88,
            inode_generation: 0,
            path: "/hugetlbfs/libhugetlbfs.tmp.abc (deleted)".into(),
            is_kernel: false,
        };
        let text_avma = module.start + 0x1000;
        let source =
            deleted_mapping_source_anchor_with_reader(&module, &sections, |address, bytes| {
                let offset = usize::try_from(address - text_avma).unwrap();
                bytes.copy_from_slice(&text[offset..offset + bytes.len()]);
                Ok(())
            })
            .expect("matching copied text should identify its original PT_LOAD");

        assert_eq!(source.file_offset, 0x400000);
        assert_eq!(source.svma, 0x400000);
    }

    #[test]
    fn deleted_mapping_rejects_nonmatching_executable_bytes() {
        let sections = ElfSectionInfo {
            build_id: None,
            file_data: None,
            base_svma: 0,
            text_svma: Some(0x401000..0x401100),
            text_file_range: Some(0x401000..0x401100),
            text: Some(crate::elf::ElfSectionData::owned(vec![0x90; 256])),
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0x400000,
                p_filesz: 0x2000,
                p_memsz: 0x2000,
                p_vaddr: 0x400000,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x800000,
            end: 0xa00000,
            file_offset: 0,
            inode: 123,
            device_major: 0,
            device_minor: 0x88,
            inode_generation: 0,
            path: "/hugetlbfs/not-the-program (deleted)".into(),
            is_kernel: false,
        };

        assert!(deleted_mapping_source_anchor_with_reader(
            &module,
            &sections,
            |_address, bytes| {
                bytes.fill(0xcc);
                Ok(())
            },
        )
        .is_none());
    }

    #[test]
    fn deleted_mapping_uses_executable_segment_without_text_section() {
        let file_bytes: Vec<u8> = (0..0x3000).map(|index| (index % 251) as u8).collect();
        let sections = ElfSectionInfo {
            build_id: None,
            file_data: Some(crate::elf::ElfSectionData::owned(file_bytes.clone())),
            base_svma: 0,
            text_svma: None,
            text_file_range: None,
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0x1000,
                p_filesz: 0x2000,
                p_memsz: 0x2000,
                p_vaddr: 0x401000,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x8000_0000,
            end: 0x8000_2000,
            file_offset: 0,
            inode: 123,
            device_major: 0,
            device_minor: 0x88,
            inode_generation: 0,
            path: "/hugetlbfs/program.tmp (deleted)".into(),
            is_kernel: false,
        };

        let source =
            deleted_mapping_source_anchor_with_reader(&module, &sections, |address, bytes| {
                let offset = usize::try_from(address - module.start).unwrap() + 0x1000;
                bytes.copy_from_slice(&file_bytes[offset..offset + bytes.len()]);
                Ok(())
            })
            .expect("executable PT_LOAD bytes should not depend on a .text section name");

        assert_eq!(source.file_offset, 0x1000);
        assert_eq!(source.svma, 0x401000);
    }

    #[test]
    fn deleted_mapping_rejects_ambiguous_executable_segment_biases() {
        let file_bytes: Vec<u8> = (0..0x3000).map(|index| (index % 251) as u8).collect();
        let sections = ElfSectionInfo {
            build_id: None,
            file_data: Some(crate::elf::ElfSectionData::owned(file_bytes.clone())),
            base_svma: 0,
            text_svma: None,
            text_file_range: None,
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![
                LoadSegment {
                    p_offset: 0x1000,
                    p_filesz: 0x2000,
                    p_memsz: 0x2000,
                    p_vaddr: 0x401000,
                    p_flags: 0x5,
                },
                LoadSegment {
                    p_offset: 0x1000,
                    p_filesz: 0x2000,
                    p_memsz: 0x2000,
                    p_vaddr: 0x801000,
                    p_flags: 0x5,
                },
            ]
            .into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x9000_0000,
            end: 0x9000_2000,
            file_offset: 0,
            inode: 123,
            device_major: 0,
            device_minor: 0x88,
            inode_generation: 0,
            path: "/hugetlbfs/program.tmp (deleted)".into(),
            is_kernel: false,
        };

        assert!(
            deleted_mapping_source_anchor_with_reader(&module, &sections, |address, bytes| {
                let offset = usize::try_from(address - module.start).unwrap() + 0x1000;
                bytes.copy_from_slice(&file_bytes[offset..offset + bytes.len()]);
                Ok(())
            },)
            .is_none()
        );
    }

    #[test]
    fn deleted_partial_mapping_preserves_nonzero_file_offset() {
        let text: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let sections = ElfSectionInfo {
            build_id: None,
            file_data: None,
            base_svma: 0,
            text_svma: Some(0x401000..0x402000),
            text_file_range: Some(0x401000..0x402000),
            text: Some(crate::elf::ElfSectionData::owned(text.clone())),
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0x400000,
                p_filesz: 0x2000,
                p_memsz: 0x2000,
                p_vaddr: 0x400000,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x8000_0000,
            end: 0x8000_1000,
            file_offset: 0x1000,
            inode: 123,
            device_major: 0,
            device_minor: 0x88,
            inode_generation: 0,
            path: "/hugetlbfs/program.tmp (deleted)".into(),
            is_kernel: false,
        };

        let source =
            deleted_mapping_source_anchor_with_reader(&module, &sections, |_address, bytes| {
                bytes.copy_from_slice(&text[..bytes.len()]);
                Ok(())
            })
            .expect("partial executable mapping should retain its source offset");

        assert_eq!(source.file_offset, 0x401000);
        assert_eq!(source.svma, 0x401000);
    }

    #[test]
    fn deleted_mapping_rejects_tiny_text_overlap() {
        let sections = ElfSectionInfo {
            build_id: None,
            file_data: None,
            base_svma: 0,
            text_svma: Some(0x401000..0x403000),
            text_file_range: Some(0x401000..0x403000),
            text: Some(crate::elf::ElfSectionData::owned(vec![0x90; 0x2000])),
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0x400000,
                p_filesz: 0x3000,
                p_memsz: 0x3000,
                p_vaddr: 0x400000,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x8000_0000,
            end: 0x8000_0010,
            file_offset: 0x1000,
            inode: 123,
            device_major: 0,
            device_minor: 0x88,
            inode_generation: 0,
            path: "/hugetlbfs/program.tmp (deleted)".into(),
            is_kernel: false,
        };

        assert!(deleted_mapping_source_anchor_with_reader(
            &module,
            &sections,
            |_address, _bytes| panic!("insufficient overlap must be rejected before reading"),
        )
        .is_none());
    }

    #[test]
    fn deleted_mapping_validation_has_a_global_comparison_budget() {
        let file_bytes: Vec<u8> = (0..0x11000).map(|index| (index % 251) as u8).collect();
        let segment = LoadSegment {
            p_offset: 0x1000,
            p_filesz: 0x10000,
            p_memsz: 0x10000,
            p_vaddr: 0x401000,
            p_flags: 0x5,
        };
        let sections = ElfSectionInfo {
            build_id: None,
            file_data: Some(crate::elf::ElfSectionData::owned(file_bytes.clone())),
            base_svma: 0,
            text_svma: None,
            text_file_range: None,
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![segment; 5].into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0xa000_0000,
            end: 0xa001_0000,
            file_offset: 0,
            inode: 123,
            device_major: 0,
            device_minor: 0x88,
            inode_generation: 0,
            path: "/hugetlbfs/program.tmp (deleted)".into(),
            is_kernel: false,
        };

        assert!(
            deleted_mapping_source_anchor_with_reader(&module, &sections, |address, bytes| {
                let offset = usize::try_from(address - module.start).unwrap() + 0x1000;
                bytes.copy_from_slice(&file_bytes[offset..offset + bytes.len()]);
                Ok(())
            },)
            .is_none()
        );
    }

    #[test]
    fn stable_symbol_source_supplies_explicit_hugetlb_image_base() {
        let mut module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x5c18_2a80_0000,
            end: 0x5c18_2ae0_0000,
            file_offset: 0,
            inode: 123,
            device_major: 0,
            device_minor: 0x88,
            inode_generation: 0,
            path: "/hugetlbfs/program.tmp (deleted)".into(),
            is_kernel: false,
        };
        module.path.set_symbol_source(ModuleSymbolSource {
            path: Arc::from("/opt/app/bin/program"),
            build_id: None,
            file_offset: 0x400000,
            svma: 0x400000,
            device: 1,
            inode: 2,
            size: 3,
            ctime: 4,
            ctime_nsec: 5,
        });
        let sections = ElfSectionInfo {
            build_id: None,
            file_data: None,
            base_svma: 0,
            text_svma: None,
            text_file_range: None,
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0x400000,
                p_filesz: 0x1000,
                p_memsz: 0x1000,
                p_vaddr: 0x400000,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };

        assert_eq!(
            resolve_image_base(&module, &sections),
            Some(ModuleImageBase::new(module.start, 0x400000))
        );
    }

    #[test]
    fn invalid_symbol_source_anchor_is_rejected() {
        let mut module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x7000_0000,
            end: 0x7000_1000,
            file_offset: 0,
            inode: 1,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/hugetlbfs/program.tmp (deleted)".into(),
            is_kernel: false,
        };
        module.path.set_symbol_source(ModuleSymbolSource {
            path: Arc::from("/opt/app/bin/program"),
            build_id: None,
            file_offset: 0x500000,
            svma: 0x400000,
            device: 1,
            inode: 2,
            size: 3,
            ctime: 4,
            ctime_nsec: 5,
        });
        let sections = ElfSectionInfo {
            build_id: None,
            file_data: None,
            base_svma: 0,
            text_svma: None,
            text_file_range: None,
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0x400000,
                p_filesz: 0x1000,
                p_memsz: 0x1000,
                p_vaddr: 0x400000,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };

        assert_eq!(resolve_image_base(&module, &sections), None);
    }

    #[test]
    fn build_id_less_symbol_source_requires_exact_file_identity() {
        let path = std::env::current_exe().unwrap();
        let file = File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let sections = load_elf_sections_from_file(&file, &path).unwrap();
        let mut source = ModuleSymbolSource {
            path: path.to_string_lossy().into_owned().into(),
            build_id: None,
            file_offset: 0,
            svma: 0,
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        };

        assert!(symbol_source_matches_file(&source, &file, &sections));
        source.inode = source.inode.saturating_add(1);
        assert!(!symbol_source_matches_file(&source, &file, &sections));
    }

    #[test]
    fn image_base_is_not_guessed_when_mapping_cannot_be_correlated() {
        let section_info = ElfSectionInfo {
            build_id: None,
            file_data: None,
            base_svma: 0,
            text_svma: Some(0x1000..0x2000),
            text_file_range: Some(0x1000..0x2000),
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0,
                p_filesz: 0x5000,
                p_memsz: 0x5000,
                p_vaddr: 0,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x7000_0000,
            end: 0x7000_1000,
            file_offset: 0x9000,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/tmp/libexample.so".into(),
            is_kernel: false,
        };

        assert_eq!(resolve_image_base(&module, &section_info), None);
    }

    #[test]
    fn loaded_elf_is_retained_when_mapping_cannot_be_correlated() {
        let module = ModuleRecord {
            id: 1,
            process_id: i32::try_from(std::process::id()).unwrap(),
            start: 0x7000_0000,
            end: 0x7000_1000,
            file_offset: u64::MAX - 0xfff,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned()
                .into(),
            is_kernel: false,
        };

        let loaded = ElfSectionCache::default()
            .load_mapping(&module)
            .expect("ELF sections still load for an uncorrelated mapping");

        assert_eq!(loaded.image_base, None);
    }

    #[test]
    fn module_path_inode_mismatch_is_rejected() {
        let path = std::env::temp_dir().join(format!(
            "stackpulse-native-module-inode-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"not-elf").unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();
        let mut module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: inode.saturating_add(1),
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
            is_kernel: false,
        };

        assert!(!module_path_matches_inode(&module));
        module.inode = inode;
        assert!(module_path_matches_inode(&module));
        let device = std::fs::metadata(&path).unwrap().dev();
        module.device_major = libc::major(device);
        module.device_minor = libc::minor(device).saturating_add(1);
        assert!(!module_path_matches_inode(&module));
        module.device_minor = libc::minor(device);
        assert!(module_path_matches_inode(&module));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_elf_load_is_retried_when_file_appears() {
        let path = std::env::temp_dir().join(format!(
            "stackpulse-native-module-retry-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let module = ModuleRecord {
            id: 1,
            process_id: 42,
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
            is_kernel: false,
        };
        let mut cache = ElfSectionCache::default();

        assert!(cache.load_mapping(&module).is_none());
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        assert!(cache.load_mapping(&module).is_some());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cached_sections_can_be_reused_and_retired_by_module_id() {
        let path = std::env::current_exe().unwrap();
        let mut module = ModuleRecord {
            id: 1,
            process_id: i32::try_from(std::process::id()).unwrap(),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
            is_kernel: false,
        };
        let mut cache = ElfSectionCache::default();
        assert!(cache.load_mapping(&module).is_some());

        cache.reuse(1, 2);
        module.id = 2;
        cache.remove(1);

        assert_eq!(cache.len(), 1);
        assert!(cache.load_mapping(&module).is_some());
    }

    #[test]
    fn exact_mapping_file_wins_over_existing_textual_path() {
        let suffix = std::process::id();
        let map_path = std::env::temp_dir().join(format!("stackpulse-native-module-map-{suffix}"));
        let textual_path =
            std::env::temp_dir().join(format!("stackpulse-native-module-path-{suffix}"));
        std::fs::write(&map_path, b"mapped object").unwrap();
        std::fs::write(&textual_path, b"replacement").unwrap();
        let mapped_inode = std::fs::metadata(&map_path).unwrap().ino();
        let module = ModuleRecord {
            id: 1,
            process_id: i32::try_from(std::process::id()).unwrap(),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: textual_path.to_string_lossy().into_owned().into(),
            is_kernel: false,
        };

        let opened = open_module_file_with_mapping_path(&module, &map_path).unwrap();
        assert_eq!(opened.metadata().unwrap().ino(), mapped_inode);

        let _ = std::fs::remove_file(map_path);
        let _ = std::fs::remove_file(textual_path);
    }

    #[test]
    fn loads_vdso_sections_from_the_target_mapping() {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let region = crate::proc_maps::parse_iter(&maps)
            .find(|region| region.path == "[vdso]")
            .expect("current process has a vDSO mapping");
        let module = ModuleRecord {
            id: 1,
            process_id: i32::try_from(std::process::id()).unwrap(),
            start: region.address.start,
            end: region.address.end,
            file_offset: region.file_offset,
            inode: region.inode,
            device_major: region.device_major,
            device_minor: region.device_minor,
            inode_generation: 0,
            path: "[vdso]".into(),
            is_kernel: false,
        };

        let loaded = ElfSectionCache::default()
            .load_mapping(&module)
            .expect("vDSO is a readable ELF mapping");

        assert!(loaded.image_base.is_some());
        assert!(loaded.sections.eh_frame.is_some() || loaded.sections.eh_frame_hdr.is_some());
    }
}
