use std::fs::File;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::elf::{
    load_elf_sections_from_bytes, load_elf_sections_from_file, ElfImageLayout, ElfSectionInfo,
};
use crate::ModuleImageBase;
use rustc_hash::FxHashMap;

use crate::spool::ModuleRecord;

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
    pub(crate) fn load_mapping(&mut self, module: &ModuleRecord) -> Option<LoadedElfMapping> {
        if module.is_kernel
            || module.path.is_empty()
            || (module.path.is_bracketed_mapping() && module.path.as_str() != "[vdso]")
        {
            return None;
        }

        let section_info = match self.by_module.entry(module.id) {
            std::collections::hash_map::Entry::Occupied(entry) => Arc::clone(entry.get()),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let section_info = Arc::new(if module.path.as_str() == "[vdso]" {
                    let bytes = local_vdso_bytes()?;
                    load_elf_sections_from_bytes(bytes, module.path.as_path()).ok()?
                } else {
                    let file = open_module_file(module)?;
                    load_elf_sections_from_file(&file, module.path.as_path()).ok()?
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
    let region = crate::proc_maps::parse_iter(&maps).find(|region| region.path == "[vdso]")?;
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
    let span = module.end.saturating_sub(module.start);
    ElfImageLayout::new(section_info).resolve_mapping(module.file_offset, module.start, span)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::LoadSegment;

    #[test]
    fn image_base_is_not_guessed_when_mapping_cannot_be_correlated() {
        let section_info = ElfSectionInfo {
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
