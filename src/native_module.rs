use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;

use crate::linux::elf_loader;
use crate::linux::elf_types::{ElfSectionInfo, ModuleInfo};
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

impl ElfSectionCache {
    pub(crate) fn module_info(
        &mut self,
        module: &ModuleRecord,
    ) -> Option<(ModuleInfo, Arc<ElfSectionInfo>)> {
        if module.is_kernel || module.path.is_empty() || module.path.is_bracketed_mapping() {
            return None;
        }

        let section_info = match self.by_module.entry(module.id) {
            std::collections::hash_map::Entry::Occupied(entry) => Arc::clone(entry.get()),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let file = open_module_file(module)?;
                let section_info = Arc::new(
                    elf_loader::load_elf_sections_from_file(&file, module.path.as_path()).ok()?,
                );
                Arc::clone(entry.insert(section_info))
            }
        };

        Some((
            module_info_with_sections(module, &section_info),
            section_info,
        ))
    }
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
    Some(file)
}

fn module_info_with_sections(module: &ModuleRecord, section_info: &ElfSectionInfo) -> ModuleInfo {
    let path = PathBuf::from(module.path.as_path());
    let name = crate::path_to_name(&path);
    let image_base = resolve_image_base(module, section_info);

    ModuleInfo {
        name,
        path,
        avma_range: module.start..module.end,
        image_base,
        is_executable: true,
    }
}

fn resolve_image_base(
    module: &ModuleRecord,
    section_info: &ElfSectionInfo,
) -> Option<ModuleImageBase> {
    let span = module.end.saturating_sub(module.start);
    elf_loader::ElfImageLayout::new(section_info).resolve_mapping(
        module.file_offset,
        module.start,
        span,
    )
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
            path: "/tmp/libexample.so".into(),
            is_kernel: false,
        };

        assert_eq!(resolve_image_base(&module, &section_info), None);
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
            path: path.to_string_lossy().into_owned().into(),
            is_kernel: false,
        };

        assert!(!module_path_matches_inode(&module));
        module.inode = inode;
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
            path: path.to_string_lossy().into_owned().into(),
            is_kernel: false,
        };
        let mut cache = ElfSectionCache::default();

        assert!(cache.module_info(&module).is_none());
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        assert!(cache.module_info(&module).is_some());

        let _ = std::fs::remove_file(path);
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
            path: textual_path.to_string_lossy().into_owned().into(),
            is_kernel: false,
        };

        let opened = open_module_file_with_mapping_path(&module, &map_path).unwrap();
        assert_eq!(opened.metadata().unwrap().ino(), mapped_inode);

        let _ = std::fs::remove_file(map_path);
        let _ = std::fs::remove_file(textual_path);
    }
}
