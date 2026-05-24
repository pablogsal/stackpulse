use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::linux::elf_loader;
use crate::linux::elf_types::{ElfSectionInfo, ModuleInfo};
use crate::ModuleImageBase;
use rustc_hash::FxHashMap;

use crate::spool::ModuleRecord;

#[derive(Clone, Default)]
pub(crate) struct ElfSectionCache {
    by_path: FxHashMap<(crate::spool::ModulePath, u64), Option<Arc<ElfSectionInfo>>>,
}

impl ElfSectionCache {
    pub(crate) fn module_info(
        &mut self,
        module: &ModuleRecord,
    ) -> Option<(ModuleInfo, Arc<ElfSectionInfo>)> {
        if module.is_kernel
            || module.path.is_empty()
            || !Path::new(&module.path).is_file()
            || !module_path_matches_inode(module)
        {
            return None;
        }

        let section_info = self
            .by_path
            .entry((module.path.clone(), module.inode))
            .or_insert_with(|| {
                elf_loader::load_elf_sections_from_path(Path::new(&module.path))
                    .ok()
                    .map(Arc::new)
            })
            .as_ref()
            .cloned()?;

        Some((
            module_info_with_sections(module, &section_info),
            section_info,
        ))
    }
}

fn module_path_matches_inode(module: &ModuleRecord) -> bool {
    module.inode == 0
        || std::fs::metadata(module.path.as_str())
            .is_ok_and(|metadata| metadata.ino() == module.inode)
}

fn module_info_with_sections(module: &ModuleRecord, section_info: &ElfSectionInfo) -> ModuleInfo {
    let path = PathBuf::from(module.path.as_str());
    let name = crate::path_to_name(&path);
    let image_base = resolve_image_base(module, section_info);
    let is_python = crate::is_python_module(&name);

    ModuleInfo {
        name,
        path,
        avma_range: module.start..module.end,
        image_base,
        file_off_start: module.file_offset,
        is_python,
        is_executable: true,
        section_info: None,
    }
}

fn resolve_image_base(
    module: &ModuleRecord,
    section_info: &ElfSectionInfo,
) -> Option<ModuleImageBase> {
    let span = module.end.saturating_sub(module.start);
    elf_loader::ElfImageLayout::new(section_info)
        .resolve_mapping(module.file_offset, module.start, span)
        .map(|resolved| resolved.image_base)
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
}
