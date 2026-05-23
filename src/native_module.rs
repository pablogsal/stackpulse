use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::linux::elf_loader;
use crate::linux::elf_types::{ElfSectionInfo, ModuleInfo};
use crate::ModuleImageBase;
use rustc_hash::FxHashMap;

use crate::spool::ModuleRecord;

#[derive(Clone, Default)]
pub(crate) struct ElfSectionCache {
    by_path: FxHashMap<String, Option<Arc<ElfSectionInfo>>>,
}

impl ElfSectionCache {
    pub(crate) fn module_info(
        &mut self,
        module: &ModuleRecord,
    ) -> Option<(ModuleInfo, Arc<ElfSectionInfo>)> {
        if module.is_kernel || module.path.is_empty() || !Path::new(&module.path).is_file() {
            return None;
        }

        let section_info = self
            .by_path
            .entry(module.path.clone())
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

fn module_info_with_sections(module: &ModuleRecord, section_info: &ElfSectionInfo) -> ModuleInfo {
    let path = PathBuf::from(&module.path);
    let name = crate::path_to_name(&path);
    let image_base = resolve_image_base(module, section_info);
    let is_python = crate::is_python_module(&name);

    ModuleInfo {
        name,
        path,
        avma_range: module.start..module.end,
        image_base: Some(image_base),
        file_off_start: module.file_offset,
        is_python,
        is_executable: true,
        section_info: None,
    }
}

fn resolve_image_base(module: &ModuleRecord, section_info: &ElfSectionInfo) -> ModuleImageBase {
    let span = module.end.saturating_sub(module.start);
    elf_loader::ElfImageLayout::new(section_info)
        .resolve_mapping(module.file_offset, module.start, span)
        .map(|resolved| resolved.image_base)
        .unwrap_or_else(|| {
            ModuleImageBase::new(
                section_info
                    .base_svma
                    .wrapping_add(module.start.saturating_sub(module.file_offset)),
                section_info.base_svma,
            )
        })
}
