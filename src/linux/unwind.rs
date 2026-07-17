use framehop::Unwinder;
use rustc_hash::FxHashSet;

use super::{elf_loader, elf_types};
use crate::native_module::ElfSectionCache;
use crate::spool::ModuleUpdate;

type UnwindPolicy = framehop::MayAllocateDuringUnwind;
pub(super) type NativeUnwinder = framehop::UnwinderNative<elf_types::ElfSectionData, UnwindPolicy>;
pub(super) type NativeCache = framehop::CacheNative<UnwindPolicy>;

#[derive(Default)]
pub(super) struct ProcessUnwinder {
    pub(super) unwinder: NativeUnwinder,
    pub(super) cache: NativeCache,
    refreshed_uncovered_pages: FxHashSet<u64>,
    elf_sections: ElfSectionCache,
}

impl Clone for ProcessUnwinder {
    fn clone(&self) -> Self {
        Self {
            unwinder: self.unwinder.clone(),
            cache: NativeCache::default(),
            refreshed_uncovered_pages: FxHashSet::default(),
            elf_sections: self.elf_sections.clone(),
        }
    }
}

impl ProcessUnwinder {
    pub(super) fn apply_module_update(&mut self, update: &ModuleUpdate) {
        for module in &update.retired {
            self.unwinder.remove_module(module.start);
        }
        for activation in &update.active {
            if let Some(source_id) = activation.source_module_id {
                self.elf_sections.reuse(source_id, activation.module.id);
            }
        }
        for activation in &update.active {
            let module = &activation.module;
            if module.is_kernel {
                continue;
            }
            if !update.mapping_changed
                && activation.source_module_id.is_none()
                && self.elf_sections.contains(module.id)
            {
                continue;
            }
            let start = module.start;
            let Some((module_info, section_info)) = self.elf_sections.module_info(module) else {
                continue;
            };
            if let Some(module) =
                elf_loader::module_to_framehop_with_section_info(&module_info, &section_info)
            {
                self.unwinder.remove_module(start);
                self.unwinder.add_module(module);
            }
        }
        for module in &update.retired {
            self.elf_sections.remove(module.id);
        }
        for source_id in update
            .active
            .iter()
            .filter_map(|activation| activation.source_module_id)
        {
            self.elf_sections.remove(source_id);
        }
        if update.mapping_changed {
            self.refreshed_uncovered_pages.clear();
        }
    }

    pub(super) fn should_refresh_for_uncovered_pc(&mut self, pc: u64) -> bool {
        self.refreshed_uncovered_pages.insert(refresh_page(pc))
    }
}

fn refresh_page(pc: u64) -> u64 {
    let page_size = crate::elf::system_page_size();
    pc - pc % page_size
}
