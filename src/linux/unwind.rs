use framehop::Unwinder;
use rustc_hash::FxHashSet;
use std::mem::size_of;
use std::ops::Range;

use crate::elf::{ElfSectionData, ElfSectionInfo};
use crate::native_module::{ElfSectionCache, LoadedElfMapping};
use crate::spool::{
    FrameMode, FrameRecord, ModuleRecord, ModuleTable, ModuleUpdate, PerfSpoolWriter,
};

mod backend;
mod sample;
#[cfg(test)]
pub(super) use backend::test_module;
pub(super) use backend::{NativeCache, NativeUnwinder};
pub(super) use sample::{build_sample_stack, StackInput};

/// Per-process executable metadata and caches used to capture native stacks.
#[derive(Default)]
pub(super) struct ProcessUnwinder {
    /// Runtime registrations and recorded frame ownership, rediscovered after fork or exec.
    jit: super::jit::JitRegistry,
    /// Ordinary and JIT unwind tables for this process's current executable code.
    unwinder: NativeUnwinder,
    /// Unwind-rule cache reused across samples; a forked child starts with an empty cache.
    cache: NativeCache,
    /// Page-aligned user addresses for which mapping rediscovery was already attempted.
    /// Cleared when executable mappings change so uncovered pages can be checked again.
    refreshed_uncovered_pages: FxHashSet<u64>,
}

impl ProcessUnwinder {
    /// Refresh live runtime metadata before unwinding a captured sample.
    /// Polling and retry deadlines are enforced by the runtime registry.
    /// Target-memory failures are best-effort; spool write failures propagate.
    pub(super) fn refresh_runtime_modules<W: std::io::Write>(
        &mut self,
        pid: i32,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> std::io::Result<()> {
        self.jit.refresh(pid, &mut self.unwinder, modules, writer)
    }

    /// Refresh failed runtime metadata before retrying the original captured stack.
    pub(super) fn refresh_runtime_frame<W: std::io::Write>(
        &mut self,
        address: u64,
        pid: i32,
        modules: &mut ModuleTable,
        writer: &mut PerfSpoolWriter<W>,
    ) -> std::io::Result<bool> {
        self.jit
            .refresh_for_frame(address, pid, &mut self.unwinder, modules, writer)
    }

    /// Pin runtime frames to their registration, then fall back to mapped files.
    /// The caller supplies the lookup address, already adjusted for returns.
    pub(super) fn resolve_frame(
        &self,
        pid: i32,
        address: u64,
        mode: FrameMode,
        modules: &mut ModuleTable,
    ) -> FrameRecord {
        if mode == FrameMode::User {
            if let Some(frame) = self.jit.frame(address) {
                return frame;
            }
        }
        modules.resolve_frame(pid, address, mode)
    }

    /// Copy ordinary modules and reset caches; rediscover runtime code in the child.
    pub(super) fn inherit_for_fork(&self) -> Self {
        Self {
            unwinder: self.unwinder.inherit_for_fork(),
            ..Self::default()
        }
    }

    /// Apply file mapping changes and invalidate runtime discovery after topology changes.
    pub(super) fn apply_module_update(
        &mut self,
        update: &ModuleUpdate,
        elf_sections: &mut ElfSectionCache,
    ) {
        for module in &update.retired {
            self.unwinder.remove_module(module.start);
        }
        for activation in &update.active {
            if let Some(source_id) = activation.source_module_id {
                elf_sections.reuse(source_id, activation.module.id);
            }
        }
        for activation in &update.active {
            let module = &activation.module;
            if module.is_kernel() {
                continue;
            }
            if !update.mapping_changed
                && activation.source_module_id.is_none()
                && elf_sections.contains(module.id)
            {
                continue;
            }
            self.load_and_install_module(module, elf_sections);
        }
        for module in &update.retired {
            elf_sections.remove(module.id);
        }
        if update.mapping_changed {
            self.jit.mappings_changed();
            self.refreshed_uncovered_pages.clear();
        }
    }

    /// Reuse the parent's ELF sections, loading only missing inherited modules.
    pub(super) fn reuse_inherited_modules(
        &mut self,
        update: &ModuleUpdate,
        elf_sections: &mut ElfSectionCache,
    ) {
        debug_assert!(update.retired.is_empty());
        for activation in &update.active {
            if let Some(source_id) = activation.source_module_id {
                if elf_sections.reuse(source_id, activation.module.id) {
                    continue;
                }
                let module = &activation.module;
                if module.is_kernel() {
                    continue;
                }
                self.load_and_install_module(module, elf_sections);
            }
        }
    }

    /// Install unwind sections only when the ELF image matches its mapping.
    fn load_and_install_module(
        &mut self,
        module: &ModuleRecord,
        elf_sections: &mut ElfSectionCache,
    ) {
        let Ok(loaded) = elf_sections.load_mapping(module) else {
            return;
        };
        if let Some(framehop_module) = module_to_framehop(module, &loaded) {
            self.unwinder.remove_module(module.start);
            self.unwinder.add_module(framehop_module);
        }
    }

    /// Retry mapping discovery once per uncovered page until mappings change.
    pub(super) fn should_refresh_for_uncovered_pc(&mut self, pc: u64) -> bool {
        self.refreshed_uncovered_pages.insert(refresh_page(pc))
    }
}

fn refresh_page(pc: u64) -> u64 {
    let page_size = crate::elf::system_page_size();
    pc - pc % page_size
}

#[inline]
fn svma_range(svma: Option<u64>, data: Option<&ElfSectionData>) -> Option<Range<u64>> {
    let start = svma?;
    let end = start.checked_add(data?.len() as u64)?;
    Some(start..end)
}

fn indexed_eh_frame_hdr(section_info: &ElfSectionInfo) -> Option<(Range<u64>, ElfSectionData)> {
    let addr = section_info.eh_frame_hdr_svma?;
    let data = section_info.eh_frame_hdr.as_ref()?;
    let range = svma_range(Some(addr), Some(data))?;
    let eh_frame_range = svma_range(section_info.eh_frame_svma, section_info.eh_frame.as_ref())?;
    let bases = gimli::BaseAddresses::default()
        .set_eh_frame(section_info.eh_frame_svma.unwrap_or_default())
        .set_eh_frame_hdr(addr)
        .set_text(
            section_info
                .text_svma
                .as_ref()
                .map_or(0, |range| range.start),
        )
        .set_got(
            section_info
                .got_svma
                .as_ref()
                .map_or(0, |range| range.start),
        );
    let parsed = gimli::EhFrameHdr::new(data, gimli::LittleEndian)
        .parse(&bases, size_of::<u64>() as u8)
        .ok()?;
    if parsed.eh_frame_ptr() != gimli::Pointer::Direct(eh_frame_range.start) {
        return None;
    }
    let table = parsed.table()?;
    for entry in table.iter(&bases) {
        let (_, fde_pointer) = entry.ok()?;
        let gimli::Pointer::Direct(fde) = fde_pointer else {
            return None;
        };
        if !eh_frame_range.contains(&fde) {
            return None;
        }
        u32::try_from(fde.checked_sub(eh_frame_range.start)?).ok()?;
        table.pointer_to_offset(fde_pointer).ok()?;
    }
    table.lookup(0, &bases).ok()?;
    Some((range, data.clone()))
}

fn module_to_framehop(
    module: &ModuleRecord,
    loaded: &LoadedElfMapping,
) -> Option<framehop::Module<ElfSectionData>> {
    let image_base = loaded.image_base?;
    let section_info = &loaded.sections;
    let (eh_frame_hdr_svma, eh_frame_hdr) = indexed_eh_frame_hdr(section_info).unzip();

    let explicit_info = framehop::ExplicitModuleSectionInfo {
        base_svma: image_base.svma,
        text_svma: section_info.text_svma.clone(),
        text: section_info.text.clone(),
        stubs_svma: None,
        stub_helper_svma: None,
        got_svma: section_info.got_svma.clone(),
        unwind_info: None,
        eh_frame_svma: svma_range(section_info.eh_frame_svma, section_info.eh_frame.as_ref()),
        eh_frame: section_info.eh_frame.clone(),
        eh_frame_hdr_svma,
        eh_frame_hdr,
        debug_frame: None,
        text_segment_svma: None,
        text_segment: None,
    };

    Some(framehop::Module::new(
        crate::path_name(module.path()).to_owned(),
        module.start..module.end,
        image_base.avma,
        explicit_info,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::elf::fake_hard_case_section_info;
    use crate::spool::{ModuleActivation, ModuleOwner};

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn fork_resets_runtime_registrations_and_caches_without_changing_parent() {
        use backend::tests::{cfi_module, unwind_overlay_frame};

        let mut parent = ProcessUnwinder::default();
        parent.unwinder.add_module(cfi_module(16));
        let runtime = cfi_module(48);
        let mut module = ModuleRecord::new(
            0,
            crate::Pid::new(7).unwrap(),
            runtime.avma_range(),
            0,
            "[jit-fork-test]",
        )
        .unwrap();
        module.jit_symbols = Some([].into());
        parent.jit =
            super::super::jit::JitRegistry::test_with_module(module, runtime, &mut parent.unwinder);
        parent.refreshed_uncovered_pages.insert(0x9000);
        for _ in 0..2 {
            let (outcome, sp) = unwind_overlay_frame(&parent.unwinder, &mut parent.cache);
            assert_eq!(outcome.return_address(), Some(0xbbbb));
            assert_eq!(sp, 0x8030);
        }
        assert!(parent.cache.stats().hits() > 0);
        let parent_hits = parent.cache.stats().hits();
        let parent_frame = parent.jit.frame(0x1001).unwrap();

        let mut child = parent.inherit_for_fork();
        assert!(child.jit.frame(0x1001).is_none());
        assert!(child.refreshed_uncovered_pages.is_empty());
        assert_eq!(child.cache.stats().hits(), 0);
        assert_eq!(child.cache.stats().misses(), 0);
        let (outcome, sp) = unwind_overlay_frame(&child.unwinder, &mut child.cache);
        assert_eq!(outcome.return_address(), Some(0xaaaa));
        assert_eq!(sp, 0x8010);
        assert!(outcome.fallback_reason().is_none());

        assert_eq!(parent.cache.stats().hits(), parent_hits);
        assert_eq!(parent.jit.frame(0x1001), Some(parent_frame));
        assert!(parent.refreshed_uncovered_pages.contains(&0x9000));
        let (outcome, sp) = unwind_overlay_frame(&parent.unwinder, &mut parent.cache);
        assert_eq!(outcome.return_address(), Some(0xbbbb));
        assert_eq!(sp, 0x8030);
        assert!(parent.cache.stats().hits() > parent_hits);
    }

    #[test]
    fn fork_reuse_keeps_parent_entry_without_reloading_inherited_module() {
        let pid = crate::Pid::try_from(std::process::id()).unwrap();
        let parent = ModuleRecord {
            jit_symbols: None,
            id: 1,
            owner: ModuleOwner::Process(pid),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: std::env::current_exe().unwrap().into(),
        };
        let mut child = parent.clone();
        child.id = 2;
        let mut elf_sections = ElfSectionCache::default();
        let parent_update = ModuleUpdate {
            active: vec![ModuleActivation {
                module: parent.clone(),
                source_module_id: None,
            }],
            mapping_changed: true,
            ..ModuleUpdate::default()
        };
        let mut parent_unwinder = ProcessUnwinder::default();
        parent_unwinder.apply_module_update(&parent_update, &mut elf_sections);
        assert_eq!(elf_sections.file_parse_count(), 1);
        let mut child_unwinder = parent_unwinder.inherit_for_fork();
        let update = ModuleUpdate {
            active: vec![ModuleActivation {
                module: child,
                source_module_id: Some(parent.id),
            }],
            mapping_changed: true,
            ..ModuleUpdate::default()
        };

        child_unwinder.reuse_inherited_modules(&update, &mut elf_sections);

        assert_eq!(elf_sections.file_parse_count(), 1);
        assert!(elf_sections.contains(parent.id));
        assert!(elf_sections.contains(2));
        assert_eq!(child_unwinder.unwinder.max_known_code_address(), 0x2000);
    }

    #[test]
    fn fork_reuse_retries_missing_parent_entry_under_child_id() {
        let child = ModuleRecord {
            jit_symbols: None,
            id: 2,
            owner: ModuleOwner::Process(crate::Pid::try_from(std::process::id()).unwrap()),
            start: 0x3000,
            end: 0x4000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: std::fs::canonicalize("/bin/true").unwrap().into(),
        };
        let update = ModuleUpdate {
            active: vec![ModuleActivation {
                module: child,
                source_module_id: Some(1),
            }],
            mapping_changed: true,
            ..ModuleUpdate::default()
        };
        let mut elf_sections = ElfSectionCache::default();
        let mut child_unwinder = ProcessUnwinder::default();

        child_unwinder.reuse_inherited_modules(&update, &mut elf_sections);

        assert_eq!(elf_sections.file_parse_count(), 1);
        assert!(!elf_sections.contains(1));
        assert!(elf_sections.contains(2));
        assert_eq!(child_unwinder.unwinder.max_known_code_address(), 0x4000);
    }

    #[test]
    fn only_indexed_eh_frame_headers_are_forwarded() {
        const VERSION: u8 = 1;
        const ABSPTR: u8 = gimli::constants::DW_EH_PE_absptr.0;
        const INDIRECT: u8 = gimli::constants::DW_EH_PE_indirect.0;
        const SDATA4: u8 = gimli::constants::DW_EH_PE_sdata4.0;
        const SDATA8: u8 = gimli::constants::DW_EH_PE_sdata8.0;
        const UDATA4: u8 = gimli::constants::DW_EH_PE_udata4.0;
        const UDATA8: u8 = gimli::constants::DW_EH_PE_udata8.0;
        const OMIT: u8 = gimli::constants::DW_EH_PE_omit.0;
        const EH_FRAME_ADDRESS: u32 = 0x2000;
        const FDE_ADDRESS: u32 = EH_FRAME_ADDRESS + 0x10;
        const INITIAL_LOCATION: u32 = 0x1000;
        const HEADER_ADDRESS: u64 = 0x3000;

        let mut indexed_header = vec![VERSION, SDATA4, UDATA4, SDATA4];
        indexed_header.extend_from_slice(&EH_FRAME_ADDRESS.to_le_bytes());
        indexed_header.extend_from_slice(&1_u32.to_le_bytes());
        indexed_header.extend_from_slice(&INITIAL_LOCATION.to_le_bytes());
        indexed_header.extend_from_slice(&FDE_ADDRESS.to_le_bytes());

        let mut omitted_table = indexed_header.clone();
        omitted_table[2] = OMIT;
        omitted_table[3] = OMIT;
        let mut zero_count = indexed_header.clone();
        zero_count[8..12].copy_from_slice(&0_u32.to_le_bytes());
        let truncated_table = indexed_header[..12].to_vec();
        let mut unsupported_table = indexed_header.clone();
        unsupported_table[3] = ABSPTR;
        let mut indirect_table = indexed_header.clone();
        indirect_table[3] = SDATA4 | INDIRECT;
        let mut out_of_range_fde = indexed_header.clone();
        out_of_range_fde[16..20].copy_from_slice(&(EH_FRAME_ADDRESS - 1).to_le_bytes());
        let mut overflowing_count = vec![VERSION, SDATA4, UDATA8, SDATA8];
        overflowing_count.extend_from_slice(&EH_FRAME_ADDRESS.to_le_bytes());
        overflowing_count.extend_from_slice(&u64::MAX.to_le_bytes());

        let section_info = |header, address| {
            let mut section_info = Arc::unwrap_or_clone(fake_hard_case_section_info());
            section_info.eh_frame_svma = Some(u64::from(EH_FRAME_ADDRESS));
            section_info.eh_frame = Some(ElfSectionData::owned(vec![0; 0x100]));
            section_info.eh_frame_hdr_svma = address;
            section_info.eh_frame_hdr = Some(ElfSectionData::owned(header));
            section_info
        };

        assert!(
            indexed_eh_frame_hdr(&section_info(indexed_header.clone(), Some(HEADER_ADDRESS)))
                .is_some()
        );

        for (name, header, address) in [
            ("omitted", omitted_table, Some(HEADER_ADDRESS)),
            ("zero count", zero_count, Some(HEADER_ADDRESS)),
            ("truncated table", truncated_table, Some(HEADER_ADDRESS)),
            (
                "unsupported encoding",
                unsupported_table,
                Some(HEADER_ADDRESS),
            ),
            ("indirect pointers", indirect_table, Some(HEADER_ADDRESS)),
            ("out-of-range FDE", out_of_range_fde, Some(HEADER_ADDRESS)),
            ("overflowing count", overflowing_count, Some(HEADER_ADDRESS)),
            ("truncated header", vec![VERSION], Some(HEADER_ADDRESS)),
            ("missing section address", indexed_header, None),
        ] {
            assert!(
                indexed_eh_frame_hdr(&section_info(header, address)).is_none(),
                "{name}"
            );
        }
    }
}
