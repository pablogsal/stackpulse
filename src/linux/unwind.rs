use framehop::Unwinder;
use rustc_hash::FxHashSet;
use std::mem::size_of;
use std::ops::Range;

use crate::elf::types::{ElfSectionData, ElfSectionInfo};
use crate::native_module::{ElfSectionCache, LoadedElfMapping};
use crate::spool::{ModuleRecord, ModuleUpdate};

type UnwindPolicy = framehop::MayAllocateDuringUnwind;
pub(super) type NativeUnwinder = framehop::UnwinderNative<ElfSectionData, UnwindPolicy>;
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
            let Some(loaded) = self.elf_sections.load_mapping(module) else {
                continue;
            };
            if let Some(module) = module_to_framehop(module, &loaded) {
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
        crate::path_to_name(module.path.as_path()),
        module.start..module.end,
        image_base.avma,
        explicit_info,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::elf::test_fixtures::fake_hard_case_section_info;

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
