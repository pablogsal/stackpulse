//! ELF sections and image-base resolution for the recorder and symbolizer.

mod loader;
#[cfg(test)]
mod test_fixtures;
mod types;

pub(crate) use loader::{load_elf_sections_from_bytes, load_elf_sections_from_file};
use stackpulse_jit::elf::{compute_vma_bias, find_load_contribution_for_file_range, FileRange};
pub(crate) use stackpulse_jit::elf::{system_page_size, LoadSegment};
#[cfg(test)]
pub(crate) use test_fixtures::fake_hard_case_section_info;
pub(crate) use types::{ElfSectionData, ElfSectionInfo};

use crate::module_base::ModuleImageBase;

#[derive(Clone, Copy)]
struct ImageReference {
    svma: u64,
    file_offset: u64,
}

pub(crate) fn resolve_mapping_image_base(
    info: &ElfSectionInfo,
    mapping_start_file_offset: u64,
    mapping_start_avma: u64,
    mapping_span: u64,
) -> Option<ModuleImageBase> {
    let reference = find_load_contribution_for_file_range(
        &info.load_segments,
        mapping_start_file_offset,
        mapping_span,
    )
    .map(|segment| ImageReference {
        svma: segment.p_vaddr,
        file_offset: segment.p_offset,
    })
    .or_else(|| {
        info.load_segments.is_empty().then(|| {
            let text_svma = info.text_svma.as_ref()?;
            let text_file_range = info.text_file_range.as_ref()?;
            let text_size = text_file_range.end.saturating_sub(text_file_range.start);
            FileRange::new(text_file_range.start, text_size)
                .correlates_with(FileRange::new(mapping_start_file_offset, mapping_span))
                .then_some(ImageReference {
                    svma: text_svma.start,
                    file_offset: text_file_range.start,
                })
        })?
    })?;
    let image_bias = compute_vma_bias(
        reference.file_offset,
        reference.svma,
        mapping_start_file_offset,
        mapping_start_avma,
    );
    Some(ModuleImageBase::new(
        info.base_svma.wrapping_add(image_bias),
        info.base_svma,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::fake_hard_case_section_info;

    fn seg(p_offset: u64, p_filesz: u64, p_memsz: u64, p_vaddr: u64) -> LoadSegment {
        LoadSegment {
            p_offset,
            p_filesz,
            p_memsz,
            p_vaddr,
            p_flags: 0x5, // PF_R | PF_X
        }
    }

    fn section_info(
        text_svma: Option<std::ops::Range<u64>>,
        text_file_range: Option<std::ops::Range<u64>>,
        load_segments: Vec<LoadSegment>,
    ) -> ElfSectionInfo {
        ElfSectionInfo {
            base_svma: 0,
            text_svma,
            text_file_range,
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: load_segments.into_boxed_slice(),
        }
    }

    #[test]
    fn test_resolve_mapping_matches_samply_hard_case() {
        let resolved = resolve_mapping_image_base(
            &fake_hard_case_section_info(),
            0x14bd000,
            0x55d605384000,
            0xf5d000,
        );
        assert_eq!(resolved, Some(ModuleImageBase::new(0x55d603ec6000, 0)));
    }

    #[test]
    fn test_resolve_mapping_uses_zero_offset_load_for_large_mapping() {
        let info = section_info(
            Some(0x0..0x1661_3000),
            Some(0x0..0x1661_3000),
            vec![seg(0, 0x1661_3000, 0x1661_3000, 0)],
        );
        let mapping_start = 0x7f61_4879_9000;

        let resolved = resolve_mapping_image_base(&info, 0, mapping_start, 0x1661_3000);

        assert_eq!(resolved, Some(ModuleImageBase::new(mapping_start, 0)));
    }

    #[test]
    fn test_resolve_mapping_falls_back_to_text_section() {
        let info = section_info(Some(0x4000..0x5000), Some(0x3000..0x4000), Vec::new());

        let resolved = resolve_mapping_image_base(&info, 0x3000, 0x7f00_1000, 0x1000);

        assert_eq!(resolved, Some(ModuleImageBase::new(0x7eff_d000, 0)));
    }

    #[test]
    fn test_resolve_mapping_does_not_guess_from_page_overlap() {
        let info = section_info(
            Some(0x23c10..0x24c10),
            Some(0x13c10..0x14c10),
            vec![seg(0x13c10, 0x1000, 0x1000, 0x23c10)],
        );

        let resolved = resolve_mapping_image_base(&info, 0x13000, 0x5555_5556_8000, 0x800);

        assert_eq!(resolved, None);
    }
}
