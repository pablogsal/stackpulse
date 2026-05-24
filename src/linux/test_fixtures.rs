//! Shared test fixtures for Linux ELF module tests.

use super::elf_types::{ElfSectionData, ElfSectionInfo};
use crate::elf::LoadSegment;
use std::sync::Arc;

/// Section info with a single write-only segment where `p_offset > p_vaddr`,
/// exercising the underflow path in base-address calculation.
pub fn fake_underflow_section_info() -> Arc<ElfSectionInfo> {
    Arc::new(ElfSectionInfo {
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
            p_offset: 0x11b000,
            p_filesz: 0x6878,
            p_memsz: 0x6878,
            p_vaddr: 0x11a000,
            p_flags: 0x2, // PF_W
        }]
        .into_boxed_slice(),
    })
}

/// Section info for a simple executable with text, eh_frame, and GOT sections.
pub fn fake_exec_section_info() -> Arc<ElfSectionInfo> {
    Arc::new(ElfSectionInfo {
        base_svma: 0,
        text_svma: Some(0x1000..0x2000),
        text_file_range: Some(0x1000..0x2000),
        text: Some(ElfSectionData::owned(vec![0u8; 0x1000])),
        eh_frame_svma: Some(0x3000),
        eh_frame: Some(ElfSectionData::owned(vec![0u8; 64])),
        eh_frame_hdr_svma: Some(0x3100),
        eh_frame_hdr: Some(ElfSectionData::owned(vec![0u8; 32])),
        got_svma: Some(0x4000..0x4100),
        load_segments: vec![LoadSegment {
            p_offset: 0,
            p_filesz: 0x5000,
            p_memsz: 0x5000,
            p_vaddr: 0,
            p_flags: 0x5, // PF_R | PF_X
        }]
        .into_boxed_slice(),
    })
}

/// Hard-case section info with 4 segments and non-zero text offsets,
/// matching the samply hard-case test scenario.
pub fn fake_hard_case_section_info() -> Arc<ElfSectionInfo> {
    Arc::new(ElfSectionInfo {
        base_svma: 0,
        text_svma: Some(0x14be0c0..(0x14be0c0 + 0xf5bf60)),
        text_file_range: Some(0x14bd0c0..(0x14bd0c0 + 0xf5bf60)),
        text: None,
        eh_frame_svma: None,
        eh_frame: None,
        eh_frame_hdr_svma: None,
        eh_frame_hdr: None,
        got_svma: None,
        load_segments: vec![
            LoadSegment {
                p_offset: 0x0,
                p_filesz: 0x14bd0bc,
                p_memsz: 0x14bd0bc,
                p_vaddr: 0x0,
                p_flags: 0x4,
            },
            LoadSegment {
                p_offset: 0x14bd0c0,
                p_filesz: 0xf5bf60,
                p_memsz: 0xf5bf60,
                p_vaddr: 0x14be0c0,
                p_flags: 0x5,
            },
            LoadSegment {
                p_offset: 0x2419020,
                p_filesz: 0x08e920,
                p_memsz: 0x08e920,
                p_vaddr: 0x241b020,
                p_flags: 0x4,
            },
            LoadSegment {
                p_offset: 0x24a7940,
                p_filesz: 0x002d48,
                p_memsz: 0x002d48,
                p_vaddr: 0x24aa940,
                p_flags: 0x6,
            },
        ]
        .into_boxed_slice(),
    })
}
