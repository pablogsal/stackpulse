//! Shared ELF segment types and helpers.
//!
//! Provides [`LoadSegment`] plus the helpers the native module loader uses to
//! map a process memory mapping back to its backing `PT_LOAD` segment and to
//! compute the SVMA-to-AVMA image-base bias for that mapping.

use goblin::elf::program_header::PT_LOAD;
use goblin::elf::Elf;

/// A PT_LOAD segment from an ELF binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadSegment {
    /// File offset of this segment
    pub p_offset: u64,
    /// Size of this segment in the file
    pub p_filesz: u64,
    /// Size of this segment in memory (may exceed p_filesz for BSS)
    pub p_memsz: u64,
    /// Virtual address of this segment (SVMA)
    pub p_vaddr: u64,
    /// Segment flags (PF_X = 0x1, PF_W = 0x2, PF_R = 0x4)
    pub p_flags: u32,
}

/// Collect PT_LOAD segments from an ELF, sorted by file offset.
pub fn collect_load_segments(elf: &Elf) -> Vec<LoadSegment> {
    let mut segments: Vec<LoadSegment> = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| LoadSegment {
            p_offset: ph.p_offset,
            p_filesz: ph.p_filesz,
            p_memsz: ph.p_memsz,
            p_vaddr: ph.p_vaddr,
            p_flags: ph.p_flags,
        })
        .collect();
    segments.sort_by_key(|s| s.p_offset);
    segments
}

/// Find the PT_LOAD segment whose file contribution should be used as the
/// reference for computing an image-wide AVMA bias for a mapping.
///
/// This deliberately does not use simple overlap. A mapping can be larger than
/// the file-backed part of the segment due to alignment or BSS, and some real
/// systems expose partial mappings of a segment. We therefore accept either:
/// - the segment fully containing the mapping's file range, or
/// - the mapping's file range fully containing the segment's file range.
pub fn find_load_contribution_for_file_range(
    segments: &[LoadSegment],
    file_off: u64,
    mapping_span: u64,
) -> Option<&LoadSegment> {
    segments
        .iter()
        .rev()
        .find(|seg| file_ranges_correlate(seg.p_offset, seg.p_filesz, file_off, mapping_span))
}

/// Check whether two file ranges mutually contain each other (either A
/// contains B or B contains A).
pub fn file_ranges_correlate(a_start: u64, a_size: u64, b_start: u64, b_size: u64) -> bool {
    let a_end = a_start.saturating_add(a_size);
    let b_end = b_start.saturating_add(b_size);
    (a_start <= b_start && b_end <= a_end) || (b_start <= a_start && a_end <= b_end)
}

/// Compute the SVMA-to-AVMA bias from a known reference point.
///
/// Given a reference whose file offset and SVMA are known, together with the
/// mapping's start file offset and start AVMA, returns the bias such that
/// `svma + bias == avma` for any address in the image.
pub fn compute_vma_bias(
    reference_file_offset: u64,
    reference_svma: u64,
    mapping_start_file_offset: u64,
    mapping_start_avma: u64,
) -> u64 {
    // Use wrapping arithmetic throughout: the intermediate values and final
    // bias are all valid as wrapping u64 since SVMA-to-AVMA biases can be
    // negative when viewed as unsigned.
    let file_delta = reference_file_offset.wrapping_sub(mapping_start_file_offset);
    let reference_avma = mapping_start_avma.wrapping_add(file_delta);
    reference_avma.wrapping_sub(reference_svma)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(p_offset: u64, p_filesz: u64, p_memsz: u64, p_vaddr: u64) -> LoadSegment {
        LoadSegment {
            p_offset,
            p_filesz,
            p_memsz,
            p_vaddr,
            p_flags: 0x5, // PF_R | PF_X
        }
    }

    /// Real Rust PIE layout (from `rustc -g -C opt-level=0`).
    /// Key property: non-uniform bias (p_vaddr - p_offset differs per segment).
    fn rust_pie_segments() -> Vec<LoadSegment> {
        vec![
            seg(0x0000000000000000, 0x13c04, 0x13c04, 0x0000000000000000), // R
            seg(0x0000000000013c10, 0x400b0, 0x400b0, 0x0000000000014c10), // R E
            seg(0x0000000000053cc0, 0x02e98, 0x03340, 0x0000000000055cc0), // RW
            seg(0x0000000000056b58, 0x009c0, 0x00a98, 0x0000000000059b58), // RW
        ]
    }

    #[test]
    fn test_find_load_contribution_for_file_range_prefers_containing_segment() {
        let segs = rust_pie_segments();

        let matched = find_load_contribution_for_file_range(&segs, 0x13000, 0x41000).unwrap();
        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_find_load_contribution_for_file_range_prefers_later_contained_segment() {
        let segs = vec![
            LoadSegment {
                p_offset: 0x0,
                p_filesz: 0x900,
                p_memsz: 0x900,
                p_vaddr: 0x0,
                p_flags: 0x4,
            },
            LoadSegment {
                p_offset: 0x900,
                p_filesz: 0x3b0,
                p_memsz: 0x3b0,
                p_vaddr: 0x1900,
                p_flags: 0x5,
            },
        ];

        let matched = find_load_contribution_for_file_range(&segs, 0x0, 0x1000).unwrap();
        assert_eq!(matched.p_offset, 0x900);

        // The bias derived from the matched contribution must map SVMA 0 to the
        // expected image-base AVMA.
        let bias = compute_vma_bias(matched.p_offset, matched.p_vaddr, 0x0, 0x5555_5555_5000);
        assert_eq!(0_u64.wrapping_add(bias), 0x5555_5555_4000);
    }

    #[test]
    fn test_find_load_contribution_rejects_page_overlap_guess() {
        // A short mapping that only page-overlaps the segment (its file range
        // neither contains nor is contained by the segment's) must not be
        // attributed to that segment.
        let segs = vec![LoadSegment {
            p_offset: 0x13c10,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_vaddr: 0x23c10,
            p_flags: 0x5,
        }];

        assert!(find_load_contribution_for_file_range(&segs, 0x13000, 0x800).is_none());
    }
}
