//! Shared ELF segment types and helpers.
//!
//! This module provides [`LoadSegment`] and [`find_load_segment_for_file_offset`],
//! used by both the native engine (module loading, framehop base computation)
//! and the Python engine (PyRuntime address resolution from core files).

use goblin::elf::program_header::PT_LOAD;
use goblin::elf::Elf;
use std::sync::OnceLock;

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

/// Find the PT_LOAD segment that backs a memory mapping at the given file offset.
///
/// The Linux kernel page-aligns segment boundaries when creating memory mappings,
/// so a mapping's `file_off_start` may be *before* the segment's raw `p_offset`.
/// For example, with segments at offsets 0x0 (size 0x13c04) and 0x13c10, the kernel
/// creates the code mapping at page-aligned offset 0x13000 — which falls inside
/// the first segment's raw range but actually belongs to the second segment.
///
/// # Matching invariant
///
/// A mapping at `file_off` is backed by segment `S` when:
///   `page_floor(S.p_offset) <= file_off < page_ceil(S.p_offset + S.p_memsz)`
///
/// When two segments share a page boundary (their page-aligned ranges overlap),
/// the segment with the larger `page_floor(p_offset)` wins. Since segments are
/// sorted by `p_offset`, reverse iteration returns the most-specific match.
///
/// Uses the current host's runtime page size when evaluating page-aligned
/// segment ranges.
pub fn find_load_segment_for_file_offset(
    segments: &[LoadSegment],
    file_off: u64,
) -> Option<&LoadSegment> {
    find_load_segment_for_file_offset_pagesz(segments, file_off, system_page_size())
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
        .find(|seg| file_ranges_correlate(seg.p_offset, seg.p_filesz, file_off, mapping_span))
}

/// Compute the SVMA-to-AVMA bias for a mapping using the matching PT_LOAD
/// contribution from the ELF image.
///
/// The returned bias is image-wide: adding it to the ELF image's base SVMA
/// yields the actual image base AVMA in the target process.
pub fn compute_vma_bias_for_mapping_strict(
    segments: &[LoadSegment],
    mapping_start_file_offset: u64,
    mapping_start_avma: u64,
    mapping_span: u64,
) -> Option<u64> {
    let seg =
        find_load_contribution_for_file_range(segments, mapping_start_file_offset, mapping_span)?;
    Some(compute_vma_bias_for_load_segment(
        seg,
        mapping_start_file_offset,
        mapping_start_avma,
    ))
}

const DEFAULT_PAGE_SIZE: u64 = 0x1000;

fn system_page_size() -> u64 {
    static PAGE_SIZE: OnceLock<u64> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size > 0 {
            page_size as u64
        } else {
            DEFAULT_PAGE_SIZE
        }
    })
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

fn compute_vma_bias_for_load_segment(
    seg: &LoadSegment,
    mapping_start_file_offset: u64,
    mapping_start_avma: u64,
) -> u64 {
    compute_vma_bias(
        seg.p_offset,
        seg.p_vaddr,
        mapping_start_file_offset,
        mapping_start_avma,
    )
}

/// Inner implementation with explicit page size (for testing with non-4K pages).
fn find_load_segment_for_file_offset_pagesz(
    segments: &[LoadSegment],
    file_off: u64,
    page_size: u64,
) -> Option<&LoadSegment> {
    let page_mask = !(page_size - 1);

    // Segments are sorted by p_offset ascending. Walk backwards so that
    // when two segments share a page boundary, the later segment (more
    // specific match) wins.
    segments.iter().rev().find(|seg| {
        let seg_page_start = seg.p_offset & page_mask;
        let seg_page_end = (seg.p_offset + seg.p_memsz + page_size - 1) & page_mask;
        file_off >= seg_page_start && file_off < seg_page_end
    })
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

    /// Real C PIE layout (from `cc -g -O0`).
    /// Key property: uniform bias for R/RE/R segments (p_vaddr == p_offset).
    fn c_pie_segments() -> Vec<LoadSegment> {
        vec![
            seg(0x000, 0x5a8, 0x5a8, 0x000),   // R
            seg(0x1000, 0x2c2, 0x2c2, 0x1000), // R E
            seg(0x2000, 0x1a0, 0x1a0, 0x2000), // R
            seg(0x2e00, 0x224, 0x240, 0x3e00), // RW (non-uniform bias here)
        ]
    }

    #[test]
    fn test_rust_pie_code_mapping_at_page_boundary() {
        let segs = rust_pie_segments();
        let matched = find_load_segment_for_file_offset(&segs, 0x13000).unwrap();
        assert_eq!(
            matched.p_offset, 0x13c10,
            "must match the code segment, not the read-only one"
        );
        assert_eq!(
            matched.p_vaddr - matched.p_offset,
            0x1000,
            "code segment bias must be 0x1000"
        );
    }

    #[test]
    fn test_rust_pie_readonly_mapping() {
        let segs = rust_pie_segments();
        let matched = find_load_segment_for_file_offset(&segs, 0x0).unwrap();
        assert_eq!(matched.p_offset, 0x0);
    }

    #[test]
    fn test_rust_pie_data_mappings() {
        let segs = rust_pie_segments();

        let matched = find_load_segment_for_file_offset(&segs, 0x53000).unwrap();
        assert_eq!(matched.p_offset, 0x53cc0);

        let matched = find_load_segment_for_file_offset(&segs, 0x56000).unwrap();
        assert_eq!(matched.p_offset, 0x56b58);
    }

    #[test]
    fn test_rust_pie_mid_segment_offsets() {
        let segs = rust_pie_segments();

        let matched = find_load_segment_for_file_offset(&segs, 0x8000).unwrap();
        assert_eq!(matched.p_offset, 0x0);

        let matched = find_load_segment_for_file_offset(&segs, 0x20000).unwrap();
        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_c_pie_uniform_bias() {
        let segs = c_pie_segments();
        // These segments come from a real Linux C binary with 4 KiB pages.
        let find = |off| find_load_segment_for_file_offset_pagesz(&segs, off, 0x1000);

        let matched = find(0x0).unwrap();
        assert_eq!(matched.p_offset, 0x0);

        let matched = find(0x1000).unwrap();
        assert_eq!(matched.p_offset, 0x1000);

        let matched = find(0x2000).unwrap();
        assert!(
            matched.p_offset == 0x2000 || matched.p_offset == 0x2e00,
            "ambiguous case: either segment is acceptable"
        );
    }

    #[test]
    fn test_file_offset_past_all_segments_returns_none() {
        let segs = rust_pie_segments();
        assert!(find_load_segment_for_file_offset(&segs, 0x1000000).is_none());
    }

    #[test]
    fn test_empty_segments_returns_none() {
        assert!(find_load_segment_for_file_offset(&[], 0x1000).is_none());
    }

    #[test]
    fn test_single_segment() {
        let segs = vec![seg(0x0, 0x5000, 0x5000, 0x0)];
        let find = |off| find_load_segment_for_file_offset_pagesz(&segs, off, 0x1000);

        assert_eq!(find(0x0).unwrap().p_offset, 0x0);
        assert_eq!(find(0x4000).unwrap().p_offset, 0x0);
        assert!(find(0x5000).is_none());
    }

    #[test]
    fn test_bss_memsz_extends_range() {
        let segs = vec![seg(0x1000, 0x100, 0x2000, 0x1000)];
        let find = |off| find_load_segment_for_file_offset_pagesz(&segs, off, 0x1000);

        let matched = find(0x2000);
        assert!(matched.is_some(), "BSS region must be covered by memsz");

        assert!(find(0x3000).is_none());
    }

    #[test]
    fn test_16k_pages_non_uniform_bias() {
        let segs = rust_pie_segments();
        let matched = find_load_segment_for_file_offset_pagesz(&segs, 0x10000, 0x4000).unwrap();
        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_16k_pages_separates_segments() {
        let segs = rust_pie_segments();
        let matched = find_load_segment_for_file_offset_pagesz(&segs, 0x0, 0x4000).unwrap();
        assert_eq!(matched.p_offset, 0x0);

        let matched = find_load_segment_for_file_offset_pagesz(&segs, 0x10000, 0x4000).unwrap();
        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_64k_pages_shared_page_ambiguity() {
        let segs = rust_pie_segments();
        let matched = find_load_segment_for_file_offset_pagesz(&segs, 0x0, 0x10000).unwrap();
        assert_eq!(matched.p_offset, 0x0);

        let matched = find_load_segment_for_file_offset_pagesz(&segs, 0x10000, 0x10000).unwrap();
        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_bias_computation_with_matched_segment() {
        let segs = rust_pie_segments();

        let file_off: u64 = 0x13000;
        let avma_start: u64 = 0x555555568000;
        let seg = find_load_segment_for_file_offset(&segs, file_off).unwrap();
        let base_avma = avma_start - file_off;
        let base_svma = seg.p_vaddr - seg.p_offset;

        let entry_svma: u64 = 0x14c10;
        let entry_avma = entry_svma - base_svma + base_avma;
        assert_eq!(entry_avma, 0x555555568c10, "entry point AVMA");

        let computed_svma = entry_avma - base_avma + base_svma;
        assert_eq!(computed_svma, entry_svma, "round-trip SVMA must match");
    }

    #[test]
    fn test_find_load_contribution_for_file_range_prefers_containing_segment() {
        let segs = rust_pie_segments();

        let matched = find_load_contribution_for_file_range(&segs, 0x13000, 0x41000).unwrap();
        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_compute_vma_bias_for_mapping_strict_rejects_page_overlap_guess() {
        let segs = vec![LoadSegment {
            p_offset: 0x13c10,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_vaddr: 0x23c10,
            p_flags: 0x5,
        }];

        let strict = compute_vma_bias_for_mapping_strict(&segs, 0x13000, 0x5555_5556_8000, 0x800);
        assert_eq!(strict, None);
    }
}
