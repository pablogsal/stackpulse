//! Shared ELF segment types and helpers.
//!
//! Provides [`LoadSegment`] plus the helpers the native module loader uses to
//! map a process memory mapping back to its backing `PT_LOAD` segment and to
//! compute the SVMA-to-AVMA image-base bias for that mapping.

mod loader;
#[cfg(test)]
mod test_fixtures;
mod types;

pub(crate) use loader::{load_elf_sections_from_bytes, load_elf_sections_from_file};
#[cfg(test)]
pub(crate) use test_fixtures::fake_hard_case_section_info;
pub(crate) use types::{ElfSectionData, ElfSectionInfo};

use std::sync::OnceLock;

use crate::ModuleImageBase;

/// A PT_LOAD segment from an ELF binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadSegment {
    /// File offset of this segment
    pub(crate) p_offset: u64,
    /// Size of this segment in the file
    pub(crate) p_filesz: u64,
    /// Size of this segment in memory (may exceed p_filesz for BSS)
    pub(crate) p_memsz: u64,
    /// Virtual address of this segment (SVMA)
    pub(crate) p_vaddr: u64,
    /// Segment flags (PF_X = 0x1, PF_W = 0x2, PF_R = 0x4)
    pub(crate) p_flags: u32,
}

impl LoadSegment {
    fn file_range(&self) -> FileRange {
        FileRange::new(self.p_offset, self.p_filesz)
    }

    fn has_file_contribution(&self) -> bool {
        self.file_range().is_valid()
    }

    fn correlates_with_mapping(&self, mapping: FileRange, page_size: PageSize) -> bool {
        if !mapping.is_valid() {
            return false;
        }
        if self.file_range().correlates_with(mapping) {
            return true;
        }

        if !mapping.is_page_aligned(page_size) {
            return false;
        }

        self.contains_page_rounded_head(mapping, page_size)
            || self.contains_page_rounded_tail(mapping, page_size)
    }

    fn contains_page_rounded_head(&self, mapping: FileRange, page_size: PageSize) -> bool {
        let segment = self.file_range();
        let (Some(segment_end), Some(mapping_end)) = (segment.end(), mapping.end()) else {
            return false;
        };
        if !(segment.page_floor_start(page_size) <= mapping.start && mapping.start < segment.start)
        {
            return false;
        }
        segment.start < mapping_end && mapping_end <= segment_end
    }

    fn contains_page_rounded_tail(&self, mapping: FileRange, page_size: PageSize) -> bool {
        let segment = self.file_range();
        let (Some(segment_end), Some(mapping_end), Some(page_ceil_end)) = (
            segment.end(),
            mapping.end(),
            segment.page_ceil_end(page_size),
        ) else {
            return false;
        };
        if !segment.contains_value(mapping.start) {
            return false;
        }

        segment_end < mapping_end && mapping_end <= page_ceil_end
    }
}

#[derive(Clone, Copy)]
struct FileRange {
    start: u64,
    size: u64,
}

impl FileRange {
    fn new(start: u64, size: u64) -> Self {
        Self { start, size }
    }

    fn end(self) -> Option<u64> {
        self.start.checked_add(self.size)
    }

    fn is_valid(self) -> bool {
        self.size != 0 && self.end().is_some()
    }

    fn contains(self, other: Self) -> bool {
        let (Some(end), Some(other_end)) = (self.end(), other.end()) else {
            return false;
        };
        self.size != 0 && other.size != 0 && self.start <= other.start && other_end <= end
    }

    fn contains_value(self, value: u64) -> bool {
        self.end()
            .is_some_and(|end| self.start <= value && value < end)
    }

    fn correlates_with(self, other: Self) -> bool {
        self.contains(other) || other.contains(self)
    }

    fn is_page_aligned(self, page_size: PageSize) -> bool {
        self.start.is_multiple_of(page_size.0)
            && self.size >= page_size.0
            && self.size.is_multiple_of(page_size.0)
    }

    fn page_floor_start(self, page_size: PageSize) -> u64 {
        page_size.align_down(self.start)
    }

    fn page_ceil_end(self, page_size: PageSize) -> Option<u64> {
        self.end().and_then(|end| page_size.align_up(end))
    }
}

#[derive(Clone, Copy)]
struct PageSize(u64);

impl PageSize {
    fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    fn align_down(self, value: u64) -> u64 {
        value - value % self.0
    }

    fn align_up(self, value: u64) -> Option<u64> {
        let remainder = value % self.0;
        if remainder == 0 {
            Some(value)
        } else {
            value.checked_add(self.0 - remainder)
        }
    }
}

/// Find the PT_LOAD segment whose file contribution should be used as the
/// reference for computing an image-wide AVMA bias for an executable mapping.
///
fn find_load_contribution_for_file_range(
    segments: &[LoadSegment],
    file_off: u64,
    mapping_span: u64,
) -> Option<&LoadSegment> {
    find_load_contribution_for_file_range_with_page_size(
        segments,
        file_off,
        mapping_span,
        system_page_size(),
    )
}

/// Variant of [`find_load_contribution_for_file_range`] with an explicit page
/// size, useful for off-host inputs and deterministic tests.
fn find_load_contribution_for_file_range_with_page_size(
    segments: &[LoadSegment],
    file_off: u64,
    mapping_span: u64,
    page_size: u64,
) -> Option<&LoadSegment> {
    let page_size = PageSize::new(page_size)?;
    let mapping = FileRange::new(file_off, mapping_span);
    let mut exact = None;
    let mut exact_bias = None;
    let mut exact_ambiguous = false;
    let mut fallback = None;
    let mut fallback_bias = None;
    let mut fallback_ambiguous = false;

    for segment in segments
        .iter()
        .filter(|segment| segment.has_file_contribution())
    {
        if !segment.correlates_with_mapping(mapping, page_size) {
            continue;
        }

        // Different PT_LOAD entries may both be contained by one coarse
        // mapping. They are interchangeable only when they describe the same
        // image-wide SVMA/file-offset relationship.
        let bias = i128::from(segment.p_vaddr) - i128::from(segment.p_offset);
        let is_exact = segment.p_offset == file_off && segment.file_range().contains(mapping);
        let (candidate, candidate_bias, ambiguous) = if is_exact {
            (&mut exact, &mut exact_bias, &mut exact_ambiguous)
        } else {
            (&mut fallback, &mut fallback_bias, &mut fallback_ambiguous)
        };
        match *candidate_bias {
            None => {
                *candidate = Some(segment);
                *candidate_bias = Some(bias);
            }
            Some(previous_bias) if previous_bias != bias => *ambiguous = true,
            Some(_) => {}
        }
    }

    let cross_bucket_ambiguous = exact_bias
        .zip(fallback_bias)
        .is_some_and(|(exact, fallback)| exact != fallback);
    if exact_ambiguous || fallback_ambiguous || cross_bucket_ambiguous {
        None
    } else if exact.is_some() {
        exact
    } else {
        fallback
    }
}

const DEFAULT_PAGE_SIZE: u64 = 0x1000;

pub(crate) fn system_page_size() -> u64 {
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

/// Compute the SVMA-to-AVMA bias from a known reference point.
///
/// Given a reference whose file offset and SVMA are known, together with the
/// mapping's start file offset and start AVMA, returns the bias such that
/// `svma + bias == avma` for any address in the image.
fn compute_vma_bias(
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

    /// Real Rust PIE layout (from `rustc -g -C opt-level=0`).
    /// Key property: non-uniform bias (p_vaddr - p_offset differs per segment).
    fn rust_pie_segments() -> Vec<LoadSegment> {
        let mut read_only = seg(0, 0x13c04, 0x13c04, 0);
        read_only.p_flags = 0x4;
        let executable = seg(0x13c10, 0x400b0, 0x400b0, 0x14c10);
        let mut read_write = seg(0x53cc0, 0x02e98, 0x03340, 0x55cc0);
        read_write.p_flags = 0x6;
        let mut read_write_bss = seg(0x56b58, 0x009c0, 0x00a98, 0x59b58);
        read_write_bss.p_flags = 0x6;
        vec![read_only, executable, read_write, read_write_bss]
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

    #[test]
    fn test_find_load_contribution_for_file_range_prefers_containing_segment() {
        let segs = rust_pie_segments();

        let matched = find_load_contribution_for_file_range(&segs, 0x13000, 0x41000).unwrap();
        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_find_load_contribution_rejects_ambiguous_shared_page_head() {
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

        assert!(find_load_contribution_for_file_range(&segs, 0x0, 0x1000).is_none());
    }

    #[test]
    fn test_find_load_contribution_rejects_cross_bucket_ambiguity() {
        let segs = vec![
            seg(0, 0x3000, 0x3000, 0),
            seg(0x1000, 0x1000, 0x1000, 0x5000),
        ];

        assert!(find_load_contribution_for_file_range_with_page_size(
            &segs, 0x1000, 0x1000, 0x1000,
        )
        .is_none());
    }

    #[test]
    fn test_find_load_contribution_accepts_non_pf_x_mapping_made_executable() {
        let mut segment = seg(0x2000, 0x1000, 0x1000, 0x3000);
        segment.p_flags = 0x6;
        let segments = [segment];

        let matched =
            find_load_contribution_for_file_range_with_page_size(&segments, 0x2000, 0x1000, 0x1000)
                .unwrap();

        assert_eq!(matched.p_offset, 0x2000);
    }

    #[test]
    fn test_find_load_contribution_ignores_zero_file_size_segments() {
        let segs = vec![
            seg(0x1000, 0x1000, 0x1000, 0x2000),
            seg(0x1000, 0, 0x1000, 0x5000),
        ];

        let matched =
            find_load_contribution_for_file_range_with_page_size(&segs, 0x1000, 0x1000, 0x1000)
                .unwrap();

        assert_eq!(matched.p_vaddr, 0x2000);
    }

    #[test]
    fn test_find_load_contribution_rejects_overflowing_file_ranges() {
        let segment_start = u64::MAX - 0xfff;
        let segs = vec![seg(segment_start, 0x2000, 0x2000, segment_start)];

        assert!(find_load_contribution_for_file_range_with_page_size(
            &segs,
            segment_start,
            0x1000,
            0x1000,
        )
        .is_none());
    }

    #[test]
    fn test_find_load_contribution_uses_broad_correlation_as_fallback() {
        let segs = vec![LoadSegment {
            p_offset: 0x20_000,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_vaddr: 0x30_000,
            p_flags: 0x5,
        }];

        let matched = find_load_contribution_for_file_range(&segs, 0x0, 0x30_000).unwrap();
        assert_eq!(matched.p_offset, 0x20_000);
    }

    #[test]
    fn test_find_load_contribution_rejects_multiple_contained_segment_biases() {
        let segs = vec![
            seg(0x1000, 0x1000, 0x1000, 0x3000),
            seg(0x3000, 0x1000, 0x1000, 0x7000),
        ];

        assert!(
            find_load_contribution_for_file_range_with_page_size(&segs, 0, 0x5000, 0x1000,)
                .is_none()
        );
    }

    #[test]
    fn test_find_load_contribution_accepts_equivalent_contained_segments() {
        let segs = vec![
            seg(0x1000, 0x1000, 0x1000, 0x3000),
            seg(0x3000, 0x1000, 0x1000, 0x5000),
        ];

        let matched =
            find_load_contribution_for_file_range_with_page_size(&segs, 0, 0x5000, 0x1000).unwrap();
        assert_eq!(matched.p_offset, 0x1000);
    }

    #[test]
    fn test_find_load_contribution_for_large_zero_offset_mapping() {
        let segs = vec![seg(0x0, 0x1661_3000, 0x1661_3000, 0x0)];

        let matched = find_load_contribution_for_file_range(&segs, 0x0, 0x1661_3000).unwrap();
        assert_eq!(matched.p_offset, 0x0);

        let mapping_start = 0x7f61_4879_9000;
        let bias = compute_vma_bias(matched.p_offset, matched.p_vaddr, 0x0, mapping_start);
        assert_eq!(0_u64.wrapping_add(bias), mapping_start);
    }

    #[test]
    fn test_image_relative_address_matches_mapping_relative_address() {
        let segs = vec![seg(0x0, 0x1661_3000, 0x1661_3000, 0x0)];
        let mapping_start = 0x7f61_4879_9000;
        let sampled_ip = mapping_start + 0x8ce_4ea0;

        let matched = find_load_contribution_for_file_range(&segs, 0x0, 0x1661_3000).unwrap();
        let image_base = compute_vma_bias(matched.p_offset, matched.p_vaddr, 0x0, mapping_start);
        let image_rel = sampled_ip - image_base;
        let mapping_rel = sampled_ip - mapping_start;

        assert_eq!(image_rel, mapping_rel);
    }

    #[test]
    fn test_find_load_contribution_uses_page_aligned_segment_start() {
        let segs = rust_pie_segments();

        let matched =
            find_load_contribution_for_file_range_with_page_size(&segs, 0x13000, 0x41000, 0x1000)
                .unwrap();

        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_find_load_contribution_uses_16k_page_alignment() {
        let segs = rust_pie_segments();

        let matched =
            find_load_contribution_for_file_range_with_page_size(&segs, 0x10000, 0x44000, 0x4000)
                .unwrap();

        assert_eq!(matched.p_offset, 0x13c10);
    }

    #[test]
    fn test_find_load_contribution_rejects_ambiguous_64k_shared_page() {
        let segs = rust_pie_segments();

        assert!(find_load_contribution_for_file_range_with_page_size(
            &segs, 0x10000, 0x10000, 0x10000,
        )
        .is_none());
    }

    #[test]
    fn test_find_load_contribution_rejects_zero_page_size() {
        let segs = rust_pie_segments();

        assert!(
            find_load_contribution_for_file_range_with_page_size(&segs, 0x0, 0x1000, 0).is_none()
        );
    }

    #[test]
    fn test_find_load_contribution_accepts_page_rounded_segment_tail() {
        let segs = vec![seg(0, 0x6ab3768, 0x6ab3768, 0x400000)];

        let matched = find_load_contribution_for_file_range_with_page_size(
            &segs, 0x26e0000, 0x43d4000, 0x1000,
        )
        .unwrap();
        assert_eq!(matched.p_offset, 0);
    }

    #[test]
    fn test_find_load_contribution_accepts_page_rounded_tail_shared_with_next_segment() {
        let executable = seg(0, 0x6a65248, 0x6a65248, 0x400000);
        let mut read_write = seg(0x6a65380, 0x1000, 0x2000, 0x6aa6380);
        read_write.p_flags = 0x6;
        let segs = vec![executable, read_write];

        let matched =
            find_load_contribution_for_file_range_with_page_size(&segs, 0x6a64000, 0x2000, 0x1000)
                .unwrap();

        assert_eq!(matched.p_offset, 0);
    }

    #[test]
    fn test_find_load_contribution_rejects_ambiguous_executable_shared_page_head() {
        let segs = rust_pie_segments();

        assert!(find_load_contribution_for_file_range_with_page_size(
            &segs, 0x13000, 0x1000, 0x1000,
        )
        .is_none());
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
