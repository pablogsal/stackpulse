//! Shared ELF section data and metadata types.

use memmap2::Mmap;
use std::fmt;
use std::ops::Deref;
use std::ops::Range;
use std::sync::Arc;

pub use super::LoadSegment;

#[derive(Clone)]
pub struct ElfSectionData {
    storage: ElfSectionStorage,
    range: Range<usize>,
}

#[derive(Clone)]
enum ElfSectionStorage {
    Owned(Arc<[u8]>),
    Mmap(Arc<Mmap>),
}

impl ElfSectionData {
    #[must_use]
    pub fn owned(data: impl Into<Arc<[u8]>>) -> Self {
        let data = data.into();
        Self {
            range: 0..data.len(),
            storage: ElfSectionStorage::Owned(data),
        }
    }

    pub(crate) fn owned_range(data: Arc<[u8]>, range: Range<usize>) -> Option<Self> {
        (range.start <= range.end && range.end <= data.len()).then_some(Self {
            storage: ElfSectionStorage::Owned(data),
            range,
        })
    }

    pub(crate) fn mmap(mmap: Arc<Mmap>, range: Range<usize>) -> Option<Self> {
        (range.start <= range.end && range.end <= mmap.len()).then_some(Self {
            storage: ElfSectionStorage::Mmap(mmap),
            range,
        })
    }
}

impl Deref for ElfSectionData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match &self.storage {
            ElfSectionStorage::Owned(data) => &data[self.range.clone()],
            ElfSectionStorage::Mmap(mmap) => &mmap[self.range.clone()],
        }
    }
}

impl AsRef<[u8]> for ElfSectionData {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl fmt::Debug for ElfSectionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfSectionData")
            .field("len", &self.len())
            .finish()
    }
}

impl PartialEq for ElfSectionData {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Eq for ElfSectionData {}

/// ELF section addresses and data needed for DWARF unwinding.
///
/// `eh_frame` and `eh_frame_hdr` clone cheaply so multiple mappings of the same
/// library share storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSectionInfo {
    /// Base stated virtual address from the first PT_LOAD segment.
    pub base_svma: u64,

    /// .text section range (SVMA)
    pub text_svma: Option<Range<u64>>,

    /// .text section range in file-offset space.
    pub text_file_range: Option<Range<u64>>,

    /// .text section data.
    pub text: Option<ElfSectionData>,

    /// .eh_frame section address (SVMA)
    pub eh_frame_svma: Option<u64>,

    /// .eh_frame section data
    pub eh_frame: Option<ElfSectionData>,

    /// .eh_frame_hdr section address (SVMA)
    pub eh_frame_hdr_svma: Option<u64>,

    /// .eh_frame_hdr section data
    pub eh_frame_hdr: Option<ElfSectionData>,

    /// .got section range (SVMA)
    pub got_svma: Option<Range<u64>>,

    /// PT_LOAD segments sorted by file offset.
    pub load_segments: Box<[LoadSegment]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::mmap_from_bytes;

    #[test]
    fn mmap_section_data_validates_and_slices_ranges() {
        let mmap = mmap_from_bytes(&[10, 20, 30, 40, 50]);

        let section = ElfSectionData::mmap(mmap.clone(), 1..4).expect("valid mmap range");

        assert_eq!(&*section, &[20, 30, 40]);
        assert_eq!(section, ElfSectionData::owned(vec![20_u8, 30, 40]));
        let start = 4;
        let end = 1;
        assert!(ElfSectionData::mmap(mmap.clone(), start..end).is_none());
        assert!(ElfSectionData::mmap(mmap, 0..6).is_none());
    }
}
