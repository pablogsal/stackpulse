//! Shared ELF section data and metadata types.

use memmap2::Mmap;
use std::fmt;
use std::ops::Deref;
use std::ops::Range;
use std::sync::{Arc, OnceLock};

use super::LoadSegment;

#[derive(Clone)]
pub(crate) struct ElfSectionData {
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
    pub(crate) fn owned(data: impl Into<Arc<[u8]>>) -> Self {
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

    /// Whether `other` holds the same section of an equally sized ELF file.
    ///
    /// File-backed sections compare their ranges rather than their bytes, so
    /// checking a reopened file does not fault in every mapped page.
    /// Decompressed sections compare their contents.
    pub(crate) fn same_layout(&self, other: &Self) -> bool {
        match (&self.storage, &other.storage) {
            (ElfSectionStorage::Mmap(mmap), ElfSectionStorage::Mmap(other_mmap)) => {
                self.range == other.range && mmap.len() == other_mmap.len()
            }
            (ElfSectionStorage::Owned(_), ElfSectionStorage::Owned(_)) => self == other,
            _ => false,
        }
    }

    pub(crate) fn owned_storage_identity(&self) -> Option<(usize, usize)> {
        match &self.storage {
            ElfSectionStorage::Owned(data) => Some((data.as_ptr() as usize, data.len())),
            ElfSectionStorage::Mmap(_) => None,
        }
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

impl From<Arc<[u8]>> for ElfSectionData {
    fn from(data: Arc<[u8]>) -> Self {
        Self::owned(data)
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
#[derive(Debug, Default)]
pub(crate) struct ElfSectionInfo {
    /// Base stated virtual address from the first PT_LOAD segment.
    pub(crate) base_svma: u64,

    /// .text section range (SVMA)
    pub(crate) text_svma: Option<Range<u64>>,

    /// .text section range in file-offset space.
    pub(crate) text_file_range: Option<Range<u64>>,

    /// .text section data.
    pub(crate) text: Option<ElfSectionData>,

    /// .eh_frame section address (SVMA)
    pub(crate) eh_frame_svma: Option<u64>,

    /// .eh_frame section data
    pub(crate) eh_frame: Option<ElfSectionData>,

    /// .eh_frame_hdr section address (SVMA)
    pub(crate) eh_frame_hdr_svma: Option<u64>,

    /// .eh_frame_hdr section data
    pub(crate) eh_frame_hdr: Option<ElfSectionData>,

    /// Whether .eh_frame_hdr holds a search table that indexes .eh_frame,
    /// validated once and shared by every mapping of this image.
    pub(crate) eh_frame_hdr_indexed: OnceLock<bool>,

    /// .got section range (SVMA)
    pub(crate) got_svma: Option<Range<u64>>,

    /// PT_LOAD segments sorted by file offset.
    pub(crate) load_segments: Box<[LoadSegment]>,
}

impl ElfSectionInfo {
    /// Whether `other` was parsed from a file with the same section layout.
    pub(crate) fn same_layout(&self, other: &Self) -> bool {
        fn same_section(left: Option<&ElfSectionData>, right: Option<&ElfSectionData>) -> bool {
            match (left, right) {
                (Some(left), Some(right)) => left.same_layout(right),
                (None, None) => true,
                _ => false,
            }
        }

        let Self {
            base_svma,
            text_svma,
            text_file_range,
            text,
            eh_frame_svma,
            eh_frame,
            eh_frame_hdr_svma,
            eh_frame_hdr,
            // A memo over the section bytes, not part of the layout.
            eh_frame_hdr_indexed: _,
            got_svma,
            load_segments,
        } = self;
        *base_svma == other.base_svma
            && *text_svma == other.text_svma
            && *text_file_range == other.text_file_range
            && same_section(text.as_ref(), other.text.as_ref())
            && *eh_frame_svma == other.eh_frame_svma
            && same_section(eh_frame.as_ref(), other.eh_frame.as_ref())
            && *eh_frame_hdr_svma == other.eh_frame_hdr_svma
            && same_section(eh_frame_hdr.as_ref(), other.eh_frame_hdr.as_ref())
            && *got_svma == other.got_svma
            && *load_segments == other.load_segments
    }
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

    #[test]
    fn owned_ranges_report_the_shared_backing_allocation() {
        let data: Arc<[u8]> = vec![1, 2, 3, 4, 5].into();
        let first = ElfSectionData::owned_range(Arc::clone(&data), 0..2).unwrap();
        let second = ElfSectionData::owned_range(data, 2..5).unwrap();

        assert_eq!(
            first.owned_storage_identity(),
            second.owned_storage_identity()
        );
        assert_eq!(first.owned_storage_identity().unwrap().1, 5);
    }
}
