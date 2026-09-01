use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::ops::Bound::{Excluded, Unbounded};
use std::ptr;
use std::slice;
use std::sync::atomic::{fence, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};

use memmap2::{MmapMut, MmapOptions};
use perf_event_open_sys::bindings::perf_event_mmap_page;

use super::aligned_bytes::{AlignedBytes, AlignedBytesPool};
use super::invalid_data;

pub(super) struct RingBuffer {
    mapping: Arc<RingMapping>,
    read_pos: u64,
}

impl RingBuffer {
    pub(super) fn new(file: &File, page_exp: u8) -> io::Result<Self> {
        let page_size = usize::try_from(crate::elf::system_page_size())
            .map_err(|_| invalid_data("system page size does not fit usize"))?;
        let data_pages = 1_usize
            .checked_shl(u32::from(page_exp))
            .ok_or_else(|| invalid_data("perf ring page count overflow"))?;
        let map_len = data_pages
            .checked_add(1)
            .and_then(|pages| pages.checked_mul(page_size))
            .ok_or_else(|| invalid_data("perf ring mapping length overflow"))?;

        let mut options = MmapOptions::new();
        options.len(map_len);
        // SAFETY: file is a live perf-event fd and the mapping length follows
        // the perf mmap ABI. MmapMut owns and unmaps the resulting mapping.
        let mut mapped = unsafe { options.map_mut(file)? };
        let metadata = mapped.as_mut_ptr().cast::<perf_event_mmap_page>();

        // SAFETY: the first mapped page is perf_event_mmap_page. Volatile
        // accesses are required because the kernel updates this mapping.
        let data_offset_raw =
            unsafe { ptr::read_volatile(std::ptr::addr_of!((*metadata).data_offset)) };
        // SAFETY: the same mapped metadata page contains data_size, which the
        // kernel may update and therefore requires a volatile read.
        let data_size_raw =
            unsafe { ptr::read_volatile(std::ptr::addr_of!((*metadata).data_size)) };
        let data_offset = usize::try_from(data_offset_raw)
            .ok()
            .filter(|&offset| offset != 0)
            .unwrap_or(page_size);
        let data_size = usize::try_from(data_size_raw)
            .ok()
            .filter(|&size| size != 0)
            .unwrap_or(data_pages * page_size);
        let valid_layout = data_size.is_power_of_two()
            && data_offset >= page_size
            && data_offset
                .checked_add(data_size)
                .is_some_and(|end| end <= map_len);
        if !valid_layout {
            return Err(invalid_data("kernel returned an invalid perf ring layout"));
        }

        // SAFETY: data_tail is readable in the live metadata mapping. Only
        // this reader writes it, so no synchronization fence is needed here.
        let committed = unsafe { ptr::read_volatile(std::ptr::addr_of!((*metadata).data_tail)) };
        let mapping = Arc::new(RingMapping {
            mapped,
            metadata: AtomicPtr::new(metadata),
            data_offset,
            data_size,
            commits: Mutex::new(CommitState::new(committed)),
            aligned_pool: Arc::new(AlignedBytesPool::default()),
        });
        Ok(Self {
            mapping,
            read_pos: committed,
        })
    }

    #[cfg(test)]
    pub(super) fn next_record(&mut self) -> io::Result<Option<RingRecord>> {
        self.next_record_to(self.snapshot_head())
    }

    pub(super) fn snapshot_head(&self) -> u64 {
        self.mapping.head()
    }

    pub(super) fn capacity_bytes(&self) -> usize {
        self.mapping.data_size
    }

    pub(super) fn next_record_to(&mut self, head: u64) -> io::Result<Option<RingRecord>> {
        if head == self.read_pos {
            return Ok(None);
        }
        let available = head
            .checked_sub(self.read_pos)
            .ok_or_else(|| invalid_data("perf ring head regressed"))?;
        if available > self.mapping.data_size as u64 {
            return Err(invalid_data(
                "perf ring contains more data than its capacity",
            ));
        }
        if available < 8 {
            return Err(invalid_data("perf ring ended with a partial record header"));
        }

        let size_position = self
            .read_pos
            .checked_add(6)
            .ok_or_else(|| invalid_data("perf ring position overflow"))?;
        let record_len = u16::from_ne_bytes([
            self.mapping.byte_at(size_position),
            self.mapping.byte_at(size_position + 1),
        ]) as usize;
        if !(8..=self.mapping.data_size).contains(&record_len) {
            return Err(invalid_data("perf ring record has an invalid length"));
        }
        if record_len as u64 > available {
            return Err(invalid_data("perf ring head exposed a partial record"));
        }

        let from = self.read_pos;
        let to = from
            .checked_add(record_len as u64)
            .ok_or_else(|| invalid_data("perf ring position overflow"))?;
        let offset = (from as usize) & (self.mapping.data_size - 1);
        let storage = if offset + record_len <= self.mapping.data_size {
            RingRecordStorage::Mapped {
                mapping: Arc::clone(&self.mapping),
                from,
                to,
                offset,
                len: record_len,
            }
        } else {
            let first_len = self.mapping.data_size - offset;
            let bytes = AlignedBytes::copy_from_slices(
                self.mapping.slice(offset, first_len),
                self.mapping.slice(0, record_len - first_len),
                Arc::clone(&self.mapping.aligned_pool),
            );
            self.mapping.complete(from, to);
            RingRecordStorage::Owned(bytes)
        };
        self.read_pos = to;
        Ok(Some(RingRecord { storage }))
    }
}

pub(super) struct RingRecord {
    storage: RingRecordStorage,
}

impl RingRecord {
    pub(super) fn as_bytes(&self) -> &[u8] {
        match &self.storage {
            RingRecordStorage::Mapped {
                mapping,
                offset,
                len,
                ..
            } => mapping.slice(*offset, *len),
            RingRecordStorage::Owned(bytes) => bytes.as_bytes(),
        }
    }

    pub(super) fn detach_bytes(&mut self) -> AlignedBytes {
        match &mut self.storage {
            RingRecordStorage::Mapped { .. } => AlignedBytes::from_unaligned_bytes(self.as_bytes()),
            RingRecordStorage::Owned(bytes) => std::mem::take(bytes),
        }
    }
}

impl Drop for RingRecord {
    fn drop(&mut self) {
        if let RingRecordStorage::Mapped {
            mapping, from, to, ..
        } = &self.storage
        {
            mapping.complete(*from, *to);
        }
    }
}

enum RingRecordStorage {
    Mapped {
        mapping: Arc<RingMapping>,
        from: u64,
        to: u64,
        offset: usize,
        len: usize,
    },
    Owned(AlignedBytes),
}

struct RingMapping {
    mapped: MmapMut,
    metadata: AtomicPtr<perf_event_mmap_page>,
    data_offset: usize,
    data_size: usize,
    commits: Mutex<CommitState>,
    aligned_pool: Arc<AlignedBytesPool>,
}

impl RingMapping {
    fn complete(&self, from: u64, to: u64) {
        let mut commits = self
            .commits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(committed) = commits.complete(from, to) {
            self.store_tail(committed);
        }
    }

    fn head(&self) -> u64 {
        let metadata = self.metadata.load(Ordering::Relaxed);
        // SAFETY: data_head is readable in the live metadata mapping. The
        // acquire fence pairs with the kernel's publication of ring bytes.
        let head = unsafe { ptr::read_volatile(std::ptr::addr_of!((*metadata).data_head)) };
        fence(Ordering::Acquire);
        head
    }

    fn store_tail(&self, tail: u64) {
        // Publish all record reads before returning their storage to the
        // kernel. This follows the perf mmap ABI's full-barrier requirement.
        fence(Ordering::AcqRel);
        // SAFETY: data_tail is writable in the live metadata mapping and
        // commits serializes all writers in this process.
        unsafe {
            let metadata = self.metadata.load(Ordering::Relaxed);
            ptr::write_volatile(std::ptr::addr_of_mut!((*metadata).data_tail), tail);
        }
    }

    fn byte_at(&self, position: u64) -> u8 {
        let offset = (position as usize) & (self.data_size - 1);
        self.slice(offset, 1)[0]
    }

    fn slice(&self, offset: usize, len: usize) -> &[u8] {
        debug_assert!(offset + len <= self.data_size);
        // SAFETY: head was acquired before the caller selected this range, so
        // the kernel has finished publishing these bytes. The kernel cannot
        // overwrite them until this reader advances data_tail, and every
        // returned record retains this mapping until that commit. Constructing
        // the exact published range also avoids exposing the concurrently
        // modified metadata and unused ring storage through MmapMut::deref.
        unsafe { slice::from_raw_parts(self.mapped.as_ptr().add(self.data_offset + offset), len) }
    }
}

struct CommitState {
    committed: u64,
    pending: BTreeMap<u64, u64>,
}

impl CommitState {
    fn new(committed: u64) -> Self {
        Self {
            committed,
            pending: BTreeMap::new(),
        }
    }

    fn complete(&mut self, from: u64, to: u64) -> Option<u64> {
        if from == self.committed {
            self.committed = to;
            while let Some(to) = self.pending.remove(&self.committed) {
                self.committed = to;
            }
            return Some(self.committed);
        }
        debug_assert!(from > self.committed);
        let mut start = from;
        let mut end = to;
        if let Some((&previous_start, &previous_end)) = self.pending.range(..=start).next_back() {
            if previous_end == start {
                start = previous_start;
            }
        }
        if let Some((&next_start, &next_end)) =
            self.pending.range((Excluded(start), Unbounded)).next()
        {
            if end == next_start {
                self.pending.remove(&next_start);
                end = next_end;
            }
        }
        if let Some(previous) = self.pending.get_mut(&start) {
            *previous = end;
        } else {
            self.pending.insert(start, end);
        }
        None
    }
}

#[cfg(any(test, feature = "bench-support"))]
#[expect(
    clippy::expect_used,
    reason = "synthetic benchmark/test mappings cannot recover from fixture setup failure"
)]
pub(super) fn mock_wrapped_ring(records: &[u8]) -> RingBuffer {
    let record_size = records
        .get(6..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_ne_bytes)
        .expect("mock ring starts with one complete perf record");
    let data_size = mock_ring_data_size(records.len());
    let tail = (data_size - usize::from(record_size) / 2) as u64;
    mock_ring(tail, records)
}

#[cfg(any(test, feature = "bench-support"))]
#[expect(
    clippy::expect_used,
    reason = "synthetic benchmark/test mappings cannot recover from fixture setup failure"
)]
pub(super) fn mock_ring(tail: u64, records: &[u8]) -> RingBuffer {
    let page_size = usize::try_from(crate::elf::system_page_size()).expect("page size");
    let data_size = mock_ring_data_size(records.len());
    let mut mapped = MmapOptions::new()
        .len(page_size + data_size)
        .map_anon()
        .expect("anonymous ring mapping");
    {
        // SAFETY: the anonymous mapping is at least one metadata page long and
        // remains owned by RingMapping for the duration of the test.
        let metadata = unsafe { &mut *mapped.as_mut_ptr().cast::<perf_event_mmap_page>() };
        metadata.data_offset = page_size as u64;
        metadata.data_size = data_size as u64;
        metadata.data_tail = tail;
        metadata.data_head = tail + records.len() as u64;
    }
    for (index, byte) in records.iter().copied().enumerate() {
        mapped[page_size + ((tail as usize + index) & (data_size - 1))] = byte;
    }
    RingBuffer {
        mapping: Arc::new(RingMapping {
            metadata: AtomicPtr::new(mapped.as_mut_ptr().cast::<perf_event_mmap_page>()),
            mapped,
            data_offset: page_size,
            data_size,
            commits: Mutex::new(CommitState::new(tail)),
            aligned_pool: Arc::new(AlignedBytesPool::default()),
        }),
        read_pos: tail,
    }
}

#[cfg(any(test, feature = "bench-support"))]
fn mock_ring_data_size(record_len: usize) -> usize {
    record_len.next_power_of_two().max(32)
}

#[cfg(any(test, feature = "bench-support"))]
pub(super) fn mock_publish(ring: &mut RingBuffer, records: &[u8]) {
    assert_eq!(
        Arc::strong_count(&ring.mapping),
        1,
        "mock ring has live records"
    );
    let mapping = &ring.mapping;
    assert!(records.len() <= mapping.data_size);
    let head = ring.read_pos + records.len() as u64;
    // SAFETY: the mock owns the anonymous mapping, no record slices are live,
    // and this simulates the kernel writing bytes before publishing data_head.
    unsafe {
        let metadata = mapping.metadata.load(Ordering::Relaxed);
        for (index, byte) in records.iter().copied().enumerate() {
            let offset = (ring.read_pos as usize + index) & (mapping.data_size - 1);
            metadata
                .cast::<u8>()
                .add(mapping.data_offset + offset)
                .write(byte);
        }
        ptr::write_volatile(std::ptr::addr_of_mut!((*metadata).data_head), head);
    }
}

#[cfg(test)]
pub(super) fn test_tail(ring: &RingBuffer) -> u64 {
    // SAFETY: the metadata page remains live and data_tail is read using the
    // same volatile access required by the perf mmap ABI.
    unsafe {
        ptr::read_volatile(std::ptr::addr_of!(
            (*ring.mapping.metadata.load(Ordering::Relaxed)).data_tail
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{mock_publish, mock_ring, test_tail as tail, CommitState};

    fn record_bytes(kind: u32, marker: u64) -> [u8; 16] {
        let mut record = [0_u8; 16];
        record[..4].copy_from_slice(&kind.to_ne_bytes());
        record[6..8].copy_from_slice(&16_u16.to_ne_bytes());
        record[8..].copy_from_slice(&marker.to_ne_bytes());
        record
    }

    fn error_kind(result: std::io::Result<Option<super::RingRecord>>) -> std::io::ErrorKind {
        match result {
            Ok(_) => panic!("invalid ring state was accepted"),
            Err(error) => error.kind(),
        }
    }

    #[test]
    fn commits_completed_records_in_read_order() {
        let mut state = CommitState::new(100);

        assert_eq!(state.complete(120, 140), None);
        assert_eq!(state.complete(100, 120), Some(140));
        assert_eq!(state.complete(160, 180), None);
        assert_eq!(state.complete(140, 160), Some(180));
    }

    #[test]
    fn coalesces_many_records_behind_a_live_record() {
        let mut state = CommitState::new(0);
        for from in 1..100_000_u64 {
            assert_eq!(state.complete(from, from + 1), None);
        }
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.complete(0, 1), Some(100_000));
        assert!(state.pending.is_empty());
    }

    #[test]
    fn randomized_drop_orders_never_commit_live_storage() {
        const RECORDS: usize = 64;
        let mut seed = 0x6a09_e667_f3bc_c909_u64;
        for _ in 0..1_000 {
            let mut order: Vec<_> = (0..RECORDS).collect();
            for index in (1..RECORDS).rev() {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                order.swap(index, (seed as usize) % (index + 1));
            }
            let mut state = CommitState::new(0);
            let mut completed = [false; RECORDS];
            for record in order.iter().copied() {
                state.complete(record as u64, record as u64 + 1);
                completed[record] = true;
                let first_live = completed
                    .iter()
                    .position(|completed| !completed)
                    .unwrap_or(RECORDS);
                assert_eq!(state.committed, first_live as u64);
            }
            assert!(state.pending.is_empty());
        }
    }

    #[test]
    fn reads_a_wrapped_record_and_commits_its_copied_storage_immediately() {
        let bytes = record_bytes(9, 0x1234_5678_9abc_def0);
        let mut ring = mock_ring(24, &bytes);

        let record = ring.next_record().expect("read ring").expect("record");
        assert_eq!(record.as_bytes(), bytes);
        assert_eq!(tail(&ring), 40);
        drop(record);
        assert_eq!(tail(&ring), 40);
    }

    #[test]
    fn reuses_aligned_storage_for_successive_wrapped_records() {
        let mut bytes = vec![0_u8; 24];
        bytes[..4].copy_from_slice(&9_u32.to_ne_bytes());
        bytes[6..8].copy_from_slice(&24_u16.to_ne_bytes());
        bytes[8..16].copy_from_slice(&1_u64.to_ne_bytes());
        let mut ring = mock_ring(24, &bytes);

        let first = ring.next_record().expect("read ring").expect("record");
        let allocation = first.as_bytes().as_ptr();
        assert_eq!(first.as_bytes(), bytes);
        drop(first);

        bytes[8..16].copy_from_slice(&2_u64.to_ne_bytes());
        mock_publish(&mut ring, &bytes);
        let second = ring.next_record().expect("read ring").expect("record");
        assert_eq!(second.as_bytes().as_ptr(), allocation);
        assert_eq!(second.as_bytes(), bytes);
    }

    #[test]
    fn out_of_order_record_drops_commit_only_contiguous_storage() {
        let first = record_bytes(1, 10);
        let second = record_bytes(2, 20);
        let mut bytes = Vec::from(first);
        bytes.extend_from_slice(&second);
        let mut ring = mock_ring(0, &bytes);

        let first = ring.next_record().expect("read first").expect("first");
        let second = ring.next_record().expect("read second").expect("second");
        drop(second);
        assert_eq!(tail(&ring), 0);
        drop(first);
        assert_eq!(tail(&ring), 32);
    }

    #[test]
    fn malformed_record_does_not_advance_or_commit_the_ring() {
        let mut bytes = [0_u8; 8];
        bytes[6..8].copy_from_slice(&7_u16.to_ne_bytes());
        let mut ring = mock_ring(0, &bytes);

        let error = match ring.next_record() {
            Ok(_) => panic!("invalid record length was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(ring.read_pos, 0);
        assert_eq!(tail(&ring), 0);
    }

    #[test]
    fn rejects_regressed_oversized_and_partial_ring_heads() {
        let mut regressed = mock_ring(100, &[]);
        assert_eq!(
            error_kind(regressed.next_record_to(99)),
            std::io::ErrorKind::InvalidData
        );

        let mut oversized = mock_ring(0, &[]);
        assert_eq!(
            error_kind(oversized.next_record_to(oversized.capacity_bytes() as u64 + 1)),
            std::io::ErrorKind::InvalidData
        );

        let mut partial_header = mock_ring(0, &[0; 7]);
        assert_eq!(
            error_kind(partial_header.next_record()),
            std::io::ErrorKind::InvalidData
        );

        let mut header = [0_u8; 8];
        header[6..8].copy_from_slice(&16_u16.to_ne_bytes());
        let mut partial_record = mock_ring(0, &header);
        assert_eq!(
            error_kind(partial_record.next_record()),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn captured_head_bounds_one_drain_batch() {
        let first = record_bytes(1, 10);
        let second = record_bytes(2, 20);
        let mut bytes = Vec::from(first);
        bytes.extend_from_slice(&second);
        let mut ring = mock_ring(0, &bytes);

        let record = ring
            .next_record_to(16)
            .expect("bounded read")
            .expect("first record");
        assert_eq!(record.as_bytes(), first);
        drop(record);
        assert!(ring.next_record_to(16).expect("bounded end").is_none());
        assert!(ring.next_record_to(32).expect("later batch").is_some());
    }
}
