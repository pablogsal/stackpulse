use std::slice;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct AlignedBytesPool {
    buffer: Mutex<Option<Vec<u64>>>,
}

impl AlignedBytesPool {
    fn take(&self, words: usize) -> Vec<u64> {
        let mut retained = self
            .buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut buffer = retained.take().unwrap_or_default();
        drop(retained);
        if buffer.len() < words {
            buffer.resize(words, 0);
        }
        buffer
    }

    fn recycle(&self, buffer: Vec<u64>) {
        let mut retained = self
            .buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if retained.is_none() {
            *retained = Some(buffer);
        }
    }
}

enum AlignedBytesStorage {
    #[cfg(any(test, feature = "bench-support"))]
    Bytes(Vec<u8>),
    Words(Vec<u64>),
    PooledWords(Vec<u64>, Arc<AlignedBytesPool>),
}

pub(super) struct AlignedBytes {
    storage: AlignedBytesStorage,
    len: usize,
}

impl AlignedBytes {
    #[cfg(any(test, feature = "bench-support"))]
    pub(super) fn from_vec(bytes: Vec<u8>) -> Self {
        if is_u64_aligned(&bytes) {
            return Self {
                len: bytes.len(),
                storage: AlignedBytesStorage::Bytes(bytes),
            };
        }
        Self::from_unaligned_bytes(&bytes)
    }

    pub(super) fn from_unaligned_bytes(bytes: &[u8]) -> Self {
        let mut words = vec![0_u64; bytes.len().div_ceil(size_of::<u64>())];
        let aligned = words_as_bytes_mut(&mut words);
        aligned[..bytes.len()].copy_from_slice(bytes);
        Self {
            storage: AlignedBytesStorage::Words(words),
            len: bytes.len(),
        }
    }

    pub(super) fn copy_from_slices(
        first: &[u8],
        second: &[u8],
        pool: Arc<AlignedBytesPool>,
    ) -> Self {
        let len = first.len().saturating_add(second.len());
        let mut words = pool.take(len.div_ceil(size_of::<u64>()));
        let aligned = words_as_bytes_mut(&mut words);
        aligned[..first.len()].copy_from_slice(first);
        aligned[first.len()..len].copy_from_slice(second);
        Self {
            storage: AlignedBytesStorage::PooledWords(words, pool),
            len,
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        match &self.storage {
            #[cfg(any(test, feature = "bench-support"))]
            AlignedBytesStorage::Bytes(bytes) => bytes,
            AlignedBytesStorage::Words(words) | AlignedBytesStorage::PooledWords(words, _) => {
                &words_as_bytes(words)[..self.len]
            }
        }
    }

    #[cfg(test)]
    pub(super) fn as_mut_bytes(&mut self) -> &mut [u8] {
        match &mut self.storage {
            AlignedBytesStorage::Bytes(bytes) => bytes,
            AlignedBytesStorage::Words(words) | AlignedBytesStorage::PooledWords(words, _) => {
                &mut words_as_bytes_mut(words)[..self.len]
            }
        }
    }

    #[cfg(any(test, feature = "bench-support"))]
    pub(super) fn len(&self) -> usize {
        self.len
    }
}

pub(super) fn is_u64_aligned(bytes: &[u8]) -> bool {
    (bytes.as_ptr() as usize).is_multiple_of(align_of::<u64>())
}

fn words_as_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: u64 has no invalid bit patterns, and the byte view covers the
    // initialized slice without outliving it.
    unsafe { slice::from_raw_parts(words.as_ptr().cast::<u8>(), size_of_val(words)) }
}

fn words_as_bytes_mut(words: &mut [u64]) -> &mut [u8] {
    // SAFETY: the byte view uniquely borrows the initialized slice and covers
    // exactly the same allocation.
    unsafe { slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), size_of_val(words)) }
}

impl Default for AlignedBytes {
    fn default() -> Self {
        Self {
            storage: AlignedBytesStorage::Words(Vec::new()),
            len: 0,
        }
    }
}

impl Drop for AlignedBytes {
    fn drop(&mut self) {
        if let AlignedBytesStorage::PooledWords(words, pool) = &mut self.storage {
            pool.recycle(std::mem::take(words));
        }
    }
}
