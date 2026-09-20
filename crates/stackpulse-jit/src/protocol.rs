//! GDB registration snapshots and bounded reads from target memory.
use super::discovery::JitDescriptorLocation;
use super::MemoryReader;
use super::{jit_error, MAX_JIT_ENTRIES, MAX_JIT_READ_SIZE, MAX_JIT_TOTAL_SIZE};
use rustc_hash::FxHashMap as HashMap;
use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub(super) enum SnapshotError {
    #[error(transparent)]
    Read(#[from] io::Error),
    #[error("GDB JIT registry exceeds {0}")]
    Limit(&'static str),
}

/// Version 1 GDB JIT descriptor as laid out in a 64-bit target process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct JitDescriptor {
    /// Protocol version. Only version 1 is defined by the interface.
    pub(super) version: u32,
    /// Producer event flag. Snapshot refreshes use the linked list instead.
    pub(super) action_flag: u32,
    /// Target address of the entry named by the current producer event.
    pub(super) relevant_entry: u64,
    /// Target address of the registration-list head, or zero.
    pub(super) first_entry: u64,
}

/// One version 1 registration-list node in a 64-bit target process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct JitCodeEntry {
    /// Target address of the next node, or zero.
    pub(super) next_entry: u64,
    /// Target address of the preceding node, or zero for the head.
    pub(super) prev_entry: u64,
    /// Target address of the in-memory ELF image.
    pub(super) symfile_addr: u64,
    /// Size of the in-memory ELF image in bytes.
    pub(super) symfile_size: u64,
}

/// Descriptor values and list membership copied before loading remote metadata.
#[derive(PartialEq, Eq)]
pub(super) struct JitSnapshot {
    pub(super) descriptors: Vec<(u64, JitDescriptor)>,
    pub(super) entries: HashMap<u64, JitCodeEntry>,
}

/// Identity of a registration at one list node.
///
/// The producer can reuse a node address, so the target buffer address and size
/// participate in identity as well.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct JitObjectId {
    /// Registration-list node address in the target process.
    pub(super) entry_addr: u64,
    /// Target address of the ELF buffer registered by this node.
    pub(super) symfile_addr: u64,
    /// Registered ELF buffer length in bytes.
    pub(super) symfile_size: u64,
}

impl JitObjectId {
    pub(super) fn new(entry_addr: u64, entry: JitCodeEntry) -> Self {
        Self {
            entry_addr,
            symfile_addr: entry.symfile_addr,
            symfile_size: entry.symfile_size,
        }
    }

    /// Return the synthetic module path used to track framehop state.
    pub(super) fn path(self) -> PathBuf {
        PathBuf::from(format!(
            "[jit-0x{:x}-0x{:x}-0x{:x}]",
            self.entry_addr, self.symfile_addr, self.symfile_size
        ))
    }
}

pub(super) fn read_descriptors<P: MemoryReader>(
    process: &P,
    locations: &[JitDescriptorLocation],
) -> io::Result<Vec<(u64, JitDescriptor)>> {
    locations
        .iter()
        .map(|location| {
            let bytes = read_array::<24>(process, location.address)?;
            let (fields, _) = bytes.as_chunks::<4>();
            let (words, _) = bytes.as_chunks::<8>();
            let descriptor = JitDescriptor {
                version: u32::from_ne_bytes(fields[0]),
                action_flag: u32::from_ne_bytes(fields[1]),
                relevant_entry: u64::from_ne_bytes(words[1]),
                first_entry: u64::from_ne_bytes(words[2]),
            };
            if descriptor.version != 1 {
                return Err(jit_error(
                    "GDB JIT descriptor",
                    format!("unsupported version {}", descriptor.version),
                ));
            }
            Ok((location.address, descriptor))
        })
        .collect()
}

pub(super) fn read_snapshot<P: MemoryReader>(
    process: &P,
    descriptors: Vec<(u64, JitDescriptor)>,
) -> Result<JitSnapshot, SnapshotError> {
    let mut entries = HashMap::default();
    let mut total_size = 0_u64;
    for (_, descriptor) in &descriptors {
        for (address, entry) in read_entries(process, descriptor.first_entry)? {
            if let Some(previous) = entries.insert(address, entry) {
                if previous != entry {
                    return Err(jit_error(
                        "GDB JIT registry",
                        "inconsistent shared registration".into(),
                    )
                    .into());
                }
                continue;
            }
            total_size = total_size
                .checked_add(entry.symfile_size)
                .ok_or_else(|| io::Error::other("JIT registry size overflow"))?;
            if entries.len() > MAX_JIT_ENTRIES {
                return Err(SnapshotError::Limit("4096 registrations"));
            }
            if total_size > MAX_JIT_TOTAL_SIZE {
                return Err(SnapshotError::Limit("256 MiB of registered objects"));
            }
        }
    }
    Ok(JitSnapshot {
        descriptors,
        entries,
    })
}

pub(super) fn read_entries<P: MemoryReader>(
    process: &P,
    first_entry: u64,
) -> Result<HashMap<u64, JitCodeEntry>, SnapshotError> {
    let mut entries = HashMap::default();
    let mut address = first_entry;
    let mut previous = 0;
    while address != 0 {
        if entries.len() == MAX_JIT_ENTRIES {
            return Err(SnapshotError::Limit("4096 registrations"));
        }
        if entries.contains_key(&address) {
            return Err(jit_error("GDB JIT traversal", format!("cycle at 0x{address:x}")).into());
        }
        let bytes = read_array::<32>(process, address)?;
        let (words, _) = bytes.as_chunks::<8>();
        let entry = JitCodeEntry {
            next_entry: u64::from_ne_bytes(words[0]),
            prev_entry: u64::from_ne_bytes(words[1]),
            symfile_addr: u64::from_ne_bytes(words[2]),
            symfile_size: u64::from_ne_bytes(words[3]),
        };
        if entry.symfile_size > MAX_JIT_READ_SIZE {
            return Err(SnapshotError::Limit("64 MiB per object"));
        }
        if entry.symfile_size == 0 {
            return Err(jit_error("GDB JIT symfile", "invalid size 0".into()).into());
        }
        if entry.prev_entry != previous {
            return Err(jit_error(
                "GDB JIT traversal",
                format!(
                    "entry 0x{address:x} points back to 0x{:x}, expected 0x{previous:x}",
                    entry.prev_entry
                ),
            )
            .into());
        }
        entries.insert(address, entry);
        previous = address;
        address = entry.next_entry;
    }
    Ok(entries)
}

fn read_array<const N: usize>(process: &impl MemoryReader, address: u64) -> io::Result<[u8; N]> {
    address
        .checked_add(N as u64)
        .ok_or_else(|| io::Error::other("JIT address range overflow"))?;
    let mut bytes = [0; N];
    process.read(address, &mut bytes)?;
    Ok(bytes)
}

pub(super) fn read_memory<P: MemoryReader>(
    process: &P,
    address: u64,
    size: u64,
) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    read_memory_into(process, address, size, &mut buffer)?;
    Ok(buffer)
}

pub(super) fn read_memory_into<P: MemoryReader>(
    process: &P,
    address: u64,
    size: u64,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    if size > MAX_JIT_READ_SIZE {
        return Err(jit_error(
            "GDB JIT memory read",
            format!("size {size} exceeds {MAX_JIT_READ_SIZE}"),
        ));
    }
    if address.checked_add(size).is_none() {
        return Err(io::Error::other("JIT address range overflow"));
    }
    let size = usize::try_from(size).map_err(|_| io::Error::other("JIT read overflow"))?;
    buffer.resize(size, 0);
    process.read(address, buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RegistryList {
        count: usize,
        image_size: u64,
    }

    impl MemoryReader for RegistryList {
        fn pid(&self) -> i32 {
            1
        }

        fn read(&self, address: u64, buffer: &mut [u8]) -> io::Result<()> {
            let index = ((address - 0x1000) / 32) as usize;
            let words = [
                if index + 1 < self.count {
                    address + 32
                } else {
                    0
                },
                if index == 0 { 0 } else { address - 32 },
                0x100000,
                self.image_size,
            ];
            for (chunk, word) in buffer.as_chunks_mut::<8>().0.iter_mut().zip(words) {
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            Ok(())
        }
    }

    #[test]
    fn registry_limits_remain_distinct_from_invalid_target_data() {
        let descriptor = JitDescriptor {
            version: 1,
            action_flag: 0,
            relevant_entry: 0,
            first_entry: 0x1000,
        };
        for (count, image_size, limit) in [
            (MAX_JIT_ENTRIES + 1, 1, "4096 registrations"),
            (1, MAX_JIT_READ_SIZE + 1, "64 MiB per object"),
            (5, MAX_JIT_READ_SIZE, "256 MiB of registered objects"),
        ] {
            let error = read_snapshot(&RegistryList { count, image_size }, vec![(1, descriptor)]);
            assert!(matches!(error, Err(SnapshotError::Limit(actual)) if actual == limit));
        }
        let error = read_snapshot(
            &RegistryList {
                count: 1,
                image_size: 0,
            },
            vec![(1, descriptor)],
        );
        assert!(matches!(error, Err(SnapshotError::Read(_))));
    }
}
