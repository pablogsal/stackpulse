//! Bounded reads of the GDB JIT descriptor and its doubly linked object list.
//!
//! The target keeps running during reads. Rechecking membership detects observed
//! changes but cannot prove an atomic snapshot or distinguish identical reuse.

use rustc_hash::FxHashSet;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

const MAX_READ: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Remote allocation identity, not a lifetime identifier: runtimes can reuse every field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct ObjectId {
    /// Target address of the registration's linked-list entry.
    pub(super) entry: u64,
    /// Target address of the registered ELF copy, separate from its executable code.
    pub(super) address: u64,
    /// Length of the registered ELF copy in bytes.
    pub(super) size: u64,
}

/// Version-one descriptor fields used to detect concurrent registry changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Descriptor {
    /// Latest GDB action: 0 = no action, 1 = register, 2 = unregister.
    /// Describes only the latest notification, so intervening changes can be missed.
    pub(super) action: u32,
    /// Target address of the entry named by that notification; may be null.
    pub(super) relevant: u64,
    /// Target address of the list head; zero means no currently registered objects.
    pub(super) first: u64,
}

/// List membership copied before loading objects and revalidated afterward.
pub(super) struct Snapshot {
    /// Descriptor addresses paired with the values read before walking their lists.
    pub(super) descriptors: Vec<(u64, Descriptor)>,
    /// Unique registrations reachable from those lists, checked against size limits.
    pub(super) objects: FxHashSet<ObjectId>,
}

impl Snapshot {
    /// Recheck descriptor fields and membership; the runtime supplies no generation counter.
    pub(super) fn is_current(&self, memory: &File) -> bool {
        self.descriptors.iter().all(|&(address, descriptor)| {
            read_descriptor(memory, address).is_ok_and(|current| current == descriptor)
        }) && snapshot(memory, self.descriptors.clone())
            .is_ok_and(|current| current.objects == self.objects)
    }
}

/// Walk every list with backlink, cycle, entry-count, and total-size checks.
pub(super) fn snapshot(memory: &File, descriptors: Vec<(u64, Descriptor)>) -> io::Result<Snapshot> {
    let mut snapshot = Snapshot {
        descriptors,
        objects: FxHashSet::default(),
    };
    let mut total = 0_u64;
    for (_, descriptor) in &snapshot.descriptors {
        let mut next = descriptor.first;
        let mut previous = 0;
        let mut visited = FxHashSet::default();
        while next != 0 {
            if !visited.insert(next) || snapshot.objects.len() >= MAX_ENTRIES {
                return Err(invalid("cyclic or oversized GDB JIT registry"));
            }
            let data = read_array::<32>(memory, next)?;
            let (words, _) = data.as_chunks::<8>();
            if u64::from_ne_bytes(words[1]) != previous {
                return Err(invalid("inconsistent GDB JIT back link"));
            }
            let id = ObjectId {
                entry: next,
                address: u64::from_ne_bytes(words[2]),
                size: u64::from_ne_bytes(words[3]),
            };
            if id.size == 0 || id.size > MAX_READ {
                return Err(invalid("invalid GDB JIT object size"));
            }
            if snapshot.objects.insert(id) {
                total = total
                    .checked_add(id.size)
                    .ok_or_else(|| invalid("GDB JIT size overflow"))?;
                if total > MAX_TOTAL_BYTES {
                    return Err(invalid("GDB JIT objects exceed memory limit"));
                }
            }
            previous = next;
            next = u64::from_ne_bytes(words[0]);
        }
    }
    Ok(snapshot)
}

/// Read a native 64-bit version-one GDB descriptor.
pub(super) fn read_descriptor(memory: &File, address: u64) -> io::Result<Descriptor> {
    let data = read_array::<24>(memory, address)?;
    let (fields, _) = data.as_chunks::<4>();
    if u32::from_ne_bytes(fields[0]) != 1 {
        return Err(invalid("unsupported GDB JIT descriptor version"));
    }
    let (words, _) = data.as_chunks::<8>();
    Ok(Descriptor {
        action: u32::from_ne_bytes(fields[1]),
        relevant: u64::from_ne_bytes(words[1]),
        first: u64::from_ne_bytes(words[2]),
    })
}

fn check_read_bounds(address: u64, size: u64) -> io::Result<()> {
    if size > MAX_READ || address.checked_add(size).is_none() {
        return Err(invalid("GDB JIT read exceeds bounds"));
    }
    Ok(())
}

fn read_array<const N: usize>(memory: &File, address: u64) -> io::Result<[u8; N]> {
    check_read_bounds(address, N as u64)?;
    let mut bytes = [0; N];
    memory.read_exact_at(&mut bytes, address)?;
    Ok(bytes)
}

/// Copy a bounded target-memory range without overflowing its end address.
pub(super) fn read(memory: &File, address: u64, size: u64) -> io::Result<Vec<u8>> {
    check_read_bounds(address, size)?;
    let mut bytes = vec![0; usize::try_from(size).map_err(|_| invalid("GDB JIT size overflow"))?];
    memory.read_exact_at(&mut bytes, address)?;
    Ok(bytes)
}

pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
