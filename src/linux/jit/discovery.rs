//! Discover runtime descriptors through the target's executable mappings.

use goblin::elf::{section_header::SHN_UNDEF, Elf};
use memmap2::Mmap;
use rustc_hash::{FxHashMap, FxHashSet};
use std::fs::File;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DISCOVERY_INTERVAL: Duration = Duration::from_secs(1);

/// Descriptor discovery and target-memory access for one process image.
///
/// Mapping changes allow rediscovery while retaining usable cached addresses.
/// Fork and exec start with fresh discovery state in the process unwinder.
#[derive(Default)]
pub(super) struct Discovery {
    /// Open `/proc/<pid>/mem` handle shared by descriptor, ELF, and unwind reads.
    /// `None` means opening has not succeeded; failures use `memory_retry_after`.
    pub(super) memory: Option<File>,
    /// Earliest recorder-clock time to retry a failed memory open.
    /// `None` allows an immediate attempt; a successful open clears the deadline.
    memory_retry_after: Option<Instant>,
    /// Last successfully read `/proc/<pid>/maps` contents.
    /// Byte equality lets complete image scans be reused without parsing the maps again.
    maps: Vec<u8>,
    /// Descriptor scans keyed by mapped pathname, plus `/proc/<pid>/exe`.
    /// Complete scans are reused until that image's mapping layout changes.
    images: FxHashMap<PathBuf, DiscoveredImage>,
    /// Sorted, deduplicated target addresses of `__jit_debug_descriptor`.
    /// An empty list can also mean discovery is incomplete; see `absent`.
    pub(super) descriptors: Vec<u64>,
    /// Recorder-clock time of the last discovery attempt, including failed reads.
    /// Mapping changes clear it so discovery can run on the next eligible poll.
    last_discovery: Option<Instant>,
    /// Every image scan completed successfully and none found a descriptor.
    /// This stops JIT checks until executable mappings change. `false` also
    /// covers unknown or failed discovery, which must remain retryable.
    absent: bool,
}

/// A failed scan keeps addresses from unchanged mappings and remains retryable.
/// A complete empty result means the image has no supported descriptor.
#[derive(Default)]
struct DiscoveredImage {
    /// Descriptor addresses found in this image, in target address space.
    /// Failed scans retain addresses that still refer to the same mapped file bytes.
    descriptors: Vec<u64>,
    /// The image was scanned successfully for its current mapping layout.
    /// Only a complete scan with no descriptors proves absence for this image.
    complete: bool,
}

impl Discovery {
    /// Successful scans found no descriptor; mapping changes make this unknown again.
    pub(super) fn is_absent(&self) -> bool {
        self.absent
    }

    /// Recheck the maps on the next poll while retaining usable cached state.
    pub(super) fn mappings_changed(&mut self) {
        self.last_discovery = None;
        self.absent = false;
    }

    /// Cache successful image scans and retry incomplete scans once per second.
    /// Confirmed absence skips I/O until mappings change. Incomplete scans stay retryable.
    /// Failures in one image neither erase its usable addresses nor block others.
    pub(super) fn refresh_descriptors(&mut self, pid: i32, now: Instant) {
        self.refresh_descriptors_with(
            pid,
            now,
            || std::fs::read(format!("/proc/{pid}/maps")),
            discover_image,
        );
    }

    fn refresh_descriptors_with(
        &mut self,
        pid: i32,
        now: Instant,
        read_maps: impl FnOnce() -> std::io::Result<Vec<u8>>,
        mut scan: impl FnMut(i32, &Path, &[crate::proc_maps::Region<'_>]) -> Option<Vec<u64>>,
    ) {
        if self.absent
            || self
                .last_discovery
                .is_some_and(|last| now.duration_since(last) < DISCOVERY_INTERVAL)
        {
            return;
        }
        self.last_discovery = Some(now);
        let Ok(maps) = read_maps() else {
            return;
        };
        if maps == self.maps
            && !self.images.is_empty()
            && self.images.values().all(|image| image.complete)
        {
            self.absent = self.descriptors.is_empty();
            return;
        }
        let regions: Vec<_> = crate::proc_maps::parse_iter(&maps).collect();
        let previous: Vec<_> = crate::proc_maps::parse_iter(&self.maps).collect();
        let executable = PathBuf::from(format!("/proc/{pid}/exe"));
        let paths: FxHashSet<_> = regions
            .iter()
            .filter(|region| region.is_executable && region.inode != 0)
            .map(|region| region.path)
            .chain([executable.as_path()])
            .collect();
        self.images.retain(|path, _| paths.contains(path.as_path()));
        for path in paths {
            let image = self.images.entry(path.to_owned()).or_default();
            if maps != self.maps {
                // The executable uses auxv rather than a pathname from maps.
                // Conservatively invalidate it for file-backed mapping changes;
                // anonymous heap and JIT mappings cannot change its load address.
                let relevant = |region: &&crate::proc_maps::Region<'_>| {
                    region.path == path || (path == executable && region.inode != 0)
                };
                let layout_changed = !regions
                    .iter()
                    .filter(relevant)
                    .eq(previous.iter().filter(relevant));
                if layout_changed {
                    image.complete = false;
                    image
                        .descriptors
                        .retain(|address| same_mapped_byte(*address, &previous, &regions));
                }
            }
            if !image.complete {
                if let Some(descriptors) = scan(pid, path, &regions) {
                    image.descriptors = descriptors;
                    image.complete = true;
                }
            }
        }
        self.maps = maps;
        self.descriptors = self
            .images
            .values()
            .flat_map(|image| image.descriptors.iter().copied())
            .collect();
        self.descriptors.sort_unstable();
        self.descriptors.dedup();
        self.absent =
            self.descriptors.is_empty() && self.images.values().all(|image| image.complete);
    }

    /// Open target memory once; retry failed opens at most once per second.
    pub(super) fn open_memory(&mut self, pid: i32, now: Instant) {
        if self.memory.is_some() || self.memory_retry_after.is_some_and(|retry| now < retry) {
            return;
        }
        match File::open(format!("/proc/{pid}/mem")) {
            Ok(memory) => {
                self.memory = Some(memory);
                self.memory_retry_after = None;
            }
            Err(error) => {
                tracing::trace!(pid, %error, "could not open GDB JIT target memory");
                self.memory_retry_after = Some(now + DISCOVERY_INTERVAL);
            }
        }
    }
}

/// VMA splits and merges preserve a descriptor if its file identity and offset agree.
fn same_mapped_byte(
    address: u64,
    previous: &[crate::proc_maps::Region<'_>],
    current: &[crate::proc_maps::Region<'_>],
) -> bool {
    if previous
        .iter()
        .any(|old| old.address.contains(&address) && current.contains(old))
    {
        return true;
    }
    let location = |regions: &[crate::proc_maps::Region<'_>]| {
        let region = regions
            .iter()
            .find(|region| region.inode != 0 && region.address.contains(&address))?;
        let offset = region
            .file_offset
            .checked_add(address - region.address.start)?;
        Some((
            region.device_major,
            region.device_minor,
            region.inode,
            offset,
        ))
    };
    location(previous).is_some_and(|old| location(current) == Some(old))
}

/// Search both regular and dynamic symbol tables for a defined descriptor.
fn descriptor_symbol(elf: &Elf<'_>) -> Option<u64> {
    if !elf.is_64 || !elf.little_endian {
        return None;
    }
    [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)]
        .into_iter()
        .find_map(|(symbols, names)| {
            symbols
                .iter()
                .find(|s| {
                    s.st_shndx != SHN_UNDEF as usize
                        && names.get_at(s.st_name) == Some("__jit_debug_descriptor")
                })
                .map(|s| s.st_value)
        })
}

/// `None` means incomplete discovery and must be retried, including unchanged maps.
/// `Some([])` confirms an image without a supported descriptor.
fn discover_image(
    pid: i32,
    path: &Path,
    regions: &[crate::proc_maps::Region<'_>],
) -> Option<Vec<u64>> {
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    let executable = proc_dir.join("exe");
    let file = if path == executable {
        File::open(&executable).ok()?
    } else {
        regions
            .iter()
            .filter(|region| region.path == path && region.is_executable)
            .find_map(|region| open_mapped_image(&proc_dir, region))?
    };
    // Empty and non-ELF executable files cannot define a GDB descriptor.
    if file.metadata().ok()?.len() == 0 {
        return Some(Vec::new());
    }
    // SAFETY: The image is mapped read-only and parsed before the file is dropped.
    let bytes = unsafe { Mmap::map(&file) }.ok()?;
    if !bytes.starts_with(b"\x7fELF") {
        return Some(Vec::new());
    }
    let elf = Elf::parse(&bytes).ok()?;
    let Some(symbol) = descriptor_symbol(&elf) else {
        return Some(Vec::new());
    };
    if path == executable {
        return Some(vec![executable_bias(pid, &elf)?.wrapping_add(symbol)]);
    }
    let sections = crate::elf::load_elf_sections_from_file(&file, path).ok()?;
    let mut addresses = Vec::new();
    for region in regions.iter().filter(|r| r.path == path && r.is_executable) {
        if let Some(base) = crate::elf::resolve_mapping_image_base(
            &sections,
            region.file_offset,
            region.address.start,
            region.address.end - region.address.start,
        ) {
            let address = base.avma.wrapping_sub(base.svma).wrapping_add(symbol);
            if regions
                .iter()
                .any(|r| r.path == path && r.address.contains(&address))
            {
                addresses.push(address);
            }
        }
    }
    // The symbol exists but the current mappings could not establish its address.
    // A later maps read can complete while a runtime is being loaded.
    (!addresses.is_empty()).then_some(addresses)
}

/// Open a mapped image through procfs and verify its recorded inode and device.
fn open_mapped_image(proc_dir: &Path, region: &crate::proc_maps::Region<'_>) -> Option<File> {
    let mapping = proc_dir.join(format!(
        "map_files/{:x}-{:x}",
        region.address.start, region.address.end
    ));
    let rooted = region
        .path
        .strip_prefix("/")
        .ok()
        .map(|path| proc_dir.join("root").join(path));
    std::iter::once(mapping).chain(rooted).find_map(|path| {
        let file = File::options()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .ok()?;
        let metadata = file.metadata().ok()?;
        (metadata.is_file()
            && metadata.ino() == region.inode
            && libc::major(metadata.dev()) == region.device_major
            && libc::minor(metadata.dev()) == region.device_minor)
            .then_some(file)
    })
}

/// Derive the main executable's relocation bias from its auxiliary vector.
fn executable_bias(pid: i32, elf: &Elf<'_>) -> Option<u64> {
    let auxv = std::fs::read(format!("/proc/{pid}/auxv")).ok()?;
    let phdr = auxv.as_chunks::<16>().0.iter().find_map(|entry| {
        let (words, _) = entry.as_chunks::<8>();
        (u64::from_ne_bytes(words[0]) == libc::AT_PHDR).then(|| u64::from_ne_bytes(words[1]))
    })?;
    let svma = elf.program_headers.iter().find_map(|segment| {
        if segment.p_type == goblin::elf::program_header::PT_PHDR {
            return Some(segment.p_vaddr);
        }
        if segment.p_type != goblin::elf::program_header::PT_LOAD {
            return None;
        }
        let offset = elf.header.e_phoff.checked_sub(segment.p_offset)?;
        (offset < segment.p_filesz)
            .then(|| segment.p_vaddr.checked_add(offset))
            .flatten()
    })?;
    Some(phdr.wrapping_sub(svma))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &[u8] = b"1000-2000 r-xp 00000000 08:01 1 /good.so\n\
        3000-4000 r-xp 00000000 08:01 2 /retry.so\n";

    #[test]
    fn confirmed_absence_skips_all_discovery_io_until_mappings_change() {
        let mut discovery = Discovery::default();
        assert!(!discovery.is_absent());
        let now = Instant::now();
        discovery.refresh_descriptors_with(
            7,
            now,
            || Ok(MAPS.to_vec()),
            |_, _, _| Some(Vec::new()),
        );
        assert!(discovery.is_absent());
        for elapsed in [
            DISCOVERY_INTERVAL / 2,
            DISCOVERY_INTERVAL,
            DISCOVERY_INTERVAL * 10,
        ] {
            discovery.refresh_descriptors_with(
                7,
                now + elapsed,
                || panic!("confirmed absence must not read maps"),
                |_, _, _| panic!("confirmed absence must not scan images"),
            );
        }

        discovery.mappings_changed();
        assert!(!discovery.is_absent());
        let mut changed = MAPS.to_vec();
        changed.extend_from_slice(b"5000-6000 r-xp 00000000 08:01 3 /runtime.so\n");
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL * 10,
            || Ok(changed),
            |_, path, _| {
                Some(if path == Path::new("/runtime.so") {
                    vec![0x5100]
                } else {
                    Vec::new()
                })
            },
        );
        assert!(!discovery.is_absent());
        assert_eq!(discovery.descriptors, [0x5100]);
    }

    #[test]
    fn failed_maps_read_after_invalidation_does_not_restore_cached_absence() {
        let mut discovery = Discovery::default();
        let now = Instant::now();
        discovery.refresh_descriptors_with(
            7,
            now,
            || Ok(MAPS.to_vec()),
            |_, _, _| Some(Vec::new()),
        );
        assert!(discovery.is_absent());
        discovery.mappings_changed();
        discovery.refresh_descriptors_with(
            7,
            now,
            || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            |_, _, _| panic!("failed maps read must not scan images"),
        );
        assert!(!discovery.is_absent());
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL / 2,
            || panic!("failed maps reads must be rate limited"),
            |_, _, _| panic!("failed maps reads must be rate limited"),
        );
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL,
            || Ok(MAPS.to_vec()),
            |_, _, _| panic!("unchanged successful image scans remain cached"),
        );
        assert!(discovery.is_absent());
    }

    #[test]
    fn incomplete_empty_discovery_retries_instead_of_caching_absence() {
        let mut discovery = Discovery::default();
        let now = Instant::now();
        discovery.refresh_descriptors_with(
            7,
            now,
            || Ok(MAPS.to_vec()),
            |_, path, _| (path != Path::new("/retry.so")).then(Vec::new),
        );
        assert!(discovery.descriptors.is_empty());
        assert!(!discovery.is_absent());
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL,
            || Ok(MAPS.to_vec()),
            |_, path, _| {
                assert_eq!(path, Path::new("/retry.so"));
                Some(vec![0x3100])
            },
        );
        assert_eq!(discovery.descriptors, [0x3100]);
        assert!(!discovery.is_absent());
    }

    #[test]
    fn initially_empty_maps_still_require_an_executable_scan() {
        let mut discovery = Discovery::default();
        let mut scanned = false;
        discovery.refresh_descriptors_with(
            7,
            Instant::now(),
            || Ok(Vec::new()),
            |_, path, _| {
                assert_eq!(path, Path::new("/proc/7/exe"));
                scanned = true;
                None
            },
        );
        assert!(scanned);
        assert!(!discovery.is_absent());
    }

    #[test]
    fn retries_incomplete_images_with_unchanged_maps_without_rescanning_successes() {
        let mut discovery = Discovery::default();
        let now = Instant::now();
        discovery.refresh_descriptors_with(
            7,
            now,
            || Ok(MAPS.to_vec()),
            |_, path, _| match path.to_str().unwrap() {
                "/good.so" => Some(vec![0x1100]),
                "/retry.so" => None,
                _ => Some(Vec::new()),
            },
        );
        assert_eq!(discovery.descriptors, [0x1100]);
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL / 2,
            || panic!("discovery must be rate limited"),
            |_, _, _| panic!("discovery must be rate limited"),
        );
        let mut attempts = 0;
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL,
            || Ok(MAPS.to_vec()),
            |_, path, _| {
                assert_eq!(path, Path::new("/retry.so"));
                attempts += 1;
                Some(vec![0x3100])
            },
        );
        assert_eq!(attempts, 1);
        assert_eq!(discovery.descriptors, [0x1100, 0x3100]);
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL * 2,
            || Ok(MAPS.to_vec()),
            |_, _, _| panic!("completed scans must be cached"),
        );
    }

    #[test]
    fn incomplete_scan_keeps_unchanged_addresses_until_the_mapping_is_removed() {
        let mut discovery = Discovery::default();
        let now = Instant::now();
        discovery.refresh_descriptors_with(
            7,
            now,
            || Ok(MAPS.to_vec()),
            |_, path, _| {
                Some(if path == Path::new("/retry.so") {
                    vec![0x3100]
                } else {
                    Vec::new()
                })
            },
        );
        let mut changed = MAPS.to_vec();
        changed.extend_from_slice(b"4000-5000 rw-p 00001000 08:01 2 /retry.so\n");
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL,
            || Ok(changed.clone()),
            |_, _, _| None,
        );
        assert_eq!(discovery.descriptors, [0x3100]);
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL * 2,
            || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            |_, _, _| panic!("failed maps reads must retain cached discovery"),
        );
        assert_eq!(discovery.descriptors, [0x3100]);
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL * 3,
            || Ok(b"1000-2000 r-xp 00000000 08:01 1 /good.so\n".to_vec()),
            |_, _, _| None,
        );
        assert!(discovery.descriptors.is_empty());
        assert!(!discovery.images.contains_key(Path::new("/retry.so")));
    }

    #[test]
    fn anonymous_mapping_changes_reuse_the_executable_scan() {
        let mut discovery = Discovery::default();
        let now = Instant::now();
        discovery.refresh_descriptors_with(
            7,
            now,
            || Ok(MAPS.to_vec()),
            |_, path, _| {
                Some(if path == Path::new("/good.so") {
                    vec![0x1100]
                } else {
                    Vec::new()
                })
            },
        );
        for (index, mapping) in [
            "5000-6000 rw-p 00000000 00:00 0 [heap]\n",
            "5000-7000 rw-p 00000000 00:00 0 [heap]\n7000-8000 r-xp 00000000 00:00 0\n",
        ]
        .iter()
        .enumerate()
        {
            let mut maps = MAPS.to_vec();
            maps.extend_from_slice(mapping.as_bytes());
            discovery.mappings_changed();
            discovery.refresh_descriptors_with(
                7,
                now + DISCOVERY_INTERVAL * (index as u32 + 1),
                || Ok(maps),
                |_, _, _| panic!("anonymous mappings must not rescan unchanged images"),
            );
            assert_eq!(discovery.descriptors, [0x1100]);
        }

        let replaced = String::from_utf8(MAPS.to_vec())
            .unwrap()
            .replace("08:01 1", "08:01 9");
        let mut scanned_executable = false;
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL * 3,
            || Ok(replaced.into_bytes()),
            |_, path, _| {
                scanned_executable |= path == Path::new("/proc/7/exe");
                Some(Vec::new())
            },
        );
        assert!(scanned_executable);
    }

    #[test]
    fn failed_rescan_preserves_a_descriptor_across_mapping_splits_and_merges() {
        let split = b"1000-2000 r-xp 00000000 08:01 1 /good.so\n\
            3000-3800 r-xp 00000000 08:01 2 /retry.so\n\
            3800-4000 rw-p 00000800 08:01 2 /retry.so\n";
        for (before, after) in [(MAPS, split.as_slice()), (split.as_slice(), MAPS)] {
            let mut discovery = Discovery::default();
            let now = Instant::now();
            discovery.refresh_descriptors_with(
                7,
                now,
                || Ok(before.to_vec()),
                |_, path, _| {
                    Some(if path == Path::new("/retry.so") {
                        vec![0x3900]
                    } else {
                        Vec::new()
                    })
                },
            );
            discovery.refresh_descriptors_with(
                7,
                now + DISCOVERY_INTERVAL,
                || Ok(after.to_vec()),
                |_, _, _| None,
            );
            assert_eq!(discovery.descriptors, [0x3900]);
            assert!(!discovery.images[Path::new("/retry.so")].complete);

            // A different file offset at the same address is a real replacement.
            let replaced = String::from_utf8(after.to_vec())
                .unwrap()
                .replace("00000800", "00001800")
                .replace("3000-4000 r-xp 00000000", "3000-4000 r-xp 00001000");
            discovery.refresh_descriptors_with(
                7,
                now + DISCOVERY_INTERVAL * 2,
                || Ok(replaced.into_bytes()),
                |_, _, _| None,
            );
            assert!(discovery.descriptors.is_empty());
        }
    }

    #[test]
    fn replacing_an_image_does_not_retain_its_old_descriptor_on_scan_failure() {
        let mut discovery = Discovery::default();
        let now = Instant::now();
        discovery.refresh_descriptors_with(
            7,
            now,
            || Ok(MAPS.to_vec()),
            |_, path, _| {
                Some(if path == Path::new("/retry.so") {
                    vec![0x3100]
                } else {
                    Vec::new()
                })
            },
        );
        let replaced = String::from_utf8(MAPS.to_vec())
            .unwrap()
            .replace("08:01 2", "08:01 3");
        discovery.refresh_descriptors_with(
            7,
            now + DISCOVERY_INTERVAL,
            || Ok(replaced.into_bytes()),
            |_, _, _| None,
        );
        assert!(discovery.descriptors.is_empty());
    }

    #[test]
    fn non_elf_images_are_confirmed_without_retries() {
        let dir = crate::test_support::TempDir::new("jit-discovery-non-elf");
        let path = dir.path().join("code");
        let pid = i32::try_from(std::process::id()).unwrap();
        for bytes in [b"".as_slice(), b"not an ELF image".as_slice()] {
            std::fs::write(&path, bytes).unwrap();
            let metadata = std::fs::metadata(&path).unwrap();
            let region = crate::proc_maps::Region {
                address: 0x1000..0x2000,
                is_executable: true,
                file_offset: 0,
                inode: metadata.ino(),
                device_major: libc::major(metadata.dev()),
                device_minor: libc::minor(metadata.dev()),
                path: &path,
            };
            assert_eq!(discover_image(pid, &path, &[region]), Some(Vec::new()));
        }
    }

    #[test]
    fn failed_memory_open_waits_before_retrying() {
        let mut discovery = Discovery::default();
        let now = Instant::now();
        discovery.open_memory(-1, now);
        assert!(discovery.memory.is_none());
        let retry = discovery.memory_retry_after.unwrap();
        let pid = i32::try_from(std::process::id()).unwrap();
        discovery.open_memory(pid, now);
        assert!(discovery.memory.is_none());
        assert_eq!(discovery.memory_retry_after, Some(retry));
        discovery.open_memory(pid, retry);
        assert!(discovery.memory.is_some());
        assert!(discovery.memory_retry_after.is_none());
    }
}
