//! Locate GDB registries in the executable and loaded ELF images.
use super::{FileIdentity, Mapping};
use crate::elf::{collect_load_segments, compute_vma_bias, find_load_contribution_for_file_range};
use goblin::elf::section_header::SHN_UNDEF;
use memmap2::Mmap;
use rustc_hash::FxHashMap as HashMap;
use std::fs::File;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const JIT_DESCRIPTOR_SYMBOL: &str = "__jit_debug_descriptor";
/// Resolved target address of the descriptor and the image that defines it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct JitDescriptorLocation {
    /// Descriptor AVMA in the target process, after applying ELF load bias.
    pub(super) address: u64,
    /// Loaded image path used to decide whether a discovery miss is transient.
    pub(super) owner: PathBuf,
    /// File offset at the descriptor address, independent of mapping splits.
    pub(super) owner_file_offset: Option<u64>,
    pub(super) owner_identity: Option<FileIdentity>,
}

/// Find a descriptor definition in the static or dynamic symbol table.
fn descriptor_symbol(elf: &goblin::elf::Elf<'_>) -> Option<u64> {
    [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)]
        .into_iter()
        .find_map(|(symbols, names)| {
            symbols
                .iter()
                .find(|symbol| {
                    symbol.st_shndx != SHN_UNDEF as usize
                        && names.get_at(symbol.st_name) == Some(JIT_DESCRIPTOR_SYMBOL)
                })
                .map(|symbol| symbol.st_value)
        })
}

/// Locate an executable descriptor through procfs and the runtime program headers.
fn executable_descriptor(pid: i32) -> std::io::Result<Option<JitDescriptorLocation>> {
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    let file = File::open(&path)?;
    // SAFETY: Concurrent mutation or truncation of a loaded image is outside
    // the supported process-image contract. The mapping lives through parsing.
    let mmap = unsafe { Mmap::map(&file) }?;
    let elf =
        goblin::elf::Elf::parse(&mmap).map_err(|error| std::io::Error::other(error.to_string()))?;
    let Some(symbol) = descriptor_symbol(&elf) else {
        return Ok(None);
    };
    let auxv = std::fs::read(format!("/proc/{pid}/auxv"))?;
    let phdr_avma = auxv
        .as_chunks::<16>()
        .0
        .iter()
        .find_map(|entry| {
            let kind = u64::from_ne_bytes(entry[..8].try_into().ok()?);
            if kind == libc::AT_PHDR {
                Some(u64::from_ne_bytes(entry[8..].try_into().ok()?))
            } else {
                None
            }
        })
        .ok_or_else(|| std::io::Error::other("missing AT_PHDR"))?;
    let phdr_svma = elf
        .program_headers
        .iter()
        .find_map(|segment| {
            if segment.p_type == goblin::elf::program_header::PT_PHDR {
                Some(segment.p_vaddr)
            } else if segment.p_type == goblin::elf::program_header::PT_LOAD {
                let offset = elf.header.e_phoff.checked_sub(segment.p_offset)?;
                if offset < segment.p_filesz {
                    segment.p_vaddr.checked_add(offset)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .ok_or_else(|| std::io::Error::other("missing ELF program headers"))?;
    Ok(Some(JitDescriptorLocation {
        address: phdr_avma.wrapping_sub(phdr_svma).wrapping_add(symbol),
        owner: path,
        owner_file_offset: None,
        owner_identity: None,
    }))
}

#[derive(PartialEq, Eq)]
struct ImageMapping {
    range: std::ops::Range<u64>,
    file_offset: u64,
    executable: bool,
    deleted: bool,
    identity: Option<FileIdentity>,
}

struct ImageSearch {
    mappings: Vec<ImageMapping>,
    descriptors: Vec<JitDescriptorLocation>,
}

/// Successful searches remain valid until that image's own mappings change.
#[derive(Default)]
pub(super) struct DescriptorDiscovery {
    images: HashMap<PathBuf, ImageSearch>,
}

impl DescriptorDiscovery {
    pub(super) fn find(
        &mut self,
        pid: i32,
        modules: &[impl Mapping],
    ) -> (Vec<JitDescriptorLocation>, bool) {
        let executable = PathBuf::from(format!("/proc/{pid}/exe"));
        let mut layouts: HashMap<&Path, Vec<ImageMapping>> = HashMap::default();
        for module in modules {
            layouts
                .entry(module.path())
                .or_default()
                .push(ImageMapping {
                    range: module.range(),
                    file_offset: module.file_offset(),
                    executable: module.executable(),
                    deleted: module.deleted(),
                    identity: module.file_identity(),
                });
        }
        layouts.retain(|_, mappings| mappings.iter().any(|mapping| mapping.executable));
        // Exec creates a fresh registry. Anonymous remappings do not change its executable.
        layouts.entry(&executable).or_default();
        self.images
            .retain(|path, cached| layouts.get(path.as_path()) == Some(&cached.mappings));
        let mut complete = true;
        let mut locations = Vec::new();
        for (path, mappings) in layouts {
            if let Some(cached) = self.images.get(path) {
                locations.extend(cached.descriptors.iter().cloned());
                continue;
            }
            let (found, image_complete) = if path == executable {
                match executable_descriptor(pid) {
                    Ok(location) => (location.into_iter().collect(), true),
                    Err(_) => (Vec::new(), false),
                }
            } else {
                image_descriptors(pid, path, modules)
            };
            locations.extend(found.iter().cloned());
            complete &= image_complete;
            // Cache only complete searches so unreadable instances remain retryable.
            if image_complete && self.images.len() < super::MAX_JIT_ENTRIES {
                self.images.insert(
                    path.to_path_buf(),
                    ImageSearch {
                        mappings,
                        descriptors: found,
                    },
                );
            }
        }
        // Preserve executable ownership when both procfs and its ordinary
        // mappings find the same descriptor; huge pages may replace those mappings.
        locations.sort_unstable_by_key(|location| (location.address, location.owner != executable));
        locations.dedup_by_key(|location| location.address);
        (locations, complete)
    }
}

fn image_descriptors(
    pid: i32,
    path: &Path,
    modules: &[impl Mapping],
) -> (Vec<JitDescriptorLocation>, bool) {
    let mut locations = Vec::new();
    let mut complete = true;
    for module in modules
        .iter()
        .filter(|module| module.path() == path && module.executable())
    {
        match image_descriptor(pid, module, modules) {
            Ok(Some(location)) => locations.push(location),
            Ok(None) => {}
            Err(_) => complete = false,
        }
    }
    (locations, complete)
}

fn image_descriptor(
    pid: i32,
    module: &impl Mapping,
    modules: &[impl Mapping],
) -> std::io::Result<Option<JitDescriptorLocation>> {
    let path = module.path();
    let mapped_path = format!(
        "/proc/{pid}/map_files/{:x}-{:x}",
        module.range().start,
        module.range().end
    );
    let open = |path: &Path| {
        let file = File::options()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || module.file_identity().is_some_and(|identity| {
                metadata.ino() != identity.inode || metadata.dev() != identity.device
            })
        {
            return Err(std::io::Error::other("mapped image identity changed"));
        }
        Ok(file)
    };
    let file = open(Path::new(&mapped_path)).or_else(|error| {
        if module.deleted() {
            return Err(error);
        }
        let relative_path = path.strip_prefix("/").unwrap_or(path);
        let target_path = PathBuf::from(format!("/proc/{pid}/root")).join(relative_path);
        open(&target_path).or_else(|_| open(path))
    })?;
    // SAFETY: Concurrent mutation or truncation of a loaded image is outside
    // the supported process-image contract. The mapping lives through parsing.
    let mmap = unsafe { Mmap::map(&file) }?;
    let Ok(elf) = goblin::elf::Elf::parse(&mmap) else {
        return Ok(None);
    };
    let Some(symbol_value) = descriptor_symbol(&elf) else {
        return Ok(None);
    };
    let mut segments = collect_load_segments(&elf);
    segments.retain(|segment| segment.p_flags & goblin::elf::program_header::PF_X != 0);
    let mapping_span = module.range().end.saturating_sub(module.range().start);
    if let Some(segment) =
        find_load_contribution_for_file_range(&segments, module.file_offset(), mapping_span)
    {
        let bias = compute_vma_bias(
            segment.p_offset,
            segment.p_vaddr,
            module.file_offset(),
            module.range().start,
        );
        let address = bias.wrapping_add(symbol_value);
        if let Some(mapping) = modules.iter().find(|mapping| {
            mapping.path() == path
                && mapping.deleted() == module.deleted()
                && mapping.file_identity() == module.file_identity()
                && mapping.range().contains(&address)
        }) {
            let owner_file_offset = mapping
                .file_offset()
                .checked_add(address - mapping.range().start);
            return Ok(Some(JitDescriptorLocation {
                address,
                owner: path.to_path_buf(),
                owner_file_offset,
                owner_identity: module.file_identity(),
            }));
        }
        return Err(std::io::Error::other("descriptor mapping is not available"));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use goblin::elf::program_header::{PF_X, PT_LOAD};
    use rustc_hash::FxHashSet as HashSet;

    fn descriptor_image() -> (TempDir, PathBuf, Vec<u8>) {
        let directory = TempDir::new("jit-discovery");
        let source = directory.path().join("registry.c");
        let path = directory.path().join("registry.so");
        std::fs::write(
            &source,
            "unsigned long __jit_debug_descriptor[3] = {1, 0, 0};\n\
             unsigned char initialized_data[8192] = {1};\n\
             const char constant = 1;\n\
             int entry(void) { return constant; }\n",
        )
        .unwrap();
        let output = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-g", "-o"])
            .arg(&path)
            .arg(&source)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        let bytes = std::fs::read(&path).unwrap();
        (directory, path, bytes)
    }

    struct TestMapping {
        path: PathBuf,
        range: std::ops::Range<u64>,
        offset: u64,
        executable: bool,
        deleted: bool,
        identity: Option<FileIdentity>,
    }
    impl Mapping for TestMapping {
        fn path(&self) -> &Path {
            &self.path
        }
        fn range(&self) -> std::ops::Range<u64> {
            self.range.clone()
        }
        fn file_offset(&self) -> u64 {
            self.offset
        }
        fn executable(&self) -> bool {
            self.executable
        }
        fn deleted(&self) -> bool {
            self.deleted
        }
        fn file_identity(&self) -> Option<FileIdentity> {
            self.identity
        }
    }
    fn mapping(path: &Path, start: u64, size: u64, offset: u64, executable: bool) -> TestMapping {
        TestMapping {
            path: path.into(),
            range: start..start + size,
            offset,
            executable,
            deleted: false,
            identity: None,
        }
    }

    #[test]
    fn file_views_and_relro_aliases_do_not_create_registries() {
        let (_directory, path, bytes) = descriptor_image();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let symbol = descriptor_symbol(&elf).unwrap();
        let mut modules = Vec::new();
        for base in [0x100000, 0x200000] {
            for segment in elf
                .program_headers
                .iter()
                .filter(|segment| segment.p_type == PT_LOAD)
            {
                modules.push(mapping(
                    &path,
                    base + segment.p_vaddr,
                    segment.p_memsz,
                    segment.p_offset,
                    segment.p_flags & PF_X != 0,
                ));
                if segment.p_flags & goblin::elf::program_header::PF_W != 0 {
                    modules.push(mapping(
                        &path,
                        base + (segment.p_vaddr & !0xfff),
                        0x1000,
                        segment.p_offset & !0xfff,
                        false,
                    ));
                }
            }
        }
        modules.push(mapping(&path, 0x400000, bytes.len() as u64, 0, false));
        modules.push(mapping(&path, 0x500000, bytes.len() as u64, 0, false));

        let (found, complete) = image_descriptors(std::process::id() as i32, &path, &modules);

        assert!(complete);
        let addresses: HashSet<_> = found.iter().map(|location| location.address).collect();
        assert_eq!(
            addresses,
            HashSet::from_iter([0x100000 + symbol, 0x200000 + symbol])
        );
    }

    #[test]
    fn pathname_replacement_cannot_supply_the_loaded_image() {
        for deleted in [false, true] {
            let (_directory, path, bytes) = descriptor_image();
            let elf = goblin::elf::Elf::parse(&bytes).unwrap();
            let segment = elf
                .program_headers
                .iter()
                .find(|segment| segment.p_type == PT_LOAD && segment.p_flags & PF_X != 0)
                .unwrap();
            let metadata = std::fs::metadata(&path).unwrap();
            let mut module = mapping(&path, 0x100000, segment.p_memsz, segment.p_offset, true);
            module.identity = Some(FileIdentity {
                inode: metadata.ino(),
                device: metadata.dev(),
            });
            module.deleted = deleted;
            std::fs::rename(&path, path.with_extension("old")).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            let (found, complete) = image_descriptors(std::process::id() as i32, &path, &[module]);
            assert!(
                found.is_empty() && !complete,
                "the replacement must not supply symbols"
            );
        }
    }

    #[test]
    fn unreadable_instance_preserves_other_registries_at_the_same_path() {
        let (_directory, path, bytes) = descriptor_image();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let address = 0x100000 + descriptor_symbol(&elf).unwrap();
        let mut modules: Vec<_> = elf
            .program_headers
            .iter()
            .filter(|segment| segment.p_type == PT_LOAD)
            .map(|segment| {
                mapping(
                    &path,
                    0x100000 + segment.p_vaddr,
                    segment.p_memsz,
                    segment.p_offset,
                    segment.p_flags & PF_X != 0,
                )
            })
            .collect();
        let mut deleted = mapping(&path, 0x300000, 0x1000, 0x1000, true);
        deleted.deleted = true;
        modules.push(deleted);
        let mut discovery = DescriptorDiscovery::default();

        for _ in 0..2 {
            let (found, complete) = discovery.find(std::process::id() as i32, &modules);

            assert!(found.iter().any(|location| location.address == address));
            assert!(!complete);
            assert!(!discovery.images.contains_key(&path));
            modules.reverse();
        }
    }
    #[test]
    fn unrelated_mapping_changes_reuse_completed_image_searches() {
        let (directory, path, bytes) = descriptor_image();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let address = 0x100000 + descriptor_symbol(&elf).unwrap();
        let mut modules: Vec<_> = elf
            .program_headers
            .iter()
            .filter(|segment| segment.p_type == PT_LOAD)
            .map(|segment| {
                mapping(
                    &path,
                    0x100000 + segment.p_vaddr,
                    segment.p_memsz,
                    segment.p_offset,
                    segment.p_flags & PF_X != 0,
                )
            })
            .collect();
        let mut discovery = DescriptorDiscovery::default();
        let pid = std::process::id() as i32;
        assert!(discovery
            .find(pid, &modules)
            .0
            .iter()
            .any(|found| found.address == address));
        // A rescan would now fail. Unrelated mappings must retain this completed search.
        std::fs::remove_file(&path).unwrap();
        let other = directory.path().join("other");
        std::fs::write(&other, b"not an ELF image").unwrap();
        modules.push(mapping(&other, 0x400000, 0x1000, 0, true));
        for has_other in [true, false] {
            let (found, complete) = discovery.find(pid, &modules);
            assert!(complete);
            assert!(found.iter().any(|found| found.address == address));
            if has_other {
                modules.pop();
            }
        }
        // A change to this image's own mappings makes the missing file retryable.
        modules[0].offset += 1;
        let (found, complete) = discovery.find(pid, &modules);
        assert!(!complete);
        assert!(!found.iter().any(|found| found.address == address));
        assert!(!discovery.images.contains_key(&path));
    }

    #[test]
    fn cached_searches_are_invalidated_by_file_identity_changes() {
        for change_device in [false, true] {
            let (_directory, path, bytes) = descriptor_image();
            let elf = goblin::elf::Elf::parse(&bytes).unwrap();
            let metadata = std::fs::metadata(&path).unwrap();
            let identity = FileIdentity {
                inode: metadata.ino(),
                device: metadata.dev(),
            };
            let mut modules: Vec<_> = elf
                .program_headers
                .iter()
                .filter(|segment| segment.p_type == PT_LOAD)
                .map(|segment| {
                    let mut module = mapping(
                        &path,
                        0x100000 + segment.p_vaddr,
                        segment.p_memsz,
                        segment.p_offset,
                        segment.p_flags & PF_X != 0,
                    );
                    module.identity = Some(identity);
                    module
                })
                .collect();
            let mut discovery = DescriptorDiscovery::default();
            let pid = std::process::id() as i32;
            discovery.find(pid, &modules);
            assert!(discovery.images.contains_key(&path));
            for module in &mut modules {
                let identity = module.identity.as_mut().unwrap();
                if change_device {
                    identity.device ^= 1;
                } else {
                    identity.inode += 1;
                }
            }
            let (found, complete) = discovery.find(pid, &modules);
            assert!(!complete);
            assert!(!found.iter().any(|found| found.owner == path));
            assert!(!discovery.images.contains_key(&path));
        }
    }
    #[test]
    fn missing_descriptor_mapping_retries_when_data_arrives() {
        let (_directory, path, bytes) = descriptor_image();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let address = 0x100000 + descriptor_symbol(&elf).unwrap();
        let module = |segment: &goblin::elf::ProgramHeader| {
            mapping(
                &path,
                0x100000 + segment.p_vaddr,
                segment.p_memsz,
                segment.p_offset,
                segment.p_flags & PF_X != 0,
            )
        };
        let mut modules: Vec<_> = elf
            .program_headers
            .iter()
            .filter(|segment| segment.p_type == PT_LOAD && segment.p_flags & PF_X != 0)
            .map(module)
            .collect();
        let mut discovery = DescriptorDiscovery::default();
        let pid = std::process::id() as i32;
        let (found, complete) = discovery.find(pid, &modules);
        assert!(
            !complete,
            "executable mapping does not prove descriptor data is ready"
        );
        assert!(!found.iter().any(|found| found.owner == path));
        assert!(!discovery.images.contains_key(&path));
        modules.extend(
            elf.program_headers
                .iter()
                .filter(|segment| segment.p_type == PT_LOAD && segment.p_flags & PF_X == 0)
                .map(module),
        );
        let (found, complete) = discovery.find(pid, &modules);
        assert!(complete);
        assert!(found.iter().any(|found| found.address == address));
    }
}
