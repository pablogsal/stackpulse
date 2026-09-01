use std::collections::VecDeque;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, Weak};

use crate::elf::{
    load_elf_sections_from_bytes, load_elf_sections_from_file, resolve_mapping_image_base,
    ElfSectionInfo,
};
use crate::module_base::ModuleImageBase;
use rustc_hash::FxHashMap;

use crate::spool::{ModuleRecord, VDSO_PATH};

const MAX_ELF_OPEN_ATTEMPTS: u8 = 2;
const MAX_SHARED_ELF_IMAGES: usize = 256;
const MAX_SHARED_ELF_OWNED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct ElfSectionCache {
    by_module: FxHashMap<u32, CachedElfImage>,
    by_image: FxHashMap<ElfImageIdentity, SharedElfImage>,
    image_order: VecDeque<ElfImageIdentity>,
    retained_owned_bytes: usize,
    open_failures: FxHashMap<u32, u8>,
    next_image_token: u64,
    #[cfg(test)]
    file_parse_count: usize,
}

#[derive(Clone)]
struct CachedElfImage {
    sections: Arc<ElfSectionInfo>,
    token: u64,
    file: Weak<File>,
    identity: Option<ElfFileIdentity>,
}

struct SharedElfImage {
    sections: Arc<ElfSectionInfo>,
    token: u64,
    file: Arc<File>,
    owned_bytes: usize,
}

impl SharedElfImage {
    fn from_cached(image: &CachedElfImage, file: Arc<File>) -> Self {
        Self {
            sections: Arc::clone(&image.sections),
            token: image.token,
            file,
            owned_bytes: elf_image_owned_bytes(&image.sections),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ElfFileIdentity {
    device: u64,
    inode: u64,
    inode_generation: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ElfImageIdentity {
    Namespaced {
        file: ElfFileIdentity,
        mount_namespace: u64,
    },
    Mapping {
        file: ElfFileIdentity,
        mapping_id: u32,
    },
}

impl ElfImageIdentity {
    fn file(&self) -> &ElfFileIdentity {
        match self {
            Self::Namespaced { file, .. } | Self::Mapping { file, .. } => file,
        }
    }
}

pub(crate) struct LoadedElfMapping {
    pub(crate) image_base: Option<ModuleImageBase>,
    pub(crate) sections: Arc<ElfSectionInfo>,
    pub(crate) file: Option<Arc<File>>,
    pub(crate) image_token: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ElfLoadError {
    Retryable,
    Unsupported,
}

impl ElfSectionCache {
    pub(crate) fn load_mapping(
        &mut self,
        module: &ModuleRecord,
    ) -> Result<LoadedElfMapping, ElfLoadError> {
        if module.is_kernel()
            || module.path.is_empty()
            || (module.path.is_bracketed_mapping() && !module.path.is_vdso())
        {
            return Err(ElfLoadError::Unsupported);
        }

        if let Some(image) = self.by_module.get(&module.id) {
            return Ok(LoadedElfMapping {
                image_base: resolve_image_base(module, &image.sections),
                sections: Arc::clone(&image.sections),
                file: image.file.upgrade(),
                image_token: image.token,
            });
        }

        let (image, file) = if module.path.is_vdso() {
            let bytes = local_vdso_bytes().ok_or(ElfLoadError::Unsupported)?;
            (
                CachedElfImage {
                    sections: Arc::new(
                        load_elf_sections_from_bytes(bytes, module.path.as_path())
                            .map_err(|_| ElfLoadError::Unsupported)?,
                    ),
                    token: self.take_image_token().ok_or(ElfLoadError::Unsupported)?,
                    file: Weak::new(),
                    identity: None,
                },
                None,
            )
        } else {
            self.ensure_open_attempt_allowed(module.id)?;
            let file =
                Arc::new(open_module_file(module).ok_or_else(|| self.failed_open(module.id))?);
            let identity =
                elf_image_identity(module, &file).ok_or_else(|| self.failed_open(module.id))?;
            let cached = self.by_image.get(&identity).map(|shared| {
                let retained_file = Arc::clone(&shared.file);
                (
                    CachedElfImage {
                        sections: Arc::clone(&shared.sections),
                        token: shared.token,
                        file: Arc::downgrade(&retained_file),
                        identity: Some(identity.file().clone()),
                    },
                    retained_file,
                )
            });
            if cached.is_some() {
                self.touch_shared_image(&identity);
            }
            let (image, file) = if let Some(cached) = cached {
                cached
            } else {
                let image = CachedElfImage {
                    sections: Arc::new(self.parse_file(&file, module.path.as_path())?),
                    token: self.take_image_token().ok_or(ElfLoadError::Unsupported)?,
                    file: Arc::downgrade(&file),
                    identity: Some(identity.file().clone()),
                };
                self.insert_shared_image(
                    identity,
                    SharedElfImage::from_cached(&image, Arc::clone(&file)),
                );
                (image, file)
            };
            (image, Some(file))
        };
        self.open_failures.remove(&module.id);
        self.by_module.insert(module.id, image.clone());

        Ok(LoadedElfMapping {
            image_base: resolve_image_base(module, &image.sections),
            sections: image.sections,
            file,
            image_token: image.token,
        })
    }

    fn failed_open(&mut self, module_id: u32) -> ElfLoadError {
        let failures = self.open_failures.entry(module_id).or_default();
        *failures = failures.saturating_add(1);
        if *failures < MAX_ELF_OPEN_ATTEMPTS {
            ElfLoadError::Retryable
        } else {
            ElfLoadError::Unsupported
        }
    }

    fn ensure_open_attempt_allowed(&self, module_id: u32) -> Result<(), ElfLoadError> {
        if self
            .open_failures
            .get(&module_id)
            .is_some_and(|&failures| failures >= MAX_ELF_OPEN_ATTEMPTS)
        {
            Err(ElfLoadError::Unsupported)
        } else {
            Ok(())
        }
    }

    fn take_image_token(&mut self) -> Option<u64> {
        let token = self.next_image_token;
        self.next_image_token = self.next_image_token.checked_add(1)?;
        Some(token)
    }

    fn parse_file(
        &mut self,
        file: &File,
        path: &std::path::Path,
    ) -> Result<ElfSectionInfo, ElfLoadError> {
        #[cfg(test)]
        {
            self.file_parse_count = self.file_parse_count.saturating_add(1);
        }
        load_elf_sections_from_file(file, path).map_err(|_| ElfLoadError::Unsupported)
    }

    fn insert_shared_image(&mut self, identity: ElfImageIdentity, image: SharedElfImage) {
        let owned_bytes = image.owned_bytes;
        if owned_bytes > MAX_SHARED_ELF_OWNED_BYTES {
            return;
        }
        if let Some(previous) = self.by_image.insert(identity.clone(), image) {
            self.debit_shared_image(&previous);
            self.image_order.retain(|cached| cached != &identity);
        }
        self.image_order.push_back(identity);
        self.retained_owned_bytes = self.retained_owned_bytes.saturating_add(owned_bytes);
        while self.by_image.len() > MAX_SHARED_ELF_IMAGES
            || self.retained_owned_bytes > MAX_SHARED_ELF_OWNED_BYTES
        {
            let Some(expired) = self.image_order.pop_front() else {
                break;
            };
            self.remove_shared_image(&expired);
        }
    }

    fn touch_shared_image(&mut self, identity: &ElfImageIdentity) {
        self.image_order.retain(|cached| cached != identity);
        self.image_order.push_back(identity.clone());
    }

    fn remove_shared_image(&mut self, identity: &ElfImageIdentity) -> Option<SharedElfImage> {
        let image = self.by_image.remove(identity)?;
        self.debit_shared_image(&image);
        Some(image)
    }

    fn debit_shared_image(&mut self, image: &SharedElfImage) {
        self.retained_owned_bytes = self.retained_owned_bytes.saturating_sub(image.owned_bytes);
    }

    pub(crate) fn acquire_file(
        &mut self,
        module: &ModuleRecord,
    ) -> Result<Arc<File>, ElfLoadError> {
        if module.path.is_vdso() {
            return Err(ElfLoadError::Unsupported);
        }
        if let Some((file, identity)) = self
            .by_module
            .get(&module.id)
            .and_then(|image| Some((image.file.upgrade()?, image.identity.as_ref()?.clone())))
        {
            if elf_file_identity(module, &file).as_ref() == Some(&identity) {
                return Ok(file);
            }
        }
        self.ensure_open_attempt_allowed(module.id)?;
        let file = Arc::new(open_module_file(module).ok_or_else(|| self.failed_open(module.id))?);
        let identity =
            elf_file_identity(module, &file).ok_or_else(|| self.failed_open(module.id))?;
        let shared_identity = elf_image_identity(module, &file);
        let current_sections = self.parse_file(&file, module.path.as_path())?;
        let shared = {
            let image = self
                .by_module
                .get_mut(&module.id)
                .ok_or(ElfLoadError::Unsupported)?;
            if image.identity.as_ref() != Some(&identity) || *image.sections != current_sections {
                return Err(ElfLoadError::Unsupported);
            }
            image.file = Arc::downgrade(&file);
            SharedElfImage::from_cached(image, Arc::clone(&file))
        };
        if let Some(shared_identity) = shared_identity {
            self.insert_shared_image(shared_identity, shared);
        }
        self.open_failures.remove(&module.id);
        Ok(file)
    }

    pub(crate) fn remove(&mut self, module_id: u32) {
        self.by_module.remove(&module_id);
        self.open_failures.remove(&module_id);
        let mapping_identity = self.by_image.keys().find_map(|identity| match identity {
            ElfImageIdentity::Mapping { mapping_id, .. } if *mapping_id == module_id => {
                Some(identity.clone())
            }
            _ => None,
        });
        if let Some(identity) = mapping_identity {
            self.remove_shared_image(&identity);
            self.image_order.retain(|cached| cached != &identity);
        }
    }

    pub(crate) fn contains(&self, module_id: u32) -> bool {
        self.by_module.contains_key(&module_id)
    }

    pub(crate) fn reuse(&mut self, source_id: u32, module_id: u32) -> bool {
        if let Some(image) = self.by_module.get(&source_id).cloned() {
            self.by_module.insert(module_id, image);
            self.open_failures.remove(&module_id);
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_module.len()
    }

    #[cfg(test)]
    pub(crate) fn file_parse_count(&self) -> usize {
        self.file_parse_count
    }
}

fn elf_image_owned_bytes(sections: &ElfSectionInfo) -> usize {
    // File-backed section ranges share the ELF mmap and do not reserve an
    // equivalent amount of resident heap memory. Bound the parsed metadata and
    // unique decompressed buffers that the cache owns instead.
    let mut owned = std::mem::size_of::<ElfSectionInfo>()
        .saturating_add(std::mem::size_of_val(sections.load_segments.as_ref()));
    let mut owned_sections = Vec::with_capacity(3);
    for section in [
        sections.text.as_ref(),
        sections.eh_frame.as_ref(),
        sections.eh_frame_hdr.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let Some((identity, bytes)) = section.owned_storage_identity() else {
            continue;
        };
        if owned_sections.contains(&identity) {
            continue;
        }
        owned_sections.push(identity);
        owned = owned.saturating_add(bytes);
    }
    owned
}

fn elf_image_identity(module: &ModuleRecord, file: &File) -> Option<ElfImageIdentity> {
    let pid = module.pid()?;
    let file = elf_file_identity(module, file)?;
    let mount_namespace = std::fs::metadata(format!("/proc/{pid}/ns/mnt"))
        .ok()
        .map(|metadata| metadata.ino());
    Some(match mount_namespace {
        Some(mount_namespace) => ElfImageIdentity::Namespaced {
            file,
            mount_namespace,
        },
        None => ElfImageIdentity::Mapping {
            file,
            mapping_id: module.id,
        },
    })
}

fn elf_file_identity(module: &ModuleRecord, file: &File) -> Option<ElfFileIdentity> {
    let metadata = file.metadata().ok()?;
    Some(ElfFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        inode_generation: module.inode_generation,
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn local_vdso_bytes() -> Option<Arc<[u8]>> {
    const MAX_MAPPED_ELF_SIZE: u64 = 16 * 1024 * 1024;
    static VDSO: OnceLock<Arc<[u8]>> = OnceLock::new();

    // Stackpulse only sends native-register samples to Framehop. The native
    // vDSO is kernel-wide, so a local copy avoids ptrace/Yama restrictions on
    // /proc/<target>/mem while retaining the target mapping's AVMA.
    if let Some(bytes) = VDSO.get() {
        return Some(Arc::clone(bytes));
    }
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let region = crate::proc_maps::parse_iter(&maps).find(|region| region.path == VDSO_PATH)?;
    let length = region.address.end.checked_sub(region.address.start)?;
    if length == 0 || length > MAX_MAPPED_ELF_SIZE {
        return None;
    }
    let mut bytes = vec![0; usize::try_from(length).ok()?];
    let memory = File::open("/proc/self/mem").ok()?;
    memory
        .read_exact_at(&mut bytes, region.address.start)
        .ok()?;
    let bytes: Arc<[u8]> = bytes.into();
    let _ = VDSO.set(Arc::clone(&bytes));
    Some(bytes)
}

#[cfg(test)]
fn module_path_matches_inode(module: &ModuleRecord) -> bool {
    open_module_file(module).is_some()
}

fn open_module_file(module: &ModuleRecord) -> Option<File> {
    let map_file = PathBuf::from(format!(
        "/proc/{}/map_files/{:x}-{:x}",
        module.pid()?,
        module.start,
        module.end
    ));
    open_module_file_with_mapping_path(module, &map_file)
}

fn open_module_file_with_mapping_path(
    module: &ModuleRecord,
    map_file: &std::path::Path,
) -> Option<File> {
    // The proc mapping names the exact object mapped by this process and must
    // win over a textual pathname that may now refer to a replacement file or
    // resolve in a different mount namespace. The pathname remains a useful
    // fallback after the process exits and map_files disappears.
    validated_module_file(map_file, module, true)
        .or_else(|| validated_module_file(module.path.as_path(), module, false))
}

fn validated_module_file(
    path: &std::path::Path,
    module: &ModuleRecord,
    allow_symlink: bool,
) -> Option<File> {
    let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
    if !allow_symlink {
        flags |= libc::O_NOFOLLOW;
    }
    let file = File::options()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    if module.inode != 0 && metadata.ino() != module.inode {
        return None;
    }
    if module.device_major != 0 || module.device_minor != 0 {
        let device = metadata.dev();
        if libc::major(device) != module.device_major || libc::minor(device) != module.device_minor
        {
            return None;
        }
    }
    Some(file)
}

fn resolve_image_base(
    module: &ModuleRecord,
    section_info: &ElfSectionInfo,
) -> Option<ModuleImageBase> {
    let span = module.end.saturating_sub(module.start);
    resolve_mapping_image_base(section_info, module.file_offset, module.start, span)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::{ElfSectionData, LoadSegment};
    use crate::spool::ModuleOwner;
    use crate::test_support::TempDir;
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use std::os::unix::fs::symlink;

    fn user_owner(pid: i32) -> ModuleOwner {
        ModuleOwner::Process(crate::Pid::new(pid).unwrap())
    }

    fn empty_sections() -> Arc<ElfSectionInfo> {
        Arc::new(ElfSectionInfo {
            base_svma: 0,
            text_svma: None,
            text_file_range: None,
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: Box::default(),
        })
    }

    fn namespaced_identity(inode: u64, size: u64, mount_namespace: u64) -> ElfImageIdentity {
        ElfImageIdentity::Namespaced {
            file: ElfFileIdentity {
                device: 1,
                inode,
                inode_generation: 0,
                size,
                modified_seconds: 0,
                modified_nanoseconds: 0,
                changed_seconds: 0,
                changed_nanoseconds: 0,
            },
            mount_namespace,
        }
    }

    #[test]
    fn image_base_is_not_guessed_when_mapping_cannot_be_correlated() {
        let section_info = ElfSectionInfo {
            base_svma: 0,
            text_svma: Some(0x1000..0x2000),
            text_file_range: Some(0x1000..0x2000),
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0,
                p_filesz: 0x5000,
                p_memsz: 0x5000,
                p_vaddr: 0,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };
        let module = ModuleRecord {
            id: 1,
            owner: user_owner(42),
            start: 0x7000_0000,
            end: 0x7000_1000,
            file_offset: 0x9000,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/tmp/libexample.so".into(),
        };

        assert_eq!(resolve_image_base(&module, &section_info), None);
    }

    #[test]
    fn loaded_elf_is_retained_when_mapping_cannot_be_correlated() {
        let module = ModuleRecord {
            id: 1,
            owner: user_owner(i32::try_from(std::process::id()).unwrap()),
            start: 0x7000_0000,
            end: 0x7000_1000,
            file_offset: u64::MAX - 0xfff,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned()
                .into(),
        };

        let loaded = ElfSectionCache::default()
            .load_mapping(&module)
            .expect("ELF sections still load for an uncorrelated mapping");

        assert_eq!(loaded.image_base, None);
    }

    #[test]
    fn module_path_identity_is_validated() {
        let path = std::env::temp_dir().join(format!(
            "stackpulse-native-module-inode-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"not-elf").unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();
        let mut module = ModuleRecord {
            id: 1,
            owner: user_owner(42),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: inode.saturating_add(1),
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };

        assert!(!module_path_matches_inode(&module));
        module.inode = inode;
        assert!(module_path_matches_inode(&module));
        let device = std::fs::metadata(&path).unwrap().dev();
        module.device_major = libc::major(device);
        module.device_minor = libc::minor(device).saturating_add(1);
        assert!(!module_path_matches_inode(&module));

        module.inode = 0;
        assert!(!module_path_matches_inode(&module));
        module.device_minor = libc::minor(device);
        assert!(module_path_matches_inode(&module));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn hostile_fifo_and_symlink_module_paths_are_rejected() {
        let temp = TempDir::new("native-module-hostile-paths");
        let fifo = temp.path().join("module.fifo");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("module-link");
        std::fs::write(&target, b"not an elf").unwrap();
        symlink(&target, &link).unwrap();

        let module = |path: &std::path::Path| ModuleRecord {
            id: 1,
            owner: user_owner(42),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };

        assert!(validated_module_file(&fifo, &module(&fifo), false).is_none());
        assert!(validated_module_file(&link, &module(&link), false).is_none());
    }

    #[test]
    fn failed_elf_load_is_retried_when_file_appears() {
        let path = std::env::temp_dir().join(format!(
            "stackpulse-native-module-retry-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let module = ModuleRecord {
            id: 1,
            owner: user_owner(42),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };
        let mut cache = ElfSectionCache::default();

        assert!(matches!(
            cache.load_mapping(&module),
            Err(ElfLoadError::Retryable)
        ));
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        assert!(cache.load_mapping(&module).is_ok());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn elf_identity_changes_after_same_size_same_mtime_rewrite() {
        let temp = TempDir::new("native-module-ctime");
        let path = temp.path().join("image");
        std::fs::write(&path, b"first").unwrap();
        let first_file = File::open(&path).unwrap();
        let modified = first_file.metadata().unwrap().modified().unwrap();
        let module = ModuleRecord {
            id: 1,
            owner: user_owner(i32::try_from(std::process::id()).unwrap()),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };
        let first_identity = elf_image_identity(&module, &first_file).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(2));
        std::fs::write(&path, b"other").unwrap();
        let second_file = File::open(&path).unwrap();
        second_file
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let second_identity = elf_image_identity(&module, &second_file).unwrap();

        assert_ne!(first_identity, second_identity);
    }

    #[test]
    fn reacquired_file_must_match_the_cached_image_identity() {
        let temp = TempDir::new("native-module-reacquire");
        let path = temp.path().join("image");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let module = ModuleRecord {
            id: 1,
            owner: user_owner(2_000_000_000),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };
        let mut cache = ElfSectionCache::default();
        let loaded = cache.load_mapping(&module).unwrap();
        let modified = loaded
            .file
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .modified()
            .unwrap();
        drop(loaded);

        let file = File::options().write(true).open(&path).unwrap();
        file.write_all_at(b"X", 0).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();

        assert_eq!(
            cache.acquire_file(&module).unwrap_err(),
            ElfLoadError::Unsupported
        );
    }

    #[test]
    fn reacquired_file_must_match_the_cached_elf_sections() {
        let temp = TempDir::new("native-module-reacquire-sections");
        let path = temp.path().join("image");
        std::fs::copy("/bin/true", &path).unwrap();
        let module = ModuleRecord {
            id: 1,
            owner: user_owner(i32::try_from(std::process::id()).unwrap()),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };
        let mut cache = ElfSectionCache::default();
        let loaded = cache.load_mapping(&module).unwrap();
        cache.by_image.clear();
        cache.image_order.clear();
        cache.retained_owned_bytes = 0;
        drop(loaded);
        assert!(cache.by_module[&module.id].file.upgrade().is_none());
        cache.by_module.get_mut(&module.id).unwrap().sections = Arc::new(ElfSectionInfo {
            base_svma: u64::MAX,
            text_svma: None,
            text_file_range: None,
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: Box::default(),
        });

        assert_eq!(
            cache.acquire_file(&module).unwrap_err(),
            ElfLoadError::Unsupported
        );
        assert!(cache.by_module[&module.id].file.upgrade().is_none());
    }

    #[test]
    fn reacquiring_the_same_file_does_not_require_the_target_namespace() {
        let temp = TempDir::new("native-module-namespace-exit");
        let path = temp.path().join("image");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let mut module = ModuleRecord {
            id: 1,
            owner: user_owner(i32::try_from(std::process::id()).unwrap()),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };
        let mut cache = ElfSectionCache::default();
        let loaded = cache.load_mapping(&module).unwrap();
        drop(loaded);

        module.owner = user_owner(2_000_000_000);

        assert!(cache.acquire_file(&module).is_ok());
    }

    #[test]
    fn cached_sections_can_be_reused_and_retired_by_module_id() {
        let path = std::env::current_exe().unwrap();
        let mut module = ModuleRecord {
            id: 1,
            owner: user_owner(i32::try_from(std::process::id()).unwrap()),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };
        let mut cache = ElfSectionCache::default();
        assert!(cache.load_mapping(&module).is_ok());

        cache.reuse(1, 2);
        module.id = 2;
        cache.remove(1);

        assert_eq!(cache.len(), 1);
        assert!(cache.load_mapping(&module).is_ok());
    }

    #[test]
    fn shared_image_cache_hit_skips_file_parse_and_retains_file() {
        let path = std::fs::canonicalize("/bin/true").unwrap();
        let mut module = ModuleRecord {
            id: 1,
            owner: user_owner(i32::try_from(std::process::id()).unwrap()),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.to_string_lossy().into_owned().into(),
        };
        let mut cache = ElfSectionCache::default();
        let LoadedElfMapping {
            sections: first_sections,
            file: first_file,
            image_token: first_token,
            ..
        } = cache.load_mapping(&module).unwrap();
        assert_eq!(cache.file_parse_count(), 1);
        drop(first_file);
        cache.remove(module.id);
        assert!(cache
            .by_image
            .values()
            .next()
            .unwrap()
            .file
            .metadata()
            .is_ok());

        module.id = 2;
        let second = cache.load_mapping(&module).unwrap();

        assert_eq!(cache.file_parse_count(), 1);
        assert!(Arc::ptr_eq(&first_sections, &second.sections));
        assert_eq!(first_token, second.image_token);
        let retained_file = Arc::clone(&cache.by_image.values().next().unwrap().file);
        let acquired_file = cache.acquire_file(&module).unwrap();
        assert!(Arc::ptr_eq(&retained_file, &acquired_file));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn shared_image_cache_is_bounded() {
        let sections = empty_sections();
        let file = Arc::new(File::open("/bin/true").unwrap());
        let mut cache = ElfSectionCache::default();
        for mount_namespace in 0..=MAX_SHARED_ELF_IMAGES as u64 {
            cache.insert_shared_image(
                namespaced_identity(mount_namespace, 1, mount_namespace),
                SharedElfImage {
                    sections: Arc::clone(&sections),
                    token: mount_namespace,
                    file: Arc::clone(&file),
                    owned_bytes: 1,
                },
            );
        }

        assert_eq!(cache.by_image.len(), MAX_SHARED_ELF_IMAGES);
        assert_eq!(cache.image_order.len(), MAX_SHARED_ELF_IMAGES);
    }

    #[test]
    fn shared_image_cache_refreshes_recently_used_images() {
        let sections = empty_sections();
        let file = Arc::new(File::open("/bin/true").unwrap());
        let mut cache = ElfSectionCache::default();
        for inode in 0..MAX_SHARED_ELF_IMAGES as u64 {
            cache.insert_shared_image(
                namespaced_identity(inode, 1, 1),
                SharedElfImage {
                    sections: Arc::clone(&sections),
                    token: inode,
                    file: Arc::clone(&file),
                    owned_bytes: 1,
                },
            );
        }
        let first = namespaced_identity(0, 1, 1);
        cache.touch_shared_image(&first);
        cache.insert_shared_image(
            namespaced_identity(MAX_SHARED_ELF_IMAGES as u64, 1, 1),
            SharedElfImage {
                sections,
                token: MAX_SHARED_ELF_IMAGES as u64,
                file,
                owned_bytes: 1,
            },
        );

        assert!(cache.by_image.contains_key(&first));
        assert!(!cache.by_image.contains_key(&namespaced_identity(1, 1, 1)));
    }

    #[test]
    fn shared_image_cache_honors_its_byte_budget() {
        let sections = empty_sections();
        let identity = |inode| namespaced_identity(inode, 1, 1);
        let file = Arc::new(File::open("/bin/true").unwrap());
        let mut cache = ElfSectionCache::default();
        for inode in 1..=3 {
            cache.insert_shared_image(
                identity(inode),
                SharedElfImage {
                    sections: Arc::clone(&sections),
                    token: inode,
                    file: Arc::clone(&file),
                    owned_bytes: MAX_SHARED_ELF_OWNED_BYTES / 2,
                },
            );
        }

        assert_eq!(cache.by_image.len(), 2);
        assert!(!cache.by_image.contains_key(&identity(1)));
        assert!(cache.retained_owned_bytes <= MAX_SHARED_ELF_OWNED_BYTES);
    }

    #[test]
    fn oversized_owned_image_is_not_shared() {
        let sections = empty_sections();
        let identity = namespaced_identity(1, 190 * 1024 * 1024, 1);
        let file = Arc::new(File::open("/bin/true").unwrap());
        let mut cache = ElfSectionCache::default();
        cache.by_module.insert(
            1,
            CachedElfImage {
                sections: Arc::clone(&sections),
                token: 1,
                file: Arc::downgrade(&file),
                identity: Some(identity.file().clone()),
            },
        );
        cache.insert_shared_image(
            identity.clone(),
            SharedElfImage {
                sections,
                token: 1,
                file,
                owned_bytes: MAX_SHARED_ELF_OWNED_BYTES + 1,
            },
        );

        assert!(cache.by_image.is_empty());
        assert!(!cache.by_image.contains_key(&identity));
        assert!(cache.image_order.is_empty());
        assert_eq!(cache.retained_owned_bytes, 0);
        assert!(cache.contains(1));
    }

    #[test]
    fn large_file_backed_image_is_charged_only_for_owned_data() {
        let sections = empty_sections();
        let identity = namespaced_identity(1, 190 * 1024 * 1024, 1);
        let file = Arc::new(File::open("/bin/true").unwrap());
        let image = CachedElfImage {
            sections,
            token: 1,
            file: Arc::downgrade(&file),
            identity: Some(identity.file().clone()),
        };
        let owned_bytes = elf_image_owned_bytes(&image.sections);
        let mut cache = ElfSectionCache::default();
        cache.insert_shared_image(identity.clone(), SharedElfImage::from_cached(&image, file));

        assert!(cache.by_image.contains_key(&identity));
        assert_eq!(cache.retained_owned_bytes, owned_bytes);
        assert!(owned_bytes < MAX_SHARED_ELF_OWNED_BYTES);
    }

    #[test]
    fn owned_bytes_charge_unique_decompressed_buffers_and_metadata_once() {
        let shared: Arc<[u8]> = vec![0_u8; 4096].into();
        let separate: Arc<[u8]> = vec![0_u8; 1024].into();
        let sections = ElfSectionInfo {
            base_svma: 0,
            text_svma: None,
            text_file_range: None,
            text: ElfSectionData::owned_range(Arc::clone(&shared), 0..1024),
            eh_frame_svma: None,
            eh_frame: ElfSectionData::owned_range(shared, 1024..4096),
            eh_frame_hdr_svma: None,
            eh_frame_hdr: ElfSectionData::owned_range(separate, 0..1024),
            got_svma: None,
            load_segments: vec![LoadSegment {
                p_offset: 0,
                p_filesz: 1,
                p_memsz: 1,
                p_vaddr: 0,
                p_flags: 0,
            }]
            .into_boxed_slice(),
        };

        assert_eq!(
            elf_image_owned_bytes(&sections),
            4096 + 1024
                + std::mem::size_of::<ElfSectionInfo>()
                + std::mem::size_of::<LoadSegment>()
        );
    }

    #[test]
    fn exact_mapping_file_wins_over_existing_textual_path() {
        let suffix = std::process::id();
        let map_path = std::env::temp_dir().join(format!("stackpulse-native-module-map-{suffix}"));
        let textual_path =
            std::env::temp_dir().join(format!("stackpulse-native-module-path-{suffix}"));
        std::fs::write(&map_path, b"mapped object").unwrap();
        std::fs::write(&textual_path, b"replacement").unwrap();
        let mapped_inode = std::fs::metadata(&map_path).unwrap().ino();
        let module = ModuleRecord {
            id: 1,
            owner: user_owner(i32::try_from(std::process::id()).unwrap()),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: textual_path.to_string_lossy().into_owned().into(),
        };

        let opened = open_module_file_with_mapping_path(&module, &map_path).unwrap();
        assert_eq!(opened.metadata().unwrap().ino(), mapped_inode);

        let _ = std::fs::remove_file(map_path);
        let _ = std::fs::remove_file(textual_path);
    }

    #[test]
    fn loads_vdso_elf_from_the_target_mapping() {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let region = crate::proc_maps::parse_iter(&maps)
            .find(|region| region.path == "[vdso]")
            .expect("current process has a vDSO mapping");
        let module = ModuleRecord {
            id: 1,
            owner: user_owner(i32::try_from(std::process::id()).unwrap()),
            start: region.address.start,
            end: region.address.end,
            file_offset: region.file_offset,
            inode: region.inode,
            device_major: region.device_major,
            device_minor: region.device_minor,
            inode_generation: 0,
            path: "[vdso]".into(),
        };

        let loaded = ElfSectionCache::default()
            .load_mapping(&module)
            .expect("vDSO is a readable ELF mapping");

        assert!(loaded.image_base.is_some());
        assert!(!loaded.sections.load_segments.is_empty());
    }
}
