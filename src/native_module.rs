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

#[derive(Clone, Default)]
pub(crate) struct ElfSectionCache {
    by_module: FxHashMap<u32, CachedElfImage>,
    by_image: FxHashMap<ElfImageIdentity, SharedElfImage>,
    open_failures: FxHashMap<u32, u8>,
    next_image_token: u64,
}

#[derive(Clone)]
struct CachedElfImage {
    sections: Arc<ElfSectionInfo>,
    token: u64,
    file: Weak<File>,
    identity: Option<ElfFileIdentity>,
}

#[derive(Clone)]
struct SharedElfImage {
    sections: Weak<ElfSectionInfo>,
    token: u64,
    file: Weak<File>,
}

impl From<&CachedElfImage> for SharedElfImage {
    fn from(image: &CachedElfImage) -> Self {
        Self {
            sections: Arc::downgrade(&image.sections),
            token: image.token,
            file: image.file.clone(),
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
            let cached = self.by_image.get_mut(&identity).and_then(|shared| {
                let sections = shared.sections.upgrade()?;
                let file = shared.file.upgrade().unwrap_or_else(|| {
                    shared.file = Arc::downgrade(&file);
                    Arc::clone(&file)
                });
                Some((
                    CachedElfImage {
                        sections,
                        token: shared.token,
                        file: shared.file.clone(),
                        identity: Some(identity.file().clone()),
                    },
                    file,
                ))
            });
            let (image, file) = if let Some(cached) = cached {
                cached
            } else {
                let image = CachedElfImage {
                    sections: Arc::new(
                        load_elf_sections_from_file(&file, module.path.as_path())
                            .map_err(|_| ElfLoadError::Unsupported)?,
                    ),
                    token: self.take_image_token().ok_or(ElfLoadError::Unsupported)?,
                    file: Arc::downgrade(&file),
                    identity: Some(identity.file().clone()),
                };
                self.by_image.insert(identity, SharedElfImage::from(&image));
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

    pub(crate) fn acquire_file(
        &mut self,
        module: &ModuleRecord,
    ) -> Result<Arc<File>, ElfLoadError> {
        if module.path.is_vdso() {
            return Err(ElfLoadError::Unsupported);
        }
        if let Some(file) = self
            .by_module
            .get(&module.id)
            .and_then(|image| image.file.upgrade())
        {
            return Ok(file);
        }
        self.ensure_open_attempt_allowed(module.id)?;
        let file = Arc::new(open_module_file(module).ok_or_else(|| self.failed_open(module.id))?);
        let identity =
            elf_file_identity(module, &file).ok_or_else(|| self.failed_open(module.id))?;
        let image = self
            .by_module
            .get_mut(&module.id)
            .ok_or(ElfLoadError::Unsupported)?;
        if image.identity.as_ref() != Some(&identity) {
            return Err(ElfLoadError::Unsupported);
        }
        image.file = Arc::downgrade(&file);
        self.open_failures.remove(&module.id);
        Ok(file)
    }

    pub(crate) fn remove(&mut self, module_id: u32) {
        self.by_module.remove(&module_id);
        self.open_failures.remove(&module_id);
        let prune_threshold = self.by_module.len().saturating_mul(2).saturating_add(256);
        if self.by_image.len() > prune_threshold {
            self.by_image
                .retain(|_, image| image.sections.strong_count() != 0);
        }
    }

    pub(crate) fn contains(&self, module_id: u32) -> bool {
        self.by_module.contains_key(&module_id)
    }

    pub(crate) fn reuse(&mut self, source_id: u32, module_id: u32) {
        if let Some(image) = self.by_module.get(&source_id).cloned() {
            self.by_module.insert(module_id, image);
            self.open_failures.remove(&module_id);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_module.len()
    }
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
    use crate::elf::LoadSegment;
    use crate::spool::ModuleOwner;
    use crate::test_support::TempDir;
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use std::os::unix::fs::symlink;

    fn user_owner(pid: i32) -> ModuleOwner {
        ModuleOwner::Process(crate::Pid::new(pid).unwrap())
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
