//! Shared ELF section extraction for unwinding and symbolization.
//!
//! Loads ELF sections used by native stack unwinding and post-recording
//! symbolization. Both consumers share these results through `native_module`.

use super::types::{ElfSectionData, ElfSectionInfo};
use super::LoadSegment;
use crate::error::{ElfParseError, Error};
use goblin::container::{Container, Ctx, Endian};
use goblin::elf::program_header::{ProgramHeader, PT_LOAD};
use goblin::elf::section_header::{SectionHeader, SHF_COMPRESSED};
use goblin::elf::Elf;
use goblin::strtab::Strtab;
use memmap2::Mmap;
use object::{CompressionFormat, Object, ObjectSection};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
fn load_elf_sections_from_path(path: &Path) -> Result<ElfSectionInfo> {
    use std::fs::File;

    let file = File::open(path)?;
    load_elf_sections_from_file(&file, path)
}

pub(crate) fn load_elf_sections_from_file(
    file: &std::fs::File,
    path: &Path,
) -> Result<ElfSectionInfo> {
    let mmap = Arc::new(unsafe { Mmap::map(file) }?);
    load_elf_sections(ElfFileData::Mmap(mmap), path)
}

pub(crate) fn load_elf_sections_from_bytes(
    bytes: Arc<[u8]>,
    path: &Path,
) -> Result<ElfSectionInfo> {
    load_elf_sections(ElfFileData::Owned(bytes), path)
}

#[derive(Clone)]
enum ElfFileData {
    Mmap(Arc<Mmap>),
    Owned(Arc<[u8]>),
}

impl ElfFileData {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Mmap(mmap) => mmap,
            Self::Owned(bytes) => bytes,
        }
    }

    fn section(&self, range: Range<usize>) -> Option<ElfSectionData> {
        match self {
            Self::Mmap(mmap) => ElfSectionData::mmap(Arc::clone(mmap), range),
            Self::Owned(bytes) => ElfSectionData::owned_range(Arc::clone(bytes), range),
        }
    }
}

fn load_elf_sections(data: ElfFileData, path: &Path) -> Result<ElfSectionInfo> {
    let bytes = data.bytes();

    // Use lazy parsing rather than Elf::parse to avoid reading symbol tables
    // and relocation sections; on a cold page cache those can be several MB per
    // library and block the sample loop for seconds in CI containers.
    let parse_err = |source| Error::from(ElfParseError::new(path, source));
    let header = Elf::parse_header(bytes).map_err(&parse_err)?;
    let mut elf = Elf::lazy_parse(header).map_err(&parse_err)?;

    let container = if elf.is_64 {
        Container::Big
    } else {
        Container::Little
    };
    let endian = if elf.little_endian {
        Endian::Little
    } else {
        Endian::Big
    };
    let ctx = Ctx::new(container, endian);

    elf.program_headers =
        ProgramHeader::parse(bytes, header.e_phoff as usize, header.e_phnum as usize, ctx)
            .unwrap_or_default();
    elf.section_headers =
        SectionHeader::parse(bytes, header.e_shoff as usize, header.e_shnum as usize, ctx)
            .unwrap_or_default();

    // Resolve the section-name string table, handling the SHN_XINDEX overflow case.
    let mut strtab_idx = header.e_shstrndx as usize;
    if strtab_idx == goblin::elf::section_header::SHN_XINDEX as usize {
        strtab_idx = elf
            .section_headers
            .first()
            .map_or(0, |sh| sh.sh_link as usize);
    }
    if let Some(shdr) = elf.section_headers.get(strtab_idx) {
        if let Ok(strtab) =
            Strtab::parse(bytes, shdr.sh_offset as usize, shdr.sh_size as usize, 0x0)
        {
            elf.shdr_strtab = strtab;
        }
    }

    let object_file = unwind_sections_have_compressed_data(&elf)
        .then(|| object::File::parse(bytes).ok())
        .flatten();
    let text = find_unwind_section_data(".text", &elf, object_file.as_ref(), &data);
    let eh_frame = find_unwind_section_data(".eh_frame", &elf, object_file.as_ref(), &data);
    let eh_frame_hdr = find_unwind_section_data(".eh_frame_hdr", &elf, object_file.as_ref(), &data);

    Ok(ElfSectionInfo {
        base_svma: calculate_base_svma(&elf),
        text_svma: find_section_range(".text", &elf),
        text_file_range: find_section_file_range(".text", &elf),
        text: text.map(|(_, data)| data),
        eh_frame_svma: eh_frame.as_ref().map(|(addr, _)| *addr),
        eh_frame: eh_frame.map(|(_, data)| data),
        eh_frame_hdr_svma: eh_frame_hdr.as_ref().map(|(addr, _)| *addr),
        eh_frame_hdr: eh_frame_hdr.map(|(_, data)| data),
        got_svma: find_section_range(".got", &elf),
        load_segments: collect_load_segments(&elf).into_boxed_slice(),
    })
}

/// Calculate the base SVMA from `PT_LOAD` segments.
///
/// This matches the relative-address base of the object itself: the virtual
/// address of the first `PT_LOAD` segment.
fn calculate_base_svma(elf: &Elf) -> u64 {
    elf.program_headers
        .iter()
        .find(|ph| ph.p_type == PT_LOAD)
        .map_or(0, |ph| ph.p_vaddr)
}

fn collect_load_segments(elf: &Elf) -> Vec<LoadSegment> {
    let mut segments: Vec<_> = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| LoadSegment {
            p_offset: ph.p_offset,
            p_filesz: ph.p_filesz,
            p_memsz: ph.p_memsz,
            p_vaddr: ph.p_vaddr,
            p_flags: ph.p_flags,
        })
        .collect();
    segments.sort_by_key(|segment| segment.p_offset);
    segments
}

/// Find a section header by name.
fn find_section_header<'a>(name: &str, elf: &'a Elf) -> Option<&'a goblin::elf::SectionHeader> {
    elf.section_headers.iter().find(|sh| {
        elf.shdr_strtab
            .get_at(sh.sh_name)
            .is_some_and(|n| n == name)
    })
}

#[cfg(test)]
fn find_section_range_in_file(name: &str, elf: &Elf) -> Option<(u64, Range<usize>)> {
    let sh = find_section_header(name, elf)?;
    section_range_in_file(sh)
}

fn section_range_in_file(sh: &goblin::elf::SectionHeader) -> Option<(u64, Range<usize>)> {
    let start = sh.sh_offset.try_into().ok()?;
    let size: usize = sh.sh_size.try_into().ok()?;
    Some((sh.sh_addr, start..start.checked_add(size)?))
}

fn find_unwind_section_data(
    name: &str,
    elf: &Elf,
    object_file: Option<&object::File<'_>>,
    data: &ElfFileData,
) -> Option<(u64, ElfSectionData)> {
    let section = find_section_header(name, elf)?;
    if section_has_compressed_data(section) {
        return object_file.and_then(|file| find_section_data_with_object(name, file, data));
    }

    let (addr, range) = section_range_in_file(section)?;
    data.section(range).map(|data| (addr, data))
}

fn unwind_sections_have_compressed_data(elf: &Elf) -> bool {
    [".eh_frame", ".eh_frame_hdr"]
        .into_iter()
        .filter_map(|name| find_section_header(name, elf))
        .any(section_has_compressed_data)
}

fn section_has_compressed_data(section: &goblin::elf::SectionHeader) -> bool {
    section.sh_flags & u64::from(SHF_COMPRESSED) != 0
}

fn find_section_data_with_object(
    name: &str,
    file: &object::File<'_>,
    storage: &ElfFileData,
) -> Option<(u64, ElfSectionData)> {
    let section = file.section_by_name(name)?;
    let file_range = section.compressed_file_range().ok()?;
    let data = match file_range.format {
        CompressionFormat::None => {
            let range = checked_usize_range(file_range.offset, file_range.uncompressed_size)?;
            storage.section(range)
        }
        _ => {
            let compressed = file_range.data(storage.bytes()).ok()?;
            let decompressed = compressed.decompress().ok()?;
            Some(ElfSectionData::owned(decompressed.into_owned()))
        }
    }?;
    Some((section.address(), data))
}

fn checked_usize_range(start: u64, size: u64) -> Option<Range<usize>> {
    let start = usize::try_from(start).ok()?;
    let size = usize::try_from(size).ok()?;
    Some(start..start.checked_add(size)?)
}

fn checked_u64_range(start: u64, size: u64) -> Option<Range<u64>> {
    Some(start..start.checked_add(size)?)
}

/// Find a section by name and return its SVMA range.
fn find_section_range(name: &str, elf: &Elf) -> Option<Range<u64>> {
    let sh = find_section_header(name, elf)?;
    checked_u64_range(sh.sh_addr, sh.sh_size)
}

/// Find a section by name and return its file-offset range.
fn find_section_file_range(name: &str, elf: &Elf) -> Option<Range<u64>> {
    let sh = find_section_header(name, elf)?;
    checked_u64_range(sh.sh_offset, sh.sh_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_extract_sections_from_libc() {
        // Test with libc which should always be available
        let libc_paths = [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/usr/lib/libc.so.6",
        ];

        let result = libc_paths
            .iter()
            .find_map(|path| load_elf_sections_from_path(Path::new(path)).ok());
        let Some(result) = result else {
            eprintln!("No libc found, skipping test");
            return;
        };
        assert!(result.text_svma.is_some(), "libc should have .text section");
        assert!(
            result.eh_frame.is_some() || result.eh_frame_hdr.is_some(),
            "libc should have .eh_frame or .eh_frame_hdr"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[allow(clippy::manual_is_multiple_of)]
    fn test_calculate_base_svma_from_real_elf() {
        use std::fs::File;

        let paths = [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/usr/lib/libc.so.6",
            "/bin/ls",
            "/usr/bin/ls",
        ];

        for path in &paths {
            if let Ok(file) = File::open(path) {
                if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                    if let Ok(elf) = Elf::parse(&mmap) {
                        let base = calculate_base_svma(&elf);
                        let first_load = elf
                            .program_headers
                            .iter()
                            .find(|ph| ph.p_type == PT_LOAD)
                            .map(|ph| ph.p_vaddr)
                            .unwrap_or(0);
                        assert!(
                            base == first_load,
                            "base_svma {base:#x} should match first PT_LOAD {first_load:#x} for {path}",
                        );
                        return;
                    }
                }
            }
        }
        eprintln!("No ELF binary found, skipping test");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_missing_section_returns_none() {
        use std::fs::File;

        let paths = ["/bin/ls", "/usr/bin/ls"];

        for path in &paths {
            if let Ok(file) = File::open(path) {
                if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                    if let Ok(elf) = Elf::parse(&mmap) {
                        // .nonexistent_section_xyz should not exist
                        let missing = find_section_range_in_file(".nonexistent_section_xyz", &elf);
                        assert!(
                            missing.is_none(),
                            "nonexistent section file range should return None"
                        );

                        let missing_range = find_section_range(".nonexistent_section_xyz", &elf);
                        assert!(
                            missing_range.is_none(),
                            "nonexistent section range should return None"
                        );
                        return;
                    }
                }
            }
        }
        eprintln!("No ELF binary found, skipping test");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_compressed_section_data_is_decompressed() {
        use std::fs::{self, File};
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::time::{SystemTime, UNIX_EPOCH};

        if !command_available("cc") || !command_available("objcopy") {
            eprintln!("cc or objcopy missing, skipping compressed-section test");
            return;
        }

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "stackpulse-compressed-section-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();

        let expected = vec![b'A'; 4096];
        let asm_path = root.join("section.s");
        let object_path = root.join("section.o");
        let compressed_path = root.join("section-compressed.o");
        let mut asm = File::create(&asm_path).unwrap();
        writeln!(asm, ".section .debug_stackpulse,\"\",@progbits").unwrap();
        writeln!(asm, ".fill {},1,{}", expected.len(), expected[0]).unwrap();

        let cc_status = Command::new("cc")
            .arg("-c")
            .arg(&asm_path)
            .arg("-o")
            .arg(&object_path)
            .status()
            .unwrap();
        assert!(cc_status.success(), "cc failed to build test object");

        let objcopy_status = Command::new("objcopy")
            .arg("--compress-debug-sections=zlib-gabi")
            .arg(&object_path)
            .arg(&compressed_path)
            .status()
            .unwrap();
        assert!(
            objcopy_status.success(),
            "objcopy failed to compress test object"
        );

        let file = File::open(&compressed_path).unwrap();
        let mmap = Arc::new(unsafe { Mmap::map(&file).unwrap() });
        let object_file = object::File::parse(&mmap[..]).unwrap();
        let compressed_range = object_file
            .section_by_name(".debug_stackpulse")
            .unwrap()
            .compressed_file_range()
            .unwrap();
        assert_ne!(compressed_range.format, CompressionFormat::None);

        let (_addr, data) = find_section_data_with_object(
            ".debug_stackpulse",
            &object_file,
            &ElfFileData::Mmap(Arc::clone(&mmap)),
        )
        .unwrap();
        assert_eq!(&data[..], expected.as_slice());

        fs::remove_dir_all(root).unwrap();

        fn command_available(command: &str) -> bool {
            Command::new(command)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok()
        }
    }

    #[test]
    fn test_load_elf_sections_from_nonexistent_path() {
        let result = load_elf_sections_from_path(Path::new("/nonexistent/path/to/binary"));
        assert!(result.is_err(), "nonexistent path should return error");
    }

    #[test]
    fn test_load_elf_sections_from_non_elf() {
        // /etc/passwd is definitely not an ELF file
        #[cfg(unix)]
        {
            let err = load_elf_sections_from_path(Path::new("/etc/passwd"))
                .expect_err("non-ELF file should return error");
            let Error::ElfParse(parse) = err else {
                panic!("non-ELF file should return structured parse error");
            };
            assert_eq!(parse.path(), Path::new("/etc/passwd"));
            assert!(std::error::Error::source(&parse).is_some());
        }
    }
}
