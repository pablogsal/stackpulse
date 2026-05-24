//! Shared ELF section extraction for DWARF unwinding.
//!
//! This module provides common functionality for loading ELF sections
//! needed by framehop for stack unwinding. Used by both `ModuleManager`
//! (live processes) and `CoreModuleLoader` (core files).

use super::elf_types::{ElfSectionData, ElfSectionInfo, ModuleInfo};
use crate::elf::{
    collect_load_segments, file_ranges_correlate, find_load_contribution_for_file_range,
    LoadSegment,
};
use crate::error::{Error, Result};
use crate::ModuleImageBase;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SvmaFileRange {
    svma: u64,
    file_offset: u64,
    size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReferenceContribution<'a> {
    Segment(&'a LoadSegment),
    Text(SvmaFileRange),
}

impl ReferenceContribution<'_> {
    fn file_range(self) -> SvmaFileRange {
        match self {
            Self::Segment(seg) => contribution_from_segment(seg),
            Self::Text(range) => range,
        }
    }

    fn is_executable(self) -> bool {
        match self {
            Self::Segment(seg) => (seg.p_flags & 0x1) != 0,
            Self::Text(_) => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedElfMapping {
    pub image_base: ModuleImageBase,
    pub is_executable: bool,
}

pub struct ElfImageLayout<'a> {
    info: &'a ElfSectionInfo,
}

impl<'a> ElfImageLayout<'a> {
    pub fn new(info: &'a ElfSectionInfo) -> Self {
        Self { info }
    }

    #[must_use]
    pub fn base_svma(&self) -> u64 {
        self.info.base_svma
    }

    #[must_use]
    pub fn resolve_mapping(
        &self,
        mapping_start_file_offset: u64,
        mapping_start_avma: u64,
        mapping_span: u64,
    ) -> Option<ResolvedElfMapping> {
        let reference = self.reference_contribution(mapping_start_file_offset, mapping_span)?;
        let image_base = resolve_image_base_from_reference(
            self.base_svma(),
            reference.file_range(),
            mapping_start_file_offset,
            mapping_start_avma,
        );

        Some(ResolvedElfMapping {
            image_base,
            is_executable: reference.is_executable(),
        })
    }

    fn reference_contribution(
        &self,
        mapping_start_file_offset: u64,
        mapping_span: u64,
    ) -> Option<ReferenceContribution<'a>> {
        find_load_contribution_for_file_range(
            &self.info.load_segments,
            mapping_start_file_offset,
            mapping_span,
        )
        .map(ReferenceContribution::Segment)
        .or_else(|| {
            self.info
                .load_segments
                .is_empty()
                .then(|| self.text_reference(mapping_start_file_offset, mapping_span))?
        })
    }

    fn text_reference(
        &self,
        mapping_start_file_offset: u64,
        mapping_span: u64,
    ) -> Option<ReferenceContribution<'a>> {
        let (text_svma, text_file_range) = (
            self.info.text_svma.as_ref()?,
            self.info.text_file_range.as_ref()?,
        );
        let text = SvmaFileRange {
            svma: text_svma.start,
            file_offset: text_file_range.start,
            size: text_file_range.end.saturating_sub(text_file_range.start),
        };
        file_ranges_correlate(
            text.file_offset,
            text.size,
            mapping_start_file_offset,
            mapping_span,
        )
        .then_some(ReferenceContribution::Text(text))
    }
}

pub fn load_elf_sections_from_path(path: &Path) -> Result<ElfSectionInfo> {
    use std::fs::File;

    let file = File::open(path)?;
    let mmap = Arc::new(unsafe { Mmap::map(&file) }?);
    let bytes = &mmap[..];

    // Use lazy parsing rather than Elf::parse to avoid reading symbol tables
    // and relocation sections; on a cold page cache those can be several MB per
    // library and block the sample loop for seconds in CI containers.
    let parse_err = |e: goblin::error::Error| {
        Error::RuntimeError(format!("Failed to parse ELF {}: {}", path.display(), e))
    };
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
    let text = find_unwind_section_data(".text", &elf, object_file.as_ref(), &mmap);
    let eh_frame = find_unwind_section_data(".eh_frame", &elf, object_file.as_ref(), &mmap);
    let eh_frame_hdr = find_unwind_section_data(".eh_frame_hdr", &elf, object_file.as_ref(), &mmap);

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

/// Find a section header by name.
fn find_section_header<'a>(name: &str, elf: &'a Elf) -> Option<&'a goblin::elf::SectionHeader> {
    elf.section_headers.iter().find(|sh| {
        elf.shdr_strtab
            .get_at(sh.sh_name)
            .is_some_and(|n| n == name)
    })
}

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
    mmap: &Arc<Mmap>,
) -> Option<(u64, ElfSectionData)> {
    let section = find_section_header(name, elf)?;
    if section_has_compressed_data(section) {
        return object_file.and_then(|file| find_section_data_with_object(name, file, mmap));
    }

    let (addr, range) = section_range_in_file(section)?;
    ElfSectionData::mmap(Arc::clone(mmap), range).map(|data| (addr, data))
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
    mmap: &Arc<Mmap>,
) -> Option<(u64, ElfSectionData)> {
    let section = file.section_by_name(name)?;
    let file_range = section.compressed_file_range().ok()?;
    let data = match file_range.format {
        CompressionFormat::None => {
            let range = checked_usize_range(file_range.offset, file_range.uncompressed_size)?;
            ElfSectionData::mmap(Arc::clone(mmap), range)
        }
        _ => {
            let compressed = file_range.data(&mmap[..]).ok()?;
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

/// Find a section by name and return its SVMA range.
fn find_section_range(name: &str, elf: &Elf) -> Option<Range<u64>> {
    find_section_header(name, elf).map(|sh| sh.sh_addr..(sh.sh_addr + sh.sh_size))
}

/// Find a section by name and return its file-offset range.
fn find_section_file_range(name: &str, elf: &Elf) -> Option<Range<u64>> {
    find_section_header(name, elf).map(|sh| sh.sh_offset..(sh.sh_offset + sh.sh_size))
}

fn contribution_from_segment(seg: &crate::elf::LoadSegment) -> SvmaFileRange {
    SvmaFileRange {
        svma: seg.p_vaddr,
        file_offset: seg.p_offset,
        size: seg.p_filesz,
    }
}

fn resolve_image_base_from_reference(
    base_svma: u64,
    reference: SvmaFileRange,
    mapping_start_file_offset: u64,
    mapping_start_avma: u64,
) -> ModuleImageBase {
    let image_bias = crate::elf::compute_vma_bias(
        reference.file_offset,
        reference.svma,
        mapping_start_file_offset,
        mapping_start_avma,
    );
    ModuleImageBase::new(base_svma.wrapping_add(image_bias), base_svma)
}

/// Calculate the memory range from `PT_LOAD` segments.
///
/// Returns (`min_vaddr`, `max_vaddr`) covering all loadable segments.
#[cfg(test)]
fn calculate_memory_range(elf: &Elf) -> (u64, u64) {
    let (min, max) = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .fold((u64::MAX, 0u64), |(mi, ma), ph| {
            (mi.min(ph.p_vaddr), ma.max(ph.p_vaddr + ph.p_memsz))
        });
    if min == u64::MAX {
        (0, 0)
    } else {
        (min, max)
    }
}

/// Convert a `ModuleInfo` to a framehop Module.
///
/// Uses one image-wide `base_avma` / `base_svma` pair together with the
/// mapping-specific `avma_range`.
///
/// This is the shared conversion logic used by both `ModuleManager`
/// and `CoreModuleLoader`.
pub fn module_to_framehop(module: &ModuleInfo) -> Option<framehop::Module<ElfSectionData>> {
    let section_info = module.section_info.as_ref()?;
    module_to_framehop_with_section_info(module, section_info)
}

#[inline]
fn svma_range(svma: Option<u64>, data: Option<&ElfSectionData>) -> Option<Range<u64>> {
    let addr = svma?;
    let len = data?.len() as u64;
    Some(addr..addr + len)
}

pub fn module_to_framehop_with_section_info(
    module: &ModuleInfo,
    section_info: &ElfSectionInfo,
) -> Option<framehop::Module<ElfSectionData>> {
    let image_base = module.image_base?;

    let explicit_info = framehop::ExplicitModuleSectionInfo {
        base_svma: image_base.svma,
        text_svma: section_info.text_svma.clone(),
        text: section_info.text.clone(),
        stubs_svma: None,
        stub_helper_svma: None,
        got_svma: section_info.got_svma.clone(),
        unwind_info: None,
        eh_frame_svma: svma_range(section_info.eh_frame_svma, section_info.eh_frame.as_ref()),
        eh_frame: section_info.eh_frame.clone(),
        eh_frame_hdr_svma: svma_range(
            section_info.eh_frame_hdr_svma,
            section_info.eh_frame_hdr.as_ref(),
        ),
        eh_frame_hdr: section_info.eh_frame_hdr.clone(),
        debug_frame: None,
        text_segment_svma: None,
        text_segment: None,
    };

    Some(framehop::Module::new(
        module.name.clone(),
        module.avma_range.clone(),
        image_base.avma,
        explicit_info,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::test_fixtures::fake_hard_case_section_info;

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
    fn test_resolve_mapping_matches_samply_hard_case() {
        let section_info = fake_hard_case_section_info();

        let resolved = ElfImageLayout::new(&section_info)
            .resolve_mapping(0x14bd000, 0x55d605384000, 0xf5d000)
            .map(|resolved| resolved.image_base);
        assert_eq!(resolved, Some(ModuleImageBase::new(0x55d603ec6000, 0)));
    }

    #[test]
    fn test_resolve_mapping_falls_back_to_text_section() {
        let section_info = ElfSectionInfo {
            base_svma: 0,
            text_svma: Some(0x4000..0x5000),
            text_file_range: Some(0x3000..0x4000),
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: Box::default(),
        };

        let resolved = ElfImageLayout::new(&section_info)
            .resolve_mapping(0x3000, 0x7f00_1000, 0x1000)
            .map(|resolved| resolved.image_base);
        assert_eq!(resolved, Some(ModuleImageBase::new(0x7eff_d000, 0)));
    }

    #[test]
    fn test_resolve_mapping_does_not_guess_from_page_overlap() {
        let section_info = ElfSectionInfo {
            base_svma: 0,
            text_svma: Some(0x23c10..0x24c10),
            text_file_range: Some(0x13c10..0x14c10),
            text: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            got_svma: None,
            load_segments: vec![crate::elf::LoadSegment {
                p_offset: 0x13c10,
                p_filesz: 0x1000,
                p_memsz: 0x1000,
                p_vaddr: 0x23c10,
                p_flags: 0x5,
            }]
            .into_boxed_slice(),
        };

        let resolved = ElfImageLayout::new(&section_info)
            .resolve_mapping(0x13000, 0x5555_5556_8000, 0x800)
            .map(|resolved| resolved.image_base);
        assert_eq!(resolved, None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_calculate_memory_range_from_real_elf() {
        use std::fs::File;

        let paths = ["/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/cat"];

        for path in &paths {
            if let Ok(file) = File::open(path) {
                if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                    if let Ok(elf) = Elf::parse(&mmap) {
                        let (min, max) = calculate_memory_range(&elf);
                        // Should have valid range
                        assert!(max >= min, "max should be >= min");
                        if min != u64::MAX {
                            // If we found PT_LOAD segments, range should be reasonable
                            assert!(max - min > 0, "memory range should be non-zero");
                        }
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

        let (_addr, data) =
            find_section_data_with_object(".debug_stackpulse", &object_file, &mmap).unwrap();
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
            let result = load_elf_sections_from_path(Path::new("/etc/passwd"));
            assert!(result.is_err(), "non-ELF file should return error");
        }
    }
}
