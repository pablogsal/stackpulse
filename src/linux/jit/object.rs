//! Decode registered ELF symbols and copy live unwind data from target memory.
//!
//! The registered ELF supplies section addresses, but its CFI bytes may be
//! unrelocated. Copy CFI from live memory instead. Even a successful read can
//! precede finalization, so content changes invalidate copied unwind rules.

use super::protocol::{invalid, read, read_into, ObjectId};
use crate::elf::ElfSectionData;
use crate::spool::model::{JitSymbol, MAX_JIT_SYMBOLS, MAX_JIT_SYMBOL_NAME};
use crate::spool::ModuleRecord;
use goblin::elf::{header::ET_REL, section_header::SHN_UNDEF, Elf};
use rustc_hash::FxHasher;
use std::fs::File;
use std::hash::Hasher;
use std::io;
use std::ops::Range;

const MAX_SYMBOL_NAME_BYTES: usize = 64 * 1024 * 1024;

/// One registration, split into disjoint executable modules that share CFI.
pub(super) struct JitObject {
    /// Disjoint executable sections and captured symbols; publication assigns module IDs.
    pub(super) modules: Vec<ModuleRecord>,
    /// Unwind modules for those sections, including fallback ownership when CFI is unavailable.
    pub(super) unwind: JitUnwind,
    /// Hash of the registered ELF copy used to detect persistent content changes.
    /// Equality cannot prove that the runtime has not reused the registration.
    image_fingerprint: u64,
}

/// Decoded unwind modules, including fallback-only modules awaiting CFI.
pub(super) struct JitUnwind {
    /// One unwind module per executable section, all sharing the copied CFI when available.
    modules: Vec<framehop::Module<ElfSectionData>>,
    /// Live `.eh_frame` read state, which determines retries and content revalidation.
    cfi: CfiState,
}

/// Whether live CFI can be retried or checked for persistent content changes.
enum CfiState {
    /// The ELF advertises no usable live `.eh_frame` range.
    Absent,
    /// An advertised range could not be copied and should be retried.
    Unreadable,
    /// Copied bytes, which may omit rules for some executable addresses.
    Loaded {
        /// Half-open target address range of live unwind bytes.
        /// A successful copy can still precede the runtime's final relocations.
        range: Range<u64>,
        /// Hash of the copied live bytes, compared during metadata revalidation.
        fingerprint: u64,
    },
}

impl JitObject {
    /// Detect persistent metadata changes even when registration notifications were missed.
    /// Reads the entire ELF image and, when available, the copied live CFI range.
    /// An unchanged fingerprint cannot rule out address reuse.
    pub(super) fn has_changed(
        &self,
        memory: &File,
        id: ObjectId,
        scratch: &mut Vec<u8>,
    ) -> io::Result<bool> {
        read_into(memory, id.address, id.size, scratch)?;
        if fingerprint(scratch) != self.image_fingerprint {
            return Ok(true);
        }
        match &self.unwind.cfi {
            CfiState::Loaded {
                range,
                fingerprint: previous,
            } => {
                read_into(memory, range.start, range.end - range.start, scratch)?;
                Ok(fingerprint(scratch) != *previous)
            }
            CfiState::Absent | CfiState::Unreadable => Ok(false),
        }
    }

    /// Retry relocated CFI without changing symbol identities or code ranges.
    pub(super) fn reload_unwind(&self, memory: &File, id: ObjectId) -> io::Result<JitUnwind> {
        let Some(module) = self.modules.first() else {
            return Ok(JitUnwind {
                modules: Vec::new(),
                cfi: CfiState::Absent,
            });
        };
        let bytes = read(memory, id.address, id.size)?;
        let elf = Elf::parse(&bytes).map_err(|error| invalid(&error.to_string()))?;
        let ranges = executable_ranges(&elf)?;
        if !ranges
            .iter()
            .cloned()
            .eq(self.modules.iter().map(|module| module.start..module.end))
        {
            return Err(invalid("JIT code ranges changed during CFI retry"));
        }
        Ok(load_unwind_modules(
            memory,
            &elf,
            &ranges,
            &module.path.to_string_lossy(),
        ))
    }
}

impl JitUnwind {
    /// Executable ranges retain unwind ownership even when their CFI is unavailable.
    pub(super) fn modules(&self) -> &[framehop::Module<ElfSectionData>] {
        &self.modules
    }

    /// Retry only advertised CFI that could not be read from target memory.
    pub(super) fn needs_retry(&self) -> bool {
        matches!(self.cfi, CfiState::Unreadable)
    }
}

/// Decode one ELF registration and prepare symbol records before publication.
pub(super) fn load_object(memory: &File, pid: i32, id: ObjectId) -> io::Result<JitObject> {
    let bytes = read(memory, id.address, id.size)?;
    let elf = Elf::parse(&bytes).map_err(|error| invalid(&error.to_string()))?;
    let ranges = executable_ranges(&elf)?;
    let name = format!("[jit-{:x}-{:x}-{:x}]", id.entry, id.address, id.size);
    let symbols = symbols(&elf, &ranges)?;
    let pid = crate::Pid::new(pid).ok_or_else(|| invalid("invalid JIT process id"))?;
    let modules = ranges
        .iter()
        .map(|range| {
            let mut module = ModuleRecord::new(0, pid, range.clone(), 0, &name)?;
            module.jit_symbols = Some(
                symbols
                    .iter()
                    .filter(|symbol| range.contains(&symbol.start))
                    .cloned()
                    .collect(),
            );
            Ok(module)
        })
        .collect::<crate::Result<Vec<_>>>()?;
    let unwind = load_unwind_modules(memory, &elf, &ranges, &name);
    Ok(JitObject {
        modules,
        unwind,
        image_fingerprint: fingerprint(&bytes),
    })
}

/// Return sorted, disjoint executable ranges from a supported ELF object.
fn executable_ranges(elf: &Elf<'_>) -> io::Result<Vec<Range<u64>>> {
    if !elf.is_64 || !elf.little_endian {
        return Err(invalid("unsupported JIT ELF architecture"));
    }
    let mut ranges: Vec<_> = elf
        .section_headers
        .iter()
        .filter(|section| section.is_executable() && section.sh_addr != 0 && section.sh_size != 0)
        .filter_map(|section| Some(section.sh_addr..section.sh_addr.checked_add(section.sh_size)?))
        .collect();
    ranges.sort_unstable_by_key(|range| range.start);
    if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(invalid("overlapping JIT code sections"));
    }
    Ok(ranges)
}

/// Copy relocated CFI once and share it across every executable section.
fn load_unwind_modules(
    memory: &File,
    elf: &Elf<'_>,
    ranges: &[Range<u64>],
    name: &str,
) -> JitUnwind {
    let eh_frame =
        section_range(elf, ".eh_frame").filter(|range| range.start != 0 && !range.is_empty());
    let cfi = match &eh_frame {
        Some(range) => match read(memory, range.start, range.end - range.start) {
            Ok(bytes) => Some(ElfSectionData::owned(bytes)),
            Err(error) => {
                tracing::trace!(name, %error, "could not read GDB JIT unwind data");
                None
            }
        },
        None => None,
    };
    // Every range shares this CFI table, including entries in earlier sections.
    let base = ranges.first().map_or(0, |range| range.start);
    let got = section_range(elf, ".got");
    let mut unwind = Vec::new();
    for range in ranges {
        let sections = framehop::ExplicitModuleSectionInfo {
            base_svma: base,
            text_svma: Some(range.clone()),
            text: None,
            stubs_svma: None,
            stub_helper_svma: None,
            got_svma: got.clone(),
            unwind_info: None,
            eh_frame_svma: eh_frame.clone(),
            eh_frame: cfi.clone(),
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            debug_frame: None,
            text_segment_svma: None,
            text_segment: None,
        };
        // An entry without CFI selects fallback unwinding instead of rules from
        // an ordinary ELF mapping that happens to contain the generated code.
        unwind.push(framehop::Module::new(
            name.into(),
            range.clone(),
            base,
            sections,
        ));
    }
    let cfi = match (eh_frame, cfi) {
        (Some(range), Some(bytes)) => CfiState::Loaded {
            range,
            fingerprint: fingerprint(&bytes),
        },
        (Some(_), None) => CfiState::Unreadable,
        (None, _) => CfiState::Absent,
    };
    JitUnwind {
        modules: unwind,
        cfi,
    }
}

/// Find a named section's non-overflowing target-memory address range.
fn section_range(elf: &Elf<'_>, name: &str) -> Option<Range<u64>> {
    let section = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(name))?;
    Some(section.sh_addr..section.sh_addr.checked_add(section.sh_size)?)
}

/// Resolve function ranges, ending zero-sized symbols at the next function.
/// Bound copied names before allocating them.
fn symbols(elf: &Elf<'_>, ranges: &[Range<u64>]) -> io::Result<Vec<JitSymbol>> {
    let mut symbols: Vec<_> = elf
        .syms
        .iter()
        .filter(|s| s.is_function() && s.st_shndx != SHN_UNDEF as usize)
        .filter_map(|symbol| {
            let section = elf.section_headers.get(symbol.st_shndx)?;
            let start = if elf.header.e_type == ET_REL {
                section.sh_addr.checked_add(symbol.st_value)?
            } else {
                symbol.st_value
            };
            let range = ranges.iter().find(|range| range.contains(&start))?;
            let name = elf.strtab.get_at(symbol.st_name)?;
            Some((start, symbol.st_size, range.end, name))
        })
        .collect();
    if symbols.len() > MAX_JIT_SYMBOLS {
        return Err(invalid("GDB JIT symbol table exceeds bounds"));
    }
    // ELF symbols can share names, so input size does not bound copied strings.
    let mut remaining_name_bytes = MAX_SYMBOL_NAME_BYTES;
    for &(_, _, _, name) in &symbols {
        if name.len() > MAX_JIT_SYMBOL_NAME || name.len() > remaining_name_bytes {
            return Err(invalid("GDB JIT symbol names exceed bounds"));
        }
        remaining_name_bytes -= name.len();
    }
    symbols.sort_unstable_by_key(|(start, ..)| *start);
    Ok(symbols
        .iter()
        .filter_map(|&(start, size, limit, name)| {
            let end = if size == 0 {
                symbols
                    .get(symbols.partition_point(|(next, ..)| *next <= start))
                    .map_or(limit, |(next, ..)| (*next).min(limit))
            } else {
                start.checked_add(size)?.min(limit)
            };
            (start < end).then(|| JitSymbol {
                start,
                end,
                name: name.into(),
            })
        })
        .collect())
}

/// Fingerprints detect persistent content changes, not unobserved registration events.
fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hasher = FxHasher::default();
    hasher.write(bytes);
    hasher.finish()
}

#[cfg(test)]
impl JitObject {
    /// Prepare lifecycle fixtures without requiring a registered ELF image.
    pub(super) fn test_with_module(
        module: ModuleRecord,
        unwind: framehop::Module<ElfSectionData>,
        image: &[u8],
    ) -> Self {
        Self {
            modules: vec![module],
            unwind: JitUnwind {
                modules: vec![unwind],
                cfi: CfiState::Absent,
            },
            image_fingerprint: fingerprint(image),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::container::{Container, Ctx, Endian};
    use goblin::elf::{
        header::Header,
        section_header::{SectionHeader, SHF_ALLOC, SHF_EXECINSTR},
        sym::{Symtab, STT_FUNC},
    };
    use goblin::strtab::Strtab;

    #[test]
    fn shared_elf_names_are_bounded_before_copying() {
        for (count, name_len, accepted) in [
            (3, 16, true),
            (65, MAX_JIT_SYMBOL_NAME, false),
            (1, MAX_JIT_SYMBOL_NAME + 1, false),
        ] {
            let mut names = vec![b'f'; name_len + 2];
            names[0] = 0;
            names[name_len + 1] = 0;
            let mut functions = Vec::new();
            for offset in 0..count {
                // ELF64 function records all reference the same string-table entry.
                functions.extend_from_slice(&1_u32.to_le_bytes()); // st_name
                functions.extend_from_slice(&[STT_FUNC, 0]); // st_info, st_other
                functions.extend_from_slice(&1_u16.to_le_bytes()); // st_shndx
                functions.extend_from_slice(&(offset as u64).to_le_bytes()); // st_value
                functions.extend_from_slice(&1_u64.to_le_bytes()); // st_size
            }
            let ctx = Ctx::new(Container::Big, Endian::Little);
            let mut header = Header::new(ctx);
            header.e_type = ET_REL;
            let mut elf = Elf::lazy_parse(header).unwrap();
            elf.section_headers = vec![
                SectionHeader::default(),
                SectionHeader {
                    sh_addr: 0x1000,
                    sh_size: count as u64,
                    sh_flags: u64::from(SHF_ALLOC | SHF_EXECINSTR),
                    ..SectionHeader::default()
                },
            ];
            elf.syms = Symtab::parse(&functions, 0, count, ctx).unwrap();
            elf.strtab = Strtab::parse(&names, 0, names.len(), 0).unwrap();
            let ranges = executable_ranges(&elf).unwrap();
            let allocations = allocation_counter::measure(|| {
                let decoded = symbols(&elf, &ranges);
                if accepted {
                    let decoded = decoded.unwrap();
                    assert_eq!(decoded.len(), count);
                    assert!(decoded.iter().all(|symbol| symbol.name.len() == name_len));
                } else {
                    assert!(
                        matches!(decoded, Err(error) if error.kind() == io::ErrorKind::InvalidData),
                        "{count} functions with {name_len}-byte names"
                    );
                }
            });
            assert!(allocations.bytes_total < MAX_JIT_SYMBOL_NAME as u64);
        }
    }
}
