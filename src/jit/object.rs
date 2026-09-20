//! Registered ELF images, symbol ownership, and live unwind sections.
use super::protocol::{self, JitObjectId};
use super::{jit_error, MAX_JIT_READ_SIZE};
use super::{MemoryReader, Symbol};
use crate::elf::find_section_range;
use goblin::elf::{header::ET_REL, section_header::SHN_UNDEF};
use std::hash::Hasher;
use std::io;
use std::ops::Deref;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

const MAX_JIT_SYMBOLS: usize = 1_000_000;

pub(super) struct JitObject<D> {
    pub(super) code_ranges: Box<[Range<u64>]>,
    pub(super) pending_modules: Box<[framehop::Module<D>]>,
    pub(super) symbols: Option<Vec<Symbol>>,
    pub(super) image_fingerprint: u64,
    pub(super) unwind: JitUnwind,
}

#[derive(Debug)]
pub(super) enum CfiState {
    Absent,
    Unreadable { range: Range<u64> },
    Loaded { range: Range<u64>, fingerprint: u64 },
}

pub(super) struct JitUnwind {
    pub(super) cfi: CfiState,
    pub(super) text: Option<Range<u64>>,
    pub(super) got: Option<Range<u64>>,
}

pub(super) struct UnwindUpdate<D> {
    pub(super) unwind: JitUnwind,
    pub(super) modules: Box<[framehop::Module<D>]>,
}

pub(super) enum ObjectChange<D> {
    Unchanged,
    Image,
    Unwind(UnwindUpdate<D>),
}

impl<D: From<Arc<[u8]>> + Deref<Target = [u8]> + Clone> JitObject<D> {
    pub(super) fn load<P: MemoryReader>(
        process: &P,
        id: JitObjectId,
        remaining_cfi: &mut u64,
    ) -> io::Result<Self> {
        if id.symfile_size == 0 {
            return Err(jit_error("GDB JIT symfile", "invalid size 0".into()));
        }
        let path = id.path();
        let data = protocol::read_memory(process, id.symfile_addr, id.symfile_size)?;
        let elf =
            goblin::elf::Elf::parse(&data).map_err(|error| io::Error::other(error.to_string()))?;
        if !elf.is_64 || !elf.little_endian {
            return Err(jit_error("GDB JIT ELF", "unsupported architecture".into()));
        }
        let code_ranges = executable_section_ranges(&elf);
        if code_ranges
            .windows(2)
            .any(|pair| pair[0].end > pair[1].start)
        {
            return Err(jit_error(
                "GDB JIT ELF",
                "overlapping executable sections".into(),
            ));
        }
        let mut symbols = jit_symbols(&elf, &code_ranges)?;
        symbols.extend(
            code_ranges
                .iter()
                .cloned()
                .map(|range| Symbol { range, name: None }),
        );
        let range = find_section_range(".eh_frame", &elf)
            .filter(|range| range.start != 0 && !range.is_empty());
        let bytes = range.as_ref().and_then(|range| {
            let size = range.end - range.start;
            if size > *remaining_cfi {
                return None;
            }
            let bytes = protocol::read_memory(process, range.start, size).ok()?;
            *remaining_cfi -= size;
            Some(bytes)
        });
        let cfi = match (range, &bytes) {
            (None, _) => CfiState::Absent,
            (Some(range), None) => CfiState::Unreadable { range },
            (Some(range), Some(bytes)) => CfiState::Loaded {
                range,
                fingerprint: fingerprint(bytes),
            },
        };
        let unwind = JitUnwind {
            cfi,
            text: find_section_range(".text", &elf).filter(|range| !range.is_empty()),
            got: find_section_range(".got", &elf).filter(|range| !range.is_empty()),
        };
        let pending_modules = unwind.build_modules(&path, &code_ranges, bytes);
        Ok(Self {
            code_ranges,
            pending_modules,
            symbols: Some(symbols),
            image_fingerprint: fingerprint(&data),
            unwind,
        })
    }

    /// CFI changes retain the already parsed symbols and executable layout.
    pub(super) fn inspect<P: MemoryReader>(
        &self,
        process: &P,
        id: JitObjectId,
        scratch: &mut Vec<u8>,
        remaining_cfi: &mut u64,
    ) -> io::Result<ObjectChange<D>> {
        protocol::read_memory_into(process, id.symfile_addr, id.symfile_size, scratch)?;
        if fingerprint(scratch) != self.image_fingerprint {
            return Ok(ObjectChange::Image);
        }
        let (range, old_fingerprint) = match &self.unwind.cfi {
            CfiState::Absent => return Ok(ObjectChange::Unchanged),
            CfiState::Unreadable { range } => (range, None),
            CfiState::Loaded { range, fingerprint } => (range, Some(*fingerprint)),
        };
        let size = range.end - range.start;
        if size > *remaining_cfi {
            return Err(jit_error(
                "GDB JIT CFI",
                "live sections exceed aggregate bounds".into(),
            ));
        }
        protocol::read_memory_into(process, range.start, size, scratch)?;
        let new_fingerprint = fingerprint(scratch);
        if old_fingerprint == Some(new_fingerprint) {
            return Ok(ObjectChange::Unchanged);
        }
        let unwind = JitUnwind {
            cfi: CfiState::Loaded {
                range: range.clone(),
                fingerprint: new_fingerprint,
            },
            text: self.unwind.text.clone(),
            got: self.unwind.got.clone(),
        };
        let modules = unwind.build_modules(&id.path(), &self.code_ranges, Some(scratch.clone()));
        *remaining_cfi -= size;
        Ok(ObjectChange::Unwind(UnwindUpdate { unwind, modules }))
    }

    pub(super) fn apply_unwind(&mut self, update: UnwindUpdate<D>) {
        self.unwind = update.unwind;
        self.pending_modules = update.modules;
    }
}

impl JitUnwind {
    /// Empty CFI still reserves every code range against ordinary mapping rules.
    fn build_modules<D: From<Arc<[u8]>> + Deref<Target = [u8]> + Clone>(
        &self,
        path: &Path,
        code_ranges: &[Range<u64>],
        bytes: Option<Vec<u8>>,
    ) -> Box<[framehop::Module<D>]> {
        let Some(first) = code_ranges.first() else {
            return Box::default();
        };
        let base = first.start;
        let text = self.text.as_ref().unwrap_or(first);
        let eh_frame = match &self.cfi {
            CfiState::Absent => None,
            CfiState::Unreadable { range } | CfiState::Loaded { range, .. } => Some(range.clone()),
        };
        // Share one index across sections; absolute addresses also cover sparse images.
        let eh_frame_hdr = bytes
            .as_deref()
            .zip(eh_frame.as_ref())
            .and_then(|(bytes, range)| {
                absolute_cfi_header(bytes, range.start, text.start, self.got.as_ref())
            });
        // A failed parse must not trigger another full index build in every module.
        let bytes = bytes.filter(|_| eh_frame_hdr.is_some());
        let sections = framehop::ExplicitModuleSectionInfo {
            base_svma: base,
            // Header construction and FDE evaluation share the image's text base.
            text_svma: Some(text.clone()),
            text: None,
            stubs_svma: None,
            stub_helper_svma: None,
            got_svma: self.got.clone(),
            unwind_info: None,
            eh_frame_svma: eh_frame,
            eh_frame: bytes.map(|bytes| D::from(Arc::<[u8]>::from(bytes))),
            eh_frame_hdr_svma: eh_frame_hdr.as_ref().map(|header| 0..header.len() as u64),
            eh_frame_hdr: eh_frame_hdr.map(D::from),
            debug_frame: None,
            text_segment_svma: None,
            text_segment: None,
        };
        let name = path.display().to_string();
        code_ranges
            .iter()
            .map(|range| {
                let mut sections = sections.clone();
                sections.base_svma = range.start;
                framehop::Module::new(name.clone(), range.clone(), range.start, sections)
            })
            .collect()
    }
}

/// Build a shared 64-bit lookup table without rewriting live CFI pointers.
fn absolute_cfi_header(
    bytes: &[u8],
    address: u64,
    text: u64,
    got: Option<&Range<u64>>,
) -> Option<Arc<[u8]>> {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};

    let mut section = EhFrame::new(bytes, LittleEndian);
    section.set_address_size(8);
    let bases = BaseAddresses::default()
        .set_eh_frame(address)
        .set_text(text)
        .set_got(got.map_or(0, |range| range.start));
    let mut entries = section.entries(&bases);
    let mut table = Vec::new();
    while let Some(entry) = entries.next().ok()? {
        if let CieOrFde::Fde(entry) = entry {
            let fde = entry.parse(EhFrame::cie_from_offset).ok()?;
            table.push((
                fde.initial_address(),
                address.checked_add(fde.offset() as u64)?,
            ));
        }
    }
    table.sort_unstable_by_key(|&(pc, _)| pc);
    let encoding = gimli::DW_EH_PE_udata8.0;
    let mut header = Vec::with_capacity(20 + table.len() * 16);
    header.extend_from_slice(&[1, encoding, encoding, encoding]);
    header.extend_from_slice(&address.to_le_bytes());
    header.extend_from_slice(&(table.len() as u64).to_le_bytes());
    for (pc, fde) in table {
        header.extend_from_slice(&pc.to_le_bytes());
        header.extend_from_slice(&fde.to_le_bytes());
    }
    Some(header.into())
}

/// Return sorted half-open executable section ranges with nonzero addresses.
fn executable_section_ranges(elf: &goblin::elf::Elf<'_>) -> Box<[Range<u64>]> {
    let mut ranges: Vec<_> = elf
        .section_headers
        .iter()
        .filter(|section| section.sh_addr != 0 && section.sh_size != 0 && section.is_executable())
        .filter_map(|section| {
            section
                .sh_addr
                .checked_add(section.sh_size)
                .map(|end| section.sh_addr..end)
        })
        .collect();
    ranges.sort_unstable_by_key(|range| range.start);
    ranges.into_boxed_slice()
}

/// Build function symbols bounded by their executable sections.
///
/// Zero-sized symbols extend to the next symbol or the end of their section.
pub(super) fn jit_symbols(
    elf: &goblin::elf::Elf<'_>,
    code_ranges: &[Range<u64>],
) -> io::Result<Vec<Symbol>> {
    let mut symbols: Vec<_> = elf
        .syms
        .iter()
        .filter(|symbol| symbol.is_function() && symbol.st_shndx != SHN_UNDEF as usize)
        .filter_map(|symbol| {
            let section = elf.section_headers.get(symbol.st_shndx)?;
            let start = if elf.header.e_type == ET_REL {
                section.sh_addr.checked_add(symbol.st_value)?
            } else {
                symbol.st_value
            };
            let range = code_ranges.iter().find(|range| range.contains(&start))?;
            let raw_name = elf.strtab.get_at(symbol.st_name)?;
            Some((start, symbol.st_size, range.end, raw_name))
        })
        .collect();
    if symbols.len() > MAX_JIT_SYMBOLS {
        return Err(jit_error(
            "GDB JIT symbols",
            "symbol table exceeds bounds".into(),
        ));
    }
    // Many symbols can reference one string, so ELF size alone does not bound
    // the memory used when names are copied and demangled.
    let mut name_budget = MAX_JIT_READ_SIZE as usize;
    for (_, _, _, name) in &symbols {
        if name.len() > 1024 * 1024 || name.len() > name_budget {
            return Err(jit_error(
                "GDB JIT symbols",
                "symbol names exceed bounds".into(),
            ));
        }
        name_budget -= name.len();
    }
    symbols.sort_unstable_by_key(|(start, ..)| *start);
    Ok(symbols
        .iter()
        .filter_map(|(start, size, section_end, name)| {
            let end = if *size == 0 {
                symbols
                    .get(symbols.partition_point(|(next, ..)| next <= start))
                    .map_or(*section_end, |(next, ..)| (*next).min(*section_end))
            } else {
                start.checked_add(*size)?.min(*section_end)
            };
            (*start < end).then(|| Symbol {
                range: *start..end,
                name: Some((*name).to_owned()),
            })
        })
        .collect())
}

fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hasher = rustc_hash::FxHasher::default();
    hasher.write(bytes);
    hasher.finish()
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use framehop::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
    use framehop::{FrameAddress, MayAllocateDuringUnwind, Unwinder};

    #[test]
    fn malformed_cfi_preserves_distant_code_ranges() {
        let ranges = [0x8000..0x8010, 0x1_0000_8000..0x1_0000_8010];
        let cfi = vec![0xff; 8];
        let unwind = JitUnwind {
            cfi: CfiState::Loaded {
                range: 0x9000..0x9008,
                fingerprint: fingerprint(&cfi),
            },
            text: None,
            got: None,
        };
        let modules =
            unwind.build_modules::<Arc<[u8]>>(Path::new("[jit-wide]"), &ranges, Some(cfi));
        assert_eq!(modules.len(), ranges.len());
        for (module, range) in modules.iter().zip(ranges) {
            assert_eq!(module.avma_range(), range);
        }
    }

    #[test]
    fn executable_sections_unwind_with_shared_cfi() {
        for second in [0x8100, 0x1_0000_8000] {
            let addresses = [0x8000_u64, second];
            for text_index in [0, 1] {
                for text_relative in [false, true] {
                    let encoding = if text_relative { 0x2c } else { 0x04 };
                    // A CIE with zR augmentation: CFA = rsp + 48, return address at CFA - 8.
                    let mut cfi = vec![
                        20, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, encoding, 0x0c,
                        7, 48, 0x90, 1, 0, 0,
                    ];
                    for (index, address) in addresses.into_iter().enumerate() {
                        let cie_pointer = cfi.len() as u32 + 4;
                        cfi.extend_from_slice(&24_u32.to_le_bytes());
                        cfi.extend_from_slice(&cie_pointer.to_le_bytes());
                        let pc = if text_relative {
                            address.wrapping_sub(addresses[text_index])
                        } else {
                            address
                        };
                        cfi.extend_from_slice(&pc.to_le_bytes());
                        cfi.extend_from_slice(&16_u64.to_le_bytes());
                        cfi.extend_from_slice(&[0, 0x0e, 48 + index as u8 * 16, 0]);
                        // CFA offset differs per function.
                    }
                    cfi.extend_from_slice(&0_u32.to_le_bytes());
                    let unwind = JitUnwind {
                        cfi: CfiState::Loaded {
                            range: 0x9000..0x9000 + cfi.len() as u64,
                            fingerprint: fingerprint(&cfi),
                        },
                        text: Some(addresses[text_index]..addresses[text_index] + 16),
                        got: None,
                    };
                    let ranges = addresses.map(|address| address..address + 16);
                    let modules = unwind.build_modules::<Arc<[u8]>>(
                        Path::new("[jit-wide]"),
                        &ranges,
                        Some(cfi),
                    );
                    let mut unwinder = UnwinderX86_64::<_, MayAllocateDuringUnwind>::new();
                    for module in modules {
                        unwinder.add_module(module);
                    }
                    let mut cache = CacheX86_64::new();
                    for (index, address) in addresses.into_iter().enumerate() {
                        let cfa_offset = 48 + index as u64 * 16;
                        let mut regs = UnwindRegsX86_64::new(address + 1, 0x1000, 0);
                        let caller = unwinder
                            .unwind_frame(
                                FrameAddress::from_instruction_pointer(address + 1),
                                &mut regs,
                                &mut cache,
                                &mut |address| {
                                    if address == 0x1000 + cfa_offset - 8 {
                                        Ok(0xbeef)
                                    } else {
                                        Err(())
                                    }
                                },
                            )
                            .unwrap();
                        assert_eq!(caller, Some(0xbeef), "section at {address:#x}");
                        assert_eq!(regs.sp(), 0x1000 + cfa_offset);
                    }
                }
            }
        }
    }
}
