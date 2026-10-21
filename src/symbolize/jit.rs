//! Resolve pinned generated-code frames from symbols captured during recording.

use std::cell::OnceCell;
use std::rc::Rc;

use crate::profile::{
    AddressSpace, Frame, FrameFlags, NativeFrame, NativeSymbol, NativeSymbolName, SymbolOrigin,
};
use crate::spool::{model::JitSymbol, ModuleRecord};
use crate::symbols::SymbolStrings;

/// Reuse prepared metadata for consecutive addresses in one generated function.
#[derive(Default)]
pub(super) struct SymbolCache {
    last_symbol: Option<((u32, usize), CachedSymbol)>,
    strings: SymbolStrings,
}

struct CachedSymbol {
    name: NativeSymbolName,
    module: Rc<str>,
}

impl CachedSymbol {
    fn resolve(&self) -> NativeSymbol {
        NativeSymbol::from_name(self.name.clone(), Rc::clone(&self.module))
    }
}

impl SymbolCache {
    pub(super) fn clear(&mut self) {
        self.last_symbol = None;
    }

    fn symbol(&mut self, module: &ModuleRecord, index: usize, symbol: &JitSymbol) -> NativeSymbol {
        let key = (module.id, index);
        if let Some((cached_key, symbol)) = &self.last_symbol {
            if *cached_key == key {
                return symbol.resolve();
            }
        }
        let name = self.strings.intern(&symbol.name);
        let path = self.strings.intern(module.path.to_string_lossy().as_ref());
        let symbol = CachedSymbol {
            name: NativeSymbolName::new(name),
            module: path,
        };
        let resolved = symbol.resolve();
        self.last_symbol = Some((key, symbol));
        resolved
    }
}

/// One index per immutable recorded module, built only when a JIT frame needs it.
#[derive(Default)]
pub(super) struct SymbolIndex {
    max_end: OnceCell<Box<[u64]>>,
}

impl SymbolIndex {
    /// Resolve the owner's frame and retain its JIT origin when no symbol matches.
    /// Symbol ranges may overlap and must be sorted by start address.
    pub(super) fn resolve_frame(
        &self,
        module: &ModuleRecord,
        process_id: i32,
        abs_ip: u64,
        cache: &mut SymbolCache,
    ) -> Option<Frame> {
        if module.pid().is_none_or(|pid| pid.get() != process_id) {
            return None;
        }
        let symbols = module.jit_symbols.as_ref()?;
        let max_end = self.max_end.get_or_init(|| {
            let mut end = 0;
            symbols
                .iter()
                .map(|symbol| {
                    end = end.max(symbol.end);
                    end
                })
                .collect()
        });
        let candidates = symbols.partition_point(|symbol| symbol.start <= abs_ip);
        let symbol = symbols[..candidates]
            .iter()
            .zip(&max_end[..candidates])
            .enumerate()
            .rev()
            .take_while(|(_, (_, end))| abs_ip < **end)
            .find_map(|(index, (symbol, _))| (abs_ip < symbol.end).then_some((index, symbol)));
        let native_symbol = if let Some((index, symbol)) = symbol {
            cache
                .symbol(module, index, symbol)
                .with_offset(abs_ip - symbol.start)
        } else {
            let path = cache.strings.intern(module.path.to_string_lossy().as_ref());
            NativeSymbol::new(address_name(abs_ip), path)
        };
        Some(Frame::Native(NativeFrame {
            pc: abs_ip,
            symbol: Some(native_symbol),
            address_space: AddressSpace::User,
            origin: SymbolOrigin::GdbJit,
            flags: FrameFlags::JIT,
        }))
    }
}

fn address_name(address: u64) -> Rc<str> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digits = (u64::BITS - address.leading_zeros()).max(1).div_ceil(4) as usize;
    let mut bytes = *b"<0x0000000000000000>";
    for index in 0..digits {
        let nibble = (address >> ((digits - index - 1) * 4)) & 0xf;
        bytes[3 + index] = HEX[nibble as usize];
    }
    bytes[3 + digits] = b'>';
    String::from_utf8_lossy(&bytes[..digits + 4])
        .as_ref()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_names_use_one_allocation_at_every_hex_digit_boundary() {
        let addresses = [0, u64::MAX].into_iter().chain((0..16).flat_map(|digits| {
            let boundary = 1_u64 << (digits * 4);
            [boundary - 1, boundary, boundary + 1]
        }));
        for address in addresses {
            let mut name = None;
            let allocations = allocation_counter::measure(|| {
                name = Some(address_name(address));
            });
            assert_eq!(allocations.count_total, 1);
            assert_eq!(name.unwrap().as_ref(), format!("<0x{address:x}>"));
        }
    }

    #[test]
    fn unnamed_jit_code_retains_its_origin() {
        let index = SymbolIndex::default();
        let mut module =
            ModuleRecord::new(0, crate::Pid::new(7).unwrap(), 0x1000..0x2000, 0, "[jit]").unwrap();
        module.jit_symbols = Some([].into());
        let Frame::Native(frame) = index
            .resolve_frame(&module, 7, 0x1108, &mut SymbolCache::default())
            .unwrap()
        else {
            panic!("expected a native JIT frame");
        };
        assert_eq!(frame.origin, SymbolOrigin::GdbJit);
        assert_eq!(frame.flags, FrameFlags::JIT);
        assert_eq!(Frame::Native(frame).name(), Some("<0x1108>"));
    }

    #[test]
    fn lookup_skips_expired_overlapping_symbols() {
        let index = SymbolIndex::default();
        let mut module =
            ModuleRecord::new(0, crate::Pid::new(7).unwrap(), 0x1000..0x2000, 0, "[jit]").unwrap();
        module.jit_symbols = Some(
            [
                JitSymbol {
                    start: 0x1000,
                    end: 0x1200,
                    name: "outer".into(),
                },
                JitSymbol {
                    start: 0x1100,
                    end: 0x1110,
                    name: "inner".into(),
                },
            ]
            .into(),
        );
        assert_eq!(
            index
                .resolve_frame(&module, 7, 0x1108, &mut SymbolCache::default())
                .unwrap()
                .name(),
            Some("inner")
        );
        assert_eq!(
            index
                .resolve_frame(&module, 7, 0x1120, &mut SymbolCache::default())
                .unwrap()
                .name(),
            Some("outer")
        );
    }

    #[test]
    fn distinct_addresses_share_function_names_and_module_paths() {
        let index = SymbolIndex::default();
        let mut module =
            ModuleRecord::new(0, crate::Pid::new(7).unwrap(), 0x1000..0x2000, 0, "[jit]").unwrap();
        module.jit_symbols = Some(
            [JitSymbol {
                start: 0x1000,
                end: 0x2000,
                name: "generated_function".repeat(256).into(),
            }]
            .into(),
        );
        let mut strings = SymbolCache::default();
        let Frame::Native(first) = index
            .resolve_frame(&module, 7, 0x1000, &mut strings)
            .unwrap()
        else {
            panic!("expected a native JIT frame");
        };
        let first = first.symbol.unwrap();
        let allocations = allocation_counter::measure(|| {
            for address in 0x1001..0x2000 {
                let Frame::Native(frame) = index
                    .resolve_frame(&module, 7, address, &mut strings)
                    .unwrap()
                else {
                    panic!("expected a native JIT frame");
                };
                let symbol = frame.symbol.unwrap();
                assert!(std::rc::Rc::ptr_eq(first.name_rc(), symbol.name_rc()));
                assert!(std::rc::Rc::ptr_eq(&first.module, &symbol.module));
                assert_eq!(symbol.offset, address - 0x1000);
            }
        });
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn indexed_lookup_matches_last_covering_symbol_across_gaps_and_overlaps() {
        let mut module =
            ModuleRecord::new(0, crate::Pid::new(7).unwrap(), 0x1000..0x2000, 0, "[jit]").unwrap();
        module.jit_symbols = Some(
            [
                (0x1010, 0x1060, "outer"),
                (0x1020, 0x1030, "inner"),
                (0x1020, 0x1028, "same-start"),
                (0x1040, 0x1050, "later-inner"),
                (0x1080, 0x1090, "after-gap"),
            ]
            .map(|(start, end, name)| JitSymbol {
                start,
                end,
                name: name.into(),
            })
            .into(),
        );
        let index = SymbolIndex::default();
        let mut strings = SymbolCache::default();
        assert!(index
            .resolve_frame(&module, 8, 0x1010, &mut strings)
            .is_none());
        assert!(index.max_end.get().is_none());
        for address in 0x1000..0x1100 {
            let expected = module
                .jit_symbols
                .as_ref()
                .unwrap()
                .iter()
                .rfind(|symbol| symbol.start <= address && address < symbol.end);
            let Frame::Native(frame) = index
                .resolve_frame(&module, 7, address, &mut strings)
                .unwrap()
            else {
                panic!("expected a native JIT frame");
            };
            let symbol = frame.symbol.unwrap();
            if let Some(expected) = expected {
                assert_eq!(
                    symbol.name(),
                    expected.name.as_ref(),
                    "address {address:#x}"
                );
                assert_eq!(symbol.offset, address - expected.start);
            } else {
                assert_eq!(symbol.name(), format!("<0x{address:x}>"));
                assert_eq!(symbol.offset, 0);
            }
        }
    }

    #[test]
    fn symbol_cache_preserves_module_identity_and_symbol_classification() {
        let modules = [
            (0, "_PyEval_EvalFrameDefault".repeat(8)),
            (1, "ordinary".repeat(32)),
            (2, "short".to_owned()),
        ]
        .map(|(id, name)| {
            let mut module = ModuleRecord::new(
                id,
                crate::Pid::new(7).unwrap(),
                0x1000..0x2000,
                0,
                format!("[jit-{id}]"),
            )
            .unwrap();
            module.jit_symbols = Some(
                [JitSymbol {
                    start: 0x1000,
                    end: 0x2000,
                    name: name.into(),
                }]
                .into(),
            );
            module
        });
        let indexes = std::array::from_fn::<_, 3, _>(|_| SymbolIndex::default());
        let mut cache = SymbolCache::default();
        for module_id in [0, 1, 2, 0] {
            let module = &modules[module_id];
            let index = &indexes[module_id];
            for offset in [0, 8, 16] {
                let Frame::Native(frame) = index
                    .resolve_frame(module, 7, 0x1000 + offset, &mut cache)
                    .unwrap()
                else {
                    panic!("expected native frame");
                };
                let symbol = frame.symbol.unwrap();
                assert_eq!(symbol.offset, offset);
                assert_eq!(symbol.module.as_ref(), format!("[jit-{}]", module.id));
                assert_eq!(symbol.is_eval_frame(), module.id == 0);
                assert_eq!(symbol.inline_depth(), 0);
                assert!(!symbol.is_hidden_by_default());
            }
            if module_id == 2 {
                let (key, _) = cache.last_symbol.as_ref().unwrap();
                assert_eq!(*key, (2, 0));
            }
        }
    }

    #[test]
    fn replacing_the_cached_symbol_preserves_live_names() {
        let count = 3;
        let mut module = ModuleRecord::new(
            0,
            crate::Pid::new(7).unwrap(),
            0x1000..0x1000 + count as u64,
            0,
            "[jit]",
        )
        .unwrap();
        module.jit_symbols = Some(
            (0..count)
                .map(|index| JitSymbol {
                    start: 0x1000 + index as u64,
                    end: 0x1001 + index as u64,
                    name: format!("function_{index}").repeat(16).into(),
                })
                .collect(),
        );
        let index = SymbolIndex::default();
        let mut cache = SymbolCache::default();
        let first = index.resolve_frame(&module, 7, 0x1000, &mut cache).unwrap();
        for offset in 1..count {
            let frame = index
                .resolve_frame(&module, 7, 0x1000 + offset as u64, &mut cache)
                .unwrap();
            assert_eq!(
                frame.name(),
                Some(format!("function_{offset}").repeat(16).as_str())
            );
        }
        assert_eq!(first.name(), Some("function_0".repeat(16).as_str()));
        assert_eq!(
            index.resolve_frame(&module, 7, 0x1000, &mut cache).unwrap(),
            first
        );
        cache.clear();
        assert!(cache.last_symbol.is_none());
        assert_eq!(first.name(), Some("function_0".repeat(16).as_str()));
    }
}
