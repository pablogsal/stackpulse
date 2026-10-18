//! Resolve pinned generated-code frames from symbols captured during recording.

use std::cell::OnceCell;

use crate::profile::{AddressSpace, Frame, FrameFlags, NativeFrame, NativeSymbol, SymbolOrigin};
use crate::spool::ModuleRecord;
use crate::symbols::SymbolStrings;

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
        strings: &mut SymbolStrings,
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
            .rev()
            .take_while(|(_, &end)| abs_ip < end)
            .find_map(|(symbol, _)| (abs_ip < symbol.end).then_some(symbol));
        let name: std::rc::Rc<str> = symbol.map_or_else(
            || format!("<0x{abs_ip:x}>").into(),
            |symbol| strings.intern(&symbol.name),
        );
        let offset = symbol.map_or(0, |symbol| abs_ip - symbol.start);
        let module_name = strings.intern(module.path.to_string_lossy().as_ref());
        let native_symbol = NativeSymbol::new(name, module_name).with_offset(offset);
        Some(Frame::Native(NativeFrame {
            pc: abs_ip,
            symbol: Some(native_symbol),
            address_space: AddressSpace::User,
            origin: SymbolOrigin::GdbJit,
            flags: FrameFlags::JIT,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::model::JitSymbol;

    #[test]
    fn unnamed_jit_code_retains_its_origin() {
        let index = SymbolIndex::default();
        let mut module =
            ModuleRecord::new(0, crate::Pid::new(7).unwrap(), 0x1000..0x2000, 0, "[jit]").unwrap();
        module.jit_symbols = Some([].into());
        let Frame::Native(frame) = index
            .resolve_frame(&module, 7, 0x1108, &mut SymbolStrings::default())
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
                .resolve_frame(&module, 7, 0x1108, &mut SymbolStrings::default())
                .unwrap()
                .name(),
            Some("inner")
        );
        assert_eq!(
            index
                .resolve_frame(&module, 7, 0x1120, &mut SymbolStrings::default())
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
        let mut strings = SymbolStrings::default();
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
        let mut strings = SymbolStrings::default();
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
}
