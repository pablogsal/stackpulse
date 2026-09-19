//! Resolve pinned generated-code frames from symbols captured during recording.

use crate::profile::{AddressSpace, Frame, FrameFlags, NativeFrame, NativeSymbol, SymbolOrigin};
use crate::spool::ModuleRecord;

/// Resolve an owning process's JIT frame, retaining its origin when no name matches.
/// The caller selects the module recorded on the frame, not a current address mapping.
/// Symbol ranges may overlap and must be sorted by start address.
pub(super) fn resolve_frame(module: &ModuleRecord, process_id: i32, abs_ip: u64) -> Option<Frame> {
    if module.pid().is_none_or(|pid| pid.get() != process_id) {
        return None;
    }
    let symbols = module.jit_symbols.as_ref()?;
    let symbol = symbols[..symbols.partition_point(|symbol| symbol.start <= abs_ip)]
        .iter()
        .rfind(|symbol| abs_ip < symbol.end);
    let name: std::rc::Rc<str> = symbol.map_or_else(
        || format!("<0x{abs_ip:x}>").into(),
        |symbol| symbol.name.as_ref().into(),
    );
    let offset = symbol.map_or(0, |symbol| abs_ip - symbol.start);
    let native_symbol =
        NativeSymbol::new(name, module.path.to_string_lossy().as_ref()).with_offset(offset);
    Some(Frame::Native(NativeFrame {
        pc: abs_ip,
        symbol: Some(native_symbol),
        address_space: AddressSpace::User,
        origin: SymbolOrigin::GdbJit,
        flags: FrameFlags::JIT,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::model::JitSymbol;

    #[test]
    fn unnamed_jit_code_retains_its_origin() {
        let mut module =
            ModuleRecord::new(0, crate::Pid::new(7).unwrap(), 0x1000..0x2000, 0, "[jit]").unwrap();
        module.jit_symbols = Some([].into());
        let Frame::Native(frame) = resolve_frame(&module, 7, 0x1108).unwrap() else {
            panic!("expected a native JIT frame");
        };
        assert_eq!(frame.origin, SymbolOrigin::GdbJit);
        assert_eq!(frame.flags, FrameFlags::JIT);
        assert_eq!(Frame::Native(frame).name(), Some("<0x1108>"));
    }

    #[test]
    fn lookup_skips_expired_overlapping_symbols() {
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
            resolve_frame(&module, 7, 0x1108).unwrap().name(),
            Some("inner")
        );
        assert_eq!(
            resolve_frame(&module, 7, 0x1120).unwrap().name(),
            Some("outer")
        );
    }
}
