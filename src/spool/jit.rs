//! Recorded symbol payloads appended to GDB JIT module records.

use std::io::{self, Write};
use std::sync::Arc;

use integer_encoding::VarIntWriter;

use super::{invalid_data, model, write_bytes, MmapSpoolCursor, ModuleRecord};

/// Write absolute symbol ranges and names after the common module fields.
pub(super) fn write_symbols(
    writer: &mut impl Write,
    symbols: &[model::JitSymbol],
) -> io::Result<()> {
    writer.write_varint(symbols.len() as u64)?;
    for symbol in symbols {
        writer.write_varint(symbol.start)?;
        writer.write_varint(symbol.end)?;
        write_bytes(writer, symbol.name.as_bytes())?;
    }
    Ok(())
}

/// Validate symbol bounds, name encoding, and lookup order while decoding.
pub(super) fn read_symbols(
    reader: &mut MmapSpoolCursor,
    module: &ModuleRecord,
) -> io::Result<Arc<[model::JitSymbol]>> {
    let count = reader.read_varint::<u64>()?;
    if count > model::MAX_JIT_SYMBOLS as u64 || module.is_kernel() {
        return Err(invalid_data("invalid JIT module"));
    }
    let mut symbols = Vec::new();
    for _ in 0..count {
        let start = reader.read_varint::<u64>()?;
        let end = reader.read_varint::<u64>()?;
        if start >= end || start < module.start || end > module.end {
            return Err(invalid_data("JIT symbol outside its code range"));
        }
        let len = reader.read_varint::<u64>()?;
        if len > model::MAX_JIT_SYMBOL_NAME as u64 {
            return Err(invalid_data("JIT symbol name too large"));
        }
        let range = reader.read_bytes_range(len as usize)?;
        let name = std::str::from_utf8(&reader.mmap[range])
            .map_err(|_| invalid_data("invalid JIT symbol name"))?;
        if symbols
            .last()
            .is_some_and(|symbol: &model::JitSymbol| symbol.start > start)
        {
            return Err(invalid_data("JIT symbols are not sorted"));
        }
        symbols.push(model::JitSymbol {
            start,
            end,
            name: name.into(),
        });
    }
    Ok(symbols.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jit_symbol_payload_rejects_invalid_ranges_names_and_order() {
        let module =
            ModuleRecord::new(0, crate::Pid::new(7).unwrap(), 0x1000..0x2000, 0, "[jit]").unwrap();
        let encode = |symbols: &[(u64, u64, &[u8])]| {
            let mut bytes = Vec::new();
            bytes.write_varint(symbols.len() as u64).unwrap();
            for &(start, end, name) in symbols {
                bytes.write_varint(start).unwrap();
                bytes.write_varint(end).unwrap();
                write_bytes(&mut bytes, name).unwrap();
            }
            bytes
        };
        for (case, bytes) in [
            ("empty range", encode(&[(0x1000, 0x1000, b"empty")])),
            ("outside module", encode(&[(0x1000, 0x2001, b"outside")])),
            ("invalid UTF-8", encode(&[(0x1000, 0x1001, &[0xff])])),
            (
                "unsorted symbols",
                encode(&[(0x1100, 0x1200, b"later"), (0x1000, 0x1100, b"earlier")]),
            ),
        ] {
            let mut reader = MmapSpoolCursor::new(crate::test_support::mmap_from_bytes(&bytes));
            assert_eq!(
                read_symbols(&mut reader, &module).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{case}"
            );
        }
        let bytes = encode(&[(0x1000, 0x1100, b"cut-off-name")]);
        let mut reader = MmapSpoolCursor::new(crate::test_support::mmap_from_bytes(
            &bytes[..bytes.len() - 1],
        ));
        assert_eq!(
            read_symbols(&mut reader, &module).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
