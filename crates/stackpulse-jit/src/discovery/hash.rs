//! Look up the descriptor through the image's dynamic ELF hash table.

use goblin::container::Ctx;
use goblin::elf::dynamic::Dynamic;
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::{Sym, Symtab};

use super::JIT_DESCRIPTOR_SYMBOL;

const GNU_HASH: u32 = gnu_hash(JIT_DESCRIPTOR_SYMBOL.as_bytes());
const SYSV_HASH: u32 = sysv_hash(JIT_DESCRIPTOR_SYMBOL.as_bytes());

pub(super) fn descriptor_symbol(
    bytes: &[u8],
    dynamic: &Dynamic,
    ctx: Ctx,
) -> Result<Option<u64>, &'static str> {
    if dynamic.info.gnu_hash.is_none() && dynamic.info.hash.is_none() {
        return Err("missing dynamic symbol hash");
    }
    if dynamic.info.syment != Sym::size(ctx.container) {
        return Err("invalid dynamic symbol entry size");
    }
    if let Some(offset) = dynamic.info.gnu_hash {
        gnu_symbol(bytes, dynamic, ctx, offset)
    } else if let Some(offset) = dynamic.info.hash {
        sysv_symbol(bytes, dynamic, ctx, offset)
    } else {
        Err("missing dynamic symbol hash")
    }
}

fn gnu_symbol(
    bytes: &[u8],
    dynamic: &Dynamic,
    ctx: Ctx,
    offset: u64,
) -> Result<Option<u64>, &'static str> {
    let table = hash_table(bytes, offset)?;
    let bucket_count = word(table, 0, ctx)? as usize;
    let first_symbol = word(table, 1, ctx)? as usize;
    let bloom_count = word(table, 2, ctx)? as usize;
    let shift = word(table, 3, ctx)?;
    if bucket_count == 0 || !bloom_count.is_power_of_two() || shift >= 32 {
        return Err("invalid GNU hash header");
    }
    let bloom_size = bloom_count
        .checked_mul(ctx.size())
        .ok_or("GNU bloom size overflow")?;
    let (bloom, remaining) = table
        .get(16..)
        .and_then(|tail| tail.split_at_checked(bloom_size))
        .ok_or("truncated GNU bloom filter")?;
    let bucket_size = bucket_count
        .checked_mul(4)
        .ok_or("GNU bucket size overflow")?;
    let (buckets, chains) = remaining
        .split_at_checked(bucket_size)
        .ok_or("truncated GNU hash buckets")?;

    let bits = (ctx.size() * 8) as u32;
    let bloom_index = (GNU_HASH / bits) as usize & (bloom_count - 1);
    let bloom_word = if ctx.is_big() {
        let low = u64::from(word(bloom, bloom_index * 2, ctx)?);
        let high = u64::from(word(bloom, bloom_index * 2 + 1, ctx)?);
        if ctx.is_little_endian() {
            low | high << 32
        } else {
            low << 32 | high
        }
    } else {
        u64::from(word(bloom, bloom_index, ctx)?)
    };
    let mask = (1_u64 << (GNU_HASH % bits)) | (1_u64 << ((GNU_HASH >> shift) % bits));
    if bloom_word & mask != mask {
        return Ok(None);
    }
    let index = word(buckets, GNU_HASH as usize % bucket_count, ctx)? as usize;
    if index == 0 {
        return Ok(None);
    }
    let chain_index = index
        .checked_sub(first_symbol)
        .ok_or("invalid GNU hash bucket")?;
    let chain_offset = chain_index
        .checked_mul(4)
        .ok_or("GNU chain offset overflow")?;
    let chains = chains
        .get(chain_offset..)
        .ok_or("GNU hash chain outside file")?;
    let symbol_limit = bytes
        .len()
        .checked_sub(dynamic.info.symtab)
        .map(|size| size / dynamic.info.syment)
        .ok_or("dynamic symbol table outside file")?;
    let remaining_symbols = symbol_limit
        .checked_sub(index)
        .ok_or("GNU symbol index outside file")?;
    for (offset, chain) in chains
        .as_chunks::<4>()
        .0
        .iter()
        .take(remaining_symbols)
        .enumerate()
    {
        let hash = word(chain, 0, ctx)?;
        if (hash | 1) == (GNU_HASH | 1) {
            if let Some(value) = symbol_value(bytes, dynamic, ctx, index + offset)? {
                return Ok(Some(value));
            }
        }
        if hash & 1 != 0 {
            return Ok(None);
        }
    }
    Err("unterminated GNU hash chain")
}

fn sysv_symbol(
    bytes: &[u8],
    dynamic: &Dynamic,
    ctx: Ctx,
    offset: u64,
) -> Result<Option<u64>, &'static str> {
    let table = hash_table(bytes, offset)?;
    let bucket_count = word(table, 0, ctx)? as usize;
    let chain_count = word(table, 1, ctx)? as usize;
    if bucket_count == 0 || chain_count == 0 {
        return Err("invalid SysV hash header");
    }
    let bucket_size = bucket_count
        .checked_mul(4)
        .ok_or("SysV bucket size overflow")?;
    let (buckets, remaining) = table
        .get(8..)
        .and_then(|tail| tail.split_at_checked(bucket_size))
        .ok_or("truncated SysV hash buckets")?;
    let chain_size = chain_count
        .checked_mul(4)
        .ok_or("SysV chain size overflow")?;
    let chains = remaining
        .get(..chain_size)
        .ok_or("truncated SysV hash chains")?;
    let symbol_size = chain_count
        .checked_mul(dynamic.info.syment)
        .ok_or("dynamic symbol size overflow")?;
    if bytes
        .get(dynamic.info.symtab..)
        .and_then(|tail| tail.get(..symbol_size))
        .is_none()
    {
        return Err("dynamic symbol table outside file");
    }
    let mut index = word(buckets, SYSV_HASH as usize % bucket_count, ctx)? as usize;
    let mut found: Option<(usize, u64)> = None;
    // SysV chains need not follow symbol order. Check the whole bucket so the
    // first definition in the symbol table still wins, and bound cyclic input.
    for _ in 0..chain_count {
        if index == 0 {
            return Ok(found.map(|(_, value)| value));
        }
        if index >= chain_count {
            return Err("invalid SysV hash chain index");
        }
        if found.is_none_or(|(previous, _)| index < previous) {
            if let Some(value) = symbol_value(bytes, dynamic, ctx, index)? {
                found = Some((index, value));
            }
        }
        index = word(chains, index, ctx)? as usize;
    }
    Err("cyclic SysV hash chain")
}

fn symbol_value(
    bytes: &[u8],
    dynamic: &Dynamic,
    ctx: Ctx,
    index: usize,
) -> Result<Option<u64>, &'static str> {
    let offset = index
        .checked_mul(dynamic.info.syment)
        .and_then(|offset| dynamic.info.symtab.checked_add(offset))
        .ok_or("dynamic symbol offset overflow")?;
    let symbol = Symtab::parse(bytes, offset, 1, ctx)
        .map_err(|_| "dynamic symbol outside file")?
        .get(0)
        .ok_or("missing dynamic symbol")?;
    if symbol.st_shndx == SHN_UNDEF as usize {
        return Ok(None);
    }
    let name = bytes
        .get(dynamic.info.strtab..)
        .and_then(|names| names.get(..dynamic.info.strsz))
        .and_then(|names| names.get(symbol.st_name..))
        .ok_or("dynamic symbol name outside string table")?;
    // String-table offsets can name a suffix of another string. Goblin also
    // accepts the final name without a NUL terminator.
    Ok(name
        .strip_prefix(JIT_DESCRIPTOR_SYMBOL.as_bytes())
        .filter(|tail| tail.is_empty() || tail[0] == 0)
        .map(|_| symbol.st_value))
}

fn hash_table(bytes: &[u8], offset: u64) -> Result<&[u8], &'static str> {
    let offset = usize::try_from(offset).map_err(|_| "ELF hash offset overflow")?;
    bytes.get(offset..).ok_or("ELF hash table outside file")
}

fn word(bytes: &[u8], index: usize, ctx: Ctx) -> Result<u32, &'static str> {
    let offset = index
        .checked_mul(4)
        .ok_or("ELF hash word offset overflow")?;
    let word = bytes
        .get(offset..)
        .and_then(|bytes| bytes.get(..4))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("truncated ELF hash word")?;
    Ok(if ctx.is_little_endian() {
        u32::from_le_bytes(word)
    } else {
        u32::from_be_bytes(word)
    })
}

const fn gnu_hash(name: &[u8]) -> u32 {
    let mut hash = 5381_u32;
    let mut index = 0;
    while index < name.len() {
        hash = hash.wrapping_mul(33).wrapping_add(name[index] as u32);
        index += 1;
    }
    hash
}

const fn sysv_hash(name: &[u8]) -> u32 {
    let mut hash = 0_u32;
    let mut index = 0;
    while index < name.len() {
        hash = hash.wrapping_shl(4).wrapping_add(name[index] as u32);
        let high = hash & 0xf000_0000;
        hash ^= high >> 24;
        hash &= !high;
        index += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::container::{Container, Endian};
    use goblin::elf::dynamic::DynamicInfo;

    const HASH_OFFSET: usize = 320;

    struct Fixture {
        bytes: Vec<u8>,
        dynamic: Dynamic,
        ctx: Ctx,
        gnu: bool,
    }

    impl Fixture {
        fn new(ctx: Ctx, gnu: bool) -> Self {
            let names = b"\0collision\0prefix__jit_debug_descriptor\0__jit_debug_descriptor_suffix\0__jit_debug_descriptor";
            let mut fixture = Self {
                bytes: vec![0; 512],
                dynamic: Dynamic {
                    dyns: Vec::new(),
                    info: DynamicInfo {
                        symtab: 32,
                        syment: Sym::size(ctx.container),
                        strtab: 160,
                        strsz: names.len(),
                        gnu_hash: gnu.then_some(HASH_OFFSET as u64),
                        hash: (!gnu).then_some(HASH_OFFSET as u64),
                        ..DynamicInfo::default()
                    },
                },
                ctx,
                gnu,
            };
            fixture.bytes[160..160 + names.len()].copy_from_slice(names);
            fixture.symbol(1, 1, 0x1111, true);
            // These two names use a suffix offset and an unterminated final name.
            fixture.symbol(2, b"\0collision\0prefix".len(), 0x2222, true);
            fixture.symbol(3, names.len() - JIT_DESCRIPTOR_SYMBOL.len(), 0x3333, true);
            if gnu {
                for (index, value) in [1, 1, 1, 5].into_iter().enumerate() {
                    fixture.write(HASH_OFFSET + index * 4, value, 4);
                }
                fixture.write(HASH_OFFSET + 16, u64::MAX, ctx.size());
                fixture.write(HASH_OFFSET + 16 + ctx.size(), 1, 4);
                for index in 0..3 {
                    fixture.chain(index, (GNU_HASH & !1) | u32::from(index == 2));
                }
            } else {
                fixture.write(HASH_OFFSET, 1, 4);
                fixture.write(HASH_OFFSET + 4, 4, 4);
                fixture.write(HASH_OFFSET + 8, 3, 4);
                // Deliberately visit the later duplicate before the earlier one.
                for (index, next) in [0, 2, 0, 1].into_iter().enumerate() {
                    fixture.chain(index, next);
                }
            }
            fixture
        }

        fn write(&mut self, offset: usize, value: u64, width: usize) {
            if self.ctx.is_little_endian() {
                self.bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
            } else {
                self.bytes[offset..offset + width]
                    .copy_from_slice(&value.to_be_bytes()[8 - width..]);
            }
        }

        fn symbol(&mut self, index: usize, name: usize, value: u64, defined: bool) {
            let offset = self.dynamic.info.symtab + index * self.dynamic.info.syment;
            self.write(offset, name as u64, 4);
            if self.ctx.is_big() {
                self.write(offset + 6, u64::from(defined), 2);
                self.write(offset + 8, value, 8);
            } else {
                self.write(offset + 4, value, 4);
                self.write(offset + 14, u64::from(defined), 2);
            }
        }

        fn chain(&mut self, index: usize, value: u32) {
            let offset = if self.gnu {
                HASH_OFFSET + 16 + self.ctx.size() + 4
            } else {
                HASH_OFFSET + 12
            };
            self.write(offset + index * 4, u64::from(value), 4);
        }

        fn lookup(&self) -> Result<Option<u64>, &'static str> {
            descriptor_symbol(&self.bytes, &self.dynamic, self.ctx)
        }
    }

    fn contexts() -> impl Iterator<Item = Ctx> {
        [Container::Little, Container::Big]
            .into_iter()
            .flat_map(|container| {
                [Endian::Little, Endian::Big]
                    .into_iter()
                    .map(move |endian| Ctx::new(container, endian))
            })
    }

    #[test]
    fn lookup_handles_byte_order_collisions_suffixes_and_duplicate_definitions() {
        for ctx in contexts() {
            for gnu in [false, true] {
                let mut fixture = Fixture::new(ctx, gnu);
                assert_eq!(fixture.lookup(), Ok(Some(0x2222)));
                fixture.symbol(2, b"\0collision\0prefix".len(), 0, true);
                assert_eq!(fixture.lookup(), Ok(Some(0)));
                fixture.symbol(2, b"\0collision\0prefix".len(), 0, false);
                assert_eq!(fixture.lookup(), Ok(Some(0x3333)));
                fixture.symbol(3, 1, 0x3333, true);
                assert_eq!(fixture.lookup(), Ok(None));
            }
        }
    }

    #[test]
    fn names_must_match_exactly_and_stay_within_the_dynamic_string_table() {
        for gnu in [false, true] {
            let mut fixture = Fixture::new(Ctx::default(), gnu);
            let longer_name = b"\0collision\0prefix__jit_debug_descriptor\0".len();
            fixture.symbol(2, longer_name, 0x2222, true);
            fixture.symbol(3, longer_name, 0x3333, true);
            assert_eq!(fixture.lookup(), Ok(None));
            fixture.symbol(2, fixture.dynamic.info.strsz + 1, 0x2222, true);
            assert!(fixture.lookup().is_err());
        }
    }

    #[test]
    fn gnu_bloom_and_empty_bucket_report_absence() {
        for ctx in contexts() {
            let mut fixture = Fixture::new(ctx, true);
            let bits = (ctx.size() * 8) as u32;
            let mask = (1_u64 << (GNU_HASH % bits)) | (1_u64 << ((GNU_HASH >> 5) % bits));
            fixture.write(HASH_OFFSET + 16, mask, ctx.size());
            assert_eq!(fixture.lookup(), Ok(Some(0x2222)));
            fixture.write(HASH_OFFSET + 16, 0, ctx.size());
            assert_eq!(fixture.lookup(), Ok(None));
            fixture.write(HASH_OFFSET + 16, u64::MAX, ctx.size());
            fixture.write(HASH_OFFSET + 16 + ctx.size(), 0, 4);
            assert_eq!(fixture.lookup(), Ok(None));
        }
    }

    #[test]
    fn gnu_lookup_does_not_read_names_for_different_hashes() {
        let mut fixture = Fixture::new(Ctx::default(), true);
        fixture.symbol(1, usize::MAX, 0x1111, true);
        fixture.chain(0, (GNU_HASH ^ 2) & !1);
        assert_eq!(fixture.lookup(), Ok(Some(0x2222)));
    }

    #[test]
    fn malformed_hash_headers_offsets_and_symbol_entries_return_errors() {
        for gnu in [false, true] {
            let mut fixture = Fixture::new(Ctx::default(), gnu);
            fixture.dynamic.info.syment = 0;
            assert!(fixture.lookup().is_err());
            fixture.dynamic.info.syment = Sym::size(fixture.ctx.container);
            fixture.dynamic.info.symtab = usize::MAX;
            assert!(fixture.lookup().is_err());
            fixture.dynamic.info.symtab = 32;
            fixture.write(HASH_OFFSET, 0, 4);
            assert!(fixture.lookup().is_err());
            fixture.write(HASH_OFFSET, 1, 4);
            fixture.bytes.truncate(HASH_OFFSET + 2);
            assert!(fixture.lookup().is_err());
        }
        let mut fixture = Fixture::new(Ctx::default(), true);
        fixture.dynamic.info.gnu_hash = Some(u64::MAX);
        assert!(fixture.lookup().is_err());
        fixture.dynamic.info.gnu_hash = None;
        assert_eq!(fixture.lookup(), Err("missing dynamic symbol hash"));
    }

    #[test]
    fn cyclic_sysv_and_unterminated_gnu_chains_return_errors() {
        let mut fixture = Fixture::new(Ctx::default(), false);
        fixture.chain(2, 3);
        assert_eq!(fixture.lookup(), Err("cyclic SysV hash chain"));
        fixture.chain(2, 4);
        assert_eq!(fixture.lookup(), Err("invalid SysV hash chain index"));

        let mut fixture = Fixture::new(Ctx::default(), true);
        for index in 0..3 {
            fixture.chain(index, 0);
        }
        fixture
            .bytes
            .truncate(HASH_OFFSET + 16 + fixture.ctx.size() + 4 + 12);
        assert_eq!(fixture.lookup(), Err("unterminated GNU hash chain"));
        fixture.write(HASH_OFFSET + 4, 2, 4);
        assert_eq!(fixture.lookup(), Err("invalid GNU hash bucket"));
    }
}
