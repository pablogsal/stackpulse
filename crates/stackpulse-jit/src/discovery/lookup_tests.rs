use super::*;
use goblin::elf::dynamic::{
    DT_DEBUG, DT_GNU_HASH, DT_HASH, DT_PLTRELSZ, DT_RELASZ, DT_RELSZ, DT_STRSZ, DT_SYMENT,
};
use goblin::elf::program_header::PT_DYNAMIC;
use std::ops::Range;
use std::process::Command;

const DEFINITION: &str = "unsigned long __jit_debug_descriptor[3] = {1, 0, 0};";

fn image(sources: &[&str], hash_style: &str, stripped: bool) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("registry.so");
    let mut compiler = Command::new("cc");
    compiler
        .args(["-shared", "-fPIC"])
        .arg(format!("-Wl,--hash-style={hash_style}"));
    if stripped {
        compiler.arg("-Wl,--strip-all");
    }
    for (index, source) in sources.iter().enumerate() {
        let path = directory.path().join(format!("registry-{index}.c"));
        std::fs::write(&path, source).unwrap();
        compiler.arg(path);
    }
    let output = compiler.arg("-o").arg(&output_path).output().unwrap();
    assert!(
        output.status.success(),
        "could not compile registry: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(output_path).unwrap();
    // Fixture edits below use the ELF64 little-endian field layout.
    assert_eq!(&bytes[4..6], &[2, 1]);
    bytes
}

fn lookup(bytes: &[u8]) -> goblin::error::Result<Option<u64>> {
    parse_descriptor(bytes).map(|image| image.map(|image| image.symbol))
}

fn dynamic_range(bytes: &[u8]) -> Range<usize> {
    let header = Elf::parse_header(bytes).unwrap();
    let ctx = Ctx::new(header.container().unwrap(), header.endianness().unwrap());
    let headers =
        ProgramHeader::parse(bytes, header.e_phoff as usize, header.e_phnum as usize, ctx).unwrap();
    let dynamic = headers
        .iter()
        .find(|header| header.p_type == PT_DYNAMIC)
        .unwrap();
    dynamic.p_offset as usize..(dynamic.p_offset + dynamic.p_filesz) as usize
}

fn remove_dynamic_tags(bytes: &mut [u8], tags: &[u64]) {
    let range = dynamic_range(bytes);
    for entry in bytes[range].as_chunks_mut::<16>().0 {
        let tag = u64::from_le_bytes(entry[..8].try_into().unwrap());
        if tags.contains(&tag) {
            // DT_DEBUG is ignored by descriptor discovery and does not end the table.
            entry[..8].copy_from_slice(&DT_DEBUG.to_le_bytes());
            entry[8..].fill(0);
        }
    }
}

fn set_dynamic_value(bytes: &mut [u8], tag: u64, value: u64) {
    let range = dynamic_range(bytes);
    let entry = bytes[range]
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .find(|entry| u64::from_le_bytes(entry[..8].try_into().unwrap()) == tag)
        .unwrap();
    entry[8..].copy_from_slice(&value.to_le_bytes());
}

fn remove_sections(bytes: &mut [u8]) {
    bytes[0x28..0x30].fill(0); // e_shoff
    bytes[0x3c..0x40].fill(0); // e_shnum and e_shstrndx
}

#[test]
fn exported_descriptors_use_each_hash_style_without_section_metadata() {
    for hash_style in ["gnu", "sysv", "both"] {
        for stripped in [false, true] {
            let bytes = image(&[DEFINITION], hash_style, stripped);
            let elf = Elf::parse(&bytes).unwrap();
            let expected = descriptor_symbol(&elf).unwrap();
            if stripped {
                assert!(elf.syms.is_empty());
            }
            let found = parse_descriptor(&bytes).unwrap().unwrap();
            assert_eq!(found.symbol, expected);
            assert_eq!(found.program_header_offset, elf.header.e_phoff);
            assert_eq!(found.program_headers, elf.program_headers);

            let mut sectionless = bytes.clone();
            remove_sections(&mut sectionless);
            assert_eq!(lookup(&sectionless).unwrap(), Some(expected));

            let mut broken_sections = bytes;
            broken_sections[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(lookup(&broken_sections).unwrap(), Some(expected));
        }
    }
}

#[test]
fn static_only_descriptors_remain_discoverable() {
    for declaration in ["static", "__attribute__((visibility(\"hidden\")))"] {
        let source = format!(
            "{declaration} unsigned long __jit_debug_descriptor[3] = {{1, 0, 0}};\n\
             void *entry(void) {{ return __jit_debug_descriptor; }}"
        );
        let bytes = image(&[&source], "gnu", false);
        let elf = Elf::parse(&bytes).unwrap();
        assert!(!elf
            .dynsyms
            .iter()
            .any(|symbol| { elf.dynstrtab.get_at(symbol.st_name) == Some(JIT_DESCRIPTOR_SYMBOL) }));
        let expected = descriptor_symbol(&elf).unwrap();
        assert_eq!(lookup(&bytes).unwrap(), Some(expected));
    }
}

#[test]
fn an_undefined_descriptor_does_not_create_a_registry() {
    let source = "extern unsigned long __jit_debug_descriptor[3];\n\
                  void *entry(void) { return __jit_debug_descriptor; }";
    for hash_style in ["gnu", "sysv", "both"] {
        let mut bytes = image(&[source], hash_style, false);
        let elf = Elf::parse(&bytes).unwrap();
        assert!(elf.dynsyms.iter().any(|symbol| {
            symbol.st_shndx == SHN_UNDEF as usize
                && elf.dynstrtab.get_at(symbol.st_name) == Some(JIT_DESCRIPTOR_SYMBOL)
        }));
        assert_eq!(descriptor_symbol(&elf), None);
        assert_eq!(lookup(&bytes).unwrap(), None);
        remove_sections(&mut bytes);
        assert_eq!(lookup(&bytes).unwrap(), None);
    }
}

#[test]
fn an_exported_descriptor_takes_precedence_over_a_local_namesake() {
    let local = "static unsigned long __jit_debug_descriptor[3] = {2, 0, 0};\n\
                 void *local_registry(void) { return __jit_debug_descriptor; }";
    for hash_style in ["gnu", "sysv", "both"] {
        let bytes = image(&[DEFINITION, local], hash_style, false);
        let elf = Elf::parse(&bytes).unwrap();
        let exported = elf
            .dynsyms
            .iter()
            .find(|symbol| elf.dynstrtab.get_at(symbol.st_name) == Some(JIT_DESCRIPTOR_SYMBOL))
            .unwrap()
            .st_value;
        let local = elf
            .syms
            .iter()
            .find(|symbol| {
                symbol.st_bind() == goblin::elf::sym::STB_LOCAL
                    && elf.strtab.get_at(symbol.st_name) == Some(JIT_DESCRIPTOR_SYMBOL)
            })
            .unwrap()
            .st_value;
        assert_ne!(exported, local);
        assert_eq!(descriptor_symbol(&elf), Some(local));
        assert_eq!(lookup(&bytes).unwrap(), Some(exported));

        let mut hashless = bytes;
        remove_dynamic_tags(&mut hashless, &[DT_HASH, DT_GNU_HASH]);
        assert_eq!(lookup(&hashless).unwrap(), Some(exported));
    }
}

#[test]
fn hashless_dynamic_symbols_use_the_matching_section() {
    let mut bytes = image(&[DEFINITION], "both", true);
    let expected = descriptor_symbol(&Elf::parse(&bytes).unwrap()).unwrap();
    remove_dynamic_tags(
        &mut bytes,
        &[DT_HASH, DT_GNU_HASH, DT_RELASZ, DT_RELSZ, DT_PLTRELSZ],
    );
    // No static symbols or relocation-derived bound can satisfy this lookup.
    let elf = Elf::parse(&bytes).unwrap();
    assert!(elf.syms.is_empty());
    assert!(elf.dynsyms.is_empty());
    assert_eq!(lookup(&bytes).unwrap(), Some(expected));
}

#[test]
fn hashless_sectionless_symbols_use_the_relocation_bound() {
    let source = "unsigned long __jit_debug_descriptor[3] = {1, 0, 0};\n\
                  unsigned long *descriptor_reference = __jit_debug_descriptor;";
    let mut bytes = image(&[source], "both", true);
    let expected = descriptor_symbol(&Elf::parse(&bytes).unwrap()).unwrap();
    remove_dynamic_tags(&mut bytes, &[DT_HASH, DT_GNU_HASH]);
    remove_sections(&mut bytes);
    let elf = Elf::parse(&bytes).unwrap();
    assert!(elf.section_headers.is_empty());
    assert_eq!(descriptor_symbol(&elf), Some(expected));
    assert_eq!(lookup(&bytes).unwrap(), Some(expected));
}

#[test]
fn malformed_required_tables_return_errors() {
    let bytes = image(&[DEFINITION], "gnu", true);
    for length in [0, 1, 16, 63] {
        assert!(lookup(&bytes[..length]).is_err());
    }
    for (tag, value) in [(DT_STRSZ, u64::MAX), (DT_SYMENT, 0)] {
        let mut broken = bytes.clone();
        set_dynamic_value(&mut broken, tag, value);
        assert!(lookup(&broken).is_err());
    }
    let mut broken = bytes;
    broken[0x20..0x28].copy_from_slice(&u64::MAX.to_le_bytes()); // e_phoff
    assert!(lookup(&broken).is_err());

    let source = "static unsigned long __jit_debug_descriptor[3] = {1, 0, 0};\n\
                  void *entry(void) { return __jit_debug_descriptor; }";
    let bytes = image(&[source], "gnu", false);
    let elf = Elf::parse(&bytes).unwrap();
    let index = elf
        .section_headers
        .iter()
        .rposition(|section| section.sh_type == SHT_SYMTAB)
        .unwrap();
    let section = elf.header.e_shoff as usize + index * elf.header.e_shentsize as usize;
    for field in [24, 32] {
        let mut broken = bytes.clone();
        broken[section + field..section + field + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(lookup(&broken).is_err());
    }
    let mut broken = bytes;
    broken[section + 40..section + 44].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(lookup(&broken).is_err());
}
