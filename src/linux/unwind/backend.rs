//! Address-based selection between ordinary and runtime unwind tables.

use crate::elf::ElfSectionData;
use framehop::{FrameAddress, Unwinder, UnwinderWithDetails};
use std::collections::BTreeMap;

type UnwindPolicy = framehop::MayAllocateDuringUnwind;
type FramehopUnwinder = framehop::UnwinderNative<ElfSectionData, UnwindPolicy>;
pub(in crate::linux) type NativeCache = framehop::CacheNative<UnwindPolicy>;

/// Unwinds runtime code before consulting ordinary executable mappings.
///
/// The tables stay separate because generated code can overlap a file mapping,
/// even when its registration supplies no CFI and requires fallback unwinding.
#[derive(Clone, Default)]
pub(in crate::linux) struct NativeUnwinder {
    /// Unwind rules from ordinary executable mappings, retained underneath JIT ranges.
    ordinary: FramehopUnwinder,
    /// Runtime modules selected throughout registered ranges, even when they have no CFI.
    jit: FramehopUnwinder,
    /// Disjoint target start addresses mapped to exclusive ends.
    /// Tracks JIT ownership independently of whether an address has an unwind rule.
    jit_ranges: BTreeMap<u64, u64>,
}

impl NativeUnwinder {
    /// Fork inherits file mappings; runtime registrations must be rediscovered.
    pub(in crate::linux) fn inherit_for_fork(&self) -> Self {
        Self {
            ordinary: self.ordinary.clone(),
            ..Self::default()
        }
    }

    /// Install a disjoint runtime range without replacing its backing mapping.
    /// The registry must reject overlap with other live runtime ranges first.
    pub(in crate::linux) fn add_jit_module(&mut self, module: framehop::Module<ElfSectionData>) {
        let range = module.avma_range();
        self.jit.remove_module(range.start);
        self.jit.add_module(module);
        self.jit_ranges.insert(range.start, range.end);
    }

    /// Retire runtime unwind rules while retaining the ordinary mapping.
    pub(in crate::linux) fn remove_jit_module(&mut self, start: u64) {
        self.jit.remove_module(start);
        self.jit_ranges.remove(&start);
    }

    /// Use the runtime table throughout registered ranges, including CFI gaps.
    fn for_address(&self, address: FrameAddress) -> &FramehopUnwinder {
        let address = address.address_for_lookup();
        if self
            .jit_ranges
            .range(..=address)
            .next_back()
            .is_some_and(|(_, end)| address < *end)
        {
            &self.jit
        } else {
            &self.ordinary
        }
    }
}

impl Unwinder for NativeUnwinder {
    type UnwindRegs = <FramehopUnwinder as Unwinder>::UnwindRegs;
    type Cache = NativeCache;
    type Module = framehop::Module<ElfSectionData>;

    fn add_module(&mut self, module: Self::Module) {
        self.ordinary.add_module(module);
    }

    fn remove_module(&mut self, start: u64) {
        self.ordinary.remove_module(start);
    }

    fn max_known_code_address(&self) -> u64 {
        self.ordinary
            .max_known_code_address()
            .max(self.jit.max_known_code_address())
    }

    fn unwind_frame<F>(
        &self,
        address: FrameAddress,
        regs: &mut Self::UnwindRegs,
        cache: &mut Self::Cache,
        read_stack: &mut F,
    ) -> Result<Option<u64>, framehop::Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.for_address(address)
            .unwind_frame(address, regs, cache, read_stack)
    }
}

impl UnwinderWithDetails for NativeUnwinder {
    fn unwind_frame_with_details<F>(
        &self,
        address: FrameAddress,
        regs: &mut Self::UnwindRegs,
        cache: &mut Self::Cache,
        read_stack: &mut F,
    ) -> Result<framehop::UnwindFrameOutcome, framehop::Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.for_address(address)
            .unwind_frame_with_details(address, regs, cache, read_stack)
    }
}

/// Build a code range without CFI for module ownership tests.
#[cfg(test)]
pub(in crate::linux) fn test_module(
    code: std::ops::Range<u64>,
) -> framehop::Module<ElfSectionData> {
    framehop::Module::new(
        "test".into(),
        code.clone(),
        code.start,
        framehop::ExplicitModuleSectionInfo {
            base_svma: code.start,
            text_svma: Some(code),
            text: None,
            stubs_svma: None,
            stub_helper_svma: None,
            got_svma: None,
            unwind_info: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            debug_frame: None,
            text_segment_svma: None,
            text_segment: None,
        },
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Link real assembler-generated CFI at a fixed address for overlay tests.
    #[cfg(target_arch = "x86_64")]
    pub(in crate::linux::unwind) fn cfi_module(
        cfa_offset: u64,
    ) -> framehop::Module<ElfSectionData> {
        let directory = crate::test_support::TempDir::new("jit-overlay-cfi");
        let output = directory.path().join("overlay");
        let compiler = std::process::Command::new("cc")
            .args([
                "-nostdlib",
                "-no-pie",
                "-Wl,--build-id=none",
                "-Wl,--no-eh-frame-hdr",
                "-Wl,-Ttext=0x1000",
                "-Wl,-e,overlay_leaf",
            ])
            .arg(format!("-DCFA_OFFSET={cfa_offset}"))
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/gdb_jit/overlay.S"
            ))
            .arg("-o")
            .arg(&output)
            .output()
            .expect("run assembler for unwind fixture");
        assert!(
            compiler.status.success(),
            "{}",
            String::from_utf8_lossy(&compiler.stderr)
        );
        let mut sections = crate::elf::load_elf_sections_from_bytes(
            std::fs::read(&output).unwrap().into(),
            &output,
        )
        .unwrap();
        sections.text = None;
        let module = crate::spool::ModuleRecord::new(
            0,
            crate::Pid::new(7).unwrap(),
            sections.text_svma.clone().unwrap(),
            0,
            &output,
        )
        .unwrap();
        let loaded = crate::native_module::LoadedElfMapping {
            image_base: Some(crate::module_base::ModuleImageBase::new(
                module.start,
                module.start,
            )),
            sections: std::sync::Arc::new(sections),
            image: None,
            image_token: 0,
        };
        super::super::module_to_framehop(&module, &loaded).unwrap()
    }

    #[cfg(target_arch = "x86_64")]
    pub(in crate::linux::unwind) fn unwind_overlay_frame(
        unwinder: &NativeUnwinder,
        cache: &mut NativeCache,
    ) -> (framehop::UnwindFrameOutcome, u64) {
        let mut regs = framehop::UnwindRegsNative::new(0x1002, 0x8000, 0x8100);
        let mut read_stack = |address| match address {
            0x8008 => Ok(0xaaaa), // CFA offset 16.
            0x8028 => Ok(0xbbbb), // CFA offset 48.
            0x8100 => Ok(0x8200), // Frame-pointer fallback.
            0x8108 => Ok(0xcccc),
            _ => Err(()),
        };
        let outcome = unwinder
            .unwind_frame_with_details(
                FrameAddress::from_return_address(0x1002).unwrap(),
                &mut regs,
                cache,
                &mut read_stack,
            )
            .unwrap();
        (outcome, regs.sp())
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn shared_cache_tracks_cfi_overlay_replacement_fallback_and_removal() {
        let ordinary = cfi_module(16);
        let runtime = cfi_module(48);
        let range = runtime.avma_range();
        assert_eq!(ordinary.avma_range(), range);
        let mut unwinder = NativeUnwinder::default();
        let mut cache = NativeCache::default();
        unwinder.add_module(ordinary.clone());
        let check = |unwinder: &NativeUnwinder, cache: &mut NativeCache, expected, sp, fallback| {
            // Repeat each lookup so the second unwind also exercises the cache.
            for _ in 0..2 {
                let (outcome, actual_sp) = unwind_overlay_frame(unwinder, cache);
                assert_eq!(outcome.return_address(), Some(expected));
                assert_eq!(actual_sp, sp);
                assert_eq!(outcome.fallback_reason().is_some(), fallback);
            }
        };
        check(&unwinder, &mut cache, 0xaaaa, 0x8010, false);
        unwinder.add_jit_module(runtime.clone());
        check(&unwinder, &mut cache, 0xbbbb, 0x8030, false);
        unwinder.remove_module(range.start);
        unwinder.add_module(ordinary);
        check(&unwinder, &mut cache, 0xbbbb, 0x8030, false);
        unwinder.add_jit_module(test_module(range.clone()));
        check(&unwinder, &mut cache, 0xcccc, 0x8110, true);
        unwinder.add_jit_module(runtime);
        check(&unwinder, &mut cache, 0xbbbb, 0x8030, false);
        unwinder.remove_jit_module(range.start);
        check(&unwinder, &mut cache, 0xaaaa, 0x8010, false);
        assert!(cache.stats().hits() > 0);
    }

    #[test]
    fn jit_overlay_preserves_ordinary_mapping_across_updates_and_removal() {
        let mut unwinder = NativeUnwinder::default();
        unwinder.add_module(test_module(0x1000..0x4000));
        for start in [0x1000, 0x2000] {
            unwinder.add_jit_module(test_module(start..0x3000));
            assert!(std::ptr::eq(
                unwinder.for_address(FrameAddress::from_instruction_pointer(start)),
                &unwinder.jit,
            ));
            assert!(std::ptr::eq(
                unwinder.for_address(FrameAddress::from_instruction_pointer(0x3800)),
                &unwinder.ordinary,
            ));
            let child = unwinder.inherit_for_fork();
            assert!(child.jit_ranges.is_empty());
            assert_eq!(
                child.max_known_code_address(),
                unwinder.ordinary.max_known_code_address()
            );
            assert!(std::ptr::eq(
                child.for_address(FrameAddress::from_instruction_pointer(start)),
                &child.ordinary,
            ));
            assert_eq!(unwinder.jit.max_known_code_address(), 0x3000);

            // Ordinary mapping updates must leave the JIT table intact.
            unwinder.remove_module(0x1000);
            assert_eq!(unwinder.jit.max_known_code_address(), 0x3000);
            unwinder.add_module(test_module(0x1000..0x5000));
            unwinder.remove_jit_module(start);
            assert_eq!(unwinder.max_known_code_address(), 0x5000);
            assert!(std::ptr::eq(
                unwinder.for_address(FrameAddress::from_instruction_pointer(start)),
                &unwinder.ordinary,
            ));
        }
    }
}
