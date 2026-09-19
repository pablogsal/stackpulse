#[cfg(target_arch = "x86_64")]
use super::super::backend::{test_module, tests::cfi_module};
use super::*;
use crate::linux::ConvertRegsNative;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
struct TestConvertRegs;

#[cfg(target_arch = "x86_64")]
impl ConvertRegs for TestConvertRegs {
    type UnwindRegs = framehop::x86_64::UnwindRegsX86_64;

    fn convert_regs(regs: &[u64]) -> Option<(u64, u64, Self::UnwindRegs)> {
        let [pc, sp, bp] = *regs else {
            return None;
        };
        Some((pc, sp, Self::UnwindRegs::new(pc, sp, bp)))
    }

    fn regs_mask() -> u64 {
        0
    }
}

#[cfg(target_arch = "aarch64")]
impl ConvertRegs for TestConvertRegs {
    type UnwindRegs = framehop::aarch64::UnwindRegsAarch64;

    fn convert_regs(regs: &[u64]) -> Option<(u64, u64, Self::UnwindRegs)> {
        let [pc, sp, fp] = *regs else {
            return None;
        };
        Some((pc, sp, Self::UnwindRegs::new(0, sp, fp)))
    }

    fn regs_mask() -> u64 {
        0
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn truncated_dwarf_stack_ignores_user_callchain() {
    let user_regs = [0x1000, 0, 8];
    let user_stack: Vec<_> = [0, 40, 0x2000]
        .into_iter()
        .flat_map(u64::to_ne_bytes)
        .collect();
    let input = StackInput {
        code_addr: None,
        user_regs: Some(&user_regs),
        user_stack: Some(&user_stack),
    };
    let callchain_stack = [
        StackFrame::InstructionPointer(0x1000, StackMode::User),
        StackFrame::ReturnAddress(0x2000, StackMode::User),
        StackFrame::ReturnAddress(0x3000, StackMode::User),
    ];
    let mut process_unwinder = ProcessUnwinder::default();
    let mut stack = Vec::new();
    let mut summary = RecordingSummary::default();

    build_sample_stack::<TestConvertRegs>(
        input,
        Priv::User,
        &mut process_unwinder,
        &mut stack,
        &callchain_stack,
        &mut summary,
        |_, _| panic!("an unknown frame must not request JIT refresh"),
    )
    .unwrap();

    assert_eq!(
        stack,
        vec![
            StackFrame::InstructionPointer(0x1000, StackMode::User),
            StackFrame::ReturnAddress(0x2000, StackMode::User),
            StackFrame::TruncatedStackMarker,
        ]
    );
    assert_eq!(summary.ignored_user_callchain_frames, 3);
    assert_eq!(
        summary
            .error_stats
            .count(SampleErrorKind::NativeStackTruncated),
        1
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn runtime_refresh_identifies_the_failing_frame_not_its_caller() {
    // The first frame follows a saved frame pointer to the second, which returns.
    for (leaf, caller, valid_cfi, expected) in [
        (0x3001, 0x1003, true, None),
        (0x1001, 0x3001, false, Some(0x1001)),
        (0x3001, 0x1003, false, Some(0x1002)),
    ] {
        let regs = [leaf, 0x8000, 0x8010];
        let saved_stack: Vec<_> = [0, 0, 0, caller, 0, 0]
            .into_iter()
            .flat_map(u64::to_ne_bytes)
            .collect();
        let mut unwinder = ProcessUnwinder::default();
        unwinder.unwinder.add_jit_module(if valid_cfi {
            cfi_module(16)
        } else {
            test_module(0x1000..0x1003)
        });
        let mut refreshed = None;
        let mut stack = Vec::new();
        build_sample_stack::<TestConvertRegs>(
            StackInput {
                code_addr: None,
                user_regs: Some(&regs),
                user_stack: Some(&saved_stack),
            },
            Priv::User,
            &mut unwinder,
            &mut stack,
            &[],
            &mut RecordingSummary::default(),
            |_, address| {
                assert!(refreshed.is_none());
                refreshed = Some(address);
                Ok(false)
            },
        )
        .unwrap();
        assert_eq!(refreshed, expected);
        assert_eq!(
            stack,
            [
                StackFrame::InstructionPointer(leaf, StackMode::User),
                StackFrame::ReturnAddress(caller, StackMode::User),
            ]
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn runtime_refresh_normalizes_a_jit_caller_at_the_end_of_its_range() {
    let regs = [0x3001, 0x8000, 0x8010];
    // Native leaf -> JIT return address at its range end -> native root.
    let saved_stack: Vec<_> = [0, 0, 0x8030, 0x1003, 0, 0, 0, 0x4001]
        .into_iter()
        .flat_map(u64::to_ne_bytes)
        .collect();
    let mut unwinder = ProcessUnwinder::default();
    unwinder
        .unwinder
        .add_jit_module(test_module(0x1000..0x1003));
    let mut refreshed = None;
    build_sample_stack::<TestConvertRegs>(
        StackInput {
            code_addr: None,
            user_regs: Some(&regs),
            user_stack: Some(&saved_stack),
        },
        Priv::User,
        &mut unwinder,
        &mut Vec::new(),
        &[],
        &mut RecordingSummary::default(),
        |_, address| {
            refreshed = Some(address);
            Ok(false)
        },
    )
    .unwrap();
    assert_eq!(refreshed, Some(0x1002));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn runtime_retry_uses_original_stack_and_records_only_final_errors() {
    let regs = [0x1001, 0x8000, 0x8200];
    // The caller's saved return address is null: the corrected rule reaches the root.
    let saved_stack = [0_u8; 16];
    let callchain = [
        StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
        StackFrame::ReturnAddress(0xffff_2000, StackMode::Kernel),
        StackFrame::InstructionPointer(0x1001, StackMode::User),
    ];
    for repair in [false, true] {
        let mut unwinder = ProcessUnwinder::default();
        // Both tables come from the same assembler program with different CFA offsets.
        unwinder.unwinder.add_jit_module(cfi_module(48));
        let mut stack = Vec::new();
        let mut summary = RecordingSummary::default();
        let mut refreshes = 0;
        build_sample_stack::<TestConvertRegs>(
            StackInput {
                code_addr: None,
                user_regs: Some(&regs),
                user_stack: Some(&saved_stack),
            },
            Priv::User,
            &mut unwinder,
            &mut stack,
            &callchain,
            &mut summary,
            |unwinder, address| {
                assert_eq!(address, 0x1001);
                refreshes += 1;
                if repair {
                    unwinder.unwinder.add_jit_module(cfi_module(16));
                }
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(refreshes, 1);
        assert_eq!(&stack[..2], &callchain[..2]);
        assert_eq!(
            stack[2],
            StackFrame::InstructionPointer(0x1001, StackMode::User)
        );
        assert_eq!(summary.ignored_user_callchain_frames, 1);
        assert_eq!(
            summary
                .error_stats
                .count(SampleErrorKind::NativeStackTruncated),
            u64::from(!repair)
        );
        assert_eq!(stack.contains(&StackFrame::TruncatedStackMarker), !repair);
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn runtime_refresh_error_preserves_the_attempt_without_committing_diagnostics() {
    let regs = [0x1001, 0x8000, 0x8200];
    let saved_stack = [0_u8; 16];
    let callchain = [StackFrame::InstructionPointer(0x1001, StackMode::User)];
    let mut unwinder = ProcessUnwinder::default();
    unwinder.unwinder.add_jit_module(cfi_module(48));
    let mut stack = Vec::new();
    let mut summary = RecordingSummary::default();

    let error = build_sample_stack::<TestConvertRegs>(
        StackInput {
            code_addr: None,
            user_regs: Some(&regs),
            user_stack: Some(&saved_stack),
        },
        Priv::User,
        &mut unwinder,
        &mut stack,
        &callchain,
        &mut summary,
        |_, _| Err(io::Error::other("cannot write refreshed metadata")),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "cannot write refreshed metadata");
    assert_eq!(
        stack,
        [
            StackFrame::InstructionPointer(0x1001, StackMode::User),
            StackFrame::TruncatedStackMarker,
        ]
    );
    assert_eq!(summary.ignored_user_callchain_frames, 0);
    assert_eq!(summary.unwind_fallbacks.total(), 0);
    assert_eq!(
        summary
            .error_stats
            .count(SampleErrorKind::NativeStackTruncated),
        0
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn runtime_retry_recovers_a_caller_after_terminal_frame_pointer_fallback() {
    let regs = [0x1001, 0x8000, 0x8010];
    // Frame pointers stop at null. The live CFI finds the caller at sp + 8.
    let saved_stack: Vec<_> = [0, 0x3001, 0, 0]
        .into_iter()
        .flat_map(u64::to_ne_bytes)
        .collect();
    let mut unwinder = ProcessUnwinder::default();
    unwinder
        .unwinder
        .add_jit_module(test_module(0x1000..0x1003));
    let mut stack = Vec::new();
    let mut summary = RecordingSummary::default();
    let mut refreshes = 0;
    build_sample_stack::<TestConvertRegs>(
        StackInput {
            code_addr: None,
            user_regs: Some(&regs),
            user_stack: Some(&saved_stack),
        },
        Priv::User,
        &mut unwinder,
        &mut stack,
        &[],
        &mut summary,
        |unwinder, address| {
            assert_eq!(address, 0x1001);
            refreshes += 1;
            unwinder.unwinder.add_jit_module(cfi_module(16));
            Ok(true)
        },
    )
    .unwrap();
    assert_eq!(refreshes, 1);
    assert_eq!(
        stack,
        [
            StackFrame::InstructionPointer(0x1001, StackMode::User),
            StackFrame::ReturnAddress(0x3001, StackMode::User),
        ]
    );
    assert_eq!(summary.unwind_fallbacks.total(), 0);
}

#[test]
fn build_sample_stack_ignores_unexpected_user_callchain() {
    let callchain_stack = [
        StackFrame::InstructionPointer(0x1000, StackMode::User),
        StackFrame::ReturnAddress(0x2000, StackMode::User),
    ];
    let sample = StackInput {
        code_addr: Some(0x3000),
        user_regs: None,
        user_stack: None,
    };
    let mut process_unwinder = ProcessUnwinder::default();
    let mut stack = Vec::new();
    let mut summary = RecordingSummary::default();

    build_sample_stack::<ConvertRegsNative>(
        sample,
        Priv::User,
        &mut process_unwinder,
        &mut stack,
        &callchain_stack,
        &mut summary,
        |_, _| panic!("invalid capture must not request JIT refresh"),
    )
    .unwrap();

    assert_eq!(
        stack,
        vec![StackFrame::InstructionPointer(0x3000, StackMode::User)]
    );
    assert_eq!(summary.ignored_user_callchain_frames, 2);
    assert_eq!(
        summary
            .error_stats
            .count(SampleErrorKind::NativeUserRegistersMissing),
        1
    );
    assert_eq!(
        summary.error_stats.count(SampleErrorKind::NativeStackRead),
        1
    );
}

#[test]
fn build_sample_stack_keeps_kernel_callchain_and_ignores_user_tail() {
    let callchain_stack = [
        StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
        StackFrame::ReturnAddress(0xffff_2000, StackMode::Kernel),
        StackFrame::InstructionPointer(0x1000, StackMode::User),
        StackFrame::ReturnAddress(0x2000, StackMode::User),
    ];
    let mut process_unwinder = ProcessUnwinder::default();
    let mut stack = Vec::new();
    let mut summary = RecordingSummary::default();

    build_sample_stack::<ConvertRegsNative>(
        StackInput {
            code_addr: None,
            user_regs: None,
            user_stack: None,
        },
        Priv::Kernel,
        &mut process_unwinder,
        &mut stack,
        &callchain_stack,
        &mut summary,
        |_, _| panic!("missing user registers must not request JIT refresh"),
    )
    .unwrap();

    assert_eq!(stack, &callchain_stack[..2]);
    assert_eq!(summary.ignored_user_callchain_frames, 2);
}

#[test]
fn build_sample_stack_treats_zero_user_stack_as_bad_sample() {
    let sample = StackInput {
        code_addr: Some(0x1000),
        user_regs: Some(&[]),
        user_stack: Some(&[]),
    };
    let mut process_unwinder = ProcessUnwinder::default();
    let mut stack = Vec::new();
    let mut summary = RecordingSummary::default();

    build_sample_stack::<ConvertRegsNative>(
        sample,
        Priv::User,
        &mut process_unwinder,
        &mut stack,
        &[],
        &mut summary,
        |_, _| panic!("invalid capture must not request JIT refresh"),
    )
    .unwrap();

    assert_eq!(
        stack,
        vec![StackFrame::InstructionPointer(0x1000, StackMode::User)]
    );
    assert_eq!(
        summary.error_stats.count(SampleErrorKind::NativeStackRead),
        1
    );
    assert_eq!(
        summary
            .error_stats
            .count(SampleErrorKind::NativeRegisterCapture),
        0
    );
    assert_eq!(
        summary
            .error_stats
            .count(SampleErrorKind::NativeStackTruncated),
        0
    );
}
