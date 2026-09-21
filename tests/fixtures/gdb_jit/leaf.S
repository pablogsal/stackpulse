/* A frame-pointer-free leaf whose caller requires the registered CFI. */
.macro busy_leaf name, section
.section \section,"ax",@progbits
.globl \name
.type \name, @function
\name:
    .cfi_startproc
    subq $40, %rsp
    .cfi_def_cfa_offset 48
1:  jmp 1b
    .cfi_endproc
.size \name, .-\name
.endm

#ifdef MULTI_SECTION
/* Both functions share .eh_frame; execution starts in the later section. */
busy_leaf unused_leaf, .jit_first
busy_leaf registered_leaf, .jit_second
#else
busy_leaf registered_leaf, .jit_first
#endif

.section .note.GNU-stack,"",@progbits
