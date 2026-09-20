/* Linked at fixed addresses for copied-memory unwind lifecycle tests. */
#ifndef FUNCTION_NAME
#define FUNCTION_NAME first
#endif
.text
.globl FUNCTION_NAME
.type FUNCTION_NAME, @function
FUNCTION_NAME:
#ifdef ZERO_SIZE_ALIASES
.globl alias
.type alias, @function
alias:
#endif

#if CFA_OFFSET != 0
    .cfi_startproc
    .cfi_def_cfa_offset CFA_OFFSET
#endif
    nop
    nop
    ret

#if CFA_OFFSET != 0
    .cfi_endproc
#endif
#ifndef ZERO_SIZE_ALIASES
.size FUNCTION_NAME, .-FUNCTION_NAME
#else
.globl next_function
.type next_function, @function
next_function:
    ret
.size next_function, .-next_function
#endif
.section .note.GNU-stack,"",@progbits
