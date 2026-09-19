/* Two linked versions occupy the same range but use different unwind rules. */
.text
.globl overlay_leaf
.type overlay_leaf, @function
overlay_leaf:
    .cfi_startproc
    .cfi_def_cfa_offset CFA_OFFSET
    nop
    nop
    ret
    .cfi_endproc
.size overlay_leaf, .-overlay_leaf
.section .note.GNU-stack,"",@progbits
