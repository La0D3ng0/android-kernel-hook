/* Trampoline verification: assemble and compare encodings. */
    .text
trampoline:
    str  x19, [x1, #0x200]
    mov  x19, x1
    str  x20, [x19, #0x208]
    str  x21, [x19, #0x210]
    str  x22, [x19, #0x218]
    str  x23, [x19, #0x220]
    str  x26, [x19, #0x228]
    str  x24, [x19, #0x230]
    str  x25, [x19, #0x238]
    str  x27, [x19, #0x240]
    str  x28, [x19, #0x248]
    str  x0, [x19, #0x58]
    stp  x2, x3, [x19, #0x68]
    stp  x4, x5, [x19, #0x78]
    stp  x6, x7, [x19, #0x88]
    stp  x8, x9, [x19, #0x98]
    stp  x10, x11, [x19, #0xA8]
    stp  x12, x13, [x19, #0xB8]
    stp  x14, x15, [x19, #0xC8]
    stp  x16, x17, [x19, #0xD8]
    stp  x18, x29, [x19, #0xE8]
    str  x30, [x19, #0xF8]
    add  x16, x19, #0xA00
    stp  q0, q1, [x16, #0x000]
    stp  q2, q3, [x16, #0x020]
    stp  q4, q5, [x16, #0x040]
    stp  q6, q7, [x16, #0x060]
    stp  q8, q9, [x16, #0x080]
    stp  q10, q11, [x16, #0x0A0]
    stp  q12, q13, [x16, #0x0C0]
    stp  q14, q15, [x16, #0x0E0]
    stp  q16, q17, [x16, #0x100]
    stp  q18, q19, [x16, #0x120]
    stp  q20, q21, [x16, #0x140]
    stp  q22, q23, [x16, #0x160]
    stp  q24, q25, [x16, #0x180]
    stp  q26, q27, [x16, #0x1A0]
    stp  q28, q29, [x16, #0x1C0]
    stp  q30, q31, [x16, #0x1E0]
    mrs  x17, fpcr
    str  x17, [x16, #0x200]
    mrs  x17, fpsr
    str  x17, [x16, #0x208]
    mrs  x26, nzcv
    ldr  x20, [x19, #0x20]
    cbz  x20, fixup_done
    add  x20, x19, x20
fixup_loop:
    ldr  x21, [x20]
    cbz  x21, fixup_done
    ldr  x22, [x20, #8]
    ldr  x23, [x20, #16]
    add  x20, x20, #0x18
    ldr  x0, [x19, #0xC28]  /* HWCAP | _IFUNC_ARG_HWCAP */
    add  x1, x19, #0xC10  /* __ifunc_arg_t */
    blr  x21
    add  x0, x0, x23
    str  x0, [x22]
    b    fixup_loop
fixup_done:
    mov  x0, x19
    ldr  x20, [x19, #8]
    blr  x20
    add  x16, x19, #0xA00
    ldp  q0, q1, [x16, #0x000]
    ldp  q2, q3, [x16, #0x020]
    ldp  q4, q5, [x16, #0x040]
    ldp  q6, q7, [x16, #0x060]
    ldp  q8, q9, [x16, #0x080]
    ldp  q10, q11, [x16, #0x0A0]
    ldp  q12, q13, [x16, #0x0C0]
    ldp  q14, q15, [x16, #0x0E0]
    ldp  q16, q17, [x16, #0x100]
    ldp  q18, q19, [x16, #0x120]
    ldp  q20, q21, [x16, #0x140]
    ldp  q22, q23, [x16, #0x160]
    ldp  q24, q25, [x16, #0x180]
    ldp  q26, q27, [x16, #0x1A0]
    ldp  q28, q29, [x16, #0x1C0]
    ldp  q30, q31, [x16, #0x1E0]
    ldr  x17, [x16, #0x200]
    msr  fpcr, x17
    ldr  x17, [x16, #0x208]
    msr  fpsr, x17
    msr  nzcv, x26
    ldp  x0, x1, [x19, #0x58]
    ldp  x2, x3, [x19, #0x68]
    ldp  x4, x5, [x19, #0x78]
    ldp  x6, x7, [x19, #0x88]
    ldp  x8, x9, [x19, #0x98]
    ldp  x10, x11, [x19, #0xA8]
    ldp  x12, x13, [x19, #0xB8]
    ldp  x14, x15, [x19, #0xC8]
    ldp  x16, x17, [x19, #0xD8]
    ldp  x18, x29, [x19, #0xE8]
    ldr  x30, [x19, #0xF8]
    ldr  x16, [x19]
    ldr  x23, [x19, #0x220]
    ldr  x28, [x19, #0x248]
    ldr  x27, [x19, #0x240]
    ldr  x25, [x19, #0x238]
    ldr  x24, [x19, #0x230]
    ldr  x22, [x19, #0x218]
    ldr  x21, [x19, #0x210]
    ldr  x20, [x19, #0x208]
    ldr  x26, [x19, #0x228]
    ldr  x19, [x19, #0x200]
    br   x16
