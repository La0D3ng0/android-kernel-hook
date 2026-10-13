#include <stdint.h>
#include <unwind.h>

extern "C" volatile unsigned int rtgum_dbi_personality_hits = 0;

/* A distinct Itanium personality with no LSDA. It deliberately only allows
 * the search and cleanup phases to continue to the caller's catch site. */
extern "C" _Unwind_Reason_Code rtgum_dbi_continue_personality(
    int version, _Unwind_Action, uint64_t, _Unwind_Exception *,
    _Unwind_Context *)
{
    ++rtgum_dbi_personality_hits;
    return version == 1 ? _URC_CONTINUE_UNWIND : _URC_FATAL_PHASE1_ERROR;
}

extern "C" long rtgum_dbi_personality_frame(long (*target)(long), long value);

/* Keeping this frame in assembly makes its CIE personality deterministic,
 * rather than depending on the C++ compiler's LSDA optimization choices. */
asm(R"(
    .text
    .p2align 2
    .globl rtgum_dbi_personality_frame
    .type rtgum_dbi_personality_frame, %function
rtgum_dbi_personality_frame:
    .cfi_startproc
    .cfi_personality 0x1b, rtgum_dbi_continue_personality
    stp x29, x30, [sp, #-16]!
    .cfi_def_cfa_offset 16
    .cfi_offset x29, -16
    .cfi_offset x30, -8
    mov x29, sp
    mov x16, x0
    mov x0, x1
    blr x16
    ldp x29, x30, [sp], #16
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size rtgum_dbi_personality_frame, .-rtgum_dbi_personality_frame
)");
