/* Runtime-only flower-instruction fixture.
 *
 * The BR lands at +24 and skips three words which are intentionally not valid
 * application instructions.  A static linear sweep will walk into them; a
 * dynamic follower records only +0,+4,+8,+24,+28.
 */

    .text
    .p2align 4
    .global rtgum_gtrace_flower
    .type rtgum_gtrace_flower, %function
rtgum_gtrace_flower:
    add     w0, w0, w1
    adr     x16, .Lreal
    br      x16
    .word   0xffffffff
    .word   0x00000000
    .word   0xdeadbeef
.Lreal:
    add     w0, w0, #39
    ret

    .global rtgum_gtrace_flower_end
    .type rtgum_gtrace_flower_end, %object
rtgum_gtrace_flower_end:
    .size rtgum_gtrace_flower, rtgum_gtrace_flower_end - rtgum_gtrace_flower
    .size rtgum_gtrace_flower_end, 0

/* Two small exported functions used by the multi-trace acceptance.  Their
 * ranges and results are intentionally distinct, so a writer routed through
 * the wrong handle is observable without relying on timing. */
    .p2align 4
    .global rtgum_multitrace_a
    .type rtgum_multitrace_a, %function
rtgum_multitrace_a:
    add     w0, w0, #10
    add     w0, w0, #1
    ret
    .global rtgum_multitrace_a_end
    .type rtgum_multitrace_a_end, %object
rtgum_multitrace_a_end:
    .size rtgum_multitrace_a, rtgum_multitrace_a_end - rtgum_multitrace_a
    .size rtgum_multitrace_a_end, 0

    .p2align 4
    .global rtgum_multitrace_b
    .type rtgum_multitrace_b, %function
rtgum_multitrace_b:
    add     w0, w0, #20
    add     w0, w0, #2
    ret
    .global rtgum_multitrace_b_end
    .type rtgum_multitrace_b_end, %object
rtgum_multitrace_b_end:
    .size rtgum_multitrace_b, rtgum_multitrace_b_end - rtgum_multitrace_b
    .size rtgum_multitrace_b_end, 0

    .section .note.GNU-stack,"",%progbits
