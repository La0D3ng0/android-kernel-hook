/*
 * librtgum-lab.so: shadow-page acceptance lab.
 *
 * lab_add(a, b) returns a + b (3 for (1,2)); the shadow REPLACE test rewrites
 * it to return 42. lab_listen(a, b) carries the LISTEN instrumentation site.
 * Both stay trivial (single ADD) so their first instruction fits the XOL
 * one-instruction whitelist.
 */

extern "C" __attribute__((visibility("default"), noinline)) long
lab_add(long a, long b)
{
    return a + b;
}

extern "C" __attribute__((visibility("default"), noinline)) long
lab_listen(long a, long b)
{
    return a + b;
}

extern "C" __attribute__((visibility("default"))) int
lab_baseline()
{
    return static_cast<int>(lab_add(1, 2));
}

/* The user gate for the INTERCEPT / BEFORE_AFTER modes. The kernel enters
 * it with x0 pointing at the on-stack register context and expects it to
 * finish with brk #0x5758 while x0 still points at the context. This gate
 * is a no-op: it leaves the registers untouched. */
extern "C" __attribute__((visibility("default"), naked)) void
lab_gate()
{
    __asm__ volatile("brk #0x5758" ::: "memory");
}

/* ---- DBI (instruction relocation) fixture --------------------------------
 * lab_flower contains the PC-relative classes the relocator must rewrite:
 * an ADRP/ADD pair for the global delta, a test-and-branch on a computed
 * bit, an indirect BLR through a function pointer, and a direct BL inside
 * the conditional arms. The tail helpers stay in the original SO, so the
 * clone's direct branches land far away and force the far-jump expansion. */

long g_flower_delta = 7;

static __attribute__((noinline)) long lab_flower_inc(long value)
{
    return value + g_flower_delta;
}

static __attribute__((noinline)) long lab_flower_dec(long value)
{
    return value - g_flower_delta;
}

static __attribute__((noinline)) long lab_flower_tail_a(long value)
{
    return value + 1;
}

static __attribute__((noinline)) long lab_flower_tail_b(long value)
{
    return value - 1;
}

extern "C" __attribute__((noinline, visibility("default"))) long
lab_flower(long a, long b)
{
    long x = a * 31 + b;
    if (x & 1)
        x = lab_flower_inc(x);
    else
        x = lab_flower_dec(x);
    long (*tail)(long) = x > 100 ? &lab_flower_tail_a : &lab_flower_tail_b;
    return tail(x);
}
