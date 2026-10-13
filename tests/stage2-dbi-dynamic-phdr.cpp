#include <link.h>
#include <stddef.h>

/* Make this fixture's unguarded PLT overlap the BTI-guarded replacement's
 * PLT after the loader reuses its base. This catches stale Stalker exclusions
 * which a same-base test with nonoverlapping sections would miss. */
__asm__(".pushsection .text\n"
        ".space 0xa0\n"
        ".popsection\n");

namespace {

int count_module(dl_phdr_info *, size_t, void *opaque)
{
    ++*static_cast<unsigned int *>(opaque);
    return 0;
}

}

extern "C" __attribute__((visibility("default"), noinline))
unsigned int rtgum_dynamic_phdr_probe()
{
    unsigned int count = 0;
    dl_iterate_phdr(count_module, &count);
    return count;
}
