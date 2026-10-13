#include <link.h>
#include <stddef.h>

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
    return count + 1000U;
}
