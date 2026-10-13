/* Pixel 8 control-process probe: one bionic import plus an image-local IFUNC. */
extern "C" unsigned long strlen(const char *text);

extern "C" __attribute__((noinline)) unsigned long ghost_needed_ifunc_impl(unsigned long value)
{
    return value + 7UL;
}

extern "C" void *ghost_needed_ifunc_resolver()
{
    return reinterpret_cast<void *>(ghost_needed_ifunc_impl);
}

extern "C" unsigned long ghost_needed_ifunc(unsigned long value)
    __attribute__((ifunc("ghost_needed_ifunc_resolver")));

extern "C" __attribute__((visibility("default"), noinline)) unsigned long
ghost_needed_ifunc_probe(unsigned long value)
{
    return ghost_needed_ifunc(value) + strlen("pixel8");
}
