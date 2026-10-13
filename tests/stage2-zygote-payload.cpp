/*
 * rt-gum-sdk stage-2 remote-resolution payload.
 *
 * Mapped into Zygote by the KPM without execution: its DT_NEEDED set
 * (libc.so, libdl.so, libm.so) is fully satisfied by Zygote's already-loaded
 * libraries, so the in-kernel symbol resolver can register the NEEDED
 * libraries and repair all imports without loading anything new. The probe
 * is only executed by the control-side sanity path, never inside Zygote.
 */

extern "C" void *memset(void *destination, int value, unsigned long length);
extern "C" unsigned long strlen(const char *text);
extern "C" void *dlopen(const char *path, int flags);
extern "C" double pow(double base, double exponent);

extern "C" __attribute__((visibility("default"), noinline)) unsigned long
ghost_zygote_probe(unsigned long value)
{
    char buffer[32];
    memset(buffer, 0, sizeof(buffer));
    const unsigned long length = strlen("rtgum");
    const double powered = pow(2.0, 3.0);
    void *handle = dlopen("libc.so", 2 /* RTLD_NOW */);
    return value + length + static_cast<unsigned long>(powered) +
           (handle != nullptr ? 1UL : 0UL);
}
