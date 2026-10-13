namespace {

using PayloadFunction = int (*)(int);

__attribute__((noinline)) int add_probe_constant(int value)
{
    return value + 0x1234;
}

PayloadFunction volatile target = &add_probe_constant;

extern "C" __attribute__((visibility("hidden"), noinline)) int
ghost_ifunc_implementation(int value)
{
    return value + 0x2345;
}

extern "C" __attribute__((visibility("hidden"))) void *ghost_ifunc_resolver()
{
    return reinterpret_cast<void *>(&ghost_ifunc_implementation);
}

} // namespace

extern "C" __attribute__((visibility("default"), ifunc("ghost_ifunc_resolver"))) int
ghost_ifunc_probe(int value);

extern "C" __attribute__((visibility("hidden"), ifunc("ghost_ifunc_resolver"))) int
ghost_hidden_ifunc_probe(int value);

namespace {

PayloadFunction volatile ifunc_target = &ghost_ifunc_probe;
PayloadFunction volatile irelative_target = &ghost_hidden_ifunc_probe;

} // namespace

extern "C" __attribute__((visibility("default"))) int ghost_linker_probe(int value)
{
    return target(value);
}

extern "C" __attribute__((visibility("default"))) int ghost_ifunc_relocation_probe(int value)
{
    return ifunc_target(value);
}

extern "C" __attribute__((visibility("default"))) int
ghost_irelative_relocation_probe(int value)
{
    return irelative_target(value);
}
