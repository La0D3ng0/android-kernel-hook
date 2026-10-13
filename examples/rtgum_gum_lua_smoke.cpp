#include <cstdio>
#include <dlfcn.h>

#include "rtgum/gum_backend.hpp"
#include "rtgum/host_api_v2.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: rtgum_gum_lua_smoke <absolute Lua helper path>\n");
        return 2;
    }

    auto gum = rtgum::CreateGumBackend();
    if (!gum->Start().ok()) return 1;

    void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        std::fprintf(stderr, "Lua helper load failed: %s\n", dlerror());
        gum->Stop();
        return 1;
    }
    using Bind = long (*)(HostApiV2*);
    auto* bind = reinterpret_cast<Bind>(dlsym(library, "rtgum_host_bind_lua"));
    HostApiV2 host{};
    host.version = RTGUM_HOST_API_V2_VERSION;
    host.size = sizeof(host);
    const rtgum::Status lookup_bound = rtgum::BindGumReadOnlyHostApi(&host);
    char result[256]{};
    const long bound = lookup_bound.ok() && bind
        ? bind(&host) : RTGUM_HOST_ERR_NOENT;
    const long evaluated = bound == 0 && host.lua_eval
        ? host.lua_eval("local rc, address = rtgum.find_export('libc.so', 'getpid'); "
                        "assert(rc == 0 and address > 0); return 42",
                        result, sizeof(result))
        : RTGUM_HOST_ERR_NOTSUP;
    if (host.lua_stop) host.lua_stop();
    dlclose(library);
    gum->Stop();
    unsigned long stale_address = 0;
    const long stopped_lookup = host.find_export
        ? host.find_export("libc.so", "getpid", &stale_address)
        : RTGUM_HOST_ERR_NOTSUP;
    if (evaluated != 0) {
        std::fprintf(stderr, "Gum Lua lookup failed: %s\n", result);
        return 1;
    }
    if (stopped_lookup != RTGUM_HOST_ERR_NXIO || stale_address != 0) {
        std::fprintf(stderr, "Gum lookup remained active after stop\n");
        return 1;
    }
    std::printf("Gum Lua self-process export lookup: %s\n", result);
    return 0;
}
