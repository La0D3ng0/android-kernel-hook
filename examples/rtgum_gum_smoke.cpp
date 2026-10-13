#include <cstdio>

#include <frida-gum.h>

#include "rtgum/gum_backend.hpp"

int main() {
    auto first = rtgum::CreateGumBackend();
    auto second = rtgum::CreateGumBackend();
    const rtgum::Status first_started = first->Start();
    const rtgum::Status second_started = second->Start();
    if (!first_started.ok() || !second_started.ok()) {
        std::fprintf(stderr, "Gum start failed\n");
        return 1;
    }

    first->Stop();
    const GumAddress getpid = gum_module_find_global_export_by_name("getpid");
    std::printf("Gum self-process getpid export: %s\n",
                getpid == 0 ? "missing" : "found");
    second->Stop();
    return getpid == 0 ? 1 : 0;
}
