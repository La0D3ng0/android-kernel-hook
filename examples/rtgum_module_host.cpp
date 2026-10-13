#include <cstdio>
#include <string>

#include "rtgum/module_runtime.hpp"

namespace {

long Log(const char* message) {
    std::printf("module: %s\n", message ? message : "");
    return 0;
}

long Status(unsigned int index, unsigned long value) {
    std::printf("module status[%u]=%lu\n", index, value);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: rtgum-module-host <absolute .ghm path> <package>\n");
        return 2;
    }
    GhostApi api{};
    api.version = RTGUM_GHOST_API_VERSION;
    api.log = Log;
    api.status = Status;
    rtgum::VisibleModuleLoader loader;
    rtgum::ModuleRuntime modules(&api, &loader, [] { return rtgum::Status::Ok(); });
    const std::string package_name(argv[2]);
    rtgum::Status status = modules.Configure({{package_name, argv[1]}});
    if (status.ok()) status = modules.LoadForPackage(package_name);
    if (status.ok()) status = modules.ReloadForPackage(package_name);
    if (status.ok()) status = modules.Unload();
    if (!status.ok()) {
        std::fprintf(stderr, "module host failed: %s\n", status.message().c_str());
        return 1;
    }
    std::puts("module load, reload, and unload passed");
    return 0;
}
