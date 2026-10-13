#include "rtgum/art_probe.hpp"

#include <cstring>

#if defined(__ANDROID__)
#include <android/api-level.h>
#include <link.h>
#elif defined(__linux__)
#include <link.h>
#endif

namespace rtgum {
namespace {

#if defined(__ANDROID__) || defined(__linux__)
bool IsArtLibrary(const char* path) noexcept {
    if (path == nullptr || *path == '\0') {
        return false;
    }
    const char* slash = std::strrchr(path, '/');
    const char* name = slash == nullptr ? path : slash + 1;
    return std::strcmp(name, "libart.so") == 0;
}

int FindArtModule(dl_phdr_info* info, std::size_t, void* opaque) {
    if (!IsArtLibrary(info->dlpi_name)) {
        return 0;
    }

    auto* output = static_cast<ArtRuntimeInfo*>(opaque);
    output->module_base = static_cast<std::uintptr_t>(info->dlpi_addr);
    output->module_path = info->dlpi_name;
    return 1;
}
#endif

}  // namespace

Status ProbeArtRuntime(ArtRuntimeInfo* output) {
    if (output == nullptr) {
        return {StatusCode::kInvalidArgument, "output must not be null"};
    }

    *output = {};
#if defined(__ANDROID__)
    output->android_api_level = android_get_device_api_level();
#endif
#if defined(__ANDROID__) || defined(__linux__)
    (void)dl_iterate_phdr(FindArtModule, output);
#endif
    return Status::Ok();
}

}  // namespace rtgum

