#pragma once

#include <cstdint>
#include <string>

#include "rtgum/status.hpp"

namespace rtgum {

struct ArtRuntimeInfo {
    int android_api_level{-1};
    std::uintptr_t module_base{0};
    std::string module_path;

    [[nodiscard]] bool loaded() const noexcept {
        return module_base != 0 || !module_path.empty();
    }
};

// Reports ART metadata already visible in the current process. This function
// does not load libart, resolve private symbols, or modify runtime structures.
Status ProbeArtRuntime(ArtRuntimeInfo* output);

}  // namespace rtgum

