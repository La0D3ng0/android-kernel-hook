#include <array>
#include <cstdint>
#include <iostream>
#include <memory>

#include "rtgum/art_probe.hpp"
#include "rtgum/memory_region.hpp"
#include "rtgum/runtime.hpp"
#include "rtgum/system_library.hpp"

int main(int argc, char** argv) {
    rtgum::Runtime runtime;
    const rtgum::Status started = runtime.Start();
    if (!started.ok()) {
        std::cerr << "runtime start failed: " << started.message() << '\n';
        return 1;
    }

    std::unique_ptr<rtgum::MemoryRegion> region;
    rtgum::Status status = rtgum::MemoryRegion::Allocate(32, &region);
    if (!status.ok()) {
        std::cerr << "memory allocation failed: " << status.message() << '\n';
        return 1;
    }

    constexpr std::array<std::uint8_t, 4> marker = {0x52, 0x54, 0x47, 0x4d};
    status = region->Write(0, marker.data(), marker.size());
    if (!status.ok()) {
        std::cerr << "memory write failed: " << status.message() << '\n';
        return 1;
    }

    status = region->SealExecutable();
    if (!status.ok()) {
        std::cerr << "memory seal failed: " << status.message() << '\n';
        return 1;
    }

    rtgum::ArtRuntimeInfo art_info;
    status = rtgum::ProbeArtRuntime(&art_info);
    if (!status.ok()) {
        std::cerr << "ART probe failed: " << status.message() << '\n';
        return 1;
    }

    std::unique_ptr<rtgum::SystemLibrary> library;
    if (argc == 2) {
        status = rtgum::SystemLibrary::Open(argv[1], &library);
        if (!status.ok()) {
            std::cerr << "library load failed: " << status.message() << '\n';
            return 1;
        }
    } else if (argc > 2) {
        std::cerr << "usage: rtgum_probe [absolute-library-path]\n";
        return 2;
    }

    std::cout << "rt-gum probe ready"
              << " state=" << static_cast<int>(runtime.state())
              << " region_size=" << region->size()
              << " writable=" << region->writable()
              << " executable=" << region->executable()
              << " android_api=" << art_info.android_api_level
              << " art_loaded=" << art_info.loaded();
    if (art_info.loaded()) {
        std::cout << " art_path=" << art_info.module_path;
    }
    if (library != nullptr) {
        std::cout << " library=" << library->path();
    }
    std::cout << '\n';
    return 0;
}
