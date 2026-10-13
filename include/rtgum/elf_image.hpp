#pragma once

#include <cstddef>
#include <cstdint>

#include "rtgum/status.hpp"

namespace rtgum {

struct ElfImageInfo {
    std::uint16_t type{0};
    std::uint16_t machine{0};
    std::uint64_t entry{0};
    std::uint64_t program_header_offset{0};
    std::uint16_t program_header_count{0};
};

class ElfImageView final {
public:
    ElfImageView(const void* data, std::size_t size) noexcept;

    Status Validate64LittleEndian(ElfImageInfo* output) const;

private:
    const std::uint8_t* data_{nullptr};
    std::size_t size_{0};
};

}  // namespace rtgum

