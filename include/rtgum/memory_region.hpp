#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "rtgum/status.hpp"

namespace rtgum {

class MemoryRegion final {
public:
    ~MemoryRegion();

    MemoryRegion(const MemoryRegion&) = delete;
    MemoryRegion& operator=(const MemoryRegion&) = delete;

    MemoryRegion(MemoryRegion&& other) noexcept;
    MemoryRegion& operator=(MemoryRegion&& other) noexcept;

    static Status Allocate(std::size_t requested_size,
                           std::unique_ptr<MemoryRegion>* output);

    Status Write(std::size_t offset, const void* source, std::size_t length);
    Status SealExecutable();

    [[nodiscard]] const std::uint8_t* data() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool writable() const noexcept;
    [[nodiscard]] bool executable() const noexcept;

private:
    MemoryRegion(void* address, std::size_t mapped_size) noexcept;
    void Reset() noexcept;

    void* address_{nullptr};
    std::size_t mapped_size_{0};
    bool writable_{false};
    bool executable_{false};
};

}  // namespace rtgum

