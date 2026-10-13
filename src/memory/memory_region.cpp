#include "rtgum/memory_region.hpp"

#include <cstring>
#include <limits>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace rtgum {
namespace {

std::size_t PageSize() noexcept {
#if defined(_WIN32)
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    return static_cast<std::size_t>(info.dwPageSize);
#else
    const long value = sysconf(_SC_PAGESIZE);
    return value > 0 ? static_cast<std::size_t>(value) : 4096U;
#endif
}

Status RoundUpToPage(std::size_t requested, std::size_t* rounded) {
    if (rounded == nullptr || requested == 0) {
        return {StatusCode::kInvalidArgument, "allocation size must be non-zero"};
    }

    const std::size_t page_size = PageSize();
    if (requested > std::numeric_limits<std::size_t>::max() - (page_size - 1U)) {
        return {StatusCode::kInvalidArgument, "allocation size overflows"};
    }

    *rounded = ((requested + page_size - 1U) / page_size) * page_size;
    return Status::Ok();
}

}  // namespace

MemoryRegion::MemoryRegion(void* address, std::size_t mapped_size) noexcept
    : address_(address), mapped_size_(mapped_size), writable_(true) {}

MemoryRegion::~MemoryRegion() {
    Reset();
}

MemoryRegion::MemoryRegion(MemoryRegion&& other) noexcept {
    *this = std::move(other);
}

MemoryRegion& MemoryRegion::operator=(MemoryRegion&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    Reset();
    address_ = std::exchange(other.address_, nullptr);
    mapped_size_ = std::exchange(other.mapped_size_, 0);
    writable_ = std::exchange(other.writable_, false);
    executable_ = std::exchange(other.executable_, false);
    return *this;
}

Status MemoryRegion::Allocate(std::size_t requested_size,
                              std::unique_ptr<MemoryRegion>* output) {
    if (output == nullptr) {
        return {StatusCode::kInvalidArgument, "output must not be null"};
    }

    std::size_t mapped_size = 0;
    const Status rounded = RoundUpToPage(requested_size, &mapped_size);
    if (!rounded.ok()) {
        return rounded;
    }

#if defined(_WIN32)
    void* address = VirtualAlloc(nullptr, mapped_size, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_READWRITE);
    if (address == nullptr) {
        return {StatusCode::kSystemError, "VirtualAlloc failed"};
    }
#else
    void* address = mmap(nullptr, mapped_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) {
        return {StatusCode::kSystemError, "mmap failed"};
    }
#endif

    output->reset(new MemoryRegion(address, mapped_size));
    return Status::Ok();
}

Status MemoryRegion::Write(std::size_t offset, const void* source,
                           std::size_t length) {
    if (!writable_) {
        return {StatusCode::kInvalidState, "memory region is sealed"};
    }
    if (source == nullptr && length != 0) {
        return {StatusCode::kInvalidArgument, "source must not be null"};
    }
    if (offset > mapped_size_ || length > mapped_size_ - offset) {
        return {StatusCode::kInvalidArgument, "write is outside the region"};
    }
    if (length == 0) {
        return Status::Ok();
    }

    std::memcpy(static_cast<std::uint8_t*>(address_) + offset, source, length);
    return Status::Ok();
}

Status MemoryRegion::SealExecutable() {
    if (address_ == nullptr) {
        return {StatusCode::kInvalidState, "memory region is not allocated"};
    }
    if (!writable_) {
        return executable_ ? Status::Ok()
                           : Status{StatusCode::kInvalidState,
                                    "memory region is not writable"};
    }

#if defined(_WIN32)
    DWORD previous = 0;
    if (VirtualProtect(address_, mapped_size_, PAGE_EXECUTE_READ, &previous) == 0) {
        return {StatusCode::kSystemError, "VirtualProtect failed"};
    }
    FlushInstructionCache(GetCurrentProcess(), address_, mapped_size_);
#else
    if (mprotect(address_, mapped_size_, PROT_READ | PROT_EXEC) != 0) {
        return {StatusCode::kSystemError, "mprotect failed"};
    }
    __builtin___clear_cache(static_cast<char*>(address_),
                            static_cast<char*>(address_) + mapped_size_);
#endif

    writable_ = false;
    executable_ = true;
    return Status::Ok();
}

const std::uint8_t* MemoryRegion::data() const noexcept {
    return static_cast<const std::uint8_t*>(address_);
}

std::size_t MemoryRegion::size() const noexcept {
    return mapped_size_;
}

bool MemoryRegion::writable() const noexcept {
    return writable_;
}

bool MemoryRegion::executable() const noexcept {
    return executable_;
}

void MemoryRegion::Reset() noexcept {
    if (address_ == nullptr) {
        return;
    }
#if defined(_WIN32)
    (void)VirtualFree(address_, 0, MEM_RELEASE);
#else
    (void)munmap(address_, mapped_size_);
#endif
    address_ = nullptr;
    mapped_size_ = 0;
    writable_ = false;
    executable_ = false;
}

}  // namespace rtgum
