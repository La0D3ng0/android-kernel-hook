// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/code_allocator.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace art_hook {
namespace {

std::size_t SystemPageSize() {
#if defined(_WIN32)
  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  return static_cast<std::size_t>(info.dwPageSize);
#else
  const long value = sysconf(_SC_PAGESIZE);
  return value > 0 ? static_cast<std::size_t>(value) : 4096U;
#endif
}

bool IsPowerOfTwo(std::size_t value) {
  return value != 0 && (value & (value - 1)) == 0;
}

}  // namespace

Status SliceAllocator::Write(void* slice, const void* bytes,
                             std::size_t size) {
  if (slice == nullptr || bytes == nullptr || size == 0U) {
    return Status(StatusCode::kInvalidArgument,
                  "slice allocator write argument is invalid");
  }
  std::memcpy(slice, bytes, size);
  auto* begin = static_cast<char*>(slice);
  __builtin___clear_cache(begin, begin + size);
  return Status::Ok();
}

CodeAllocator::CodeAllocator(std::size_t slice_size)
    : page_size_(SystemPageSize()), slice_size_(slice_size) {
  if (slice_size_ == 0 || slice_size_ > page_size_) {
    throw std::invalid_argument("slice size must fit in one page");
  }
  slices_per_page_ = page_size_ / slice_size_;
}

CodeAllocator::~CodeAllocator() { ReleasePages(); }

Result<void*> CodeAllocator::Allocate(const AllocationSpec& spec,
                                      std::size_t alignment) {
  if (!IsPowerOfTwo(alignment)) {
    return Status(StatusCode::kInvalidArgument,
                  "alignment must be a non-zero power of two");
  }
  if (spec.near.has_value() && spec.max_distance == 0) {
    return Status(StatusCode::kInvalidArgument,
                  "near allocation requires a non-zero max_distance");
  }

  std::lock_guard<std::mutex> lock(mutex_);
  if (sealed_) {
    return Status(StatusCode::kUnavailable,
                  "allocator has already been sealed executable");
  }

  for (auto it = free_.begin(); it != free_.end(); ++it) {
    const auto address = reinterpret_cast<std::uintptr_t>(*it);
    if ((address & (alignment - 1U)) == 0U && IsNear(*it, spec)) {
      void* result = *it;
      free_.erase(it);
      return result;
    }
  }
  return AllocatePage(spec);
}

Status CodeAllocator::Free(void* slice) {
  if (slice == nullptr) {
    return Status(StatusCode::kInvalidArgument, "slice is null");
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if (sealed_) {
    return Status(StatusCode::kUnavailable,
                  "sealed executable slices cannot be recycled");
  }
  if (std::find(free_.begin(), free_.end(), slice) != free_.end()) {
    return Status(StatusCode::kInvalidArgument, "slice was already freed");
  }
  free_.push_back(slice);
  return Status::Ok();
}

Result<void*> CodeAllocator::Allocate(std::size_t slice_size) {
  return Allocate(AllocationSpec{}, slice_size == page_size_ ? 1U
                                                             : slice_size);
}

Status CodeAllocator::Seal() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (sealed_) {
    return Status::Ok();
  }
  for (void* page : pages_) {
#if defined(_WIN32)
    DWORD old_protection = 0;
    if (VirtualProtect(page, page_size_, PAGE_EXECUTE_READ, &old_protection) ==
        0) {
      return Status(StatusCode::kPlatformError, "VirtualProtect failed");
    }
    FlushInstructionCache(GetCurrentProcess(), page, page_size_);
#else
    if (mprotect(page, page_size_, PROT_READ | PROT_EXEC) != 0) {
      return Status(StatusCode::kPlatformError, "mprotect failed");
    }
    auto* begin = static_cast<char*>(page);
    __builtin___clear_cache(begin, begin + page_size_);
#endif
  }
  sealed_ = true;
  free_.clear();
  return Status::Ok();
}

Result<void*> CodeAllocator::AllocatePage(const AllocationSpec& spec) {
  void* hint = spec.near.has_value()
                   ? reinterpret_cast<void*>(*spec.near & ~(page_size_ - 1U))
                   : nullptr;
#if defined(_WIN32)
  void* page = VirtualAlloc(hint, page_size_, MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);
#else
  void* page = mmap(hint, page_size_, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    page = nullptr;
  }
#endif
  if (page == nullptr) {
    return Status(StatusCode::kResourceExhausted,
                  "unable to allocate a writable code page");
  }
  if (!IsNear(page, spec)) {
#if defined(_WIN32)
    VirtualFree(page, 0, MEM_RELEASE);
#else
    munmap(page, page_size_);
#endif
    return Status(StatusCode::kUnavailable,
                  "platform allocator could not satisfy near constraint");
  }

  pages_.push_back(page);
  auto* bytes = static_cast<std::uint8_t*>(page);
  for (std::size_t i = 1; i < slices_per_page_; ++i) {
    free_.push_back(bytes + i * slice_size_);
  }
  return page;
}

bool CodeAllocator::IsNear(void* slice, const AllocationSpec& spec) const {
  if (!spec.near.has_value()) {
    return true;
  }
  const auto begin = reinterpret_cast<std::uintptr_t>(slice);
  if (begin > std::numeric_limits<std::uintptr_t>::max() - slice_size_) {
    return false;
  }
  const auto end = begin + slice_size_;
  const auto target = *spec.near;
  const auto begin_distance = begin > target ? begin - target : target - begin;
  const auto end_distance = end > target ? end - target : target - end;
  return begin_distance <= spec.max_distance &&
         end_distance <= spec.max_distance;
}

void CodeAllocator::ReleasePages() noexcept {
  for (void* page : pages_) {
#if defined(_WIN32)
    VirtualFree(page, 0, MEM_RELEASE);
#else
    munmap(page, page_size_);
#endif
  }
  pages_.clear();
  free_.clear();
}

}  // namespace art_hook
