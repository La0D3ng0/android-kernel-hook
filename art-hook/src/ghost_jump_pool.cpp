// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "ghost_jump_pool.h"

#include <cstdint>

namespace art_hook {
namespace {

constexpr std::size_t kPageSize = 4096U;
constexpr std::size_t kPoolSlotSize = 512U;
constexpr unsigned int kPoolSlotCount =
    static_cast<unsigned int>(kPageSize / kPoolSlotSize);

unsigned int FirstFreeSlot(unsigned int mask, unsigned int count) {
  for (unsigned int slot = 0U; slot < count; ++slot) {
    if ((mask & (1U << slot)) == 0U) return slot;
  }
  return count;
}

}  // namespace

GhostJumpPool::~GhostJumpPool() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (PoolPage &page : pages_) {
    if (page.base != nullptr && host_ != nullptr) {
      (void)host_->ghost_free(reinterpret_cast<unsigned long>(page.base));
    }
  }
  pages_.clear();
}

Result<void *> GhostJumpPool::Allocate(std::size_t slice_size) {
  if (slice_size == 0U || slice_size > kPageSize) {
    return Status(StatusCode::kInvalidArgument,
                  "ghost jump pool slice size is out of range");
  }
  if (host_ == nullptr || host_->ghost_alloc == nullptr ||
      host_->ghost_free == nullptr || host_->ghost_protect == nullptr ||
      host_->ghost_code_write == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "ghost jump pool host is incomplete");
  }
  std::lock_guard<std::mutex> lock(mutex_);

  const std::size_t slot_size =
      slice_size <= kPoolSlotSize ? kPoolSlotSize : kPageSize;
  const unsigned int slot_count =
      slot_size == kPoolSlotSize ? kPoolSlotCount : 1U;
  for (PoolPage &page : pages_) {
    if (page.slice_size != slot_size || page.slot_count != slot_count) continue;
    const unsigned int slot = FirstFreeSlot(page.used_mask, page.slot_count);
    if (slot == page.slot_count) continue;
    page.used_mask |= 1U << slot;
    auto *base = static_cast<unsigned char *>(page.base);
    return static_cast<void *>(base + static_cast<std::size_t>(slot) * slot_size);
  }

  unsigned long page_address = 0UL;
  const long status = host_->ghost_alloc(kPageSize, 3U /* Read|Write */,
                                         &page_address);
  if (status != 0 || page_address == 0UL) {
    return Status(StatusCode::kResourceExhausted,
                  "ghost_alloc failed for the jump pool");
  }
  PoolPage page;
  page.base = reinterpret_cast<void *>(page_address);
  page.slice_size = slot_size;
  page.used_mask = 1U;
  page.slot_count = slot_count;
  page.needs_protect = true;
  pages_.push_back(page);
  return page.base;
}

Status GhostJumpPool::Write(void *slice, const void *bytes, std::size_t size) {
  if (slice == nullptr || bytes == nullptr || size == 0U || host_ == nullptr ||
      host_->ghost_code_write == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ghost jump pool write argument is invalid");
  }
  std::lock_guard<std::mutex> lock(mutex_);
  const auto address = reinterpret_cast<std::uintptr_t>(slice);
  for (PoolPage &page : pages_) {
    const auto base = reinterpret_cast<std::uintptr_t>(page.base);
    if (address < base || address >= base + kPageSize) continue;
    const std::size_t offset = static_cast<std::size_t>(address - base);
    if ((offset % page.slice_size) != 0U || size > page.slice_size) {
      return Status(StatusCode::kResourceExhausted,
                    "ghost jump pool slot capacity exceeded");
    }
    const unsigned int slot =
        static_cast<unsigned int>(offset / page.slice_size);
    if (slot >= page.slot_count || (page.used_mask & (1U << slot)) == 0U) {
      return Status(StatusCode::kNotFound,
                    "ghost jump pool slot is not allocated");
    }
    const long status = host_->ghost_code_write(
        static_cast<unsigned long>(address), bytes,
        static_cast<unsigned long>(size));
    if (status != 0) {
      return Status(StatusCode::kPlatformError,
                    "ghost code commit failed for the jump pool slot");
    }
    return Status::Ok();
  }
  return Status(StatusCode::kNotFound, "ghost jump pool slice not found");
}

Status GhostJumpPool::Finalize(void *slice) {
  if (slice == nullptr || host_ == nullptr || host_->ghost_protect == nullptr) {
    return Status(StatusCode::kInvalidArgument, "ghost jump pool finalize arg");
  }
  std::lock_guard<std::mutex> lock(mutex_);
  const auto address = reinterpret_cast<std::uintptr_t>(slice);
  for (PoolPage &page : pages_) {
    const auto base = reinterpret_cast<std::uintptr_t>(page.base);
    if (address < base || address >= base + kPageSize) continue;
    const std::size_t offset = static_cast<std::size_t>(address - base);
    if ((offset % page.slice_size) != 0U) {
      return Status(StatusCode::kInvalidArgument,
                    "ghost jump pool slice is misaligned");
    }
    if (!page.needs_protect) return Status::Ok();
    const long status = host_->ghost_protect(
        reinterpret_cast<unsigned long>(page.base), 5U /* Read|Execute */);
    if (status != 0) {
      return Status(StatusCode::kPlatformError,
                    "ghost_protect failed for the jump pool page");
    }
    page.needs_protect = false;
    return Status::Ok();
  }
  return Status(StatusCode::kNotFound, "ghost jump pool slice not found");
}

Status GhostJumpPool::Free(void *slice) {
  (void)slice;
  /* Retired: a thread suspended inside the trampoline may resume later. The
   * pool and its slices live until process exit. */
  return Status::Ok();
}

}  // namespace art_hook
