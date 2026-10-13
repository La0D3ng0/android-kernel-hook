// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>

#include "art_hook/status.h"

namespace art_hook {

struct AllocationSpec final {
  std::optional<std::uintptr_t> near;
  std::size_t max_distance = 0;
};

// Backend boundary for trampoline allocation. The default CodeAllocator uses
// process-visible mmap; a host may substitute a VMA-less backend (e.g. the
// Mako ghost jump pool over ghostMalloc(RWX)) so no maps entry appears.
class SliceAllocator {
 public:
  virtual ~SliceAllocator() = default;

  // Allocates one slice of the given size and returns its address. The
  // caller writes the code bytes before any execution; backends that hand
  // out writable (non-executable) memory must switch the page to RX inside
  // Finalize, which the caller invokes once the slice is written.
  [[nodiscard]] virtual Result<void*> Allocate(std::size_t slice_size) = 0;
  // Commits bytes to the final slice address. The default backend writes
  // directly; a sealed ghost pool overrides this and writes through its KPM
  // alias so existing trampolines never become writable in EL0.
  [[nodiscard]] virtual Status Write(void* slice, const void* bytes,
                                     std::size_t size);
  [[nodiscard]] virtual Status Free(void* slice) = 0;
  [[nodiscard]] virtual Status Finalize(void* slice) { return Status::Ok(); }
};

class CodeAllocator final : public SliceAllocator {
 public:
  explicit CodeAllocator(std::size_t slice_size);
  ~CodeAllocator() override;

  CodeAllocator(const CodeAllocator&) = delete;
  CodeAllocator& operator=(const CodeAllocator&) = delete;

  [[nodiscard]] Result<void*> Allocate(
      const AllocationSpec& spec = {}, std::size_t alignment = 1);
  [[nodiscard]] Status Free(void* slice) override;

  // SliceAllocator view: ignores the AllocationSpec.
  [[nodiscard]] Result<void*> Allocate(std::size_t slice_size) override;

  // Applies W^X to every page and flushes the instruction cache. No further
  // allocations are accepted after sealing.
  [[nodiscard]] Status Seal();

  [[nodiscard]] std::size_t page_size() const noexcept { return page_size_; }
  [[nodiscard]] std::size_t slice_size() const noexcept { return slice_size_; }

 private:
  [[nodiscard]] Result<void*> AllocatePage(const AllocationSpec& spec);
  [[nodiscard]] bool IsNear(void* slice, const AllocationSpec& spec) const;
  void ReleasePages() noexcept;

  std::size_t page_size_ = 0;
  std::size_t slice_size_ = 0;
  std::size_t slices_per_page_ = 0;
  bool sealed_ = false;
  std::vector<void*> pages_;
  std::vector<void*> free_;
  std::mutex mutex_;
};

}  // namespace art_hook
