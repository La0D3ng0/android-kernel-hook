// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <mutex>
#include <vector>

#include "art_hook/code_allocator.h"
#include "art_hook/mako_host.h"

namespace art_hook {

// VMA-less trampoline pool for the Mako ghost module. Pages come from the
// host's ghost_alloc(RWX) (ghostMalloc): no maps entry, no link_map record,
// nothing a scanner enumerating /proc/self/maps can attribute. Each page is
// sliced into fixed 512-byte slots (8 per page), sized for the current
// 448-byte full-context ARM64 trampoline. A 256-byte slot would overflow this
// emitter, so capacity is checked and a whole page is used for larger slices.
// Freed slices are
// retired for process lifetime because a thread suspended inside a trampoline
// may resume after unhook.
class GhostJumpPool final : public SliceAllocator {
 public:
  explicit GhostJumpPool(const MakoHostApi *host) : host_(host) {}
  ~GhostJumpPool() override;

  GhostJumpPool(const GhostJumpPool &) = delete;
  GhostJumpPool &operator=(const GhostJumpPool &) = delete;

  [[nodiscard]] Result<void *> Allocate(std::size_t slice_size) override;
  [[nodiscard]] Status Write(void *slice, const void *bytes,
                             std::size_t size) override;
  [[nodiscard]] Status Free(void *slice) override;
  [[nodiscard]] Status Finalize(void *slice) override;

 private:
  struct PoolPage final {
    void *base = nullptr;
    std::size_t slice_size = 0;
    unsigned int used_mask = 0;  // bit per slot
    unsigned int slot_count = 0;
    bool needs_protect = false;  // RW page awaiting the RX switch
  };

  const MakoHostApi *host_ = nullptr;
  std::vector<PoolPage> pages_;
  std::mutex mutex_;
};

}  // namespace art_hook
