// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include "art_hook/code_allocator.h"
#include "art_hook/status.h"

namespace art_hook {

struct LsplantArm64BridgeRequest final {
  void* art_method = nullptr;
  std::size_t entrypoint_offset = 0;
};

// Decodes the pinned LSPlant AArch64 bridge request. The request is validated
// before any executable memory is allocated so an upstream template change
// fails closed instead of producing malformed code.
[[nodiscard]] Result<LsplantArm64BridgeRequest>
DecodeLsplantArm64BridgeRequest(std::span<const std::uint8_t> request);

// Own implementation of LSPlant's ArtMethod-to-ArtMethod bridge. This bridge
// only changes x0 to the replacement ArtMethod and tail-branches to its quick
// entrypoint. Callback context capture remains the responsibility of the
// separate Arm64Trampoline class.
class LsplantArm64Bridge final {
 public:
  ~LsplantArm64Bridge() = default;

  LsplantArm64Bridge(const LsplantArm64Bridge&) = delete;
  LsplantArm64Bridge& operator=(const LsplantArm64Bridge&) = delete;
  LsplantArm64Bridge(LsplantArm64Bridge&&) = delete;
  LsplantArm64Bridge& operator=(LsplantArm64Bridge&&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<LsplantArm64Bridge>> Create(
      const LsplantArm64BridgeRequest& request);
  [[nodiscard]] static Result<std::unique_ptr<LsplantArm64Bridge>>
  CreateFromLsplantRequest(std::span<const std::uint8_t> request);

  [[nodiscard]] void* entrypoint() const noexcept { return entrypoint_; }
  [[nodiscard]] std::size_t code_size() const noexcept { return code_size_; }
  [[nodiscard]] const std::vector<std::uint32_t>& words() const noexcept {
    return words_;
  }

 private:
  LsplantArm64Bridge(std::unique_ptr<CodeAllocator> allocator,
                     void* entrypoint, std::size_t code_size,
                     std::vector<std::uint32_t> words)
      : allocator_(std::move(allocator)), entrypoint_(entrypoint),
        code_size_(code_size), words_(std::move(words)) {}

  std::unique_ptr<CodeAllocator> allocator_;
  void* entrypoint_ = nullptr;
  std::size_t code_size_ = 0;
  std::vector<std::uint32_t> words_;
};

// Captureless callbacks suitable for lsplant::InitInfo. The pool owns every
// generated bridge until LSPlant calls Recycle after unhooking.
class LsplantArm64BridgePool final {
 public:
  [[nodiscard]] static void* Allocate(
      std::span<const std::uint8_t> request) noexcept;
  static void Recycle(void* memory) noexcept;
  [[nodiscard]] static std::size_t live_count() noexcept;
};

}  // namespace art_hook
