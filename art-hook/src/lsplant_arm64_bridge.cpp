// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/lsplant_arm64_bridge.h"

#include <cstring>
#include <mutex>
#include <unordered_map>

namespace art_hook {
namespace {

constexpr std::uint32_t kLsplantLoadMethod = 0x58000060U;
constexpr std::uint32_t kLoadEntrypointBase = 0xf8400010U;
constexpr std::uint32_t kLoadEntrypointMask = 0xffe00fffU;
constexpr std::uint32_t kBranchEntrypoint = 0xd61f0200U;

constexpr std::uint32_t kLoadAlignedMethod = 0x58000080U;
constexpr std::uint32_t kNop = 0xd503201fU;
constexpr std::size_t kLsplantRequestSize = 20U;
constexpr std::size_t kBridgeSize = 24U;
constexpr std::size_t kBridgeSliceSize = 32U;
constexpr std::size_t kMaxLdurOffset = 0xffU;

std::mutex& PoolMutex() {
  static std::mutex mutex;
  return mutex;
}

std::unordered_map<void*, std::unique_ptr<LsplantArm64Bridge>>& Bridges() {
  static std::unordered_map<void*, std::unique_ptr<LsplantArm64Bridge>> bridges;
  return bridges;
}

template <typename T>
T ReadUnaligned(const std::uint8_t* data) noexcept {
  T value{};
  std::memcpy(&value, data, sizeof(value));
  return value;
}

}  // namespace

Result<LsplantArm64BridgeRequest> DecodeLsplantArm64BridgeRequest(
    std::span<const std::uint8_t> request) {
  if (request.size() != kLsplantRequestSize) {
    return Status(StatusCode::kInvalidArgument,
                  "unexpected LSPlant AArch64 trampoline size");
  }
  if constexpr (sizeof(void*) != sizeof(std::uint64_t)) {
    return Status(StatusCode::kUnsupported,
                  "LSPlant AArch64 bridge requires 64-bit pointers");
  }

  const std::uint32_t load_method =
      ReadUnaligned<std::uint32_t>(request.data());
  const std::uint32_t load_entrypoint =
      ReadUnaligned<std::uint32_t>(request.data() + sizeof(std::uint32_t));
  const std::uint32_t branch =
      ReadUnaligned<std::uint32_t>(request.data() + 2U * sizeof(std::uint32_t));
  if (load_method != kLsplantLoadMethod ||
      (load_entrypoint & kLoadEntrypointMask) != kLoadEntrypointBase ||
      branch != kBranchEntrypoint) {
    return Status(StatusCode::kUnsupported,
                  "LSPlant AArch64 trampoline template changed");
  }

  const std::uintptr_t method_address =
      ReadUnaligned<std::uintptr_t>(request.data() + 3U * sizeof(std::uint32_t));
  if (method_address == 0U) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant replacement ArtMethod is null");
  }

  const std::size_t immediate =
      static_cast<std::size_t>((load_entrypoint >> 12U) & 0x1ffU);
  if (immediate > kMaxLdurOffset) {
    return Status(StatusCode::kUnsupported,
                  "LSPlant AArch64 trampoline has a negative LDUR offset");
  }
  return LsplantArm64BridgeRequest{reinterpret_cast<void*>(method_address),
                                   immediate};
}

Result<std::unique_ptr<LsplantArm64Bridge>> LsplantArm64Bridge::Create(
    const LsplantArm64BridgeRequest& request) {
  if (request.art_method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "replacement ArtMethod is null");
  }
  if (request.entrypoint_offset > kMaxLdurOffset) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod entrypoint offset cannot be encoded");
  }

  std::vector<std::uint32_t> words{
      kLoadAlignedMethod,
      kLoadEntrypointBase |
          (static_cast<std::uint32_t>(request.entrypoint_offset) << 12U),
      kBranchEntrypoint,
      kNop,
  };
  auto allocator = std::make_unique<CodeAllocator>(kBridgeSliceSize);
  auto allocation = allocator->Allocate({}, 16U);
  if (!allocation.ok()) {
    return allocation.status();
  }
  auto* code = static_cast<std::uint8_t*>(allocation.value());
  std::memcpy(code, words.data(), words.size() * sizeof(std::uint32_t));
  const std::uintptr_t method_address =
      reinterpret_cast<std::uintptr_t>(request.art_method);
  std::memcpy(code + words.size() * sizeof(std::uint32_t), &method_address,
              sizeof(method_address));

  Status sealed = allocator->Seal();
  if (!sealed.ok()) {
    return sealed;
  }
  return std::unique_ptr<LsplantArm64Bridge>(new LsplantArm64Bridge(
      std::move(allocator), code, kBridgeSize, std::move(words)));
}

Result<std::unique_ptr<LsplantArm64Bridge>>
LsplantArm64Bridge::CreateFromLsplantRequest(
    std::span<const std::uint8_t> request) {
  auto decoded = DecodeLsplantArm64BridgeRequest(request);
  if (!decoded.ok()) {
    return decoded.status();
  }
  return Create(decoded.value());
}

void* LsplantArm64BridgePool::Allocate(
    std::span<const std::uint8_t> request) noexcept {
  try {
    auto bridge = LsplantArm64Bridge::CreateFromLsplantRequest(request);
    if (!bridge.ok()) {
      return nullptr;
    }
    void* entrypoint = bridge.value()->entrypoint();
    std::lock_guard lock(PoolMutex());
    auto [iterator, inserted] =
        Bridges().emplace(entrypoint, std::move(bridge.value()));
    return inserted ? iterator->first : nullptr;
  } catch (...) {
    return nullptr;
  }
}

void LsplantArm64BridgePool::Recycle(void* memory) noexcept {
  if (memory == nullptr) {
    return;
  }
  std::lock_guard lock(PoolMutex());
  Bridges().erase(memory);
}

std::size_t LsplantArm64BridgePool::live_count() noexcept {
  std::lock_guard lock(PoolMutex());
  return Bridges().size();
}

}  // namespace art_hook
