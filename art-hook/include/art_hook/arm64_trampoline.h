// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "art_hook/code_allocator.h"
#include "art_hook/status.h"

namespace art_hook {

struct alignas(16) Arm64VectorRegister final {
  std::uint64_t low = 0;
  std::uint64_t high = 0;
};

// Stack-backed context passed to the C++ dispatch function. General and SIMD
// registers plus NZCV/FPCR/FPSR may be changed by dispatch. sp and x16 are
// inspection-only: the generated epilogue restores its own stack frame and
// uses x16 as the final branch scratch register. SVE/SME state is not captured.
struct alignas(16) Arm64CpuContext final {
  std::array<std::uint64_t, 31> x{};
  std::uint64_t sp = 0;
  std::uint64_t nzcv = 0;
  std::uint64_t fpcr = 0;
  std::uint64_t fpsr = 0;
  std::uint64_t reserved = 0;
  std::array<Arm64VectorRegister, 32> q{};
  std::uint64_t next_pc = 0;
  std::uint64_t user_data = 0;
};

static_assert(alignof(Arm64CpuContext) == 16,
              "ARM64 context must preserve SP alignment");
static_assert(offsetof(Arm64CpuContext, x) == 0);
static_assert(offsetof(Arm64CpuContext, sp) == 248);
static_assert(offsetof(Arm64CpuContext, nzcv) == 256);
static_assert(offsetof(Arm64CpuContext, q) == 288);
static_assert(offsetof(Arm64CpuContext, next_pc) == 800);
static_assert(offsetof(Arm64CpuContext, user_data) == 808);
static_assert(sizeof(Arm64CpuContext) == 816,
              "ARM64 context ABI changed unexpectedly");

// Return nullptr to restore the context and return through its saved x30.
// Return a code address to restore the context and tail-branch to that address.
// The function must not allow an exception to cross the trampoline boundary.
using Arm64Dispatch = void *(*)(Arm64CpuContext *context,
                                void *user_data) noexcept;

class Arm64Trampoline final {
public:
  ~Arm64Trampoline() = default;

  Arm64Trampoline(const Arm64Trampoline &) = delete;
  Arm64Trampoline &operator=(const Arm64Trampoline &) = delete;
  Arm64Trampoline(Arm64Trampoline &&) = delete;
  Arm64Trampoline &operator=(Arm64Trampoline &&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<Arm64Trampoline>>
  Create(Arm64Dispatch dispatch, void *user_data = nullptr);

  // Variant that places the trampoline in a caller-supplied slice allocator
  // (e.g. the Mako ghost jump pool). The allocator must hand out executable
  // (or to-be-sealed) slices of at least slice_size bytes.
  [[nodiscard]] static Result<std::unique_ptr<Arm64Trampoline>>
  Create(Arm64Dispatch dispatch, void *user_data, SliceAllocator &allocator);

  [[nodiscard]] void *entrypoint() const noexcept { return entrypoint_; }
  [[nodiscard]] std::size_t code_size() const noexcept {
    return words_.size() * sizeof(std::uint32_t);
  }
  [[nodiscard]] const std::vector<std::uint32_t> &words() const noexcept {
    return words_;
  }

private:
  Arm64Trampoline(std::unique_ptr<CodeAllocator> allocator, void *entrypoint,
                  std::vector<std::uint32_t> words)
      : allocator_(std::move(allocator)), entrypoint_(entrypoint),
        words_(std::move(words)) {}

  std::unique_ptr<CodeAllocator> allocator_;
  void *entrypoint_ = nullptr;
  std::vector<std::uint32_t> words_;
};

} // namespace art_hook
