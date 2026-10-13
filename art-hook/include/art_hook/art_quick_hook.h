// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "art_hook/arm64_trampoline.h"
#include "art_hook/art_method.h"
#include "art_hook/status.h"

namespace art_hook {

struct ArtQuickHookOptions final {
  std::optional<std::uint32_t> access_flags;
  std::optional<void *> jni_code;
  std::optional<void *> interpreter_code;
};

// Owns an ARM64 dispatch trampoline and the transaction that redirects an
// ArtMethod quick entrypoint to it. The mutation gate is shared so destruction
// can make a best-effort rollback without leaving a dangling code pointer.
class ArtQuickHook final {
public:
  ~ArtQuickHook() noexcept;

  ArtQuickHook(const ArtQuickHook &) = delete;
  ArtQuickHook &operator=(const ArtQuickHook &) = delete;
  ArtQuickHook(ArtQuickHook &&) = delete;
  ArtQuickHook &operator=(ArtQuickHook &&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<ArtQuickHook>>
  Create(void *method, ArtMethodLayout layout, Arm64Dispatch dispatch,
         void *user_data, std::shared_ptr<ArtMutationGate> gate,
         const ArtQuickHookOptions &options = {});

  [[nodiscard]] Status Activate();
  [[nodiscard]] Status Deactivate();

  [[nodiscard]] bool active() const noexcept { return patch_.applied(); }
  [[nodiscard]] void *trampoline_entrypoint() const noexcept {
    return trampoline_->entrypoint();
  }
  [[nodiscard]] void *original_quick_code() const noexcept {
    return original_.quick_code;
  }
  [[nodiscard]] const ArtMethodState &original_state() const noexcept {
    return original_;
  }

private:
  ArtQuickHook(std::unique_ptr<Arm64Trampoline> trampoline,
               ArtMethodPatch patch, ArtMethodState original,
               std::shared_ptr<ArtMutationGate> gate)
      : trampoline_(std::move(trampoline)), patch_(std::move(patch)),
        original_(std::move(original)), gate_(std::move(gate)) {}

  std::unique_ptr<Arm64Trampoline> trampoline_;
  ArtMethodPatch patch_;
  ArtMethodState original_;
  std::shared_ptr<ArtMutationGate> gate_;
};

// One-step equivalent of hook_method_safe: create the trampoline and commit
// the ArtMethod mutation through the supplied STW gate before returning.
[[nodiscard]] Result<std::unique_ptr<ArtQuickHook>>
HookMethodSafe(void *method, ArtMethodLayout layout, Arm64Dispatch dispatch,
               void *user_data, std::shared_ptr<ArtMutationGate> gate,
               const ArtQuickHookOptions &options = {});

} // namespace art_hook
