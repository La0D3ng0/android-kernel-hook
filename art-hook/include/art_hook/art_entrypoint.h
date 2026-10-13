// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "art_hook/arm64_trampoline.h"
#include "art_hook/art_method.h"
#include "art_hook/art_quick_hook.h"
#include "art_hook/status.h"
#include "art_hook/vm.h"

namespace art_hook {

class ArtDeoptimizer;

using ArtInvocationCallback = void (*)(Arm64CpuContext *context,
                                       void *user_data) noexcept;

struct ArtMethodCallbacks final {
  ArtInvocationCallback on_enter = nullptr;
  ArtInvocationCallback on_leave = nullptr;
  void *user_data = nullptr;
};

struct ArtMethodSelector final {
  std::string class_name;
  std::string method_name;
  std::string descriptor;
  bool is_static = false;
};

using ArtMethodIdDecoder = void *(*)(jmethodID method_id,
                                     void *user_data) noexcept;

struct ResolvedArtMethod final {
  jmethodID method_id = nullptr;
  void *method = nullptr;
};

// Resolves a Java method and delegates conversion of potentially opaque JNI
// method IDs to a caller-supplied, runtime-versioned decoder.
[[nodiscard]] Result<ResolvedArtMethod>
ResolveArtMethod(Env env, const ArtMethodSelector &selector,
                 ArtMethodIdDecoder decoder, void *decoder_user_data = nullptr);

// Explicit decoder for runtimes where the embedding layer has verified that a
// jmethodID is the ArtMethod address. Do not use this as an API-level guess.
[[nodiscard]] void *DirectArtMethodIdDecoder(jmethodID method_id,
                                             void *user_data) noexcept;

// Provides paired raw ARM64 on-enter/on-leave callbacks around an ArtMethod's
// current quick entrypoint. The callback sees the native quick ABI register
// context; Java descriptor marshalling belongs to a higher typed layer.
class ArtMethodInterceptor final {
public:
  ~ArtMethodInterceptor() noexcept;

  ArtMethodInterceptor(const ArtMethodInterceptor &) = delete;
  ArtMethodInterceptor &operator=(const ArtMethodInterceptor &) = delete;
  ArtMethodInterceptor(ArtMethodInterceptor &&) = delete;
  ArtMethodInterceptor &operator=(ArtMethodInterceptor &&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<ArtMethodInterceptor>>
  Create(void *method, ArtMethodLayout layout, ArtMethodCallbacks callbacks,
         std::shared_ptr<ArtMutationGate> mutation_gate,
         ArtQuickHookOptions options = {});

  // Activate(deoptimizer) deliberately deoptimizes first, then snapshots and
  // replaces the resulting quick entrypoint. Reversing this order would let
  // deoptimization overwrite the newly installed trampoline.
  [[nodiscard]] Status Activate();
  [[nodiscard]] Status Activate(ArtDeoptimizer &deoptimizer);
  [[nodiscard]] Status Deactivate();

  [[nodiscard]] bool active() const noexcept;
  [[nodiscard]] std::size_t in_flight() const noexcept;
  [[nodiscard]] void *original_quick_code() const noexcept;
  [[nodiscard]] void *entrypoint() const noexcept;

private:
  struct State;

  ArtMethodInterceptor(void *method, ArtMethodLayout layout,
                       ArtQuickHookOptions options,
                       std::shared_ptr<ArtMutationGate> mutation_gate,
                       std::unique_ptr<State> state,
                       std::unique_ptr<Arm64Trampoline> leave_trampoline);

  [[nodiscard]] Status ActivateAfterDeoptimization();
  static void *EnterDispatch(Arm64CpuContext *context,
                             void *user_data) noexcept;
  static void *LeaveDispatch(Arm64CpuContext *context,
                             void *user_data) noexcept;

  void *method_ = nullptr;
  ArtMethodLayout layout_;
  ArtQuickHookOptions options_;
  std::shared_ptr<ArtMutationGate> mutation_gate_;
  std::unique_ptr<State> state_;
  std::unique_ptr<Arm64Trampoline> leave_trampoline_;
  std::unique_ptr<ArtQuickHook> entry_hook_;
  bool ever_activated_ = false;
};

} // namespace art_hook
