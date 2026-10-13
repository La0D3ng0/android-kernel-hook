// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "art_hook/status.h"

namespace art_hook {

class ArtRunnableGate {
public:
  using Operation = std::function<Status()>;

  virtual ~ArtRunnableGate() = default;
  [[nodiscard]] virtual Status Run(const Operation &operation) noexcept = 0;
};

// Use only when the caller has already entered an ART Runnable state and holds
// the mutator lock shared. It provides exception containment, not a state
// transition.
class ArtAlreadyRunnableGate final : public ArtRunnableGate {
public:
  [[nodiscard]] Status Run(const Operation &operation) noexcept override;
};

enum class ArtLegacyDeoptimizationKind : std::uint32_t {
  kFull = 3,
  kSelective = 5,
};

struct alignas(void *) ArtLegacyDeoptimizationRequest final {
  std::uint32_t kind = 0;
  std::uint32_t padding = 0;
  void *method = nullptr;
};

static_assert(offsetof(ArtLegacyDeoptimizationRequest, method) == 8U);

// All callbacks are version-correct wrappers supplied by the embedding layer.
// In particular, this library does not cast private ART symbols to guessed
// signatures and does not infer Instrumentation/Runtime object offsets.
struct ArtDeoptimizationApi final {
  using IsDeoptimizationEnabled = bool (*)(void *instrumentation) noexcept;
  using EnableDeoptimization = void (*)(void *instrumentation);
  using DeoptimizeMethod = void (*)(void *instrumentation, void *method);
  using DeoptimizeEverything = void (*)(void *instrumentation,
                                        const char *reason);
  using DeoptimizeBootImage = void (*)(void *runtime);
  using PrepareLegacyDebugger = Status (*)(void *user_data) noexcept;
  using LegacyRequest = void (*)(const ArtLegacyDeoptimizationRequest *request);
  using LegacyManage = void (*)();

  int android_api_level = 0;
  void *instrumentation = nullptr;
  void *runtime = nullptr;

  IsDeoptimizationEnabled is_deoptimization_enabled = nullptr;
  EnableDeoptimization enable_deoptimization = nullptr;
  DeoptimizeMethod deoptimize_method = nullptr;
  DeoptimizeEverything deoptimize_everything = nullptr;
  DeoptimizeBootImage deoptimize_boot_image = nullptr;

  PrepareLegacyDebugger prepare_legacy_debugger = nullptr;
  void *legacy_user_data = nullptr;
  LegacyRequest legacy_request = nullptr;
  LegacyManage legacy_manage = nullptr;
};

class ArtDeoptimizer final {
public:
  [[nodiscard]] static Result<std::unique_ptr<ArtDeoptimizer>>
  Create(ArtDeoptimizationApi api, std::shared_ptr<ArtRunnableGate> gate);

  [[nodiscard]] Status DeoptimizeMethod(void *method);
  [[nodiscard]] Status
  DeoptimizeEverything(const std::string &reason = "art-hook");
  [[nodiscard]] Status DeoptimizeBootImage();

  [[nodiscard]] int android_api_level() const noexcept {
    return api_.android_api_level;
  }

private:
  ArtDeoptimizer(ArtDeoptimizationApi api,
                 std::shared_ptr<ArtRunnableGate> gate)
      : api_(std::move(api)), gate_(std::move(gate)) {}

  [[nodiscard]] Status EnsureInstrumentationEnabled();
  [[nodiscard]] Status RunLegacy(ArtLegacyDeoptimizationKind kind,
                                 void *method);

  ArtDeoptimizationApi api_;
  std::shared_ptr<ArtRunnableGate> gate_;
};

} // namespace art_hook
