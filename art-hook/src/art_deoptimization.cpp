// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/art_deoptimization.h"

#include <exception>

namespace art_hook {

Status ArtAlreadyRunnableGate::Run(const Operation &operation) noexcept {
  if (!operation) {
    return Status(StatusCode::kInvalidArgument,
                  "ART runnable operation is empty");
  }
  try {
    return operation();
  } catch (const std::exception &error) {
    return Status(StatusCode::kPlatformError,
                  std::string("ART runnable operation threw: ") + error.what());
  } catch (...) {
    return Status(StatusCode::kPlatformError,
                  "ART runnable operation threw an unknown exception");
  }
}

Result<std::unique_ptr<ArtDeoptimizer>>
ArtDeoptimizer::Create(ArtDeoptimizationApi api,
                       std::shared_ptr<ArtRunnableGate> gate) {
  if (api.android_api_level < 21) {
    return Status(StatusCode::kUnsupported,
                  "ART deoptimization requires Android 5.0 or newer");
  }
  if (gate == nullptr) {
    return Status(StatusCode::kInvalidArgument, "ART runnable gate is null");
  }
  return std::unique_ptr<ArtDeoptimizer>(
      new ArtDeoptimizer(std::move(api), std::move(gate)));
}

Status ArtDeoptimizer::EnsureInstrumentationEnabled() {
  if (api_.instrumentation == nullptr ||
      api_.is_deoptimization_enabled == nullptr ||
      api_.enable_deoptimization == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "ART Instrumentation deoptimization backend is incomplete");
  }
  if (!api_.is_deoptimization_enabled(api_.instrumentation)) {
    api_.enable_deoptimization(api_.instrumentation);
    if (!api_.is_deoptimization_enabled(api_.instrumentation)) {
      return Status(StatusCode::kPlatformError,
                    "ART deoptimization did not become enabled");
    }
  }
  return Status::Ok();
}

Status ArtDeoptimizer::DeoptimizeMethod(void *method) {
  if (method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod to deoptimize is null");
  }
  if (api_.android_api_level < 24) {
    return Status(StatusCode::kUnsupported,
                  "selective ART deoptimization requires Android 7.0+");
  }
  if (api_.android_api_level < 30) {
    return RunLegacy(ArtLegacyDeoptimizationKind::kSelective, method);
  }
  if (api_.deoptimize_method == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "Instrumentation::Deoptimize wrapper is unavailable");
  }
  return gate_->Run([this, method] {
    Status enabled = EnsureInstrumentationEnabled();
    if (!enabled.ok()) {
      return enabled;
    }
    api_.deoptimize_method(api_.instrumentation, method);
    return Status::Ok();
  });
}

Status ArtDeoptimizer::DeoptimizeEverything(const std::string &reason) {
  if (api_.android_api_level < 24) {
    return Status(StatusCode::kUnsupported,
                  "full ART deoptimization requires Android 7.0+");
  }
  if (api_.android_api_level < 30) {
    return RunLegacy(ArtLegacyDeoptimizationKind::kFull, nullptr);
  }
  if (reason.empty()) {
    return Status(StatusCode::kInvalidArgument,
                  "deoptimization reason is empty");
  }
  if (api_.deoptimize_everything == nullptr) {
    return Status(
        StatusCode::kUnavailable,
        "Instrumentation::DeoptimizeEverything wrapper is unavailable");
  }
  return gate_->Run([this, &reason] {
    Status enabled = EnsureInstrumentationEnabled();
    if (!enabled.ok()) {
      return enabled;
    }
    api_.deoptimize_everything(api_.instrumentation, reason.c_str());
    return Status::Ok();
  });
}

Status ArtDeoptimizer::DeoptimizeBootImage() {
  if (api_.android_api_level < 26) {
    return Status(StatusCode::kUnsupported,
                  "boot-image deoptimization requires Android 8.0+");
  }
  if (api_.runtime == nullptr || api_.deoptimize_boot_image == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "Runtime::DeoptimizeBootImage wrapper is unavailable");
  }
  return gate_->Run([this] {
    api_.deoptimize_boot_image(api_.runtime);
    return Status::Ok();
  });
}

Status ArtDeoptimizer::RunLegacy(ArtLegacyDeoptimizationKind kind,
                                 void *method) {
  if (api_.prepare_legacy_debugger == nullptr ||
      api_.legacy_request == nullptr || api_.legacy_manage == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "legacy JDWP deoptimization backend is incomplete");
  }
  return gate_->Run([this, kind, method] {
    Status prepared = api_.prepare_legacy_debugger(api_.legacy_user_data);
    if (!prepared.ok()) {
      return prepared;
    }
    ArtLegacyDeoptimizationRequest request;
    request.kind = static_cast<std::uint32_t>(kind);
    request.method = method;
    api_.legacy_request(&request);
    api_.legacy_manage();
    return Status::Ok();
  });
}

} // namespace art_hook
