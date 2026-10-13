// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "art_hook/status.h"
#include "art_hook/vm.h"

namespace art_hook {

struct LsplantBackendConfig final {
  using InlineHooker = std::function<void*(void* target, void* replacement)>;
  using InlineUnhooker = std::function<bool(void* target)>;
  using ArtSymbolResolver =
      std::function<void*(std::string_view symbol_name)>;

  InlineHooker inline_hooker;
  InlineUnhooker inline_unhooker;
  ArtSymbolResolver art_symbol_resolver;
  ArtSymbolResolver art_symbol_prefix_resolver;

  std::string generated_class_name = "ArtHooker_";
  std::string generated_source_name = "art-hook";
  std::string generated_field_name = "callback";
  std::string generated_method_name = "{target}";

  // On ARM64, rebuild LSPlant's ArtMethod bridge with art-hook's own encoder
  // and W^X allocator. Other architectures must leave this disabled.
  bool use_custom_arm64_bridge = true;

  [[nodiscard]] Status Validate() const;
};

class LsplantHook final {
 public:
  ~LsplantHook() noexcept;

  LsplantHook(const LsplantHook&) = delete;
  LsplantHook& operator=(const LsplantHook&) = delete;
  LsplantHook(LsplantHook&&) = delete;
  LsplantHook& operator=(LsplantHook&&) = delete;

  [[nodiscard]] Status Unhook();
  [[nodiscard]] bool active() const noexcept { return active_; }
  [[nodiscard]] jobject target_method() const noexcept { return target_method_; }
  [[nodiscard]] jobject backup_method() const noexcept { return backup_method_; }

 private:
  friend class LsplantBackend;

  LsplantHook(Vm vm, jobject target_method, jobject backup_method)
      : vm_(vm), target_method_(target_method), backup_method_(backup_method) {}

  void ReleaseReferences(JNIEnv* env) noexcept;

  Vm vm_;
  jobject target_method_ = nullptr;
  jobject backup_method_ = nullptr;
  bool active_ = true;
};

// Native facade over LSPlant. LSPlant owns ART-version adaptation and method
// backup/deoptimization; callers still provide the inline hook and complete
// libart symbol-resolution backends required by LSPlant itself.
class LsplantBackend final {
 public:
  LsplantBackend(const LsplantBackend&) = delete;
  LsplantBackend& operator=(const LsplantBackend&) = delete;
  LsplantBackend(LsplantBackend&&) = delete;
  LsplantBackend& operator=(LsplantBackend&&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<LsplantBackend>> Create(
      Vm vm, Env env, const LsplantBackendConfig& config);

  [[nodiscard]] Result<std::unique_ptr<LsplantHook>> Hook(
      Env env, jobject target_method, jobject hooker_object,
      jobject callback_method) const;
  [[nodiscard]] Result<bool> IsHooked(Env env, jobject target_method) const;
  [[nodiscard]] Status Deoptimize(Env env, jobject method) const;
  [[nodiscard]] Result<void*> GetNativeFunction(Env env, jobject method) const;
  [[nodiscard]] Status MakeClassInheritable(Env env, jclass klass) const;

 private:
  explicit LsplantBackend(Vm vm) : vm_(vm) {}

  Vm vm_;
};

}  // namespace art_hook
