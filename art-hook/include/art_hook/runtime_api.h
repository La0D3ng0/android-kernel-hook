// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>

#include <string>

#include "art_hook/jvmti.h"
#include "art_hook/status.h"
#include "art_hook/vm.h"

namespace art_hook {

enum class RuntimeFlavor { kArt, kDalvik, kHotSpot, kUnknown };

struct RuntimeInfo final {
  RuntimeFlavor flavor = RuntimeFlavor::kUnknown;
  int android_api_level = 0;
  std::string android_release;
  std::string architecture;
  bool has_java_vm = false;
  bool has_jvmti = false;
  bool has_libart = false;
};

class RuntimeApi final {
 public:
  RuntimeApi() = default;
  ~RuntimeApi();

  RuntimeApi(const RuntimeApi&) = delete;
  RuntimeApi& operator=(const RuntimeApi&) = delete;
  RuntimeApi(RuntimeApi&& other) noexcept;
  RuntimeApi& operator=(RuntimeApi&& other) noexcept;

  [[nodiscard]] static Result<RuntimeApi> Discover(JavaVM* known_vm = nullptr);

  [[nodiscard]] const RuntimeInfo& info() const noexcept { return info_; }
  [[nodiscard]] Vm vm() const noexcept { return Vm(vm_); }
  [[nodiscard]] JvmtiEnv jvmti() const noexcept { return JvmtiEnv(jvmti_); }
  [[nodiscard]] void* FindArtSymbol(const char* name) const noexcept;

  // ART private-ABI mutation is intentionally not treated as available merely
  // because libart is loaded. A versioned backend must pass its own probes.
  [[nodiscard]] Status RequireArtMutationBackend() const;

 private:
  RuntimeInfo info_;
  JavaVM* vm_ = nullptr;
  void* jvmti_ = nullptr;
  void* libart_ = nullptr;
};

[[nodiscard]] const char* RuntimeFlavorName(RuntimeFlavor flavor) noexcept;

}  // namespace art_hook
