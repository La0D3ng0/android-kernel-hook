// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>

#include <string>
#include <vector>

#include "art_hook/status.h"
#include "art_hook/vm.h"

namespace art_hook {

struct NativeMethod final {
  std::string name;
  std::string signature;
  void* function = nullptr;
};

class ClassFactory final {
 public:
  explicit ClassFactory(Env env) : env_(env) {}

  [[nodiscard]] Result<LocalRef<jclass>> Use(
      std::string class_name) const;
  [[nodiscard]] Status RegisterNatives(
      jclass klass, const std::vector<NativeMethod>& methods) const;
  [[nodiscard]] Result<LocalRef<jobject>> LoadDex(
      const std::vector<std::uint8_t>& dex, jobject parent_loader = nullptr) const;
  [[nodiscard]] Result<LocalRef<jclass>> LoadClass(
      jobject loader, std::string class_name) const;

 private:
  Env env_;
};

}  // namespace art_hook
