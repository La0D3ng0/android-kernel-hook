// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "art_hook/status.h"

namespace art_hook {

constexpr jint kJvmtiVersion1_0 = static_cast<jint>(0x30010000U);
constexpr jint kJvmtiVersion1_2 = static_cast<jint>(0x30010200U);

// Android's public NDK omits jvmti.h. This wrapper deliberately exposes only
// the four operations used by jvmti.js and treats the environment as opaque.
class JvmtiEnv final {
 public:
  explicit JvmtiEnv(void* handle) : handle_(handle) {}

  [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] Status Deallocate(void* memory) const;
  [[nodiscard]] Result<std::pair<jint, jclass*>> GetLoadedClasses() const;
  [[nodiscard]] Status IterateOverInstancesOfClass(
      jclass klass, jint object_filter, void* heap_object_callback,
      const void* user_data) const;
  [[nodiscard]] Status GetObjectsWithTags(
      jint tag_count, const std::int64_t* tags, jint* count,
      jobject** objects, std::int64_t** result_tags) const;
  [[nodiscard]] Status AddCanTagObjectsCapability() const;

 private:
  [[nodiscard]] void* FunctionAt(std::size_t one_based_offset) const;

  void* handle_ = nullptr;
};

}  // namespace art_hook
