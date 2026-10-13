// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/jvmti.h"

#include <array>
#include <utility>

namespace art_hook {
namespace {

Status CheckJvmtiResult(const char* operation, jint result) {
  if (result == 0) {
    return Status::Ok();
  }
  return Status(StatusCode::kJniError,
                std::string(operation) + " failed: " +
                    std::to_string(result));
}

}  // namespace

void* JvmtiEnv::FunctionAt(std::size_t one_based_offset) const {
  if (handle_ == nullptr || one_based_offset == 0) {
    return nullptr;
  }
  auto*** environment = reinterpret_cast<void***>(handle_);
  if (*environment == nullptr) {
    return nullptr;
  }
  return (*environment)[one_based_offset - 1];
}

Status JvmtiEnv::Deallocate(void* memory) const {
  using Function = jint (*)(void*, unsigned char*);
  auto function = reinterpret_cast<Function>(FunctionAt(47));
  if (function == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "JVMTI Deallocate is unavailable");
  }
  return CheckJvmtiResult(
      "JVMTI::Deallocate",
      function(handle_, static_cast<unsigned char*>(memory)));
}

Result<std::pair<jint, jclass*>> JvmtiEnv::GetLoadedClasses() const {
  using Function = jint (*)(void*, jint*, jclass**);
  auto function = reinterpret_cast<Function>(FunctionAt(78));
  if (function == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "JVMTI GetLoadedClasses is unavailable");
  }
  jint count = 0;
  jclass* classes = nullptr;
  const jint result = function(handle_, &count, &classes);
  Status status = CheckJvmtiResult("JVMTI::GetLoadedClasses", result);
  if (!status.ok()) {
    return status;
  }
  return std::make_pair(count, classes);
}

Status JvmtiEnv::IterateOverInstancesOfClass(
    jclass klass, jint object_filter, void* heap_object_callback,
    const void* user_data) const {
  using Function = jint (*)(void*, jclass, jint, void*, const void*);
  auto function = reinterpret_cast<Function>(FunctionAt(112));
  if (function == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "JVMTI IterateOverInstancesOfClass is unavailable");
  }
  return CheckJvmtiResult(
      "JVMTI::IterateOverInstancesOfClass",
      function(handle_, klass, object_filter, heap_object_callback, user_data));
}

Status JvmtiEnv::GetObjectsWithTags(
    jint tag_count, const std::int64_t* tags, jint* count,
    jobject** objects, std::int64_t** result_tags) const {
  using Function = jint (*)(void*, jint, const std::int64_t*, jint*,
                            jobject**, std::int64_t**);
  auto function = reinterpret_cast<Function>(FunctionAt(114));
  if (function == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "JVMTI GetObjectsWithTags is unavailable");
  }
  return CheckJvmtiResult(
      "JVMTI::GetObjectsWithTags",
      function(handle_, tag_count, tags, count, objects, result_tags));
}

Status JvmtiEnv::AddCanTagObjectsCapability() const {
  using Function = jint (*)(void*, const void*);
  auto function = reinterpret_cast<Function>(FunctionAt(142));
  if (function == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "JVMTI AddCapabilities is unavailable");
  }
  // can_tag_objects is the first JVMTI capability bit in the JVMTI ABI.
  std::array<unsigned char, 16> capabilities{};
  capabilities[0] = 1U;
  return CheckJvmtiResult("JVMTI::AddCapabilities",
                          function(handle_, capabilities.data()));
}

}  // namespace art_hook
