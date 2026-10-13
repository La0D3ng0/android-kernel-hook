// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/lsplant_backend.h"

#include <mutex>
#include <span>
#include <utility>

#include "art_hook/lsplant_arm64_bridge.h"
#include "lsplant.hpp"

namespace art_hook {
namespace {

struct LsplantInitializationState final {
  std::mutex mutex;
  bool attempted = false;
  bool initialized = false;
};

LsplantInitializationState& InitializationState() {
  static LsplantInitializationState state;
  return state;
}

Status JniFailure(Env env, const char* operation) {
  Status exception = env.ExceptionStatus(operation);
  if (!exception.ok()) {
    return exception;
  }
  return Status(StatusCode::kPlatformError,
                std::string(operation) + " failed without a Java exception");
}

}  // namespace

Status LsplantBackendConfig::Validate() const {
  if (!inline_hooker || !inline_unhooker) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant inline hook callbacks are required");
  }
  if (!art_symbol_resolver || !art_symbol_prefix_resolver) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant libart symbol resolvers are required");
  }
  if (generated_class_name.empty() || generated_field_name.empty() ||
      generated_method_name.empty()) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant generated member names must not be empty");
  }
#if !defined(__aarch64__)
  if (use_custom_arm64_bridge) {
    return Status(StatusCode::kUnsupported,
                  "the custom LSPlant bridge is ARM64-only");
  }
#endif
  return Status::Ok();
}

LsplantHook::~LsplantHook() noexcept {
  auto scoped = vm_.GetEnv();
  if (!scoped.ok()) {
    return;
  }
  JNIEnv* env = scoped.value().get();
  if (active_ && target_method_ != nullptr) {
    static_cast<void>(lsplant::UnHook(env, target_method_));
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
    }
  }
  active_ = false;
  ReleaseReferences(env);
}

Status LsplantHook::Unhook() {
  if (!active_) {
    return Status::Ok();
  }
  auto scoped = vm_.GetEnv();
  if (!scoped.ok()) {
    return scoped.status();
  }
  Env env = scoped.value().env();
  if (!lsplant::UnHook(env.get(), target_method_)) {
    return JniFailure(env, "LSPlant::UnHook");
  }
  active_ = false;
  return Status::Ok();
}

void LsplantHook::ReleaseReferences(JNIEnv* env) noexcept {
  if (target_method_ != nullptr) {
    env->DeleteGlobalRef(target_method_);
    target_method_ = nullptr;
  }
  if (backup_method_ != nullptr) {
    env->DeleteGlobalRef(backup_method_);
    backup_method_ = nullptr;
  }
}

Result<std::unique_ptr<LsplantBackend>> LsplantBackend::Create(
    Vm vm, Env env, const LsplantBackendConfig& config) {
  if (vm.get() == nullptr || env.get() == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant requires a JavaVM and JNIEnv");
  }
  Status valid = config.Validate();
  if (!valid.ok()) {
    return valid;
  }

  auto& state = InitializationState();
  std::lock_guard lock(state.mutex);
  if (!state.attempted) {
    state.attempted = true;
    lsplant::InitInfo info{
        .inline_hooker = config.inline_hooker,
        .inline_unhooker = config.inline_unhooker,
        .art_symbol_resolver = config.art_symbol_resolver,
        .art_symbol_prefix_resolver = config.art_symbol_prefix_resolver,
        .generated_class_name = config.generated_class_name,
        .generated_source_name = config.generated_source_name,
        .generated_field_name = config.generated_field_name,
        .generated_method_name = config.generated_method_name,
        .executable_memory_allocator =
            config.use_custom_arm64_bridge
                ? lsplant::InitInfo::MemoryAllocator(
                      &LsplantArm64BridgePool::Allocate)
                : lsplant::InitInfo::MemoryAllocator{},
        .executable_memory_recycler =
            config.use_custom_arm64_bridge
                ? lsplant::InitInfo::MemoryRecycler(
                      &LsplantArm64BridgePool::Recycle)
                : lsplant::InitInfo::MemoryRecycler{},
    };
    state.initialized = lsplant::Init(env.get(), info);
  }
  if (!state.initialized) {
    return Status(StatusCode::kPlatformError,
                  "LSPlant initialization failed; reinitialization is unsafe");
  }
  return std::unique_ptr<LsplantBackend>(new LsplantBackend(vm));
}

Result<std::unique_ptr<LsplantHook>> LsplantBackend::Hook(
    Env env, jobject target_method, jobject hooker_object,
    jobject callback_method) const {
  if (env.get() == nullptr || target_method == nullptr ||
      hooker_object == nullptr || callback_method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant hook arguments must not be null");
  }
  jobject backup =
      lsplant::Hook(env.get(), target_method, hooker_object, callback_method);
  if (backup == nullptr) {
    return JniFailure(env, "LSPlant::Hook");
  }

  JNIEnv* jni = env.get();
  jobject target_global = jni->NewGlobalRef(target_method);
  jobject backup_global = jni->NewGlobalRef(backup);
  // lsplant::Hook returns a GlobalRef (see Hook() -> JNI_NewGlobalRef).
  // CheckJNI on debuggable apps aborts if DeleteLocalRef is used on it.
  if (jni->GetObjectRefType(backup) == JNILocalRefType) {
    jni->DeleteLocalRef(backup);
  }
  if (target_global == nullptr || backup_global == nullptr) {
    if (target_global != nullptr) {
      jni->DeleteGlobalRef(target_global);
    }
    if (backup_global != nullptr) {
      jni->DeleteGlobalRef(backup_global);
    }
    static_cast<void>(lsplant::UnHook(jni, target_method));
    return JniFailure(env, "NewGlobalRef(LSPlant hook)");
  }
  return std::unique_ptr<LsplantHook>(
      new LsplantHook(vm_, target_global, backup_global));
}

Result<bool> LsplantBackend::IsHooked(Env env, jobject target_method) const {
  if (env.get() == nullptr || target_method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant target method is null");
  }
  const bool hooked = lsplant::IsHooked(env.get(), target_method);
  Status exception = env.ExceptionStatus("LSPlant::IsHooked");
  if (!exception.ok()) {
    return exception;
  }
  return hooked;
}

Status LsplantBackend::Deoptimize(Env env, jobject method) const {
  if (env.get() == nullptr || method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant method is null");
  }
  if (!lsplant::Deoptimize(env.get(), method)) {
    return JniFailure(env, "LSPlant::Deoptimize");
  }
  return Status::Ok();
}

Result<void*> LsplantBackend::GetNativeFunction(Env env,
                                                 jobject method) const {
  if (env.get() == nullptr || method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant native method is null");
  }
  void* function = lsplant::GetNativeFunction(env.get(), method);
  Status exception = env.ExceptionStatus("LSPlant::GetNativeFunction");
  if (!exception.ok()) {
    return exception;
  }
  if (function == nullptr) {
    return Status(StatusCode::kNotFound,
                  "method has no registered native function");
  }
  return function;
}

Status LsplantBackend::MakeClassInheritable(Env env, jclass klass) const {
  if (env.get() == nullptr || klass == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "LSPlant class is null");
  }
  if (!lsplant::MakeClassInheritable(env.get(), klass)) {
    return JniFailure(env, "LSPlant::MakeClassInheritable");
  }
  return Status::Ok();
}

}  // namespace art_hook
