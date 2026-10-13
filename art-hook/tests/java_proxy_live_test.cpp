// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include <jni.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <exception>
#include <string>

#include "art_hook/java_proxy.h"
#include "art_hook/status.h"
#include "art_hook/vm.h"

namespace {

void CopyMessage(const std::string& message, char* output,
                 std::size_t output_size) noexcept {
  if (output == nullptr || output_size == 0U) {
    return;
  }
  const std::size_t length = std::min(message.size(), output_size - 1U);
  std::memcpy(output, message.data(), length);
  output[length] = '\0';
}

int Fail(const art_hook::Status& status, char* output,
         std::size_t output_size) noexcept {
  CopyMessage(status.ToString(), output, output_size);
  return static_cast<int>(status.code());
}

art_hook::Status Check(bool condition, const char* message) {
  return condition
      ? art_hook::Status::Ok()
      : art_hook::Status(art_hook::StatusCode::kPlatformError, message);
}

}  // namespace

extern "C" __attribute__((visibility("default"))) int
art_hook_java_proxy_live_test(JNIEnv* raw_env, char* error,
                              std::size_t error_size) noexcept {
  try {
    if (raw_env == nullptr) {
      return Fail({art_hook::StatusCode::kInvalidArgument,
                   "JNIEnv is null"},
                  error, error_size);
    }
    art_hook::Env env(raw_env);
    JavaVM* vm = nullptr;
    if (raw_env->GetJavaVM(&vm) != JNI_OK || vm == nullptr) {
      return Fail({art_hook::StatusCode::kJniError,
                   "JNIEnv::GetJavaVM failed"},
                  error, error_size);
    }

    auto integer_class = env.FindClass("java/lang/Integer");
    if (!integer_class.ok()) {
      return Fail(integer_class.status(), error, error_size);
    }
    auto integer = art_hook::JavaObjectProxy::Create(
        vm, env, nullptr, integer_class.value().get());
    if (!integer.ok()) {
      return Fail(integer.status(), error, error_size);
    }
    if (!integer.value()->Has("sum") || integer.value()->List().empty()) {
      return Fail({art_hook::StatusCode::kNotFound,
                   "Integer proxy did not enumerate sum"},
                  error, error_size);
    }
    auto sum = integer.value()->Invoke(
        env, "sum",
        {art_hook::JavaValue::Int(19), art_hook::JavaValue::Int(23)},
        "(II)I");
    if (!sum.ok()) {
      return Fail(sum.status(), error, error_size);
    }
    auto checked = Check(sum.value().kind == art_hook::JavaValueKind::kInt &&
                             sum.value().value.i == 42,
                         "Integer.sum proxy result is incorrect");
    if (!checked.ok()) {
      return Fail(checked, error, error_size);
    }

    auto builder_class = env.FindClass("java/lang/StringBuilder");
    if (!builder_class.ok()) {
      return Fail(builder_class.status(), error, error_size);
    }
    auto builder_type = art_hook::JavaObjectProxy::Create(
        vm, env, nullptr, builder_class.value().get());
    if (!builder_type.ok()) {
      return Fail(builder_type.status(), error, error_size);
    }
    auto constructed = builder_type.value()->Construct(env, {}, "()V");
    if (!constructed.ok()) {
      return Fail(constructed.status(), error, error_size);
    }
    art_hook::LocalRef<jobject> builder_local(raw_env,
                                              constructed.value().value.l);
    auto builder = art_hook::JavaObjectProxy::Create(
        vm, env, builder_local.get(), builder_class.value().get());
    if (!builder.ok()) {
      return Fail(builder.status(), error, error_size);
    }
    auto text = env.NewStringUtf("native-proxy");
    if (!text.ok()) {
      return Fail(text.status(), error, error_size);
    }
    auto append = builder.value()->Invoke(
        env, "append", {art_hook::JavaValue::Object(text.value().get())},
        "(Ljava/lang/String;)Ljava/lang/StringBuilder;");
    if (!append.ok()) {
      return Fail(append.status(), error, error_size);
    }
    art_hook::LocalRef<jobject> append_result(raw_env,
                                              append.value().value.l);
    auto length = builder.value()->Invoke(env, "length", {}, "()I");
    if (!length.ok()) {
      return Fail(length.status(), error, error_size);
    }
    checked = Check(length.value().kind == art_hook::JavaValueKind::kInt &&
                        length.value().value.i == 12,
                    "StringBuilder.length proxy result is incorrect");
    if (!checked.ok()) {
      return Fail(checked, error, error_size);
    }

    auto clone = builder.value()->Clone(env);
    if (!clone.ok()) {
      return Fail(clone.status(), error, error_size);
    }
    auto same = clone.value()->IsSameObject(env, builder_local.get());
    if (!same.ok() || !same.value()) {
      return Fail(same.ok()
                      ? art_hook::Status(
                            art_hook::StatusCode::kPlatformError,
                            "cloned proxy does not reference the same object")
                      : same.status(),
                  error, error_size);
    }
    checked = Check(builder.value()->ToString(env).find("<instance:") == 0U,
                    "instance proxy string form is incorrect");
    if (!checked.ok()) {
      return Fail(checked, error, error_size);
    }
    if (!builder.value()->Dispose(env).ok() ||
        builder.value()->Invoke(env, "length", {}, "()I").ok()) {
      return Fail({art_hook::StatusCode::kPlatformError,
                   "disposed proxy still accepts calls"},
                  error, error_size);
    }

    CopyMessage("JAVA_PROXY_LIVE_TEST_PASS sum=42 length=12", error,
                error_size);
    return 0;
  } catch (const std::exception& exception) {
    CopyMessage(std::string("exception: ") + exception.what(), error,
                error_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  } catch (...) {
    CopyMessage("unknown exception", error, error_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  }
}
