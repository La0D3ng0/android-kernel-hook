// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/vm.h"

#include <utility>

#include "art_hook/jni_result.h"

namespace art_hook {

Result<LocalRef<jclass>> Env::FindClass(const char* name) const {
  if (handle_ == nullptr || name == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "FindClass requires a valid environment and name");
  }
  jclass klass = handle_->FindClass(name);
  Status exception = ExceptionStatus("JNIEnv::FindClass");
  if (!exception.ok()) {
    return exception;
  }
  if (klass == nullptr) {
    return Status(StatusCode::kNotFound,
                  std::string("class not found: ") + name);
  }
  return LocalRef<jclass>(handle_, klass);
}

Result<std::string> Env::StringFromJni(jstring value) const {
  if (value == nullptr) {
    return Status(StatusCode::kInvalidArgument, "jstring is null");
  }
  const char* chars = handle_->GetStringUTFChars(value, nullptr);
  if (chars == nullptr) {
    Status exception = ExceptionStatus("JNIEnv::GetStringUTFChars");
    return exception.ok()
               ? Status(StatusCode::kResourceExhausted,
                        "GetStringUTFChars returned null")
               : exception;
  }
  std::string result(chars);
  handle_->ReleaseStringUTFChars(value, chars);
  return result;
}

Result<LocalRef<jstring>> Env::NewStringUtf(const std::string& value) const {
  jstring result = handle_->NewStringUTF(value.c_str());
  Status exception = ExceptionStatus("JNIEnv::NewStringUTF");
  if (!exception.ok()) {
    return exception;
  }
  if (result == nullptr) {
    return Status(StatusCode::kResourceExhausted,
                  "NewStringUTF returned null");
  }
  return LocalRef<jstring>(handle_, result);
}

Status Env::ExceptionStatus(const char* operation, bool clear) const {
  if (!handle_->ExceptionCheck()) {
    return Status::Ok();
  }
  if (clear) {
    handle_->ExceptionClear();
  }
  return Status(StatusCode::kJniError,
                std::string(operation) + " raised a Java exception");
}

Result<std::string> Env::ClassName(jclass klass) const {
  if (klass == nullptr) {
    return Status(StatusCode::kInvalidArgument, "class is null");
  }
  auto class_class = FindClass("java/lang/Class");
  if (!class_class.ok()) {
    return class_class.status();
  }
  jmethodID get_name =
      handle_->GetMethodID(class_class.value().get(), "getName",
                           "()Ljava/lang/String;");
  Status exception = ExceptionStatus("Class.getName lookup");
  if (!exception.ok()) {
    return exception;
  }
  if (get_name == nullptr) {
    return Status(StatusCode::kNotFound, "Class.getName method not found");
  }
  LocalRef<jstring> name(
      handle_, static_cast<jstring>(handle_->CallObjectMethod(klass, get_name)));
  exception = ExceptionStatus("Class.getName");
  if (!exception.ok()) {
    return exception;
  }
  return StringFromJni(name.get());
}

Result<std::string> Env::ObjectClassName(jobject object) const {
  if (object == nullptr) {
    return Status(StatusCode::kInvalidArgument, "object is null");
  }
  LocalRef<jclass> klass(handle_, handle_->GetObjectClass(object));
  Status exception = ExceptionStatus("JNIEnv::GetObjectClass");
  if (!exception.ok()) {
    return exception;
  }
  return ClassName(klass.get());
}

ScopedEnv::~ScopedEnv() { Detach(); }

ScopedEnv::ScopedEnv(ScopedEnv&& other) noexcept
    : vm_(other.vm_), env_(other.env_), attached_(other.attached_) {
  other.vm_ = nullptr;
  other.env_ = nullptr;
  other.attached_ = false;
}

ScopedEnv& ScopedEnv::operator=(ScopedEnv&& other) noexcept {
  if (this != &other) {
    Detach();
    vm_ = other.vm_;
    env_ = other.env_;
    attached_ = other.attached_;
    other.vm_ = nullptr;
    other.env_ = nullptr;
    other.attached_ = false;
  }
  return *this;
}

void ScopedEnv::Detach() noexcept {
  if (attached_ && vm_ != nullptr) {
    vm_->DetachCurrentThread();
  }
  attached_ = false;
}

Result<ScopedEnv> Vm::GetEnv(jint version) const {
  if (handle_ == nullptr) {
    return Status(StatusCode::kInvalidArgument, "JavaVM is null");
  }
  JNIEnv* env = nullptr;
  const jint result = handle_->GetEnv(reinterpret_cast<void**>(&env), version);
  if (result == JNI_OK) {
    return ScopedEnv(handle_, env, false);
  }
  if (result == JNI_EDETACHED) {
    return AttachCurrentThread();
  }
  return CheckJniResult("JavaVM::GetEnv", result);
}

Result<ScopedEnv> Vm::AttachCurrentThread() const {
  if (handle_ == nullptr) {
    return Status(StatusCode::kInvalidArgument, "JavaVM is null");
  }
  JNIEnv* env = nullptr;
  const jint result = handle_->AttachCurrentThread(&env, nullptr);
  Status status = CheckJniResult("JavaVM::AttachCurrentThread", result);
  if (!status.ok()) {
    return status;
  }
  return ScopedEnv(handle_, env, true);
}

}  // namespace art_hook
