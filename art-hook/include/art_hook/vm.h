// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>

#include <functional>
#include <string>
#include <utility>

#include "art_hook/status.h"

namespace art_hook {

template <typename T>
class LocalRef final {
 public:
  LocalRef() = default;
  LocalRef(JNIEnv* env, T value) : env_(env), value_(value) {}
  ~LocalRef() { Reset(); }

  LocalRef(const LocalRef&) = delete;
  LocalRef& operator=(const LocalRef&) = delete;

  LocalRef(LocalRef&& other) noexcept
      : env_(other.env_), value_(other.Release()) {}

  LocalRef& operator=(LocalRef&& other) noexcept {
    if (this != &other) {
      Reset();
      env_ = other.env_;
      value_ = other.Release();
    }
    return *this;
  }

  [[nodiscard]] T get() const noexcept { return value_; }
  [[nodiscard]] explicit operator bool() const noexcept {
    return value_ != nullptr;
  }

  [[nodiscard]] T Release() noexcept {
    T result = value_;
    value_ = nullptr;
    return result;
  }

  void Reset(T value = nullptr) noexcept {
    if (env_ != nullptr && value_ != nullptr) {
      env_->DeleteLocalRef(value_);
    }
    value_ = value;
  }

 private:
  JNIEnv* env_ = nullptr;
  T value_ = nullptr;
};

class Env final {
 public:
  explicit Env(JNIEnv* handle) : handle_(handle) {}

  [[nodiscard]] JNIEnv* get() const noexcept { return handle_; }
  [[nodiscard]] jint version() const noexcept { return handle_->GetVersion(); }

  [[nodiscard]] Result<LocalRef<jclass>> FindClass(const char* name) const;
  [[nodiscard]] Result<std::string> StringFromJni(jstring value) const;
  [[nodiscard]] Result<LocalRef<jstring>> NewStringUtf(
      const std::string& value) const;
  [[nodiscard]] Status ExceptionStatus(const char* operation,
                                       bool clear = true) const;
  [[nodiscard]] Result<std::string> ClassName(jclass klass) const;
  [[nodiscard]] Result<std::string> ObjectClassName(jobject object) const;

 private:
  JNIEnv* handle_ = nullptr;
};

class ScopedEnv final {
 public:
  ScopedEnv(JavaVM* vm, JNIEnv* env, bool attached)
      : vm_(vm), env_(env), attached_(attached) {}
  ~ScopedEnv();

  ScopedEnv(const ScopedEnv&) = delete;
  ScopedEnv& operator=(const ScopedEnv&) = delete;

  ScopedEnv(ScopedEnv&& other) noexcept;
  ScopedEnv& operator=(ScopedEnv&& other) noexcept;

  [[nodiscard]] Env env() const noexcept { return Env(env_); }
  [[nodiscard]] JNIEnv* get() const noexcept { return env_; }
  void KeepAttached() noexcept { attached_ = false; }

 private:
  void Detach() noexcept;

  JavaVM* vm_ = nullptr;
  JNIEnv* env_ = nullptr;
  bool attached_ = false;
};

class Vm final {
 public:
  explicit Vm(JavaVM* handle) : handle_(handle) {}

  [[nodiscard]] JavaVM* get() const noexcept { return handle_; }
  [[nodiscard]] Result<ScopedEnv> GetEnv(
      jint version = JNI_VERSION_1_6) const;
  [[nodiscard]] Result<ScopedEnv> AttachCurrentThread() const;

  template <typename Callback>
  auto Perform(Callback&& callback) const
      -> Result<decltype(callback(std::declval<Env>()))> {
    auto scoped = GetEnv();
    if (!scoped.ok()) {
      return scoped.status();
    }
    return callback(scoped.value().env());
  }

 private:
  JavaVM* handle_ = nullptr;
};

}  // namespace art_hook
