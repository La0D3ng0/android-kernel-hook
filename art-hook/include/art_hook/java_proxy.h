// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "art_hook/class_model.h"
#include "art_hook/jni_types.h"
#include "art_hook/status.h"
#include "art_hook/vm.h"

namespace art_hook {

enum class JavaProxyStrategy {
  kVirtual,
  kDirect,
};

enum class JavaValueKind {
  kVoid,
  kBoolean,
  kByte,
  kChar,
  kShort,
  kInt,
  kLong,
  kFloat,
  kDouble,
  kObject,
};

// A non-owning JNI value. Object results are local references owned by the
// caller's JNIEnv, matching the lifetime of ordinary JNI calls.
struct JavaValue final {
  JavaValueKind kind = JavaValueKind::kVoid;
  jvalue value{};

  [[nodiscard]] static JavaValue Void() noexcept;
  [[nodiscard]] static JavaValue Boolean(jboolean value) noexcept;
  [[nodiscard]] static JavaValue Byte(jbyte value) noexcept;
  [[nodiscard]] static JavaValue Char(jchar value) noexcept;
  [[nodiscard]] static JavaValue Short(jshort value) noexcept;
  [[nodiscard]] static JavaValue Int(jint value) noexcept;
  [[nodiscard]] static JavaValue Long(jlong value) noexcept;
  [[nodiscard]] static JavaValue Float(jfloat value) noexcept;
  [[nodiscard]] static JavaValue Double(jdouble value) noexcept;
  [[nodiscard]] static JavaValue Object(jobject value) noexcept;

  [[nodiscard]] bool IsCompatibleWith(const TypeDescriptor& type) const
      noexcept;
};

struct JavaProxyClass final {
  std::string name;
  std::vector<ClassMember> members;
};

struct JavaProxyMember final {
  ClassMember member;
  std::string declaring_class;
  std::size_t inheritance_depth = 0;
};

// Native equivalent of class-factory.js' wrapperHandler and $list/$has/$find.
// The hierarchy is ordered from the wrapped class to java.lang.Object.
class JavaProxyIndex final {
 public:
  [[nodiscard]] static Result<std::shared_ptr<JavaProxyIndex>> Create(
      std::vector<JavaProxyClass> hierarchy);

  [[nodiscard]] std::vector<std::string> List() const;
  [[nodiscard]] bool Has(std::string_view name) const;
  [[nodiscard]] std::vector<JavaProxyMember> Find(
      std::string_view name) const;

  [[nodiscard]] Result<JavaProxyMember> ResolveMethod(
      std::string_view name, const std::vector<JavaValue>& arguments,
      std::optional<std::string_view> descriptor = std::nullopt) const;
  [[nodiscard]] Result<JavaProxyMember> ResolveConstructor(
      const std::vector<JavaValue>& arguments,
      std::optional<std::string_view> descriptor = std::nullopt) const;
  [[nodiscard]] Result<JavaProxyMember> ResolveField(
      std::string_view name,
      std::optional<std::string_view> descriptor = std::nullopt) const;

  [[nodiscard]] const std::vector<JavaProxyClass>& hierarchy() const noexcept;

 private:
  struct State;

  explicit JavaProxyIndex(std::unique_ptr<State> state);
  [[nodiscard]] Result<JavaProxyMember> ResolveCallable(
      std::string_view name, MemberKind kind,
      const std::vector<JavaValue>& arguments,
      std::optional<std::string_view> descriptor) const;

  std::unique_ptr<State> state_;
};

// Explicit C++ wrapper replacing JavaScript's Proxy object. It owns global
// references to the object and its class hierarchy, and performs lazy member
// resolution through JavaProxyIndex.
class JavaObjectProxy final {
 public:
  JavaObjectProxy(const JavaObjectProxy&) = delete;
  JavaObjectProxy& operator=(const JavaObjectProxy&) = delete;
  ~JavaObjectProxy();

  [[nodiscard]] static Result<std::unique_ptr<JavaObjectProxy>> Create(
      JavaVM* vm, const Env& env, jobject object, jclass declared_class,
      JavaProxyStrategy strategy = JavaProxyStrategy::kVirtual);

  [[nodiscard]] std::vector<std::string> List() const;
  [[nodiscard]] bool Has(std::string_view name) const;
  [[nodiscard]] std::vector<JavaProxyMember> Find(
      std::string_view name) const;

  [[nodiscard]] Result<JavaValue> Invoke(
      const Env& env, std::string_view name,
      const std::vector<JavaValue>& arguments,
      std::optional<std::string_view> descriptor = std::nullopt) const;
  [[nodiscard]] Result<JavaValue> Construct(
      const Env& env, const std::vector<JavaValue>& arguments,
      std::optional<std::string_view> descriptor = std::nullopt) const;
  [[nodiscard]] Result<JavaValue> GetField(
      const Env& env, std::string_view name,
      std::optional<std::string_view> descriptor = std::nullopt) const;
  [[nodiscard]] Status SetField(
      const Env& env, std::string_view name, const JavaValue& value,
      std::optional<std::string_view> descriptor = std::nullopt) const;

  [[nodiscard]] Result<std::unique_ptr<JavaObjectProxy>> Clone(
      const Env& env) const;
  [[nodiscard]] Result<std::unique_ptr<JavaObjectProxy>> Super(
      const Env& env) const;
  [[nodiscard]] Result<bool> IsSameObject(const Env& env,
                                          jobject other) const;
  [[nodiscard]] Result<std::string> ClassName(const Env& env) const;
  [[nodiscard]] std::string ToString(const Env& env) const;
  [[nodiscard]] Status Dispose(const Env& env) noexcept;

  [[nodiscard]] bool disposed() const noexcept;
  [[nodiscard]] jobject handle() const noexcept;
  [[nodiscard]] jclass declared_class() const noexcept;
  [[nodiscard]] JavaProxyStrategy strategy() const noexcept;

 private:
  struct State;

  explicit JavaObjectProxy(std::unique_ptr<State> state);
  std::unique_ptr<State> state_;
};

}  // namespace art_hook
