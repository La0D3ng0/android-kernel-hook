// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/java_proxy.h"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace art_hook {
namespace {

constexpr std::int32_t kJavaAccStatic = 0x0008;

JavaValue MakeValue(JavaValueKind kind) noexcept {
  JavaValue result;
  result.kind = kind;
  return result;
}

JavaValueKind KindForType(const TypeDescriptor& type) noexcept {
  if (type.is_reference()) {
    return JavaValueKind::kObject;
  }
  switch (type.primitive) {
    case PrimitiveType::kBoolean:
      return JavaValueKind::kBoolean;
    case PrimitiveType::kByte:
      return JavaValueKind::kByte;
    case PrimitiveType::kChar:
      return JavaValueKind::kChar;
    case PrimitiveType::kShort:
      return JavaValueKind::kShort;
    case PrimitiveType::kInt:
      return JavaValueKind::kInt;
    case PrimitiveType::kLong:
      return JavaValueKind::kLong;
    case PrimitiveType::kFloat:
      return JavaValueKind::kFloat;
    case PrimitiveType::kDouble:
      return JavaValueKind::kDouble;
    case PrimitiveType::kVoid:
      return JavaValueKind::kVoid;
  }
  return JavaValueKind::kVoid;
}

Status CheckArguments(const MethodDescriptor& method,
                      const std::vector<JavaValue>& arguments) {
  if (method.arguments.size() != arguments.size()) {
    return Status(StatusCode::kInvalidArgument,
                  "Java argument count does not match descriptor");
  }
  for (std::size_t index = 0; index != arguments.size(); ++index) {
    if (!arguments[index].IsCompatibleWith(method.arguments[index])) {
      return Status(StatusCode::kInvalidArgument,
                    "Java argument type does not match descriptor at index " +
                        std::to_string(index));
    }
  }
  return Status::Ok();
}

std::vector<jvalue> RawArguments(const std::vector<JavaValue>& arguments) {
  std::vector<jvalue> result;
  result.reserve(arguments.size());
  for (const auto& argument : arguments) {
    result.push_back(argument.value);
  }
  return result;
}

Result<JavaValue> CheckCallResult(const Env& env, const char* operation,
                                  JavaValue result) {
  Status status = env.ExceptionStatus(operation);
  if (!status.ok()) {
    return status;
  }
  return result;
}

Result<JavaValue> CallStatic(JNIEnv* env, const Env& checked_env, jclass klass,
                             jmethodID method, const TypeDescriptor& return_type,
                             const jvalue* arguments) {
  switch (KindForType(return_type)) {
    case JavaValueKind::kVoid:
      env->CallStaticVoidMethodA(klass, method, arguments);
      return CheckCallResult(checked_env, "CallStaticVoidMethodA",
                             JavaValue::Void());
    case JavaValueKind::kBoolean:
      return CheckCallResult(checked_env, "CallStaticBooleanMethodA",
          JavaValue::Boolean(env->CallStaticBooleanMethodA(klass, method, arguments)));
    case JavaValueKind::kByte:
      return CheckCallResult(checked_env, "CallStaticByteMethodA",
          JavaValue::Byte(env->CallStaticByteMethodA(klass, method, arguments)));
    case JavaValueKind::kChar:
      return CheckCallResult(checked_env, "CallStaticCharMethodA",
          JavaValue::Char(env->CallStaticCharMethodA(klass, method, arguments)));
    case JavaValueKind::kShort:
      return CheckCallResult(checked_env, "CallStaticShortMethodA",
          JavaValue::Short(env->CallStaticShortMethodA(klass, method, arguments)));
    case JavaValueKind::kInt:
      return CheckCallResult(checked_env, "CallStaticIntMethodA",
          JavaValue::Int(env->CallStaticIntMethodA(klass, method, arguments)));
    case JavaValueKind::kLong:
      return CheckCallResult(checked_env, "CallStaticLongMethodA",
          JavaValue::Long(env->CallStaticLongMethodA(klass, method, arguments)));
    case JavaValueKind::kFloat:
      return CheckCallResult(checked_env, "CallStaticFloatMethodA",
          JavaValue::Float(env->CallStaticFloatMethodA(klass, method, arguments)));
    case JavaValueKind::kDouble:
      return CheckCallResult(checked_env, "CallStaticDoubleMethodA",
          JavaValue::Double(env->CallStaticDoubleMethodA(klass, method, arguments)));
    case JavaValueKind::kObject:
      return CheckCallResult(checked_env, "CallStaticObjectMethodA",
          JavaValue::Object(env->CallStaticObjectMethodA(klass, method, arguments)));
  }
  return Status(StatusCode::kUnsupported, "unsupported static return type");
}

Result<JavaValue> CallVirtual(JNIEnv* env, const Env& checked_env,
                              jobject object, jmethodID method,
                              const TypeDescriptor& return_type,
                              const jvalue* arguments) {
  switch (KindForType(return_type)) {
    case JavaValueKind::kVoid:
      env->CallVoidMethodA(object, method, arguments);
      return CheckCallResult(checked_env, "CallVoidMethodA", JavaValue::Void());
    case JavaValueKind::kBoolean:
      return CheckCallResult(checked_env, "CallBooleanMethodA",
          JavaValue::Boolean(env->CallBooleanMethodA(object, method, arguments)));
    case JavaValueKind::kByte:
      return CheckCallResult(checked_env, "CallByteMethodA",
          JavaValue::Byte(env->CallByteMethodA(object, method, arguments)));
    case JavaValueKind::kChar:
      return CheckCallResult(checked_env, "CallCharMethodA",
          JavaValue::Char(env->CallCharMethodA(object, method, arguments)));
    case JavaValueKind::kShort:
      return CheckCallResult(checked_env, "CallShortMethodA",
          JavaValue::Short(env->CallShortMethodA(object, method, arguments)));
    case JavaValueKind::kInt:
      return CheckCallResult(checked_env, "CallIntMethodA",
          JavaValue::Int(env->CallIntMethodA(object, method, arguments)));
    case JavaValueKind::kLong:
      return CheckCallResult(checked_env, "CallLongMethodA",
          JavaValue::Long(env->CallLongMethodA(object, method, arguments)));
    case JavaValueKind::kFloat:
      return CheckCallResult(checked_env, "CallFloatMethodA",
          JavaValue::Float(env->CallFloatMethodA(object, method, arguments)));
    case JavaValueKind::kDouble:
      return CheckCallResult(checked_env, "CallDoubleMethodA",
          JavaValue::Double(env->CallDoubleMethodA(object, method, arguments)));
    case JavaValueKind::kObject:
      return CheckCallResult(checked_env, "CallObjectMethodA",
          JavaValue::Object(env->CallObjectMethodA(object, method, arguments)));
  }
  return Status(StatusCode::kUnsupported, "unsupported virtual return type");
}

Result<JavaValue> CallDirect(JNIEnv* env, const Env& checked_env,
                             jobject object, jclass klass, jmethodID method,
                             const TypeDescriptor& return_type,
                             const jvalue* arguments) {
  switch (KindForType(return_type)) {
    case JavaValueKind::kVoid:
      env->CallNonvirtualVoidMethodA(object, klass, method, arguments);
      return CheckCallResult(checked_env, "CallNonvirtualVoidMethodA",
                             JavaValue::Void());
    case JavaValueKind::kBoolean:
      return CheckCallResult(checked_env, "CallNonvirtualBooleanMethodA",
          JavaValue::Boolean(env->CallNonvirtualBooleanMethodA(object, klass, method, arguments)));
    case JavaValueKind::kByte:
      return CheckCallResult(checked_env, "CallNonvirtualByteMethodA",
          JavaValue::Byte(env->CallNonvirtualByteMethodA(object, klass, method, arguments)));
    case JavaValueKind::kChar:
      return CheckCallResult(checked_env, "CallNonvirtualCharMethodA",
          JavaValue::Char(env->CallNonvirtualCharMethodA(object, klass, method, arguments)));
    case JavaValueKind::kShort:
      return CheckCallResult(checked_env, "CallNonvirtualShortMethodA",
          JavaValue::Short(env->CallNonvirtualShortMethodA(object, klass, method, arguments)));
    case JavaValueKind::kInt:
      return CheckCallResult(checked_env, "CallNonvirtualIntMethodA",
          JavaValue::Int(env->CallNonvirtualIntMethodA(object, klass, method, arguments)));
    case JavaValueKind::kLong:
      return CheckCallResult(checked_env, "CallNonvirtualLongMethodA",
          JavaValue::Long(env->CallNonvirtualLongMethodA(object, klass, method, arguments)));
    case JavaValueKind::kFloat:
      return CheckCallResult(checked_env, "CallNonvirtualFloatMethodA",
          JavaValue::Float(env->CallNonvirtualFloatMethodA(object, klass, method, arguments)));
    case JavaValueKind::kDouble:
      return CheckCallResult(checked_env, "CallNonvirtualDoubleMethodA",
          JavaValue::Double(env->CallNonvirtualDoubleMethodA(object, klass, method, arguments)));
    case JavaValueKind::kObject:
      return CheckCallResult(checked_env, "CallNonvirtualObjectMethodA",
          JavaValue::Object(env->CallNonvirtualObjectMethodA(object, klass, method, arguments)));
  }
  return Status(StatusCode::kUnsupported, "unsupported direct return type");
}

}  // namespace

JavaValue JavaValue::Void() noexcept { return MakeValue(JavaValueKind::kVoid); }
JavaValue JavaValue::Boolean(jboolean input) noexcept {
  auto result = MakeValue(JavaValueKind::kBoolean); result.value.z = input; return result;
}
JavaValue JavaValue::Byte(jbyte input) noexcept {
  auto result = MakeValue(JavaValueKind::kByte); result.value.b = input; return result;
}
JavaValue JavaValue::Char(jchar input) noexcept {
  auto result = MakeValue(JavaValueKind::kChar); result.value.c = input; return result;
}
JavaValue JavaValue::Short(jshort input) noexcept {
  auto result = MakeValue(JavaValueKind::kShort); result.value.s = input; return result;
}
JavaValue JavaValue::Int(jint input) noexcept {
  auto result = MakeValue(JavaValueKind::kInt); result.value.i = input; return result;
}
JavaValue JavaValue::Long(jlong input) noexcept {
  auto result = MakeValue(JavaValueKind::kLong); result.value.j = input; return result;
}
JavaValue JavaValue::Float(jfloat input) noexcept {
  auto result = MakeValue(JavaValueKind::kFloat); result.value.f = input; return result;
}
JavaValue JavaValue::Double(jdouble input) noexcept {
  auto result = MakeValue(JavaValueKind::kDouble); result.value.d = input; return result;
}
JavaValue JavaValue::Object(jobject input) noexcept {
  auto result = MakeValue(JavaValueKind::kObject); result.value.l = input; return result;
}

bool JavaValue::IsCompatibleWith(const TypeDescriptor& type) const noexcept {
  return kind == KindForType(type) && kind != JavaValueKind::kVoid;
}

struct JavaProxyIndex::State final {
  explicit State(std::vector<JavaProxyClass> input)
      : hierarchy(std::move(input)) {}

  std::vector<JavaProxyClass> hierarchy;
  mutable std::mutex mutex;
  mutable std::unordered_map<std::string, std::vector<JavaProxyMember>> cache;
};

JavaProxyIndex::JavaProxyIndex(std::unique_ptr<State> state)
    : state_(std::move(state)) {}

Result<std::shared_ptr<JavaProxyIndex>> JavaProxyIndex::Create(
    std::vector<JavaProxyClass> hierarchy) {
  if (hierarchy.empty()) {
    return Status(StatusCode::kInvalidArgument,
                  "Java proxy hierarchy is empty");
  }
  for (const auto& klass : hierarchy) {
    if (klass.name.empty()) {
      return Status(StatusCode::kInvalidArgument,
                    "Java proxy class name is empty");
    }
  }
  return std::shared_ptr<JavaProxyIndex>(new JavaProxyIndex(
      std::make_unique<State>(std::move(hierarchy))));
}

const std::vector<JavaProxyClass>& JavaProxyIndex::hierarchy() const noexcept {
  return state_->hierarchy;
}

std::vector<std::string> JavaProxyIndex::List() const {
  std::vector<std::string> result;
  std::unordered_set<std::string> seen;
  // class-factory.js concatenates superclass names first, then removes dupes.
  for (auto klass = state_->hierarchy.rbegin();
       klass != state_->hierarchy.rend(); ++klass) {
    for (const auto& member : klass->members) {
      if (seen.insert(member.name).second) {
        result.push_back(member.name);
      }
    }
  }
  return result;
}

bool JavaProxyIndex::Has(std::string_view name) const {
  return !Find(name).empty();
}

std::vector<JavaProxyMember> JavaProxyIndex::Find(std::string_view name) const {
  const std::string key(name);
  std::lock_guard<std::mutex> lock(state_->mutex);
  const auto cached = state_->cache.find(key);
  if (cached != state_->cache.end()) {
    return cached->second;
  }

  std::vector<JavaProxyMember> result;
  for (std::size_t depth = 0; depth != state_->hierarchy.size(); ++depth) {
    const auto& klass = state_->hierarchy[depth];
    for (const auto& member : klass.members) {
      if (member.name == name) {
        result.push_back({member, klass.name, depth});
      }
    }
    // $find delegates to the superclass only if the local model has no spec.
    if (!result.empty()) {
      break;
    }
  }
  state_->cache.emplace(key, result);
  return result;
}

Result<JavaProxyMember> JavaProxyIndex::ResolveCallable(
    std::string_view name, MemberKind kind,
    const std::vector<JavaValue>& arguments,
    std::optional<std::string_view> descriptor) const {
  std::vector<JavaProxyMember> matches;
  for (const auto& candidate : Find(name)) {
    if (candidate.member.kind != kind) {
      continue;
    }
    if (descriptor.has_value() && candidate.member.descriptor != *descriptor) {
      continue;
    }
    auto parsed = ParseMethodDescriptor(candidate.member.descriptor);
    if (!parsed.ok()) {
      return parsed.status();
    }
    if (CheckArguments(parsed.value(), arguments).ok()) {
      matches.push_back(candidate);
    }
  }
  if (matches.empty()) {
    return Status(StatusCode::kNotFound,
                  "no compatible Java callable named " + std::string(name));
  }
  if (matches.size() != 1U) {
    return Status(StatusCode::kInvalidArgument,
                  "Java callable is ambiguous; provide an exact descriptor");
  }
  return matches.front();
}

Result<JavaProxyMember> JavaProxyIndex::ResolveMethod(
    std::string_view name, const std::vector<JavaValue>& arguments,
    std::optional<std::string_view> descriptor) const {
  return ResolveCallable(name, MemberKind::kMethod, arguments, descriptor);
}

Result<JavaProxyMember> JavaProxyIndex::ResolveConstructor(
    const std::vector<JavaValue>& arguments,
    std::optional<std::string_view> descriptor) const {
  return ResolveCallable("<init>", MemberKind::kConstructor, arguments,
                         descriptor);
}

Result<JavaProxyMember> JavaProxyIndex::ResolveField(
    std::string_view name, std::optional<std::string_view> descriptor) const {
  std::vector<JavaProxyMember> matches;
  for (const auto& candidate : Find(name)) {
    if (candidate.member.kind == MemberKind::kField &&
        (!descriptor.has_value() || candidate.member.descriptor == *descriptor)) {
      matches.push_back(candidate);
    }
  }
  if (matches.empty()) {
    return Status(StatusCode::kNotFound,
                  "Java field not found: " + std::string(name));
  }
  if (matches.size() != 1U) {
    return Status(StatusCode::kInvalidArgument,
                  "Java field is ambiguous; provide an exact descriptor");
  }
  return matches.front();
}

struct JavaObjectProxy::State final {
  struct ClassEntry final {
    jclass handle = nullptr;
    ClassModel model;
  };

  JavaVM* vm = nullptr;
  jobject object = nullptr;
  JavaProxyStrategy strategy = JavaProxyStrategy::kVirtual;
  std::vector<ClassEntry> hierarchy;
  std::shared_ptr<JavaProxyIndex> index;
  mutable std::recursive_mutex mutex;
  bool disposed = false;
};

JavaObjectProxy::JavaObjectProxy(std::unique_ptr<State> state)
    : state_(std::move(state)) {}

JavaObjectProxy::~JavaObjectProxy() {
  if (state_ == nullptr || state_->disposed || state_->vm == nullptr) {
    return;
  }
  auto scoped = Vm(state_->vm).GetEnv();
  if (scoped.ok()) {
    (void)Dispose(scoped.value().env());
  }
}

Result<std::unique_ptr<JavaObjectProxy>> JavaObjectProxy::Create(
    JavaVM* vm, const Env& env, jobject object, jclass declared_class,
    JavaProxyStrategy strategy) {
  if (env.get() == nullptr || declared_class == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Java proxy requires JNIEnv and declared class");
  }
  JavaVM* actual_vm = nullptr;
  const jint vm_result = env.get()->GetJavaVM(&actual_vm);
  if (vm_result != JNI_OK || actual_vm == nullptr) {
    return Status(StatusCode::kJniError, "JNIEnv::GetJavaVM failed");
  }
  if (vm != nullptr && vm != actual_vm) {
    return Status(StatusCode::kInvalidArgument,
                  "Java proxy JavaVM does not own the supplied JNIEnv");
  }

  auto state = std::make_unique<State>();
  state->vm = actual_vm;
  state->strategy = strategy;
  if (object != nullptr) {
    state->object = env.get()->NewGlobalRef(object);
    Status exception = env.ExceptionStatus("NewGlobalRef(object)");
    if (!exception.ok() || state->object == nullptr) {
      return exception.ok()
                 ? Status(StatusCode::kResourceExhausted,
                          "NewGlobalRef(object) returned null")
                 : exception;
    }
  }

  std::vector<JavaProxyClass> index_hierarchy;
  jclass current = declared_class;
  bool owns_current_local = false;
  while (current != nullptr) {
    auto model = ClassModel::Inspect(env, current);
    if (!model.ok()) {
      if (owns_current_local) {
        env.get()->DeleteLocalRef(current);
      }
      if (state->object != nullptr) {
        env.get()->DeleteGlobalRef(state->object);
      }
      for (const auto& entry : state->hierarchy) {
        env.get()->DeleteGlobalRef(entry.handle);
      }
      return model.status();
    }
    auto global = static_cast<jclass>(env.get()->NewGlobalRef(current));
    Status exception = env.ExceptionStatus("NewGlobalRef(class)");
    if (!exception.ok() || global == nullptr) {
      if (owns_current_local) {
        env.get()->DeleteLocalRef(current);
      }
      if (state->object != nullptr) {
        env.get()->DeleteGlobalRef(state->object);
      }
      for (const auto& entry : state->hierarchy) {
        env.get()->DeleteGlobalRef(entry.handle);
      }
      return exception.ok()
                 ? Status(StatusCode::kResourceExhausted,
                          "NewGlobalRef(class) returned null")
                 : exception;
    }
    index_hierarchy.push_back({model.value().name(), model.value().members()});
    state->hierarchy.push_back({global, std::move(model).value()});

    jclass next = env.get()->GetSuperclass(current);
    exception = env.ExceptionStatus("JNIEnv::GetSuperclass");
    if (owns_current_local) {
      env.get()->DeleteLocalRef(current);
    }
    if (!exception.ok()) {
      if (next != nullptr) {
        env.get()->DeleteLocalRef(next);
      }
      if (state->object != nullptr) {
        env.get()->DeleteGlobalRef(state->object);
      }
      for (const auto& entry : state->hierarchy) {
        env.get()->DeleteGlobalRef(entry.handle);
      }
      return exception;
    }
    current = next;
    owns_current_local = current != nullptr;
  }

  auto index = JavaProxyIndex::Create(std::move(index_hierarchy));
  if (!index.ok()) {
    if (state->object != nullptr) {
      env.get()->DeleteGlobalRef(state->object);
    }
    for (const auto& entry : state->hierarchy) {
      env.get()->DeleteGlobalRef(entry.handle);
    }
    return index.status();
  }
  state->index = std::move(index).value();
  return std::unique_ptr<JavaObjectProxy>(
      new JavaObjectProxy(std::move(state)));
}

std::vector<std::string> JavaObjectProxy::List() const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  return state_->disposed ? std::vector<std::string>{} : state_->index->List();
}

bool JavaObjectProxy::Has(std::string_view name) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  return !state_->disposed && state_->index->Has(name);
}

std::vector<JavaProxyMember> JavaObjectProxy::Find(std::string_view name) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  return state_->disposed ? std::vector<JavaProxyMember>{}
                          : state_->index->Find(name);
}

Result<JavaValue> JavaObjectProxy::Invoke(
    const Env& env, std::string_view name,
    const std::vector<JavaValue>& arguments,
    std::optional<std::string_view> descriptor) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status(StatusCode::kUnavailable, "Java proxy is disposed");
  }
  auto resolved = state_->index->ResolveMethod(name, arguments, descriptor);
  if (!resolved.ok()) {
    return resolved.status();
  }
  auto parsed = ParseMethodDescriptor(resolved.value().member.descriptor);
  if (!parsed.ok()) {
    return parsed.status();
  }
  const auto& entry = state_->hierarchy[resolved.value().inheritance_depth];
  JNIEnv* handle = env.get();
  const bool is_static =
      (resolved.value().member.modifiers & kJavaAccStatic) != 0;
  jmethodID method = is_static
      ? handle->GetStaticMethodID(entry.handle,
                                  resolved.value().member.name.c_str(),
                                  resolved.value().member.descriptor.c_str())
      : handle->GetMethodID(entry.handle, resolved.value().member.name.c_str(),
                            resolved.value().member.descriptor.c_str());
  Status exception = env.ExceptionStatus("JNI method lookup");
  if (!exception.ok()) {
    return exception;
  }
  if (method == nullptr) {
    return Status(StatusCode::kNotFound, "JNI method ID is null");
  }
  auto raw = RawArguments(arguments);
  const jvalue* raw_data = raw.empty() ? nullptr : raw.data();
  if (is_static) {
    return CallStatic(handle, env, entry.handle, method,
                      parsed.value().return_type, raw_data);
  }
  if (state_->object == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "instance method requires an object wrapper");
  }
  if (state_->strategy == JavaProxyStrategy::kDirect) {
    return CallDirect(handle, env, state_->object, entry.handle, method,
                      parsed.value().return_type, raw_data);
  }
  return CallVirtual(handle, env, state_->object, method,
                     parsed.value().return_type, raw_data);
}

Result<JavaValue> JavaObjectProxy::Construct(
    const Env& env, const std::vector<JavaValue>& arguments,
    std::optional<std::string_view> descriptor) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status(StatusCode::kUnavailable, "Java proxy is disposed");
  }
  auto resolved = state_->index->ResolveConstructor(arguments, descriptor);
  if (!resolved.ok()) {
    return resolved.status();
  }
  const auto& entry = state_->hierarchy[resolved.value().inheritance_depth];
  jmethodID method = env.get()->GetMethodID(
      entry.handle, "<init>", resolved.value().member.descriptor.c_str());
  Status exception = env.ExceptionStatus("constructor lookup");
  if (!exception.ok()) {
    return exception;
  }
  if (method == nullptr) {
    return Status(StatusCode::kNotFound, "JNI constructor ID is null");
  }
  auto raw = RawArguments(arguments);
  jobject object = env.get()->NewObjectA(
      entry.handle, method, raw.empty() ? nullptr : raw.data());
  return CheckCallResult(env, "NewObjectA", JavaValue::Object(object));
}

Result<JavaValue> JavaObjectProxy::GetField(
    const Env& env, std::string_view name,
    std::optional<std::string_view> descriptor) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status(StatusCode::kUnavailable, "Java proxy is disposed");
  }
  auto resolved = state_->index->ResolveField(name, descriptor);
  if (!resolved.ok()) {
    return resolved.status();
  }
  auto type = ParseType(resolved.value().member.descriptor);
  if (!type.ok()) {
    return type.status();
  }
  const auto& entry = state_->hierarchy[resolved.value().inheritance_depth];
  const bool is_static =
      (resolved.value().member.modifiers & kJavaAccStatic) != 0;
  JNIEnv* handle = env.get();
  jfieldID field = is_static
      ? handle->GetStaticFieldID(entry.handle, resolved.value().member.name.c_str(),
                                 resolved.value().member.descriptor.c_str())
      : handle->GetFieldID(entry.handle, resolved.value().member.name.c_str(),
                           resolved.value().member.descriptor.c_str());
  Status exception = env.ExceptionStatus("JNI field lookup");
  if (!exception.ok()) {
    return exception;
  }
  if (field == nullptr) {
    return Status(StatusCode::kNotFound, "JNI field ID is null");
  }
  if (!is_static && state_->object == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "instance field requires an object wrapper");
  }

#define ART_HOOK_GET_FIELD(kind_name, suffix, factory)                         \
  case JavaValueKind::kind_name: {                                            \
    const auto value = is_static                                              \
        ? handle->GetStatic##suffix##Field(entry.handle, field)               \
        : handle->Get##suffix##Field(state_->object, field);                  \
    return CheckCallResult(env, "Get" #suffix "Field", factory(value));      \
  }
  switch (KindForType(type.value())) {
    ART_HOOK_GET_FIELD(kBoolean, Boolean, JavaValue::Boolean)
    ART_HOOK_GET_FIELD(kByte, Byte, JavaValue::Byte)
    ART_HOOK_GET_FIELD(kChar, Char, JavaValue::Char)
    ART_HOOK_GET_FIELD(kShort, Short, JavaValue::Short)
    ART_HOOK_GET_FIELD(kInt, Int, JavaValue::Int)
    ART_HOOK_GET_FIELD(kLong, Long, JavaValue::Long)
    ART_HOOK_GET_FIELD(kFloat, Float, JavaValue::Float)
    ART_HOOK_GET_FIELD(kDouble, Double, JavaValue::Double)
    ART_HOOK_GET_FIELD(kObject, Object, JavaValue::Object)
    case JavaValueKind::kVoid:
      break;
  }
#undef ART_HOOK_GET_FIELD
  return Status(StatusCode::kUnsupported, "void field is invalid");
}

Status JavaObjectProxy::SetField(
    const Env& env, std::string_view name, const JavaValue& value,
    std::optional<std::string_view> descriptor) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status(StatusCode::kUnavailable, "Java proxy is disposed");
  }
  auto resolved = state_->index->ResolveField(name, descriptor);
  if (!resolved.ok()) {
    return resolved.status();
  }
  auto type = ParseType(resolved.value().member.descriptor);
  if (!type.ok()) {
    return type.status();
  }
  if (!value.IsCompatibleWith(type.value())) {
    return Status(StatusCode::kInvalidArgument,
                  "Java field value does not match descriptor");
  }
  const auto& entry = state_->hierarchy[resolved.value().inheritance_depth];
  const bool is_static =
      (resolved.value().member.modifiers & kJavaAccStatic) != 0;
  JNIEnv* handle = env.get();
  jfieldID field = is_static
      ? handle->GetStaticFieldID(entry.handle, resolved.value().member.name.c_str(),
                                 resolved.value().member.descriptor.c_str())
      : handle->GetFieldID(entry.handle, resolved.value().member.name.c_str(),
                           resolved.value().member.descriptor.c_str());
  Status exception = env.ExceptionStatus("JNI field lookup");
  if (!exception.ok()) {
    return exception;
  }
  if (field == nullptr) {
    return Status(StatusCode::kNotFound, "JNI field ID is null");
  }
  if (!is_static && state_->object == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "instance field requires an object wrapper");
  }

#define ART_HOOK_SET_FIELD(kind_name, suffix, member)                          \
  case JavaValueKind::kind_name:                                              \
    if (is_static) {                                                          \
      handle->SetStatic##suffix##Field(entry.handle, field, value.value.member); \
    } else {                                                                  \
      handle->Set##suffix##Field(state_->object, field, value.value.member);   \
    }                                                                         \
    break
  switch (value.kind) {
    ART_HOOK_SET_FIELD(kBoolean, Boolean, z);
    ART_HOOK_SET_FIELD(kByte, Byte, b);
    ART_HOOK_SET_FIELD(kChar, Char, c);
    ART_HOOK_SET_FIELD(kShort, Short, s);
    ART_HOOK_SET_FIELD(kInt, Int, i);
    ART_HOOK_SET_FIELD(kLong, Long, j);
    ART_HOOK_SET_FIELD(kFloat, Float, f);
    ART_HOOK_SET_FIELD(kDouble, Double, d);
    ART_HOOK_SET_FIELD(kObject, Object, l);
    case JavaValueKind::kVoid:
      return Status(StatusCode::kInvalidArgument, "void field value is invalid");
  }
#undef ART_HOOK_SET_FIELD
  return env.ExceptionStatus("SetField");
}

Result<std::unique_ptr<JavaObjectProxy>> JavaObjectProxy::Clone(
    const Env& env) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status(StatusCode::kUnavailable, "Java proxy is disposed");
  }
  return Create(state_->vm, env, state_->object, state_->hierarchy.front().handle,
                state_->strategy);
}

Result<std::unique_ptr<JavaObjectProxy>> JavaObjectProxy::Super(
    const Env& env) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status(StatusCode::kUnavailable, "Java proxy is disposed");
  }
  if (state_->hierarchy.size() < 2U) {
    return Status(StatusCode::kNotFound, "Java proxy has no superclass");
  }
  return Create(state_->vm, env, state_->object, state_->hierarchy[1].handle,
                JavaProxyStrategy::kDirect);
}

Result<bool> JavaObjectProxy::IsSameObject(const Env& env,
                                           jobject other) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status(StatusCode::kUnavailable, "Java proxy is disposed");
  }
  return env.get()->IsSameObject(state_->object, other) == JNI_TRUE;
}

Result<std::string> JavaObjectProxy::ClassName(const Env& env) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status(StatusCode::kUnavailable, "Java proxy is disposed");
  }
  if (state_->object == nullptr) {
    return state_->hierarchy.front().model.name();
  }
  return env.ObjectClassName(state_->object);
}

std::string JavaObjectProxy::ToString(const Env& env) const {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return "<disposed>";
  }
  const std::string& wrapper = state_->hierarchy.front().model.name();
  if (state_->object == nullptr) {
    return "<class: " + wrapper + ">";
  }
  auto actual = env.ObjectClassName(state_->object);
  if (!actual.ok() || actual.value() == wrapper) {
    return "<instance: " + wrapper + ">";
  }
  return "<instance: " + wrapper + ", $className: " + actual.value() + ">";
}

Status JavaObjectProxy::Dispose(const Env& env) noexcept {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  if (state_->disposed) {
    return Status::Ok();
  }
  if (state_->object != nullptr) {
    env.get()->DeleteGlobalRef(state_->object);
    state_->object = nullptr;
  }
  for (auto& entry : state_->hierarchy) {
    if (entry.handle != nullptr) {
      env.get()->DeleteGlobalRef(entry.handle);
      entry.handle = nullptr;
    }
  }
  state_->disposed = true;
  return Status::Ok();
}

bool JavaObjectProxy::disposed() const noexcept {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  return state_->disposed;
}

jobject JavaObjectProxy::handle() const noexcept {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  return state_->disposed ? nullptr : state_->object;
}

jclass JavaObjectProxy::declared_class() const noexcept {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  return state_->disposed || state_->hierarchy.empty()
             ? nullptr
             : state_->hierarchy.front().handle;
}

JavaProxyStrategy JavaObjectProxy::strategy() const noexcept {
  std::lock_guard<std::recursive_mutex> lock(state_->mutex);
  return state_->strategy;
}

}  // namespace art_hook
