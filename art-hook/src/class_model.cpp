// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/class_model.h"

#include <algorithm>
#include <utility>

#include "art_hook/jni_types.h"

namespace art_hook {
namespace {

Result<std::string> ClassObjectDescriptor(const Env& env, jobject class_object) {
  if (class_object == nullptr) {
    return Status(StatusCode::kInvalidArgument, "type class is null");
  }
  auto name = env.ClassName(static_cast<jclass>(class_object));
  if (!name.ok()) {
    return name.status();
  }
  if (!name.value().empty() && name.value().front() == '[') {
    std::string descriptor = name.value();
    std::replace(descriptor.begin(), descriptor.end(), '.', '/');
    return descriptor;
  }
  auto type = ParseType(name.value());
  if (!type.ok()) {
    return type.status();
  }
  return type.value().jni_name;
}

Result<std::string> ReflectedName(const Env& env, jobject reflected,
                                  jmethodID get_name) {
  JNIEnv* jni = env.get();
  LocalRef<jstring> value(
      jni, static_cast<jstring>(jni->CallObjectMethod(reflected, get_name)));
  Status status = env.ExceptionStatus("Member.getName");
  if (!status.ok()) {
    return status;
  }
  return env.StringFromJni(value.get());
}

Result<std::vector<std::string>> ParameterDescriptors(
    const Env& env, jobject reflected, jmethodID get_parameter_types) {
  JNIEnv* jni = env.get();
  LocalRef<jobjectArray> parameters(
      jni, static_cast<jobjectArray>(
               jni->CallObjectMethod(reflected, get_parameter_types)));
  Status status = env.ExceptionStatus("Executable.getParameterTypes");
  if (!status.ok()) {
    return status;
  }
  const jsize count = jni->GetArrayLength(parameters.get());
  status = env.ExceptionStatus("GetArrayLength(parameter types)");
  if (!status.ok()) {
    return status;
  }
  std::vector<std::string> result;
  result.reserve(static_cast<std::size_t>(count));
  for (jsize i = 0; i < count; ++i) {
    LocalRef<jobject> parameter(
        jni, jni->GetObjectArrayElement(parameters.get(), i));
    status = env.ExceptionStatus("GetObjectArrayElement(parameter type)");
    if (!status.ok()) {
      return status;
    }
    auto descriptor = ClassObjectDescriptor(env, parameter.get());
    if (!descriptor.ok()) {
      return descriptor.status();
    }
    result.push_back(std::move(descriptor).value());
  }
  return result;
}

std::string MakeMethodDescriptor(const std::vector<std::string>& arguments,
                                 const std::string& return_type) {
  std::string result("(");
  for (const auto& argument : arguments) {
    result += argument;
  }
  result.push_back(')');
  result += return_type;
  return result;
}

Result<std::vector<ClassMember>> InspectFields(const Env& env, jclass klass,
                                               jclass class_class) {
  JNIEnv* jni = env.get();
  jmethodID get_fields = jni->GetMethodID(
      class_class, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
  Status status = env.ExceptionStatus("Class.getDeclaredFields lookup");
  if (!status.ok() || get_fields == nullptr) {
    return status.ok() ? Status(StatusCode::kNotFound,
                                "Class.getDeclaredFields is unavailable")
                       : status;
  }
  LocalRef<jobjectArray> fields(
      jni, static_cast<jobjectArray>(jni->CallObjectMethod(klass, get_fields)));
  status = env.ExceptionStatus("Class.getDeclaredFields");
  if (!status.ok()) {
    return status;
  }

  auto field_class_result = env.FindClass("java/lang/reflect/Field");
  if (!field_class_result.ok()) {
    return field_class_result.status();
  }
  jclass field_class = field_class_result.value().get();
  jmethodID get_name = jni->GetMethodID(
      field_class, "getName", "()Ljava/lang/String;");
  jmethodID get_type = jni->GetMethodID(
      field_class, "getType", "()Ljava/lang/Class;");
  jmethodID get_modifiers = jni->GetMethodID(field_class, "getModifiers", "()I");
  status = env.ExceptionStatus("Field reflection method lookup");
  if (!status.ok() || get_name == nullptr || get_type == nullptr ||
      get_modifiers == nullptr) {
    return status.ok() ? Status(StatusCode::kNotFound,
                                "Field reflection methods are unavailable")
                       : status;
  }

  const jsize count = jni->GetArrayLength(fields.get());
  std::vector<ClassMember> result;
  result.reserve(static_cast<std::size_t>(count));
  for (jsize i = 0; i < count; ++i) {
    LocalRef<jobject> field(jni,
                            jni->GetObjectArrayElement(fields.get(), i));
    auto name = ReflectedName(env, field.get(), get_name);
    if (!name.ok()) {
      return name.status();
    }
    LocalRef<jobject> type(
        jni, jni->CallObjectMethod(field.get(), get_type));
    status = env.ExceptionStatus("Field.getType");
    if (!status.ok()) {
      return status;
    }
    auto descriptor = ClassObjectDescriptor(env, type.get());
    if (!descriptor.ok()) {
      return descriptor.status();
    }
    const jint modifiers = jni->CallIntMethod(field.get(), get_modifiers);
    status = env.ExceptionStatus("Field.getModifiers");
    if (!status.ok()) {
      return status;
    }
    result.push_back({MemberKind::kField, std::move(name).value(),
                      std::move(descriptor).value(), modifiers});
  }
  return result;
}

Result<std::vector<ClassMember>> InspectExecutables(
    const Env& env, jclass klass, jclass class_class, bool constructors) {
  JNIEnv* jni = env.get();
  const char* getter_name =
      constructors ? "getDeclaredConstructors" : "getDeclaredMethods";
  const char* getter_signature =
      constructors ? "()[Ljava/lang/reflect/Constructor;"
                   : "()[Ljava/lang/reflect/Method;";
  jmethodID get_executables =
      jni->GetMethodID(class_class, getter_name, getter_signature);
  Status status = env.ExceptionStatus("Class executable lookup");
  if (!status.ok() || get_executables == nullptr) {
    return status.ok()
               ? Status(StatusCode::kNotFound,
                        "Class executable enumeration is unavailable")
               : status;
  }
  LocalRef<jobjectArray> executables(
      jni, static_cast<jobjectArray>(
               jni->CallObjectMethod(klass, get_executables)));
  status = env.ExceptionStatus("Class executable enumeration");
  if (!status.ok()) {
    return status;
  }

  const char* reflected_class_name =
      constructors ? "java/lang/reflect/Constructor"
                   : "java/lang/reflect/Method";
  auto reflected_class_result = env.FindClass(reflected_class_name);
  if (!reflected_class_result.ok()) {
    return reflected_class_result.status();
  }
  jclass reflected_class = reflected_class_result.value().get();
  jmethodID get_name = nullptr;
  if (!constructors) {
    get_name = jni->GetMethodID(reflected_class, "getName",
                                "()Ljava/lang/String;");
  }
  jmethodID get_parameters = jni->GetMethodID(
      reflected_class, "getParameterTypes", "()[Ljava/lang/Class;");
  jmethodID get_modifiers =
      jni->GetMethodID(reflected_class, "getModifiers", "()I");
  jmethodID get_return_type = constructors
                                  ? nullptr
                                  : jni->GetMethodID(reflected_class,
                                                     "getReturnType",
                                                     "()Ljava/lang/Class;");
  status = env.ExceptionStatus("Executable reflection method lookup");
  if (!status.ok() || get_parameters == nullptr || get_modifiers == nullptr ||
      (!constructors && (get_name == nullptr || get_return_type == nullptr))) {
    return status.ok()
               ? Status(StatusCode::kNotFound,
                        "Executable reflection methods are unavailable")
               : status;
  }

  const jsize count = jni->GetArrayLength(executables.get());
  std::vector<ClassMember> result;
  result.reserve(static_cast<std::size_t>(count));
  for (jsize i = 0; i < count; ++i) {
    LocalRef<jobject> reflected(
        jni, jni->GetObjectArrayElement(executables.get(), i));
    std::string name = "<init>";
    if (!constructors) {
      auto name_result = ReflectedName(env, reflected.get(), get_name);
      if (!name_result.ok()) {
        return name_result.status();
      }
      name = std::move(name_result).value();
    }
    auto parameters =
        ParameterDescriptors(env, reflected.get(), get_parameters);
    if (!parameters.ok()) {
      return parameters.status();
    }
    std::string return_type = "V";
    if (!constructors) {
      LocalRef<jobject> type(
          jni, jni->CallObjectMethod(reflected.get(), get_return_type));
      status = env.ExceptionStatus("Method.getReturnType");
      if (!status.ok()) {
        return status;
      }
      auto descriptor = ClassObjectDescriptor(env, type.get());
      if (!descriptor.ok()) {
        return descriptor.status();
      }
      return_type = std::move(descriptor).value();
    }
    const jint modifiers = jni->CallIntMethod(reflected.get(), get_modifiers);
    status = env.ExceptionStatus("Executable.getModifiers");
    if (!status.ok()) {
      return status;
    }
    result.push_back(
        {constructors ? MemberKind::kConstructor : MemberKind::kMethod,
         std::move(name),
         MakeMethodDescriptor(parameters.value(), return_type), modifiers});
  }
  return result;
}

}  // namespace

Result<ClassModel> ClassModel::Inspect(const Env& env, jclass klass) {
  if (env.get() == nullptr || klass == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ClassModel::Inspect requires a class");
  }
  auto name = env.ClassName(klass);
  if (!name.ok()) {
    return name.status();
  }
  auto class_class = env.FindClass("java/lang/Class");
  if (!class_class.ok()) {
    return class_class.status();
  }

  auto fields = InspectFields(env, klass, class_class.value().get());
  if (!fields.ok()) {
    return fields.status();
  }
  auto methods = InspectExecutables(env, klass, class_class.value().get(), false);
  if (!methods.ok()) {
    return methods.status();
  }
  auto constructors =
      InspectExecutables(env, klass, class_class.value().get(), true);
  if (!constructors.ok()) {
    return constructors.status();
  }

  ClassModel model;
  model.name_ = std::move(name).value();
  model.members_ = std::move(fields).value();
  auto method_items = std::move(methods).value();
  model.members_.insert(model.members_.end(),
                        std::make_move_iterator(method_items.begin()),
                        std::make_move_iterator(method_items.end()));
  auto constructor_items = std::move(constructors).value();
  model.members_.insert(model.members_.end(),
                        std::make_move_iterator(constructor_items.begin()),
                        std::make_move_iterator(constructor_items.end()));
  return model;
}

bool ClassModel::Has(std::string_view name) const noexcept {
  return std::any_of(members_.begin(), members_.end(),
                     [name](const ClassMember& member) {
                       return member.name == name;
                     });
}

std::vector<ClassMember> ClassModel::Find(std::string_view name) const {
  std::vector<ClassMember> result;
  std::copy_if(members_.begin(), members_.end(), std::back_inserter(result),
               [name](const ClassMember& member) {
                 return member.name == name;
               });
  return result;
}

}  // namespace art_hook
