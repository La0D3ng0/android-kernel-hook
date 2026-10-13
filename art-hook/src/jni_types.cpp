// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/jni_types.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <utility>

namespace art_hook {
namespace {

struct PrimitiveSpec final {
  std::string_view canonical;
  char shorty;
  PrimitiveType type;
  std::size_t slots;
  std::size_t bytes;
};

constexpr std::array<PrimitiveSpec, 9> kPrimitives = {{
    {"boolean", 'Z', PrimitiveType::kBoolean, 1, 1},
    {"byte", 'B', PrimitiveType::kByte, 1, 1},
    {"char", 'C', PrimitiveType::kChar, 1, 2},
    {"short", 'S', PrimitiveType::kShort, 1, 2},
    {"int", 'I', PrimitiveType::kInt, 1, 4},
    {"long", 'J', PrimitiveType::kLong, 2, 8},
    {"float", 'F', PrimitiveType::kFloat, 1, 4},
    {"double", 'D', PrimitiveType::kDouble, 2, 8},
    {"void", 'V', PrimitiveType::kVoid, 0, 0},
}};

const PrimitiveSpec* FindPrimitive(std::string_view value) {
  for (const auto& spec : kPrimitives) {
    if (value == spec.canonical ||
        (value.size() == 1 && value.front() == spec.shorty)) {
      return &spec;
    }
  }
  return nullptr;
}

TypeDescriptor MakePrimitive(const PrimitiveSpec& spec) {
  return {JavaTypeKind::kPrimitive,
          spec.type,
          std::string(spec.canonical),
          std::string(1, spec.shorty),
          spec.slots,
          spec.bytes,
          0};
}

Result<TypeDescriptor> ParseJniType(std::string_view input,
                                    std::size_t* consumed,
                                    bool allow_void) {
  if (input.empty()) {
    return Status(StatusCode::kInvalidArgument, "empty JNI type descriptor");
  }

  std::size_t dimensions = 0;
  while (dimensions < input.size() && input[dimensions] == '[') {
    ++dimensions;
  }
  if (dimensions == input.size()) {
    return Status(StatusCode::kInvalidArgument,
                  "array descriptor has no element type");
  }

  const std::string_view element = input.substr(dimensions);
  TypeDescriptor base;
  std::size_t base_consumed = 0;
  if (const PrimitiveSpec* primitive = FindPrimitive(element.substr(0, 1));
      primitive != nullptr) {
    if (primitive->type == PrimitiveType::kVoid &&
        (!allow_void || dimensions != 0)) {
      return Status(StatusCode::kInvalidArgument,
                    "void is not valid in this descriptor position");
    }
    base = MakePrimitive(*primitive);
    base_consumed = 1;
  } else if (element.front() == 'L') {
    const std::size_t end = element.find(';');
    if (end == std::string_view::npos || end == 1) {
      return Status(StatusCode::kInvalidArgument,
                    "invalid object type descriptor");
    }
    std::string class_name(element.substr(1, end - 1));
    std::replace(class_name.begin(), class_name.end(), '/', '.');
    base.kind = JavaTypeKind::kObject;
    base.canonical_name = std::move(class_name);
    base.jni_name = std::string(element.substr(0, end + 1));
    base.slot_count = 1;
    base.byte_size = sizeof(void*);
    base_consumed = end + 1;
  } else {
    return Status(StatusCode::kInvalidArgument,
                  "unknown JNI type descriptor");
  }

  *consumed = dimensions + base_consumed;
  if (dimensions == 0) {
    return base;
  }

  TypeDescriptor array;
  array.kind = JavaTypeKind::kArray;
  array.primitive = base.primitive;
  array.canonical_name = base.canonical_name;
  for (std::size_t i = 0; i < dimensions; ++i) {
    array.canonical_name += "[]";
  }
  array.jni_name = std::string(input.substr(0, *consumed));
  array.slot_count = 1;
  array.byte_size = sizeof(void*);
  array.array_dimensions = dimensions;
  return array;
}

bool IsValidClassName(std::string_view name) {
  if (name.empty()) {
    return false;
  }
  return std::none_of(name.begin(), name.end(), [](char c) {
    return c == '[' || c == ';' || c == '(' || c == ')';
  });
}

}  // namespace

Result<TypeDescriptor> ParseType(std::string_view name) {
  if (name.empty()) {
    return Status(StatusCode::kInvalidArgument, "type name is empty");
  }

  if (name.front() == '[' || name.front() == 'L' || name.size() == 1) {
    std::size_t consumed = 0;
    auto parsed = ParseJniType(name, &consumed, true);
    if (parsed.ok() && consumed == name.size()) {
      return parsed;
    }
    if (name.front() == '[' || name.front() == 'L') {
      return parsed.ok()
                 ? Result<TypeDescriptor>(Status(
                       StatusCode::kInvalidArgument,
                       "trailing data after JNI type descriptor"))
                 : parsed;
    }
  }

  if (const PrimitiveSpec* primitive = FindPrimitive(name);
      primitive != nullptr) {
    return MakePrimitive(*primitive);
  }

  std::size_t dimensions = 0;
  while (name.size() >= 2 && name.substr(name.size() - 2) == "[]") {
    ++dimensions;
    name.remove_suffix(2);
  }
  if (!IsValidClassName(name)) {
    return Status(StatusCode::kInvalidArgument, "invalid Java type name");
  }

  auto primitive = FindPrimitive(name);
  if (dimensions == 0) {
    TypeDescriptor object;
    object.kind = JavaTypeKind::kObject;
    object.canonical_name = std::string(name);
    std::replace(object.canonical_name.begin(), object.canonical_name.end(),
                 '/', '.');
    object.jni_name = MakeJniObjectTypeName(object.canonical_name);
    object.slot_count = 1;
    object.byte_size = sizeof(void*);
    return object;
  }

  TypeDescriptor array;
  array.kind = JavaTypeKind::kArray;
  array.array_dimensions = dimensions;
  array.slot_count = 1;
  array.byte_size = sizeof(void*);
  if (primitive != nullptr) {
    if (primitive->type == PrimitiveType::kVoid) {
      return Status(StatusCode::kInvalidArgument, "void[] is not valid");
    }
    array.primitive = primitive->type;
    array.canonical_name = std::string(primitive->canonical);
    array.jni_name.assign(dimensions, '[');
    array.jni_name.push_back(primitive->shorty);
  } else {
    array.canonical_name = std::string(name);
    std::replace(array.canonical_name.begin(), array.canonical_name.end(),
                 '/', '.');
    array.jni_name.assign(dimensions, '[');
    array.jni_name += MakeJniObjectTypeName(array.canonical_name);
  }
  for (std::size_t i = 0; i < dimensions; ++i) {
    array.canonical_name += "[]";
  }
  return array;
}

Result<MethodDescriptor> ParseMethodDescriptor(std::string_view descriptor) {
  if (descriptor.empty() || descriptor.front() != '(') {
    return Status(StatusCode::kInvalidArgument,
                  "method descriptor must begin with '('");
  }

  MethodDescriptor result;
  result.jni_name = std::string(descriptor);
  std::size_t cursor = 1;
  while (cursor < descriptor.size() && descriptor[cursor] != ')') {
    std::size_t consumed = 0;
    auto argument = ParseJniType(descriptor.substr(cursor), &consumed, false);
    if (!argument.ok()) {
      return argument.status();
    }
    result.arguments.push_back(std::move(argument).value());
    cursor += consumed;
  }
  if (cursor >= descriptor.size() || descriptor[cursor] != ')') {
    return Status(StatusCode::kInvalidArgument,
                  "method descriptor is missing ')'");
  }

  ++cursor;
  std::size_t consumed = 0;
  auto return_type = ParseJniType(descriptor.substr(cursor), &consumed, true);
  if (!return_type.ok()) {
    return return_type.status();
  }
  cursor += consumed;
  if (cursor != descriptor.size()) {
    return Status(StatusCode::kInvalidArgument,
                  "trailing data after method descriptor");
  }

  result.return_type = std::move(return_type).value();
  result.shorty.push_back(TypeToShorty(result.return_type));
  for (const auto& argument : result.arguments) {
    result.shorty.push_back(TypeToShorty(argument));
  }
  return result;
}

std::string MakeJniObjectTypeName(std::string_view type_name) {
  std::string result;
  result.reserve(type_name.size() + 2);
  result.push_back('L');
  for (const char c : type_name) {
    result.push_back(c == '.' ? '/' : c);
  }
  result.push_back(';');
  return result;
}

char TypeToShorty(const TypeDescriptor& type) noexcept {
  if (type.kind != JavaTypeKind::kPrimitive) {
    return 'L';
  }
  for (const auto& spec : kPrimitives) {
    if (spec.type == type.primitive) {
      return spec.shorty;
    }
  }
  return 'V';
}

}  // namespace art_hook
