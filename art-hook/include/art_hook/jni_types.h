// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "art_hook/status.h"

namespace art_hook {

enum class JavaTypeKind { kPrimitive, kObject, kArray };

enum class PrimitiveType {
  kBoolean,
  kByte,
  kChar,
  kShort,
  kInt,
  kLong,
  kFloat,
  kDouble,
  kVoid,
};

struct TypeDescriptor final {
  JavaTypeKind kind = JavaTypeKind::kPrimitive;
  PrimitiveType primitive = PrimitiveType::kVoid;
  std::string canonical_name;
  std::string jni_name;
  std::size_t slot_count = 0;
  std::size_t byte_size = 0;
  std::size_t array_dimensions = 0;

  [[nodiscard]] bool is_reference() const noexcept {
    return kind != JavaTypeKind::kPrimitive;
  }
};

struct MethodDescriptor final {
  std::vector<TypeDescriptor> arguments;
  TypeDescriptor return_type;
  std::string jni_name;
  std::string shorty;
};

[[nodiscard]] Result<TypeDescriptor> ParseType(std::string_view name);
[[nodiscard]] Result<MethodDescriptor> ParseMethodDescriptor(
    std::string_view descriptor);
[[nodiscard]] std::string MakeJniObjectTypeName(std::string_view type_name);
[[nodiscard]] char TypeToShorty(const TypeDescriptor& type) noexcept;

}  // namespace art_hook
