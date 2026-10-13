// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "art_hook/status.h"

namespace art_hook {

constexpr std::uint32_t kDexAccPublic = 0x0001;
constexpr std::uint32_t kDexAccPrivate = 0x0002;
constexpr std::uint32_t kDexAccProtected = 0x0004;
constexpr std::uint32_t kDexAccStatic = 0x0008;
constexpr std::uint32_t kDexAccFinal = 0x0010;
constexpr std::uint32_t kDexAccNative = 0x0100;
constexpr std::uint32_t kDexAccAbstract = 0x0400;
constexpr std::uint32_t kDexAccConstructor = 0x00010000;

struct DexFieldSpec final {
  std::string name;
  std::string type;
  std::uint32_t access_flags = kDexAccPublic;
};

struct DexMethodSpec final {
  std::string name;
  std::string return_type;
  std::vector<std::string> arguments;
  std::uint32_t access_flags = kDexAccPublic | kDexAccNative;
};

struct DexClassSpec final {
  std::string name;
  std::string super_class = "Ljava/lang/Object;";
  std::string source_file_name = "Generated.java";
  std::vector<std::string> interfaces;
  std::vector<DexFieldSpec> fields;
  std::vector<DexMethodSpec> methods;
};

class DexBuilder final {
 public:
  [[nodiscard]] Result<std::vector<std::uint8_t>> Build(
      DexClassSpec spec) const;
};

[[nodiscard]] std::vector<std::uint8_t> EncodeUleb128(std::uint32_t value);
[[nodiscard]] std::uint32_t Adler32(const std::uint8_t* data,
                                    std::size_t size);
[[nodiscard]] Status ValidateDex(const std::vector<std::uint8_t>& dex);

}  // namespace art_hook
