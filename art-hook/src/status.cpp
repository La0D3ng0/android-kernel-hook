// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/status.h"

#include <array>

namespace art_hook {

std::string Status::ToString() const {
  static constexpr std::array<const char*, 9> kNames = {
      "OK",          "INVALID_ARGUMENT", "NOT_FOUND",
      "JNI_ERROR",   "UNAVAILABLE",      "UNSUPPORTED",
      "EXHAUSTED",   "IO_ERROR",         "PLATFORM_ERROR",
  };
  const auto index = static_cast<std::size_t>(code_);
  const char* name = index < kNames.size() ? kNames[index] : "UNKNOWN";
  return message_.empty() ? std::string(name)
                          : std::string(name) + ": " + message_;
}

}  // namespace art_hook
