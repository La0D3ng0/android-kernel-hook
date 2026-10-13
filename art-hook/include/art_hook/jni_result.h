// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <string>

#include "art_hook/status.h"

namespace art_hook {

inline Status CheckJniResult(const char* operation, int result) {
  if (result == 0) {
    return Status::Ok();
  }
  return Status(StatusCode::kJniError,
                std::string(operation) + " failed: " +
                    std::to_string(result));
}

}  // namespace art_hook
