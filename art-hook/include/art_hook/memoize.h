// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <functional>
#include <mutex>
#include <optional>
#include <utility>

namespace art_hook {  // C++ public API

// Mirrors memoize.js: the first successful invocation computes one value and
// later arguments are ignored. std::call_once retries if the computation throws.
template <typename Value>
class Memoized final {
 public:
  template <typename Compute>
  explicit Memoized(Compute&& compute)
      : compute_(std::forward<Compute>(compute)) {}

  [[nodiscard]] const Value& Get() const {
    std::call_once(once_, [this] { value_.emplace(compute_()); });
    return *value_;
  }

 private:
  std::function<Value()> compute_;
  mutable std::once_flag once_;
  mutable std::optional<Value> value_;
};

}  // namespace art_hook
