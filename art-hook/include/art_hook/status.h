// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace art_hook {  // C++ public API

enum class StatusCode {
  kOk = 0,
  kInvalidArgument,
  kNotFound,
  kJniError,
  kUnavailable,
  kUnsupported,
  kResourceExhausted,
  kIoError,
  kPlatformError,
};

class Status final {
 public:
  Status() = default;
  Status(StatusCode code, std::string message)
      : code_(code), message_(std::move(message)) {}

  static Status Ok() { return {}; }

  [[nodiscard]] bool ok() const noexcept { return code_ == StatusCode::kOk; }
  [[nodiscard]] StatusCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }
  [[nodiscard]] std::string ToString() const;

 private:
  StatusCode code_ = StatusCode::kOk;
  std::string message_;
};

template <typename T>
class Result final {
 public:
  Result(T value) : value_(std::move(value)) {}
  Result(Status status) : status_(std::move(status)) {
    if (status_.ok()) {
      throw std::invalid_argument("Result error status must not be OK");
    }
  }

  [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
  [[nodiscard]] const Status& status() const noexcept { return status_; }

  [[nodiscard]] const T& value() const& {
    EnsureValue();
    return *value_;
  }

  [[nodiscard]] T& value() & {
    EnsureValue();
    return *value_;
  }

  [[nodiscard]] T&& value() && {
    EnsureValue();
    return std::move(*value_);
  }

 private:
  void EnsureValue() const {
    if (!ok() || !value_.has_value()) {
      throw std::logic_error(status_.ToString());
    }
  }

  std::optional<T> value_;
  Status status_;
};

}  // namespace art_hook
