// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "art_hook/status.h"
#include "art_hook/vm.h"

namespace art_hook {

enum class MemberKind { kField, kMethod, kConstructor };

struct ClassMember final {
  MemberKind kind = MemberKind::kField;
  std::string name;
  std::string descriptor;
  std::int32_t modifiers = 0;
};

class ClassModel final {
 public:
  [[nodiscard]] static Result<ClassModel> Inspect(const Env& env,
                                                   jclass klass);

  [[nodiscard]] const std::string& name() const noexcept { return name_; }
  [[nodiscard]] const std::vector<ClassMember>& members() const noexcept {
    return members_;
  }
  [[nodiscard]] bool Has(std::string_view name) const noexcept;
  [[nodiscard]] std::vector<ClassMember> Find(std::string_view name) const;

 private:
  std::string name_;
  std::vector<ClassMember> members_;
};

}  // namespace art_hook
