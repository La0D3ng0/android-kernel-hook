#pragma once

#include <memory>

#include "rtgum/component.hpp"

namespace rtgum {

// The initial Lua adapter creates a VM with standard libraries disabled.
std::unique_ptr<Component> CreateLuaBackend();

}  // namespace rtgum

