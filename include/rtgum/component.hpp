#pragma once

#include <string_view>

#include "rtgum/status.hpp"

namespace rtgum {

class Component {
public:
    virtual ~Component() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    virtual Status Start() = 0;
    virtual void Stop() noexcept = 0;
};

}  // namespace rtgum

