#pragma once

#include <cstddef>
#include <memory>
#include <mutex>
#include <vector>

#include "rtgum/component.hpp"
#include "rtgum/status.hpp"

namespace rtgum {

enum class RuntimeState {
    kCold,
    kStarting,
    kReady,
    kStopping,
    kStopped,
    kFailed,
};

class Runtime final {
public:
    Runtime() = default;
    ~Runtime();

    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;

    Status Add(std::unique_ptr<Component> component);
    Status Start();
    Status Stop();

    [[nodiscard]] RuntimeState state() const noexcept;
    [[nodiscard]] std::size_t component_count() const noexcept;

private:
    void RollbackStarted(std::size_t started_count) noexcept;

    mutable std::mutex mutex_;
    std::vector<std::unique_ptr<Component>> components_;
    std::size_t started_count_{0};
    RuntimeState state_{RuntimeState::kCold};
};

}  // namespace rtgum
