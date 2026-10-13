#include "rtgum/runtime.hpp"

#include <string>

namespace rtgum {

Runtime::~Runtime() {
    (void)Stop();
}

Status Runtime::Add(std::unique_ptr<Component> component) {
    if (component == nullptr) {
        return {StatusCode::kInvalidArgument, "component must not be null"};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != RuntimeState::kCold) {
        return {StatusCode::kInvalidState,
                "components can only be added before the runtime starts"};
    }

    components_.push_back(std::move(component));
    return Status::Ok();
}

Status Runtime::Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != RuntimeState::kCold && state_ != RuntimeState::kStopped) {
        return {StatusCode::kInvalidState, "runtime is not startable"};
    }

    state_ = RuntimeState::kStarting;
    started_count_ = 0;
    for (const auto& component : components_) {
        const Status status = component->Start();
        if (!status.ok()) {
            RollbackStarted(started_count_);
            started_count_ = 0;
            state_ = RuntimeState::kFailed;
            return {status.code(),
                    std::string(component->name()) + ": " + status.message()};
        }
        ++started_count_;
    }

    state_ = RuntimeState::kReady;
    return Status::Ok();
}

Status Runtime::Stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == RuntimeState::kCold || state_ == RuntimeState::kStopped) {
        state_ = RuntimeState::kStopped;
        return Status::Ok();
    }
    if (state_ == RuntimeState::kStarting || state_ == RuntimeState::kStopping) {
        return {StatusCode::kInvalidState, "runtime transition is in progress"};
    }

    state_ = RuntimeState::kStopping;
    RollbackStarted(started_count_);
    started_count_ = 0;
    state_ = RuntimeState::kStopped;
    return Status::Ok();
}

RuntimeState Runtime::state() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

std::size_t Runtime::component_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return components_.size();
}

void Runtime::RollbackStarted(std::size_t started_count) noexcept {
    while (started_count > 0) {
        --started_count;
        components_[started_count]->Stop();
    }
}

}  // namespace rtgum
