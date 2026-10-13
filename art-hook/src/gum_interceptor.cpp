// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/gum_interceptor.h"

#include <new>
#include <string>
#include <type_traits>
#include <utility>

namespace art_hook {
namespace {

static_assert(std::is_standard_layout<GumInterceptorApi>::value,
              "GumInterceptorApi must remain a C-compatible descriptor");

Status ValidateApi(const GumInterceptorApi &api,
                   const GumInterceptorRuntimeOptions &options) {
  if (api.abi_version != GumInterceptorApi::kAbiVersion) {
    return {StatusCode::kUnsupported,
            "unsupported Gum interceptor adapter ABI " +
                std::to_string(api.abi_version)};
  }
  if (api.reserved != 0U) {
    return {StatusCode::kInvalidArgument,
            "Gum interceptor adapter reserved field must be zero"};
  }
  if (options.manage_embedded_lifecycle &&
      (api.init_embedded == nullptr || api.deinit_embedded == nullptr)) {
    return {StatusCode::kInvalidArgument,
            "managed Gum lifecycle requires init and deinit wrappers"};
  }
  if (api.obtain == nullptr || api.object_unref == nullptr ||
      api.make_call_listener == nullptr ||
      api.make_probe_listener == nullptr || api.attach == nullptr ||
      api.detach == nullptr || api.replace == nullptr ||
      api.revert == nullptr || api.begin_transaction == nullptr ||
      api.end_transaction == nullptr || api.flush == nullptr ||
      api.get_nth_argument == nullptr ||
      api.replace_nth_argument == nullptr ||
      api.get_return_value == nullptr ||
      api.replace_return_value == nullptr || api.get_function == nullptr ||
      api.get_cpu_context == nullptr ||
      api.get_return_address == nullptr || api.get_thread_id == nullptr ||
      api.get_depth == nullptr ||
      api.get_listener_function_data == nullptr ||
      api.get_replacement_data == nullptr ||
      api.get_current_invocation == nullptr) {
    return {StatusCode::kInvalidArgument,
            "Gum interceptor adapter is incomplete"};
  }
  return Status::Ok();
}

Status GumOperationError(const char *operation, int result) {
  const char *reason = "unknown error";
  switch (result) {
  case -1:
    reason = "wrong function signature";
    break;
  case -2:
    reason = "target already hooked";
    break;
  case -3:
    reason = "interceptor policy violation";
    break;
  case -4:
    reason = "wrong listener or replacement type";
    break;
  default:
    break;
  }
  return {StatusCode::kPlatformError,
          std::string("Gum ") + operation + " failed: " + reason +
              " (" + std::to_string(result) + ")"};
}

} // namespace

struct GumInterceptorRuntime::ListenerState final {
  const GumInterceptorApi *api = nullptr;
  GumInvocationCallbacks callbacks;
  GumInvocationCallback probe = nullptr;
};

void *GumInvocationContext::Argument(std::uint32_t index) const noexcept {
  return api_->get_nth_argument(context_, index);
}

void GumInvocationContext::ReplaceArgument(std::uint32_t index,
                                           void *value) const noexcept {
  api_->replace_nth_argument(context_, index, value);
}

void *GumInvocationContext::ReturnValue() const noexcept {
  return api_->get_return_value(context_);
}

void GumInvocationContext::ReplaceReturnValue(void *value) const noexcept {
  api_->replace_return_value(context_, value);
}

void *GumInvocationContext::function() const noexcept {
  return api_->get_function(context_);
}

void *GumInvocationContext::cpu_context() const noexcept {
  return api_->get_cpu_context(context_);
}

void *GumInvocationContext::return_address() const noexcept {
  return api_->get_return_address(context_);
}

std::uint64_t GumInvocationContext::thread_id() const noexcept {
  return api_->get_thread_id(context_);
}

std::uint32_t GumInvocationContext::depth() const noexcept {
  return api_->get_depth(context_);
}

void *GumInvocationContext::listener_function_data() const noexcept {
  return api_->get_listener_function_data(context_);
}

void *GumInvocationContext::replacement_data() const noexcept {
  return api_->get_replacement_data(context_);
}

Result<std::shared_ptr<GumInterceptorRuntime>> GumInterceptorRuntime::Create(
    GumInterceptorApi api, const GumInterceptorRuntimeOptions &options) {
  const Status valid = ValidateApi(api, options);
  if (!valid.ok()) {
    return valid;
  }

  bool initialized = false;
  if (options.manage_embedded_lifecycle) {
    api.init_embedded();
    initialized = true;
  }

  void *const interceptor = api.obtain();
  if (interceptor == nullptr) {
    if (initialized) {
      api.deinit_embedded();
    }
    return Status(StatusCode::kUnavailable,
                  "gum_interceptor_obtain returned null");
  }

  auto runtime = std::shared_ptr<GumInterceptorRuntime>(
      new (std::nothrow) GumInterceptorRuntime(api, options, interceptor));
  if (runtime == nullptr) {
    api.object_unref(interceptor);
    if (initialized) {
      api.deinit_embedded();
    }
    return Status(StatusCode::kResourceExhausted,
                  "unable to allocate Gum interceptor runtime");
  }
  runtime->embedded_initialized_ = initialized;
  return runtime;
}

GumInterceptorRuntime::~GumInterceptorRuntime() noexcept {
  if (interceptor_ != nullptr) {
    api_.object_unref(interceptor_);
    interceptor_ = nullptr;
  }
  if (embedded_initialized_) {
    api_.deinit_embedded();
    embedded_initialized_ = false;
  }
}

void GumInterceptorRuntime::OnEnterThunk(void *context, void *data) noexcept {
  auto *state = static_cast<ListenerState *>(data);
  if (state != nullptr && state->callbacks.on_enter != nullptr) {
    GumInvocationContext wrapped(state->api, context);
    state->callbacks.on_enter(wrapped, state->callbacks.user_data);
  }
}

void GumInterceptorRuntime::OnLeaveThunk(void *context, void *data) noexcept {
  auto *state = static_cast<ListenerState *>(data);
  if (state != nullptr && state->callbacks.on_leave != nullptr) {
    GumInvocationContext wrapped(state->api, context);
    state->callbacks.on_leave(wrapped, state->callbacks.user_data);
  }
}

void GumInterceptorRuntime::OnProbeThunk(void *context, void *data) noexcept {
  auto *state = static_cast<ListenerState *>(data);
  if (state != nullptr && state->probe != nullptr) {
    GumInvocationContext wrapped(state->api, context);
    state->probe(wrapped, state->callbacks.user_data);
  }
}

void GumInterceptorRuntime::DestroyListenerState(void *data) noexcept {
  delete static_cast<ListenerState *>(data);
}

Result<std::unique_ptr<GumInlineHook>> GumInterceptorRuntime::Attach(
    void *target, GumInvocationCallbacks callbacks,
    const GumAttachOptions &options) {
  if (target == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Gum inline-hook target is null");
  }
  if (callbacks.on_enter == nullptr && callbacks.on_leave == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Gum inline hook requires an enter or leave callback");
  }

  std::lock_guard<std::recursive_mutex> lock(mutex_);
  auto *state = new (std::nothrow) ListenerState();
  if (state == nullptr) {
    return Status(StatusCode::kResourceExhausted,
                  "unable to allocate Gum listener state");
  }
  state->api = &api_;
  state->callbacks = callbacks;

  void *const listener = api_.make_call_listener(
      callbacks.on_enter != nullptr ? OnEnterThunk : nullptr,
      callbacks.on_leave != nullptr ? OnLeaveThunk : nullptr, state,
      DestroyListenerState);
  if (listener == nullptr) {
    delete state;
    return Status(StatusCode::kResourceExhausted,
                  "gum_make_call_listener returned null");
  }

  const int attached = api_.attach(interceptor_, target, listener,
                                   options.listener_function_data);
  if (attached != 0) {
    api_.object_unref(listener);
    return GumOperationError("attach", attached);
  }

  const Status flushed = MaybeFlushLocked();
  if (!flushed.ok()) {
    api_.detach(interceptor_, listener);
    (void)MaybeFlushLocked();
    api_.object_unref(listener);
    return flushed;
  }
  return std::unique_ptr<GumInlineHook>(
      new GumInlineHook(shared_from_this(), target, listener, false));
}

Result<std::unique_ptr<GumInlineHook>> GumInterceptorRuntime::Probe(
    void *instruction, GumInvocationCallback on_hit, void *user_data,
    const GumAttachOptions &options) {
  if (instruction == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Gum probe instruction is null");
  }
  if (on_hit == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Gum probe callback is null");
  }

  std::lock_guard<std::recursive_mutex> lock(mutex_);
  auto *state = new (std::nothrow) ListenerState();
  if (state == nullptr) {
    return Status(StatusCode::kResourceExhausted,
                  "unable to allocate Gum probe state");
  }
  state->api = &api_;
  state->callbacks.user_data = user_data;
  state->probe = on_hit;

  void *const listener = api_.make_probe_listener(
      OnProbeThunk, state, DestroyListenerState);
  if (listener == nullptr) {
    delete state;
    return Status(StatusCode::kResourceExhausted,
                  "gum_make_probe_listener returned null");
  }

  const int attached = api_.attach(interceptor_, instruction, listener,
                                   options.listener_function_data);
  if (attached != 0) {
    api_.object_unref(listener);
    return GumOperationError("probe attach", attached);
  }

  const Status flushed = MaybeFlushLocked();
  if (!flushed.ok()) {
    api_.detach(interceptor_, listener);
    (void)MaybeFlushLocked();
    api_.object_unref(listener);
    return flushed;
  }
  return std::unique_ptr<GumInlineHook>(
      new GumInlineHook(shared_from_this(), instruction, listener, true));
}

Result<std::unique_ptr<GumReplacementHook>> GumInterceptorRuntime::Replace(
    void *target, void *replacement, const GumReplaceOptions &options) {
  if (target == nullptr || replacement == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Gum replacement target and implementation must be non-null");
  }

  std::lock_guard<std::recursive_mutex> lock(mutex_);
  void *original = nullptr;
  const int replaced = api_.replace(interceptor_, target, replacement,
                                    options.replacement_data, &original);
  if (replaced != 0) {
    return GumOperationError("replace", replaced);
  }
  if (original == nullptr) {
    api_.revert(interceptor_, target);
    (void)MaybeFlushLocked();
    return Status(StatusCode::kPlatformError,
                  "Gum replace did not provide an original-function bridge");
  }

  const Status flushed = MaybeFlushLocked();
  if (!flushed.ok()) {
    api_.revert(interceptor_, target);
    (void)MaybeFlushLocked();
    return flushed;
  }
  return std::unique_ptr<GumReplacementHook>(new GumReplacementHook(
      shared_from_this(), target, replacement, original));
}

Result<std::unique_ptr<GumInterceptorTransaction>>
GumInterceptorRuntime::BeginTransaction() {
  std::unique_lock<std::recursive_mutex> lock(mutex_);
  api_.begin_transaction(interceptor_);
  ++transaction_depth_;
  return std::unique_ptr<GumInterceptorTransaction>(
      new GumInterceptorTransaction(shared_from_this(), std::move(lock)));
}

Status GumInterceptorRuntime::Flush() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (transaction_depth_ != 0U) {
    return {StatusCode::kUnavailable,
            "cannot explicitly flush an open Gum transaction"};
  }
  if (api_.flush(interceptor_) == 0) {
    return {StatusCode::kPlatformError, "gum_interceptor_flush failed"};
  }
  return Status::Ok();
}

std::optional<GumInvocationContext>
GumInterceptorRuntime::CurrentInvocation() const noexcept {
  void *const context = api_.get_current_invocation();
  if (context == nullptr) {
    return std::nullopt;
  }
  return GumInvocationContext(&api_, context);
}

Status GumInterceptorRuntime::MaybeFlushLocked() {
  if (!options_.auto_flush || transaction_depth_ != 0U) {
    return Status::Ok();
  }
  if (api_.flush(interceptor_) == 0) {
    return {StatusCode::kPlatformError, "gum_interceptor_flush failed"};
  }
  return Status::Ok();
}

Status GumInterceptorRuntime::DetachLocked(void *listener, bool *active) {
  if (active == nullptr || !*active) {
    return Status::Ok();
  }
  api_.detach(interceptor_, listener);
  *active = false;
  const Status flushed = MaybeFlushLocked();
  api_.object_unref(listener);
  return flushed;
}

Status GumInterceptorRuntime::RevertLocked(void *target, bool *active) {
  if (active == nullptr || !*active) {
    return Status::Ok();
  }
  api_.revert(interceptor_, target);
  *active = false;
  return MaybeFlushLocked();
}

GumInlineHook::~GumInlineHook() noexcept { (void)Detach(); }

Status GumInlineHook::Detach() {
  std::lock_guard<std::recursive_mutex> lock(runtime_->mutex_);
  const Status result = runtime_->DetachLocked(listener_, &active_);
  if (!active_) {
    listener_ = nullptr;
  }
  return result;
}

GumReplacementHook::~GumReplacementHook() noexcept { (void)Revert(); }

Status GumReplacementHook::Revert() {
  std::lock_guard<std::recursive_mutex> lock(runtime_->mutex_);
  return runtime_->RevertLocked(target_, &active_);
}

GumInterceptorTransaction::~GumInterceptorTransaction() noexcept {
  (void)Commit();
}

Status GumInterceptorTransaction::Commit() {
  if (!active_) {
    return Status::Ok();
  }
  runtime_->api_.end_transaction(runtime_->interceptor_);
  if (runtime_->transaction_depth_ != 0U) {
    --runtime_->transaction_depth_;
  }
  active_ = false;
  const Status flushed = runtime_->MaybeFlushLocked();
  lock_.unlock();
  return flushed;
}

} // namespace art_hook
