// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/art_entrypoint.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <utility>

#include "art_hook/art_deoptimization.h"
#include "art_hook/jni_types.h"

namespace art_hook {
namespace {

constexpr std::size_t kMaximumInvocationDepth = 128;

struct InvocationFrame final {
  const void *state = nullptr;
  std::atomic<std::size_t> *in_flight = nullptr;
  std::uint64_t return_address = 0;
  std::uint64_t entry_sp = 0;
};

struct InvocationStack final {
  std::array<InvocationFrame, kMaximumInvocationDepth> frames{};
  std::size_t size = 0;
};

thread_local InvocationStack g_invocations;

void DiscardFrame(std::size_t index) noexcept {
  InvocationFrame &frame = g_invocations.frames[index];
  if (frame.in_flight != nullptr) {
    frame.in_flight->fetch_sub(1U, std::memory_order_acq_rel);
  }
  frame = {};
}

void PruneUnwoundFrames(std::uint64_t current_sp) noexcept {
  while (g_invocations.size != 0U &&
         g_invocations.frames[g_invocations.size - 1U].entry_sp < current_sp) {
    DiscardFrame(g_invocations.size - 1U);
    --g_invocations.size;
  }
}

} // namespace

struct ArtMethodInterceptor::State final {
  ArtMethodCallbacks callbacks;
  std::atomic<void *> original_quick_code{nullptr};
  void *leave_entrypoint = nullptr;
  std::atomic<std::size_t> in_flight{0};
};

ArtMethodInterceptor::ArtMethodInterceptor(
    void *method, ArtMethodLayout layout, ArtQuickHookOptions options,
    std::shared_ptr<ArtMutationGate> mutation_gate,
    std::unique_ptr<State> state,
    std::unique_ptr<Arm64Trampoline> leave_trampoline)
    : method_(method), layout_(std::move(layout)), options_(std::move(options)),
      mutation_gate_(std::move(mutation_gate)), state_(std::move(state)),
      leave_trampoline_(std::move(leave_trampoline)) {}

Result<ResolvedArtMethod> ResolveArtMethod(Env env,
                                           const ArtMethodSelector &selector,
                                           ArtMethodIdDecoder decoder,
                                           void *decoder_user_data) {
  if (env.get() == nullptr || selector.class_name.empty() ||
      selector.method_name.empty() || selector.descriptor.empty() ||
      decoder == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "method resolution requires class, name, descriptor, and "
                  "an ArtMethod ID decoder");
  }
  auto descriptor = ParseMethodDescriptor(selector.descriptor);
  if (!descriptor.ok()) {
    return descriptor.status();
  }

  std::string class_name = selector.class_name;
  if (class_name.size() >= 2U && class_name.front() == 'L' &&
      class_name.back() == ';') {
    class_name = class_name.substr(1, class_name.size() - 2U);
  }
  std::replace(class_name.begin(), class_name.end(), '.', '/');
  auto klass = env.FindClass(class_name.c_str());
  if (!klass.ok()) {
    return klass.status();
  }

  JNIEnv *jni = env.get();
  jmethodID method_id =
      selector.is_static
          ? jni->GetStaticMethodID(klass.value().get(),
                                   selector.method_name.c_str(),
                                   selector.descriptor.c_str())
          : jni->GetMethodID(klass.value().get(), selector.method_name.c_str(),
                             selector.descriptor.c_str());
  Status exception = env.ExceptionStatus("ArtMethod lookup");
  if (!exception.ok()) {
    return exception;
  }
  if (method_id == nullptr) {
    return Status(StatusCode::kNotFound, "Java method was not found");
  }
  void *method = decoder(method_id, decoder_user_data);
  if (method == nullptr) {
    return Status(StatusCode::kUnavailable,
                  "ArtMethod ID decoder rejected the JNI method ID");
  }
  return ResolvedArtMethod{method_id, method};
}

void *DirectArtMethodIdDecoder(jmethodID method_id, void *) noexcept {
  return reinterpret_cast<void *>(method_id);
}

Result<std::unique_ptr<ArtMethodInterceptor>>
ArtMethodInterceptor::Create(void *method, ArtMethodLayout layout,
                             ArtMethodCallbacks callbacks,
                             std::shared_ptr<ArtMutationGate> mutation_gate,
                             ArtQuickHookOptions options) {
  if (callbacks.on_enter == nullptr && callbacks.on_leave == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod interceptor has no callbacks");
  }
  if (mutation_gate == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod interceptor mutation gate is null");
  }
  Status valid = layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  auto current = ReadArtMethodState(method, layout);
  if (!current.ok()) {
    return current.status();
  }
  if (current.value().quick_code == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod quick entrypoint is null");
  }

  auto state = std::make_unique<State>();
  state->callbacks = callbacks;
  auto leave = Arm64Trampoline::Create(LeaveDispatch, state.get());
  if (!leave.ok()) {
    return leave.status();
  }
  state->leave_entrypoint = leave.value()->entrypoint();

  return std::unique_ptr<ArtMethodInterceptor>(new ArtMethodInterceptor(
      method, std::move(layout), std::move(options), std::move(mutation_gate),
      std::move(state), std::move(leave).value()));
}

ArtMethodInterceptor::~ArtMethodInterceptor() noexcept {
  if (entry_hook_ != nullptr && entry_hook_->active()) {
    const Status ignored = entry_hook_->Deactivate();
    (void)ignored;
  }
  if (ever_activated_) {
    // A thread may have been suspended inside either generated trampoline and
    // resume after the ArtMethod is restored. Conservatively retire executable
    // mappings and callback state for process lifetime instead of unmapping a
    // possibly live PC/LR target.
    (void)entry_hook_.release();
    (void)leave_trampoline_.release();
    (void)state_.release();
  }
}

Status ArtMethodInterceptor::Activate() {
  return ActivateAfterDeoptimization();
}

Status ArtMethodInterceptor::Activate(ArtDeoptimizer &deoptimizer) {
  if (active()) {
    return Status(StatusCode::kUnavailable,
                  "ArtMethod interceptor is already active");
  }
  Status deoptimized = deoptimizer.DeoptimizeMethod(method_);
  if (!deoptimized.ok()) {
    return deoptimized;
  }
  return ActivateAfterDeoptimization();
}

Status ArtMethodInterceptor::ActivateAfterDeoptimization() {
  if (active()) {
    return Status(StatusCode::kUnavailable,
                  "ArtMethod interceptor is already active");
  }

  if (entry_hook_ != nullptr) {
    state_->original_quick_code.store(entry_hook_->original_quick_code(),
                                      std::memory_order_release);
    return entry_hook_->Activate();
  }

  auto hook = ArtQuickHook::Create(method_, layout_, EnterDispatch,
                                   state_.get(), mutation_gate_, options_);
  if (!hook.ok()) {
    return hook.status();
  }
  state_->original_quick_code.store(hook.value()->original_quick_code(),
                                    std::memory_order_release);
  Status activated = hook.value()->Activate();
  if (!activated.ok()) {
    state_->original_quick_code.store(nullptr, std::memory_order_release);
    return activated;
  }
  entry_hook_ = std::move(hook).value();
  ever_activated_ = true;
  return Status::Ok();
}

Status ArtMethodInterceptor::Deactivate() {
  if (!active()) {
    return Status(StatusCode::kUnavailable,
                  "ArtMethod interceptor is not active");
  }
  return entry_hook_->Deactivate();
}

bool ArtMethodInterceptor::active() const noexcept {
  return entry_hook_ != nullptr && entry_hook_->active();
}

std::size_t ArtMethodInterceptor::in_flight() const noexcept {
  return state_->in_flight.load(std::memory_order_acquire);
}

void *ArtMethodInterceptor::original_quick_code() const noexcept {
  return state_->original_quick_code.load(std::memory_order_acquire);
}

void *ArtMethodInterceptor::entrypoint() const noexcept {
  return entry_hook_ == nullptr ? nullptr
                                : entry_hook_->trampoline_entrypoint();
}

void *ArtMethodInterceptor::EnterDispatch(Arm64CpuContext *context,
                                          void *user_data) noexcept {
  auto *state = static_cast<State *>(user_data);
  void *const original =
      state->original_quick_code.load(std::memory_order_acquire);
  if (original == nullptr) {
    return nullptr;
  }

  PruneUnwoundFrames(context->sp);
  if (g_invocations.size == kMaximumInvocationDepth) {
    return original;
  }

  InvocationFrame &frame = g_invocations.frames[g_invocations.size++];
  frame.state = state;
  frame.in_flight = &state->in_flight;
  frame.return_address = context->x[30];
  frame.entry_sp = context->sp;
  state->in_flight.fetch_add(1U, std::memory_order_acq_rel);

  if (state->callbacks.on_enter != nullptr) {
    state->callbacks.on_enter(context, state->callbacks.user_data);
  }
  context->x[30] = reinterpret_cast<std::uintptr_t>(state->leave_entrypoint);
  return original;
}

void *ArtMethodInterceptor::LeaveDispatch(Arm64CpuContext *context,
                                          void *user_data) noexcept {
  auto *state = static_cast<State *>(user_data);
  PruneUnwoundFrames(context->sp);

  std::size_t index = g_invocations.size;
  while (index != 0U) {
    --index;
    if (g_invocations.frames[index].state == state) {
      break;
    }
  }
  if (g_invocations.size == 0U || g_invocations.frames[index].state != state) {
    std::abort();
  }

  const InvocationFrame frame = g_invocations.frames[index];
  for (std::size_t stale = g_invocations.size; stale > index + 1U;) {
    --stale;
    DiscardFrame(stale);
  }
  g_invocations.frames[index] = {};
  g_invocations.size = index;
  context->x[30] = frame.return_address;
  if (state->callbacks.on_leave != nullptr) {
    state->callbacks.on_leave(context, state->callbacks.user_data);
  }
  state->in_flight.fetch_sub(1U, std::memory_order_acq_rel);
  return nullptr;
}

} // namespace art_hook
