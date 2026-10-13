// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/art_quick_hook.h"

#include <cstdint>
#include <utility>

namespace art_hook {

ArtQuickHook::~ArtQuickHook() noexcept {
  if (!patch_.applied()) {
    return;
  }

  const Status status = patch_.Revert(*gate_);
  if (!status.ok()) {
    // Keeping the executable mapping alive is safer than freeing code still
    // referenced by an ArtMethod. Callers should still deactivate explicitly
    // so a rollback error can be observed and handled.
    (void)trampoline_.release();
  }
}

Result<std::unique_ptr<ArtQuickHook>>
ArtQuickHook::Create(void *method, ArtMethodLayout layout,
                     Arm64Dispatch dispatch, void *user_data,
                     std::shared_ptr<ArtMutationGate> gate,
                     const ArtQuickHookOptions &options) {
  if (gate == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Art quick hook mutation gate is null");
  }

  auto patch = ArtMethodPatch::Create(method, std::move(layout));
  if (!patch.ok()) {
    return patch.status();
  }
  ArtMethodState original = patch.value().original_state();
  if (original.quick_code == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod quick entrypoint is null");
  }

  auto trampoline = Arm64Trampoline::Create(dispatch, user_data);
  if (!trampoline.ok()) {
    return trampoline.status();
  }
  Status staged = patch.value().SetQuickCode(trampoline.value()->entrypoint());
  if (staged.ok() && options.access_flags.has_value()) {
    staged = patch.value().SetAccessFlags(*options.access_flags);
  }
  if (staged.ok() && options.jni_code.has_value()) {
    staged = patch.value().SetJniCode(*options.jni_code);
  }
  if (staged.ok() && options.interpreter_code.has_value()) {
    staged = patch.value().SetInterpreterCode(*options.interpreter_code);
  }
  if (!staged.ok()) {
    return staged;
  }

  return std::unique_ptr<ArtQuickHook>(
      new ArtQuickHook(std::move(trampoline).value(), std::move(patch).value(),
                       std::move(original), std::move(gate)));
}

Status ArtQuickHook::Activate() { return patch_.Commit(*gate_); }

Status ArtQuickHook::Deactivate() { return patch_.Revert(*gate_); }

Result<std::unique_ptr<ArtQuickHook>>
HookMethodSafe(void *method, ArtMethodLayout layout, Arm64Dispatch dispatch,
               void *user_data, std::shared_ptr<ArtMutationGate> gate,
               const ArtQuickHookOptions &options) {
  auto hook = ArtQuickHook::Create(method, std::move(layout), dispatch,
                                   user_data, std::move(gate), options);
  if (!hook.ok()) {
    return hook.status();
  }
  Status activated = hook.value()->Activate();
  if (!activated.ok()) {
    return activated;
  }
  return std::move(hook).value();
}

} // namespace art_hook
