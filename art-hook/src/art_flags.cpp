// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/art_flags.h"

#include <functional>
#include <optional>
#include <utility>

namespace art_hook {
namespace {

using FlagTargetBuilder =
    std::function<Result<std::uint32_t>(std::uint32_t current_flags)>;

Result<ArtAccessFlagUpdate>
MutateArtAccessFlagsSafe(void *method, const ArtMethodLayout &layout,
                         const FlagTargetBuilder &build_target,
                         ArtMutationGate &gate) {
  if (method == nullptr || !build_target) {
    return Status(StatusCode::kInvalidArgument,
                  "safe access-flags update is incomplete");
  }

  std::optional<ArtAccessFlagUpdate> update;
  Status status = gate.Run([&] {
    auto state = ReadArtMethodState(method, layout);
    if (!state.ok()) {
      return state.status();
    }
    auto target = build_target(state.value().access_flags);
    if (!target.ok()) {
      return target.status();
    }

    update = ArtAccessFlagUpdate{state.value().access_flags, target.value()};
    if (!update->changed()) {
      return Status::Ok();
    }

    auto patch = ArtMethodPatch::Create(method, layout);
    if (!patch.ok()) {
      return patch.status();
    }
    Status staged = patch.value().SetAccessFlags(target.value());
    if (!staged.ok()) {
      return staged;
    }
    // This is intentionally nested. ArtThreadListMutationGate keeps the outer
    // STW window and does not call SuspendAll a second time.
    return patch.value().Commit(gate);
  });
  if (!status.ok()) {
    return status;
  }
  if (!update.has_value()) {
    return Status(StatusCode::kPlatformError,
                  "safe access-flags update produced no result");
  }
  return *update;
}

} // namespace

Status ArtAccessFlagMutation::Validate() const {
  if ((clear_mask & set_mask) != 0U) {
    return Status(StatusCode::kInvalidArgument,
                  "access flag clear/set masks overlap");
  }
  return Status::Ok();
}

Result<std::uint32_t> ArtAccessFlagMutation::Apply(std::uint32_t flags) const {
  Status valid = Validate();
  if (!valid.ok()) {
    return valid;
  }
  return (flags & ~clear_mask) | set_mask;
}

Result<std::uint32_t> GetArtCompileDontBotherFlag(int android_api_level) {
  if (android_api_level < 21) {
    return Status(StatusCode::kUnsupported,
                  "ART access flags require Android 5.0+");
  }
  if (android_api_level >= 27) {
    return 0x02000000U;
  }
  if (android_api_level >= 24) {
    return 0x01000000U;
  }
  return 0U;
}

Result<ArtAccessFlagMutation>
BuildArtHookAccessFlagMutation(std::uint32_t current_flags,
                               const ArtHookAccessFlagOptions &options) {
  auto compile_dont_bother =
      GetArtCompileDontBotherFlag(options.android_api_level);
  if (!compile_dont_bother.ok()) {
    return compile_dont_bother.status();
  }

  ArtAccessFlagMutation mutation;
  if (options.disable_fast_interpreter) {
    mutation.clear_mask |= kArtAccFastInterpreterToInterpreterInvoke;
  }
  if (options.disable_single_implementation) {
    mutation.clear_mask |= kArtAccSingleImplementation;
  }
  if (options.disable_nterp_fast_path) {
    mutation.clear_mask |= kArtAccNterpEntryPointFastPath;
  }
  if (options.clear_skip_access_checks_for_non_native &&
      (current_flags & kArtAccNative) == 0U) {
    mutation.clear_mask |= kArtAccSkipAccessChecks;
  }
  if (options.prevent_compilation) {
    mutation.set_mask |= compile_dont_bother.value();
  }
  if (options.make_public) {
    mutation.clear_mask |= kArtAccPrivate | kArtAccProtected;
    mutation.set_mask |= kArtAccPublic;
  }
  if (options.remove_final) {
    mutation.clear_mask |= kArtAccFinal;
  }
  if (options.mark_native) {
    mutation.clear_mask |= kArtAccCriticalNative | kArtAccFastNative;
    mutation.set_mask |= kArtAccNative;
  }

  Status valid = mutation.Validate();
  if (!valid.ok()) {
    return valid;
  }
  return mutation;
}

Result<std::uint32_t> ReadArtAccessFlagsSafe(const void *method,
                                             const ArtMethodLayout &layout,
                                             ArtMutationGate &gate) {
  if (method == nullptr) {
    return Status(StatusCode::kInvalidArgument, "ArtMethod is null");
  }
  std::optional<std::uint32_t> flags;
  Status status = gate.Run([&] {
    auto state = ReadArtMethodState(method, layout);
    if (!state.ok()) {
      return state.status();
    }
    flags = state.value().access_flags;
    return Status::Ok();
  });
  if (!status.ok()) {
    return status;
  }
  if (!flags.has_value()) {
    return Status(StatusCode::kPlatformError,
                  "safe access-flags read produced no result");
  }
  return *flags;
}

Result<ArtAccessFlagUpdate>
WriteArtAccessFlagsSafe(void *method, const ArtMethodLayout &layout,
                        std::uint32_t flags, ArtMutationGate &gate) {
  return MutateArtAccessFlagsSafe(
      method, layout,
      [flags](std::uint32_t) -> Result<std::uint32_t> { return flags; }, gate);
}

Result<ArtAccessFlagUpdate>
UpdateArtAccessFlagsSafe(void *method, const ArtMethodLayout &layout,
                         const ArtAccessFlagMutation &mutation,
                         ArtMutationGate &gate) {
  Status valid = mutation.Validate();
  if (!valid.ok()) {
    return valid;
  }
  return MutateArtAccessFlagsSafe(
      method, layout,
      [&mutation](std::uint32_t current) { return mutation.Apply(current); },
      gate);
}

Result<ArtAccessFlagUpdate>
ApplyArtHookAccessFlagsSafe(void *method, const ArtMethodLayout &layout,
                            const ArtHookAccessFlagOptions &options,
                            ArtMutationGate &gate) {
  return MutateArtAccessFlagsSafe(
      method, layout,
      [&options](std::uint32_t current) -> Result<std::uint32_t> {
        auto mutation = BuildArtHookAccessFlagMutation(current, options);
        if (!mutation.ok()) {
          return mutation.status();
        }
        return mutation.value().Apply(current);
      },
      gate);
}

} // namespace art_hook
