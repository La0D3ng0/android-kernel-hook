// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstdint>

#include "art_hook/art_method.h"
#include "art_hook/status.h"

namespace art_hook {

constexpr std::uint32_t kArtAccPublic = 0x00000001U;
constexpr std::uint32_t kArtAccPrivate = 0x00000002U;
constexpr std::uint32_t kArtAccProtected = 0x00000004U;
constexpr std::uint32_t kArtAccStatic = 0x00000008U;
constexpr std::uint32_t kArtAccFinal = 0x00000010U;
constexpr std::uint32_t kArtVisibilityMask =
    kArtAccPublic | kArtAccPrivate | kArtAccProtected;

struct ArtAccessFlagMutation final {
  std::uint32_t clear_mask = 0;
  std::uint32_t set_mask = 0;

  [[nodiscard]] Status Validate() const;
  [[nodiscard]] Result<std::uint32_t> Apply(std::uint32_t flags) const;
};

struct ArtHookAccessFlagOptions final {
  int android_api_level = 0;
  bool disable_fast_interpreter = true;
  bool disable_single_implementation = true;
  bool disable_nterp_fast_path = true;
  bool clear_skip_access_checks_for_non_native = true;
  bool prevent_compilation = true;

  // These alter Java-level semantics and are therefore explicit rather than
  // part of the default android.js-compatible target-method policy.
  bool make_public = false;
  bool remove_final = false;
  bool mark_native = false;
};

struct ArtAccessFlagUpdate final {
  std::uint32_t before = 0;
  std::uint32_t after = 0;

  [[nodiscard]] bool changed() const noexcept { return before != after; }
};

[[nodiscard]] Result<std::uint32_t>
GetArtCompileDontBotherFlag(int android_api_level);

[[nodiscard]] Result<ArtAccessFlagMutation>
BuildArtHookAccessFlagMutation(std::uint32_t current_flags,
                               const ArtHookAccessFlagOptions &options);

[[nodiscard]] Result<std::uint32_t>
ReadArtAccessFlagsSafe(const void *method, const ArtMethodLayout &layout,
                       ArtMutationGate &gate);

[[nodiscard]] Result<ArtAccessFlagUpdate>
WriteArtAccessFlagsSafe(void *method, const ArtMethodLayout &layout,
                        std::uint32_t flags, ArtMutationGate &gate);

[[nodiscard]] Result<ArtAccessFlagUpdate>
UpdateArtAccessFlagsSafe(void *method, const ArtMethodLayout &layout,
                         const ArtAccessFlagMutation &mutation,
                         ArtMutationGate &gate);

[[nodiscard]] Result<ArtAccessFlagUpdate>
ApplyArtHookAccessFlagsSafe(void *method, const ArtMethodLayout &layout,
                            const ArtHookAccessFlagOptions &options,
                            ArtMutationGate &gate);

} // namespace art_hook
