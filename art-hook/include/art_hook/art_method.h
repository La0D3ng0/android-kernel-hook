// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "art_hook/status.h"

namespace art_hook {

struct ArtMethodLayout final {
  std::size_t method_size = 0;
  std::size_t access_flags_offset = 0;
  std::size_t jni_code_offset = 0;
  std::size_t quick_code_offset = 0;
  std::optional<std::size_t> interpreter_code_offset;

  [[nodiscard]] Status
  Validate(std::size_t pointer_size = sizeof(void *)) const;
};

struct ArtMethodProbeSpec final {
  void *method = nullptr;
  std::uintptr_t expected_jni_code_start = 0;
  std::uintptr_t expected_jni_code_end = 0;
  std::uint32_t expected_access_flags = 0;
  std::uint32_t relevant_access_flags_mask = 0xffffffffU;
  int android_api_level = 0;
  bool has_interpreter_entrypoint = false;
};

[[nodiscard]] Result<ArtMethodLayout>
ProbeArtMethodLayout(const ArtMethodProbeSpec &spec);

struct ArtMethodState final {
  std::uint32_t access_flags = 0;
  void *jni_code = nullptr;
  void *quick_code = nullptr;
  std::optional<void *> interpreter_code;
};

constexpr std::uint32_t kArtAccNative = 0x00000100U;
constexpr std::uint32_t kArtAccFastNative = 0x00080000U;
constexpr std::uint32_t kArtAccCriticalNative = 0x00200000U;
constexpr std::uint32_t kArtAccNterpEntryPointFastPath = 0x00100000U;
constexpr std::uint32_t kArtAccSingleImplementation = 0x08000000U;
constexpr std::uint32_t kArtAccFastInterpreterToInterpreterInvoke = 0x40000000U;
constexpr std::uint32_t kArtAccSkipAccessChecks = 0x00080000U;

struct ArtHookFlagPlan final {
  std::uint32_t target_flags = 0;
  std::uint32_t replacement_flags = 0;
};

// Mirrors the versioned flag policy used by android.js. It does not perform
// deoptimization; callers must still arrange that through a validated ART
// instrumentation backend when compiled direct calls need to be redirected.
[[nodiscard]] Result<ArtHookFlagPlan>
BuildArtHookFlagPlan(std::uint32_t original_flags, int android_api_level);

[[nodiscard]] Result<ArtMethodState>
ReadArtMethodState(const void *method, const ArtMethodLayout &layout);

class ArtMutationGate {
public:
  using Operation = std::function<Status()>;

  virtual ~ArtMutationGate() = default;
  [[nodiscard]] virtual Status Run(const Operation &operation) noexcept = 0;
};

// Adapter for art::ThreadList::SuspendAll/ResumeAll. The caller must provide a
// validated ThreadList pointer and version-correct function wrappers.
class ArtThreadListMutationGate final : public ArtMutationGate {
public:
  using SuspendAll = void (*)(void *thread_list, const char *cause,
                              bool long_suspend);
  using ResumeAll = void (*)(void *thread_list);

  ArtThreadListMutationGate(void *thread_list, SuspendAll suspend_all,
                            ResumeAll resume_all,
                            std::string cause = "art-hook")
      : thread_list_(thread_list), suspend_all_(suspend_all),
        resume_all_(resume_all), cause_(std::move(cause)) {}

  [[nodiscard]] Status Run(const Operation &operation) noexcept override;

private:
  void *thread_list_ = nullptr;
  SuspendAll suspend_all_ = nullptr;
  ResumeAll resume_all_ = nullptr;
  std::string cause_;
};

class ArtMethodClone final {
public:
  [[nodiscard]] void *data() noexcept { return bytes_.data(); }
  [[nodiscard]] const void *data() const noexcept { return bytes_.data(); }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }

private:
  friend Result<ArtMethodClone> CloneArtMethod(const void *,
                                               const ArtMethodLayout &, int);
  std::vector<std::uint8_t> bytes_;
};

[[nodiscard]] Result<ArtMethodClone>
CloneArtMethod(const void *method, const ArtMethodLayout &layout,
               int android_api_level);

class ArtMethodPatch final {
public:
  ArtMethodPatch(const ArtMethodPatch &) = delete;
  ArtMethodPatch &operator=(const ArtMethodPatch &) = delete;
  ArtMethodPatch(ArtMethodPatch &&other) noexcept
      : method_(std::exchange(other.method_, nullptr)),
        layout_(std::move(other.layout_)),
        original_(std::move(other.original_)),
        staged_(std::move(other.staged_)), dirty_(std::move(other.dirty_)),
        applied_(std::exchange(other.applied_, false)) {}
  ArtMethodPatch &operator=(ArtMethodPatch &&) = delete;

  [[nodiscard]] static Result<ArtMethodPatch> Create(void *method,
                                                     ArtMethodLayout layout);

  [[nodiscard]] Status SetAccessFlags(std::uint32_t value);
  [[nodiscard]] Status SetJniCode(void *value);
  [[nodiscard]] Status SetQuickCode(void *value);
  [[nodiscard]] Status SetInterpreterCode(void *value);

  [[nodiscard]] Status Commit(ArtMutationGate &gate);
  [[nodiscard]] Status Revert(ArtMutationGate &gate);

  [[nodiscard]] bool applied() const noexcept { return applied_; }
  [[nodiscard]] ArtMethodState original_state() const noexcept;
  [[nodiscard]] const ArtMethodLayout &layout() const noexcept {
    return layout_;
  }

private:
  struct DirtyField final {
    std::size_t offset;
    std::size_t size;
  };

  ArtMethodPatch(void *method, ArtMethodLayout layout,
                 std::vector<std::uint8_t> original)
      : method_(method), layout_(std::move(layout)), original_(original),
        staged_(std::move(original)) {}

  [[nodiscard]] Status StagePointer(std::size_t offset, void *value,
                                    const char *field_name);
  [[nodiscard]] Status StageBytes(std::size_t offset, const void *value,
                                  std::size_t size);
  [[nodiscard]] Status WriteDirty(const std::vector<std::uint8_t> &source,
                                  const std::vector<std::uint8_t> &expected);

  void *method_ = nullptr;
  ArtMethodLayout layout_;
  std::vector<std::uint8_t> original_;
  std::vector<std::uint8_t> staged_;
  std::vector<DirtyField> dirty_;
  bool applied_ = false;
};

} // namespace art_hook
