// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/art_method.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <utility>

namespace art_hook {
namespace {

std::recursive_mutex g_art_suspension_mutex;
thread_local std::size_t g_art_suspension_depth = 0;

Status CheckMappedRange(const void *address, std::size_t size,
                        bool require_write) {
  if (address == nullptr || size == 0) {
    return Status(StatusCode::kInvalidArgument,
                  "memory range is null or empty");
  }
  const auto start = reinterpret_cast<std::uintptr_t>(address);
  if (start > std::numeric_limits<std::uintptr_t>::max() - size) {
    return Status(StatusCode::kInvalidArgument, "memory range overflows");
  }
  const auto end = start + size;

#if defined(__linux__) || defined(__ANDROID__)
  /* stdio rather than iostreams: the ghost-loaded Mako image must stay free
   * of stream globals, and this probe runs on every layout lookup. */
  std::FILE *maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) {
    return Status(StatusCode::kIoError, "unable to open /proc/self/maps");
  }
  Status result(StatusCode::kNotFound,
                "ArtMethod range is not present in /proc/self/maps");
  char line[512];
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    unsigned long long mapping_start = 0;
    unsigned long long mapping_end = 0;
    char permissions[5] = {};
    if (std::sscanf(line, "%llx-%llx %4s", &mapping_start, &mapping_end,
                    permissions) != 3) {
      continue;
    }
    if (start >= mapping_start && end <= mapping_end) {
      if (permissions[0] != 'r') {
        result = Status(StatusCode::kUnavailable,
                        "ArtMethod range is not readable");
        break;
      }
      if (require_write && permissions[1] != 'w') {
        result = Status(StatusCode::kUnavailable,
                        "ArtMethod range is not writable");
        break;
      }
      result = Status::Ok();
      break;
    }
  }
  std::fclose(maps);
  return result;
#else
  (void)require_write;
  return Status::Ok();
#endif
}

template <typename T>
T ReadValue(const std::uint8_t *base, std::size_t offset) {
  T value{};
  std::memcpy(&value, base + offset, sizeof(value));
  return value;
}

bool ContainsPointer(std::uintptr_t value, std::uintptr_t start,
                     std::uintptr_t end) {
  return start < end && value >= start && value < end;
}

Status RunMutationOperation(const ArtMutationGate::Operation &operation) {
  try {
    return operation();
  } catch (const std::exception &error) {
    return Status(StatusCode::kPlatformError,
                  std::string("ART mutation threw: ") + error.what());
  } catch (...) {
    return Status(StatusCode::kPlatformError,
                  "ART mutation threw an unknown exception");
  }
}

} // namespace

Status ArtMethodLayout::Validate(std::size_t pointer_size) const {
  if (pointer_size != 4U && pointer_size != 8U) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod pointer size must be 4 or 8");
  }
  if (method_size == 0 || method_size > 512U) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod size is outside the supported range");
  }
  const auto field_fits = [this](std::size_t offset, std::size_t size) {
    return offset <= method_size && size <= method_size - offset;
  };
  if (!field_fits(access_flags_offset, sizeof(std::uint32_t)) ||
      !field_fits(jni_code_offset, pointer_size) ||
      !field_fits(quick_code_offset, pointer_size) ||
      (interpreter_code_offset.has_value() &&
       !field_fits(*interpreter_code_offset, pointer_size))) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod field offset lies outside the method");
  }
  if ((jni_code_offset % pointer_size) != 0 ||
      (quick_code_offset % pointer_size) != 0 ||
      (interpreter_code_offset.has_value() &&
       (*interpreter_code_offset % pointer_size) != 0)) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod pointer field is misaligned");
  }
  if ((access_flags_offset % alignof(std::uint32_t)) != 0) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod access flags are misaligned");
  }

  struct FieldRange final {
    std::size_t begin;
    std::size_t end;
  };
  std::array<FieldRange, 4> fields{};
  std::size_t count = 0;
  fields[count++] = {access_flags_offset,
                     access_flags_offset + sizeof(std::uint32_t)};
  fields[count++] = {jni_code_offset, jni_code_offset + pointer_size};
  fields[count++] = {quick_code_offset, quick_code_offset + pointer_size};
  if (interpreter_code_offset.has_value()) {
    fields[count++] = {*interpreter_code_offset,
                       *interpreter_code_offset + pointer_size};
  }
  for (std::size_t i = 0; i < count; ++i) {
    for (std::size_t j = i + 1U; j < count; ++j) {
      if (fields[i].begin < fields[j].end && fields[j].begin < fields[i].end) {
        return Status(StatusCode::kInvalidArgument, "ArtMethod fields overlap");
      }
    }
  }
  return Status::Ok();
}

Result<ArtMethodLayout> ProbeArtMethodLayout(const ArtMethodProbeSpec &spec) {
  if (spec.android_api_level < 21) {
    return Status(StatusCode::kUnsupported,
                  "ArtMethod probing requires Android 5.0 or newer");
  }
  if (spec.expected_jni_code_start >= spec.expected_jni_code_end) {
    return Status(StatusCode::kInvalidArgument,
                  "expected JNI code range is empty");
  }
  if (spec.relevant_access_flags_mask == 0U) {
    return Status(StatusCode::kInvalidArgument,
                  "relevant access-flags mask is empty");
  }
  Status mapped = CheckMappedRange(spec.method, 68U, false);
  if (!mapped.ok()) {
    return mapped;
  }

  const auto *bytes = static_cast<const std::uint8_t *>(spec.method);
  std::optional<std::size_t> jni_code_offset;
  std::optional<std::size_t> access_flags_offset;
  for (std::size_t offset = 0; offset < 64U; offset += 4U) {
    if (!jni_code_offset.has_value()) {
      const auto address = ReadValue<std::uintptr_t>(bytes, offset);
      if (ContainsPointer(address, spec.expected_jni_code_start,
                          spec.expected_jni_code_end)) {
        jni_code_offset = offset;
      }
    }
    if (!access_flags_offset.has_value()) {
      const auto flags = ReadValue<std::uint32_t>(bytes, offset);
      if ((flags & spec.relevant_access_flags_mask) ==
          (spec.expected_access_flags & spec.relevant_access_flags_mask)) {
        access_flags_offset = offset;
      }
    }
    if (jni_code_offset.has_value() && access_flags_offset.has_value()) {
      break;
    }
  }
  if (!jni_code_offset.has_value() || !access_flags_offset.has_value()) {
    return Status(StatusCode::kNotFound,
                  "unable to identify ArtMethod fields from probe method");
  }

  const std::size_t entrypoint_field_size =
      spec.android_api_level <= 21 ? 8U : sizeof(void *);
  ArtMethodLayout layout;
  layout.jni_code_offset = *jni_code_offset;
  layout.quick_code_offset = *jni_code_offset + entrypoint_field_size;
  layout.access_flags_offset = *access_flags_offset;
  layout.method_size = spec.android_api_level <= 21
                           ? layout.quick_code_offset + 32U
                           : layout.quick_code_offset + sizeof(void *);
  if (spec.has_interpreter_entrypoint) {
    if (layout.jni_code_offset < entrypoint_field_size) {
      return Status(StatusCode::kInvalidArgument,
                    "interpreter entrypoint would underflow ArtMethod");
    }
    layout.interpreter_code_offset =
        layout.jni_code_offset - entrypoint_field_size;
  }
  Status valid = layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  return layout;
}

Result<ArtMethodState> ReadArtMethodState(const void *method,
                                          const ArtMethodLayout &layout) {
  Status valid = layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  Status mapped = CheckMappedRange(method, layout.method_size, false);
  if (!mapped.ok()) {
    return mapped;
  }
  const auto *bytes = static_cast<const std::uint8_t *>(method);
  ArtMethodState state;
  state.access_flags =
      ReadValue<std::uint32_t>(bytes, layout.access_flags_offset);
  state.jni_code = ReadValue<void *>(bytes, layout.jni_code_offset);
  state.quick_code = ReadValue<void *>(bytes, layout.quick_code_offset);
  if (layout.interpreter_code_offset.has_value()) {
    state.interpreter_code =
        ReadValue<void *>(bytes, *layout.interpreter_code_offset);
  }
  return state;
}

Result<ArtHookFlagPlan> BuildArtHookFlagPlan(std::uint32_t original_flags,
                                             int android_api_level) {
  if (android_api_level < 21) {
    return Status(StatusCode::kUnsupported,
                  "ART hook flags require Android 5.0 or newer");
  }
  std::uint32_t compile_dont_bother = 0;
  if (android_api_level >= 27) {
    compile_dont_bother = 0x02000000U;
  } else if (android_api_level >= 24) {
    compile_dont_bother = 0x01000000U;
  }

  std::uint32_t removed_target_flags =
      kArtAccFastInterpreterToInterpreterInvoke | kArtAccSingleImplementation |
      kArtAccNterpEntryPointFastPath;
  if ((original_flags & kArtAccNative) == 0U) {
    removed_target_flags |= kArtAccSkipAccessChecks;
  }

  ArtHookFlagPlan plan;
  plan.target_flags =
      (original_flags & ~removed_target_flags) | compile_dont_bother;
  plan.replacement_flags =
      (original_flags & ~(kArtAccCriticalNative | kArtAccFastNative |
                          kArtAccNterpEntryPointFastPath)) |
      kArtAccNative | compile_dont_bother;
  return plan;
}

Status ArtThreadListMutationGate::Run(const Operation &operation) noexcept {
  if (thread_list_ == nullptr || suspend_all_ == nullptr ||
      resume_all_ == nullptr || !operation) {
    return Status(StatusCode::kInvalidArgument,
                  "ART thread suspension gate is incomplete");
  }

  // Android has one ART runtime per process. Coordinate every gate instance so
  // separate wrappers cannot overlap SuspendAll windows for the same runtime.
  std::lock_guard<std::recursive_mutex> lock(g_art_suspension_mutex);
  if (g_art_suspension_depth != 0U) {
    ++g_art_suspension_depth;
    Status nested_result = RunMutationOperation(operation);
    --g_art_suspension_depth;
    return nested_result;
  }

  try {
    suspend_all_(thread_list_, cause_.c_str(), false);
  } catch (const std::exception &error) {
    return Status(StatusCode::kPlatformError,
                  std::string("ART suspend threw: ") + error.what());
  } catch (...) {
    return Status(StatusCode::kPlatformError,
                  "ART suspend threw an unknown exception");
  }

  g_art_suspension_depth = 1U;
  Status result = RunMutationOperation(operation);
  g_art_suspension_depth = 0U;

  try {
    resume_all_(thread_list_);
  } catch (const std::exception &error) {
    return Status(StatusCode::kPlatformError,
                  std::string("ART resume threw: ") + error.what());
  } catch (...) {
    return Status(StatusCode::kPlatformError,
                  "ART resume threw an unknown exception");
  }
  return result;
}

Result<ArtMethodClone> CloneArtMethod(const void *method,
                                      const ArtMethodLayout &layout,
                                      int android_api_level) {
  if (android_api_level < 23) {
    return Status(
        StatusCode::kUnsupported,
        "Android 5.x ArtMethod cloning requires mirror::Object::Clone");
  }
  Status valid = layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  Status mapped = CheckMappedRange(method, layout.method_size, false);
  if (!mapped.ok()) {
    return mapped;
  }
  ArtMethodClone clone;
  clone.bytes_.resize(layout.method_size);
  std::memcpy(clone.bytes_.data(), method, layout.method_size);
  return clone;
}

Result<ArtMethodPatch> ArtMethodPatch::Create(void *method,
                                              ArtMethodLayout layout) {
  Status valid = layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  Status mapped = CheckMappedRange(method, layout.method_size, true);
  if (!mapped.ok()) {
    return mapped;
  }
  std::vector<std::uint8_t> original(layout.method_size);
  std::memcpy(original.data(), method, original.size());
  return ArtMethodPatch(method, std::move(layout), std::move(original));
}

ArtMethodState ArtMethodPatch::original_state() const noexcept {
  ArtMethodState state;
  state.access_flags =
      ReadValue<std::uint32_t>(original_.data(), layout_.access_flags_offset);
  state.jni_code = ReadValue<void *>(original_.data(), layout_.jni_code_offset);
  state.quick_code =
      ReadValue<void *>(original_.data(), layout_.quick_code_offset);
  if (layout_.interpreter_code_offset.has_value()) {
    state.interpreter_code =
        ReadValue<void *>(original_.data(), *layout_.interpreter_code_offset);
  }
  return state;
}

Status ArtMethodPatch::SetAccessFlags(std::uint32_t value) {
  return StageBytes(layout_.access_flags_offset, &value, sizeof(value));
}

Status ArtMethodPatch::SetJniCode(void *value) {
  return StagePointer(layout_.jni_code_offset, value, "JNI code");
}

Status ArtMethodPatch::SetQuickCode(void *value) {
  return StagePointer(layout_.quick_code_offset, value, "quick code");
}

Status ArtMethodPatch::SetInterpreterCode(void *value) {
  if (!layout_.interpreter_code_offset.has_value()) {
    return Status(StatusCode::kUnsupported,
                  "ArtMethod layout has no interpreter entrypoint");
  }
  return StagePointer(*layout_.interpreter_code_offset, value,
                      "interpreter code");
}

Status ArtMethodPatch::StagePointer(std::size_t offset, void *value,
                                    const char *field_name) {
  if (value == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  std::string(field_name) + " pointer is null");
  }
  if ((reinterpret_cast<std::uintptr_t>(value) & 3U) != 0U) {
    return Status(StatusCode::kInvalidArgument,
                  std::string(field_name) +
                      " pointer is not instruction aligned");
  }
  return StageBytes(offset, &value, sizeof(value));
}

Status ArtMethodPatch::StageBytes(std::size_t offset, const void *value,
                                  std::size_t size) {
  if (applied_) {
    return Status(StatusCode::kUnavailable,
                  "cannot alter an applied ArtMethod patch");
  }
  if (value == nullptr || offset > staged_.size() ||
      size > staged_.size() - offset) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod staged field is out of range");
  }
  std::memcpy(staged_.data() + offset, value, size);
  const auto matching = [offset, size](const DirtyField &field) {
    return field.offset == offset && field.size == size;
  };
  const auto existing = std::find_if(dirty_.begin(), dirty_.end(), matching);
  const bool changed = std::memcmp(staged_.data() + offset,
                                   original_.data() + offset, size) != 0;
  if (!changed && existing != dirty_.end()) {
    dirty_.erase(existing);
  } else if (changed && existing == dirty_.end()) {
    dirty_.push_back({offset, size});
  }
  return Status::Ok();
}

Status ArtMethodPatch::Commit(ArtMutationGate &gate) {
  if (method_ == nullptr) {
    return Status(StatusCode::kUnavailable, "ArtMethod patch was moved from");
  }
  if (applied_) {
    return Status(StatusCode::kUnavailable,
                  "ArtMethod patch is already applied");
  }
  if (dirty_.empty()) {
    return Status(StatusCode::kInvalidArgument,
                  "ArtMethod patch has no staged fields");
  }
  Status status = gate.Run([this] { return WriteDirty(staged_, original_); });
  if (status.ok()) {
    applied_ = true;
  }
  return status;
}

Status ArtMethodPatch::Revert(ArtMutationGate &gate) {
  if (method_ == nullptr) {
    return Status(StatusCode::kUnavailable, "ArtMethod patch was moved from");
  }
  if (!applied_) {
    return Status(StatusCode::kUnavailable, "ArtMethod patch is not applied");
  }
  Status status = gate.Run([this] { return WriteDirty(original_, staged_); });
  if (status.ok()) {
    applied_ = false;
  }
  return status;
}

Status ArtMethodPatch::WriteDirty(const std::vector<std::uint8_t> &source,
                                  const std::vector<std::uint8_t> &expected) {
  Status mapped = CheckMappedRange(method_, layout_.method_size, true);
  if (!mapped.ok()) {
    return mapped;
  }
  auto *destination = static_cast<std::uint8_t *>(method_);
  for (const auto &field : dirty_) {
    if (std::memcmp(destination + field.offset, expected.data() + field.offset,
                    field.size) != 0) {
      return Status(StatusCode::kUnavailable,
                    "ArtMethod changed after the patch snapshot");
    }
  }
  for (const auto &field : dirty_) {
    std::memcpy(destination + field.offset, source.data() + field.offset,
                field.size);
  }
  std::atomic_thread_fence(std::memory_order_seq_cst);
  return Status::Ok();
}

} // namespace art_hook
