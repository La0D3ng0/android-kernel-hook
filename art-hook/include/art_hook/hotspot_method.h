// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "art_hook/status.h"

namespace art_hook {

constexpr std::uint32_t kJvmAccNative = 0x00000100U;
constexpr std::uint32_t kJvmAccIsOld = 0x00010000U;
constexpr std::uint32_t kJvmAccIsObsolete = 0x00020000U;
constexpr std::uint32_t kJvmAccNotC2Compilable = 0x02000000U;
constexpr std::uint32_t kJvmAccNotC1Compilable = 0x04000000U;
constexpr std::uint32_t kJvmAccNotC2OsrCompilable = 0x08000000U;

enum class HotSpotAdapterLocation {
  kMethodEarly,
  kConstMethod,
  kMethodLate,
};

// Layout derived by jvm.js from the JDK version and Method::size(true).
struct HotSpotMethodLayout final {
  int jvm_version = 0;
  std::size_t pointer_size = 0;
  std::size_t method_size = 0;
  HotSpotAdapterLocation adapter_location =
      HotSpotAdapterLocation::kMethodLate;

  std::size_t const_method_offset = 0;
  std::size_t method_data_offset = 0;
  std::size_t method_counters_offset = 0;
  std::size_t adapter_offset = 0;
  std::size_t access_flags_offset = 0;
  std::size_t vtable_index_offset = 0;
  std::size_t i2i_entry_offset = 0;
  std::size_t native_function_offset = 0;
  std::size_t signature_handler_offset = 0;

  std::size_t constant_pool_offset = 0;
  std::size_t stackmap_data_offset = 0;
  std::size_t const_method_size_offset = 0;
  std::size_t method_idnum_offset = 0;
  std::size_t constant_pool_cache_offset = 0;
  std::size_t constant_pool_instance_klass_offset = 0;

  [[nodiscard]] Status Validate() const;
};

[[nodiscard]] Result<HotSpotMethodLayout> BuildHotSpotMethodLayout(
    int jvm_version, std::size_t pointer_size,
    std::size_t native_method_size);

// The vtable offset is instruction-probed by the embedding backend, exactly as
// jvm.js probes create_new_default_vtable_indices on x64.
struct HotSpotInstanceKlassLayout final {
  std::size_t pointer_size = 0;
  std::size_t vtable_offset = 0;
  std::size_t methods_offset = 0;
  std::size_t member_names_offset = 0;
  std::size_t oop_map_cache_offset = 0;

  [[nodiscard]] Status Validate() const;
};

[[nodiscard]] Result<HotSpotInstanceKlassLayout>
BuildHotSpotInstanceKlassLayout(int jvm_version, std::size_t pointer_size,
                                std::size_t vtable_offset);

struct HotSpotMethodRecord final {
  void* method = nullptr;
  void* const_method = nullptr;
  std::size_t const_method_size = 0;

  void* const_method_pointer = nullptr;
  void* method_data_pointer = nullptr;
  void* method_counters_pointer = nullptr;
  void* stackmap_pointer = nullptr;
  void* access_flags_pointer = nullptr;
  void* vtable_index_pointer = nullptr;
  void* adapter_pointer = nullptr;
  void* i2i_entry_pointer = nullptr;
  void* signature_handler_pointer = nullptr;

  void* instance_klass = nullptr;
  void* methods_array = nullptr;
  std::int32_t methods_count = 0;
  std::uint16_t method_index = 0;
  std::int32_t vtable_index = -1;
  void* vtable = nullptr;
  std::uint32_t access_flags = 0;
  void* member_names = nullptr;
  void* constant_pool_cache = nullptr;
  void* oop_map_cache = nullptr;
};

[[nodiscard]] Result<HotSpotMethodRecord> ReadHotSpotMethod(
    void* method, const HotSpotMethodLayout& method_layout,
    const HotSpotInstanceKlassLayout& klass_layout);

class HotSpotMethodImage final {
 public:
  HotSpotMethodImage(const HotSpotMethodImage&) = delete;
  HotSpotMethodImage& operator=(const HotSpotMethodImage&) = delete;
  HotSpotMethodImage(HotSpotMethodImage&&) noexcept = default;
  HotSpotMethodImage& operator=(HotSpotMethodImage&&) noexcept = default;

  [[nodiscard]] const HotSpotMethodRecord& record() const noexcept {
    return record_;
  }
  [[nodiscard]] HotSpotMethodRecord& record() noexcept { return record_; }
  [[nodiscard]] const HotSpotMethodRecord& original() const noexcept {
    return original_;
  }

 private:
  friend Result<HotSpotMethodImage> CloneHotSpotMethod(
      void*, const HotSpotMethodLayout&,
      const HotSpotInstanceKlassLayout&);

  HotSpotMethodImage() = default;

  std::vector<std::uint8_t> bytes_;
  HotSpotMethodRecord record_;
  HotSpotMethodRecord original_;
};

[[nodiscard]] Result<HotSpotMethodImage> CloneHotSpotMethod(
    void* method, const HotSpotMethodLayout& method_layout,
    const HotSpotInstanceKlassLayout& klass_layout);

struct HotSpotInstallContext final {
  const HotSpotMethodRecord* replacement = nullptr;
  const HotSpotMethodRecord* previous = nullptr;
  void* java_thread = nullptr;
  bool reverting = false;
};

// Version-correct wrappers for private HotSpot APIs. after_install performs the
// OopMapCache, dependent-code, ConstantPoolCache, class graph, and resolved
// method/member-name adjustments in installJvmMethod().
struct HotSpotMethodApi final {
  using MethodOperation = Status (*)(void* user_data, void* method);
  using SetNativeFunction = Status (*)(void* user_data, void* method,
                                       void* implementation);
  using RestoreUnshareableInfo = Status (*)(void* user_data, void* method,
                                            void* java_thread);
  using LinkMethod = Status (*)(void* user_data, void* method,
                                void* java_thread);
  using AfterInstall = Status (*)(void* user_data,
                                  const HotSpotInstallContext& context);
  using ForceSweep = Status (*)(void* user_data);

  void* user_data = nullptr;
  MethodOperation clear_code = nullptr;
  MethodOperation clear_native_function = nullptr;
  SetNativeFunction set_native_function = nullptr;
  RestoreUnshareableInfo restore_unshareable_info = nullptr;
  LinkMethod link_method = nullptr;
  AfterInstall after_install = nullptr;
  ForceSweep force_sweep = nullptr;

  [[nodiscard]] Status Validate(int jvm_version) const;
};

class HotSpotMutationGate {
 public:
  using Operation = std::function<Status()>;

  virtual ~HotSpotMutationGate() = default;
  [[nodiscard]] virtual Status Run(const Operation& operation) noexcept = 0;
};

// For callers already running in VMThread::execute's VM operation. Production
// integrations should normally provide a gate that enters that operation.
class HotSpotDirectMutationGate final : public HotSpotMutationGate {
 public:
  [[nodiscard]] Status Run(const Operation& operation) noexcept override;
};

// Synchronous C++ form of JvmMethodMangler. The JavaScript next-tick batching
// is represented by the injected mutation gate, so every state transition is
// completed inside one caller-controlled HotSpot safepoint.
class HotSpotMethodMangler final {
 public:
  HotSpotMethodMangler(const HotSpotMethodMangler&) = delete;
  HotSpotMethodMangler& operator=(const HotSpotMethodMangler&) = delete;
  ~HotSpotMethodMangler();

  [[nodiscard]] static Result<std::unique_ptr<HotSpotMethodMangler>> Create(
      void** method_id_slot, HotSpotMethodLayout method_layout,
      HotSpotInstanceKlassLayout klass_layout, HotSpotMethodApi api,
      std::shared_ptr<HotSpotMutationGate> gate);

  [[nodiscard]] Status Replace(void* implementation, void* java_thread);
  [[nodiscard]] Status Revert(void* java_thread);
  [[nodiscard]] Result<void**> ResolveTarget();

  [[nodiscard]] bool active() const noexcept;
  [[nodiscard]] void* original_method() const noexcept;
  [[nodiscard]] void* replacement_method() const noexcept;

 private:
  struct State;

  explicit HotSpotMethodMangler(std::unique_ptr<State> state);
  std::unique_ptr<State> state_;
};

}  // namespace art_hook
