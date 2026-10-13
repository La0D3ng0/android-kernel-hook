// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/hotspot_method.h"

#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <utility>

namespace art_hook {
namespace {

constexpr std::size_t kMaximumConstMethodSize = 16U * 1024U * 1024U;

void RetireImage(HotSpotMethodImage image) {
  static auto* mutex = new std::mutex();
  static auto* images = new std::vector<HotSpotMethodImage>();
  std::lock_guard<std::mutex> lock(*mutex);
  images->push_back(std::move(image));
}

bool FieldFits(std::size_t offset, std::size_t size,
               std::size_t container_size) noexcept {
  return offset <= container_size && size <= container_size - offset;
}

template <typename T>
T ReadValue(const void* address) noexcept {
  T result{};
  std::memcpy(&result, address, sizeof(result));
  return result;
}

template <typename T>
void WriteValue(void* address, T value) noexcept {
  std::memcpy(address, &value, sizeof(value));
}

void* Add(void* base, std::size_t offset) noexcept {
  return static_cast<void*>(static_cast<std::uint8_t*>(base) + offset);
}

void* ReadPointer(const void* address, std::size_t pointer_size) noexcept {
  if (pointer_size == 4U) {
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(
        ReadValue<std::uint32_t>(address)));
  }
  return reinterpret_cast<void*>(static_cast<std::uintptr_t>(
      ReadValue<std::uint64_t>(address)));
}

void WritePointer(void* address, void* value,
                  std::size_t pointer_size) noexcept {
  const auto integer = reinterpret_cast<std::uintptr_t>(value);
  if (pointer_size == 4U) {
    WriteValue(address, static_cast<std::uint32_t>(integer));
  } else {
    WriteValue(address, static_cast<std::uint64_t>(integer));
  }
}

Status Invoke(const HotSpotMethodApi::MethodOperation operation,
              void* user_data, void* method, const char* name) {
  if (operation == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  std::string("missing HotSpot API: ") + name);
  }
  return operation(user_data, method);
}

Status PrepareNativeMethod(HotSpotMethodImage& image, void* implementation,
                           void* java_thread,
                           const HotSpotMethodLayout& layout,
                           const HotSpotMethodApi& api) {
  auto& method = image.record();
  WritePointer(method.const_method_pointer, method.const_method,
               layout.pointer_size);
  const std::uint32_t flags =
      method.access_flags | kJvmAccNative | kJvmAccNotC2Compilable |
      kJvmAccNotC1Compilable | kJvmAccNotC2OsrCompilable;
  WriteValue(method.access_flags_pointer, flags);
  method.access_flags = flags;

  WritePointer(method.signature_handler_pointer, nullptr, layout.pointer_size);
  WritePointer(method.adapter_pointer, nullptr, layout.pointer_size);
  WritePointer(method.i2i_entry_pointer, nullptr, layout.pointer_size);
  Status status = Invoke(api.clear_code, api.user_data, method.method,
                         "Method::clear_code");
  if (!status.ok()) {
    return status;
  }

  WritePointer(method.method_data_pointer, nullptr, layout.pointer_size);
  WritePointer(method.method_counters_pointer, nullptr, layout.pointer_size);
  WritePointer(method.stackmap_pointer, nullptr, layout.pointer_size);

  status = Invoke(api.clear_native_function, api.user_data, method.method,
                  "Method::clear_native_function");
  if (!status.ok()) {
    return status;
  }
  status = api.set_native_function(api.user_data, method.method,
                                   implementation);
  if (!status.ok()) {
    return status;
  }
  status = api.restore_unshareable_info(api.user_data, method.method,
                                        java_thread);
  if (!status.ok()) {
    return status;
  }
  if (layout.jvm_version >= 17) {
    status = api.link_method(api.user_data, method.method, java_thread);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::Ok();
}

Status InstallMethod(const HotSpotMethodRecord& replacement,
                     HotSpotMethodRecord& previous, void** method_id_slot,
                     void* java_thread, bool reverting,
                     const HotSpotMethodLayout& layout,
                     const HotSpotMethodApi& api) {
  if (replacement.method_index >=
      static_cast<std::uint32_t>(replacement.methods_count)) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot method index lies outside methods array");
  }
  if (replacement.methods_array == nullptr || method_id_slot == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot install target is incomplete");
  }

  void* methods_slot = Add(
      replacement.methods_array,
      static_cast<std::size_t>(replacement.method_index) * layout.pointer_size);
  void* old_methods_value = ReadPointer(methods_slot, layout.pointer_size);
  void* old_method_id = ReadPointer(method_id_slot, layout.pointer_size);
  void* vtable_slot = nullptr;
  void* old_vtable_value = nullptr;
  if (replacement.vtable_index >= 0) {
    if (replacement.vtable == nullptr) {
      return Status(StatusCode::kInvalidArgument,
                    "HotSpot vtable pointer is null");
    }
    vtable_slot = Add(
        replacement.vtable,
        static_cast<std::size_t>(replacement.vtable_index) * layout.pointer_size);
    old_vtable_value = ReadPointer(vtable_slot, layout.pointer_size);
  }
  const std::uint32_t old_previous_flags =
      ReadValue<std::uint32_t>(previous.access_flags_pointer);

  WritePointer(methods_slot, replacement.method, layout.pointer_size);
  if (vtable_slot != nullptr) {
    WritePointer(vtable_slot, replacement.method, layout.pointer_size);
  }
  WritePointer(method_id_slot, replacement.method, layout.pointer_size);
  const std::uint32_t obsolete_flags =
      previous.access_flags | kJvmAccIsOld | kJvmAccIsObsolete;
  WriteValue(previous.access_flags_pointer, obsolete_flags);

  HotSpotInstallContext context;
  context.replacement = &replacement;
  context.previous = &previous;
  context.java_thread = java_thread;
  context.reverting = reverting;
  Status status = api.after_install(api.user_data, context);
  if (status.ok()) {
    previous.access_flags = obsolete_flags;
    return status;
  }

  WritePointer(methods_slot, old_methods_value, layout.pointer_size);
  if (vtable_slot != nullptr) {
    WritePointer(vtable_slot, old_vtable_value, layout.pointer_size);
  }
  WritePointer(method_id_slot, old_method_id, layout.pointer_size);
  WriteValue(previous.access_flags_pointer, old_previous_flags);
  return Status(status.code(),
                "HotSpot install callback failed; direct slots rolled back: " +
                    status.message());
}

}  // namespace

Status HotSpotMethodLayout::Validate() const {
  if (jvm_version < 8) {
    return Status(StatusCode::kUnsupported,
                  "HotSpot method mangling requires JDK 8 or newer");
  }
  if (pointer_size != 4U && pointer_size != 8U) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot pointer size must be 4 or 8");
  }
  if (method_size < 8U * pointer_size || method_size > 1024U) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot Method size is outside the supported range");
  }
  const std::size_t pointer_fields[] = {
      const_method_offset, method_data_offset, method_counters_offset,
      i2i_entry_offset, native_function_offset, signature_handler_offset};
  for (const std::size_t offset : pointer_fields) {
    if (!FieldFits(offset, pointer_size, method_size) ||
        (offset % pointer_size) != 0U) {
      return Status(StatusCode::kInvalidArgument,
                    "HotSpot Method pointer field is invalid");
    }
  }
  if (adapter_location != HotSpotAdapterLocation::kConstMethod &&
      (!FieldFits(adapter_offset, pointer_size, method_size) ||
       (adapter_offset % pointer_size) != 0U)) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot Method adapter field is invalid");
  }
  if (!FieldFits(access_flags_offset, sizeof(std::uint32_t), method_size) ||
      !FieldFits(vtable_index_offset, sizeof(std::int32_t), method_size)) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot Method scalar field is invalid");
  }
  if ((constant_pool_offset % pointer_size) != 0U ||
      (stackmap_data_offset % pointer_size) != 0U ||
      (adapter_location == HotSpotAdapterLocation::kConstMethod &&
       (adapter_offset % pointer_size) != 0U)) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot ConstMethod pointer field is misaligned");
  }
  return Status::Ok();
}

Result<HotSpotMethodLayout> BuildHotSpotMethodLayout(
    int jvm_version, std::size_t pointer_size,
    std::size_t native_method_size) {
  HotSpotMethodLayout result;
  result.jvm_version = jvm_version;
  result.pointer_size = pointer_size;
  result.method_size = native_method_size;
  if (jvm_version >= 17) {
    result.adapter_location = HotSpotAdapterLocation::kMethodEarly;
  } else if (jvm_version >= 9) {
    result.adapter_location = HotSpotAdapterLocation::kConstMethod;
  } else {
    result.adapter_location = HotSpotAdapterLocation::kMethodLate;
  }

  result.const_method_offset = pointer_size;
  result.method_data_offset = 2U * pointer_size;
  result.method_counters_offset = 3U * pointer_size;
  const std::size_t early_adapter_offset = 4U * pointer_size;
  const std::size_t early_adapter_size =
      result.adapter_location == HotSpotAdapterLocation::kMethodEarly
          ? pointer_size
          : 0U;
  result.access_flags_offset = early_adapter_offset + early_adapter_size;
  result.vtable_index_offset = result.access_flags_offset + 4U;
  result.i2i_entry_offset = result.vtable_index_offset + 4U + 8U;
  const std::size_t late_adapter_offset = result.i2i_entry_offset + pointer_size;
  result.adapter_offset =
      result.adapter_location == HotSpotAdapterLocation::kMethodEarly
          ? early_adapter_offset
          : late_adapter_offset;
  if (native_method_size >= 2U * pointer_size) {
    result.native_function_offset = native_method_size - 2U * pointer_size;
    result.signature_handler_offset = native_method_size - pointer_size;
  }

  result.constant_pool_offset = 8U;
  result.stackmap_data_offset = result.constant_pool_offset + pointer_size;
  const std::size_t const_adapter_offset =
      result.stackmap_data_offset + pointer_size;
  const std::size_t const_adapter_size =
      result.adapter_location == HotSpotAdapterLocation::kConstMethod
          ? pointer_size
          : 0U;
  if (result.adapter_location == HotSpotAdapterLocation::kConstMethod) {
    result.adapter_offset = const_adapter_offset;
  }
  result.const_method_size_offset =
      const_adapter_offset + const_adapter_size;
  result.method_idnum_offset = result.const_method_size_offset + 0xeU;
  result.constant_pool_cache_offset = 2U * pointer_size;
  result.constant_pool_instance_klass_offset = 3U * pointer_size;

  Status valid = result.Validate();
  if (!valid.ok()) {
    return valid;
  }
  return result;
}

Status HotSpotInstanceKlassLayout::Validate() const {
  if (pointer_size != 4U && pointer_size != 8U) {
    return Status(StatusCode::kInvalidArgument,
                  "InstanceKlass pointer size must be 4 or 8");
  }
  if (vtable_offset < 0x100U || (vtable_offset % pointer_size) != 0U) {
    return Status(StatusCode::kInvalidArgument,
                  "InstanceKlass vtable offset is invalid");
  }
  const std::size_t offsets[] = {methods_offset, member_names_offset,
                                 oop_map_cache_offset};
  for (const std::size_t offset : offsets) {
    if (offset >= vtable_offset || (offset % pointer_size) != 0U) {
      return Status(StatusCode::kInvalidArgument,
                    "InstanceKlass field offset is invalid");
    }
  }
  return Status::Ok();
}

Result<HotSpotInstanceKlassLayout> BuildHotSpotInstanceKlassLayout(
    int jvm_version, std::size_t pointer_size, std::size_t vtable_offset) {
  if (jvm_version < 8) {
    return Status(StatusCode::kUnsupported,
                  "InstanceKlass layout requires JDK 8 or newer");
  }
  const std::size_t oop_multiplier =
      ((jvm_version >= 10 && jvm_version <= 11) || jvm_version >= 15)
          ? 17U
          : 18U;
  const std::size_t largest_multiplier =
      oop_multiplier > 17U ? oop_multiplier : 17U;
  if (pointer_size == 0U ||
      vtable_offset < largest_multiplier * pointer_size) {
    return Status(StatusCode::kInvalidArgument,
                  "InstanceKlass vtable offset is too small");
  }
  HotSpotInstanceKlassLayout result;
  result.pointer_size = pointer_size;
  result.vtable_offset = vtable_offset;
  result.methods_offset = vtable_offset - 7U * pointer_size;
  result.member_names_offset = vtable_offset - 17U * pointer_size;
  result.oop_map_cache_offset = vtable_offset - oop_multiplier * pointer_size;
  Status valid = result.Validate();
  if (!valid.ok()) {
    return valid;
  }
  return result;
}

Result<HotSpotMethodRecord> ReadHotSpotMethod(
    void* method, const HotSpotMethodLayout& method_layout,
    const HotSpotInstanceKlassLayout& klass_layout) {
  Status valid = method_layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  valid = klass_layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  if (method_layout.pointer_size != klass_layout.pointer_size) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot layout pointer sizes disagree");
  }
  if (method == nullptr) {
    return Status(StatusCode::kInvalidArgument, "HotSpot Method is null");
  }

  const std::size_t pointer_size = method_layout.pointer_size;
  void* const_method = ReadPointer(
      Add(method, method_layout.const_method_offset), pointer_size);
  if (const_method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot ConstMethod is null");
  }
  const std::int32_t size_words = ReadValue<std::int32_t>(
      Add(const_method, method_layout.const_method_size_offset));
  if (size_words <= 0 ||
      static_cast<std::uint64_t>(size_words) >
          kMaximumConstMethodSize / pointer_size) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot ConstMethod size is invalid");
  }
  const std::size_t const_size =
      static_cast<std::size_t>(size_words) * pointer_size;
  if (!FieldFits(method_layout.method_idnum_offset, sizeof(std::uint16_t),
                 const_size)) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot ConstMethod fields exceed its size");
  }

  void* constant_pool = ReadPointer(
      Add(const_method, method_layout.constant_pool_offset), pointer_size);
  if (constant_pool == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot ConstantPool is null");
  }
  void* instance_klass = ReadPointer(
      Add(constant_pool, method_layout.constant_pool_instance_klass_offset),
      pointer_size);
  if (instance_klass == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot InstanceKlass is null");
  }
  void* methods = ReadPointer(Add(instance_klass, klass_layout.methods_offset),
                              pointer_size);
  if (methods == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot methods array is null");
  }

  HotSpotMethodRecord result;
  result.method = method;
  result.const_method = const_method;
  result.const_method_size = const_size;
  result.const_method_pointer = Add(method, method_layout.const_method_offset);
  result.method_data_pointer = Add(method, method_layout.method_data_offset);
  result.method_counters_pointer =
      Add(method, method_layout.method_counters_offset);
  result.stackmap_pointer =
      Add(const_method, method_layout.stackmap_data_offset);
  result.access_flags_pointer =
      Add(method, method_layout.access_flags_offset);
  result.vtable_index_pointer =
      Add(method, method_layout.vtable_index_offset);
  result.adapter_pointer =
      method_layout.adapter_location == HotSpotAdapterLocation::kConstMethod
          ? Add(const_method, method_layout.adapter_offset)
          : Add(method, method_layout.adapter_offset);
  result.i2i_entry_pointer = Add(method, method_layout.i2i_entry_offset);
  result.signature_handler_pointer =
      Add(method, method_layout.signature_handler_offset);
  result.instance_klass = instance_klass;
  result.methods_count = ReadValue<std::int32_t>(methods);
  if (result.methods_count <= 0) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot methods array count is invalid");
  }
  result.methods_array = Add(methods, pointer_size);
  result.method_index = ReadValue<std::uint16_t>(
      Add(const_method, method_layout.method_idnum_offset));
  if (result.method_index >=
      static_cast<std::uint32_t>(result.methods_count)) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot method index exceeds methods array");
  }
  result.vtable_index = ReadValue<std::int32_t>(result.vtable_index_pointer);
  result.vtable = Add(instance_klass, klass_layout.vtable_offset);
  result.access_flags = ReadValue<std::uint32_t>(result.access_flags_pointer);
  result.member_names = method_layout.jvm_version >= 10
      ? ReadPointer(Add(instance_klass, klass_layout.member_names_offset),
                    pointer_size)
      : nullptr;
  result.constant_pool_cache = ReadPointer(
      Add(constant_pool, method_layout.constant_pool_cache_offset),
      pointer_size);
  result.oop_map_cache = ReadPointer(
      Add(instance_klass, klass_layout.oop_map_cache_offset), pointer_size);
  return result;
}

Result<HotSpotMethodImage> CloneHotSpotMethod(
    void* method, const HotSpotMethodLayout& method_layout,
    const HotSpotInstanceKlassLayout& klass_layout) {
  auto original = ReadHotSpotMethod(method, method_layout, klass_layout);
  if (!original.ok()) {
    return original.status();
  }
  HotSpotMethodImage image;
  image.bytes_.resize(original.value().const_method_size +
                      method_layout.method_size);
  std::memcpy(image.bytes_.data(), original.value().const_method,
              original.value().const_method_size);
  void* cloned_method =
      image.bytes_.data() + original.value().const_method_size;
  std::memcpy(cloned_method, method, method_layout.method_size);
  WritePointer(Add(cloned_method, method_layout.const_method_offset),
               image.bytes_.data(), method_layout.pointer_size);
  auto cloned = ReadHotSpotMethod(cloned_method, method_layout, klass_layout);
  if (!cloned.ok()) {
    return cloned.status();
  }
  image.record_ = std::move(cloned).value();
  image.original_ = std::move(original).value();
  return image;
}

Status HotSpotMethodApi::Validate(int jvm_version) const {
  if (clear_code == nullptr || clear_native_function == nullptr ||
      set_native_function == nullptr || restore_unshareable_info == nullptr ||
      after_install == nullptr || force_sweep == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot method API is incomplete");
  }
  if (jvm_version >= 17 && link_method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "JDK 17+ HotSpot API requires Method::link_method");
  }
  return Status::Ok();
}

Status HotSpotDirectMutationGate::Run(
    const Operation& operation) noexcept {
  if (!operation) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot mutation operation is empty");
  }
  try {
    return operation();
  } catch (const std::exception& error) {
    return Status(StatusCode::kPlatformError,
                  std::string("HotSpot mutation threw: ") + error.what());
  } catch (...) {
    return Status(StatusCode::kPlatformError,
                  "HotSpot mutation threw an unknown exception");
  }
}

struct HotSpotMethodMangler::State final {
  void** method_id_slot = nullptr;
  void* original_method = nullptr;
  HotSpotMethodLayout method_layout;
  HotSpotInstanceKlassLayout klass_layout;
  HotSpotMethodApi api;
  std::shared_ptr<HotSpotMutationGate> gate;
  std::optional<HotSpotMethodImage> original_image;
  std::optional<HotSpotMethodImage> replacement_image;
  std::unique_ptr<void*> resolved_target;
  mutable std::mutex mutex;
  bool active = false;
  bool replacement_safe_to_release = true;
};

HotSpotMethodMangler::HotSpotMethodMangler(std::unique_ptr<State> state)
    : state_(std::move(state)) {}

HotSpotMethodMangler::~HotSpotMethodMangler() {
  if (state_ == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> lock(state_->mutex);
  if (state_->replacement_image.has_value() &&
      !state_->replacement_safe_to_release) {
    // An active or not-yet-swept Method may still be referenced by HotSpot.
    // Keep its allocation alive for the process instead of risking a UAF.
    RetireImage(std::move(*state_->replacement_image));
    state_->replacement_image.reset();
  }
}

Result<std::unique_ptr<HotSpotMethodMangler>> HotSpotMethodMangler::Create(
    void** method_id_slot, HotSpotMethodLayout method_layout,
    HotSpotInstanceKlassLayout klass_layout, HotSpotMethodApi api,
    std::shared_ptr<HotSpotMutationGate> gate) {
  if (method_id_slot == nullptr || gate == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot mangler requires method ID slot and mutation gate");
  }
  Status valid = method_layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  valid = klass_layout.Validate();
  if (!valid.ok()) {
    return valid;
  }
  if (method_layout.pointer_size != sizeof(void*)) {
    return Status(StatusCode::kUnsupported,
                  "HotSpot mutation pointer size must match this process");
  }
  valid = api.Validate(method_layout.jvm_version);
  if (!valid.ok()) {
    return valid;
  }
  void* method = ReadPointer(method_id_slot, method_layout.pointer_size);
  auto parsed = ReadHotSpotMethod(method, method_layout, klass_layout);
  if (!parsed.ok()) {
    return parsed.status();
  }

  auto state = std::make_unique<State>();
  state->method_id_slot = method_id_slot;
  state->original_method = method;
  state->method_layout = std::move(method_layout);
  state->klass_layout = std::move(klass_layout);
  state->api = api;
  state->gate = std::move(gate);
  return std::unique_ptr<HotSpotMethodMangler>(
      new HotSpotMethodMangler(std::move(state)));
}

Status HotSpotMethodMangler::Replace(void* implementation,
                                     void* java_thread) {
  if (implementation == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "HotSpot replacement implementation is null");
  }
  std::lock_guard<std::mutex> lock(state_->mutex);
  return state_->gate->Run([&]() -> Status {
    if (!state_->original_image.has_value()) {
      auto original = CloneHotSpotMethod(state_->original_method,
                                         state_->method_layout,
                                         state_->klass_layout);
      if (!original.ok()) {
        return original.status();
      }
      auto replacement = CloneHotSpotMethod(state_->original_method,
                                            state_->method_layout,
                                            state_->klass_layout);
      if (!replacement.ok()) {
        return replacement.status();
      }
      state_->original_image.emplace(std::move(original).value());
      state_->replacement_image.emplace(std::move(replacement).value());
      Status prepared = PrepareNativeMethod(
          *state_->replacement_image, implementation, java_thread,
          state_->method_layout, state_->api);
      if (!prepared.ok()) {
        state_->replacement_image.reset();
        state_->original_image.reset();
        return prepared;
      }
    } else if (state_->active) {
      return state_->api.set_native_function(
          state_->api.user_data,
          state_->replacement_image->record().method, implementation);
    } else {
      Status prepared = PrepareNativeMethod(
          *state_->replacement_image, implementation, java_thread,
          state_->method_layout, state_->api);
      if (!prepared.ok()) {
        return prepared;
      }
    }

    auto previous = state_->original_image->original();
    Status installed = InstallMethod(
        state_->replacement_image->record(), previous,
        state_->method_id_slot, java_thread, false, state_->method_layout,
        state_->api);
    if (installed.ok()) {
      state_->active = true;
      state_->replacement_safe_to_release = false;
    }
    return installed;
  });
}

Status HotSpotMethodMangler::Revert(void* java_thread) {
  std::lock_guard<std::mutex> lock(state_->mutex);
  if (!state_->active || !state_->original_image.has_value() ||
      !state_->replacement_image.has_value()) {
    return Status::Ok();
  }
  return state_->gate->Run([&]() -> Status {
    const auto& original = state_->original_image->original();
    WriteValue(original.access_flags_pointer, original.access_flags);
    WriteValue(original.vtable_index_pointer, original.vtable_index);

    HotSpotMethodRecord restored = original;
    auto previous = state_->replacement_image->record();
    Status installed = InstallMethod(restored, previous, state_->method_id_slot,
                                     java_thread, true, state_->method_layout,
                                     state_->api);
    if (!installed.ok()) {
      return installed;
    }
    state_->active = false;
    Status swept = state_->api.force_sweep(state_->api.user_data);
    if (!swept.ok()) {
      return swept;
    }
    state_->replacement_safe_to_release = true;
    return Status::Ok();
  });
}

Result<void**> HotSpotMethodMangler::ResolveTarget() {
  std::lock_guard<std::mutex> lock(state_->mutex);
  if (!state_->original_image.has_value() || !state_->active) {
    return state_->method_id_slot;
  }
  if (state_->resolved_target != nullptr) {
    return state_->resolved_target.get();
  }
  const auto& original = state_->original_image->original();
  // nonvirtual_vtable_index from jvm.js: old direct calls need no vtable slot.
  WriteValue(original.vtable_index_pointer, static_cast<std::int32_t>(-2));
  state_->resolved_target = std::make_unique<void*>(state_->original_method);
  return state_->resolved_target.get();
}

bool HotSpotMethodMangler::active() const noexcept {
  std::lock_guard<std::mutex> lock(state_->mutex);
  return state_->active;
}

void* HotSpotMethodMangler::original_method() const noexcept {
  return state_->original_method;
}

void* HotSpotMethodMangler::replacement_method() const noexcept {
  std::lock_guard<std::mutex> lock(state_->mutex);
  return state_->replacement_image.has_value()
             ? state_->replacement_image->record().method
             : nullptr;
}

}  // namespace art_hook
