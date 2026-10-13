// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <new>
#include <string>
#include <utility>

#include "art_hook/art_entrypoint.h"
#include "art_hook/art_flags.h"
#include "art_hook/art_method.h"
#include "art_hook/status.h"

namespace {

struct LiveTest final {
  std::uint64_t return_value = 0;
  std::atomic<std::uint64_t> enter_count{0};
  std::atomic<std::uint64_t> leave_count{0};
  void *method = nullptr;
  art_hook::ArtMethodLayout layout;
  std::shared_ptr<art_hook::ArtMutationGate> mutation_gate;
  std::unique_ptr<art_hook::ArtMethodInterceptor> hook;
};

void CopyMessage(const std::string &message, char *output,
                 std::size_t output_size) noexcept {
  if (output == nullptr || output_size == 0) {
    return;
  }
  const std::size_t length =
      message.size() < output_size - 1U ? message.size() : output_size - 1U;
  std::memcpy(output, message.data(), length);
  output[length] = '\0';
}

int ReturnStatus(const art_hook::Status &status, char *output,
                 std::size_t output_size) noexcept {
  CopyMessage(status.ok() ? "OK" : status.message(), output, output_size);
  return status.ok() ? 0 : static_cast<int>(status.code());
}

template <typename Function>
Function FunctionFromAddress(void *address) noexcept {
  static_assert(sizeof(Function) == sizeof(address));
  Function result = nullptr;
  std::memcpy(&result, &address, sizeof(result));
  return result;
}

void CountEnter(art_hook::Arm64CpuContext *, void *user_data) noexcept {
  auto *test = static_cast<LiveTest *>(user_data);
  test->enter_count.fetch_add(1U, std::memory_order_relaxed);
}

void OverrideReturnValue(art_hook::Arm64CpuContext *context,
                         void *user_data) noexcept {
  auto *test = static_cast<LiveTest *>(user_data);
  test->leave_count.fetch_add(1U, std::memory_order_relaxed);
  context->x[0] = test->return_value;
}

} // namespace

extern "C" __attribute__((visibility("default"))) void *art_hook_live_create(
    void *method, void *jni_code_start, void *jni_code_end,
    std::uint32_t expected_access_flags,
    std::uint32_t relevant_access_flags_mask, int android_api_level,
    void *thread_list, void *suspend_all_address, void *resume_all_address,
    std::uint64_t return_value, char *error, std::size_t error_size) noexcept {
  try {
    if (method == nullptr || thread_list == nullptr ||
        suspend_all_address == nullptr || resume_all_address == nullptr) {
      CopyMessage("live-test input is null", error, error_size);
      return nullptr;
    }

    art_hook::ArtMethodProbeSpec probe;
    probe.method = method;
    probe.expected_jni_code_start =
        reinterpret_cast<std::uintptr_t>(jni_code_start);
    probe.expected_jni_code_end =
        reinterpret_cast<std::uintptr_t>(jni_code_end);
    probe.expected_access_flags = expected_access_flags;
    probe.relevant_access_flags_mask = relevant_access_flags_mask;
    probe.android_api_level = android_api_level;
    auto layout = art_hook::ProbeArtMethodLayout(probe);
    if (!layout.ok()) {
      CopyMessage(layout.status().message(), error, error_size);
      return nullptr;
    }

    using Gate = art_hook::ArtThreadListMutationGate;
    auto gate = std::make_shared<Gate>(
        thread_list, FunctionFromAddress<Gate::SuspendAll>(suspend_all_address),
        FunctionFromAddress<Gate::ResumeAll>(resume_all_address),
        "art-hook live test");

    auto test = std::unique_ptr<LiveTest>(new (std::nothrow) LiveTest());
    if (test == nullptr) {
      CopyMessage("unable to allocate live-test state", error, error_size);
      return nullptr;
    }
    test->return_value = return_value;
    test->method = method;
    test->layout = layout.value();
    test->mutation_gate = gate;

    art_hook::ArtMethodCallbacks callbacks;
    callbacks.on_enter = CountEnter;
    callbacks.on_leave = OverrideReturnValue;
    callbacks.user_data = test.get();
    auto hook = art_hook::ArtMethodInterceptor::Create(
        method, std::move(layout).value(), callbacks, gate);
    if (!hook.ok()) {
      CopyMessage(hook.status().message(), error, error_size);
      return nullptr;
    }
    test->hook = std::move(hook).value();
    CopyMessage("OK", error, error_size);
    return test.release();
  } catch (const std::exception &exception) {
    CopyMessage(exception.what(), error, error_size);
    return nullptr;
  } catch (...) {
    CopyMessage("unknown C++ exception", error, error_size);
    return nullptr;
  }
}

extern "C" __attribute__((visibility("default"))) int
art_hook_live_activate(void *handle, char *error,
                       std::size_t error_size) noexcept {
  if (handle == nullptr) {
    return ReturnStatus(
        {art_hook::StatusCode::kInvalidArgument, "live-test handle is null"},
        error, error_size);
  }
  try {
    auto *test = static_cast<LiveTest *>(handle);
    return ReturnStatus(test->hook->Activate(), error, error_size);
  } catch (const std::exception &exception) {
    CopyMessage(exception.what(), error, error_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  } catch (...) {
    CopyMessage("unknown C++ exception", error, error_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  }
}

extern "C" __attribute__((visibility("default"))) int
art_hook_live_deactivate(void *handle, char *error,
                         std::size_t error_size) noexcept {
  if (handle == nullptr) {
    return ReturnStatus(
        {art_hook::StatusCode::kInvalidArgument, "live-test handle is null"},
        error, error_size);
  }
  try {
    auto *test = static_cast<LiveTest *>(handle);
    return ReturnStatus(test->hook->Deactivate(), error, error_size);
  } catch (const std::exception &exception) {
    CopyMessage(exception.what(), error, error_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  } catch (...) {
    CopyMessage("unknown C++ exception", error, error_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  }
}

extern "C" __attribute__((visibility("default"))) void
art_hook_live_destroy(void *handle) noexcept {
  delete static_cast<LiveTest *>(handle);
}

extern "C" __attribute__((visibility("default"))) std::uint64_t
art_hook_live_enter_count(void *handle) noexcept {
  if (handle == nullptr) {
    return 0;
  }
  return static_cast<LiveTest *>(handle)->enter_count.load(
      std::memory_order_relaxed);
}

extern "C" __attribute__((visibility("default"))) std::uint64_t
art_hook_live_leave_count(void *handle) noexcept {
  if (handle == nullptr) {
    return 0;
  }
  return static_cast<LiveTest *>(handle)->leave_count.load(
      std::memory_order_relaxed);
}

extern "C" __attribute__((visibility("default"))) int
art_hook_live_flags_cycle(void *handle, std::uint32_t clear_mask,
                          std::uint32_t set_mask, std::uint32_t *before,
                          std::uint32_t *during, std::uint32_t *after,
                          char *error, std::size_t error_size) noexcept {
  if (handle == nullptr || before == nullptr || during == nullptr ||
      after == nullptr) {
    return ReturnStatus(
        {art_hook::StatusCode::kInvalidArgument, "flags-cycle input is null"},
        error, error_size);
  }
  try {
    auto *test = static_cast<LiveTest *>(handle);
    art_hook::ArtAccessFlagMutation mutation;
    mutation.clear_mask = clear_mask;
    mutation.set_mask = set_mask;
    auto updated = art_hook::UpdateArtAccessFlagsSafe(
        test->method, test->layout, mutation, *test->mutation_gate);
    if (!updated.ok()) {
      return ReturnStatus(updated.status(), error, error_size);
    }
    *before = updated.value().before;
    *during = updated.value().after;

    auto restored = art_hook::WriteArtAccessFlagsSafe(
        test->method, test->layout, updated.value().before,
        *test->mutation_gate);
    if (!restored.ok()) {
      return ReturnStatus(restored.status(), error, error_size);
    }
    *after = restored.value().after;
    return ReturnStatus(art_hook::Status::Ok(), error, error_size);
  } catch (const std::exception &exception) {
    CopyMessage(exception.what(), error, error_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  } catch (...) {
    CopyMessage("unknown C++ exception", error, error_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  }
}
