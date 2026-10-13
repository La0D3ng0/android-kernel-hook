// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <string>

#include "art_hook/gum_interceptor.h"
#include "art_hook/status.h"

namespace {

struct CallbackState final {
  std::atomic<std::uint64_t> enter_count{0};
  std::atomic<std::uint64_t> leave_count{0};
  std::atomic<std::uint64_t> probe_count{0};
};

art_hook::GumInterceptorRuntime *g_replacement_runtime = nullptr;
void *g_expected_replacement_data = nullptr;
std::atomic<std::uint64_t> g_replacement_data_seen{0};

void CopyMessage(const std::string &message, char *output,
                 std::size_t output_size) noexcept {
  if (output == nullptr || output_size == 0U) {
    return;
  }
  const std::size_t length =
      message.size() < output_size - 1U ? message.size() : output_size - 1U;
  std::memcpy(output, message.data(), length);
  output[length] = '\0';
}

template <typename Function>
Function FunctionFromAddress(void *address) noexcept {
  static_assert(sizeof(Function) == sizeof(address));
  Function result = nullptr;
  std::memcpy(&result, &address, sizeof(result));
  return result;
}

void MutateFirstArgument(art_hook::GumInvocationContext &context,
                         void *user_data) noexcept {
  auto *state = static_cast<CallbackState *>(user_data);
  state->enter_count.fetch_add(1U, std::memory_order_relaxed);
  const auto first = reinterpret_cast<std::uintptr_t>(context.Argument(0));
  context.ReplaceArgument(0, reinterpret_cast<void *>(first + 1U));
}

void DoubleReturnValue(art_hook::GumInvocationContext &context,
                       void *user_data) noexcept {
  auto *state = static_cast<CallbackState *>(user_data);
  state->leave_count.fetch_add(1U, std::memory_order_relaxed);
  const auto result =
      reinterpret_cast<std::uintptr_t>(context.ReturnValue());
  context.ReplaceReturnValue(reinterpret_cast<void *>(result * 2U));
}

void CountProbe(art_hook::GumInvocationContext &, void *user_data) noexcept {
  static_cast<CallbackState *>(user_data)->probe_count.fetch_add(
      1U, std::memory_order_relaxed);
}

art_hook::Status Expect(std::uint64_t actual, std::uint64_t expected,
                        const char *step) {
  if (actual == expected) {
    return art_hook::Status::Ok();
  }
  return {art_hook::StatusCode::kPlatformError,
          std::string(step) + " returned " + std::to_string(actual) +
              ", expected " + std::to_string(expected)};
}

} // namespace

extern "C" __attribute__((visibility("default"), noinline)) std::uint64_t
art_hook_gum_live_target(std::uint64_t first, std::uint64_t second) noexcept {
#if defined(__aarch64__)
  __asm__ __volatile__("nop\n\tnop\n\tnop\n\tnop" ::: "memory");
#endif
  return first + second;
}

extern "C" __attribute__((visibility("default"), noinline)) std::uint64_t
art_hook_gum_live_replacement(std::uint64_t first,
                              std::uint64_t second) noexcept {
  if (g_replacement_runtime != nullptr) {
    const auto invocation = g_replacement_runtime->CurrentInvocation();
    if (invocation.has_value() &&
        invocation->replacement_data() == g_expected_replacement_data) {
      g_replacement_data_seen.fetch_add(1U, std::memory_order_relaxed);
    }
  }
  return first * second + 1U;
}

extern "C" __attribute__((visibility("default"))) std::size_t
art_hook_gum_live_api_size() noexcept {
  return sizeof(art_hook::GumInterceptorApi);
}

extern "C" __attribute__((visibility("default"))) int
art_hook_gum_live_run(const void *api_data, std::size_t api_size,
                      void *target_address, void *replacement_address,
                      char *output, std::size_t output_size) noexcept {
  using TargetFunction = std::uint64_t (*)(std::uint64_t, std::uint64_t);

  try {
    if (api_data == nullptr || target_address == nullptr ||
        replacement_address == nullptr) {
      CopyMessage("live Gum test input is null", output, output_size);
      return static_cast<int>(art_hook::StatusCode::kInvalidArgument);
    }
    if (api_size != sizeof(art_hook::GumInterceptorApi)) {
      CopyMessage("Gum adapter descriptor size mismatch", output,
                  output_size);
      return static_cast<int>(art_hook::StatusCode::kUnsupported);
    }

    art_hook::GumInterceptorApi api;
    std::memcpy(&api, api_data, sizeof(api));
    auto runtime = art_hook::GumInterceptorRuntime::Create(api);
    if (!runtime.ok()) {
      CopyMessage(runtime.status().ToString(), output, output_size);
      return static_cast<int>(runtime.status().code());
    }

    auto target = FunctionFromAddress<TargetFunction>(target_address);
    auto replacement_function =
        FunctionFromAddress<TargetFunction>(replacement_address);
    CallbackState callbacks_state;

    const std::uint64_t before = target(3U, 4U);
    art_hook::Status status = Expect(before, 7U, "unhooked target");
    if (!status.ok()) {
      CopyMessage(status.ToString(), output, output_size);
      return static_cast<int>(status.code());
    }

    art_hook::GumInvocationCallbacks callbacks;
    callbacks.on_enter = MutateFirstArgument;
    callbacks.on_leave = DoubleReturnValue;
    callbacks.user_data = &callbacks_state;

    auto transaction = runtime.value()->BeginTransaction();
    if (!transaction.ok()) {
      CopyMessage(transaction.status().ToString(), output, output_size);
      return static_cast<int>(transaction.status().code());
    }
    auto hook = runtime.value()->Attach(target_address, callbacks);
    if (!hook.ok()) {
      CopyMessage(hook.status().ToString(), output, output_size);
      return static_cast<int>(hook.status().code());
    }
    status = transaction.value()->Commit();
    if (!status.ok()) {
      CopyMessage(status.ToString(), output, output_size);
      return static_cast<int>(status.code());
    }

    const std::uint64_t hooked = target(3U, 4U);
    status = Expect(hooked, 16U, "attached target");
    if (!status.ok()) {
      CopyMessage(status.ToString(), output, output_size);
      return static_cast<int>(status.code());
    }
    status = hook.value()->Detach();
    if (!status.ok()) {
      CopyMessage(status.ToString(), output, output_size);
      return static_cast<int>(status.code());
    }
    const std::uint64_t restored = target(3U, 4U);
    status = Expect(restored, 7U, "detached target");
    if (!status.ok()) {
      CopyMessage(status.ToString(), output, output_size);
      return static_cast<int>(status.code());
    }

    auto probe = runtime.value()->Probe(target_address, CountProbe,
                                        &callbacks_state);
    if (!probe.ok()) {
      CopyMessage(probe.status().ToString(), output, output_size);
      return static_cast<int>(probe.status().code());
    }
    const std::uint64_t probed = target(3U, 4U);
    status = probe.value()->Detach();
    if (!status.ok()) {
      CopyMessage(status.ToString(), output, output_size);
      return static_cast<int>(status.code());
    }
    if (probed != 7U || callbacks_state.probe_count.load() != 1U) {
      CopyMessage("instruction probe did not observe exactly one call", output,
                  output_size);
      return static_cast<int>(art_hook::StatusCode::kPlatformError);
    }

    constexpr std::uintptr_t kReplacementData = 0x5151U;
    art_hook::GumReplaceOptions replace_options;
    replace_options.replacement_data =
        reinterpret_cast<void *>(kReplacementData);
    g_expected_replacement_data = replace_options.replacement_data;
    g_replacement_data_seen.store(0U, std::memory_order_relaxed);
    auto replacement = runtime.value()->Replace(
        target_address, replacement_address, replace_options);
    if (!replacement.ok()) {
      g_replacement_runtime = nullptr;
      CopyMessage(replacement.status().ToString(), output, output_size);
      return static_cast<int>(replacement.status().code());
    }

    const std::uint64_t replaced = target(3U, 4U);
    auto original = FunctionFromAddress<TargetFunction>(
        replacement.value()->original_function());
    const std::uint64_t original_result = original(3U, 4U);
    status = replacement.value()->Revert();
    g_replacement_runtime = nullptr;
    if (!status.ok()) {
      CopyMessage(status.ToString(), output, output_size);
      return static_cast<int>(status.code());
    }
    const std::uint64_t final_result = target(3U, 4U);

    if (replacement_function(3U, 4U) != 13U || replaced != 13U ||
        original_result != 7U || final_result != 7U ||
        callbacks_state.enter_count.load() != 1U ||
        callbacks_state.leave_count.load() != 1U) {
      CopyMessage(
          "Gum replacement or callback counters differ: replaced=" +
              std::to_string(replaced) +
              " original=" + std::to_string(original_result) +
              " final=" + std::to_string(final_result) +
              " enter=" +
              std::to_string(callbacks_state.enter_count.load()) +
              " leave=" +
              std::to_string(callbacks_state.leave_count.load()),
          output, output_size);
      return static_cast<int>(art_hook::StatusCode::kPlatformError);
    }

    CopyMessage(
        "GUM_LIVE_TEST_PASS before=7 hooked=16 restored=7 probe=1 "
        "replaced=13 original=7 final=7 enter=1 leave=1",
        output, output_size);
    return 0;
  } catch (const std::exception &exception) {
    g_replacement_runtime = nullptr;
    CopyMessage(exception.what(), output, output_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  } catch (...) {
    g_replacement_runtime = nullptr;
    CopyMessage("unknown C++ exception", output, output_size);
    return static_cast<int>(art_hook::StatusCode::kPlatformError);
  }
}
