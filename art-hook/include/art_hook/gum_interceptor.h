// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

#include "art_hook/status.h"

namespace art_hook {

// Version-neutral C ABI used between art-hook and a concrete Frida Gum build.
// The adapter owns all Gum-version-specific structs such as GumAttachOptions.
struct GumInterceptorApi final {
  static constexpr std::uint32_t kAbiVersion = 1;

  using RawInvocationCallback = void (*)(void *context, void *user_data);
  using DestroyNotify = void (*)(void *data);

  std::uint32_t abi_version = kAbiVersion;
  std::uint32_t reserved = 0;

  void (*init_embedded)() = nullptr;
  void (*deinit_embedded)() = nullptr;
  void *(*obtain)() = nullptr;
  void (*object_unref)(void *object) = nullptr;

  void *(*make_call_listener)(RawInvocationCallback on_enter,
                              RawInvocationCallback on_leave, void *data,
                              DestroyNotify data_destroy) = nullptr;
  void *(*make_probe_listener)(RawInvocationCallback on_hit, void *data,
                               DestroyNotify data_destroy) = nullptr;

  int (*attach)(void *interceptor, void *target, void *listener,
                void *listener_function_data) = nullptr;
  void (*detach)(void *interceptor, void *listener) = nullptr;
  int (*replace)(void *interceptor, void *target, void *replacement,
                 void *replacement_data, void **original_function) = nullptr;
  void (*revert)(void *interceptor, void *target) = nullptr;
  void (*begin_transaction)(void *interceptor) = nullptr;
  void (*end_transaction)(void *interceptor) = nullptr;
  int (*flush)(void *interceptor) = nullptr;

  void *(*get_nth_argument)(void *context, std::uint32_t index) = nullptr;
  void (*replace_nth_argument)(void *context, std::uint32_t index,
                               void *value) = nullptr;
  void *(*get_return_value)(void *context) = nullptr;
  void (*replace_return_value)(void *context, void *value) = nullptr;
  void *(*get_function)(void *context) = nullptr;
  void *(*get_cpu_context)(void *context) = nullptr;
  void *(*get_return_address)(void *context) = nullptr;
  std::uint64_t (*get_thread_id)(void *context) = nullptr;
  std::uint32_t (*get_depth)(void *context) = nullptr;
  void *(*get_listener_function_data)(void *context) = nullptr;
  void *(*get_replacement_data)(void *context) = nullptr;
  void *(*get_current_invocation)() = nullptr;
};

class GumInvocationContext final {
public:
  [[nodiscard]] void *Argument(std::uint32_t index) const noexcept;
  void ReplaceArgument(std::uint32_t index, void *value) const noexcept;
  [[nodiscard]] void *ReturnValue() const noexcept;
  void ReplaceReturnValue(void *value) const noexcept;

  [[nodiscard]] void *function() const noexcept;
  [[nodiscard]] void *cpu_context() const noexcept;
  [[nodiscard]] void *return_address() const noexcept;
  [[nodiscard]] std::uint64_t thread_id() const noexcept;
  [[nodiscard]] std::uint32_t depth() const noexcept;
  [[nodiscard]] void *listener_function_data() const noexcept;
  [[nodiscard]] void *replacement_data() const noexcept;
  [[nodiscard]] void *raw() const noexcept { return context_; }

private:
  friend class GumInterceptorRuntime;

  GumInvocationContext(const GumInterceptorApi *api, void *context) noexcept
      : api_(api), context_(context) {}

  const GumInterceptorApi *api_ = nullptr;
  void *context_ = nullptr;
};

using GumInvocationCallback =
    void (*)(GumInvocationContext &context, void *user_data) noexcept;

struct GumInvocationCallbacks final {
  GumInvocationCallback on_enter = nullptr;
  GumInvocationCallback on_leave = nullptr;
  void *user_data = nullptr;
};

struct GumInterceptorRuntimeOptions final {
  // Enable only when the embedding owns Gum. A Frida agent or CModule already
  // runs inside an initialized Gum runtime and must leave this false.
  bool manage_embedded_lifecycle = false;
  bool auto_flush = true;
};

struct GumAttachOptions final {
  void *listener_function_data = nullptr;
};

struct GumReplaceOptions final {
  void *replacement_data = nullptr;
};

class GumInlineHook;
class GumReplacementHook;
class GumInterceptorTransaction;

class GumInterceptorRuntime final
    : public std::enable_shared_from_this<GumInterceptorRuntime> {
public:
  ~GumInterceptorRuntime() noexcept;

  GumInterceptorRuntime(const GumInterceptorRuntime &) = delete;
  GumInterceptorRuntime &operator=(const GumInterceptorRuntime &) = delete;
  GumInterceptorRuntime(GumInterceptorRuntime &&) = delete;
  GumInterceptorRuntime &operator=(GumInterceptorRuntime &&) = delete;

  [[nodiscard]] static Result<std::shared_ptr<GumInterceptorRuntime>>
  Create(GumInterceptorApi api,
         const GumInterceptorRuntimeOptions &options = {});

  [[nodiscard]] Result<std::unique_ptr<GumInlineHook>>
  Attach(void *target, GumInvocationCallbacks callbacks,
         const GumAttachOptions &options = {});
  [[nodiscard]] Result<std::unique_ptr<GumInlineHook>>
  Probe(void *instruction, GumInvocationCallback on_hit, void *user_data,
        const GumAttachOptions &options = {});
  [[nodiscard]] Result<std::unique_ptr<GumReplacementHook>>
  Replace(void *target, void *replacement,
          const GumReplaceOptions &options = {});

  [[nodiscard]] Result<std::unique_ptr<GumInterceptorTransaction>>
  BeginTransaction();
  [[nodiscard]] Status Flush();
  [[nodiscard]] std::optional<GumInvocationContext>
  CurrentInvocation() const noexcept;

private:
  friend class GumInlineHook;
  friend class GumReplacementHook;
  friend class GumInterceptorTransaction;

  struct ListenerState;

  GumInterceptorRuntime(GumInterceptorApi api,
                        GumInterceptorRuntimeOptions options,
                        void *interceptor) noexcept
      : api_(api), options_(options), interceptor_(interceptor) {}

  static void OnEnterThunk(void *context, void *data) noexcept;
  static void OnLeaveThunk(void *context, void *data) noexcept;
  static void OnProbeThunk(void *context, void *data) noexcept;
  static void DestroyListenerState(void *data) noexcept;

  [[nodiscard]] Status MaybeFlushLocked();
  [[nodiscard]] Status DetachLocked(void *listener, bool *active);
  [[nodiscard]] Status RevertLocked(void *target, bool *active);

  GumInterceptorApi api_;
  GumInterceptorRuntimeOptions options_;
  void *interceptor_ = nullptr;
  bool embedded_initialized_ = false;
  std::size_t transaction_depth_ = 0;
  mutable std::recursive_mutex mutex_;
};

// Owns a Gum call listener or probe attached at a native instruction address.
class GumInlineHook final {
public:
  ~GumInlineHook() noexcept;

  GumInlineHook(const GumInlineHook &) = delete;
  GumInlineHook &operator=(const GumInlineHook &) = delete;
  GumInlineHook(GumInlineHook &&) = delete;
  GumInlineHook &operator=(GumInlineHook &&) = delete;

  [[nodiscard]] Status Detach();
  [[nodiscard]] bool active() const noexcept { return active_; }
  [[nodiscard]] bool is_probe() const noexcept { return probe_; }
  [[nodiscard]] void *target() const noexcept { return target_; }

private:
  friend class GumInterceptorRuntime;

  GumInlineHook(std::shared_ptr<GumInterceptorRuntime> runtime, void *target,
                void *listener, bool probe) noexcept
      : runtime_(std::move(runtime)), target_(target), listener_(listener),
        probe_(probe) {}

  std::shared_ptr<GumInterceptorRuntime> runtime_;
  void *target_ = nullptr;
  void *listener_ = nullptr;
  bool probe_ = false;
  bool active_ = true;
};

// Owns a Gum replacement and the callable original-function trampoline.
class GumReplacementHook final {
public:
  ~GumReplacementHook() noexcept;

  GumReplacementHook(const GumReplacementHook &) = delete;
  GumReplacementHook &operator=(const GumReplacementHook &) = delete;
  GumReplacementHook(GumReplacementHook &&) = delete;
  GumReplacementHook &operator=(GumReplacementHook &&) = delete;

  [[nodiscard]] Status Revert();
  [[nodiscard]] bool active() const noexcept { return active_; }
  [[nodiscard]] void *target() const noexcept { return target_; }
  [[nodiscard]] void *replacement() const noexcept { return replacement_; }
  [[nodiscard]] void *original_function() const noexcept { return original_; }

private:
  friend class GumInterceptorRuntime;

  GumReplacementHook(std::shared_ptr<GumInterceptorRuntime> runtime,
                     void *target, void *replacement,
                     void *original) noexcept
      : runtime_(std::move(runtime)), target_(target),
        replacement_(replacement), original_(original) {}

  std::shared_ptr<GumInterceptorRuntime> runtime_;
  void *target_ = nullptr;
  void *replacement_ = nullptr;
  void *original_ = nullptr;
  bool active_ = true;
};

// Holds the runtime lock across a Gum transaction so attachment batches from
// different threads cannot interleave. Commit applies and optionally flushes.
class GumInterceptorTransaction final {
public:
  ~GumInterceptorTransaction() noexcept;

  GumInterceptorTransaction(const GumInterceptorTransaction &) = delete;
  GumInterceptorTransaction &operator=(const GumInterceptorTransaction &) =
      delete;
  GumInterceptorTransaction(GumInterceptorTransaction &&) = delete;
  GumInterceptorTransaction &operator=(GumInterceptorTransaction &&) = delete;

  [[nodiscard]] Status Commit();
  [[nodiscard]] bool active() const noexcept { return active_; }

private:
  friend class GumInterceptorRuntime;

  GumInterceptorTransaction(
      std::shared_ptr<GumInterceptorRuntime> runtime,
      std::unique_lock<std::recursive_mutex> lock) noexcept
      : runtime_(std::move(runtime)), lock_(std::move(lock)) {}

  std::shared_ptr<GumInterceptorRuntime> runtime_;
  std::unique_lock<std::recursive_mutex> lock_;
  bool active_ = true;
};

} // namespace art_hook
