// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "art_hook/arm64_trampoline.h"
#include "art_hook/art_deoptimization.h"
#include "art_hook/art_entrypoint.h"
#include "art_hook/art_flags.h"
#include "art_hook/art_method.h"
#include "art_hook/art_quick_hook.h"
#include "art_hook/code_allocator.h"
#include "art_hook/dex.h"
#include "art_hook/gum_interceptor.h"
#include "art_hook/hotspot_method.h"
#include "art_hook/instruction_scan.h"
#include "art_hook/java_proxy.h"
#include "art_hook/jni_types.h"
#include "art_hook/lru.h"
#include "art_hook/lsplant_arm64_bridge.h"
#if defined(ART_HOOK_HAS_LSPLANT)
#include "art_hook/lsplant_backend.h"
#endif
#include "art_hook/memoize.h"
#include "art_hook/runtime_api.h"
#include "art_hook/status.h"

namespace {

int g_failures = 0;

void Check(bool condition, const char *expression, int line) {
  if (!condition) {
    ++g_failures;
    std::cerr << "FAIL line " << line << ": " << expression << '\n';
  }
}

#define CHECK(expression) Check((expression), #expression, __LINE__)

void TestStatus() {
  art_hook::Status ok;
  CHECK(ok.ok());
  art_hook::Status error(art_hook::StatusCode::kNotFound, "missing");
  CHECK(!error.ok());
  CHECK(error.ToString() == "NOT_FOUND: missing");
}

void TestLru() {
  std::vector<int> destroyed;
  art_hook::LruCache<std::string, int> cache(
      2, [&destroyed](int &value, void *) { destroyed.push_back(value); });
  cache.Put("a", 1);
  cache.Put("b", 2);
  CHECK(cache.Get("a") == std::optional<int>(1));
  cache.Put("c", 3);
  CHECK(!cache.Get("b").has_value());
  CHECK(destroyed == std::vector<int>({2}));
  cache.Put("a", 4);
  CHECK(destroyed == std::vector<int>({2, 1}));
  cache.Dispose();
  CHECK(cache.size() == 0);
}

void TestMemoize() {
  int calls = 0;
  art_hook::Memoized<int> value([&calls] { return ++calls; });
  CHECK(value.Get() == 1);
  CHECK(value.Get() == 1);
  CHECK(calls == 1);
}

void TestInstructionScan() {
  struct Instruction final {
    int address;
    int next;
  };
  auto value = art_hook::ParseInstructionsAt(
      10,
      [](int address) {
        return Instruction{address, address + 4};
      },
      [](const Instruction &instruction,
         const Instruction *previous) -> std::optional<int> {
        if (instruction.address == 18 && previous != nullptr) {
          return previous->address;
        }
        return std::nullopt;
      },
      8);
  CHECK(value == std::optional<int>(14));
}

void TestTypes() {
  auto integer = art_hook::ParseType("int");
  CHECK(integer.ok());
  CHECK(integer.value().jni_name == "I");
  CHECK(integer.value().byte_size == 4);

  auto object = art_hook::ParseType("java.lang.String");
  CHECK(object.ok());
  CHECK(object.value().jni_name == "Ljava/lang/String;");

  auto array = art_hook::ParseType("java.lang.String[][]");
  CHECK(array.ok());
  CHECK(array.value().jni_name == "[[Ljava/lang/String;");
  CHECK(array.value().array_dimensions == 2);

  auto method = art_hook::ParseMethodDescriptor("(ILjava/lang/String;[J)V");
  CHECK(method.ok());
  CHECK(method.value().arguments.size() == 3);
  CHECK(method.value().return_type.jni_name == "V");
  CHECK(method.value().shorty == "VILL");

  CHECK(!art_hook::ParseMethodDescriptor("(I").ok());
  CHECK(art_hook::MakeJniObjectTypeName("java.lang.String") ==
        "Ljava/lang/String;");
}

void TestJavaProxyIndex() {
  art_hook::JavaProxyClass derived;
  derived.name = "com.example.Derived";
  derived.members = {
      {art_hook::MemberKind::kConstructor, "<init>", "(I)V", 0x0001},
      {art_hook::MemberKind::kMethod, "run", "(I)I", 0x0001},
      {art_hook::MemberKind::kMethod, "run", "(Ljava/lang/String;)I",
       0x0001},
      {art_hook::MemberKind::kField, "value", "I", 0x0001},
  };
  art_hook::JavaProxyClass base;
  base.name = "com.example.Base";
  base.members = {
      {art_hook::MemberKind::kMethod, "run", "(J)J", 0x0001},
      {art_hook::MemberKind::kMethod, "baseOnly", "()V", 0x0001},
      {art_hook::MemberKind::kField, "value", "J", 0x0001},
  };

  auto index = art_hook::JavaProxyIndex::Create({derived, base});
  CHECK(index.ok());
  if (!index.ok()) {
    return;
  }
  CHECK(index.value()->Has("run"));
  CHECK(index.value()->Has("baseOnly"));
  CHECK(!index.value()->Has("missing"));

  const auto names = index.value()->List();
  CHECK(names == std::vector<std::string>(
                     {"run", "baseOnly", "value", "<init>"}));

  const auto run_members = index.value()->Find("run");
  CHECK(run_members.size() == 2U);
  CHECK(run_members.size() == 2U && run_members[0].inheritance_depth == 0U);
  CHECK(run_members.size() == 2U &&
        run_members[0].declaring_class == "com.example.Derived");

  auto int_run = index.value()->ResolveMethod(
      "run", {art_hook::JavaValue::Int(7)});
  CHECK(int_run.ok());
  CHECK(int_run.ok() && int_run.value().member.descriptor == "(I)I");
  auto string_run = index.value()->ResolveMethod(
      "run", {art_hook::JavaValue::Object(nullptr)});
  CHECK(string_run.ok());
  CHECK(string_run.ok() &&
        string_run.value().member.descriptor == "(Ljava/lang/String;)I");
  CHECK(!index.value()
             ->ResolveMethod("run", {art_hook::JavaValue::Long(7)})
             .ok());

  auto constructor = index.value()->ResolveConstructor(
      {art_hook::JavaValue::Int(1)}, "(I)V");
  CHECK(constructor.ok());
  auto field = index.value()->ResolveField("value");
  CHECK(field.ok());
  CHECK(field.ok() && field.value().member.descriptor == "I");
}

void TestDex(const char *output_path) {
  CHECK(art_hook::EncodeUleb128(0) == std::vector<std::uint8_t>({0}));
  CHECK(art_hook::EncodeUleb128(0x80) ==
        std::vector<std::uint8_t>({0x80, 0x01}));

  art_hook::DexClassSpec spec;
  spec.name = "Lre/frida/NativeProbe;";
  spec.fields.push_back({"value", "I", art_hook::kDexAccPublic});
  spec.methods.push_back(
      {"ping", "I", {"I"}, art_hook::kDexAccPublic | art_hook::kDexAccNative});
  spec.methods.push_back({"name",
                          "Ljava/lang/String;",
                          {},
                          art_hook::kDexAccPublic | art_hook::kDexAccNative});

  art_hook::DexBuilder builder;
  auto dex = builder.Build(std::move(spec));
  if (!dex.ok()) {
    std::cerr << "DEX build failed: " << dex.status().ToString() << '\n';
  }
  CHECK(dex.ok());
  if (dex.ok()) {
    CHECK(dex.value().size() > 0x70);
    CHECK(art_hook::ValidateDex(dex.value()).ok());
    if (output_path != nullptr) {
      std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
      output.write(reinterpret_cast<const char *>(dex.value().data()),
                   static_cast<std::streamsize>(dex.value().size()));
      CHECK(output.good());
    }
    auto damaged = dex.value();
    damaged.back() ^= 1U;
    CHECK(!art_hook::ValidateDex(damaged).ok());
  }
}

void TestAllocator() {
  art_hook::CodeAllocator allocator(64);
  auto first = allocator.Allocate();
  auto second = allocator.Allocate();
  CHECK(first.ok());
  CHECK(second.ok());
  CHECK(first.ok() && second.ok() && first.value() != second.value());
  if (first.ok()) {
    std::memset(first.value(), 0, allocator.slice_size());
    CHECK(allocator.Free(first.value()).ok());
  }
  CHECK(allocator.Seal().ok());
  CHECK(!allocator.Allocate().ok());
}

class TestMutationGate final : public art_hook::ArtMutationGate {
public:
  art_hook::Status Run(const Operation &operation) noexcept override {
    ++run_count;
    try {
      return operation();
    } catch (...) {
      return {art_hook::StatusCode::kPlatformError,
              "test mutation operation threw"};
    }
  }

  int run_count = 0;
};

int g_suspend_count = 0;
int g_resume_count = 0;

void TestSuspendAll(void *, const char *, bool) { ++g_suspend_count; }
void TestResumeAll(void *) { ++g_resume_count; }

void TestThreadListMutationGate() {
  g_suspend_count = 0;
  g_resume_count = 0;
  int thread_list = 0;
  art_hook::ArtThreadListMutationGate gate(&thread_list, TestSuspendAll,
                                           TestResumeAll, "art-hook-test");
  const auto status = gate.Run([]() -> art_hook::Status {
    throw std::runtime_error("expected test exception");
  });
  CHECK(!status.ok());
  CHECK(g_suspend_count == 1);
  CHECK(g_resume_count == 1);

  g_suspend_count = 0;
  g_resume_count = 0;
  int nested_calls = 0;
  art_hook::ArtThreadListMutationGate nested_gate(
      &thread_list, TestSuspendAll, TestResumeAll, "art-hook nested test");
  const auto nested = gate.Run([&]() -> art_hook::Status {
    ++nested_calls;
    return nested_gate.Run([&]() -> art_hook::Status {
      ++nested_calls;
      return art_hook::Status::Ok();
    });
  });
  CHECK(nested.ok());
  CHECK(nested_calls == 2);
  CHECK(g_suspend_count == 1);
  CHECK(g_resume_count == 1);
}

struct ConcurrentSuspensionState final {
  std::atomic<int> active{0};
  std::atomic<int> maximum_active{0};
  std::atomic<int> suspend_calls{0};
  std::atomic<int> resume_calls{0};
};

void ConcurrentSuspendAll(void *thread_list, const char *, bool) {
  auto *state = static_cast<ConcurrentSuspensionState *>(thread_list);
  ++state->suspend_calls;
  const int active = state->active.fetch_add(1) + 1;
  int maximum = state->maximum_active.load();
  while (maximum < active &&
         !state->maximum_active.compare_exchange_weak(maximum, active)) {
  }
}

void ConcurrentResumeAll(void *thread_list) {
  auto *state = static_cast<ConcurrentSuspensionState *>(thread_list);
  state->active.fetch_sub(1);
  ++state->resume_calls;
}

void TestConcurrentThreadListMutationGate() {
  ConcurrentSuspensionState state;
  std::atomic<int> operations{0};
  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  for (int index = 0; index != 8; ++index) {
    workers.emplace_back([&] {
      art_hook::ArtThreadListMutationGate gate(&state, ConcurrentSuspendAll,
                                               ConcurrentResumeAll,
                                               "art-hook concurrent test");
      const auto status = gate.Run([&]() -> art_hook::Status {
        ++operations;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        return art_hook::Status::Ok();
      });
      if (!status.ok()) {
        ++failures;
      }
    });
  }
  for (auto &worker : workers) {
    worker.join();
  }
  CHECK(failures.load() == 0);
  CHECK(operations.load() == 8);
  CHECK(state.suspend_calls.load() == 8);
  CHECK(state.resume_calls.load() == 8);
  CHECK(state.maximum_active.load() == 1);
  CHECK(state.active.load() == 0);
}

void TestArtAccessFlags() {
  CHECK(art_hook::GetArtCompileDontBotherFlag(23).ok());
  CHECK(art_hook::GetArtCompileDontBotherFlag(23).value() == 0U);
  CHECK(art_hook::GetArtCompileDontBotherFlag(26).value() == 0x01000000U);
  CHECK(art_hook::GetArtCompileDontBotherFlag(30).value() == 0x02000000U);
  CHECK(!art_hook::GetArtCompileDontBotherFlag(20).ok());

  art_hook::ArtAccessFlagMutation invalid;
  invalid.clear_mask = art_hook::kArtAccFinal;
  invalid.set_mask = art_hook::kArtAccFinal;
  CHECK(!invalid.Validate().ok());

  const std::uint32_t original =
      art_hook::kArtAccPrivate | art_hook::kArtAccFinal |
      art_hook::kArtAccFastInterpreterToInterpreterInvoke |
      art_hook::kArtAccSingleImplementation |
      art_hook::kArtAccNterpEntryPointFastPath |
      art_hook::kArtAccSkipAccessChecks;
  art_hook::ArtHookAccessFlagOptions options;
  options.android_api_level = 30;
  options.make_public = true;
  options.remove_final = true;
  auto mutation = art_hook::BuildArtHookAccessFlagMutation(original, options);
  CHECK(mutation.ok());
  auto target = mutation.ok()
                    ? mutation.value().Apply(original)
                    : art_hook::Result<std::uint32_t>(mutation.status());
  CHECK(target.ok());
  if (target.ok()) {
    CHECK((target.value() & art_hook::kArtAccPublic) != 0U);
    CHECK(
        (target.value() & (art_hook::kArtAccPrivate |
                           art_hook::kArtAccProtected | art_hook::kArtAccFinal |
                           art_hook::kArtAccFastInterpreterToInterpreterInvoke |
                           art_hook::kArtAccSingleImplementation |
                           art_hook::kArtAccNterpEntryPointFastPath |
                           art_hook::kArtAccSkipAccessChecks)) == 0U);
    CHECK((target.value() & 0x02000000U) != 0U);
  }

  alignas(16) std::array<std::uint8_t, 48> method{};
  void *const jni_code = reinterpret_cast<void *>(0x10001000U);
  void *const quick_code = reinterpret_cast<void *>(0x20002000U);
  std::memcpy(method.data() + 4, &original, sizeof(original));
  std::memcpy(method.data() + 16, &jni_code, sizeof(jni_code));
  std::memcpy(method.data() + 24, &quick_code, sizeof(quick_code));
  art_hook::ArtMethodLayout layout;
  layout.method_size = 32;
  layout.access_flags_offset = 4;
  layout.jni_code_offset = 16;
  layout.quick_code_offset = 24;

  g_suspend_count = 0;
  g_resume_count = 0;
  int thread_list = 0;
  art_hook::ArtThreadListMutationGate gate(
      &thread_list, TestSuspendAll, TestResumeAll, "art-hook flags test");
  auto updated = art_hook::UpdateArtAccessFlagsSafe(method.data(), layout,
                                                    mutation.value(), gate);
  CHECK(updated.ok());
  CHECK(updated.ok() && updated.value().before == original);
  CHECK(updated.ok() && target.ok() && updated.value().after == target.value());
  CHECK(g_suspend_count == 1);
  CHECK(g_resume_count == 1);

  auto read = art_hook::ReadArtAccessFlagsSafe(method.data(), layout, gate);
  CHECK(read.ok());
  CHECK(read.ok() && target.ok() && read.value() == target.value());
  auto restored =
      art_hook::WriteArtAccessFlagsSafe(method.data(), layout, original, gate);
  CHECK(restored.ok());
  CHECK(restored.ok() && restored.value().after == original);
  CHECK(g_suspend_count == 3);
  CHECK(g_resume_count == 3);

  auto policy_updated = art_hook::ApplyArtHookAccessFlagsSafe(
      method.data(), layout, options, gate);
  CHECK(policy_updated.ok());
  CHECK(policy_updated.ok() && target.ok() &&
        policy_updated.value().after == target.value());
  auto policy_restored =
      art_hook::WriteArtAccessFlagsSafe(method.data(), layout, original, gate);
  CHECK(policy_restored.ok());
  CHECK(g_suspend_count == 5);
  CHECK(g_resume_count == 5);
}

void TestArtMethod() {
  alignas(16) std::array<std::uint8_t, 80> method{};
  constexpr std::uint32_t kFlags = 0x0109U;
  void *const jni_code = reinterpret_cast<void *>(0x10001000U);
  void *const quick_code = reinterpret_cast<void *>(0x20002000U);
  std::memcpy(method.data() + 4, &kFlags, sizeof(kFlags));
  std::memcpy(method.data() + 16, &jni_code, sizeof(jni_code));
  std::memcpy(method.data() + 24, &quick_code, sizeof(quick_code));

  art_hook::ArtMethodProbeSpec probe;
  probe.method = method.data();
  probe.expected_jni_code_start = 0x10000000U;
  probe.expected_jni_code_end = 0x10010000U;
  probe.expected_access_flags = kFlags | 0x40000000U;
  probe.relevant_access_flags_mask = ~0x40000000U;
  probe.android_api_level = 30;
  auto layout = art_hook::ProbeArtMethodLayout(probe);
  CHECK(layout.ok());
  if (!layout.ok()) {
    return;
  }
  CHECK(layout.value().method_size == 32);
  CHECK(layout.value().access_flags_offset == 4);
  CHECK(layout.value().jni_code_offset == 16);
  CHECK(layout.value().quick_code_offset == 24);

  auto flag_plan = art_hook::BuildArtHookFlagPlan(
      kFlags | art_hook::kArtAccFastInterpreterToInterpreterInvoke |
          art_hook::kArtAccSingleImplementation,
      30);
  CHECK(flag_plan.ok());
  CHECK(flag_plan.ok() &&
        (flag_plan.value().target_flags &
         art_hook::kArtAccFastInterpreterToInterpreterInvoke) == 0U);
  CHECK(flag_plan.ok() && (flag_plan.value().target_flags &
                           art_hook::kArtAccSingleImplementation) == 0U);
  CHECK(flag_plan.ok() && (flag_plan.value().target_flags & 0x02000000U) != 0U);
  CHECK(flag_plan.ok() &&
        (flag_plan.value().replacement_flags & art_hook::kArtAccNative) != 0U);
  CHECK(!art_hook::BuildArtHookFlagPlan(kFlags, 19).ok());

  auto overlapping = layout.value();
  overlapping.jni_code_offset = overlapping.access_flags_offset;
  CHECK(!overlapping.Validate().ok());

  auto clone = art_hook::CloneArtMethod(method.data(), layout.value(), 30);
  CHECK(clone.ok());
  CHECK(clone.ok() && clone.value().size() == 32);
  CHECK(!art_hook::CloneArtMethod(method.data(), layout.value(), 22).ok());

  auto patch = art_hook::ArtMethodPatch::Create(method.data(), layout.value());
  CHECK(patch.ok());
  if (!patch.ok()) {
    return;
  }
  void *const replacement = reinterpret_cast<void *>(0x30003000U);
  CHECK(patch.value().SetAccessFlags(0x0101U).ok());
  CHECK(patch.value().SetQuickCode(replacement).ok());

  TestMutationGate gate;
  CHECK(patch.value().Commit(gate).ok());
  auto patched_state =
      art_hook::ReadArtMethodState(method.data(), layout.value());
  CHECK(patched_state.ok());
  CHECK(patched_state.ok() && patched_state.value().access_flags == 0x0101U);
  CHECK(patched_state.ok() && patched_state.value().quick_code == replacement);
  CHECK(patch.value().Revert(gate).ok());
  auto reverted_state =
      art_hook::ReadArtMethodState(method.data(), layout.value());
  CHECK(reverted_state.ok());
  CHECK(reverted_state.ok() && reverted_state.value().access_flags == kFlags);
  CHECK(reverted_state.ok() && reverted_state.value().quick_code == quick_code);
  CHECK(gate.run_count == 2);

  auto conflict =
      art_hook::ArtMethodPatch::Create(method.data(), layout.value());
  CHECK(conflict.ok());
  void *const staged = reinterpret_cast<void *>(0x40004000U);
  void *const external = reinterpret_cast<void *>(0x50005000U);
  if (conflict.ok()) {
    CHECK(conflict.value().SetQuickCode(staged).ok());
    std::memcpy(method.data() + layout.value().quick_code_offset, &external,
                sizeof(external));
    CHECK(!conflict.value().Commit(gate).ok());
    auto conflict_state =
        art_hook::ReadArtMethodState(method.data(), layout.value());
    CHECK(conflict_state.ok());
    CHECK(conflict_state.ok() && conflict_state.value().quick_code == external);
  }
}

struct HotSpotApiTestState final {
  std::size_t native_function_offset = 0;
  int clear_code_calls = 0;
  int clear_native_calls = 0;
  int set_native_calls = 0;
  int restore_calls = 0;
  int link_calls = 0;
  int install_calls = 0;
  int sweep_calls = 0;
  bool saw_revert = false;
};

art_hook::Status HotSpotClearCode(void *user_data, void *) {
  ++static_cast<HotSpotApiTestState *>(user_data)->clear_code_calls;
  return art_hook::Status::Ok();
}

art_hook::Status HotSpotClearNative(void *user_data, void *method) {
  auto *state = static_cast<HotSpotApiTestState *>(user_data);
  ++state->clear_native_calls;
  void *empty = nullptr;
  std::memcpy(static_cast<std::uint8_t *>(method) +
                  state->native_function_offset,
              &empty, sizeof(empty));
  return art_hook::Status::Ok();
}

art_hook::Status HotSpotSetNative(void *user_data, void *method,
                                  void *implementation) {
  auto *state = static_cast<HotSpotApiTestState *>(user_data);
  ++state->set_native_calls;
  std::memcpy(static_cast<std::uint8_t *>(method) +
                  state->native_function_offset,
              &implementation, sizeof(implementation));
  return art_hook::Status::Ok();
}

art_hook::Status HotSpotRestore(void *user_data, void *, void *) {
  ++static_cast<HotSpotApiTestState *>(user_data)->restore_calls;
  return art_hook::Status::Ok();
}

art_hook::Status HotSpotLink(void *user_data, void *, void *) {
  ++static_cast<HotSpotApiTestState *>(user_data)->link_calls;
  return art_hook::Status::Ok();
}

art_hook::Status HotSpotAfterInstall(
    void *user_data, const art_hook::HotSpotInstallContext &context) {
  auto *state = static_cast<HotSpotApiTestState *>(user_data);
  ++state->install_calls;
  state->saw_revert = state->saw_revert || context.reverting;
  CHECK(context.replacement != nullptr);
  CHECK(context.previous != nullptr);
  return art_hook::Status::Ok();
}

art_hook::Status HotSpotForceSweep(void *user_data) {
  ++static_cast<HotSpotApiTestState *>(user_data)->sweep_calls;
  return art_hook::Status::Ok();
}

void TestHotSpotMethodMangler() {
  constexpr std::size_t kPointerSize = sizeof(void *);
  constexpr std::size_t kMethodSize = 96U;
  auto method_layout =
      art_hook::BuildHotSpotMethodLayout(17, kPointerSize, kMethodSize);
  CHECK(method_layout.ok());
  auto klass_layout = art_hook::BuildHotSpotInstanceKlassLayout(
      17, kPointerSize, 0x180U);
  CHECK(klass_layout.ok());
  if (!method_layout.ok() || !klass_layout.ok()) {
    return;
  }
  CHECK(method_layout.value().adapter_location ==
        art_hook::HotSpotAdapterLocation::kMethodEarly);
  CHECK(method_layout.value().access_flags_offset == 40U);
  CHECK(method_layout.value().const_method_size_offset == 24U);
  CHECK(klass_layout.value().methods_offset == 0x148U);

  std::vector<std::uint8_t> instance_klass(0x1c0U);
  std::vector<std::uint8_t> constant_pool(4U * kPointerSize);
  std::vector<std::uint8_t> methods(kPointerSize + 3U * kPointerSize);
  std::vector<std::uint8_t> const_method(64U);
  std::vector<std::uint8_t> method(kMethodSize);
  std::uint64_t cache_marker = 0x11U;
  std::uint64_t oop_marker = 0x22U;

  const auto write_pointer = [](void *address, void *value) {
    std::memcpy(address, &value, sizeof(value));
  };
  const auto read_pointer = [](const void *address) {
    void *value = nullptr;
    std::memcpy(&value, address, sizeof(value));
    return value;
  };

  write_pointer(method.data() + method_layout.value().const_method_offset,
                const_method.data());
  write_pointer(const_method.data() +
                    method_layout.value().constant_pool_offset,
                constant_pool.data());
  const std::int32_t const_words =
      static_cast<std::int32_t>(const_method.size() / kPointerSize);
  std::memcpy(const_method.data() +
                  method_layout.value().const_method_size_offset,
              &const_words, sizeof(const_words));
  const std::uint16_t method_index = 1U;
  std::memcpy(const_method.data() + method_layout.value().method_idnum_offset,
              &method_index, sizeof(method_index));

  write_pointer(constant_pool.data() +
                    method_layout.value().constant_pool_cache_offset,
                &cache_marker);
  write_pointer(constant_pool.data() +
                    method_layout.value().constant_pool_instance_klass_offset,
                instance_klass.data());
  write_pointer(instance_klass.data() + klass_layout.value().methods_offset,
                methods.data());
  write_pointer(instance_klass.data() +
                    klass_layout.value().member_names_offset,
                &oop_marker);

  const std::int32_t method_count = 3;
  std::memcpy(methods.data(), &method_count, sizeof(method_count));
  write_pointer(methods.data() + kPointerSize + method_index * kPointerSize,
                method.data());
  constexpr std::int32_t kVtableIndex = 2;
  std::memcpy(method.data() + method_layout.value().vtable_index_offset,
              &kVtableIndex, sizeof(kVtableIndex));
  write_pointer(instance_klass.data() + klass_layout.value().vtable_offset +
                    kVtableIndex * kPointerSize,
                method.data());
  constexpr std::uint32_t kOriginalFlags = 0x0001U;
  std::memcpy(method.data() + method_layout.value().access_flags_offset,
              &kOriginalFlags, sizeof(kOriginalFlags));
  void *non_null = &cache_marker;
  write_pointer(method.data() + method_layout.value().method_data_offset,
                non_null);
  write_pointer(method.data() + method_layout.value().method_counters_offset,
                non_null);
  write_pointer(method.data() + method_layout.value().adapter_offset,
                non_null);
  write_pointer(method.data() + method_layout.value().i2i_entry_offset,
                non_null);
  write_pointer(method.data() + method_layout.value().signature_handler_offset,
                non_null);
  write_pointer(const_method.data() +
                    method_layout.value().stackmap_data_offset,
                non_null);

  auto parsed = art_hook::ReadHotSpotMethod(
      method.data(), method_layout.value(), klass_layout.value());
  CHECK(parsed.ok());
  CHECK(parsed.ok() && parsed.value().method_index == method_index);
  CHECK(parsed.ok() && parsed.value().vtable_index == kVtableIndex);
  auto clone = art_hook::CloneHotSpotMethod(
      method.data(), method_layout.value(), klass_layout.value());
  CHECK(clone.ok());
  CHECK(clone.ok() && clone.value().record().method != method.data());
  CHECK(clone.ok() &&
        clone.value().record().const_method != const_method.data());

  HotSpotApiTestState api_state;
  api_state.native_function_offset =
      method_layout.value().native_function_offset;
  art_hook::HotSpotMethodApi api;
  api.user_data = &api_state;
  api.clear_code = HotSpotClearCode;
  api.clear_native_function = HotSpotClearNative;
  api.set_native_function = HotSpotSetNative;
  api.restore_unshareable_info = HotSpotRestore;
  api.link_method = HotSpotLink;
  api.after_install = HotSpotAfterInstall;
  api.force_sweep = HotSpotForceSweep;
  auto gate = std::make_shared<art_hook::HotSpotDirectMutationGate>();
  void *method_id = method.data();
  auto mangler = art_hook::HotSpotMethodMangler::Create(
      &method_id, method_layout.value(), klass_layout.value(), api, gate);
  CHECK(mangler.ok());
  if (!mangler.ok()) {
    return;
  }

  void *implementation = reinterpret_cast<void *>(0x12345678U);
  CHECK(mangler.value()->Replace(implementation, &oop_marker).ok());
  CHECK(mangler.value()->active());
  void *replacement = mangler.value()->replacement_method();
  CHECK(replacement != nullptr && replacement != method.data());
  CHECK(method_id == replacement);
  CHECK(read_pointer(methods.data() + kPointerSize +
                     method_index * kPointerSize) == replacement);
  CHECK(read_pointer(instance_klass.data() + klass_layout.value().vtable_offset +
                     kVtableIndex * kPointerSize) == replacement);
  CHECK(read_pointer(static_cast<std::uint8_t *>(replacement) +
                     method_layout.value().native_function_offset) ==
        implementation);
  CHECK(read_pointer(static_cast<std::uint8_t *>(replacement) +
                     method_layout.value().method_data_offset) == nullptr);
  std::uint32_t live_flags = 0;
  std::memcpy(&live_flags,
              method.data() + method_layout.value().access_flags_offset,
              sizeof(live_flags));
  CHECK((live_flags & (art_hook::kJvmAccIsOld |
                       art_hook::kJvmAccIsObsolete)) != 0U);
  CHECK(api_state.clear_code_calls == 1);
  CHECK(api_state.restore_calls == 1);
  CHECK(api_state.link_calls == 1);
  CHECK(api_state.install_calls == 1);

  auto original_target = mangler.value()->ResolveTarget();
  CHECK(original_target.ok());
  CHECK(original_target.ok() && *original_target.value() == method.data());
  std::int32_t direct_vtable_index = 0;
  std::memcpy(&direct_vtable_index,
              method.data() + method_layout.value().vtable_index_offset,
              sizeof(direct_vtable_index));
  CHECK(direct_vtable_index == -2);

  void *second_implementation = reinterpret_cast<void *>(0x87654321U);
  CHECK(mangler.value()->Replace(second_implementation, &oop_marker).ok());
  CHECK(api_state.set_native_calls == 2);
  CHECK(read_pointer(static_cast<std::uint8_t *>(replacement) +
                     method_layout.value().native_function_offset) ==
        second_implementation);

  CHECK(mangler.value()->Revert(&oop_marker).ok());
  CHECK(!mangler.value()->active());
  CHECK(method_id == method.data());
  CHECK(read_pointer(methods.data() + kPointerSize +
                     method_index * kPointerSize) == method.data());
  CHECK(read_pointer(instance_klass.data() + klass_layout.value().vtable_offset +
                     kVtableIndex * kPointerSize) == method.data());
  std::memcpy(&live_flags,
              method.data() + method_layout.value().access_flags_offset,
              sizeof(live_flags));
  CHECK(live_flags == kOriginalFlags);
  std::memcpy(&direct_vtable_index,
              method.data() + method_layout.value().vtable_index_offset,
              sizeof(direct_vtable_index));
  CHECK(direct_vtable_index == kVtableIndex);
  CHECK(api_state.install_calls == 2);
  CHECK(api_state.saw_revert);
  CHECK(api_state.sweep_calls == 1);
}

struct IntegerDispatchData final {
  std::uint64_t delta;
};

void *IntegerDispatch(art_hook::Arm64CpuContext *context,
                      void *user_data) noexcept {
  auto *data = static_cast<IntegerDispatchData *>(user_data);
  context->x[0] = context->x[0] + context->x[1] + data->delta;
  return nullptr;
}

void *FloatingDispatch(art_hook::Arm64CpuContext *context, void *) noexcept {
  double first = 0;
  double second = 0;
  std::memcpy(&first, &context->q[0].low, sizeof(first));
  std::memcpy(&second, &context->q[1].low, sizeof(second));
  const double result = first + second;
  std::memcpy(&context->q[0].low, &result, sizeof(result));
  context->q[0].high = 0;
  return nullptr;
}

__attribute__((noinline)) std::uint64_t OriginalAdd(std::uint64_t first,
                                                    std::uint64_t second) {
  return first + second;
}

struct TailDispatchData final {
  void *target;
};

void *TailDispatch(art_hook::Arm64CpuContext *, void *user_data) noexcept {
  return static_cast<TailDispatchData *>(user_data)->target;
}

void TestArtQuickHook() {
  alignas(16) std::array<std::uint8_t, 48> method{};
  constexpr std::uint32_t kFlags = 0x0109U;
  void *const jni_code = reinterpret_cast<void *>(0x10001000U);
  void *const quick_code = reinterpret_cast<void *>(0x20002000U);
  std::memcpy(method.data() + 4, &kFlags, sizeof(kFlags));
  std::memcpy(method.data() + 16, &jni_code, sizeof(jni_code));
  std::memcpy(method.data() + 24, &quick_code, sizeof(quick_code));

  art_hook::ArtMethodLayout layout;
  layout.method_size = 32;
  layout.access_flags_offset = 4;
  layout.jni_code_offset = 16;
  layout.quick_code_offset = 24;

  auto gate = std::make_shared<TestMutationGate>();
  IntegerDispatchData data{3};
  art_hook::ArtQuickHookOptions options;
  options.access_flags = 0x0101U;
  auto hook = art_hook::ArtQuickHook::Create(
      method.data(), layout, IntegerDispatch, &data, gate, options);
  CHECK(hook.ok());
  if (!hook.ok()) {
    return;
  }
  CHECK(hook.value()->original_quick_code() == quick_code);
  CHECK(hook.value()->Activate().ok());
  CHECK(hook.value()->active());
  auto active_state = art_hook::ReadArtMethodState(method.data(), layout);
  CHECK(active_state.ok());
  CHECK(active_state.ok() && active_state.value().quick_code ==
                                 hook.value()->trampoline_entrypoint());
  CHECK(active_state.ok() && active_state.value().access_flags == 0x0101U);
  CHECK(hook.value()->Deactivate().ok());
  CHECK(!hook.value()->active());

  auto restored_state = art_hook::ReadArtMethodState(method.data(), layout);
  CHECK(restored_state.ok());
  CHECK(restored_state.ok() && restored_state.value().quick_code == quick_code);
  CHECK(restored_state.ok() && restored_state.value().access_flags == kFlags);

  {
    auto scoped = art_hook::ArtQuickHook::Create(method.data(), layout,
                                                 IntegerDispatch, &data, gate);
    CHECK(scoped.ok());
    if (scoped.ok()) {
      CHECK(scoped.value()->Activate().ok());
    }
  }
  restored_state = art_hook::ReadArtMethodState(method.data(), layout);
  CHECK(restored_state.ok());
  CHECK(restored_state.ok() && restored_state.value().quick_code == quick_code);
  CHECK(gate->run_count == 4);

  auto safe = art_hook::HookMethodSafe(method.data(), layout, IntegerDispatch,
                                       &data, gate);
  CHECK(safe.ok());
  CHECK(safe.ok() && safe.value()->active());
  CHECK(safe.ok() && safe.value()->Deactivate().ok());
  CHECK(gate->run_count == 6);
}

struct DeoptimizationTestState final {
  bool enabled = false;
  int enable_calls = 0;
  int method_calls = 0;
  int everything_calls = 0;
  int boot_image_calls = 0;
  int prepare_calls = 0;
  int manage_calls = 0;
  std::string reason;
  art_hook::ArtLegacyDeoptimizationRequest request;
  void *method_storage = nullptr;
  std::size_t quick_code_offset = 0;
  void *deoptimized_quick_code = nullptr;
};

DeoptimizationTestState *g_deoptimization_state = nullptr;

bool TestIsDeoptimizationEnabled(void *) noexcept {
  return g_deoptimization_state->enabled;
}

void TestEnableDeoptimization(void *) {
  g_deoptimization_state->enabled = true;
  ++g_deoptimization_state->enable_calls;
}

void TestDeoptimizeMethod(void *, void *method) {
  ++g_deoptimization_state->method_calls;
  CHECK(method == g_deoptimization_state->method_storage);
  if (g_deoptimization_state->method_storage != nullptr &&
      g_deoptimization_state->deoptimized_quick_code != nullptr) {
    std::memcpy(
        static_cast<std::uint8_t *>(g_deoptimization_state->method_storage) +
            g_deoptimization_state->quick_code_offset,
        &g_deoptimization_state->deoptimized_quick_code, sizeof(void *));
  }
}

void TestDeoptimizeEverything(void *, const char *reason) {
  ++g_deoptimization_state->everything_calls;
  g_deoptimization_state->reason = reason;
}

void TestDeoptimizeBootImage(void *) {
  ++g_deoptimization_state->boot_image_calls;
}

art_hook::Status TestPrepareLegacyDebugger(void *) noexcept {
  ++g_deoptimization_state->prepare_calls;
  return art_hook::Status::Ok();
}

void TestLegacyRequest(
    const art_hook::ArtLegacyDeoptimizationRequest *request) {
  g_deoptimization_state->request = *request;
}

void TestLegacyManage() { ++g_deoptimization_state->manage_calls; }

art_hook::ArtDeoptimizationApi
MakeInstrumentationApi(DeoptimizationTestState *state) {
  g_deoptimization_state = state;
  art_hook::ArtDeoptimizationApi api;
  api.android_api_level = 30;
  api.instrumentation = state;
  api.runtime = state;
  api.is_deoptimization_enabled = TestIsDeoptimizationEnabled;
  api.enable_deoptimization = TestEnableDeoptimization;
  api.deoptimize_method = TestDeoptimizeMethod;
  api.deoptimize_everything = TestDeoptimizeEverything;
  api.deoptimize_boot_image = TestDeoptimizeBootImage;
  return api;
}

void TestArtDeoptimization() {
  DeoptimizationTestState state;
  auto runnable = std::make_shared<art_hook::ArtAlreadyRunnableGate>();
  auto deoptimizer = art_hook::ArtDeoptimizer::Create(
      MakeInstrumentationApi(&state), runnable);
  CHECK(deoptimizer.ok());
  if (!deoptimizer.ok()) {
    return;
  }

  int method = 0;
  state.method_storage = &method;
  CHECK(deoptimizer.value()->DeoptimizeMethod(&method).ok());
  CHECK(state.enabled);
  CHECK(state.enable_calls == 1);
  CHECK(state.method_calls == 1);
  CHECK(deoptimizer.value()->DeoptimizeEverything("unit-test").ok());
  CHECK(state.enable_calls == 1);
  CHECK(state.everything_calls == 1);
  CHECK(state.reason == "unit-test");
  CHECK(deoptimizer.value()->DeoptimizeBootImage().ok());
  CHECK(state.boot_image_calls == 1);
  CHECK(!deoptimizer.value()->DeoptimizeEverything("").ok());

  DeoptimizationTestState legacy_state;
  g_deoptimization_state = &legacy_state;
  art_hook::ArtDeoptimizationApi legacy_api;
  legacy_api.android_api_level = 29;
  legacy_api.prepare_legacy_debugger = TestPrepareLegacyDebugger;
  legacy_api.legacy_request = TestLegacyRequest;
  legacy_api.legacy_manage = TestLegacyManage;
  auto legacy = art_hook::ArtDeoptimizer::Create(legacy_api, runnable);
  CHECK(legacy.ok());
  if (legacy.ok()) {
    CHECK(legacy.value()->DeoptimizeMethod(&method).ok());
    CHECK(legacy_state.request.kind ==
          static_cast<std::uint32_t>(
              art_hook::ArtLegacyDeoptimizationKind::kSelective));
    CHECK(legacy_state.request.method == &method);
    CHECK(legacy.value()->DeoptimizeEverything().ok());
    CHECK(legacy_state.request.kind ==
          static_cast<std::uint32_t>(
              art_hook::ArtLegacyDeoptimizationKind::kFull));
    CHECK(legacy_state.request.method == nullptr);
    CHECK(legacy_state.prepare_calls == 2);
    CHECK(legacy_state.manage_calls == 2);
  }

  art_hook::ArtDeoptimizationApi old_api;
  old_api.android_api_level = 23;
  auto old = art_hook::ArtDeoptimizer::Create(old_api, runnable);
  CHECK(old.ok());
  CHECK(old.ok() && !old.value()->DeoptimizeMethod(&method).ok());
  CHECK(old.ok() && !old.value()->DeoptimizeEverything().ok());
  CHECK(old.ok() && !old.value()->DeoptimizeBootImage().ok());
}

struct FakeGumListener final {
  art_hook::GumInterceptorApi::RawInvocationCallback on_enter = nullptr;
  art_hook::GumInterceptorApi::RawInvocationCallback on_leave = nullptr;
  void *data = nullptr;
  art_hook::GumInterceptorApi::DestroyNotify destroy = nullptr;
};

struct FakeGumContext final {
  std::array<void *, 4> arguments{};
  void *return_value = nullptr;
  void *function = nullptr;
  void *cpu_context = nullptr;
  void *return_address = nullptr;
  void *listener_function_data = nullptr;
  void *replacement_data = nullptr;
  std::uint64_t thread_id = 0;
  std::uint32_t depth = 0;
};

struct FakeGumState final {
  FakeGumListener *attached_listener = nullptr;
  void *attached_target = nullptr;
  void *listener_function_data = nullptr;
  void *replacement_target = nullptr;
  void *replacement_function = nullptr;
  void *replacement_data = nullptr;
  void *current_invocation = nullptr;
  int init_calls = 0;
  int deinit_calls = 0;
  int obtain_calls = 0;
  int interceptor_unref_calls = 0;
  int listener_destroy_calls = 0;
  int attach_calls = 0;
  int detach_calls = 0;
  int replace_calls = 0;
  int revert_calls = 0;
  int begin_calls = 0;
  int end_calls = 0;
  int flush_calls = 0;
  bool flush_result = true;
};

FakeGumState *g_fake_gum = nullptr;

void FakeGumInit() { ++g_fake_gum->init_calls; }
void FakeGumDeinit() { ++g_fake_gum->deinit_calls; }
void *FakeGumObtain() {
  ++g_fake_gum->obtain_calls;
  return g_fake_gum;
}

void FakeGumUnref(void *object) {
  if (object == g_fake_gum) {
    ++g_fake_gum->interceptor_unref_calls;
    return;
  }
  auto *listener = static_cast<FakeGumListener *>(object);
  if (listener->destroy != nullptr) {
    listener->destroy(listener->data);
  }
  ++g_fake_gum->listener_destroy_calls;
  delete listener;
}

void *FakeGumMakeCallListener(
    art_hook::GumInterceptorApi::RawInvocationCallback on_enter,
    art_hook::GumInterceptorApi::RawInvocationCallback on_leave, void *data,
    art_hook::GumInterceptorApi::DestroyNotify destroy) {
  return new FakeGumListener{on_enter, on_leave, data, destroy};
}

void *FakeGumMakeProbeListener(
    art_hook::GumInterceptorApi::RawInvocationCallback on_hit, void *data,
    art_hook::GumInterceptorApi::DestroyNotify destroy) {
  return new FakeGumListener{on_hit, nullptr, data, destroy};
}

int FakeGumAttach(void *, void *target, void *listener,
                  void *listener_function_data) {
  ++g_fake_gum->attach_calls;
  g_fake_gum->attached_target = target;
  g_fake_gum->attached_listener = static_cast<FakeGumListener *>(listener);
  g_fake_gum->listener_function_data = listener_function_data;
  return 0;
}

void FakeGumDetach(void *, void *listener) {
  ++g_fake_gum->detach_calls;
  CHECK(g_fake_gum->attached_listener == listener);
  g_fake_gum->attached_listener = nullptr;
  g_fake_gum->attached_target = nullptr;
}

int FakeGumReplace(void *, void *target, void *replacement,
                   void *replacement_data, void **original_function) {
  ++g_fake_gum->replace_calls;
  g_fake_gum->replacement_target = target;
  g_fake_gum->replacement_function = replacement;
  g_fake_gum->replacement_data = replacement_data;
  *original_function = reinterpret_cast<void *>(0x44440000U);
  return 0;
}

void FakeGumRevert(void *, void *target) {
  ++g_fake_gum->revert_calls;
  CHECK(g_fake_gum->replacement_target == target);
  g_fake_gum->replacement_target = nullptr;
  g_fake_gum->replacement_function = nullptr;
}

void FakeGumBegin(void *) { ++g_fake_gum->begin_calls; }
void FakeGumEnd(void *) { ++g_fake_gum->end_calls; }
int FakeGumFlush(void *) {
  ++g_fake_gum->flush_calls;
  return g_fake_gum->flush_result ? 1 : 0;
}

void *FakeGumGetArgument(void *context, std::uint32_t index) {
  return static_cast<FakeGumContext *>(context)->arguments.at(index);
}

void FakeGumReplaceArgument(void *context, std::uint32_t index, void *value) {
  static_cast<FakeGumContext *>(context)->arguments.at(index) = value;
}

void *FakeGumGetReturnValue(void *context) {
  return static_cast<FakeGumContext *>(context)->return_value;
}

void FakeGumReplaceReturnValue(void *context, void *value) {
  static_cast<FakeGumContext *>(context)->return_value = value;
}

void *FakeGumGetFunction(void *context) {
  return static_cast<FakeGumContext *>(context)->function;
}

void *FakeGumGetCpuContext(void *context) {
  return static_cast<FakeGumContext *>(context)->cpu_context;
}

void *FakeGumGetReturnAddress(void *context) {
  return static_cast<FakeGumContext *>(context)->return_address;
}

std::uint64_t FakeGumGetThreadId(void *context) {
  return static_cast<FakeGumContext *>(context)->thread_id;
}

std::uint32_t FakeGumGetDepth(void *context) {
  return static_cast<FakeGumContext *>(context)->depth;
}

void *FakeGumGetListenerFunctionData(void *context) {
  return static_cast<FakeGumContext *>(context)->listener_function_data;
}

void *FakeGumGetReplacementData(void *context) {
  return static_cast<FakeGumContext *>(context)->replacement_data;
}

void *FakeGumGetCurrentInvocation() {
  return g_fake_gum->current_invocation;
}

art_hook::GumInterceptorApi MakeFakeGumApi(FakeGumState *state) {
  g_fake_gum = state;
  art_hook::GumInterceptorApi api;
  api.init_embedded = FakeGumInit;
  api.deinit_embedded = FakeGumDeinit;
  api.obtain = FakeGumObtain;
  api.object_unref = FakeGumUnref;
  api.make_call_listener = FakeGumMakeCallListener;
  api.make_probe_listener = FakeGumMakeProbeListener;
  api.attach = FakeGumAttach;
  api.detach = FakeGumDetach;
  api.replace = FakeGumReplace;
  api.revert = FakeGumRevert;
  api.begin_transaction = FakeGumBegin;
  api.end_transaction = FakeGumEnd;
  api.flush = FakeGumFlush;
  api.get_nth_argument = FakeGumGetArgument;
  api.replace_nth_argument = FakeGumReplaceArgument;
  api.get_return_value = FakeGumGetReturnValue;
  api.replace_return_value = FakeGumReplaceReturnValue;
  api.get_function = FakeGumGetFunction;
  api.get_cpu_context = FakeGumGetCpuContext;
  api.get_return_address = FakeGumGetReturnAddress;
  api.get_thread_id = FakeGumGetThreadId;
  api.get_depth = FakeGumGetDepth;
  api.get_listener_function_data = FakeGumGetListenerFunctionData;
  api.get_replacement_data = FakeGumGetReplacementData;
  api.get_current_invocation = FakeGumGetCurrentInvocation;
  return api;
}

struct GumCallbackState final {
  int enter_calls = 0;
  int leave_calls = 0;
  int probe_calls = 0;
};

void TestGumEnter(art_hook::GumInvocationContext &context,
                  void *user_data) noexcept {
  auto *state = static_cast<GumCallbackState *>(user_data);
  ++state->enter_calls;
  CHECK(context.function() == reinterpret_cast<void *>(0x11110000U));
  CHECK(context.cpu_context() == reinterpret_cast<void *>(0x22220000U));
  CHECK(context.return_address() == reinterpret_cast<void *>(0x33330000U));
  CHECK(context.thread_id() == 37U);
  CHECK(context.depth() == 2U);
  CHECK(context.listener_function_data() ==
        reinterpret_cast<void *>(0x55550000U));
  const auto first = reinterpret_cast<std::uintptr_t>(context.Argument(0));
  context.ReplaceArgument(0, reinterpret_cast<void *>(first + 1U));
}

void TestGumLeave(art_hook::GumInvocationContext &context,
                  void *user_data) noexcept {
  auto *state = static_cast<GumCallbackState *>(user_data);
  ++state->leave_calls;
  const auto result =
      reinterpret_cast<std::uintptr_t>(context.ReturnValue());
  context.ReplaceReturnValue(reinterpret_cast<void *>(result * 2U));
}

void TestGumProbe(art_hook::GumInvocationContext &, void *user_data) noexcept {
  ++static_cast<GumCallbackState *>(user_data)->probe_calls;
}

void TestGumInterceptor() {
  FakeGumState state;
  auto api = MakeFakeGumApi(&state);
  auto invalid_api = api;
  invalid_api.abi_version = 99;
  CHECK(!art_hook::GumInterceptorRuntime::Create(invalid_api).ok());

  art_hook::GumInterceptorRuntimeOptions runtime_options;
  runtime_options.manage_embedded_lifecycle = true;
  auto runtime =
      art_hook::GumInterceptorRuntime::Create(api, runtime_options);
  CHECK(runtime.ok());
  if (!runtime.ok()) {
    return;
  }
  CHECK(state.init_calls == 1);
  CHECK(state.obtain_calls == 1);

  GumCallbackState callback_state;
  art_hook::GumInvocationCallbacks callbacks;
  callbacks.on_enter = TestGumEnter;
  callbacks.on_leave = TestGumLeave;
  callbacks.user_data = &callback_state;
  art_hook::GumAttachOptions attach_options;
  attach_options.listener_function_data =
      reinterpret_cast<void *>(0x55550000U);

  auto transaction = runtime.value()->BeginTransaction();
  CHECK(transaction.ok());
  auto hook = runtime.value()->Attach(
      reinterpret_cast<void *>(0x11110000U), callbacks, attach_options);
  CHECK(hook.ok());
  CHECK(state.flush_calls == 0);
  CHECK(transaction.ok() && transaction.value()->Commit().ok());
  CHECK(state.begin_calls == 1);
  CHECK(state.end_calls == 1);
  CHECK(state.flush_calls == 1);

  FakeGumContext context;
  context.arguments[0] = reinterpret_cast<void *>(3U);
  context.return_value = reinterpret_cast<void *>(8U);
  context.function = reinterpret_cast<void *>(0x11110000U);
  context.cpu_context = reinterpret_cast<void *>(0x22220000U);
  context.return_address = reinterpret_cast<void *>(0x33330000U);
  context.listener_function_data = state.listener_function_data;
  context.thread_id = 37;
  context.depth = 2;
  CHECK(state.attached_listener != nullptr);
  if (state.attached_listener != nullptr) {
    state.attached_listener->on_enter(&context,
                                      state.attached_listener->data);
    state.attached_listener->on_leave(&context,
                                      state.attached_listener->data);
  }
  CHECK(callback_state.enter_calls == 1);
  CHECK(callback_state.leave_calls == 1);
  CHECK(context.arguments[0] == reinterpret_cast<void *>(4U));
  CHECK(context.return_value == reinterpret_cast<void *>(16U));
  CHECK(hook.ok() && hook.value()->Detach().ok());
  CHECK(hook.ok() && hook.value()->Detach().ok());
  CHECK(state.detach_calls == 1);
  CHECK(state.listener_destroy_calls == 1);

  auto probe = runtime.value()->Probe(
      reinterpret_cast<void *>(0x66660000U), TestGumProbe, &callback_state);
  CHECK(probe.ok());
  CHECK(probe.ok() && probe.value()->is_probe());
  if (state.attached_listener != nullptr) {
    state.attached_listener->on_enter(&context,
                                      state.attached_listener->data);
  }
  CHECK(callback_state.probe_calls == 1);
  CHECK(probe.ok() && probe.value()->Detach().ok());

  art_hook::GumReplaceOptions replace_options;
  replace_options.replacement_data = reinterpret_cast<void *>(0x77770000U);
  auto replacement = runtime.value()->Replace(
      reinterpret_cast<void *>(0x88880000U),
      reinterpret_cast<void *>(0x99990000U), replace_options);
  CHECK(replacement.ok());
  CHECK(replacement.ok() && replacement.value()->original_function() ==
                                reinterpret_cast<void *>(0x44440000U));
  context.replacement_data = state.replacement_data;
  state.current_invocation = &context;
  auto current = runtime.value()->CurrentInvocation();
  CHECK(current.has_value());
  CHECK(current.has_value() && current->replacement_data() ==
                                   reinterpret_cast<void *>(0x77770000U));
  state.current_invocation = nullptr;
  CHECK(!runtime.value()->CurrentInvocation().has_value());
  CHECK(replacement.ok() && replacement.value()->Revert().ok());
  CHECK(replacement.ok() && replacement.value()->Revert().ok());
  CHECK(state.revert_calls == 1);
  CHECK(runtime.value()->Flush().ok());

  hook = art_hook::Status(art_hook::StatusCode::kUnavailable, "released");
  probe = art_hook::Status(art_hook::StatusCode::kUnavailable, "released");
  replacement =
      art_hook::Status(art_hook::StatusCode::kUnavailable, "released");
  transaction =
      art_hook::Status(art_hook::StatusCode::kUnavailable, "released");
  runtime.value().reset();
  CHECK(state.interceptor_unref_calls == 1);
  CHECK(state.deinit_calls == 1);
}

struct InterceptorCallbackState final {
  int enter_calls = 0;
  int leave_calls = 0;
};

void TestOnEnter(art_hook::Arm64CpuContext *context, void *user_data) noexcept {
  auto *state = static_cast<InterceptorCallbackState *>(user_data);
  ++state->enter_calls;
  ++context->x[1];
}

void TestOnLeave(art_hook::Arm64CpuContext *context, void *user_data) noexcept {
  auto *state = static_cast<InterceptorCallbackState *>(user_data);
  ++state->leave_calls;
  context->x[0] *= 2U;
}

__attribute__((noinline)) std::uint64_t
OriginalArtMethodAdd(void *, std::uint64_t first, std::uint64_t second) {
  return first + second;
}

__attribute__((noinline)) std::uint64_t
PreDeoptimizationArtMethodAdd(void *, std::uint64_t, std::uint64_t) {
  return 0xffffU;
}

void TestArtMethodInterceptor() {
#if defined(__aarch64__)
  alignas(16) std::array<std::uint8_t, 48> method{};
  constexpr std::uint32_t kFlags = 0x0109U;
  void *const jni_code = reinterpret_cast<void *>(0x10001000U);
  void *quick_code = reinterpret_cast<void *>(
      reinterpret_cast<std::uintptr_t>(&PreDeoptimizationArtMethodAdd));
  std::memcpy(method.data() + 4, &kFlags, sizeof(kFlags));
  std::memcpy(method.data() + 16, &jni_code, sizeof(jni_code));
  std::memcpy(method.data() + 24, &quick_code, sizeof(quick_code));

  art_hook::ArtMethodLayout layout;
  layout.method_size = 32;
  layout.access_flags_offset = 4;
  layout.jni_code_offset = 16;
  layout.quick_code_offset = 24;

  auto mutation_gate = std::make_shared<TestMutationGate>();
  InterceptorCallbackState callback_state;
  art_hook::ArtMethodCallbacks callbacks;
  callbacks.on_enter = TestOnEnter;
  callbacks.on_leave = TestOnLeave;
  callbacks.user_data = &callback_state;
  auto interceptor = art_hook::ArtMethodInterceptor::Create(
      method.data(), layout, callbacks, mutation_gate);
  CHECK(interceptor.ok());
  if (!interceptor.ok()) {
    return;
  }

  DeoptimizationTestState deoptimization_state;
  deoptimization_state.method_storage = method.data();
  deoptimization_state.quick_code_offset = layout.quick_code_offset;
  deoptimization_state.deoptimized_quick_code = reinterpret_cast<void *>(
      reinterpret_cast<std::uintptr_t>(&OriginalArtMethodAdd));
  auto runnable = std::make_shared<art_hook::ArtAlreadyRunnableGate>();
  auto deoptimizer = art_hook::ArtDeoptimizer::Create(
      MakeInstrumentationApi(&deoptimization_state), runnable);
  CHECK(deoptimizer.ok());
  CHECK(deoptimizer.ok() &&
        interceptor.value()->Activate(*deoptimizer.value()).ok());
  CHECK(interceptor.value()->original_quick_code() ==
        deoptimization_state.deoptimized_quick_code);

  auto active = art_hook::ReadArtMethodState(method.data(), layout);
  CHECK(active.ok());
  if (active.ok()) {
    using QuickFunction =
        std::uint64_t (*)(void *, std::uint64_t, std::uint64_t);
    auto function = reinterpret_cast<QuickFunction>(active.value().quick_code);
    for (std::size_t iteration = 0; iteration != 1024U; ++iteration) {
      CHECK(function(method.data(), 3U, 4U) == 16U);
    }
  }
  CHECK(callback_state.enter_calls == 1024);
  CHECK(callback_state.leave_calls == 1024);
  CHECK(interceptor.value()->in_flight() == 0U);
  CHECK(interceptor.value()->Deactivate().ok());

  auto restored = art_hook::ReadArtMethodState(method.data(), layout);
  CHECK(restored.ok());
  CHECK(restored.ok() && restored.value().quick_code ==
                             deoptimization_state.deoptimized_quick_code);
#endif
}

void TestArm64Trampoline() {
  IntegerDispatchData integer_data{9};
  auto integer_trampoline =
      art_hook::Arm64Trampoline::Create(IntegerDispatch, &integer_data);
  CHECK(integer_trampoline.ok());
  if (!integer_trampoline.ok()) {
    return;
  }
  const auto &words = integer_trampoline.value()->words();
  CHECK(!words.empty());
  CHECK(words.front() == 0xd503245fU);
  CHECK(std::find(words.begin(), words.end(), 0xd10cc3ffU) != words.end());
  CHECK(std::find(words.begin(), words.end(), 0xad187ffeU) != words.end());
  CHECK(std::find(words.begin(), words.end(), 0xad587ffeU) != words.end());
  CHECK(std::find(words.begin(), words.end(), 0xd53b4210U) != words.end());
  CHECK(std::find(words.begin(), words.end(), 0xd51b4210U) != words.end());
  CHECK(std::find(words.begin(), words.end(), 0xd63f0200U) != words.end());
  CHECK(words.size() >= 3);
  CHECK(words[words.size() - 3] == 0xb4000050U);
  CHECK(words[words.size() - 2] == 0xd61f0200U);
  CHECK(words.back() == 0xd65f03c0U);

#if defined(__aarch64__)
  using IntegerFunction = std::uint64_t (*)(std::uint64_t, std::uint64_t);
  auto integer_function = reinterpret_cast<IntegerFunction>(
      integer_trampoline.value()->entrypoint());
  CHECK(integer_function(5, 7) == 21);

  auto floating_trampoline =
      art_hook::Arm64Trampoline::Create(FloatingDispatch, nullptr);
  CHECK(floating_trampoline.ok());
  if (floating_trampoline.ok()) {
    using FloatingFunction = double (*)(double, double);
    auto floating_function = reinterpret_cast<FloatingFunction>(
        floating_trampoline.value()->entrypoint());
    CHECK(floating_function(1.25, 2.5) == 3.75);
  }

  TailDispatchData tail_data{
      reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(&OriginalAdd))};
  auto tail_trampoline =
      art_hook::Arm64Trampoline::Create(TailDispatch, &tail_data);
  CHECK(tail_trampoline.ok());
  if (tail_trampoline.ok()) {
    auto tail_function = reinterpret_cast<IntegerFunction>(
        tail_trampoline.value()->entrypoint());
    CHECK(tail_function(13, 29) == 42);
  }
#endif
}

void TestLsplantArm64Bridge() {
  constexpr std::size_t kEntrypointOffset = 32U;
  const std::array<std::uint32_t, 3> template_words{
      0x58000060U,
      0xf8400010U |
          (static_cast<std::uint32_t>(kEntrypointOffset) << 12U),
      0xd61f0200U,
  };
  std::array<std::uint8_t, 20> request{};
  std::memcpy(request.data(), template_words.data(),
              template_words.size() * sizeof(std::uint32_t));
  const std::uintptr_t method_address = 0x1234567812345678ULL;
  std::memcpy(request.data() + 12U, &method_address, sizeof(method_address));

  auto decoded = art_hook::DecodeLsplantArm64BridgeRequest(request);
  CHECK(decoded.ok());
  CHECK(decoded.ok() && decoded.value().art_method ==
                            reinterpret_cast<void*>(method_address));
  CHECK(decoded.ok() &&
        decoded.value().entrypoint_offset == kEntrypointOffset);

  auto bridge = art_hook::LsplantArm64Bridge::CreateFromLsplantRequest(request);
  CHECK(bridge.ok());
  if (bridge.ok()) {
    const auto& words = bridge.value()->words();
    CHECK(words.size() == 4U);
    CHECK(words[0] == 0x58000080U);
    CHECK(words[1] == template_words[1]);
    CHECK(words[2] == 0xd61f0200U);
    CHECK(words[3] == 0xd503201fU);
    CHECK(bridge.value()->code_size() == 24U);
  }

  const std::size_t before = art_hook::LsplantArm64BridgePool::live_count();
  void* pooled = art_hook::LsplantArm64BridgePool::Allocate(request);
  CHECK(pooled != nullptr);
  CHECK(art_hook::LsplantArm64BridgePool::live_count() == before + 1U);
  art_hook::LsplantArm64BridgePool::Recycle(pooled);
  CHECK(art_hook::LsplantArm64BridgePool::live_count() == before);

  request[0] ^= 0xffU;
  CHECK(!art_hook::DecodeLsplantArm64BridgeRequest(request).ok());
  CHECK(art_hook::LsplantArm64BridgePool::Allocate(request) == nullptr);

  auto oversized = art_hook::LsplantArm64Bridge::Create(
      {reinterpret_cast<void*>(method_address), 0x100U});
  CHECK(!oversized.ok());
}

void TestLsplantBackendConfig() {
#if defined(ART_HOOK_HAS_LSPLANT)
  art_hook::LsplantBackendConfig config;
  CHECK(!config.Validate().ok());

  config.inline_hooker = [](void*, void*) -> void* { return nullptr; };
  config.inline_unhooker = [](void*) { return false; };
  config.art_symbol_resolver = [](std::string_view) -> void* {
    return nullptr;
  };
  config.art_symbol_prefix_resolver = [](std::string_view) -> void* {
    return nullptr;
  };
  CHECK(config.Validate().ok());

  config.generated_method_name.clear();
  CHECK(!config.Validate().ok());
#endif
}

void TestRuntimeDiscovery() {
  auto runtime = art_hook::RuntimeApi::Discover();
  CHECK(runtime.ok());
  if (runtime.ok()) {
    CHECK(!runtime.value().info().architecture.empty());
    std::cout << "runtime="
              << art_hook::RuntimeFlavorName(runtime.value().info().flavor)
              << " api=" << runtime.value().info().android_api_level
              << " arch=" << runtime.value().info().architecture << '\n';
  }
}

} // namespace

int main(int argc, char **argv) {
  TestStatus();
  TestLru();
  TestMemoize();
  TestInstructionScan();
  TestTypes();
  TestJavaProxyIndex();
  TestDex(argc >= 2 ? argv[1] : nullptr);
  TestAllocator();
  TestThreadListMutationGate();
  TestConcurrentThreadListMutationGate();
  TestArtAccessFlags();
  TestArtMethod();
  TestHotSpotMethodMangler();
  TestArtQuickHook();
  TestArtDeoptimization();
  TestGumInterceptor();
  TestArtMethodInterceptor();
  TestArm64Trampoline();
  TestLsplantArm64Bridge();
  TestLsplantBackendConfig();
  TestRuntimeDiscovery();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "all art-hook tests passed\n";
  return EXIT_SUCCESS;
}
