// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
//
// Mako ghost hook engine. This translation unit builds the ghost-loaded
// libmako-ghost.so: a standalone SHARED library that the stage-2 Daemon
// lazily links into ghost memory on its first artHook call (the Manager
// switch pushes its path into the KPM cache). It never links the Daemon and
// never touches ArtMethod fields through the user VA directly — every field
// access goes through the host's Shadow Data Page ops, so the tampered value
// lives only in the kernel's shadow copy while scanners keep reading the
// clean original page.
//
// Resolution follows the design note: className+methodName+sig through
// standard reflection, or a reflected java.lang.reflect.Method object for
// hidden-API methods. Both paths land on the same entry-point replacement.
#include <jni.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <vector>

#include <sys/system_properties.h>

#include "art_hook/arm64_trampoline.h"
#include "art_hook/art_method.h"
#include "art_hook/art_probe.h"
#include "art_hook/mako_host.h"
#include "art_hook/status.h"
#include "ghost_jump_pool.h"

namespace {

using art_hook::Arm64CpuContext;
using art_hook::Arm64Trampoline;
using art_hook::ArtMethodLayout;
using art_hook::ArtMethodProbeSpec;
using art_hook::ClassifyJniId;
using art_hook::GhostJumpPool;
using art_hook::JniIdClassification;
using art_hook::JniIdMode;
using art_hook::JniIdReason;
using art_hook::JniIdView;
using art_hook::ProbeArtMethodLayout;
using art_hook::Status;
using art_hook::StatusCode;

constexpr std::size_t kMaximumInvocationDepth = 128;

const MakoHostApi *g_host = nullptr;
std::mutex g_mutex;
std::unique_ptr<GhostJumpPool> g_pool;
ArtMethodLayout g_layout{};
bool g_layout_ready = false;
bool g_trust_registered = false;
bool g_trampoline_self_tested = false;
std::vector<void *> g_states;

using DecodeMethodIdFn = void *(*)(void *jni_id_manager, jmethodID id);
DecodeMethodIdFn g_decode_method_id = nullptr;
void *g_jni_id_manager = nullptr;
bool g_decoder_resolved = false;

const MakoReflectionCache *InheritedReflection() {
  if (g_host == nullptr || g_host->reflection == nullptr) return nullptr;
  const MakoReflectionCache *cache = g_host->reflection;
  if (cache->version != MAKO_REFLECTION_CACHE_VERSION ||
      cache->size < sizeof(MakoReflectionCache) ||
      cache->object_hash_code == nullptr ||
      cache->method_get_return_type == nullptr ||
      cache->method_get_parameter_types == nullptr ||
      cache->class_get_name == nullptr)
    return nullptr;
  return cache;
}

struct MakoHookState {
  jmethodID method_id = nullptr;
  void *method = nullptr;
  unsigned long page_va = 0;
  unsigned long quick_page_offset = 0; /* offset of quick_code inside page */
  unsigned long long original_quick = 0;
  unsigned long long original_entry = 0; /* quick ?: interpreter bridge */
  std::atomic<bool> active{false};
  /* Revert is split into two phases. Once the entry patch has been removed,
   * cleanup_pending keeps a failed page-unregister operation retryable without
   * attempting to unpatch the same word a second time. */
  bool cleanup_pending = false;
  bool retirement_waiting = false;
  std::atomic<std::size_t> in_flight{0};
  std::atomic<std::size_t> dispatchers_running{0};
  std::atomic<std::size_t> callbacks_running{0};
  void *leave_entry = nullptr;
  std::atomic<MakoArtCallback> on_enter{nullptr};
  std::atomic<MakoArtCallback> on_leave{nullptr};
  std::atomic<void *> user_data{nullptr};
  std::unique_ptr<Arm64Trampoline> enter_trampoline;
  std::unique_ptr<Arm64Trampoline> leave_trampoline;
};

struct InvocationFrame {
  MakoHookState *state = nullptr;
  std::uint64_t return_address = 0;
  std::uint64_t entry_sp = 0;
};

struct InvocationStack {
  std::array<InvocationFrame, kMaximumInvocationDepth> frames{};
  std::size_t size = 0;
};

bool HasActiveHookOnPage(unsigned long page_va,
                         const MakoHookState *except = nullptr) {
  for (void *opaque : g_states) {
    auto *state = static_cast<MakoHookState *>(opaque);
    if (state == nullptr || state == except || state->page_va != page_va)
      continue;
    if (state->active.load(std::memory_order_acquire)) return true;
  }
  return false;
}

bool HasAnyActiveHook(const MakoHookState *except = nullptr) {
  for (void *opaque : g_states) {
    auto *state = static_cast<MakoHookState *>(opaque);
    if (state == nullptr || state == except) continue;
    if (state->active.load(std::memory_order_acquire)) return true;
  }
  return false;
}

MakoHookState *FindState(unsigned long handle) {
  auto *candidate = reinterpret_cast<MakoHookState *>(handle);
  if (candidate == nullptr) return nullptr;
  for (void *opaque : g_states) {
    if (opaque == candidate) return candidate;
  }
  return nullptr;
}

bool HasActiveHookAt(unsigned long page_va, unsigned long page_offset) {
  for (void *opaque : g_states) {
    auto *state = static_cast<MakoHookState *>(opaque);
    if (state != nullptr && state->page_va == page_va &&
        state->quick_page_offset == page_offset &&
        state->active.load(std::memory_order_acquire))
      return true;
  }
  return false;
}

void RollBackUnusedPage(unsigned long page_va) {
  if (g_host == nullptr || HasActiveHookOnPage(page_va)) return;
  if (g_host->art_page_unregister != nullptr)
    (void)g_host->art_page_unregister(page_va);
  if (!HasAnyActiveHook() && g_trust_registered &&
      g_host->art_trust_clear != nullptr) {
    if (g_host->art_trust_clear() == 0) g_trust_registered = false;
  }
}

thread_local InvocationStack g_invocations;
thread_local MakoHookState *g_current_callback = nullptr;

long MakoLog(const char *text);

void *SelfTestDispatch(Arm64CpuContext *context, void *user_data) noexcept {
  if (context == nullptr || user_data != reinterpret_cast<void *>(0x4d414b4fUL))
    return reinterpret_cast<void *>(1UL);
  /* Exercise context writeback as well as the return-through-x30 path. */
  context->x[0] = 0x525447554dUL;
  return nullptr;
}

bool EnsureTrampolineWorks() {
  if (g_trampoline_self_tested) return true;
  if (!g_pool) return false;
  MakoLog("rtgum-mako: trampoline self-test enter");
  auto result = Arm64Trampoline::Create(
      SelfTestDispatch, reinterpret_cast<void *>(0x4d414b4fUL), *g_pool);
  if (!result.ok()) {
    MakoLog("rtgum-mako: trampoline self-test allocation failed");
    return false;
  }
  using SelfTestEntry = unsigned long (*)();
  auto entry = reinterpret_cast<SelfTestEntry>(result.value()->entrypoint());
  const unsigned long value = entry();
  if (value != 0x525447554dUL) {
    MakoLog("rtgum-mako: trampoline self-test result mismatch");
    return false;
  }
  /* The pool owns the executable page; destroying the metadata object does
   * not reclaim the retired slice. */
  g_trampoline_self_tested = true;
  MakoLog("rtgum-mako: trampoline self-test pass");
  return true;
}

void ReleaseInFlight(MakoHookState *state) noexcept {
  if (state == nullptr) return;
  std::size_t current = state->in_flight.load(std::memory_order_acquire);
  while (current != 0U &&
         !state->in_flight.compare_exchange_weak(
             current, current - 1U, std::memory_order_acq_rel,
             std::memory_order_acquire)) {
  }
}

void PruneUnwoundFrames(std::uint64_t current_sp) noexcept {
  while (g_invocations.size != 0U &&
         g_invocations.frames[g_invocations.size - 1U].entry_sp < current_sp) {
    MakoHookState *state = g_invocations.frames[g_invocations.size - 1U].state;
    ReleaseInFlight(state);
    g_invocations.frames[g_invocations.size - 1U] = {};
    --g_invocations.size;
  }
}

void InvokeCallback(MakoHookState *state,
                    std::atomic<MakoArtCallback> &slot,
                    Arm64CpuContext *context) noexcept {
  state->callbacks_running.fetch_add(1U, std::memory_order_acq_rel);
  MakoArtCallback callback = slot.load(std::memory_order_acquire);
  void *user_data = state->user_data.load(std::memory_order_acquire);
  MakoHookState *previous = g_current_callback;
  g_current_callback = state;
  if (callback != nullptr) callback(context, user_data);
  g_current_callback = previous;
  state->callbacks_running.fetch_sub(1U, std::memory_order_acq_rel);
}

void *EnterDispatch(Arm64CpuContext *context, void *user_data) noexcept {
  auto *state = static_cast<MakoHookState *>(user_data);
  state->dispatchers_running.fetch_add(1U, std::memory_order_acq_rel);
  const auto original = state->original_entry;
  if (original == 0ULL) {
    state->dispatchers_running.fetch_sub(1U, std::memory_order_acq_rel);
    return nullptr;
  }
  if (!state->active.load(std::memory_order_acquire)) {
    state->dispatchers_running.fetch_sub(1U, std::memory_order_acq_rel);
    return reinterpret_cast<void *>(original);
  }
  PruneUnwoundFrames(context->sp);
  if (g_invocations.size == kMaximumInvocationDepth) {
    state->dispatchers_running.fetch_sub(1U, std::memory_order_acq_rel);
    return reinterpret_cast<void *>(original);
  }
  InvocationFrame &frame = g_invocations.frames[g_invocations.size++];
  frame.state = state;
  frame.return_address = context->x[30];
  frame.entry_sp = context->sp;
  state->in_flight.fetch_add(1U, std::memory_order_acq_rel);
  InvokeCallback(state, state->on_enter, context);
  context->x[30] = reinterpret_cast<std::uintptr_t>(state->leave_entry);
  state->dispatchers_running.fetch_sub(1U, std::memory_order_acq_rel);
  return reinterpret_cast<void *>(original);
}

void *LeaveDispatch(Arm64CpuContext *context, void *user_data) noexcept {
  auto *state = static_cast<MakoHookState *>(user_data);
  state->dispatchers_running.fetch_add(1U, std::memory_order_acq_rel);
  PruneUnwoundFrames(context->sp);
  std::size_t index = g_invocations.size;
  while (index != 0U) {
    --index;
    if (g_invocations.frames[index].state == state) break;
  }
  if (g_invocations.size == 0U || g_invocations.frames[index].state != state) {
    /* Unmatched leave (stack unwound past the frame): still deliver the
     * callback, but there is no caller frame to restore. */
    InvokeCallback(state, state->on_leave, context);
    ReleaseInFlight(state);
    state->dispatchers_running.fetch_sub(1U, std::memory_order_acq_rel);
    return nullptr;
  }
  const InvocationFrame frame = g_invocations.frames[index];
  for (std::size_t stale = g_invocations.size; stale > index + 1U;) {
    --stale;
    MakoHookState *stale_state = g_invocations.frames[stale].state;
    ReleaseInFlight(stale_state);
    g_invocations.frames[stale] = {};
  }
  g_invocations.frames[index] = {};
  g_invocations.size = index;
  context->x[30] = frame.return_address;
  InvokeCallback(state, state->on_leave, context);
  ReleaseInFlight(state);
  state->dispatchers_running.fetch_sub(1U, std::memory_order_acq_rel);
  return nullptr;
}

long MakoLog(const char *text) {
  if (g_host == nullptr || g_host->log == nullptr) return -1;
  return g_host->log(text);
}

/* The ghost module has no caller-provided JNIEnv (modules pass null, exactly
 * like the visible Java backend). libnativehelper is loaded in every app
 * process; resolve it at runtime so the image keeps no extra DT_NEEDED. */
extern "C" void *dlsym(void *handle, const char *symbol);

using GetCreatedJavaVMs = jint (*)(JavaVM **, jsize, jsize *);

JNIEnv *AcquireEnv() {
  static GetCreatedJavaVMs get_created = nullptr;
  if (get_created == nullptr) {
    get_created = reinterpret_cast<GetCreatedJavaVMs>(
        dlsym(nullptr, "JNI_GetCreatedJavaVMs"));
    /* A ghost image is not registered in the app linker namespace, so
     * RTLD_DEFAULT may legitimately hide libart even though it is mapped.
     * Resolve the same public export through the Daemon's already-mapped ELF
     * resolver in that case; this does not load another library. */
    if (get_created == nullptr && g_host != nullptr &&
        g_host->find_export != nullptr) {
      unsigned long address = 0;
      if (g_host->find_export("libart.so", "JNI_GetCreatedJavaVMs", &address) ==
              0 &&
          address != 0)
        get_created = reinterpret_cast<GetCreatedJavaVMs>(address);
    }
  }
  if (get_created == nullptr) return nullptr;
  JavaVM *vm = nullptr;
  jsize count = 0;
  if (get_created(&vm, 1, &count) != JNI_OK || vm == nullptr) return nullptr;
  JNIEnv *env = nullptr;
  const jint attached =
      vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
  if (attached == JNI_OK && env != nullptr) return env;
  if (attached == JNI_EDETACHED &&
      vm->AttachCurrentThread(&env, nullptr) == JNI_OK)
    return env;
  return nullptr;
}

char ReflectionShortyType(JNIEnv *env, jobject class_object,
                          const MakoReflectionCache *cache) {
  if (env == nullptr || class_object == nullptr || cache == nullptr) return '\0';
  jstring name = static_cast<jstring>(env->CallObjectMethod(
      class_object, reinterpret_cast<jmethodID>(cache->class_get_name)));
  if (name == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    if (name != nullptr) env->DeleteLocalRef(name);
    return '\0';
  }
  const char *text = env->GetStringUTFChars(name, nullptr);
  if (text == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    env->DeleteLocalRef(name);
    return '\0';
  }
  char result = 'L';
  if (std::strcmp(text, "void") == 0) result = 'V';
  else if (std::strcmp(text, "boolean") == 0) result = 'Z';
  else if (std::strcmp(text, "byte") == 0) result = 'B';
  else if (std::strcmp(text, "char") == 0) result = 'C';
  else if (std::strcmp(text, "short") == 0) result = 'S';
  else if (std::strcmp(text, "int") == 0) result = 'I';
  else if (std::strcmp(text, "long") == 0) result = 'J';
  else if (std::strcmp(text, "float") == 0) result = 'F';
  else if (std::strcmp(text, "double") == 0) result = 'D';
  env->ReleaseStringUTFChars(name, text);
  env->DeleteLocalRef(name);
  return result;
}

bool BuildReflectedShorty(JNIEnv *env, jobject method_object,
                          std::string &out) {
  out.clear();
  const MakoReflectionCache *cache = InheritedReflection();
  if (env == nullptr || method_object == nullptr || cache == nullptr) return false;
  jobject return_type = env->CallObjectMethod(
      method_object,
      reinterpret_cast<jmethodID>(cache->method_get_return_type));
  if (return_type == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    if (return_type != nullptr) env->DeleteLocalRef(return_type);
    return false;
  }
  jobjectArray parameter_types = static_cast<jobjectArray>(env->CallObjectMethod(
      method_object,
      reinterpret_cast<jmethodID>(cache->method_get_parameter_types)));
  if (parameter_types == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    env->DeleteLocalRef(return_type);
    if (parameter_types != nullptr) env->DeleteLocalRef(parameter_types);
    return false;
  }
  const char return_code = ReflectionShortyType(env, return_type, cache);
  env->DeleteLocalRef(return_type);
  if (return_code == '\0') {
    env->DeleteLocalRef(parameter_types);
    return false;
  }
  out.push_back(return_code);
  const jsize count = env->GetArrayLength(parameter_types);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    env->DeleteLocalRef(parameter_types);
    out.clear();
    return false;
  }
  for (jsize index = 0; index < count; ++index) {
    jobject parameter = env->GetObjectArrayElement(parameter_types, index);
    if (parameter == nullptr || env->ExceptionCheck()) {
      env->ExceptionClear();
      if (parameter != nullptr) env->DeleteLocalRef(parameter);
      env->DeleteLocalRef(parameter_types);
      out.clear();
      return false;
    }
    const char code = ReflectionShortyType(env, parameter, cache);
    env->DeleteLocalRef(parameter);
    if (code == '\0' || code == 'V') {
      env->DeleteLocalRef(parameter_types);
      out.clear();
      return false;
    }
    out.push_back(code);
  }
  env->DeleteLocalRef(parameter_types);
  return true;
}

int DeviceApiLevel() {
  char value[PROP_VALUE_MAX] = {};
  if (__system_property_get("ro.build.version.sdk", value) > 0) {
    const int level = std::atoi(value);
    if (level > 0) return level;
  }
  return 35; /* Pixel 8 lab default */
}

/* Finds the first executable mapping whose path contains the needle. Uses
 * stdio rather than iostreams: no global constructors, so the KPM's remote
 * linker never has to run init arrays for this image. */
bool FindExecutableRange(const char *needle, unsigned long long &start,
                         unsigned long long &end) {
  std::FILE *maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) return false;
  char line[512];
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    char perms[8] = {};
    if (std::sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
    if (std::strchr(perms, 'x') == nullptr) continue;
    if (std::strstr(line, needle) == nullptr) continue;
    std::fclose(maps);
    return true;
  }
  std::fclose(maps);
  start = 0;
  end = 0;
  return false;
}

/* True when `address` falls inside any mapping whose path contains
 * `needle` (any permission; entry stubs may live in non-executable
 * segments). */
bool InPathSegment(unsigned long long address, const char *needle) {
  std::FILE *maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) return false;
  char line[512];
  bool found = false;
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    if (std::sscanf(line, "%llx-%llx", &start, &end) != 2) continue;
    if (std::strstr(line, needle) == nullptr) continue;
    if (address >= start && address < end) {
      found = true;
      break;
    }
  }
  std::fclose(maps);
  return found;
}

namespace {
bool FindRangeContaining(unsigned long long address,
                         unsigned long long &out_start,
                         unsigned long long &out_end);

}  // namespace

/* Dump a pending JNI exception's toString() into the kernel log. */
void LogPendingJniException(JNIEnv *env, unsigned *gate) {
  if (gate != nullptr && *gate >= 3U) return;
  if (gate != nullptr) ++*gate;
  jthrowable exc = env->ExceptionOccurred();
  if (exc == nullptr) {
    MakoLog("rtgum-mako: jni-exc <no pending exception>");
    return;
  }
  /* CheckJNI rejects every ordinary JNI call while an exception is pending.
   * Keep the throwable local reference, clear the pending state first, and
   * only then inspect it. The old order called GetObjectClass here and turned
   * the diagnostic path itself into the process-fatal error. */
  env->ExceptionClear();
  jclass exc_class = env->GetObjectClass(exc);
  if (exc_class == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    MakoLog("rtgum-mako: jni-exc <class lookup failed>");
    env->DeleteLocalRef(exc);
    return;
  }
  jmethodID to_string = env->GetMethodID(
      exc_class, "toString", "()Ljava/lang/String;");
  if (to_string != nullptr) {
    jstring str = static_cast<jstring>(env->CallObjectMethod(exc, to_string));
    if (str != nullptr && !env->ExceptionCheck()) {
      const char *cstr = env->GetStringUTFChars(str, nullptr);
      if (cstr != nullptr) {
        char buffer[320];
        std::snprintf(buffer, sizeof(buffer), "rtgum-mako: jni-exc %s", cstr);
        MakoLog(buffer);
        env->ReleaseStringUTFChars(str, cstr);
      }
      env->DeleteLocalRef(str);
    } else {
      env->ExceptionClear();
      MakoLog("rtgum-mako: jni-exc <toString failed>");
    }
  } else {
    env->ExceptionClear();
    MakoLog("rtgum-mako: jni-exc <no toString method id>");
  }
  if (exc_class != nullptr) env->DeleteLocalRef(exc_class);
  env->DeleteLocalRef(exc);
}

/* True when `address` falls inside any executable mapping. Entry points
 * spread across libart.so / libartbase.so / libartpalette.so, so checking
 * library names is too strict. */
bool InExecSegment(unsigned long long address) {
  std::FILE *maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) return false;
  char line[512];
  bool found = false;
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    char perms[8] = {};
    if (std::sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
    if (std::strchr(perms, 'x') == nullptr) continue;
    if (address >= start && address < end) {
      found = true;
      break;
    }
  }
  std::fclose(maps);
  return found;
}

/* Authoritative ArtMethod layout from art_method.h (Android 14+, 64-bit):
 *   declaring_class @0 (4B), access_flags @4 (4B),
 *   dex_method_index @8 (4B), method_index @12 (2B), hotness @14 (2B),
 *   ptr_sized_fields_.data_ (the JNI entry point) @16 (8B),
 *   ptr_sized_fields_.entry_point_from_quick_compiled_code_ @24 (8B).
 * Total size 32. There is no separate interpreter entry field on these
 * builds: interpreted dispatch goes through the quick entry bridge. */
art_hook::Result<ArtMethodLayout> ProbeLayoutModern(void *method,
                                          unsigned long long libart_start,
                                          unsigned long long libart_end) {
  if (method == nullptr) {
    return Status(StatusCode::kInvalidArgument, "null method for layout probe");
  }
  unsigned long long mapping_start = 0;
  unsigned long long mapping_end = 0;
  if (!FindRangeContaining(reinterpret_cast<unsigned long long>(method),
                           mapping_start, mapping_end) ||
      mapping_end - reinterpret_cast<unsigned long long>(method) < 32ULL) {
    return Status(StatusCode::kNotFound,
                  "method range is not fully mapped");
  }
  const auto *bytes = static_cast<const unsigned char *>(method);
  unsigned long long jni = 0;
  unsigned long long quick = 0;
  __builtin_memcpy(&jni, bytes + 16, sizeof(jni));
  __builtin_memcpy(&quick, bytes + 24, sizeof(quick));
  /* data_ (@16) may hold a code item pointer (managed methods) or a JNI
   * resolver stub that lives in a read-only segment (intrinsics), so only
   * require it to be a mapped pointer. The quick entry point (@24) is what
   * we patch: it may be an art_quick bridge in libart.so (native methods),
   * compiled code in boot.oat, or JIT code in the profile cache. */
  unsigned long long jni_segment_start = 0;
  unsigned long long jni_segment_end = 0;
  const bool jni_ok =
      jni != 0ULL && FindRangeContaining(jni, jni_segment_start, jni_segment_end);
  const bool quick_ok = quick != 0ULL && InExecSegment(quick);
  if (!jni_ok || !quick_ok) {
    return Status(StatusCode::kNotFound,
                  "entry points do not resolve inside executable code");
  }
  ArtMethodLayout layout;
  layout.method_size = 32U;
  layout.access_flags_offset = 4U;
  layout.jni_code_offset = 16U;
  layout.quick_code_offset = 24U;
  layout.interpreter_code_offset = std::nullopt;
  return layout;
}

/* ART runtime code segments become trusted readers: their PCs see the
 * tampered shadow page; every other code path (scanners) sees the original. */
void RegisterArtTrustRanges() {
  if (g_host == nullptr || g_host->art_trust_add == nullptr) return;
  std::FILE *maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) return;
  char line[512];
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    char perms[8] = {};
    if (std::sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
    if (std::strchr(perms, 'x') == nullptr) continue;
    const bool art_runtime = std::strstr(line, "libart.so") != nullptr;
    const bool oat_code = std::strstr(line, ".oat") != nullptr ||
                          std::strstr(line, "/oat/") != nullptr;
    if (!art_runtime && !oat_code) continue;
    (void)g_host->art_trust_add(static_cast<unsigned long>(start),
                                static_cast<unsigned long>(end));
  }
  std::fclose(maps);
  g_trust_registered = true;
  MakoLog("rtgum-mako: art trust ranges registered");
}

/* A jmethodID is NOT promised to be an address. AOSP jni_id_type.h defines
 * three modes:
 *
 *   kPointer          the id IS the ArtMethod*  (historical ABI)
 *   kIndices          the id is a tagged index into a JniIdManager table; an
 *                     odd value can never be a pointer, which is what makes the
 *                     tag usable
 *   kSwapablePointer  the id is a pointer into a swapable table
 *
 * Only kPointer can be turned into an ArtMethod address by casting. In the other
 * two the address lives in a table owned by the runtime and is reached through
 * JniIdManager::DecodeMethodId when the running ART exports it. DecodeArtMethod
 * classifies first, resolves the runtime helper through the host, and validates
 * its result as an ArtMethod before returning it. Casting a small token is never
 * used as a fallback.
 *
 * Object.hashCode remains useful, but only as an *anchor*: it is a JNI native
 * method whose entry_point_from_jni must land in libart's executable range, so
 * it validates a candidate layout that was already derived. It cannot turn an
 * index token into an address. */
namespace {

bool FindRangeContaining(unsigned long long address,
                         unsigned long long &out_start,
                         unsigned long long &out_end) {
  out_start = 0;
  out_end = 0;
#if defined(__aarch64__)
  /* ART Runtime and JniIdManager live in the native heap and may carry an MTE
   * top-byte tag. maps has untagged addresses. Preserve the tag on the bounds
   * returned to callers so their range arithmetic remains in one address
   * domain, while retaining the original tagged pointer for actual loads. */
  const unsigned long long tag = address & 0xff00000000000000ULL;
  const unsigned long long mapped_address = address & 0x00ffffffffffffffULL;
#else
  const unsigned long long tag = 0;
  const unsigned long long mapped_address = address;
#endif
  std::FILE *maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) return false;
  char line[512];
  bool found = false;
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    if (std::sscanf(line, "%llx-%llx", &start, &end) != 2) continue;
    if (mapped_address >= start && mapped_address < end) {
      out_start = start | tag;
      out_end = end | tag;
      found = true;
      break;
    }
  }
  std::fclose(maps);
  return found;
}

void LogMapsAround(unsigned long long address) {
  std::FILE *maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) {
    MakoLog("rtgum-mako: cannot open /proc/self/maps");
    return;
  }
  char line[512];
  unsigned long long best_start = 0;
  unsigned long long best_end = 0;
  char best[512] = {};
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    if (std::sscanf(line, "%llx-%llx", &start, &end) != 2) continue;
    if (address >= start && address < end) {
      std::snprintf(best, sizeof(best), "rtgum-mako: maps-hit [%llx,%llx) %s",
                    start, end, line + 49);
      break;
    }
    if (start <= address && start > best_end) {
      best_start = start;
      best_end = end;
      std::snprintf(best, sizeof(best), "rtgum-mako: maps-below [%llx,%llx)",
                    start, end);
    }
  }
  std::fclose(maps);
  if (best[0] != '\0') {
    MakoLog(best);
  } else {
    char buffer[96];
    std::snprintf(buffer, sizeof(buffer), "rtgum-mako: maps-miss for 0x%llx",
                  address);
    MakoLog(buffer);
  }
}

}  // namespace

/* Builds the classification view for a candidate id from the process mapping
 * table. Nothing here dereferences the value: readability is decided from the
 * mapping, which is the only way to know a probe would not fault. */
JniIdView ClassifyView(uintptr_t value)
{
  JniIdView view;
  view.value = value;
  if (value == 0U) return view;
  unsigned long long start = 0;
  unsigned long long end = 0;
  if (!FindRangeContaining(value, start, end)) return view;
  view.mapped = true;
  view.executable = InExecSegment(value);
  /* A whole 32-byte ArtMethod record has to fit, or a layout probe that reads
   * four fields would run off the end of the mapping. */
  view.readable = end > static_cast<unsigned long long>(value) &&
                  end - static_cast<unsigned long long>(value) >= 32ULL;
  return view;
}

bool ResolveRuntimeIdDecoder(JNIEnv *env) {
  if (g_decoder_resolved)
    return g_decode_method_id != nullptr && g_jni_id_manager != nullptr;
  g_decoder_resolved = true;
  if (env == nullptr || g_host == nullptr || g_host->find_export == nullptr)
    return false;

  constexpr const char *kDecodeMethodId =
      "_ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID";
  constexpr const char *kRuntimeInstance = "_ZN3art7Runtime9instance_E";
  unsigned long decoder_address = 0;
  unsigned long runtime_slot_address = 0;
  if (g_host->find_export("libart.so", kDecodeMethodId, &decoder_address) != 0 ||
      decoder_address == 0 ||
      g_host->find_export("libart.so", kRuntimeInstance,
                          &runtime_slot_address) != 0 ||
      runtime_slot_address == 0 || !InExecSegment(decoder_address)) {
    MakoLog("rtgum-mako: runtime jmethodID decoder symbols unavailable");
    return false;
  }

  unsigned long long slot_start = 0;
  unsigned long long slot_end = 0;
  if (!FindRangeContaining(runtime_slot_address, slot_start, slot_end) ||
      slot_end - runtime_slot_address < sizeof(void *))
    return false;
  void *runtime = nullptr;
  __builtin_memcpy(&runtime, reinterpret_cast<const void *>(runtime_slot_address),
                   sizeof(runtime));
  if (runtime == nullptr) return false;

  unsigned long long runtime_start = 0;
  unsigned long long runtime_end = 0;
  const auto runtime_address = reinterpret_cast<uintptr_t>(runtime);
  if (!FindRangeContaining(runtime_address, runtime_start, runtime_end))
    return false;

  JavaVM *vm = nullptr;
  if (env->GetJavaVM(&vm) != JNI_OK || vm == nullptr) return false;

  /* ART 13+ keeps unique_ptr<JniIdManager> immediately before JavaVMExt*.
   * Locate JavaVMExt by identity instead of hard-coding the Runtime offset;
   * the bounded window mirrors the runtime-layout probe used by the bundled
   * Frida Java bridge. */
  constexpr uintptr_t kRuntimeScanStart = 384U;
  constexpr uintptr_t kRuntimeScanWords = 100U;
  void *manager = nullptr;
  for (uintptr_t offset = kRuntimeScanStart;
       offset < kRuntimeScanStart + kRuntimeScanWords * sizeof(void *);
       offset += sizeof(void *)) {
    if (runtime_address + offset + sizeof(void *) > runtime_end) break;
    void *candidate_vm = nullptr;
    __builtin_memcpy(&candidate_vm,
                     reinterpret_cast<const void *>(runtime_address + offset),
                     sizeof(candidate_vm));
    if (candidate_vm != vm || offset < sizeof(void *)) continue;
    __builtin_memcpy(&manager,
                     reinterpret_cast<const void *>(runtime_address + offset -
                                                    sizeof(void *)),
                     sizeof(manager));
    unsigned long long manager_start = 0;
    unsigned long long manager_end = 0;
    if (manager != nullptr &&
        FindRangeContaining(reinterpret_cast<uintptr_t>(manager), manager_start,
                            manager_end))
      break;
    manager = nullptr;
  }
  if (manager == nullptr) {
    MakoLog("rtgum-mako: JniIdManager location not validated");
    return false;
  }

  g_decode_method_id = reinterpret_cast<DecodeMethodIdFn>(decoder_address);
  g_jni_id_manager = manager;
  MakoLog("rtgum-mako: runtime jmethodID decoder ready");
  return true;
}

void *DecodeManagedArtMethod(JNIEnv *env, jmethodID id,
                             unsigned long long libart_start,
                             unsigned long long libart_end) {
  if (!ResolveRuntimeIdDecoder(env)) return nullptr;
  void *record = g_decode_method_id(g_jni_id_manager, id);
  if (record == nullptr) return nullptr;
  const uintptr_t value = reinterpret_cast<uintptr_t>(record);
  const JniIdView view = ClassifyView(value);
  if (!JniIdMayBeDereferenced(view)) return nullptr;

  ArtMethodProbeSpec spec;
  spec.method = record;
  spec.expected_jni_code_start = static_cast<std::uintptr_t>(libart_start);
  spec.expected_jni_code_end = static_cast<std::uintptr_t>(libart_end);
  spec.expected_access_flags = 0x100U;
  spec.relevant_access_flags_mask = 0x100U;
  spec.android_api_level = DeviceApiLevel();
  spec.has_interpreter_entrypoint = true;
  const bool modern_ok = ProbeLayoutModern(record, libart_start, libart_end).ok();
  const bool generic_ok = ProbeArtMethodLayout(spec).ok();
  if (!modern_ok && !generic_ok) {
    MakoLog("rtgum-mako: decoded ArtMethod failed layout validation");
    return nullptr;
  }
  char buffer[192];
  std::snprintf(buffer, sizeof(buffer),
                "rtgum-mako: managed id decoded raw=0x%llx record=0x%llx resolver=%s",
                static_cast<unsigned long long>(
                    reinterpret_cast<uintptr_t>(id)),
                static_cast<unsigned long long>(value),
                modern_ok ? "runtime+layout-modern" : "runtime+layout-scan");
  MakoLog(buffer);
  return record;
}

const char *IdModeName(JniIdMode mode)
{
  switch (mode) {
    case JniIdMode::Pointer: return "pointer";
    case JniIdMode::Index: return "index";
    case JniIdMode::SwapablePointer: return "swapable-pointer";
    case JniIdMode::Null: return "null";
    default: return "unresolved";
  }
}

const char *IdReasonName(JniIdReason reason)
{
  switch (reason) {
    case JniIdReason::IsNull: return "null";
    case JniIdReason::OddTagg: return "odd-tag";
    case JniIdReason::BelowMappingFloor: return "below-mapping-floor";
    case JniIdReason::OutsideAnyMapping: return "outside-any-mapping";
    case JniIdReason::Unaligned: return "unaligned";
    case JniIdReason::NotReadable: return "not-readable";
    case JniIdReason::LayoutRejected: return "layout-rejected";
    case JniIdReason::DirectArtMethod: return "direct-artmethod";
    case JniIdReason::IndexToken: return "index-token";
    default: return "none";
  }
}


void *DecodeArtMethod(JNIEnv *env, jmethodID id, unsigned long long libart_start,
                      unsigned long long libart_end) {
  if (id == nullptr) return nullptr;
  const uintptr_t value = reinterpret_cast<uintptr_t>(id);
  const JniIdView view = ClassifyView(value);

  /* Two DIFFERENT questions, and conflating them was a real bug:
   *
   *   a) may this value be dereferenced at all? - null, an odd tag, a value
   *      below the mapping floor, an unmapped/unaligned/short-read candidate.
   *      This must be answered before any read, because reading the first word
   *      of a small integer is a fault, not a wrong answer.
   *   b) is it an ArtMethod record? - only answerable by probing, and only
   *      legal once (a) says yes.
   *
   * The previous version asked ClassifyJniId(view, false) here, i.e. it fed a
   * hardcoded "layout is bad" into the classifier and then treated the
   * resulting Unresolved/LayoutRejected as final. Every candidate that passed
   * (a) was therefore rejected before ProbeLayoutModern/ProbeArtMethodLayout
   * were ever called, and the probe result could never change the verdict -
   * "layout-rejected" was produced by control flow, not by a layout verdict.
   * JniIdMayBeDereferenced answers (a) alone; the layout verdict is applied
   * below, after the probes have actually run. */
  if (!JniIdMayBeDereferenced(view)) {
    const JniIdClassification classified = ClassifyJniId(view, false);
    char buffer[224];
    std::snprintf(buffer, sizeof(buffer),
                  "rtgum-mako: id-mode=%s reason=%s raw-id=0x%llx "
                  "resolved-record=unavailable resolver=none",
                  IdModeName(classified.mode), IdReasonName(classified.reason),
                  static_cast<unsigned long long>(value));
    MakoLog(buffer);
    return DecodeManagedArtMethod(env, id, libart_start, libart_end);
  }

  /* Safe to read: report the candidate's own bytes before judging them.
   * "layout-rejected" alone cannot be told apart from "the probe is looking at
   * the right address with the wrong expectations", and those two need
   * opposite fixes; the words are the only evidence that separates them. */
  {
    const auto *bytes = reinterpret_cast<const unsigned char *>(value);
    unsigned long long w0 = 0, w8 = 0, w16 = 0, w24 = 0;
    __builtin_memcpy(&w0, bytes, sizeof(w0));
    __builtin_memcpy(&w8, bytes + 8, sizeof(w8));
    __builtin_memcpy(&w16, bytes + 16, sizeof(w16));
    __builtin_memcpy(&w24, bytes + 24, sizeof(w24));
    unsigned long long seg_a = 0, seg_b = 0;
    const bool w0_mapped = FindRangeContaining(w0, seg_a, seg_b);
    const bool w16_mapped = FindRangeContaining(w16, seg_a, seg_b);
    const bool w24_exec = InExecSegment(w24);
    /* Short records with a short tag, because the Daemon log channel truncates
     * (silently) at 224 bytes. */
    char line[160];
    std::snprintf(line, sizeof(line), "rk-cand id=0x%llx",
                  static_cast<unsigned long long>(value));
    MakoLog(line);
    std::snprintf(line, sizeof(line), "rk-w0=%016llx w8=%016llx", w0, w8);
    MakoLog(line);
    std::snprintf(line, sizeof(line), "rk-w16=%016llx w24=%016llx", w16, w24);
    MakoLog(line);
    std::snprintf(line, sizeof(line), "rk-f m0=%u m16=%u x24=%u",
                  w0_mapped ? 1U : 0U, w16_mapped ? 1U : 0U, w24_exec ? 1U : 0U);
    MakoLog(line);
  }

  /* Now the layout verdict is meaningful, and it is the probe that decides. */
  ArtMethodProbeSpec spec;
  spec.expected_jni_code_start = static_cast<std::uintptr_t>(libart_start);
  spec.expected_jni_code_end = static_cast<std::uintptr_t>(libart_end);
  spec.expected_access_flags = 0x100U; /* kAccNative */
  spec.relevant_access_flags_mask = 0x100U;
  spec.android_api_level = DeviceApiLevel();
  spec.has_interpreter_entrypoint = true;

  spec.method = reinterpret_cast<void *>(value);
  const bool modern_ok =
      ProbeLayoutModern(reinterpret_cast<void *>(value), libart_start, libart_end).ok();
  const bool generic_ok = ProbeArtMethodLayout(spec).ok();
  /* The layout verdict is the probe's, and it is applied here - after the
   * probes have run (see the note at the top of this function). */
  const JniIdClassification classified =
      ClassifyJniId(view, modern_ok || generic_ok);
  if (classified.resolved()) {
    char buffer[224];
    std::snprintf(buffer, sizeof(buffer),
                  "rtgum-mako: id-mode=pointer raw-id=0x%llx record=0x%llx "
                  "resolver=%s",
                  static_cast<unsigned long long>(value),
                  static_cast<unsigned long long>(classified.record),
                  modern_ok ? "layout-modern" : "layout-scan");
    MakoLog(buffer);
    return reinterpret_cast<void *>(classified.record);
  }

  /* Safe to read, but not an ArtMethod record. Under kSwapablePointer that is
   * what a table slot looks like, and telling it apart from an unrelated
   * pointer needs the runtime's own decode. Report it rather than probing
   * further: the candidate's own bytes are already in the log above, which is
   * what separates "wrong address" from "right address, wrong expectations". */
  {
    char buffer[200];
    std::snprintf(buffer, sizeof(buffer),
                  "rtgum-mako: id-mode=%s reason=%s raw-id=0x%llx rejected m=%u g=%u",
                  IdModeName(classified.mode), IdReasonName(classified.reason),
                  static_cast<unsigned long long>(value), modern_ok ? 1U : 0U,
                  generic_ok ? 1U : 0U);
    MakoLog(buffer);
  }
  return DecodeManagedArtMethod(env, id, libart_start, libart_end);
}
/* Definition of the InstallHook declared above (see the note there). */
long InstallHook(JNIEnv *env, jmethodID id, MakoArtCallback on_enter,
                 MakoArtCallback on_leave, void *user_data,
                 unsigned long *out_handle) {
  if (env == nullptr || id == nullptr || out_handle == nullptr) return -22;
  *out_handle = 0;
  if (g_host == nullptr || !g_pool) return -14;
  if (!EnsureTrampolineWorks()) return -14;
  unsigned long long libart_start = 0;
  unsigned long long libart_end = 0;
  if (!FindExecutableRange("libart.so", libart_start, libart_end)) {
    MakoLog("rtgum-mako: libart.so range lookup failed");
    return -14;
  }
  void *method = DecodeArtMethod(env, id, libart_start, libart_end);
  if (method == nullptr) {
    /* Log the token itself, never a dereference of it. An earlier version read
     * the first word at `id` here "just for diagnostics": under kIndices that
     * is a load from a small integer, i.e. a fault in the failure path, which
     * is the worst place to add one. DecodeArtMethod has already reported the
     * classification and, for a rejected pointer, its own bytes. */
    char buffer[160];
    std::snprintf(buffer, sizeof(buffer),
                  "rtgum-mako: jmethodID decode rejected raw-id=0x%llx art=[0x%llx,0x%llx)",
                  static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(id)),
                  static_cast<unsigned long long>(libart_start),
                  static_cast<unsigned long long>(libart_end));
    MakoLog(buffer);
    return -14;
  }
  const auto method_address = reinterpret_cast<std::uintptr_t>(method);
  const unsigned long page_va = method_address & ~0xFFFUL;
  const unsigned long quick_page_offset =
      (method_address - page_va) + g_layout.quick_code_offset;
  if (quick_page_offset + sizeof(unsigned long) > 0x1000UL) return -14;

  /* Stacking two independent states on one ArtMethod loses the lower patch
   * when either state is reverted. Reject it explicitly; different methods on
   * the same data page continue to share the page through incremental patches. */
  if (HasActiveHookAt(page_va, quick_page_offset)) {
    MakoLog("rtgum-mako: duplicate ArtMethod hook rejected");
    return -16;
  }

  /* Register the ART data page with the kernel (idempotent; the Daemon
   * wrapper treats -EBUSY as success). One shadow page is shared by every
   * ArtMethod on the page through incremental patches. */
  unsigned long page_handle = 0;
  long status = g_host->art_page_register(page_va, &page_handle);
  if (status != 0) {
    MakoLog("rtgum-mako: art page register failed");
    return status;
  }
  if (!g_trust_registered) RegisterArtTrustRanges();

  unsigned long quick_value = 0;
  if (g_host->art_page_read(page_va, quick_page_offset, &quick_value) != 0) {
    RollBackUnusedPage(page_va);
    return -14;
  }
  unsigned long interpreter_value = 0;
  if (g_layout.interpreter_code_offset.has_value()) {
    const unsigned long interpreter_page_offset =
        (method_address - page_va) + *g_layout.interpreter_code_offset;
    (void)g_host->art_page_read(page_va, interpreter_page_offset,
                                &interpreter_value);
  }
  const unsigned long long original_entry =
      quick_value != 0ULL ? quick_value : interpreter_value;
  if (original_entry == 0ULL) {
    MakoLog("rtgum-mako: method has no quick or interpreter entry");
    RollBackUnusedPage(page_va);
    return -2;
  }
  {
    char text[160];
    std::snprintf(text, sizeof(text),
                  "rtgum-mako: install read quick=0x%llx page=0x%lx off=0x%lx",
                  static_cast<unsigned long long>(quick_value), page_va,
                  quick_page_offset);
    MakoLog(text);
  }

  auto *state = new (std::nothrow) MakoHookState();
  if (state == nullptr) {
    RollBackUnusedPage(page_va);
    return -12;
  }
  state->method_id = id;
  state->method = method;
  state->page_va = page_va;
  state->quick_page_offset = quick_page_offset;
  state->original_quick = quick_value;
  state->original_entry = original_entry;
  state->on_enter.store(on_enter, std::memory_order_relaxed);
  state->on_leave.store(on_leave, std::memory_order_relaxed);
  state->user_data.store(user_data, std::memory_order_relaxed);

  auto enter = Arm64Trampoline::Create(EnterDispatch, state, *g_pool);
  if (!enter.ok()) {
    char buffer[256];
    std::snprintf(buffer, sizeof(buffer), "rtgum-mako: trampoline alloc failed (enter): %s",
                  enter.status().ToString().c_str());
    MakoLog(buffer);
    delete state;
    RollBackUnusedPage(page_va);
    return -12;
  }
  auto leave = Arm64Trampoline::Create(LeaveDispatch, state, *g_pool);
  if (!leave.ok()) {
    MakoLog("rtgum-mako: trampoline alloc failed (leave)");
    delete state;
    RollBackUnusedPage(page_va);
    return -12;
  }
  state->enter_trampoline = std::move(enter).value();
  state->leave_trampoline = std::move(leave).value();
  state->leave_entry = state->leave_trampoline->entrypoint();

  const unsigned long trampoline =
      reinterpret_cast<unsigned long>(state->enter_trampoline->entrypoint());
  status = g_host->art_page_patch(page_va, quick_page_offset, trampoline);
  if (status != 0) {
    char text[128];
    std::snprintf(text, sizeof(text),
                  "rtgum-mako: art page patch failed rc=%ld", status);
    MakoLog(text);
    delete state;
    RollBackUnusedPage(page_va);
    return status;
  }
  state->active.store(true, std::memory_order_release);
  g_states.push_back(state);
  *out_handle = reinterpret_cast<unsigned long>(state);

  /* In-band scanner-view self-check. Mako's own code is NOT in the trusted
   * ranges, so a direct read of the hooked field through the user VA is
   * served the ORIGINAL page — exactly what a scanner sees — while the
   * kernel-mediated read returns the tampered shadow value. Gate on the KPM
   * fault hooks: without them the direct read would SIGSEGV. */
  if (g_host->art_shadow_query != nullptr && g_host->art_shadow_query() > 0) {
    const auto *slot = reinterpret_cast<const volatile unsigned long long *>(
        method_address + g_layout.quick_code_offset);
    const unsigned long long scanner_view = *slot;
    unsigned long trusted_view = 0;
    (void)g_host->art_page_read(page_va, quick_page_offset, &trusted_view);
    char text[200];
    std::snprintf(text,
                  sizeof(text),
                  "rtgum-mako: views scanner=0x%llx trusted=0x%llx",
                  static_cast<unsigned long long>(scanner_view),
                  static_cast<unsigned long long>(trusted_view));
    MakoLog(text);
    std::snprintf(text,
                  sizeof(text),
                  "rtgum-mako: views original=0x%llx page=0x%lx off=0x%lx",
                  static_cast<unsigned long long>(quick_value),
                  page_va,
                  quick_page_offset);
    MakoLog(text);
  }
  MakoLog("rtgum-mako: hook installed");
  return 0;
}

}  // namespace

jclass FindClassViaAppLoader(JNIEnv *env, const char *name);

bool EnsureLayout(JNIEnv *env) {
  if (g_layout_ready) return true;
  unsigned long long libart_start = 0;
  unsigned long long libart_end = 0;
  if (!FindExecutableRange("libart.so", libart_start, libart_end)) {
    MakoLog("rtgum-mako: libart.so executable range not found");
    return false;
  }
  jmethodID anchor = nullptr;
  const MakoReflectionCache *reflection = InheritedReflection();
  if (reflection != nullptr) {
    anchor = reinterpret_cast<jmethodID>(reflection->object_hash_code);
    MakoLog("rtgum-mako: inherited pre-fork reflection cache");
  } else {
    jclass object_class = env->FindClass("java/lang/Object");
    if (object_class == nullptr || env->ExceptionCheck()) {
      env->ExceptionClear();
      MakoLog("rtgum-mako: Object class lookup failed");
      return false;
    }
    anchor = env->GetMethodID(object_class, "hashCode", "()I");
    env->DeleteLocalRef(object_class);
  }
  if (anchor == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    MakoLog("rtgum-mako: Object.hashCode lookup failed");
    return false;
  }
  void *method = DecodeArtMethod(env, anchor, libart_start, libart_end);
  if (method == nullptr) {
    MakoLog("rtgum-mako: jmethodID decode rejected");
    return false;
  }
  auto layout = ProbeLayoutModern(method, libart_start, libart_end);
  if (!layout.ok()) {
    /* Fall back to the generic scanner for older layouts. */
    ArtMethodProbeSpec spec;
    spec.method = method;
    spec.expected_jni_code_start = static_cast<std::uintptr_t>(libart_start);
    spec.expected_jni_code_end = static_cast<std::uintptr_t>(libart_end);
    spec.expected_access_flags = 0x100U;
    spec.relevant_access_flags_mask = 0x100U;
    spec.android_api_level = DeviceApiLevel();
    spec.has_interpreter_entrypoint = true;
    layout = ProbeArtMethodLayout(spec);
    if (!layout.ok()) {
      MakoLog("rtgum-mako: ArtMethod layout probe failed");
      return false;
    }
  }
  g_layout = layout.value();
  g_layout_ready = true;
  MakoLog("rtgum-mako: ArtMethod layout probed");
  return true;
}

long HookActivityCreate(void *env_ptr, const char *class_name,
                        MakoArtCallback on_enter, MakoArtCallback on_leave,
                        void *user_data, unsigned long *out_handle) {
  if (out_handle == nullptr) return -22;
  *out_handle = 0;
  if (class_name == nullptr) return -22;
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_host == nullptr) return -14;
  JNIEnv *env = static_cast<JNIEnv *>(env_ptr);
  if (env == nullptr) env = AcquireEnv();
  if (env == nullptr) return -14;
  if (!EnsureLayout(env)) return -14;

  /* A quick-ABI receiver is a managed heap reference, not a JNI jobject. The
   * former performCreate anchor cast a register to jobject and crashed under
   * both CheckJNI and ordinary ART. Avoid receiver conversion entirely:
   * wildcard mode hooks Activity.onCreate, which every valid Activity must call
   * through super; an exact class hooks that class directly. */
  std::string target(class_name);
  const bool any = target == "*";
  if (target.size() >= 2U && target.front() == 'L' && target.back() == ';')
    target = target.substr(1U, target.size() - 2U);
  std::replace(target.begin(), target.end(), '.', '/');

  const char *lookup = any ? "android/app/Activity" : target.c_str();
  jclass activity = env->FindClass(lookup);
  if ((activity == nullptr || env->ExceptionCheck()) && !any) {
    env->ExceptionClear();
    activity = FindClassViaAppLoader(env, lookup);
  }
  if (activity == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    MakoLog("rtgum-mako: Activity target class lookup failed");
    return -2;
  }
  jmethodID on_create = env->GetMethodID(
      activity, "onCreate", "(Landroid/os/Bundle;)V");
  if (on_create == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    env->DeleteLocalRef(activity);
    MakoLog("rtgum-mako: Activity.onCreate method lookup failed");
    return -2;
  }
  jobject reflected = env->ToReflectedMethod(activity, on_create, JNI_FALSE);
  if (reflected != nullptr && !env->ExceptionCheck()) {
    std::string shorty;
    if (BuildReflectedShorty(env, reflected, shorty)) {
      char text[96];
      std::snprintf(text, sizeof(text),
                    "rtgum-mako: method shorty=%s source=pre-fork-cache",
                    shorty.c_str());
      MakoLog(text);
    }
    env->DeleteLocalRef(reflected);
  } else {
    env->ExceptionClear();
    if (reflected != nullptr) env->DeleteLocalRef(reflected);
  }
  env->DeleteLocalRef(activity);
  const long rc = InstallHook(env, on_create, on_enter, on_leave, user_data,
                              out_handle);
  if (rc == 0)
    MakoLog(any ? "rtgum-mako: Activity.onCreate hook installed"
                : "rtgum-mako: target onCreate hook installed");
  return rc;
}

/* The ghost module runs on a raw clone thread: JNI FindClass resolves through
 * the bootstrap loader only, so app classes are invisible. Fall back to the
 * Application's class loader through the framework path. */
jclass FindClassViaAppLoader(JNIEnv *env, const char *name) {
  static unsigned s_step_logs = 0;
  const auto step_log = [](const char *message) {
    if (s_step_logs < 3U) {
      ++s_step_logs;
      MakoLog(message);
    }
  };
  /* Hidden-API enforcement blocks ActivityThread.currentActivityThread()
   * calls; use only public API: the main thread's context class loader is
   * the application's PathClassLoader once the app is initializing. */
  jclass looper = env->FindClass("android/os/Looper");
  if (looper == nullptr || env->ExceptionCheck()) {
    LogPendingJniException(env, &s_step_logs);
    env->ExceptionClear();
    step_log("rtgum-mako: apploader step0 Looper class missing");
    return nullptr;
  }
  jclass result = nullptr;
  jobject loader = nullptr;
  jstring name_string = nullptr;
  jmethodID get_main = env->GetStaticMethodID(
      looper, "getMainLooper", "()Landroid/os/Looper;");
  if (get_main == nullptr) {
    env->ExceptionClear();
    step_log("rtgum-mako: apploader step1a getMainLooper method id blocked");
    env->DeleteLocalRef(looper);
    return nullptr;
  }
  jobject main_looper = env->CallStaticObjectMethod(looper, get_main);
  if (main_looper == nullptr || env->ExceptionCheck()) {
    LogPendingJniException(env, &s_step_logs);
    env->ExceptionClear();
    step_log("rtgum-mako: apploader step1 getMainLooper failed");
    env->DeleteLocalRef(looper);
    return nullptr;
  }
  jmethodID get_thread = env->GetMethodID(
      looper, "getThread", "()Ljava/lang/Thread;");
  jobject main_thread = (get_thread != nullptr)
                            ? env->CallObjectMethod(main_looper, get_thread)
                            : nullptr;
  if (main_thread == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    step_log("rtgum-mako: apploader step2 getThread failed");
    env->DeleteLocalRef(main_looper);
    env->DeleteLocalRef(looper);
    return nullptr;
  }
  jclass thread_class = env->FindClass("java/lang/Thread");
  jmethodID get_ccl = thread_class != nullptr
                          ? env->GetMethodID(thread_class, "getContextClassLoader",
                                             "()Ljava/lang/ClassLoader;")
                          : nullptr;
  loader = (get_ccl != nullptr) ? env->CallObjectMethod(main_thread, get_ccl)
                                : nullptr;
  if (loader == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    step_log("rtgum-mako: apploader step3 context loader not ready");
    if (thread_class != nullptr) env->DeleteLocalRef(thread_class);
    env->DeleteLocalRef(main_thread);
    env->DeleteLocalRef(main_looper);
    env->DeleteLocalRef(looper);
    return nullptr;
  }
  jclass loader_class = env->FindClass("java/lang/ClassLoader");
  jmethodID load_class = loader_class != nullptr
                             ? env->GetMethodID(loader_class, "loadClass",
                                                "(Ljava/lang/String;)Ljava/lang/Class;")
                             : nullptr;
  name_string = env->NewStringUTF(name);
  if (load_class != nullptr && name_string != nullptr)
    result = static_cast<jclass>(
        env->CallObjectMethod(loader, load_class, name_string));
  if (result == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    step_log("rtgum-mako: apploader step4 loadClass failed");
    result = nullptr;
  } else {
    step_log("rtgum-mako: apploader resolved class via main thread loader");
  }
  if (name_string != nullptr) env->DeleteLocalRef(name_string);
  if (loader_class != nullptr) env->DeleteLocalRef(loader_class);
  env->DeleteLocalRef(loader);
  if (thread_class != nullptr) env->DeleteLocalRef(thread_class);
  env->DeleteLocalRef(main_thread);
  env->DeleteLocalRef(main_looper);
  env->DeleteLocalRef(looper);
  return result;
}

long HookMethod(void *env_ptr, const char *class_name, const char *method_name,
                const char *signature, int is_static,
                MakoArtCallback on_enter, MakoArtCallback on_leave,
                void *user_data, unsigned long *out_handle) {
  static unsigned s_trace_logs = 0;
  const auto trace_log = [](const char *message) {
    if (s_trace_logs < 8U) {
      ++s_trace_logs;
      MakoLog(message);
    }
  };
  if (out_handle == nullptr) return -22;
  *out_handle = 0;
  if (class_name == nullptr || method_name == nullptr || signature == nullptr)
    return -22;
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_host == nullptr) return -14;
  trace_log("rtgum-mako: hm1 lock");
  JNIEnv *env = static_cast<JNIEnv *>(env_ptr);
  if (env == nullptr) env = AcquireEnv();
  if (env == nullptr) {
    MakoLog("rtgum-mako: JNIEnv acquisition failed");
    return -14;
  }
  trace_log("rtgum-mako: hm2 env");
  if (!EnsureLayout(env)) return -14;
  trace_log("rtgum-mako: hm3 layout");

  std::string name(class_name);
  if (name.size() >= 2U && name.front() == 'L' && name.back() == ';')
    name = name.substr(1U, name.size() - 2U);
  std::replace(name.begin(), name.end(), '.', '/');
  trace_log("rtgum-mako: hm3a findclass-in");
  jclass klass = env->FindClass(name.c_str());
  trace_log("rtgum-mako: hm3b findclass-out");
  if (klass == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    trace_log("rtgum-mako: hm3c apploader-in");
    klass = FindClassViaAppLoader(env, name.c_str());
    trace_log("rtgum-mako: hm3d apploader-out");
  }
  trace_log("rtgum-mako: hm4 findclass");
  if (klass == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    static unsigned s_lookup_logs = 0;
    if (s_lookup_logs < 3U) {
      ++s_lookup_logs;
      MakoLog("rtgum-mako: class lookup failed");
    }
    return -2;
  }
  jmethodID id = is_static
                     ? env->GetStaticMethodID(klass, method_name, signature)
                     : env->GetMethodID(klass, method_name, signature);
  trace_log("rtgum-mako: hm5 getmethod");
  if (id == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    env->DeleteLocalRef(klass);
    return -2;
  }
  jobject reflected = env->ToReflectedMethod(
      klass, id, is_static != 0 ? JNI_TRUE : JNI_FALSE);
  if (reflected != nullptr && !env->ExceptionCheck()) {
    std::string shorty;
    if (BuildReflectedShorty(env, reflected, shorty)) {
      char text[96];
      std::snprintf(text, sizeof(text),
                    "rtgum-mako: method shorty=%s source=pre-fork-cache",
                    shorty.c_str());
      MakoLog(text);
    }
    env->DeleteLocalRef(reflected);
  } else {
    env->ExceptionClear();
    if (reflected != nullptr) env->DeleteLocalRef(reflected);
  }
  env->DeleteLocalRef(klass);
  trace_log("rtgum-mako: hm6 install");
  return InstallHook(env, id, on_enter, on_leave, user_data, out_handle);
}

long HookReflected(void *env_ptr, void *method_object,
                   MakoArtCallback on_enter, MakoArtCallback on_leave,
                   void *user_data, unsigned long *out_handle) {
  if (out_handle == nullptr) return -22;
  *out_handle = 0;
  if (method_object == nullptr) return -22;
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_host == nullptr) return -14;
  JNIEnv *env = static_cast<JNIEnv *>(env_ptr);
  if (env == nullptr) env = AcquireEnv();
  if (env == nullptr) return -14;
  if (!EnsureLayout(env)) return -14;
  jmethodID id = env->FromReflectedMethod(static_cast<jobject>(method_object));
  if (id == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    return -2;
  }
  std::string shorty;
  if (BuildReflectedShorty(env, static_cast<jobject>(method_object), shorty)) {
    char text[96];
    std::snprintf(text, sizeof(text),
                  "rtgum-mako: reflected shorty=%s source=pre-fork-cache",
                  shorty.c_str());
    MakoLog(text);
  }
  return InstallHook(env, id, on_enter, on_leave, user_data, out_handle);
}

long RevertLocked(MakoHookState *state,
                  std::unique_lock<std::mutex> &lock) {
  if (state == nullptr) return -22;
  if (g_host == nullptr) return -14;
  if (state->active.load(std::memory_order_acquire)) {
    if (g_host->art_page_unpatch == nullptr) return -95;
    const long status = g_host->art_page_unpatch(
        state->page_va, state->quick_page_offset);
    if (status != 0) return status;

    /* Publish inactive immediately after restoring the entry. A new dispatch
     * can then only tail-call the original entry and cannot acquire a module
     * callback while its .ghm is being retired. */
    state->active.store(false, std::memory_order_release);
    state->cleanup_pending = true;
    state->on_enter.store(nullptr, std::memory_order_release);
    state->on_leave.store(nullptr, std::memory_order_release);
    state->user_data.store(nullptr, std::memory_order_release);
    /* A callback may query hook status while teardown is in progress. Do not
     * hold the registry mutex while waiting for it, otherwise that harmless
     * query deadlocks the callback against its own retirement. Self-revert is
     * reported as BUSY and completed later by the Daemon's teardown sweep. */
    if (g_current_callback == state) return -16;
    state->retirement_waiting = true;
    lock.unlock();
    while (state->callbacks_running.load(std::memory_order_acquire) != 0U ||
           state->dispatchers_running.load(std::memory_order_acquire) != 0U)
      asm volatile("yield" ::: "memory");
    lock.lock();
    state->retirement_waiting = false;
    if (!state->cleanup_pending) return 0;
  } else if (!state->cleanup_pending) {
    /* Revert is intentionally idempotent for teardown paths. */
    return 0;
  } else if (state->retirement_waiting) {
    return -16;
  }

  const bool last_on_page = !HasActiveHookOnPage(state->page_va);
  if (last_on_page && g_host->art_page_unregister != nullptr) {
    const long unregister_status =
        g_host->art_page_unregister(state->page_va);
    if (unregister_status != 0) {
      char text[160];
      std::snprintf(text, sizeof(text),
                    "rtgum-mako: shadow unregister failed rc=%ld page=0x%lx",
                    unregister_status, state->page_va);
      MakoLog(text);
      return unregister_status;
    }
  }
  state->cleanup_pending = false;
  if (!HasAnyActiveHook() && g_trust_registered &&
      g_host->art_trust_clear != nullptr) {
    const long clear_status = g_host->art_trust_clear();
    if (clear_status == 0) {
      g_trust_registered = false;
    } else {
      MakoLog("rtgum-mako: hook reverted but trust clear failed");
    }
  }
  /* Trampolines stay retired: a suspended thread may resume inside them. */
  MakoLog("rtgum-mako: hook reverted");
  return 0;
}

long Revert(unsigned long handle) {
  std::unique_lock<std::mutex> lock(g_mutex);
  return RevertLocked(FindState(handle), lock);
}

long StatusOf(unsigned long handle, unsigned int *out_state) {
  if (out_state == nullptr) return -22;
  std::lock_guard<std::mutex> lock(g_mutex);
  auto *state = FindState(handle);
  if (state == nullptr) {
    *out_state = 0U;
    return -2;
  }
  *out_state = state->active.load(std::memory_order_acquire) ? 1U : 0U;
  return 0;
}

/* Reports the id encoding and, when it is reachable, the ArtMethod address.
 *
 * This is the supported way for a consumer to obtain the record: it re-uses the
 * same classification the hook path uses, so a caller can never be more
 * optimistic about a jmethodID than the installer itself is. A runtime whose
 * ids are table tokens yields MAKO_ID_ERR_UNSUPPORTED with the record left at
 * zero - the caller is told to stop, not handed a guess. */
long ProbeId(void *env_ptr, void *method_object, unsigned int *out_mode,
             unsigned long *out_record, unsigned long *out_offset_hint) {
  if (out_mode != nullptr) *out_mode = MAKO_JNI_ID_NULL;
  if (out_record != nullptr) *out_record = 0;
  if (out_offset_hint != nullptr) *out_offset_hint = 0;
  if (method_object == nullptr) return MAKO_ID_ERR_REJECTED;
  std::lock_guard<std::mutex> lock(g_mutex);
  JNIEnv *env = static_cast<JNIEnv *>(env_ptr);
  if (env == nullptr) env = AcquireEnv();
  if (env == nullptr) return MAKO_ID_ERR_REJECTED;

  const jmethodID id = env->FromReflectedMethod(static_cast<jobject>(method_object));
  if (id == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    MakoLog("rtgum-mako: probe_id FromReflectedMethod returned null");
    return MAKO_ID_ERR_REJECTED;
  }
  const uintptr_t value = reinterpret_cast<uintptr_t>(id);
  const JniIdView view = ClassifyView(value);
  unsigned long long libart_start = 0;
  unsigned long long libart_end = 0;
  if (!FindExecutableRange("libart.so", libart_start, libart_end)) {
    MakoLog("rtgum-mako: probe_id libart range unavailable");
    return MAKO_ID_ERR_UNSUPPORTED;
  }
  void *record = DecodeArtMethod(env, id, libart_start, libart_end);
  const JniIdClassification raw_classification = ClassifyJniId(view, false);
  if (record == nullptr) {
    if (out_mode != nullptr) {
      *out_mode = raw_classification.mode == JniIdMode::Index
                      ? MAKO_JNI_ID_INDEX
                  : raw_classification.mode == JniIdMode::SwapablePointer
                      ? MAKO_JNI_ID_SWAPABLE_POINTER
                      : MAKO_JNI_ID_UNRESOLVED;
    }
    return MAKO_ID_ERR_UNSUPPORTED;
  }

  const uintptr_t record_value = reinterpret_cast<uintptr_t>(record);
  if (out_mode != nullptr) {
    if (record_value == value)
      *out_mode = MAKO_JNI_ID_POINTER;
    else if ((value & 1U) != 0U || value < 0x10000U)
      *out_mode = MAKO_JNI_ID_INDEX;
    else
      *out_mode = MAKO_JNI_ID_SWAPABLE_POINTER;
  }
  if (out_record != nullptr) *out_record = record_value;
  if (out_offset_hint != nullptr)
    *out_offset_hint = g_layout_ready ? g_layout.quick_code_offset : 24U;
  return MAKO_ID_OK;
}

extern "C" __attribute__((visibility("default"))) void rtgum_mako_entry(
    const MakoHostApi *host, MakoHookApi *out) {
  if (out == nullptr) return;
  out->version = 0;
  out->size = 0;
  out->hook_method = nullptr;
  out->hook_reflected = nullptr;
  out->hook_activity_create = nullptr;
  out->revert = nullptr;
  out->status = nullptr;
  out->probe_id = nullptr;
  if (host == nullptr || host->version != MAKO_HOST_API_VERSION ||
      host->size < sizeof(MakoHostApi))
    return;
  std::lock_guard<std::mutex> lock(g_mutex);
  g_host = host;
  if (!g_pool) g_pool.reset(new (std::nothrow) GhostJumpPool(host));
  out->version = MAKO_HOOK_API_VERSION;
  out->size = sizeof(MakoHookApi);
  out->hook_method = HookMethod;
  out->hook_reflected = HookReflected;
  out->hook_activity_create = HookActivityCreate;
  out->revert = Revert;
  out->status = StatusOf;
  out->probe_id = ProbeId;
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(
    void *) {
  /* This is a final safety net. Well-behaved user modules revert their own
   * handles first, while the Daemon also tracks every handle it issued. Direct
   * users of the backend may omit both, so never leave an ArtMethod pointing
   * into an image that is about to be unmapped. */
  std::unique_lock<std::mutex> lock(g_mutex);
  long first_error = 0;
  for (auto iterator = g_states.rbegin(); iterator != g_states.rend(); ++iterator) {
    auto *state = static_cast<MakoHookState *>(*iterator);
    const long status = RevertLocked(state, lock);
    if (status != 0 && first_error == 0) first_error = status;
  }
  if (first_error != 0)
    MakoLog("rtgum-mako: unload cleanup incomplete");
  else
    MakoLog("rtgum-mako: unload cleanup complete");
}

/* The KPM's MODULE_LINK looks the export "ghostEntry" up during the link
 * step; the real bind surface is rtgum_mako_entry, resolved afterwards via
 * MODULE_SYMBOL. This alias keeps the link step happy without adding a
 * second entry point. */
extern "C" __attribute__((visibility("default"))) void ghostEntry(void *) {}

/* Local byte-copy primitives. The ghost image is resolved by the KPM's own
 * linker, and bionic's memmove/memcpy/memset/memcmp/strlen are GNU IFUNC
 * symbols whose variant selection must not run on raw clone threads. With
 * -Bsymbolic-functions, every in-image reference binds to these local
 * definitions instead of the provider PLT slots. */
extern "C" __attribute__((visibility("default"), noinline)) void *
memmove(void *destination, const void *source, std::size_t length) {
  auto *to = static_cast<unsigned char *>(destination);
  const auto *from = static_cast<const unsigned char *>(source);
  if (to < from) {
    for (std::size_t i = 0; i < length; ++i) to[i] = from[i];
  } else if (to > from) {
    for (std::size_t i = length; i > 0U; --i) to[i - 1U] = from[i - 1U];
  }
  return destination;
}

extern "C" __attribute__((visibility("default"), noinline)) void *
memcpy(void *destination, const void *source, std::size_t length) {
  auto *to = static_cast<unsigned char *>(destination);
  const auto *from = static_cast<const unsigned char *>(source);
  for (std::size_t i = 0; i < length; ++i) to[i] = from[i];
  return destination;
}

extern "C" __attribute__((visibility("default"), noinline)) void *
memset(void *destination, int value, std::size_t length) {
  auto *to = static_cast<unsigned char *>(destination);
  for (std::size_t i = 0; i < length; ++i)
    to[i] = static_cast<unsigned char>(value);
  return destination;
}

extern "C" __attribute__((visibility("default"), noinline)) int
memcmp(const void *left, const void *right, std::size_t length) {
  const auto *a = static_cast<const unsigned char *>(left);
  const auto *b = static_cast<const unsigned char *>(right);
  for (std::size_t i = 0; i < length; ++i) {
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

extern "C" __attribute__((visibility("default"), noinline)) std::size_t
strlen(const char *text) {
  std::size_t length = 0;
  if (text == nullptr) return 0;
  while (text[length] != '\0') ++length;
  return length;
}

/* Fortify wrappers kept local too, so no reference path escapes into the
 * provider's IFUNC-plumbed libc entry points. */
extern "C" __attribute__((visibility("default"), noinline)) void *
__memmove_chk(void *destination, const void *source, std::size_t length,
              std::size_t destination_size) {
  if (length > destination_size) __builtin_trap();
  return memmove(destination, source, length);
}

extern "C" __attribute__((visibility("default"), noinline)) std::size_t
__strlen_chk(const char *text, std::size_t text_size) {
  const std::size_t length = strlen(text);
  if (length >= text_size) __builtin_trap();
  return length;
}

extern "C" __attribute__((visibility("default"), noinline)) void *
memchr(const void *block, int value, std::size_t length) {
  const auto *bytes = static_cast<const unsigned char *>(block);
  for (std::size_t i = 0; i < length; ++i) {
    if (bytes[i] == static_cast<unsigned char>(value))
      return const_cast<unsigned char *>(&bytes[i]);
  }
  return nullptr;
}

extern "C" __attribute__((visibility("default"), noinline)) char *
strchr(const char *text, int value) {
  if (text == nullptr) return nullptr;
  for (std::size_t i = 0;; ++i) {
    if (text[i] == static_cast<char>(value))
      return const_cast<char *>(&text[i]);
    if (text[i] == '\0') return nullptr;
  }
}

extern "C" __attribute__((visibility("default"), noinline)) char *
strstr(const char *haystack, const char *needle) {
  if (haystack == nullptr || needle == nullptr) return nullptr;
  if (needle[0] == '\0') return const_cast<char *>(haystack);
  for (std::size_t i = 0; haystack[i] != '\0'; ++i) {
    std::size_t j = 0;
    while (needle[j] != '\0' && haystack[i + j] == needle[j]) ++j;
    if (needle[j] == '\0') return const_cast<char *>(&haystack[i]);
  }
  return nullptr;
}

extern "C" __attribute__((visibility("default"), noinline)) int
strcmp(const char *left, const char *right) {
  if (left == nullptr || right == nullptr)
    return (left != nullptr) - (right != nullptr);
  std::size_t i = 0;
  while (left[i] != '\0' && left[i] == right[i]) ++i;
  return static_cast<unsigned char>(left[i]) - static_cast<unsigned char>(right[i]);
}

extern "C" __attribute__((visibility("default"), noinline)) int
strncmp(const char *left, const char *right, std::size_t length) {
  if (length == 0) return 0;
  if (left == nullptr || right == nullptr)
    return (left != nullptr) - (right != nullptr);
  for (std::size_t i = 0; i < length; ++i) {
    if (left[i] != right[i] || left[i] == '\0')
      return static_cast<unsigned char>(left[i]) - static_cast<unsigned char>(right[i]);
  }
  return 0;
}

extern "C" __attribute__((visibility("default"))) jint JNI_OnLoad(JavaVM *vm,
                                                                  void *) {
  JNIEnv *env = nullptr;
  if (vm == nullptr ||
      vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
    return JNI_ERR;
  return JNI_VERSION_1_6;
}
