// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/mako_seed.h"

#include <atomic>
#include <mutex>

#include "mako_reflection_cache.h"

namespace {
MakoReflectionSeed g_seed{};
std::mutex g_prepare_mutex;
std::atomic<bool> g_ready{false};
}  // namespace

extern "C" __attribute__((visibility("default"))) int
mako_seed_prepare(JNIEnv* env) {
  if (env == nullptr || env->ExceptionCheck()) return MAKO_ERR_INVALID;
  if (g_ready.load(std::memory_order_acquire)) return MAKO_OK;
  std::lock_guard<std::mutex> lock(g_prepare_mutex);
  if (g_ready.load(std::memory_order_relaxed)) return MAKO_OK;
  MakoReflectionSeed candidate{};
  const int status = BuildReflectionSeed(env, &candidate);
  if (status != MAKO_OK) return status;
  g_seed = candidate;
  g_ready.store(true, std::memory_order_release);
  return MAKO_OK;
}

extern "C" __attribute__((visibility("default"))) const MakoReflectionSeed*
mako_seed_export(void) {
  return g_ready.load(std::memory_order_acquire) ? &g_seed : nullptr;
}

extern "C" __attribute__((visibility("default"))) int
mako_seed_ready(void) {
  return g_ready.load(std::memory_order_acquire) ? 1 : 0;
}

extern "C" __attribute__((visibility("default"))) jint
JNI_OnLoad(JavaVM* vm, void*) {
  JNIEnv* env = nullptr;
  if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env),
                                  JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
  // Preparation belongs to the explicit pre-fork host call, not DSO load.
  return JNI_VERSION_1_6;
}

extern "C" __attribute__((visibility("default"))) jint JNICALL
Java_com_rtgum_mako_PreForkHost_prepare(JNIEnv* env, jclass) {
  return mako_seed_prepare(env);
}

extern "C" __attribute__((visibility("default"))) jboolean JNICALL
Java_com_rtgum_mako_PreForkHost_ready(JNIEnv*, jclass) {
  return mako_seed_ready() == 1 ? JNI_TRUE : JNI_FALSE;
}

extern "C" __attribute__((visibility("default"))) void
JNI_OnUnload(JavaVM* vm, void*) {
  JNIEnv* env = nullptr;
  if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env),
                                  JNI_VERSION_1_6) != JNI_OK) return;
  std::lock_guard<std::mutex> lock(g_prepare_mutex);
  g_ready.store(false, std::memory_order_release);
  ReleaseReflectionSeed(env, &g_seed);
}
