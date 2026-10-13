// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include <jni.h>

#include <mutex>
#include <optional>

#include "art_hook/runtime_api.h"

namespace {

std::mutex g_mutex;
std::optional<art_hook::RuntimeApi> g_runtime;

}  // namespace

extern "C" __attribute__((visibility("default"))) jint JNI_OnLoad(
    JavaVM* vm, void*) {
  auto runtime = art_hook::RuntimeApi::Discover(vm);
  if (!runtime.ok()) {
    return JNI_ERR;
  }
  std::lock_guard<std::mutex> lock(g_mutex);
  g_runtime.emplace(std::move(runtime).value());
  return JNI_VERSION_1_6;
}

extern "C" __attribute__((visibility("default"))) void JNI_OnUnload(
    JavaVM*, void*) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_runtime.reset();
}

extern "C" __attribute__((visibility("default"))) const char*
art_hook_build_id() {
  return "art-hook-cpp/0.1.0";
}
