// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/mako.h"
#include "art_hook/mako_seed.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <string>

#include "mako_reflection_cache.h"

namespace {

MakoReflectionSeed g_reflection{};
std::mutex g_prepare_mutex;
std::atomic<bool> g_ready{false};

int ConsumeJniError(JNIEnv* env, int code = MAKO_ERR_JNI) {
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    return code;
  }
  return MAKO_OK;
}

int ShortyForType(JNIEnv* env, jobject type, char* result) {
  if (type == nullptr || result == nullptr) {
    return MAKO_ERR_JNI;
  }
  auto* name = static_cast<jstring>(
      env->CallObjectMethod(type, g_reflection.get_class_name));
  if (ConsumeJniError(env) != MAKO_OK || name == nullptr) {
    return MAKO_ERR_JNI;
  }
  const char* chars = env->GetStringUTFChars(name, nullptr);
  if (ConsumeJniError(env) != MAKO_OK || chars == nullptr) {
    env->DeleteLocalRef(name);
    return MAKO_ERR_JNI;
  }
  char code = 'L';
  if (std::strcmp(chars, "void") == 0) code = 'V';
  else if (std::strcmp(chars, "boolean") == 0) code = 'Z';
  else if (std::strcmp(chars, "byte") == 0) code = 'B';
  else if (std::strcmp(chars, "char") == 0) code = 'C';
  else if (std::strcmp(chars, "short") == 0) code = 'S';
  else if (std::strcmp(chars, "int") == 0) code = 'I';
  else if (std::strcmp(chars, "long") == 0) code = 'J';
  else if (std::strcmp(chars, "float") == 0) code = 'F';
  else if (std::strcmp(chars, "double") == 0) code = 'D';
  env->ReleaseStringUTFChars(name, chars);
  env->DeleteLocalRef(name);
  *result = code;
  return MAKO_OK;
}

int ResolveReflected(JNIEnv* env, jobject method, jmethodID* method_id,
                     char* shorty, size_t capacity, size_t* needed) {
  if (env == nullptr || method == nullptr || method_id == nullptr ||
      shorty == nullptr || env->ExceptionCheck()) {
    return MAKO_ERR_INVALID;
  }
  *method_id = nullptr;
  if (needed != nullptr) *needed = 0;
  const int prepared = mako_prepare(env);
  if (prepared != MAKO_OK) return prepared;
  if (!env->IsInstanceOf(method, g_reflection.method_class)) {
    return ConsumeJniError(env) == MAKO_OK ? MAKO_ERR_INVALID : MAKO_ERR_JNI;
  }
  if (ConsumeJniError(env) != MAKO_OK) return MAKO_ERR_JNI;

  auto* parameters = static_cast<jobjectArray>(
      env->CallObjectMethod(method, g_reflection.get_parameter_types));
  if (ConsumeJniError(env) != MAKO_OK || parameters == nullptr) {
    return MAKO_ERR_JNI;
  }
  const jsize count = env->GetArrayLength(parameters);
  if (ConsumeJniError(env) != MAKO_OK || count < 0) {
    env->DeleteLocalRef(parameters);
    return MAKO_ERR_JNI;
  }
  const size_t required = static_cast<size_t>(count) + 2U;
  if (needed != nullptr) *needed = required;
  if (capacity < required) {
    env->DeleteLocalRef(parameters);
    return MAKO_ERR_SPACE;
  }

  auto* return_type = env->CallObjectMethod(method,
                                            g_reflection.get_return_type);
  if (ConsumeJniError(env) != MAKO_OK || return_type == nullptr) {
    env->DeleteLocalRef(parameters);
    return MAKO_ERR_JNI;
  }
  int status = ShortyForType(env, return_type, &shorty[0]);
  env->DeleteLocalRef(return_type);
  if (status != MAKO_OK) {
    env->DeleteLocalRef(parameters);
    return status;
  }
  for (jsize i = 0; i < count; ++i) {
    jobject parameter = env->GetObjectArrayElement(parameters, i);
    if (ConsumeJniError(env) != MAKO_OK || parameter == nullptr) {
      status = MAKO_ERR_JNI;
      break;
    }
    status = ShortyForType(env, parameter,
                           &shorty[static_cast<size_t>(i) + 1U]);
    env->DeleteLocalRef(parameter);
    if (status != MAKO_OK) break;
  }
  env->DeleteLocalRef(parameters);
  if (status != MAKO_OK) return status;

  const jmethodID id = env->FromReflectedMethod(method);
  if (ConsumeJniError(env) != MAKO_OK || id == nullptr) {
    return MAKO_ERR_JNI;
  }
  shorty[required - 1U] = '\0';
  *method_id = id;
  return MAKO_OK;
}

}  // namespace

extern "C" __attribute__((visibility("default"))) int
mako_prepare(JNIEnv* env) {
  if (env == nullptr || env->ExceptionCheck()) return MAKO_ERR_INVALID;
  if (g_ready.load(std::memory_order_acquire)) return MAKO_OK;
  std::lock_guard<std::mutex> lock(g_prepare_mutex);
  if (g_ready.load(std::memory_order_relaxed)) return MAKO_OK;

  MakoReflectionSeed candidate{};
  const int status = BuildReflectionSeed(env, &candidate);
  if (status != MAKO_OK) return status;
  g_reflection = candidate;
  g_ready.store(true, std::memory_order_release);
  return MAKO_OK;
}

extern "C" __attribute__((visibility("default"))) int
mako_adopt_seed(JNIEnv* env, const MakoReflectionSeed* seed) {
  if (env == nullptr || seed == nullptr || env->ExceptionCheck() ||
      seed->version != MAKO_SEED_VERSION ||
      seed->size != sizeof(MakoReflectionSeed) ||
      seed->magic != MAKO_SEED_MAGIC ||
      seed->method_class == nullptr || seed->class_class == nullptr ||
      seed->get_return_type == nullptr ||
      seed->get_parameter_types == nullptr ||
      seed->get_class_name == nullptr) return MAKO_ERR_INVALID;
  std::lock_guard<std::mutex> lock(g_prepare_mutex);
  if (g_ready.load(std::memory_order_relaxed)) return MAKO_ERR_BUSY;
  if (env->GetObjectRefType(seed->method_class) != JNIGlobalRefType ||
      env->GetObjectRefType(seed->class_class) != JNIGlobalRefType) {
    return ConsumeJniError(env) == MAKO_OK ? MAKO_ERR_INVALID : MAKO_ERR_JNI;
  }
  if (ConsumeJniError(env) != MAKO_OK) return MAKO_ERR_JNI;
  MakoReflectionSeed candidate = *seed;
  candidate.method_class = static_cast<jclass>(
      env->NewGlobalRef(seed->method_class));
  if (ConsumeJniError(env) != MAKO_OK || candidate.method_class == nullptr) {
    if (candidate.method_class != nullptr)
      env->DeleteGlobalRef(candidate.method_class);
    return MAKO_ERR_JNI;
  }
  candidate.class_class = static_cast<jclass>(
      env->NewGlobalRef(seed->class_class));
  if (ConsumeJniError(env) != MAKO_OK || candidate.class_class == nullptr) {
    ReleaseReflectionSeed(env, &candidate);
    return MAKO_ERR_JNI;
  }
  g_reflection = candidate;
  g_ready.store(true, std::memory_order_release);
  return MAKO_OK;
}

extern "C" __attribute__((visibility("default"))) int
mako_reflection_ready(void) {
  return g_ready.load(std::memory_order_acquire) ? 1 : 0;
}

extern "C" __attribute__((visibility("default"))) int
mako_resolve_reflected(JNIEnv* env, jobject method, jmethodID* method_id,
                       char* shorty, size_t capacity, size_t* needed) {
  return ResolveReflected(env, method, method_id, shorty, capacity, needed);
}

extern "C" __attribute__((visibility("default"))) int
mako_resolve_method(JNIEnv* env, const char* class_name,
                    const char* method_name, const char* signature,
                    int is_static, jmethodID* method_id, char* shorty,
                    size_t capacity, size_t* needed) {
  if (env == nullptr || class_name == nullptr || method_name == nullptr ||
      signature == nullptr || method_id == nullptr || shorty == nullptr ||
      *class_name == '\0' || *method_name == '\0' || *signature == '\0' ||
      env->ExceptionCheck()) {
    return MAKO_ERR_INVALID;
  }
  *method_id = nullptr;
  if (needed != nullptr) *needed = 0;
  const int prepared = mako_prepare(env);
  if (prepared != MAKO_OK) return prepared;
  try {
    std::string name(class_name);
    if (name.size() >= 2U && name.front() == 'L' && name.back() == ';') {
      name = name.substr(1U, name.size() - 2U);
    }
    std::replace(name.begin(), name.end(), '.', '/');
    jclass klass = env->FindClass(name.c_str());
    if (ConsumeJniError(env, MAKO_ERR_NOT_FOUND) != MAKO_OK ||
        klass == nullptr) {
      return MAKO_ERR_NOT_FOUND;
    }
    const jmethodID found = is_static
        ? env->GetStaticMethodID(klass, method_name, signature)
        : env->GetMethodID(klass, method_name, signature);
    if (ConsumeJniError(env, MAKO_ERR_NOT_FOUND) != MAKO_OK ||
        found == nullptr) {
      env->DeleteLocalRef(klass);
      return MAKO_ERR_NOT_FOUND;
    }
    jobject reflected = env->ToReflectedMethod(
        klass, found, is_static ? JNI_TRUE : JNI_FALSE);
    const int status = ConsumeJniError(env);
    env->DeleteLocalRef(klass);
    if (status != MAKO_OK || reflected == nullptr) {
      return MAKO_ERR_JNI;
    }
    const int resolved = ResolveReflected(env, reflected, method_id,
                                          shorty, capacity, needed);
    env->DeleteLocalRef(reflected);
    return resolved;
  } catch (...) {
    return MAKO_ERR_JNI;
  }
}

extern "C" __attribute__((visibility("default"))) const char*
mako_build_id(void) {
  return "mako-reflection/0.2.0";
}

extern "C" __attribute__((visibility("default"))) jint
JNI_OnLoad(JavaVM* vm, void*) {
  JNIEnv* env = nullptr;
  if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env),
                                  JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  // The host may adopt its inherited seed after this library loads.
  return JNI_VERSION_1_6;
}

extern "C" __attribute__((visibility("default"))) void
JNI_OnUnload(JavaVM* vm, void*) {
  JNIEnv* env = nullptr;
  if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env),
                                  JNI_VERSION_1_6) != JNI_OK) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_prepare_mutex);
  g_ready.store(false, std::memory_order_release);
  ReleaseReflectionSeed(env, &g_reflection);
}
