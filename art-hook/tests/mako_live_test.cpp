// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include <dlfcn.h>
#include <jni.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <cstdio>

#include "art_hook/mako.h"
#include "art_hook/mako_seed.h"

namespace {

using Ready = int (*)();
using Prepare = int (*)(JNIEnv*);
using Adopt = int (*)(JNIEnv*, const MakoReflectionSeed*);
using ExportSeed = const MakoReflectionSeed* (*)();
using ResolveName = int (*)(JNIEnv*, const char*, const char*, const char*,
                            int, jmethodID*, char*, size_t, size_t*);
using ResolveReflected = int (*)(JNIEnv*, jobject, jmethodID*, char*,
                                 size_t, size_t*);

jstring Report(JNIEnv* env, const char* message) {
  return env->NewStringUTF(message);
}

const char* CheckResolution(JNIEnv* env, jclass probe_class,
                            ResolveName by_name,
                            ResolveReflected by_reflected) {
  jmethodID named_id = nullptr;
  jmethodID reflected_id = nullptr;
  char named_shorty[32] = {};
  char reflected_shorty[32] = {};
  size_t needed = 0;
  const int name_status = by_name(
      env, "MakoProbe", "sample", "(I[Ljava/lang/String;D)J", 1,
      &named_id, named_shorty, sizeof(named_shorty), &needed);
  if (name_status != MAKO_OK || named_id == nullptr ||
      std::strcmp(named_shorty, "JILD") != 0 || needed != 5U) {
    return "class/name/signature resolution failed";
  }

  jobject reflected = env->ToReflectedMethod(probe_class, named_id, JNI_TRUE);
  if (env->ExceptionCheck() || reflected == nullptr) {
    return "ToReflectedMethod failed";
  }
  const int reflected_status = by_reflected(
      env, reflected, &reflected_id, reflected_shorty,
      sizeof(reflected_shorty), &needed);
  env->DeleteLocalRef(reflected);
  if (reflected_status != MAKO_OK || reflected_id != named_id ||
      std::strcmp(reflected_shorty, "JILD") != 0 || needed != 5U) {
    return "Method object resolution failed";
  }

  jmethodID string_id = nullptr;
  char string_shorty[8] = {};
  const int string_status = by_name(
      env, "java/lang/String", "valueOf", "(I)Ljava/lang/String;", 1,
      &string_id, string_shorty, sizeof(string_shorty), &needed);
  if (string_status != MAKO_OK || string_id == nullptr ||
      std::strcmp(string_shorty, "LI") != 0 || needed != 3U) {
    return "framework method resolution failed";
  }

  char tiny[2] = {};
  jmethodID tiny_id = nullptr;
  const int small_status = by_name(
      env, "MakoProbe", "sample", "(I[Ljava/lang/String;D)J", 1,
      &tiny_id, tiny, sizeof(tiny), &needed);
  if (small_status != MAKO_ERR_SPACE || needed != 5U ||
      tiny_id != nullptr) return "shorty capacity check failed";
  return nullptr;
}

const char* CheckLateLoad(JNIEnv* env, jclass probe_class, bool inherited) {
  const MakoReflectionSeed* seed = nullptr;
  if (inherited) {
    void* cache = dlopen("/data/local/tmp/libmako-cache.so",
                         RTLD_NOW | RTLD_NOLOAD);
    if (cache == nullptr) return "pre-fork cache image missing";
    auto export_seed = reinterpret_cast<ExportSeed>(
        dlsym(cache, "mako_seed_export"));
    seed = export_seed == nullptr ? nullptr : export_seed();
    dlclose(cache);
    if (seed == nullptr) return "pre-fork cache not prepared";
  }

  void* image = dlopen("/data/local/tmp/libmako.so", RTLD_NOW | RTLD_LOCAL);
  if (image == nullptr) return "late Mako load failed";
  auto ready = reinterpret_cast<Ready>(dlsym(image, "mako_reflection_ready"));
  auto prepare = reinterpret_cast<Prepare>(dlsym(image, "mako_prepare"));
  auto adopt = reinterpret_cast<Adopt>(dlsym(image, "mako_adopt_seed"));
  auto by_name = reinterpret_cast<ResolveName>(
      dlsym(image, "mako_resolve_method"));
  auto by_reflected = reinterpret_cast<ResolveReflected>(
      dlsym(image, "mako_resolve_reflected"));
  if (ready == nullptr || prepare == nullptr || adopt == nullptr ||
      by_name == nullptr || by_reflected == nullptr || ready() != 0) {
    dlclose(image);
    return "Mako was already prepared before the handoff";
  }

  if (inherited) {
    MakoReflectionSeed invalid = *seed;
    invalid.version += 1U;
    if (adopt(env, &invalid) != MAKO_ERR_INVALID || ready() != 0) {
      dlclose(image);
      return "seed ABI rejection failed";
    }
    invalid = *seed;
    invalid.method_class = static_cast<jclass>(env->NewLocalRef(probe_class));
    const int local_status = adopt(env, &invalid);
    env->DeleteLocalRef(invalid.method_class);
    if (local_status != MAKO_ERR_INVALID || ready() != 0) {
      dlclose(image);
      return "non-global class reference accepted";
    }
    if (adopt(env, seed) != MAKO_OK || ready() != 1 ||
        adopt(env, seed) != MAKO_ERR_BUSY) {
      dlclose(image);
      return "seed handoff failed";
    }
  } else if (prepare(env) != MAKO_OK || ready() != 1) {
    dlclose(image);
    return "fallback preparation failed";
  }

  const char* result = CheckResolution(env, probe_class, by_name, by_reflected);
  dlclose(image);
  return result;
}

const char* CheckFork(JNIEnv* env, jclass probe_class) {
  void* premature = dlopen("/data/local/tmp/libmako.so",
                           RTLD_NOW | RTLD_NOLOAD);
  if (premature != nullptr) {
    dlclose(premature);
    return "Mako image was present before fork";
  }
  JavaVM* vm = nullptr;
  if (env->GetJavaVM(&vm) != JNI_OK || vm == nullptr) {
    return "JavaVM lookup failed";
  }
  auto probe_global = static_cast<jclass>(env->NewGlobalRef(probe_class));
  if (env->ExceptionCheck() || probe_global == nullptr) {
    return "probe class global reference failed";
  }
  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) {
    env->DeleteGlobalRef(probe_global);
    return "fork result pipe failed";
  }
  const pid_t child = fork();
  if (child < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    env->DeleteGlobalRef(probe_global);
    return "fork failed";
  }
  if (child == 0) {
    close(pipe_fds[0]);
    alarm(10);
    JNIEnv* child_env = nullptr;
    const char* error = vm->GetEnv(reinterpret_cast<void**>(&child_env),
                                   JNI_VERSION_1_6) == JNI_OK &&
                                child_env != nullptr
                            ? CheckLateLoad(child_env, probe_global, true)
                            : "child JNIEnv unavailable";
    const char* message = error == nullptr ? "PASS" : error;
    (void)write(pipe_fds[1], message, std::strlen(message));
    close(pipe_fds[1]);
    _exit(error == nullptr ? 0 : 1);
  }
  close(pipe_fds[1]);
  env->DeleteGlobalRef(probe_global);
  int status = 0;
  bool done = false;
  for (int i = 0; i < 150; ++i) {
    const pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) {
      done = true;
      break;
    }
    if (waited < 0) break;
    usleep(100000);
  }
  if (!done) {
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    close(pipe_fds[0]);
    return "fork child timed out";
  }
  char message[128] = {};
  const ssize_t count = read(pipe_fds[0], message, sizeof(message) - 1U);
  close(pipe_fds[0]);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || count <= 0 ||
      std::strcmp(message, "PASS") != 0) {
    static char detail[256];
    std::snprintf(detail, sizeof(detail),
                  "fork child failed: exit=%d signal=%d message=%s",
                  WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                  WIFSIGNALED(status) ? WTERMSIG(status) : 0,
                  count > 0 ? message : "(none)");
    return detail;
  }
  return nullptr;
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_MakoProbe_runNative(JNIEnv* env, jclass probe_class, jboolean inherited) {
  if (inherited == JNI_TRUE) {
    const char* error = CheckFork(env, probe_class);
    if (error != nullptr) return Report(env, error);
  }
  const char* error = CheckLateLoad(env, probe_class,
                                    inherited == JNI_TRUE);
  if (error != nullptr) return Report(env, error);
  return Report(env, inherited == JNI_TRUE ? "mako inherited cache: PASS" :
                                         "mako fallback: PASS");
}
