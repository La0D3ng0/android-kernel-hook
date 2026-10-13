// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "mako_reflection_cache.h"

namespace {

int ConsumeJniError(JNIEnv* env) {
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    return MAKO_ERR_JNI;
  }
  return MAKO_OK;
}

}  // namespace

void ReleaseReflectionSeed(JNIEnv* env, MakoReflectionSeed* seed) {
  if (seed->method_class != nullptr) env->DeleteGlobalRef(seed->method_class);
  if (seed->class_class != nullptr) env->DeleteGlobalRef(seed->class_class);
  *seed = {};
}

int BuildReflectionSeed(JNIEnv* env, MakoReflectionSeed* candidate) {
  if (env == nullptr || candidate == nullptr || env->ExceptionCheck()) {
    return MAKO_ERR_INVALID;
  }
  *candidate = {};
  jclass method_local = env->FindClass("java/lang/reflect/Method");
  if (ConsumeJniError(env) != MAKO_OK || method_local == nullptr) {
    if (method_local != nullptr) env->DeleteLocalRef(method_local);
    return MAKO_ERR_JNI;
  }
  jclass class_local = env->FindClass("java/lang/Class");
  if (ConsumeJniError(env) != MAKO_OK || class_local == nullptr) {
    env->DeleteLocalRef(method_local);
    return MAKO_ERR_JNI;
  }
  candidate->get_return_type = env->GetMethodID(
      method_local, "getReturnType", "()Ljava/lang/Class;");
  int status = ConsumeJniError(env);
  if (status == MAKO_OK && candidate->get_return_type != nullptr) {
    candidate->get_parameter_types = env->GetMethodID(
        method_local, "getParameterTypes", "()[Ljava/lang/Class;");
    status = ConsumeJniError(env);
  }
  if (status == MAKO_OK && candidate->get_parameter_types != nullptr) {
    candidate->get_class_name = env->GetMethodID(
        class_local, "getName", "()Ljava/lang/String;");
    status = ConsumeJniError(env);
  }
  if (status == MAKO_OK &&
      (candidate->get_return_type == nullptr ||
       candidate->get_parameter_types == nullptr ||
       candidate->get_class_name == nullptr)) status = MAKO_ERR_JNI;
  if (status == MAKO_OK) {
    candidate->method_class = static_cast<jclass>(env->NewGlobalRef(method_local));
    candidate->class_class = static_cast<jclass>(env->NewGlobalRef(class_local));
    status = ConsumeJniError(env);
    if (candidate->method_class == nullptr || candidate->class_class == nullptr)
      status = MAKO_ERR_JNI;
  }
  env->DeleteLocalRef(method_local);
  env->DeleteLocalRef(class_local);
  if (status != MAKO_OK) {
    ReleaseReflectionSeed(env, candidate);
    return status;
  }
  candidate->version = MAKO_SEED_VERSION;
  candidate->size = sizeof(*candidate);
  candidate->magic = MAKO_SEED_MAGIC;
  return MAKO_OK;
}
