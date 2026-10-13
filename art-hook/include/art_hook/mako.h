// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  MAKO_OK = 0,
  MAKO_ERR_INVALID = -22,
  MAKO_ERR_NOT_FOUND = -2,
  MAKO_ERR_JNI = -14,
  MAKO_ERR_BUSY = -16,
  MAKO_ERR_SPACE = -28,
};

struct MakoReflectionSeed;

// Initialize the fallback cache in this process. A caller that inherited a
// prepared seed should call mako_adopt_seed first instead. Resolution calls
// mako_prepare on first use if no seed was adopted.
int mako_prepare(JNIEnv* env);
// Clone the inherited global class references and reuse its method IDs.
// The seed must come from mako_seed_export in the same fork lineage.
int mako_adopt_seed(JNIEnv* env, const struct MakoReflectionSeed* seed);
int mako_reflection_ready(void);

// Both routes return a JNI method ID and a reflection-derived shorty. A
// jmethodID may be opaque: neither function treats it as an ArtMethod address.
// needed receives the required shorty buffer size including the terminator.
int mako_resolve_method(JNIEnv* env, const char* class_name,
                        const char* method_name, const char* signature,
                        int is_static, jmethodID* method_id, char* shorty,
                        size_t capacity, size_t* needed);
int mako_resolve_reflected(JNIEnv* env, jobject method,
                           jmethodID* method_id, char* shorty,
                           size_t capacity, size_t* needed);

const char* mako_build_id(void);

#ifdef __cplusplus
}
#endif
