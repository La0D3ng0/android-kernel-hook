// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <jni.h>
#include <stdint.h>

#include "art_hook/mako.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAKO_SEED_VERSION 1U
#define MAKO_SEED_MAGIC UINT64_C(0x4d414b4f53454544)

// Process-local JNI handles. Copy only across a fork of the same JavaVM;
// never serialize this structure or pass it between unrelated processes.
typedef struct MakoReflectionSeed {
  uint32_t version;
  uint32_t size;
  uint64_t magic;
  jclass method_class;
  jclass class_class;
  jmethodID get_return_type;
  jmethodID get_parameter_types;
  jmethodID get_class_name;
} MakoReflectionSeed;

int mako_seed_prepare(JNIEnv* env);
const MakoReflectionSeed* mako_seed_export(void);
int mako_seed_ready(void);

#ifdef __cplusplus
}
#endif
