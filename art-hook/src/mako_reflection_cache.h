// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include "art_hook/mako_seed.h"

int BuildReflectionSeed(JNIEnv* env, MakoReflectionSeed* candidate);
void ReleaseReflectionSeed(JNIEnv* env, MakoReflectionSeed* seed);
