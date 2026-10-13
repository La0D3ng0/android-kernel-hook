// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

// Stable umbrella header for the native migration. Individual headers remain
// available for users who want a smaller include surface.
#include "art_hook/arm64_trampoline.h"
#include "art_hook/art_deoptimization.h"
#include "art_hook/art_entrypoint.h"
#include "art_hook/art_flags.h"
#include "art_hook/art_method.h"
#include "art_hook/art_quick_hook.h"
#include "art_hook/class_factory.h"
#include "art_hook/class_model.h"
#include "art_hook/code_allocator.h"
#include "art_hook/dex.h"
#include "art_hook/gum_interceptor.h"
#include "art_hook/hotspot_method.h"
#include "art_hook/instruction_scan.h"
#include "art_hook/java_proxy.h"
#include "art_hook/jni_result.h"
#include "art_hook/jni_types.h"
#include "art_hook/jvmti.h"
#include "art_hook/lru.h"
#include "art_hook/lsplant_arm64_bridge.h"
#include "art_hook/memoize.h"
#include "art_hook/runtime_api.h"
#include "art_hook/status.h"
#include "art_hook/vm.h"

#if defined(ART_HOOK_HAS_LSPLANT)
#include "art_hook/lsplant_backend.h"
#endif
