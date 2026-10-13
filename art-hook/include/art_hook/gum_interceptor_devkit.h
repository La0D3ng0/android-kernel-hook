// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include "art_hook/gum_interceptor.h"

namespace art_hook {

// Available when art_hook_core is built with ART_HOOK_WITH_FRIDA_GUM=ON.
[[nodiscard]] GumInterceptorApi MakeFridaGumInterceptorApi() noexcept;

} // namespace art_hook
