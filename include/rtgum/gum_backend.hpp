#pragma once

#include <memory>

#include "rtgum/component.hpp"
#include "rtgum/host_api_v2.h"

namespace rtgum {

// This adapter only owns Gum's embedded lifecycle. Hook APIs are intentionally
// kept out of the first milestone so activation remains explicit and auditable.
std::unique_ptr<Component> CreateGumBackend();

// Adds a read-only Gum export lookup to a host table while Gum is running.
// Calls made after the last GumBackend stops return RTGUM_HOST_ERR_NXIO.
Status BindGumReadOnlyHostApi(HostApiV2* host);

}  // namespace rtgum
