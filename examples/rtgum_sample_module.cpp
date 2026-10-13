#include "rtgum/ghost_api.h"

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi* api) {
    if (!api || api->version != RTGUM_GHOST_API_VERSION) return;
    if (api->log) api->log("sample module entered");
    if (api->status) api->status(RTGUM_DAEMON_STATUS_MODULES, 1);
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi* api) {
    if (api && api->log) api->log("sample module unloaded");
}
