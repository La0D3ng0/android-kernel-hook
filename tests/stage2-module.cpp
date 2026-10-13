/*
 * rt-gum-sdk stage-2 user module (.ghm) — module version 1.
 *
 * User modules only include the declaration-only GhostApi header; the Daemon
 * passes a ready-made GhostApi* when it calls ghostEntry. This module has no
 * libc dependency: all services (logging, ghost memory) come from GhostApi.
 */

#include <rtgum/ghost_api.h>

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION) return;

    api->log("rtgum-stage2-module: ghostEntry");
    unsigned long address = 0;
    const long result = api->ghost_alloc(4096, 3 /* Read | Write */, &address);
    if (result != 0 || address == 0) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xEEUL);
        return;
    }
    *reinterpret_cast<volatile unsigned long *>(address) = 0x47484d31UL; /* "GHM1" */
    if (api->ghost_protect(address, 5U) != 0) { /* RW → RX */
        api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xEDUL);
        (void)api->ghost_free(address);
        return;
    }
    if (api->ghost_free(address) != 0) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xEFUL);
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 1UL);
    api->log("rtgum-stage2-module: ghost alloc roundtrip ok");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (!api) return;
    api->log("rtgum-stage2-module: unload");
}
