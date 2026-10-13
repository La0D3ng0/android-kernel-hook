/*
 * Stage-2 error module: GhostApi/HostApi version mismatch (workflow "syntax
 * error"). Sets extra=224 and never installs a hook. No libc.
 */

#include <rtgum/ghost_api.h>

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api) return;
    if (api->status)
        api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_HOST_UNAVAILABLE);
    if (api->log) api->log("rtgum-jnicode-badver: host version rejected");
    if (!api->host || api->host->version == 99UL) {
        /* Unreachable on a v2 Daemon; keeps the required-version check visible. */
        if (api->log) api->log("rtgum-jnicode-badver: unexpected host v99");
    }
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (api && api->log) api->log("rtgum-jnicode-badver: unload");
}
