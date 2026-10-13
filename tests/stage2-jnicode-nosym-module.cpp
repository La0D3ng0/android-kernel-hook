/*
 * Stage-2 error module: library is present, requested symbol is not (workflow
 * "runtime error"). Waits until stringFromJNI resolves, then hook_native_symbol
 * on a missing name. extra=227, no handle. No libc.
 */

#include <rtgum/ghost_api.h>

namespace {

GhostApi *g_api = nullptr;
const HostApiV2 *g_host = nullptr;
unsigned long g_jni_handle = 0;

unsigned long UnusedReplacement(void *env, unsigned long thiz)
{
    (void)env;
    (void)thiz;
    return 0;
}

void InstallWhenLoaded(void *)
{
    if (!g_host || !g_host->wait_export || !g_host->hook_native_symbol) return;
    unsigned long mapped = 0;
    const long waited = g_host->wait_export("libjnicode.so", RTGUM_JNI_STRING_FROM_JNI,
                                            RTGUM_HOST_WAIT_EXPORT_DEFAULT_MS, &mapped);
    if (waited != 0 || mapped == 0) {
        if (g_api && g_api->status)
            g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_LOOKUP_FAILED);
        if (g_api && g_api->log) g_api->log("rtgum-jnicode-nosym: lib never mapped");
        return;
    }

    unsigned long original = 0;
    unsigned long handle = 0;
    const long rc = g_host->hook_native_symbol(
        "libjnicode.so", RTGUM_JNI_MISSING_SYMBOL,
        reinterpret_cast<unsigned long>(UnusedReplacement), &original, &handle);
    if (rc == 0 && handle != 0) {
        if (g_host->hook_native_revert) (void)g_host->hook_native_revert(handle);
        if (g_api && g_api->status)
            g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_NATIVE_REPLACE_FAILED);
        if (g_api && g_api->log)
            g_api->log("rtgum-jnicode-nosym: missing symbol unexpectedly resolved");
        return;
    }
    g_jni_handle = 0;
    if (g_api && g_api->status)
        g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_LOOKUP_FAILED);
    if (g_api && g_api->log) g_api->log("rtgum-jnicode-nosym: symbol missing");
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION) return;
    g_api = api;
    if (!api->host || api->host->version != RTGUM_HOST_API_V2_VERSION ||
        api->host->size < sizeof(HostApiV2) || api->host->hook_native_symbol == nullptr ||
        api->host->wait_export == nullptr ||
        (api->host->capabilities & (RTGUM_HOST_CAP_NATIVE_SYMBOL | RTGUM_HOST_CAP_WAIT_EXPORT |
                                    RTGUM_HOST_CAP_DEFER)) !=
            (RTGUM_HOST_CAP_NATIVE_SYMBOL | RTGUM_HOST_CAP_WAIT_EXPORT | RTGUM_HOST_CAP_DEFER)) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_HOST_UNAVAILABLE);
        api->log("rtgum-jnicode-nosym: host v2 unavailable");
        return;
    }
    g_host = api->host;
    if (g_host->defer(InstallWhenLoaded, nullptr) != 0) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_DEFER_FAILED);
        api->log("rtgum-jnicode-nosym: defer failed");
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_POLL_ARMED);
    api->log("rtgum-jnicode-nosym: poll armed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (g_host && g_host->hook_native_revert && g_jni_handle != 0) {
        (void)g_host->hook_native_revert(g_jni_handle);
        g_jni_handle = 0;
    }
    if (api && api->log) api->log("rtgum-jnicode-nosym: unload");
}
