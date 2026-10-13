/*
 * Stage-2 user module: rewrite the owned JNICode APK native export.
 * No libc. HostApiV2 hook_native_symbol is the 无痕 shadowHook shape:
 * soname + symbol + replacement + original.
 */

#include <rtgum/ghost_api.h>

namespace {

GhostApi *g_api = nullptr;
const HostApiV2 *g_host = nullptr;
unsigned long g_jni_original = 0;
unsigned long g_jni_handle = 0;

bool Contains(const char *text, const char *needle)
{
    if (!text || !needle || *needle == '\0') return false;
    for (; *text != '\0'; ++text) {
        const char *left = text;
        const char *right = needle;
        while (*left != '\0' && *right != '\0' && *left == *right) {
            ++left;
            ++right;
        }
        if (*right == '\0') return true;
    }
    return false;
}

unsigned long HookedStringFromJni(void *env, unsigned long thiz)
{
    using Original = unsigned long (*)(void *, unsigned long);
    if (g_jni_original != 0) {
        (void)reinterpret_cast<Original>(g_jni_original)(env, thiz);
    }
    if (!env) return 0;
    void **table = *reinterpret_cast<void ***>(env);
    using NewStringUTFFn = unsigned long (*)(void *, const char *);
    auto *new_string_utf =
        reinterpret_cast<NewStringUTFFn>(table[RTGUM_JNI_NEW_STRING_UTF_INDEX]);
    return new_string_utf(env, RTGUM_JNI_REPLACEMENT_TEXT);
}

void InstallWhenLoaded(void *)
{
    if (!g_host || !g_host->wait_export || !g_host->hook_native_symbol) return;
    unsigned long target = 0;
    const long waited = g_host->wait_export("libjnicode.so", RTGUM_JNI_STRING_FROM_JNI,
                                            RTGUM_HOST_WAIT_EXPORT_DEFAULT_MS, &target);
    if (waited != 0 || target == 0) {
        if (g_api && g_api->status)
            g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_LOOKUP_FAILED);
        if (g_api && g_api->log) g_api->log("rtgum-jnicode-module: export wait failed");
        return;
    }
    unsigned long original = 0;
    unsigned long handle = 0;
    const long rc = g_host->hook_native_symbol(
        "libjnicode.so", RTGUM_JNI_STRING_FROM_JNI,
        reinterpret_cast<unsigned long>(HookedStringFromJni), &original, &handle);
    if (rc == 0 && handle != 0) {
        g_jni_original = original;
        g_jni_handle = handle;
        if (g_api && g_api->status)
            g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_REPLACED);
        if (g_api && g_api->log) g_api->log("rtgum-jnicode-module: jni replaced");
        return;
    }
    if (g_api && g_api->status)
        g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_NATIVE_REPLACE_FAILED);
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION) return;
    g_api = api;
    if (!api->host || api->host->version != RTGUM_HOST_API_V2_VERSION ||
        api->host->size < sizeof(HostApiV2) || api->host->hook_native_symbol == nullptr ||
        api->host->wait_export == nullptr ||
        (api->host->capabilities & (RTGUM_HOST_CAP_NATIVE_SYMBOL | RTGUM_HOST_CAP_DEFER |
                                    RTGUM_HOST_CAP_WAIT_EXPORT)) !=
            (RTGUM_HOST_CAP_NATIVE_SYMBOL | RTGUM_HOST_CAP_DEFER | RTGUM_HOST_CAP_WAIT_EXPORT)) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_HOST_UNAVAILABLE);
        api->log("rtgum-jnicode-module: host v2 unavailable");
        return;
    }
    g_host = api->host;
    (void)Contains; /* keep helper for future path filters */
    if (g_host->defer(InstallWhenLoaded, nullptr) != 0) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_DEFER_FAILED);
        api->log("rtgum-jnicode-module: defer failed");
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_POLL_ARMED);
    api->log("rtgum-jnicode-module: poll armed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (g_host && g_host->hook_native_revert && g_jni_handle != 0) {
        (void)g_host->hook_native_revert(g_jni_handle);
        g_jni_handle = 0;
        g_jni_original = 0;
    }
    if (api && api->log) api->log("rtgum-jnicode-module: unload");
}
