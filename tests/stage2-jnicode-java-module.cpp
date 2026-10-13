/*
 * Stage-2 user module: rewrite JNICode MainActivity.onCreate via HostApiV2.
 * No libc. JAVA_HOOK is provided by the Daemon; LSPlant lives in a system-
 * loaded helper SO, not in this ghost image.
 */

#include <rtgum/ghost_api.h>

namespace {

GhostApi *g_api = nullptr;
const HostApiV2 *g_host = nullptr;
unsigned long g_java_handle = 0;

bool CmdlineEquals(const char *left, const char *right)
{
    if (!left || !right) return false;
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

bool PackageCmdlineReady()
{
    if (!g_api || !g_api->cmdline) return false;
    char cmdline[256];
    cmdline[0] = '\0';
    const long length = g_api->cmdline(cmdline, sizeof(cmdline));
    return length > 0 && CmdlineEquals(cmdline, "com.laodeng.jnicode");
}

void InstallWhenReady(void *)
{
    if (!g_host || !g_host->hook_java_method) return;
    for (unsigned int attempt = 0; attempt < 5000U; ++attempt) {
        if (PackageCmdlineReady()) break;
        if (g_host->sleep_ms) g_host->sleep_ms(2U);
    }
    if (g_api && g_api->log) g_api->log("rtgum-jnicode-java: cmdline ready");
    for (unsigned int attempt = 0; attempt < 8000U; ++attempt) {
        unsigned long handle = 0;
        const long rc = g_host->hook_java_method(nullptr, RTGUM_JAVA_MAIN_CLASS,
                                                 RTGUM_JAVA_ONCREATE_NAME,
                                                 RTGUM_JAVA_ONCREATE_SIG, &handle);
        if (rc == 0 && handle != 0) {
            g_java_handle = handle;
            if (g_api && g_api->status) g_api->status(RTGUM_DAEMON_STATUS_EXTRA, 4UL);
            if (g_api && g_api->log) g_api->log("rtgum-jnicode-java: onCreate replaced");
            return;
        }
        if (rc != RTGUM_HOST_ERR_NOENT && rc != RTGUM_HOST_ERR_BUSY) {
            if (g_api && g_api->status)
                g_api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xE2UL);
            if (g_api && g_api->log) g_api->log("rtgum-jnicode-java: replace failed");
            return;
        }
        if (g_host->sleep_ms) g_host->sleep_ms(5U);
    }
    if (g_api && g_api->status) g_api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xE3UL);
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION) return;
    g_api = api;
    if (!api->host || api->host->version != RTGUM_HOST_API_V2_VERSION ||
        api->host->size < sizeof(HostApiV2) ||
        (api->host->capabilities & (RTGUM_HOST_CAP_JAVA_HOOK | RTGUM_HOST_CAP_DEFER)) !=
            (RTGUM_HOST_CAP_JAVA_HOOK | RTGUM_HOST_CAP_DEFER) ||
        api->host->hook_java_method == nullptr) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xE0UL);
        api->log("rtgum-jnicode-java: host java unavailable");
        return;
    }
    g_host = api->host;
    if (g_host->defer(InstallWhenReady, nullptr) != 0) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xE1UL);
        api->log("rtgum-jnicode-java: defer failed");
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 3UL);
    api->log("rtgum-jnicode-java: poll armed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (g_host && g_host->hook_java_revert && g_java_handle != 0) {
        (void)g_host->hook_java_revert(g_java_handle);
        g_java_handle = 0;
    }
    if (api && api->log) api->log("rtgum-jnicode-java: unload");
}
