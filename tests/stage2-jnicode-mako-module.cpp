/*
 * Stage-2 user module: stealth Mako ART hook on JNICode MainActivity.onCreate.
 * No libc. The Daemon lazily loads libmako-ghost.so from the KPM cache on the
 * first artHook call; this module only exercises the HostApiV2 art_hook_*
 * surface. The hook itself is transparent (callbacks count invocations), and
 * the Shadow Data Page scheme is verified in-band by mako's scanner-view
 * self-check, so the test asserts status words and KPM shadow counters rather
 * than a rewritten UI.
 */

#include <rtgum/ghost_api.h>

namespace {

GhostApi *g_api = nullptr;
const HostApiV2 *g_host = nullptr;
unsigned long g_mako_handle = 0;
volatile unsigned long g_enter_count = 0;

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
    /* Any app process: the daemon only dispatches us into the configured
     * target package, so a non-empty cmdline means the app is up. */
    return length > 0;
}

void OnEnter(void *, void *)
{
    const unsigned long count =
        __atomic_add_fetch(&g_enter_count, 1UL, __ATOMIC_RELAXED);
    /* Stable marker for the scenario poller; the log carries the count. */
    if (g_api && g_api->status)
        g_api->status(RTGUM_DAEMON_STATUS_EXTRA, 0x101UL);
    if (g_api && g_api->log && count <= 8UL)
        g_api->log("rtgum-jnicode-mako: onCreate enter");
}

void OnLeave(void *, void *) {}

void InstallWhenReady(void *)
{
    if (!g_host || !g_host->art_hook_activity_create) return;
    for (unsigned int attempt = 0; attempt < 5000U; ++attempt) {
        if (PackageCmdlineReady()) break;
        if (g_host->sleep_ms) g_host->sleep_ms(2U);
    }
    if (g_api && g_api->log) g_api->log("rtgum-jnicode-mako: cmdline ready");
    for (unsigned int attempt = 0; attempt < 8000U; ++attempt) {
        unsigned long handle = 0;
        /* "*" hooks the bootstrap Activity.onCreate base method. This avoids
         * converting a raw quick-ABI managed receiver into a JNI jobject. */
        const long rc = g_host->art_hook_activity_create(
            nullptr, "*", OnEnter, OnLeave, nullptr, &handle);
        if (rc == 0 && handle != 0) {
            g_mako_handle = handle;
            if (g_api && g_api->status) g_api->status(RTGUM_DAEMON_STATUS_EXTRA, 4UL);
            if (g_api && g_api->log) g_api->log("rtgum-jnicode-mako: onCreate mako-hooked");
            return;
        }
        if (rc != RTGUM_HOST_ERR_NOENT && rc != RTGUM_HOST_ERR_BUSY) {
            if (g_api && g_api->status)
                g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                              0x2000UL + (static_cast<unsigned long>(-rc) & 0xFFFUL));
            if (g_api && g_api->log) g_api->log("rtgum-jnicode-mako: art hook failed");
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
        (api->host->capabilities & (RTGUM_HOST_CAP_ART_MAKO | RTGUM_HOST_CAP_DEFER)) !=
            (RTGUM_HOST_CAP_ART_MAKO | RTGUM_HOST_CAP_DEFER) ||
        api->host->art_hook_method == nullptr) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xE0UL);
        api->log("rtgum-jnicode-mako: host art hook unavailable");
        return;
    }
    g_host = api->host;
    if (g_host->defer(InstallWhenReady, nullptr) != 0) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, 0xE1UL);
        api->log("rtgum-jnicode-mako: defer failed");
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 3UL);
    api->log("rtgum-jnicode-mako: poll armed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (g_host && g_host->art_hook_revert && g_mako_handle != 0) {
        (void)g_host->art_hook_revert(g_mako_handle);
        g_mako_handle = 0;
    }
    if (api && api->log) api->log("rtgum-jnicode-mako: unload");
}
