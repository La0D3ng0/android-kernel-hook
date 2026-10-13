/*
 * Stage-2 user module for the ART acceptance fixture (dev.rtgum.lab).
 *
 * It hooks LabTarget.add(II)I and makes it return 42. That is the behavioural
 * half of the acceptance criterion, and it is what the lab's ArtMethod
 * self-check needs in order to be able to conclude anything at all: a scanner
 * that still reads the original entry point is only meaningful while a hook on
 * that very method is known to be live.
 *
 * No libc. The Daemon lazily loads libmako-ghost.so from the KPM cache on the
 * first artHook call, so this module only ever touches the HostApiV2 surface.
 *
 * Installation publishes an ARMED marker. The status changes to 42 only from
 * the first real leave callback, so a device-side poller cannot mistake a
 * patched ArtMethod for an invocation that never happened.
 */

#include <rtgum/ghost_api.h>

namespace {

GhostApi *g_api = nullptr;
const HostApiV2 *g_host = nullptr;
unsigned long g_handle = 0;
volatile unsigned long g_calls = 0;

bool CmdlineReady()
{
    if (!g_api || !g_api->cmdline) return false;
    char cmdline[256];
    cmdline[0] = '\0';
    /* Any app process: the Daemon only dispatches us into the configured
     * package, so a non-empty cmdline means the app is up and its classes can
     * be resolved. */
    return g_api->cmdline(cmdline, sizeof(cmdline)) > 0;
}

void OnEnter(void *, void *) {}

/* At an ART quick entry x0 is ArtMethod*. For this static method the two int
 * arguments therefore arrive in x1/x2; the result still returns in x0, so the
 * leave callback writes x[0]. */
void OnLeave(void *context, void *)
{
    if (context == nullptr) return;
    auto *regs = static_cast<unsigned long *>(context);
    regs[0] = static_cast<unsigned long>(RTGUM_LAB_HOOK_RESULT);
    const unsigned long count = __atomic_add_fetch(&g_calls, 1UL, __ATOMIC_RELAXED);
    if (count == 1UL && g_api && g_api->status)
        g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                      RTGUM_LAB_MODULE_EXTRA_HOOKED);
    if (count <= 4UL && g_api && g_api->log)
        g_api->log("rtgum-lab-mako: add() rewritten to 42");
}

void InstallWhenReady(void *)
{
    if (!g_host || !g_host->art_hook_method_ex || !g_host->wait_export) return;
    for (unsigned int attempt = 0; attempt < 5000U; ++attempt) {
        if (CmdlineReady()) break;
        if (g_host->sleep_ms) g_host->sleep_ms(2U);
    }
    if (g_api && g_api->log) g_api->log("rtgum-lab-mako: cmdline ready");

    /* The baseline is evidence only when it predates the hook. Wait for the
     * Lab's native fixture to publish the hard gate after both methods have
     * been sampled; a status flag that merely reports a race afterwards cannot
     * make an already-raced baseline valid. */
    unsigned long ready_address = 0;
    const long ready_rc = g_host->wait_export(
        "libghostlab.so", "rtgum_lab_baseline_ready",
        RTGUM_HOST_WAIT_EXPORT_DEFAULT_MS, &ready_address);
    if (ready_rc != 0 || ready_address == 0) {
        if (g_api && g_api->log) g_api->log("rtgum-lab-mako: baseline gate missing");
        if (g_api && g_api->status)
            g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                          RTGUM_LAB_MODULE_EXTRA_HOOK_FAILED);
        return;
    }
    using BaselineReady = unsigned long (*)();
    auto baseline_ready = reinterpret_cast<BaselineReady>(ready_address);
    bool ready = false;
    for (unsigned int attempt = 0; attempt < 4000U; ++attempt) {
        if (baseline_ready() == 1UL) {
            ready = true;
            break;
        }
        if (g_host->sleep_ms) g_host->sleep_ms(2U);
    }
    if (!ready) {
        if (g_api && g_api->log) g_api->log("rtgum-lab-mako: baseline gate timeout");
        if (g_api && g_api->status)
            g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                          RTGUM_LAB_MODULE_EXTRA_HOOK_FAILED);
        return;
    }
    if (g_api && g_api->log) g_api->log("rtgum-lab-mako: baseline ready");

    for (unsigned int attempt = 0; attempt < 8000U; ++attempt) {
        unsigned long handle = 0;
        const long rc = g_host->art_hook_method_ex(
            nullptr, RTGUM_LAB_MODULE_CLASS, RTGUM_LAB_MODULE_METHOD,
            RTGUM_LAB_MODULE_SIGNATURE, RTGUM_ART_METHOD_STATIC,
            OnEnter, OnLeave, nullptr, &handle);
        if (rc == 0 && handle != 0) {
            /* Exercise two incremental patches on the same ArtMethod page,
             * then remove only the control method. The primary add() patch
             * must remain active and untouched() is genuinely unhooked by the
             * time the UI performs its acceptance calls. */
            unsigned long same_page = 0;
            const long same_page_rc = g_host->art_hook_method_ex(
                nullptr, RTGUM_LAB_MODULE_CLASS, "untouched",
                RTGUM_LAB_MODULE_SIGNATURE, RTGUM_ART_METHOD_STATIC,
                nullptr, nullptr, nullptr, &same_page);
            const long same_page_revert =
                same_page_rc == 0 && same_page != 0
                    ? g_host->art_hook_revert(same_page)
                    : RTGUM_HOST_ERR_BUSY;
            if (same_page_rc != 0 || same_page == 0 || same_page_revert != 0) {
                (void)g_host->art_hook_revert(handle);
                if (g_api && g_api->status)
                    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                                  RTGUM_LAB_MODULE_EXTRA_HOOK_FAILED);
                if (g_api && g_api->log)
                    g_api->log("rtgum-lab-mako: same-page patch lifecycle failed");
                return;
            }
            /* Teardown hardening acceptance: the backend must reject a second
             * state for the same ArtMethod and must reject an invented handle
             * without dereferencing it. Both used to corrupt the incremental
             * page patch or crash the process, respectively. */
            unsigned long duplicate = 0;
            const long duplicate_rc = g_host->art_hook_method_ex(
                nullptr, RTGUM_LAB_MODULE_CLASS, RTGUM_LAB_MODULE_METHOD,
                RTGUM_LAB_MODULE_SIGNATURE, RTGUM_ART_METHOD_STATIC,
                OnEnter, OnLeave, nullptr, &duplicate);
            unsigned int invalid_state = 0;
            const long invalid_rc = g_host->art_hook_status != nullptr
                ? g_host->art_hook_status(0x1234UL, &invalid_state)
                : 0;
            if (duplicate_rc != RTGUM_HOST_ERR_BUSY || duplicate != 0 ||
                invalid_rc >= 0) {
                (void)g_host->art_hook_revert(handle);
                if (g_api && g_api->status)
                    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                                  RTGUM_LAB_MODULE_EXTRA_HOOK_FAILED);
                if (g_api && g_api->log)
                    g_api->log("rtgum-lab-mako: handle hardening check failed");
                return;
            }
            g_handle = handle;
            if (g_api && g_api->status)
                g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                              RTGUM_LAB_MODULE_EXTRA_HOOK_ARMED);
            if (g_api && g_api->log)
                g_api->log("rtgum-lab-mako: page and handle hardening pass");
            return;
        }
        if (rc != RTGUM_HOST_ERR_NOENT && rc != RTGUM_HOST_ERR_BUSY) {
            /* Report the error code itself, not just "failed": 0x2000|code is
             * what the poller prints, and the low 12 bits identify the cause. */
            if (g_api && g_api->status)
                g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                              RTGUM_LAB_MODULE_EXTRA_HOOK_FAILED);
            if (g_api && g_api->log)
                g_api->log("rtgum-lab-mako: art_hook_method failed");
            return;
        }
        if (g_host->sleep_ms) g_host->sleep_ms(5U);
    }
    if (g_api && g_api->status)
        g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_LAB_MODULE_EXTRA_HOOK_FAILED);
    if (g_api && g_api->log) g_api->log("rtgum-lab-mako: hook retries exhausted");
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION) return;
    g_api = api;
    if (!api->host || api->host->version != RTGUM_HOST_API_V2_VERSION ||
        api->host->size < sizeof(HostApiV2) ||
        (api->host->capabilities &
         (RTGUM_HOST_CAP_ART_MAKO | RTGUM_HOST_CAP_DEFER |
          RTGUM_HOST_CAP_WAIT_EXPORT | RTGUM_HOST_CAP_ART_METHOD_FLAGS)) !=
            (RTGUM_HOST_CAP_ART_MAKO | RTGUM_HOST_CAP_DEFER |
             RTGUM_HOST_CAP_WAIT_EXPORT | RTGUM_HOST_CAP_ART_METHOD_FLAGS) ||
        api->host->art_hook_method_ex == nullptr ||
        api->host->wait_export == nullptr) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_HOST_UNAVAILABLE);
        api->log("rtgum-lab-mako: host art hook unavailable");
        return;
    }
    g_host = api->host;
    if (g_host->defer(InstallWhenReady, nullptr) != 0) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_DEFER_FAILED);
        api->log("rtgum-lab-mako: defer failed");
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_POLL_ARMED);
    api->log("rtgum-lab-mako: poll armed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (g_host && g_host->art_hook_revert && g_handle != 0) {
        (void)g_host->art_hook_revert(g_handle);
        g_handle = 0;
    }
    if (api && api->log) api->log("rtgum-lab-mako: unload");
}
