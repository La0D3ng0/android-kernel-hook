/* End-to-end acceptance module for the Daemon ELF resolver. */

#include <rtgum/ghost_api.h>

#include <stddef.h>

namespace {

GhostApi *g_api = nullptr;

bool host_has_symbol_api(const HostApiV2 *host)
{
    return host && host->version == RTGUM_HOST_API_V2_VERSION &&
           host->size >= offsetof(HostApiV2, symbolize_batch) +
                             sizeof(host->symbolize_batch) &&
           (host->capabilities & RTGUM_HOST_CAP_SYMBOL_RESOLVER) != 0UL &&
           host->find_export && host->wait_export && host->symbolize_pc &&
           host->symbolize_batch;
}

void fail(const char *message)
{
    if (!g_api) return;
    g_api->log(message);
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                  RTGUM_MODULE_EXTRA_SYMBOLS_FAILED);
}

void symbol_job(void *)
{
    const HostApiV2 *host = g_api ? g_api->host : nullptr;
    if (!host_has_symbol_api(host)) {
        fail("rtgum-symbol: host symbol api unavailable");
        return;
    }

    unsigned long libc_open = 0;
    if (host->find_export("libc.so", "open", &libc_open) != 0 ||
        libc_open == 0) {
        fail("rtgum-symbol: libc.so!open failed");
        return;
    }
    g_api->log("rtgum-symbol: libc.so!open resolved");

    /* This function is LOCAL in .symtab and absent from .dynsym.  Resolving
     * it proves the VMA-less image path uses the original ELF/full table
     * cache rather than the private linker's dynamic export lookup. */
    unsigned long ghost_probe = 0;
    if (host->find_export("rtgum-stage2-symbol.ghm",
                          "ghost_symbol_probe",
                          &ghost_probe) != 0 ||
        ghost_probe == 0) {
        fail("rtgum-symbol: ghost full symtab failed");
        return;
    }
    g_api->log("rtgum-symbol: ghost .symtab resolved");

    unsigned long lab_add = 0;
    if (host->wait_export("libghostlab.so", "lab_add",
                          RTGUM_HOST_WAIT_EXPORT_DEFAULT_MS,
                          &lab_add) != 0 ||
        lab_add == 0) {
        fail("rtgum-symbol: libghostlab.so!lab_add failed");
        return;
    }

    /* __on_dlclose is a local crt symbol in the Lab ELF and is intentionally
     * absent from .dynsym.  This exercises the mapped-image miss -> disk
     * .symtab fallback independently of the VMA-less ghost-image path above. */
    unsigned long lab_internal = 0;
    if (host->find_export("libghostlab.so", "__on_dlclose",
                          &lab_internal) != 0 ||
        lab_internal == 0) {
        fail("rtgum-symbol: disk full symtab fallback failed");
        return;
    }
    g_api->log("rtgum-symbol: disk .symtab fallback resolved");

    char rendered[320];
    if (host->symbolize_pc(lab_add, rendered, sizeof(rendered)) != 0) {
        fail("rtgum-symbol: trace symbolize failed");
        return;
    }
    g_api->log(rendered);

    unsigned long pcs[2] = {lab_add, ghost_probe};
    char batch[700];
    if (host->symbolize_batch(pcs, 2, batch, sizeof(batch)) != 0) {
        fail("rtgum-symbol: batch symbolize failed");
        return;
    }
    g_api->log("rtgum-symbol: batch trace map ready");

    unsigned long missing = ~0UL;
    const long missing_status =
        host->find_export("libghostlab.so", "definitely_missing_symbol", &missing);
    if (missing_status != RTGUM_HOST_ERR_NOENT || missing != 0) {
        fail("rtgum-symbol: missing symbol contract failed");
        return;
    }
    char missing_text[64];
    const long missing_pc = host->symbolize_pc(1UL, missing_text,
                                               sizeof(missing_text));
    if (missing_pc != RTGUM_HOST_ERR_NOENT ||
        missing_text[0] != 's' || missing_text[1] != 'y') {
        fail("rtgum-symbol: missing PC contract failed");
        return;
    }
    /* Keep the decisive evidence adjacent in the bounded kernel log.  A cold
     * resolver may perform hundreds of page-table reads before reaching this
     * point, so the earlier progress messages are diagnostics only. */
    g_api->log("rtgum-symbol: libc.so!open resolved");
    g_api->log("rtgum-symbol: ghost .symtab resolved");
    g_api->log("rtgum-symbol: disk .symtab fallback resolved");
    g_api->log(rendered);
    g_api->log("rtgum-symbol: symbol not found");
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                  RTGUM_MODULE_EXTRA_SYMBOLS_READY);
    g_api->log("rtgum-symbol: PASS");
}

} // namespace

/* Kept local intentionally; `used` retains it in .symtab while hidden
 * visibility keeps it out of .dynsym. */
extern "C" __attribute__((used, noinline, visibility("hidden")))
unsigned long ghost_symbol_probe(unsigned long value)
{
    return value ^ 0x53594d42UL;
}

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION || !api->host) return;
    g_api = api;
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 0);
    if (!host_has_symbol_api(api->host) || !api->host->defer ||
        api->host->defer(symbol_job, nullptr) != 0) {
        fail("rtgum-symbol: defer failed");
    }
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (api) api->log("rtgum-symbol: unload");
    g_api = nullptr;
}
