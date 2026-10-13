/* In-process GTrace acceptance module.
 *
 * The Lab fixture contains an actual `br x16` over three deliberately invalid
 * words.  Gum Stalker executes on this deferred worker thread, so its callouts
 * are emitted only for instructions which really run.  The shared formatter
 * then turns those records into path/edge/gap events for automation.
 */

#include <rtgum/ghost_api.h>
#include <rtgum/gum_api.h>

#include <stddef.h>

namespace {

constexpr unsigned long kPathCapacity = 64UL;
constexpr unsigned long kTextCapacity = 8192UL;

GhostApi *g_api = nullptr;
RtGumGtraceStep g_steps[kPathCapacity];
char g_text[kTextCapacity];

bool Contains(const char *text, const char *needle)
{
    if (!text || !needle || *needle == '\0') return false;
    for (unsigned long at = 0UL; text[at] != '\0'; ++at) {
        unsigned long index = 0UL;
        while (needle[index] != '\0' && text[at + index] == needle[index]) ++index;
        if (needle[index] == '\0') return true;
    }
    return false;
}

void Fail(const char *message)
{
    if (!g_api) return;
    g_api->log(message);
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                  RTGUM_MODULE_EXTRA_GTRACE_FAILED);
}

void LogLines(const char *text)
{
    if (!g_api || !text) return;
    char line[224];
    unsigned long used = 0UL;
    for (unsigned long index = 0UL;; ++index) {
        const char ch = text[index];
        if (ch == '\n' || ch == '\0') {
            if (used != 0UL) {
                line[used] = '\0';
                g_api->log(line);
                used = 0UL;
            }
            if (ch == '\0') break;
            continue;
        }
        if (used + 1UL >= sizeof(line)) {
            Fail("rtgum-gtrace: formatter line exceeds log transport");
            return;
        }
        line[used++] = ch;
    }
}

bool HostReady(const HostApiV2 *host)
{
    return host && host->version == RTGUM_HOST_API_V2_VERSION &&
           host->size >= offsetof(HostApiV2, gtrace_format_path) +
                             sizeof(host->gtrace_format_path) &&
           (host->capabilities & RTGUM_HOST_CAP_GTRACE_RUNTIME) != 0UL &&
           (host->capabilities & RTGUM_HOST_CAP_DBI_STALKER_BTI_CHECKED) != 0UL &&
           host->wait_export && host->defer && host->dbi_stalker_start &&
           host->dbi_stalker_stop && host->gtrace_format_path;
}

void Run(void *)
{
    const HostApiV2 *host = g_api ? g_api->host : nullptr;
    if (!HostReady(host)) {
        Fail("rtgum-gtrace: runtime host unavailable");
        return;
    }
    unsigned long begin = 0UL;
    unsigned long end = 0UL;
    if (host->wait_export("libghostlab.so", "rtgum_gtrace_flower",
                          RTGUM_HOST_WAIT_EXPORT_DEFAULT_MS, &begin) != 0 ||
        host->wait_export("libghostlab.so", "rtgum_gtrace_flower_end",
                          RTGUM_HOST_WAIT_EXPORT_DEFAULT_MS, &end) != 0 ||
        begin == 0UL || end <= begin || ((begin | end) & 3UL) != 0UL ||
        end - begin > 4096UL) {
        Fail("rtgum-gtrace: flower fixture unavailable");
        return;
    }

    RtGumStalkerStats stats{};
    stats.gtrace_buffer = g_steps;
    stats.gtrace_capacity = kPathCapacity;
    const long started = host->dbi_stalker_start(&stats, begin, end - begin);
    if (started != 0L) {
        Fail("rtgum-gtrace: stalker start failed");
        return;
    }
    using Flower = int (*)(int, int);
    const int value = reinterpret_cast<Flower>(begin)(1, 2);
    const long stopped = host->dbi_stalker_stop();
    if (stopped != 0L || value != 42 || stats.gtrace_count != 5UL ||
        stats.gtrace_total != 5UL || stats.gtrace_dropped != 0UL ||
        stats.gtrace_head != 0UL) {
        Fail("rtgum-gtrace: dynamic execution contract failed");
        return;
    }

    bool saw_br = false;
    bool saw_junk = false;
    for (unsigned long index = 0UL; index < stats.gtrace_count; ++index) {
        const RtGumGtraceStep &step = g_steps[index];
        if (step.pc == begin + 8UL && step.instruction == 0xD61F0200U &&
            step.next_pc == begin + 24UL)
            saw_br = true;
        if (step.pc == begin + 12UL || step.pc == begin + 16UL ||
            step.pc == begin + 20UL)
            saw_junk = true;
    }
    if (!saw_br || saw_junk) {
        Fail("rtgum-gtrace: BR landing or junk filtering failed");
        return;
    }

    const long formatted = host->gtrace_format_path(
        g_steps, stats.gtrace_count, begin, end, g_text, sizeof(g_text));
    if (formatted != 0L ||
        !Contains(g_text, "kind=br branch=indirect reg=x16") ||
        !Contains(g_text, "target-scope=internal") ||
        !Contains(g_text,
                  "bytes=12 direction=forward candidate-junk=1") ||
        !Contains(g_text,
                  "gtrace-summary executed=5 branches=2 indirect=2 "
                  "internal-targets=1 gaps=1 skipped-bytes=12 losses=0 "
                  "mismatches=0 unreadable=0")) {
        Fail("rtgum-gtrace: formatted path contract failed");
        return;
    }
    LogLines(g_text);
    g_api->log("rtgum-gtrace: result=42 executed=5 junk-executed=0");
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                  RTGUM_MODULE_EXTRA_GTRACE_READY);
    g_api->log("rtgum-gtrace: PASS");
}

} // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION || !api->host) return;
    g_api = api;
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 0UL);
    if (!HostReady(api->host) || api->host->defer(Run, nullptr) != 0L)
        Fail("rtgum-gtrace: defer failed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (api) api->log("rtgum-gtrace: unload");
    g_api = nullptr;
}
