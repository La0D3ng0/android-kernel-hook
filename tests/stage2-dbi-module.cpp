/*
 * rtgum-stage2-dbi.ghm: in-app DBI (instruction relocation) self-test module.
 *
 * Runs inside the target application process. It resolves a real libc symbol
 * of that process, reads its code bytes through the HostApi, relocates them
 * with the application's own source VA and a ghost page as the clone VA, then
 * executes the clone *in that same process* and compares the behaviour with
 * the original function.
 *
 * This is the piece the control-tool differential cannot show: the clone page
 * has no VMA (ghost memory), the relocation base is the app's own address, and
 * the caller is the app itself.
 *
 * Exports:
 *   ghostEntry(GhostApi*)
 *   ghostModuleUnload(GhostApi*)
 */

#include <rtgum/ghost_api.h>
#include <rtgum/gum_api.h>

#include <stddef.h>

#include "../tools/dbi/rtgum-dbi.h"

namespace {

constexpr unsigned long kReadLength = 160UL;   /* bsearch body: 152 bytes */
constexpr unsigned long kCloneReserve = 4096UL;
constexpr unsigned long kMaxInstructions = kReadLength / 4UL;

/* 0 = running, 1 = armed (clone executed in-process), high values = failure. */
constexpr unsigned long kExtraArmed = 0x210UL;
constexpr unsigned long kExtraLookupFailed = 0x211UL;
constexpr unsigned long kExtraReadFailed = 0x212UL;
constexpr unsigned long kExtraAllocFailed = 0x213UL;
constexpr unsigned long kExtraRelocFailed = 0x214UL;
constexpr unsigned long kExtraResultMismatch = 0x215UL;
constexpr unsigned long kExtraStalkerFailed = 0x216UL;
constexpr unsigned long kExtraStalkerArmed = 0x220UL;

#ifndef RTGUM_DBI_STALKER_REQUIRED
#define RTGUM_DBI_STALKER_REQUIRED 0
#endif

unsigned char g_source[kReadLength];
unsigned char g_code[kCloneReserve];
constexpr uint32_t kMaxSites = 16U;
rtgum_dbi::SiteRecord g_records[kMaxSites];
rtgum_dbi::OffsetMapEntry g_map[kMaxInstructions];
rtgum_dbi::BranchTraceEntry g_trace[kMaxInstructions];
rtgum_dbi::LiteralRange g_literals[kMaxInstructions];

int g_compare_calls = 0;

/* Inline cache maintenance: __builtin___clear_cache() lowers to a call to the
 * libc symbol __clear_cache, which a -nostdlib module cannot import (the KPM
 * remote resolver rejects the image). Emit the dc/ic sequence directly. */
void clear_cache_range(unsigned long start, unsigned long end)
{
    unsigned long ctr = 0;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    const unsigned long data_line = 4UL << ((ctr >> 16) & 0xfUL);
    const unsigned long instruction_line = 4UL << (ctr & 0xfUL);
    for (unsigned long address = start & ~(data_line - 1UL); address < end;
         address += data_line)
        __asm__ volatile("dc civac, %0" ::"r"(address) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (unsigned long address = start & ~(instruction_line - 1UL); address < end;
         address += instruction_line)
        __asm__ volatile("ic ivau, %0" ::"r"(address) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
}

int compare_ints(const void *left, const void *right)
{
    ++g_compare_calls;
    const int a = *static_cast<const int *>(left);
    const int b = *static_cast<const int *>(right);
    return a < b ? -1 : (a > b ? 1 : 0);
}

/* Tiny decimal formatter: the module has no libc. */
void append_number(char *out, unsigned long &cursor, unsigned long value)
{
    char digits[24];
    unsigned int count = 0;
    if (value == 0) digits[count++] = '0';
    while (value != 0 && count < sizeof(digits)) {
        digits[count++] = static_cast<char>('0' + (value % 10UL));
        value /= 10UL;
    }
    while (count != 0) out[cursor++] = digits[--count];
    out[cursor] = '\0';
}

void log_value(GhostApi *api, const char *label, unsigned long value)
{
    char text[96];
    unsigned long cursor = 0;
    while (label[cursor] != '\0' && cursor < sizeof(text) - 24UL) {
        text[cursor] = label[cursor];
        ++cursor;
    }
    append_number(text, cursor, value);
    api->log(text);
}

void log_hex(GhostApi *api, const char *label, unsigned long value)
{
    char text[96];
    unsigned long cursor = 0;
    while (label[cursor] != '\0' && cursor < sizeof(text) - 24UL) {
        text[cursor] = label[cursor];
        ++cursor;
    }
    static const char kHex[] = "0123456789abcdef";
    text[cursor++] = '0';
    text[cursor++] = 'x';
    bool started = false;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const unsigned long nibble = (value >> shift) & 0xfUL;
        if (!started && nibble == 0 && shift != 0) continue;
        started = true;
        text[cursor++] = kHex[nibble];
    }
    text[cursor] = '\0';
    api->log(text);
}

} // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || !api->host) return;
    api->log("rtgum-dbi-module: entry");
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 0);

    const HostApiV2 *host = api->host;
    if (!host->find_export) {
        api->log("rtgum-dbi-module: host api incomplete");
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraLookupFailed);
        return;
    }

    unsigned long target = 0;
    const long found = host->find_export("libc.so", "bsearch", &target);
    if (found != 0 || target == 0) {
        api->log("rtgum-dbi-module: bsearch not found");
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraLookupFailed);
        return;
    }
    log_hex(api, "rtgum-dbi-module: app bsearch at ", target);

    /* The module runs inside the target process, so its own memory is
     * directly readable: copy the code bytes without any host helper. The
     * length is clamped to the end of the containing page. */
    const unsigned long page_end = (target & ~0xfffUL) + 0x1000UL;
    unsigned long read_length = kReadLength;
    if (target + read_length > page_end) read_length = page_end - target;
    read_length &= ~3UL;
    if (read_length < 16UL) {
        api->log("rtgum-dbi-module: target too close to the page end");
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraReadFailed);
        return;
    }
    const volatile unsigned char *code_bytes =
        reinterpret_cast<const volatile unsigned char *>(target);
    for (unsigned long index = 0; index < read_length; ++index)
        g_source[index] = code_bytes[index];
    log_value(api, "rtgum-dbi-module: code bytes=", read_length);

    /* Ghost page inside this process: no VMA is created for it. */
    unsigned long clone = 0;
    if (api->ghost_alloc(kCloneReserve, 3U /* RW */, &clone) != 0 || clone == 0) {
        api->log("rtgum-dbi-module: ghost alloc failed");
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraAllocFailed);
        return;
    }
    log_hex(api, "rtgum-dbi-module: ghost clone at ", clone);

    rtgum_dbi::RelocationResult result = rtgum_dbi::make_result(
        g_code, sizeof(g_code), g_map, kMaxInstructions, g_trace,
        kMaxInstructions, g_literals, kMaxInstructions);
    result.dispatcher.enabled = true;
    result.dispatcher.mode = 3U;
    result.dispatcher.record_base = reinterpret_cast<unsigned long>(g_records);
    result.dispatcher.record_stride = sizeof(rtgum_dbi::SiteRecord);
    result.dispatcher.max_sites = kMaxSites;
    if (!rtgum_dbi::Relocator::relocate(g_source, read_length, target, clone,
                                        result)) {
        log_value(api, "rtgum-dbi-module: relocate failed unsupported=",
                  result.unsupported ? 1UL : 0UL);
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraRelocFailed);
        return;
    }
    log_value(api, "rtgum-dbi-module: cloned bytes=", result.code_size);
    log_value(api, "rtgum-dbi-module: literals=", result.literal_count);
    log_value(api, "rtgum-dbi-module: literal-ranges=", static_cast<unsigned long>(result.literal_size));
    log_value(api, "rtgum-dbi-module: dispatcher-sites=", static_cast<unsigned long>(result.site_count));

    /* Copy into the ghost page (writable for both) and publish it. */
    auto *destination = reinterpret_cast<volatile unsigned char *>(clone);
    for (size_t index = 0; index < result.code_size; ++index)
        destination[index] = g_code[index];
    clear_cache_range(clone, clone + result.code_size);
    if (api->ghost_protect(clone, 5U /* RX */) != 0) {
        api->log("rtgum-dbi-module: ghost protect failed");
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraAllocFailed);
        return;
    }

    using Bsearch = void *(*)(const void *, const void *, unsigned long,
                              unsigned long, int (*)(const void *, const void *));
    auto *original = reinterpret_cast<Bsearch>(target);
    auto *relocated = reinterpret_cast<Bsearch>(clone);
    static const int sorted[] = {1, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    const int probes[] = {1, 17, 37, 4, 100};
    unsigned long matched = 0;
    unsigned long compared = 0;
#if RTGUM_DBI_STALKER_REQUIRED
    const size_t required_size = offsetof(HostApiV2, dbi_stalker_stop) +
                                 sizeof(host->dbi_stalker_stop);
    if (host->size < required_size ||
        (host->capabilities & RTGUM_HOST_CAP_DBI_STALKER_BTI_CHECKED) == 0 ||
        !host->dbi_stalker_start || !host->dbi_stalker_invalidate ||
        !host->dbi_stalker_stop) {
        api->log("rtgum-dbi-module: stalker host unavailable");
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraStalkerFailed);
        return;
    }
    void *expected[sizeof(probes) / sizeof(probes[0])]{};
    for (unsigned int index = 0; index < sizeof(probes) / sizeof(probes[0]); ++index)
        expected[index] = original(&probes[index], sorted, 12, sizeof(int), compare_ints);
    RtGumStalkerStats stalker_stats{};
    const long stalker_started = host->dbi_stalker_start(
        &stalker_stats, clone, result.code_size);
    if (stalker_started != 0) {
        log_value(api, "rtgum-dbi-module: stalker start failed=",
                  static_cast<unsigned long>(-stalker_started));
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraStalkerFailed);
        return;
    }
#endif
    for (unsigned int index = 0; index < sizeof(probes) / sizeof(probes[0]); ++index) {
        const int key = probes[index];
#if RTGUM_DBI_STALKER_REQUIRED
        void *actual = relocated(&key, sorted, 12, sizeof(int), compare_ints);
        if (index == 1U && host->dbi_stalker_invalidate(clone) != 0) {
            host->dbi_stalker_stop();
            api->log("rtgum-dbi-module: stalker invalidate failed");
            api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraStalkerFailed);
            return;
        }
        if (expected[index] == actual) ++matched;
#else
        void *expected = original(&key, sorted, 12, sizeof(int), compare_ints);
        void *actual = relocated(&key, sorted, 12, sizeof(int), compare_ints);
        if (expected == actual) ++matched;
#endif
        ++compared;
    }
#if RTGUM_DBI_STALKER_REQUIRED
    const long stalker_stopped = host->dbi_stalker_stop();
    log_value(api, "rtgum-dbi-module: stalker blocks=", stalker_stats.blocks);
    log_value(api, "rtgum-dbi-module: stalker calls=", stalker_stats.calls);
    log_value(api, "rtgum-dbi-module: stalker returns=", stalker_stats.returns);
    log_value(api, "rtgum-dbi-module: stalker compiled=", stalker_stats.compiled);
    log_value(api, "rtgum-dbi-module: stalker shadow-matched=", stalker_stats.matched_returns);
    log_value(api, "rtgum-dbi-module: stalker shadow-mismatched=", stalker_stats.mismatched_returns);
    log_value(api, "rtgum-dbi-module: stalker shadow-unpaired=", stalker_stats.unpaired_returns);
    log_value(api, "rtgum-dbi-module: stalker shadow-unwound=", stalker_stats.unwound_frames);
    log_value(api, "rtgum-dbi-module: stalker shadow-overflow=", stalker_stats.shadow_overflow);
    log_value(api, "rtgum-dbi-module: stalker shadow-remaining=", stalker_stats.shadow_remaining);
    log_value(api, "rtgum-dbi-module: stalker pac-checks=", stalker_stats.pac_checks);
    log_value(api, "rtgum-dbi-module: stalker bti-checks=", stalker_stats.bti_checks);
    log_value(api, "rtgum-dbi-module: stalker bti-guarded=", stalker_stats.bti_guarded);
    log_value(api, "rtgum-dbi-module: stalker bti-rejected=", stalker_stats.bti_rejected);
    if (stalker_stopped != 0 || stalker_stats.blocks == 0 ||
        stalker_stats.calls == 0 || stalker_stats.returns == 0 ||
        stalker_stats.matched_returns == 0 ||
        stalker_stats.mismatched_returns != 0 ||
        stalker_stats.unpaired_returns != 0 ||
        stalker_stats.shadow_overflow != 0 ||
        stalker_stats.shadow_remaining != 0 ||
        stalker_stats.pac_checks == 0 ||
        stalker_stats.bti_checks == 0 ||
        stalker_stats.bti_rejected != 0) {
        api->log("rtgum-dbi-module: stalker did not follow clone");
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraStalkerFailed);
        return;
    }
    api->log("rtgum-dbi-module: stalker completed");
#endif
    log_value(api, "rtgum-dbi-module: probes matched=", matched);
    log_value(api, "rtgum-dbi-module: comparator calls=",
              static_cast<unsigned long>(g_compare_calls));
    if (matched != compared) {
        api->status(RTGUM_DAEMON_STATUS_EXTRA, kExtraResultMismatch);
        return;
    }
    api->log("rtgum-dbi-module: in-app clone executed and matched");
    api->status(RTGUM_DAEMON_STATUS_EXTRA,
                RTGUM_DBI_STALKER_REQUIRED ? kExtraStalkerArmed : kExtraArmed);
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (!api) return;
    api->log("rtgum-dbi-module: unload");
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 0);
}
