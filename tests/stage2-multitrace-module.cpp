/* Per-handle asynchronous trace acceptance module.
 *
 * Registers two functions before either is called.  Each registration owns a
 * different traceMode/memReadMode/writer route.  Calls are then interleaved,
 * one handle is removed, and the surviving handle is called again.  This
 * catches the old design where the second traceStart overwrote process-global
 * code-handler configuration or where traceStop detached the wrong target.
 */

#include <rtgum/ghost_api.h>

#include <atomic>
#include <stddef.h>

namespace {

constexpr unsigned long kStepCapacity = 32UL;

struct WriterState {
    unsigned long handle;
    unsigned long target;
    unsigned long begin;
    unsigned long end;
    unsigned int trace_mode;
    unsigned int mem_read_mode;
    unsigned long callbacks;
    unsigned long successful;
    unsigned long steps;
    unsigned long violations;
    unsigned int expected_words[3];
};

GhostApi *g_api = nullptr;
WriterState g_writer_a{};
WriterState g_writer_b{};
unsigned long g_handle_a = 0UL;
unsigned long g_handle_b = 0UL;

struct QueryRaceState {
    const HostApiV2 *host;
    unsigned long handle_a;
    unsigned long handle_b;
    unsigned long target_a;
    unsigned long target_b;
    std::atomic<unsigned long> queries{0UL};
    std::atomic<unsigned long> violations{0UL};
    std::atomic<unsigned int> started{0U};
    std::atomic<unsigned int> stop{0U};
    std::atomic<unsigned int> done{0U};
};

QueryRaceState g_query_race{};

void AppendNumber(char *out, unsigned long &cursor, unsigned long value)
{
    char digits[24];
    unsigned int count = 0U;
    if (value == 0UL) digits[count++] = '0';
    while (value != 0UL && count < sizeof(digits)) {
        digits[count++] = static_cast<char>('0' + value % 10UL);
        value /= 10UL;
    }
    while (count != 0U) out[cursor++] = digits[--count];
    out[cursor] = '\0';
}

void LogPair(const char *label, unsigned long a, unsigned long b)
{
    if (!g_api) return;
    char text[160];
    unsigned long cursor = 0UL;
    while (label[cursor] != '\0' && cursor + 48UL < sizeof(text)) {
        text[cursor] = label[cursor];
        ++cursor;
    }
    AppendNumber(text, cursor, a);
    text[cursor++] = '/';
    AppendNumber(text, cursor, b);
    g_api->log(text);
}

void Cleanup(const HostApiV2 *host)
{
    if (!host || !host->trace_stop) return;
    if (g_handle_a != 0UL) {
        (void)host->trace_stop(g_handle_a);
        g_handle_a = 0UL;
    }
    if (g_handle_b != 0UL) {
        (void)host->trace_stop(g_handle_b);
        g_handle_b = 0UL;
    }
}

void Fail(const char *message)
{
    if (!g_api) return;
    g_api->log(message);
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                  RTGUM_MODULE_EXTRA_MULTI_TRACE_FAILED);
}

long WriteBatch(const RtGumTraceBatch *batch, void *user_data)
{
    auto *state = static_cast<WriterState *>(user_data);
    if (!state) return -1L;
    ++state->callbacks;
    bool valid = batch != nullptr &&
        batch->version == RTGUM_TRACE_BATCH_VERSION &&
        batch->size >= sizeof(RtGumTraceBatch) &&
        batch->handle == state->handle &&
        batch->target == state->target &&
        batch->invocation == state->callbacks &&
        batch->thread_id != 0UL &&
        batch->trace_mode == state->trace_mode &&
        batch->mem_read_mode == state->mem_read_mode &&
        batch->result == 0L && batch->steps != nullptr &&
        batch->count == 3UL && batch->total == 3UL &&
        batch->dropped == 0UL;
    if (valid) {
        for (unsigned long index = 0UL; index < batch->count; ++index) {
            const RtGumGtraceStep &step = batch->steps[index];
            const bool has_instruction =
                (step.flags & RTGUM_GTRACE_STEP_INSN_VALID) != 0U;
            if (step.sequence != index + 1UL ||
                step.pc != state->begin + index * 4UL ||
                (index != 2UL && step.next_pc != step.pc + 4UL) ||
                (step.flags & (RTGUM_GTRACE_STEP_NEXT_VALID |
                               RTGUM_GTRACE_STEP_DYNAMIC |
                               RTGUM_GTRACE_STEP_DBI_CALLOUT)) !=
                    (RTGUM_GTRACE_STEP_NEXT_VALID |
                     RTGUM_GTRACE_STEP_DYNAMIC |
                     RTGUM_GTRACE_STEP_DBI_CALLOUT) ||
                (state->mem_read_mode == RTGUM_TRACE_MEM_READ_CODE &&
                 (!has_instruction ||
                  step.instruction != state->expected_words[index])) ||
                (state->mem_read_mode == RTGUM_TRACE_MEM_READ_NONE &&
                 (has_instruction || step.instruction != 0U))) {
                valid = false;
                break;
            }
        }
    }
    if (!valid) {
        ++state->violations;
        return -1L;
    }
    ++state->successful;
    state->steps += batch->count;
    return 0L;
}

bool HostReady(const HostApiV2 *host)
{
    return host && host->version == RTGUM_HOST_API_V2_VERSION &&
        host->size >= offsetof(HostApiV2, trace_query) +
                          sizeof(host->trace_query) &&
        (host->capabilities & RTGUM_HOST_CAP_MULTI_TRACE) != 0UL &&
        host->wait_export && host->defer && host->sleep_ms && host->trace_start &&
        host->trace_stop && host->trace_query;
}

bool Resolve(const HostApiV2 *host, const char *name, unsigned long *address)
{
    return host->wait_export("libghostlab.so", name,
                             RTGUM_HOST_WAIT_EXPORT_DEFAULT_MS, address) == 0L &&
           *address != 0UL;
}

void QueryRace(void *argument)
{
    auto *race = static_cast<QueryRaceState *>(argument);
    if (!race || !race->host) return;
    race->started.store(1U, std::memory_order_release);
    while (race->stop.load(std::memory_order_acquire) == 0U) {
        const unsigned long handles[2] = {race->handle_a, race->handle_b};
        const unsigned long targets[2] = {race->target_a, race->target_b};
        for (unsigned int index = 0U; index != 2U; ++index) {
            RtGumTraceStats stats{};
            const long result = race->host->trace_query(handles[index], &stats);
            if (result == 0L) {
                if (stats.version != RTGUM_TRACE_STATS_VERSION ||
                    stats.size < sizeof(stats) ||
                    stats.handle != handles[index] ||
                    stats.target != targets[index])
                    race->violations.fetch_add(1UL, std::memory_order_relaxed);
            } else if (result != RTGUM_HOST_ERR_NOENT) {
                race->violations.fetch_add(1UL, std::memory_order_relaxed);
            }
            race->queries.fetch_add(1UL, std::memory_order_relaxed);
        }
    }
    race->done.store(1U, std::memory_order_release);
}

bool FinishQueryRace(const HostApiV2 *host)
{
    if (!host || g_query_race.started.load(std::memory_order_acquire) == 0U)
        return false;
    g_query_race.stop.store(1U, std::memory_order_release);
    for (unsigned int wait = 0U;
         g_query_race.done.load(std::memory_order_acquire) == 0U &&
         wait != 1000U; ++wait)
        host->sleep_ms(1U);
    return g_query_race.done.load(std::memory_order_acquire) != 0U &&
        g_query_race.queries.load(std::memory_order_acquire) != 0UL &&
        g_query_race.violations.load(std::memory_order_acquire) == 0UL;
}

void Run(void *)
{
    const HostApiV2 *host = g_api ? g_api->host : nullptr;
    if (!HostReady(host)) {
        Fail("rtgum-multitrace: runtime host unavailable");
        return;
    }
    unsigned long a = 0UL, a_end = 0UL, b = 0UL, b_end = 0UL;
    if (!Resolve(host, "rtgum_multitrace_a", &a) ||
        !Resolve(host, "rtgum_multitrace_a_end", &a_end) ||
        !Resolve(host, "rtgum_multitrace_b", &b) ||
        !Resolve(host, "rtgum_multitrace_b_end", &b_end) ||
        a_end <= a || b_end <= b || a_end - a > 256UL ||
        b_end - b > 256UL) {
        Fail("rtgum-multitrace: fixtures unavailable");
        return;
    }

    g_writer_a.target = a;
    g_writer_a.begin = a;
    g_writer_a.end = a_end;
    g_writer_a.trace_mode = RTGUM_TRACE_MODE_EXECUTED_PATH;
    g_writer_a.mem_read_mode = RTGUM_TRACE_MEM_READ_CODE;
    g_writer_a.expected_words[0] = 0x11002800U; /* add w0, w0, #10 */
    g_writer_a.expected_words[1] = 0x11000400U; /* add w0, w0, #1 */
    g_writer_a.expected_words[2] = 0xd65f03c0U; /* ret */
    g_writer_b.target = b;
    g_writer_b.begin = b;
    g_writer_b.end = b_end;
    g_writer_b.trace_mode = RTGUM_TRACE_MODE_EXECUTED_PATH |
                            RTGUM_TRACE_MODE_SUMMARY;
    g_writer_b.mem_read_mode = RTGUM_TRACE_MEM_READ_NONE;

    RtGumTraceConfig config_a{};
    config_a.version = RTGUM_TRACE_CONFIG_VERSION;
    config_a.size = sizeof(config_a);
    config_a.target = a;
    config_a.watched_start = a;
    config_a.watched_size = a_end - a;
    config_a.trace_mode = g_writer_a.trace_mode;
    config_a.mem_read_mode = g_writer_a.mem_read_mode;
    config_a.step_capacity = kStepCapacity;
    config_a.writer = WriteBatch;
    config_a.writer_user_data = &g_writer_a;
    RtGumTraceConfig config_b = config_a;
    config_b.target = b;
    config_b.watched_start = b;
    config_b.watched_size = b_end - b;
    config_b.trace_mode = g_writer_b.trace_mode;
    config_b.mem_read_mode = g_writer_b.mem_read_mode;
    config_b.writer_user_data = &g_writer_b;

    const long started_a = host->trace_start(&config_a, &g_handle_a);
    if (started_a != 0L || g_handle_a == 0UL) {
        Fail("rtgum-multitrace: trace A registration failed");
        return;
    }
    g_writer_a.handle = g_handle_a;
    const long started_b = host->trace_start(&config_b, &g_handle_b);
    if (started_b != 0L || g_handle_b == 0UL || g_handle_b == g_handle_a) {
        Cleanup(host);
        Fail("rtgum-multitrace: trace B registration failed");
        return;
    }
    g_writer_b.handle = g_handle_b;

    using Fixture = int (*)(int);
    auto *function_a = reinterpret_cast<Fixture>(a);
    auto *function_b = reinterpret_cast<Fixture>(b);
    const int a1 = function_a(1);
    const int b1 = function_b(1);
    const int a2 = function_a(2);
    const int b2 = function_b(2);
    RtGumTraceStats stats_a{};
    RtGumTraceStats stats_b{};
    const bool first_phase = a1 == 12 && a2 == 13 && b1 == 23 && b2 == 24 &&
        g_writer_a.callbacks == 2UL && g_writer_a.successful == 2UL &&
        g_writer_b.callbacks == 2UL && g_writer_b.successful == 2UL &&
        g_writer_a.steps == 6UL && g_writer_b.steps == 6UL &&
        g_writer_a.violations == 0UL && g_writer_b.violations == 0UL &&
        host->trace_query(g_handle_a, &stats_a) == 0L &&
        host->trace_query(g_handle_b, &stats_b) == 0L &&
        stats_a.handle == g_handle_a && stats_b.handle == g_handle_b &&
        stats_a.target == a && stats_b.target == b &&
        stats_a.invocations == 2UL && stats_a.completed == 2UL &&
        stats_b.invocations == 2UL && stats_b.completed == 2UL &&
        stats_a.active == 0UL && stats_b.active == 0UL &&
        stats_a.busy == 0UL && stats_b.busy == 0UL &&
        stats_a.failures == 0UL && stats_b.failures == 0UL &&
        stats_a.writer_errors == 0UL && stats_b.writer_errors == 0UL &&
        stats_a.trace_mode == g_writer_a.trace_mode &&
        stats_b.trace_mode == g_writer_b.trace_mode &&
        stats_a.mem_read_mode == g_writer_a.mem_read_mode &&
        stats_b.mem_read_mode == g_writer_b.mem_read_mode;
    if (!first_phase) {
        Cleanup(host);
        Fail("rtgum-multitrace: A/B context isolation failed");
        return;
    }

    g_query_race.host = host;
    g_query_race.handle_a = g_handle_a;
    g_query_race.handle_b = g_handle_b;
    g_query_race.target_a = a;
    g_query_race.target_b = b;
    g_query_race.queries.store(0UL, std::memory_order_relaxed);
    g_query_race.violations.store(0UL, std::memory_order_relaxed);
    g_query_race.started.store(0U, std::memory_order_relaxed);
    g_query_race.stop.store(0U, std::memory_order_relaxed);
    g_query_race.done.store(0U, std::memory_order_relaxed);
    if (host->defer(QueryRace, &g_query_race) != 0L) {
        Cleanup(host);
        Fail("rtgum-multitrace: query race worker failed");
        return;
    }
    for (unsigned int wait = 0U;
         g_query_race.started.load(std::memory_order_acquire) == 0U &&
         wait != 1000U; ++wait)
        host->sleep_ms(1U);
    if (g_query_race.started.load(std::memory_order_acquire) == 0U) {
        g_query_race.stop.store(1U, std::memory_order_release);
        for (unsigned int wait = 0U;
             g_query_race.done.load(std::memory_order_acquire) == 0U &&
             wait != 1000U; ++wait)
            host->sleep_ms(1U);
        Cleanup(host);
        Fail("rtgum-multitrace: query race worker timeout");
        return;
    }

    const unsigned long stale_a = g_handle_a;
    if (host->trace_stop(g_handle_a) != 0L) {
        (void)FinishQueryRace(host);
        Cleanup(host);
        Fail("rtgum-multitrace: trace A stop failed");
        return;
    }
    g_handle_a = 0UL;
    const int untraced_a = function_a(3);
    const int live_b = function_b(3);
    RtGumTraceStats live_stats{};
    RtGumTraceStats stale_stats{};
    if (untraced_a != 14 || live_b != 25 ||
        g_writer_a.callbacks != 2UL || g_writer_b.callbacks != 3UL ||
        g_writer_b.successful != 3UL || g_writer_b.violations != 0UL ||
        g_writer_a.steps != 6UL || g_writer_b.steps != 9UL ||
        host->trace_query(stale_a, &stale_stats) != RTGUM_HOST_ERR_NOENT ||
        host->trace_stop(stale_a) != RTGUM_HOST_ERR_NOENT ||
        host->trace_query(g_handle_b, &live_stats) != 0L ||
        live_stats.invocations != 3UL || live_stats.completed != 3UL ||
        live_stats.writer_errors != 0UL || live_stats.active != 0UL) {
        (void)FinishQueryRace(host);
        Cleanup(host);
        Fail("rtgum-multitrace: independent teardown failed");
        return;
    }

    if (!FinishQueryRace(host)) {
        Cleanup(host);
        Fail("rtgum-multitrace: query stop race failed");
        return;
    }
    const unsigned long stale_b = g_handle_b;
    if (host->trace_stop(g_handle_b) != 0L ||
        host->trace_stop(stale_b) != RTGUM_HOST_ERR_NOENT) {
        g_handle_b = 0UL;
        Fail("rtgum-multitrace: stale handle contract failed");
        return;
    }
    g_handle_b = 0UL;

    LogPair("rtgum-multitrace: callbacks A/B=",
            g_writer_a.callbacks, g_writer_b.callbacks);
    LogPair("rtgum-multitrace: steps A/B=",
            g_writer_a.steps, g_writer_b.steps);
    g_api->log("rtgum-multitrace: per-handle config isolated");
    g_api->log("rtgum-multitrace: relocated prologue coverage complete");
    g_api->log("rtgum-multitrace: query-stop race safe");
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                  RTGUM_MODULE_EXTRA_MULTI_TRACE_READY);
    g_api->log("rtgum-multitrace: PASS");
}

} // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION || !api->host) return;
    g_api = api;
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 0UL);
    if (!HostReady(api->host) || api->host->defer(Run, nullptr) != 0L)
        Fail("rtgum-multitrace: defer failed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(
    GhostApi *api)
{
    if (api && api->host &&
        g_query_race.started.load(std::memory_order_acquire) != 0U &&
        g_query_race.done.load(std::memory_order_acquire) == 0U)
        (void)FinishQueryRace(api->host);
    if (api && api->host) Cleanup(api->host);
    if (api) api->log("rtgum-multitrace: unload");
    g_api = nullptr;
}
