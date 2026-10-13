/*
 * Sandboxed Lua 5.4 helper. Ordinary in-process host tests may load this
 * SHARED image through the system linker; the KPM/Zygote path caches its ELF
 * bytes and ghost-links it through Daemon::load_ghost_image. It is never
 * statically linked into the Daemon.
 *
 * A single worker owns lua_State. Gum hook threads only publish bounded
 * invocation snapshots; they never allocate, log, block, or enter Lua.
 */

#include "rtgum/gum_api.h"
#include "rtgum/host_api_v2.h"

#include <android/log.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <vector>

extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
}

namespace {

constexpr const char *kTag = "rtgum-lua";
constexpr std::size_t kMaximumScriptBytes = 256U * 1024U;
constexpr std::size_t kLuaHeapLimit = 16U * 1024U * 1024U;
constexpr unsigned long kLuaInstructionLimit = 10000000UL;
constexpr unsigned long long kLuaTimeLimitNs = 30000000000ULL;
constexpr int kLuaHookInterval = 1000;
constexpr std::size_t kMaximumGumHooks = 32U;
constexpr std::size_t kMaximumLuaAllocations = 64U;
constexpr std::size_t kCallbackQueueCapacity = 256U;
constexpr std::size_t kMaximumPendingCommands = 64U;
constexpr std::size_t kMaximumTraceEntries = 16U;
constexpr std::size_t kTraceBatchCapacity = 8U;
constexpr unsigned long kMaximumMemoryTransfer = 64U * 1024U;

HostApiV2 *g_host = nullptr;
lua_State *g_lua = nullptr;

void Log(const char *message);
void DrainCallbackQueue(unsigned int maximum);

bool HostFieldAvailable(std::size_t offset, std::size_t size)
{
    return g_host != nullptr && g_host->size >= offset + size;
}

#define RTGUM_HOST_FIELD_AVAILABLE(field)                                      \
    (HostFieldAvailable(offsetof(HostApiV2, field), sizeof(g_host->field)) &&  \
     g_host->field != nullptr)

bool GumAvailable()
{
    return g_host != nullptr &&
           (g_host->capabilities & RTGUM_HOST_CAP_GUM) != 0UL &&
           RTGUM_HOST_FIELD_AVAILABLE(gum_find_export) &&
           RTGUM_HOST_FIELD_AVAILABLE(gum_intercept_attach_address) &&
           RTGUM_HOST_FIELD_AVAILABLE(gum_intercept_revert);
}

void CopyError(const char *message, char *error, unsigned long capacity)
{
    if (error == nullptr || capacity == 0UL) return;
    unsigned long length = 0UL;
    if (message != nullptr)
        while (message[length] != '\0') ++length;
    if (length + 1UL > capacity) length = capacity - 1UL;
    if (message != nullptr && length != 0UL)
        std::memcpy(error, message, static_cast<std::size_t>(length));
    error[length] = '\0';
}

void Log(const char *message)
{
    if (RTGUM_HOST_FIELD_AVAILABLE(log) &&
        (g_host->capabilities & RTGUM_HOST_CAP_LOG) != 0UL) {
        (void)g_host->log(message != nullptr ? message : "");
        return;
    }
    __android_log_print(ANDROID_LOG_INFO, kTag, "%s",
                        message != nullptr ? message : "");
}

struct LuaAllocatorState {
    std::size_t used = 0U;
    std::size_t peak = 0U;
};

LuaAllocatorState g_lua_allocator{};

void *LimitedLuaAllocator(void *user, void *pointer,
                          std::size_t old_size, std::size_t new_size)
{
    auto *state = static_cast<LuaAllocatorState *>(user);
    if (new_size == 0U) {
        if (pointer != nullptr) {
            state->used = old_size <= state->used ? state->used - old_size : 0U;
            std::free(pointer);
        }
        return nullptr;
    }
    if (pointer == nullptr) old_size = 0U;
    if (new_size > old_size) {
        if (state->used > kLuaHeapLimit ||
            new_size - old_size > kLuaHeapLimit - state->used)
            return nullptr;
    }
    void *resized = std::realloc(pointer, new_size);
    if (resized == nullptr) return nullptr;
    if (new_size >= old_size)
        state->used += new_size - old_size;
    else
        state->used -= old_size - new_size;
    if (state->used > state->peak) state->peak = state->used;
    return resized;
}

struct EvalBudget {
    unsigned long instructions = 0UL;
    unsigned long long deadline_ns = 0ULL;
    bool active = false;
};

EvalBudget g_eval_budget{};

unsigned long long MonotonicNs()
{
    timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0ULL;
    return static_cast<unsigned long long>(value.tv_sec) * 1000000000ULL +
           static_cast<unsigned long long>(value.tv_nsec);
}

void LuaBudgetHook(lua_State *L, lua_Debug *)
{
    if (!g_eval_budget.active) return;
    g_eval_budget.instructions += static_cast<unsigned long>(kLuaHookInterval);
    const unsigned long long now = MonotonicNs();
    if (g_eval_budget.instructions > kLuaInstructionLimit ||
        (g_eval_budget.deadline_ns != 0ULL && now > g_eval_budget.deadline_ns))
        luaL_error(L, "Lua execution budget exceeded");
}

void BeginLuaBudget(lua_State *L)
{
    const unsigned long long now = MonotonicNs();
    g_eval_budget.instructions = 0UL;
    g_eval_budget.deadline_ns = now == 0ULL ? 0ULL : now + kLuaTimeLimitNs;
    g_eval_budget.active = true;
    lua_sethook(L, LuaBudgetHook, LUA_MASKCOUNT, kLuaHookInterval);
}

void EndLuaBudget(lua_State *L)
{
    lua_sethook(L, nullptr, 0, 0);
    g_eval_budget.active = false;
}

enum : unsigned int {
    kHookFree = 0U,
    kHookActive = 1U,
    kHookRetiring = 2U,
};

enum class GumHookKind : unsigned int {
    kAttach = 1U,
    kReplace = 2U,
};

struct GumHookEntry {
    std::atomic<unsigned int> state{0U};
    std::atomic<unsigned long> generation{0UL};
    std::atomic<int> on_enter_ref{LUA_NOREF};
    std::atomic<int> on_leave_ref{LUA_NOREF};
    unsigned long handle = 0UL;
    unsigned long target = 0UL;
    GumHookKind kind = GumHookKind::kAttach;
    char symbol[48]{};
};

GumHookEntry g_gum_hooks[kMaximumGumHooks];
std::atomic<unsigned long> g_hook_generation{1UL};

void *EncodeCookie(std::size_t slot, unsigned long generation)
{
    const std::uintptr_t value =
        (static_cast<std::uintptr_t>(generation & 0xffffffffUL) << 8U) |
        static_cast<std::uintptr_t>(slot + 1U);
    return reinterpret_cast<void *>(value);
}

bool DecodeCookie(void *cookie, std::size_t limit,
                  std::size_t &slot, unsigned long &generation)
{
    const std::uintptr_t value = reinterpret_cast<std::uintptr_t>(cookie);
    const std::uintptr_t encoded_slot = value & 0xffU;
    if (encoded_slot == 0U || encoded_slot > limit) return false;
    slot = static_cast<std::size_t>(encoded_slot - 1U);
    generation = static_cast<unsigned long>(value >> 8U);
    return generation != 0UL;
}

struct CallbackEvent {
    std::size_t slot = 0U;
    unsigned long generation = 0UL;
    unsigned long sequence = 0UL;
    bool leave = false;
    RtGumInvocation invocation{};
};

struct CallbackCell {
    std::atomic<std::size_t> sequence{0U};
    CallbackEvent event{};
};

CallbackCell g_callback_queue[kCallbackQueueCapacity];
std::atomic<std::size_t> g_callback_enqueue{0U};
std::size_t g_callback_dequeue = 0U;
std::atomic<unsigned long> g_callback_sequence{0UL};
std::atomic<unsigned long> g_callback_queued{0UL};
std::atomic<unsigned long> g_callback_dispatched{0UL};
std::atomic<unsigned long> g_callback_full_drops{0UL};
std::atomic<unsigned long> g_callback_stale_drops{0UL};
std::atomic<unsigned long> g_callback_recursive_drops{0UL};
std::atomic<unsigned long> g_callback_lua_errors{0UL};

constexpr std::size_t kRecursionGuardSlots = 64U;
std::atomic<unsigned long> g_recursion_guards[kRecursionGuardSlots];

unsigned long CurrentThreadKey()
{
#if defined(__aarch64__)
    unsigned long key = 0UL;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(key));
    return key != 0UL ? key : 1UL;
#else
    return static_cast<unsigned long>(
        reinterpret_cast<std::uintptr_t>(pthread_self())) | 1UL;
#endif
}

bool IsCallbackThreadGuarded()
{
    const unsigned long key = CurrentThreadKey();
    std::size_t index = (key >> 4U) & (kRecursionGuardSlots - 1U);
    for (std::size_t probe = 0U; probe < 8U; ++probe) {
        if (g_recursion_guards[index].load(std::memory_order_acquire) == key)
            return true;
        index = (index + 1U) & (kRecursionGuardSlots - 1U);
    }
    return false;
}

long AcquireCallbackThreadGuard()
{
    const unsigned long key = CurrentThreadKey();
    std::size_t index = (key >> 4U) & (kRecursionGuardSlots - 1U);
    for (std::size_t probe = 0U; probe < 8U; ++probe) {
        unsigned long expected = 0UL;
        if (g_recursion_guards[index].compare_exchange_strong(
                expected, key, std::memory_order_acq_rel))
            return static_cast<long>(index);
        if (expected == key) return -1L;
        index = (index + 1U) & (kRecursionGuardSlots - 1U);
    }
    return -1L;
}

void ReleaseCallbackThreadGuard(long slot)
{
    if (slot >= 0L && static_cast<std::size_t>(slot) < kRecursionGuardSlots)
        g_recursion_guards[slot].store(0UL, std::memory_order_release);
}

void InitializeCallbackQueue()
{
    g_callback_enqueue.store(0U, std::memory_order_relaxed);
    g_callback_dequeue = 0U;
    for (std::size_t index = 0U; index < kCallbackQueueCapacity; ++index) {
        g_callback_queue[index].sequence.store(index, std::memory_order_relaxed);
        g_callback_queue[index].event = {};
    }
}

bool EnqueueCallback(const CallbackEvent &event)
{
    std::size_t position = g_callback_enqueue.load(std::memory_order_relaxed);
    for (;;) {
        CallbackCell &cell = g_callback_queue[position &
                                              (kCallbackQueueCapacity - 1U)];
        const std::size_t sequence = cell.sequence.load(std::memory_order_acquire);
        const std::intptr_t difference = static_cast<std::intptr_t>(sequence) -
                                         static_cast<std::intptr_t>(position);
        if (difference == 0) {
            if (g_callback_enqueue.compare_exchange_weak(
                    position, position + 1U, std::memory_order_relaxed)) {
                cell.event = event;
                cell.sequence.store(position + 1U, std::memory_order_release);
                g_callback_queued.fetch_add(1UL, std::memory_order_relaxed);
                return true;
            }
        } else if (difference < 0) {
            g_callback_full_drops.fetch_add(1UL, std::memory_order_relaxed);
            return false;
        } else {
            position = g_callback_enqueue.load(std::memory_order_relaxed);
        }
    }
}

bool DequeueCallback(CallbackEvent &event)
{
    CallbackCell &cell =
        g_callback_queue[g_callback_dequeue & (kCallbackQueueCapacity - 1U)];
    const std::size_t sequence = cell.sequence.load(std::memory_order_acquire);
    const std::intptr_t difference = static_cast<std::intptr_t>(sequence) -
        static_cast<std::intptr_t>(g_callback_dequeue + 1U);
    if (difference != 0) return false;
    event = cell.event;
    cell.sequence.store(g_callback_dequeue + kCallbackQueueCapacity,
                        std::memory_order_release);
    ++g_callback_dequeue;
    return true;
}

void PublishGumCallback(RtGumInvocation *invocation, void *user, bool leave)
{
    if (invocation == nullptr) return;
    if (IsCallbackThreadGuarded()) {
        g_callback_recursive_drops.fetch_add(1UL, std::memory_order_relaxed);
        return;
    }
    std::size_t slot = 0U;
    unsigned long generation = 0UL;
    if (!DecodeCookie(user, kMaximumGumHooks, slot, generation)) return;
    GumHookEntry &entry = g_gum_hooks[slot];
    if (entry.state.load(std::memory_order_acquire) != kHookActive ||
        (entry.generation.load(std::memory_order_acquire) & 0xffffffffUL) !=
            generation) {
        g_callback_stale_drops.fetch_add(1UL, std::memory_order_relaxed);
        return;
    }
    const int callback = leave
        ? entry.on_leave_ref.load(std::memory_order_acquire)
        : entry.on_enter_ref.load(std::memory_order_acquire);
    if (callback == LUA_NOREF) return;
    CallbackEvent event{};
    event.slot = slot;
    event.generation = generation;
    event.sequence = g_callback_sequence.fetch_add(
        1UL, std::memory_order_relaxed) + 1UL;
    event.leave = leave;
    event.invocation = *invocation;
    event.invocation.context = 0UL;
    (void)EnqueueCallback(event);
}

void GumOnEnter(RtGumInvocation *invocation, void *user)
{
    PublishGumCallback(invocation, user, false);
}

void GumOnLeave(RtGumInvocation *invocation, void *user)
{
    PublishGumCallback(invocation, user, true);
}

void GumPushInvocation(lua_State *L, const CallbackEvent &event)
{
    const RtGumInvocation &invocation = event.invocation;
    lua_newtable(L);
    lua_pushinteger(L, static_cast<lua_Integer>(invocation.function));
    lua_setfield(L, -2, "function");
    lua_pushinteger(L, 0);
    lua_setfield(L, -2, "context");
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "context_valid");
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "asynchronous");
    lua_pushstring(L, event.leave ? "leave" : "enter");
    lua_setfield(L, -2, "phase");
    lua_pushinteger(L, static_cast<lua_Integer>(event.sequence));
    lua_setfield(L, -2, "sequence");
    for (int index = 0; index < 8; ++index) {
        lua_pushinteger(L, static_cast<lua_Integer>(invocation.args[index]));
        lua_rawseti(L, -2, index + 1);
    }
    if (event.leave) {
        lua_pushinteger(L, static_cast<lua_Integer>(invocation.return_value));
        lua_setfield(L, -2, "retval");
        lua_pushinteger(L, static_cast<lua_Integer>(invocation.system_error));
        lua_setfield(L, -2, "syserr");
    }
}

void DispatchCallback(const CallbackEvent &event)
{
    if (g_lua == nullptr || event.slot >= kMaximumGumHooks) {
        g_callback_stale_drops.fetch_add(1UL, std::memory_order_relaxed);
        return;
    }
    GumHookEntry &entry = g_gum_hooks[event.slot];
    if (entry.state.load(std::memory_order_acquire) != kHookActive ||
        (entry.generation.load(std::memory_order_acquire) & 0xffffffffUL) !=
            event.generation) {
        g_callback_stale_drops.fetch_add(1UL, std::memory_order_relaxed);
        return;
    }
    const int callback = event.leave
        ? entry.on_leave_ref.load(std::memory_order_acquire)
        : entry.on_enter_ref.load(std::memory_order_acquire);
    if (callback == LUA_NOREF) {
        g_callback_stale_drops.fetch_add(1UL, std::memory_order_relaxed);
        return;
    }
    const long guard = AcquireCallbackThreadGuard();
    if (guard < 0L) {
        g_callback_recursive_drops.fetch_add(1UL, std::memory_order_relaxed);
        return;
    }
    lua_rawgeti(g_lua, LUA_REGISTRYINDEX, callback);
    GumPushInvocation(g_lua, event);
    BeginLuaBudget(g_lua);
    const int called = lua_pcall(g_lua, 1, 0, 0);
    EndLuaBudget(g_lua);
    if (called != LUA_OK) {
        g_callback_lua_errors.fetch_add(1UL, std::memory_order_relaxed);
        Log(lua_tostring(g_lua, -1));
        lua_pop(g_lua, 1);
    } else {
        g_callback_dispatched.fetch_add(1UL, std::memory_order_relaxed);
    }
    ReleaseCallbackThreadGuard(guard);
}

void DrainCallbackQueue(unsigned int maximum)
{
    CallbackEvent event{};
    for (unsigned int count = 0U; count < maximum && DequeueCallback(event);
         ++count)
        DispatchCallback(event);
}

struct LuaAllocationEntry { unsigned long address = 0UL; };
LuaAllocationEntry g_lua_allocations[kMaximumLuaAllocations]{};

struct StoredTraceBatch {
    RtGumTraceBatch batch{};
    RtGumGtraceStep *steps = nullptr;
};

struct LuaTraceEntry {
    std::atomic<unsigned int> state{0U};
    std::atomic<unsigned long> generation{0UL};
    std::atomic_flag lock = ATOMIC_FLAG_INIT;
    unsigned long handle = 0UL;
    std::atomic<unsigned long> local_dropped{0UL};
    std::size_t head = 0U;
    std::size_t count = 0U;
    StoredTraceBatch batches[kTraceBatchCapacity]{};
};

LuaTraceEntry g_trace_entries[kMaximumTraceEntries];
std::atomic<unsigned long> g_trace_generation{1UL};

void TraceLock(LuaTraceEntry &entry)
{
    while (entry.lock.test_and_set(std::memory_order_acquire))
        __asm__ volatile("yield" ::: "memory");
}

void TraceUnlock(LuaTraceEntry &entry)
{
    entry.lock.clear(std::memory_order_release);
}

void FreeStoredBatch(StoredTraceBatch &stored)
{
    std::free(stored.steps);
    stored = {};
}

long TraceWriter(const RtGumTraceBatch *batch, void *user)
{
    if (batch == nullptr) return RTGUM_HOST_ERR_INVAL;
    std::size_t slot = 0U;
    unsigned long generation = 0UL;
    if (!DecodeCookie(user, kMaximumTraceEntries, slot, generation))
        return RTGUM_HOST_ERR_INVAL;
    LuaTraceEntry &entry = g_trace_entries[slot];
    const unsigned int state = entry.state.load(std::memory_order_acquire);
    if ((state != kHookActive && state != kHookRetiring) ||
        (entry.generation.load(std::memory_order_acquire) & 0xffffffffUL) != generation)
        return RTGUM_HOST_ERR_NOENT;
    RtGumGtraceStep *steps = nullptr;
    if (batch->count != 0UL) {
        if (batch->count > 4096UL || batch->steps == nullptr)
            return RTGUM_HOST_ERR_INVAL;
        const std::size_t bytes = static_cast<std::size_t>(batch->count) *
                                  sizeof(RtGumGtraceStep);
        steps = static_cast<RtGumGtraceStep *>(std::malloc(bytes));
        if (steps == nullptr) return RTGUM_HOST_ERR_NOMEM;
        std::memcpy(steps, batch->steps, bytes);
    }
    if (entry.lock.test_and_set(std::memory_order_acquire)) {
        std::free(steps);
        entry.local_dropped.fetch_add(1UL, std::memory_order_relaxed);
        return RTGUM_HOST_ERR_AGAIN;
    }
    if (entry.count == kTraceBatchCapacity) {
        FreeStoredBatch(entry.batches[entry.head]);
        entry.head = (entry.head + 1U) % kTraceBatchCapacity;
        --entry.count;
        entry.local_dropped.fetch_add(1UL, std::memory_order_relaxed);
    }
    const std::size_t tail = (entry.head + entry.count) % kTraceBatchCapacity;
    entry.batches[tail].batch = *batch;
    entry.batches[tail].batch.steps = steps;
    entry.batches[tail].steps = steps;
    ++entry.count;
    TraceUnlock(entry);
    return 0;
}

RtGumStalkerStats g_stalker_stats{};
std::vector<RtGumGtraceStep> g_stalker_steps;
bool g_stalker_active = false;

enum class WorkerCommandKind : unsigned int { kEval, kStop };

struct WorkerCommand {
    WorkerCommandKind kind = WorkerCommandKind::kEval;
    char *script = nullptr;
    std::size_t script_size = 0U;
    char *error = nullptr;
    unsigned long error_capacity = 0UL;
    bool synchronous = true;
    bool done = false;
    long result = RTGUM_HOST_ERR_NXIO;
    pthread_cond_t completion{};
    WorkerCommand *next = nullptr;
};

pthread_mutex_t g_worker_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_worker_condition = PTHREAD_COND_INITIALIZER;
pthread_t g_worker_thread{};
bool g_worker_running = false;
bool g_worker_joinable = false;
bool g_worker_accepting = false;
std::atomic<unsigned long> g_worker_key{0UL};
WorkerCommand *g_command_head = nullptr;
WorkerCommand *g_command_tail = nullptr;
std::size_t g_command_count = 0U;

void OpenSandbox(lua_State *L);

long EnsureLuaOnWorker()
{
    if (g_lua != nullptr) return 0;
    g_lua_allocator = {};
    g_lua = lua_newstate(LimitedLuaAllocator, &g_lua_allocator);
    if (g_lua == nullptr) return RTGUM_HOST_ERR_NOMEM;
    OpenSandbox(g_lua);
    return 0;
}

void CloseLuaOnWorker()
{
    if (g_lua != nullptr) {
        lua_close(g_lua);
        g_lua = nullptr;
    }
    g_lua_allocator.used = 0U;
}

long LuaEvalOnWorker(const char *script, std::size_t script_size,
                     char *error, unsigned long error_capacity)
{
    const long ready = EnsureLuaOnWorker();
    if (ready != 0) {
        CopyError("lua_newstate failed", error, error_capacity);
        return ready;
    }
    if (luaL_loadbufferx(g_lua, script, script_size,
                         "rtgum-script", "t") != LUA_OK) {
        CopyError(lua_tostring(g_lua, -1), error, error_capacity);
        lua_pop(g_lua, 1);
        return RTGUM_HOST_ERR_INVAL;
    }
    BeginLuaBudget(g_lua);
    const int called = lua_pcall(g_lua, 0, 1, 0);
    EndLuaBudget(g_lua);
    if (called != LUA_OK) {
        CopyError(lua_tostring(g_lua, -1), error, error_capacity);
        lua_pop(g_lua, 1);
        return RTGUM_HOST_ERR_NXIO;
    }
    if (lua_isnil(g_lua, -1)) {
        CopyError("ok", error, error_capacity);
    } else if (lua_isinteger(g_lua, -1)) {
        char text[64]{};
        std::snprintf(text, sizeof(text), "ok result=%lld",
                      static_cast<long long>(lua_tointeger(g_lua, -1)));
        CopyError(text, error, error_capacity);
    } else if (lua_isstring(g_lua, -1)) {
        CopyError(lua_tostring(g_lua, -1), error, error_capacity);
    } else {
        CopyError("ok", error, error_capacity);
    }
    lua_pop(g_lua, 1);
    return 0;
}

void CompleteCommand(WorkerCommand *command, long result)
{
    pthread_mutex_lock(&g_worker_mutex);
    command->result = result;
    command->done = true;
    if (command->synchronous) pthread_cond_signal(&command->completion);
    pthread_mutex_unlock(&g_worker_mutex);
    if (!command->synchronous) {
        if (result != 0) {
            Log("rtgum-lua: asynchronous script failed");
            if (command->error != nullptr) Log(command->error);
        }
        std::free(command->error);
        std::free(command->script);
        std::free(command);
    }
}

void ReleaseHookEntry(GumHookEntry &entry)
{
    entry.state.store(kHookFree, std::memory_order_release);
    entry.generation.fetch_add(1UL, std::memory_order_acq_rel);
    const int enter = entry.on_enter_ref.exchange(LUA_NOREF, std::memory_order_acq_rel);
    const int leave = entry.on_leave_ref.exchange(LUA_NOREF, std::memory_order_acq_rel);
    if (g_lua != nullptr && enter != LUA_NOREF)
        luaL_unref(g_lua, LUA_REGISTRYINDEX, enter);
    if (g_lua != nullptr && leave != LUA_NOREF)
        luaL_unref(g_lua, LUA_REGISTRYINDEX, leave);
    entry.handle = 0UL;
    entry.target = 0UL;
    entry.symbol[0] = '\0';
}

long RevertHookEntry(GumHookEntry &entry)
{
    unsigned int expected = kHookActive;
    if (!entry.state.compare_exchange_strong(expected, kHookRetiring,
                                              std::memory_order_acq_rel))
        return expected == kHookFree ? RTGUM_HOST_ERR_NOENT : RTGUM_HOST_ERR_BUSY;
    const long result = g_host->gum_intercept_revert(entry.handle);
    if (result != 0 && result != RTGUM_HOST_ERR_NOENT) {
        entry.state.store(kHookActive, std::memory_order_release);
        return result;
    }
    ReleaseHookEntry(entry);
    return 0;
}

void ClearTraceStorage(LuaTraceEntry &entry)
{
    TraceLock(entry);
    for (std::size_t index = 0U; index < kTraceBatchCapacity; ++index)
        FreeStoredBatch(entry.batches[index]);
    entry.head = 0U;
    entry.count = 0U;
    entry.local_dropped.store(0UL, std::memory_order_relaxed);
    TraceUnlock(entry);
}

long StopRuntimeOnWorker()
{
    if (g_stalker_active && RTGUM_HOST_FIELD_AVAILABLE(dbi_stalker_stop)) {
        const long stopped = g_host->dbi_stalker_stop();
        if (stopped != 0) return stopped;
        g_stalker_active = false;
        g_stalker_steps.clear();
        g_stalker_stats = {};
    }
    if (RTGUM_HOST_FIELD_AVAILABLE(trace_stop)) {
        for (LuaTraceEntry &entry : g_trace_entries) {
            if (entry.state.load(std::memory_order_acquire) != kHookActive) continue;
            entry.state.store(kHookRetiring, std::memory_order_release);
            long stopped = RTGUM_HOST_ERR_BUSY;
            for (unsigned int retry = 0U; retry < 5000U; ++retry) {
                stopped = g_host->trace_stop(entry.handle);
                if (stopped != RTGUM_HOST_ERR_BUSY) break;
                usleep(1000);
            }
            if (stopped != 0 && stopped != RTGUM_HOST_ERR_NOENT) {
                entry.state.store(kHookActive, std::memory_order_release);
                return stopped;
            }
            entry.state.store(kHookFree, std::memory_order_release);
            entry.generation.fetch_add(1UL, std::memory_order_acq_rel);
            entry.handle = 0UL;
            ClearTraceStorage(entry);
        }
    }
    if (GumAvailable()) {
        for (GumHookEntry &entry : g_gum_hooks) {
            if (entry.state.load(std::memory_order_acquire) != kHookActive) continue;
            const long reverted = RevertHookEntry(entry);
            if (reverted != 0) return reverted;
        }
        if (RTGUM_HOST_FIELD_AVAILABLE(gum_memory_free)) {
            for (LuaAllocationEntry &allocation : g_lua_allocations) {
                if (allocation.address == 0UL) continue;
                const long freed = g_host->gum_memory_free(allocation.address);
                if (freed != 0 && freed != RTGUM_HOST_ERR_NOENT) return freed;
                allocation.address = 0UL;
            }
        }
    }
    CallbackEvent discarded{};
    while (DequeueCallback(discarded))
        g_callback_stale_drops.fetch_add(1UL, std::memory_order_relaxed);
    CloseLuaOnWorker();
    return 0;
}

void *LuaWorkerMain(void *)
{
    g_worker_key.store(CurrentThreadKey(), std::memory_order_release);
    pthread_mutex_lock(&g_worker_mutex);
    g_worker_running = true;
    g_worker_accepting = true;
    pthread_cond_broadcast(&g_worker_condition);
    pthread_mutex_unlock(&g_worker_mutex);
    for (;;) {
        WorkerCommand *command = nullptr;
        pthread_mutex_lock(&g_worker_mutex);
        if (g_command_head == nullptr) {
            timespec wake{};
            clock_gettime(CLOCK_REALTIME, &wake);
            wake.tv_nsec += 2000000L;
            if (wake.tv_nsec >= 1000000000L) {
                ++wake.tv_sec;
                wake.tv_nsec -= 1000000000L;
            }
            (void)pthread_cond_timedwait(&g_worker_condition, &g_worker_mutex, &wake);
        }
        if (g_command_head != nullptr) {
            command = g_command_head;
            g_command_head = command->next;
            if (g_command_head == nullptr) g_command_tail = nullptr;
            if (g_command_count != 0U) --g_command_count;
        }
        pthread_mutex_unlock(&g_worker_mutex);
        DrainCallbackQueue(64U);
        if (command == nullptr) continue;
        if (command->kind == WorkerCommandKind::kEval) {
            const long result = LuaEvalOnWorker(command->script, command->script_size,
                                                command->error, command->error_capacity);
            CompleteCommand(command, result);
            continue;
        }
        const long stopped = StopRuntimeOnWorker();
        if (stopped != 0) {
            pthread_mutex_lock(&g_worker_mutex);
            g_worker_accepting = true;
            pthread_mutex_unlock(&g_worker_mutex);
            CompleteCommand(command, stopped);
            continue;
        }
        pthread_mutex_lock(&g_worker_mutex);
        g_worker_running = false;
        g_worker_accepting = false;
        command->result = 0;
        command->done = true;
        pthread_cond_signal(&command->completion);
        pthread_cond_broadcast(&g_worker_condition);
        pthread_mutex_unlock(&g_worker_mutex);
        g_worker_key.store(0UL, std::memory_order_release);
        return nullptr;
    }
}

long EnsureWorker()
{
    pthread_mutex_lock(&g_worker_mutex);
    if (g_worker_running) {
        const bool accepting = g_worker_accepting;
        pthread_mutex_unlock(&g_worker_mutex);
        return accepting ? 0 : RTGUM_HOST_ERR_BUSY;
    }
    if (g_worker_joinable) {
        pthread_mutex_unlock(&g_worker_mutex);
        return RTGUM_HOST_ERR_BUSY;
    }
    InitializeCallbackQueue();
    g_command_head = nullptr;
    g_command_tail = nullptr;
    g_command_count = 0U;
    if (pthread_create(&g_worker_thread, nullptr, LuaWorkerMain, nullptr) != 0) {
        pthread_mutex_unlock(&g_worker_mutex);
        return RTGUM_HOST_ERR_NXIO;
    }
    g_worker_joinable = true;
    while (!g_worker_running)
        pthread_cond_wait(&g_worker_condition, &g_worker_mutex);
    pthread_mutex_unlock(&g_worker_mutex);
    return 0;
}

bool ValidateScript(const char *script, std::size_t &size,
                    char *error, unsigned long error_capacity)
{
    if (script == nullptr) {
        CopyError("null script", error, error_capacity);
        return false;
    }
    size = 0U;
    while (size <= kMaximumScriptBytes && script[size] != '\0') ++size;
    if (size > kMaximumScriptBytes) {
        CopyError("Lua script is too large", error, error_capacity);
        return false;
    }
    return true;
}

WorkerCommand *CreateEvalCommand(const char *script, std::size_t size,
                                 char *error, unsigned long error_capacity,
                                 bool synchronous)
{
    auto *command = static_cast<WorkerCommand *>(std::calloc(1U, sizeof(WorkerCommand)));
    if (command == nullptr) return nullptr;
    command->script = static_cast<char *>(std::malloc(size + 1U));
    if (command->script == nullptr) {
        std::free(command);
        return nullptr;
    }
    std::memcpy(command->script, script, size + 1U);
    command->script_size = size;
    command->kind = WorkerCommandKind::kEval;
    command->synchronous = synchronous;
    if (synchronous) {
        command->error = error;
        command->error_capacity = error_capacity;
        pthread_cond_init(&command->completion, nullptr);
    } else {
        command->error_capacity = 512UL;
        command->error = static_cast<char *>(std::calloc(512U, 1U));
    }
    return command;
}

long QueueEval(const char *script, char *error, unsigned long error_capacity,
               bool synchronous)
{
    std::size_t size = 0U;
    if (!ValidateScript(script, size, error, error_capacity))
        return RTGUM_HOST_ERR_INVAL;
    const long started = EnsureWorker();
    if (started != 0) return started;
    if (g_worker_key.load(std::memory_order_acquire) == CurrentThreadKey()) {
        CopyError("Lua VM is busy", error, error_capacity);
        return RTGUM_HOST_ERR_BUSY;
    }
    WorkerCommand *command = CreateEvalCommand(script, size, error, error_capacity,
                                                synchronous);
    if (command == nullptr) {
        CopyError("Lua command allocation failed", error, error_capacity);
        return RTGUM_HOST_ERR_NOMEM;
    }
    pthread_mutex_lock(&g_worker_mutex);
    if (!g_worker_running || !g_worker_accepting) {
        pthread_mutex_unlock(&g_worker_mutex);
        if (synchronous) pthread_cond_destroy(&command->completion);
        if (!synchronous) std::free(command->error);
        std::free(command->script);
        std::free(command);
        return RTGUM_HOST_ERR_BUSY;
    }
    if (g_command_count >= kMaximumPendingCommands) {
        pthread_mutex_unlock(&g_worker_mutex);
        if (synchronous) pthread_cond_destroy(&command->completion);
        if (!synchronous) std::free(command->error);
        std::free(command->script);
        std::free(command);
        CopyError("Lua command queue is full", error, error_capacity);
        return RTGUM_HOST_ERR_AGAIN;
    }
    if (g_command_tail != nullptr) g_command_tail->next = command;
    else g_command_head = command;
    g_command_tail = command;
    ++g_command_count;
    pthread_cond_signal(&g_worker_condition);
    if (!synchronous) {
        pthread_mutex_unlock(&g_worker_mutex);
        CopyError("async queued", error, error_capacity);
        return 0;
    }
    while (!command->done)
        pthread_cond_wait(&command->completion, &g_worker_mutex);
    const long result = command->result;
    pthread_mutex_unlock(&g_worker_mutex);
    pthread_cond_destroy(&command->completion);
    std::free(command->script);
    std::free(command);
    return result;
}

long LuaEval(const char *script, char *error, unsigned long error_capacity)
{
    return QueueEval(script, error, error_capacity, true);
}

long AsyncLuaEval(const char *script, char *error, unsigned long error_capacity)
{
    return QueueEval(script, error, error_capacity, false);
}

long LuaStop()
{
    if (g_worker_key.load(std::memory_order_acquire) == CurrentThreadKey())
        return RTGUM_HOST_ERR_BUSY;
    pthread_mutex_lock(&g_worker_mutex);
    if (!g_worker_running) {
        pthread_mutex_unlock(&g_worker_mutex);
        return 0;
    }
    if (!g_worker_accepting) {
        pthread_mutex_unlock(&g_worker_mutex);
        return RTGUM_HOST_ERR_BUSY;
    }
    g_worker_accepting = false;
    auto *command = static_cast<WorkerCommand *>(std::calloc(1U, sizeof(WorkerCommand)));
    if (command == nullptr) {
        g_worker_accepting = true;
        pthread_mutex_unlock(&g_worker_mutex);
        return RTGUM_HOST_ERR_NOMEM;
    }
    command->kind = WorkerCommandKind::kStop;
    command->synchronous = true;
    pthread_cond_init(&command->completion, nullptr);
    if (g_command_tail != nullptr) g_command_tail->next = command;
    else g_command_head = command;
    g_command_tail = command;
    ++g_command_count;
    pthread_cond_signal(&g_worker_condition);
    while (!command->done)
        pthread_cond_wait(&command->completion, &g_worker_mutex);
    const long result = command->result;
    pthread_mutex_unlock(&g_worker_mutex);
    pthread_cond_destroy(&command->completion);
    std::free(command);
    if (result != 0) return result;
    pthread_join(g_worker_thread, nullptr);
    pthread_mutex_lock(&g_worker_mutex);
    g_worker_joinable = false;
    pthread_mutex_unlock(&g_worker_mutex);
    return 0;
}

int LuaLog(lua_State *L)
{
    Log(luaL_checkstring(L, 1));
    return 0;
}

int LuaFindExport(lua_State *L)
{
    if (g_host == nullptr ||
        (g_host->capabilities & RTGUM_HOST_CAP_FIND_EXPORT) == 0UL ||
        !RTGUM_HOST_FIELD_AVAILABLE(find_export))
        return luaL_error(L, "find_export unavailable");
    unsigned long address = 0UL;
    const long result = g_host->find_export(luaL_checkstring(L, 1),
                                             luaL_checkstring(L, 2), &address);
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    lua_pushinteger(L, static_cast<lua_Integer>(address));
    return 2;
}

int LuaHookSymbol(lua_State *L)
{
    if (g_host == nullptr ||
        (g_host->capabilities & RTGUM_HOST_CAP_NATIVE_SYMBOL) == 0UL ||
        !RTGUM_HOST_FIELD_AVAILABLE(hook_native_symbol))
        return luaL_error(L, "hook_native_symbol unavailable");
    const lua_Integer replacement = luaL_checkinteger(L, 3);
    if (replacement == 0) return luaL_error(L, "invalid replacement address");
    unsigned long original = 0UL;
    unsigned long handle = 0UL;
    const long result = g_host->hook_native_symbol(
        luaL_checkstring(L, 1), luaL_checkstring(L, 2),
        static_cast<unsigned long>(replacement), &original, &handle);
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    lua_pushinteger(L, static_cast<lua_Integer>(original));
    lua_pushinteger(L, static_cast<lua_Integer>(handle));
    return 3;
}

int LuaRevert(lua_State *L)
{
    if (g_host == nullptr ||
        (g_host->capabilities & RTGUM_HOST_CAP_NATIVE_REPLACE) == 0UL ||
        !RTGUM_HOST_FIELD_AVAILABLE(hook_native_revert))
        return luaL_error(L, "hook_native_revert unavailable");
    const lua_Integer handle = luaL_checkinteger(L, 1);
    if (handle <= 0) return luaL_error(L, "invalid hook handle");
    lua_pushinteger(L, static_cast<lua_Integer>(
        g_host->hook_native_revert(static_cast<unsigned long>(handle))));
    return 1;
}

GumHookEntry *ReserveHookEntry(int enter_ref, int leave_ref,
                               const char *symbol, std::size_t &slot,
                               unsigned long &generation)
{
    for (std::size_t index = 0U; index < kMaximumGumHooks; ++index) {
        GumHookEntry &entry = g_gum_hooks[index];
        unsigned int expected = kHookFree;
        if (!entry.state.compare_exchange_strong(expected, kHookRetiring,
                                                  std::memory_order_acq_rel))
            continue;
        generation = g_hook_generation.fetch_add(1UL, std::memory_order_acq_rel) &
                     0xffffffffUL;
        if (generation == 0UL)
            generation = g_hook_generation.fetch_add(1UL, std::memory_order_acq_rel) &
                         0xffffffffUL;
        entry.generation.store(generation, std::memory_order_release);
        entry.on_enter_ref.store(enter_ref, std::memory_order_release);
        entry.on_leave_ref.store(leave_ref, std::memory_order_release);
        entry.handle = 0UL;
        entry.target = 0UL;
        entry.symbol[0] = '\0';
        if (symbol != nullptr)
            std::snprintf(entry.symbol, sizeof(entry.symbol), "%s", symbol);
        slot = index;
        return &entry;
    }
    return nullptr;
}

void AbandonReservedHook(GumHookEntry &entry) { ReleaseHookEntry(entry); }

int PushAttachResult(lua_State *L, unsigned long target,
                     const char *symbol, int enter_ref, int leave_ref)
{
    std::size_t slot = 0U;
    unsigned long generation = 0UL;
    GumHookEntry *entry = ReserveHookEntry(enter_ref, leave_ref, symbol,
                                           slot, generation);
    if (entry == nullptr) {
        if (enter_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, enter_ref);
        if (leave_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, leave_ref);
        return luaL_error(L, "gum hook table full");
    }
    entry->kind = GumHookKind::kAttach;
    entry->target = target;
    entry->state.store(kHookActive, std::memory_order_release);
    unsigned long handle = 0UL;
    const long result = g_host->gum_intercept_attach_address(
        target, GumOnEnter, GumOnLeave, EncodeCookie(slot, generation), &handle);
    if (result != 0) {
        entry->state.store(kHookRetiring, std::memory_order_release);
        AbandonReservedHook(*entry);
        lua_pushinteger(L, static_cast<lua_Integer>(result));
        lua_pushinteger(L, 0);
        return 2;
    }
    entry->handle = handle;
    lua_pushinteger(L, 0);
    lua_pushinteger(L, static_cast<lua_Integer>(handle));
    return 2;
}

int LuaGumFindExport(lua_State *L)
{
    if (!GumAvailable()) return luaL_error(L, "gum backend unavailable");
    unsigned long address = 0UL;
    const long result = g_host->gum_find_export(
        luaL_checkstring(L, 1), luaL_checkstring(L, 2), &address);
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    lua_pushinteger(L, static_cast<lua_Integer>(address));
    return 2;
}

int LuaGumAttach(lua_State *L)
{
    if (!GumAvailable()) return luaL_error(L, "gum backend unavailable");
    const char *soname = luaL_checkstring(L, 1);
    const char *symbol = luaL_checkstring(L, 2);
    const int enter_ref = lua_isfunction(L, 3)
        ? (lua_pushvalue(L, 3), luaL_ref(L, LUA_REGISTRYINDEX)) : LUA_NOREF;
    const int leave_ref = lua_isfunction(L, 4)
        ? (lua_pushvalue(L, 4), luaL_ref(L, LUA_REGISTRYINDEX)) : LUA_NOREF;
    unsigned long target = 0UL;
    const long found = g_host->gum_find_export(soname, symbol, &target);
    if (found != 0 || target == 0UL) {
        if (enter_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, enter_ref);
        if (leave_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, leave_ref);
        lua_pushinteger(L, static_cast<lua_Integer>(
            found != 0 ? found : RTGUM_HOST_ERR_NOENT));
        lua_pushinteger(L, 0);
        return 2;
    }
    return PushAttachResult(L, target, symbol, enter_ref, leave_ref);
}

int LuaGumAttachAddress(lua_State *L)
{
    if (!GumAvailable()) return luaL_error(L, "gum backend unavailable");
    const lua_Integer address = luaL_checkinteger(L, 1);
    if (address == 0) return luaL_error(L, "invalid hook address");
    const int enter_ref = lua_isfunction(L, 2)
        ? (lua_pushvalue(L, 2), luaL_ref(L, LUA_REGISTRYINDEX)) : LUA_NOREF;
    const int leave_ref = lua_isfunction(L, 3)
        ? (lua_pushvalue(L, 3), luaL_ref(L, LUA_REGISTRYINDEX)) : LUA_NOREF;
    return PushAttachResult(L, static_cast<unsigned long>(address),
                            "<address>", enter_ref, leave_ref);
}

GumHookEntry *FindHookByHandle(unsigned long handle)
{
    for (GumHookEntry &entry : g_gum_hooks)
        if (entry.state.load(std::memory_order_acquire) == kHookActive &&
            entry.handle == handle)
            return &entry;
    return nullptr;
}

int LuaGumRevert(lua_State *L)
{
    if (!GumAvailable()) return luaL_error(L, "gum backend unavailable");
    const lua_Integer raw = luaL_checkinteger(L, 1);
    if (raw <= 0) return luaL_error(L, "invalid gum handle");
    GumHookEntry *entry = FindHookByHandle(static_cast<unsigned long>(raw));
    const long result = entry != nullptr ? RevertHookEntry(*entry)
                                         : RTGUM_HOST_ERR_NOENT;
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    return 1;
}

int LuaGumClearAll(lua_State *L)
{
    if (!GumAvailable()) return luaL_error(L, "gum backend unavailable");
    unsigned long reverted = 0UL;
    long first_error = 0L;
    for (GumHookEntry &entry : g_gum_hooks) {
        if (entry.state.load(std::memory_order_acquire) != kHookActive) continue;
        const long result = RevertHookEntry(entry);
        if (result == 0) ++reverted;
        else if (first_error == 0L) first_error = result;
    }
    lua_pushinteger(L, static_cast<lua_Integer>(first_error));
    lua_pushinteger(L, static_cast<lua_Integer>(reverted));
    return 2;
}

int LuaGumReplace(lua_State *L)
{
    if (!GumAvailable() || !RTGUM_HOST_FIELD_AVAILABLE(gum_replace))
        return luaL_error(L, "gum replace unavailable");
    const lua_Integer target = luaL_checkinteger(L, 1);
    const lua_Integer replacement = luaL_checkinteger(L, 2);
    if (target == 0 || replacement == 0)
        return luaL_error(L, "invalid replace address");
    std::size_t slot = 0U;
    unsigned long generation = 0UL;
    GumHookEntry *entry = ReserveHookEntry(LUA_NOREF, LUA_NOREF, "<replace>",
                                           slot, generation);
    if (entry == nullptr) return luaL_error(L, "gum hook table full");
    unsigned long original = 0UL;
    unsigned long handle = 0UL;
    const long result = g_host->gum_replace(
        static_cast<unsigned long>(target), static_cast<unsigned long>(replacement),
        &original, &handle);
    if (result != 0) {
        AbandonReservedHook(*entry);
    } else {
        entry->kind = GumHookKind::kReplace;
        entry->target = static_cast<unsigned long>(target);
        entry->handle = handle;
        entry->state.store(kHookActive, std::memory_order_release);
    }
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    lua_pushinteger(L, static_cast<lua_Integer>(original));
    lua_pushinteger(L, static_cast<lua_Integer>(handle));
    return 3;
}

int LuaGumMemoryRead(lua_State *L)
{
    if (!GumAvailable() || !RTGUM_HOST_FIELD_AVAILABLE(gum_memory_read))
        return luaL_error(L, "gum memory read unavailable");
    const lua_Integer address = luaL_checkinteger(L, 1);
    const lua_Integer length = luaL_checkinteger(L, 2);
    if (address == 0 || length <= 0 ||
        static_cast<unsigned long>(length) > kMaximumMemoryTransfer)
        return luaL_error(L, "invalid memory read range");
    std::vector<char> buffer(static_cast<std::size_t>(length));
    const long result = g_host->gum_memory_read(
        static_cast<unsigned long>(address), buffer.data(),
        static_cast<unsigned long>(length));
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    if (result == 0) lua_pushlstring(L, buffer.data(), static_cast<std::size_t>(length));
    else lua_pushnil(L);
    return 2;
}

int LuaGumMemoryWrite(lua_State *L)
{
    if (!GumAvailable() || !RTGUM_HOST_FIELD_AVAILABLE(gum_memory_write))
        return luaL_error(L, "gum memory write unavailable");
    const lua_Integer address = luaL_checkinteger(L, 1);
    std::size_t length = 0U;
    const char *bytes = luaL_checklstring(L, 2, &length);
    if (address == 0 || length == 0U || length > kMaximumMemoryTransfer)
        return luaL_error(L, "invalid memory write range");
    lua_pushinteger(L, static_cast<lua_Integer>(g_host->gum_memory_write(
        static_cast<unsigned long>(address), bytes,
        static_cast<unsigned long>(length))));
    return 1;
}

int LuaGumReadCString(lua_State *L)
{
    if (!GumAvailable() || !RTGUM_HOST_FIELD_AVAILABLE(gum_memory_read))
        return luaL_error(L, "gum memory read unavailable");
    const lua_Integer address = luaL_checkinteger(L, 1);
    const lua_Integer maximum = luaL_optinteger(L, 2, 4096);
    if (address == 0 || maximum <= 0 ||
        static_cast<unsigned long>(maximum) > kMaximumMemoryTransfer)
        return luaL_error(L, "invalid cstring range");
    std::vector<char> value;
    value.reserve(static_cast<std::size_t>(maximum));
    unsigned long current = static_cast<unsigned long>(address);
    unsigned long remaining = static_cast<unsigned long>(maximum);
    long result = 0L;
    bool terminated = false;
    while (remaining != 0UL && !terminated) {
        char chunk_buffer[256]{};
        unsigned long chunk = 4096UL - (current & 4095UL);
        if (chunk > remaining) chunk = remaining;
        if (chunk > sizeof(chunk_buffer)) chunk = sizeof(chunk_buffer);
        result = g_host->gum_memory_read(current, chunk_buffer, chunk);
        if (result != 0) break;
        unsigned long used = 0UL;
        while (used < chunk && chunk_buffer[used] != '\0') ++used;
        value.insert(value.end(), chunk_buffer, chunk_buffer + used);
        terminated = used != chunk;
        current += chunk;
        remaining -= chunk;
    }
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    if (result != 0) lua_pushnil(L);
    else lua_pushlstring(L, value.data(), value.size());
    return 2;
}

int LuaGumMemoryAlloc(lua_State *L)
{
    if (!GumAvailable() || !RTGUM_HOST_FIELD_AVAILABLE(gum_memory_alloc))
        return luaL_error(L, "gum memory alloc unavailable");
    const lua_Integer size = luaL_checkinteger(L, 1);
    if (size <= 0 || static_cast<unsigned long>(size) > kMaximumMemoryTransfer)
        return luaL_error(L, "invalid allocation size");
    LuaAllocationEntry *slot = nullptr;
    for (LuaAllocationEntry &entry : g_lua_allocations)
        if (entry.address == 0UL) { slot = &entry; break; }
    if (slot == nullptr) return luaL_error(L, "gum allocation table full");
    unsigned long address = 0UL;
    const long result = g_host->gum_memory_alloc(static_cast<unsigned long>(size),
                                                  &address);
    if (result == 0 && address != 0UL) slot->address = address;
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    lua_pushinteger(L, static_cast<lua_Integer>(address));
    return 2;
}

int LuaGumMemoryFree(lua_State *L)
{
    if (!GumAvailable() || !RTGUM_HOST_FIELD_AVAILABLE(gum_memory_free))
        return luaL_error(L, "gum memory free unavailable");
    const lua_Integer address = luaL_checkinteger(L, 1);
    if (address == 0) return luaL_error(L, "invalid allocation address");
    LuaAllocationEntry *slot = nullptr;
    for (LuaAllocationEntry &entry : g_lua_allocations)
        if (entry.address == static_cast<unsigned long>(address)) {
            slot = &entry;
            break;
        }
    if (slot == nullptr) {
        lua_pushinteger(L, static_cast<lua_Integer>(RTGUM_HOST_ERR_NOENT));
        return 1;
    }
    const long result = g_host->gum_memory_free(slot->address);
    if (result == 0 || result == RTGUM_HOST_ERR_NOENT) slot->address = 0UL;
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    return 1;
}

int LuaGumCall(lua_State *L)
{
    if (!GumAvailable()) return luaL_error(L, "gum backend unavailable");
    const int count = lua_gettop(L);
    if (count < 1 || count > 9)
        return luaL_error(L, "gum_call expects address and up to 8 arguments");
    const lua_Integer raw_address = luaL_checkinteger(L, 1);
    if (raw_address == 0) return luaL_error(L, "invalid call address");
    unsigned long arguments[8]{};
    for (int index = 1; index < count; ++index)
        arguments[index - 1] = static_cast<unsigned long>(
            luaL_checkinteger(L, index + 1));
    using Function = unsigned long (*)(unsigned long, unsigned long,
                                        unsigned long, unsigned long,
                                        unsigned long, unsigned long,
                                        unsigned long, unsigned long);
    auto function = reinterpret_cast<Function>(
        static_cast<unsigned long>(raw_address));
    const unsigned long result = function(
        arguments[0], arguments[1], arguments[2], arguments[3],
        arguments[4], arguments[5], arguments[6], arguments[7]);
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    return 1;
}

void PushStalkerStats(lua_State *L)
{
    lua_newtable(L);
#define RTGUM_PUSH_STALKER_FIELD(field)                                        \
    lua_pushinteger(L, static_cast<lua_Integer>(g_stalker_stats.field));       \
    lua_setfield(L, -2, #field)
    RTGUM_PUSH_STALKER_FIELD(blocks);
    RTGUM_PUSH_STALKER_FIELD(calls);
    RTGUM_PUSH_STALKER_FIELD(returns);
    RTGUM_PUSH_STALKER_FIELD(compiled);
    RTGUM_PUSH_STALKER_FIELD(matched_returns);
    RTGUM_PUSH_STALKER_FIELD(mismatched_returns);
    RTGUM_PUSH_STALKER_FIELD(unpaired_returns);
    RTGUM_PUSH_STALKER_FIELD(unwound_frames);
    RTGUM_PUSH_STALKER_FIELD(pac_checks);
    RTGUM_PUSH_STALKER_FIELD(bti_checks);
    RTGUM_PUSH_STALKER_FIELD(bti_guarded);
    RTGUM_PUSH_STALKER_FIELD(bti_rejected);
    RTGUM_PUSH_STALKER_FIELD(gtrace_count);
    RTGUM_PUSH_STALKER_FIELD(gtrace_total);
    RTGUM_PUSH_STALKER_FIELD(gtrace_dropped);
#undef RTGUM_PUSH_STALKER_FIELD
}

int LuaGumStalkerStart(lua_State *L)
{
    if (!GumAvailable() || !RTGUM_HOST_FIELD_AVAILABLE(dbi_stalker_start))
        return luaL_error(L, "gum stalker unavailable");
    if (g_stalker_active) {
        lua_pushinteger(L, static_cast<lua_Integer>(RTGUM_HOST_ERR_BUSY));
        return 1;
    }
    const lua_Integer start = luaL_checkinteger(L, 1);
    const lua_Integer size = luaL_checkinteger(L, 2);
    const lua_Integer capacity = luaL_optinteger(L, 3, 0);
    if (start == 0 || size <= 0 || capacity < 0 || capacity > 4096)
        return luaL_error(L, "invalid stalker range");
    g_stalker_stats = {};
    g_stalker_steps.assign(static_cast<std::size_t>(capacity), RtGumGtraceStep{});
    if (!g_stalker_steps.empty()) {
        g_stalker_stats.gtrace_buffer = g_stalker_steps.data();
        g_stalker_stats.gtrace_capacity = g_stalker_steps.size();
    }
    const long result = g_host->dbi_stalker_start(
        &g_stalker_stats, static_cast<unsigned long>(start),
        static_cast<unsigned long>(size));
    if (result == 0) g_stalker_active = true;
    else g_stalker_steps.clear();
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    return 1;
}

int LuaGumStalkerInvalidate(lua_State *L)
{
    if (!g_stalker_active || !RTGUM_HOST_FIELD_AVAILABLE(dbi_stalker_invalidate))
        return luaL_error(L, "gum stalker inactive");
    const lua_Integer address = luaL_checkinteger(L, 1);
    if (address == 0) return luaL_error(L, "invalid invalidate address");
    lua_pushinteger(L, static_cast<lua_Integer>(
        g_host->dbi_stalker_invalidate(static_cast<unsigned long>(address))));
    return 1;
}

int LuaGumStalkerStop(lua_State *L)
{
    if (!g_stalker_active || !RTGUM_HOST_FIELD_AVAILABLE(dbi_stalker_stop)) {
        lua_pushinteger(L, static_cast<lua_Integer>(RTGUM_HOST_ERR_NOENT));
        lua_pushnil(L);
        return 2;
    }
    const long result = g_host->dbi_stalker_stop();
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    if (result == 0) {
        g_stalker_active = false;
        PushStalkerStats(L);
        g_stalker_steps.clear();
    } else lua_pushnil(L);
    return 2;
}

unsigned long TableUnsigned(lua_State *L, int table, const char *field,
                            unsigned long fallback, bool required)
{
    lua_getfield(L, table, field);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        if (required) luaL_error(L, "missing trace field '%s'", field);
        return fallback;
    }
    const lua_Integer value = luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    if (value < 0) luaL_error(L, "negative trace field '%s'", field);
    return static_cast<unsigned long>(value);
}

unsigned long TableAddress(lua_State *L, int table, const char *field,
                           bool required)
{
    lua_getfield(L, table, field);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        if (required) luaL_error(L, "missing trace field '%s'", field);
        return 0UL;
    }
    const lua_Integer value = luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    if (value == 0 && required)
        luaL_error(L, "zero trace address '%s'", field);
    return static_cast<unsigned long>(value);
}

LuaTraceEntry *FindTraceEntry(unsigned long handle)
{
    for (LuaTraceEntry &entry : g_trace_entries) {
        const unsigned int state = entry.state.load(std::memory_order_acquire);
        if ((state == kHookActive || state == kHookRetiring) &&
            entry.handle == handle) return &entry;
    }
    return nullptr;
}

int LuaGumTraceStart(lua_State *L)
{
    if (!GumAvailable() || !RTGUM_HOST_FIELD_AVAILABLE(trace_start))
        return luaL_error(L, "gum trace unavailable");
    luaL_checktype(L, 1, LUA_TTABLE);
    LuaTraceEntry *entry = nullptr;
    std::size_t slot = 0U;
    for (std::size_t index = 0U; index < kMaximumTraceEntries; ++index) {
        unsigned int expected = kHookFree;
        if (g_trace_entries[index].state.compare_exchange_strong(
                expected, kHookRetiring, std::memory_order_acq_rel)) {
            entry = &g_trace_entries[index];
            slot = index;
            break;
        }
    }
    if (entry == nullptr) return luaL_error(L, "gum trace table full");
    ClearTraceStorage(*entry);
    unsigned long generation = g_trace_generation.fetch_add(
        1UL, std::memory_order_acq_rel) & 0xffffffffUL;
    if (generation == 0UL)
        generation = g_trace_generation.fetch_add(
            1UL, std::memory_order_acq_rel) & 0xffffffffUL;
    entry->generation.store(generation, std::memory_order_release);
    RtGumTraceConfig config{};
    config.version = RTGUM_TRACE_CONFIG_VERSION;
    config.size = sizeof(config);
    config.target = TableAddress(L, 1, "target", true);
    config.watched_start = TableAddress(L, 1, "watched_start", true);
    config.watched_size = TableUnsigned(L, 1, "watched_size", 0UL, true);
    config.trace_mode = static_cast<unsigned int>(TableUnsigned(
        L, 1, "trace_mode", RTGUM_TRACE_MODE_EXECUTED_PATH, false));
    config.mem_read_mode = static_cast<unsigned int>(TableUnsigned(
        L, 1, "mem_read_mode", RTGUM_TRACE_MEM_READ_CODE, false));
    config.step_capacity = TableUnsigned(L, 1, "step_capacity", 256UL, false);
    config.writer = TraceWriter;
    config.writer_user_data = EncodeCookie(slot, generation);
    entry->state.store(kHookActive, std::memory_order_release);
    unsigned long handle = 0UL;
    const long result = g_host->trace_start(&config, &handle);
    if (result != 0) {
        entry->state.store(kHookFree, std::memory_order_release);
        entry->generation.fetch_add(1UL, std::memory_order_acq_rel);
    } else entry->handle = handle;
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    lua_pushinteger(L, static_cast<lua_Integer>(handle));
    return 2;
}

void PushTraceStep(lua_State *L, const RtGumGtraceStep &step)
{
    lua_newtable(L);
    lua_pushinteger(L, static_cast<lua_Integer>(step.sequence));
    lua_setfield(L, -2, "sequence");
    lua_pushinteger(L, static_cast<lua_Integer>(step.pc));
    lua_setfield(L, -2, "pc");
    lua_pushinteger(L, static_cast<lua_Integer>(step.next_pc));
    lua_setfield(L, -2, "next_pc");
    lua_pushinteger(L, static_cast<lua_Integer>(step.instruction));
    lua_setfield(L, -2, "instruction");
    lua_pushinteger(L, static_cast<lua_Integer>(step.flags));
    lua_setfield(L, -2, "flags");
}

void PushTraceBatch(lua_State *L, StoredTraceBatch &stored)
{
    const RtGumTraceBatch &batch = stored.batch;
    lua_newtable(L);
#define RTGUM_PUSH_BATCH_FIELD(field)                                          \
    lua_pushinteger(L, static_cast<lua_Integer>(batch.field));                 \
    lua_setfield(L, -2, #field)
    RTGUM_PUSH_BATCH_FIELD(handle);
    RTGUM_PUSH_BATCH_FIELD(target);
    RTGUM_PUSH_BATCH_FIELD(invocation);
    RTGUM_PUSH_BATCH_FIELD(thread_id);
    RTGUM_PUSH_BATCH_FIELD(trace_mode);
    RTGUM_PUSH_BATCH_FIELD(mem_read_mode);
    RTGUM_PUSH_BATCH_FIELD(result);
    RTGUM_PUSH_BATCH_FIELD(count);
    RTGUM_PUSH_BATCH_FIELD(total);
    RTGUM_PUSH_BATCH_FIELD(dropped);
    RTGUM_PUSH_BATCH_FIELD(blocks);
    RTGUM_PUSH_BATCH_FIELD(calls);
    RTGUM_PUSH_BATCH_FIELD(returns);
    RTGUM_PUSH_BATCH_FIELD(compiled);
#undef RTGUM_PUSH_BATCH_FIELD
    lua_newtable(L);
    for (unsigned long index = 0UL; index < batch.count; ++index) {
        PushTraceStep(L, stored.steps[index]);
        lua_rawseti(L, -2, static_cast<lua_Integer>(index + 1UL));
    }
    lua_setfield(L, -2, "steps");
}

void PushTraceBatches(lua_State *L, LuaTraceEntry &entry, std::size_t maximum)
{
    lua_newtable(L);
    std::size_t emitted = 0U;
    while (emitted < maximum) {
        StoredTraceBatch stored{};
        TraceLock(entry);
        if (entry.count == 0U) {
            TraceUnlock(entry);
            break;
        }
        stored = entry.batches[entry.head];
        entry.batches[entry.head] = {};
        entry.head = (entry.head + 1U) % kTraceBatchCapacity;
        --entry.count;
        TraceUnlock(entry);
        PushTraceBatch(L, stored);
        lua_rawseti(L, -2, static_cast<lua_Integer>(emitted + 1U));
        FreeStoredBatch(stored);
        ++emitted;
    }
}

int LuaGumTraceRead(lua_State *L)
{
    const lua_Integer raw = luaL_checkinteger(L, 1);
    const lua_Integer maximum = luaL_optinteger(L, 2, kTraceBatchCapacity);
    if (raw <= 0 || maximum <= 0 || maximum > 64)
        return luaL_error(L, "invalid trace read");
    LuaTraceEntry *entry = FindTraceEntry(static_cast<unsigned long>(raw));
    if (entry == nullptr) {
        lua_pushinteger(L, static_cast<lua_Integer>(RTGUM_HOST_ERR_NOENT));
        lua_pushnil(L);
        return 2;
    }
    lua_pushinteger(L, 0);
    PushTraceBatches(L, *entry, static_cast<std::size_t>(maximum));
    return 2;
}

void PushTraceStats(lua_State *L, const RtGumTraceStats &stats,
                    LuaTraceEntry &entry)
{
    lua_newtable(L);
#define RTGUM_PUSH_TRACE_FIELD(field)                                          \
    lua_pushinteger(L, static_cast<lua_Integer>(stats.field));                 \
    lua_setfield(L, -2, #field)
    RTGUM_PUSH_TRACE_FIELD(handle);
    RTGUM_PUSH_TRACE_FIELD(target);
    RTGUM_PUSH_TRACE_FIELD(invocations);
    RTGUM_PUSH_TRACE_FIELD(completed);
    RTGUM_PUSH_TRACE_FIELD(busy);
    RTGUM_PUSH_TRACE_FIELD(failures);
    RTGUM_PUSH_TRACE_FIELD(writer_errors);
    RTGUM_PUSH_TRACE_FIELD(active);
    RTGUM_PUSH_TRACE_FIELD(trace_mode);
    RTGUM_PUSH_TRACE_FIELD(mem_read_mode);
    RTGUM_PUSH_TRACE_FIELD(retiring);
#undef RTGUM_PUSH_TRACE_FIELD
    TraceLock(entry);
    lua_pushinteger(L, static_cast<lua_Integer>(entry.count));
    lua_setfield(L, -2, "queued_batches");
    lua_pushinteger(L, static_cast<lua_Integer>(
        entry.local_dropped.load(std::memory_order_relaxed)));
    lua_setfield(L, -2, "local_dropped");
    TraceUnlock(entry);
}

int LuaGumTraceQuery(lua_State *L)
{
    if (!RTGUM_HOST_FIELD_AVAILABLE(trace_query))
        return luaL_error(L, "gum trace query unavailable");
    const lua_Integer raw = luaL_checkinteger(L, 1);
    LuaTraceEntry *entry = raw > 0 ? FindTraceEntry(static_cast<unsigned long>(raw))
                                  : nullptr;
    if (entry == nullptr) {
        lua_pushinteger(L, static_cast<lua_Integer>(RTGUM_HOST_ERR_NOENT));
        lua_pushnil(L);
        return 2;
    }
    RtGumTraceStats stats{};
    const long result = g_host->trace_query(entry->handle, &stats);
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    if (result == 0) PushTraceStats(L, stats, *entry);
    else lua_pushnil(L);
    return 2;
}

int LuaGumTraceStop(lua_State *L)
{
    if (!RTGUM_HOST_FIELD_AVAILABLE(trace_stop))
        return luaL_error(L, "gum trace stop unavailable");
    const lua_Integer raw = luaL_checkinteger(L, 1);
    LuaTraceEntry *entry = raw > 0 ? FindTraceEntry(static_cast<unsigned long>(raw))
                                  : nullptr;
    if (entry == nullptr) {
        lua_pushinteger(L, static_cast<lua_Integer>(RTGUM_HOST_ERR_NOENT));
        lua_pushnil(L);
        return 2;
    }
    entry->state.store(kHookRetiring, std::memory_order_release);
    const long result = g_host->trace_stop(entry->handle);
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    if (result != 0 && result != RTGUM_HOST_ERR_NOENT) {
        entry->state.store(kHookActive, std::memory_order_release);
        lua_pushnil(L);
        return 2;
    }
    PushTraceBatches(L, *entry, kTraceBatchCapacity);
    entry->state.store(kHookFree, std::memory_order_release);
    entry->generation.fetch_add(1UL, std::memory_order_acq_rel);
    entry->handle = 0UL;
    ClearTraceStorage(*entry);
    return 2;
}

int LuaGumCallbackStats(lua_State *L)
{
    lua_newtable(L);
#define RTGUM_PUSH_ATOMIC_STAT(name, value)                                    \
    lua_pushinteger(L, static_cast<lua_Integer>(                               \
        value.load(std::memory_order_acquire)));                              \
    lua_setfield(L, -2, name)
    RTGUM_PUSH_ATOMIC_STAT("queued", g_callback_queued);
    RTGUM_PUSH_ATOMIC_STAT("dispatched", g_callback_dispatched);
    RTGUM_PUSH_ATOMIC_STAT("full_drops", g_callback_full_drops);
    RTGUM_PUSH_ATOMIC_STAT("stale_drops", g_callback_stale_drops);
    RTGUM_PUSH_ATOMIC_STAT("recursive_drops", g_callback_recursive_drops);
    RTGUM_PUSH_ATOMIC_STAT("lua_errors", g_callback_lua_errors);
#undef RTGUM_PUSH_ATOMIC_STAT
    lua_pushinteger(L, static_cast<lua_Integer>(g_lua_allocator.used));
    lua_setfield(L, -2, "heap_used");
    lua_pushinteger(L, static_cast<lua_Integer>(g_lua_allocator.peak));
    lua_setfield(L, -2, "heap_peak");
    return 1;
}

int LuaGumCapabilities(lua_State *L)
{
    lua_newtable(L);
#define RTGUM_PUSH_CAPABILITY(name, expression)                                \
    lua_pushboolean(L, (expression) ? 1 : 0);                                 \
    lua_setfield(L, -2, name)
    RTGUM_PUSH_CAPABILITY("find_export", GumAvailable());
    RTGUM_PUSH_CAPABILITY("attach", GumAvailable());
    RTGUM_PUSH_CAPABILITY("replace", GumAvailable() &&
                                    RTGUM_HOST_FIELD_AVAILABLE(gum_replace));
    RTGUM_PUSH_CAPABILITY("memory_read", GumAvailable() &&
                                        RTGUM_HOST_FIELD_AVAILABLE(gum_memory_read));
    RTGUM_PUSH_CAPABILITY("memory_write", GumAvailable() &&
                                         RTGUM_HOST_FIELD_AVAILABLE(gum_memory_write));
    RTGUM_PUSH_CAPABILITY("memory_alloc", GumAvailable() &&
                                         RTGUM_HOST_FIELD_AVAILABLE(gum_memory_alloc));
    RTGUM_PUSH_CAPABILITY("memory_free", GumAvailable() &&
                                        RTGUM_HOST_FIELD_AVAILABLE(gum_memory_free));
    RTGUM_PUSH_CAPABILITY("native_call", GumAvailable());
    RTGUM_PUSH_CAPABILITY("async_callbacks", GumAvailable());
    RTGUM_PUSH_CAPABILITY("stalker", GumAvailable() &&
                                      RTGUM_HOST_FIELD_AVAILABLE(dbi_stalker_start) &&
                                      RTGUM_HOST_FIELD_AVAILABLE(dbi_stalker_stop));
    RTGUM_PUSH_CAPABILITY("trace", GumAvailable() &&
                                    RTGUM_HOST_FIELD_AVAILABLE(trace_start) &&
                                    RTGUM_HOST_FIELD_AVAILABLE(trace_stop) &&
                                    RTGUM_HOST_FIELD_AVAILABLE(trace_query));
#undef RTGUM_PUSH_CAPABILITY
    return 1;
}

void Register(lua_State *L, const char *name, lua_CFunction function)
{
    lua_pushcfunction(L, function);
    lua_setfield(L, -2, name);
}

void OpenSandbox(lua_State *L)
{
    luaL_requiref(L, LUA_GNAME, luaopen_base, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_COLIBNAME, luaopen_coroutine, 1);
    lua_pop(L, 1);
    const char *removed[] = {
        "dofile", "loadfile", "load", "require", "collectgarbage", nullptr};
    for (const char **name = removed; *name != nullptr; ++name) {
        lua_pushnil(L);
        lua_setglobal(L, *name);
    }
    lua_newtable(L);
    Register(L, "log", LuaLog);
    Register(L, "find_export", LuaFindExport);
    Register(L, "hook_native_symbol", LuaHookSymbol);
    Register(L, "revert", LuaRevert);
    Register(L, "gum_find_export", LuaGumFindExport);
    Register(L, "gum_intercept_attach", LuaGumAttach);
    Register(L, "gum_intercept_attach_address", LuaGumAttachAddress);
    Register(L, "gum_intercept_revert", LuaGumRevert);
    Register(L, "gum_replace", LuaGumReplace);
    Register(L, "gum_clear_all", LuaGumClearAll);
    Register(L, "gum_memory_read", LuaGumMemoryRead);
    Register(L, "gum_memory_write", LuaGumMemoryWrite);
    Register(L, "gum_memory_alloc", LuaGumMemoryAlloc);
    Register(L, "gum_memory_free", LuaGumMemoryFree);
    Register(L, "gum_call", LuaGumCall);
    Register(L, "memory_read", LuaGumMemoryRead);
    Register(L, "memory_write", LuaGumMemoryWrite);
    Register(L, "read_cstring", LuaGumReadCString);
    Register(L, "gum_stalker_start_current_thread", LuaGumStalkerStart);
    Register(L, "gum_stalker_invalidate", LuaGumStalkerInvalidate);
    Register(L, "gum_stalker_stop", LuaGumStalkerStop);
    Register(L, "gum_trace_start", LuaGumTraceStart);
    Register(L, "gum_trace_read", LuaGumTraceRead);
    Register(L, "gum_trace_query", LuaGumTraceQuery);
    Register(L, "gum_trace_stop", LuaGumTraceStop);
    Register(L, "gum_callback_stats", LuaGumCallbackStats);
    Register(L, "gum_capabilities", LuaGumCapabilities);
    lua_setglobal(L, "rtgum");
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(void *) {}

extern "C" __attribute__((visibility("default"))) long
rtgum_host_bind_lua(HostApiV2 *host)
{
    if (host == nullptr || host->version != RTGUM_HOST_API_V2_VERSION ||
        host->size < static_cast<unsigned long>(
            offsetof(HostApiV2, lua_stop) + sizeof(host->lua_stop)))
        return RTGUM_HOST_ERR_INVAL;
    pthread_mutex_lock(&g_worker_mutex);
    if ((g_worker_running || g_lua != nullptr) && g_host != host) {
        pthread_mutex_unlock(&g_worker_mutex);
        return RTGUM_HOST_ERR_BUSY;
    }
    g_host = host;
    host->lua_eval = LuaEval;
    host->lua_stop = LuaStop;
    host->capabilities |= RTGUM_HOST_CAP_LUA;
    if (host->size >= static_cast<unsigned long>(
            offsetof(HostApiV2, lua_eval_async) + sizeof(host->lua_eval_async))) {
        host->lua_eval_async = AsyncLuaEval;
        host->capabilities |= RTGUM_HOST_CAP_LUA_ASYNC;
    }
    pthread_mutex_unlock(&g_worker_mutex);
    Log("host bind lua");
    return 0;
}
