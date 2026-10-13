/* Visible-path Lua helper acceptance.  The fake Gum table exercises the same
 * callback queue and Lua surface used by the ghost-loaded device path. */

#include "rtgum/gum_api.h"
#include "rtgum/host_api_v2.h"

#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <string>

namespace {

HostApiV2 *g_reentry_host = nullptr;
bool g_find_called = false;
long g_reentry_result = 0;
void (*g_enter)(RtGumInvocation *, void *) = nullptr;
void (*g_leave)(RtGumInvocation *, void *) = nullptr;
void *g_callback_user = nullptr;
unsigned long g_attach_handle = 0UL;
unsigned long g_attach_sequence = 0UL;
unsigned long g_revert_count = 0UL;
unsigned char g_memory[256]{};
bool g_memory_live = false;
constexpr unsigned long kTestPointerTag = 0xB400000000000000UL;
RtGumStalkerStats *g_stalker_stats = nullptr;
unsigned long g_trace_handle = 0UL;

bool ResultIs(const char *text, long long value)
{
    char expected[64]{};
    std::snprintf(expected, sizeof(expected), "result=%lld", value);
    return text != nullptr && std::strstr(text, expected) != nullptr;
}

long TestFindExport(const char *, const char *, unsigned long *address)
{
    g_find_called = true;
    char message[64]{};
    g_reentry_result =
        g_reentry_host->lua_eval("return 1", message, sizeof(message));
    *address = 0x1234UL;
    return 0;
}

long FakeGumFindExport(const char *, const char *, unsigned long *address)
{
    if (address == nullptr) return RTGUM_HOST_ERR_INVAL;
    *address = 0x1234UL;
    return 0;
}

long FakeGumAttachAddress(
    unsigned long address,
    void (*on_enter)(RtGumInvocation *, void *),
    void (*on_leave)(RtGumInvocation *, void *),
    void *user_data,
    unsigned long *out_handle)
{
    if (address == 0UL || out_handle == nullptr) return RTGUM_HOST_ERR_INVAL;
    g_enter = on_enter;
    g_leave = on_leave;
    g_callback_user = user_data;
    g_attach_handle = 100UL + ++g_attach_sequence;
    *out_handle = g_attach_handle;
    return 0;
}

long FakeGumAttach(
    const char *, const char *,
    void (*on_enter)(RtGumInvocation *, void *),
    void (*on_leave)(RtGumInvocation *, void *),
    void *user_data,
    unsigned long *out_handle)
{
    return FakeGumAttachAddress(0x1234UL, on_enter, on_leave, user_data,
                                out_handle);
}

long FakeGumRevert(unsigned long handle)
{
    if (handle == 0UL) return RTGUM_HOST_ERR_INVAL;
    ++g_revert_count;
    if (handle == g_attach_handle) g_attach_handle = 0UL;
    return 0;
}

long FakeGumReplace(unsigned long target, unsigned long replacement,
                    unsigned long *out_original, unsigned long *out_handle)
{
    if (target == 0UL || replacement == 0UL || out_original == nullptr ||
        out_handle == nullptr)
        return RTGUM_HOST_ERR_INVAL;
    *out_original = 0x8888UL;
    g_attach_handle = 0x303UL;
    *out_handle = g_attach_handle;
    return 0;
}

bool MemoryRange(unsigned long address, unsigned long length,
                 unsigned long &offset)
{
    const unsigned long base = reinterpret_cast<unsigned long>(g_memory);
    const unsigned long untagged = address & 0x00FFFFFFFFFFFFFFUL;
    if (!g_memory_live || untagged < base || untagged + length < untagged ||
        untagged + length > base + sizeof(g_memory))
        return false;
    offset = untagged - base;
    return true;
}

long FakeMemoryRead(unsigned long address, void *buffer, unsigned long length)
{
    unsigned long offset = 0UL;
    if (buffer == nullptr || length == 0UL ||
        !MemoryRange(address, length, offset))
        return RTGUM_HOST_ERR_NXIO;
    std::memcpy(buffer, g_memory + offset, static_cast<std::size_t>(length));
    return 0;
}

long FakeMemoryWrite(unsigned long address, const void *buffer,
                     unsigned long length)
{
    unsigned long offset = 0UL;
    if (buffer == nullptr || length == 0UL ||
        !MemoryRange(address, length, offset))
        return RTGUM_HOST_ERR_NXIO;
    std::memcpy(g_memory + offset, buffer, static_cast<std::size_t>(length));
    return 0;
}

long FakeMemoryAlloc(unsigned long size, unsigned long *out_address)
{
    if (size == 0UL || size > sizeof(g_memory) || out_address == nullptr)
        return RTGUM_HOST_ERR_INVAL;
    std::memset(g_memory, 0, sizeof(g_memory));
    g_memory_live = true;
    *out_address = reinterpret_cast<unsigned long>(g_memory) | kTestPointerTag;
    return 0;
}

long FakeMemoryFree(unsigned long address)
{
    if (!g_memory_live ||
        (address & 0x00FFFFFFFFFFFFFFUL) !=
            reinterpret_cast<unsigned long>(g_memory))
        return RTGUM_HOST_ERR_NOENT;
    g_memory_live = false;
    return 0;
}

long FakeStalkerStart(RtGumStalkerStats *stats, unsigned long start,
                      unsigned long size)
{
    if (stats == nullptr || start == 0UL || size == 0UL)
        return RTGUM_HOST_ERR_INVAL;
    g_stalker_stats = stats;
    stats->blocks = 2UL;
    stats->calls = 1UL;
    if (stats->gtrace_buffer != nullptr && stats->gtrace_capacity != 0UL) {
        stats->gtrace_buffer[0].sequence = 1UL;
        stats->gtrace_buffer[0].pc = start;
        stats->gtrace_count = 1UL;
        stats->gtrace_total = 1UL;
    }
    return 0;
}

long FakeStalkerInvalidate(unsigned long address)
{
    return address != 0UL ? 0L : RTGUM_HOST_ERR_INVAL;
}

long FakeStalkerStop()
{
    if (g_stalker_stats == nullptr) return RTGUM_HOST_ERR_NOENT;
    g_stalker_stats->returns = 1UL;
    g_stalker_stats = nullptr;
    return 0;
}

long FakeTraceStart(const RtGumTraceConfig *config, unsigned long *out_handle)
{
    if (config == nullptr || out_handle == nullptr || config->writer == nullptr ||
        config->target == 0UL || config->watched_size == 0UL)
        return RTGUM_HOST_ERR_INVAL;
    g_trace_handle = 0x901UL;
    *out_handle = g_trace_handle;
    RtGumGtraceStep steps[2]{};
    steps[0].sequence = 1UL;
    steps[0].pc = config->target;
    steps[0].next_pc = config->target + 4UL;
    steps[0].instruction = 0xD503201FU;
    steps[0].flags = RTGUM_GTRACE_STEP_INSN_VALID |
                     RTGUM_GTRACE_STEP_NEXT_VALID;
    steps[1] = steps[0];
    steps[1].sequence = 2UL;
    steps[1].pc += 4UL;
    steps[1].next_pc += 4UL;
    RtGumTraceBatch batch{};
    batch.version = RTGUM_TRACE_BATCH_VERSION;
    batch.size = sizeof(batch);
    batch.handle = g_trace_handle;
    batch.target = config->target;
    batch.invocation = 1UL;
    batch.trace_mode = config->trace_mode;
    batch.mem_read_mode = config->mem_read_mode;
    batch.steps = steps;
    batch.count = 2UL;
    batch.total = 2UL;
    return config->writer(&batch, config->writer_user_data);
}

long FakeTraceStop(unsigned long handle)
{
    if (handle != g_trace_handle) return RTGUM_HOST_ERR_NOENT;
    g_trace_handle = 0UL;
    return 0;
}

long FakeTraceQuery(unsigned long handle, RtGumTraceStats *stats)
{
    if (handle != g_trace_handle || stats == nullptr)
        return RTGUM_HOST_ERR_NOENT;
    *stats = {};
    stats->version = RTGUM_TRACE_STATS_VERSION;
    stats->size = sizeof(*stats);
    stats->handle = handle;
    stats->target = 0x4000UL;
    stats->invocations = 1UL;
    stats->completed = 1UL;
    stats->active = 1UL;
    return 0;
}

extern "C" unsigned long TestNativeAdd(unsigned long a, unsigned long b,
                                        unsigned long, unsigned long,
                                        unsigned long, unsigned long,
                                        unsigned long, unsigned long)
{
    return a + b;
}

int Fail(const char *message)
{
    std::fprintf(stderr, "%s\n", message);
    return 1;
}

}  // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return Fail("usage: rtgum-jnicode-lua-test <librtgum-lua-helper.so>");
    void *library = dlopen(argv[1], RTLD_NOW);
    if (!library) {
        std::fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }
    using BindFn = long (*)(HostApiV2 *);
    auto *bind = reinterpret_cast<BindFn>(
        dlsym(library, "rtgum_host_bind_lua"));
    if (!bind) return Fail("rtgum_host_bind_lua missing");

    HostApiV2 host{};
    host.version = RTGUM_HOST_API_V2_VERSION;
    host.size = sizeof(HostApiV2);
    host.gum_find_export = FakeGumFindExport;
    host.gum_intercept_attach = FakeGumAttach;
    host.gum_intercept_attach_address = FakeGumAttachAddress;
    host.gum_intercept_revert = FakeGumRevert;
    host.gum_replace = FakeGumReplace;
    host.gum_memory_read = FakeMemoryRead;
    host.gum_memory_write = FakeMemoryWrite;
    host.gum_memory_alloc = FakeMemoryAlloc;
    host.gum_memory_free = FakeMemoryFree;
    host.dbi_stalker_start = FakeStalkerStart;
    host.dbi_stalker_invalidate = FakeStalkerInvalidate;
    host.dbi_stalker_stop = FakeStalkerStop;
    host.trace_start = FakeTraceStart;
    host.trace_stop = FakeTraceStop;
    host.trace_query = FakeTraceQuery;
    host.capabilities = RTGUM_HOST_CAP_GUM;
    if (bind(&host) != 0 || host.lua_eval == nullptr ||
        host.lua_stop == nullptr)
        return Fail("bind lua failed");
    if ((host.capabilities &
         (RTGUM_HOST_CAP_LUA | RTGUM_HOST_CAP_LUA_ASYNC)) !=
            (RTGUM_HOST_CAP_LUA | RTGUM_HOST_CAP_LUA_ASYNC) ||
        host.lua_eval_async == nullptr)
        return Fail("Lua sync/async capabilities missing");

    char text[512]{};
    if (host.lua_eval("return 40+2", text, sizeof(text)) != 0 ||
        !ResultIs(text, 42))
        return Fail("valid script failed");

    host.find_export = TestFindExport;
    g_reentry_host = &host;
    if (host.lua_eval("return rtgum.find_export('self', 'symbol')", text,
                      sizeof(text)) == 0 ||
        g_find_called)
        return Fail("find_export bypassed its capability bit");
    host.capabilities |= RTGUM_HOST_CAP_FIND_EXPORT;
    if (host.lua_eval("return rtgum.find_export('self', 'symbol')", text,
                      sizeof(text)) != 0 ||
        !g_find_called || g_reentry_result != RTGUM_HOST_ERR_BUSY)
        return Fail("find_export or worker reentry guard failed");

    const char *callback_script =
        "enter_count,leave_count=0,0\n"
        "local function enter(i) "
        "assert(i.asynchronous and not i.context_valid and i.context==0 and "
        "i.phase=='enter' and i[1]==11); enter_count=enter_count+1 end\n"
        "local function leave(i) assert(i.phase=='leave' and i.retval==33 and "
        "i.syserr==44); leave_count=leave_count+1 end\n"
        "local rc,h=rtgum.gum_intercept_attach('libc.so','open',enter,leave)\n"
        "hook_handle=h; return rc";
    if (host.lua_eval(callback_script, text, sizeof(text)) != 0 ||
        !ResultIs(text, 0) || g_enter == nullptr || g_leave == nullptr)
        return Fail("Lua Gum attach failed");
    auto old_enter = g_enter;
    auto old_leave = g_leave;
    void *old_user = g_callback_user;
    RtGumInvocation invocation{};
    invocation.function = 0x1234UL;
    invocation.args[0] = 11UL;
    invocation.return_value = 33UL;
    invocation.system_error = 44U;
    old_enter(&invocation, old_user);
    old_leave(&invocation, old_user);
    if (host.lua_eval("return enter_count*100+leave_count", text,
                      sizeof(text)) != 0 ||
        !ResultIs(text, 101))
        return Fail("queued Lua enter/leave callbacks were not dispatched");

    if (host.lua_eval("return rtgum.gum_intercept_revert(hook_handle)", text,
                      sizeof(text)) != 0 ||
        !ResultIs(text, 0))
        return Fail("Lua Gum revert failed");
    old_enter(&invocation, old_user);
    old_leave(&invocation, old_user);
    if (host.lua_eval("return enter_count*100+leave_count", text,
                      sizeof(text)) != 0 ||
        !ResultIs(text, 101))
        return Fail("late callbacks survived revert");

    if (host.lua_eval(
            "local rc,h=rtgum.gum_intercept_attach_address(0x1234,"
            "function(i) enter_count=enter_count+1 end,nil); hook2=h; return rc",
            text, sizeof(text)) != 0 ||
        !ResultIs(text, 0))
        return Fail("address attach after slot reuse failed");
    auto new_enter = g_enter;
    void *new_user = g_callback_user;
    old_enter(&invocation, old_user);
    new_enter(&invocation, new_user);
    if (host.lua_eval(
            "local s=rtgum.gum_callback_stats(); "
            "return enter_count*1000+leave_count*100+"
            "((s.stale_drops>=3 and s.dispatched>=3) and 1 or 0)",
            text, sizeof(text)) != 0 ||
        !ResultIs(text, 2101))
        return Fail("slot generation or callback statistics failed");

    if (host.lua_eval(
            "local rc,p=rtgum.gum_memory_alloc(32); if rc~=0 then return -1 end; "
            "if rtgum.gum_memory_write(p,'abc\\0')~=0 then return -2 end; "
            "local rr,s=rtgum.gum_memory_read(p,4); "
            "local fr=rtgum.gum_memory_free(p); "
            "return (rr==0 and s=='abc\\0' and fr==0) and 1 or -3",
            text, sizeof(text)) != 0 ||
        !ResultIs(text, 1) || g_memory_live)
        return Fail("Lua Gum memory lifecycle failed");

    char native_script[256]{};
    std::snprintf(native_script, sizeof(native_script),
                  "return rtgum.gum_call(%llu,20,22)",
                  static_cast<unsigned long long>(
                      reinterpret_cast<unsigned long>(&TestNativeAdd)));
    if (host.lua_eval(native_script, text, sizeof(text)) != 0 ||
        !ResultIs(text, 42))
        return Fail("Lua native Gum call failed");

    if (host.lua_eval(
            "local rc,o,h=rtgum.gum_replace(0x1111,0x2222); replace_handle=h; "
            "return (rc==0 and o==0x8888 and h~=0) and 1 or 0",
            text, sizeof(text)) != 0 ||
        !ResultIs(text, 1) ||
        host.lua_eval("return rtgum.gum_intercept_revert(replace_handle)",
                      text, sizeof(text)) != 0 ||
        !ResultIs(text, 0))
        return Fail("Lua Gum replace/revert failed");

    if (host.lua_eval(
            "local a=rtgum.gum_stalker_start_current_thread(0x4000,0x100,4); "
            "local i=rtgum.gum_stalker_invalidate(0x4000); "
            "local z,s=rtgum.gum_stalker_stop(); "
            "return (a==0 and i==0 and z==0 and s.blocks==2 and "
            "s.returns==1 and s.gtrace_count==1) and 1 or 0",
            text, sizeof(text)) != 0 || !ResultIs(text, 1))
        return Fail("Lua Gum Stalker lifecycle failed");

    if (host.lua_eval(
            "local rc,h=rtgum.gum_trace_start({target=0x4000,"
            "watched_start=0x4000,watched_size=0x100,step_capacity=8}); "
            "local qr,q=rtgum.gum_trace_query(h); "
            "local rr,b=rtgum.gum_trace_read(h,8); "
            "local sr,t=rtgum.gum_trace_stop(h); "
            "return (rc==0 and qr==0 and q.completed==1 and rr==0 and "
            "#b==1 and #b[1].steps==2 and sr==0) and 1 or 0",
            text, sizeof(text)) != 0 || !ResultIs(text, 1))
        return Fail("Lua Gum multi-trace lifecycle failed");

    if (host.lua_eval_async("async_value=73", text, sizeof(text)) != 0 ||
        host.lua_eval("return async_value", text, sizeof(text)) != 0 ||
        !ResultIs(text, 73))
        return Fail("Lua async FIFO failed");

    if (host.lua_eval(
            "local rc,h=rtgum.gum_intercept_attach_address(0x2345,"
            "function() while true do end end,nil); budget_hook=h; return rc",
            text, sizeof(text)) != 0 || !ResultIs(text, 0))
        return Fail("callback budget fixture attach failed");
    auto budget_enter = g_enter;
    void *budget_user = g_callback_user;
    budget_enter(&invocation, budget_user);
    if (host.lua_eval(
            "local s=rtgum.gum_callback_stats(); "
            "return s.lua_errors>=1 and 1 or 0",
            text, sizeof(text)) != 0 || !ResultIs(text, 1))
        return Fail("Lua callback execution budget did not terminate a loop");

    if (host.lua_eval(
            "return (os==nil and io==nil and package==nil and require==nil "
            "and load==nil and loadfile==nil and dofile==nil and "
            "collectgarbage==nil) and 1 or 0",
            text, sizeof(text)) != 0 ||
        !ResultIs(text, 1))
        return Fail("sandbox left a code/file loading primitive available");
    if (host.lua_eval("return string.rep('x',17*1024*1024)", text,
                      sizeof(text)) == 0 ||
        host.lua_eval("return 5", text, sizeof(text)) != 0 ||
        !ResultIs(text, 5))
        return Fail("Lua heap limit did not fail closed and recover");
    if (host.lua_eval("function (", text, sizeof(text)) == 0)
        return Fail("syntax error was accepted");
    std::string oversized(256U * 1024U + 1U, 'x');
    if (host.lua_eval(oversized.c_str(), text, sizeof(text)) !=
            RTGUM_HOST_ERR_INVAL ||
        std::strstr(text, "too large") == nullptr)
        return Fail("oversized script was accepted");
    if (host.lua_eval("\x1bLua", text, sizeof(text)) == 0)
        return Fail("binary Lua chunk was accepted");
    if (host.lua_eval("error('boom')", text, sizeof(text)) == 0 ||
        std::strstr(text, "boom") == nullptr)
        return Fail("runtime error contract failed");

    HostApiV2 other_host{};
    other_host.version = RTGUM_HOST_API_V2_VERSION;
    other_host.size = sizeof(other_host);
    if (bind(&other_host) != RTGUM_HOST_ERR_BUSY)
        return Fail("live Lua VM allowed host replacement");
    const unsigned long reverts_before_stop = g_revert_count;
    if (host.lua_stop() != 0 || g_revert_count <= reverts_before_stop)
        return Fail("lua_stop did not detach active Gum hooks");
    old_enter(&invocation, old_user);
    if (bind(&other_host) != 0)
        return Fail("host replacement after stop failed");
    if (other_host.lua_eval("return 1", text, sizeof(text)) != 0 ||
        !ResultIs(text, 1))
        return Fail("lua_eval after stop did not recreate the VM");
    other_host.lua_stop();

    std::puts("lua sync=1 async=1 callback-enter=1 callback-leave=1 stale=1 "
              "replace=1 memory=1 native-call=1 stalker=1 trace=1 budget=1 "
              "sandbox=1 heap-limit=1 teardown=1");
    std::puts("jnicode-lua PASS");
    dlclose(library);
    return 0;
}
