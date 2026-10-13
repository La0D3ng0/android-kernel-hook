/*
 * rtgum-stage2-gumlua.ghm: Gum Lua demo module for the three target apps.
 *
 * ghostEntry receives the GhostApi from the Daemon, evaluates an embedded
 * Lua script through the sandboxed helper, and lets the script attach a Gum
 * Interceptor hook on libc.so!getpid. The script logs every hit through the
 * Daemon's KPM log channel, so the proof lands in dmesg without any socket
 * or file I/O in the target process.
 *
 * Exports:
 *   ghostEntry(GhostApi*)
 *   ghostModuleUnload(GhostApi*)
 */

#include <rtgum/ghost_api.h>

namespace {

constexpr const char *kLuaScript =
    "local targets = { \"getpid\" }\n"
    "local hits, leaves = {}, {}\n"
    "for _, name in ipairs(targets) do\n"
    "    local function onEnter(inv)\n"
    "        hits[name] = (hits[name] or 0) + 1\n"
    "        if hits[name] == 1 then\n"
    "            rtgum.log(\"gum-lua \" .. name .. \" hit=1 lua-enter=1\")\n"
    "        end\n"
    "    end\n"
    "    local function onLeave(inv)\n"
    "        leaves[name] = (leaves[name] or 0) + 1\n"
    "        if leaves[name] == 1 then\n"
    "            rtgum.log(\"gum-lua \" .. name .. \" leave=1 lua-leave=1\")\n"
    "        end\n"
    "    end\n"
    "    local rc, handle = rtgum.gum_intercept_attach(\"libc.so\", name, onEnter, onLeave)\n"
    "    if rc ~= 0 then\n"
    "        rtgum.log(\"gum-lua attach failed \" .. name .. \" rc=\" .. rc)\n"
    "    else\n"
    "        rtgum.log(\"gum-lua armed \" .. name .. \" handle=\" .. handle)\n"
    "    end\n"
    "end\n"
    "local rc2, addr = rtgum.gum_find_export(\"libc.so\", \"getpid\")\n"
    "rtgum.log(\"gum-lua find getpid=0x\" .. string.format(\"%x\", addr))\n"
    "local arc, path = rtgum.gum_memory_alloc(32)\n"
    "if arc == 0 then\n"
    "    local wrc = rtgum.gum_memory_write(path, \"ghost\\0\")\n"
    "    local rrc, bytes = rtgum.gum_memory_read(path, 6)\n"
    "    if wrc == 0 and rrc == 0 and bytes == \"ghost\\0\" then\n"
    "        rtgum.log(\"gum-lua ghost-memory=1\")\n"
    "    end\n"
    "    rtgum.gum_memory_free(path)\n"
    "end\n"
    "if rc2 == 0 then rtgum.gum_call(addr) end\n"
    "local mrc, malloc_addr = rtgum.gum_find_export(\"libc.so\", \"malloc\")\n"
    "local frc, free_addr = rtgum.gum_find_export(\"libc.so\", \"free\")\n"
    "if mrc == 0 and frc == 0 then\n"
    "    local heap = rtgum.gum_call(malloc_addr, 32)\n"
    "    if heap ~= 0 then\n"
    "        local wrc = rtgum.gum_memory_write(heap, \"rtgum\\0\")\n"
    "        local rrc, bytes = rtgum.gum_memory_read(heap, 6)\n"
    "        if wrc == 0 and rrc == 0 and bytes == \"rtgum\\0\" then\n"
    "            rtgum.log(\"gum-lua ordinary-memory=1\")\n"
    "        end\n"
    "        rtgum.gum_call(free_addr, heap)\n"
    "    end\n"
    "end\n"
    "return \"armed\"\n";

} // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || !api->host) return;
    api->log("rtgum-gumlua-module: entry");
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 0);
    char error[256];
    error[0] = '\0';
    long rc = RTGUM_HOST_ERR_NOTSUP;
    /* This fixture publishes ARMED only after the script has actually
     * installed its hooks.  Modules that do not expose a completion status
     * may use lua_eval_async, but must treat its result as QUEUED, not ARMED. */
    if (api->host->lua_eval != nullptr)
        rc = api->host->lua_eval(kLuaScript, error, sizeof(error));
    if (rc != 0) {
        api->log("rtgum-gumlua-module: lua eval failed");
        if (error[0] != '\0') api->log(error);
        api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_GUMLUA_FAILED);
        return;
    }
    api->log("rtgum-gumlua-module: lua armed");
    api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_GUMLUA_ARMED);
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (!api || !api->host) return;
    /* Clear the script's Interceptor hooks before the module image goes
     * away, then close the sandboxed VM. */
    const long cleared = api->host->lua_eval("return rtgum.gum_clear_all()", nullptr, 0);
    (void)cleared;
    api->host->lua_stop();
    api->log("rtgum-gumlua-module: unload");
    api->status(RTGUM_DAEMON_STATUS_EXTRA, 0);
}
