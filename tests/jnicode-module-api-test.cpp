/*
 * Visible-path HostApiV2.hook_native_symbol (无痕 shadowHook shape).
 * Covers no-hook, valid rewrite, missing symbol, revert, and stale handle.
 */

#include "rtgum/native_backend.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {

long OpenRead(const char *path)
{
    return open(path, O_RDONLY | O_CLOEXEC);
}

long ReadFd(long fd, void *buffer, unsigned long size)
{
    const ssize_t count = read(static_cast<int>(fd), buffer, static_cast<size_t>(size));
    return count;
}

long CloseFd(long fd)
{
    return close(static_cast<int>(fd));
}

long MapAnonymous(unsigned long size, unsigned long protection)
{
    void *address = mmap(nullptr, static_cast<size_t>(size), static_cast<int>(protection),
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) return -static_cast<long>(errno);
    return reinterpret_cast<long>(address);
}

long Protect(unsigned long address, unsigned long size, unsigned long protection)
{
    if (mprotect(reinterpret_cast<void *>(address), static_cast<size_t>(size),
                 static_cast<int>(protection)) != 0) {
        return -static_cast<long>(errno);
    }
    return 0;
}

long Unmap(unsigned long address, unsigned long size)
{
    return munmap(reinterpret_cast<void *>(address), static_cast<size_t>(size)) == 0
               ? 0
               : -static_cast<long>(errno);
}

void ClearCache(unsigned long address, unsigned long size)
{
    __builtin___clear_cache(reinterpret_cast<char *>(address),
                            reinterpret_cast<char *>(address + size));
}

rtgum::native::Engine g_engine;
const char *g_last_utf = nullptr;
unsigned long g_original = 0;
unsigned long g_calls = 0;

jstring MockNewStringUTF(JNIEnv *, const char *utf)
{
    g_last_utf = utf;
    return reinterpret_cast<jstring>(static_cast<uintptr_t>(0xC0FFEEUL));
}

unsigned long HookedStringFromJni(void *env, unsigned long thiz)
{
    using Original = unsigned long (*)(void *, unsigned long);
    ++g_calls;
    (void)reinterpret_cast<Original>(g_original)(env, thiz);
    void **table = *reinterpret_cast<void ***>(env);
    using NewStringUTFFn = unsigned long (*)(void *, const char *);
    auto *new_string_utf = reinterpret_cast<NewStringUTFFn>(
        table[RTGUM_JNI_NEW_STRING_UTF_INDEX]);
    return new_string_utf(env, RTGUM_JNI_REPLACEMENT_TEXT);
}

long HostFindExport(const char *soname, const char *symbol, unsigned long *out_address)
{
    return g_engine.FindExport(soname, symbol, out_address);
}

long HostReplace(unsigned long target,
                 unsigned long replacement,
                 unsigned long *out_original,
                 unsigned long *out_handle)
{
    return g_engine.Replace(target, replacement, out_original, out_handle);
}

long HostRevert(unsigned long handle)
{
    return g_engine.Revert(handle);
}

long HostQuery(unsigned long handle, unsigned int *out_backend, unsigned int *out_state)
{
    return g_engine.Query(handle, out_backend, out_state);
}

long HostHookSymbol(const char *soname,
                    const char *symbol,
                    unsigned long replacement,
                    unsigned long *out_original,
                    unsigned long *out_handle)
{
    return g_engine.HookSymbol(soname, symbol, replacement, out_original, out_handle);
}

long HostWaitExport(const char *soname,
                    const char *symbol,
                    unsigned int timeout_ms,
                    unsigned long *out_address)
{
    return g_engine.WaitExport(soname, symbol, timeout_ms, out_address);
}

long SleepMs(unsigned int milliseconds)
{
    struct timespec spec;
    spec.tv_sec = static_cast<time_t>(milliseconds / 1000U);
    spec.tv_nsec = static_cast<long>(milliseconds % 1000U) * 1000000L;
    return nanosleep(&spec, nullptr) == 0 ? 0 : -static_cast<long>(errno);
}

int Fail(const char *message)
{
    std::fprintf(stderr, "%s\n", message);
    return 1;
}

bool UtfEquals(const char *expected)
{
    return g_last_utf != nullptr && std::strcmp(g_last_utf, expected) == 0;
}

}  // namespace

int main(int argc, char **argv)
{
    if (argc != 2) return Fail("usage: rtgum-jnicode-module-api-test <libjnicode.so>");

    static_assert(offsetof(JNINativeInterface, NewStringUTF) ==
                      RTGUM_JNI_NEW_STRING_UTF_INDEX * sizeof(void *),
                  "JNI NewStringUTF index mismatch");
    static_assert(offsetof(HostApiV2, hook_native_symbol) >
                      offsetof(HostApiV2, hook_java_method),
                  "hook_native_symbol must stay after Java pointers");
    static_assert(offsetof(HostApiV2, wait_export) >
                      offsetof(HostApiV2, hook_native_symbol),
                  "wait_export must stay after hook_native_symbol");
    static_assert(offsetof(HostApiV2, load_dex) > offsetof(HostApiV2, wait_export),
                  "load_dex must stay after wait_export");
    static_assert(offsetof(HostApiV2, gtrace_decode) > offsetof(HostApiV2, hook_binder),
                  "gtrace_decode must stay after hook_binder");
    static_assert(offsetof(HostApiV2, gtrace_format_path) >
                      offsetof(HostApiV2, jni_trace_register),
                  "runtime GTrace formatter must remain append-only");
    static_assert(offsetof(HostApiV2, trace_start) >
                      offsetof(HostApiV2, gtrace_format_path),
                  "multi-trace API must remain append-only");
    static_assert(offsetof(HostApiV2, trace_query) >
                      offsetof(HostApiV2, trace_stop),
                  "multi-trace query must follow teardown");
    static_assert(offsetof(HostApiV2, lua_eval_async) >
                      offsetof(HostApiV2, trace_query),
                  "Lua async submission must remain append-only");
    static_assert((RTGUM_HOST_CAP_LUA_ASYNC &
                   (RTGUM_HOST_CAP_LUA | RTGUM_HOST_CAP_MULTI_TRACE)) == 0UL,
                  "Lua async capability bit must remain unique");

    void *library = dlopen(argv[1], RTLD_NOW);
    if (!library) {
        std::fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    g_engine.ops.open_read = OpenRead;
    g_engine.ops.read = ReadFd;
    g_engine.ops.close = CloseFd;
    g_engine.ops.mmap = MapAnonymous;
    g_engine.ops.mprotect = Protect;
    g_engine.ops.munmap = Unmap;
    g_engine.ops.clear_cache = ClearCache;
    g_engine.ops.sleep_ms = SleepMs;

    HostApiV2 host{};
    host.version = RTGUM_HOST_API_V2_VERSION;
    host.size = sizeof(HostApiV2);
    host.capabilities = RTGUM_HOST_CAP_FIND_EXPORT | RTGUM_HOST_CAP_NATIVE_REPLACE |
                        RTGUM_HOST_CAP_NATIVE_SYMBOL | RTGUM_HOST_CAP_WAIT_EXPORT;
    host.find_export = HostFindExport;
    host.hook_native_replace = HostReplace;
    host.hook_native_revert = HostRevert;
    host.hook_query = HostQuery;
    host.hook_native_symbol = HostHookSymbol;
    host.wait_export = HostWaitExport;
    host.sleep_ms = SleepMs;

    JNINativeInterface functions{};
    functions.NewStringUTF = MockNewStringUTF;
    JNIEnv env{};
    env.functions = &functions;

    unsigned long target = 0;
    if (host.find_export("libjnicode.so", RTGUM_JNI_STRING_FROM_JNI, &target) != 0 ||
        target == 0) {
        return Fail("find_export failed");
    }
    using JniFn = unsigned long (*)(void *, unsigned long);
    auto original = reinterpret_cast<JniFn>(target);

    g_last_utf = nullptr;
    const unsigned long baseline = original(&env, 0);
    if (baseline != 0xC0FFEEUL || !UtfEquals(RTGUM_JNI_ORIGINAL_TEXT)) {
        return Fail("no-hook baseline mismatch");
    }

    unsigned long missing_original = 1;
    unsigned long missing_handle = 1;
    const long missing = host.hook_native_symbol(
        "libjnicode.so", RTGUM_JNI_MISSING_SYMBOL,
        reinterpret_cast<unsigned long>(HookedStringFromJni), &missing_original, &missing_handle);
    if (missing != RTGUM_HOST_ERR_NOENT || missing_handle != 0 || missing_original != 0) {
        std::fprintf(stderr, "missing-symbol rc=%ld handle=%lu original=%lu\n",
                     missing, missing_handle, missing_original);
        return 1;
    }
    g_last_utf = nullptr;
    if (original(&env, 0) != 0xC0FFEEUL || !UtfEquals(RTGUM_JNI_ORIGINAL_TEXT)) {
        return Fail("missing-symbol mutated the export");
    }

    unsigned long waited = 0;
    if (host.wait_export("libjnicode.so", RTGUM_JNI_STRING_FROM_JNI, 0U, &waited) != 0 ||
        waited != target) {
        return Fail("wait_export immediate miss");
    }
    unsigned long missing_waited = 1;
    if (host.wait_export("libjnicode.so", RTGUM_JNI_MISSING_SYMBOL, 20U, &missing_waited) !=
            RTGUM_HOST_ERR_NOENT ||
        missing_waited != 0) {
        return Fail("wait_export missing-symbol did not time out");
    }

    unsigned long handle = 0;
    const long replaced = host.hook_native_symbol(
        "libjnicode.so", RTGUM_JNI_STRING_FROM_JNI,
        reinterpret_cast<unsigned long>(HookedStringFromJni), &g_original, &handle);
    if (replaced != 0 || handle == 0 || g_original == 0) {
        std::fprintf(stderr, "hook_native_symbol failed rc=%ld handle=%lu\n", replaced, handle);
        return 1;
    }
    unsigned int backend = 0;
    unsigned int state = 0;
    if (host.hook_query(handle, &backend, &state) != 0 ||
        backend != RTGUM_HOST_BACKEND_NATIVE || state != RTGUM_HOST_HOOK_ACTIVE) {
        host.hook_native_revert(handle);
        return Fail("query after install is not ACTIVE");
    }

    g_last_utf = nullptr;
    g_calls = 0;
    const unsigned long hooked = original(&env, 0);
    if (g_calls != 1 || hooked != 0xC0FFEEUL || !UtfEquals(RTGUM_JNI_REPLACEMENT_TEXT)) {
        host.hook_native_revert(handle);
        return Fail("valid rewrite mismatch");
    }

    if (host.hook_native_revert(handle) != 0) return Fail("revert failed");
    if (host.hook_native_revert(handle) != 0) return Fail("idempotent revert failed");
    if (host.hook_query(handle, &backend, &state) != 0 || state != RTGUM_HOST_HOOK_INACTIVE) {
        return Fail("stale handle is not INACTIVE");
    }

    g_last_utf = nullptr;
    if (original(&env, 0) != 0xC0FFEEUL || !UtfEquals(RTGUM_JNI_ORIGINAL_TEXT)) {
        return Fail("restored value mismatch");
    }

    dlclose(library);
    std::puts("module-api no-hook=1 valid=1 missing-symbol=1 wait-export=1 revert=1 stale-handle=1");
    std::puts("jnicode-module-api PASS");
    return 0;
}
